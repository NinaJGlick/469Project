"""
Single-file, production-ready Flask application for secure file uploads and downloads.

Run in development:
    export FLASK_APP=app.py
    export SECRET_KEY="replace-with-a-strong-random-hex-key"
    flask run

Run in production (example with Gunicorn):
    export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    gunicorn -w 4 -b 127.0.0.1:8000 app:app
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from pathlib import Path
from typing import Final

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------

BASE_DIR: Final[Path] = Path(__file__).resolve().parent
DEFAULT_UPLOAD_DIR: Final[Path] = BASE_DIR / "uploads"

# Strict allowlist of safe, non-executable extensions.
# Never allow active web content (e.g., .html, .svg, .js) if files could ever
# be rendered inline, even though we also force attachment downloads.
ALLOWED_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        "txt",
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "csv",
        "json",
        "zip",
    }
)

# Restrict download filenames strictly to server-generated UUID-style names
# (32 hex chars + lowercase alphanumeric extension).
SAFE_STORED_FILENAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-f0-9]{32}\.[a-z0-9]{1,10}$"
)

MAX_UPLOAD_BYTES: Final[int] = 16 * 1024 * 1024  # 16 MiB

# ---------------------------------------------------------------------------
# HTML Template (Auto-escaped by Jinja2)
# ---------------------------------------------------------------------------

INDEX_TEMPLATE: Final[str] = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure File Vault</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 720px; margin: 2.5rem auto; padding: 0 1rem; color: #1f2937; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
    .card { border: 1px solid #d1d5db; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; background: #f9fafb; }
    .flash { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; }
    .flash.error { background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
    .flash.success { background: #dcfce7; color: #166534; border: 1px solid #4ade80; }
    ul { list-style: none; padding: 0; }
    li { display: flex; justify-content: space-between; align-items: center; padding: 0.6rem 0; border-bottom: 1px solid #e5e7eb; }
    li:last-child { border-bottom: none; }
    code { background: #f3f4f6; padding: 0.15rem 0.35rem; border-radius: 4px; font-size: 0.9rem; }
    button { background: #2563eb; color: #fff; border: none; padding: 0.55rem 1rem; border-radius: 6px; cursor: pointer; font-weight: 600; }
    button:hover { background: #1d4ed8; }
    a { color: #2563eb; text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline; }
    .hint { font-size: 0.85rem; color: #4b5563; margin-top: 0.5rem; }
  </style>
</head>
<body>
  <h1>Secure File Upload &amp; Download</h1>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  <div class="card">
    <form action="{{ url_for('upload_file') }}" method="post" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <label for="file"><strong>Select a file to upload:</strong></label><br><br>
      <input id="file" type="file" name="file" required>
      <button type="submit">Upload</button>
      <p class="hint">
        Max size: {{ max_mb }} MB. Allowed types: {{ allowed_exts }}.
      </p>
    </form>
  </div>

  <div class="card">
    <h2 style="font-size: 1.15rem; margin-top: 0;">Stored Files</h2>
    {% if files %}
      <ul>
        {% for item in files %}
          <li>
            <span>
              <code>{{ item.name }}</code>
              <small style="color:#6b7280;">({{ item.size_kb }} KB)</small>
            </span>
            <a href="{{ url_for('download_file', filename=item.name) }}">Download</a>
          </li>
        {% endfor %}
      </ul>
    {% else %}
      <p class="hint">No files uploaded yet.</p>
    {% endif %}
  </div>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Security & File Validation Helpers
# ---------------------------------------------------------------------------


def _get_or_create_csrf_token() -> str:
    """Retrieve or generate a per-session cryptographically random CSRF token."""
    token = session.get("_csrf_token")
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _validate_csrf_token() -> None:
    """Verify submitted CSRF token against session token in constant time."""
    session_token = session.get("_csrf_token")
    submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if (
        not isinstance(session_token, str)
        or not isinstance(submitted_token, str)
        or not secrets.compare_digest(session_token, submitted_token)
    ):
        abort(403, description="Invalid or missing CSRF token.")


def _extract_allowed_extension(raw_filename: str) -> str | None:
    """
    Sanitize an untrusted filename and return its lowercase extension
    if and only if it belongs to ALLOWED_EXTENSIONS.
    """
    cleaned = secure_filename(raw_filename)
    if not cleaned or "." not in cleaned:
        return None
    ext = cleaned.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None
    return ext


def _has_valid_magic_bytes(stream, ext: str) -> bool:
    """
    Inspect the leading bytes of the uploaded file stream to ensure the
    content signature matches the claimed extension, then rewind the stream.
    """
    header = stream.read(16)
    stream.seek(0)

    if not header:
        return False

    signatures: dict[str, tuple[bytes, ...]] = {
        "pdf": (b"%PDF-",),
        "png": (b"\x89PNG\r\n\x1a\n",),
        "jpg": (b"\xff\xd8\xff",),
        "jpeg": (b"\xff\xd8\xff",),
        "gif": (b"GIF87a", b"GIF89a"),
        "zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    }

    if ext == "webp":
        return len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP"

    if ext in signatures:
        return any(header.startswith(sig) for sig in signatures[ext])

    if ext in {"txt", "csv", "json"}:
        # Reject NUL bytes (strong indicator of binary payloads disguised as text)
        # and verify valid UTF-8 encoding on the initial chunk.
        sample = stream.read(4096)
        stream.seek(0)
        if b"\x00" in sample:
            return False
        try:
            sample.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    return False


def _resolve_safe_upload_path(upload_dir: Path, filename: str) -> Path:
    """
    Validate that `filename` matches our strict storage pattern and resolves
    strictly inside `upload_dir` without symlink escapes or path traversal.
    """
    if not SAFE_STORED_FILENAME_RE.fullmatch(filename):
        abort(400, description="Invalid file identifier.")

    base = upload_dir.resolve()
    candidate = (base / filename).resolve()

    if candidate.parent != base or not candidate.is_file():
        abort(404, description="File not found.")

    return candidate


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask application instance."""
    app = Flask(__name__)

    # Configure structured logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        if os.environ.get("FLASK_ENV") == "production":
            raise RuntimeError("SECRET_KEY environment variable must be set in production.")
        app.logger.warning(
            "SECRET_KEY not set; generating ephemeral key for local development."
        )
        secret_key = secrets.token_hex(32)

    upload_folder = Path(os.environ.get("UPLOAD_FOLDER", DEFAULT_UPLOAD_DIR)).resolve()
    upload_folder.mkdir(parents=True, exist_ok=True)
    # Restrict directory permissions to owner (rwx------) on POSIX systems
    try:
        os.chmod(upload_folder, 0o700)
    except OSError:
        pass

    app.config.update(
        SECRET_KEY=secret_key,
        UPLOAD_FOLDER=str(upload_folder),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Set SESSION_COOKIE_SECURE=True when serving over HTTPS in production
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    )

    if test_config:
        app.config.update(test_config)

    # -----------------------------------------------------------------------
    # Security Headers Middleware
    # -----------------------------------------------------------------------

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "style-src 'unsafe-inline'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none';"
        )
        return response

    # -----------------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------------

    @app.get("/")
    def index() -> str:
        upload_dir = Path(app.config["UPLOAD_FOLDER"]).resolve()
        stored_files: list[dict[str, object]] = []

        for entry in sorted(upload_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if entry.is_file() and not entry.is_symlink() and SAFE_STORED_FILENAME_RE.fullmatch(entry.name):
                size_kb = max(1, round(entry.stat().st_size / 1024))
                stored_files.append({"name": entry.name, "size_kb": size_kb})

        return render_template_string(
            INDEX_TEMPLATE,
            csrf_token=_get_or_create_csrf_token(),
            files=stored_files,
            max_mb=app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
            allowed_exts=", ".join(sorted(ALLOWED_EXTENSIONS)),
        )

    @app.post("/upload")
    def upload_file() -> Response:
        _validate_csrf_token()

        if "file" not in request.files:
            flash("No file part found in request.", "error")
            return redirect(url_for("index"))

        uploaded = request.files["file"]
        if not uploaded or not uploaded.filename:
            flash("No file selected.", "error")
            return redirect(url_for("index"))

        ext = _extract_allowed_extension(uploaded.filename)
        if ext is None:
            flash("Unsupported or disallowed file extension.", "error")
            return redirect(url_for("index"))

        if not _has_valid_magic_bytes(uploaded.stream, ext):
            app.logger.warning(
                "Rejected upload with mismatched content signature for extension .%s",
                ext,
            )
            flash("File content does not match its file extension.", "error")
            return redirect(url_for("index"))

        # Generate an unpredictable, collision-free server filename so user input
        # never controls filesystem paths or overwrites existing files.
        stored_name = f"{secrets.token_hex(16)}.{ext}"
        upload_dir = Path(app.config["UPLOAD_FOLDER"]).resolve()
        destination = upload_dir / stored_name

        # Write atomically via exclusive creation flag ('xb') to prevent overwrites
        try:
            with open(destination, "xb") as out_file:
                while chunk := uploaded.stream.read(65536):
                    out_file.write(chunk)
            try:
                os.chmod(destination, 0o600)
            except OSError:
                pass
        except OSError:
            app.logger.exception("Failed to write uploaded file to disk.")
            if destination.exists():
                destination.unlink(missing_ok=True)
            abort(500, description="Internal error while saving file.")

        app.logger.info("Stored uploaded file as %s", stored_name)
        flash(f"File uploaded successfully as {stored_name}.", "success")
        return redirect(url_for("index"))

    @app.get("/download/<path:filename>")
    def download_file(filename: str) -> Response:
        upload_dir = Path(app.config["UPLOAD_FOLDER"]).resolve()
        safe_path = _resolve_safe_upload_path(upload_dir, filename)

        app.logger.info("Serving download for %s", safe_path.name)
        # Force attachment disposition and generic binary/sniff-protected delivery
        # so browsers download rather than execute or render active content.
        return send_from_directory(
            directory=str(upload_dir),
            path=safe_path.name,
            as_attachment=True,
            download_name=safe_path.name,
            mimetype="application/octet-stream",
            max_age=0,
        )

    @app.get("/health")
    def health_check() -> tuple[dict[str, str], int]:
        return {"status": "ok"}, 200

    # -----------------------------------------------------------------------
    # Centralized Error Handlers
    # -----------------------------------------------------------------------

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(_err: RequestEntityTooLarge) -> Response:
        max_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        flash(f"File exceeds the maximum allowed size of {max_mb} MB.", "error")
        return redirect(url_for("index"))

    @app.errorhandler(HTTPException)
    def handle_http_exception(err: HTTPException) -> tuple[dict[str, str], int]:
        return {"error": err.name, "message": err.description or "Request error."}, err.code or 400

    @app.errorhandler(Exception)
    def handle_unexpected_exception(err: Exception) -> tuple[dict[str, str], int]:
        app.logger.exception("Unhandled server exception: %s", err)
        return {"error": "Internal Server Error", "message": "An unexpected error occurred."}, 500

    return app


app = create_app()

if __name__ == "__main__":
    # Debug mode is strictly disabled by default; enable only explicitly via env var.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=debug_mode)