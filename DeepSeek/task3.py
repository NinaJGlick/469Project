"""
Secure Flask file upload/download application (single-file version).

Run:
    pip install Flask Werkzeug
    SECRET_KEY=change-me UPLOAD_DIR=./uploads python app.py

Security properties:
    - Path-traversal safe (sanitize + resolve + containment check).
    - Extension allow/deny lists; filename character whitelist.
    - Atomic writes (temp file + os.replace) with O_EXCL unique naming.
    - Size limit enforced via MAX_CONTENT_LENGTH.
    - Generic error messages; no stack traces leaked to clients.
    - Defense-in-depth response headers (CSP, nosniff, frame deny).
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
import unicodedata
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    Blueprint,
    abort,
    jsonify,
    render_template_string,
    request,
    send_from_directory,
)
from werkzeug.datastructures import FileStorage


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

class Config:
    """Configuration sourced from environment variables."""

    UPLOAD_DIR: Path = Path(os.environ.get("UPLOAD_DIR", "./uploads")).resolve()

    # Max request body size (bytes). Flask returns 413 automatically.
    MAX_CONTENT_LENGTH: int = int(os.environ.get("MAX_UPLOAD_BYTES", 16 * 1024 * 1024))

    ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
        ext.strip().lower()
        for ext in os.environ.get(
            "ALLOWED_EXTENSIONS", "png,jpg,jpeg,gif,pdf,txt,csv,json,zip"
        ).split(",")
        if ext.strip()
    )

    FORBIDDEN_EXTENSIONS: frozenset[str] = frozenset(
        {"exe", "sh", "bat", "cmd", "php", "py", "js", "html", "htm"}
    )

    MAX_FILENAME_LENGTH: int = 200

    SECRET_KEY: Optional[str] = os.environ.get("SECRET_KEY")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class FilenameError(ValueError):
    """Raised when a user-provided filename is unacceptable."""


class FileStorageError(Exception):
    """Raised on filesystem/storage failures."""


# --------------------------------------------------------------------------- #
# Utilities
# --------------------------------------------------------------------------- #

_SAFE_FILENAME_RE = re.compile(r"^[\w\-. ]+$", re.UNICODE)


def sanitize_filename(raw_name: str) -> str:
    """
    Normalize an untrusted filename into a safe single component.

    Rejects: path separators, dotfiles, control chars, disallowed chars,
    forbidden extensions, and unsupported extensions.
    """
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise FilenameError("Filename is empty.")

    # Strip any directory components (handle Windows separators too).
    candidate = raw_name.replace("\\", "/").split("/")[-1].strip()
    candidate = unicodedata.normalize("NFKC", candidate)

    if candidate.startswith("."):
        raise FilenameError("Filenames may not start with a dot.")
    if any(ord(ch) < 32 for ch in candidate):
        raise FilenameError("Filename contains control characters.")
    if len(candidate) > Config.MAX_FILENAME_LENGTH:
        raise FilenameError("Filename is too long.")
    if not _SAFE_FILENAME_RE.match(candidate):
        raise FilenameError("Filename contains disallowed characters.")

    suffix = Path(candidate).suffix.lower().lstrip(".")
    if not suffix:
        raise FilenameError("Filename must include an extension.")
    if suffix in Config.FORBIDDEN_EXTENSIONS:
        raise FilenameError("This file type is not permitted.")
    if suffix not in Config.ALLOWED_EXTENSIONS:
        raise FilenameError("Unsupported file extension.")

    return candidate


def resolve_upload_path(filename: str) -> Path:
    """Resolve a sanitized filename inside UPLOAD_DIR; guard against escape."""
    base = Config.UPLOAD_DIR
    base.mkdir(parents=True, exist_ok=True)
    target = (base / filename).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise FilenameError("Invalid file path.") from exc
    return target


# --------------------------------------------------------------------------- #
# Storage service
# --------------------------------------------------------------------------- #

def _unique_destination(directory: Path, filename: str) -> Path:
    """Atomically reserve a non-colliding filename in `directory`."""
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    counter = 0
    while True:
        candidate_name = filename if counter == 0 else f"{stem}-{counter}{suffix}"
        candidate = directory / candidate_name
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            os.close(fd)
            return candidate
        except FileExistsError:
            counter += 1
            if counter > 1000:
                raise FileStorageError("Could not allocate a unique filename.")


def store_upload(upload: FileStorage) -> str:
    """Persist an upload safely; return the stored filename."""
    if upload is None or not upload.filename:
        raise FilenameError("No file was provided.")

    safe_name = sanitize_filename(upload.filename)
    Config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    tmp_fd, tmp_path = tempfile.mkstemp(dir=Config.UPLOAD_DIR, prefix=".upload-")
    try:
        with os.fdopen(tmp_fd, "wb") as tmp:
            upload.save(tmp)
            tmp.flush()
            os.fsync(tmp.fileno())

        dest = _unique_destination(Config.UPLOAD_DIR, safe_name)
        os.replace(tmp_path, dest)
        return dest.name
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def get_existing_upload(filename: str) -> Path:
    """Return the path for download; raise if invalid or missing."""
    safe_name = sanitize_filename(filename)
    path = resolve_upload_path(safe_name)
    if not path.is_file():
        raise FileNotFoundError(safe_name)
    return path


# --------------------------------------------------------------------------- #
# Templates (inline)
# --------------------------------------------------------------------------- #

INDEX_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>File Upload</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }
    label, input, button { display: block; margin: .5rem 0; }
    .ok { color: #096; }
  </style>
</head>
<body>
  <h1>Upload a file</h1>
  <p>Allowed types: {{ allowed|join(', ') }}</p>

  {% if uploaded %}
    <p class="ok">Uploaded as
      <a href="{{ url_for('main.download', filename=uploaded) }}">{{ uploaded }}</a>
    </p>
  {% endif %}

  <form method="post" action="{{ url_for('main.upload') }}" enctype="multipart/form-data">
    <label for="file">Choose a file</label>
    <input id="file" name="file" type="file" required>
    <button type="submit">Upload</button>
  </form>
</body>
</html>
"""

ERROR_TEMPLATE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Error {{ status }}</title></head>
<body>
  <h1>Error {{ status }}</h1>
  <p>{{ message }}</p>
  <p><a href="{{ url_for('main.index') }}">Back</a></p>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

bp = Blueprint("main", __name__)
logger = logging.getLogger(__name__)


def _wants_json() -> bool:
    return request.accept_mimetypes.best == "application/json"


@bp.get("/")
def index():
    return render_template_string(
        INDEX_TEMPLATE, allowed=sorted(Config.ALLOWED_EXTENSIONS)
    )


@bp.post("/upload")
def upload():
    if "file" not in request.files:
        abort(400, description="Missing 'file' part.")

    try:
        stored_name = store_upload(request.files["file"])
    except FilenameError as exc:
        logger.info("Rejected upload: %s", exc)
        abort(400, description=str(exc))
    except FileStorageError:
        logger.exception("Storage failure during upload")
        abort(500)

    if _wants_json():
        return jsonify(filename=stored_name), 201
    return render_template_string(
        INDEX_TEMPLATE,
        allowed=sorted(Config.ALLOWED_EXTENSIONS),
        uploaded=stored_name,
    ), 201


@bp.get("/files/<path:filename>")
def download(filename: str):
    try:
        path = get_existing_upload(filename)
    except (FilenameError, FileNotFoundError):
        abort(404)

    return send_from_directory(
        Config.UPLOAD_DIR,
        path.name,
        as_attachment=True,
        download_name=path.name,
    )


# --------------------------------------------------------------------------- #
# App factory & error handlers
# --------------------------------------------------------------------------- #

def _error_response(status: int, message: str):
    if _wants_json():
        return jsonify(error=message), status
    return render_template_string(ERROR_TEMPLATE, status=status, message=message), status


def create_app(config_object: type = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    if not app.config.get("SECRET_KEY"):
        app.logger.warning("SECRET_KEY is not set.")

    app.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)
    os.chmod(app.config["UPLOAD_DIR"], 0o750)

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    @app.errorhandler(400)
    def _bad(_e):
        return _error_response(400, "Bad request.")

    @app.errorhandler(404)
    def _nf(_e):
        return _error_response(404, "Not found.")

    @app.errorhandler(413)
    def _too_large(_e):
        return _error_response(413, "Uploaded file is too large.")

    @app.errorhandler(500)
    def _ise(_e):
        return _error_response(500, "Internal server error.")

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'",
        )
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    app.register_blueprint(bp)
    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )