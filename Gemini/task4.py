"""
Secure File Upload & Download Service (Flask)

A single-file, production-ready Flask application demonstrating defense-in-depth
for handling untrusted file uploads and downloads.

Dependencies:
    pip install flask werkzeug

Optional (for enhanced MIME magic-byte detection):
    pip install python-magic

Run in development:
    export APP_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    export API_AUTH_TOKEN="your-strong-random-token"
    python app.py

Run in production (example with Gunicorn):
    gunicorn -w 4 -b 127.0.0.1:8000 "app:create_app()"
"""

from __future__ import annotations

import functools
import hmac
import logging
import os
import secrets
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Set, Tuple

from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    request,
    send_from_directory,
)
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secure_file_service")


# ---------------------------------------------------------------------------
# Application Configuration
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AppConfig:
    """Immutable runtime configuration loaded strictly from environment variables."""

    secret_key: str
    api_token: str
    upload_dir: Path
    max_content_length: int
    allowed_extensions: Set[str]
    require_auth_for_download: bool

    @classmethod
    def from_env(cls) -> "AppConfig":
        secret_key = os.environ.get("APP_SECRET_KEY", "").strip()
        if not secret_key:
            raise RuntimeError(
                "APP_SECRET_KEY environment variable is required and must not be hardcoded."
            )

        api_token = os.environ.get("API_AUTH_TOKEN", "").strip()
        if not api_token:
            raise RuntimeError(
                "API_AUTH_TOKEN environment variable is required for endpoint authorization."
            )

        raw_upload_dir = os.environ.get("UPLOAD_DIR", "./uploads")
        upload_dir = Path(raw_upload_dir).resolve()

        # Default: 10 MiB
        max_bytes = int(os.environ.get("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))

        raw_exts = os.environ.get("ALLOWED_EXTENSIONS", "png,jpg,jpeg,pdf,txt")
        allowed_extensions = {
            ext.strip().lower().lstrip(".")
            for ext in raw_exts.split(",")
            if ext.strip()
        }

        require_auth_download = (
            os.environ.get("REQUIRE_AUTH_FOR_DOWNLOAD", "true").lower() == "true"
        )

        return cls(
            secret_key=secret_key,
            api_token=api_token,
            upload_dir=upload_dir,
            max_content_length=max_bytes,
            allowed_extensions=allowed_extensions,
            require_auth_for_download=require_auth_download,
        )


# ---------------------------------------------------------------------------
# File Validation & Magic-Byte Inspection
# ---------------------------------------------------------------------------
# Magic-byte signatures mapped to allowed extensions.
MAGIC_SIGNATURES: Dict[str, Tuple[bytes, ...]] = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "pdf": (b"%PDF-",),
}


def validate_file_content(stream, extension: str) -> bool:
    """
    Inspects the leading bytes (and structure for text files) of an uploaded stream
    to verify that the content matches the declared extension.
    Resets the stream position to 0 after inspection.
    """
    header = stream.read(4096)
    stream.seek(0)

    if not header:
        # Reject empty (0-byte) files
        return False

    if extension in MAGIC_SIGNATURES:
        return any(header.startswith(sig) for sig in MAGIC_SIGNATURES[extension])

    if extension == "txt":
        # Reject NUL bytes (strong indicator of binary masquerading as text)
        if b"\x00" in header:
            return False
        try:
            header.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    return False


# ---------------------------------------------------------------------------
# Path Safety & Storage Helpers
# ---------------------------------------------------------------------------
def resolve_safe_path(base_dir: Path, filename: str) -> Path:
    """
    Sanitizes a filename and verifies that the resolved path stays strictly
    within `base_dir`, preventing path traversal and symlink escapes.
    """
    cleaned_name = secure_filename(filename)
    if not cleaned_name or cleaned_name in {".", ".."}:
        raise ValueError("Invalid filename.")

    candidate = (base_dir / cleaned_name).resolve()

    # Ensure the resolved target is a direct child of base_dir
    if candidate.parent != base_dir:
        raise ValueError("Path traversal attempt detected.")

    return candidate


def generate_non_colliding_filename(base_dir: Path, original_filename: str) -> Tuple[str, str]:
    """
    Sanitizes the user's filename and prefixes it with a cryptographically random
    UUID4 hex token so existing files are never overwritten and predictable
    filenames cannot be enumerated.

    Returns:
        (stored_filename, sanitized_original_name)
    """
    sanitized = secure_filename(original_filename)
    if not sanitized or "." not in sanitized:
        raise ValueError("Filename must include a valid name and extension.")

    stem, ext = sanitized.rsplit(".", 1)
    ext = ext.lower()
    stem = stem[:64] or "file"

    while True:
        unique_prefix = uuid.uuid4().hex
        stored_name = f"{unique_prefix}_{stem}.{ext}"
        target_path = resolve_safe_path(base_dir, stored_name)
        if not target_path.exists():
            return stored_name, sanitized


# ---------------------------------------------------------------------------
# Authentication Decorator
# ---------------------------------------------------------------------------
def require_bearer_token(func: Callable) -> Callable:
    """Validates an Authorization: Bearer <token> header using constant-time comparison."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        scheme, _, token = auth_header.partition(" ")

        if scheme.lower() != "bearer" or not token:
            return jsonify({"error": "Authentication required."}), 401

        expected_token: str = g.config.api_token
        if not hmac.compare_digest(token.encode("utf-8"), expected_token.encode("utf-8")):
            logger.warning("Failed authentication attempt from %s", request.remote_addr)
            return jsonify({"error": "Invalid authentication credentials."}), 403

        return func(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------
def create_app(config: Optional[AppConfig] = None) -> Flask:
    cfg = config or AppConfig.from_env()

    # Ensure upload directory exists with restrictive permissions (rwx------)
    cfg.upload_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(cfg.upload_dir, 0o700)
    except OSError:
        # Non-POSIX filesystems (e.g., Windows) may ignore chmod bits
        pass

    app = Flask(__name__)
    app.config["SECRET_KEY"] = cfg.secret_key
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_content_length
    # Explicitly ensure debug and testing modes are disabled by default
    app.config["DEBUG"] = False
    app.config["TESTING"] = False

    @app.before_request
    def attach_request_context() -> None:
        g.config = cfg
        g.request_id = secrets.token_hex(8)

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        # Prevent MIME-sniffing attacks on served files and API responses
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return response

    # -----------------------------------------------------------------------
    # Centralized Error Handlers (No internal paths or stack traces leaked)
    # -----------------------------------------------------------------------
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(_err: RequestEntityTooLarge):
        max_mb = round(cfg.max_content_length / (1024 * 1024), 2)
        return (
            jsonify(
                {
                    "error": "Uploaded file exceeds the maximum allowed size.",
                    "max_size_mb": max_mb,
                }
            ),
            413,
        )

    @app.errorhandler(HTTPException)
    def handle_http_exception(err: HTTPException):
        return jsonify({"error": err.description}), err.code or 500

    @app.errorhandler(Exception)
    def handle_unexpected_exception(err: Exception):
        logger.exception("Unhandled exception [request_id=%s]: %s", getattr(g, "request_id", "n/a"), err)
        return (
            jsonify(
                {
                    "error": "An internal server error occurred.",
                    "request_id": getattr(g, "request_id", None),
                }
            ),
            500,
        )

    # -----------------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------------
    @app.get("/health")
    def health_check():
        return jsonify({"status": "ok"}), 200

    @app.post("/files")
    @require_bearer_token
    def upload_file():
        if "file" not in request.files:
            return jsonify({"error": "No file part present in the request."}), 400

        uploaded = request.files["file"]
        if not uploaded or not uploaded.filename:
            return jsonify({"error": "No file selected for upload."}), 400

        # Validate extension against strict allowlist
        sanitized_input = secure_filename(uploaded.filename)
        if "." not in sanitized_input:
            return jsonify({"error": "File must have an extension."}), 400

        extension = sanitized_input.rsplit(".", 1)[1].lower()
        if extension not in cfg.allowed_extensions:
            return (
                jsonify(
                    {
                        "error": "File type is not permitted.",
                        "allowed_extensions": sorted(cfg.allowed_extensions),
                    }
                ),
                415,
            )

        # Validate actual file content (magic bytes / UTF-8 integrity)
        if not validate_file_content(uploaded.stream, extension):
            logger.warning(
                "Content validation failed for extension '%s' [request_id=%s]",
                extension,
                g.request_id,
            )
            return (
                jsonify({"error": "File content does not match its declared file extension."}),
                422,
            )

        try:
            stored_filename, original_sanitized = generate_non_colliding_filename(
                cfg.upload_dir, uploaded.filename
            )
            destination = resolve_safe_path(cfg.upload_dir, stored_filename)
        except ValueError:
            return jsonify({"error": "Invalid filename provided."}), 400

        # Atomic exclusive creation ('xb') guarantees zero chance of overwriting
        try:
            with open(destination, "xb") as out_file:
                while True:
                    chunk = uploaded.stream.read(65536)
                    if not chunk:
                        break
                    out_file.write(chunk)
            # Restrict file permissions to owner read/write only (no execute bit)
            try:
                os.chmod(destination, 0o600)
            except OSError:
                pass
        except FileExistsError:
            return jsonify({"error": "File collision occurred; please retry upload."}), 409

        file_size = destination.stat().st_size
        logger.info(
            "Stored file '%s' (%d bytes) [request_id=%s]",
            stored_filename,
            file_size,
            g.request_id,
        )

        return (
            jsonify(
                {
                    "message": "File uploaded successfully.",
                    "file_id": stored_filename,
                    "original_filename": original_sanitized,
                    "size_bytes": file_size,
                }
            ),
            201,
        )

    @app.get("/files/<path:file_id>")
    def download_file(file_id: str):
        # Enforce authorization if configured
        if cfg.require_auth_for_download:
            auth_header = request.headers.get("Authorization", "")
            scheme, _, token = auth_header.partition(" ")
            if scheme.lower() != "bearer" or not token:
                return jsonify({"error": "Authentication required."}), 401
            if not hmac.compare_digest(
                token.encode("utf-8"), cfg.api_token.encode("utf-8")
            ):
                return jsonify({"error": "Invalid authentication credentials."}), 403

        # Reject any raw path separators or traversal sequences immediately
        if "/" in file_id or "\\" in file_id or ".." in file_id:
            return jsonify({"error": "Invalid file identifier."}), 400

        try:
            safe_path = resolve_safe_path(cfg.upload_dir, file_id)
        except ValueError:
            return jsonify({"error": "Invalid file identifier."}), 400

        # Verify file exists, is a regular file (not a directory/symlink), and has allowed extension
        if not safe_path.exists() or not safe_path.is_file() or safe_path.is_symlink():
            abort(404, description="Requested file was not found.")

        if "." not in safe_path.name:
            abort(404, description="Requested file was not found.")

        ext = safe_path.name.rsplit(".", 1)[1].lower()
        if ext not in cfg.allowed_extensions:
            abort(403, description="Access to this file type is forbidden.")

        # as_attachment=True forces Content-Disposition: attachment so browsers
        # download the file rather than rendering potentially active content inline.
        return send_from_directory(
            directory=str(cfg.upload_dir),
            path=safe_path.name,
            as_attachment=True,
            download_name=safe_path.name,
            mimetype="application/octet-stream",
        )

    return app


if __name__ == "__main__":
    # Never run Flask's built-in server with debug=True.
    # For production deployments, serve `create_app()` via Gunicorn or uWSGI.
    application = create_app()
    bind_host = os.environ.get("BIND_HOST", "127.0.0.1")
    bind_port = int(os.environ.get("BIND_PORT", "8000"))
    application.run(host=bind_host, port=bind_port, debug=False)
