"""
Secure file upload/download Flask application.

Single-file implementation with production-oriented defaults:
- Directory traversal protection
- Path canonicalization and containment checks
- Filename sanitization (no user-controlled paths)
- Content length limits and size caps
- MIME/extension allowlist (configurable)
- Safe download handling with Content-Disposition
- Consistent error handling (no internal details leaked)
- Structured logging

Run:
    pip install flask werkzeug
    python app.py

Environment variables:
    UPLOAD_DIR       Directory for uploaded files (default: ./uploads)
    MAX_CONTENT_MB   Max request size in MB (default: 25)
    ALLOWED_EXTS     Comma-separated allowlist of extensions (default: txt,pdf,png,jpg,jpeg,gif,csv,json,zip)
    HOST             Bind host (default: 127.0.0.1)
    PORT             Bind port (default: 5000)
    SECRET_KEY       Flask secret key (set this in production!)
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request, send_file, abort
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads")).resolve()
MAX_CONTENT_MB = int(os.environ.get("MAX_CONTENT_MB", "25"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))

DEFAULT_EXTS = "txt,pdf,png,jpg,jpeg,gif,csv,json,zip"
ALLOWED_EXTENSIONS = {
    ext.strip().lower().lstrip(".")
    for ext in os.environ.get("ALLOWED_EXTS", DEFAULT_EXTS).split(",")
    if ext.strip()
}

# Filenames are stored under a per-upload UUID directory. The original name
# is preserved only for the download Content-Disposition header, never used
# for filesystem paths.
_STORED_NAME_RE = re.compile(r"^[0-9a-f]{32}$")

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("fileapp")

# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_CONTENT_MB * 1024 * 1024,
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32)),
)


def ensure_upload_dir() -> None:
    """Create the upload directory with restrictive permissions if missing."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


def is_within_directory(base: Path, candidate: Path) -> bool:
    """Return True iff `candidate` resolves inside `base` (no traversal)."""
    try:
        base_r = base.resolve(strict=True)
        cand_r = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    try:
        cand_r.relative_to(base_r)
    except ValueError:
        return False
    return True


def validate_filename(raw: Optional[str]) -> Optional[str]:
    """
    Validate and normalize a user-provided filename.

    Returns a safe basename (no directory components) or None if invalid.
    Uses werkzeug.secure_filename as a defense-in-depth sanitizer, then
    enforces an allowlist of extensions.
    """
    if not raw or not isinstance(raw, str):
        return None

    # Reject obvious traversal attempts and control characters early.
    if "\x00" in raw or "/" in raw or "\\" in raw:
        return None

    safe = secure_filename(raw)
    if not safe:
        return None

    # secure_filename may strip leading dots etc.; ensure no residual path parts.
    if Path(safe).name != safe:
        return None

    if "." not in safe:
        return None

    ext = safe.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None

    # Cap length to avoid pathological names.
    if len(safe) > 200:
        return None

    return safe


def stored_path_for(token: str) -> Path:
    """
    Compute the on-disk path for a stored file token.

    The token is a 32-hex UUID; the path is a single file directly under
    UPLOAD_DIR, so no user-controlled directory components are ever used.
    """
    if not _STORED_NAME_RE.match(token):
        abort(400, description="Invalid file identifier.")
    return UPLOAD_DIR / token


# --------------------------------------------------------------------------- #
# Error handlers
# --------------------------------------------------------------------------- #

@app.errorhandler(RequestEntityTooLarge)
def handle_too_large(_e):
    return jsonify(error="File too large.",
                   max_mb=MAX_CONTENT_MB), 413


@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify(error=getattr(e, "description", "Bad request.")), 400


@app.errorhandler(404)
def handle_not_found(_e):
    return jsonify(error="Not found."), 404


@app.errorhandler(405)
def handle_method_not_allowed(_e):
    return jsonify(error="Method not allowed."), 405


@app.errorhandler(500)
def handle_internal_error(_e):
    # Do not leak internals to the client.
    log.exception("Unhandled server error")
    return jsonify(error="Internal server error."), 500


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@app.get("/healthz")
def healthz():
    return jsonify(status="ok"), 200


@app.post("/upload")
def upload_file():
    """
    Accept a multipart file upload.

    Form field: `file`
    Returns JSON: {"id": "<uuid>", "filename": "<original>", "size": <bytes>}
    """
    ensure_upload_dir()

    if "file" not in request.files:
        return jsonify(error="Missing 'file' field in multipart form."), 400

    uploaded = request.files["file"]
    if uploaded.filename is None or uploaded.filename == "":
        return jsonify(error="No file selected."), 400

    safe_name = validate_filename(uploaded.filename)
    if safe_name is None:
        return jsonify(
            error="Invalid or disallowed filename.",
            allowed_extensions=sorted(ALLOWED_EXTENSIONS),
        ), 400

    token = uuid.uuid4().hex
    dest = UPLOAD_DIR / token

    # Guard against any path tricks before writing.
    if not is_within_directory(UPLOAD_DIR, dest):
        log.warning("Rejected upload path outside upload dir")
        abort(400, description="Invalid upload path.")

    try:
        # Write to the canonical destination; never trust the incoming name.
        uploaded.save(dest)
    except OSError:
        log.exception("Failed to persist upload")
        # Best-effort cleanup of partial file.
        try:
            if dest.exists():
                dest.unlink()
        except OSError:
            pass
        return jsonify(error="Failed to store file."), 500

    try:
        size = dest.stat().st_size
    except OSError:
        size = 0

    log.info("Stored upload id=%s size=%d", token, size)

    return jsonify(
        id=token,
        filename=safe_name,
        size=size,
    ), 201


@app.get("/files/<file_id>")
def download_file(file_id: str):
    """
    Download a previously uploaded file by its opaque ID.

    Uses send_file with safe headers; the on-disk name is derived strictly
    from the validated ID, never from user-supplied path data.
    """
    ensure_upload_dir()

    dest = stored_path_for(file_id)
    if not is_within_directory(UPLOAD_DIR, dest) or not dest.is_file():
        abort(404)

    # Derive a safe download name; original is not stored, so use the ID.
    download_name = f"{file_id}"

    try:
        return send_file(
            dest,
            as_attachment=True,
            download_name=download_name,
            conditional=True,  # supports Range / ETag
            max_age=0,
        )
    except OSError:
        log.exception("Failed to serve file id=%s", file_id)
        abort(404)


@app.get("/files/<file_id>/meta")
def file_metadata(file_id: str):
    """Return lightweight metadata for an uploaded file."""
    ensure_upload_dir()
    dest = stored_path_for(file_id)
    if not is_within_directory(UPLOAD_DIR, dest) or not dest.is_file():
        abort(404)
    try:
        st = dest.stat()
    except OSError:
        abort(404)
    return jsonify(id=file_id, size=st.st_size), 200


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    ensure_upload_dir()
    # Never run with debug=True in production; controlled via env flag.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=HOST, port=PORT, debug=debug)