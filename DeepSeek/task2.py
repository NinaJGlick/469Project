"""
Single-file Flask file upload/download service.

Features
--------
- POST /files            Upload one or more files (multipart, field name "file")
- GET  /files            List stored filenames
- GET  /files/<name>     Download a stored file (as attachment)
- GET  /healthz          Liveness probe

Security / correctness
----------------------
- Filename sanitization via werkzeug.secure_filename + strict regex
- Extension whitelist (configurable)
- Path-containment check when resolving downloads (defeats traversal)
- MAX_CONTENT_LENGTH enforced by Werkzeug (413)
- Empty uploads rejected
- Collisions get a UUID suffix; files are never overwritten
- Optional X-API-Key auth (constant-time compare) when UPLOAD_API_KEY is set
- All errors returned as JSON {"error": "..."} with correct status codes
- Internal exceptions logged, never leaked to clients

Run
---
    pip install flask python-dotenv werkzeug pytest
    python app.py                     # dev server on :5000
    # production:
    gunicorn -w 4 -b 0.0.0.0:8000 app:app

Environment
-----------
    SECRET_KEY            Flask secret (random if unset)
    UPLOAD_FOLDER         Directory for uploads (default: ./uploads)
    MAX_UPLOAD_BYTES      Max request size (default: 16 MiB)
    ALLOWED_EXTENSIONS    Comma-separated, no dots (default: see below)
    UPLOAD_API_KEY        If set, uploads require header X-API-Key
    LOG_LEVEL             default INFO
"""
from __future__ import annotations

import hmac
import io
import logging
import os
import re
import shutil
import sys
import uuid
from dataclasses import dataclass
from functools import wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import (
    Flask,
    Blueprint,
    current_app,
    jsonify,
    request,
    send_from_directory,
)
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("file_service")


def _configure_logging(level_name: str = "INFO") -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
        root.addHandler(handler)
    root.setLevel(level)
    logger.setLevel(level)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ValidationError(Exception):
    """User-facing validation failure (4xx)."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class StorageError(Exception):
    """Internal storage failure (5xx). Details are logged, not returned."""


def register_error_handlers(app: Flask) -> None:
    def _json_error(message: str, status: int):
        return jsonify({"error": message}), status

    @app.errorhandler(ValidationError)
    def _handle_validation(exc: ValidationError):
        return _json_error(exc.message, exc.status_code)

    @app.errorhandler(StorageError)
    def _handle_storage(exc: StorageError):
        logger.exception("Storage error: %s", exc)
        return _json_error("A storage error occurred.", 500)

    @app.errorhandler(RequestEntityTooLarge)
    def _handle_too_large(_exc: RequestEntityTooLarge):
        max_mb = current_app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)
        return _json_error(
            f"File is too large. Maximum upload size is {max_mb:.1f} MiB.", 413
        )

    @app.errorhandler(HTTPException)
    def _handle_http(exc: HTTPException):
        return _json_error(exc.description or exc.name, exc.code or 500)

    @app.errorhandler(Exception)
    def _handle_unexpected(exc: Exception):
        logger.exception("Unhandled exception")
        return _json_error("An unexpected error occurred.", 500)


# ---------------------------------------------------------------------------
# Storage backend
# ---------------------------------------------------------------------------

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


@dataclass(frozen=True)
class StoredFile:
    stored_name: str
    original_name: str
    size: int


def _sanitize_filename(raw: str) -> str:
    if not raw or not raw.strip():
        raise ValidationError("A filename is required.")
    safe = secure_filename(raw)
    if not safe:
        raise ValidationError("The provided filename is not valid.")
    if safe.startswith("."):
        raise ValidationError("Hidden filenames are not allowed.")
    if not _SAFE_NAME_RE.match(safe):
        raise ValidationError("Filename contains disallowed characters.")
    return safe


def _check_extension(filename: str, allowed: frozenset[str]) -> str:
    if "." not in filename:
        raise ValidationError("File must have an extension.")
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in allowed:
        raise ValidationError(
            f"Extension '.{ext}' is not allowed. Allowed: {sorted(allowed)}",
            415,
        )
    return ext


def _unique_target(folder: Path, name: str) -> Path:
    target = folder / name
    if not target.exists():
        return target
    return folder / f"{target.stem}-{uuid.uuid4().hex}{target.suffix}"


class FileStorageBackend:
    """Filesystem store rooted at a single directory."""

    def __init__(self, root: Path, allowed_extensions: frozenset[str]) -> None:
        self._root = Path(root).resolve()
        self._allowed = allowed_extensions
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def _safe_join(self, name: str) -> Path:
        candidate = (self._root / name).resolve()
        if not candidate.is_relative_to(self._root) or candidate == self._root:
            raise ValidationError("Invalid file identifier.", 400)
        if candidate.is_dir():
            raise ValidationError("Invalid file identifier.", 400)
        return candidate

    def save(self, file: FileStorage) -> StoredFile:
        if not file or not file.filename:
            raise ValidationError("No file was provided.")
        safe_name = _sanitize_filename(file.filename)
        _check_extension(safe_name, self._allowed)

        try:
            target = _unique_target(self._root, safe_name)
            file.save(target)
        except OSError as exc:
            raise StorageError(f"Failed to persist upload: {exc}") from exc

        try:
            size = target.stat().st_size
        except OSError as exc:
            target.unlink(missing_ok=True)
            raise StorageError(f"Uploaded file is unreadable: {exc}") from exc

        if size == 0:
            target.unlink(missing_ok=True)
            raise ValidationError("Uploaded file is empty.")

        logger.info("Stored %s (%d bytes)", target.name, size)
        return StoredFile(target.name, file.filename, size)

    def path_for(self, stored_name: str) -> Path:
        name = _sanitize_filename(stored_name)
        if name != stored_name:
            raise ValidationError("Invalid file identifier.")
        path = self._safe_join(name)
        if not path.is_file():
            raise ValidationError("File not found.", 404)
        return path

    def list_files(self) -> list[str]:
        try:
            return sorted(p.name for p in self._root.iterdir() if p.is_file())
        except OSError as exc:
            raise StorageError(f"Failed to list files: {exc}") from exc


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

bp = Blueprint("files", __name__)


def _backend() -> FileStorageBackend:
    cfg = current_app.config
    return FileStorageBackend(cfg["UPLOAD_FOLDER"], cfg["ALLOWED_EXTENSIONS"])


def require_api_key(view):
    """Enforce X-API-Key only when UPLOAD_API_KEY is configured."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        expected = current_app.config.get("UPLOAD_API_KEY")
        if not expected:
            return view(*args, **kwargs)
        provided = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(provided, expected):
            raise ValidationError("Missing or invalid API key.", 401)
        return view(*args, **kwargs)

    return wrapper


@bp.get("/healthz")
def health():
    return jsonify({"status": "ok"})


@bp.post("/files")
@require_api_key
def upload_file():
    if "file" not in request.files:
        raise ValidationError("Missing 'file' field in multipart form data.")
    uploads = request.files.getlist("file")
    if not uploads:
        raise ValidationError("No files provided.")

    backend = _backend()
    stored: list[StoredFile] = []
    for item in uploads:
        if isinstance(item, FileStorage) and item.filename == "":
            continue  # browser sent an empty field
        stored.append(backend.save(item))

    if not stored:
        raise ValidationError("No non-empty files were provided.")

    return (
        jsonify(
            {
                "files": [
                    {
                        "stored_name": s.stored_name,
                        "original_name": s.original_name,
                        "size": s.size,
                        "download_url": f"/files/{s.stored_name}",
                    }
                    for s in stored
                ]
            }
        ),
        201,
    )


@bp.get("/files")
def list_files():
    return jsonify({"files": _backend().list_files()})


@bp.get("/files/<path:filename>")
def download_file(filename: str):
    backend = _backend()
    path = backend.path_for(filename)
    return send_from_directory(
        backend.root,
        path.name,
        as_attachment=True,
        download_name=path.name,
        max_age=0,
    )


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _allowed_exts_from_env() -> frozenset[str]:
    raw = os.environ.get(
        "ALLOWED_EXTENSIONS", "txt,pdf,png,jpg,jpeg,gif,csv,json,zip"
    )
    return frozenset(e.strip().lower() for e in raw.split(",") if e.strip())


def create_app(config_object: dict | object | None = None) -> Flask:
    app = Flask(__name__)

    # Defaults (env-driven)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or os.urandom(32),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_BYTES", 16 * 1024 * 1024)),
        UPLOAD_FOLDER=Path(
            os.environ.get(
                "UPLOAD_FOLDER",
                Path(__file__).resolve().parent / "uploads",
            )
        ).resolve(),
        ALLOWED_EXTENSIONS=_allowed_exts_from_env(),
        UPLOAD_API_KEY=os.environ.get("UPLOAD_API_KEY") or None,
        LOG_LEVEL=os.environ.get("LOG_LEVEL", "INFO"),
        JSON_SORT_KEYS=False,
    )

    if config_object is not None:
        if isinstance(config_object, dict):
            app.config.update(config_object)
        else:
            app.config.from_object(config_object)

    # Normalize types regardless of how config was supplied.
    app.config["UPLOAD_FOLDER"] = Path(app.config["UPLOAD_FOLDER"]).resolve()
    app.config["ALLOWED_EXTENSIONS"] = frozenset(app.config["ALLOWED_EXTENSIONS"])

    _configure_logging(app.config["LOG_LEVEL"])
    app.config["UPLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)

    app.register_blueprint(bp)
    register_error_handlers(app)
    return app


# ---------------------------------------------------------------------------
# Tests (run with: python app.py --test)
# ---------------------------------------------------------------------------


def _run_tests() -> int:
    try:
        import pytest
    except ImportError:
        print("pytest not installed; run: pip install pytest", file=sys.stderr)
        return 2

    test_src = r'''
import io
import shutil
import pytest
from app import create_app

TEST_UPLOAD_DIR = "/tmp/flask_file_service_test_uploads"

class _TestConfig:
    TESTING = True
    UPLOAD_FOLDER = TEST_UPLOAD_DIR
    MAX_CONTENT_LENGTH = 1024 * 1024
    ALLOWED_EXTENSIONS = frozenset({"txt", "pdf"})
    UPLOAD_API_KEY = None
    SECRET_KEY = "test"

@pytest.fixture()
def client():
    shutil.rmtree(TEST_UPLOAD_DIR, ignore_errors=True)
    app = create_app(_TestConfig)
    with app.test_client() as c:
        yield c
    shutil.rmtree(TEST_UPLOAD_DIR, ignore_errors=True)

def _upload(client, name, data, field="file"):
    return client.post(
        "/files",
        data={field: (io.BytesIO(data), name)},
        content_type="multipart/form-data",
    )

def test_health(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.get_json()["status"] == "ok"

def test_upload_and_download_roundtrip(client):
    payload = b"hello world"
    r = _upload(client, "note.txt", payload)
    assert r.status_code == 201, r.get_json()
    body = r.get_json()["files"][0]
    assert body["original_name"] == "note.txt"
    assert body["size"] == len(payload)
    r2 = client.get(f"/files/{body['stored_name']}")
    assert r2.status_code == 200 and r2.data == payload

def test_rejects_disallowed_extension(client):
    r = _upload(client, "evil.exe", b"x")
    assert r.status_code == 415

def test_rejects_empty_file(client):
    r = _upload(client, "empty.txt", b"")
    assert r.status_code == 400

def test_rejects_missing_field(client):
    r = client.post("/files", data={}, content_type="multipart/form-data")
    assert r.status_code == 400

def test_rejects_path_traversal_download(client):
    r = client.get("/files/..%2F..%2Fetc%2Fpasswd")
    assert r.status_code in (400, 404)

def test_rejects_oversize(client):
    r = _upload(client, "big.txt", b"a" * (1024 * 1024 + 10))
    assert r.status_code == 413

def test_collision_gets_unique_name(client):
    r1 = _upload(client, "dup.txt", b"one")
    r2 = _upload(client, "dup.txt", b"two")
    assert r1.status_code == 201 and r2.status_code == 201
    n1 = r1.get_json()["files"][0]["stored_name"]
    n2 = r2.get_json()["files"][0]["stored_name"]
    assert n1 != n2

def test_list_files(client):
    _upload(client, "a.txt", b"a")
    _upload(client, "b.txt", b"b")
    r = client.get("/files")
    assert r.status_code == 200
    names = r.get_json()["files"]
    assert "a.txt" in names and "b.txt" in names

def test_api_key_enforced_when_configured():
    shutil.rmtree(TEST_UPLOAD_DIR, ignore_errors=True)
    app = create_app({
        "TESTING": True,
        "UPLOAD_FOLDER": TEST_UPLOAD_DIR,
        "MAX_CONTENT_LENGTH": 1024 * 1024,
        "ALLOWED_EXTENSIONS": frozenset({"txt"}),
        "UPLOAD_API_KEY": "s3cret",
        "SECRET_KEY": "test",
    })
    with app.test_client() as c:
        r = c.post("/files", data={"file": (io.BytesIO(b"x"), "a.txt")},
                   content_type="multipart/form-data")
        assert r.status_code == 401
        r = c.post("/files",
                   headers={"X-API-Key": "s3cret"},
                   data={"file": (io.BytesIO(b"x"), "a.txt")},
                   content_type="multipart/form-data")
        assert r.status_code == 201
    shutil.rmtree(TEST_UPLOAD_DIR, ignore_errors=True)
'''
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        test_file = Path(td) / "test_app_inline.py"
        test_file.write_text(test_src)
        # Make `import app` resolve to this file.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        return pytest.main([str(test_file), "-q"])


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

app = create_app()


if __name__ == "__main__":
    if "--test" in sys.argv:
        raise SystemExit(_run_tests())
    debug = _env_bool("FLASK_DEBUG", False)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug)