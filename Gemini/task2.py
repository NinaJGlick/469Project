from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import uuid

from flask import Flask, current_app, jsonify, request, send_from_directory, url_for
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
from werkzeug.wrappers import Response


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class Config:
    SECRET_KEY: str = os.environ.get("SECRET_KEY", os.urandom(32).hex())
    BASE_DIR: Path = Path(__file__).resolve().parent
    UPLOAD_FOLDER: Path = Path(
        os.environ.get("UPLOAD_FOLDER", BASE_DIR / "uploads")
    ).resolve()
    MAX_CONTENT_LENGTH: int = int(
        os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)  # 16 MB
    )
    ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
        {"txt", "pdf", "png", "jpg", "jpeg", "gif", "csv", "json"}
    )


# ---------------------------------------------------------------------------
# Domain Exceptions & Storage Layer
# ---------------------------------------------------------------------------
class StorageError(Exception):
    """Base exception for storage-related failures."""


class InvalidFileError(StorageError):
    """Raised when an uploaded file fails validation checks."""


class FileNotFoundStorageError(StorageError):
    """Raised when a requested file does not exist or escapes root."""


@dataclass(frozen=True)
class StoredFileMetadata:
    stored_name: str
    original_name: str
    size_bytes: int
    uploaded_at: str


class LocalFileStorage:
    """Manages safe local persistence and retrieval of uploaded files."""

    def __init__(self, root_dir: Path, allowed_extensions: frozenset[str]) -> None:
        self.root_dir = root_dir.resolve()
        self.allowed_extensions = {ext.lower() for ext in allowed_extensions}
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def _validate_extension(self, filename: str) -> str:
        if "." not in filename:
            raise InvalidFileError("File must have an extension.")
        ext = filename.rsplit(".", 1)[1].lower()
        if ext not in self.allowed_extensions:
            allowed = ", ".join(sorted(self.allowed_extensions))
            raise InvalidFileError(
                f"Extension '.{ext}' is not permitted. Allowed types: {allowed}."
            )
        return ext

    def _resolve_safe_path(self, filename: str) -> Path:
        safe_name = secure_filename(filename)
        if not safe_name or safe_name != filename:
            raise FileNotFoundStorageError("Invalid filename format.")

        candidate = (self.root_dir / safe_name).resolve()
        if candidate.parent != self.root_dir:
            raise FileNotFoundStorageError("Access denied.")
        return candidate

    def save(self, file_storage: FileStorage) -> StoredFileMetadata:
        if not file_storage or not file_storage.filename:
            raise InvalidFileError("No file provided in request.")

        clean_name = secure_filename(file_storage.filename)
        if not clean_name:
            raise InvalidFileError("Filename contains no valid ASCII characters.")

        self._validate_extension(clean_name)

        stored_name = f"{uuid.uuid4().hex[:12]}_{clean_name}"
        destination = self.root_dir / stored_name
        file_storage.save(destination)

        return StoredFileMetadata(
            stored_name=stored_name,
            original_name=clean_name,
            size_bytes=destination.stat().st_size,
            uploaded_at=datetime.now(timezone.utc).isoformat(),
        )

    def get_file_path(self, stored_name: str) -> Path:
        target = self._resolve_safe_path(stored_name)
        if not target.is_file():
            raise FileNotFoundStorageError(f"File '{stored_name}' not found.")
        return target

    def list_files(self) -> list[dict[str, str | int]]:
        entries: list[dict[str, str | int]] = []
        for item in sorted(self.root_dir.iterdir()):
            if item.is_file() and not item.name.startswith("."):
                stat = item.stat()
                entries.append(
                    {
                        "stored_name": item.name,
                        "size_bytes": stat.st_size,
                        "modified_at": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    }
                )
        return entries


# ---------------------------------------------------------------------------
# Application Factory, Routes & Error Handlers
# ---------------------------------------------------------------------------
def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    if not app.debug and not app.testing:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )

    storage = LocalFileStorage(
        root_dir=app.config["UPLOAD_FOLDER"],
        allowed_extensions=app.config["ALLOWED_EXTENSIONS"],
    )

    @app.get("/health")
    def health_check() -> tuple[Response, int]:
        return jsonify({"status": "ok"}), 200

    @app.post("/api/v1/files")
    def upload_file() -> tuple[Response, int]:
        if "file" not in request.files:
            raise InvalidFileError("Multipart form field 'file' is missing.")

        metadata = storage.save(request.files["file"])
        download_url = url_for(
            "download_file", filename=metadata.stored_name, _external=True
        )
        current_app.logger.info(
            "Uploaded file '%s' (%d bytes)", metadata.stored_name, metadata.size_bytes
        )

        return (
            jsonify(
                {
                    "message": "File uploaded successfully.",
                    "file": {
                        "stored_name": metadata.stored_name,
                        "original_name": metadata.original_name,
                        "size_bytes": metadata.size_bytes,
                        "uploaded_at": metadata.uploaded_at,
                        "download_url": download_url,
                    },
                }
            ),
            201,
        )

    @app.get("/api/v1/files")
    def list_files() -> tuple[Response, int]:
        files = storage.list_files()
        return jsonify({"count": len(files), "files": files}), 200

    @app.get("/api/v1/files/<string:filename>")
    def download_file(filename: str) -> Response:
        safe_path = storage.get_file_path(filename)
        return send_from_directory(
            directory=safe_path.parent,
            path=safe_path.name,
            as_attachment=True,
        )

    @app.errorhandler(InvalidFileError)
    def handle_invalid_file(err: InvalidFileError) -> tuple[Response, int]:
        return jsonify({"error": "invalid_file", "message": str(err)}), 400

    @app.errorhandler(FileNotFoundStorageError)
    def handle_file_not_found(err: FileNotFoundStorageError) -> tuple[Response, int]:
        return jsonify({"error": "not_found", "message": str(err)}), 404

    @app.errorhandler(413)
    def handle_payload_too_large(_err: HTTPException) -> tuple[Response, int]:
        max_mb = app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)
        return (
            jsonify(
                {
                    "error": "payload_too_large",
                    "message": f"File exceeds maximum allowed size of {max_mb:.1f} MB.",
                }
            ),
            413,
        )

    @app.errorhandler(HTTPException)
    def handle_http_exception(err: HTTPException) -> tuple[Response, int]:
        return (
            jsonify(
                {
                    "error": err.name.lower().replace(" ", "_"),
                    "message": err.description,
                }
            ),
            err.code or 500,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_error(err: Exception) -> tuple[Response, int]:
        app.logger.exception("Unhandled server exception: %s", err)
        return (
            jsonify(
                {
                    "error": "internal_server_error",
                    "message": "An unexpected error occurred.",
                }
            ),
            500,
        )

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)