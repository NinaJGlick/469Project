
import hmac
import io
import logging
import os
import re
import stat
import uuid
import warnings
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from PIL import Image, UnidentifiedImageError
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename


# Configuration
MAX_FILE_SIZE = 8 * 1024 * 1024  # 8 MB
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}
ALLOWED_FORMATS = {
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
}
IMAGE_MAX_PIXELS = 20_000_000

Image.MAX_IMAGE_PIXELS = IMAGE_MAX_PIXELS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app():
    app = Flask(__name__)

    api_token = os.environ.get("FILE_API_TOKEN", "")
    if len(api_token) < 32:
        raise RuntimeError(
            "FILE_API_TOKEN must be configured with "
            "at least 32 characters."
        )

    upload_dir = Path(
        os.environ.get("UPLOAD_DIR", "./uploads")
    ).resolve()

    upload_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    if not upload_dir.is_dir():
        raise RuntimeError("Invalid upload directory configuration.")

    app.config.update(
        MAX_CONTENT_LENGTH=MAX_FILE_SIZE + 1024 * 1024,
        UPLOAD_DIR=upload_dir,
        DEBUG=False,
    )

    def authorized():
        provided = request.headers.get("Authorization", "")
        expected = f"Bearer {api_token}"
        return hmac.compare_digest(provided, expected)

    @app.before_request
    def require_authentication():
        if not authorized():
            return jsonify({"error": "Unauthorized"}), 401

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return jsonify({"error": error.name}), error.code

    @app.errorhandler(Exception)
    def handle_server_error(error):
        logger.exception("Unexpected application error")
        return jsonify({"error": "Internal server error"}), 500

    def validate_image(data, extension):
        """Validate and normalize uploaded image content."""
        try:
            with warnings.catch_warnings():
                warnings.simplefilter(
                    "error", Image.DecompressionBombWarning
                )

                with Image.open(io.BytesIO(data)) as image:
                    if image.format != ALLOWED_FORMATS[extension]:
                        return None

                    image.load()

                    if image.width * image.height > IMAGE_MAX_PIXELS:
                        return None

                    if extension in {".jpg", ".jpeg"}:
                        image = image.convert("RGB")
                        output_format = "JPEG"
                    else:
                        image = image.convert("RGBA")
                        output_format = "PNG"

                    output = io.BytesIO()
                    image.save(output, format=output_format)
                    validated_data = output.getvalue()

                    if len(validated_data) > MAX_FILE_SIZE:
                        return None

                    return validated_data

        except (
            UnidentifiedImageError,
            OSError,
            ValueError,
            Image.DecompressionBombError,
            Image.DecompressionBombWarning,
        ):
            return None

    @app.post("/upload")
    def upload_file():
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        uploaded_file = request.files["file"]

        if not uploaded_file.filename:
            return jsonify({"error": "Filename is required"}), 400

        original_filename = secure_filename(uploaded_file.filename)

        if not original_filename:
            return jsonify({"error": "Invalid filename"}), 400

        extension = Path(original_filename).suffix.lower()

        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({
                "error": "File type not allowed",
                "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
            }), 400

        data = uploaded_file.stream.read(MAX_FILE_SIZE + 1)

        if len(data) > MAX_FILE_SIZE:
            return jsonify({"error": "File exceeds size limit"}), 413

        if not data:
            return jsonify({"error": "Empty files are not allowed"}), 400

        validated_data = validate_image(data, extension)

        if validated_data is None:
            return jsonify({
                "error": "Invalid or unsupported image content"
            }), 400

        file_id = uuid.uuid4().hex
        stored_extension = (
            ".png" if extension == ".png" else ".jpg"
        )

        stored_filename = f"{file_id}{stored_extension}"
        destination = app.config["UPLOAD_DIR"] / stored_filename

        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            descriptor = os.open(destination, flags, 0o600)

            try:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(validated_data)
            except Exception:
                destination.unlink(missing_ok=True)
                raise

        except FileExistsError:
            return jsonify({"error": "File identifier collision"}), 409
        except OSError:
            logger.exception("Unable to store uploaded file")
            return jsonify({"error": "Unable to save file"}), 500

        return jsonify({
            "message": "File uploaded successfully",
            "file_id": file_id,
            "filename": stored_filename,
            "download_url": f"/download/{file_id}",
        }), 201

    @app.get("/download/<file_id>")
    def download_file(file_id):
        # Only server-generated hexadecimal UUID identifiers are accepted.
        if not re.fullmatch(r"[0-9a-f]{32}", file_id):
            return jsonify({"error": "Invalid file identifier"}), 400

        upload_directory = app.config["UPLOAD_DIR"]

        for extension in (".png", ".jpg"):
            filename = f"{file_id}{extension}"
            file_path = upload_directory / filename

            try:
                flags = os.O_RDONLY

                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW

                descriptor = os.open(file_path, flags)

            except FileNotFoundError:
                continue
            except OSError:
                logger.exception("Unable to open requested file")
                return jsonify({"error": "Unable to download file"}), 500

            file_stat = os.fstat(descriptor)

            if not stat.S_ISREG(file_stat.st_mode):
                os.close(descriptor)
                return jsonify({"error": "File not available"}), 404

            file_object = os.fdopen(descriptor, "rb")

            try:
                response = send_file(
                    file_object,
                    as_attachment=True,
                    download_name=filename,
                    mimetype=(
                        "image/png"
                        if extension == ".png"
                        else "image/jpeg"
                    ),
                )
                response.call_on_close(file_object.close)
                response.headers["Cache-Control"] = "no-store"
                response.headers["X-Content-Type-Options"] = "nosniff"
                return response
            except Exception:
                file_object.close()
                raise

        return jsonify({"error": "File not found"}), 404

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=False)
