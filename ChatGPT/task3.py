
import logging
import os
import sqlite3
import uuid
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    app.config.update(
        MAX_CONTENT_LENGTH=MAX_FILE_SIZE,
        UPLOAD_FOLDER=Path(app.instance_path) / "uploads",
        DATABASE=Path(app.instance_path) / "files.db",
    )

    Path(app.instance_path).mkdir(
        parents=True, exist_ok=True, mode=0o700
    )
    app.config["UPLOAD_FOLDER"].mkdir(
        parents=True, exist_ok=True, mode=0o700
    )

    logging.basicConfig(level=logging.INFO)
    initialize_database(app)

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return jsonify({
            "error": error.description
        }), error.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        app.logger.exception("Unexpected server error")
        return jsonify({
            "error": "An internal server error occurred."
        }), 500

    @app.post("/upload")
    def upload_file():
        if "file" not in request.files:
            return jsonify({
                "error": "No file was provided."
            }), 400

        uploaded_file = request.files["file"]

        if not uploaded_file.filename:
            return jsonify({
                "error": "A filename is required."
            }), 400

        filename = secure_filename(uploaded_file.filename)

        if not filename or "." not in filename:
            return jsonify({
                "error": "Invalid filename."
            }), 400

        extension = filename.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({
                "error": "File type is not allowed."
            }), 415

        file_id = str(uuid.uuid4())
        stored_filename = f"{file_id}.{extension}"
        destination = app.config["UPLOAD_FOLDER"] / stored_filename

        # Exclusive creation prevents accidental overwriting.
        try:
            with destination.open("xb") as output:
                while True:
                    chunk = uploaded_file.stream.read(64 * 1024)
                    if not chunk:
                        break

                    output.write(chunk)

            with connect_database(app) as connection:
                connection.execute(
                    """
                    INSERT INTO files
                        (id, original_name, stored_name)
                    VALUES (?, ?, ?)
                    """,
                    (file_id, filename, stored_filename),
                )
                connection.commit()

        except (OSError, sqlite3.Error):
            destination.unlink(missing_ok=True)
            app.logger.exception("Unable to store uploaded file")
            return jsonify({
                "error": "Unable to store file."
            }), 500

        return jsonify({
            "message": "File uploaded successfully.",
            "file_id": file_id,
            "filename": filename,
            "download_url": f"/download/{file_id}",
        }), 201

    @app.get("/download/<file_id>")
    def download_file(file_id):
        try:
            normalized_id = str(uuid.UUID(file_id))
        except ValueError:
            abort(404, description="File not found.")

        with connect_database(app) as connection:
            record = connection.execute(
                """
                SELECT original_name, stored_name
                FROM files
                WHERE id = ?
                """,
                (normalized_id,),
            ).fetchone()

        if record is None:
            abort(404, description="File not found.")

        original_name, stored_name = record

        # Only server-generated names are used for disk access.
        file_path = app.config["UPLOAD_FOLDER"] / stored_name

        if not file_path.is_file():
            app.logger.error(
                "Stored file missing: %s", normalized_id
            )
            abort(404, description="File not found.")

        response = send_file(
            file_path,
            as_attachment=True,
            download_name=original_name,
            mimetype="application/octet-stream",
            conditional=True,
        )

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"

        return response

    return app


def connect_database(app):
    connection = sqlite3.connect(
        app.config["DATABASE"],
        timeout=10,
    )
    return connection


def initialize_database(app):
    with connect_database(app) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE
            )
            """
        )
        connection.commit()


app = create_app()


if __name__ == "__main__":
    app.run(debug=False)
