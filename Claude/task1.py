"""A small Flask app for uploading files and downloading them again.

Endpoints
---------
GET  /                      Simple HTML page with an upload form and file list
POST /upload                Upload a file (multipart form field named "file")
GET  /files                 JSON list of uploaded files
GET  /download/<file_id>    Download a previously uploaded file

Configuration (environment variables)
-------------------------------------
UPLOAD_DIR          Where files are stored (default: ./uploads)
MAX_UPLOAD_MB       Maximum upload size in megabytes (default: 16)
ALLOWED_EXTENSIONS  Comma-separated list, e.g. "pdf,png,txt".
                    Use "*" to allow every extension.
"""

import os
import re
import uuid
from pathlib import Path

from flask import (
    Flask,
    abort,
    jsonify,
    render_template_string,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_EXTENSIONS = "txt,pdf,png,jpg,jpeg,gif,csv,json,md,zip,docx,xlsx,pptx"

# Stored files are named "<32 hex chars>_<sanitized original name>".
STORED_NAME_RE = re.compile(r"^[0-9a-f]{32}_.+$")


def create_app(config=None):
    app = Flask(__name__)

    app.config["UPLOAD_DIR"] = Path(
        os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads")
    ).resolve()
    app.config["MAX_CONTENT_LENGTH"] = (
        int(os.environ.get("MAX_UPLOAD_MB", "16")) * 1024 * 1024
    )
    raw_exts = os.environ.get("ALLOWED_EXTENSIONS", DEFAULT_EXTENSIONS).strip()
    app.config["ALLOWED_EXTENSIONS"] = (
        None
        if raw_exts == "*"
        else {e.strip().lower().lstrip(".") for e in raw_exts.split(",") if e.strip()}
    )

    if config:
        app.config.update(config)

    app.config["UPLOAD_DIR"] = Path(app.config["UPLOAD_DIR"])
    app.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ helpers

    def extension_allowed(filename: str) -> bool:
        allowed = app.config["ALLOWED_EXTENSIONS"]
        if allowed is None:
            return True
        return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed

    def original_name(stored_name: str) -> str:
        return stored_name.split("_", 1)[1]

    def describe(path: Path) -> dict:
        return {
            "id": path.name,
            "filename": original_name(path.name),
            "size_bytes": path.stat().st_size,
            "download_url": url_for("download_file", file_id=path.name),
        }

    # ------------------------------------------------------------------- routes

    PAGE = """
    <!doctype html>
    <title>File uploads</title>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem; }
      li { margin: .25rem 0; }
      small { color: #666; }
    </style>
    <h1>Upload a file</h1>
    <form method="post" action="{{ url_for('upload_file') }}" enctype="multipart/form-data">
      <input type="file" name="file" required>
      <button type="submit">Upload</button>
    </form>
    <h2>Uploaded files</h2>
    {% if files %}
      <ul>
        {% for f in files %}
          <li><a href="{{ f.download_url }}">{{ f.filename }}</a>
              <small>({{ f.size_bytes }} bytes)</small></li>
        {% endfor %}
      </ul>
    {% else %}
      <p>Nothing uploaded yet.</p>
    {% endif %}
    """

    def list_files():
        paths = [
            p
            for p in app.config["UPLOAD_DIR"].iterdir()
            if p.is_file() and STORED_NAME_RE.match(p.name)
        ]
        paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return [describe(p) for p in paths]

    @app.get("/")
    def index():
        return render_template_string(PAGE, files=list_files())

    @app.post("/upload")
    def upload_file():
        if "file" not in request.files:
            return jsonify(error="No file part in the request (expected field 'file')."), 400

        file = request.files["file"]
        if not file.filename:
            return jsonify(error="No file selected."), 400

        safe_name = secure_filename(file.filename)
        if not safe_name:
            return jsonify(error="Invalid filename."), 400
        if not extension_allowed(safe_name):
            return jsonify(error="File type not allowed."), 400

        # A random prefix keeps names unique, so uploads never overwrite each other.
        stored_name = f"{uuid.uuid4().hex}_{safe_name}"
        destination = app.config["UPLOAD_DIR"] / stored_name
        file.save(destination)

        body = describe(destination)
        response = jsonify(body)
        response.status_code = 201
        response.headers["Location"] = body["download_url"]
        return response

    @app.get("/files")
    def files():
        return jsonify(files=list_files())

    @app.get("/download/<file_id>")
    def download_file(file_id):
        if not STORED_NAME_RE.match(file_id):
            abort(404)
        # send_from_directory also guards against path traversal.
        # as_attachment forces a download, so uploaded HTML/SVG is never rendered inline.
        return send_from_directory(
            app.config["UPLOAD_DIR"],
            file_id,
            as_attachment=True,
            download_name=original_name(file_id),
        )

    # ------------------------------------------------------------ error handlers

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_err):
        limit_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return jsonify(error=f"File too large (limit is {limit_mb} MB)."), 413

    @app.errorhandler(404)
    def not_found(_err):
        return jsonify(error="Not found."), 404

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
