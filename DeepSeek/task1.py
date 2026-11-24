import os
import uuid
from pathlib import Path
from flask import (
    Flask,
    request,
    jsonify,
    send_from_directory,
    render_template_string,
    abort,
)
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "csv", "docx", "xlsx", "zip"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def allowed_file(filename: str) -> bool:
    """Return True if the file has an allowed extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def unique_filename(original_name: str) -> str:
    """
    Build a safe, collision-free filename while preserving the extension.
    Example: report.pdf -> 3f8c1e2a-...._report.pdf
    """
    safe = secure_filename(original_name)
    stem, ext = os.path.splitext(safe)
    return f"{uuid.uuid4().hex}_{stem}{ext}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Simple HTML form + list of stored files for manual testing."""
    files = sorted(p.name for p in UPLOAD_DIR.iterdir() if p.is_file())
    rows = "".join(
        f'<li><a href="/files/{name}">{name}</a></li>' for name in files
    )
    return render_template_string(
        """
        <!doctype html>
        <html>
        <head><title>File Upload Demo</title></head>
        <body>
          <h1>Upload a file</h1>
          <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
          </form>
          <h2>Uploaded files</h2>
          <ul>{{ rows|safe }}</ul>
        </body>
        </html>
        """,
        rows=rows or "<li><em>No files yet.</em></li>",
    )


@app.route("/upload", methods=["POST"])
def upload_file():
    """
    Accepts a multipart/form-data POST with a 'file' field.
    Returns JSON: {"filename": "<stored_name>", "original": "<original_name>"}
    """
    if "file" not in request.files:
        return jsonify(error="No file part in request"), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify(error="No file selected"), 400

    if not allowed_file(file.filename):
        return jsonify(
            error=f"Extension not allowed. Allowed: {sorted(ALLOWED_EXTENSIONS)}"
        ), 400

    stored_name = unique_filename(file.filename)
    save_path = UPLOAD_DIR / stored_name
    file.save(save_path)

    return jsonify(
        message="File uploaded successfully",
        stored_filename=stored_name,
        original_filename=file.filename,
        size_bytes=save_path.stat().st_size,
    ), 201


@app.route("/files", methods=["GET"])
def list_files():
    """Return a JSON list of stored files (name + size)."""
    files = [
        {"name": p.name, "size_bytes": p.stat().st_size}
        for p in sorted(UPLOAD_DIR.iterdir())
        if p.is_file()
    ]
    return jsonify(count=len(files), files=files)


@app.route("/files/<path:filename>", methods=["GET"])
def download_file(filename: str):
    """
    Download a previously uploaded file by its stored name.
    `secure_filename` prevents path traversal attacks.
    """
    safe_name = secure_filename(filename)
    target = UPLOAD_DIR / safe_name
    if not target.is_file():
        abort(404, description="File not found")
    return send_from_directory(
        UPLOAD_DIR,
        safe_name,
        as_attachment=True,
        download_name=safe_name,
    )


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(413)
def too_large(_e):
    return jsonify(error="File too large", max_mb=MAX_CONTENT_LENGTH // (1024 * 1024)), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify(error=str(e)), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)