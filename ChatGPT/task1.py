
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from pathlib import Path
from uuid import uuid4

app = Flask(__name__)

UPLOAD_FOLDER = Path(__file__).resolve().parent / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "csv"}


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    filename = secure_filename(file.filename)

    if not filename:
        return jsonify({"error": "Invalid filename"}), 400

    # Generate a unique filename to prevent overwriting files.
    stored_filename = f"{uuid4().hex}_{filename}"
    file_path = UPLOAD_FOLDER / stored_filename

    file.save(file_path)

    return jsonify({
        "message": "File uploaded successfully",
        "filename": stored_filename,
        "download_url": f"/download/{stored_filename}"
    }), 201


@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    if not (UPLOAD_FOLDER / filename).is_file():
        return jsonify({"error": "File not found"}), 404

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=True
    )


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(error):
    return jsonify({"error": "File exceeds the 16 MB limit"}), 413


if __name__ == "__main__":
    app.run(debug=False)
