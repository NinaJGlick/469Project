import os
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    send_from_directory,
    render_template_string,
    flash,
)
from werkzeug.utils import secure_filename

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "csv", "zip"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = "super-secret-key-change-in-production"

# Ensure the upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flask File Upload & Download</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
        .flash { padding: 10px; background: #e0f2fe; border-left: 4px solid #0284c7; margin-bottom: 20px; }
        form { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 6px; }
        ul { list-style: none; padding: 0; }
        li { padding: 8px 0; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }
    </style>
</head>
<body>
    <h1>File Server</h1>

    {% with messages = get_flashed_messages() %}
      {% if messages %}
        {% for message in messages %}
          <div class="flash">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <form action="{{ url_for('upload_file') }}" method="post" enctype="multipart/form-data">
        <h3>Upload a File</h3>
        <input type="file" name="file" required>
        <button type="submit">Upload</button>
    </form>

    <h3>Available Files</h3>
    {% if files %}
        <ul>
        {% for file in files %}
            <li>
                <span>{{ file }}</span>
                <a href="{{ url_for('download_file', filename=file) }}">Download</a>
            </li>
        {% endfor %}
        </ul>
    {% else %}
        <p>No files uploaded yet.</p>
    {% endif %}
</body>
</html>
"""


def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET"])
def index():
    """Render the main page with upload form and list of uploaded files."""
    files = [
        f for f in os.listdir(app.config["UPLOAD_FOLDER"]) if not f.startswith(".")
    ]
    return render_template_string(HTML_TEMPLATE, files=files)


@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file uploads."""
    if "file" not in request.files:
        flash("No file part in the request.")
        return redirect(url_for("index"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file selected.")
        return redirect(url_for("index"))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)
        flash(f'File "{filename}" uploaded successfully!')
    else:
        flash("File type not allowed.")

    return redirect(url_for("index"))


@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    """Serve a previously uploaded file for download."""
    safe_filename = secure_filename(filename)
    return send_from_directory(
        app.config["UPLOAD_FOLDER"], safe_filename, as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)