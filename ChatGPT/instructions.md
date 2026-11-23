# Instuctions for ChatGPT tasks

## Task 1
### Run the following:
- `pip install -r requirements.txt`\
- `python task1.py` (Local testing)
- `curl -X POST \
  -F "file=@example.pdf" \
  http://127.0.0.1:5000/upload` (Upload the file)
- `curl -O -J \
  http://127.0.0.1:5000/download/a1b2c3_example.pdf` (Download the file)

## Task 2
### Run the following:
- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip install -r requirements.txt`
- `python task2.py` (Local testing)
- `gunicorn --bind 127.0.0.1:8000 task1:app` (Production deployment)
- `curl -X POST \
  -F "file=@example.pdf" \
  http://127.0.0.1:5000/upload` (Upload the file)
- `curl -OJ \
  http://127.0.0.1:5000/download/a92c4b63d5e74fc39a1e2b80764d3a15.pdf` (Download the file)

## Task 3
### Run the following:
- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip install -r requirements.txt`
- `python task3.py` (Local testing)
- ` gunicorn --workers 2 --bind 127.0.0.1:8000 app:app` (Production deployment)
- `curl -X POST \
  -F "file=@example.pdf" \
  http://127.0.0.1:5000/upload` (Upload the file)
- `curl -L \
  -o downloaded.pdf \
  http://127.0.0.1:5000/download/c7c20521-2344-45c4-80d3-1a9cb629d784` (Download the file)

## Task 4
 ### Run the following:
- `python -m venv venv`
- `source venv/bin/activate`
- `pip install -r requirements.txt`
- `python -c "import secrets; print(secrets.token_urlsafe(32))"` (Generate a secure authentication token)
- `export FILE_API_TOKEN="your-generated-token"`\
    `export UPLOAD_DIR="./uploads"` (Set the resulting token as an environment variable, without placing it in your source code)
- `python task4.py` (Local testing)
- `gunicorn --workers 4 --bind 127.0.0.1:8000 app:app` (Production)
- `curl -X POST http://127.0.0.1:5000/upload \
  -H "Authorization: Bearer $FILE_API_TOKEN" \
  -F "file=@photo.png"` (Upload file)
- `curl -H "Authorization: Bearer $FILE_API_TOKEN" \
  http://127.0.0.1:5000/download/a3f947d18b2c4f5e9c6d73081b254a6f \
  -o downloaded.png` (Download file)