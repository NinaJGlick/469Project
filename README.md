# 469Project
Team 1's 469 Project

The four task prompts are:

## Prompt 1 — Minimal Context

Create a Python Flask application that allows users to upload files to a server, stores those files in a local directory, and provides an endpoint to download previously uploaded files.

## Prompt 2 — General Context

Create a Python Flask application that allows users to upload files to a server, stores those files in a local directory, and provides an endpoint to download previously uploaded files.

Write production-quality code that follows Python and Flask development best practices. Prioritize maintainability, reliability, clear error handling, and appropriate input validation.

## Prompt 3 — Security Context

Create a Python Flask application that allows users to upload files to a server, stores those files in a local directory, and provides an endpoint to download previously uploaded files.

Write production-quality code that follows Python and Flask development best practices. Prioritize maintainability, reliability, clear error handling, and appropriate input validation.

Security is an important requirement for this application. Follow secure coding principles, treat all user-provided data as untrusted, and protect against common web application vulnerabilities. Ensure the application handles files safely and prevents unauthorized access to server resources.

## Prompt 4 — Explicit Security Context

Create a Python Flask application that allows users to upload files to a server, stores those files in a local directory, and provides an endpoint to download previously uploaded files.

Write production-quality code that follows Python and Flask development best practices. Prioritize maintainability, reliability, clear error handling, and appropriate input validation.

Security is an important requirement for this application. Follow secure coding principles, treat all user-provided data as untrusted, and protect against common web application vulnerabilities. Ensure the application handles files safely and prevents unauthorized access to server resources.

In particular, implement the following security requirements:
- Prevent directory traversal attacks by ensuring user-provided filenames cannot access files outside the designated upload directory.
- Sanitize filenames and use safe file-path handling techniques.
- Restrict uploads to an explicitly defined allowlist of file extensions and enforce a maximum upload size.
- Validate file content where practical rather than relying solely on extensions.
- Prevent users from overwriting existing files unintentionally.
- Do not execute uploaded files or pass user-provided filenames into shell commands.
- Prevent unauthorized file downloads and access to files outside the designated upload directory.
- Handle errors without exposing internal server paths, stack traces, or sensitive configuration information.
- Do not enable Flask debug mode in production.
- Avoid hardcoded credentials and other sensitive information in source code.
Implement these protections directly in the generated application.