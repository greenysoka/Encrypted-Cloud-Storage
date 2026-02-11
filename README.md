# E2EE Cloud Webserver

E2EE Cloud Webserver is a simple and secure self-hosted file vault built with Flask.
Files are encrypted in the browser before upload (AES-256-GCM), so the server only stores opaque ciphertext blobs.
Access is protected by a master password and TOTP 2FA.

You can run it on a VPS or in a container. Use HTTPS in production.

**The Goal: Self-host a secure, private webserver in untrusted environments.**

## Features

- **End-to-end encryption**: Files are encrypted client-side before upload.
- **Zero-knowledge design**: The server never receives your plaintext password or file contents.
- **Password + 2FA**: Master password login with TOTP support. (Both encrypted)
- **Multiple uploads in a queue**: Batch file uploads are handled in a client-side queue with progress.
- **Thumbnail caching**: Decrypted image thumbnails are cached in the browser to avoid repeat fetch/decrypt work.
- **Storage usage view**: Used/total storage and percentage indicator.
- **File actions**: Rename, download, and delete files.

## Performance Note

With thumbnail caching enabled, the cloud feels very fast during navigation and page reloads because image previews usually load from local browser cache instead of being fetched and decrypted again. The bare hardwre only matters for uploads which are handled in queues.

## Minimum Requirements

- **CPU**: Average server CPU (up to 25% of one core)
- **Disk**: At least 60 MB for the web server and dependencies + what you need for your files
- **RAM**: At least 45-50 MB in average

## Setup

1. **Install dependencies**

```bash
pip install -r config/requirements.txt
```

2. **Configure environment**

- Copy `config/.env.example` to `config/.env`:

```bash
cp config/.env.example config/.env
```

- Create a `FLASK_SECRET_KEY` in `config/.env` (a long random pattern of numbers & letters is recommended for production)

3. **Run**

```bash
python app.py
```

Open `http://127.0.0.1:5000` for local usage.
If you deploy in a container, remove `SERVER_PORT` from `.env` so runtime port detection is used.

## Usage

- **First run**: Set a master password, vault limits & 2FA TOTP (required).
- **Unlock**: Sign in with password + TOTP (not required directly after setup)
- **Upload**: Drag-and-drop or select one/multiple files; uploads are encrypted client-side and processed in a queue.
- **Browse**: Search, filter, sort, toggle list/grid, and preview images directly in the app.

## Project Status

Development is still going. See [TODO.md](TODO.md) for the active roadmap and upcoming features.

(Screenshots are following)