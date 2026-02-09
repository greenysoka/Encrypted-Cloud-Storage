# Encrypted Cloud Storage

Welcome to your very own **Encrypted Cloud Storage**!

This is a simple & secure file storage application built with Flask. 
It keeps your files safe with AES-GCM encryption and requires a password + TOTP 2FA verification to decrypt and access anything.

I started this project because I wanted to have a simple & secure file storage application that I could use to store my files anywhere I want. You can host it like me on a VPS or even in a container.
Make sure you connect a domain that offers HTTPS (SSL) for your server.

## Features

- **Encryption Magic**: Everything you upload is encrypted before it hits the disk. Even if someone gets access to your server, they see nothing.
- **Password Protection**: Set a master password to unlock and view your vault.
- **Two-Factor Auth (2FA)**: Add an extra layer of security with TOTP
- **File Management**: Upload, view, and delete files with ease. Images and videos can be previewed directly in your browser!
- **Storage Limits**: Keep track of your usage with a handy progress bar.

## Setup

1.  **Install Requirements**:
    Make sure you have Python installed, then grab the dependencies:
    ```bash
    pip install -r "config/requirements.txt"
    ```

2.  **Configure**:
    The app looks for a `.env` file in the `config/` folder for secrets.
    - Create `config/.env` and add:
      ```
      FLASK_SECRET_KEY=your-super-secret-key-here
      SERVER_PORT=5000
      ```
    - Check out `config/config.toml` if you want to tweak storage limits or sessions.

3.  **Run it!**:
    ```bash
    python app.py
    ```
    Open your browser and head to `http://127.0.0.1:5000` if hosted locally.
    If you host it in a container, remove the SERVER_PORT from the .env file.
    The code will then automatically detect the port.

## Usage

- **First Run**:
    - You'll be asked to set a **Master Password**. make it a good one!
    - Optionally, scan the QR code to set up 2FA.
- **Unlock**: Enter your password and 2FA code to access your files.
- **Upload**: Drag and drop or select files to encryption-upload them.
- **Enjoy**: View, download, and delete your files with ease. And don't worry, everything is safe & encrypted! ^^

---

Made with <3
& built in a private repo first, moved all files to this public repo then :)