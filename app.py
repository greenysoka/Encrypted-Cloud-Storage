import base64
import io
import json
import mimetypes
import os
import secrets
import uuid
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename



import pyotp
import qrcode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from filelock import FileLock
from werkzeug.middleware.proxy_fix import ProxyFix




BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / "config" / ".env"


def load_env_file():
    if not ENV_PATH.exists():
        return
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_config() -> dict:

    cfg = {
        "storage_dir": "storage",
        "max_upload_mb": 200,
        "max_storage_mb": 1000,
        "pbkdf2_iterations": 600000,
        "session_hours": 8,
        "secret_key_env": "FLASK_SECRET_KEY",
        "secure_cookies": 1,
        "encrypt_metadata": 1,
        "totp_valid_window": 2,
    }

    for key, output_key, cast in [
        ("STORAGE_DIR", "storage_dir",str),
        ("MAX_UPLOAD_MB", "max_upload_mb", int),
        ("MAX_STORAGE_MB", "max_storage_mb", int),
        ("PBKDF2_ITERATIONS", "pbkdf2_iterations", int),
        ("SESSION_HOURS", "session_hours", int),
        ("SECURE_COOKIES", "secure_cookies", int),
        ("ENCRYPT_METADATA", "encrypt_metadata", int),
        ("TOTP_VALID_WINDOW", "totp_valid_window", int),
    ]:
        val = os.environ.get(key)
        if val is not None:
            try:
                cfg[output_key] = cast(val)
            except ValueError:
                pass

    storage_dir = Path(os.environ.get("STORAGE_DIR", cfg["storage_dir"]))
    if not storage_dir.is_absolute():
        storage_dir = BASE_DIR / storage_dir
    
    custom_cfg_path = storage_dir / "config.json"
    if custom_cfg_path.exists():
        try:
            custom = json.loads(custom_cfg_path.read_text(encoding="utf-8"))
            for k, v in custom.items():
                if k in cfg:
                    cfg[k] = type(cfg[k])(v)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    return cfg


CFG = load_config()
STORAGE_DIR_REL = CFG["storage_dir"]
STORAGE_DIR = Path(STORAGE_DIR_REL)
if not STORAGE_DIR.is_absolute():
    STORAGE_DIR = BASE_DIR / STORAGE_DIR_REL

PLAINTEXT_METADATA_PATH = STORAGE_DIR / "metadata.json"
METADATA_ENCRYPTED = bool(CFG["encrypt_metadata"])
METADATA_PATH = STORAGE_DIR / ("metadata.enc" if METADATA_ENCRYPTED else "metadata.json")
AUTH_PATH = STORAGE_DIR / "auth.json"
LOCK_PATH = STORAGE_DIR / "metadata.lock"
SESSION_DIR = STORAGE_DIR / "sessions"
CUSTOM_CONFIG_PATH = STORAGE_DIR / "config.json"

PBKDF2_ITERS = int(CFG["pbkdf2_iterations"])
TOTP_ISSUER = "EncryptedCloud"
TOTP_WINDOW = int(CFG["totp_valid_window"])



app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

load_env_file()

secret_key = os.environ.get(CFG["secret_key_env"])
if not secret_key or secret_key == "change-me-please":
    raise RuntimeError(
        f"Missing secret key! Please set env var {CFG['secret_key_env']} in config/.env or environment!"
    )

app.config.update(
    SECRET_KEY=secret_key,
    MAX_CONTENT_LENGTH=CFG["max_upload_mb"] * 1024 * 1024,
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR=SESSION_DIR,
    SESSION_PERMANENT=True,
    SESSION_USE_SIGNER=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=CFG["session_hours"]),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=CFG["secure_cookies"],
)
Session(app)


@app.after_request
def add_security_headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"

    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
    if CFG["secure_cookies"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def ensure_storage():
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def encrypt_text(hpw_hex: str, text: str) -> str:
    blob = encrypt_bytes(hpw_hex, text.encode("utf-8"))
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_text(hpw_hex: str, token: str) -> str:
    blob = base64.urlsafe_b64decode(token.encode("ascii"))
    return decrypt_bytes(hpw_hex, blob).decode("utf-8")


def load_metadata(hpw_hex: str | None = None) -> list[dict]:
    ensure_storage()
    if METADATA_ENCRYPTED:
        if METADATA_PATH.exists():
            if not hpw_hex:
                raise ValueError("Missing password hash for decryption")
            data = METADATA_PATH.read_bytes()
            if not data:
                return []
            try:
                plaintext = decrypt_bytes(hpw_hex, data)
                return json.loads(plaintext.decode("utf-8"))
            except Exception as exc:
                raise ValueError("Failed to decrypt metadata. Wrong password?") from exc

        if PLAINTEXT_METADATA_PATH.exists():
            try:
                return json.loads(PLAINTEXT_METADATA_PATH.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return []
        return []
    

    if not PLAINTEXT_METADATA_PATH.exists():
        return []
    try:
        return json.loads(PLAINTEXT_METADATA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def save_metadata(items: list[dict], hpw_hex: str | None = None) -> None:
    ensure_storage()
    if METADATA_ENCRYPTED:
        if not hpw_hex:
            raise ValueError("Missing password hash for encryption")
        payload = json.dumps(items, indent=2).encode("utf-8")
        encrypted = encrypt_bytes(hpw_hex, payload)
        

        tmp_path = METADATA_PATH.with_suffix(".tmp")
        tmp_path.write_bytes(encrypted)
        tmp_path.replace(METADATA_PATH)
        

        if PLAINTEXT_METADATA_PATH.exists():
            PLAINTEXT_METADATA_PATH.unlink()
        return

    tmp_path = PLAINTEXT_METADATA_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(items, indent=2), encoding="utf-8")
    tmp_path.replace(PLAINTEXT_METADATA_PATH)


def public_metadata(items: list[dict]) -> list[dict]:
    safe_keys = ("id", "alias", "mime", "size", "uploaded_at", "display_name")
    return [{key: item.get(key) for key in safe_keys} for item in items]


def resolve_download_name(meta: dict, hpw_hex: str) -> str:
    if meta.get("original_name"):
        return meta["original_name"]
    name_enc = meta.get("name_enc")
    if name_enc:
        try:
            return decrypt_text(hpw_hex, name_enc)
        except Exception:
            return meta.get("alias") or "file"
    return meta.get("alias") or "file"


def resolve_display_name(meta: dict, hpw_hex: str) -> str:
    if meta.get("original_name"):
        return meta["original_name"]
    name_enc = meta.get("name_enc")
    if name_enc:
        try:
            return decrypt_text(hpw_hex, name_enc)
        except Exception:
            return meta.get("alias") or "file"
    return meta.get("alias") or "file"


def build_view_metadata(items: list[dict], hpw_hex: str) -> list[dict]:
    view_items = []
    for item in items:
        entry = dict(item)
        entry["display_name"] = resolve_display_name(item, hpw_hex)
        view_items.append(entry)
    return public_metadata(view_items)


def compute_storage_usage(items: list[dict]) -> int:
    return sum(int(item.get("size") or 0) for item in items)


def is_unlocked() -> bool:
    return bool(session.get("hpw"))


def require_unlocked():
    if not is_unlocked():
        abort(401)


def derive_key(hpw_hex: str, salt: bytes) -> bytes:
    try:
        hpw_bytes = bytes.fromhex(hpw_hex)
    except ValueError as exc:
        raise ValueError("Invalid password hash") from exc
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(hpw_bytes)


def derive_verifier(hpw_hex: str, salt: bytes) -> bytes:
    return derive_key(hpw_hex, salt)


def load_auth() -> dict | None:
    ensure_storage()
    if not AUTH_PATH.exists():
        return None
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if "salt" not in data or "verifier" not in data:
        return None
    return data


def save_auth(salt: bytes, verifier: bytes, totp_enc: str) -> None:
    ensure_storage()
    payload = {
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "verifier": base64.urlsafe_b64encode(verifier).decode("ascii"),
        "totp_enc": totp_enc,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    tmp_path = AUTH_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp_path.replace(AUTH_PATH)
    try:
        os.chmod(AUTH_PATH, 0o600)
    except OSError:
        pass


def verify_password(hpw_hex: str) -> bool:
    auth = load_auth()
    if not auth:
        return False
    try:
        salt = base64.urlsafe_b64decode(auth["salt"].encode("ascii"))
        verifier = base64.urlsafe_b64decode(auth["verifier"].encode("ascii"))
    except Exception:
        return False
    try:
        derived = derive_verifier(hpw_hex, salt)
    except Exception:
        return False
    return secrets.compare_digest(derived, verifier)


def is_password_set() -> bool:
    return load_auth() is not None


def build_totp_uri(secret: str) -> str:
    label = urllib.parse.quote(f"{TOTP_ISSUER}:vault")
    issuer = urllib.parse.quote(TOTP_ISSUER)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&digits=6"


def generate_qr_data_uri(secret: str) -> str:
    uri = build_totp_uri(secret)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def get_totp_secret(auth: dict, hpw_hex: str) -> str:
    totp_enc = auth.get("totp_enc")
    if not totp_enc:
        raise ValueError("Missing TOTP secret")
    return decrypt_text(hpw_hex, totp_enc)


def encrypt_bytes(hpw_hex: str, plaintext: bytes) -> bytes:

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(hpw_hex, salt)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    return salt + nonce + ciphertext


def decrypt_bytes(hpw_hex: str, blob: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("Corrupted ciphertext")
    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    key = derive_key(hpw_hex, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)


ensure_storage()

@app.get("/")
def index():
    if not is_unlocked():
        return redirect(url_for("unlock"))
    try:
        hpw = session["hpw"]
        items = load_metadata(hpw)
        files = build_view_metadata(items, hpw)
    except ValueError:
        abort(403)
    used_bytes = compute_storage_usage(items)
    total_mb = max(CFG["max_storage_mb"], 0)
    total_bytes = total_mb * 1024 * 1024 if total_mb else 0
    percent = min(int((used_bytes / total_bytes) * 100), 100) if total_bytes else 0
    return render_template(
        "index.html",
        files=files,
        used_bytes=used_bytes,
        total_bytes=total_bytes,
        used_mb=round(used_bytes / 1024 / 1024, 1),
        total_mb=total_mb,
        percent=percent,
    )


@app.get("/unlock")
def unlock():
    auth = load_auth()
    setup_password = not auth
    setup_totp = bool(auth) and not auth.get("totp_enc")
    setup_required = setup_password or setup_totp
    return render_template(
        "unlock.html",
        setup=setup_required,
        setup_password=setup_password,
        setup_totp=setup_totp,
    )


@app.post("/unlock")
@limiter.limit("5 per minute")
def unlock_post():
    data = request.get_json(silent=True) or request.form
    hpw = (data.get("hpw") or "").strip()
    if len(hpw) != 64:
        return jsonify({"ok": False, "error": "Invalid password hash"}), 400
    totp_code = (data.get("totp") or "").strip()
    client_time = data.get("client_time")
    server_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    drift_sec = None
    try:
        if client_time is not None:
            drift_sec = int((server_time_ms - int(client_time)) / 1000)
    except (TypeError, ValueError):
        drift_sec = None
    auth = load_auth()

    if not auth:
        if not totp_code:
            try:
                custom_config = {}
                if "max_upload_mb" in data:
                    custom_config["max_upload_mb"] = int(data["max_upload_mb"])
                if "max_storage_mb" in data:
                    custom_config["max_storage_mb"] = int(data["max_storage_mb"])
                if "session_hours" in data:
                    custom_config["session_hours"] = int(data["session_hours"])
                
                if custom_config:
                    ensure_storage()
                    CUSTOM_CONFIG_PATH.write_text(json.dumps(custom_config, indent=2), encoding="utf-8")
            except (ValueError, TypeError):
                 pass

            secret = pyotp.random_base32()
            session["setup_totp"] = secret
            return jsonify(
                {
                    "ok": True,
                    "setup": True,
                    "totp_secret": secret,
                    "totp_uri": build_totp_uri(secret),
                    "totp_qr": generate_qr_data_uri(secret),
                }
            )
        secret = session.get("setup_totp")
        if not secret:
            return jsonify({"ok": False, "error": "Setup expired. Try again."}), 400
        if not pyotp.TOTP(secret).verify(totp_code, valid_window=TOTP_WINDOW):
            return jsonify({"ok": False, "error": "Invalid TOTP code", "drift_sec": drift_sec}), 403
        salt = os.urandom(16)
        verifier = derive_verifier(hpw, salt)
        totp_enc = encrypt_text(hpw, secret)
        save_auth(salt, verifier, totp_enc)
        session["hpw"] = hpw
        session.permanent = True
        session.pop("setup_totp", None)
        return jsonify({"ok": True})

    if not verify_password(hpw):
        return jsonify({"ok": False, "error": "Invalid password"}), 403

    if not auth.get("totp_enc"):
        if not totp_code:
            secret = session.get("setup_totp")
            if not secret:
                secret = pyotp.random_base32()
                session["setup_totp"] = secret
            return jsonify(
                {
                    "ok": True,
                    "setup": True,
                    "totp_secret": secret,
                    "totp_uri": build_totp_uri(secret),
                    "totp_qr": generate_qr_data_uri(secret),
                    "message": "Two-factor setup required",
                }
            )
        secret = session.get("setup_totp")
        if not secret:
            return jsonify({"ok": False, "error": "Setup expired. Try again."}), 400
        if not pyotp.TOTP(secret).verify(totp_code, valid_window=TOTP_WINDOW):
            return jsonify({"ok": False, "error": "Invalid TOTP code", "drift_sec": drift_sec}), 403
        try:
            salt = base64.urlsafe_b64decode(auth["salt"].encode("ascii"))
            verifier = base64.urlsafe_b64decode(auth["verifier"].encode("ascii"))
        except Exception:
            return jsonify({"ok": False, "error": "Auth store corrupted"}), 500
        totp_enc = encrypt_text(hpw, secret)
        save_auth(salt, verifier, totp_enc)
        session["hpw"] = hpw
        session.permanent = True
        session.pop("setup_totp", None)
        return jsonify({"ok": True})

    if not totp_code:
        return jsonify({"ok": False, "error": "Missing TOTP code"}), 400
    try:
        secret = get_totp_secret(auth, hpw)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid password"}), 403
    if not pyotp.TOTP(secret).verify(totp_code, valid_window=TOTP_WINDOW):
        return jsonify({"ok": False, "error": "Invalid TOTP code", "drift_sec": drift_sec}), 403

    session["hpw"] = hpw
    session.permanent = True
    return jsonify({"ok": True})


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/totp/qr")
def totp_qr():
    secret = session.get("setup_totp")
    if not secret:
        abort(404)
    data_uri = generate_qr_data_uri(secret)
    png_data = base64.b64decode(data_uri.split(",", 1)[1])
    return send_file(io.BytesIO(png_data), mimetype="image/png", download_name="totp.png")


@app.post("/upload")
@limiter.limit("10 per minute")
def upload():
    require_unlocked()
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file uploaded"}), 400
    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"ok": False, "error": "Missing filename"}), 400

    original_name = file.filename
    safe_name = secure_filename(original_name) or f"file-{uuid.uuid4().hex}"
    data = file.read()
    if not data:
        return jsonify({"ok": False, "error": "Empty file"}), 400

    hpw = session["hpw"]

    with FileLock(LOCK_PATH):
        try:
            items = load_metadata(hpw)
        except ValueError:
            return jsonify({"ok": False, "error": "Vault locked"}), 403
        

        used_bytes = compute_storage_usage(items)
        if CFG["max_storage_mb"]:
             total_bytes = CFG["max_storage_mb"] * 1024 * 1024
             if used_bytes + len(data) > total_bytes:
                 return jsonify({"ok": False, "error": "Storage limit reached"}), 413
        
        encrypted_blob = encrypt_bytes(hpw, data)
        file_id = uuid.uuid4().hex
        alias = f"vault-{secrets.token_hex(4)}"
        blob_path = STORAGE_DIR / f"{file_id}.bin"
        blob_path.write_bytes(encrypted_blob)

        mime_type = file.mimetype or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
        meta = {
            "id": file_id,
            "alias": alias,
            "mime": mime_type,
            "size": len(data),
            "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        if METADATA_ENCRYPTED:
            meta["original_name"] = original_name
        else:
            meta["name_enc"] = encrypt_text(hpw, original_name)
        items.insert(0, meta)
        save_metadata(items, hpw)
    return jsonify({"ok": True, "file": public_metadata([meta])[0]})


@app.get("/files/<file_id>")
def view_file(file_id: str):
    require_unlocked()
    hpw = session["hpw"]
    try:
        items = load_metadata(hpw)
    except ValueError:
        abort(403)
    meta = next((m for m in items if m.get("id") == file_id), None)
    if not meta:
        abort(404)

    blob_path = STORAGE_DIR / f"{file_id}.bin"
    if not blob_path.exists():
        abort(404)

    try:
        plaintext = decrypt_bytes(hpw, blob_path.read_bytes())
    except Exception:
        abort(403)

    as_attachment = request.args.get("download") == "1"
    response = send_file(
        io.BytesIO(plaintext),
        mimetype=meta.get("mime", "application/octet-stream"),
        as_attachment=as_attachment,
        download_name=resolve_download_name(meta, hpw),
    )
    return response


@app.delete("/files/<file_id>")
def delete_file(file_id: str):
    require_unlocked()
    hpw = session["hpw"]
    with FileLock(LOCK_PATH):
        try:
            items = load_metadata(hpw)
        except ValueError:
           abort(403)
        meta = next((m for m in items if m.get("id") == file_id), None)
        if not meta:
            abort(404)

        blob_path = STORAGE_DIR / f"{file_id}.bin"
        if blob_path.exists():
            try:
                blob_path.unlink()
            except OSError:
                pass

        items = [m for m in items if m.get("id") != file_id]
        save_metadata(items, hpw)
    return jsonify({"ok": True})


@app.get("/api/files")
def api_files():
    require_unlocked()
    try:
        hpw = session["hpw"]
        items = load_metadata(hpw)
    except ValueError:
        abort(403)
    return jsonify({"files": build_view_metadata(items, hpw)})


@app.errorhandler(401)
def handle_401(_):
    if request.accept_mimetypes.accept_html:
        return redirect(url_for("unlock"))
    return jsonify({"ok": False, "error": "Locked"}), 401


if __name__ == "__main__":
    ensure_storage()
    port = int(os.getenv("SERVER_PORT", 5000))
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", port=port, host="0.0.0.0")
