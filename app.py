"""
app.py — Flask application: route definitions for secure-file-share.

Upload flow (both modes):
    1. Receive file + password + mode
    2. Derive KEK via PBKDF2
    3. Compute SHA-256 plaintext fingerprint
    4. Mode A: generate random AES key, wrap with RSA-OAEP
       Mode B: ephemeral ECDH via pfs.py → derive AES key → destroy ephem. privkey
    5. Encrypt file with AES-256-GCM
    6. Sign ciphertext with RSA-PSS
    7. Persist: .enc, .key/.ecpub, .sig, .sha256, .salt, .meta
    8. Append audit log entry

Download flow:
    1. Load ciphertext, signature, fingerprint, key material
    2. Verify RSA-PSS signature — abort if invalid
    3. Mode A: unwrap AES key with RSA-OAEP private key
       Mode B: reproduce ECDH + HKDF to recover AES key
    4. Decrypt AES-256-GCM — abort if auth tag fails
    5. Verify SHA-256 fingerprint
    6. Serve file + display fingerprint
    7. Append audit log entry
"""

import json
import os
import uuid
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from dotenv import load_dotenv
from cryptography.exceptions import InvalidSignature, InvalidTag

from config import (
    MAX_CONTENT_LENGTH,
    SECRET_KEY,
    STORAGE_FILES,
    STORAGE_FPS,
    STORAGE_KEYS,
    STORAGE_SIGS,
)
from crypto import aes, fingerprint, kdf, rsa_keys, signatures
from crypto.ecdh import (
    derive_shared_key,
    ec_public_key_to_pem,
    generate_ec_keypair,
    load_ec_private_key,
    load_ec_public_key,
    ec_private_key_to_pem,
)
from crypto.pfs import perform_pfs_exchange
from crypto.rsa_keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    private_key_to_pem,
    public_key_to_pem,
)
from audit.log import append_entry, read_and_verify

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"]         = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Ensure storage directories exist at startup
for _dir in (STORAGE_FILES, STORAGE_KEYS, STORAGE_SIGS, STORAGE_FPS):
    _dir.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _meta_path(file_id: str) -> Path:
    return STORAGE_FILES / f"{file_id}.meta"


def _save_meta(file_id: str, meta: dict) -> None:
    _meta_path(file_id).write_text(json.dumps(meta))


def _load_meta(file_id: str) -> dict:
    return json.loads(_meta_path(file_id).read_text())


def _client_ip() -> str:
    return request.remote_addr or "unknown"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/keys", methods=["GET", "POST"])
def keys():
    rsa_priv = rsa_pub = ec_priv = ec_pub = None

    if request.method == "POST":
        key_type = request.form.get("key_type", "both")

        if key_type in ("rsa", "both"):
            priv, pub = generate_keypair()
            rsa_priv  = private_key_to_pem(priv).decode()
            rsa_pub   = public_key_to_pem(pub).decode()
            append_entry("KEYGEN", "n/a", "RSA", _client_ip())

        if key_type in ("ec", "both"):
            priv, pub = generate_ec_keypair()
            ec_priv   = ec_private_key_to_pem(priv).decode()
            ec_pub    = ec_public_key_to_pem(pub).decode()
            append_entry("KEYGEN", "n/a", "ECDH", _client_ip())

    return render_template(
        "keys.html",
        rsa_priv=rsa_priv, rsa_pub=rsa_pub,
        ec_priv=ec_priv,   ec_pub=ec_pub,
    )


@app.route("/upload", methods=["POST"])
def upload():
    file        = request.files.get("file")
    password    = request.form.get("password", "")
    mode        = request.form.get("mode", "A")
    rsa_pub_pem = request.form.get("rsa_public_key", "").encode()
    rsa_prv_pem = request.form.get("rsa_private_key", "").encode()
    ec_pub_pem  = request.form.get("ec_public_key", "").encode()

    if not file or not file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    plaintext = file.read()
    if not plaintext:
        flash("File is empty.", "error")
        return redirect(url_for("index"))

    file_id   = str(uuid.uuid4())
    fp_hex    = fingerprint.compute(plaintext)

    # --- Key derivation (both modes add PBKDF2 layer) ---
    _kek, salt = kdf.derive_key(password)

    try:
        if mode == "A":
            # Mode A: RSA key transport
            if not rsa_pub_pem or not rsa_prv_pem:
                flash("Mode A requires both RSA public and private keys.", "error")
                return redirect(url_for("index"))

            recipient_pub = load_public_key(rsa_pub_pem)
            signer_priv   = load_private_key(rsa_prv_pem)

            session_key = os.urandom(32)
            wrapped_key = rsa_keys.wrap_key(session_key, recipient_pub)

            ciphertext  = aes.encrypt(plaintext, session_key)
            sig         = signatures.sign_ciphertext(ciphertext, signer_priv)

            STORAGE_KEYS.joinpath(f"{file_id}.key").write_bytes(wrapped_key)
            meta = {"mode": "RSA", "salt": salt.hex(), "filename": file.filename}

        else:
            # Mode B: ECDH + PFS
            if not ec_pub_pem or not rsa_prv_pem:
                flash("Mode B requires EC public key and RSA private key (for signing).", "error")
                return redirect(url_for("index"))

            recipient_ec_pub  = load_ec_public_key(ec_pub_pem)
            signer_priv       = load_private_key(rsa_prv_pem)

            session_key, ephem_pub_pem = perform_pfs_exchange(recipient_ec_pub)

            ciphertext = aes.encrypt(plaintext, session_key)
            sig        = signatures.sign_ciphertext(ciphertext, signer_priv)

            STORAGE_KEYS.joinpath(f"{file_id}.ecpub").write_bytes(ephem_pub_pem)
            meta = {"mode": "ECDH", "salt": salt.hex(), "filename": file.filename}

    except ValueError:
        flash("Invalid key format — paste the complete PEM block including the -----BEGIN----- and -----END----- lines.", "error")
        return redirect(url_for("index"))
    except Exception:
        flash("Encryption failed — check that the key matches the selected mode.", "error")
        return redirect(url_for("index"))

    # Persist artefacts
    STORAGE_FILES.joinpath(f"{file_id}.enc").write_bytes(ciphertext)
    STORAGE_SIGS.joinpath(f"{file_id}.sig").write_bytes(sig)
    STORAGE_FPS.joinpath(f"{file_id}.sha256").write_text(fp_hex)
    _save_meta(file_id, meta)

    append_entry("UPLOAD", file_id, meta["mode"], _client_ip())
    flash(f"File uploaded successfully. File ID: {file_id}", "success")
    return redirect(url_for("download_page", file_id=file_id))


@app.route("/download/<file_id>", methods=["GET", "POST"])
def download_page(file_id: str):
    enc_path = STORAGE_FILES / f"{file_id}.enc"
    sig_path = STORAGE_SIGS  / f"{file_id}.sig"
    fp_path  = STORAGE_FPS   / f"{file_id}.sha256"
    meta_path = _meta_path(file_id)

    for p in (enc_path, sig_path, fp_path, meta_path):
        if not p.exists():
            flash("File not found.", "error")
            return redirect(url_for("index"))

    meta          = _load_meta(file_id)
    stored_fp     = fp_path.read_text().strip()
    ciphertext    = enc_path.read_bytes()
    sig           = sig_path.read_bytes()

    if request.method == "GET":
        return render_template(
            "download.html",
            file_id=file_id,
            mode=meta["mode"],
            fingerprint=stored_fp,
            filename=meta.get("filename", "file"),
        )

    # POST: perform decryption
    password    = request.form.get("password", "")
    rsa_prv_pem = request.form.get("rsa_private_key", "").encode()
    rsa_pub_pem = request.form.get("rsa_public_key", "").encode()
    ec_prv_pem  = request.form.get("ec_private_key", "").encode()

    try:
        if not rsa_pub_pem:
            flash("RSA public key required for signature verification.", "error")
            return redirect(url_for("download_page", file_id=file_id))

        verifier_pub = load_public_key(rsa_pub_pem)
        signatures.verify_ciphertext(ciphertext, sig, verifier_pub)
    except InvalidSignature:
        append_entry("VERIFY_FAIL", file_id, meta["mode"], _client_ip())
        flash("Signature verification failed — the file may have been tampered with, or the wrong public key was provided.", "error")
        return render_template("verify.html", file_id=file_id, ok=False)
    except ValueError:
        flash("Invalid public key format — paste the complete PEM block including the -----BEGIN----- and -----END----- lines.", "error")
        return redirect(url_for("download_page", file_id=file_id))
    except Exception:
        flash("Signature check failed — check that you've pasted the sender's RSA public key.", "error")
        return redirect(url_for("download_page", file_id=file_id))

    append_entry("VERIFY_OK", file_id, meta["mode"], _client_ip())

    try:
        if meta["mode"] == "RSA":
            if not rsa_prv_pem:
                flash("RSA private key required for Mode A decryption.", "error")
                return redirect(url_for("download_page", file_id=file_id))

            recipient_priv = load_private_key(rsa_prv_pem)
            wrapped_key    = STORAGE_KEYS.joinpath(f"{file_id}.key").read_bytes()
            session_key    = rsa_keys.unwrap_key(wrapped_key, recipient_priv)

        else:
            if not ec_prv_pem:
                flash("EC private key required for Mode B decryption.", "error")
                return redirect(url_for("download_page", file_id=file_id))

            recipient_ec_priv = load_ec_private_key(ec_prv_pem)
            ephem_pub_pem     = STORAGE_KEYS.joinpath(f"{file_id}.ecpub").read_bytes()
            ephem_pub         = load_ec_public_key(ephem_pub_pem)
            session_key       = derive_shared_key(recipient_ec_priv, ephem_pub)

        plaintext = aes.decrypt(ciphertext, session_key)

    except InvalidTag:
        flash("Wrong key or password — the file could not be decrypted. Check you're using the correct private key.", "error")
        return redirect(url_for("download_page", file_id=file_id))
    except ValueError:
        flash("Invalid key format — paste the complete PEM block including the -----BEGIN----- and -----END----- lines.", "error")
        return redirect(url_for("download_page", file_id=file_id))
    except Exception:
        flash("Decryption failed — check that you're using the correct key type for this file's encryption mode.", "error")
        return redirect(url_for("download_page", file_id=file_id))

    fp_ok      = fingerprint.verify(plaintext, stored_fp)
    actual_fp  = fingerprint.compute(plaintext)

    if not fp_ok:
        append_entry(
            "FINGERPRINT_MISMATCH", file_id, meta["mode"], _client_ip(),
            extra={"stored_fp": stored_fp, "actual_fp": actual_fp},
        )
        flash("WARNING: Fingerprint mismatch — recovered file differs from original!", "warning")

    append_entry("DOWNLOAD", file_id, meta["mode"], _client_ip())

    import io
    return send_file(
        io.BytesIO(plaintext),
        download_name=meta.get("filename", "decrypted_file"),
        as_attachment=True,
    )


@app.route("/verify/<file_id>")
def verify_page(file_id: str):
    enc_path = STORAGE_FILES / f"{file_id}.enc"
    sig_path = STORAGE_SIGS  / f"{file_id}.sig"

    if not enc_path.exists() or not sig_path.exists():
        flash("File not found.", "error")
        return redirect(url_for("index"))

    rsa_pub_pem = request.args.get("public_key", "").encode()
    if not rsa_pub_pem:
        return render_template("verify.html", file_id=file_id, ok=None, needs_key=True)

    ciphertext = enc_path.read_bytes()
    sig        = sig_path.read_bytes()

    try:
        verifier_pub = load_public_key(rsa_pub_pem)
        signatures.verify_ciphertext(ciphertext, sig, verifier_pub)
        ok = True
        append_entry("VERIFY_OK", file_id, "unknown", _client_ip())
    except (InvalidSignature, Exception):
        ok = False
        append_entry("VERIFY_FAIL", file_id, "unknown", _client_ip())

    return render_template("verify.html", file_id=file_id, ok=ok)


@app.route("/audit")
def audit():
    entries = read_and_verify()
    return render_template("audit.html", entries=entries)


if __name__ == "__main__":
    # Never run with debug=True in production — it exposes the interactive
    # debugger which allows arbitrary code execution.
    app.run(debug=False, host="127.0.0.1", port=5000)
