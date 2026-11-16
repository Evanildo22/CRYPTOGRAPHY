# Demo

`demo.sh` is a self-contained terminal walkthrough of the full cryptographic pipeline. It runs without the Flask server, exercising the `crypto/` and `audit/` modules directly.

## Run

From the project root, with the dependencies installed:

```bash
bash demo/demo.sh
```

## What it demonstrates (8 steps)

1. RSA-2048 and P-256 EC keypair generation
2. PBKDF2-HMAC-SHA256 password derivation, with its wall-clock cost (brute-force resistance)
3. SHA-256 plaintext fingerprint
4. Mode B upload: ephemeral ECDH exchange, session key derivation, AES-256-GCM encrypt, RSA-PSS sign
5. Tamper detection: flips a single ciphertext bit and shows `InvalidTag` raised
6. Download: RSA-PSS verify → ECDH reproduce → AES-256-GCM decrypt → fingerprint check
7. Audit log tamper detection: writes entries, edits a field, and shows the `TAMPERED` flag
8. Full test suite (`pytest tests/ -q`)
