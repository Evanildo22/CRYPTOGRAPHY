# Demo

`demo.sh` is a self-contained terminal walkthrough of the full cryptographic pipeline. It runs without the Flask server — directly exercising the `crypto/` and `audit/` modules.

## What it demonstrates (8 steps)

1. RSA-2048 and P-256 EC keypair generation
2. PBKDF2-HMAC-SHA256 password derivation — shows wall-clock cost (brute-force resistance)
3. SHA-256 plaintext fingerprint
4. Mode B upload: ephemeral ECDH exchange, session key derivation, AES-256-GCM encrypt, RSA-PSS sign
5. Tamper detection — flips a single ciphertext bit, shows `InvalidTag` raised
6. Download: RSA-PSS verify → ECDH reproduce → AES-256-GCM decrypt → fingerprint check
7. Audit log HMAC tamper detection — writes entries, then edits a field and shows `TAMPERED` flag
8. Full test suite (`pytest tests/ -q`)

## Record with asciinema

```bash
# Install
pip install asciinema   # or: brew install asciinema

# Record (from project root)
asciinema rec demo/demo.cast --command "bash demo/demo.sh"

# Upload and get shareable URL
asciinema upload demo/demo.cast
```

## Record with terminalizer

```bash
npm install -g terminalizer

terminalizer record demo/demo --command "bash demo/demo.sh"
terminalizer render demo/demo   # → demo.gif
```

## Run standalone

```bash
cd /path/to/CRYPTOGRAPHY
bash demo/demo.sh
```
