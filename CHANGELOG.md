# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.0.0] — 2026-04-09

### Added

**Core cryptographic modules (`crypto/`)**
- `aes.py` — AES-256-GCM authenticated encryption. Layout: `tag (16 B) || iv (12 B) || ciphertext`. Tag prepended so storage reads fail-fast on tampered blobs.
- `rsa_keys.py` — RSA-2048 keypair generation, PEM serialisation, and OAEP key-wrap / unwrap. PKCS#1 v1.5 explicitly excluded (Bleichenbacher vulnerability).
- `ecdh.py` — P-256 ephemeral keypair generation, ECDH exchange, HKDF-SHA256 derivation to 256-bit AES key. Domain-separation `info` label prevents cross-context key reuse.
- `pfs.py` — Perfect Forward Secrecy lifecycle module. Generates ephemeral keypair, derives session key, zeroes private key bytes via `ctypes.memset`, and returns only the public key + derived session key. Never writes to disk.
- `signatures.py` — RSA-PSS-SHA256 sign / verify over ciphertext (sign-then-encrypt ordering). `PSS.MAX_LENGTH` salt (32 bytes) provides maximum security margin.
- `kdf.py` — PBKDF2-HMAC-SHA256 at 600,000 iterations with 128-bit random salt. Derives 256-bit KEK from user password. NIST SP 800-132 compliant iteration count.
- `fingerprint.py` — SHA-256 plaintext commitment. Computed at upload, verified post-decrypt. Constant-time comparison via `hmac.compare_digest`.

**Audit log (`audit/log.py`)**
- Append-only JSON Lines log. Every entry includes timestamp, event type, file ID, mode, IP address, and HMAC-SHA256 over canonical sorted-key JSON.
- Audit viewer re-verifies every HMAC on read; tampered entries surfaced as `TAMPERED` in the UI.
- Log key loaded from `AUDIT_LOG_KEY` environment variable — never in code.

**Flask application (`app.py`)**
- `/` — landing page with mode selector and upload form
- `/upload` (POST) — full upload pipeline: PBKDF2 → fingerprint → Mode A or B key derivation → AES-256-GCM encrypt → RSA-PSS sign → persist → audit log
- `/download/<id>` (GET/POST) — signature verify (abort if invalid) → key recovery → AES-256-GCM decrypt (abort on `InvalidTag`) → fingerprint verify → serve file → audit log
- `/verify/<id>` — standalone RSA-PSS signature verification result page
- `/keys` (GET/POST) — RSA-2048 and P-256 EC keypair generator; keys never stored server-side
- `/audit` — read-only log viewer with per-entry HMAC re-verification

**Tests (`tests/`)**
- 83 pytest unit tests across 8 files; 6 AES-256-GCM throughput benchmarks (`-m benchmark`) for 1/10/100 MiB payloads, reporting median MB/s per direction
- Coverage: encrypt/decrypt round-trips, per-call IV uniqueness, bit-flip detection in any ciphertext byte, wrong-key rejection, PEM serialisation round-trips, OAEP wrap/unwrap, ECDH both-sides-agree, PFS no-disk-write assertion, PSS non-determinism, PBKDF2 determinism and salt uniqueness, SHA-256 known vectors, audit log HMAC tamper detection

**Documentation**
- `README.md` — security goals, architecture diagram, cryptographic primitive table, quickstart, known limitations
- `THREAT_MODEL.md` — trust boundary diagram, 7 adversary profiles (ADV-1 through ADV-7), 6 attack trees (AT-1 through AT-6), per-primitive mitigation tables with residual risks, explicit non-goals section, prioritised hardening backlog
- `CHANGELOG.md` — this file
- `.env.example` — environment variable template

**Configuration**
- `config.py` — single source of truth for all security constants: PBKDF2 iterations, key sizes, storage paths, HKDF labels
- `requirements.txt` — pinned dependency versions (`cryptography==42.0.5`, `Flask==3.0.3`, `pytest==8.2.0`, `python-dotenv==1.0.1`)
- `.gitignore` — excludes `.env`, `__pycache__`, all storage artefacts (ciphertext, keys, signatures, logs)

**Frontend**
- Dark-theme UI with mode-toggle JavaScript (Mode A shows RSA key field; Mode B shows EC key field)
- Audit log table with colour-coded HMAC status (green OK / red TAMPERED)
- Fingerprint display on download page with `sha256sum` verification hint
