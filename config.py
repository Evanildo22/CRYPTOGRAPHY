"""
Application configuration.

All tuneable constants live here so security-sensitive values
(iteration counts, key sizes) are easy to audit and change in one place
rather than scattered across modules.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Storage paths
# ---------------------------------------------------------------------------
STORAGE_FILES = BASE_DIR / "storage" / "files"
STORAGE_KEYS  = BASE_DIR / "storage" / "keys"
STORAGE_SIGS  = BASE_DIR / "storage" / "sigs"
STORAGE_FPS   = BASE_DIR / "storage" / "fingerprints"
STORAGE_AUDIT = BASE_DIR / "storage" / "audit"

# ---------------------------------------------------------------------------
# Upload limits
# ---------------------------------------------------------------------------
MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024   # 16 MiB hard cap for uploads

# ---------------------------------------------------------------------------
# KDF parameters
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS: int = 600_000   # NIST SP 800-132 recommended minimum for SHA-256
PBKDF2_SALT_BYTES: int = 16        # 128-bit random salt
PBKDF2_KEY_BYTES:  int = 32        # 256-bit derived key

# ---------------------------------------------------------------------------
# AES-GCM parameters
# ---------------------------------------------------------------------------
AES_IV_BYTES:  int = 12   # 96-bit IV — recommended size for GCM to avoid GHASH weaknesses
AES_KEY_BYTES: int = 32   # 256-bit session key
AES_TAG_BYTES: int = 16   # 128-bit authentication tag (GCM default)

# ---------------------------------------------------------------------------
# RSA parameters
# ---------------------------------------------------------------------------
RSA_KEY_SIZE_BITS: int = 2048   # Minimum recommended by NIST through 2030

# ---------------------------------------------------------------------------
# ECDH parameters
# ---------------------------------------------------------------------------
HKDF_INFO:          bytes = b"secure-file-share-session-key-v1"
HKDF_DERIVED_BYTES: int   = 32   # 256-bit AES key from HKDF output

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
AUDIT_LOG_KEY: bytes = bytes.fromhex(
    os.environ.get("AUDIT_LOG_KEY", "0" * 64)   # must be overridden in production
)

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------
SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
