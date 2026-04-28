"""
crypto/kdf.py — Password-Based Key Derivation Function (PBKDF2-HMAC-SHA256).

Design decisions
----------------
* PBKDF2-HMAC-SHA256 with 600,000 iterations is used (NIST SP 800-132
  recommended minimum for SHA-256 in 2023).  Argon2id would be a stronger
  choice for new systems (memory-hard, GPU-resistant) but PBKDF2 is in
  the standard library of every language and is the baseline reference
  implementation for a demonstration system.
* A fresh 128-bit (16-byte) salt is generated per key derivation.  The
  salt prevents rainbow-table attacks and ensures that two users with the
  same password get different derived keys.  It is stored alongside the
  wrapped key material so it can be reproduced on download.
* The derived key is a Key-Encryption Key (KEK): it protects the AES
  session key, not the file data directly.  This layering (password →
  PBKDF2 → KEK → AES-GCM → file data) means that a password change only
  requires re-wrapping the session key, not re-encrypting the entire file.
* In Mode B, the HKDF output from the ECDH exchange plays the equivalent
  role of the KEK — the PBKDF2 layer in Mode B is therefore optional and
  is used as a second factor rather than the primary key protection.
"""

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from config import PBKDF2_ITERATIONS, PBKDF2_SALT_BYTES, PBKDF2_KEY_BYTES


def derive_key(password: str | bytes, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derive a 256-bit key from *password* using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    password:
        User-supplied password.  Strings are UTF-8 encoded before hashing.
    salt:
        16-byte salt.  If ``None``, a fresh random salt is generated.
        Pass an existing salt to reproduce a previously derived key.

    Returns
    -------
    tuple[bytes, bytes]
        ``(derived_key, salt)``

        * ``derived_key`` — 32-byte pseudorandom key (use as KEK or AES key).
        * ``salt`` — the salt used; store this alongside the ciphertext.

    Notes
    -----
    The salt *must* be stored to allow reproduction on download.  It is
    not secret — the security of the scheme depends entirely on the
    iteration count and the password entropy.
    """
    if salt is None:
        salt = os.urandom(PBKDF2_SALT_BYTES)

    if isinstance(password, str):
        password = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password), salt
