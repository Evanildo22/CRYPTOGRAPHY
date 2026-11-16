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
* The derived password key never encrypts file data on its own.  It is
  combined with the session key (RSA-transported in Mode A, ECDH-derived
  in Mode B) by ``derive_file_key`` to produce the AES-256-GCM file key.
  Decryption therefore needs both the recipient's private key and the
  password; either one alone yields nothing.
* The combiner is HKDF-SHA256 over ``session_key || password_key`` with a
  domain-separation label.  Both inputs are fixed-length (32 bytes), so
  the concatenation is unambiguous.  As long as either input is secret
  and uniformly random, the output is indistinguishable from random — the
  same construction used for hybrid key exchange in TLS 1.3.
"""

import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from config import (
    FILE_KEY_INFO,
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_BYTES,
    PBKDF2_SALT_BYTES,
)


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

        * ``derived_key`` — 32-byte password key (input to ``derive_file_key``).
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


def derive_file_key(session_key: bytes, password_key: bytes) -> bytes:
    """
    Combine the session key and the password key into the AES-256-GCM file key.

    Parameters
    ----------
    session_key:
        32-byte key from RSA key transport (Mode A) or ECDH + HKDF (Mode B).
    password_key:
        32-byte key from ``derive_key``.

    Returns
    -------
    bytes
        32-byte file key.  Reproducing it requires both inputs.

    Raises
    ------
    ValueError
        If either input is not exactly 32 bytes.
    """
    if len(session_key) != PBKDF2_KEY_BYTES or len(password_key) != PBKDF2_KEY_BYTES:
        raise ValueError("session_key and password_key must each be 32 bytes")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_BYTES,
        salt=None,
        info=FILE_KEY_INFO,
    )
    return hkdf.derive(session_key + password_key)
