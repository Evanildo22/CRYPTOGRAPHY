"""
crypto/aes.py — AES-256-GCM symmetric encryption / decryption.

Design decisions
----------------
* GCM mode is chosen over CBC+HMAC because it provides authenticated
  encryption (AEAD) in a single pass: confidentiality and integrity are
  inseparable, eliminating the "MAC-then-encrypt vs encrypt-then-MAC"
  debate entirely.
* A fresh 96-bit IV is generated per operation using os.urandom.  96 bits
  is the recommended IV size for GCM; longer IVs require an extra GHASH
  reduction step and offer no practical security benefit.
* The 128-bit authentication tag is *prepended* to the stored ciphertext
  (layout: [tag || iv || ciphertext]).  Prepending the tag means that the
  very first bytes read from storage trigger integrity verification, making
  it impossible to accidentally skip the check.
* Decryption raises cryptography.exceptions.InvalidTag on any tampering.
  The caller must not suppress this exception.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import AES_IV_BYTES, AES_TAG_BYTES


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM under *key*.

    Parameters
    ----------
    plaintext:
        Raw bytes to encrypt.  Must be non-empty.
    key:
        32-byte (256-bit) symmetric key.

    Returns
    -------
    bytes
        Packed blob: ``tag (16 B) || iv (12 B) || ciphertext``.
        All three components are needed for decryption.

    Raises
    ------
    ValueError
        If *key* is not exactly 32 bytes.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)} bytes")

    iv  = os.urandom(AES_IV_BYTES)
    aes = AESGCM(key)

    # AESGCM.encrypt returns ciphertext || tag (tag appended by the library)
    ciphertext_with_tag: bytes = aes.encrypt(iv, plaintext, associated_data=None)

    # Split so we can store tag first for early-rejection on read
    ciphertext = ciphertext_with_tag[:-AES_TAG_BYTES]
    tag        = ciphertext_with_tag[-AES_TAG_BYTES:]

    return tag + iv + ciphertext


def decrypt(blob: bytes, key: bytes) -> bytes:
    """
    Decrypt *blob* produced by :func:`encrypt`.

    The authentication tag is verified before any plaintext bytes are
    returned.  If the tag is invalid — indicating tampering or key mismatch —
    ``cryptography.exceptions.InvalidTag`` is raised and no plaintext is
    released.

    Parameters
    ----------
    blob:
        Packed blob: ``tag (16 B) || iv (12 B) || ciphertext``.
    key:
        32-byte (256-bit) symmetric key.

    Returns
    -------
    bytes
        Recovered plaintext.

    Raises
    ------
    ValueError
        If *blob* is too short to contain the minimum framing.
    cryptography.exceptions.InvalidTag
        If decryption or authentication fails (tampered data / wrong key).
    """
    min_len = AES_TAG_BYTES + AES_IV_BYTES
    if len(blob) < min_len:
        raise ValueError(
            f"Ciphertext blob is too short: expected at least {min_len} bytes, "
            f"got {len(blob)}"
        )

    tag        = blob[:AES_TAG_BYTES]
    iv         = blob[AES_TAG_BYTES : AES_TAG_BYTES + AES_IV_BYTES]
    ciphertext = blob[AES_TAG_BYTES + AES_IV_BYTES :]

    aes = AESGCM(key)
    # Re-assemble in the order the library expects: ciphertext || tag
    return aes.decrypt(iv, ciphertext + tag, associated_data=None)
