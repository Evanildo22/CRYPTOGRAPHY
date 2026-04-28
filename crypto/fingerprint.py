"""
crypto/fingerprint.py — SHA-256 plaintext integrity fingerprinting.

Design decisions
----------------
* The fingerprint is computed over the *plaintext* before encryption.
  This lets the recipient independently verify the recovered file after
  decryption — if the fingerprint matches, the file is byte-for-byte
  identical to what was uploaded.
* SHA-256 is collision-resistant under current cryptanalysis.  A
  collision attack would require an adversary to find two plaintexts with
  the same digest — computationally infeasible with 2^128 expected work.
* The fingerprint is stored as a lowercase hex string in a ``.sha256``
  file alongside the ciphertext.  This format is compatible with the
  standard ``sha256sum`` command-line tool, allowing out-of-band
  verification without this application.
* Fingerprint verification is performed *after* AES-GCM decryption
  succeeds.  GCM already guarantees ciphertext integrity; the plaintext
  fingerprint provides an additional, independently verifiable commitment
  that can be shared with the recipient before the file is transmitted.
"""

import hashlib


def compute(plaintext: bytes) -> str:
    """
    Compute the SHA-256 digest of *plaintext* and return it as a lowercase
    hex string.

    Parameters
    ----------
    plaintext:
        Raw file bytes before encryption.

    Returns
    -------
    str
        64-character lowercase hex digest (e.g. ``"a3f1...b2c9"``).
    """
    return hashlib.sha256(plaintext).hexdigest()


def verify(plaintext: bytes, expected_hex: str) -> bool:
    """
    Recompute the SHA-256 digest of *plaintext* and compare it to
    *expected_hex*.

    Parameters
    ----------
    plaintext:
        Decrypted file bytes.
    expected_hex:
        Hex digest stored at upload time (output of :func:`compute`).

    Returns
    -------
    bool
        ``True`` if the digest matches, ``False`` if there is a mismatch.
        A ``False`` return indicates the recovered plaintext differs from
        what was originally uploaded — the caller should surface this to
        the user as a warning.

    Notes
    -----
    Uses ``hmac.compare_digest`` internally to perform a constant-time
    comparison and avoid timing oracle attacks, even though SHA-256 digests
    are not secret values.
    """
    import hmac
    actual_hex = compute(plaintext)
    return hmac.compare_digest(actual_hex.lower(), expected_hex.lower())
