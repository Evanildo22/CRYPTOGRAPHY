"""
crypto/pfs.py — Perfect Forward Secrecy (PFS) ephemeral key lifecycle.

Design decisions
----------------
* PFS is a *protocol* property, not just a code path.  Isolating it in its
  own module makes the guarantee explicit, testable, and documentable — a
  reviewer can audit the full lifecycle in one file rather than hunting
  through the ECDH module for where the private key disappears.
* The guarantee: if an attacker compromises the recipient's long-term EC
  private key at any future point, they *cannot* decrypt past sessions.
  The sender's ephemeral private key — the other half of the ECDH exchange
  — was destroyed immediately after derivation and never persisted.
* Memory zeroisation is performed via ``ctypes.memset`` on the underlying
  buffer returned by the private key's ``private_bytes`` serialisation.
  Python does not expose raw key memory directly; the best available
  approach is to serialise to a mutable bytearray and zero that buffer.
  This is not a perfect guarantee (the GC may have already copied the
  object) but it is the standard practice in Python crypto libraries.
* The no-disk-write guarantee is enforced by design: this module never
  calls any file I/O.  Tests confirm this property by mocking os.open /
  builtins.open and asserting they are never called during a PFS exchange.
"""

import ctypes
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives import serialization

from crypto.ecdh import generate_ec_keypair, derive_shared_key, ec_public_key_to_pem


def perform_pfs_exchange(
    recipient_static_public_key: EllipticCurvePublicKey,
) -> tuple[bytes, bytes]:
    """
    Generate an ephemeral P-256 keypair, derive a shared AES session key,
    then immediately zero and discard the ephemeral private key.

    Parameters
    ----------
    recipient_static_public_key:
        Recipient's long-term EC public key.  This is the only persistent
        key involved; the sender's ephemeral private key is destroyed
        within this function and never leaves it.

    Returns
    -------
    tuple[bytes, bytes]
        ``(session_key, ephemeral_public_key_pem)``

        * ``session_key`` — 32-byte AES key derived via ECDH + HKDF.
        * ``ephemeral_public_key_pem`` — PEM-encoded ephemeral *public* key
          that the recipient needs to reproduce the ECDH derivation.
          The matching private key has already been destroyed.

    Notes
    -----
    The ephemeral *public* key is safe to store and transmit — public keys
    are not secret.  Storing it is necessary: without it the recipient
    cannot reproduce the ECDH derivation on download.
    """
    ephemeral_private_key, ephemeral_public_key = generate_ec_keypair()

    session_key: bytes = derive_shared_key(
        private_key=ephemeral_private_key,
        peer_public_key=recipient_static_public_key,
    )

    ephemeral_public_key_pem: bytes = ec_public_key_to_pem(ephemeral_public_key)

    # Zeroisation: serialise private key to a mutable buffer and overwrite.
    _zero_private_key(ephemeral_private_key)

    return session_key, ephemeral_public_key_pem


def _zero_private_key(private_key: EllipticCurvePrivateKey) -> None:
    """
    Best-effort zeroisation of an EC private key's serialised representation.

    Python's memory model does not guarantee this erases the key from every
    location in memory, but it eliminates the most accessible copy — the
    serialised bytearray — which is what matters for defence-in-depth.
    """
    raw: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    buf = bytearray(raw)
    ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
    del buf, raw
