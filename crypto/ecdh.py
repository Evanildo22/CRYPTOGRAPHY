"""
crypto/ecdh.py — Elliptic-curve Diffie-Hellman (ECDH) key exchange on P-256
with HKDF-SHA256 key derivation.

Design decisions
----------------
* P-256 (NIST secp256r1) is the most widely deployed EC curve and is
  supported by every modern TLS library.  X25519 would be a stronger choice
  for new designs (faster, simpler, better side-channel profile) but P-256
  maximises compatibility for a demonstration system.
* HKDF (RFC 5869) post-processes the ECDH shared secret before use.  The
  raw ECDH output is a curve point's x-coordinate, which is not uniformly
  random.  HKDF extracts and expands it into a proper pseudorandom key.
* The HKDF ``info`` parameter is a domain-separation label.  Binding it to
  this application prevents a key derived here from being reused in a
  different context even if the same shared secret appears (e.g. cross-
  protocol attacks).
* This module is stateless — it operates on keys passed in and returns
  derived key material.  Ephemeral key *lifecycle* (creation, zeroisation,
  no-disk-write guarantee) is the responsibility of pfs.py.
"""

import os
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
    SECP256R1,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from config import HKDF_INFO, HKDF_DERIVED_BYTES


def generate_ec_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """
    Generate a fresh P-256 (secp256r1) keypair using a CSPRNG.

    Returns
    -------
    tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]
        ``(private_key, public_key)``
    """
    private_key: EllipticCurvePrivateKey = generate_private_key(SECP256R1())
    return private_key, private_key.public_key()


def derive_shared_key(
    private_key: EllipticCurvePrivateKey,
    peer_public_key: EllipticCurvePublicKey,
    salt: bytes | None = None,
) -> bytes:
    """
    Perform ECDH and derive a 256-bit AES session key via HKDF-SHA256.

    Parameters
    ----------
    private_key:
        Caller's EC private key (ephemeral on the sender side, static on
        the recipient side).
    peer_public_key:
        Peer's EC public key (static on the sender side, ephemeral on the
        recipient side — both sides use the same two keys, just swapped).
    salt:
        Optional HKDF salt.  If ``None``, HKDF uses a zero-filled salt of
        hash length, which is still secure; an explicit salt adds entropy
        if available.

    Returns
    -------
    bytes
        32-byte pseudorandom AES session key.
    """
    # ECDH exchange — raw_shared is the x-coordinate of the shared point
    raw_shared: bytes = private_key.exchange(ECDH(), peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_DERIVED_BYTES,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(raw_shared)


def ec_public_key_to_pem(public_key: EllipticCurvePublicKey) -> bytes:
    """Serialise an EC public key to SubjectPublicKeyInfo PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def ec_private_key_to_pem(private_key: EllipticCurvePrivateKey) -> bytes:
    """Serialise an EC private key to PKCS#8 PEM (unencrypted)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_ec_public_key(pem: bytes) -> EllipticCurvePublicKey:
    """Deserialise a SubjectPublicKeyInfo PEM EC public key."""
    return serialization.load_pem_public_key(pem)  # type: ignore[return-value]


def load_ec_private_key(pem: bytes) -> EllipticCurvePrivateKey:
    """Deserialise a PKCS#8 PEM EC private key."""
    return serialization.load_pem_private_key(pem, password=None)  # type: ignore[return-value]
