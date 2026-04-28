"""
crypto/rsa_keys.py — RSA-2048 keypair generation, OAEP key-wrap / unwrap,
and PEM serialisation.

Design decisions
----------------
* OAEP with SHA-256 and MGF1-SHA-256 is used exclusively.  PKCS#1 v1.5
  padding is explicitly *not* used: it is vulnerable to Bleichenbacher's
  adaptive chosen-ciphertext attack (CCA2).  OAEP provides CCA2 security
  under the random-oracle model.
* Key size is 2048 bits — the NIST SP 800-131A minimum through 2030.
  3072 bits would extend the horizon but is rarely required for a
  demonstration system.
* RSA is used only for *key transport* (wrapping the short AES session key).
  Encrypting file data directly with RSA would be slower, limited by block
  size, and semantically fragile.  The hybrid model (RSA wraps AES key,
  AES encrypts data) is the standard for all TLS, PGP, and CMS-based systems.
* Private keys are serialised without encryption (NoEncryption()) because
  the calling layer (kdf.py + the upload flow) handles key protection via
  the PBKDF2-derived KEK separately.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from config import RSA_KEY_SIZE_BITS


def generate_keypair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generate a fresh RSA-2048 keypair using a CSPRNG.

    Returns
    -------
    tuple[RSAPrivateKey, RSAPublicKey]
        ``(private_key, public_key)``
    """
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE_BITS,
    )
    return private_key, private_key.public_key()


def private_key_to_pem(private_key: RSAPrivateKey) -> bytes:
    """Serialise *private_key* to PKCS#8 PEM (unencrypted)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: RSAPublicKey) -> bytes:
    """Serialise *public_key* to SubjectPublicKeyInfo PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes) -> RSAPrivateKey:
    """Deserialise an unencrypted PKCS#8 PEM private key."""
    return serialization.load_pem_private_key(pem, password=None)  # type: ignore[return-value]


def load_public_key(pem: bytes) -> RSAPublicKey:
    """Deserialise a SubjectPublicKeyInfo PEM public key."""
    return serialization.load_pem_public_key(pem)  # type: ignore[return-value]


def _oaep_padding() -> padding.OAEP:
    """
    Return a pre-configured OAEP padding object.

    SHA-256 is used for both the main hash and MGF1 mask generation.
    Using the same digest for both is consistent with RFC 8017 and avoids
    subtle implementation differences when the two hashes differ.
    """
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_key(session_key: bytes, recipient_public_key: RSAPublicKey) -> bytes:
    """
    Encrypt (wrap) *session_key* with *recipient_public_key* using RSA-OAEP.

    Parameters
    ----------
    session_key:
        The AES session key bytes to protect (typically 32 bytes).
    recipient_public_key:
        Recipient's RSA-2048 public key.

    Returns
    -------
    bytes
        Ciphertext wrapping of the session key (256 bytes for RSA-2048).
    """
    return recipient_public_key.encrypt(session_key, _oaep_padding())


def unwrap_key(wrapped_key: bytes, recipient_private_key: RSAPrivateKey) -> bytes:
    """
    Decrypt (unwrap) a key previously wrapped by :func:`wrap_key`.

    Parameters
    ----------
    wrapped_key:
        Bytes returned by :func:`wrap_key`.
    recipient_private_key:
        Matching RSA private key.

    Returns
    -------
    bytes
        Recovered plaintext session key.

    Raises
    ------
    ValueError
        If decryption fails (wrong key or corrupted wrapping).
    """
    return recipient_private_key.decrypt(wrapped_key, _oaep_padding())
