"""
crypto/signatures.py — RSA-PSS digital signatures over ciphertext.

Design decisions
----------------
* Signatures are computed over the *ciphertext*, not the plaintext.  This
  follows the "sign-then-encrypt" ordering recommended by Bellare & Namprempre
  (2000): the signature covers exactly what is stored and transmitted,
  binding the uploader's identity to the specific encrypted blob.
* RSA-PSS (Probabilistic Signature Scheme) is used instead of PKCS#1 v1.5
  signatures.  PKCS#1 v1.5 signing has known forgery vulnerabilities in
  certain multi-prime and small-exponent configurations; PSS has a tight
  security proof under the random-oracle model.
* Salt length is set to PSS.MAX_LENGTH (equivalent to ``hLen`` — the hash
  output length, 32 bytes for SHA-256).  Using the maximum salt length
  maximises the security margin: a longer salt means the PSS output is
  more strongly randomised, making it harder to distinguish valid signatures
  from random strings without the public key.
* Verification is the *first* operation performed on download — before any
  decryption attempt.  This ensures the file's provenance is established
  before any potentially malleable ciphertext is passed to the AES layer.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def sign_ciphertext(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Sign *ciphertext* with *private_key* using RSA-PSS-SHA-256.

    Parameters
    ----------
    ciphertext:
        The encrypted blob to authenticate (output of ``aes.encrypt``).
    private_key:
        Uploader's RSA-2048 private key.

    Returns
    -------
    bytes
        DER-encoded RSA-PSS signature (256 bytes for RSA-2048).
    """
    return private_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            # MAX_LENGTH sets salt to hLen (32 bytes for SHA-256).
            # This is the maximum meaningful salt size and provides the
            # strongest security bound for RSA-PSS.
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_ciphertext(
    ciphertext: bytes,
    signature: bytes,
    public_key: RSAPublicKey,
) -> None:
    """
    Verify *signature* over *ciphertext* using *public_key*.

    Parameters
    ----------
    ciphertext:
        The encrypted blob to verify.
    signature:
        Signature bytes returned by :func:`sign_ciphertext`.
    public_key:
        Uploader's RSA-2048 public key.

    Returns
    -------
    None
        Returns silently if the signature is valid.

    Raises
    ------
    cryptography.exceptions.InvalidSignature
        If the signature is invalid — either the ciphertext was tampered
        with, the wrong public key is used, or the signature is corrupted.
        The caller must treat this as a fatal error and abort the request.
    """
    public_key.verify(
        signature,
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
