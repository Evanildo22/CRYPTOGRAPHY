"""
tests/test_signatures.py — RSA-PSS sign / verify over ciphertext.

Coverage:
  * Valid signature verifies without exception
  * Tampered ciphertext fails verification
  * Wrong public key fails verification
  * Signature is non-deterministic (PSS is randomised)
  * Truncated / empty signature raises
  * Signature is performed on ciphertext bytes (not plaintext)
"""

import os
import pytest
from cryptography.exceptions import InvalidSignature

from crypto.signatures import sign_ciphertext, verify_ciphertext
from crypto.rsa_keys import generate_keypair


@pytest.fixture(scope="module")
def signer():
    return generate_keypair()


CIPHERTEXT = os.urandom(256)   # arbitrary bytes representing encrypted data


class TestSignVerifyRoundTrip:
    def test_valid_signature_passes(self, signer):
        priv, pub = signer
        sig = sign_ciphertext(CIPHERTEXT, priv)
        verify_ciphertext(CIPHERTEXT, sig, pub)   # must not raise

    def test_verify_returns_none_on_success(self, signer):
        priv, pub = signer
        sig    = sign_ciphertext(CIPHERTEXT, priv)
        result = verify_ciphertext(CIPHERTEXT, sig, pub)
        assert result is None

    def test_pss_is_non_deterministic(self, signer):
        """PSS randomises the salt; two signatures of the same data must differ."""
        priv, _ = signer
        sig1 = sign_ciphertext(CIPHERTEXT, priv)
        sig2 = sign_ciphertext(CIPHERTEXT, priv)
        assert sig1 != sig2

    def test_signature_length(self, signer):
        """RSA-2048 signatures are always exactly 256 bytes."""
        priv, _ = signer
        sig = sign_ciphertext(CIPHERTEXT, priv)
        assert len(sig) == 256


class TestTamperedCiphertextRejection:
    def test_byte_flip_in_body_aborts(self, signer):
        priv, pub  = signer
        sig        = sign_ciphertext(CIPHERTEXT, priv)
        tampered   = bytearray(CIPHERTEXT)
        tampered[0] ^= 0x01
        with pytest.raises(InvalidSignature):
            verify_ciphertext(bytes(tampered), sig, pub)

    def test_extra_byte_appended_aborts(self, signer):
        priv, pub = signer
        sig       = sign_ciphertext(CIPHERTEXT, priv)
        with pytest.raises(InvalidSignature):
            verify_ciphertext(CIPHERTEXT + b"\x00", sig, pub)

    def test_truncated_ciphertext_aborts(self, signer):
        priv, pub = signer
        sig       = sign_ciphertext(CIPHERTEXT, priv)
        with pytest.raises(InvalidSignature):
            verify_ciphertext(CIPHERTEXT[:-1], sig, pub)

    def test_wrong_public_key_aborts(self, signer):
        priv, _       = signer
        _, wrong_pub  = generate_keypair()
        sig           = sign_ciphertext(CIPHERTEXT, priv)
        with pytest.raises(InvalidSignature):
            verify_ciphertext(CIPHERTEXT, sig, wrong_pub)

    def test_tampered_signature_aborts(self, signer):
        priv, pub = signer
        sig       = bytearray(sign_ciphertext(CIPHERTEXT, priv))
        sig[0]   ^= 0xFF
        with pytest.raises(InvalidSignature):
            verify_ciphertext(CIPHERTEXT, bytes(sig), pub)

    def test_empty_signature_aborts(self, signer):
        _, pub = signer
        with pytest.raises(Exception):
            verify_ciphertext(CIPHERTEXT, b"", pub)
