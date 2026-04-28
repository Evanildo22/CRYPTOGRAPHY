"""
tests/test_rsa.py — RSA keypair generation, OAEP wrap / unwrap, PEM serialisation.

Coverage:
  * Keypair generation produces distinct keys
  * PEM round-trip: serialise → deserialise
  * Key wrap / unwrap round-trip: recovered session key equals original
  * Wrong private key: unwrap raises
  * Tampered wrapped key: unwrap raises
  * Key size: generated key is RSA-2048
"""

import os
import pytest

from crypto.rsa_keys import (
    generate_keypair,
    private_key_to_pem,
    public_key_to_pem,
    load_private_key,
    load_public_key,
    wrap_key,
    unwrap_key,
)
from config import RSA_KEY_SIZE_BITS


@pytest.fixture(scope="module")
def rsa_keypair():
    return generate_keypair()


class TestKeypairGeneration:
    def test_generates_rsa_2048(self, rsa_keypair):
        priv, _ = rsa_keypair
        assert priv.key_size == RSA_KEY_SIZE_BITS

    def test_two_keypairs_are_distinct(self):
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        assert public_key_to_pem(pub1) != public_key_to_pem(pub2)


class TestPemRoundTrip:
    def test_private_key_pem_roundtrip(self, rsa_keypair):
        priv, _ = rsa_keypair
        pem      = private_key_to_pem(priv)
        restored = load_private_key(pem)
        assert restored.key_size == priv.key_size
        assert private_key_to_pem(restored) == pem

    def test_public_key_pem_roundtrip(self, rsa_keypair):
        _, pub   = rsa_keypair
        pem      = public_key_to_pem(pub)
        restored = load_public_key(pem)
        assert public_key_to_pem(restored) == pem

    def test_private_pem_contains_header(self, rsa_keypair):
        priv, _ = rsa_keypair
        pem      = private_key_to_pem(priv)
        assert b"BEGIN PRIVATE KEY" in pem

    def test_public_pem_contains_header(self, rsa_keypair):
        _, pub = rsa_keypair
        pem    = public_key_to_pem(pub)
        assert b"BEGIN PUBLIC KEY" in pem


class TestOaepWrapUnwrap:
    def test_roundtrip(self, rsa_keypair):
        priv, pub   = rsa_keypair
        session_key = os.urandom(32)
        wrapped     = wrap_key(session_key, pub)
        recovered   = unwrap_key(wrapped, priv)
        assert recovered == session_key

    def test_wrap_is_non_deterministic(self, rsa_keypair):
        """OAEP is probabilistic; two wrappings of the same key must differ."""
        _, pub      = rsa_keypair
        session_key = os.urandom(32)
        assert wrap_key(session_key, pub) != wrap_key(session_key, pub)

    def test_wrong_private_key_raises(self, rsa_keypair):
        _, pub      = rsa_keypair
        session_key = os.urandom(32)
        wrapped     = wrap_key(session_key, pub)

        wrong_priv, _ = generate_keypair()
        with pytest.raises(Exception):
            unwrap_key(wrapped, wrong_priv)

    def test_tampered_wrapped_key_raises(self, rsa_keypair):
        priv, pub   = rsa_keypair
        session_key = os.urandom(32)
        wrapped     = bytearray(wrap_key(session_key, pub))
        wrapped[10] ^= 0xFF
        with pytest.raises(Exception):
            unwrap_key(bytes(wrapped), priv)

    def test_wrapped_output_length(self, rsa_keypair):
        """RSA-2048 OAEP output is always exactly 256 bytes."""
        _, pub      = rsa_keypair
        session_key = os.urandom(32)
        wrapped     = wrap_key(session_key, pub)
        assert len(wrapped) == RSA_KEY_SIZE_BITS // 8
