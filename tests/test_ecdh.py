"""
tests/test_ecdh.py — ECDH P-256 key exchange and HKDF derivation.

Coverage:
  * Shared secret derivation: both sides compute the same key
  * Cross-key: different key pairs produce different shared secrets
  * HKDF output length: exactly 32 bytes
  * HKDF is deterministic for same inputs
  * PEM round-trip for EC public and private keys
  * Different salts produce different derived keys
"""

import os
import pytest

from crypto.ecdh import (
    generate_ec_keypair,
    derive_shared_key,
    ec_public_key_to_pem,
    ec_private_key_to_pem,
    load_ec_public_key,
    load_ec_private_key,
)
from config import HKDF_DERIVED_BYTES


@pytest.fixture(scope="module")
def alice():
    return generate_ec_keypair()


@pytest.fixture(scope="module")
def bob():
    return generate_ec_keypair()


class TestSharedSecretDerivation:
    def test_both_sides_agree(self, alice, bob):
        """Alice uses her private key + Bob's public key; Bob does the reverse."""
        alice_priv, alice_pub = alice
        bob_priv,   bob_pub   = bob

        key_a = derive_shared_key(alice_priv, bob_pub)
        key_b = derive_shared_key(bob_priv,   alice_pub)
        assert key_a == key_b

    def test_output_length(self, alice, bob):
        alice_priv, _ = alice
        _, bob_pub    = bob
        key = derive_shared_key(alice_priv, bob_pub)
        assert len(key) == HKDF_DERIVED_BYTES

    def test_different_keypairs_produce_different_secrets(self, alice, bob):
        alice_priv, _ = alice
        _, bob_pub    = bob

        eve_priv, eve_pub = generate_ec_keypair()
        key_ab = derive_shared_key(alice_priv, bob_pub)
        key_ae = derive_shared_key(alice_priv, eve_pub)
        assert key_ab != key_ae

    def test_deterministic_for_same_inputs(self, alice, bob):
        alice_priv, _ = alice
        _, bob_pub    = bob
        salt = os.urandom(16)
        key1 = derive_shared_key(alice_priv, bob_pub, salt=salt)
        key2 = derive_shared_key(alice_priv, bob_pub, salt=salt)
        assert key1 == key2

    def test_different_salts_produce_different_keys(self, alice, bob):
        alice_priv, _ = alice
        _, bob_pub    = bob
        key1 = derive_shared_key(alice_priv, bob_pub, salt=b"salt1")
        key2 = derive_shared_key(alice_priv, bob_pub, salt=b"salt2")
        assert key1 != key2


class TestPemRoundTrip:
    def test_public_key_pem_roundtrip(self, alice):
        _, pub   = alice
        pem      = ec_public_key_to_pem(pub)
        restored = load_ec_public_key(pem)
        assert ec_public_key_to_pem(restored) == pem

    def test_private_key_pem_roundtrip(self, alice):
        priv, _  = alice
        pem      = ec_private_key_to_pem(priv)
        restored = load_ec_private_key(pem)
        assert ec_private_key_to_pem(restored) == pem

    def test_public_pem_header(self, alice):
        _, pub = alice
        pem    = ec_public_key_to_pem(pub)
        assert b"BEGIN PUBLIC KEY" in pem

    def test_keypairs_are_distinct(self):
        _, pub1 = generate_ec_keypair()
        _, pub2 = generate_ec_keypair()
        assert ec_public_key_to_pem(pub1) != ec_public_key_to_pem(pub2)
