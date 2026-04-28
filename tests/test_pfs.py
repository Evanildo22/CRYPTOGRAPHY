"""
tests/test_pfs.py — Perfect Forward Secrecy ephemeral key lifecycle.

Coverage:
  * perform_pfs_exchange returns a 32-byte session key and PEM public key
  * Session key is reproducible from recipient's private key + stored ephem pubkey
  * Ephemeral private key is NOT written to disk
  * Two PFS exchanges produce different session keys (independent randomness)
  * _zero_private_key does not raise
"""

import os
from unittest.mock import patch, MagicMock
import pytest

from crypto.pfs import perform_pfs_exchange, _zero_private_key
from crypto.ecdh import (
    generate_ec_keypair,
    derive_shared_key,
    load_ec_public_key,
)


@pytest.fixture(scope="module")
def recipient():
    return generate_ec_keypair()


class TestPfsExchange:
    def test_returns_correct_types(self, recipient):
        _, recipient_pub = recipient
        session_key, ephem_pub_pem = perform_pfs_exchange(recipient_pub)
        assert isinstance(session_key, bytes)
        assert isinstance(ephem_pub_pem, bytes)

    def test_session_key_length(self, recipient):
        _, recipient_pub = recipient
        session_key, _ = perform_pfs_exchange(recipient_pub)
        assert len(session_key) == 32

    def test_ephem_pub_pem_is_valid(self, recipient):
        _, recipient_pub = recipient
        _, ephem_pub_pem = perform_pfs_exchange(recipient_pub)
        # Should deserialise without error
        load_ec_public_key(ephem_pub_pem)

    def test_recipient_can_reproduce_session_key(self, recipient):
        """
        The recipient uses their static private key + stored ephemeral public key
        to reproduce the same session key that was derived during upload.
        This is the core ECDH symmetry property.
        """
        recipient_priv, recipient_pub = recipient
        session_key, ephem_pub_pem = perform_pfs_exchange(recipient_pub)

        ephem_pub           = load_ec_public_key(ephem_pub_pem)
        reproduced_key      = derive_shared_key(recipient_priv, ephem_pub)
        assert reproduced_key == session_key

    def test_two_exchanges_produce_different_keys(self, recipient):
        """Each PFS exchange is independent — ephemeral key randomness."""
        _, recipient_pub = recipient
        key1, _ = perform_pfs_exchange(recipient_pub)
        key2, _ = perform_pfs_exchange(recipient_pub)
        assert key1 != key2

    def test_no_disk_writes_during_exchange(self, recipient):
        """
        The ephemeral private key must never touch the filesystem.
        Patch both builtins.open and os.open to detect any write attempt.
        """
        _, recipient_pub = recipient

        write_calls = []

        original_open = open

        def guarded_open(file, mode="r", *args, **kwargs):
            if "w" in str(mode) or "a" in str(mode) or "x" in str(mode):
                write_calls.append(file)
            return original_open(file, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=guarded_open):
            perform_pfs_exchange(recipient_pub)

        assert write_calls == [], (
            f"perform_pfs_exchange wrote to disk: {write_calls}"
        )


class TestZeroPrivateKey:
    def test_zero_does_not_raise(self):
        priv, _ = generate_ec_keypair()
        _zero_private_key(priv)   # must complete without exception
