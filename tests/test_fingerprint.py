"""
tests/test_fingerprint.py — SHA-256 plaintext fingerprint compute / verify.

Coverage:
  * compute returns 64-char hex string
  * compute is deterministic
  * compute is sensitive to byte-level changes
  * verify returns True for matching digest
  * verify returns False for mismatched digest (corrupted plaintext)
  * verify is case-insensitive on the hex string
  * known-vector: SHA-256("") == e3b0c44...
"""

import pytest

from crypto.fingerprint import compute, verify


class TestCompute:
    def test_returns_hex_string(self):
        fp = compute(b"hello")
        assert isinstance(fp, str)

    def test_hex_length(self):
        fp = compute(b"hello world")
        assert len(fp) == 64

    def test_is_lowercase_hex(self):
        fp = compute(b"test")
        assert fp == fp.lower()
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        data = b"deterministic data"
        assert compute(data) == compute(data)

    def test_sensitive_to_single_bit_flip(self):
        data    = b"original"
        flipped = bytearray(data)
        flipped[0] ^= 0x01
        assert compute(data) != compute(bytes(flipped))

    def test_empty_bytes_known_vector(self):
        """SHA-256('') == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert compute(b"") == expected

    def test_known_vector_hello(self):
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assert compute(b"hello") == expected


class TestVerify:
    def test_returns_true_for_correct_digest(self):
        data = b"file contents"
        fp   = compute(data)
        assert verify(data, fp) is True

    def test_returns_false_for_tampered_data(self):
        data    = b"original file"
        fp      = compute(data)
        tampered = data + b"\x00"
        assert verify(tampered, fp) is False

    def test_returns_false_for_wrong_digest(self):
        data = b"some data"
        assert verify(data, "a" * 64) is False

    def test_case_insensitive_comparison(self):
        data = b"case test"
        fp   = compute(data).upper()   # uppercase hex
        assert verify(data, fp) is True

    def test_returns_false_for_single_byte_change(self):
        data    = b"important document"
        fp      = compute(data)
        altered = bytearray(data)
        altered[-1] ^= 0x80
        assert verify(bytes(altered), fp) is False
