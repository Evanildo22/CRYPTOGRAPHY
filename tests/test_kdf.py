"""
tests/test_kdf.py — PBKDF2-HMAC-SHA256 key derivation.

Coverage:
  * Output is 32 bytes
  * Same password + salt → same key (determinism)
  * Different salts → different keys
  * Different passwords → different keys
  * Auto-generated salt is 16 bytes and unique per call
  * String and bytes passwords produce the same result
  * Empty password is accepted (weak but not an error)
"""

import os
import pytest

from crypto.kdf import derive_key
from config import PBKDF2_SALT_BYTES, PBKDF2_KEY_BYTES


class TestOutputProperties:
    def test_key_length(self):
        key, _ = derive_key("password")
        assert len(key) == PBKDF2_KEY_BYTES

    def test_salt_length_when_auto_generated(self):
        _, salt = derive_key("password")
        assert len(salt) == PBKDF2_SALT_BYTES

    def test_returns_tuple(self):
        result = derive_key("password")
        assert isinstance(result, tuple) and len(result) == 2


class TestDeterminism:
    def test_same_password_same_salt_same_key(self):
        key1, _    = derive_key("secret", salt=b"A" * 16)
        key2, _    = derive_key("secret", salt=b"A" * 16)
        assert key1 == key2

    def test_reproduced_from_stored_salt(self):
        key1, salt = derive_key("my-password")
        key2, _    = derive_key("my-password", salt=salt)
        assert key1 == key2


class TestUniqueness:
    def test_different_salts_produce_different_keys(self):
        key1, _ = derive_key("password", salt=b"\x00" * 16)
        key2, _ = derive_key("password", salt=b"\xFF" * 16)
        assert key1 != key2

    def test_auto_salts_are_unique(self):
        _, salt1 = derive_key("password")
        _, salt2 = derive_key("password")
        assert salt1 != salt2   # probabilistic; astronomically unlikely to collide

    def test_different_passwords_produce_different_keys(self):
        salt     = os.urandom(16)
        key1, _  = derive_key("password1", salt=salt)
        key2, _  = derive_key("password2", salt=salt)
        assert key1 != key2


class TestInputHandling:
    def test_string_and_bytes_password_equivalent(self):
        salt    = os.urandom(16)
        key_str, _ = derive_key("hello", salt=salt)
        key_bytes, _ = derive_key(b"hello", salt=salt)
        assert key_str == key_bytes

    def test_empty_password_accepted(self):
        key, salt = derive_key("")
        assert len(key) == PBKDF2_KEY_BYTES
        assert len(salt) == PBKDF2_SALT_BYTES

    def test_unicode_password(self):
        key, _ = derive_key("p\u00e4ssw\u00f6rd\u00df")   # German characters
        assert len(key) == PBKDF2_KEY_BYTES
