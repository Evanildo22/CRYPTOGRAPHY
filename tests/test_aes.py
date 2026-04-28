"""
tests/test_aes.py — AES-256-GCM encrypt / decrypt unit tests.

Coverage:
  * Round-trip: decryption inverts encryption
  * Wrong key: InvalidTag raised
  * Tampered ciphertext: InvalidTag raised (body modification)
  * Tampered tag: InvalidTag raised (first-16-byte modification)
  * Tampered IV: InvalidTag raised
  * Short blob: ValueError raised before any decryption attempt
  * Key length validation: ValueError on wrong key sizes

Benchmarks (run with -m benchmark, skipped by default):
  * Encrypt + decrypt throughput for 1 MiB, 10 MiB, and 100 MiB payloads
  * Reports MB/s for each direction so results are hardware-independent
"""

import os
import time
import pytest
from cryptography.exceptions import InvalidTag

from crypto.aes import encrypt, decrypt
from config import AES_TAG_BYTES, AES_IV_BYTES


PLAINTEXT = b"The quick brown fox jumps over the lazy dog."
KEY_32    = os.urandom(32)


class TestEncryptDecryptRoundTrip:
    def test_basic_roundtrip(self):
        blob      = encrypt(PLAINTEXT, KEY_32)
        recovered = decrypt(blob, KEY_32)
        assert recovered == PLAINTEXT

    def test_empty_plaintext(self):
        """GCM should handle zero-length plaintext (produces tag + iv only)."""
        blob      = encrypt(b"", KEY_32)
        recovered = decrypt(blob, KEY_32)
        assert recovered == b""

    def test_large_plaintext(self):
        large     = os.urandom(1024 * 1024)   # 1 MiB
        key       = os.urandom(32)
        blob      = encrypt(large, key)
        recovered = decrypt(blob, key)
        assert recovered == large

    def test_different_ivs_per_call(self):
        """Each encrypt call must produce a unique IV (probabilistic)."""
        blob1 = encrypt(PLAINTEXT, KEY_32)
        blob2 = encrypt(PLAINTEXT, KEY_32)
        iv1   = blob1[AES_TAG_BYTES : AES_TAG_BYTES + AES_IV_BYTES]
        iv2   = blob2[AES_TAG_BYTES : AES_TAG_BYTES + AES_IV_BYTES]
        assert iv1 != iv2, "Two encrypt calls produced the same IV (CSPRNG failure)"

    def test_ciphertext_differs_from_plaintext(self):
        blob = encrypt(PLAINTEXT, KEY_32)
        body = blob[AES_TAG_BYTES + AES_IV_BYTES :]
        assert body != PLAINTEXT


class TestTamperDetection:
    def test_tampered_ciphertext_body_raises(self):
        blob = bytearray(encrypt(PLAINTEXT, KEY_32))
        # Flip a bit in the ciphertext body
        blob[-1] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt(bytes(blob), KEY_32)

    def test_tampered_tag_raises(self):
        blob = bytearray(encrypt(PLAINTEXT, KEY_32))
        blob[0] ^= 0x01   # flip bit in tag
        with pytest.raises(InvalidTag):
            decrypt(bytes(blob), KEY_32)

    def test_tampered_iv_raises(self):
        blob = bytearray(encrypt(PLAINTEXT, KEY_32))
        blob[AES_TAG_BYTES] ^= 0x80   # flip bit in IV
        with pytest.raises(InvalidTag):
            decrypt(bytes(blob), KEY_32)

    def test_wrong_key_raises(self):
        blob      = encrypt(PLAINTEXT, KEY_32)
        wrong_key = os.urandom(32)
        with pytest.raises(InvalidTag):
            decrypt(blob, wrong_key)

    def test_truncated_blob_raises_value_error(self):
        with pytest.raises(ValueError, match="too short"):
            decrypt(b"\x00" * 5, KEY_32)

    def test_bit_flip_in_any_byte_detected(self):
        """Flip every byte in the blob one at a time; each must raise InvalidTag."""
        blob = encrypt(b"sensitive data", KEY_32)
        for i in range(len(blob)):
            tampered = bytearray(blob)
            tampered[i] ^= 0x55
            with pytest.raises((InvalidTag, ValueError)):
                decrypt(bytes(tampered), KEY_32)


class TestKeyValidation:
    def test_short_key_raises(self):
        with pytest.raises(ValueError, match="32-byte"):
            encrypt(PLAINTEXT, b"short")

    def test_long_key_raises(self):
        with pytest.raises(ValueError, match="32-byte"):
            encrypt(PLAINTEXT, b"a" * 33)


# ---------------------------------------------------------------------------
# Benchmarks
#
# Skipped during normal `pytest` runs — only execute with `-m benchmark`:
#   pytest tests/test_aes.py -m benchmark -v -s
#
# Each case warms up with one un-timed call (avoids measuring lazy imports /
# first-call JIT effects), then runs REPEATS timed iterations and reports the
# median throughput in MB/s.  Median is used rather than mean because a single
# OS scheduling interruption can skew averages significantly.
# ---------------------------------------------------------------------------

BENCHMARK_SIZES = [
    ("1 MiB",   1 * 1024 * 1024),
    ("10 MiB", 10 * 1024 * 1024),
    ("100 MiB", 100 * 1024 * 1024),
]

REPEATS = 5   # median over 5 runs per size/direction


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def _bench_encrypt(data: bytes, key: bytes) -> float:
    """Return encrypt throughput in MB/s (median over REPEATS)."""
    # Warm-up: exclude first call from timing
    encrypt(data, key)

    times = []
    for _ in range(REPEATS):
        t0 = time.perf_counter()
        encrypt(data, key)
        times.append(time.perf_counter() - t0)

    mb = len(data) / (1024 * 1024)
    return mb / _median(times)


def _bench_decrypt(data: bytes, key: bytes) -> float:
    """Return decrypt throughput in MB/s (median over REPEATS).

    Pre-encrypts data once outside the timed loop so we measure only the
    decrypt path, not encrypt overhead.
    """
    blob = encrypt(data, key)
    # Warm-up
    decrypt(blob, key)

    times = []
    for _ in range(REPEATS):
        t0 = time.perf_counter()
        decrypt(blob, key)
        times.append(time.perf_counter() - t0)

    mb = len(data) / (1024 * 1024)
    return mb / _median(times)


@pytest.mark.benchmark
class TestAesThroughput:
    """
    AES-256-GCM throughput benchmarks.

    Run with:
        pytest tests/test_aes.py -m benchmark -v -s

    Expected ballpark on modern hardware (CPython 3.11, software AES):
        1 MiB   ~400–800 MB/s
        10 MiB  ~400–800 MB/s
        100 MiB ~400–800 MB/s
    AES-NI hardware acceleration (most x86-64 CPUs since 2010) means
    throughput is roughly flat across sizes — the per-call overhead
    (IV generation, tag computation) is small relative to data volume.
    """

    @pytest.mark.parametrize("label,size", BENCHMARK_SIZES)
    def test_encrypt_throughput(self, label: str, size: int, capsys):
        key  = os.urandom(32)
        data = os.urandom(size)

        mbps = _bench_encrypt(data, key)

        with capsys.disabled():
            print(f"\n  encrypt  {label:>8}  {mbps:>8.1f} MB/s  "
                  f"(median of {REPEATS} runs)")

        # Sanity floor: fail loudly if something is catastrophically wrong.
        # 10 MB/s is ~40× slower than any modern CPU with AES-NI; if we're
        # below this, the implementation is broken rather than merely slow.
        assert mbps > 10, (
            f"encrypt throughput {mbps:.1f} MB/s is below the 10 MB/s sanity floor"
        )

    @pytest.mark.parametrize("label,size", BENCHMARK_SIZES)
    def test_decrypt_throughput(self, label: str, size: int, capsys):
        key  = os.urandom(32)
        data = os.urandom(size)

        mbps = _bench_decrypt(data, key)

        with capsys.disabled():
            print(f"\n  decrypt  {label:>8}  {mbps:>8.1f} MB/s  "
                  f"(median of {REPEATS} runs)")

        assert mbps > 10, (
            f"decrypt throughput {mbps:.1f} MB/s is below the 10 MB/s sanity floor"
        )
