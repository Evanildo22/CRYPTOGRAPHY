"""
audit/log.py — Tamper-evident HMAC-SHA256 append-only audit log.

Design decisions
----------------
* Every log entry is a JSON object with an HMAC-SHA256 field computed over
  all other fields in the entry.  An attacker who edits a past entry cannot
  reproduce the correct HMAC without the server's secret key (AUDIT_LOG_KEY).
* Entries are stored one-per-line (JSON Lines format) in a flat file.  This
  keeps the on-disk format human-readable, ``grep``-able, and easy to stream
  without loading the entire log into memory.
* The HMAC covers the serialised JSON of the entry *without* the hmac field
  itself.  The canonical form is sorted-key JSON to ensure deterministic
  serialisation across Python versions and platforms.
* Each entry includes a ``prev_hash`` field — the SHA-256 hash of the
  previous entry's canonical content.  This forms a hash chain: deleting
  any entry breaks the chain for every subsequent entry, making deletions
  detectable without the server secret.  The first entry uses a fixed
  genesis sentinel as its ``prev_hash``.
* The audit viewer re-verifies every HMAC and the full hash chain before
  rendering.  Any entry whose HMAC does not match is flagged as TAMPERED;
  any gap in the chain is flagged as CHAIN BREAK.
* The log key is loaded from an environment variable (AUDIT_LOG_KEY) and
  must be a 32-byte hex string.  Using an environment variable ensures it
  is never committed to version control.
"""

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from config import AUDIT_LOG_KEY, STORAGE_AUDIT

EventType = Literal[
    "UPLOAD",
    "DOWNLOAD",
    "VERIFY_OK",
    "VERIFY_FAIL",
    "DECRYPT_FAIL",
    "KEYGEN",
    "FINGERPRINT_MISMATCH",
]

LOG_FILE: Path = STORAGE_AUDIT / "audit.log"

# Sentinel prev_hash value used by the first entry in the log.
_GENESIS = "0" * 64


def _compute_hmac(entry_without_hmac: dict) -> str:
    """HMAC-SHA256 over the canonical (sorted-key) JSON of the entry."""
    canonical = json.dumps(entry_without_hmac, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        AUDIT_LOG_KEY,
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _entry_hash(entry_without_hmac: dict) -> str:
    """SHA-256 of the canonical entry content — used to build the hash chain."""
    canonical = json.dumps(entry_without_hmac, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_entry_hash() -> str:
    """Return the hash of the last entry in the log, or the genesis sentinel."""
    if not LOG_FILE.exists():
        return _GENESIS
    last_line = None
    with LOG_FILE.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                last_line = line
    if last_line is None:
        return _GENESIS
    try:
        entry = json.loads(last_line)
        entry.pop("hmac", None)
        return _entry_hash(entry)
    except (json.JSONDecodeError, Exception):
        return _GENESIS


def append_entry(
    event_type: EventType,
    file_id: str,
    mode: str,
    ip_address: str,
    extra: dict | None = None,
) -> None:
    """
    Append a signed, chained entry to the audit log.

    Parameters
    ----------
    event_type:
        One of the defined EventType literals.
    file_id:
        UUID of the file involved in the event.
    mode:
        Encryption mode — ``"RSA"`` or ``"ECDH"``.
    ip_address:
        Client IP address from the request context.
    extra:
        Optional dict of additional key/value pairs to include in the entry.
        Use sparingly; do not include sensitive values.

    Notes
    -----
    This function never raises on I/O errors — a logging failure must not
    prevent the main operation from completing.  Errors are printed to
    stderr for operator visibility without crashing the request.
    """
    entry: dict = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "file_id":    file_id,
        "mode":       mode,
        "ip_address": ip_address,
        "prev_hash":  _last_entry_hash(),
    }
    if extra:
        entry.update(extra)

    entry["hmac"] = _compute_hmac(entry)

    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError as exc:
        import sys
        print(f"[AUDIT ERROR] Failed to write log entry: {exc}", file=sys.stderr)


def read_and_verify() -> list[dict]:
    """
    Read all log entries, re-verify each HMAC, and verify the hash chain.

    Returns
    -------
    list[dict]
        Each dict is the parsed log entry with two additional keys:
        ``"hmac_ok"``   — True if the entry's HMAC matches.
        ``"chain_ok"``  — True if this entry's prev_hash matches the hash
                          of the preceding entry (detects deletions).
    """
    if not LOG_FILE.exists():
        return []

    entries: list[dict] = []
    expected_prev = _GENESIS

    with LOG_FILE.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                entries.append({"raw": line, "hmac_ok": False, "chain_ok": False, "parse_error": True})
                continue

            stored_hmac = entry.pop("hmac", None)

            # HMAC verification
            expected_hmac = _compute_hmac(entry)
            hmac_ok = hmac.compare_digest(stored_hmac or "", expected_hmac)

            # Chain verification — prev_hash must match hash of previous entry
            actual_prev = entry.get("prev_hash", _GENESIS)
            chain_ok = hmac.compare_digest(actual_prev, expected_prev)

            # Compute this entry's hash for the next iteration
            expected_prev = _entry_hash(entry)

            entry["hmac"]     = stored_hmac
            entry["hmac_ok"]  = hmac_ok
            entry["chain_ok"] = chain_ok
            entries.append(entry)

    return entries
