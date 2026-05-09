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
* The audit viewer re-verifies every HMAC before rendering.  Any entry whose
  HMAC does not match is flagged as TAMPERED in the UI.
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


def _compute_hmac(entry_without_hmac: dict) -> str:
    """
    Compute HMAC-SHA256 over the canonical JSON representation of
    *entry_without_hmac*.

    Canonical form: JSON with sorted keys, no extra whitespace.
    """
    canonical = json.dumps(entry_without_hmac, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        AUDIT_LOG_KEY,
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def append_entry(
    event_type: EventType,
    file_id: str,
    mode: str,
    ip_address: str,
    extra: dict | None = None,
) -> None:
    """
    Append a signed entry to the audit log.

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
    Read all log entries and re-verify each HMAC.

    Returns
    -------
    list[dict]
        Each dict is the parsed log entry with an additional key
        ``"hmac_ok"`` (``True`` / ``False``) indicating whether the
        stored HMAC matches the recomputed value.
    """
    if not LOG_FILE.exists():
        return []

    entries: list[dict] = []
    with LOG_FILE.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                entries.append({"raw": line, "hmac_ok": False, "parse_error": True})
                continue

            stored_hmac = entry.pop("hmac", None)
            expected_hmac = _compute_hmac(entry)
            entry["hmac"]    = stored_hmac
            entry["hmac_ok"] = hmac.compare_digest(
                stored_hmac or "", expected_hmac
            )
            entries.append(entry)

    return entries
