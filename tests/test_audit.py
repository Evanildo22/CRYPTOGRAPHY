"""
tests/test_audit.py — Append-only HMAC-SHA256 audit log.

Coverage:
  * Entries are appended correctly and can be read back
  * HMAC is present in each entry
  * Unmodified entries have hmac_ok == True
  * A tampered entry has hmac_ok == False
  * Log is append-only (existing entries survive a new append)
  * read_and_verify handles an empty / missing log file gracefully
  * Tampered HMAC field is detected
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import config   # import before patching so we can swap the constant


@pytest.fixture()
def temp_log(tmp_path, monkeypatch):
    """Redirect LOG_FILE to a temp directory for each test."""
    import audit.log as log_module
    temp_log_file = tmp_path / "test_audit.log"
    monkeypatch.setattr(log_module, "LOG_FILE", temp_log_file)
    # Also patch STORAGE_AUDIT to point at tmp_path
    monkeypatch.setattr(config, "STORAGE_AUDIT", tmp_path)
    return temp_log_file, log_module


class TestAppendAndRead:
    def test_entry_appears_after_append(self, temp_log):
        path, log = temp_log
        log.append_entry("UPLOAD", "file-uuid-1", "RSA", "127.0.0.1")
        entries = log.read_and_verify()
        assert len(entries) == 1
        assert entries[0]["event_type"] == "UPLOAD"

    def test_multiple_entries_ordered(self, temp_log):
        path, log = temp_log
        log.append_entry("UPLOAD",   "id-1", "RSA",  "1.1.1.1")
        log.append_entry("DOWNLOAD", "id-1", "RSA",  "1.1.1.1")
        log.append_entry("UPLOAD",   "id-2", "ECDH", "2.2.2.2")
        entries = log.read_and_verify()
        assert len(entries) == 3
        assert entries[0]["event_type"] == "UPLOAD"
        assert entries[1]["event_type"] == "DOWNLOAD"
        assert entries[2]["mode"]       == "ECDH"

    def test_empty_log_returns_empty_list(self, temp_log):
        _, log = temp_log
        # No entries appended
        assert log.read_and_verify() == []

    def test_missing_log_file_returns_empty_list(self, temp_log):
        path, log = temp_log
        assert not path.exists()
        assert log.read_and_verify() == []


class TestHmacIntegrity:
    def test_fresh_entries_have_hmac_ok_true(self, temp_log):
        _, log = temp_log
        log.append_entry("KEYGEN", "n/a", "RSA", "10.0.0.1")
        entries = log.read_and_verify()
        assert all(e["hmac_ok"] for e in entries)

    def test_tampered_event_type_detected(self, temp_log):
        path, log = temp_log
        log.append_entry("UPLOAD", "file-abc", "RSA", "127.0.0.1")

        # Directly edit the log file to change the event_type
        lines = path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["event_type"] = "DOWNLOAD"   # tamper
        lines[0] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")

        entries = log.read_and_verify()
        assert entries[0]["hmac_ok"] is False

    def test_tampered_hmac_field_detected(self, temp_log):
        path, log = temp_log
        log.append_entry("VERIFY_OK", "file-xyz", "ECDH", "192.168.1.1")

        lines = path.read_text().splitlines()
        entry = json.loads(lines[0])
        # Replace HMAC with garbage
        entry["hmac"] = "0" * 64
        lines[0] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")

        entries = log.read_and_verify()
        assert entries[0]["hmac_ok"] is False

    def test_extra_field_in_entry_invalidates_hmac(self, temp_log):
        path, log = temp_log
        log.append_entry("DOWNLOAD", "file-def", "RSA", "10.0.0.2")

        lines  = path.read_text().splitlines()
        entry  = json.loads(lines[0])
        entry["injected"] = "malicious"   # add a field after HMAC computed
        lines[0] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")

        entries = log.read_and_verify()
        assert entries[0]["hmac_ok"] is False

    def test_prior_entries_survive_new_append(self, temp_log):
        _, log = temp_log
        log.append_entry("UPLOAD",   "id-a", "RSA",  "1.0.0.1")
        log.append_entry("DOWNLOAD", "id-a", "RSA",  "1.0.0.1")

        entries = log.read_and_verify()
        assert len(entries) == 2
        assert all(e["hmac_ok"] for e in entries)


class TestExtraFields:
    def test_extra_kwarg_stored_in_entry(self, temp_log):
        _, log = temp_log
        log.append_entry(
            "FINGERPRINT_MISMATCH", "file-x", "ECDH", "5.5.5.5",
            extra={"stored_fp": "aabb", "actual_fp": "ccdd"},
        )
        entries = log.read_and_verify()
        assert entries[0]["stored_fp"] == "aabb"
        assert entries[0]["hmac_ok"]   is True
