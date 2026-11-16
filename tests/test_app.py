"""
tests/test_app.py — End-to-end upload / download through the Flask routes.

Coverage:
  * Round trip in Mode A (RSA) and Mode B (ECDH) returns the original file
  * A wrong password fails decryption even with the correct private key
  * A wrong private key fails decryption even with the correct password
  * Upload without a password is rejected
  * Failed decryptions are recorded in the audit log
"""

import io

import pytest

import app as app_module
import audit.log as log_module
from crypto.ecdh import ec_private_key_to_pem, ec_public_key_to_pem, generate_ec_keypair
from crypto.rsa_keys import generate_keypair, private_key_to_pem, public_key_to_pem

PLAINTEXT = b"quarterly report - confidential\n" * 50
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Flask test client with storage and audit log redirected to tmp_path."""
    for name in ("STORAGE_FILES", "STORAGE_KEYS", "STORAGE_SIGS", "STORAGE_FPS"):
        directory = tmp_path / name.lower()
        directory.mkdir()
        monkeypatch.setattr(app_module, name, directory)
    monkeypatch.setattr(log_module, "LOG_FILE", tmp_path / "audit.log")
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


@pytest.fixture(scope="module")
def keys():
    """PEM-encoded signer RSA pair, recipient RSA pair and recipient EC pair."""
    def rsa_pair():
        priv, pub = generate_keypair()
        return private_key_to_pem(priv).decode(), public_key_to_pem(pub).decode()

    ec_priv, ec_pub = generate_ec_keypair()
    signer_priv, signer_pub = rsa_pair()
    recipient_priv, recipient_pub = rsa_pair()
    other_priv, _ = rsa_pair()
    other_ec_priv, _ = generate_ec_keypair()
    return {
        "signer_priv": signer_priv, "signer_pub": signer_pub,
        "rsa_priv": recipient_priv, "rsa_pub": recipient_pub,
        "ec_priv": ec_private_key_to_pem(ec_priv).decode(),
        "ec_pub": ec_public_key_to_pem(ec_pub).decode(),
        "other_rsa_priv": other_priv,
        "other_ec_priv": ec_private_key_to_pem(other_ec_priv).decode(),
    }


def _upload(client, keys, mode, password=PASSWORD):
    data = {
        "file": (io.BytesIO(PLAINTEXT), "report.txt"),
        "password": password,
        "mode": mode,
        "rsa_private_key": keys["signer_priv"],
    }
    if mode == "A":
        data["rsa_public_key"] = keys["rsa_pub"]
    else:
        data["ec_public_key"] = keys["ec_pub"]
    return client.post("/upload", data=data, content_type="multipart/form-data")


def _file_id(response):
    assert "/download/" in response.headers["Location"]
    return response.headers["Location"].rsplit("/", 1)[-1]


def _download(client, keys, mode, file_id, password=PASSWORD, private_key=None):
    data = {"password": password, "rsa_public_key": keys["signer_pub"]}
    if mode == "A":
        data["rsa_private_key"] = private_key or keys["rsa_priv"]
    else:
        data["ec_private_key"] = private_key or keys["ec_priv"]
    return client.post(f"/download/{file_id}", data=data)


def _events():
    return [entry["event_type"] for entry in log_module.read_and_verify()]


@pytest.mark.parametrize("mode", ["A", "B"])
class TestRoundTrip:
    def test_correct_key_and_password_recover_file(self, client, keys, mode):
        file_id = _file_id(_upload(client, keys, mode))
        response = _download(client, keys, mode, file_id)

        assert "dl=" in response.headers["Location"]
        token = response.headers["Location"].split("dl=")[1]
        assert client.get(f"/fetch/{token}").data == PLAINTEXT
        assert _events()[-1] == "DOWNLOAD"

    def test_wrong_password_fails(self, client, keys, mode):
        file_id = _file_id(_upload(client, keys, mode))
        response = _download(client, keys, mode, file_id, password="wrong-password")

        assert "dl=" not in response.headers["Location"]
        assert _events()[-1] == "DECRYPT_FAIL"

    def test_wrong_private_key_fails(self, client, keys, mode):
        file_id = _file_id(_upload(client, keys, mode))
        wrong = keys["other_rsa_priv"] if mode == "A" else keys["other_ec_priv"]
        response = _download(client, keys, mode, file_id, private_key=wrong)

        assert "dl=" not in response.headers["Location"]
        assert _events()[-1] == "DECRYPT_FAIL"

    def test_stored_ciphertext_is_not_plaintext(self, client, keys, mode):
        file_id = _file_id(_upload(client, keys, mode))
        blob = (app_module.STORAGE_FILES / f"{file_id}.enc").read_bytes()
        assert PLAINTEXT[:32] not in blob


def test_upload_without_password_is_rejected(client, keys):
    response = _upload(client, keys, "A", password="")
    assert "/download/" not in response.headers["Location"]
    assert list(app_module.STORAGE_FILES.iterdir()) == []
