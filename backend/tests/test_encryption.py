"""
Automated tests for SentinelGuard encryption / decryption system.

Run with:  cd backend && python -m pytest tests/test_encryption.py -v
"""
import hashlib
import os
import sys
import tempfile

import pytest

# Ensure backend/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.crypto import (
    KDF_ARGON2ID,
    KDF_PBKDF2,
    decrypt_file,
    encrypt_file,
    get_download_filename,
    parse_sguard,
    MAGIC,
)


# ─── helpers ──────────────────────────────────────────────────────────────────

SAMPLE_PDF = b"%PDF-1.7 fake pdf content for testing\x00\x00\x00"
SAMPLE_TEXT = b"The quick brown fox jumps over the lazy dog.\n" * 20
SAMPLE_BINARY = bytes(range(256)) * 4  # 1024 bytes

PASSWORD = "SentinelGuard@2026!"


# ─── encrypt / decrypt round-trip ─────────────────────────────────────────────


@pytest.mark.parametrize("data,filename", [
    (SAMPLE_PDF, "document.pdf"),
    (SAMPLE_TEXT, "notes.txt"),
    (SAMPLE_BINARY, "image.png"),
    (b"\x00" * 512, "zeros.bin"),
    (b"tiny", "tiny.txt"),
])
def test_encrypt_decrypt_roundtrip(data: bytes, filename: str):
    """Encrypt then decrypt must return identical bytes."""
    blob = encrypt_file(data, PASSWORD, filename)
    plaintext, meta = decrypt_file(blob, PASSWORD)
    assert plaintext == data
    assert meta["original_filename"] == filename
    assert meta["algorithm"] == "AES-256-GCM"
    assert meta["version"] == 1


def test_encrypt_produces_valid_sguard():
    """The encrypted blob must start with the correct magic + version."""
    blob = encrypt_file(SAMPLE_PDF, PASSWORD, "test.pdf")
    assert blob[:6] == MAGIC
    assert blob[6] == 1  # version byte


def test_unique_salt_and_nonce():
    """Two encryptions of the same file must differ (fresh random salt/nonce)."""
    e1 = encrypt_file(SAMPLE_PDF, PASSWORD, "test.pdf")
    e2 = encrypt_file(SAMPLE_PDF, PASSWORD, "test.pdf")
    assert e1 != e2, "Ciphertexts should differ due to random salt/nonce"

    # Both must decrypt correctly
    d1, _ = decrypt_file(e1, PASSWORD)
    d2, _ = decrypt_file(e2, PASSWORD)
    assert d1 == SAMPLE_PDF
    assert d2 == SAMPLE_PDF


def test_sha256_roundtrip():
    """SHA-256 of original must match SHA-256 reported after decryption."""
    original_hash = hashlib.sha256(SAMPLE_PDF).hexdigest()
    blob = encrypt_file(SAMPLE_PDF, PASSWORD, "test.pdf")
    _, meta = decrypt_file(blob, PASSWORD)
    assert meta["original_sha256"] == original_hash


# ─── password validation ──────────────────────────────────────────────────────


def test_wrong_password():
    """Decryption with wrong password must raise ValueError."""
    blob = encrypt_file(SAMPLE_PDF, PASSWORD, "test.pdf")
    with pytest.raises(ValueError, match="[Dd]ecryption failed|password"):
        decrypt_file(blob, "WrongPassword123!")


def test_empty_password_encrypt():
    """Encryption with an empty password must be rejected."""
    with pytest.raises(ValueError, match="Password is required"):
        encrypt_file(SAMPLE_PDF, "", "test.pdf")


def test_password_mismatch():
    """Encrypt with one password, decrypt with another must fail."""
    blob = encrypt_file(SAMPLE_TEXT, "Password_A_12345", "data.txt")
    with pytest.raises(ValueError):
        decrypt_file(blob, "Password_B_12345")


# ─── tamper detection ─────────────────────────────────────────────────────────


def test_tampered_ciphertext():
    """Flipping a byte in the ciphertext/tag must cause decryption failure."""
    blob = encrypt_file(SAMPLE_PDF, PASSWORD, "test.pdf")
    tampered = bytearray(blob)
    tampered[-1] ^= 0xFF  # flip last byte (part of GCM tag)
    with pytest.raises(ValueError, match="[Dd]ecryption failed"):
        decrypt_file(bytes(tampered), PASSWORD)


def test_truncated_ciphertext():
    """Truncating the ciphertext must cause decryption failure."""
    blob = encrypt_file(SAMPLE_PDF, PASSWORD, "test.pdf")
    truncated = blob[: len(blob) - 20]
    with pytest.raises(ValueError):
        decrypt_file(truncated, PASSWORD)


# ─── format validation ────────────────────────────────────────────────────────


def test_invalid_magic():
    """Non-SGUARD files must be rejected."""
    with pytest.raises(ValueError, match="bad magic"):
        parse_sguard(b"NOTSGUARD" + b"\x00" * 100)


def test_undersized_file():
    """Files smaller than the minimum header must be rejected."""
    with pytest.raises(ValueError, match="too small"):
        parse_sguard(b"SGUARD")


# ─── metadata extraction ──────────────────────────────────────────────────────


def test_original_filename_preserved():
    """The original filename must survive the encrypt/decrypt round-trip."""
    blob = encrypt_file(SAMPLE_PDF, PASSWORD, "My long filename with spaces.pdf")
    _, meta = decrypt_file(blob, PASSWORD)
    assert meta["original_filename"] == "My long filename with spaces.pdf"


def test_metadata_does_not_contain_password():
    """The parsed .sguard blob must never contain the password."""
    blob = encrypt_file(SAMPLE_PDF, PASSWORD, "secret.pdf")
    parsed = parse_sguard(blob)
    blob_bytes = blob
    assert PASSWORD.encode() not in blob_bytes


# ─── KDF fallback ─────────────────────────────────────────────────────────────


def test_pbkdf2_fallback():
    """Force PBKDF2 path by patching out argon2 and verifying encryption works."""
    from services import crypto
    orig = crypto._try_argon2
    crypto._try_argon2 = lambda pw, salt: None  # force PBKDF2
    try:
        blob = encrypt_file(SAMPLE_TEXT, PASSWORD, "fallback.txt")
        parsed = parse_sguard(blob)
        assert parsed["kdf_id"] == KDF_PBKDF2
        plaintext, meta = decrypt_file(blob, PASSWORD)
        assert plaintext == SAMPLE_TEXT
        assert meta["kdf"] == "PBKDF2-HMAC-SHA256"
    finally:
        crypto._try_argon2 = orig


# ─── download filename helper ────────────────────────────────────────────────


def test_download_filename():
    assert get_download_filename("report.pdf") == "report.sguard"
    assert get_download_filename("/tmp/file.zip") == "file.sguard"
    assert get_download_filename("noext") == "noext.sguard"


# ─── large file ──────────────────────────────────────────────────────────────


def test_large_file():
    """Encrypt/decrypt a 2 MB binary blob."""
    large = os.urandom(2 * 1024 * 1024)
    blob = encrypt_file(large, PASSWORD, "big.bin")
    plaintext, _ = decrypt_file(blob, PASSWORD)
    assert plaintext == large


# ─── scanner regression ───────────────────────────────────────────────────────


def test_scanner_still_works():
    """Ensure the existing scanner module hasn't been broken."""
    from scanner.analyzers import entropy, sha256
    assert isinstance(entropy(b"hello world"), float)
    assert isinstance(sha256.__call__, type(sha256.__call__)) or callable(sha256)


# ─── API integration tests ──────────────────────────────────────────────────
# These use FastAPI's TestClient to simulate real HTTP requests.
# Run with:  cd backend && python -m pytest tests/test_encryption.py -v -k api

import json
from io import BytesIO
from fastapi.testclient import TestClient

from main import app

API_CLIENT = TestClient(app)
_API_TOKEN = None


def _get_token() -> str:
    """Register or log in to get a JWT token."""
    global _API_TOKEN
    if _API_TOKEN:
        return _API_TOKEN
    r = API_CLIENT.post("/auth/register", json={
        "email": "test_enc_api@test.com",
        "display_name": "API Tester",
        "password": "TestPassword123!",
    })
    if r.status_code == 409:
        r = API_CLIENT.post("/auth/login", json={
            "email": "test_enc_api@test.com",
            "password": "TestPassword123!",
        })
    _API_TOKEN = r.json()["access_token"]
    return _API_TOKEN


def _auth_headers(token: str = None) -> dict:
    return {"Authorization": f"Bearer {token or _get_token()}"}


def _multipart_encrypt(file_bytes: bytes, filename: str, password: str, token: str = None):
    """Simulate browser FormData upload for encryption."""
    return API_CLIENT.post(
        "/encrypt",
        files={"file": (filename, BytesIO(file_bytes), "application/octet-stream")},
        data={"password": password},
        headers=_auth_headers(token),
    )


def _multipart_decrypt(file_bytes: bytes, filename: str, password: str, token: str = None):
    """Simulate browser FormData upload for decryption."""
    return API_CLIENT.post(
        "/decrypt",
        files={"file": (filename, BytesIO(file_bytes), "application/octet-stream")},
        data={"password": password},
        headers=_auth_headers(token),
    )


# ── API: encrypt PDF ─────────────────────────────────────────────────────────

def test_api_encrypt_pdf():
    """Encrypt a PDF file via API endpoint."""
    r = _multipart_encrypt(SAMPLE_PDF, "document.pdf", PASSWORD)
    assert r.status_code == 200
    result = r.json()
    assert result["original_filename"] == "document.pdf"
    assert result["algorithm"] == "AES-256-GCM"
    assert result["kdf"] == "Argon2id"
    assert result["file_size"] > 0
    assert result["download_url"].startswith("/encrypt/download/")
    assert result["original_sha256"] == hashlib.sha256(SAMPLE_PDF).hexdigest()


# ── API: encrypt text ────────────────────────────────────────────────────────

def test_api_encrypt_text():
    """Encrypt a text file via API endpoint."""
    r = _multipart_encrypt(SAMPLE_TEXT, "notes.txt", PASSWORD)
    assert r.status_code == 200
    result = r.json()
    assert result["original_filename"] == "notes.txt"
    assert result["algorithm"] == "AES-256-GCM"


# ── API: encrypt binary ──────────────────────────────────────────────────────

def test_api_encrypt_binary():
    """Encrypt arbitrary binary data via API endpoint."""
    r = _multipart_encrypt(SAMPLE_BINARY, "image.png", PASSWORD)
    assert r.status_code == 200
    assert r.json()["original_filename"] == "image.png"


# ── API: download encrypted file ─────────────────────────────────────────────

def test_api_download_encrypted():
    """After encrypting, download the .sguard file."""
    r = _multipart_encrypt(SAMPLE_PDF, "report.pdf", PASSWORD)
    assert r.status_code == 200
    result = r.json()

    # Download
    dl = API_CLIENT.get(result["download_url"], headers=_auth_headers())
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/octet-stream"
    sguard_data = dl.content
    assert sguard_data[:6] == MAGIC
    assert len(sguard_data) == result["file_size"]


# ── API: decrypt success ─────────────────────────────────────────────────────

def test_api_decrypt_success():
    """Encrypt then decrypt via API — must return identical file."""
    enc = _multipart_encrypt(SAMPLE_PDF, "test.pdf", PASSWORD)
    assert enc.status_code == 200

    dl = API_CLIENT.get(enc.json()["download_url"], headers=_auth_headers())
    assert dl.status_code == 200

    dec = _multipart_decrypt(dl.content, "test.sguard", PASSWORD)
    assert dec.status_code == 200
    result = dec.json()
    assert result["original_filename"] == "test.pdf"
    assert result["integrity"] == "VERIFIED"
    assert result["original_sha256"] == hashlib.sha256(SAMPLE_PDF).hexdigest()

    # Download the decrypted file
    dl2 = API_CLIENT.get(result["download_url"], headers=_auth_headers())
    assert dl2.status_code == 200
    assert dl2.content == SAMPLE_PDF


# ── API: wrong password ──────────────────────────────────────────────────────

def test_api_wrong_password():
    """Decrypting with wrong password must return 400."""
    enc = _multipart_encrypt(SAMPLE_PDF, "test.pdf", PASSWORD)
    dl = API_CLIENT.get(enc.json()["download_url"], headers=_auth_headers())

    dec = _multipart_decrypt(dl.content, "test.sguard", "WrongPassword123!")
    assert dec.status_code == 400
    assert "incorrect" in dec.json()["detail"].lower() or "password" in dec.json()["detail"].lower()


# ── API: tampered ciphertext ─────────────────────────────────────────────────

def test_api_tampered_ciphertext():
    """Tampered .sguard file must fail decryption with 400."""
    enc = _multipart_encrypt(SAMPLE_PDF, "test.pdf", PASSWORD)
    dl = API_CLIENT.get(enc.json()["download_url"], headers=_auth_headers())

    tampered = bytearray(dl.content)
    tampered[-1] ^= 0xFF

    dec = _multipart_decrypt(bytes(tampered), "test.sguard", PASSWORD)
    assert dec.status_code == 400


# ── API: invalid sguard file ─────────────────────────────────────────────────

def test_api_invalid_sguard():
    """Non-.sguard data must fail with 400."""
    dec = _multipart_decrypt(b"NOTSGUARD" + b"\x00" * 100, "bad.sguard", PASSWORD)
    assert dec.status_code == 400


# ── API: SHA-256 round trip via API ──────────────────────────────────────────

def test_api_sha256_round_trip():
    """Encrypted then decrypted must have matching SHA-256 hashes."""
    enc = _multipart_encrypt(SAMPLE_PDF, "test.pdf", PASSWORD)
    dl = API_CLIENT.get(enc.json()["download_url"], headers=_auth_headers())
    dec = _multipart_decrypt(dl.content, "test.sguard", PASSWORD)

    assert dec.status_code == 200
    original_hash = hashlib.sha256(SAMPLE_PDF).hexdigest()
    assert dec.json()["original_sha256"] == original_hash

    # Verify the actual downloaded bytes match
    dl2 = API_CLIENT.get(dec.json()["download_url"], headers=_auth_headers())
    assert hashlib.sha256(dl2.content).hexdigest() == original_hash


# ── API: unique salt/nonce on same input ─────────────────────────────────────

def test_api_unique_salt_nonce():
    """Encrypt same file twice — ciphertexts must differ, both decrypt."""
    enc1 = _multipart_encrypt(SAMPLE_PDF, "test.pdf", PASSWORD)
    enc2 = _multipart_encrypt(SAMPLE_PDF, "test.pdf", PASSWORD)

    dl1 = API_CLIENT.get(enc1.json()["download_url"], headers=_auth_headers())
    dl2 = API_CLIENT.get(enc2.json()["download_url"], headers=_auth_headers())

    assert dl1.content != dl2.content

    dec1 = _multipart_decrypt(dl1.content, "test.sguard", PASSWORD)
    dec2 = _multipart_decrypt(dl2.content, "test.sguard", PASSWORD)
    assert dec1.status_code == 200
    assert dec2.status_code == 200
    assert dec1.json()["original_sha256"] == dec2.json()["original_sha256"]


# ── API: empty password rejected ─────────────────────────────────────────────

def test_api_empty_password():
    """Encryption with empty password must be rejected."""
    r = _multipart_encrypt(SAMPLE_PDF, "test.pdf", "")
    assert r.status_code in (400, 422), f"Expected 400 or 422, got {r.status_code}: {r.text}"


# ── API: encryption history ──────────────────────────────────────────────────

def test_api_encryption_history():
    """After encryption, history record must be created."""
    _multipart_encrypt(SAMPLE_PDF, "history_test.pdf", PASSWORD)

    hist = API_CLIENT.get("/encryption/history", headers=_auth_headers())
    assert hist.status_code == 200
    records = hist.json()
    assert len(records) >= 1

    record = records[0]
    assert record["original_filename"] == "history_test.pdf"
    assert record["algorithm"] == "AES-256-GCM"
    assert record["kdf"] == "Argon2id"
    assert record["status"] == "success"
    assert record["sha256"] == hashlib.sha256(SAMPLE_PDF).hexdigest()
    assert "created_at" in record


# ── API: unauthenticated requests rejected ───────────────────────────────────

def test_api_encrypt_unauthenticated():
    """Encryption without auth must return 403/401."""
    r = API_CLIENT.post(
        "/encrypt",
        files={"file": ("test.pdf", BytesIO(SAMPLE_PDF), "application/octet-stream")},
        data={"password": PASSWORD},
    )
    assert r.status_code in (401, 403)


def test_api_decrypt_unauthenticated():
    """Decryption without auth must return 403/401."""
    r = API_CLIENT.post(
        "/decrypt",
        files={"file": ("test.sguard", BytesIO(b"SGUARD" + b"\x00" * 50), "application/octet-stream")},
        data={"password": PASSWORD},
    )
    assert r.status_code in (401, 403)


# ── API: large file via API ──────────────────────────────────────────────────

def test_api_large_file():
    """Encrypt/decrypt a 1 MB file via API."""
    large = os.urandom(1024 * 1024)
    enc = _multipart_encrypt(large, "big.bin", PASSWORD)
    assert enc.status_code == 200

    dl = API_CLIENT.get(enc.json()["download_url"], headers=_auth_headers())
    dec = _multipart_decrypt(dl.content, "big.sguard", PASSWORD)
    assert dec.status_code == 200

    dl2 = API_CLIENT.get(dec.json()["download_url"], headers=_auth_headers())
    assert dl2.content == large


# ── API: small file via API ──────────────────────────────────────────────────

def test_api_small_file():
    """Encrypt/decrypt a tiny file via API."""
    tiny = b"hello"
    enc = _multipart_encrypt(tiny, "tiny.txt", PASSWORD)
    assert enc.status_code == 200

    dl = API_CLIENT.get(enc.json()["download_url"], headers=_auth_headers())
    dec = _multipart_decrypt(dl.content, "tiny.sguard", PASSWORD)
    assert dec.status_code == 200

    dl2 = API_CLIENT.get(dec.json()["download_url"], headers=_auth_headers())
    assert dl2.content == tiny


# ── API: docx/zip/image round trip ──────────────────────────────────────────

def test_api_docx_like():
    """Encrypt/decrypt a DOCX-like file."""
    data = b"PK\x03\x04" + os.urandom(512)  # fake ZIP/DOCX header
    enc = _multipart_encrypt(data, "report.docx", PASSWORD)
    assert enc.status_code == 200
    dl = API_CLIENT.get(enc.json()["download_url"], headers=_auth_headers())
    dec = _multipart_decrypt(dl.content, "report.sguard", PASSWORD)
    assert dec.status_code == 200
    dl2 = API_CLIENT.get(dec.json()["download_url"], headers=_auth_headers())
    assert dl2.content == data


def test_api_zip_like():
    """Encrypt/decrypt a ZIP-like file."""
    data = b"PK\x05\x06" + os.urandom(256)  # fake ZIP EOCD header
    enc = _multipart_encrypt(data, "archive.zip", PASSWORD)
    assert enc.status_code == 200
    dl = API_CLIENT.get(enc.json()["download_url"], headers=_auth_headers())
    dec = _multipart_decrypt(dl.content, "archive.sguard", PASSWORD)
    assert dec.status_code == 200
    dl2 = API_CLIENT.get(dec.json()["download_url"], headers=_auth_headers())
    assert dl2.content == data
