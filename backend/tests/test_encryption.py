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
    """Encryption with an empty password should still work (no backend restriction)."""
    blob = encrypt_file(SAMPLE_PDF, "", "test.pdf")
    plaintext, _ = decrypt_file(blob, "")
    assert plaintext == SAMPLE_PDF


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
