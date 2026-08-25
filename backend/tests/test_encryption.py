from pathlib import Path
import os
import pytest

from services.encryption import EncryptedFileError, decrypt_file, encrypt_file, read_header, sha256_file


@pytest.mark.parametrize("name,payload", [("note.txt", b"hello SentinelGuard"), ("empty.txt", b""), ("photo.png", os.urandom(4096)), ("archive.zip", os.urandom(8192))])
def test_encrypt_decrypt_roundtrip(tmp_path: Path, name: str, payload: bytes):
    source, encrypted, restored = tmp_path / name, tmp_path / "file.sguard", tmp_path / "restored"
    source.write_bytes(payload)
    header = encrypt_file(source, encrypted, "A strong passphrase 123!", name)
    assert header["algorithm"] == "AES-256-GCM"
    decrypt_file(encrypted, restored, "A strong passphrase 123!")
    assert sha256_file(source) == sha256_file(restored)


def test_fresh_salt_nonce_and_ciphertext(tmp_path: Path):
    source = tmp_path / "same.txt"; source.write_text("identical")
    a, b = tmp_path / "a.sguard", tmp_path / "b.sguard"
    encrypt_file(source, a, "A strong passphrase 123!", source.name)
    encrypt_file(source, b, "A strong passphrase 123!", source.name)
    first, _, _ = read_header(a); second, _, _ = read_header(b)
    assert first["salt"] != second["salt"] and first["nonce"] != second["nonce"] and a.read_bytes() != b.read_bytes()


def test_wrong_password_and_tampering_never_output_plaintext(tmp_path: Path):
    source = tmp_path / "note.txt"; source.write_text("confidential")
    encrypted = tmp_path / "file.sguard"; output = tmp_path / "output.txt"
    encrypt_file(source, encrypted, "A strong passphrase 123!", source.name)
    with pytest.raises(EncryptedFileError): decrypt_file(encrypted, output, "wrong password")
    assert not output.exists()
    data = bytearray(encrypted.read_bytes()); data[-20] ^= 1; encrypted.write_bytes(data)
    with pytest.raises(EncryptedFileError): decrypt_file(encrypted, output, "A strong passphrase 123!")
    assert not output.exists()
