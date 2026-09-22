"""Secure Vault storage: per-user AES-256-GCM protection under a Vault password.

Reuse strategy (no new crypto primitives introduced):
- Vault password verification: bcrypt via services.auth (same as login).
- File encryption key: Argon2id raw derivation via services.crypto.derive_key
  (the same KDF and parameters as the existing .sguard encryption flow).
The Vault password itself is never stored, logged, or persisted in any form;
only its bcrypt hash (for verification) exists in the database.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import struct
from pathlib import Path

from services.auth import hash_password, verify_password
from services.crypto import derive_key, KEY_LEN, NONCE_LEN
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_MAGIC = b"SGVAULT1"
MIN_VAULT_PASSWORD = 8


def is_strong_vault_password(password: str) -> bool:
    return (
        isinstance(password, str)
        and MIN_VAULT_PASSWORD <= len(password) <= 128
        and re.search(r"[A-Za-z]", password)
        and re.search(r"\d", password)
    )


def hash_vault_password(password: str) -> str:
    return hash_password(password)


def verify_vault_password(password: str, password_hash: str) -> bool:
    try:
        return verify_password(password, password_hash)
    except Exception:
        return False


def _file_key(vault_password: str, salt: bytes) -> bytes:
    """Per-file AES key: Argon2id(vault_password, per-file salt), 32 bytes."""
    key, _ = derive_key(vault_password, salt)
    return key


def encrypt_vault_blob(plaintext: bytes, vault_password: str, original_filename: str) -> bytes:
    """Return an authenticated vault blob bound to filename + vault password."""
    if not plaintext:
        raise ValueError("File is empty")
    name = Path(original_filename).name
    if not name or name in {".", ".."}:
        raise ValueError("A valid original filename is required")

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = _file_key(vault_password, salt)
    name_bytes = name.encode("utf-8")

    header = bytearray()
    header += VAULT_MAGIC                                   # 8 bytes
    header += struct.pack("<H", len(salt)) + salt           # salt
    header += struct.pack("<H", len(nonce)) + nonce         # nonce
    header += struct.pack("<H", len(name_bytes)) + name_bytes
    header += hashlib.sha256(plaintext).digest()            # 32 bytes

    # AAD authenticates the header so metadata cannot be swapped either.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, bytes(header))
    return bytes(header) + ciphertext


def decrypt_vault_blob(blob: bytes, vault_password: str) -> tuple[bytes, str]:
    """Return (plaintext, original_filename). Raises ValueError on wrong password
    or tampering — GCM authentication failure is indistinguishable by design."""
    minimum = len(VAULT_MAGIC) + 2 + 16 + 2 + 12 + 2 + 1 + 32
    if len(blob) < minimum:
        raise ValueError("Invalid vault file")
    offset = 0
    if blob[: len(VAULT_MAGIC)] != VAULT_MAGIC:
        raise ValueError("Invalid vault file")
    offset += len(VAULT_MAGIC)

    salt_len = struct.unpack_from("<H", blob, offset)[0]; offset += 2
    if salt_len != 16 or offset + salt_len > len(blob):
        raise ValueError("Invalid vault file")
    salt = blob[offset: offset + salt_len]; offset += salt_len

    nonce_len = struct.unpack_from("<H", blob, offset)[0]; offset += 2
    if nonce_len != NONCE_LEN or offset + nonce_len > len(blob):
        raise ValueError("Invalid vault file")
    nonce = blob[offset: offset + nonce_len]; offset += nonce_len

    name_len = struct.unpack_from("<H", blob, offset)[0]; offset += 2
    if not name_len or offset + name_len > len(blob):
        raise ValueError("Invalid vault file")
    try:
        original_filename = blob[offset: offset + name_len].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid vault file") from exc
    if Path(original_filename).name != original_filename or original_filename in {".", ".."}:
        raise ValueError("Invalid vault file")
    offset += name_len

    if offset + 32 > len(blob):
        raise ValueError("Invalid vault file")
    expected_sha = blob[offset: offset + 32]; offset += 32

    ciphertext = blob[offset:]
    if len(ciphertext) < 16:
        raise ValueError("Invalid vault file")

    key = _file_key(vault_password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, blob[:offset])
    except Exception as exc:
        raise ValueError("Vault password is incorrect or the file is corrupted") from exc

    if hashlib.sha256(plaintext).digest() != expected_sha:
        raise ValueError("Integrity verification failed")
    return plaintext, original_filename


def new_stored_name() -> str:
    return secrets.token_hex(16) + ".vault"


def safe_vault_path(vault_dir: Path, stored_name: str) -> Path:
    """Resolve a stored name inside vault_dir, refusing traversal of any kind."""
    if not re.fullmatch(r"[0-9a-f]{32}\.vault", stored_name or ""):
        raise ValueError("Invalid stored file name")
    base = vault_dir.resolve()
    candidate = (base / stored_name).resolve()
    if candidate.parent != base:
        raise ValueError("Invalid stored file name")
    return candidate
