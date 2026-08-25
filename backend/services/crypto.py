"""
SentinelGuard file encryption/decryption service.

.sguard file format (version 1):
  MAGIC:          b"SGUARD"           (6 bytes)
  VERSION:        1                   (1 byte)
  KDF_ID:         0x01=Argon2id       (1 byte)
  SALT_LEN:       uint16 LE           (2 bytes)
  SALT:           variable
  NONCE_LEN:      uint16 LE           (2 bytes)
  NONCE:          variable
  NAME_LEN:       uint16 LE           (2 bytes)
  ORIG_NAME:      variable (UTF-8)
  SHA256:         32 bytes
  CIPHERTEXT:     remaining bytes (AES-256-GCM encrypted)
"""
from __future__ import annotations

import hashlib
import os
import struct
import logging
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("sentinelguard.crypto")

MAGIC = b"SGUARD"
VERSION = 1
KDF_ARGON2ID = 0x01
KDF_PBKDF2 = 0x02

# Argon2 parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32

# PBKDF2 fallback parameters (NIST SP 800-132 minimums exceeded)
PBKDF2_ITERATIONS = 600_000
PBKDF2_HASH_LEN = 32

# AES-GCM
NONCE_LEN = 12  # 96 bits — recommended for AES-GCM
KEY_LEN = 32    # 256 bits


def _try_argon2(password: bytes, salt: bytes) -> Optional[bytes]:
    """Derive a 256-bit key via Argon2id. Returns None if argon2-cffi is unavailable."""
    try:
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID,
        )
    except ImportError:
        logger.info("argon2-cffi not installed; falling back to PBKDF2")
        return None


def _pbkdf2(password: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit key via PBKDF2-HMAC-SHA256."""
    import hashlib as _hl
    return _hl.pbkdf2_hmac(
        "sha256", password, salt, PBKDF2_ITERATIONS, dklen=PBKDF2_HASH_LEN
    )


def derive_key(password: str, salt: bytes) -> tuple[bytes, int]:
    """Derive an AES-256 key from a password and salt.

    Returns (key, kdf_id).
    """
    pw_bytes = password.encode("utf-8")
    key = _try_argon2(pw_bytes, salt)
    if key is not None:
        return key, KDF_ARGON2ID
    return _pbkdf2(pw_bytes, salt), KDF_PBKDF2


def _read_uint16(data: bytes, offset: int) -> tuple[int, int]:
    val = struct.unpack_from("<H", data, offset)[0]
    return val, offset + 2


def encrypt_file(
    plaintext: bytes,
    password: str,
    original_filename: str,
) -> bytes:
    """Encrypt file bytes and return a complete .sguard blob."""
    salt = os.urandom(16)
    nonce = os.urandom(NONCE_LEN)
    key, kdf_id = derive_key(password, salt)

    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # includes GCM tag

    # Compute original SHA-256
    orig_sha256 = hashlib.sha256(plaintext).digest()

    # Build .sguard binary
    orig_name_bytes = original_filename.encode("utf-8")
    header = bytearray()
    header += MAGIC                              # 6 bytes
    header += struct.pack("B", VERSION)          # 1 byte
    header += struct.pack("B", kdf_id)           # 1 byte
    header += struct.pack("<H", len(salt))       # 2 bytes
    header += salt                               # 16 bytes
    header += struct.pack("<H", len(nonce))      # 2 bytes
    header += nonce                              # 12 bytes
    header += struct.pack("<H", len(orig_name_bytes))  # 2 bytes
    header += orig_name_bytes                    # variable
    header += orig_sha256                        # 32 bytes
    header += ciphertext                         # variable

    return bytes(header)


def parse_sguard(data: bytes) -> dict:
    """Parse a .sguard blob. Returns metadata + ciphertext.

    Raises ValueError on invalid format / bad magic / wrong version.
    """
    if len(data) < 6 + 1 + 1 + 2 + 2 + 2 + 32:
        raise ValueError("File too small to be a valid .sguard file")

    offset = 0
    magic = data[offset:offset + 6]
    offset += 6
    if magic != MAGIC:
        raise ValueError("Invalid .sguard file: bad magic bytes")

    version = data[offset]
    offset += 1
    if version > VERSION:
        raise ValueError(f"Unsupported .sguard version: {version}")

    kdf_id = data[offset]
    offset += 1

    # Salt
    salt_len, offset = _read_uint16(data, offset)
    salt = data[offset:offset + salt_len]
    offset += salt_len

    # Nonce
    nonce_len, offset = _read_uint16(data, offset)
    nonce = data[offset:offset + nonce_len]
    offset += nonce_len

    # Original filename
    name_len, offset = _read_uint16(data, offset)
    orig_name = data[offset:offset + name_len].decode("utf-8", errors="replace")
    offset += name_len

    # SHA-256
    orig_sha256 = data[offset:offset + 32]
    offset += 32

    ciphertext = data[offset:]

    return {
        "version": version,
        "kdf_id": kdf_id,
        "salt": salt,
        "nonce": nonce,
        "original_filename": orig_name,
        "original_sha256": orig_sha256,
        "ciphertext": ciphertext,
    }


def decrypt_file(data: bytes, password: str) -> tuple[bytes, dict]:
    """Decrypt a .sguard blob.

    Returns (plaintext_bytes, metadata_dict).

    Raises ValueError on bad password, corrupted data, or format errors.
    """
    parsed = parse_sguard(data)

    kdf_id = parsed["kdf_id"]
    salt = parsed["salt"]
    nonce = parsed["nonce"]
    ciphertext = parsed["ciphertext"]

    # Derive the same key
    pw_bytes = password.encode("utf-8")
    if kdf_id == KDF_ARGON2ID:
        key = _try_argon2(pw_bytes, salt)
        if key is None:
            raise ValueError("Argon2id KDF required but unavailable")
    elif kdf_id == KDF_PBKDF2:
        key = _pbkdf2(pw_bytes, salt)
    else:
        raise ValueError(f"Unknown KDF identifier: {kdf_id:#x}")

    # Decrypt + verify GCM authentication tag
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(
            "Decryption failed. The password may be incorrect or the "
            "encrypted file may have been modified or corrupted."
        ) from e

    # Verify SHA-256 integrity
    computed_sha256 = hashlib.sha256(plaintext).digest()
    if computed_sha256 != parsed["original_sha256"]:
        raise ValueError(
            "Integrity verification failed: SHA-256 hash mismatch after decryption."
        )

    return plaintext, {
        "original_filename": parsed["original_filename"],
        "original_sha256": computed_sha256.hex(),
        "algorithm": "AES-256-GCM",
        "kdf": "Argon2id" if kdf_id == KDF_ARGON2ID else "PBKDF2-HMAC-SHA256",
        "version": parsed["version"],
    }


def get_download_filename(original_filename: str) -> str:
    """Return the .sguard download filename for a given original file."""
    stem = Path(original_filename).stem
    return f"{stem}.sguard"
