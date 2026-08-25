"""SentinelGuard's versioned authenticated encrypted-file format.

The wire format is ``SGUARD01 | header length (uint32 big endian) | JSON header |
ciphertext | GCM tag``.  The complete header is authenticated as AES-GCM AAD.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"SGUARD01"
TAG_LENGTH = 16
CHUNK_SIZE = 1024 * 1024
KDF_PARAMETERS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 2, "hash_len": 32}


class EncryptedFileError(ValueError):
    """A malformed, unsupported, or unauthentic SentinelGuard file."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(CHUNK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def _key(password: str, salt: bytes, params: dict) -> bytes:
    if not password:
        raise EncryptedFileError("An encryption password is required.")
    try:
        return hash_secret_raw(password.encode("utf-8"), salt, type=Type.ID, **params)
    except (TypeError, ValueError) as exc:
        raise EncryptedFileError("Invalid key-derivation parameters.") from exc


def _safe_name(filename: str) -> str:
    # This name is metadata only, but avoid preserving paths or control characters.
    name = Path(filename).name.replace("\x00", "").strip()
    return name[:255] or "restored-file"


def encrypt_file(source: Path, destination: Path, password: str, original_filename: str) -> dict:
    """Encrypt *source* to *destination* without loading the whole file into memory."""
    salt, nonce = os.urandom(16), os.urandom(12)
    params = KDF_PARAMETERS.copy()
    header = {
        "format": "SENTINELGUARD",
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": "Argon2id",
        "kdf_parameters": params,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "original_filename": _safe_name(original_filename),
        "original_extension": Path(_safe_name(original_filename)).suffix.lower(),
        "original_sha256": sha256_file(source),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    encoded_header = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded_header) > 64 * 1024:
        raise EncryptedFileError("Encrypted-file metadata is too large.")
    key = _key(password, salt, params)
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        cipher.authenticate_additional_data(encoded_header)
        with destination.open("xb") as encrypted, source.open("rb") as plaintext:
            encrypted.write(MAGIC + struct.pack(">I", len(encoded_header)) + encoded_header)
            for block in iter(lambda: plaintext.read(CHUNK_SIZE), b""):
                encrypted.write(cipher.update(block))
            encrypted.write(cipher.finalize())
            encrypted.write(cipher.tag)
    finally:
        # Best effort: do not retain a second long-lived key reference.
        key = b""
    return header


def read_header(source: Path) -> tuple[dict, bytes, int]:
    """Read and validate public, non-secret `.sguard` metadata."""
    try:
        size = source.stat().st_size
        with source.open("rb") as encrypted:
            if encrypted.read(len(MAGIC)) != MAGIC:
                raise EncryptedFileError("This is not a SentinelGuard encrypted file.")
            raw_length = encrypted.read(4)
            if len(raw_length) != 4:
                raise EncryptedFileError("The encrypted file header is incomplete.")
            length = struct.unpack(">I", raw_length)[0]
            if not 2 <= length <= 64 * 1024 or size < len(MAGIC) + 4 + length + TAG_LENGTH:
                raise EncryptedFileError("The encrypted file is corrupted.")
            raw_header = encrypted.read(length)
            header = json.loads(raw_header.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EncryptedFileError("The encrypted file metadata is invalid.") from exc
    required = {"format", "version", "algorithm", "kdf", "kdf_parameters", "salt", "nonce", "original_filename", "original_sha256"}
    if not isinstance(header, dict) or not required.issubset(header) or header["format"] != "SENTINELGUARD" or header["version"] != 1:
        raise EncryptedFileError("Unsupported SentinelGuard encrypted-file format.")
    if header["algorithm"] != "AES-256-GCM" or header["kdf"] != "Argon2id":
        raise EncryptedFileError("Unsupported encryption parameters.")
    return header, raw_header, len(MAGIC) + 4 + length


def decrypt_file(source: Path, destination: Path, password: str) -> dict:
    """Decrypt only after the GCM tag validates; delete any partial plaintext on failure."""
    header, raw_header, ciphertext_offset = read_header(source)
    try:
        salt = base64.b64decode(header["salt"], validate=True)
        nonce = base64.b64decode(header["nonce"], validate=True)
        params = header["kdf_parameters"]
        if len(salt) != 16 or len(nonce) != 12 or set(params) != set(KDF_PARAMETERS) or any(not isinstance(params[k], int) for k in params):
            raise ValueError
        # Bound attacker-controlled KDF work before deriving a key.
        if not (1 <= params["time_cost"] <= 6 and 8192 <= params["memory_cost"] <= 131072 and 1 <= params["parallelism"] <= 4 and params["hash_len"] == 32):
            raise ValueError
    except (KeyError, ValueError, TypeError, base64.binascii.Error) as exc:
        raise EncryptedFileError("The encrypted file metadata is invalid.") from exc
    key = _key(password, salt, params)
    try:
        tag_offset = source.stat().st_size - TAG_LENGTH
        with source.open("rb") as encrypted, destination.open("xb") as plaintext:
            encrypted.seek(tag_offset)
            tag = encrypted.read(TAG_LENGTH)
            encrypted.seek(ciphertext_offset)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(raw_header)
            remaining = tag_offset - ciphertext_offset
            while remaining:
                block = encrypted.read(min(CHUNK_SIZE, remaining))
                if not block:
                    raise EncryptedFileError("The encrypted file is corrupted.")
                remaining -= len(block)
                plaintext.write(decryptor.update(block))
            plaintext.write(decryptor.finalize())
    except (InvalidTag, OSError) as exc:
        destination.unlink(missing_ok=True)
        raise EncryptedFileError("Decryption failed. The password may be incorrect or the encrypted file may have been modified or corrupted.") from exc
    finally:
        key = b""
    if sha256_file(destination) != header["original_sha256"]:
        destination.unlink(missing_ok=True)
        raise EncryptedFileError("Decryption failed. The password may be incorrect or the encrypted file may have been modified or corrupted.")
    return header
