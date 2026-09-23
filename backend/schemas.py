from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class RegisterIn(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=10, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    email: str
    display_name: str
    created_at: datetime


class ThreatOut(BaseModel):
    category: str
    severity: str
    message: str
    evidence: str = ""


class ScanOut(BaseModel):
    id: int
    filename: str
    sha256: str
    mime_type: str
    extension: str
    size: int
    entropy: float
    risk_score: int
    risk_level: str
    analysis_status: str = "completed"
    analysis_error: str | None = None
    details: dict
    threats: list[ThreatOut]
    created_at: datetime


class EncryptResult(BaseModel):
    """Returned when an encrypted file is ready for download (via a separate download endpoint)."""
    id: int
    original_filename: str
    encrypted_filename: str
    original_sha256: str
    algorithm: str
    kdf: str
    file_size: int
    download_url: str


class EncryptHistoryOut(BaseModel):
    id: int
    original_filename: str
    encrypted_filename: str
    file_size: int
    sha256: str
    algorithm: str
    kdf: str
    status: str
    created_at: datetime


# ── Vault ───────────────────────────────────────────────────────────────────

class VaultSetupIn(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    confirm: str = Field(min_length=1, max_length=128)


class VaultUnlockIn(BaseModel):
    password: str = Field(min_length=1, max_length=128)


class VaultStatusOut(BaseModel):
    exists: bool
    unlocked: bool
    item_count: int = 0


class VaultUnlockOut(BaseModel):
    vault_token: str
    expires_in: int


class VaultItemOut(BaseModel):
    id: int
    original_filename: str
    file_size: int
    sha256: str
    algorithm: str
    kdf: str
    created_at: datetime


class VaultAddOut(BaseModel):
    item: VaultItemOut


# ── Quarantine ──────────────────────────────────────────────────────────────

class QuarantineIn(BaseModel):
    scan_id: int


class QuarantineOut(BaseModel):
    id: int
    scan_id: int
    filename: str
    risk_score: int
    risk_level: str
    reason: str
    created_at: datetime
