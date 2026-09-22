from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, EmailStr, Field


# Auth Schemas
class RegisterIn(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=10, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    email: str
    display_name: str
    retention_days: int = 30
    created_at: datetime


class UserSettingsIn(BaseModel):
    display_name: Optional[str] = Field(None, min_length=2, max_length=100)
    retention_days: Optional[int] = Field(None, ge=1, le=365)


# Scan & Threat Schemas
class ThreatOut(BaseModel):
    category: str
    severity: str
    message: str


class ScanSummaryOut(BaseModel):
    id: int
    filename: str
    sha256: str
    mime_type: str
    extension: str
    size: int
    entropy: float
    risk_score: int
    risk_level: str
    concern_level: str
    finding_count: int
    is_quarantined: bool = False
    created_at: datetime


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
    concern_level: str
    is_quarantined: bool = False
    quarantine_reason: str = ""
    details: dict[str, Any]
    threats: list[ThreatOut]
    created_at: datetime


# Encryption & Vault Schemas
class EncryptResult(BaseModel):
    id: int
    original_filename: str
    encrypted_filename: str
    original_sha256: str
    algorithm: str
    kdf: str
    file_size: int
    download_url: str
    vault_file_id: Optional[int] = None


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


class VaultFileOut(BaseModel):
    id: int
    original_filename: str
    encrypted_filename: str
    file_size: int
    original_sha256: str
    algorithm: str
    kdf: str
    notes: str
    created_at: datetime


class VaultDecryptOut(BaseModel):
    original_filename: str
    original_sha256: str
    algorithm: str
    kdf: str
    file_size: int
    integrity: str
    download_url: str


# Quarantine Schemas
class QuarantineItemOut(BaseModel):
    id: int
    scan_id: int
    original_filename: str
    reason: str
    risk_score: int
    risk_level: str
    concern_level: str
    findings_count: int
    status: str
    created_at: datetime


class QuarantineActionIn(BaseModel):
    reason: Optional[str] = "Manual user quarantine"


# Dashboard & Health Schemas
class DashboardStatsOut(BaseModel):
    total_scans: int
    files_requiring_review: int
    protected_files: int
    reports_generated: int
    risk_levels: dict[str, int]
    concern_levels: dict[str, int]
    recent_scans: list[ScanSummaryOut]
    recent_vault_files: list[VaultFileOut]


class HealthStatusOut(BaseModel):
    status: str
    timestamp: datetime
    version: str = "1.0.0"
    engine: str = "online"
