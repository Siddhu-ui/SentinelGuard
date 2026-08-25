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
