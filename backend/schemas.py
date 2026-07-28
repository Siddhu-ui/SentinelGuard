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
