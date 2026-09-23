from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    scans: Mapped[list["Scan"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    encryptions: Mapped[list["EncryptionRecord"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(64), unique=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    mime_type: Mapped[str] = mapped_column(String(150))
    extension: Mapped[str] = mapped_column(String(20))
    size: Mapped[int] = mapped_column(Integer)
    entropy: Mapped[float] = mapped_column()
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(20))
    details_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    user: Mapped[User] = relationship(back_populates="scans")
    threats: Mapped[list["Threat"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

class Threat(Base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    category: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    scan: Mapped[Scan] = relationship(back_populates="threats")

class EncryptionRecord(Base):
    __tablename__ = "encryption_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    operation: Mapped[str] = mapped_column(String(12), default="encrypt")
    original_filename: Mapped[str] = mapped_column(String(255))
    encrypted_filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(64), default="")
    file_size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    original_sha256: Mapped[str] = mapped_column(String(64), default="")
    algorithm: Mapped[str] = mapped_column(String(50))
    kdf: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="success")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    user: Mapped[User] = relationship(back_populates="encryptions")


class VaultKey(Base):
    """Per-user Vault credential. Stores only a salted hash of the Vault password —
    never the plaintext. Argon2id params mirror services.crypto for auditability."""
    __tablename__ = "vault_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class VaultRecord(Base):
    """A file protected in the user's Vault. Bytes live on disk encrypted with
    AES-256-GCM under a key derived from the Vault password (Argon2id per file).
    The plaintext password and the derived key are never persisted."""
    __tablename__ = "vault_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(80), unique=True)
    original_sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(Integer)  # decrypted size
    algorithm: Mapped[str] = mapped_column(String(50), default="AES-256-GCM")
    kdf: Mapped[str] = mapped_column(String(50), default="Argon2id")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class QuarantineRecord(Base):
    """A suspicious scan artifact isolated from normal storage. Content is kept
    opaque on disk under a server-generated name; nothing is ever executed."""
    __tablename__ = "quarantine_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(80), unique=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
