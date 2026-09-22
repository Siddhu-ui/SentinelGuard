from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(255))
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    
    scans: Mapped[list["Scan"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    encryptions: Mapped[list["EncryptionRecord"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    vault_files: Mapped[list["VaultFile"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    quarantine_items: Mapped[list["QuarantineItem"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user", cascade="all, delete-orphan")


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
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    quarantine_reason: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    
    user: Mapped[User] = relationship(back_populates="scans")
    threats: Mapped[list["Threat"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    quarantine_entry: Mapped["QuarantineItem"] = relationship(back_populates="scan", uselist=False, cascade="all, delete-orphan")


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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    user: Mapped[User] = relationship(back_populates="encryptions")


class VaultFile(Base):
    __tablename__ = "vault_files"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    encrypted_filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(64), unique=True)
    file_size: Mapped[int] = mapped_column(Integer)
    original_sha256: Mapped[str] = mapped_column(String(64), default="")
    algorithm: Mapped[str] = mapped_column(String(50), default="AES-256-GCM")
    kdf: Mapped[str] = mapped_column(String(50), default="Argon2id")
    notes: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    user: Mapped[User] = relationship(back_populates="vault_files")


class QuarantineItem(Base):
    __tablename__ = "quarantine_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True, index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(String(255))
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(20))
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="quarantined")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    
    user: Mapped[User] = relationship(back_populates="quarantine_items")
    scan: Mapped[Scan] = relationship(back_populates="quarantine_entry")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    details: Mapped[str] = mapped_column(String(255))
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    user: Mapped[User] = relationship(back_populates="audit_logs")
