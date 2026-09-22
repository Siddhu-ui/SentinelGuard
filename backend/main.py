import hashlib
import json
import logging
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database import Base, engine, get_db, migrate_legacy_schema
from models import AuditLog, EncryptionRecord, QuarantineItem, Scan, Threat, User, VaultFile
from scanner.analyzers import analyze
from schemas import (
    ChangePasswordIn,
    DashboardStatsOut,
    EncryptHistoryOut,
    EncryptResult,
    HealthStatusOut,
    LoginIn,
    QuarantineItemOut,
    RegisterIn,
    ScanOut,
    ScanSummaryOut,
    TokenOut,
    UserOut,
    UserSettingsIn,
    VaultDecryptOut,
    VaultFileOut,
)
from services.auth import create_token, current_user, hash_password, verify_password
from services.crypto import (
    decrypt_file,
    encrypt_file,
    get_download_filename,
    parse_sguard,
)
from services.report import render_pdf
from settings import settings

logger = logging.getLogger("sentinelguard")

# Database initialization & additive migrations
Base.metadata.create_all(bind=engine)
migrate_legacy_schema()

# Storage directory setup
settings.upload_path.mkdir(parents=True, exist_ok=True)
vault_storage = settings.upload_path / "vault"
vault_storage.mkdir(parents=True, exist_ok=True)
protected_storage = settings.upload_path / "protected"
protected_storage.mkdir(parents=True, exist_ok=True)
quarantine_storage = settings.upload_path / "quarantine"
quarantine_storage.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="SentinelGuard API",
    version="1.0.0",
    description="Privacy-focused file security platform. Static pre-analysis and AES-256-GCM file protection.",
)

# CORS Configuration
cors_list = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_list or ["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _safe_resolve(base_dir: Path, filename: str) -> Path:
    """Ensure filename does not perform path traversal outside base_dir."""
    safe_name = Path(filename).name
    if safe_name != filename or safe_name in {".", "..", ""}:
        raise HTTPException(status_code=400, detail="Invalid filename or path")
    target = (base_dir / safe_name).resolve()
    if not str(target).startswith(str(base_dir.resolve())):
        raise HTTPException(status_code=400, detail="Path traversal attempt blocked")
    return target


def scan_out(s: Scan) -> dict:
    d = json.loads(s.details_json) if s.details_json else {}
    concern = d.get("concern_level", "Low concern" if s.risk_score <= 20 else "Review recommended" if s.risk_score <= 50 else "High concern")
    return {
        "id": s.id,
        "filename": s.filename,
        "sha256": s.sha256,
        "mime_type": s.mime_type,
        "extension": s.extension,
        "size": s.size,
        "entropy": s.entropy,
        "risk_score": s.risk_score,
        "risk_level": s.risk_level,
        "concern_level": concern,
        "is_quarantined": bool(s.is_quarantined),
        "quarantine_reason": s.quarantine_reason or "",
        "details": d,
        "threats": [{"category": t.category, "severity": t.severity, "message": t.message} for t in s.threats],
        "created_at": s.created_at,
    }


def scan_summary(s: Scan) -> dict:
    d = json.loads(s.details_json) if s.details_json else {}
    concern = d.get("concern_level", "Low concern" if s.risk_score <= 20 else "Review recommended" if s.risk_score <= 50 else "High concern")
    return {
        "id": s.id,
        "filename": s.filename,
        "sha256": s.sha256,
        "mime_type": s.mime_type,
        "extension": s.extension,
        "size": s.size,
        "entropy": s.entropy,
        "risk_score": s.risk_score,
        "risk_level": s.risk_level,
        "concern_level": concern,
        "finding_count": len(s.threats),
        "is_quarantined": bool(s.is_quarantined),
        "created_at": s.created_at,
    }


# ==============================================================================
# Health Endpoints
# ==============================================================================

@app.get("/health", response_model=HealthStatusOut)
@app.get("/api/v1/health", response_model=HealthStatusOut)
def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc),
        "version": "1.0.0",
        "engine": "online",
    }


# ==============================================================================
# Authentication Endpoints
# ==============================================================================

@app.post("/auth/register", response_model=TokenOut)
@app.post("/api/v1/auth/register", response_model=TokenOut)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == body.email.lower())):
        raise HTTPException(status_code=409, detail="Email is already registered")
    user = User(
        email=body.email.lower(),
        display_name=body.display_name.strip(),
        password_hash=hash_password(body.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"access_token": create_token(user)}


@app.post("/auth/login", response_model=TokenOut)
@app.post("/api/v1/auth/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user)}


@app.get("/auth/me", response_model=UserOut)
@app.get("/api/v1/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@app.post("/api/v1/auth/change-password")
def change_password(body: ChangePasswordIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password incorrect")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"status": "success", "message": "Password updated successfully"}


# ==============================================================================
# Security Scan Endpoints
# ==============================================================================

@app.post("/scans", response_model=ScanOut)
@app.post("/api/v1/scan", response_model=ScanOut)
async def create_scan(
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    filename = Path(file.filename or "upload.bin").name
    ext = Path(filename).suffix.lower().lstrip(".")
    allowed = {"pdf", "png", "jpg", "jpeg", "gif", "bmp", "zip", "rar", "docx", "xlsx", "pptx", "exe"}
    if ext not in allowed:
        raise HTTPException(status_code=415, detail=f"Unsupported file extension: .{ext}")

    stored = f"{uuid.uuid4().hex}_{ext}"
    target = settings.upload_path / stored
    size = 0

    try:
        with target.open("wb") as dst:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_mb * 1024 * 1024:
                    raise HTTPException(status_code=413, detail="File exceeds maximum upload size limit")
                dst.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        
        result = analyze(target, ext)
    except HTTPException:
        target.unlink(missing_ok=True)
        raise
    except Exception as e:
        target.unlink(missing_ok=True)
        logger.error("Scan analysis failed: %s", str(e))
        raise HTTPException(status_code=500, detail="Static analysis could not be completed.")

    scan = Scan(
        user_id=user.id,
        filename=filename,
        stored_name=stored,
        sha256=result["sha256"],
        mime_type=result["mime_type"],
        extension=ext,
        size=size,
        entropy=result["entropy"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        details_json=json.dumps(result),
        is_quarantined=False,
    )
    db.add(scan)
    db.flush()

    for issue in result["issues"]:
        db.add(Threat(
            scan_id=scan.id,
            category=issue["category"],
            severity=issue["severity"],
            message=issue["message"],
        ))

    db.commit()
    db.refresh(scan)
    return scan_out(scan)


@app.get("/scans", response_model=list[ScanOut])
@app.get("/api/v1/scans", response_model=list[ScanOut])
def list_scans(
    q: str = "",
    concern: str = "",
    limit: int = 100,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = q[:100].strip()
    stmt = select(Scan).where(Scan.user_id == user.id)
    if q:
        stmt = stmt.where(Scan.filename.ilike(f"%{q}%"))
    if concern:
        c_lower = concern.lower()
        if "low" in c_lower:
            stmt = stmt.where(Scan.risk_score <= 20)
        elif "review" in c_lower:
            stmt = stmt.where(Scan.risk_score > 20, Scan.risk_score <= 50)
        elif "high" in c_lower or "critical" in c_lower:
            stmt = stmt.where(Scan.risk_score > 50)

    stmt = stmt.order_by(Scan.created_at.desc()).limit(min(limit, 200))
    scans = db.scalars(stmt).unique().all()
    return [scan_out(x) for x in scans]


@app.get("/scans/{scan_id}", response_model=ScanOut)
@app.get("/api/v1/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_out(scan)


@app.delete("/scans/{scan_id}", status_code=204)
@app.delete("/api/v1/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Securely remove scan file from disk
    (settings.upload_path / scan.stored_name).unlink(missing_ok=True)
    (quarantine_storage / scan.stored_name).unlink(missing_ok=True)
    
    db.delete(scan)
    db.commit()


@app.delete("/scans", status_code=204)
@app.delete("/api/v1/scans", status_code=204)
def delete_all_scans(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Clear authenticated user's scan history and stored scan files."""
    scans = db.scalars(select(Scan).where(Scan.user_id == user.id)).unique().all()
    for scan in scans:
        (settings.upload_path / scan.stored_name).unlink(missing_ok=True)
        (quarantine_storage / scan.stored_name).unlink(missing_ok=True)
        db.delete(scan)
    db.commit()


# ==============================================================================
# PDF Reports Endpoints
# ==============================================================================

@app.get("/scans/{scan_id}/report.pdf")
@app.get("/api/v1/scans/{scan_id}/report")
def get_scan_report(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    pdf_stream = render_pdf(scan)
    return StreamingResponse(
        pdf_stream,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sentinelguard-report-{scan.id}.pdf"'},
    )


@app.get("/api/v1/reports", response_model=list[ScanSummaryOut])
def list_reports(q: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)):
    stmt = select(Scan).where(Scan.user_id == user.id)
    if q.strip():
        stmt = stmt.where(Scan.filename.ilike(f"%{q.strip()}%"))
    stmt = stmt.order_by(Scan.created_at.desc())
    scans = db.scalars(stmt).unique().all()
    return [scan_summary(s) for s in scans]


# ==============================================================================
# Protection & Encryption Endpoints
# ==============================================================================

@app.post("/encrypt", response_model=EncryptResult)
@app.post("/api/v1/files/protect", response_model=EncryptResult)
async def protect_file(
    file: UploadFile = File(...),
    password: str = Form(...),
    save_to_vault: bool = Form(True),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Encrypt an uploaded file using AES-256-GCM. Stores in vault if save_to_vault=True."""
    if not password or not password.strip():
        raise HTTPException(status_code=400, detail="Password is required")
    if len(password) > 128:
        raise HTTPException(status_code=400, detail="Password is too long (max 128 chars)")

    original_name = Path(file.filename or "upload.bin").name
    plaintext = await file.read()
    if not plaintext:
        raise HTTPException(status_code=400, detail="File is empty")
    if len(plaintext) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds maximum upload size")

    original_sha256 = hashlib.sha256(plaintext).hexdigest()

    try:
        sguard_blob = encrypt_file(plaintext, password, original_name)
    except Exception as e:
        logger.error("Encryption failed: %s", str(e))
        raise HTTPException(status_code=500, detail="Encryption failed. Please try again.")

    stored_name = f"{uuid.uuid4().hex}.sguard"
    download_name = get_download_filename(original_name)

    # Save encrypted blob in protected directory
    target_path = protected_storage / stored_name
    target_path.write_bytes(sguard_blob)

    # Record in encryption history
    enc_record = EncryptionRecord(
        user_id=user.id,
        operation="encrypt",
        original_filename=original_name,
        encrypted_filename=download_name,
        stored_name=stored_name,
        file_size=len(sguard_blob),
        sha256=original_sha256,
        original_sha256=original_sha256,
        algorithm="AES-256-GCM",
        kdf="Argon2id",
        status="success",
    )
    db.add(enc_record)
    db.flush()

    vault_file_id = None
    if save_to_vault:
        vault_entry = VaultFile(
            user_id=user.id,
            original_filename=original_name,
            encrypted_filename=download_name,
            stored_name=stored_name,
            file_size=len(sguard_blob),
            original_sha256=original_sha256,
            algorithm="AES-256-GCM",
            kdf="Argon2id",
            notes=notes.strip()[:250],
        )
        db.add(vault_entry)
        db.flush()
        vault_file_id = vault_entry.id

    db.commit()

    return {
        "id": enc_record.id,
        "original_filename": original_name,
        "encrypted_filename": download_name,
        "original_sha256": original_sha256,
        "algorithm": "AES-256-GCM",
        "kdf": "Argon2id",
        "file_size": len(sguard_blob),
        "download_url": f"/encrypt/download/{enc_record.id}",
        "vault_file_id": vault_file_id,
    }


@app.get("/encrypt/download/{record_id}")
@app.get("/api/v1/files/download/{record_id}")
async def download_encrypted(
    record_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    record = db.scalar(select(EncryptionRecord).where(
        EncryptionRecord.id == record_id,
        EncryptionRecord.user_id == user.id,
    ))
    if not record:
        raise HTTPException(status_code=404, detail="Encrypted file not found")

    path = protected_storage / record.stored_name
    if not path.exists():
        path = protected_storage / record.encrypted_filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Encrypted file not found on disk")

    download_name = get_download_filename(record.original_filename)
    return StreamingResponse(
        path.open("rb"),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{download_name}"'},
    )


@app.get("/encryption/history", response_model=list[EncryptHistoryOut])
async def encryption_history(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    records = db.scalars(
        select(EncryptionRecord)
        .where(EncryptionRecord.user_id == user.id)
        .order_by(EncryptionRecord.created_at.desc())
    ).all()
    return records


@app.post("/decrypt")
async def decrypt(
    file: UploadFile = File(...),
    password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not password or not password.strip():
        raise HTTPException(status_code=400, detail="Password is required")

    filename = Path(file.filename or "upload.sguard").name
    if not filename.lower().endswith(".sguard"):
        raise HTTPException(status_code=400, detail="Only .sguard files can be decrypted")
    
    sguard_data = await file.read()
    if not sguard_data:
        raise HTTPException(status_code=400, detail="File is empty")
    if len(sguard_data) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds maximum upload size")

    try:
        plaintext, meta = decrypt_file(sguard_data, password)
    except ValueError as e:
        logger.warning("Decryption rejected: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Decryption failed: %s", str(e))
        raise HTTPException(status_code=500, detail="Decryption failed. Please try again.")

    decrypted_name = f"{uuid.uuid4().hex}_decrypted"
    target = protected_storage / decrypted_name
    target.write_bytes(plaintext)

    original_filename = Path(meta["original_filename"]).name

    return {
        "id": 0,
        "original_filename": original_filename,
        "original_sha256": meta["original_sha256"],
        "algorithm": meta["algorithm"],
        "kdf": meta["kdf"],
        "file_size": len(plaintext),
        "integrity": "VERIFIED",
        "download_url": f"/decrypt/download/{decrypted_name}/{original_filename}",
    }


@app.get("/decrypt/download/{stored_name}/{original_filename}")
async def download_decrypted(
    stored_name: str,
    original_filename: str,
    user: User = Depends(current_user),
):
    if not re.fullmatch(r'[a-f0-9]+_decrypted', stored_name):
        raise HTTPException(status_code=400, detail="Invalid stored file identifier")
    safe_filename = Path(original_filename).name
    if safe_filename != original_filename or safe_filename in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid original filename")

    path = protected_storage / stored_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Decrypted file not found or has expired")

    return StreamingResponse(
        path.open("rb"),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )


# ==============================================================================
# Secure Vault Endpoints
# ==============================================================================

@app.get("/api/v1/vault", response_model=list[VaultFileOut])
def list_vault_files(
    q: str = "",
    sort_by: str = "date",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    stmt = select(VaultFile).where(VaultFile.user_id == user.id)
    if q.strip():
        stmt = stmt.where(VaultFile.original_filename.ilike(f"%{q.strip()}%"))
    
    if sort_by == "name":
        stmt = stmt.order_by(VaultFile.original_filename.asc())
    elif sort_by == "size":
        stmt = stmt.order_by(VaultFile.file_size.desc())
    else:
        stmt = stmt.order_by(VaultFile.created_at.desc())

    files = db.scalars(stmt).all()
    return files


@app.post("/api/v1/vault/upload", response_model=VaultFileOut)
async def upload_to_vault(
    file: UploadFile = File(...),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Directly upload an existing .sguard file into the user's Secure Vault."""
    filename = Path(file.filename or "file.sguard").name
    if not filename.lower().endswith(".sguard"):
        raise HTTPException(status_code=400, detail="Vault upload requires a valid .sguard encrypted file.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="File is empty")
    if len(content) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds maximum upload size")

    try:
        parsed = parse_sguard(content)
        orig_name = parsed["original_filename"]
        orig_sha = parsed["original_sha256"].hex()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid .sguard file format: {str(e)}")

    stored_name = f"{uuid.uuid4().hex}.sguard"
    target = protected_storage / stored_name
    target.write_bytes(content)

    vault_file = VaultFile(
        user_id=user.id,
        original_filename=orig_name,
        encrypted_filename=filename,
        stored_name=stored_name,
        file_size=len(content),
        original_sha256=orig_sha,
        algorithm="AES-256-GCM",
        kdf="Argon2id" if parsed["kdf_id"] == 1 else "PBKDF2-HMAC-SHA256",
        notes=notes.strip()[:250],
    )
    db.add(vault_file)
    db.commit()
    db.refresh(vault_file)
    return vault_file


@app.post("/api/v1/vault/{vault_id}/decrypt", response_model=VaultDecryptOut)
def decrypt_vault_file(
    vault_id: int,
    password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Decrypt a file currently stored in the Vault with the user password."""
    vf = db.scalar(select(VaultFile).where(VaultFile.id == vault_id, VaultFile.user_id == user.id))
    if not vf:
        raise HTTPException(status_code=404, detail="Vault file not found")

    file_path = protected_storage / vf.stored_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Encrypted file not found on disk")

    data = file_path.read_bytes()
    try:
        plaintext, meta = decrypt_file(data, password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failed. Please try again.")

    decrypted_name = f"{uuid.uuid4().hex}_decrypted"
    target = protected_storage / decrypted_name
    target.write_bytes(plaintext)

    orig_name = Path(meta["original_filename"]).name

    return {
        "original_filename": orig_name,
        "original_sha256": meta["original_sha256"],
        "algorithm": meta["algorithm"],
        "kdf": meta["kdf"],
        "file_size": len(plaintext),
        "integrity": "VERIFIED",
        "download_url": f"/decrypt/download/{decrypted_name}/{orig_name}",
    }


@app.get("/api/v1/vault/{vault_id}/download")
def download_vault_file(
    vault_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    vf = db.scalar(select(VaultFile).where(VaultFile.id == vault_id, VaultFile.user_id == user.id))
    if not vf:
        raise HTTPException(status_code=404, detail="Vault file not found")

    path = protected_storage / vf.stored_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Encrypted vault file not found on disk")

    return StreamingResponse(
        path.open("rb"),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{vf.encrypted_filename}"'},
    )


@app.delete("/api/v1/vault/{vault_id}", status_code=204)
def delete_vault_file(
    vault_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    vf = db.scalar(select(VaultFile).where(VaultFile.id == vault_id, VaultFile.user_id == user.id))
    if not vf:
        raise HTTPException(status_code=404, detail="Vault file not found")

    path = protected_storage / vf.stored_name
    path.unlink(missing_ok=True)

    db.delete(vf)
    db.commit()


# ==============================================================================
# Quarantine Endpoints
# ==============================================================================

@app.get("/api/v1/quarantine", response_model=list[QuarantineItemOut])
def list_quarantine(user: User = Depends(current_user), db: Session = Depends(get_db)):
    items = db.scalars(
        select(QuarantineItem)
        .where(QuarantineItem.user_id == user.id, QuarantineItem.status == "quarantined")
        .order_by(QuarantineItem.created_at.desc())
    ).all()
    
    result = []
    for item in items:
        concern = "Low concern" if item.risk_score <= 20 else "Review recommended" if item.risk_score <= 50 else "High concern"
        result.append({
            "id": item.id,
            "scan_id": item.scan_id,
            "original_filename": item.original_filename,
            "reason": item.reason,
            "risk_score": item.risk_score,
            "risk_level": item.risk_level,
            "concern_level": concern,
            "findings_count": item.findings_count,
            "status": item.status,
            "created_at": item.created_at,
        })
    return result


@app.post("/api/v1/quarantine/{scan_id}", response_model=QuarantineItemOut)
def quarantine_scan(
    scan_id: int,
    reason: str = Form("Moved to quarantine after review"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    src = settings.upload_path / scan.stored_name
    dst = quarantine_storage / scan.stored_name
    if src.exists():
        shutil.move(str(src), str(dst))

    scan.is_quarantined = True
    scan.quarantine_reason = reason.strip()

    existing_qi = db.scalar(select(QuarantineItem).where(QuarantineItem.scan_id == scan.id))
    if existing_qi:
        existing_qi.status = "quarantined"
        existing_qi.reason = reason.strip()
        qi = existing_qi
    else:
        qi = QuarantineItem(
            user_id=user.id,
            scan_id=scan.id,
            original_filename=scan.filename,
            stored_name=scan.stored_name,
            reason=reason.strip(),
            risk_score=scan.risk_score,
            risk_level=scan.risk_level,
            findings_count=len(scan.threats),
            status="quarantined",
        )
        db.add(qi)

    db.commit()
    db.refresh(qi)

    concern = "Low concern" if qi.risk_score <= 20 else "Review recommended" if qi.risk_score <= 50 else "High concern"
    return {
        "id": qi.id,
        "scan_id": qi.scan_id,
        "original_filename": qi.original_filename,
        "reason": qi.reason,
        "risk_score": qi.risk_score,
        "risk_level": qi.risk_level,
        "concern_level": concern,
        "findings_count": qi.findings_count,
        "status": qi.status,
        "created_at": qi.created_at,
    }


@app.post("/api/v1/quarantine/{scan_id}/restore")
def restore_quarantine(
    scan_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    src = quarantine_storage / scan.stored_name
    dst = settings.upload_path / scan.stored_name
    if src.exists():
        shutil.move(str(src), str(dst))

    scan.is_quarantined = False
    scan.quarantine_reason = ""

    qi = db.scalar(select(QuarantineItem).where(QuarantineItem.scan_id == scan.id))
    if qi:
        qi.status = "restored"

    db.commit()
    return {"status": "restored", "scan_id": scan.id}


@app.delete("/api/v1/quarantine/{scan_id}", status_code=204)
def delete_quarantined_file(
    scan_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    (quarantine_storage / scan.stored_name).unlink(missing_ok=True)
    (settings.upload_path / scan.stored_name).unlink(missing_ok=True)

    db.delete(scan)
    db.commit()


# ==============================================================================
# Dashboard & Overview Endpoints
# ==============================================================================

@app.get("/dashboard")
@app.get("/api/v1/dashboard")
def get_dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    scans = db.scalars(select(Scan).where(Scan.user_id == user.id).order_by(Scan.created_at.desc())).all()
    vault_files = db.scalars(select(VaultFile).where(VaultFile.user_id == user.id).order_by(VaultFile.created_at.desc())).all()
    
    total = len(scans)
    requiring_review = sum(1 for s in scans if s.risk_score > 20)
    protected_count = len(vault_files)
    reports_count = total

    risk_counts = {level: sum(x.risk_level == level for x in scans) for level in ["Safe", "Low", "Medium", "High", "Critical"]}
    concern_counts = {
        "Low concern": sum(1 for s in scans if s.risk_score <= 20),
        "Review recommended": sum(1 for s in scans if 20 < s.risk_score <= 50),
        "High concern": sum(1 for s in scans if s.risk_score > 50),
    }

    return {
        "total": total,
        "total_scans": total,
        "threats": requiring_review,
        "files_requiring_review": requiring_review,
        "protected_files": protected_count,
        "reports_generated": reports_count,
        "risk_levels": risk_counts,
        "concern_levels": concern_counts,
        "recent": [scan_out(x) for x in scans[:8]],
        "recent_scans": [scan_summary(x) for x in scans[:8]],
        "recent_vault_files": vault_files[:5],
    }


# ==============================================================================
# Settings Endpoints
# ==============================================================================

@app.get("/api/v1/settings")
def get_settings(user: User = Depends(current_user)):
    return {
        "display_name": user.display_name,
        "email": user.email,
        "retention_days": user.retention_days,
        "max_upload_mb": settings.max_upload_mb,
        "version": "1.0.0",
        "created_at": user.created_at,
    }


@app.post("/api/v1/settings")
def update_settings(
    body: UserSettingsIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    if body.retention_days is not None:
        user.retention_days = body.retention_days
    db.commit()
    return {"status": "success", "message": "Settings updated"}
