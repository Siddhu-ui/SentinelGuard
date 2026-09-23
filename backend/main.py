import hashlib, json, secrets, shutil, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from database import Base, engine, get_db
from models import EncryptionRecord, QuarantineRecord, Scan, Threat, User, VaultKey, VaultRecord
from schemas import (EncryptHistoryOut, EncryptResult, LoginIn, QuarantineIn, QuarantineOut, RegisterIn,
                     ScanOut, TokenOut, UserOut, VaultAddOut, VaultItemOut, VaultSetupIn, VaultStatusOut,
                     VaultUnlockIn, VaultUnlockOut)
from services.vault import (decrypt_vault_blob, encrypt_vault_blob, hash_vault_password,
                            is_strong_vault_password, new_stored_name, safe_vault_path,
                            verify_vault_password)
import bcrypt, jwt
from scanner.analyzers import analyze
from services.auth import create_token, current_user, hash_password, verify_password
from services.crypto import encrypt_file, decrypt_file, get_download_filename
from services.report import render_pdf
from settings import settings

Base.metadata.create_all(bind=engine)
from database import migrate_legacy_schema
migrate_legacy_schema()
settings.upload_path.mkdir(parents=True, exist_ok=True); settings.upload_path.joinpath("protected").mkdir(parents=True, exist_ok=True)
app=FastAPI(title="SentinelGuard API", version="1.0.0", description="Static pre-analysis of suspicious files. Files are never executed.")
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def scan_out(s: Scan) -> dict:
    d=json.loads(s.details_json)
    # analysis_status distinguishes a completed analysis (with or without findings)
    # from one where the engine itself failed; the frontend surfaces this directly.
    status=d.get("analysis_status", "completed")
    return {"id":s.id,"filename":s.filename,"sha256":s.sha256,"mime_type":s.mime_type,"extension":s.extension,"size":s.size,"entropy":s.entropy,"risk_score":s.risk_score,"risk_level":s.risk_level,"analysis_status":status,"analysis_error":d.get("analysis_error"),"details":d,"threats":[{"category":t.category,"severity":t.severity,"message":t.message,"evidence":(d.get("evidence_by_message") or {}).get(t.message,"")} for t in s.threats],"created_at":s.created_at}

@app.get("/health")
def health(): return {"status":"ok", "timestamp":datetime.now(timezone.utc)}

@app.post("/auth/register", response_model=TokenOut)
def register(body:RegisterIn, db:Session=Depends(get_db)):
    if db.scalar(select(User).where(User.email==body.email.lower())): raise HTTPException(409,"Email is already registered")
    user=User(email=body.email.lower(),display_name=body.display_name,password_hash=hash_password(body.password)); db.add(user); db.commit(); db.refresh(user)
    return {"access_token":create_token(user)}

@app.post("/auth/login", response_model=TokenOut)
def login(body:LoginIn, db:Session=Depends(get_db)):
    user=db.scalar(select(User).where(User.email==body.email.lower()))
    if not user or not verify_password(body.password,user.password_hash): raise HTTPException(401,"Invalid email or password")
    return {"access_token":create_token(user)}

@app.get("/auth/me", response_model=UserOut)
def me(user:User=Depends(current_user)): return user

@app.post("/scans", response_model=ScanOut)
async def create_scan(file:UploadFile=File(...), user:User=Depends(current_user), db:Session=Depends(get_db)):
    filename=Path(file.filename or "upload.bin").name
    # Scoring never uses the filename: only the stored bytes are analyzed.
    ext=Path(filename).suffix.lower().lstrip(".")
    allowed={"pdf","png","jpg","jpeg","gif","bmp","zip","rar","docx","xlsx","pptx","exe"}
    if ext not in allowed: raise HTTPException(415,"Unsupported file extension")
    stored=uuid.uuid4().hex; target=settings.upload_path/stored; size=0
    analysis_error=""
    try:
        with target.open("wb") as dst:
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>settings.max_upload_mb*1024*1024: raise HTTPException(413,"File exceeds maximum upload size")
                dst.write(chunk)
        try:
            result=analyze(target,ext)
            result["analysis_status"]="completed"
        except Exception as exc:
            # The engine failed: record the scan with status="failed" instead of
            # silently reporting a clean 0/100 file. Never delete the stored upload.
            import logging; logging.getLogger("sentinelguard").error("Analysis failed for %s: %s", stored, type(exc).__name__)
            analysis_error="The analysis engine could not process this file. Results are unavailable for this upload."
            result={"analysis_status":"failed","analysis_error":analysis_error,"sha256":"","entropy":0.0,"entropy_category":"Low","mime_type":"Unknown","signatures":[],"risk_score":0,"risk_level":"Unknown","recommendation":"Analysis failed; re-upload the file or contact support.","issues":[],"finding_count":0,"severity_breakdown":{},"analysis_sections":[],"file_dna":{},"hex_preview":[],"score_breakdown":[]}
    except HTTPException:
        target.unlink(missing_ok=True); raise
    except Exception:
        target.unlink(missing_ok=True); raise
    scan=Scan(user_id=user.id,filename=filename,stored_name=stored,sha256=result["sha256"],mime_type=result["mime_type"],extension=ext,size=size,entropy=result["entropy"],risk_score=result["risk_score"],risk_level=result["risk_level"],details_json=json.dumps(result))
    db.add(scan); db.flush()
    evidence_by_message={i["message"]:i.get("evidence","") for i in result.get("issues",[])}
    for issue in result.get("issues",[]): db.add(Threat(scan_id=scan.id,category=issue["category"],severity=issue["severity"],message=issue["message"]))
    result["evidence_by_message"]=evidence_by_message
    scan.details_json=json.dumps(result)
    db.commit(); db.refresh(scan); return scan_out(scan)

@app.get("/scans", response_model=list[ScanOut])
def list_scans(q:str="", limit:int=50, user:User=Depends(current_user), db:Session=Depends(get_db)):
    q=q[:100]; stmt=select(Scan).where(Scan.user_id==user.id,Scan.filename.ilike(f"%{q}%")).order_by(Scan.created_at.desc()).limit(min(limit,100))
    return [scan_out(x) for x in db.scalars(stmt).unique().all()]

@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    scan=db.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==user.id))
    if not scan: raise HTTPException(404,"Scan not found")
    return scan_out(scan)

@app.delete("/scans/{scan_id}",status_code=204)
def delete_scan(scan_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    scan=db.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==user.id))
    if not scan: raise HTTPException(404,"Scan not found")
    (settings.upload_path/scan.stored_name).unlink(missing_ok=True); db.delete(scan); db.commit()

@app.delete("/scans", status_code=204)
def delete_all_scans(user:User=Depends(current_user), db:Session=Depends(get_db)):
    """Clear only the authenticated user's scan history and stored scan files."""
    scans = db.scalars(select(Scan).where(Scan.user_id == user.id)).unique().all()
    for scan in scans:
        (settings.upload_path / scan.stored_name).unlink(missing_ok=True)
        db.delete(scan)
    db.commit()

@app.get("/scans/{scan_id}/report.pdf")
def report(scan_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    scan=db.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==user.id))
    if not scan: raise HTTPException(404,"Scan not found")
    return StreamingResponse(render_pdf(scan),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="sentinelguard-{scan.id}.pdf"'})

@app.get("/dashboard")
def dashboard(user:User=Depends(current_user),db:Session=Depends(get_db)):
    scans=db.scalars(select(Scan).where(Scan.user_id==user.id).order_by(Scan.created_at.desc())).all()
    counts={level:sum(x.risk_level==level for x in scans) for level in ["Safe","Low","Medium","High","Critical","Unknown"]}
    return {"total":len(scans),"threats":sum(x.risk_score>20 for x in scans),"risk_levels":counts,"recent":[scan_out(x) for x in scans[:8]]}

# ── Secure Vault ────────────────────────────────────────────────────────

VAULT_TOKEN_MINUTES = 15
VAULT_SESSION_PREFIX = "vault:"


def secrets_hex(n: int = 24) -> str:
    return secrets.token_hex(n)


def vault_password_plaintext(vault_token: str) -> str:
    """The Vault password is carried inside the short-lived vault JWT (scope=vault)
    for the session only — it is never written to the database or disk. The token
    is signed server-side and expires in 15 minutes."""
    try:
        data = jwt.decode(vault_token, settings.secret_key, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Vault session expired. Unlock the Vault again.")
    pw = data.get("vp")
    if not pw:
        raise HTTPException(401, "Vault session expired. Unlock the Vault again.")
    return str(pw)


def vault_dir() -> Path:
    d = settings.upload_path / "vault"
    d.mkdir(parents=True, exist_ok=True)
    return d


def vault_status_for(user: User, db: Session) -> VaultStatusOut:
    key = db.scalar(select(VaultKey).where(VaultKey.user_id == user.id))
    count = db.scalar(select(func.count()).select_from(VaultRecord).where(VaultRecord.user_id == user.id)) or 0
    return VaultStatusOut(exists=key is not None, unlocked=False, item_count=int(count))


def make_vault_token(user: User, vault_password: str) -> str:
    """Short-lived vault session token. It carries the Vault password so the
    server can re-derive per-file keys without persisting either one."""
    exp = datetime.now(timezone.utc) + timedelta(minutes=VAULT_TOKEN_MINUTES)
    return jwt.encode({"scope": "vault", "sub": str(user.id), "vp": vault_password, "exp": exp},
                      settings.secret_key, algorithm="HS256")


def vault_password_plaintext(vault_token: str) -> str:
    """The Vault password rides inside the short-lived vault JWT (scope=vault)
    for the session only; it is never written to the database or disk."""
    try:
        data = jwt.decode(vault_token, settings.secret_key, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Vault session expired. Unlock the Vault again.")
    pw = data.get("vp")
    if not pw:
        raise HTTPException(401, "Vault session expired. Unlock the Vault again.")
    return str(pw)


def current_vault_user(token: str, user: User, db: Session) -> User:
    """Validate a vault-scoped JWT for the signed-in user; 401 when locked/foreign."""
    try:
        data = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        if data.get("scope") != "vault" or int(data["sub"]) != user.id:
            raise ValueError
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        raise HTTPException(401, "Vault is locked. Unlock it with your Vault password.")
    return user


@app.get("/vault/status", response_model=VaultStatusOut)
def vault_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return vault_status_for(user, db)


@app.post("/vault/setup", response_model=VaultUnlockOut)
def vault_setup(body: VaultSetupIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """First-time Vault password creation. Only a bcrypt hash is stored."""
    if db.scalar(select(VaultKey).where(VaultKey.user_id == user.id)):
        raise HTTPException(409, "Vault already exists. Use unlock instead.")
    if body.password != body.confirm:
        raise HTTPException(400, "Passwords do not match")
    if not is_strong_vault_password(body.password):
        raise HTTPException(400, "Vault password must be 8+ characters and include letters and numbers")
    db.add(VaultKey(user_id=user.id, password_hash=hash_vault_password(body.password)))
    db.commit()
    return VaultUnlockOut(vault_token=make_vault_token(user, body.password), expires_in=VAULT_TOKEN_MINUTES * 60)


@app.post("/vault/unlock", response_model=VaultUnlockOut)
def vault_unlock(body: VaultUnlockIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    key = db.scalar(select(VaultKey).where(VaultKey.user_id == user.id))
    if not key:
        raise HTTPException(404, "Vault has not been set up yet")
    if not verify_vault_password(body.password, key.password_hash):
        raise HTTPException(403, "Incorrect Vault password")
    return VaultUnlockOut(vault_token=make_vault_token(user, body.password), expires_in=VAULT_TOKEN_MINUTES * 60)


@app.get("/vault/items", response_model=list[VaultItemOut])
def vault_items(vault_token: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    current_vault_user(vault_token, user, db)
    rows = db.scalars(select(VaultRecord).where(VaultRecord.user_id == user.id).order_by(VaultRecord.created_at.desc())).all()
    return [VaultItemOut(id=r.id, original_filename=r.original_filename, file_size=r.file_size,
                         sha256=r.original_sha256, algorithm=r.algorithm, kdf=r.kdf, created_at=r.created_at)
            for r in rows]


@app.post("/vault/items", response_model=VaultAddOut)
async def vault_add(file: UploadFile = File(...), vault_token: str = Form(...),
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    current_vault_user(vault_token, user, db)
    plaintext = await file.read()
    if not plaintext:
        raise HTTPException(400, "File is empty")
    if len(plaintext) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, "File exceeds maximum upload size")
    original_name = Path(file.filename or "file.bin").name
    if original_name in {"", ".", ".."}:
        raise HTTPException(400, "Invalid filename")
    blob = encrypt_vault_blob(plaintext, vault_password_plaintext(vault_token), original_name)
    record = VaultRecord(user_id=user.id, original_filename=original_name,
                         stored_name=new_stored_name(), original_sha256=hashlib.sha256(plaintext).hexdigest(),
                         file_size=len(plaintext))
    db.add(record); db.commit(); db.refresh(record)
    safe_vault_path(vault_dir(), record.stored_name).write_bytes(blob)
    return VaultAddOut(item=VaultItemOut(id=record.id, original_filename=record.original_filename,
                                         file_size=record.file_size, sha256=record.original_sha256,
                                         algorithm=record.algorithm, kdf=record.kdf, created_at=record.created_at))


@app.get("/vault/items/{item_id}/download")
def vault_download(item_id: int, vault_token: str,
                   user: User = Depends(current_user), db: Session = Depends(get_db)):
    current_vault_user(vault_token, user, db)
    record = db.scalar(select(VaultRecord).where(VaultRecord.id == item_id, VaultRecord.user_id == user.id))
    if not record:
        raise HTTPException(404, "Vault item not found")
    path = safe_vault_path(vault_dir(), record.stored_name)
    if not path.exists():
        raise HTTPException(404, "Vault item is missing on disk")
    blob = path.read_bytes()
    try:
        plaintext, original_name = decrypt_vault_blob(blob, vault_password_plaintext(vault_token))
    except ValueError as exc:
        raise HTTPException(403, str(exc))
    import io as _io
    return StreamingResponse(_io.BytesIO(plaintext), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{original_name}"'})


@app.delete("/vault/items/{item_id}", status_code=204)
def vault_delete(item_id: int, vault_token: str,
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    current_vault_user(vault_token, user, db)
    record = db.scalar(select(VaultRecord).where(VaultRecord.id == item_id, VaultRecord.user_id == user.id))
    if not record:
        raise HTTPException(404, "Vault item not found")
    safe_vault_path(vault_dir(), record.stored_name).unlink(missing_ok=True)
    db.delete(record); db.commit()


# ── Quarantine ──────────────────────────────────────────────────────────


def quarantine_dir() -> Path:
    d = settings.upload_path / "quarantine"
    d.mkdir(parents=True, exist_ok=True)
    return d


def quarantine_out(q: QuarantineRecord) -> dict:
    return {"id": q.id, "scan_id": q.scan_id, "filename": q.filename, "risk_score": q.risk_score,
            "risk_level": q.risk_level, "reason": q.reason, "created_at": q.created_at}


@app.post("/quarantine", response_model=QuarantineOut)
def quarantine_file(body: QuarantineIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Move a suspicious scanned file out of normal storage into isolation."""
    scan = db.scalar(select(Scan).where(Scan.id == body.scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    if db.scalar(select(QuarantineRecord).where(QuarantineRecord.scan_id == scan.id, QuarantineRecord.user_id == user.id)):
        raise HTTPException(409, "This scan is already quarantined")
    source = settings.upload_path / scan.stored_name
    if not source.exists():
        raise HTTPException(404, "The scanned file is no longer available on disk")
    findings = db.scalars(select(Threat).where(Threat.scan_id == scan.id)).all()
    reason = "; ".join(f"[{t.severity}] {t.category}: {t.message}" for t in findings) or \
        f"{scan.risk_level} risk ({scan.risk_score}/100) flagged by the analyst"
    stored = "q_" + secrets_hex()
    target = quarantine_dir() / stored
    # Copy, then remove from normal uploads: file lives only inside quarantine.
    shutil.copyfile(source, target)
    record = QuarantineRecord(user_id=user.id, scan_id=scan.id, filename=scan.filename,
                              stored_name=stored, risk_score=scan.risk_score,
                              risk_level=scan.risk_level, reason=reason)
    db.add(record)
    source.unlink(missing_ok=True)
    db.commit(); db.refresh(record)
    return quarantine_out(record)


@app.get("/quarantine", response_model=list[QuarantineOut])
def quarantine_list(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(QuarantineRecord).where(QuarantineRecord.user_id == user.id).order_by(QuarantineRecord.created_at.desc())).all()
    return [quarantine_out(r) for r in rows]


@app.post("/quarantine/{record_id}/restore", response_model=ScanOut)
def quarantine_restore(record_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Return the file to normal scan storage. The scan record itself is kept."""
    record = db.scalar(select(QuarantineRecord).where(QuarantineRecord.id == record_id, QuarantineRecord.user_id == user.id))
    if not record:
        raise HTTPException(404, "Quarantine record not found")
    source = quarantine_dir() / record.stored_name
    if not source.exists():
        raise HTTPException(404, "Quarantined file is missing on disk")
    scan = db.get(Scan, record.scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(404, "Original scan not found")
    target = settings.upload_path / scan.stored_name
    shutil.copyfile(source, target)
    source.unlink(missing_ok=True)  # no duplicate left inside quarantine
    db.delete(record); db.commit()
    db.refresh(scan)
    return scan_out(scan)


@app.delete("/quarantine/{record_id}", status_code=204)
def quarantine_delete(record_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    record = db.scalar(select(QuarantineRecord).where(QuarantineRecord.id == record_id, QuarantineRecord.user_id == user.id))
    if not record:
        raise HTTPException(404, "Quarantine record not found")
    (quarantine_dir() / record.stored_name).unlink(missing_ok=True)
    db.delete(record); db.commit()


# ── Encryption ──────────────────────────────────────────────────────────────

@app.post("/encrypt")
async def encrypt(
    file: UploadFile = File(...),
    password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Encrypt an uploaded file using AES-256-GCM. Returns JSON with download URL."""
    if not password or not password.strip():
        raise HTTPException(400, "Password is required")
    if len(password) > 128:
        raise HTTPException(400, "Password too long")

    original_name = Path(file.filename or "upload.bin").name
    protected_dir = settings.upload_path / "protected"
    protected_dir.mkdir(parents=True, exist_ok=True)

    # Read all bytes into memory (must be complete for AES-GCM)
    plaintext = await file.read()
    if not plaintext:
        raise HTTPException(400, "File is empty")
    if len(plaintext) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, "File exceeds maximum upload size")

    import hashlib
    original_sha256 = hashlib.sha256(plaintext).hexdigest()

    # Encrypt
    try:
        sguard_blob = encrypt_file(plaintext, password, original_name)
    except Exception as e:
        import logging; logging.getLogger("sentinelguard").error("Encryption failed: %s", type(e).__name__)
        raise HTTPException(500, "Encryption failed. Please try again.")

    # Store the encrypted file on disk so the frontend can download it
    encrypted_name = f"{uuid.uuid4().hex}.sguard"
    target = protected_dir / encrypted_name
    target.write_bytes(sguard_blob)

    download_name = get_download_filename(original_name)

    # Record in encryption history
    record = EncryptionRecord(
        user_id=user.id,
        operation="encrypt",
        original_filename=original_name,
        encrypted_filename=encrypted_name,
        stored_name=encrypted_name,
        file_size=len(sguard_blob),
        sha256=original_sha256,
        original_sha256=original_sha256,
        algorithm="AES-256-GCM",
        kdf="Argon2id",
        status="success",
    )
    db.add(record); db.commit(); db.refresh(record)

    return EncryptResult(
        id=record.id,
        original_filename=original_name,
        encrypted_filename=download_name,
        original_sha256=original_sha256,
        algorithm="AES-256-GCM",
        kdf="Argon2id",
        file_size=len(sguard_blob),
        download_url=f"/encrypt/download/{record.id}",
    )


@app.get("/encrypt/download/{record_id}")
async def download_encrypted(
    record_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Download an encrypted .sguard file."""
    record = db.scalar(select(EncryptionRecord).where(
        EncryptionRecord.id == record_id,
        EncryptionRecord.user_id == user.id,
    ))
    if not record:
        raise HTTPException(404, "Encrypted file not found")

    path = settings.upload_path / "protected" / record.encrypted_filename
    if not path.exists():
        raise HTTPException(404, "Encrypted file not found on disk")

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


# ── Decryption ──────────────────────────────────────────────────────────────

@app.post("/decrypt")
async def decrypt(
    file: UploadFile = File(...),
    password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Decrypt a .sguard file. Returns JSON with download URL for restored file."""
    if not password or not password.strip():
        raise HTTPException(400, "Password is required")

    filename = Path(file.filename or "upload.sguard").name
    if not filename.lower().endswith(".sguard"):
        raise HTTPException(400, "Only .sguard files can be decrypted")
    sguard_data = await file.read()
    if not sguard_data:
        raise HTTPException(400, "File is empty")
    if len(sguard_data) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, "File exceeds maximum upload size")

    # Decrypt
    try:
        plaintext, meta = decrypt_file(sguard_data, password)
    except ValueError as e:
        import logging; logging.getLogger("sentinelguard").warning(
            "Decryption rejected: %s", type(e).__name__
        )
        raise HTTPException(400, str(e))
    except Exception as e:
        import logging; logging.getLogger("sentinelguard").error("Decryption failed: %s", type(e).__name__)
        raise HTTPException(500, "Decryption failed. Please try again.")

    # Store decrypted file for download
    protected_dir = settings.upload_path / "protected"
    protected_dir.mkdir(parents=True, exist_ok=True)
    decrypted_name = f"{uuid.uuid4().hex}_decrypted"
    target = protected_dir / decrypted_name
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
    """Download a decrypted file, preserving original filename."""
    # Sanitize: stored_name must be a plain hex UUID
    import re
    if not re.fullmatch(r'[a-f0-9]+_decrypted', stored_name):
        raise HTTPException(400, "Invalid stored name")
    safe_filename = Path(original_filename).name
    if safe_filename != original_filename or safe_filename in {".", ".."}:
        raise HTTPException(400, "Invalid original filename")

    path = settings.upload_path / "protected" / stored_name
    if not path.exists():
        raise HTTPException(404, "Decrypted file not found")

    return StreamingResponse(
        path.open("rb"),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )


# --- Optional single-service static hosting --------------------------------
# When a built frontend exists at ../frontend/dist (e.g. inside the production
# container), serve it from this same origin so the app deploys as ONE service
# with no CORS setup and a single public URL. Local dev keeps using the Vite
# dev server on :5173. Must be registered AFTER all API routes above.
_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.is_dir():
    try:
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")
    except Exception:  # never let static hosting break the API
        pass
