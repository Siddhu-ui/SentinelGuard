import json, shutil, uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from database import Base, engine, get_db
from models import EncryptionRecord, Scan, Threat, User
from schemas import EncryptHistoryOut, EncryptResult, LoginIn, RegisterIn, ScanOut, TokenOut, UserOut
from scanner.analyzers import analyze
from services.auth import create_token, current_user, hash_password, verify_password
from services.crypto import encrypt_file, decrypt_file, get_download_filename
from services.report import render_pdf
from settings import settings

Base.metadata.create_all(bind=engine); settings.upload_path.mkdir(parents=True, exist_ok=True); settings.upload_path.joinpath("protected").mkdir(parents=True, exist_ok=True)
app=FastAPI(title="SentinelGuard API", version="1.0.0", description="Static pre-analysis of suspicious files. Files are never executed.")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.cors_origins.split(",")], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def scan_out(s: Scan) -> dict:
    d=json.loads(s.details_json); return {"id":s.id,"filename":s.filename,"sha256":s.sha256,"mime_type":s.mime_type,"extension":s.extension,"size":s.size,"entropy":s.entropy,"risk_score":s.risk_score,"risk_level":s.risk_level,"details":d,"threats":[{"category":t.category,"severity":t.severity,"message":t.message} for t in s.threats],"created_at":s.created_at}

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
    ext=Path(filename).suffix.lower().lstrip(".")
    allowed={"pdf","png","jpg","jpeg","gif","bmp","zip","rar","docx","xlsx","pptx","exe"}
    if ext not in allowed: raise HTTPException(415,"Unsupported file extension")
    stored=uuid.uuid4().hex; target=settings.upload_path/stored; size=0
    try:
        with target.open("wb") as dst:
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>settings.max_upload_mb*1024*1024: raise HTTPException(413,"File exceeds maximum upload size")
                dst.write(chunk)
        result=analyze(target,ext)
    except Exception:
        target.unlink(missing_ok=True); raise
    scan=Scan(user_id=user.id,filename=filename,stored_name=stored,sha256=result["sha256"],mime_type=result["mime_type"],extension=ext,size=size,entropy=result["entropy"],risk_score=result["risk_score"],risk_level=result["risk_level"],details_json=json.dumps(result))
    db.add(scan); db.flush()
    for issue in result["issues"]: db.add(Threat(scan_id=scan.id,category=issue["category"],severity=issue["severity"],message=issue["message"]))
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

@app.get("/scans/{scan_id}/report.pdf")
def report(scan_id:int,user:User=Depends(current_user),db:Session=Depends(get_db)):
    scan=db.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==user.id))
    if not scan: raise HTTPException(404,"Scan not found")
    return StreamingResponse(render_pdf(scan),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="sentinelguard-{scan.id}.pdf"'})

@app.get("/dashboard")
def dashboard(user:User=Depends(current_user),db:Session=Depends(get_db)):
    scans=db.scalars(select(Scan).where(Scan.user_id==user.id).order_by(Scan.created_at.desc())).all()
    counts={level:sum(x.risk_level==level for x in scans) for level in ["Safe","Low","Medium","High","Critical"]}
    return {"total":len(scans),"threats":sum(x.risk_score>20 for x in scans),"risk_levels":counts,"recent":[scan_out(x) for x in scans[:8]]}

# ── Encryption ──────────────────────────────────────────────────────────────

@app.post("/encrypt")
async def encrypt(
    file: UploadFile = File(...),
    password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Encrypt an uploaded file using AES-256-GCM. Returns JSON with download URL."""
    if not password or len(password) < 1:
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
        original_filename=original_name,
        encrypted_filename=encrypted_name,
        file_size=len(sguard_blob),
        sha256=original_sha256,
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
    if not password:
        raise HTTPException(400, "Password is required")

    filename = Path(file.filename or "upload.sguard").name
    sguard_data = await file.read()
    if not sguard_data:
        raise HTTPException(400, "File is empty")

    # Decrypt
    try:
        plaintext, meta = decrypt_file(sguard_data, password)
    except ValueError as e:
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

    original_filename = meta["original_filename"]

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
    if not re.match(r'^[a-f0-9]+_decrypted$', stored_name):
        raise HTTPException(400, "Invalid stored name")

    path = settings.upload_path / "protected" / stored_name
    if not path.exists():
        raise HTTPException(404, "Decrypted file not found")

    return StreamingResponse(
        path.open("rb"),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{original_filename}"'},
    )
