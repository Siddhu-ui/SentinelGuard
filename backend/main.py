import json, os, uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from database import Base, engine, get_db
from models import EncryptionRecord, Scan, Threat, User
from schemas import EncryptionOut, LoginIn, RegisterIn, ScanOut, TokenOut, UserOut
from scanner.analyzers import analyze
from services.auth import create_token, current_user, hash_password, verify_password
from services.report import render_pdf
from services.encryption import EncryptedFileError, decrypt_file, encrypt_file, read_header
from settings import settings

Base.metadata.create_all(bind=engine)
settings.upload_path.mkdir(parents=True, exist_ok=True)
settings.protected_path.mkdir(parents=True, exist_ok=True)
app=FastAPI(title="SentinelGuard API", version="1.0.0", description="Static pre-analysis of suspicious files. Files are never executed.")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.cors_origins.split(",")], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def scan_out(s: Scan) -> dict:
    d=json.loads(s.details_json); return {"id":s.id,"filename":s.filename,"sha256":s.sha256,"mime_type":s.mime_type,"extension":s.extension,"size":s.size,"entropy":s.entropy,"risk_score":s.risk_score,"risk_level":s.risk_level,"details":d,"threats":[{"category":t.category,"severity":t.severity,"message":t.message} for t in s.threats],"created_at":s.created_at}

def encryption_out(record: EncryptionRecord) -> dict:
    return {key: getattr(record, key) for key in ("id", "operation", "original_filename", "encrypted_filename", "file_size", "original_sha256", "algorithm", "kdf", "status", "created_at")}

async def save_upload(file: UploadFile, directory, suffix: str = "") -> tuple[Path, int]:
    """Write browser input to a server-generated private path with a hard size limit."""
    target = directory / f"{uuid.uuid4().hex}{suffix}"
    size = 0
    try:
        with target.open("xb") as dst:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_mb * 1024 * 1024:
                    raise HTTPException(413, "File exceeds maximum upload size")
                dst.write(chunk)
        try: os.chmod(target, 0o600)
        except OSError: pass
        return target, size
    except Exception:
        target.unlink(missing_ok=True)
        raise

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
        with target.open("xb") as dst:
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
    encryption_records=db.scalars(select(EncryptionRecord).where(EncryptionRecord.user_id==user.id).order_by(EncryptionRecord.created_at.desc())).all()
    counts={level:sum(x.risk_level==level for x in scans) for level in ["Safe","Low","Medium","High","Critical"]}
    activity=([{"type":"scan","filename":x.filename,"status":x.risk_level,"created_at":x.created_at} for x in scans]+[{"type":x.operation,"filename":x.original_filename,"status":x.status,"created_at":x.created_at} for x in encryption_records])
    activity.sort(key=lambda x:x["created_at"], reverse=True)
    return {"total":len(scans),"threats":sum(x.risk_score>20 for x in scans),"risk_levels":counts,"encrypted":sum(x.operation=="encrypt" for x in encryption_records),"decrypted":sum(x.operation=="decrypt" for x in encryption_records),"recent":[scan_out(x) for x in scans[:8]],"activity":activity[:8]}

@app.post("/encryption/encrypt", response_model=EncryptionOut)
async def encrypt_upload(file: UploadFile=File(...), password: str=Form(...), confirm_password: str=Form(...), user:User=Depends(current_user), db:Session=Depends(get_db)):
    if password != confirm_password: raise HTTPException(422, "Encryption passwords do not match")
    if len(password) < 12: raise HTTPException(422, "Use an encryption password of at least 12 characters")
    filename=Path(file.filename or "upload.bin").name
    incoming, size = await save_upload(file, settings.upload_path, ".tmp")
    stored_name=uuid.uuid4().hex; destination=settings.protected_path/stored_name
    try:
        header=encrypt_file(incoming, destination, password, filename)
    except EncryptedFileError as exc:
        destination.unlink(missing_ok=True); raise HTTPException(400, str(exc))
    finally:
        incoming.unlink(missing_ok=True)
    record=EncryptionRecord(user_id=user.id,operation="encrypt",original_filename=header["original_filename"],encrypted_filename=f"{header['original_filename']}.sguard",stored_name=stored_name,file_size=size,original_sha256=header["original_sha256"],algorithm=header["algorithm"],kdf=header["kdf"],status="secure")
    db.add(record); db.commit(); db.refresh(record); return encryption_out(record)

@app.post("/encryption/decrypt", response_model=EncryptionOut)
async def decrypt_upload(file: UploadFile=File(...), password: str=Form(...), user:User=Depends(current_user), db:Session=Depends(get_db)):
    filename=Path(file.filename or "encrypted.sguard").name
    if Path(filename).suffix.lower() != ".sguard": raise HTTPException(415, "Upload a .sguard file")
    incoming, _ = await save_upload(file, settings.upload_path, ".tmp")
    stored_name=uuid.uuid4().hex; destination=settings.protected_path/stored_name
    try:
        header=decrypt_file(incoming, destination, password)
    except EncryptedFileError as exc:
        destination.unlink(missing_ok=True); raise HTTPException(400, str(exc))
    finally:
        incoming.unlink(missing_ok=True)
    size=destination.stat().st_size
    record=EncryptionRecord(user_id=user.id,operation="decrypt",original_filename=header["original_filename"],encrypted_filename=filename,stored_name=stored_name,file_size=size,original_sha256=header["original_sha256"],algorithm=header["algorithm"],kdf=header["kdf"],status="verified")
    db.add(record); db.commit(); db.refresh(record); return encryption_out(record)

@app.get("/encryption/history", response_model=list[EncryptionOut])
def encryption_history(limit:int=50, user:User=Depends(current_user), db:Session=Depends(get_db)):
    records=db.scalars(select(EncryptionRecord).where(EncryptionRecord.user_id==user.id).order_by(EncryptionRecord.created_at.desc()).limit(min(limit,100))).all()
    return [encryption_out(x) for x in records]

@app.get("/encryption/{record_id}/download")
def download_encryption(record_id:int, user:User=Depends(current_user), db:Session=Depends(get_db)):
    record=db.scalar(select(EncryptionRecord).where(EncryptionRecord.id==record_id,EncryptionRecord.user_id==user.id))
    if not record: raise HTTPException(404, "Encryption record not found")
    path=settings.protected_path/record.stored_name
    if not path.is_file(): raise HTTPException(404, "The protected file is no longer available")
    filename=record.encrypted_filename if record.operation=="encrypt" else record.original_filename
    return StreamingResponse(path.open("rb"), media_type="application/octet-stream", headers={"Content-Disposition":f"attachment; filename={json.dumps(filename)}"})
