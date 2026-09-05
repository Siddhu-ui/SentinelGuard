from pathlib import Path
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database import Base
from models import EncryptionRecord, Scan, Threat, User
from main import delete_all_scans, delete_scan


def _db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return Session(engine)


def _scan(db, user_id, stored_name):
    scan = Scan(user_id=user_id, filename="sample.pdf", stored_name=stored_name,
                sha256="a" * 64, mime_type="PDF document", extension="pdf",
                size=10, entropy=1, risk_score=0, risk_level="Safe", details_json="{}")
    db.add(scan); db.commit(); db.refresh(scan)
    return scan


def test_user_can_delete_owned_scan_and_file(tmp_path, monkeypatch):
    db = _db(); owner = User(email="owner@example.com", display_name="Owner", password_hash="x")
    db.add(owner); db.commit(); db.refresh(owner)
    stored = "owned"; (tmp_path / stored).write_bytes(b"x")
    monkeypatch.setattr("settings.settings.upload_dir", str(tmp_path))
    scan = _scan(db, owner.id, stored)
    delete_scan(scan.id, owner, db)
    assert db.get(Scan, scan.id) is None
    assert not (tmp_path / stored).exists()


def test_user_cannot_delete_another_users_scan(tmp_path, monkeypatch):
    db = _db(); owner = User(email="owner2@example.com", display_name="Owner", password_hash="x"); other = User(email="other@example.com", display_name="Other", password_hash="x")
    db.add_all([owner, other]); db.commit(); db.refresh(owner); db.refresh(other)
    monkeypatch.setattr("settings.settings.upload_dir", str(tmp_path))
    scan = _scan(db, owner.id, "owned2")
    try:
        delete_scan(scan.id, other, db)
        assert False, "expected ownership rejection"
    except HTTPException as exc:
        assert exc.status_code == 404
    assert db.get(Scan, scan.id) is not None


def test_delete_all_is_user_scoped_and_preserves_encryption(tmp_path, monkeypatch):
    db = _db(); owner = User(email="owner3@example.com", display_name="Owner", password_hash="x"); other = User(email="other3@example.com", display_name="Other", password_hash="x")
    db.add_all([owner, other]); db.commit(); db.refresh(owner); db.refresh(other)
    monkeypatch.setattr("settings.settings.upload_dir", str(tmp_path))
    _scan(db, owner.id, "one"); _scan(db, other.id, "two")
    enc = EncryptionRecord(user_id=owner.id, original_filename="a.pdf", encrypted_filename="a.sguard", file_size=1, sha256="b" * 64, algorithm="AES-256-GCM", kdf="Argon2id")
    db.add(enc); db.commit()
    delete_all_scans(owner, db)
    assert db.query(Scan).filter_by(user_id=owner.id).count() == 0
    assert db.query(Scan).filter_by(user_id=other.id).count() == 1
    assert db.get(EncryptionRecord, enc.id) is not None
