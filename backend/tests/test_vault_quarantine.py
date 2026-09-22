import io
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from database import Base, engine, SessionLocal
from main import app
from models import User, Scan, VaultFile, QuarantineItem
from services.crypto import encrypt_file

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield

def register_user(email="test@sentinelguard.io", name="Test User", pw="StrongPassword123!"):
    r = client.post("/api/v1/auth/register", json={"email": email, "display_name": name, "password": pw})
    assert r.status_code == 200
    return r.json()["access_token"]

def test_health_endpoints():
    r1 = client.get("/health")
    assert r1.status_code == 200
    assert r1.json()["status"] == "ok"
    assert r1.json()["engine"] == "online"

    r2 = client.get("/api/v1/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"

def test_vault_protect_and_list():
    token = register_user()
    headers = {"Authorization": f"Bearer {token}"}

    # Protect a file and save to vault
    file_bytes = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>%%EOF"
    r = client.post(
        "/api/v1/files/protect",
        headers=headers,
        data={"password": "SafeVaultPassword99!", "save_to_vault": "true", "notes": "Important financial statement"},
        files={"file": ("financial_report.pdf", file_bytes, "application/pdf")},
    )
    assert r.status_code == 200
    res = r.json()
    assert res["original_filename"] == "financial_report.pdf"
    assert res["vault_file_id"] is not None

    # List vault files
    r_list = client.get("/api/v1/vault", headers=headers)
    assert r_list.status_code == 200
    vault_files = r_list.json()
    assert len(vault_files) == 1
    assert vault_files[0]["original_filename"] == "financial_report.pdf"
    assert vault_files[0]["notes"] == "Important financial statement"

    # Decrypt from vault
    vault_id = vault_files[0]["id"]
    r_dec = client.post(
        f"/api/v1/vault/{vault_id}/decrypt",
        headers=headers,
        data={"password": "SafeVaultPassword99!"},
    )
    assert r_dec.status_code == 200
    dec_res = r_dec.json()
    assert dec_res["original_filename"] == "financial_report.pdf"
    assert dec_res["integrity"] == "VERIFIED"

    # Decrypt with wrong password fails
    r_dec_bad = client.post(
        f"/api/v1/vault/{vault_id}/decrypt",
        headers=headers,
        data={"password": "WrongPassword123!"},
    )
    assert r_dec_bad.status_code == 400

    # Delete from vault
    r_del = client.delete(f"/api/v1/vault/{vault_id}", headers=headers)
    assert r_del.status_code == 204

    # Verify deleted
    r_list_after = client.get("/api/v1/vault", headers=headers)
    assert len(r_list_after.json()) == 0

def test_vault_user_isolation():
    token_user_a = register_user("user_a@sentinelguard.io")
    token_user_b = register_user("user_b@sentinelguard.io")

    headers_a = {"Authorization": f"Bearer {token_user_a}"}
    headers_b = {"Authorization": f"Bearer {token_user_b}"}

    # User A creates a vault file
    r = client.post(
        "/api/v1/files/protect",
        headers=headers_a,
        data={"password": "UserAPassword123!", "save_to_vault": "true"},
        files={"file": ("secret_a.pdf", b"%PDF-1.4\nSecret A content\n%%EOF", "application/pdf")},
    )
    assert r.status_code == 200
    vault_id_a = r.json()["vault_file_id"]

    # User B cannot list User A's vault file
    r_list_b = client.get("/api/v1/vault", headers=headers_b)
    assert len(r_list_b.json()) == 0

    # User B cannot decrypt User A's vault file
    r_dec_b = client.post(
        f"/api/v1/vault/{vault_id_a}/decrypt",
        headers=headers_b,
        data={"password": "UserAPassword123!"},
    )
    assert r_dec_b.status_code == 404

    # User B cannot delete User A's vault file
    r_del_b = client.delete(f"/api/v1/vault/{vault_id_a}", headers=headers_b)
    assert r_del_b.status_code == 404

def test_quarantine_workflow():
    token = register_user()
    headers = {"Authorization": f"Bearer {token}"}

    # Upload a scan
    file_bytes = b"%PDF-1.4\n/JavaScript (alert(1))\n%%EOF"
    r_scan = client.post(
        "/api/v1/scan",
        headers=headers,
        files={"file": ("suspicious_doc.pdf", file_bytes, "application/pdf")},
    )
    assert r_scan.status_code == 200
    scan_id = r_scan.json()["id"]

    # Quarantine the scan
    r_q = client.post(
        f"/api/v1/quarantine/{scan_id}",
        headers=headers,
        data={"reason": "Suspicious JavaScript embedded"},
    )
    assert r_q.status_code == 200
    q_data = r_q.json()
    assert q_data["original_filename"] == "suspicious_doc.pdf"
    assert q_data["reason"] == "Suspicious JavaScript embedded"

    # List quarantine
    r_q_list = client.get("/api/v1/quarantine", headers=headers)
    assert len(r_q_list.json()) == 1
    assert r_q_list.json()[0]["scan_id"] == scan_id

    # Restore from quarantine
    r_res = client.post(f"/api/v1/quarantine/{scan_id}/restore", headers=headers)
    assert r_res.status_code == 200

    # List quarantine is now empty
    r_q_list_after = client.get("/api/v1/quarantine", headers=headers)
    assert len(r_q_list_after.json()) == 0

    # Quarantine again then delete permanently
    client.post(f"/api/v1/quarantine/{scan_id}", headers=headers)
    r_del = client.delete(f"/api/v1/quarantine/{scan_id}", headers=headers)
    assert r_del.status_code == 204

    # Scan is completely removed
    r_get_scan = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert r_get_scan.status_code == 404

def test_dashboard_real_statistics():
    token = register_user()
    headers = {"Authorization": f"Bearer {token}"}

    # Initial empty dashboard
    r_dash = client.get("/api/v1/dashboard", headers=headers)
    assert r_dash.status_code == 200
    dash = r_dash.json()
    assert dash["total_scans"] == 0
    assert dash["files_requiring_review"] == 0
    assert dash["protected_files"] == 0
    assert dash["reports_generated"] == 0

    # Add 1 clean scan
    client.post(
        "/api/v1/scan",
        headers=headers,
        files={"file": ("clean.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")},
    )

    # Add 1 suspicious scan
    client.post(
        "/api/v1/scan",
        headers=headers,
        files={"file": ("suspicious.pdf", b"%PDF-1.4\n/JavaScript\n/OpenAction\n%%EOF", "application/pdf")},
    )

    # Add 1 protected vault file
    client.post(
        "/api/v1/files/protect",
        headers=headers,
        data={"password": "MySecretPassword123!", "save_to_vault": "true"},
        files={"file": ("doc.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")},
    )

    # Verify updated stats
    r_dash2 = client.get("/api/v1/dashboard", headers=headers)
    dash2 = r_dash2.json()
    assert dash2["total_scans"] == 2
    assert dash2["files_requiring_review"] == 1
    assert dash2["protected_files"] == 1
    assert dash2["reports_generated"] == 2
    assert len(dash2["recent_scans"]) == 2
