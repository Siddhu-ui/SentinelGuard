import io
import json
import pytest
from fastapi.testclient import TestClient
from database import Base, engine
from main import app

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield

def register_user(email="security_test@sentinelguard.io", name="Sec Tester", pw="StrongSecret123!"):
    r = client.post("/api/v1/auth/register", json={"email": email, "display_name": name, "password": pw})
    assert r.status_code == 200
    return r.json()["access_token"]

def test_path_traversal_protection():
    token = register_user()
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt path traversal on download decrypted
    r = client.get("/decrypt/download/../../etc/passwd/test.pdf", headers=headers)
    assert r.status_code in {400, 404}

    # Attempt path traversal on scan deletion with invalid scan id
    r2 = client.delete("/api/v1/scans/999999", headers=headers)
    assert r2.status_code == 404

def test_pdf_report_generation():
    token = register_user()
    headers = {"Authorization": f"Bearer {token}"}

    # Scan a PDF
    pdf_bytes = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>%%EOF"
    r_scan = client.post(
        "/api/v1/scan",
        headers=headers,
        files={"file": ("invoice_2026.pdf", pdf_bytes, "application/pdf")},
    )
    assert r_scan.status_code == 200
    scan_id = r_scan.json()["id"]

    # Generate PDF report
    r_rep = client.get(f"/api/v1/scans/{scan_id}/report", headers=headers)
    assert r_rep.status_code == 200
    assert r_rep.headers["content-type"] == "application/pdf"
    assert len(r_rep.content) > 500  # Valid generated PDF
    assert r_rep.content.startswith(b"%PDF")

def test_settings_and_password_change():
    token = register_user()
    headers = {"Authorization": f"Bearer {token}"}

    # Get settings
    r_set = client.get("/api/v1/settings", headers=headers)
    assert r_set.status_code == 200
    assert r_set.json()["email"] == "security_test@sentinelguard.io"
    assert r_set.json()["retention_days"] == 30

    # Update settings
    r_up = client.post(
        "/api/v1/settings",
        headers=headers,
        json={"display_name": "Updated Sec Analyst", "retention_days": 90},
    )
    assert r_up.status_code == 200

    # Verify updated settings
    r_set2 = client.get("/api/v1/settings", headers=headers)
    assert r_set2.json()["display_name"] == "Updated Sec Analyst"
    assert r_set2.json()["retention_days"] == 90

    # Change password
    r_pw = client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": "StrongSecret123!", "new_password": "NewSuperSecret456!"},
    )
    assert r_pw.status_code == 200

    # Old password fails login
    r_old_login = client.post(
        "/api/v1/auth/login",
        json={"email": "security_test@sentinelguard.io", "password": "StrongSecret123!"},
    )
    assert r_old_login.status_code == 401

    # New password succeeds login
    r_new_login = client.post(
        "/api/v1/auth/login",
        json={"email": "security_test@sentinelguard.io", "password": "NewSuperSecret456!"},
    )
    assert r_new_login.status_code == 200
    assert "access_token" in r_new_login.json()
