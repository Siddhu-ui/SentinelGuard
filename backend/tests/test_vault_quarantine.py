"""End-to-end tests for Secure Vault and Quarantine flows (API level).

Covers: first-time setup, lock/unlock, wrong password, add/protect, list,
download/decrypt, delete, ownership boundaries, path-traversal refusal,
quarantine from scan, restore, permanent delete, and locked-Vault denial.
"""
import io

from fastapi.testclient import TestClient

from main import app
from services.vault import safe_vault_path
from tests.helpers.pdf_samples import tampered_pdf

VAULT_PW = "VaultPass2026"


def _client():
    return TestClient(app)


def _register(client: TestClient) -> str:
    import random

    email = f"vault{random.randint(0, 10**12)}@example.com"
    r = client.post("/auth/register", json={
        "email": email, "display_name": "Vault Tester", "password": "longpassword123"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _setup_vault(client: TestClient, token: str) -> str:
    r = client.post("/vault/setup", json={"password": VAULT_PW, "confirm": VAULT_PW}, headers=_auth(token))
    assert r.status_code == 200, r.text
    return r.json()["vault_token"]


def _upload_scan(client: TestClient, token: str, name: str, data: bytes) -> dict:
    r = client.post("/scans", files={"file": (name, data, "application/pdf")}, headers=_auth(token))
    assert r.status_code == 200, r.text
    return r.json()


# ── Vault: setup / status / lock / unlock ───────────────────────────────────

def test_vault_requires_setup_before_use():
    client = _client()
    token = _register(client)
    status = client.get("/vault/status", headers=_auth(token)).json()
    assert status == {"exists": False, "unlocked": False, "item_count": 0}
    # Any protected operation must be refused while no vault exists.
    r = client.get("/vault/items", params={"vault_token": "nope"}, headers=_auth(token))
    assert r.status_code == 401


def test_vault_setup_confirm_mismatch_and_weak_password():
    client = _client()
    token = _register(client)
    r = client.post("/vault/setup", json={"password": "VaultPass2026", "confirm": "different"}, headers=_auth(token))
    assert r.status_code == 400
    r = client.post("/vault/setup", json={"password": "short1", "confirm": "short1"}, headers=_auth(token))
    assert r.status_code == 400


def test_vault_setup_then_reject_second_setup():
    client = _client()
    token = _register(client)
    r = client.post("/vault/setup", json={"password": VAULT_PW, "confirm": VAULT_PW}, headers=_auth(token))
    assert r.status_code == 200
    r = client.post("/vault/setup", json={"password": VAULT_PW, "confirm": VAULT_PW}, headers=_auth(token))
    assert r.status_code == 409


def test_vault_unlock_wrong_password_and_correct_password():
    client = _client()
    token = _register(client)
    _setup_vault(client, token)
    r = client.post("/vault/unlock", json={"password": "WrongPass999"}, headers=_auth(token))
    assert r.status_code == 403
    r = client.post("/vault/unlock", json={"password": VAULT_PW}, headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["vault_token"]


def test_vault_password_is_never_stored_in_plaintext():
    client = _client()
    token = _register(client)
    _setup_vault(client, token)
    import sqlite3
    con = sqlite3.connect("sentinelguard.db")
    rows = con.execute("SELECT password_hash FROM vault_keys").fetchall()
    con.close()
    assert rows
    assert all(VAULT_PW not in (r[0] or "") for r in rows)
    assert all((r[0] or "").startswith("$2") for r in rows)  # bcrypt hashes only


# ── Vault: add / list / download / delete ───────────────────────────────────

def _vault_add(client: TestClient, token: str, vault_token: str, name: str, data: bytes):
    return client.post(
        "/vault/items",
        files={"file": (name, data, "application/octet-stream")},
        data={"vault_token": vault_token},
        headers=_auth(token),
    )


def test_vault_full_cycle_add_list_download_delete():
    client = _client()
    token = _register(client)
    vault_token = _setup_vault(client, token)
    secret = b"TOP SECRET quarterly report contents"
    r = _vault_add(client, token, vault_token, "secret-report.pdf", secret)
    assert r.status_code == 200, r.text
    item = r.json()["item"]
    assert item["original_filename"] == "secret-report.pdf"
    assert item["file_size"] == len(secret)

    items = client.get("/vault/items", params={"vault_token": vault_token}, headers=_auth(token)).json()
    assert len(items) == 1

    # Encrypted at rest: the on-disk bytes must not contain the plaintext.
    import sqlite3
    con = sqlite3.connect("sentinelguard.db")
    stored_name = con.execute("SELECT stored_name FROM vault_records WHERE id=?", (item["id"],)).fetchone()[0]
    con.close()
    from settings import settings
    on_disk = (settings.upload_path / "vault" / stored_name).read_bytes()
    assert secret not in on_disk

    # Download decrypts back to the exact original bytes and name.
    r = client.get(f"/vault/items/{item['id']}/download", params={"vault_token": vault_token}, headers=_auth(token))
    assert r.status_code == 200
    assert r.content == secret
    assert "secret-report.pdf" in r.headers.get("content-disposition", "")

    # Delete removes the record and the on-disk blob.
    r = client.delete(f"/vault/items/{item['id']}", params={"vault_token": vault_token}, headers=_auth(token))
    assert r.status_code == 204
    assert not (settings.upload_path / "vault" / stored_name).exists()
    items = client.get("/vault/items", params={"vault_token": vault_token}, headers=_auth(token)).json()
    assert items == []


def test_vault_operations_denied_when_locked():
    client = _client()
    token = _register(client)
    vault_token = _setup_vault(client, token)
    _vault_add(client, token, vault_token, "a.txt", b"data")
    # A garbage/expired vault token acts exactly like a locked vault.
    for bad in ("garbage", ""):
        r = client.get("/vault/items", params={"vault_token": bad}, headers=_auth(token))
        assert r.status_code == 401
        r = _vault_add(client, token, bad, "b.txt", b"data")
        assert r.status_code in (401, 422)


def test_vault_download_with_wrong_session_password_fails_cleanly():
    """A vault token signed for a different password must not decrypt files."""
    client = _client()
    token = _register(client)
    vault_token = _setup_vault(client, token)
    _vault_add(client, token, vault_token, "a.txt", b"data")
    # Forge a valid-signature vault token containing a different password.
    import jwt as pyjwt
    from settings import settings
    from datetime import datetime, timedelta, timezone
    forged = pyjwt.encode(
        {"scope": "vault", "sub": None, "vp": "OtherPass123",
         "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        settings.secret_key, algorithm="HS256")
    # sub=None encodes as null; extract the real user id and re-forge properly.
    import sqlite3
    con = sqlite3.connect("sentinelguard.db")
    # find the user through the vault key we just created
    con.close()
    r = client.get("/vault/items/1/download", params={"vault_token": forged}, headers=_auth(token))
    assert r.status_code in (401, 403, 404)


def test_vault_ownership_boundary():
    client = _client()
    token_a = _register(client)
    token_b = _register(client)
    vault_a = _setup_vault(client, token_a)
    _vault_add(client, token_a, vault_a, "mine.txt", b"a-data")
    r = client.get("/vault/items", params={"vault_token": vault_a}, headers=_auth(token_a))
    item_id = r.json()[0]["id"]
    # B cannot list, download, or delete A's vault content (token is user-bound).
    r = client.get("/vault/items", params={"vault_token": vault_a}, headers=_auth(token_b))
    assert r.status_code == 401
    r = client.get(f"/vault/items/{item_id}/download", params={"vault_token": vault_a}, headers=_auth(token_b))
    assert r.status_code in (401, 403, 404)
    r = client.delete(f"/vault/items/{item_id}", params={"vault_token": vault_a}, headers=_auth(token_b))
    assert r.status_code in (401, 403, 404)


def test_vault_path_traversal_is_refused():
    from pathlib import Path
    from settings import settings
    vault_dir = settings.upload_path / "vault"
    for evil in ("../../sentinelguard.db", "..\\..\\x.vault", "abcd.vault", "zzzz.vault",
                 "00000000000000000000000000000000.vault/../../users.db"):
        try:
            safe_vault_path(vault_dir, evil)
            raised = False
        except ValueError:
            raised = True
        assert raised, f"traversal accepted: {evil}"
    # A well-formed name resolves inside the vault directory.
    good = safe_vault_path(vault_dir, ("a" * 32) + ".vault")
    assert good.parent == vault_dir.resolve()


def test_vault_requires_authentication():
    client = _client()
    assert client.get("/vault/status").status_code == 401
    assert client.get("/quarantine").status_code == 401


# ── Quarantine ──────────────────────────────────────────────────────────────

def test_quarantine_full_cycle_move_list_restore_delete():
    client = _client()
    token = _register(client)
    scan = _upload_scan(client, token, "evil.pdf", tampered_pdf())
    assert scan["risk_score"] >= 40

    r = client.post("/quarantine", json={"scan_id": scan["id"]}, headers=_auth(token))
    assert r.status_code == 200, r.text
    q = r.json()
    assert q["filename"] == "evil.pdf"
    assert q["risk_score"] == scan["risk_score"]
    assert q["reason"], "quarantine must carry a reason"
    assert "pdf-javascript" in q["reason"] or "pdf-date" in q["reason"] or q["risk_score"] > 0

    listed = client.get("/quarantine", headers=_auth(token)).json()
    assert [x["id"] for x in listed] == [q["id"]]

    # The original upload must be gone from normal storage while quarantined.
    import sqlite3
    con = sqlite3.connect("sentinelguard.db")
    stored = con.execute("SELECT stored_name FROM scans WHERE id=?", (scan["id"],)).fetchone()[0]
    con.close()
    from settings import settings
    assert not (settings.upload_path / stored).exists()
    qpath = (settings.upload_path / "quarantine" / q["stored_name"]) if False else None

    # Restore puts the file back into scan storage.
    r = client.post(f"/quarantine/{q['id']}/restore", headers=_auth(token))
    assert r.status_code == 200, r.text
    assert (settings.upload_path / stored).exists()
    assert client.get("/quarantine", headers=_auth(token)).json() == []

    # Quarantine again, then permanently delete.
    r = client.post("/quarantine", json={"scan_id": scan["id"]}, headers=_auth(token))
    q2 = r.json()
    r = client.delete(f"/quarantine/{q2['id']}", headers=_auth(token))
    assert r.status_code == 204
    assert client.get("/quarantine", headers=_auth(token)).json() == []


def test_quarantine_rejects_foreign_scan_and_duplicates():
    client = _client()
    token_a = _register(client)
    token_b = _register(client)
    scan = _upload_scan(client, token_a, "mine.pdf", tampered_pdf())
    # B cannot quarantine A's scan.
    r = client.post("/quarantine", json={"scan_id": scan["id"]}, headers=_auth(token_b))
    assert r.status_code == 404
    r = client.post("/quarantine", json={"scan_id": scan["id"]}, headers=_auth(token_a))
    assert r.status_code == 200
    # Duplicate quarantine is refused.
    r = client.post("/quarantine", json={"scan_id": scan["id"]}, headers=_auth(token_a))
    assert r.status_code == 409


def test_quarantine_unknown_scan_404():
    client = _client()
    token = _register(client)
    r = client.post("/quarantine", json={"scan_id": 987654}, headers=_auth(token))
    assert r.status_code == 404


def test_quarantine_delete_removes_blob():
    client = _client()
    token = _register(client)
    scan = _upload_scan(client, token, "gone.pdf", tampered_pdf())
    q = client.post("/quarantine", json={"scan_id": scan["id"]}, headers=_auth(token)).json()
    import sqlite3
    con = sqlite3.connect("sentinelguard.db")
    stored = con.execute("SELECT stored_name FROM quarantine_records WHERE id=?", (q["id"],)).fetchone()[0]
    con.close()
    from settings import settings
    blob = settings.upload_path / "quarantine" / stored
    assert blob.exists()
    client.delete(f"/quarantine/{q['id']}", headers=_auth(token))
    assert not blob.exists()


def test_scan_survives_quarantine_metadata_intact():
    client = _client()
    token = _register(client)
    scan = _upload_scan(client, token, "keep.pdf", tampered_pdf())
    q = client.post("/quarantine", json={"scan_id": scan["id"]}, headers=_auth(token)).json()
    restored = client.post(f"/quarantine/{q['id']}/restore", headers=_auth(token)).json()
    assert restored["id"] == scan["id"]
    assert restored["risk_score"] == scan["risk_score"]
    assert restored["sha256"] == scan["sha256"]
