"""Regression tests for the full scan pipeline on PDFs.

Covers: upload -> analyzers -> findings -> risk score -> database -> API,
deterministic evidence-based scoring, the clean/tampered PDF pair, and the
distinct "analysis failed" state.
"""
import json
import os

from fastapi.testclient import TestClient

from main import app
from scanner.analyzers import analyze
from tests.helpers.pdf_samples import build_pdf, clean_pdf, tampered_pdf


def _client():
    return TestClient(app)


def _register(client: TestClient) -> str:
    import random

    email = f"pipeline{random.randint(0, 10**12)}@example.com"
    r = client.post(
        "/auth/register",
        json={"email": email, "display_name": "Pipeline Tester", "password": "longpassword123"},
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _upload(client: TestClient, token: str, name: str, data: bytes) -> dict:
    r = client.post(
        "/scans",
        files={"file": (name, data, "application/pdf")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return r.json()


# ── Clean PDF: completed analysis, low concern ──────────────────────────────

def test_clean_pdf_has_low_concern_and_completed_status():
    client = _client()
    token = _register(client)
    scan = _upload(client, token, "certificate-clean.pdf", clean_pdf())

    assert scan["analysis_status"] == "completed"
    assert scan["analysis_error"] is None
    assert scan["risk_score"] <= 20
    assert scan["risk_level"] == "Safe"
    categories = {t["category"] for t in scan["threats"]}
    assert not categories & {"pdf-javascript", "pdf-action", "pdf-embedded-file"}
    # Clean still carries real structural detail, not an empty payload.
    assert scan["details"]["finding_count"] == len(scan["threats"])
    assert scan["details"]["analysis_sections"]


# ── Tampered PDF: findings across sections reach the API ────────────────────

def test_tampered_pdf_produces_structured_findings_and_nonzero_score():
    client = _client()
    token = _register(client)
    scan = _upload(client, token, "invoice-tampered.pdf", tampered_pdf())

    assert scan["analysis_status"] == "completed"
    assert scan["risk_score"] >= 40
    assert scan["risk_level"] in {"Medium", "High", "Critical"}

    categories = {t["category"] for t in scan["threats"]}
    assert "pdf-javascript" in categories
    assert "pdf-action" in categories
    assert "pdf-embedded-file" in categories
    # Every finding carries concrete evidence; nothing is hardcoded.
    assert scan["threats"], "tampered file must produce findings"
    for t in scan["threats"]:
        assert t["evidence"], f"finding {t['category']} lacks evidence"
        assert t["message"]

    sections = {s["name"]: s for s in scan["details"]["analysis_sections"]}
    assert sections["Structural analysis"]["findings"] >= 3
    assert sections["Content analysis"]["findings"] >= 1  # date inconsistency
    # Score must equal the deterministic sum of finding weights.
    assert scan["risk_score"] == min(
        100, sum(i["weight"] for i in scan["details"]["issues"])
    )
    # The threat rows must be persisted and served back with evidence.
    assert len(scan["threats"]) == scan["details"]["finding_count"]


def test_score_is_independent_of_filename():
    client = _client()
    token = _register(client)
    innocent = _upload(client, token, "totally-innocent.pdf", tampered_pdf())
    plain = _upload(client, token, "a.pdf", tampered_pdf())
    assert innocent["risk_score"] == plain["risk_score"]
    assert innocent["risk_level"] == plain["risk_level"]


# ── Determinism: same bytes, same score ─────────────────────────────────────

def test_analyze_is_deterministic_for_identical_bytes(tmp_path):
    p1 = tmp_path / "one.pdf"
    p2 = tmp_path / "two.pdf"
    p1.write_bytes(tampered_pdf())
    p2.write_bytes(tampered_pdf())
    r1 = analyze(p1, "pdf")
    r2 = analyze(p2, "pdf")
    assert r1["risk_score"] == r2["risk_score"]
    assert r1["issues"] == r2["issues"]
    assert r1["analysis_sections"] == r2["analysis_sections"]


# ── Failure is distinct from "no findings" ──────────────────────────────────

def test_analysis_failure_is_reported_not_silently_clean(monkeypatch):
    client = _client()
    token = _register(client)

    def boom(target, extension):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr("main.analyze", boom)
    r = client.post(
        "/scans",
        files={"file": ("broken.pdf", clean_pdf(), "application/pdf")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    scan = r.json()
    assert scan["analysis_status"] == "failed"
    assert scan["analysis_error"]
    assert scan["risk_level"] == "Unknown"
    assert scan["threats"] == []


# ── No MZ/PE/polyglot false positives on prose PDFs ─────────────────────────

def test_prose_pdf_mentions_of_mz_pe_are_not_polyglot_findings():
    prose = (
        b"%PDF-1.7 text about MZ headers and PE executables, "
        b"no binary payload follows. Issued: 01 Jan 2026."
    )
    p = tmp_pdf(prose)
    result = analyze(p, "pdf")
    assert not any(i["category"] == "embedded-executable" for i in result["issues"])
    assert not any(i["category"] == "signature-mismatch" for i in result["issues"])


def test_high_entropy_alone_does_not_flag_tampering(tmp_path):
    import os

    rng = os.urandom  # entropy indicator, but structurally a valid PDF
    payload = rng(2048)
    data = build_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: b"<< /Type /Page /Parent 2 0 R >>",
            4: b"<< /Length %d >>\nstream\n" % len(payload) + payload + b"\nendstream",
        }
    )
    p = tmp_path / "high-entropy.pdf"
    p.write_bytes(data)
    result = analyze(p, "pdf")
    entropy_findings = [i for i in result["issues"] if i["category"] == "entropy"]
    # Entropy may appear as a low-severity supporting signal at most.
    assert all(i["severity"] == "low" for i in entropy_findings)
    assert all(int(i["weight"]) <= 10 for i in entropy_findings)
    # No action/embedded-file/polyglot conclusions from entropy alone.
    assert not any(
        i["category"] in {"pdf-javascript", "pdf-action", "pdf-embedded-file", "embedded-executable"}
        for i in result["issues"]
    )


def tmp_pdf(body: bytes):
    import tempfile
    from pathlib import Path

    p = Path(tempfile.mkdtemp()) / "prose.pdf"
    p.write_bytes(body)
    return p


# ── Real-world tamper formats (mirrors SentinelGuard_Tampered_Certificate_Test.pdf) ──

def _realistic_certificate_pdf(*, tampered: bool) -> bytes:
    """ReportLab-style certificate with a C2PA manifest whose /EF precedes /Filespec."""
    import zlib

    amended = (
        b"AMENDED ISSUE DATE: 28 September 2026\n"
        b"TEST TAMPER INDICATOR: visible date conflicts with encoded verification data"
        if tampered
        else b""
    )
    qr_line = b"QR DATA: Certificate ID SG-CERT-2026-0017 | Issue Date 12 September 2026\n"
    page_text = (
        b"BT /F1 12 Tf 72 720 Td (CERTIFICATE OF COMPLETION) Tj ET\n"
        b"BT /F1 12 Tf 72 700 Td (Issue Date: 12 September 2026) Tj ET\n"
        + (b"BT /F1 12 Tf 72 680 Td (" + amended.strip() + b") Tj ET\n" if amended else b"")
        + b"BT /F1 12 Tf 72 660 Td (" + qr_line.strip() + b") Tj ET"
    )
    creator = (
        b"Adobe Photoshop (TEST TAMPER METADATA)" if tampered else b"SentinelGuard Test Harness"
    )
    manifest = zlib.compress(b"c2pa manifest payload jumb jumd " + os.urandom(64))
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 8 0 R >> >> /Contents 4 0 R >>",
        4: b"<< /Length %d >>\nstream\n" % len(page_text) + page_text + b"\nendstream",
        # Producer-style objects: /EF appears BEFORE /Filespec (real-world order)
        5: b"<< /Length %d /Type /EmbeddedFile /Subtype /application#2Fc2pa >>\nstream\n"
        % len(manifest)
        + manifest
        + b"\nendstream",
        6: b"<< /AFRelationship /C2PA_Manifest /F (Content Credentials) /EF << /F 5 0 R >> "
        b"/Type /Filespec >>",
        7: b"<< /Type /Catalog /Names << /EmbeddedFiles << /Names [(Content Credentials) 5 0 R] >> >> >>",
        8: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        9: b"<< /Producer (ReportLab PDF Library) /Creator (" + creator + b") >>",
    }
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + objects[num] + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (max(objects) + 1)
    for num in range(1, max(objects) + 1):
        out += f"{offsets[num]:010d} 00000 n \n".encode()
    out += (
        b"trailer\n<< /Size %d /Root 1 0 R /Info 9 0 R >>\nstartxref\n%d\n%%%%EOF"
        % (max(objects) + 1, xref)
    )
    return bytes(out)


def test_realistic_tampered_certificate_produces_findings(tmp_path):
    p = tmp_path / "SentinelGuard_Tampered_Certificate_Test.pdf"
    p.write_bytes(_realistic_certificate_pdf(tampered=True))
    result = analyze(p, "pdf")
    categories = {i["category"] for i in result["issues"]}
    assert "pdf-date" in categories, "amended-vs-original issue-date conflict must be found"
    assert "pdf-metadata" in categories, "editing tool in Creator must be found"
    date_issues = [i for i in result["issues"] if i["category"] == "pdf-date"]
    assert any("Amended" in i["evidence"] or "28 September" in i["evidence"] for i in date_issues)
    assert result["risk_score"] >= 30


def test_realistic_clean_certificate_stays_low_concern(tmp_path):
    p = tmp_path / "SentinelGuard_Clean_Certificate_Test.pdf"
    p.write_bytes(_realistic_certificate_pdf(tampered=False))
    result = analyze(p, "pdf")
    categories = {i["category"] for i in result["issues"]}
    assert "pdf-date" not in categories, "single consistent issue date must not flag"
    assert "pdf-metadata" not in categories, "benign Creator string must not flag"
    assert result["risk_score"] <= 20


def test_embedded_file_found_regardless_of_ef_filespec_order(tmp_path):
    """Producers emit /EF and /Filespec in either order; both must be detected."""
    ef_first = b"%PDF-1.7\n<< /F (x) /EF << /F 5 0 R >> /Type /Filespec >>\n%%EOF"
    fs_first = b"%PDF-1.7\n<< /Type /Filespec /F (x) /EF << /F 5 0 R >> >>\n%%EOF"
    from scanner.analyzers import _RE_FILESPEC_EF

    assert _RE_FILESPEC_EF.search(ef_first)
    assert _RE_FILESPEC_EF.search(fs_first)
