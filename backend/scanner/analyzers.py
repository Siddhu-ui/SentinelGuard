"""Bounded, explainable static analysis. Uploaded files are never executed."""
from __future__ import annotations

from collections import Counter
from datetime import date
import hashlib
import io
import math
import re
from pathlib import Path

# ── File identification ─────────────────────────────────────────────────────

SIGNATURES = {
    b"%PDF-": ("PDF document", "pdf"), b"\x89PNG\r\n\x1a\n": ("PNG image", "png"),
    b"\xff\xd8\xff": ("JPEG image", "jpg"), b"GIF87a": ("GIF image", "gif"),
    b"GIF89a": ("GIF image", "gif"), b"PK\x03\x04": ("ZIP archive", "zip"),
    b"Rar!\x1a\x07": ("RAR archive", "rar"), b"BM": ("BMP image", "bmp"),
}
EXPECTED = {"jpg": "JPEG image", "jpeg": "JPEG image", "png": "PNG image", "gif": "GIF image", "bmp": "BMP image", "pdf": "PDF document", "zip": "ZIP archive", "rar": "RAR archive", "exe": "Windows executable", "docx": "ZIP archive", "xlsx": "ZIP archive", "pptx": "ZIP archive"}
WEIGHTS = {"signature-mismatch": 35, "embedded-executable": 40, "pdf-javascript": 28, "pdf-action": 18, "pdf-embedded-file": 20, "pdf-metadata": 6, "pdf-date": 15, "entropy": 6, "steganography": 8, "pdf-integrity": 14}

SEVERITY_ORDER = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def read_sample(path: Path, limit=8 * 1024 * 1024) -> bytes:
    with path.open("rb") as f: return f.read(limit)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()


def entropy(data: bytes) -> float:
    if not data: return 0.0
    total = len(data)
    return round(-sum((n / total) * math.log2(n / total) for n in Counter(data).values()), 3)


def signatures(data: bytes) -> list[dict]:
    """Find file headers only; MZ is deliberately excluded from substring matching."""
    found = []
    for marker, (label, ext) in SIGNATURES.items():
        at = data.find(marker)
        if at >= 0: found.append({"type": label, "extension": ext, "offset": at})
    if data[:2] == b"MZ": found.append({"type": "Windows executable", "extension": "exe", "offset": 0})
    return found


def _issue(category, severity, message, evidence, confidence="medium", weight=None) -> dict:
    return {"category": category, "severity": severity, "confidence": confidence, "weight": WEIGHTS.get(category, 8) if weight is None else weight, "evidence": evidence, "message": message}


# ── Validated polyglot check (no MZ/PE substring false positives) ───────────

def _valid_pe_at(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 64 > len(data) or data[offset:offset + 2] != b"MZ": return False
    pe_offset = int.from_bytes(data[offset + 0x3C:offset + 0x40], "little")
    if pe_offset < 0x40 or pe_offset > 0x100000 or offset + pe_offset + 24 > len(data): return False
    pe = offset + pe_offset
    if data[pe:pe + 4] != b"PE\x00\x00": return False
    sections = int.from_bytes(data[pe + 6:pe + 8], "little")
    opt_size = int.from_bytes(data[pe + 20:pe + 22], "little")
    if not 1 <= sections <= 96 or not 0xE0 <= opt_size <= 0x400: return False
    return pe + 24 + opt_size + sections * 40 <= len(data)


def embedded_pe(data: bytes) -> list[dict]:
    results = []; start = 0
    while True:
        at = data.find(b"MZ", start)
        if at < 0: break
        if at > 0 and _valid_pe_at(data, at):
            results.append({"category": "embedded-executable", "severity": "high", "confidence": "high", "weight": 40, "evidence": f"Validated PE header at byte offset {at} (MZ, PE\\0\\0, section table).", "message": f"Validated embedded Windows executable structure at offset {at}."})
        start = at + 2
    return results


# ── PDF analysis ────────────────────────────────────────────────────────────

_PDF_TEXT_DATE = r"(\d{4}[-:]\d{2}[-:]\d{2}|\d{1,2}\s+\w+\s+\d{4}|\w+\s+\d{1,2},?\s+\d{4})"
_RE_JS = re.compile(rb"/(JavaScript|JS)\b")
_RE_ACTION = re.compile(rb"/(OpenAction|AA)\b")
_RE_LAUNCH = re.compile(rb"/(Launch|SubmitForm|GoToR)\b")
# /EF and /Filespec appear in either order depending on the producer.
_RE_FILESPEC_EF = re.compile(rb"(?:/Filespec\b.{0,600}?/EF\b|/EF\b.{0,600}?/Filespec\b)", re.S)
_RE_OBFUSCATED_JS = re.compile(rb"/(JavaScript|JS)\s*\(", re.I)
_RE_EMBEDDED_DATE = re.compile(rb"(\d{4}-\d{2}-\d{2})")
_RE_STREAM_LENGTH = re.compile(rb"/Length\s+(\d+)")
# 'Issued:', 'Issue Date:', 'Issue:' all denote the issue date; the date group
# itself starts at a digit or a month name so the prefix cannot capture 'Date 12'.
_ISSUE_DATE_PREFIX = r"Issue(?:d)?(?:\s+Date)?\s*[:=]\s*"
_RE_VISIBLE_ISSUE_DATE = re.compile(_ISSUE_DATE_PREFIX + _PDF_TEXT_DATE, re.I)
_RE_VISIBLE_VALID_DATE = re.compile(r"Valid (?:through|until|thru)\s*[:=]\s*" + _PDF_TEXT_DATE, re.I)
_RE_QR_DATE = re.compile(r"QR[^\n]{0,100}?" + _ISSUE_DATE_PREFIX + _PDF_TEXT_DATE, re.I)
# A second, conflicting issue date stated elsewhere in the document.
_RE_AMENDED_ISSUE_DATE = re.compile(r"Amended\s+(?:Issue\s+Date|Issued)\s*[:=]\s*" + _PDF_TEXT_DATE, re.I)
_EDIT_TOOLS = ("photoshop", "gimp", "canva", "illustrator", "inkscape", "pdftk", "qpdf", "pikepdf")

_MONTHS = ["", "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"]
_RE_MONTH_TOKEN = re.compile(r"[A-Za-z]{3,}")


def _visible_month(text_date: str) -> int | None:
    """Month number from a textual date like '01 Jan 2026' or 'January 1, 2026'."""
    token = _RE_MONTH_TOKEN.search(text_date or "")
    if not token: return None
    word = token.group(0).lower()
    for month, name in enumerate(_MONTHS):
        if name and (name == word or name[:3] == word[:3]): return month
    return None


def _pdf_integrity_issues(data: bytes) -> list[dict]:
    """Structural integrity checks: EOF marker, startxref, stream length honesty."""
    issues: list[dict] = []
    if b"%%EOF" not in data[-2048:] and b"%%EOF" not in data[:2048]:
        issues.append(_issue("pdf-integrity", "medium", "PDF is missing its %%EOF end-of-file marker.", "No %%EOF marker found in the first or last 2 KiB of the file.", "high"))
    if b"startxref" not in data[-4096:]:
        issues.append(_issue("pdf-integrity", "low", "PDF lacks a startxref trailer; cross-reference table may be damaged.", "No startxref keyword near end of file.", "medium"))
    for m in _RE_STREAM_LENGTH.finditer(data):
        declared = int(m.group(1))
        if declared > len(data):
            issues.append(_issue("pdf-integrity", "medium", f"A stream declares /Length {declared}, exceeding the file size.", f"Declared /Length={declared}; file is only {len(data)} bytes.", "high"))
            break
    return issues


def _visible_year(text_date: str) -> int | None:
    """Year number from a textual date containing a four-digit year."""
    m = re.search(r"\b(\d{4})\b", text_date or "")
    return int(m.group(1)) if m else None


def _pdf_content_consistency(text: str, data: bytes) -> list[dict]:
    """Content-consistency indicators between a document's own visible dates,
    QR/audit lines, and ISO dates embedded in its raw bytes."""
    issues: list[dict] = []
    issue_match = _RE_VISIBLE_ISSUE_DATE.search(text)
    valid_match = _RE_VISIBLE_VALID_DATE.search(text)
    qr_match = _RE_QR_DATE.search(text)
    amended_match = _RE_AMENDED_ISSUE_DATE.search(text)
    if issue_match and valid_match and issue_match.group(1) == valid_match.group(1):
        issues.append(_issue("pdf-date", "medium", "Issue and expiry dates are identical.", f"Issued={issue_match.group(1)}; Valid through={valid_match.group(1)}.", "medium", 10))
    if issue_match and qr_match and issue_match.group(1) != qr_match.group(1):
        issues.append(_issue("pdf-date", "high", "QR/document date inconsistency detected.", f"Visible issue date={issue_match.group(1)}; QR payload date={qr_match.group(1)}.", "high", 25))
    if issue_match and amended_match and issue_match.group(1) != amended_match.group(1):
        issues.append(_issue("pdf-date", "high", "Document states two different issue dates.", f"Issue Date={issue_match.group(1)}; Amended Issue Date={amended_match.group(1)}.", "high", 25))
    # Visible textual issue date vs. an ISO date embedded in the raw bytes
    if issue_match:
        visible = issue_match.group(1)
        month = _visible_month(visible)
        for m in _RE_EMBEDDED_DATE.finditer(data):
            iso = m.group(1)
            try:
                parts = [int(x) for x in iso.decode().split("-")]
                parsed = date(parts[0], parts[1], parts[2])
            except Exception:
                continue
            if month and parsed.month != month and parsed.year == _visible_year(visible):
                issues.append(_issue("pdf-date", "high", "Embedded date contradicts the visible issue date.", f"Visible issue date={visible}; embedded ISO date={iso.decode()}.", "medium", 18))
                break
            if month and parsed.month == month and parsed.year != _visible_year(visible):
                # Same month but a different year is still a mismatch worth surfacing.
                issues.append(_issue("pdf-date", "medium", "Embedded ISO date year differs from the visible issue date.", f"Visible issue date={visible}; embedded ISO date={iso.decode()}.", "medium", 10))
                break
    return issues


def pdf_analysis(data: bytes) -> list[dict]:
    """Run every PDF analyzer; a failing sub-check is skipped, not fatal."""
    issues: list[dict] = []

    # 1. Raw structural tokens (run even if pypdf cannot parse the file)
    if _RE_JS.search(data):
        issues.append(_issue("pdf-javascript", "high", "PDF contains JavaScript actions.", "PDF token /JavaScript or /JS found.", "high"))
    if _RE_ACTION.search(data):
        issues.append(_issue("pdf-action", "medium", "PDF contains automatic or additional actions.", "PDF token /OpenAction or /AA found.", "medium"))
    if _RE_LAUNCH.search(data):
        issues.append(_issue("pdf-action", "medium", "PDF contains launch or submit actions.", "PDF token /Launch, /SubmitForm or /GoToR found.", "medium"))
    if _RE_FILESPEC_EF.search(data):
        issues.append(_issue("pdf-embedded-file", "medium", "PDF contains an embedded file attachment.", "A file specification with an embedded-file stream was found.", "high"))
    if _RE_OBFUSCATED_JS.search(data) and not _RE_JS.search(data):
        issues.append(_issue("pdf-javascript", "medium", "Obfuscated JavaScript definition found.", "Inline /JavaScript ( definition without a matching action token.", "medium", 14))

    # 2. Structured checks through pypdf (metadata, text, consistency)
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data), strict=False)
        metadata = reader.metadata or {}
        pages = reader.pages
        text = "\n".join((page.extract_text() or "") for page in pages)

        if not metadata.get("/Producer") or not metadata.get("/Creator"):
            issues.append(_issue("pdf-metadata", "low", "PDF metadata is sparse or incomplete.", "Creator/Producer metadata is missing; weak signal only.", "low"))
        author = str(metadata.get("/Author", ""))
        creator = str(metadata.get("/Creator", ""))
        producer = str(metadata.get("/Producer", ""))
        editing_tool_hit = next((t for t in _EDIT_TOOLS if t in author.lower() or t in creator.lower() or t in producer.lower()), None)
        if editing_tool_hit:
            issues.append(_issue("pdf-metadata", "medium", "Editing-software metadata is present.", f"Document metadata identifies '{editing_tool_hit}' in Author/Creator/Producer; this is an observable editing signal, not proof of fraud.", "medium", 10))
        try:
            creation = metadata.get("/CreationDate")
            modification = metadata.get("/ModDate")
            if creation and modification and str(modification) < str(creation):
                issues.append(_issue("pdf-date", "medium", "PDF modification date precedes its creation date.", f"CreationDate={creation}; ModDate={modification}.", "high"))
        except Exception:
            pass

        issues.extend(_pdf_content_consistency(text, data))
    except Exception:
        # pypdf failure must not erase raw-token findings; malformed-file signal is
        # raised separately by _pdf_integrity_issues (startxref/%%EOF).
        pass

    # 3. Structural integrity and validated polyglot check
    issues.extend(_pdf_integrity_issues(data))
    issues.extend(embedded_pe(data))
    return issues


# ── Steganography (images only) ─────────────────────────────────────────────

def image_stego(data: bytes, file_ext: str) -> tuple[float, list[dict]]:
    if file_ext not in {"png", "jpg", "jpeg", "gif", "bmp"}: return 0.0, []
    try:
        from PIL import Image
        import numpy as np
        image = Image.open(io.BytesIO(data)); image.verify(); image = Image.open(io.BytesIO(data)).convert("RGB")
        ratio = float((np.asarray(image) & 1).mean()); score = max(0.0, 1 - abs(ratio - .5) * 20) * 8
        return round(score, 1), [_issue("steganography", "low", f"LSB distribution is {ratio:.3f}; supporting heuristic only.", f"Pixel LSB ratio={ratio:.3f}.", "low", int(score))] if score > 6 else []
    except Exception: return 0.0, []


# ── Bounded, UI-safe previews ───────────────────────────────────────────────

def _hex_preview(data: bytes, limit: int = 256) -> list[dict]:
    """Return a bounded, UI-friendly binary preview; never expose the whole file."""
    rows = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        rows.append({"offset": f"{offset:08X}", "hex": " ".join(f"{b:02X}" for b in chunk), "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)})
    return rows


def _analysis_sections(issues: list[dict]) -> list[dict]:
    groups = {
        "Structural analysis": {"keys": {"signature-mismatch", "embedded-executable", "pdf-action", "pdf-javascript", "pdf-embedded-file", "pdf-integrity"}, "explanation": "Headers, actions, embedded objects, and file structure."},
        "Content analysis": {"keys": {"pdf-date"}, "explanation": "Observable document content and metadata consistency signals."},
        "Metadata analysis": {"keys": {"pdf-metadata"}, "explanation": "Document metadata is a supporting signal, not proof of tampering."},
        "Steganography analysis": {"keys": {"steganography"}, "explanation": "Potential steganographic indicators from bounded image heuristics."},
        "Polyglot analysis": {"keys": {"embedded-executable"}, "explanation": "Validated secondary signatures only; incidental byte patterns are ignored."},
        "Integrity analysis": {"keys": {"signature-mismatch", "pdf-integrity", "pdf-date"}, "explanation": "Hash, declared type, and consistency indicators."},
    }
    result = []
    for name, spec in groups.items():
        matched = [i for i in issues if i["category"] in spec["keys"]]
        severity = max((i["severity"] for i in matched), key=lambda value: SEVERITY_ORDER.get(value, 0), default="none")
        result.append({"name": name, "score": min(100, sum(int(i["weight"]) for i in matched)), "findings": len(matched), "severity": severity, "explanation": spec["explanation"]})
    return result


def analyze(path: Path, extension: str) -> dict:
    data = read_sample(path); sigs = signatures(data); issues = []
    actual = next((s["type"] for s in sigs if s["offset"] == 0), "Unknown binary data")
    expected = EXPECTED.get(extension)
    if expected and actual != expected: issues.append(_issue("signature-mismatch", "high", f"Extension .{extension} expects {expected}, but header indicates {actual}.", f"Expected {expected}; observed {actual} at offset 0.", "high"))
    issues.extend(embedded_pe(data) if extension != "exe" else [])
    if extension == "pdf" and actual == "PDF document": issues.extend(pdf_analysis(data))
    ent = entropy(data)
    if ent >= 7.75: issues.append(_issue("entropy", "low", f"High Shannon entropy ({ent}/8) is a supporting signal only.", f"Shannon entropy={ent}/8.", "low"))
    stego, stego_issues = image_stego(data, extension); issues.extend(stego_issues)
    score = min(100, sum(int(i["weight"]) for i in issues))
    level = "Safe" if score <= 20 else "Low" if score <= 40 else "Medium" if score <= 60 else "High" if score <= 80 else "Critical"
    recommendation = {"Safe": "No action required; retain normal file hygiene.", "Low": "Confirm the source before opening.", "Medium": "Verify the source and open only in an isolated environment.", "High": "Do not open directly; investigate in a sandbox.", "Critical": "Quarantine the file and escalate to security personnel."}[level]
    digest = sha256(path)
    severity_breakdown = {lvl: sum(1 for i in issues if i["severity"] == lvl) for lvl in ("info", "low", "medium", "high", "critical")}
    return {"sha256": digest, "entropy": ent, "entropy_category": "High" if ent >= 7.75 else "Medium" if ent >= 5 else "Low", "mime_type": actual, "signatures": sigs, "risk_score": score, "risk_level": level, "recommendation": recommendation, "steganography_confidence": stego, "issues": issues, "finding_count": len(issues), "severity_breakdown": severity_breakdown, "analysis_sections": _analysis_sections(issues), "file_dna": {"type": actual, "mime_type": actual, "extension": extension, "size": path.stat().st_size, "sha256": digest, "entropy": ent, "signatures": sigs, "embedded_data": any(i["category"] == "pdf-embedded-file" for i in issues), "steganography_indicators": sum(1 for i in issues if i["category"] == "steganography"), "polyglot_indicators": sum(1 for i in issues if i["category"] == "embedded-executable")}, "hex_preview": _hex_preview(data), "score_breakdown": [{"category": i["category"], "severity": i["severity"], "confidence": i["confidence"], "weight": i["weight"], "evidence": i["evidence"]} for i in issues]}
