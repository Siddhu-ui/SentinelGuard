"""Bounded, explainable static analysis. Uploaded files are never executed."""
from __future__ import annotations

from collections import Counter
import hashlib
import io
import math
import re
from pathlib import Path

SIGNATURES = {
    b"%PDF-": ("PDF document", "pdf"),
    b"\x89PNG\r\n\x1a\n": ("PNG image", "png"),
    b"\xff\xd8\xff": ("JPEG image", "jpg"),
    b"GIF87a": ("GIF image", "gif"),
    b"GIF89a": ("GIF image", "gif"),
    b"PK\x03\x04": ("ZIP archive", "zip"),
    b"Rar!\x1a\x07": ("RAR archive", "rar"),
    b"BM": ("BMP image", "bmp"),
}

EXPECTED = {
    "jpg": "JPEG image",
    "jpeg": "JPEG image",
    "png": "PNG image",
    "gif": "GIF image",
    "bmp": "BMP image",
    "pdf": "PDF document",
    "zip": "ZIP archive",
    "rar": "RAR archive",
    "exe": "Windows executable",
    "docx": "ZIP archive",
    "xlsx": "ZIP archive",
    "pptx": "ZIP archive",
}

WEIGHTS = {
    "signature-mismatch": 35,
    "embedded-executable": 40,
    "pdf-javascript": 28,
    "pdf-action": 18,
    "pdf-embedded-file": 20,
    "pdf-metadata": 6,
    "pdf-date": 15,
    "entropy": 6,
    "steganography": 8,
}


def read_sample(path: Path, limit: int = 8 * 1024 * 1024) -> bytes:
    with path.open("rb") as f:
        return f.read(limit)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return round(-sum((n / total) * math.log2(n / total) for n in Counter(data).values()), 3)


def signatures(data: bytes) -> list[dict]:
    """Find file headers; MZ is deliberately excluded from arbitrary substring matching."""
    found = []
    for marker, (label, ext) in SIGNATURES.items():
        at = data.find(marker)
        if at >= 0:
            found.append({"type": label, "extension": ext, "offset": at})
    if data[:2] == b"MZ":
        found.append({"type": "Windows executable", "extension": "exe", "offset": 0})
    return found


def _valid_pe_at(data: bytes, offset: int) -> bool:
    """Validate that bytes at offset actually form a valid PE executable header structure.
    
    Prevents false positives on plain text or PDF content containing incidental 'MZ' characters.
    """
    if offset < 0 or offset + 64 > len(data) or data[offset:offset + 2] != b"MZ":
        return False
    pe_offset = int.from_bytes(data[offset + 0x3C:offset + 0x40], "little")
    if pe_offset < 0x40 or pe_offset > 0x100000 or offset + pe_offset + 24 > len(data):
        return False
    pe = offset + pe_offset
    if data[pe:pe + 4] != b"PE\0\0":
        return False
    sections = int.from_bytes(data[pe + 6:pe + 8], "little")
    opt_size = int.from_bytes(data[pe + 20:pe + 22], "little")
    if not (1 <= sections <= 96) or not (0xE0 <= opt_size <= 0x400):
        return False
    return pe + 24 + opt_size + sections * 40 <= len(data)


def embedded_pe(data: bytes) -> list[dict]:
    results = []
    start = 0
    while True:
        at = data.find(b"MZ", start)
        if at < 0:
            break
        if at > 0 and _valid_pe_at(data, at):
            results.append({
                "category": "embedded-executable",
                "severity": "high",
                "confidence": "high",
                "weight": 40,
                "evidence": f"Validated PE header at byte offset {at} (MZ, PE\\0\\0, section table).",
                "message": f"Validated embedded Windows executable structure at offset {at}.",
                "recommendation": "Investigate file origin in an isolated environment before trusting.",
            })
        start = at + 2
    return results


def _issue(
    category: str,
    severity: str,
    message: str,
    evidence: str,
    confidence: str = "medium",
    weight: int | None = None,
    recommendation: str = "",
) -> dict:
    default_rec = {
        "signature-mismatch": "Verify file extension matches intended file type.",
        "embedded-executable": "Investigate embedded binary payload before opening.",
        "pdf-javascript": "Open with JavaScript execution disabled in PDF reader.",
        "pdf-action": "Inspect automatic launch actions before opening.",
        "pdf-embedded-file": "Inspect or extract embedded attachment in a safe viewer.",
        "pdf-metadata": "Verify document through issuing organization if authenticity matters.",
        "pdf-date": "Review document timestamps with the issuing party for consistency.",
        "entropy": "High entropy may indicate compression or encryption; verify file source.",
        "steganography": "Inspect image pixel data if covert data transmission is suspected.",
    }.get(category, "Review static indicators before trusting or sharing.")

    return {
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "weight": WEIGHTS.get(category, 8) if weight is None else weight,
        "evidence": evidence,
        "message": message,
        "recommendation": recommendation or default_rec,
    }


def pdf_analysis(data: bytes) -> list[dict]:
    issues = []
    if re.search(rb"/(JavaScript|JS)\b", data):
        issues.append(_issue(
            "pdf-javascript",
            "high",
            "PDF contains JavaScript actions.",
            "PDF token /JavaScript or /JS found in document structure.",
            "high",
            recommendation="Open document with JavaScript execution disabled.",
        ))
    if re.search(rb"/AA\b|/OpenAction\b", data):
        issues.append(_issue(
            "pdf-action",
            "medium",
            "PDF contains automatic or additional launch actions.",
            "PDF token /AA or /OpenAction found.",
            "medium",
            recommendation="Inspect automatic trigger actions prior to viewing.",
        ))
    if re.search(rb"/Filespec\b.*?/EF\b", data, re.S):
        issues.append(_issue(
            "pdf-embedded-file",
            "medium",
            "PDF contains an embedded file attachment.",
            "A file specification with an embedded-file stream (/EF) was found.",
            "high",
            recommendation="Inspect embedded attachments in a sandboxed viewer.",
        ))
    
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data), strict=False)
        metadata = reader.metadata or {}
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        
        issue_match = re.search(r"Issued:\s*(\d{1,2}\s+\w+\s+\d{4})", text, re.I)
        valid_match = re.search(r"Valid through:\s*(\d{1,2}\s+\w+\s+\d{4})", text, re.I)
        qr_match = re.search(r"QR[^\n]*?(?:issued|date)\s*[:=]?\s*(\d{1,2}\s+\w+\s+\d{4})", text, re.I)
        
        if issue_match and valid_match and issue_match.group(1) == valid_match.group(1):
            issues.append(_issue(
                "pdf-date",
                "medium",
                "Issue and expiry dates appear identical.",
                f"Issued={issue_match.group(1)}; Valid through={valid_match.group(1)}.",
                "medium",
                10,
                recommendation="Verify validity period with the document issuer.",
            ))
        if issue_match and qr_match and issue_match.group(1) != qr_match.group(1):
            issues.append(_issue(
                "pdf-date",
                "high",
                "QR metadata and visible date inconsistency detected.",
                f"Visible issue date={issue_match.group(1)}; QR payload date={qr_match.group(1)}.",
                "high",
                25,
                recommendation="Values differ and should be verified with the issuer. Mismatch does not independently establish forgery.",
            ))
        
        # Metadata analysis
        creator = str(metadata.get("/Creator", "") or "")
        producer = str(metadata.get("/Producer", "") or "")
        author = str(metadata.get("/Author", "") or "")
        
        if not creator and not producer:
            issues.append(_issue(
                "pdf-metadata",
                "low",
                "PDF metadata is sparse or incomplete.",
                "Creator and Producer metadata fields are not specified.",
                "low",
                recommendation="Normal for stripped documents; verify source if provenance is critical.",
            ))
        
        all_meta = f"{creator} {producer} {author}".lower()
        if any(tool in all_meta for tool in ("photoshop", "gimp", "canva", "pixlr")):
            issues.append(_issue(
                "pdf-metadata",
                "medium",
                "Image-editing software identified in document metadata.",
                f"Metadata identifies editing software ({all_meta.strip()[:60]}); this is an observable editing signal, not proof of tampering.",
                "medium",
                10,
                recommendation="Verify document through the issuing organization if authenticity matters.",
            ))
        
        c_date = metadata.get("/CreationDate")
        m_date = metadata.get("/ModDate")
        if c_date and m_date and str(m_date) < str(c_date):
            issues.append(_issue(
                "pdf-date",
                "medium",
                "PDF modification timestamp precedes creation timestamp.",
                f"CreationDate={c_date}; ModDate={m_date}.",
                "high",
                recommendation="Review timestamp sequencing with the sender.",
            ))
    except Exception:
        pass

    return issues


def image_stego(data: bytes, file_ext: str) -> tuple[float, list[dict]]:
    if file_ext not in {"png", "jpg", "jpeg", "gif", "bmp"}:
        return 0.0, []
    try:
        from PIL import Image
        import numpy as np
        image = Image.open(io.BytesIO(data))
        image.verify()
        image = Image.open(io.BytesIO(data)).convert("RGB")
        ratio = float((np.asarray(image) & 1).mean())
        score = max(0.0, 1 - abs(ratio - 0.5) * 20) * 8
        if score > 6:
            return round(score, 1), [_issue(
                "steganography",
                "low",
                f"Least Significant Bit (LSB) variance is {ratio:.3f}.",
                f"Pixel LSB distribution ratio={ratio:.3f}; supporting indicator only.",
                "low",
                int(score),
                recommendation="Check if the image is expected to contain hidden payloads.",
            )]
        return round(score, 1), []
    except Exception:
        return 0.0, []


def _hex_preview(data: bytes, limit: int = 256) -> list[dict]:
    """Return a bounded binary preview of the first bytes; never expose entire file."""
    rows = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        rows.append({
            "offset": f"{offset:08X}",
            "hex": " ".join(f"{b:02X}" for b in chunk),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
        })
    return rows


def _analysis_sections(issues: list[dict], signatures_found: list[dict], entropy_value: float) -> list[dict]:
    groups = {
        "Structural analysis": {
            "keys": {"signature-mismatch", "embedded-executable", "pdf-action", "pdf-javascript", "pdf-embedded-file"},
            "explanation": "File headers, markers, actions, and embedded stream boundaries.",
        },
        "Content analysis": {
            "keys": {"pdf-date", "pdf-metadata"},
            "explanation": "Observable document text, date alignment, and metadata consistency signals.",
        },
        "Metadata analysis": {
            "keys": {"pdf-metadata"},
            "explanation": "Document metadata is a supporting context indicator, not proof of tampering.",
        },
        "Steganography analysis": {
            "keys": {"steganography"},
            "explanation": "Least significant bit distribution and bounded image heuristics.",
        },
        "Polyglot analysis": {
            "keys": {"embedded-executable"},
            "explanation": "Validated secondary signatures only; incidental byte patterns are excluded.",
        },
        "Integrity analysis": {
            "keys": {"signature-mismatch", "pdf-date"},
            "explanation": "Cryptographic hash, declared MIME type, and structural consistency.",
        },
    }
    result = []
    for name, spec in groups.items():
        matched = [i for i in issues if i["category"] in spec["keys"]]
        severity = max(
            (i["severity"] for i in matched),
            key=lambda value: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0),
            default="none",
        )
        result.append({
            "name": name,
            "score": min(100, sum(int(i["weight"]) for i in matched)),
            "findings": len(matched),
            "severity": severity,
            "explanation": spec["explanation"],
        })
    return result


def analyze(path: Path, extension: str) -> dict:
    data = read_sample(path)
    sigs = signatures(data)
    issues = []
    
    actual = next((s["type"] for s in sigs if s["offset"] == 0), "Unknown binary data")
    expected = EXPECTED.get(extension)
    if expected and actual != expected:
        issues.append(_issue(
            "signature-mismatch",
            "high",
            f"Declared extension .{extension} expects {expected}, but header indicates {actual}.",
            f"Expected {expected}; observed {actual} at offset 0.",
            "high",
        ))
    
    # Embedded executable analysis (polyglot / payload check)
    if extension != "exe":
        issues.extend(embedded_pe(data))
    
    # PDF specific analysis
    if extension == "pdf" and actual == "PDF document":
        issues.extend(pdf_analysis(data))
    
    # Shannon Entropy analysis
    ent = entropy(data)
    if ent >= 7.75:
        issues.append(_issue(
            "entropy",
            "low",
            f"High Shannon entropy ({ent}/8) detected.",
            f"Shannon entropy={ent}/8; common in encrypted, compressed, or packed data.",
            "low",
        ))
    
    # Image Steganography
    stego, stego_issues = image_stego(data, extension)
    issues.extend(stego_issues)
    
    # Calculate deterministic explainable risk score
    score = min(100, sum(int(i["weight"]) for i in issues))
    
    # Map score to standardized product concern levels
    if score <= 20:
        concern_level = "Low concern"
        risk_level = "Safe"
        assessment_summary = "No significant suspicious indicators were detected during static pre-analysis."
        recommendation = "No action required; maintain normal file hygiene."
    elif score <= 50:
        concern_level = "Review recommended"
        risk_level = "Medium"
        assessment_summary = "Potential security indicators detected that warrant manual review."
        recommendation = "Review findings and verify file provenance before trusting or executing."
    else:
        concern_level = "High concern"
        risk_level = "High"
        assessment_summary = "Multiple high-severity security indicators detected in static analysis."
        recommendation = "Do not open directly; quarantine or inspect in an isolated environment."
    
    digest = sha256(path)
    file_size = path.stat().st_size
    
    # Construct concise "Why?" explanations
    why_items = []
    if not any(i["category"] == "signature-mismatch" for i in issues):
        why_items.append(f"File signature matches {actual}")
    else:
        why_items.append(f"Signature mismatch: declared .{extension} vs detected {actual}")
        
    if not any(i["category"] == "embedded-executable" for i in issues):
        why_items.append("No validated polyglot or embedded executable structure detected")
    else:
        why_items.append("Validated embedded executable structure detected")
        
    if extension == "pdf":
        if not any("pdf-" in i["category"] for i in issues):
            why_items.append("PDF structure and metadata appear consistent")
        else:
            pdf_issues = [i["message"] for i in issues if "pdf-" in i["category"]]
            why_items.append(f"PDF indicators: {', '.join(pdf_issues[:2])}")
    
    if ent < 7.75:
        why_items.append(f"Entropy ({ent}/8) is within typical bounds")
    else:
        why_items.append(f"High entropy ({ent}/8) suggests compression or encryption")

    # Construct File DNA security fingerprint
    file_dna = {
        "type": actual,
        "mime_type": actual,
        "extension": extension,
        "size": file_size,
        "sha256": digest,
        "entropy": ent,
        "entropy_formatted": f"{ent} / 8",
        "structure_status": "Consistent" if not any(i["category"] in {"signature-mismatch", "embedded-executable"} for i in issues) else "Anomaly detected",
        "metadata_status": "No significant anomaly" if not any(i["category"] == "pdf-metadata" for i in issues) else "Review recommended",
        "embedded_content": "Detected" if any(i["category"] == "pdf-embedded-file" for i in issues) else "None detected",
        "steganography_indicators": "Indicator noted" if any(i["category"] == "steganography" for i in issues) else "None detected",
        "polyglot_indicators": "Detected" if any(i["category"] == "embedded-executable" for i in issues) else "None detected",
        "integrity_status": "Verified" if not any(i["category"] == "signature-mismatch" for i in issues) else "Mismatch",
        "signatures": sigs,
    }

    # Score breakdown table
    score_breakdown = [
        {
            "category": i["category"],
            "severity": i["severity"],
            "confidence": i["confidence"],
            "weight": i["weight"],
            "evidence": i["evidence"],
        }
        for i in issues
    ]
    if not score_breakdown:
        score_breakdown.append({
            "category": "Baseline",
            "severity": "none",
            "confidence": "high",
            "weight": 0,
            "evidence": "No suspicious indicators detected.",
        })

    return {
        "sha256": digest,
        "entropy": ent,
        "entropy_category": "High" if ent >= 7.75 else "Medium" if ent >= 5 else "Low",
        "mime_type": actual,
        "extension": extension,
        "size": file_size,
        "signatures": sigs,
        "risk_score": score,
        "risk_level": risk_level,
        "concern_level": concern_level,
        "assessment_summary": assessment_summary,
        "recommendation": recommendation,
        "steganography_confidence": stego,
        "issues": issues,
        "finding_count": len(issues),
        "why": why_items,
        "score_explanation": "Risk score is based on detected security indicators. It is not a probability of maliciousness.",
        "analysis_sections": _analysis_sections(issues, sigs, ent),
        "file_dna": file_dna,
        "hex_preview": _hex_preview(data),
        "score_breakdown": score_breakdown,
        "disclaimer": "Static analysis provides security indicators and does not independently establish maliciousness or document authenticity.",
    }
