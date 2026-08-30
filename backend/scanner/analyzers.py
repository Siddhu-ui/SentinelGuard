"""Bounded, explainable static analysis. Uploaded files are never executed."""
from collections import Counter
import hashlib, io, math, re
from pathlib import Path

SIGNATURES = {
    b"%PDF-": ("PDF document", "pdf"), b"\x89PNG\r\n\x1a\n": ("PNG image", "png"),
    b"\xff\xd8\xff": ("JPEG image", "jpg"), b"GIF87a": ("GIF image", "gif"),
    b"GIF89a": ("GIF image", "gif"), b"PK\x03\x04": ("ZIP archive", "zip"),
    b"Rar!\x1a\x07": ("RAR archive", "rar"), b"BM": ("BMP image", "bmp"),
}
EXPECTED = {"jpg":"JPEG image","jpeg":"JPEG image","png":"PNG image","gif":"GIF image","bmp":"BMP image","pdf":"PDF document","zip":"ZIP archive","rar":"RAR archive","exe":"Windows executable","docx":"ZIP archive","xlsx":"ZIP archive","pptx":"ZIP archive"}
WEIGHTS = {"signature-mismatch":35,"embedded-executable":40,"pdf-javascript":28,"pdf-action":18,"pdf-embedded-file":20,"pdf-metadata":6,"pdf-date":15,"entropy":6,"steganography":8}

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
    if data[:2] == b"MZ": found.append({"type":"Windows executable", "extension":"exe", "offset":0})
    return found

def _valid_pe_at(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 64 > len(data) or data[offset:offset + 2] != b"MZ": return False
    pe_offset = int.from_bytes(data[offset + 0x3C:offset + 0x40], "little")
    if pe_offset < 0x40 or pe_offset > 0x100000 or offset + pe_offset + 24 > len(data): return False
    pe = offset + pe_offset
    if data[pe:pe + 4] != b"PE\0\0": return False
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
            results.append({"category":"embedded-executable","severity":"high","confidence":"high","weight":40,"evidence":f"Validated PE header at byte offset {at} (MZ, PE\\0\\0, section table).","message":f"Validated embedded Windows executable structure at offset {at}."})
        start = at + 2
    return results

def _issue(category, severity, message, evidence, confidence="medium", weight=None):
    return {"category":category,"severity":severity,"confidence":confidence,"weight":WEIGHTS.get(category, 8) if weight is None else weight,"evidence":evidence,"message":message}

def pdf_analysis(data: bytes) -> list[dict]:
    issues = []
    if re.search(rb"/(JavaScript|JS)\b", data): issues.append(_issue("pdf-javascript","high","PDF contains JavaScript actions.","PDF token /JavaScript or /JS found.","high"))
    if re.search(rb"/AA\b|/OpenAction\b", data): issues.append(_issue("pdf-action","medium","PDF contains automatic or additional actions.","PDF token /AA or /OpenAction found.","medium"))
    if re.search(rb"/Filespec\b.*?/EF\b", data, re.S): issues.append(_issue("pdf-embedded-file","medium","PDF contains an embedded file attachment.","A file specification with an embedded-file stream was found.","high"))
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data), strict=False)
        metadata = reader.metadata or {}
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        issue_match = re.search(r"Issued:\s*(\d{1,2}\s+\w+\s+\d{4})", text, re.I)
        valid_match = re.search(r"Valid through:\s*(\d{1,2}\s+\w+\s+\d{4})", text, re.I)
        qr_match = re.search(r"QR[^\n]*?(?:issued|date)\s*[:=]?\s*(\d{1,2}\s+\w+\s+\d{4})", text, re.I)
        if issue_match and valid_match and issue_match.group(1) == valid_match.group(1):
            issues.append(_issue("pdf-date","medium","Issue and expiry dates are identical.",f"Issued={issue_match.group(1)}; Valid through={valid_match.group(1)}.","medium",10))
        if issue_match and qr_match and issue_match.group(1) != qr_match.group(1):
            issues.append(_issue("pdf-date","high","QR/document inconsistency detected.",f"Visible issue date={issue_match.group(1)}; QR payload date={qr_match.group(1)}.","high",25))
        if not metadata.get("/Producer") or not metadata.get("/Creator"):
            issues.append(_issue("pdf-metadata","low","PDF metadata is sparse or incomplete.","Creator/Producer metadata is missing; weak signal only.","low"))
        author = str(metadata.get("/Author", ""))
        if any(x in author.lower() for x in ("photoshop", "gimp", "canva")):
            issues.append(_issue("pdf-metadata","medium","Editing-software metadata is present.",f"Author metadata identifies {author}; this is an observable editing signal, not proof of fraud.","medium",10))
        if metadata.get("/CreationDate") and metadata.get("/ModDate") and str(metadata["/ModDate"]) < str(metadata["/CreationDate"]):
            issues.append(_issue("pdf-date","medium","PDF modification date precedes its creation date.",f"CreationDate={metadata['/CreationDate']}; ModDate={metadata['/ModDate']}.","high"))
    except Exception: pass
    return issues

def image_stego(data: bytes, file_ext: str) -> tuple[float, list[dict]]:
    if file_ext not in {"png","jpg","jpeg","gif","bmp"}: return 0.0, []
    try:
        from PIL import Image
        import numpy as np
        image = Image.open(io.BytesIO(data)); image.verify(); image = Image.open(io.BytesIO(data)).convert("RGB")
        ratio = float((np.asarray(image) & 1).mean()); score = max(0.0, 1 - abs(ratio - .5) * 20) * 8
        return round(score, 1), [_issue("steganography","low",f"LSB distribution is {ratio:.3f}; supporting heuristic only.",f"Pixel LSB ratio={ratio:.3f}.","low",int(score))] if score > 6 else []
    except Exception: return 0.0, []

def analyze(path: Path, extension: str) -> dict:
    data = read_sample(path); sigs = signatures(data); issues = []
    actual = next((s["type"] for s in sigs if s["offset"] == 0), "Unknown binary data")
    expected = EXPECTED.get(extension)
    if expected and actual != expected: issues.append(_issue("signature-mismatch","high",f"Extension .{extension} expects {expected}, but header indicates {actual}.",f"Expected {expected}; observed {actual} at offset 0.","high"))
    issues.extend(embedded_pe(data) if extension != "exe" else [])
    if extension == "pdf" and actual == "PDF document": issues.extend(pdf_analysis(data))
    ent = entropy(data)
    if ent >= 7.75: issues.append(_issue("entropy","low",f"High Shannon entropy ({ent}/8) is a supporting signal only.",f"Shannon entropy={ent}/8.","low"))
    stego, stego_issues = image_stego(data, extension); issues.extend(stego_issues)
    score = min(100, sum(int(i["weight"]) for i in issues))
    level = "Safe" if score <= 20 else "Low" if score <= 40 else "Medium" if score <= 60 else "High" if score <= 80 else "Critical"
    recommendation = {"Safe":"No action required; retain normal file hygiene.","Low":"Confirm the source before opening.","Medium":"Verify the source and open only in an isolated environment.","High":"Do not open directly; investigate in a sandbox.","Critical":"Quarantine the file and escalate to security personnel."}[level]
    return {"sha256":sha256(path),"entropy":ent,"entropy_category":"High" if ent >= 7.75 else "Medium" if ent >= 5 else "Low","mime_type":actual,"signatures":sigs,"risk_score":score,"risk_level":level,"recommendation":recommendation,"steganography_confidence":stego,"issues":issues,"score_breakdown":[{"category":i["category"],"weight":i["weight"],"evidence":i["evidence"]} for i in issues]}
