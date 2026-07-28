"""Bounded, explainable static file-analysis primitives; uploaded files are never executed."""
from collections import Counter
import hashlib, math
from pathlib import Path

SIGNATURES = {
    b"%PDF-": ("PDF document", "pdf"), b"\x89PNG\r\n\x1a\n": ("PNG image", "png"),
    b"\xff\xd8\xff": ("JPEG image", "jpg"), b"GIF87a": ("GIF image", "gif"), b"GIF89a": ("GIF image", "gif"),
    b"PK\x03\x04": ("ZIP archive", "zip"), b"MZ": ("Windows executable", "exe"),
    b"Rar!\x1a\x07": ("RAR archive", "rar"), b"BM": ("BMP image", "bmp"),
}
EXPECTED = {"jpg": "JPEG image", "jpeg": "JPEG image", "png": "PNG image", "gif": "GIF image", "bmp": "BMP image", "pdf": "PDF document", "zip": "ZIP archive", "rar": "RAR archive", "exe": "Windows executable", "docx": "ZIP archive", "xlsx": "ZIP archive", "pptx": "ZIP archive"}

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
    return round(-sum((n/total) * math.log2(n/total) for n in Counter(data).values()), 3)

def signatures(data: bytes) -> list[dict]:
    # Search only first 8 MiB, preventing scans from becoming resource attacks.
    found=[]
    for marker, (label, ext) in SIGNATURES.items():
        at=data.find(marker)
        if at >= 0: found.append({"type": label, "extension": ext, "offset": at})
    return found

def image_stego(data: bytes, file_ext: str) -> tuple[float, list[dict]]:
    if file_ext not in {"png", "jpg", "jpeg", "gif", "bmp"}: return 0.0, []
    try:
        from PIL import Image
        import numpy as np
        import io
        image = Image.open(io.BytesIO(data)); image.verify()
        image = Image.open(io.BytesIO(data)).convert("RGB")
        arr = np.asarray(image)
        lsb = arr & 1
        ratio = float(lsb.mean())
        # Natural images can be near 0.5; only a very even distribution is a weak signal.
        score = max(0.0, 1 - abs(ratio - .5) * 20) * 25
        return round(score, 1), [{"category":"steganography", "severity":"low", "message":f"LSB distribution is {ratio:.3f}; heuristic confidence {score:.0f}% (not proof of hidden data)."}] if score > 18 else []
    except Exception:
        return 0.0, [{"category":"image-analysis", "severity":"low", "message":"Image pixel analysis could not be completed."}]

def analyze(path: Path, extension: str) -> dict:
    data = read_sample(path); sigs = signatures(data); issues=[]; score=0
    actual = sigs[0]["type"] if sigs and sigs[0]["offset"] == 0 else "Unknown binary data"
    expected = EXPECTED.get(extension)
    if expected and actual != expected:
        issues.append({"category":"signature-mismatch","severity":"high","message":f"Extension .{extension} expects {expected}, but header indicates {actual}."}); score += 35
    embedded = [s for s in sigs if s["offset"] > 0]
    if embedded:
        issues.append({"category":"polyglot","severity":"high","message":"Embedded signatures found: " + ", ".join(f"{x['type']} at offset {x['offset']}" for x in embedded)}); score += min(40, 15 * len(embedded))
    ent = entropy(data)
    if ent >= 7.75:
        issues.append({"category":"entropy","severity":"medium","message":f"High Shannon entropy ({ent}/8) may indicate packed, encrypted, or compressed content."}); score += 15
    stego, stego_issues = image_stego(data, extension); issues.extend(stego_issues); score += int(stego)
    if any(s["extension"] == "exe" for s in sigs) and extension != "exe": score += 20
    score = min(100, score)
    level = "Safe" if score <= 20 else "Low" if score <= 40 else "Medium" if score <= 60 else "High" if score <= 80 else "Critical"
    recommendations = {"Safe":"No action required; retain normal file hygiene.","Low":"Confirm the source before opening.","Medium":"Verify the source and open only in an isolated environment.","High":"Do not open directly; investigate in a sandbox.","Critical":"Quarantine the file and escalate to security personnel."}[level]
    return {"sha256":sha256(path), "entropy":ent, "entropy_category":"High" if ent >= 7.75 else "Medium" if ent >= 5 else "Low", "mime_type":actual, "signatures":sigs, "risk_score":score, "risk_level":level, "recommendation":recommendations, "steganography_confidence":stego, "issues":issues}
