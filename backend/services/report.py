from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor
from reportlab.pdfgen.canvas import Canvas
from models import Scan
import json

def render_pdf(scan: Scan) -> BytesIO:
    out=BytesIO(); c=Canvas(out, pagesize=letter); width,height=letter; y=750
    c.setFillColor(HexColor("#0F172A")); c.rect(0, height-74, width, 74, fill=1, stroke=0)
    c.setFillColor(HexColor("#06B6D4")); c.setFont("Helvetica-Bold", 20); c.drawString(42, height-45, "SentinelGuard Security Report")
    c.setFillColor(HexColor("#111827")); c.setFont("Helvetica", 10)
    entries=[("Filename",scan.filename),("SHA-256",scan.sha256),("Risk",f"{scan.risk_level} ({scan.risk_score}/100)"),("Detected type",scan.mime_type),("Entropy",str(scan.entropy)),("Scanned",scan.created_at.isoformat())]
    for label,value in entries: c.drawString(42,y,f"{label}: {value}"); y-=22
    y-=8; c.setFont("Helvetica-Bold",12); c.drawString(42,y,"Findings"); y-=20; c.setFont("Helvetica",10)
    details=json.loads(scan.details_json)
    for issue in details.get("issues",[]) or [{"message":"No suspicious indicators detected."}]:
        text=issue["message"]
        for line in [text[i:i+94] for i in range(0,len(text),94)]: c.drawString(48,y,"• "+line); y-=16
    y-=8; c.setFont("Helvetica-Bold",12); c.drawString(42,y,"Recommendation"); y-=18; c.setFont("Helvetica",10); c.drawString(42,y,details.get("recommendation","Review findings."))
    c.showPage(); c.save(); out.seek(0); return out
