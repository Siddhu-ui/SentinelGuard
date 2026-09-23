from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor
from reportlab.pdfgen.canvas import Canvas
from models import Scan
import json

def render_pdf(scan: Scan) -> BytesIO:
    out=BytesIO(); c=Canvas(out, pagesize=letter); width,height=letter; details=json.loads(scan.details_json); y=750
    def heading(text):
        nonlocal y
        if y < 90: c.showPage(); y=750
        c.setFillColor(HexColor("#9F1239")); c.setFont("Helvetica-Bold", 12); c.drawString(42,y,text.upper()); y-=20
    def line(text, x=42, size=9, color="#1F2937"):
        nonlocal y
        if y < 55: c.showPage(); y=750
        c.setFillColor(HexColor(color)); c.setFont("Helvetica", size)
        for part in [text[i:i+100] for i in range(0,len(text),100)] or [""]:
            c.drawString(x,y,part); y-=13
    c.setFillColor(HexColor("#18070D")); c.rect(0, height-84, width, 84, fill=1, stroke=0)
    c.setFillColor(HexColor("#FF3A4D")); c.setFont("Helvetica-Bold", 21); c.drawString(42, height-42, "SENTINELGUARD")
    c.setFillColor(HexColor("#FFD6DD")); c.setFont("Helvetica", 10); c.drawString(42, height-62, "SECURITY ANALYSIS REPORT · STATIC PRE-ANALYSIS")
    c.setFillColor(HexColor("#111827")); y=height-112
    heading("File information")
    for label,value in [("Filename",scan.filename),("Scan ID",str(scan.id)),("SHA-256",scan.sha256),("Detected type",scan.mime_type),("Size",f"{scan.size:,} bytes"),("Scanned",scan.created_at.isoformat())]: line(f"{label}: {value}")
    y-=8; heading("Risk assessment"); line(f"{scan.risk_score}/100 · {scan.risk_level.upper()} RISK",42,14,"#9F1239"); line(f"Findings: {details.get('finding_count', len(details.get('issues', [])))} · Entropy: {scan.entropy}/8")
    y-=5; heading("Analysis results")
    for section in details.get("analysis_sections", []): line(f"{section['name']}: {section['score']}/100 · {section['findings']} findings · {section['severity']}")
    y-=5; heading("Risk score breakdown")
    for item in details.get("score_breakdown",[]) or [{"category":"none","weight":0,"evidence":"No suspicious indicators detected."}]: line(f"+{item.get('weight',0)} {item.get('category','finding')} [{item.get('confidence','unknown')} confidence] — {item.get('evidence','')}",48)
    y-=5; heading("Recommendations"); line(details.get("recommendation","Review findings.")); line("Static analysis provides indicators and does not independently establish maliciousness or document authenticity.",42,8,"#6B7280")
    c.showPage(); c.save(); out.seek(0); return out
