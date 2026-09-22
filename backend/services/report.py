import json
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor
from reportlab.pdfgen.canvas import Canvas
from models import Scan


def render_pdf(scan: Scan) -> BytesIO:
    out = BytesIO()
    c = Canvas(out, pagesize=letter)
    width, height = letter
    details = json.loads(scan.details_json) if scan.details_json else {}
    y = height - 50

    def check_page_break(needed_space: int = 40):
        nonlocal y
        if y < needed_space:
            c.showPage()
            y = height - 50

    def draw_header():
        nonlocal y
        c.setFillColor(HexColor("#0f172a"))  # Deep navy/slate
        c.rect(0, height - 70, width, 70, fill=1, stroke=0)
        c.setFillColor(HexColor("#38bdf8"))  # Cyan/Shield accent
        c.setFont("Helvetica-Bold", 18)
        c.drawString(40, height - 35, "SENTINELGUARD")
        c.setFillColor(HexColor("#94a3b8"))
        c.setFont("Helvetica", 9)
        c.drawString(40, height - 52, "FILE SECURITY CENTER  •  STATIC SECURITY ANALYSIS REPORT")
        y = height - 90

    def heading(text: str):
        nonlocal y
        check_page_break(70)
        y -= 10
        c.setFillColor(HexColor("#0284c7"))
        c.setFont("Helvetica-Bold", 11)
        c.drawString(40, y, text.upper())
        c.setStrokeColor(HexColor("#e2e8f0"))
        c.setLineWidth(0.5)
        c.line(40, y - 4, width - 40, y - 4)
        y -= 18

    def row(label: str, value: str, is_code: bool = False):
        nonlocal y
        check_page_break(30)
        c.setFillColor(HexColor("#64748b"))
        c.setFont("Helvetica", 9)
        c.drawString(40, y, label)
        c.setFillColor(HexColor("#0f172a"))
        c.setFont("Courier" if is_code else "Helvetica-Bold", 9)
        val_str = str(value)
        if len(val_str) > 65:
            val_str = val_str[:62] + "..."
        c.drawString(160, y, val_str)
        y -= 15

    def paragraph(text: str, x: int = 40, size: int = 8.5, color: str = "#334155", leading: int = 12):
        nonlocal y
        check_page_break(30)
        c.setFillColor(HexColor(color))
        c.setFont("Helvetica", size)
        words = text.split()
        current_line = []
        for word in words:
            current_line.append(word)
            line_str = " ".join(current_line)
            if len(line_str) > 85:
                current_line.pop()
                c.drawString(x, y, " ".join(current_line))
                y -= leading
                check_page_break(25)
                current_line = [word]
        if current_line:
            c.drawString(x, y, " ".join(current_line))
            y -= leading

    # Draw First Page
    draw_header()

    # 1. File Information
    heading("1. File Information")
    row("Filename", scan.filename)
    row("Scan ID", f"SG-{scan.id:06d}")
    row("SHA-256", scan.sha256, is_code=True)
    row("Detected Type", scan.mime_type)
    row("File Size", f"{scan.size:,} bytes ({(scan.size/1024):.1f} KB)")
    row("Entropy", f"{scan.entropy:.3f} / 8.000 ({details.get('entropy_category', 'Normal')})")
    row("Analysis Date", scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(scan.created_at, "strftime") else str(scan.created_at))

    # 2. Risk Assessment
    heading("2. Security Assessment")
    concern = details.get("concern_level", "Low concern" if scan.risk_score <= 20 else "Review recommended" if scan.risk_score <= 50 else "High concern")
    concern_color = "#10b981" if scan.risk_score <= 20 else "#f59e0b" if scan.risk_score <= 50 else "#ef4444"
    
    check_page_break(50)
    c.setFillColor(HexColor(concern_color))
    c.rect(40, y - 25, width - 80, 30, fill=1, stroke=0)
    c.setFillColor(HexColor("#ffffff"))
    c.setFont("Helvetica-Bold", 12)
    c.drawString(55, y - 16, f"RISK SCORE: {scan.risk_score}/100  —  {concern.upper()}")
    y -= 38

    paragraph(f"Assessment Summary: {details.get('assessment_summary', 'Static pre-analysis complete.')}", x=40, size=9, color="#1e293b")
    paragraph(f"Score Context: {details.get('score_explanation', 'Risk score is based on detected security indicators. It is not a probability of maliciousness.')}", x=40, size=8, color="#64748b")

    # 3. Analysis Coverage Matrix
    heading("3. Analysis Coverage")
    sections = details.get("analysis_sections", [])
    if sections:
        for s in sections:
            check_page_break(25)
            sev_color = "#10b981" if s["severity"] in {"none", "clear"} else "#f59e0b" if s["severity"] in {"low", "medium"} else "#ef4444"
            c.setFillColor(HexColor("#0f172a"))
            c.setFont("Helvetica-Bold", 8.5)
            c.drawString(40, y, s["name"])
            c.setFillColor(HexColor(sev_color))
            c.drawString(200, y, f"[{s['severity'].upper()}] - {s['findings']} finding(s)")
            c.setFillColor(HexColor("#64748b"))
            c.setFont("Helvetica", 8)
            c.drawString(320, y, s.get("explanation", "")[:50])
            y -= 14
    else:
        paragraph("All static analysis modules executed normally.", x=40)

    # 4. Detected Security Indicators & Findings
    heading("4. Detected Security Indicators")
    issues = details.get("issues", [])
    if issues:
        for idx, issue in enumerate(issues, start=1):
            check_page_break(50)
            c.setFillColor(HexColor("#0f172a"))
            c.setFont("Helvetica-Bold", 8.5)
            c.drawString(40, y, f"Indicator {idx}: {issue.get('category', 'Finding').upper()} (Weight: +{issue.get('weight', 0)})")
            y -= 12
            paragraph(f"• Severity: {issue.get('severity', 'info').upper()}  |  Confidence: {issue.get('confidence', 'medium')}", x=50, size=8, color="#475569")
            paragraph(f"• Evidence: {issue.get('evidence', '')}", x=50, size=8, color="#0f172a")
            paragraph(f"• Recommendation: {issue.get('recommendation', '')}", x=50, size=8, color="#0284c7")
            y -= 6
    else:
        paragraph("✓ No suspicious indicators detected during static pre-analysis.", x=40, size=9, color="#10b981")

    # 5. File DNA Fingerprint
    heading("5. File DNA Security Fingerprint")
    dna = details.get("file_dna", {})
    if dna:
        row("Structure Status", str(dna.get("structure_status", "Consistent")))
        row("Metadata Status", str(dna.get("metadata_status", "No significant anomaly")))
        row("Embedded Content", str(dna.get("embedded_content", "None detected")))
        row("Steganography Signal", str(dna.get("steganography_indicators", "None detected")))
        row("Polyglot Signal", str(dna.get("polyglot_indicators", "None detected")))
        row("Integrity Status", str(dna.get("integrity_status", "Verified")))

    # 6. Recommendations & Disclaimer
    heading("6. Recommendations & Disclaimer")
    paragraph(f"Primary Action: {details.get('recommendation', 'Maintain standard file verification practices.')}", x=40, size=9, color="#0f172a")
    y -= 8
    c.setStrokeColor(HexColor("#cbd5e1"))
    c.setLineWidth(0.5)
    c.line(40, y, width - 40, y)
    y -= 12
    paragraph(
        "DISCLAIMER: Static analysis provides security indicators and does not independently establish maliciousness, "
        "document authenticity, or complete safety. Files should be verified with the issuing source if authenticity is required.",
        x=40,
        size=7.5,
        color="#94a3b8",
        leading=10,
    )

    c.showPage()
    c.save()
    out.seek(0)
    return out
