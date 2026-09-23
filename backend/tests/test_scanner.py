from pathlib import Path
from scanner.analyzers import analyze, embedded_pe

def test_pdf_prose_mz_is_not_embedded_executable(tmp_path: Path):
    p = tmp_path / "sample.pdf"
    p.write_bytes(b"%PDF-1.7\nThis document mentions Windows executable, MZ and PE but contains no binary.\n%%EOF")
    result = analyze(p, "pdf")
    assert not any(i["category"] == "embedded-executable" for i in result["issues"])

def test_invalid_pe_is_ignored():
    assert embedded_pe(b"%PDF-1.7\nMZ ordinary text PE\\0\\0") == []

def test_score_is_sum_of_explainable_weights(tmp_path: Path):
    p = tmp_path / "sample.pdf"
    p.write_bytes(b"%PDF-1.7\n/JavaScript\n%%EOF")
    result = analyze(p, "pdf")
    assert result["risk_score"] == min(100, sum(i["weight"] for i in result["issues"]))
    assert all(i["evidence"] for i in result["issues"])

def test_result_contains_bounded_explainable_analysis(tmp_path: Path):
    p = tmp_path / "sample.pdf"
    p.write_bytes(b"%PDF-1.7\n" + b"A" * 300 + b"\n%%EOF")
    result = analyze(p, "pdf")
    assert result["finding_count"] == len(result["issues"])
    assert result["file_dna"]["size"] == p.stat().st_size
    assert len(result["hex_preview"]) <= 16
    assert {"name", "score", "findings", "severity"}.issubset(result["analysis_sections"][0])
