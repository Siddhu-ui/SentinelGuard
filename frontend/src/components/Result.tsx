import React, { useState } from 'react';
import {
  AlertTriangle,
  Copy,
  Download,
  X,
  ChevronDown,
  ChevronUp,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  FileText,
  Binary,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Info,
  Trash2,
} from 'lucide-react';
import { ApiFn, Scan } from './App';

export default function Result({
  scan,
  token,
  api,
  close,
  onQuarantine,
  onDelete,
  onProtect,
  showToast,
}: {
  scan: Scan;
  token: string;
  api: ApiFn;
  close: () => void;
  onQuarantine: () => void;
  onDelete: () => void;
  onProtect: () => void;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
}) {
  const [downloading, setDownloading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [techOpen, setTechOpen] = useState(false);

  const details = scan.details || {};
  const concern = scan.concern_level || details.concern_level || (scan.risk_score <= 20 ? 'Low concern' : scan.risk_score <= 50 ? 'Review recommended' : 'High concern');

  const getConcernBadge = () => {
    if (scan.risk_score <= 20) {
      return <span className="badge badge-low badge-lg">LOW CONCERN</span>;
    }
    if (scan.risk_score <= 50) {
      return <span className="badge badge-review badge-lg">REVIEW RECOMMENDED</span>;
    }
    return <span className="badge badge-high badge-lg">HIGH CONCERN</span>;
  };

  const copyHash = () => {
    navigator.clipboard.writeText(scan.sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const downloadReport = async () => {
    setDownloading(true);
    try {
      const apiUrl = (import.meta as any).env?.VITE_API_URL || (import.meta as any).env?.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
      const r = await fetch(`${apiUrl}/api/v1/scans/${scan.id}/report`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error('Failed to generate PDF report');
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentinelguard-report-${scan.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast('Report downloaded successfully.', 'success');
    } catch (err: any) {
      showToast(err.message || 'Report download failed', 'error');
    } finally {
      setDownloading(false);
    }
  };

  const dna = details.file_dna || {};
  const scoreBreakdown = details.score_breakdown || [];
  const whyPoints: string[] = details.why || [];
  const hexPreview: any[] = details.hex_preview || [];

  return (
    <div className="modal-backdrop" onClick={close}>
      <div className="modal-container" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <div className="header-title-wrap">
            <p className="eyebrow">SECURITY ANALYSIS RESULT</p>
            <h2>{scan.filename}</h2>
          </div>
          <button className="iconbtn" onClick={close} aria-label="Close dialog">
            <X size={20} />
          </button>
        </div>

        <div className="modal-scroll-body">
          {/* A. Overall Assessment Banner */}
          <section className="assessment-banner">
            <div className="assessment-left">
              <div className="concern-tag-wrap">{getConcernBadge()}</div>
              <div className="score-display">
                <span className="score-number">{scan.risk_score}</span>
                <span className="score-total">/ 100</span>
              </div>
            </div>
            <div className="assessment-right">
              <p className="assessment-summary">
                {details.assessment_summary || 'Static pre-analysis complete.'}
              </p>
              <p className="score-disclaimer">
                Risk score is based on detected security indicators. It is not a probability of maliciousness.
              </p>
            </div>
          </section>

          {/* B. Why? Concise Summary */}
          {whyPoints.length > 0 && (
            <section className="result-section why-section">
              <h3>Why this assessment?</h3>
              <ul className="why-list">
                {whyPoints.map((point, i) => (
                  <li key={i}>
                    <CheckCircle2 size={16} className="text-ok" />
                    <span>{point}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* C. Findings & Security Indicators */}
          <section className="result-section">
            <h3>Detected Security Findings ({scan.threats?.length || 0})</h3>
            {scan.threats && scan.threats.length > 0 ? (
              <div className="findings-list">
                {scan.threats.map((threat: any, idx: number) => {
                  const issueDetail = (details.issues || []).find(
                    (i: any) => i.category === threat.category
                  );
                  return (
                    <div key={idx} className={`finding-card finding-${threat.severity}`}>
                      <div className="finding-head">
                        <div className="finding-title">
                          <AlertTriangle size={18} />
                          <strong>{threat.category.toUpperCase()}</strong>
                        </div>
                        <span className={`severity-tag sev-${threat.severity}`}>
                          {threat.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="finding-msg">{threat.message}</p>
                      {issueDetail?.evidence && (
                        <div className="finding-evidence">
                          <small>Evidence:</small>
                          <code>{issueDetail.evidence}</code>
                        </div>
                      )}
                      {issueDetail?.recommendation && (
                        <div className="finding-rec">
                          <small>Recommendation:</small>
                          <span>{issueDetail.recommendation}</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="finding-clean-card">
                <CheckCircle2 size={24} className="text-ok" />
                <div>
                  <strong>No suspicious indicators detected</strong>
                  <p className="muted">
                    No anomalous header mismatches, action hooks, or suspicious structural tokens were identified.
                  </p>
                </div>
              </div>
            )}
          </section>

          {/* D. Risk Score Breakdown */}
          <section className="result-section">
            <h3>Risk Score Breakdown</h3>
            <div className="breakdown-table-wrap">
              <table className="breakdown-table">
                <thead>
                  <tr>
                    <th>Security Indicator</th>
                    <th>Evidence / Finding</th>
                    <th style={{ textAlign: 'right' }}>Score Contribution</th>
                  </tr>
                </thead>
                <tbody>
                  {scoreBreakdown.map((item: any, i: number) => (
                    <tr key={i}>
                      <td>
                        <strong>{item.category}</strong>
                      </td>
                      <td className="muted">{item.evidence}</td>
                      <td style={{ textAlign: 'right' }}>
                        <span className="weight-pill">+{item.weight}</span>
                      </td>
                    </tr>
                  ))}
                  <tr className="total-row">
                    <td>
                      <strong>Total Risk Score</strong>
                    </td>
                    <td></td>
                    <td style={{ textAlign: 'right' }}>
                      <strong>{scan.risk_score} / 100</strong>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* E. File DNA Security Fingerprint */}
          <section className="result-section">
            <h3>File DNA</h3>
            <div className="dna-grid">
              <div className="dna-card">
                <span className="dna-label">File Type</span>
                <strong className="dna-value">{dna.type || scan.mime_type}</strong>
              </div>
              <div className="dna-card">
                <span className="dna-label">File Size</span>
                <strong className="dna-value">{(scan.size / 1024).toFixed(1)} KB</strong>
              </div>
              <div className="dna-card">
                <span className="dna-label">Entropy</span>
                <strong className="dna-value">{scan.entropy} / 8</strong>
              </div>
              <div className="dna-card">
                <span className="dna-label">Structure</span>
                <strong className="dna-value">{dna.structure_status || 'Consistent'}</strong>
              </div>
              <div className="dna-card">
                <span className="dna-label">Metadata</span>
                <strong className="dna-value">{dna.metadata_status || 'No anomaly'}</strong>
              </div>
              <div className="dna-card">
                <span className="dna-label">Embedded Content</span>
                <strong className="dna-value">{dna.embedded_content || 'None detected'}</strong>
              </div>
              <div className="dna-card">
                <span className="dna-label">Steganography</span>
                <strong className="dna-value">{dna.steganography_indicators || 'None detected'}</strong>
              </div>
              <div className="dna-card">
                <span className="dna-label">Polyglot Indicator</span>
                <strong className="dna-value">{dna.polyglot_indicators || 'None detected'}</strong>
              </div>
              <div className="dna-card dna-card-full">
                <span className="dna-label">SHA-256 Digest</span>
                <div className="hash-row">
                  <code>{scan.sha256}</code>
                  <button className="iconbtn" onClick={copyHash} title="Copy SHA-256">
                    <Copy size={14} />
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            </div>
          </section>

          {/* F. Technical Analysis (Collapsed by default) */}
          <section className="result-section">
            <button
              className="tech-toggle-btn"
              onClick={() => setTechOpen(!techOpen)}
            >
              <span>Technical Analysis (Binary Inspector & Signatures)</span>
              {techOpen ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
            </button>

            {techOpen && (
              <div className="tech-details-body">
                {hexPreview.length > 0 && (
                  <div className="hex-inspector-wrap">
                    <h4>Binary Preview (First 256 bytes)</h4>
                    <pre className="hex-box">
                      {hexPreview
                        .map(
                          (row: any) =>
                            `${row.offset}  ${row.hex.padEnd(48, ' ')}  ${row.ascii}`
                        )
                        .join('\n')}
                    </pre>
                  </div>
                )}
                <div className="signatures-inspector">
                  <h4>Detected Byte Signatures</h4>
                  <ul className="sig-list">
                    {(details.signatures || []).map((sig: any, idx: number) => (
                      <li key={idx}>
                        <span>{sig.type} (.{sig.extension})</span>
                        <code>offset: {sig.offset}</code>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </section>
        </div>

        {/* G. Actions After Scan */}
        <div className="modal-footer">
          <div className="action-button-group">
            <button
              className="btn btn-primary"
              onClick={downloadReport}
              disabled={downloading}
            >
              <Download size={16} />
              <span>{downloading ? 'Generating Report...' : 'Generate Report'}</span>
            </button>
            <button className="btn btn-outline" onClick={onProtect}>
              <Lock size={16} />
              <span>Protect File</span>
            </button>
            <button className="btn btn-outline" onClick={onQuarantine}>
              <ShieldAlert size={16} />
              <span>Move to Quarantine</span>
            </button>
            <button className="btn btn-danger-ghost" onClick={onDelete}>
              <Trash2 size={16} />
              <span>Delete</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
