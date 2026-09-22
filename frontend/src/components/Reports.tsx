import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Search,
  Eye,
  CheckCircle2,
  Shield,
  Clock,
  ArrowRight,
} from 'lucide-react';
import { ApiFn, Scan } from './App';

export default function Reports({
  token,
  api,
  onOpenScan,
  showToast,
}: {
  token: string;
  api: ApiFn;
  onOpenScan: (s: Scan) => void;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
}) {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [downloadingId, setDownloadingId] = useState<number | null>(null);

  const loadReports = async () => {
    setLoading(true);
    try {
      const res = await api(`/api/v1/reports?q=${encodeURIComponent(search)}`, token);
      setReports(res || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to load reports', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, [search]);

  const downloadReport = async (scanId: number, filename: string) => {
    setDownloadingId(scanId);
    try {
      const apiUrl = (import.meta as any).env?.VITE_API_URL || (import.meta as any).env?.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
      const r = await fetch(`${apiUrl}/api/v1/scans/${scanId}/report`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error('Download report failed');
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentinelguard-report-${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast(`Report for ${filename} downloaded.`, 'success');
    } catch (err: any) {
      showToast(err.message || 'Download failed', 'error');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleOpenFullScan = async (scanId: number) => {
    try {
      const scan = await api(`/api/v1/scans/${scanId}`, token);
      onOpenScan(scan);
    } catch (err: any) {
      showToast(err.message || 'Failed to open scan details', 'error');
    }
  };

  const getConcernBadge = (score: number) => {
    if (score <= 20) return <span className="badge badge-low">LOW CONCERN</span>;
    if (score <= 50) return <span className="badge badge-review">REVIEW</span>;
    return <span className="badge badge-high">HIGH CONCERN</span>;
  };

  return (
    <div className="reports-page">
      <header className="page-header">
        <p className="eyebrow">VERIFIED DOCUMENTATION</p>
        <h1>Security Reports</h1>
        <p className="muted">
          Formal PDF reports summarizing file information, risk indicators, score breakdown, and recommendations.
        </p>
      </header>

      <div className="filter-bar">
        <div className="search-box">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            placeholder="Search reports by filename..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {loading ? (
        <div className="dashboard-loading">
          <div className="spinner" />
          <p className="muted">Compiling reports...</p>
        </div>
      ) : reports.length === 0 ? (
        <div className="empty-card">
          <FileText size={40} className="empty-icon" />
          <h3>No reports available</h3>
          <p className="muted">Reports will appear here after you complete a file scan.</p>
        </div>
      ) : (
        <div className="reports-table-wrap">
          <table className="sg-table">
            <thead>
              <tr>
                <th>Document / Scan</th>
                <th>Assessment</th>
                <th>Findings</th>
                <th>Generated</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((rep) => (
                <tr key={rep.id}>
                  <td>
                    <div className="file-cell">
                      <FileText size={18} className="file-icon" />
                      <div>
                        <strong>{rep.filename}</strong>
                        <small className="muted block">
                          Report ID: SG-{String(rep.id).padStart(6, '0')} • {(rep.size / 1024).toFixed(1)} KB
                        </small>
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="concern-cell">
                      {getConcernBadge(rep.risk_score)}
                      <span className="score-hint">({rep.risk_score}/100)</span>
                    </div>
                  </td>
                  <td>
                    <span className="muted">{rep.finding_count} indicator(s)</span>
                  </td>
                  <td>
                    <span className="muted">
                      {new Date(rep.created_at).toLocaleDateString([], {
                        month: 'short',
                        day: 'numeric',
                        year: 'numeric',
                      })}
                    </span>
                  </td>
                  <td>
                    <div className="table-actions">
                      <button
                        className="btn-sm btn-outline"
                        onClick={() => handleOpenFullScan(rep.id)}
                      >
                        <Eye size={14} /> View
                      </button>
                      <button
                        className="btn-sm btn-primary"
                        onClick={() => downloadReport(rep.id, rep.filename)}
                        disabled={downloadingId === rep.id}
                      >
                        <Download size={14} />
                        {downloadingId === rep.id ? 'Generating...' : 'PDF'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
