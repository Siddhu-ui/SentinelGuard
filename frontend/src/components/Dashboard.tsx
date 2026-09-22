import React from 'react';
import {
  Shield,
  FileUp,
  Lock,
  Archive,
  AlertTriangle,
  FileText,
  Clock,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Trash2,
  LockKeyhole,
} from 'lucide-react';
import { Scan, Tab } from './App';

export default function Dashboard({
  data,
  onOpenScan,
  onNavigate,
  onDeleteScan,
  onQuarantineScan,
  onProtectFile,
}: {
  data: any;
  onOpenScan: (s: Scan) => void;
  onNavigate: (t: Tab) => void;
  onDeleteScan: (id: number) => Promise<void>;
  onQuarantineScan: (id: number) => Promise<void>;
  onProtectFile: (f?: any) => void;
}) {
  if (!data) {
    return (
      <div className="dashboard-loading">
        <div className="spinner" />
        <p className="muted">Loading File Security Center...</p>
      </div>
    );
  }

  const totalScans = data.total_scans ?? data.total ?? 0;
  const requiringReview = data.files_requiring_review ?? data.threats ?? 0;
  const protectedFiles = data.protected_files ?? 0;
  const reportsGenerated = data.reports_generated ?? totalScans;
  const recentScans: Scan[] = data.recent_scans || data.recent || [];

  const getConcernBadge = (scan: Scan) => {
    const score = scan.risk_score;
    if (score <= 20) {
      return <span className="badge badge-low">LOW CONCERN</span>;
    }
    if (score <= 50) {
      return <span className="badge badge-review">REVIEW</span>;
    }
    return <span className="badge badge-high">HIGH CONCERN</span>;
  };

  const formatDate = (dateStr: string) => {
    try {
      const d = new Date(dateStr);
      const now = new Date();
      if (d.toDateString() === now.toDateString()) {
        return 'Today, ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
      return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="dashboard-view">
      {/* File Security Center Header */}
      <header className="dashboard-header">
        <div className="header-meta">
          <p className="eyebrow">FILE SECURITY CENTER</p>
          <h1>SENTINELGUARD</h1>
          <p className="subtitle">
            Protect your files. Understand suspicious indicators.
          </p>
        </div>
      </header>

      {/* Primary Actions */}
      <section className="primary-actions-grid">
        <button
          className="action-card action-scan"
          onClick={() => onNavigate('scan')}
        >
          <div className="action-icon-wrap">
            <FileUp size={24} />
          </div>
          <div className="action-info">
            <h3>Scan File</h3>
            <p>Static pre-analysis of file structure and metadata</p>
          </div>
          <ArrowRight size={18} className="action-arrow" />
        </button>

        <button
          className="action-card action-protect"
          onClick={() => onNavigate('protect')}
        >
          <div className="action-icon-wrap">
            <Lock size={24} />
          </div>
          <div className="action-info">
            <h3>Protect File</h3>
            <p>AES-256-GCM authenticated file encryption</p>
          </div>
          <ArrowRight size={18} className="action-arrow" />
        </button>

        <button
          className="action-card action-vault"
          onClick={() => onNavigate('vault')}
        >
          <div className="action-icon-wrap">
            <Archive size={24} />
          </div>
          <div className="action-info">
            <h3>Open Vault</h3>
            <p>Manage encrypted files and securely decrypt</p>
          </div>
          <ArrowRight size={18} className="action-arrow" />
        </button>
      </section>

      {/* Security Overview Metrics */}
      <section className="metrics-section">
        <div className="section-title">
          <h2>Security Overview</h2>
        </div>
        <div className="metrics-grid">
          <div className="metric-card">
            <span className="metric-label">Files Scanned</span>
            <strong className="metric-val">{totalScans}</strong>
            <small className="metric-sub">Total files analyzed</small>
          </div>

          <div className={`metric-card ${requiringReview > 0 ? 'metric-alert' : ''}`}>
            <span className="metric-label">Files Requiring Review</span>
            <strong className="metric-val">{requiringReview}</strong>
            <small className="metric-sub">Indicators requiring attention</small>
          </div>

          <div className="metric-card">
            <span className="metric-label">Protected Files</span>
            <strong className="metric-val">{protectedFiles}</strong>
            <small className="metric-sub">Stored in Secure Vault</small>
          </div>

          <div className="metric-card">
            <span className="metric-label">Reports Generated</span>
            <strong className="metric-val">{reportsGenerated}</strong>
            <small className="metric-sub">Verified security reports</small>
          </div>
        </div>
      </section>

      {/* Recent Activity */}
      <section className="activity-section">
        <div className="section-header-flex">
          <h2>Recent Activity</h2>
          {recentScans.length > 0 && (
            <button className="link-btn" onClick={() => onNavigate('history')}>
              View all history <ArrowRight size={14} />
            </button>
          )}
        </div>

        {recentScans.length === 0 ? (
          <div className="empty-card">
            <ShieldCheck size={40} className="empty-icon" />
            <h3>No files scanned yet</h3>
            <p className="muted">
              Upload a file to begin your first static security analysis.
            </p>
            <button className="btn btn-primary" onClick={() => onNavigate('scan')}>
              <FileUp size={16} /> Scan your first file
            </button>
          </div>
        ) : (
          <div className="activity-table-wrapper">
            <table className="sg-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Risk / Concern Level</th>
                  <th>Date</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <div className="file-cell">
                        <FileText size={18} className="file-icon" />
                        <div>
                          <strong>{scan.filename}</strong>
                          <small className="muted block">
                            {(scan.size / 1024).toFixed(1)} KB • {scan.mime_type}
                          </small>
                        </div>
                      </div>
                    </td>
                    <td>
                      <div className="concern-cell">
                        {getConcernBadge(scan)}
                        <span className="score-hint">({scan.risk_score}/100)</span>
                      </div>
                    </td>
                    <td>
                      <span className="muted">{formatDate(scan.created_at)}</span>
                    </td>
                    <td>
                      <div className="table-actions">
                        <button
                          className="btn-sm btn-outline"
                          onClick={() => onOpenScan(scan)}
                        >
                          View
                        </button>
                        <button
                          className="btn-sm btn-ghost"
                          title="Quarantine"
                          onClick={() => onQuarantineScan(scan.id)}
                        >
                          <ShieldAlert size={14} />
                        </button>
                        <button
                          className="btn-sm btn-danger-ghost"
                          title="Delete"
                          onClick={() => onDeleteScan(scan.id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
