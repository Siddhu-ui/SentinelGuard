import React, { useState, useEffect } from 'react';
import {
  AlertOctagon,
  ShieldAlert,
  RotateCcw,
  Trash2,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Info,
} from 'lucide-react';
import { ApiFn, Scan } from './App';

export type QuarantineItem = {
  id: number;
  scan_id: number;
  original_filename: string;
  reason: string;
  risk_score: number;
  risk_level: string;
  concern_level: string;
  findings_count: number;
  status: string;
  created_at: string;
};

export default function Quarantine({
  token,
  api,
  onOpenScan,
  onRefresh,
  showToast,
}: {
  token: string;
  api: ApiFn;
  onOpenScan: (s: Scan) => void;
  onRefresh: () => void;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
}) {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [loading, setLoading] = useState(true);

  const loadQuarantine = async () => {
    setLoading(true);
    try {
      const res = await api('/api/v1/quarantine', token);
      setItems(res || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to load quarantine list', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadQuarantine();
  }, []);

  const handleRestore = async (scanId: number) => {
    try {
      await api(`/api/v1/quarantine/${scanId}/restore`, token, { method: 'POST' });
      showToast('File restored from quarantine.', 'success');
      loadQuarantine();
      onRefresh();
    } catch (err: any) {
      showToast(err.message || 'Failed to restore file', 'error');
    }
  };

  const handleDeletePermanent = async (scanId: number) => {
    if (!window.confirm('Permanently delete this quarantined file and its scan record?')) return;
    try {
      await api(`/api/v1/quarantine/${scanId}`, token, { method: 'DELETE' });
      showToast('Quarantined file deleted permanently.', 'success');
      loadQuarantine();
      onRefresh();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete file', 'error');
    }
  };

  const handleViewFindings = async (scanId: number) => {
    try {
      const scan = await api(`/api/v1/scans/${scanId}`, token);
      onOpenScan(scan);
    } catch (err: any) {
      showToast(err.message || 'Failed to fetch scan details', 'error');
    }
  };

  return (
    <div className="quarantine-page">
      <header className="page-header">
        <p className="eyebrow">ISOLATED FILES</p>
        <h1>Quarantine Area</h1>
        <p className="muted">
          Suspicious files isolated from normal operations. Quarantined files cannot be downloaded or opened without explicit restore.
        </p>
      </header>

      <div className="notice-banner">
        <Info size={18} className="text-accent" />
        <span>
          Quarantine keeps high-concern files isolated. SentinelGuard does not execute files or act as a destructive antivirus sandbox.
        </span>
      </div>

      {loading ? (
        <div className="dashboard-loading">
          <div className="spinner" />
          <p className="muted">Loading quarantined items...</p>
        </div>
      ) : items.length === 0 ? (
        <div className="empty-card">
          <CheckCircle2 size={40} className="empty-icon text-ok" />
          <h3>No files in quarantine</h3>
          <p className="muted">Files flagged with high concern can be moved here to prevent accidental sharing.</p>
        </div>
      ) : (
        <div className="quarantine-list">
          {items.map((item) => (
            <div key={item.id} className="quarantine-card">
              <div className="quarantine-card-head">
                <div className="quarantine-info">
                  <ShieldAlert size={22} className="text-danger" />
                  <div>
                    <strong>{item.original_filename}</strong>
                    <p className="muted">Reason: {item.reason}</p>
                  </div>
                </div>
                <div className="quarantine-meta">
                  <span className="badge badge-high">{item.concern_level.toUpperCase()}</span>
                  <span className="score-hint">Risk: {item.risk_score}/100</span>
                </div>
              </div>

              <div className="quarantine-footer">
                <small className="muted">
                  Scan ID: #{item.scan_id} • Findings: {item.findings_count}
                </small>
                <div className="quarantine-actions">
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={() => handleViewFindings(item.scan_id)}
                  >
                    <FileText size={14} /> View Findings
                  </button>
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={() => handleRestore(item.scan_id)}
                  >
                    <RotateCcw size={14} /> Restore
                  </button>
                  <button
                    className="btn btn-danger-ghost btn-sm"
                    onClick={() => handleDeletePermanent(item.scan_id)}
                  >
                    <Trash2 size={14} /> Delete Permanently
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
