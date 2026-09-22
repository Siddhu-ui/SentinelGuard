import React, { useState, useEffect } from 'react';
import {
  History as HistoryIcon,
  Search,
  Trash2,
  Eye,
  Download,
  Lock,
  ShieldAlert,
  FileText,
  ArrowUpDown,
  Filter,
} from 'lucide-react';
import { ApiFn, Scan } from './App';

export default function HistoryPage({
  token,
  api,
  onOpenScan,
  onDeleteScan,
  onQuarantineScan,
  onProtectFile,
  showToast,
}: {
  token: string;
  api: ApiFn;
  onOpenScan: (s: Scan) => void;
  onDeleteScan: (id: number) => Promise<void>;
  onQuarantineScan: (id: number) => Promise<void>;
  onProtectFile: (f?: any) => void;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
}) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [concernFilter, setConcernFilter] = useState<'all' | 'low' | 'review' | 'high'>('all');

  const loadHistory = async () => {
    setLoading(true);
    try {
      const concernParam = concernFilter === 'all' ? '' : concernFilter;
      const res = await api(`/api/v1/scans?q=${encodeURIComponent(search)}&concern=${concernParam}`, token);
      setScans(res || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to load scan history', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, [search, concernFilter]);

  const handleClearAll = async () => {
    if (!window.confirm('Clear all your scan history? This action cannot be undone.')) return;
    try {
      await api('/api/v1/scans', token, { method: 'DELETE' });
      showToast('All scan history cleared.', 'success');
      loadHistory();
    } catch (err: any) {
      showToast(err.message || 'Failed to clear history', 'error');
    }
  };

  const getConcernBadge = (score: number) => {
    if (score <= 20) return <span className="badge badge-low">LOW CONCERN</span>;
    if (score <= 50) return <span className="badge badge-review">REVIEW</span>;
    return <span className="badge badge-high">HIGH CONCERN</span>;
  };

  const formatDate = (dateStr: string) => {
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="history-page">
      <header className="page-header flex-between">
        <div>
          <p className="eyebrow">AUDIT RECORD</p>
          <h1>Scan History</h1>
          <p className="muted">Deterministic records of previous file analyses and findings.</p>
        </div>
        {scans.length > 0 && (
          <button className="btn btn-danger-ghost" onClick={handleClearAll}>
            <Trash2 size={16} /> Clear All History
          </button>
        )}
      </header>

      {/* Filter and Search Bar */}
      <div className="filter-bar">
        <div className="search-box">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            placeholder="Search scans by filename..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="filter-pills">
          <button
            className={`pill ${concernFilter === 'all' ? 'active' : ''}`}
            onClick={() => setConcernFilter('all')}
          >
            All
          </button>
          <button
            className={`pill ${concernFilter === 'low' ? 'active' : ''}`}
            onClick={() => setConcernFilter('low')}
          >
            Low Concern
          </button>
          <button
            className={`pill ${concernFilter === 'review' ? 'active' : ''}`}
            onClick={() => setConcernFilter('review')}
          >
            Review Recommended
          </button>
          <button
            className={`pill ${concernFilter === 'high' ? 'active' : ''}`}
            onClick={() => setConcernFilter('high')}
          >
            High Concern
          </button>
        </div>
      </div>

      {loading ? (
        <div className="dashboard-loading">
          <div className="spinner" />
          <p className="muted">Fetching scan records...</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="empty-card">
          <HistoryIcon size={40} className="empty-icon" />
          <h3>No scan history matches your filter</h3>
          <p className="muted">Try adjusting your search criteria or scan a new file.</p>
        </div>
      ) : (
        <div className="history-table-wrap">
          <table className="sg-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Risk / Concern</th>
                <th>Score</th>
                <th>Findings</th>
                <th>Date</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
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
                  <td>{getConcernBadge(scan.risk_score)}</td>
                  <td>
                    <strong>{scan.risk_score}</strong> / 100
                  </td>
                  <td>
                    <span className="muted">{scan.threats?.length || 0} indicator(s)</span>
                  </td>
                  <td>
                    <span className="muted">{formatDate(scan.created_at)}</span>
                  </td>
                  <td>
                    <div className="table-actions">
                      <button className="btn-sm btn-outline" onClick={() => onOpenScan(scan)}>
                        <Eye size={14} /> View
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
    </div>
  );
}
