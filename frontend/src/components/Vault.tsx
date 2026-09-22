import React, { useState, useEffect } from 'react';
import {
  Archive,
  Lock,
  Unlock,
  Download,
  Trash2,
  Search,
  Plus,
  Shield,
  FileText,
  AlertCircle,
  CheckCircle2,
  X,
  KeyRound,
} from 'lucide-react';
import { ApiFn } from './App';

export type VaultItem = {
  id: number;
  original_filename: string;
  encrypted_filename: string;
  file_size: number;
  original_sha256: string;
  algorithm: string;
  kdf: string;
  notes: string;
  created_at: string;
};

export default function Vault({
  token,
  api,
  showToast,
  onNavigateToProtect,
}: {
  token: string;
  api: ApiFn;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
  onNavigateToProtect: () => void;
}) {
  const [items, setItems] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'date' | 'name' | 'size'>('date');
  const [decryptModalItem, setDecryptModalItem] = useState<VaultItem | null>(null);
  const [decryptPassword, setDecryptPassword] = useState('');
  const [decrypting, setDecrypting] = useState(false);
  const [decryptResult, setDecryptResult] = useState<any>(null);
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadNotes, setUploadNotes] = useState('');
  const [uploading, setUploading] = useState(false);

  const loadVault = async () => {
    setLoading(true);
    try {
      const res = await api(`/api/v1/vault?q=${encodeURIComponent(search)}&sort_by=${sortBy}`, token);
      setItems(res || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to load vault items', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadVault();
  }, [search, sortBy]);

  const handleDelete = async (id: number) => {
    if (!window.confirm('Are you sure you want to permanently delete this protected file from the vault?')) return;
    try {
      await api(`/api/v1/vault/${id}`, token, { method: 'DELETE' });
      showToast('File removed from vault.', 'success');
      loadVault();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete vault file', 'error');
    }
  };

  const handleDownloadEncrypted = async (item: VaultItem) => {
    try {
      const apiUrl = (import.meta as any).env?.VITE_API_URL || (import.meta as any).env?.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
      const r = await fetch(`${apiUrl}/api/v1/vault/${item.id}/download`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error('Download failed');
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = item.encrypted_filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast('Encrypted container downloaded.', 'success');
    } catch (err: any) {
      showToast(err.message || 'Download failed', 'error');
    }
  };

  const handleDecrypt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!decryptModalItem || !decryptPassword) return;
    setDecrypting(true);
    try {
      const formData = new FormData();
      formData.append('password', decryptPassword);
      const res = await api(`/api/v1/vault/${decryptModalItem.id}/decrypt`, token, {
        method: 'POST',
        body: formData,
      });
      setDecryptResult(res);
      showToast('File decrypted and verified successfully.', 'success');
    } catch (err: any) {
      showToast(err.message || 'Decryption failed. Check password.', 'error');
    } finally {
      setDecrypting(false);
    }
  };

  const handleDownloadDecrypted = async () => {
    if (!decryptResult) return;
    const apiUrl = (import.meta as any).env?.VITE_API_URL || (import.meta as any).env?.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
    const r = await fetch(apiUrl + decryptResult.download_url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = decryptResult.original_filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const handleUploadSguard = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadFile) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', uploadFile);
      formData.append('notes', uploadNotes);
      await api('/api/v1/vault/upload', token, {
        method: 'POST',
        body: formData,
      });
      showToast('.sguard file imported to Secure Vault.', 'success');
      setUploadModalOpen(false);
      setUploadFile(null);
      setUploadNotes('');
      loadVault();
    } catch (err: any) {
      showToast(err.message || 'Import failed', 'error');
    } finally {
      setUploading(false);
    }
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
    <div className="vault-page">
      <header className="page-header flex-between">
        <div>
          <p className="eyebrow">AES-256-GCM STORAGE</p>
          <h1>Secure Vault</h1>
          <p className="muted">
            Encrypted storage for high-value files. Stored with Argon2id-derived AES-256-GCM ciphertexts.
          </p>
        </div>
        <div className="header-actions">
          <button className="btn btn-outline" onClick={() => setUploadModalOpen(true)}>
            Import .sguard
          </button>
          <button className="btn btn-primary" onClick={onNavigateToProtect}>
            <Plus size={16} /> Protect New File
          </button>
        </div>
      </header>

      {/* Search & Filter Bar */}
      <div className="filter-bar">
        <div className="search-box">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            placeholder="Search protected files..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="sort-controls">
          <span className="muted">Sort by:</span>
          <select value={sortBy} onChange={(e: any) => setSortBy(e.target.value)}>
            <option value="date">Date Protected</option>
            <option value="name">File Name</option>
            <option value="size">File Size</option>
          </select>
        </div>
      </div>

      {/* Vault Items List */}
      {loading ? (
        <div className="dashboard-loading">
          <div className="spinner" />
          <p className="muted">Accessing Secure Vault...</p>
        </div>
      ) : items.length === 0 ? (
        <div className="empty-card">
          <Archive size={40} className="empty-icon" />
          <h3>Your Secure Vault is empty</h3>
          <p className="muted">
            Protect a file with AES-256-GCM encryption to store and organize it safely in your vault.
          </p>
          <button className="btn btn-primary" onClick={onNavigateToProtect}>
            <Lock size={16} /> Protect your first file
          </button>
        </div>
      ) : (
        <div className="vault-grid">
          {items.map((item) => (
            <div key={item.id} className="vault-card">
              <div className="vault-card-head">
                <div className="vault-file-info">
                  <FileText size={20} className="vault-icon" />
                  <div>
                    <strong>{item.original_filename}</strong>
                    <small className="muted block">
                      Encrypted • {(item.file_size / 1024).toFixed(1)} KB • {formatDate(item.created_at)}
                    </small>
                  </div>
                </div>
                <span className="cipher-pill">{item.algorithm}</span>
              </div>

              {item.notes && <p className="vault-notes">{item.notes}</p>}

              <div className="vault-card-actions">
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => {
                    setDecryptModalItem(item);
                    setDecryptPassword('');
                    setDecryptResult(null);
                  }}
                >
                  <Unlock size={14} /> Open
                </button>
                <button
                  className="btn btn-outline btn-sm"
                  onClick={() => handleDownloadEncrypted(item)}
                  title="Download encrypted container"
                >
                  <Download size={14} /> Download
                </button>
                <button
                  className="btn btn-danger-ghost btn-sm"
                  onClick={() => handleDelete(item.id)}
                  title="Delete from vault"
                >
                  <Trash2 size={14} /> Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* In-Vault Decrypt Modal */}
      {decryptModalItem && (
        <div className="modal-backdrop" onClick={() => setDecryptModalItem(null)}>
          <div className="modal-container modal-sm" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="header-title-wrap">
                <p className="eyebrow">VAULT DECRYPTION</p>
                <h3>Decrypt {decryptModalItem.original_filename}</h3>
              </div>
              <button className="iconbtn" onClick={() => setDecryptModalItem(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="modal-body">
              {!decryptResult ? (
                <form onSubmit={handleDecrypt} className="decrypt-form">
                  <p className="muted">
                    Enter the passphrase used when protecting this file to decrypt and verify SHA-256 integrity.
                  </p>
                  <div className="form-group">
                    <label>Passphrase</label>
                    <input
                      type="password"
                      autoFocus
                      required
                      placeholder="Enter encryption passphrase"
                      value={decryptPassword}
                      onChange={(e) => setDecryptPassword(e.target.value)}
                    />
                  </div>
                  <div className="modal-actions">
                    <button type="button" className="btn btn-outline" onClick={() => setDecryptModalItem(null)}>
                      Cancel
                    </button>
                    <button type="submit" className="btn btn-primary" disabled={decrypting || !decryptPassword}>
                      {decrypting ? 'Decrypting...' : 'Decrypt & Verify'}
                    </button>
                  </div>
                </form>
              ) : (
                <div className="decrypt-success-wrap">
                  <CheckCircle2 size={36} className="text-ok" />
                  <h4>Integrity Verified</h4>
                  <p className="muted">
                    AES-256-GCM authentication tag and SHA-256 hash matched original file.
                  </p>
                  <div className="detail-box">
                    <small>Filename:</small>
                    <strong>{decryptResult.original_filename}</strong>
                    <small>Original SHA-256:</small>
                    <code>{decryptResult.original_sha256}</code>
                  </div>
                  <button className="btn btn-primary btn-block" onClick={handleDownloadDecrypted}>
                    <Download size={16} /> Download Restored File
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Import .sguard Modal */}
      {uploadModalOpen && (
        <div className="modal-backdrop" onClick={() => setUploadModalOpen(false)}>
          <div className="modal-container modal-sm" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="header-title-wrap">
                <p className="eyebrow">IMPORT FILE</p>
                <h3>Import .sguard Container</h3>
              </div>
              <button className="iconbtn" onClick={() => setUploadModalOpen(false)}>
                <X size={18} />
              </button>
            </div>
            <form onSubmit={handleUploadSguard} className="modal-body">
              <div className="form-group">
                <label>Select .sguard File</label>
                <input
                  type="file"
                  accept=".sguard"
                  required
                  onChange={(e) => {
                    if (e.target.files?.[0]) setUploadFile(e.target.files[0]);
                  }}
                />
              </div>
              <div className="form-group">
                <label>Notes (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g., Client tax form 2026"
                  value={uploadNotes}
                  onChange={(e) => setUploadNotes(e.target.value)}
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-outline" onClick={() => setUploadModalOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={uploading || !uploadFile}>
                  {uploading ? 'Importing...' : 'Import to Vault'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
