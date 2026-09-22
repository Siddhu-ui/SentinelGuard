import React, { useState, useEffect } from 'react';
import {
  Lock,
  Shield,
  Download,
  CheckCircle2,
  FileUp,
  Archive,
  Info,
  Key,
} from 'lucide-react';
import { ApiFn } from './App';

export default function Encrypt({
  token,
  api,
  prefillFile,
  onComplete,
  onViewVault,
  showToast,
}: {
  token: string;
  api: ApiFn;
  prefillFile?: File | null;
  onComplete?: () => void;
  onViewVault: () => void;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
}) {
  const [file, setFile] = useState<File | null>(prefillFile || null);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [saveToVault, setSaveToVault] = useState(true);
  const [notes, setNotes] = useState('');
  const [encrypting, setEncrypting] = useState(false);
  const [result, setResult] = useState<any>(null);

  useEffect(() => {
    if (prefillFile) setFile(prefillFile);
  }, [prefillFile]);

  const handleEncrypt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      showToast('Please select a file to protect', 'error');
      return;
    }
    if (password.length < 8) {
      showToast('Password must be at least 8 characters', 'error');
      return;
    }
    if (password !== confirmPassword) {
      showToast('Passwords do not match', 'error');
      return;
    }

    setEncrypting(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('password', password);
      formData.append('save_to_vault', saveToVault ? 'true' : 'false');
      formData.append('notes', notes);

      const res = await api('/api/v1/files/protect', token, {
        method: 'POST',
        body: formData,
      });

      setResult(res);
      showToast('File protected with AES-256-GCM successfully.', 'success');
      if (onComplete) onComplete();
    } catch (err: any) {
      showToast(err.message || 'Encryption failed', 'error');
    } finally {
      setEncrypting(false);
    }
  };

  const handleDownload = async () => {
    if (!result) return;
    const apiUrl = (import.meta as any).env?.VITE_API_URL || (import.meta as any).env?.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
    const r = await fetch(apiUrl + result.download_url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = result.encrypted_filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="protect-page">
      <header className="page-header">
        <p className="eyebrow">CRYPTOGRAPHIC SECURITY</p>
        <h1>Protect File</h1>
        <p className="muted">
          Encrypt files with AES-256-GCM and Argon2id key derivation into self-authenticating .sguard packages.
        </p>
      </header>

      <div className="protect-layout">
        {!result ? (
          <form onSubmit={handleEncrypt} className="protect-form-card">
            {/* Step 1: Select File */}
            <div className="form-step">
              <span className="step-badge">1</span>
              <div className="step-content">
                <h3>Select File</h3>
                <div className="file-picker-wrap">
                  <input
                    type="file"
                    id="protect-file-input"
                    className="hidden-file-input"
                    onChange={(e) => {
                      if (e.target.files?.[0]) setFile(e.target.files[0]);
                    }}
                  />
                  <label htmlFor="protect-file-input" className="file-picker-box">
                    <FileUp size={24} className="picker-icon" />
                    {file ? (
                      <div>
                        <strong>{file.name}</strong>
                        <small className="muted block">{(file.size / 1024).toFixed(1)} KB</small>
                      </div>
                    ) : (
                      <div>
                        <span>Click to choose a file</span>
                        <small className="muted block">Any file format up to 100 MB</small>
                      </div>
                    )}
                  </label>
                </div>
              </div>
            </div>

            {/* Step 2: Set Passphrase */}
            <div className="form-step">
              <span className="step-badge">2</span>
              <div className="step-content">
                <h3>Set Encryption Passphrase</h3>
                <div className="form-group">
                  <label>Passphrase (min 8 characters)</label>
                  <input
                    type="password"
                    required
                    placeholder="Enter strong passphrase"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label>Confirm Passphrase</label>
                  <input
                    type="password"
                    required
                    placeholder="Repeat passphrase"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                </div>
              </div>
            </div>

            {/* Step 3: Vault Storage Options */}
            <div className="form-step">
              <span className="step-badge">3</span>
              <div className="step-content">
                <h3>Storage & Vault Options</h3>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={saveToVault}
                    onChange={(e) => setSaveToVault(e.target.checked)}
                  />
                  <span>Save encrypted file to my Secure Vault</span>
                </label>

                {saveToVault && (
                  <div className="form-group mt-2">
                    <label>Vault Note (Optional)</label>
                    <input
                      type="text"
                      placeholder="e.g. Confidential tax documents"
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                    />
                  </div>
                )}
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-primary btn-lg btn-block"
              disabled={encrypting || !file || !password}
            >
              <Lock size={18} />
              <span>{encrypting ? 'Encrypting with AES-256-GCM...' : 'Encrypt & Protect File'}</span>
            </button>
          </form>
        ) : (
          <div className="protect-success-card">
            <CheckCircle2 size={48} className="text-ok" />
            <h2>File Protected Successfully</h2>
            <p className="muted">
              The file is encrypted with AES-256-GCM. An authenticated .sguard package has been created.
            </p>

            <div className="detail-box">
              <div className="detail-row">
                <span className="muted">Original:</span>
                <strong>{result.original_filename}</strong>
              </div>
              <div className="detail-row">
                <span className="muted">Protected Package:</span>
                <code>{result.encrypted_filename}</code>
              </div>
              <div className="detail-row">
                <span className="muted">SHA-256 Hash:</span>
                <code>{result.original_sha256}</code>
              </div>
              <div className="detail-row">
                <span className="muted">Cipher:</span>
                <span>{result.algorithm} ({result.kdf})</span>
              </div>
            </div>

            <div className="success-actions">
              <button className="btn btn-primary" onClick={handleDownload}>
                <Download size={16} /> Download .sguard Package
              </button>
              {result.vault_file_id && (
                <button className="btn btn-outline" onClick={onViewVault}>
                  <Archive size={16} /> View in Secure Vault
                </button>
              )}
              <button
                className="btn btn-ghost"
                onClick={() => {
                  setResult(null);
                  setFile(null);
                  setPassword('');
                  setConfirmPassword('');
                }}
              >
                Protect Another File
              </button>
            </div>
          </div>
        )}

        {/* Informational Sidebar */}
        <aside className="protect-info-aside">
          <div className="info-card">
            <div className="info-card-head">
              <Shield size={18} className="text-accent" />
              <strong>Cryptographic Disclaimer</strong>
            </div>
            <p className="muted">
              Encryption protects the confidentiality and integrity of the encrypted file. It does not make an unsafe file safe.
            </p>
          </div>

          <div className="info-card">
            <div className="info-card-head">
              <Key size={18} className="text-accent" />
              <strong>Zero-Knowledge Password</strong>
            </div>
            <p className="muted">
              SentinelGuard never stores your encryption passwords. If you lose your passphrase, the ciphertext cannot be recovered.
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}
