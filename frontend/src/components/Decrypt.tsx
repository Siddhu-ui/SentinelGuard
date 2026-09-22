import React, { useState } from 'react';
import {
  Unlock,
  Download,
  FileUp,
  CheckCircle2,
  AlertCircle,
  Shield,
  KeyRound,
} from 'lucide-react';
import { ApiFn } from './App';

export default function Decrypt({
  token,
  api,
  showToast,
}: {
  token: string;
  api: ApiFn;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [decrypting, setDecrypting] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleDecrypt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      showToast('Please select a .sguard file to decrypt', 'error');
      return;
    }
    if (!password) {
      showToast('Passphrase is required', 'error');
      return;
    }

    setDecrypting(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('password', password);

      const res = await api('/decrypt', token, {
        method: 'POST',
        body: formData,
      });

      setResult(res);
      showToast('File decrypted and verified successfully.', 'success');
    } catch (err: any) {
      showToast(err.message || 'Decryption failed. Please check the passphrase.', 'error');
    } finally {
      setDecrypting(false);
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
    a.download = result.original_filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="decrypt-page">
      <header className="page-header">
        <p className="eyebrow">INTEGRITY VERIFICATION</p>
        <h1>Decrypt .sguard File</h1>
        <p className="muted">
          Decrypt protected .sguard packages, verify GCM authentication tags, and restore original files.
        </p>
      </header>

      <div className="decrypt-layout">
        {!result ? (
          <form onSubmit={handleDecrypt} className="decrypt-card">
            <div className="form-group">
              <label>Select .sguard Container</label>
              <div className="file-picker-wrap">
                <input
                  type="file"
                  id="decrypt-file-input"
                  accept=".sguard"
                  className="hidden-file-input"
                  onChange={(e) => {
                    if (e.target.files?.[0]) setFile(e.target.files[0]);
                  }}
                />
                <label htmlFor="decrypt-file-input" className="file-picker-box">
                  <FileUp size={24} className="picker-icon" />
                  {file ? (
                    <div>
                      <strong>{file.name}</strong>
                      <small className="muted block">{(file.size / 1024).toFixed(1)} KB</small>
                    </div>
                  ) : (
                    <div>
                      <span>Click to select .sguard file</span>
                      <small className="muted block">Only .sguard containers supported</small>
                    </div>
                  )}
                </label>
              </div>
            </div>

            <div className="form-group">
              <label>Passphrase</label>
              <input
                type="password"
                required
                placeholder="Enter decryption passphrase"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary btn-lg btn-block"
              disabled={decrypting || !file || !password}
            >
              <Unlock size={18} />
              <span>{decrypting ? 'Decrypting & Verifying...' : 'Decrypt File'}</span>
            </button>
          </form>
        ) : (
          <div className="decrypt-success-card">
            <CheckCircle2 size={48} className="text-ok" />
            <h2>Decryption & Integrity Verified</h2>
            <p className="muted">
              GCM tag and SHA-256 integrity checks passed. The original file has been restored.
            </p>

            <div className="detail-box">
              <div className="detail-row">
                <span className="muted">Restored File:</span>
                <strong>{result.original_filename}</strong>
              </div>
              <div className="detail-row">
                <span className="muted">File Size:</span>
                <span>{(result.file_size / 1024).toFixed(1)} KB</span>
              </div>
              <div className="detail-row">
                <span className="muted">Original SHA-256:</span>
                <code>{result.original_sha256}</code>
              </div>
              <div className="detail-row">
                <span className="muted">Status:</span>
                <span className="badge badge-low">VERIFIED</span>
              </div>
            </div>

            <div className="success-actions">
              <button className="btn btn-primary" onClick={handleDownload}>
                <Download size={16} /> Download Restored File
              </button>
              <button
                className="btn btn-ghost"
                onClick={() => {
                  setResult(null);
                  setFile(null);
                  setPassword('');
                }}
              >
                Decrypt Another File
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
