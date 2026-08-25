import React, { useState, useRef, useEffect } from 'react';
import { Lock, FileUp, Download, CheckCircle2, AlertTriangle, Eye, EyeOff, Copy, ShieldCheck } from 'lucide-react';

interface EncryptResult {
  id: number;
  original_filename: string;
  encrypted_filename: string;
  original_sha256: string;
  algorithm: string;
  kdf: string;
  file_size: number;
  download_url: string;
}

interface Props {
  token: string;
  api: (p: string, t: string, o?: RequestInit) => Promise<any>;
}

export default function Encrypt({ token, api }: Props) {
  const [file, setFile] = useState<File>();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<EncryptResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Reset when file changes
  useEffect(() => { setResult(null); setError(''); }, [file]);

  const errors: string[] = [];
  if (password && password.length < 10) errors.push('Password must be at least 10 characters');
  if (confirm && password !== confirm) errors.push('Passwords do not match');
  const valid = !!file && password.length >= 10 && password === confirm;

  const handleEncrypt = async () => {
    if (!file || !valid) return;
    setBusy(true);
    setError('');
    try {
      const form = new FormData();
      form.append('file', file);
      form.append('password', password);
      const res = await api('/encrypt', token, { method: 'POST', body: form });
      setResult(res);
    } catch (e: any) {
      setError(e.message || 'Encryption failed. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = async () => {
    if (!result) return;
    try {
      const r = await fetch((import.meta.env.VITE_API_URL || 'http://localhost:8000') + result.download_url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error('Download failed');
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = result.encrypted_filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e: any) {
      setError(e.message || 'Download failed. Please try again.');
    }
  };

  const handleReset = () => {
    setFile(undefined);
    setPassword('');
    setConfirm('');
    setResult(null);
    setError('');
    if (inputRef.current) inputRef.current.value = '';
  };

  // ── Success state ──────────────────────────────────────────────────
  if (result) {
    return (
      <div className="encrypt-success">
        <header>
          <p className="eyebrow">ENCRYPTION COMPLETE</p>
          <h1>✓ Encryption Successful</h1>
        </header>
        <div className="encrypt-result-card">
          <div className="result-row"><b>File</b><span>{result.original_filename}</span></div>
          <div className="result-row"><b>Encrypted format</b><span>.sguard</span></div>
          <div className="result-row"><b>Algorithm</b><span>{result.algorithm}</span></div>
          <div className="result-row"><b>Key derivation</b><span>{result.kdf}</span></div>
          <div className="result-row"><b>File size</b><span>{(result.file_size / 1024).toFixed(1)} KB</span></div>
          <div className="result-row">
            <b>Original SHA-256</b>
            <span className="sha-hash">
              <code>{result.original_sha256}</code>
              <button className="iconbtn" onClick={() => navigator.clipboard.writeText(result.original_sha256)}>
                <Copy size={13} /> Copy
              </button>
            </span>
          </div>
          <div className="result-actions">
            <button className="primary" onClick={handleDownload}>
              <Download size={16} /> Download Encrypted File
            </button>
            <button className="ghost-btn" onClick={handleReset}>Encrypt another file</button>
          </div>
        </div>
      </div>
    );
  }

  // ── Upload / encrypt form ──────────────────────────────────────────
  return (
    <>
      <header>
        <p className="eyebrow">ENCRYPT FILE</p>
        <h1>Encrypt a file</h1>
        <p className="muted">Files are encrypted with AES-256-GCM. Only you hold the password.</p>
      </header>

      {error && <div className="error"><AlertTriangle size={14} /> {error}</div>}

      <div className="encrypt-form">
        {/* File selector */}
        <div className="enc-drop" onClick={() => inputRef.current?.click()}>
          <input
            ref={inputRef}
            type="file"
            className="file-input"
            onChange={e => setFile(e.target.files?.[0])}
          />
          {file ? (
            <div className="enc-file-info">
              <FileUp size={28} />
              <div>
                <strong>{file.name}</strong>
                <small>{(file.size / 1024).toFixed(1)} KB</small>
              </div>
            </div>
          ) : (
            <div className="enc-file-info">
              <FileUp size={28} />
              <div>
                <strong>Choose a file to encrypt</strong>
                <small>Any file type · up to 100 MB</small>
              </div>
            </div>
          )}
        </div>

        {/* Password */}
        <div className="pw-field">
          <input
            type={showPw ? 'text' : 'password'}
            placeholder="Encryption password (10+ characters)"
            value={password}
            onChange={e => setPassword(e.target.value)}
            minLength={10}
          />
          <button type="button" className="pw-toggle" onClick={() => setShowPw(!showPw)}>
            {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>

        {/* Confirm password */}
        <div className="pw-field">
          <input
            type={showPw ? 'text' : 'password'}
            placeholder="Confirm password"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
          />
        </div>

        {/* Validation messages */}
        {errors.length > 0 && (
          <div className="enc-errors">
            {errors.map((e, i) => <p key={i}><AlertTriangle size={13} /> {e}</p>)}
          </div>
        )}

        {/* Encrypt button */}
        <button
          className="primary"
          disabled={!valid || busy}
          onClick={handleEncrypt}
        >
          <Lock size={16} />
          {busy ? 'Encrypting…' : 'Encrypt file'}
        </button>

        <p className="muted" style={{ fontSize: 12, textAlign: 'center', marginTop: 12 }}>
          <ShieldCheck size={13} style={{ verticalAlign: -2, marginRight: 4 }} />
          Password is never stored. Lost passwords cannot be recovered.
        </p>
      </div>
    </>
  );
}
