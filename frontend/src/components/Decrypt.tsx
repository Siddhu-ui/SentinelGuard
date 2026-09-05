import React, { useState, useRef, useEffect } from 'react';
import { Lock, FileUp, Download, CheckCircle2, AlertTriangle, Eye, EyeOff, Copy, ShieldCheck } from 'lucide-react';

interface DecryptResult {
  id: number;
  original_filename: string;
  original_sha256: string;
  algorithm: string;
  kdf: string;
  file_size: number;
  integrity: string;
  download_url: string;
}

interface Props {
  token: string;
  api: (p: string, t: string, o?: RequestInit) => Promise<any>;
}

export default function Decrypt({ token, api }: Props) {
  const [file, setFile] = useState<File>();
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<DecryptResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { setResult(null); setError(''); }, [file]);

  const valid = !!file && file.name.endsWith('.sguard') && password.length > 0;

  const handleDecrypt = async () => {
    if (!file || !valid) return;
    setBusy(true);
    setError('');
    try {
      const form = new FormData();
      form.append('file', file);
      form.append('password', password);
      const res = await api('/decrypt', token, { method: 'POST', body: form });
      setResult(res);
    } catch (e: any) {
      setError(e.message || 'Decryption failed. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = async () => {
    if (!result) return;
    try {
      const r = await fetch((import.meta.env.VITE_API_URL || 'http://127.0.0.1:8001') + result.download_url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error('Download failed');
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = result.original_filename;
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
    setResult(null);
    setError('');
    if (inputRef.current) inputRef.current.value = '';
  };

  // ── Success state ──────────────────────────────────────────────────
  if (result) {
    return (
      <div className="encrypt-success">
        <header>
          <p className="eyebrow">DECRYPTION COMPLETE</p>
          <h1>✓ Decryption Successful</h1>
        </header>
        <div className="encrypt-result-card">
          <div className="result-row"><b>Original file</b><span>{result.original_filename}</span></div>
          <div className="result-row"><b>Algorithm</b><span>{result.algorithm}</span></div>
          <div className="result-row"><b>Key derivation</b><span>{result.kdf}</span></div>
          <div className="result-row"><b>Integrity</b><span className="integrity-ok">{result.integrity}</span></div>
          <div className="result-row"><b>File size</b><span>{(result.file_size / 1024).toFixed(1)} KB</span></div>
          <div className="result-row">
            <b>SHA-256</b>
            <span className="sha-hash">
              <code>{result.original_sha256}</code>
              <button className="iconbtn" onClick={() => navigator.clipboard.writeText(result.original_sha256)}>
                <Copy size={13} /> Copy
              </button>
            </span>
          </div>
          <div className="result-actions">
            <button className="primary" onClick={handleDownload}>
              <Download size={16} /> Download Original File
            </button>
            <button className="ghost-btn" onClick={handleReset}>Decrypt another file</button>
          </div>
        </div>
      </div>
    );
  }

  // ── Upload / decrypt form ──────────────────────────────────────────
  return (
    <>
      <header>
        <p className="eyebrow">DECRYPT FILE</p>
        <h1>Decrypt a file</h1>
        <p className="muted">Upload a .sguard file and enter the password used during encryption.</p>
      </header>

      {error && <div className="error"><AlertTriangle size={14} /> {error}</div>}

      <div className="encrypt-form">
        {/* File selector */}
        <div className="enc-drop" onClick={() => inputRef.current?.click()}>
          <input
            ref={inputRef}
            type="file"
            className="file-input"
            accept=".sguard"
            onChange={e => setFile(e.target.files?.[0])}
          />
          {file ? (
            <div className="enc-file-info">
              <Lock size={28} />
              <div>
                <strong>{file.name}</strong>
                <small>{(file.size / 1024).toFixed(1)} KB</small>
              </div>
            </div>
          ) : (
            <div className="enc-file-info">
              <Lock size={28} />
              <div>
                <strong>Choose a .sguard file to decrypt</strong>
                <small>Only .sguard files accepted</small>
              </div>
            </div>
          )}
        </div>

        {/* Password */}
        <div className="pw-field">
          <input
            type={showPw ? 'text' : 'password'}
            placeholder="Decryption password"
            value={password}
            onChange={e => setPassword(e.target.value)}
          />
          <button type="button" className="pw-toggle" onClick={() => setShowPw(!showPw)}>
            {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>

        {/* Decrypt button */}
        <button
          className="primary"
          disabled={!valid || busy}
          onClick={handleDecrypt}
        >
          <Lock size={16} />
          {busy ? 'Decrypting…' : 'Decrypt file'}
        </button>

        <p className="muted" style={{ fontSize: 12, textAlign: 'center', marginTop: 12 }}>
          <ShieldCheck size={13} style={{ verticalAlign: -2, marginRight: 4 }} />
          Decryption is performed locally in your browser and server.
        </p>
      </div>
    </>
  );
}
