import React, { useEffect, useState } from 'react';
import { History, AlertTriangle } from 'lucide-react';

interface EncryptRecord {
  id: number;
  original_filename: string;
  encrypted_filename: string;
  file_size: number;
  sha256: string;
  algorithm: string;
  kdf: string;
  status: string;
  created_at: string;
}

interface Props {
  token: string;
  api: (p: string, t: string, o?: RequestInit) => Promise<any>;
}

export default function EncryptHistory({ token, api }: Props) {
  const [records, setRecords] = useState<EncryptRecord[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api('/encryption/history', token).then(setRecords).catch((e: any) => setError(e.message));
  }, []);

  return (
    <>
      <header>
        <p className="eyebrow">ENCRYPTION HISTORY</p>
        <h1>Past encryptions</h1>
      </header>

      {error && <div className="error"><AlertTriangle size={14} /> {error}</div>}

      <div className="table">
        {records.length === 0 ? (
          <div className="empty">
            <History size={28} style={{ marginBottom: 10, opacity: 0.4 }} />
            <p>No encrypted files yet.</p>
          </div>
        ) : (
          records.map(r => (
            <div className="row" key={r.id} style={{ cursor: 'default' }}>
              <span>
                <b>{r.original_filename}</b>
                <small>{r.algorithm} · {r.kdf}</small>
              </span>
              <span className="badge safe">{r.status}</span>
              <small>{new Date(r.created_at).toLocaleString()}</small>
            </div>
          ))
        )}
      </div>
    </>
  );
}
