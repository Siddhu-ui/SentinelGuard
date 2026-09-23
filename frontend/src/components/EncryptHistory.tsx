import React, { useEffect, useState } from 'react';
import { History, AlertTriangle, KeyRound } from 'lucide-react';
import { EmptyState } from './VaultPage';

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
          <EmptyState
            icon={<KeyRound size={30}/>}
            title="No encrypted files yet"
            body="Use Encrypt file to protect a document — every encryption is recorded here."
          />
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
