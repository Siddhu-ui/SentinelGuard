import React, { useEffect, useState } from 'react';
import { Activity, FileUp, History, LogOut, ShieldCheck, Lock, Unlock, Key } from 'lucide-react';
import Dashboard from './Dashboard';
import Upload from './Upload';
import HistoryPage from './History';
import Result from './Result';
import VirtualScan from './VirtualScan';
import Encrypt from './Encrypt';
import Decrypt from './Decrypt';
import EncryptHistory from './EncryptHistory';

export type Scan = {
  id: number; filename: string; sha256: string; mime_type: string; size: number;
  entropy: number; risk_score: number; risk_level: string; details: any; threats: any[]; created_at: string;
};

export type ApiFn = (p: string, t: string, o?: RequestInit) => Promise<any>;

type Tab = 'dashboard' | 'upload' | 'history' | 'encrypt' | 'decrypt' | 'encrypt-history';

export default function App({ token, signout, api }: { token: string; signout: () => void; api: ApiFn }) {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [data, setData] = useState<any>();
  const [scan, setScan] = useState<Scan>();
  const [error, setError] = useState('');
  const [pendingFile, setPendingFile] = useState<File>();

  const load = async () => {
    try {
      const r = await fetch((import.meta.env.VITE_API_URL || 'http://localhost:8000') + '/dashboard', {
        headers: { Authorization: `Bearer ${token}` },
      });
      const j = await r.json();
      if (r.status === 401) { signout(); return; }
      if (!r.ok) throw new Error(j.detail);
      setData(j);
    } catch (e: any) { setError(e.message); }
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="shell">
      <aside>
        <div className="brand"><ShieldCheck /> SentinelGuard</div>
        <nav>
          <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}><Activity /> Dashboard</button>
          <button className={tab === 'upload' ? 'active' : ''} onClick={() => setTab('upload')}><FileUp /> Analyze file</button>
          <button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}><History /> History</button>
          <div className="nav-divider" />
          <button className={tab === 'encrypt' ? 'active' : ''} onClick={() => setTab('encrypt')}><Lock /> Encrypt file</button>
          <button className={tab === 'decrypt' ? 'active' : ''} onClick={() => setTab('decrypt')}><Unlock /> Decrypt file</button>
          <button className={tab === 'encrypt-history' ? 'active' : ''} onClick={() => setTab('encrypt-history')}><Key /> Encryption history</button>
        </nav>
        <div className="aside-footer">
          <div className="pulse" /><span>Engine online</span>
          <button className="logout" onClick={signout}><LogOut /> Sign out</button>
        </div>
      </aside>
      <main className="content">
        {error && <p className="error toast">{error}</p>}
        {tab === 'dashboard' && <Dashboard data={data} open={setScan} />}
        {tab === 'upload' && <Upload onStart={f => { setPendingFile(f); setTab('dashboard'); }} />}
        {tab === 'history' && <HistoryPage token={token} open={setScan} onAuthFailure={signout} />}
        {tab === 'encrypt' && <Encrypt token={token} api={api} />}
        {tab === 'decrypt' && <Decrypt token={token} api={api} />}
        {tab === 'encrypt-history' && <EncryptHistory token={token} api={api} />}
        {scan && <Result scan={scan} token={token} close={() => setScan(undefined)} />}
        {pendingFile && (
          <VirtualScan
            file={pendingFile}
            token={token}
            onDone={s => { setScan(s); setPendingFile(undefined); load(); }}
            onCancel={() => setPendingFile(undefined)}
            onAuthFailure={signout}
          />
        )}
      </main>
    </div>
  );
}
