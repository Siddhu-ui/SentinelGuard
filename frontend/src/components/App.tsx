import React, { useEffect, useState } from 'react';
import {
  Activity,
  FileUp,
  History,
  LogOut,
  ShieldCheck,
  Lock,
  Unlock,
  Archive,
  FileText,
  AlertOctagon,
  Settings as SettingsIcon,
  Menu,
  X,
  Radio,
} from 'lucide-react';
import Dashboard from './Dashboard';
import Upload from './Upload';
import HistoryPage from './History';
import Result from './Result';
import Vault from './Vault';
import Quarantine from './Quarantine';
import Reports from './Reports';
import Encrypt from './Encrypt';
import Decrypt from './Decrypt';
import Settings from './Settings';

export type Scan = {
  id: number;
  filename: string;
  sha256: string;
  mime_type: string;
  extension?: string;
  size: number;
  entropy: number;
  risk_score: number;
  risk_level: string;
  concern_level: string;
  is_quarantined?: boolean;
  quarantine_reason?: string;
  details: any;
  threats: any[];
  created_at: string;
};

export type ApiFn = (p: string, t: string, o?: RequestInit) => Promise<any>;

export type Tab =
  | 'dashboard'
  | 'scan'
  | 'vault'
  | 'reports'
  | 'history'
  | 'quarantine'
  | 'protect'
  | 'decrypt'
  | 'settings';

export default function App({
  token,
  signout,
  api,
  backendOnline,
}: {
  token: string;
  signout: () => void;
  api: ApiFn;
  backendOnline: boolean | null;
}) {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [data, setData] = useState<any>(null);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [protectPrefillFile, setProtectPrefillFile] = useState<File | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: 'info' | 'success' | 'error' } | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const showToast = (msg: string, type: 'info' | 'success' | 'error' = 'info') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 4000);
  };

  const loadDashboard = async () => {
    try {
      const res = await api('/api/v1/dashboard', token);
      setData(res);
    } catch (err: any) {
      showToast(err.message, 'error');
    }
  };

  const deleteScan = async (id: number) => {
    try {
      await api(`/api/v1/scans/${id}`, token, { method: 'DELETE' });
      showToast('Scan record deleted successfully.', 'success');
      if (activeScan?.id === id) setActiveScan(null);
      await loadDashboard();
    } catch (err: any) {
      showToast(err.message, 'error');
    }
  };

  const moveToQuarantine = async (scanId: number, reason: string = 'Moved to quarantine after review') => {
    try {
      const formData = new FormData();
      formData.append('reason', reason);
      await api(`/api/v1/quarantine/${scanId}`, token, {
        method: 'POST',
        body: formData,
      });
      showToast('File moved to quarantine.', 'success');
      if (activeScan?.id === scanId) {
        setActiveScan({ ...activeScan, is_quarantined: true, quarantine_reason: reason });
      }
      await loadDashboard();
    } catch (err: any) {
      showToast(err.message, 'error');
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: <Activity size={18} /> },
    { id: 'scan', label: 'Scan File', icon: <FileUp size={18} /> },
    { id: 'vault', label: 'Secure Vault', icon: <Archive size={18} /> },
    { id: 'reports', label: 'Reports', icon: <FileText size={18} /> },
    { id: 'history', label: 'History', icon: <History size={18} /> },
    { id: 'quarantine', label: 'Quarantine', icon: <AlertOctagon size={18} /> },
    { id: 'protect', label: 'Protect File', icon: <Lock size={18} /> },
    { id: 'decrypt', label: 'Decrypt File', icon: <Unlock size={18} /> },
    { id: 'settings', label: 'Settings', icon: <SettingsIcon size={18} /> },
  ];

  return (
    <div className="shell">
      {/* Mobile Header */}
      <header className="mobile-header">
        <div className="brand">
          <ShieldCheck className="brand-icon" />
          <span>SENTINELGUARD</span>
        </div>
        <button
          className="iconbtn mobile-menu-toggle"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label="Toggle navigation menu"
        >
          {mobileMenuOpen ? <X size={22} /> : <Menu size={22} />}
        </button>
      </header>

      {/* Sidebar Navigation */}
      <aside className={`sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}>
        <div className="brand desktop-only">
          <ShieldCheck className="brand-icon" />
          <div className="brand-text">
            <strong>SENTINELGUARD</strong>
            <small>File Security Platform</small>
          </div>
        </div>

        <nav className="nav-menu">
          {navItems.map((item) => (
            <button
              key={item.id}
              className={`nav-btn ${tab === item.id ? 'active' : ''}`}
              onClick={() => {
                setTab(item.id as Tab);
                setMobileMenuOpen(false);
              }}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          ))}
        </nav>

        <div className="aside-footer">
          <div className="status-indicator">
            <span className={`status-dot ${backendOnline ? 'online' : 'offline'}`} />
            <span className="status-text">
              {backendOnline === null ? 'Checking engine...' : backendOnline ? 'Engine Online' : 'Backend Offline'}
            </span>
          </div>
          <button className="logout-btn" onClick={signout}>
            <LogOut size={16} />
            <span>Sign out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="content">
        {toast && <div className={`toast toast-${toast.type}`}>{toast.msg}</div>}

        {tab === 'dashboard' && (
          <Dashboard
            data={data}
            onOpenScan={(s) => setActiveScan(s)}
            onNavigate={(t) => setTab(t)}
            onDeleteScan={deleteScan}
            onQuarantineScan={(id) => moveToQuarantine(id)}
            onProtectFile={(file) => {
              setProtectPrefillFile(file);
              setTab('protect');
            }}
          />
        )}

        {tab === 'scan' && (
          <Upload
            token={token}
            api={api}
            onScanComplete={(scan) => {
              setActiveScan(scan);
              loadDashboard();
            }}
            showToast={showToast}
          />
        )}

        {tab === 'vault' && (
          <Vault
            token={token}
            api={api}
            showToast={showToast}
            onNavigateToProtect={() => setTab('protect')}
          />
        )}

        {tab === 'reports' && (
          <Reports
            token={token}
            api={api}
            onOpenScan={(s) => setActiveScan(s)}
            showToast={showToast}
          />
        )}

        {tab === 'history' && (
          <HistoryPage
            token={token}
            api={api}
            onOpenScan={(s) => setActiveScan(s)}
            onDeleteScan={deleteScan}
            onQuarantineScan={(id) => moveToQuarantine(id)}
            onProtectFile={(file) => {
              setProtectPrefillFile(file);
              setTab('protect');
            }}
            showToast={showToast}
          />
        )}

        {tab === 'quarantine' && (
          <Quarantine
            token={token}
            api={api}
            onOpenScan={(s) => setActiveScan(s)}
            onRefresh={loadDashboard}
            showToast={showToast}
          />
        )}

        {tab === 'protect' && (
          <Encrypt
            token={token}
            api={api}
            prefillFile={protectPrefillFile}
            onComplete={() => {
              setProtectPrefillFile(null);
              loadDashboard();
            }}
            onViewVault={() => setTab('vault')}
            showToast={showToast}
          />
        )}

        {tab === 'decrypt' && (
          <Decrypt
            token={token}
            api={api}
            showToast={showToast}
          />
        )}

        {tab === 'settings' && (
          <Settings
            token={token}
            api={api}
            signout={signout}
            showToast={showToast}
          />
        )}

        {/* Scan Result Modal */}
        {activeScan && (
          <Result
            scan={activeScan}
            token={token}
            api={api}
            close={() => setActiveScan(null)}
            onQuarantine={() => moveToQuarantine(activeScan.id)}
            onDelete={() => deleteScan(activeScan.id)}
            onProtect={() => {
              setActiveScan(null);
              setTab('protect');
            }}
            showToast={showToast}
          />
        )}
      </main>

      {/* Mobile Bottom Navigation */}
      <nav className="mobile-bottom-nav">
        <button
          className={`mob-nav-btn ${tab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setTab('dashboard')}
        >
          <Activity size={20} />
          <span>Dashboard</span>
        </button>
        <button
          className={`mob-nav-btn ${tab === 'scan' ? 'active' : ''}`}
          onClick={() => setTab('scan')}
        >
          <FileUp size={20} />
          <span>Scan</span>
        </button>
        <button
          className={`mob-nav-btn ${tab === 'vault' ? 'active' : ''}`}
          onClick={() => setTab('vault')}
        >
          <Archive size={20} />
          <span>Vault</span>
        </button>
        <button
          className={`mob-nav-btn ${tab === 'reports' ? 'active' : ''}`}
          onClick={() => setTab('reports')}
        >
          <FileText size={20} />
          <span>Reports</span>
        </button>
        <button
          className={`mob-nav-btn ${tab === 'history' ? 'active' : ''}`}
          onClick={() => setTab('history')}
        >
          <History size={20} />
          <span>History</span>
        </button>
      </nav>
    </div>
  );
}
