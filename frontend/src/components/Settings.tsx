import React, { useState, useEffect } from 'react';
import {
  User,
  Shield,
  HardDrive,
  Lock,
  Info,
  LogOut,
  Save,
  CheckCircle2,
} from 'lucide-react';
import { ApiFn } from './App';

export default function Settings({
  token,
  api,
  signout,
  showToast,
}: {
  token: string;
  api: ApiFn;
  signout: () => void;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
}) {
  const [settings, setSettings] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [displayName, setDisplayName] = useState('');
  const [retentionDays, setRetentionDays] = useState(30);
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [savingAccount, setSavingAccount] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const res = await api('/api/v1/settings', token);
      setSettings(res);
      setDisplayName(res.display_name || '');
      setRetentionDays(res.retention_days || 30);
    } catch (err: any) {
      showToast(err.message || 'Failed to load settings', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingAccount(true);
    try {
      await api('/api/v1/settings', token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          display_name: displayName,
          retention_days: Number(retentionDays),
        }),
      });
      showToast('Settings saved successfully.', 'success');
      loadSettings();
    } catch (err: any) {
      showToast(err.message || 'Failed to update settings', 'error');
    } finally {
      setSavingAccount(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPw.length < 10) {
      showToast('New password must be at least 10 characters', 'error');
      return;
    }
    if (newPw !== confirmPw) {
      showToast('New passwords do not match', 'error');
      return;
    }
    setSavingPassword(true);
    try {
      await api('/api/v1/auth/change-password', token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          current_password: currentPw,
          new_password: newPw,
        }),
      });
      showToast('Password changed successfully.', 'success');
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
    } catch (err: any) {
      showToast(err.message || 'Failed to change password', 'error');
    } finally {
      setSavingPassword(false);
    }
  };

  return (
    <div className="settings-page">
      <header className="page-header">
        <p className="eyebrow">CONFIGURATION</p>
        <h1>Settings & Privacy</h1>
        <p className="muted">Manage your account profile, storage preferences, security credentials, and privacy controls.</p>
      </header>

      {loading ? (
        <div className="dashboard-loading">
          <div className="spinner" />
          <p className="muted">Loading settings...</p>
        </div>
      ) : (
        <div className="settings-grid">
          {/* Section 1: Account */}
          <section className="settings-card">
            <div className="settings-card-head">
              <User size={20} className="text-accent" />
              <h3>Account Profile</h3>
            </div>
            <form onSubmit={handleUpdateProfile} className="settings-form">
              <div className="form-group">
                <label>Email Address</label>
                <input type="text" disabled value={settings?.email || ''} />
                <small className="muted">Email cannot be modified.</small>
              </div>
              <div className="form-group">
                <label>Display Name</label>
                <input
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                />
              </div>
              <button type="submit" className="btn btn-primary btn-sm" disabled={savingAccount}>
                <Save size={14} /> {savingAccount ? 'Saving...' : 'Save Profile'}
              </button>
            </form>
          </section>

          {/* Section 2: Security & Credentials */}
          <section className="settings-card">
            <div className="settings-card-head">
              <Shield size={20} className="text-accent" />
              <h3>Security & Password</h3>
            </div>
            <form onSubmit={handleChangePassword} className="settings-form">
              <div className="form-group">
                <label>Current Password</label>
                <input
                  type="password"
                  required
                  placeholder="Enter current password"
                  value={currentPw}
                  onChange={(e) => setCurrentPw(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label>New Password (min 10 chars)</label>
                <input
                  type="password"
                  required
                  placeholder="Enter new strong password"
                  value={newPw}
                  onChange={(e) => setNewPw(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label>Confirm New Password</label>
                <input
                  type="password"
                  required
                  placeholder="Repeat new password"
                  value={confirmPw}
                  onChange={(e) => setConfirmPw(e.target.value)}
                />
              </div>
              <button type="submit" className="btn btn-primary btn-sm" disabled={savingPassword}>
                <Save size={14} /> {savingPassword ? 'Updating...' : 'Update Password'}
              </button>
            </form>
          </section>

          {/* Section 3: Storage Preferences */}
          <section className="settings-card">
            <div className="settings-card-head">
              <HardDrive size={20} className="text-accent" />
              <h3>Storage Preferences</h3>
            </div>
            <div className="settings-form">
              <div className="form-group">
                <label>File Retention Period</label>
                <select
                  value={retentionDays}
                  onChange={(e) => setRetentionDays(Number(e.target.value))}
                >
                  <option value={7}>7 Days</option>
                  <option value={30}>30 Days</option>
                  <option value={90}>90 Days</option>
                  <option value={365}>1 Year</option>
                </select>
                <small className="muted">Scans older than this period can be scheduled for auto-purge.</small>
              </div>
              <div className="form-group">
                <label>Maximum Upload Limit</label>
                <input type="text" disabled value={`${settings?.max_upload_mb || 100} MB per file`} />
              </div>
            </div>
          </section>

          {/* Section 4: Privacy Architecture */}
          <section className="settings-card">
            <div className="settings-card-head">
              <Lock size={20} className="text-accent" />
              <h3>Privacy Guarantee</h3>
            </div>
            <div className="privacy-body">
              <p className="muted">
                SentinelGuard operates under strict zero-leak principles:
              </p>
              <ul className="privacy-list">
                <li>✓ Files analyzed locally via explainable static heuristics</li>
                <li>✓ No transmission to third-party AI or external cloud APIs</li>
                <li>✓ Files are never executed on host servers</li>
                <li>✓ Secure deletion upon user request</li>
              </ul>
            </div>
          </section>

          {/* Section 5: About SentinelGuard */}
          <section className="settings-card settings-card-full">
            <div className="settings-card-head">
              <Info size={20} className="text-accent" />
              <h3>About SentinelGuard</h3>
            </div>
            <div className="about-details">
              <div>
                <strong>Version:</strong> {settings?.version || '1.0.0'} (V1 Commercial Platform)
              </div>
              <div>
                <strong>Engine:</strong> Static Pre-Analysis & AES-256-GCM / Argon2id Crypter
              </div>
              <div className="session-logout-wrap">
                <button className="btn btn-danger-ghost" onClick={signout}>
                  <LogOut size={16} /> Sign out from current session
                </button>
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
