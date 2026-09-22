import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import Auth from './components/Auth';
import App from './components/App';
import Landing from './components/Landing';
import './style.css';

const DEFAULT_URLS = [
  (import.meta as any).env?.VITE_API_URL,
  (import.meta as any).env?.VITE_API_BASE_URL,
  'http://127.0.0.1:8001',
  'http://localhost:8001',
  'http://127.0.0.1:8000',
  'http://localhost:8000',
].filter(Boolean);

let activeApiBase = DEFAULT_URLS[0] || 'http://127.0.0.1:8001';

export async function api(path: string, token: string = '', opts: RequestInit = {}) {
  const headers: Record<string, string> = {
    ...(opts.headers as Record<string, string> || {}),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  let r: Response | null = null;
  let lastErr: any = null;

  // Try active API base, fallback to alternate port if connection refused
  const urlsToTry = [activeApiBase, ...DEFAULT_URLS.filter((u) => u !== activeApiBase)];

  for (const baseUrl of urlsToTry) {
    try {
      r = await fetch(baseUrl + path, { ...opts, headers });
      activeApiBase = baseUrl;
      break;
    } catch (err) {
      lastErr = err;
    }
  }

  if (!r) {
    throw new Error('SentinelGuard backend is unavailable. Please check that the backend is running.');
  }

  if (!r.ok) {
    let msg = 'Request failed';
    try {
      const j = await r.json();
      if (j && j.detail) {
        msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail);
      }
    } catch {
      msg = `Server returned error (${r.status})`;
    }
    if (r.status === 401) {
      msg = 'Your session has expired. Please sign in again.';
    }
    throw new Error(msg);
  }
  return r.headers.get('content-type')?.includes('json') ? r.json() : r;
}

function Root() {
  const [token, setToken] = useState<string>(localStorage.getItem('token') || '');
  const [authMode, setAuthMode] = useState<'login' | 'register' | null>(null);
  const [checking, setChecking] = useState<boolean>(!!token);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  const checkHealth = async () => {
    let isOk = false;
    for (const url of DEFAULT_URLS) {
      try {
        const res = await fetch(url + '/api/v1/health');
        if (res.ok) {
          activeApiBase = url;
          isOk = true;
          break;
        }
      } catch {}
    }
    setBackendOnline(isOk);
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!token) {
      setChecking(false);
      return;
    }
    api('/api/v1/auth/me', token)
      .catch(() => {
        localStorage.removeItem('token');
        setToken('');
      })
      .finally(() => setChecking(false));
  }, [token]);

  if (checking) {
    return (
      <main className="auth">
        <div className="auth-card">
          <p className="muted">Restoring secure session...</p>
        </div>
      </main>
    );
  }

  if (!token && !authMode) {
    return (
      <Landing
        backendOnline={backendOnline}
        onSignIn={() => setAuthMode('login')}
        onRegister={() => setAuthMode('register')}
      />
    );
  }

  if (!token) {
    return (
      <Auth
        api={api}
        initialRegister={authMode === 'register'}
        onBack={() => setAuthMode(null)}
        onAuth={(t: string) => {
          localStorage.setItem('token', t);
          setToken(t);
          setAuthMode(null);
        }}
      />
    );
  }

  return (
    <App
      token={token}
      api={api}
      backendOnline={backendOnline}
      signout={() => {
        localStorage.removeItem('token');
        setToken('');
      }}
    />
  );
}

createRoot(document.getElementById('root')!).render(<Root />);
