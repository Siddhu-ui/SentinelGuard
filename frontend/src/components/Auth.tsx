import React, { useState } from 'react';
import { ShieldCheck, ArrowLeft, Lock, Mail, User } from 'lucide-react';
import { ApiFn } from './App';

export default function Auth({
  api,
  initialRegister,
  onBack,
  onAuth,
}: {
  api: ApiFn;
  initialRegister: boolean;
  onBack: () => void;
  onAuth: (token: string) => void;
}) {
  const [isRegister, setIsRegister] = useState(initialRegister);
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isRegister) {
        if (password.length < 10) {
          throw new Error('Password must be at least 10 characters');
        }
        const res = await api('/api/v1/auth/register', '', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            display_name: displayName,
            password,
          }),
        });
        onAuth(res.access_token);
      } else {
        const res = await api('/api/v1/auth/login', '', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        onAuth(res.access_token);
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <button className="back-btn" onClick={onBack}>
          <ArrowLeft size={16} /> Back
        </button>

        <div className="auth-header">
          <ShieldCheck size={36} className="brand-icon" />
          <h2>{isRegister ? 'Create SentinelGuard Account' : 'Sign in to SentinelGuard'}</h2>
          <p className="muted">
            {isRegister
              ? 'Start scanning and protecting your files securely.'
              : 'Enter your credentials to access your security center.'}
          </p>
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit} className="auth-form">
          {isRegister && (
            <div className="form-group">
              <label>Full Name / Display Name</label>
              <div className="input-icon-wrap">
                <User size={16} className="input-icon" />
                <input
                  type="text"
                  required
                  placeholder="e.g. Alex Rivera"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                />
              </div>
            </div>
          )}

          <div className="form-group">
            <label>Email Address</label>
            <div className="input-icon-wrap">
              <Mail size={16} className="input-icon" />
              <input
                type="email"
                required
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>

          <div className="form-group">
            <label>Password</label>
            <div className="input-icon-wrap">
              <Lock size={16} className="input-icon" />
              <input
                type="password"
                required
                placeholder={isRegister ? 'Minimum 10 characters' : 'Enter password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <button type="submit" className="btn btn-primary btn-lg btn-block" disabled={loading}>
            {loading ? 'Authenticating...' : isRegister ? 'Create Account' : 'Sign In'}
          </button>
        </form>

        <div className="auth-toggle">
          {isRegister ? (
            <p>
              Already have an account?{' '}
              <button className="link-btn" onClick={() => setIsRegister(false)}>
                Sign in
              </button>
            </p>
          ) : (
            <p>
              Don't have an account?{' '}
              <button className="link-btn" onClick={() => setIsRegister(true)}>
                Create one
              </button>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
