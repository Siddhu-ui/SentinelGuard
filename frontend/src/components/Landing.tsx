import React from 'react';
import {
  ShieldCheck,
  FileUp,
  Lock,
  Archive,
  FileText,
  CheckCircle2,
  ArrowRight,
  Shield,
  Layers,
  Search,
} from 'lucide-react';

export default function Landing({
  backendOnline,
  onSignIn,
  onRegister,
}: {
  backendOnline: boolean | null;
  onSignIn: () => void;
  onRegister: () => void;
}) {
  return (
    <div className="landing-page">
      {/* Top Navbar */}
      <header className="landing-nav">
        <div className="brand">
          <ShieldCheck className="brand-icon" />
          <span>SENTINELGUARD</span>
        </div>
        <div className="nav-actions">
          <div className="status-indicator mr-4">
            <span className={`status-dot ${backendOnline ? 'online' : 'offline'}`} />
            <span className="status-text">
              {backendOnline === null ? 'Connecting...' : backendOnline ? 'Engine Online' : 'Backend Offline'}
            </span>
          </div>
          <button className="btn btn-outline btn-sm" onClick={onSignIn}>
            Sign In
          </button>
          <button className="btn btn-primary btn-sm" onClick={onRegister}>
            Create Account
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero-section">
        <p className="eyebrow">PRIVACY-FOCUSED FILE SECURITY PLATFORM</p>
        <h1 className="hero-title">
          Scan, Understand, Protect & Store Files Securely
        </h1>
        <p className="hero-sub">
          A static file analysis and cryptographic vault platform. Inspect file headers, detect anomalies,
          and secure sensitive documents before you trust or share them.
        </p>

        <div className="hero-cta-group">
          <button className="btn btn-primary btn-lg" onClick={onRegister}>
            Get Started Free <ArrowRight size={18} />
          </button>
          <button className="btn btn-outline btn-lg" onClick={onSignIn}>
            Sign In
          </button>
        </div>
      </section>

      {/* Pillars Section */}
      <section className="pillars-section">
        <div className="section-title text-center">
          <p className="eyebrow">CORE CAPABILITIES</p>
          <h2>Four Pillars of File Security</h2>
        </div>

        <div className="pillars-grid">
          <div className="pillar-card">
            <div className="pillar-icon">
              <FileUp size={24} />
            </div>
            <h3>1. Scan & Inspect</h3>
            <p className="muted">
              Bounded static pre-analysis. Inspects file signatures, Shannon entropy, embedded PE headers,
              PDF action hooks, and image LSB heuristics without ever executing the file.
            </p>
          </div>

          <div className="pillar-card">
            <div className="pillar-icon">
              <Lock size={24} />
            </div>
            <h3>2. Protect Files</h3>
            <p className="muted">
              Military-grade AES-256-GCM encryption paired with Argon2id password key derivation.
              Wraps files into self-authenticating .sguard packages.
            </p>
          </div>

          <div className="pillar-card">
            <div className="pillar-icon">
              <Archive size={24} />
            </div>
            <h3>3. Secure Vault</h3>
            <p className="muted">
              Personal encrypted repository. Organize sensitive documents, decrypt on demand with SHA-256
              integrity verification, and isolate untrusted files in quarantine.
            </p>
          </div>

          <div className="pillar-card">
            <div className="pillar-icon">
              <FileText size={24} />
            </div>
            <h3>4. Security Reports</h3>
            <p className="muted">
              Export professional, verified PDF security analysis reports with explainable score breakdowns,
              finding evidence, and clear recommendations.
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <p className="muted">
          © 2026 SentinelGuard. Static pre-analysis provides security indicators and does not independently establish maliciousness or document authenticity.
        </p>
      </footer>
    </div>
  );
}
