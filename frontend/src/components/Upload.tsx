import React, { useState, useRef } from 'react';
import {
  FileUp,
  Shield,
  CheckCircle2,
  AlertCircle,
  FileCheck,
  Lock,
  Layers,
  FileCode,
  Binary,
} from 'lucide-react';
import { ApiFn, Scan } from './App';

const MAX_SIZE_MB = 100;
const SUPPORTED_EXTS = ['pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'zip', 'rar', 'docx', 'xlsx', 'pptx', 'exe'];

export default function Upload({
  token,
  api,
  onScanComplete,
  showToast,
}: {
  token: string;
  api: ApiFn;
  onScanComplete: (s: Scan) => void;
  showToast: (msg: string, type?: 'info' | 'success' | 'error') => void;
}) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [currentStage, setCurrentStage] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const stages = [
    { label: 'Checking file type & magic bytes', icon: <FileCheck size={16} /> },
    { label: 'Checking structure & headers', icon: <Layers size={16} /> },
    { label: 'Checking metadata & timestamps', icon: <FileCode size={16} /> },
    { label: 'Checking embedded content & actions', icon: <Binary size={16} /> },
    { label: 'Calculating explainable security indicators', icon: <Shield size={16} /> },
  ];

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateAndSetFile = (file: File) => {
    setError(null);
    const ext = file.name.split('.').pop()?.toLowerCase() || '';
    if (!SUPPORTED_EXTS.includes(ext)) {
      setError(`Unsupported file format (.${ext}). Supported formats: ${SUPPORTED_EXTS.join(', ').toUpperCase()}`);
      return;
    }
    if (file.size > MAX_SIZE_MB * 1024 * 1024) {
      setError(`File exceeds maximum upload size limit of ${MAX_SIZE_MB} MB.`);
      return;
    }
    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const startAnalysis = async () => {
    if (!selectedFile) return;
    setScanning(true);
    setError(null);
    setCurrentStage(0);

    // Realistic sequential progress feedback
    const stageInterval = setInterval(() => {
      setCurrentStage((prev) => (prev < stages.length - 1 ? prev + 1 : prev));
    }, 450);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const result = await api('/api/v1/scan', token, {
        method: 'POST',
        body: formData,
      });

      clearInterval(stageInterval);
      setCurrentStage(stages.length);
      setTimeout(() => {
        setScanning(false);
        onScanComplete(result);
        showToast('Scan complete. Results ready.', 'success');
      }, 300);
    } catch (err: any) {
      clearInterval(stageInterval);
      setScanning(false);
      setError(err.message || 'An error occurred during analysis.');
      showToast(err.message || 'Analysis failed.', 'error');
    }
  };

  return (
    <div className="scan-page">
      <header className="page-header">
        <p className="eyebrow">STATIC ANALYSIS</p>
        <h1>Scan & Inspect File</h1>
        <p className="muted">
          Analyze headers, structure, and metadata before opening or sharing. Files are never executed.
        </p>
      </header>

      <div className="upload-container">
        {!scanning ? (
          <>
            <div
              className={`dropzone ${dragActive ? 'active' : ''} ${selectedFile ? 'has-file' : ''}`}
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                type="file"
                ref={fileInputRef}
                style={{ display: 'none' }}
                onChange={(e) => {
                  if (e.target.files?.[0]) validateAndSetFile(e.target.files[0]);
                }}
              />
              <FileUp size={44} className="dropzone-icon" />
              {selectedFile ? (
                <div className="selected-file-details">
                  <h3>{selectedFile.name}</h3>
                  <p className="muted">
                    {(selectedFile.size / 1024).toFixed(1)} KB • Ready for security inspection
                  </p>
                  <span className="btn-sm btn-outline">Change file</span>
                </div>
              ) : (
                <div className="dropzone-prompt">
                  <h3>Drop your file here, or browse</h3>
                  <p className="muted">Supported: PDF, Images, Archives, Office Docs, Executables</p>
                  <span className="size-pill">Max {MAX_SIZE_MB} MB</span>
                </div>
              )}
            </div>

            {error && <div className="alert alert-error">{error}</div>}

            {selectedFile && (
              <div className="upload-actions">
                <button className="btn btn-primary btn-lg" onClick={startAnalysis}>
                  <Shield size={18} /> Begin Security Analysis
                </button>
              </div>
            )}

            <div className="privacy-card">
              <div className="privacy-header">
                <Lock size={16} className="text-accent" />
                <strong>Privacy & Security Guarantee</strong>
              </div>
              <p className="muted">
                Your file is analyzed locally and statically in memory. SentinelGuard never transmits your documents
                to external AI services or third-party cloud scanners. Uploaded files are never executed.
              </p>
            </div>
          </>
        ) : (
          <div className="scanning-progress-card">
            <div className="scanning-header">
              <div className="spinner" />
              <div>
                <h3>Analyzing {selectedFile?.name}</h3>
                <p className="muted">Executing bounded static analysis heuristics...</p>
              </div>
            </div>

            <div className="stages-list">
              {stages.map((stage, idx) => {
                const isDone = idx < currentStage;
                const isCurrent = idx === currentStage;
                return (
                  <div
                    key={idx}
                    className={`stage-item ${isDone ? 'done' : ''} ${isCurrent ? 'active' : ''}`}
                  >
                    <div className="stage-icon">
                      {isDone ? <CheckCircle2 size={16} className="text-ok" /> : stage.icon}
                    </div>
                    <span className="stage-label">{stage.label}</span>
                    <span className="stage-status">
                      {isDone ? 'Complete' : isCurrent ? 'Analyzing...' : 'Waiting'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
