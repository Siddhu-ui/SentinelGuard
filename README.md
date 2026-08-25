# SentinelGuard

> Intelligent Detection of Steganographic and Polyglot Files Using Cryptography

SentinelGuard statically analyzes suspicious files before they are opened, then optionally protects files with authenticated encryption. It is not antivirus software.

## Features

- File security analysis: magic-byte validation, SHA-256 fingerprints, entropy, polyglot and image-steganography indicators
- Explainable threat score, recommendations, PDF reports, and owner-scoped scan history
- Password-based AES-256-GCM file encryption and authenticated decryption
- Versioned `.sguard` encrypted-file format, SHA-256 integrity verification, and protected-file history

## Architecture

```text
React/Vite UI → FastAPI API → SQLAlchemy/SQLite
                     ├─ scanner: bounded static analysis
                     └─ encryption: Argon2id + AES-256-GCM
```

### Encryption flow

```text
Password → Argon2id + random salt → AES-256 key
         → AES-256-GCM + random nonce → .sguard
```

### Decryption flow

```text
.sguard → read authenticated metadata → Argon2id + stored salt
        → AES-256-GCM authentication verification → original file
```

SHA-256 is a hashing/integrity fingerprint, not encryption. AES-256-GCM provides confidentiality plus authenticated integrity. Argon2id derives a key from a password; passwords and AES keys are never stored or logged.

Encryption protects confidentiality and integrity; it does not remove malware or make an unsafe file trustworthy.

## Quick start

### Backend

```powershell
cd backend
Copy-Item .env.example .env
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest
uvicorn main:app --reload
```

The API runs at `http://localhost:8000`; interactive documentation is at `/docs`.

### Frontend

```powershell
cd frontend
npm install
npm run build
npm run dev
```

Open the Vite URL (normally `http://localhost:5173`). Register, analyze a file, or use Encrypt File / Decrypt File directly. `VITE_API_URL` selects the development API URL.

## Security model

Uploads are size-checked, assigned server-generated names, kept outside static web paths, and are never executed. Every API endpoint is authenticated and owner-scoped. Encryption generates a fresh 16-byte salt and 12-byte GCM nonce for each operation. The `.sguard` header is versioned and authenticated as AES-GCM additional authenticated data. Partial plaintext is deleted if authentication fails.

Runtime files remain in `backend/uploads/` and `backend/protected/`, both excluded from Git. Configure deployment secrets and paths using `backend/.env` (never commit it).

## Project layout

```text
backend/
  main.py                 FastAPI endpoints
  models.py               SQLAlchemy records, including encryption history
  services/encryption.py  Argon2id + streaming AES-256-GCM `.sguard` format
  scanner/                bounded static analysis
  tests/                  cryptographic regression tests
frontend/                 React/Vite interface
docs/API.md               API reference
```

## Limitations

The current 100 MB upload cap prevents resource exhaustion. AES-GCM is streamed to disk, but the protected output is retained for authenticated owner download until an application cleanup policy removes it. Heuristic scanner findings can be false positives; use them as input to a security decision, not proof of malware.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. To report a vulnerability, follow [SECURITY.md](SECURITY.md).

Released under the [MIT License](LICENSE).
