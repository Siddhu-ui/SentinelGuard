# sentinentalGuard

> A privacy-conscious pre-analysis tool for identifying suspicious files before they are opened.

SentinelGuard is a pre-analysis security tool for identifying suspicious files before they are opened. It detects signature mismatches, entropy anomalies, embedded signatures, image steganography indicators, and produces an explainable risk report. It is not antivirus software.

## Features

- Static file checks without executing uploads
- Signature, entropy, polyglot, and image-steganography indicators
- Explainable risk score and downloadable PDF report
- Per-user scan history protected by JWT authentication

## Repository topics

`sentinentalGuard`, `cybersecurity`, `file-analysis`, `fastapi`, `react`, `malware-analysis`, `security-tools`

## Quick start

### Backend

```powershell
cd backend
Copy-Item .env.example .env
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

The API is served at `http://localhost:8000`; interactive API documentation is at `/docs`.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL (normally `http://localhost:5173`). Register an account, then upload a file. The default development API URL can be changed with `VITE_API_URL`.

## Security model

Uploads are size-checked, assigned server-generated UUID names, never executed, and stored outside static web paths. File paths are never derived from user input. Authentication uses short-lived JWTs and bcrypt hashes; endpoints are scoped to the authenticated owner. The scanner uses bounded reads for costly checks.

## Project layout

```
backend/
  main.py                 FastAPI application and endpoints
  database.py             SQLite setup
  models.py               SQLAlchemy models
  schemas.py              validated request/response models
  services/               auth, scan orchestration, reporting
  scanner/                signature, entropy, polyglot, image analysis
  uploads/                private runtime upload storage
frontend/                 React/Vite user interface
docs/API.md               API quick reference
```

## Optional scanners

`python-magic`, `Pillow`, and `yara-python` enhance detection. The application degrades gracefully when an optional native dependency is unavailable. VirusTotal integration is intentionally not enabled by default: it may upload file hashes/data to a third party and requires an explicit API key and privacy review.

## Limitations

Heuristics can create false positives. A high entropy score is common in compressed and encrypted files. Treat results as an input to security decisions, not proof of malware.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. To report a vulnerability, follow [SECURITY.md](SECURITY.md); do not publish security issues or suspicious samples in public issues.

## License

Released under the [MIT License](LICENSE).
