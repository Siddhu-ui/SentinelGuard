# SentinelGuard — Production Deployment Guide

The app ships as **one service**: the FastAPI backend serves both the REST API
and the built frontend from a single origin, with a **persistent volume** for
the SQLite database, uploads, Secure Vault and Quarantine files. No CORS
setup, no separate frontend hosting, one URL.

Verified locally before this guide: 72/72 backend tests, `tsc --noEmit` +
`vite build` clean, same-origin serving confirmed, and a real end-to-end API
flow (register → scan clean+tampered PDFs → quarantine → restore → delete).

---

## Option A — Fly.io (recommended, one command)

Everything is already configured: `Dockerfile`, `fly.toml`, and an optional
GitHub Actions workflow (`.github/workflows/deploy.yml`).

### 1. Install and authenticate (one-time)

```bash
# Windows (PowerShell) or macOS:
curl -L https://fly.io/install.sh | sh        # or: winget install Fly.Flyctl
flyctl auth signup    # or: flyctl auth login
```

### 2. Deploy

From the repository root:

> **One-time note:** the GitHub Actions `FLY_API_TOKEN` should be created with
> `flyctl tokens create deploy` — it can push to an existing app but **cannot
> create apps, volumes or secrets**. The workflow therefore expects a one-time
> local bootstrap (below); after that it deploys on every push.

```powershell
# Generate a strong JWT secret first; you will paste it below
python -c "import secrets; print(secrets.token_hex(32))"

flyctl auth login                          # one-time interactive auth
flyctl apps create sentinelguard-siddhu    # creates the app (CI cannot do this with a deploy token)
flyctl secrets set SECRET_KEY=<paste-the-hex-above> --app sentinelguard-siddhu
flyctl volumes create sentinelguard_data --size 3 --region iad --app sentinelguard-siddhu
flyctl deploy                              # uses fly.toml; builds remotely
```

Alternatively, re-run the **"Deploy to Fly.io"** workflow from the GitHub
Actions tab after the bootstrap — it will detect the app/volume exist and go
straight to deploying.

That is the whole deployment. `fly.toml` already sets:

| Setting | Value |
|---|---|
| `DATABASE_URL` | `sqlite:////data/sentinelguard.db` (on the persistent volume) |
| `UPLOAD_DIR` | `/data/uploads` (uploads, Vault blobs, quarantine files) |
| `PORT` | `8080` |
| Health check | `GET /health` every 15s |
| HTTPS | forced, auto machine start/stop |

### 3. Verify the live deployment

```bash
flyctl status                     # app running, health checks passing
flyctl logs                       # watch boot
curl https://<your-app>.fly.dev/health
# should return: {"status":"ok",...}
```

Then open `https://<your-app>.fly.dev/` — the frontend is served from the same
origin and talks to the API directly. Register an account, scan a PDF, and try
Secure Vault / Quarantine to confirm the full stack on the live instance.

### 4. Optional: automatic deploys on every push

Add your Fly token as a repository secret and the included workflow deploys
automatically:

```bash
flyctl tokens create deploy            # copy the output
# GitHub → your repo → Settings → Secrets and variables → Actions →
# New repository secret → Name: FLY_API_TOKEN, Secret: <paste>
```

`.github/workflows/deploy.yml` then builds and deploys on every push to
`secure-Quarantine` (and manual runs from the Actions tab).

### 5. Operations notes

- **Persistence**: everything durable lives on the `sentinelguard_data`
  volume (`/data`). It survives deploys and restarts. Scale it with
  `flyctl volumes extend sentinelguard_data --size 10`.
- **Backups**: `flyctl postgres` is not used here; snapshot the volume instead
  (`flyctl volumes snapshots list sentinelguard_data`).
- **Scaling**: `flyctl scale memory 1024 --vm-size shared-cpu-2x` if you expect
  heavier PDF analysis load.
- **SECRET_KEY rotation**: `flyctl secrets set SECRET_KEY=<new>` then
  `flyctl deploy --restart-only`. Users will need to sign in again; vault and
  file encryption are unaffected (keys derive from user passwords).

---

## Option B — Render (no CLI, fully dashboard-driven)

1. Push this branch to GitHub (already done: `secure-Quarantine`).
2. Render dashboard → **New → Blueprint**, point it at the repo/branch — or
   **New → Web Service** with these settings:
   - **Environment:** Docker
   - **Region:** closest to you
   - **Instance type:** Free (fine for testing) or Starter
   - **Disk** (Starter+): mount 3 GB at `/data`
3. Set environment variables in the Render dashboard:

   | Key | Value |
   |---|---|
   | `SECRET_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` |
   | `DATABASE_URL` | `sqlite:////data/sentinelguard.db` |
   | `UPLOAD_DIR` | `/data/uploads` |
   | `PORT` | `10000` (Render sets this; the app reads it) |
   | `CORS_ORIGINS` | `https://<your-service>.onrender.com` |
   | `MAX_UPLOAD_MB` | `100` |

4. Health check path: `/health`. Deploy.

> Render's free tier has **no persistent disk** — database and files reset on
> redeploy. Use Starter (or Fly.io) for real persistence.

---

## Option C — Split deploy (Vercel frontend + any Python host backend)

Only if you prefer separate hosting; CORS + two env vars are required.

1. **Backend** on Fly.io/Render/Railway as above (Options A/B), with
   `CORS_ORIGINS=https://<your-frontend>.vercel.app,https://<your-frontend>.vercel.app/*`
   — or run it locally and expose it (`cloudflared tunnel --url
   http://127.0.0.1:8001`).
2. **Frontend** on Vercel:

```bash
cd frontend
vercel login          # interactive
vercel --prod
```

With Project → Settings → Environment Variables:

| Key | Value |
|---|---|
| `VITE_API_URL` | `https://<your-backend-host>` (or your tunnel URL) |

Vite bakes `VITE_API_URL` in at build time — redeploy the frontend after
changing it. The code already handles this: production builds default to
same-origin (`''`) unless `VITE_API_URL` is set.

---

## Local container smoke test (optional, needs Docker Desktop running)

```bash
docker build -t sentinelguard .
docker run --rm -p 8080:8080 \
  -e SECRET_KEY=local-test-secret-change-me \
  -v sg_data:/data \
  sentinelguard
# open http://localhost:8080
```

---

## Environment variable reference

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `SECRET_KEY` | **Yes in production** | `development-only-change-me` | JWT signing. Set a 64-char random hex value. |
| `DATABASE_URL` | Recommended | `sqlite:///./sentinelguard.db` | Point at the persistent volume. |
| `UPLOAD_DIR` | Recommended | `./uploads` | Persistent storage for uploads, Vault blobs, quarantine files. |
| `CORS_ORIGINS` | Only for split hosting | localhost dev origins | Comma-separated allowed origins; unnecessary for the single-service deploy. |
| `MAX_UPLOAD_MB` | Optional | `100` | Upload size limit. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Optional | `60` | Session length. |
| `VITE_API_URL` | Frontend only | same-origin in prod builds | Set only when frontend and backend are on different origins. |

**Never commit** `SECRET_KEY` — set it via `flyctl secrets` / Render
dashboard. The plaintext Vault password is never stored anywhere in any
deployment mode; only its bcrypt hash exists, and file keys derive per-file
via Argon2id.
