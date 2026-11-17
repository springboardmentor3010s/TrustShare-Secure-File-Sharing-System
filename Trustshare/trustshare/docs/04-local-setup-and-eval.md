# TrustShare — Local Machine Setup & Milestone 1 Evaluation Guide

This guide walks you through running the exact repository on your own computer (Windows, macOS, or Linux in VS Code), verifying all three databases (**PostgreSQL**, **MongoDB**, **Redis**), running the automated test suite, and demonstrating every Milestone 1 criterion.

---

## Option A — Fastest Full-Stack Launch (Docker Compose — Recommended)

Starts **PostgreSQL 16**, **MongoDB 7** (with collection schema validators & indexes), **Redis 7**, **FastAPI** (auto-running Alembic migrations), and **Next.js 15** in one command.

### Prerequisites
- Docker Desktop (or Docker Engine + Compose v2)
- Git

### Commands
```bash
cd trustshare
cp .env.example .env

# Build and start all 5 services
docker compose up --build -d

# Seed the 4 demo RBAC accounts + sample encrypted files
docker compose exec backend python -m scripts.seed_demo

# Verify service health
docker compose ps
```

### Open in Browser
- **TrustShare Web App:** `http://localhost:3000`
- **FastAPI Interactive Swagger UI:** `http://localhost:8000/docs` (also proxied at `http://localhost:3000/docs`)
- **Liveness Check:** `http://localhost:8000/api/v1/health`

Inside the app, open **Datastore Status** in the left sidebar—all four cards (`POSTGRESQL`, `MONGODB`, `REDIS`, `OBJECT STORAGE`) will display **Connected** with live millisecond latencies.

---

## Option B — Local VS Code Development (Hot-Reload Frontend + Backend)

Best when actively developing Milestone 2–4 features: run only the 3 databases in Docker (or locally installed services), and run FastAPI + Next.js natively with live reload.

### Step 1 — Start PostgreSQL, MongoDB & Redis
```bash
cd trustshare
cp .env.example .env
docker compose up -d postgres mongodb redis
```
*(If running PostgreSQL/MongoDB/Redis natively without Docker, update `DATABASE_URL`, `MONGODB_URI`, and `REDIS_URL` in `.env`.)*

### Step 2 — Start FastAPI Backend (Terminal 1)
```bash
cd trustshare/backend
python -m venv .venv

# Activate venv:
# macOS / Linux:
source .venv/bin/activate
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1

pip install -r requirements.txt

# Apply PostgreSQL schema migrations & seed demo data
alembic upgrade head
python -m scripts.seed_demo

# Run FastAPI with hot reload
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Step 3 — Start Next.js Frontend (Terminal 2)
```bash
cd trustshare/frontend
npm install
npm run dev
```
Open `http://localhost:3000`. Next.js automatically proxies `/api/v1/*` and `/docs` to `http://127.0.0.1:8000` via `next.config.ts`.

### Step 4 — Run the Automated Milestone 1 Test Suite
```bash
cd trustshare/backend
pytest -v tests/test_milestone1.py
```

---

## Demo RBAC Credentials (Created by `seed_demo.py`)

| Role | Email | Password | What to Demonstrate |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@trustshare.dev` | `Admin@1234` | Full vault, upload/version/shred, Users & RBAC management, org-wide audit logs, datastore telemetry |
| **Manager** | `manager@trustshare.dev` | `Manager@1234` | 2 GB vault, org-wide audit read, read-only user list (cannot change roles) |
| **Member** | `member@trustshare.dev` | `Member@1234` | 500 MB personal vault, folder/upload/versioning, own audit logs only (403 on `/users`) |
| **Guest** | `guest@trustshare.dev` | `Guest@1234` | Read-only shared files download; Upload & Folder creation restricted in UI and blocked (`403`) in API |

---

## Milestone 1 Evaluation Walkthrough (All 8 Tasks Mapped)

| Spec Task | Artifact / File Path | Live Demo Verification |
| :--- | :--- | :--- |
| **(i) Objectives & workflows** | `docs/01-objectives-and-workflows.md` | Threat model table, 4-tier RBAC matrix, 5 collaboration workflows, quantitative SLI targets |
| **(ii) Architecture & DB schema** | `docs/02-architecture-and-schema.md`, `backend/app/models/`, `backend/alembic/versions/`, `backend/scripts/init_mongo.js` | 10 PostgreSQL tables + MongoDB JSON Schema validator & compound indexes + Redis TTL keyspace + envelope AEAD wire spec |
| **(iii) UI wireframes & workflow plan** | `docs/03-wireframes-and-ux.html` | Open in any browser—7 interactive tabs covering M1–M3 screens and flow lanes |
| **(iv) Next.js + FastAPI setup** | `frontend/` (Next.js 15 + TS + Tailwind + Axios), `backend/` (FastAPI + SQLAlchemy 2 + Alembic + Pydantic) | Live web app at `:3000` + OpenAPI docs at `:8000/docs` |
| **(v) Configure Postgres, Mongo, Redis** | `docker-compose.yml`, `backend/app/db/{postgres,mongo,redis_client}.py` | Visit `/dashboard/system` or `GET /api/v1/health/datastores` |
| **(vi) Auth & RBAC** | `backend/app/core/{security,rbac}.py`, `backend/app/api/v1/{auth,users}.py`, `/login`, `/register`, `/dashboard/security`, `/dashboard/admin` | Register/login, enroll TOTP QR MFA, revoke session, switch between Admin & Guest to show 403 enforcement |
| **(vii) Secure file upload workflows** | `backend/app/services/storage.py`, `backend/app/api/v1/files.py`, `UploadModal.tsx` | Upload any valid file -> inspect `data/encrypted_objects/` to confirm raw `TSENC01` AES-256-GCM ciphertext; try uploading a `.exe` -> blocked with `415` & logged |
| **(viii) File management dashboard** | `frontend/src/app/dashboard/page.tsx`, `FileDetailDrawer.tsx`, `FolderModal.tsx` | Create nested folders, search/filter by category, inspect SHA-256 & DEK ID, upload `v2`, download `v1` vs `v2`, trash/restore/shred |

---

## Production Security Hardening Before Milestone 4 Deployment
1. Generate fresh secrets—never reuse `.env.example` defaults:
   ```bash
   # JWT_SECRET_KEY
   openssl rand -hex 32
   # MASTER_KEK_B64
   python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
   ```
2. Move `MASTER_KEK` wrapping to **AWS KMS** or **Azure Key Vault** so the root KEK never enters application memory.
3. Enforce TLS termination (NGINX / AWS ALB / Cloudflare) and set `APP_ENV=production` (disables `dev_reset_token` echo in `/auth/password/forgot` once SMTP/SendGrid is wired in Milestone 3).

---

## Pushing to GitHub
```bash
cd trustshare
git init
git add .
git commit -m "feat(m1): complete TrustShare architecture, wireframes, auth/RBAC, encrypted upload & vault dashboard"
git branch -M main
git remote add origin https://github.com/<your-username>/trustshare.git
git push -u origin main
```
