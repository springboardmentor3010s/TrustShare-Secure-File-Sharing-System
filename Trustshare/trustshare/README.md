# TrustShare — Intelligent Encrypted File Sharing & Digital Collaboration Platform

Full-stack secure file-sharing platform built with **FastAPI**, **Next.js 15 (TypeScript + Tailwind CSS + Axios)**, **PostgreSQL**, **MongoDB**, **Redis**, and **server-side streaming AES-256-GCM envelope encryption**.

---

## Milestone 1 Status (Weeks 1 & 2 — Complete)

- **(i) Objectives, Threat Model & Workflows:** [`docs/01-objectives-and-workflows.md`](docs/01-objectives-and-workflows.md)
- **(ii) System Architecture & Polyglot DB Schema:** [`docs/02-architecture-and-schema.md`](docs/02-architecture-and-schema.md)
- **(iii) Interactive UI Wireframes & Workflow Blueprint:** [`docs/03-wireframes-and-ux.html`](docs/03-wireframes-and-ux.html)
- **(iv) Next.js + FastAPI Scaffold:** [`frontend/`](frontend/) & [`backend/`](backend/)
- **(v) PostgreSQL, MongoDB & Redis Integration:** [`docker-compose.yml`](docker-compose.yml) & [`backend/app/db/`](backend/app/db/)
- **(vi) Auth, JWT Refresh Rotation, TOTP MFA, OAuth2, Password Recovery & 4-Tier RBAC:** [`backend/app/api/v1/auth.py`](backend/app/api/v1/auth.py), [`backend/app/core/rbac.py`](backend/app/core/rbac.py)
- **(vii) Secure File Upload (Sanitization, Magic-Byte Guard, SHA-256, Chunked AES-256-GCM Envelope Encryption & Versioning):** [`backend/app/services/storage.py`](backend/app/services/storage.py), [`backend/app/api/v1/files.py`](backend/app/api/v1/files.py)
- **(viii) File Management Dashboard, Audit Viewer, MFA Center & Admin RBAC Console:** [`frontend/src/app/dashboard/`](frontend/src/app/dashboard/)

For complete local setup (Docker Compose + native VS Code) and evaluator demo steps, see [`docs/04-local-setup-and-eval.md`](docs/04-local-setup-and-eval.md).

---

## Quick Start (Docker Compose)

```bash
cp .env.example .env
docker compose up --build -d
docker compose exec backend python -m scripts.seed_demo
```

- **Web App:** `http://localhost:3000`
- **API Swagger Docs:** `http://localhost:8000/docs`
- **Default Admin Login:** `admin@trustshare.dev` / `Admin@1234` (Manager, Member, and Guest demo accounts are also pre-seeded)

---

## Repository Structure

```text
trustshare/
├── docker-compose.yml               # PostgreSQL 16 + MongoDB 7 + Redis 7 + FastAPI + Next.js
├── .env.example                     # Environment configuration template
├── docs/
│   ├── 01-objectives-and-workflows.md
│   ├── 02-architecture-and-schema.md
│   ├── 03-wireframes-and-ux.html    # Standalone interactive wireframe studio (M1–M3)
│   └── 04-local-setup-and-eval.md   # Local setup + Milestone 1 demo & verification guide
├── backend/
│   ├── alembic/                     # Versioned PostgreSQL schema migrations (10 domain tables)
│   ├── scripts/
│   │   ├── init_mongo.js            # MongoDB schema validator & compound indexes
│   │   └── seed_demo.py             # Idempotent RBAC + encrypted sample file seeder
│   ├── app/
│   │   ├── core/                    # Config, bcrypt/JWT/TOTP/KEK crypto, RBAC permissions
│   │   ├── db/                      # PostgreSQL, MongoDB (w/ resilient fallback), Redis clients
│   │   ├── models/                  # SQLAlchemy 2.0 ORM models (M1 active + M2/M3 ready)
│   │   ├── schemas/                 # Pydantic v2 request/response contracts
│   │   ├── services/                # Magic-byte validator, chunked AES-256-GCM storage, audit logger
│   │   └── api/v1/                  # health, auth, users, folders, files routers
│   └── tests/test_milestone1.py     # End-to-end automated verification suite
└── frontend/
    ├── next.config.ts               # Seamless /api/* and /docs reverse proxy to FastAPI
    └── src/
        ├── app/                     # /login, /register, /dashboard (+ activity, security, admin, system)
        ├── components/              # UploadModal, FolderModal, FileDetailDrawer
        └── lib/                     # Axios JWT/refresh client, AuthContext, formatters, types
```
