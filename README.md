# TrustShare backend

FastAPI service for authenticated file management, AES-256-GCM client-inaccessible server-side encryption, recipient-bound/expiring share links, PostgreSQL metadata, MongoDB audit/activity events, Redis revocation/rate limits, and S3-compatible object storage. The workspace was empty when implementation began; there was no React app or TrustShare data-model document to integrate/derive additional schema details from.

## Local run (Docker Compose)

1. Copy `.env.example` to `.env`. Replace `JWT_SECRET` and `MASTER_KEY_B64` with independently generated secrets. Generate them in Python, for example: `python -c "import secrets,base64; print(secrets.token_urlsafe(48)); print(base64.b64encode(secrets.token_bytes(32)).decode())"`. Never commit `.env`.
2. Start the stack with `docker compose up --build`.
3. API: `http://localhost:8000`; OpenAPI Swagger: `http://localhost:8000/docs`; MinIO console: `http://localhost:9001`.
4. Container startup applies Alembic migrations before starting Uvicorn.

### Windows / PowerShell development

PowerShell activation is optional. From `D:\trustshare`, use the virtual environment executables directly; this also works when script execution policy blocks `Activate.ps1`:

```powershell
docker compose up -d postgres mongo redis minio
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`. `python trustshare.py` is not the launch command; this project has no `trustshare.py` script. Stop the local server with Ctrl+C and stop dependencies with `docker compose down`.

Native development requires Python 3.11+, PostgreSQL, MongoDB, Redis, and an S3-compatible bucket. Configure `.env` first. `S3_ENDPOINT_URL` may be unset for AWS S3. Bucket permissions should be private and scoped to this service.

## API flow

- Register with `POST /api/auth/register`; authenticate via `POST /api/auth/login` using JSON (`email`, `password`). Access tokens are short-lived bearer JWTs; refresh tokens rotate and are recorded/revocable in PostgreSQL. Logout revokes the access token in Redis and a supplied refresh token.
- Optional MFA: authenticated `POST /api/auth/mfa/setup`, configure the returned TOTP URI in an authenticator app, then `POST /api/auth/mfa/enable?code=...`; logins then require `POST /api/auth/verify-mfa`.
- Upload using multipart `POST /api/files/upload` (`file`, optional `folder_id`, optional `file_id` to create a new version). File downloads require owner authentication. Soft-deleted items are hidden from normal listing.
- Create a share with `POST /api/shares`. The raw token is returned exactly once; only SHA-256 token hashes are persisted. For recipient-restricted links, the recipient must sign in and their email must match. `view` permits inline preview at `/api/shares/access/{token}/preview`, while `download` permits the dedicated download route. A view-only link cannot technically stop an authorized recipient from saving bytes rendered by their own device/browser.
- Swagger supports interactive bearer-token authorization. Admin analytics/security routes require a user whose role is explicitly `admin`; self-registration always creates `user` roles.
- Bootstrap the first administrator only after registering the account: connect through an authenticated PostgreSQL administration channel and run `UPDATE users SET role = 'admin' WHERE email = 'admin@example.com';`. Do not expose a public role-elevation endpoint.

## Reset email and operational security

Password recovery sends one-time tokens by SMTP only when `SMTP_HOST` and `SMTP_FROM` are configured; failures never expose the token in an API response. Configure `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, and TLS-capable SMTP. Add these values to `.env` (they are environment settings, not source constants). The forgot-password response stays generic to resist user enumeration.

Use HTTPS at the deployment ingress/load balancer; this project does not terminate TLS. Set exact production `CORS_ORIGINS`, strong independent secrets, private encrypted backups, cloud IAM least privilege, secret management, network restrictions, monitoring, and tested key rotation/recovery. The master key must remain stable and backed up securely: losing it makes stored file versions unrecoverable. Do not expose it to the frontend. Application-level plaintext exists only in request/download memory; avoid request-body logging, swap/core dumps, and untrusted host access.

Uploads are bounded in memory by `MAX_UPLOAD_BYTES`, allowlisted by extension, checked against declared MIME and selected file signatures, then encrypted before object storage. Extend signature validation and malware scanning to match your product's approved file types. MongoDB writes are best-effort at request call sites; production should monitor log-store health and decide on fail-closed behavior based on audit retention requirements. Rate limits are per IP/path and require trusted-proxy-aware IP handling if deployed behind a proxy.

## Database and migration workflow

PostgreSQL tables include users, folders, files, file_versions, encryption_keys, permissions, share_links, notifications, password_resets, and refresh_sessions. UUID keys and foreign keys are used. Migrations live in `alembic/`; after model changes create a reviewed migration with `alembic revision --autogenerate -m "describe change"`, inspect it, and apply with `alembic upgrade head`.

## API smoke check

Run the local automated checks with `python -m pytest -q`. They cover AES-GCM round-trip/tamper detection, encrypted MFA seed storage, validation, Swagger, health, and unauthorized access. After the stack reports healthy, open `/docs` and exercise register, login, folder creation, upload, download, share creation, link access/download, notification listing, and logout against the running data services; no external service credentials are bundled.

## React frontend (`frontend/`)

The React + Vite + Tailwind CSS frontend lives in `D:\trustshare\frontend` and connects to the FastAPI backend via Axios (`/api`).

### Prerequisites
- Node.js 18+ and npm
- Running FastAPI backend (`http://localhost:8000`)

### Run locally

```powershell
cd D:\trustshare\frontend
copy .env.example .env
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` and `/health` requests to `http://localhost:8000`, and `VITE_API_BASE_URL` can also point directly to your backend URL.
