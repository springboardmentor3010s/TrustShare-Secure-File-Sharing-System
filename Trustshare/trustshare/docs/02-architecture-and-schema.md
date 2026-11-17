# TrustShare — Secure System Architecture & Database Schema
**Milestone 1 · Task (ii) Deliverable**

---

## 1. Architectural Pattern: Modular Monolith with Microservice-Ready Boundaries

**Design Decision:** Implement the six backend services shown in the specification diagram (`Auth`, `File`, `Encryption`, `Sharing`, `Notification`, `Analytics`) as **strictly isolated Python domain modules inside a single FastAPI application**, backed by PostgreSQL, MongoDB, Redis, and pluggable Object Storage (local vault for M1; AWS S3 / Azure Blob for M2), orchestrated with Docker Compose.

**Trade-off Rationale:**
- **Why not 6 separate microservices + Kafka + Kubernetes in Week 1?** Deploying 6 independent Python containers plus a message broker adds distributed transactions, cross-service JWT propagation, and heavy local RAM overhead (~4–6 GB) without improving any Milestone 1–4 evaluation criterion.
- **Why modular boundaries still matter:** Keeping `core/security.py`, `core/rbac.py`, `services/storage.py`, `services/audit.py`, and versioned routers under `api/v1/` cleanly decoupled allows any single module (e.g., async email notifications via Celery/Redis in M3) to scale independently later without rewriting schemas or client contracts.

### Layered System Diagram

```text
+-----------------------------------------------------------------------------------+
|                        CLIENT LAYER (Next.js 15 + TypeScript)                     |
|  Login / Register / MFA  |  File Vault & Versioning  |  Audit Log  |  Admin RBAC  |
|                Axios Client (Bearer JWT + Auto Refresh Interceptor)               |
+-----------------------------------------+-----------------------------------------+
                                          | HTTPS / TLS (Reverse-Proxy /api/v1/*)
                                          v
+-----------------------------------------------------------------------------------+
|                     FASTAPI SECURITY GATEWAY & SERVICE LAYER                      |
|  Middleware: CORS | Security Headers (nosniff, Referrer) | X-Request-ID Tracing   |
|  Auth Guard: JWT Verify -> Redis JTI Denylist -> Session Check -> RBAC Scope      |
|  +--------------+ +--------------+ +----------------+ +------------+ +---------+  |
|  | Auth & MFA   | | File & Folder| | Envelope AEAD  | | Sharing    | | Audit & |  |
|  | Service (M1) | | Service (M1) | | AES-256-GCM    | | ACLs (M2)  | | Health  |  |
|  +--------------+ +--------------+ +----------------+ +------------+ +---------+  |
+----------+-------------------+--------------------+----------------------+--------+
           |                   |                    |                      |
           v                   v                    v                      v
  +-----------------+  +---------------+   +-----------------+   +------------------+
  | PostgreSQL 16+  |  | Redis 7+      |   | MongoDB 7       |   | Encrypted Object |
  | Users, Sessions,|  | Session Cache,|   | audit_logs,     |   | Storage          |
  | RBAC, Folders,  |  | JWT Denylist, |   | security_events |   | Local Vault (M1) |
  | Files, Versions,|  | Rate Limiter, |   | (JSONL failover |   | AWS S3 / Azure   |
  | Wrapped DEKs,   |  | MFA & Reset   |   |  in standalone  |   | Blob (M2)        |
  | Shares, Notifs  |  | TTL Tokens    |   |  dev mode)      |   | Ciphertext ONLY  |
  +-----------------+  +---------------+   +-----------------+   +------------------+
```

---

## 2. Envelope Encryption & Streaming AEAD Specification

To satisfy *"unique AES-256 key per uploaded file"*, *"keys never exposed to users"*, *"periodic key rotation"*, and *"in-memory decryption"* safely for large files:

1. **Key Hierarchy (2-Tier Envelope):**
   - **Root Key Encryption Key (`MASTER_KEK`):** 256-bit key loaded exclusively into FastAPI process memory from environment / KMS, tagged with `kek_version`.
   - **Per-Version Data Encryption Key (`DEK`):** Fresh `os.urandom(32)` generated per upload/version. Wrapped using `AESGCM(MASTER_KEK).encrypt(wrap_nonce, dek, aad=b"trustshare:dek:v1")`. Only `wrapped_dek` and `wrap_nonce` are stored in PostgreSQL `encryption_keys`.
   - **Fast Key Rotation (M2):** Rotating `MASTER_KEK` from `v1 -> v2` only re-wraps the 32-byte `wrapped_dek` column in PostgreSQL—multi-gigabyte files in S3/Azure do not need re-uploading.

2. **Chunked Wire Format (`TSENC01\x00`):**
   ```text
   [ 8B Magic: "TSENC01\0" ]
   Repeated for chunk i = 0, 1, ..., N-1:
     [ 4B uint32_be: ciphertext_len ][ 1B uint8: is_final (0 or 1) ]
     [ ciphertext_len bytes: AES-256-GCM(key=DEK,
                                         nonce=base_nonce XOR uint64_be(i),
                                         plaintext=chunk_i (<= 64 KiB),
                                         aad="ts-chunk-v1:" || uint64_be(i) || is_final) ]
   ```
   - Prevents **modification** (128-bit GCM authentication tag per chunk).
   - Prevents **chunk reordering** (`i` bound into both nonce and AAD).
   - Prevents **tail truncation** (decoder rejects stream if EOF arrives before an authenticated `is_final == 1` frame).

---

## 3. PostgreSQL Relational Schema (Alembic Managed — 10 Domain Tables)

### Entity Relationship Overview
```text
users (1) ----< (N) user_sessions
users (1) ----< (N) oauth_accounts
users (1) ----< (N) folders (self-referencing parent_id -> folders.id)
users (1) ----< (N) files >---- (0..1) folders
files (1) ----< (N) file_versions
encryption_keys (1) ---- (0..1) file_versions / files
files (1) ----< (N) share_links        [Provisioned for Milestone 2]
files (1) ----< (N) file_permissions   [Active for Guest ACLs + Milestone 2]
users (1) ----< (N) notifications      [Provisioned for Milestone 3]
```

### Table Specifications

| Table | Primary Key | Key Columns & Types | Constraints & Indexes | Milestone |
| :--- | :--- | :--- | :--- | :---: |
| **`users`** | `id` (`VARCHAR(36)` UUID) | `email`, `full_name`, `password_hash`, `role` (`admin\|manager\|member\|guest`), `is_active`, `mfa_enabled`, `mfa_secret_encrypted`, `storage_quota_bytes` (`BIGINT`), `storage_used_bytes` (`BIGINT`), `failed_login_count`, `last_login_at`, `created_at`, `updated_at` | `UNIQUE(email)`, `IDX(role)` | M1 |
| **`user_sessions`** | `id` (UUID) | `user_id` (FK `users`), `refresh_jti`, `ip_address`, `user_agent`, `is_revoked`, `expires_at`, `last_seen_at`, `created_at` | `UNIQUE(refresh_jti)`, `IDX(user_id)`, `IDX(is_revoked)` | M1 |
| **`oauth_accounts`** | `id` (UUID) | `user_id` (FK `users`), `provider` (`google\|github`), `provider_user_id`, `provider_email`, `created_at` | `UNIQUE(provider, provider_user_id)`, `IDX(user_id)` | M1 |
| **`folders`** | `id` (UUID) | `owner_id` (FK `users`), `parent_id` (FK `folders`, nullable), `name`, `color`, `is_deleted`, `created_at`, `updated_at` | `IDX(owner_id)`, `IDX(parent_id)`, `IDX(is_deleted)` | M1 |
| **`encryption_keys`** | `id` (UUID) | `kek_version` (`INT`), `algorithm`, `wrapped_dek` (`BYTEA`), `wrap_nonce` (`BYTEA`), `stream_base_nonce` (`BYTEA`), `chunk_size` (`INT`), `status` (`active\|rotated\|revoked`), `rotated_at`, `created_at` | `IDX(kek_version)` | M1 + M2 |
| **`files`** | `id` (UUID) | `owner_id` (FK `users`), `folder_id` (FK `folders`), `name`, `original_name`, `extension`, `mime_type`, `category`, `description`, `tags` (`JSON`), `size_bytes`, `encrypted_size_bytes`, `sha256_checksum`, `current_version`, `storage_backend`, `storage_key`, `is_encrypted`, `encryption_key_id` (FK), `download_count`, `is_starred`, `is_deleted`, `deleted_at`, `created_at`, `updated_at` | `UNIQUE(storage_key)`, `IDX(owner_id, folder_id, category, name, sha256_checksum, is_deleted)` | M1 |
| **`file_versions`** | `id` (UUID) | `file_id` (FK `files`), `version_number` (`INT`), `uploaded_by` (FK `users`), `size_bytes`, `encrypted_size_bytes`, `mime_type`, `sha256_checksum`, `storage_backend`, `storage_key`, `is_encrypted`, `encryption_key_id` (FK), `change_note`, `created_at` | `UNIQUE(file_id, version_number)`, `UNIQUE(storage_key)`, `IDX(file_id)` | M1 |
| **`share_links`** | `id` (UUID) | `file_id` (FK `files`), `created_by` (FK `users`), `token_hash` (`CHAR(64)`), `permission`, `password_hash`, `max_downloads`, `download_count`, `expires_at`, `is_revoked`, `created_at` | `UNIQUE(token_hash)`, `IDX(file_id, expires_at, is_revoked)` | M2 |
| **`file_permissions`** | `id` (UUID) | `file_id` (FK `files`), `grantee_user_id` (FK `users`), `granted_by` (FK `users`), `permission` (`view\|download\|edit`), `expires_at`, `created_at` | `UNIQUE(file_id, grantee_user_id)`, `IDX(grantee_user_id)` | M1 + M2 |
| **`notifications`** | `id` (UUID) | `user_id` (FK `users`), `event_type`, `severity`, `title`, `message`, `is_read`, `created_at` | `IDX(user_id, is_read)` | M3 |

---

## 4. MongoDB Document Schema (`backend/scripts/init_mongo.js`)

### Collection: `audit_logs`
```json
{
  "event_id": "9f6b1c82-3b7e-4e99-82bc-4a92d68d1b10",
  "timestamp": "2026-11-17T15:52:10.412891+00:00",
  "actor_id": "2c8d45a1-...",
  "actor_email": "admin@trustshare.dev",
  "actor_role": "admin",
  "action": "file.uploaded",
  "category": "file",
  "resource_type": "file",
  "resource_id": "b7a13f09-...",
  "resource_name": "ISO27001-Compliance-Readiness-Brief.pdf",
  "status": "success",
  "severity": "info",
  "ip_address": "127.0.0.1",
  "user_agent": "Mozilla/5.0 ...",
  "request_id": "8e31f09ab412cc01",
  "details": {
    "size_bytes": 18420,
    "encrypted_size_bytes": 18449,
    "category": "document",
    "sha256": "e3b0c44298fc...",
    "is_encrypted": true,
    "encryption_key_id": "4e19aa02-..."
  }
}
```
- **Indexes:** `event_id` (unique), `(timestamp: -1)`, `(actor_id: 1, timestamp: -1)`, `(resource_type: 1, resource_id: 1, timestamp: -1)`, `(category: 1, severity: 1, timestamp: -1)`.
- **Collection `security_events`:** Automatically receives mirrored copies of all `warning`/`critical` and `blocked`/`failure` events with `{ resolved: false }` for Milestone 3 anomaly detection and alerting.

---

## 5. Redis Key-Space Design (`backend/app/db/redis_client.py`)

| Key Pattern | Value | TTL | Purpose |
| :--- | :--- | :--- | :--- |
| `ts:sess:{session_id}` | JSON `{user_id, role, ip}` | `7 days` | Fast active-session lookup |
| `ts:sess:revoked:{session_id}` | `"1"` | Access token remaining TTL | Instant logout / admin suspension propagation |
| `ts:jwt:deny:{jti}` | `"1"` | Access token remaining TTL | Immediate revocation of logged-out access JWTs |
| `ts:rl:login:{ip}:{email}` | Integer counter | `300 sec` | Brute-force login protection (`>= 5` triggers `429`) |
| `ts:mfa:{sha256(token)}` | JSON `{user_id}` | `300 sec` | Single-use pre-MFA login step-up challenge |
| `ts:mfa:setup:{user_id}` | KEK-encrypted TOTP seed | `600 sec` | Pending authenticator enrollment prior to verification |
| `ts:pwdreset:{sha256(token)}` | `user_id` | `900 sec` | Single-use password recovery token |

---

## 6. Milestone 1 REST API Contract (`/api/v1`)

| Method & Endpoint | Auth / RBAC | Description |
| :--- | :--- | :--- |
| `GET  /health` | Public | Service liveness & version |
| `GET  /health/datastores` | Authenticated | Live telemetry for PostgreSQL, MongoDB, Redis & Storage |
| `POST /auth/register` | Public | Register member account + issue session JWT pair |
| `POST /auth/login` | Public (rate-limited) | Login with bcrypt check; returns JWTs or MFA challenge |
| `POST /auth/mfa/verify-login` | MFA challenge | Verify 6-digit TOTP and issue session JWT pair |
| `POST /auth/mfa/setup` | Authenticated | Generate TOTP secret + inline QR PNG data URI |
| `POST /auth/mfa/enable` | Authenticated | Confirm TOTP code & store KEK-encrypted seed |
| `POST /auth/mfa/disable` | Authenticated | Disable MFA (requires password + valid TOTP) |
| `POST /auth/refresh` | Refresh JWT | Rotate refresh token JTI (revokes session on replay) |
| `POST /auth/logout` | Authenticated | Denylist JTI + revoke session in Postgres & Redis |
| `GET  /auth/me` | Authenticated | Current user profile, quota & effective RBAC scopes |
| `GET  /auth/sessions` | Authenticated | List active sessions across devices |
| `DELETE /auth/sessions/{id}` | Authenticated | Revoke a specific session |
| `POST /auth/password/change` | Authenticated | Rotate password & revoke other active sessions |
| `POST /auth/password/forgot` | Public | Issue 15-min single-use Redis recovery token |
| `POST /auth/password/reset` | Reset token | Reset password & revoke all active sessions |
| `GET  /auth/oauth/{provider}/authorize` | Public | Google / GitHub OAuth2 authorization URL builder |
| `GET  /users` | `user:read_all` | List organization users (Admin / Manager) |
| `PATCH /users/{id}` | `user:manage_roles` | Update role, quota, or active status (Admin only) |
| `GET  /users/roles/matrix` | Authenticated | Retrieve full RBAC role-to-permission matrix |
| `GET  /users/audit-logs` | `audit:read_own/all` | Paginated, filterable MongoDB audit trail |
| `GET  /folders` | `file:read` | List root, child, or all folders with file counts |
| `POST /folders` | `folder:manage` | Create folder with color & optional parent |
| `GET  /folders/{id}/breadcrumbs` | `file:read` | Resolve ancestor breadcrumb trail |
| `PATCH /folders/{id}` | `folder:manage` | Rename or recolor folder |
| `DELETE /folders/{id}` | `folder:manage` | Soft-delete folder & safely relocate contents |
| `GET  /files/summary` | `file:read` | Vault KPI summary & category breakdown |
| `POST /files/upload` | `file:upload` | Validated streaming AES-256-GCM upload |
| `POST /files/{id}/versions` | `file:version` | Upload new encrypted revision (`v2, v3, ...`) |
| `GET  /files` | `file:read` | Search, filter, sort & paginate files |
| `GET  /files/{id}` | `file:read` | Detailed cryptographic metadata + version timeline |
| `PATCH /files/{id}` | `file:update` | Update name, folder, category, tags, note, star |
| `GET  /files/{id}/download` | `file:download` | Stream-decrypt latest or historical `?version=N` |
| `DELETE /files/{id}` | `file:delete` | Move to Trash, or `?permanent=true` to shred keys/blobs |
| `POST /files/{id}/restore` | `file:delete` | Restore trashed file |
