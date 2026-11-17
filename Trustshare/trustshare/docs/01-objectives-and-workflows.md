# TrustShare — Project Objectives, Threat Model & Collaboration Workflows
**Milestone 1 · Task (i) Deliverable**

---

## 1. Core Objective & Problem Statement

Organizations, academic teams, and external collaborators routinely exchange sensitive documents over general-purpose email attachments or unmanaged cloud drives that lack expiring access controls, tamper verification, per-file encryption isolation, and verifiable audit trails.

**TrustShare** solves this by providing a centralized, role-governed file-sharing platform where:
1. Every uploaded file passes strict server-side type, magic-byte, filename, and quota validation before acceptance.
2. Plaintext bytes are **never** written to persistent storage—each file version is encrypted in streaming 64 KiB chunks using a **unique 256-bit AES-256-GCM Data Encryption Key (DEK)** wrapped under a server-managed root **Key Encryption Key (KEK)**.
3. Access is gated by **bcrypt-authenticated credentials**, optional **RFC 6238 TOTP MFA**, **short-lived JWTs with rotating refresh tokens**, **four-tier RBAC**, and (in Milestone 2) **time- and download-bounded share links**.
4. Every security-relevant event—authentication, upload, blocked file, version update, download, session revocation, and role change—is recorded in an append-only audit log.

---

## 2. Explicit Threat Model & Trust Boundaries

Separating what server-side encryption guarantees from what it does *not* guarantee is essential for accurate security engineering:

| Threat Scenario | Protected? | Mechanism in TrustShare |
| :--- | :---: | :--- |
| **Compromised S3 bucket / stolen storage disk** | **Yes** | Storage holds only `AES-256-GCM` ciphertext frames (`TSENC01`); neither raw DEKs nor KEK reside in object storage. |
| **PostgreSQL database dump leaked alone** | **Yes** | `encryption_keys.wrapped_dek` stores DEKs encrypted under `MASTER_KEK` (env/KMS), and passwords use `bcrypt` (cost 12); share/reset tokens are SHA-256 hashed. |
| **Ciphertext tampering, chunk reordering, or truncation** | **Yes** | Per-chunk GCM authentication tag binds `chunk_index` and `is_final` flag via Associated Authenticated Data (AAD); decryption aborts immediately on `InvalidTag`. |
| **Malware / webshell upload disguised as `.pdf` or `.png`** | **Yes** | Extension denylist + double-extension filter + magic-byte signature verification (blocks PE/MZ, ELF, Mach-O, PHP, spoofed PDF/PNG) + UUID-isolated storage paths. |
| **Credential stuffing & stolen refresh token replay** | **Yes** | Redis sliding login rate limiter (5 attempts / 5 min), optional TOTP MFA, JTI denylist on logout, and automatic session revocation on refresh-token replay. |
| **Unauthorized privilege escalation (e.g., Guest uploading)** | **Yes** | Declarative FastAPI `require_permission(...)` dependencies checked on every route; violations return `403` and emit a `security` audit event. |
| **Memory exhaustion (OOM) on concurrent large transfers** | **Yes** | Fixed 64 KiB streaming encryption and decryption generators—never loads full files into RAM. |
| **Root compromise of live FastAPI host + KEK simultaneously** | **No (Out of Scope)** | Inherent trade-off of the specified **Server-Side Encryption** architecture. Mitigated in production (M4) via AWS KMS/Azure Key Vault, short key cache lifetimes, least-privilege IAM, and SIEM alerting. Client-side E2EE would be required to remove server trust entirely, at the cost of server-side malware inspection. |

---

## 3. Personas & Role-Based Access Control (RBAC) Matrix

| Capability / Permission Scope | `admin` | `manager` | `member` | `guest` |
| :--- | :---: | :---: | :---: | :---: |
| **Default Encrypted Vault Quota** | 5 GB | 2 GB | 500 MB | 0 MB (read-only) |
| Authenticate, manage own sessions, enable TOTP MFA | Yes | Yes | Yes | Yes |
| Browse & stream-decrypt authorized files (`file:read`, `file:download`) | Yes | Yes | Yes | Yes (shared only) |
| Upload new encrypted files (`file:upload`) | Yes | Yes | Yes | **Blocked (403)** |
| Organize folders & edit metadata (`folder:manage`, `file:update`) | Yes | Yes | Yes | **Blocked (403)** |
| Upload new file versions (`file:version`) | Yes | Yes | Yes | **Blocked (403)** |
| Soft-delete & restore own files (`file:delete`) | Yes | Yes | Yes | **Blocked (403)** |
| Create expiring share links (`share:create` — M2) | Yes | Yes | Yes | **Blocked (403)** |
| View own activity logs (`audit:read_own`) | Yes | Yes | Yes | Yes |
| View org-wide audit logs & user directory (`audit:read_all`, `user:read_all`) | Yes | Yes | **Blocked** | **Blocked** |
| Assign roles, change quotas, suspend accounts (`user:manage_roles`) | Yes | **Blocked** | **Blocked** | **Blocked** |
| Inspect org-wide file inventory & revoke any share (`share:revoke_any`) | Yes | **Blocked** | **Blocked** | **Blocked** |

---

## 4. End-to-End Secure Collaboration Workflows

### Workflow A — Registration, Login, MFA Step-Up & Token Lifecycle (M1 — Active)
```text
[User Browser] --HTTPS POST /auth/login--> [FastAPI Auth Router]
   |-- 1. Check Redis rate limit (ts:rl:login:{ip}:{email}) -> 429 if >= 5 failures / 5m
   |-- 2. Fetch user in PostgreSQL + verify bcrypt(12) hash -> log failure if mismatch
   |-- 3. If mfa_enabled:
   |       Store SHA-256(mfa_token) in Redis (TTL 300s) -> return { mfa_required: true }
   |       User submits 6-digit RFC 6238 TOTP -> decrypt seed with KEK -> verify window ±1
   |-- 4. Create user_sessions row (Postgres) + cache session in Redis (TTL 7d)
   |-- 5. Issue signed Access JWT (30m, unique jti) + Refresh JWT (7d, rotated refresh_jti)
   '-- 6. Append auth.login_success event to MongoDB audit_logs
```

### Workflow B — Validated Streaming Envelope-Encrypted Upload (M1 — Active)
```text
[User Browser] --Multipart Stream--> [FastAPI /files/upload]
   |-- 1. Enforce JWT + RBAC permission (file:upload) + target folder ownership
   |-- 2. Sanitize filename (NFC normalize, strip path traversal & control chars)
   |-- 3. Check extension denylist + double-extension guard
   |-- 4. Read first 64 KiB chunk -> inspect magic bytes (reject PE/MZ, ELF, Mach-O, PHP, spoofed PDF/PNG)
   |-- 5. Generate fresh 256-bit DEK -> wrap DEK under root KEK (AES-256-GCM) -> random 12B base nonce
   |-- 6. For each 64 KiB chunk:
   |       Check max upload size (50 MB) & user remaining quota -> 413 + delete partial file on overflow
   |       Update streaming SHA-256 plaintext digest
   |       Derive chunk_nonce = base_nonce XOR chunk_index; AAD = chunk_index || is_final
   |       Encrypt chunk with AES-256-GCM -> write framed ciphertext to isolated object path
   |-- 7. Persist wrapped_dek in encryption_keys, metadata in files + file_versions (v1), increment quota
   '-- 8. Append file.uploaded (or file.upload_blocked) to MongoDB audit_logs
```

### Workflow C — Authorized Streaming Decryption & Download (M1 — Active)
```text
[Authorized User] --GET /files/{id}/download?version=N--> [FastAPI]
   |-- 1. Verify JWT, active session, RBAC (file:download), and ownership / FilePermission ACL
   |-- 2. Fetch EncryptionKey metadata -> unwrap DEK in memory using root KEK (discard raw DEK reference after init)
   |-- 3. Stream-decrypt each 64 KiB frame, verifying GCM tag + chunk index + final-frame marker
   |-- 4. Deliver plaintext over HTTPS StreamingResponse with X-Content-SHA256 header (0 bytes written to disk)
   '-- 5. Increment download_count in PostgreSQL + log file.downloaded in MongoDB
```

### Workflow D — Controlled Temporary Share Link Lifecycle (M2 — Schema Provisioned)
```text
[File Owner] --POST /shares--> Generate 256-bit URL-safe token -> store SHA-256(token) in share_links
   with permission (view|download), optional bcrypt link password, expires_at, and max_downloads.
[Recipient]  --GET /s/{token}--> Validate !is_revoked && now < expires_at && download_count < max_downloads
   && optional password -> stream-decrypt in memory -> atomic increment download_count -> audit & notify owner.
```

### Workflow E — File Revisioning & Cryptographic Erasure (M1 — Active)
```text
New Version: POST /files/{id}/versions -> mints a brand-new DEK & isolated ciphertext object (v2),
             preserving v1 intact for audit/rollback while updating files.current_version = 2.
Soft Delete: DELETE /files/{id} -> marks is_deleted=true (recoverable in Trash).
Hard Shred:  DELETE /files/{id}?permanent=true -> deletes all version ciphertext objects, deletes wrapped
             DEK rows from encryption_keys (cryptographic erasure), reclaims user quota, logs warning event.
```

---

## 5. Concrete Quantitative Performance & Security Targets

Sections 8–9 of the project specification list qualitative metric categories. Below are the concrete, testable Service Level Indicators (SLIs) adopted for TrustShare across Milestones 1–4:

| Domain | Metric | Target Threshold | Verification Method |
| :--- | :--- | :--- | :--- |
| **Security** | Server-side AES-256-GCM throughput | `>= 80 MB/s` single-worker streaming; `< 40 ms` overhead on a 5 MB file | Timed upload/download benchmark |
| **Security** | Malicious header / RBAC violation blocking | `100%` deterministic block rate on denylisted extensions, PE/ELF headers, expired/replayed tokens, and unauthorized role calls | Automated `pytest` security suite |
| **Security** | Brute-force lockout response | Block on attempt `#6` within a `300 s` window (`HTTP 429`) + critical audit event | Rate-limit integration test |
| **File Mgmt** | Time-to-first-byte (TTFB) on download | `< 150 ms` p95 (streaming starts on chunk #0 decryption) | API latency probe |
| **File Mgmt** | Backend RAM growth per concurrent transfer | `< 2 MB` per active stream regardless of file size (64 KiB chunk buffer) | Memory profiling under 50 MB upload |
| **System** | Metadata & listing API latency | `< 100 ms` p95 for paginated folder/file queries up to 10,000 files | Indexed PostgreSQL queries |
| **System** | Concurrent users supported (single container) | `>= 50` concurrent authenticated sessions without error (`< 0.1%` 5xx) | Load test in Milestone 4 |
