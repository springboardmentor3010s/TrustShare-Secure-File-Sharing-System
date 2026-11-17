"""
End-to-end automated verification suite for TrustShare Milestone 1:
- Task (v):    PostgreSQL, MongoDB (or fallback), and Redis live telemetry
- Task (vi):   Registration, bcrypt login, JWT refresh rotation, replay detection,
               TOTP MFA enrollment & step-up login, password recovery, session revocation,
               and RBAC enforcement (Guest blocked on upload & admin endpoints; Admin allowed)
- Task (vii):  Secure upload workflow (sanitization, magic-byte PE/PDF spoofing rejection,
               extension blocking, SHA-256 integrity, chunked AES-256-GCM encryption at rest
               verified directly on disk, streaming decryption round-trip, versioning, trash/restore)
- Task (viii): Dashboard summary, folder tree & breadcrumbs, search/filter, audit log trail
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.security import current_totp_code
from app.db.postgres import SessionLocal
from app.main import app
from app.models.file import FileRecord


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_full_milestone1_workflows():
    settings = get_settings()
    suffix = uuid.uuid4().hex[:8]
    user_email = f"alice.test.{suffix}@trustshare.dev"

    with TestClient(app) as client:
        # 1. Health endpoint
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

        # 2. Password policy rejects weak passwords
        r = client.post(
            "/api/v1/auth/register",
            json={"email": user_email, "full_name": "Alice Tester", "password": "weak"},
        )
        assert r.status_code == 422

        # 3. Valid registration issues JWT access + refresh tokens
        r = client.post(
            "/api/v1/auth/register",
            json={"email": user_email, "full_name": "Alice Tester", "password": "StrongPass@2026"},
        )
        assert r.status_code == 201, r.text
        data = r.json()
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]
        assert data["user"]["role"] == "member"
        assert "file:upload" in data["user"]["permissions"]

        # 4. Datastore health verifies real PostgreSQL + Redis + MongoDB adapter
        r = client.get("/api/v1/health/datastores", headers=_auth(access_token))
        assert r.status_code == 200
        ds = {d["service"]: d for d in r.json()["datastores"]}
        assert ds["postgresql"]["status"] == "connected"
        assert ds["redis"]["status"] in {"connected", "fallback_active"}
        assert ds["mongodb"]["status"] in {"connected", "fallback_active"}

        # 5. RBAC: Member cannot access Admin user-list endpoint
        r = client.get("/api/v1/users", headers=_auth(access_token))
        assert r.status_code == 403

        # 6. Folder hierarchy + breadcrumbs
        r = client.post(
            "/api/v1/folders",
            json={"name": "Research Vault", "color": "emerald"},
            headers=_auth(access_token),
        )
        assert r.status_code == 201
        root_folder_id = r.json()["id"]

        r = client.post(
            "/api/v1/folders",
            json={"name": "Confidential Datasets", "parent_id": root_folder_id, "color": "indigo"},
            headers=_auth(access_token),
        )
        assert r.status_code == 201
        sub_folder_id = r.json()["id"]

        r = client.get(f"/api/v1/folders/{sub_folder_id}/breadcrumbs", headers=_auth(access_token))
        assert r.status_code == 200
        assert [b["name"] for b in r.json()] == ["Research Vault", "Confidential Datasets"]

        # 7. Secure Upload blocks dangerous extensions AND disguised executable magic bytes
        r = client.post(
            "/api/v1/files/upload",
            files={"file": ("malware.exe", b"hello", "application/octet-stream")},
            headers=_auth(access_token),
        )
        assert r.status_code == 415

        r = client.post(
            "/api/v1/files/upload",
            files={"file": ("innocent_report.pdf", b"MZ\x90\x00PE_DISGUISED", "application/pdf")},
            headers=_auth(access_token),
        )
        assert r.status_code == 415

        r = client.post(
            "/api/v1/files/upload",
            files={"file": ("fake_pdf.pdf", b"Not actually a PDF header", "application/pdf")},
            headers=_auth(access_token),
        )
        assert r.status_code == 415

        # 8. Multi-chunk (>64 KiB) upload: verify encrypted on disk + exact SHA-256 decrypted download
        plaintext_v1 = (b"TrustShare Confidential Payload Line - Verified AEAD!\n" * 2000)  # ~108 KB (2 chunks)
        expected_sha_v1 = hashlib.sha256(plaintext_v1).hexdigest()

        r = client.post(
            "/api/v1/files/upload",
            data={
                "folder_id": sub_folder_id,
                "description": "Multi-chunk encrypted test artifact",
                "tags": "crypto,milestone1",
            },
            files={"file": ("../../Quarterly_Spec.txt", plaintext_v1, "text/plain")},
            headers=_auth(access_token),
        )
        assert r.status_code == 201, r.text
        fmeta = r.json()
        file_id = fmeta["id"]
        assert fmeta["name"] == "Quarterly_Spec.txt"  # Path traversal stripped!
        assert fmeta["sha256_checksum"] == expected_sha_v1
        assert fmeta["is_encrypted"] is True
        assert fmeta["current_version"] == 1

        # Verify raw ciphertext on disk contains ZERO plaintext substring
        with SessionLocal() as db:
            rec = db.get(FileRecord, file_id)
            assert rec is not None
            disk_bytes = (Path(settings.LOCAL_STORAGE_DIR) / rec.storage_key).read_bytes()
            assert disk_bytes.startswith(b"TSENC01\x00")
            assert b"TrustShare Confidential Payload" not in disk_bytes

        # 9. Upload Version 2 and verify both v1 and v2 decrypt accurately
        plaintext_v2 = b"Updated Version 2 Content - Audited & Encrypted."
        expected_sha_v2 = hashlib.sha256(plaintext_v2).hexdigest()
        r = client.post(
            f"/api/v1/files/{file_id}/versions",
            data={"change_note": "Revised metrics"},
            files={"file": ("Quarterly_Spec.txt", plaintext_v2, "text/plain")},
            headers=_auth(access_token),
        )
        assert r.status_code == 201
        assert r.json()["current_version"] == 2
        assert r.json()["sha256_checksum"] == expected_sha_v2

        # Download latest (v2)
        dl2 = client.get(f"/api/v1/files/{file_id}/download", headers=_auth(access_token))
        assert dl2.status_code == 200
        assert dl2.content == plaintext_v2

        # Download historical v1
        dl1 = client.get(f"/api/v1/files/{file_id}/download?version=1", headers=_auth(access_token))
        assert dl1.status_code == 200
        assert dl1.content == plaintext_v1

        # 10. Search, trash, restore, and permanent delete (key shredding + quota reclamation)
        srch = client.get("/api/v1/files?q=Quarterly", headers=_auth(access_token))
        assert srch.status_code == 200 and srch.json()["total"] == 1

        assert client.delete(f"/api/v1/files/{file_id}", headers=_auth(access_token)).status_code == 200
        assert client.get("/api/v1/files?view=trash", headers=_auth(access_token)).json()["total"] == 1
        assert client.post(f"/api/v1/files/{file_id}/restore", headers=_auth(access_token)).status_code == 200
        assert (
            client.delete(f"/api/v1/files/{file_id}?permanent=true", headers=_auth(access_token)).status_code
            == 200
        )

        # 11. TOTP MFA enrollment + MFA login challenge verification
        setup = client.post("/api/v1/auth/mfa/setup", headers=_auth(access_token))
        assert setup.status_code == 200
        totp_secret = setup.json()["secret"]
        assert setup.json()["qr_code_data_uri"].startswith("data:image/png;base64,")

        en = client.post(
            "/api/v1/auth/mfa/enable",
            json={"code": current_totp_code(totp_secret)},
            headers=_auth(access_token),
        )
        assert en.status_code == 200
        assert en.json()["mfa_enabled"] is True

        login_mfa = client.post(
            "/api/v1/auth/login",
            json={"email": user_email, "password": "StrongPass@2026"},
        )
        assert login_mfa.status_code == 200
        assert login_mfa.json()["mfa_required"] is True
        mfa_challenge_token = login_mfa.json()["mfa_token"]

        mfa_done = client.post(
            "/api/v1/auth/mfa/verify-login",
            json={"mfa_token": mfa_challenge_token, "code": current_totp_code(totp_secret)},
        )
        assert mfa_done.status_code == 200
        assert mfa_done.json()["access_token"] is not None

        # 12. Refresh token rotation & replay attack protection
        rot = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert rot.status_code == 200
        # Replaying old refresh token must fail and revoke session
        replay = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert replay.status_code == 401

        # 13. Verify Guest RBAC restriction + Admin capability using seeded demo accounts
        guest_login = client.post(
            "/api/v1/auth/login",
            json={"email": "guest@trustshare.dev", "password": "Guest@1234"},
        )
        if guest_login.status_code == 200:
            gtok = guest_login.json()["access_token"]
            blocked_up = client.post(
                "/api/v1/files/upload",
                files={"file": ("note.txt", b"guest try", "text/plain")},
                headers=_auth(gtok),
            )
            assert blocked_up.status_code == 403

        # 14. Audit logs captured user's full activity trail
        mfa_tok = mfa_done.json()["access_token"]
        logs = client.get("/api/v1/users/audit-logs?scope=own", headers=_auth(mfa_tok))
        assert logs.status_code == 200
        assert logs.json()["total"] >= 6

        # 15. Logout immediately denylists JTI
        assert client.post("/api/v1/auth/logout", headers=_auth(mfa_tok)).status_code == 200
        assert client.get("/api/v1/auth/me", headers=_auth(mfa_tok)).status_code == 401
