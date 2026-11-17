"""
Idempotent demo data seeder for TrustShare Milestone 1.

Seeds 4 RBAC accounts (Admin, Manager, Member, Guest), nested project folders,
real AES-256-GCM envelope-encrypted sample files (including a multi-version file),
a guest read-only permission grant, and corresponding audit log entries.

Run from backend/:  python -m scripts.seed_demo
"""

from __future__ import annotations

import io
from sqlalchemy import select

import app.models  # noqa: F401
from app.core.rbac import ROLE_DEFAULT_QUOTA_MB, Role
from app.core.security import hash_password
from app.db.mongo import init_mongo
from app.db.postgres import Base, SessionLocal, engine
from app.db.redis_client import init_redis
from app.models.file import EncryptionKey, FileRecord, FileVersion, Folder
from app.models.share import FilePermission
from app.models.user import User
from app.services.audit import log_audit_event
from app.services.storage import store_uploaded_stream

DEMO_USERS = [
    ("admin@trustshare.dev", "Aarav Sen (Admin)", "Admin@1234", Role.ADMIN),
    ("manager@trustshare.dev", "Priya Nair (Manager)", "Manager@1234", Role.MANAGER),
    ("member@trustshare.dev", "Rohan Das (Member)", "Member@1234", Role.MEMBER),
    ("guest@trustshare.dev", "External Auditor (Guest)", "Guest@1234", Role.GUEST),
]


def _seed_encrypted_file(
    db,
    *,
    owner: User,
    folder_id: str | None,
    filename: str,
    content: bytes,
    mime: str,
    description: str,
    tags: list[str],
    starred: bool = False,
    v2_content: bytes | None = None,
    v2_note: str | None = None,
) -> FileRecord:
    existing = db.scalar(
        select(FileRecord).where(
            FileRecord.owner_id == owner.id,
            FileRecord.name == filename,
            FileRecord.is_deleted.is_(False),
        )
    )
    if existing:
        return existing

    stored = store_uploaded_stream(
        stream=io.BytesIO(content),
        raw_filename=filename,
        client_content_type=mime,
        owner_id=owner.id,
        remaining_quota_bytes=owner.storage_quota_bytes - owner.storage_used_bytes,
    )
    ek = EncryptionKey(
        kek_version=stored.kek_version or 1,
        algorithm="AES-256-GCM-CHUNKED",
        wrapped_dek=stored.wrapped_dek or b"",
        wrap_nonce=stored.wrap_nonce or b"",
        stream_base_nonce=stored.stream_base_nonce or b"",
        chunk_size=stored.chunk_size or 65536,
        status="active",
    )
    db.add(ek)
    db.flush()

    rec = FileRecord(
        owner_id=owner.id,
        folder_id=folder_id,
        name=stored.sanitized_name,
        original_name=filename,
        extension=stored.extension,
        mime_type=stored.mime_type,
        category=stored.inferred_category,
        description=description,
        tags=tags,
        size_bytes=stored.plaintext_size,
        encrypted_size_bytes=stored.encrypted_size,
        sha256_checksum=stored.sha256_hex,
        current_version=1,
        storage_backend=stored.storage_backend,
        storage_key=stored.storage_key,
        is_encrypted=stored.is_encrypted,
        encryption_key_id=ek.id,
        is_starred=starred,
    )
    db.add(rec)
    db.flush()

    db.add(
        FileVersion(
            file_id=rec.id,
            version_number=1,
            uploaded_by=owner.id,
            size_bytes=stored.plaintext_size,
            encrypted_size_bytes=stored.encrypted_size,
            mime_type=stored.mime_type,
            sha256_checksum=stored.sha256_hex,
            storage_backend=stored.storage_backend,
            storage_key=stored.storage_key,
            is_encrypted=stored.is_encrypted,
            encryption_key_id=ek.id,
            change_note="Initial baseline draft",
        )
    )
    owner.storage_used_bytes += stored.plaintext_size

    log_audit_event(
        action="file.uploaded",
        category="file",
        actor=owner,
        resource_type="file",
        resource_id=rec.id,
        resource_name=rec.name,
        details={
            "size_bytes": rec.size_bytes,
            "category": rec.category,
            "sha256": rec.sha256_checksum,
            "is_encrypted": True,
        },
    )

    if v2_content is not None:
        s2 = store_uploaded_stream(
            stream=io.BytesIO(v2_content),
            raw_filename=filename,
            client_content_type=mime,
            owner_id=owner.id,
            remaining_quota_bytes=owner.storage_quota_bytes - owner.storage_used_bytes,
        )
        ek2 = EncryptionKey(
            kek_version=s2.kek_version or 1,
            algorithm="AES-256-GCM-CHUNKED",
            wrapped_dek=s2.wrapped_dek or b"",
            wrap_nonce=s2.wrap_nonce or b"",
            stream_base_nonce=s2.stream_base_nonce or b"",
            chunk_size=s2.chunk_size or 65536,
            status="active",
        )
        db.add(ek2)
        db.flush()
        db.add(
            FileVersion(
                file_id=rec.id,
                version_number=2,
                uploaded_by=owner.id,
                size_bytes=s2.plaintext_size,
                encrypted_size_bytes=s2.encrypted_size,
                mime_type=s2.mime_type,
                sha256_checksum=s2.sha256_hex,
                storage_backend=s2.storage_backend,
                storage_key=s2.storage_key,
                is_encrypted=s2.is_encrypted,
                encryption_key_id=ek2.id,
                change_note=v2_note or "Updated revision",
            )
        )
        rec.current_version = 2
        rec.size_bytes = s2.plaintext_size
        rec.encrypted_size_bytes = s2.encrypted_size
        rec.sha256_checksum = s2.sha256_hex
        rec.storage_key = s2.storage_key
        rec.encryption_key_id = ek2.id
        owner.storage_used_bytes += s2.plaintext_size

        log_audit_event(
            action="file.version_uploaded",
            category="file",
            actor=owner,
            resource_type="file",
            resource_id=rec.id,
            resource_name=rec.name,
            details={"version": 2, "size_bytes": s2.plaintext_size, "sha256": s2.sha256_hex},
        )

    return rec


def seed() -> None:
    Base.metadata.create_all(bind=engine)
    init_mongo()
    init_redis()

    with SessionLocal() as db:
        users_by_role: dict[Role, User] = {}
        for email, full_name, password, role in DEMO_USERS:
            u = db.scalar(select(User).where(User.email == email))
            if not u:
                u = User(
                    email=email,
                    full_name=full_name,
                    password_hash=hash_password(password),
                    role=role.value,
                    storage_quota_bytes=ROLE_DEFAULT_QUOTA_MB[role] * 1024 * 1024,
                )
                db.add(u)
                db.flush()
                log_audit_event(
                    action="auth.account_provisioned",
                    category="admin",
                    actor=u,
                    resource_type="user",
                    resource_id=u.id,
                    resource_name=u.email,
                    details={"role": role.value, "seeded": True},
                )
            users_by_role[role] = u

        admin = users_by_role[Role.ADMIN]
        member = users_by_role[Role.MEMBER]
        guest = users_by_role[Role.GUEST]

        # Seed folders for Admin
        folder_specs = [
            ("Security Policies", "indigo"),
            ("Financial Reports Q4", "emerald"),
            ("Architecture & Specs", "amber"),
            ("Client Contracts", "rose"),
        ]
        folders: dict[str, Folder] = {}
        for fname, color in folder_specs:
            f = db.scalar(
                select(Folder).where(
                    Folder.owner_id == admin.id, Folder.name == fname, Folder.is_deleted.is_(False)
                )
            )
            if not f:
                f = Folder(owner_id=admin.id, name=fname, color=color)
                db.add(f)
                db.flush()
            folders[fname] = f

        # Seed encrypted demo files for Admin
        policy_doc = _seed_encrypted_file(
            db,
            owner=admin,
            folder_id=folders["Security Policies"].id,
            filename="TrustShare-Zero-Trust-Access-Policy.md",
            content=(
                b"# TrustShare Access Control & Encryption Policy (v1.0)\n\n"
                b"- Every uploaded object is encrypted server-side with a unique 256-bit AES-GCM DEK.\n"
                b"- DEKs are wrapped with the root KEK before persistence.\n"
            ),
            v2_content=(
                b"# TrustShare Access Control & Encryption Policy (v2.0 - Approved)\n\n"
                b"1. **Envelope Encryption:** Unique 256-bit AES-256-GCM DEK per file version (64 KiB AEAD chunks).\n"
                b"2. **RBAC Tiers:** Admin, Manager, Member, and read-only External Guest.\n"
                b"3. **Authentication:** bcrypt (cost 12), short-lived JWT + rotating refresh JTI, optional RFC 6238 TOTP MFA.\n"
                b"4. **Auditability:** All auth, upload, download, and RBAC events logged immutably.\n"
            ),
            v2_note="Added chunked AEAD specification and RBAC enforcement rules",
            mime="text/markdown",
            description="Approved security governance, envelope key handling, and RBAC policy.",
            tags=["security", "aes-256", "policy", "approved"],
            starred=True,
        )

        _seed_encrypted_file(
            db,
            owner=admin,
            folder_id=folders["Financial Reports Q4"].id,
            filename="Q4-2026-Cloud-Storage-Budget.csv",
            content=(
                b"service,tier,monthly_estimate_usd,encryption,owner\n"
                b"AWS S3,Standard-IA,142.50,AES-256-GCM Envelope,Platform Team\n"
                b"PostgreSQL RDS,db.t4g.medium,68.00,TLS + KMS Volume,Backend Team\n"
                b"MongoDB Atlas,M10,57.00,WiredTiger Encrypted,Security Team\n"
                b"Redis Cache,cache.t4g.small,24.00,In-Transit TLS,Auth Team\n"
            ),
            mime="text/csv",
            description="Projected monthly cloud infrastructure cost breakdown for Milestone 4 deployment.",
            tags=["finance", "q4-2026", "cloud", "aws"],
            starred=True,
        )

        _seed_encrypted_file(
            db,
            owner=admin,
            folder_id=folders["Architecture & Specs"].id,
            filename="database-retention-config.json",
            content=(
                b'{\n'
                b'  "platform": "TrustShare",\n'
                b'  "encryption": {"cipher": "AES-256-GCM", "chunk_kib": 64, "envelope_kek_version": 1},\n'
                b'  "retention_days": {"trash": 30, "audit_logs": 365, "revoked_sessions": 90},\n'
                b'  "share_defaults": {"max_expiry_days": 14, "require_tls": true}\n'
                b'}\n'
            ),
            mime="application/json",
            description="Retention windows and encryption defaults across PostgreSQL, MongoDB, and Redis.",
            tags=["architecture", "config", "retention"],
        )

        minimal_pdf = (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
            b"4 0 obj<</Length 58>>stream\nBT /F1 14 Tf 72 720 Td (TrustShare Compliance Brief) Tj ET\nendstream endobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n"
            b"0000000101 00000 n \n0000000173 00000 n \ntrailer<</Size 5/Root 1 0 R>>\nstartxref\n282\n%%EOF\n"
        )
        compliance_pdf = _seed_encrypted_file(
            db,
            owner=admin,
            folder_id=None,
            filename="ISO27001-Compliance-Readiness-Brief.pdf",
            content=minimal_pdf,
            mime="application/pdf",
            description="Executive summary of controls verified during Milestone 1 security review.",
            tags=["compliance", "iso27001", "executive"],
            starred=False,
        )

        # Also seed one file for Member so logging in as Member shows active workspace
        _seed_encrypted_file(
            db,
            owner=member,
            folder_id=None,
            filename="Sprint-1-Collaboration-Notes.md",
            content=(
                b"# Sprint 1 Team Notes\n\n"
                b"- Completed auth + RBAC integration tests.\n"
                b"- Verified magic-byte executable rejection on upload endpoint.\n"
            ),
            mime="text/markdown",
            description="Engineering handoff notes for Milestone 1 evaluation.",
            tags=["sprint-1", "engineering"],
            starred=True,
        )

        # Grant Guest read/download access to the policy doc & compliance PDF
        for shared_file in (policy_doc, compliance_pdf):
            existing_perm = db.scalar(
                select(FilePermission).where(
                    FilePermission.file_id == shared_file.id,
                    FilePermission.grantee_user_id == guest.id,
                )
            )
            if not existing_perm:
                db.add(
                    FilePermission(
                        file_id=shared_file.id,
                        grantee_user_id=guest.id,
                        granted_by=admin.id,
                        permission="download",
                    )
                )

        db.commit()
        print("Seeded TrustShare demo users, folders, AES-256-GCM encrypted files, and audit logs.")


if __name__ == "__main__":
    seed()
