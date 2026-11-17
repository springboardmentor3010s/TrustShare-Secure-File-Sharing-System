"""
File Management & Secure Upload Module (Module 2 + Module 4 envelope encryption foundation):
(i)   Secure validated upload (magic-byte check, sanitization, quota, SHA-256, chunked AES-256-GCM)
(ii)  File categorization (auto-detected + user-editable category & tags)
(iii) Folder assignment & relocation
(iv)  File search, multi-facet filtering & sorting
(v)   File version management (upload new version, list version timeline, download any version)
(vi)  File metadata management, trash/restore, permanent purge, and dashboard analytics summary
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.rbac import Permission
from app.db.postgres import get_db
from app.models.file import EncryptionKey, FileRecord, FileVersion, Folder
from app.models.share import FilePermission
from app.models.user import User
from app.schemas.file import (
    CategoryBreakdown,
    DashboardSummary,
    FileDetailOut,
    FileListResponse,
    FileOut,
    FileUpdate,
    FileVersionOut,
)
from app.services.audit import log_audit_event
from app.services.storage import (
    UploadValidationError,
    delete_stored_blob,
    sanitize_filename,
    store_uploaded_stream,
    stream_decrypted_blob,
)

router = APIRouter(prefix="/files", tags=["Files & Secure Upload"])


def _can_read_file(db: Session, user: User, record: FileRecord) -> bool:
    if record.owner_id == user.id:
        return True
    if user.role == "admin":
        return True
    perm = db.scalar(
        select(FilePermission).where(
            FilePermission.file_id == record.id,
            FilePermission.grantee_user_id == user.id,
        )
    )
    if perm:
        if perm.expires_at is None or perm.expires_at > datetime.now(timezone.utc):
            return True
    return False


def _enrich_file_out(db: Session, record: FileRecord) -> FileOut:
    out = FileOut.model_validate(record)
    owner = db.get(User, record.owner_id)
    if owner:
        out.owner_name = owner.full_name
        out.owner_email = owner.email
    return out


def _parse_tags(raw_tags: str | None) -> list[str]:
    if not raw_tags:
        return []
    raw_tags = raw_tags.strip()
    if raw_tags.startswith("["):
        try:
            parsed = json.loads(raw_tags)
            if isinstance(parsed, list):
                return [str(t).strip()[:32] for t in parsed if str(t).strip()][:12]
        except json.JSONDecodeError:
            pass
    return [t.strip()[:32] for t in raw_tags.split(",") if t.strip()][:12]


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    user: User = Depends(require_permission(Permission.FILE_READ)),
    db: Session = Depends(get_db),
) -> DashboardSummary:
    # Include own files + explicitly shared files for read-only guests
    if user.role == "guest":
        shared_ids = select(FilePermission.file_id).where(FilePermission.grantee_user_id == user.id)
        base_filter = [FileRecord.id.in_(shared_ids), FileRecord.is_deleted.is_(False)]
    else:
        base_filter = [FileRecord.owner_id == user.id, FileRecord.is_deleted.is_(False)]

    total_files = db.scalar(select(func.count(FileRecord.id)).where(*base_filter)) or 0
    encrypted_files = (
        db.scalar(
            select(func.count(FileRecord.id)).where(*base_filter, FileRecord.is_encrypted.is_(True))
        )
        or 0
    )
    starred_files = (
        db.scalar(
            select(func.count(FileRecord.id)).where(*base_filter, FileRecord.is_starred.is_(True))
        )
        or 0
    )
    trashed_files = (
        db.scalar(
            select(func.count(FileRecord.id)).where(
                FileRecord.owner_id == user.id, FileRecord.is_deleted.is_(True)
            )
        )
        or 0
    )
    total_folders = (
        db.scalar(
            select(func.count(Folder.id)).where(
                Folder.owner_id == user.id, Folder.is_deleted.is_(False)
            )
        )
        or 0
    )
    total_downloads = (
        db.scalar(select(func.coalesce(func.sum(FileRecord.download_count), 0)).where(*base_filter))
        or 0
    )
    total_versions = (
        db.scalar(
            select(func.count(FileVersion.id))
            .join(FileRecord, FileVersion.file_id == FileRecord.id)
            .where(*base_filter)
        )
        or 0
    )

    cat_rows = db.execute(
        select(
            FileRecord.category,
            func.count(FileRecord.id),
            func.coalesce(func.sum(FileRecord.size_bytes), 0),
        )
        .where(*base_filter)
        .group_by(FileRecord.category)
        .order_by(func.sum(FileRecord.size_bytes).desc())
    ).all()

    categories = [
        CategoryBreakdown(category=row[0], count=int(row[1]), size_bytes=int(row[2]))
        for row in cat_rows
    ]

    pct = (
        round((user.storage_used_bytes / user.storage_quota_bytes) * 100, 2)
        if user.storage_quota_bytes > 0
        else 0.0
    )

    return DashboardSummary(
        total_files=int(total_files),
        total_folders=int(total_folders),
        encrypted_files=int(encrypted_files),
        starred_files=int(starred_files),
        trashed_files=int(trashed_files),
        total_versions=int(total_versions),
        total_downloads=int(total_downloads),
        storage_used_bytes=int(user.storage_used_bytes),
        storage_quota_bytes=int(user.storage_quota_bytes),
        storage_used_pct=min(100.0, pct),
        categories=categories,
    )


@router.post("/upload", response_model=FileDetailOut, status_code=status.HTTP_201_CREATED)
def upload_file(
    request: Request,
    file: UploadFile = File(...),
    folder_id: str | None = Form(default=None),
    category: str | None = Form(default=None),
    description: str | None = Form(default=None),
    tags: str | None = Form(default=None),
    user: User = Depends(require_permission(Permission.FILE_UPLOAD)),
    db: Session = Depends(get_db),
) -> FileDetailOut:
    clean_folder_id = folder_id.strip() if folder_id and folder_id.strip() else None
    if clean_folder_id:
        folder = db.get(Folder, clean_folder_id)
        if not folder or folder.owner_id != user.id or folder.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target folder not found.")

    remaining_quota = max(0, user.storage_quota_bytes - user.storage_used_bytes)

    try:
        stored = store_uploaded_stream(
            stream=file.file,
            raw_filename=file.filename,
            client_content_type=file.content_type,
            owner_id=user.id,
            remaining_quota_bytes=remaining_quota,
            override_category=category.strip() if category else None,
        )
    except UploadValidationError as exc:
        log_audit_event(
            action="file.upload_blocked",
            category="security",
            status="blocked",
            severity="warning",
            actor=user,
            resource_type="file",
            resource_name=(file.filename or "unknown")[:200],
            request=request,
            details={"reason_code": exc.reason_code, "message": exc.message},
        )
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    key_id: str | None = None
    if stored.is_encrypted and stored.wrapped_dek and stored.wrap_nonce and stored.stream_base_nonce:
        enc_key = EncryptionKey(
            kek_version=stored.kek_version or 1,
            algorithm="AES-256-GCM-CHUNKED",
            wrapped_dek=stored.wrapped_dek,
            wrap_nonce=stored.wrap_nonce,
            stream_base_nonce=stored.stream_base_nonce,
            chunk_size=stored.chunk_size or 65536,
            status="active",
        )
        db.add(enc_key)
        db.flush()
        key_id = enc_key.id

    record = FileRecord(
        owner_id=user.id,
        folder_id=clean_folder_id,
        name=stored.sanitized_name,
        original_name=(file.filename or stored.sanitized_name)[:255],
        extension=stored.extension,
        mime_type=stored.mime_type,
        category=stored.inferred_category,
        description=description.strip()[:2000] if description else None,
        tags=_parse_tags(tags),
        size_bytes=stored.plaintext_size,
        encrypted_size_bytes=stored.encrypted_size,
        sha256_checksum=stored.sha256_hex,
        current_version=1,
        storage_backend=stored.storage_backend,
        storage_key=stored.storage_key,
        is_encrypted=stored.is_encrypted,
        encryption_key_id=key_id,
    )
    db.add(record)
    db.flush()

    v1 = FileVersion(
        file_id=record.id,
        version_number=1,
        uploaded_by=user.id,
        size_bytes=stored.plaintext_size,
        encrypted_size_bytes=stored.encrypted_size,
        mime_type=stored.mime_type,
        sha256_checksum=stored.sha256_hex,
        storage_backend=stored.storage_backend,
        storage_key=stored.storage_key,
        is_encrypted=stored.is_encrypted,
        encryption_key_id=key_id,
        change_note="Initial upload",
    )
    db.add(v1)
    user.storage_used_bytes += stored.plaintext_size
    db.commit()
    db.refresh(record)

    log_audit_event(
        action="file.uploaded",
        category="file",
        actor=user,
        resource_type="file",
        resource_id=record.id,
        resource_name=record.name,
        request=request,
        details={
            "size_bytes": record.size_bytes,
            "encrypted_size_bytes": record.encrypted_size_bytes,
            "category": record.category,
            "sha256": record.sha256_checksum,
            "is_encrypted": record.is_encrypted,
            "encryption_key_id": key_id,
        },
    )

    detail = FileDetailOut.model_validate(record)
    detail.owner_name = user.full_name
    detail.owner_email = user.email
    return detail


@router.post("/{file_id}/versions", response_model=FileDetailOut, status_code=status.HTTP_201_CREATED)
def upload_new_version(
    file_id: str,
    request: Request,
    file: UploadFile = File(...),
    change_note: str | None = Form(default=None),
    user: User = Depends(require_permission(Permission.FILE_VERSION)),
    db: Session = Depends(get_db),
) -> FileDetailOut:
    record = db.get(FileRecord, file_id)
    if not record or record.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
    if record.owner_id != user.id and user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted.")

    remaining_quota = max(0, user.storage_quota_bytes - user.storage_used_bytes)
    try:
        stored = store_uploaded_stream(
            stream=file.file,
            raw_filename=file.filename or record.name,
            client_content_type=file.content_type,
            owner_id=record.owner_id,
            remaining_quota_bytes=remaining_quota,
            override_category=record.category,
        )
    except UploadValidationError as exc:
        log_audit_event(
            action="file.version_upload_blocked",
            category="security",
            status="blocked",
            severity="warning",
            actor=user,
            resource_type="file",
            resource_id=record.id,
            resource_name=record.name,
            request=request,
            details={"reason_code": exc.reason_code, "message": exc.message},
        )
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    key_id: str | None = None
    if stored.is_encrypted and stored.wrapped_dek and stored.wrap_nonce and stored.stream_base_nonce:
        enc_key = EncryptionKey(
            kek_version=stored.kek_version or 1,
            algorithm="AES-256-GCM-CHUNKED",
            wrapped_dek=stored.wrapped_dek,
            wrap_nonce=stored.wrap_nonce,
            stream_base_nonce=stored.stream_base_nonce,
            chunk_size=stored.chunk_size or 65536,
            status="active",
        )
        db.add(enc_key)
        db.flush()
        key_id = enc_key.id

    next_ver = record.current_version + 1
    ver = FileVersion(
        file_id=record.id,
        version_number=next_ver,
        uploaded_by=user.id,
        size_bytes=stored.plaintext_size,
        encrypted_size_bytes=stored.encrypted_size,
        mime_type=stored.mime_type,
        sha256_checksum=stored.sha256_hex,
        storage_backend=stored.storage_backend,
        storage_key=stored.storage_key,
        is_encrypted=stored.is_encrypted,
        encryption_key_id=key_id,
        change_note=(change_note.strip()[:500] if change_note else f"Version {next_ver}"),
    )
    db.add(ver)

    record.current_version = next_ver
    record.size_bytes = stored.plaintext_size
    record.encrypted_size_bytes = stored.encrypted_size
    record.mime_type = stored.mime_type
    record.sha256_checksum = stored.sha256_hex
    record.storage_key = stored.storage_key
    record.is_encrypted = stored.is_encrypted
    record.encryption_key_id = key_id
    record.updated_at = datetime.now(timezone.utc)

    owner = db.get(User, record.owner_id)
    if owner:
        owner.storage_used_bytes += stored.plaintext_size

    db.commit()
    db.refresh(record)

    log_audit_event(
        action="file.version_uploaded",
        category="file",
        actor=user,
        resource_type="file",
        resource_id=record.id,
        resource_name=record.name,
        request=request,
        details={"version": next_ver, "size_bytes": stored.plaintext_size, "sha256": stored.sha256_hex},
    )

    detail = FileDetailOut.model_validate(record)
    if owner:
        detail.owner_name = owner.full_name
        detail.owner_email = owner.email
    return detail


@router.get("", response_model=FileListResponse)
def list_files(
    q: str | None = Query(default=None, description="Search filename or description"),
    folder_id: str | None = Query(default=None),
    category: str | None = Query(default=None),
    view: str = Query(default="all", pattern="^(all|folder|starred|recent|trash|shared|org)$"),
    sort_by: str = Query(default="updated_at", pattern="^(name|size_bytes|created_at|updated_at|download_count)$"),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require_permission(Permission.FILE_READ)),
    db: Session = Depends(get_db),
) -> FileListResponse:
    stmt = select(FileRecord)

    if view == "org":
        if user.role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")
        stmt = stmt.where(FileRecord.is_deleted.is_(False))
    elif view == "shared" or user.role == "guest":
        shared_ids = select(FilePermission.file_id).where(FilePermission.grantee_user_id == user.id)
        stmt = stmt.where(FileRecord.id.in_(shared_ids), FileRecord.is_deleted.is_(False))
    elif view == "trash":
        stmt = stmt.where(FileRecord.owner_id == user.id, FileRecord.is_deleted.is_(True))
    elif view == "starred":
        stmt = stmt.where(
            FileRecord.owner_id == user.id,
            FileRecord.is_deleted.is_(False),
            FileRecord.is_starred.is_(True),
        )
    elif view == "folder":
        stmt = stmt.where(FileRecord.owner_id == user.id, FileRecord.is_deleted.is_(False))
        if folder_id:
            stmt = stmt.where(FileRecord.folder_id == folder_id)
        else:
            stmt = stmt.where(FileRecord.folder_id.is_(None))
    else:  # all | recent
        stmt = stmt.where(FileRecord.owner_id == user.id, FileRecord.is_deleted.is_(False))
        if folder_id:
            stmt = stmt.where(FileRecord.folder_id == folder_id)

    if category:
        stmt = stmt.where(FileRecord.category == category)

    if q and q.strip():
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                FileRecord.name.ilike(pattern),
                FileRecord.description.ilike(pattern),
                FileRecord.extension.ilike(pattern),
            )
        )

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    sort_col = getattr(FileRecord, sort_by, FileRecord.updated_at)
    stmt = stmt.order_by(sort_col.asc() if sort_dir == "asc" else sort_col.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    rows = db.scalars(stmt).all()
    return FileListResponse(
        items=[_enrich_file_out(db, r) for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.get("/{file_id}", response_model=FileDetailOut)
def get_file_detail(
    file_id: str,
    user: User = Depends(require_permission(Permission.FILE_READ)),
    db: Session = Depends(get_db),
) -> FileDetailOut:
    record = db.get(FileRecord, file_id)
    if not record or not _can_read_file(db, user, record):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
    detail = FileDetailOut.model_validate(record)
    owner = db.get(User, record.owner_id)
    if owner:
        detail.owner_name = owner.full_name
        detail.owner_email = owner.email
    detail.versions = [FileVersionOut.model_validate(v) for v in record.versions]
    return detail


@router.patch("/{file_id}", response_model=FileDetailOut)
def update_file_metadata(
    file_id: str,
    payload: FileUpdate,
    request: Request,
    user: User = Depends(require_permission(Permission.FILE_UPDATE)),
    db: Session = Depends(get_db),
) -> FileDetailOut:
    record = db.get(FileRecord, file_id)
    if not record or record.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
    if record.owner_id != user.id and user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted.")

    changes: dict = {}
    if payload.name is not None:
        safe_name, _ = sanitize_filename(payload.name)
        # Preserve original extension if user omitted it while renaming
        if record.extension and not safe_name.lower().endswith(record.extension):
            safe_name = f"{safe_name}{record.extension}"
        record.name = safe_name
        changes["name"] = safe_name

    if payload.folder_id != "__UNCHANGED__":
        if payload.folder_id:
            target_folder = db.get(Folder, payload.folder_id)
            if not target_folder or target_folder.owner_id != record.owner_id or target_folder.is_deleted:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found.")
            record.folder_id = target_folder.id
        else:
            record.folder_id = None
        changes["folder_id"] = record.folder_id

    if payload.category is not None:
        record.category = payload.category
        changes["category"] = payload.category

    if payload.description is not None:
        record.description = payload.description.strip() or None
        changes["description_updated"] = True

    if payload.tags is not None:
        record.tags = [t.strip()[:32] for t in payload.tags if t.strip()][:12]
        changes["tags"] = record.tags

    if payload.is_starred is not None:
        record.is_starred = payload.is_starred
        changes["is_starred"] = payload.is_starred

    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)

    log_audit_event(
        action="file.metadata_updated",
        category="file",
        actor=user,
        resource_type="file",
        resource_id=record.id,
        resource_name=record.name,
        request=request,
        details=changes,
    )
    return get_file_detail(file_id=record.id, user=user, db=db)


@router.get("/{file_id}/download")
def download_file(
    file_id: str,
    request: Request,
    version: int | None = Query(default=None, ge=1),
    user: User = Depends(require_permission(Permission.FILE_DOWNLOAD)),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    record = db.get(FileRecord, file_id)
    if not record or record.is_deleted or not _can_read_file(db, user, record):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    if version is not None:
        ver = db.scalar(
            select(FileVersion).where(
                FileVersion.file_id == record.id, FileVersion.version_number == version
            )
        )
        if not ver:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File version not found.")
        storage_key = ver.storage_key
        is_encrypted = ver.is_encrypted
        key_id = ver.encryption_key_id
        mime_type = ver.mime_type
        size_bytes = ver.size_bytes
        chosen_version = ver.version_number
    else:
        storage_key = record.storage_key
        is_encrypted = record.is_encrypted
        key_id = record.encryption_key_id
        mime_type = record.mime_type
        size_bytes = record.size_bytes
        chosen_version = record.current_version

    wrapped_dek = wrap_nonce = base_nonce = None
    if is_encrypted and key_id:
        ek = db.get(EncryptionKey, key_id)
        if not ek or ek.status == "revoked":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Encryption key unavailable or revoked.",
            )
        wrapped_dek = ek.wrapped_dek
        wrap_nonce = ek.wrap_nonce
        base_nonce = ek.stream_base_nonce

    record.download_count += 1
    db.commit()

    log_audit_event(
        action="file.downloaded",
        category="file",
        actor=user,
        resource_type="file",
        resource_id=record.id,
        resource_name=record.name,
        request=request,
        details={"version": chosen_version, "decrypted_in_memory": is_encrypted},
    )

    try:
        iterator = stream_decrypted_blob(
            storage_key=storage_key,
            is_encrypted=is_encrypted,
            wrapped_dek=wrapped_dek,
            wrap_nonce=wrap_nonce,
            stream_base_nonce=base_nonce,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stored object missing.")

    encoded_name = quote(record.name)
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
        "Content-Length": str(size_bytes),
        "X-Content-SHA256": record.sha256_checksum,
        "X-TrustShare-Encrypted-At-Rest": str(is_encrypted).lower(),
    }
    return StreamingResponse(iterator, media_type=mime_type, headers=headers)


@router.delete("/{file_id}")
def soft_delete_file(
    file_id: str,
    request: Request,
    permanent: bool = Query(default=False),
    user: User = Depends(require_permission(Permission.FILE_DELETE)),
    db: Session = Depends(get_db),
) -> dict:
    record = db.get(FileRecord, file_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
    if record.owner_id != user.id and user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted.")

    if not permanent and not record.is_deleted:
        record.is_deleted = True
        record.deleted_at = datetime.now(timezone.utc)
        db.commit()
        log_audit_event(
            action="file.trashed",
            category="file",
            actor=user,
            resource_type="file",
            resource_id=record.id,
            resource_name=record.name,
            request=request,
        )
        return {"message": "File moved to Trash."}

    # Permanent cryptographic erasure: delete all encrypted version blobs + key material + reclaim quota
    reclaimed = sum(v.size_bytes for v in record.versions)
    key_ids = [v.encryption_key_id for v in record.versions if v.encryption_key_id]
    blob_keys = [v.storage_key for v in record.versions]
    fname = record.name
    fid = record.id

    owner = db.get(User, record.owner_id)
    db.delete(record)
    db.flush()

    for kid in set(key_ids):
        ek = db.get(EncryptionKey, kid)
        if ek:
            db.delete(ek)

    if owner:
        owner.storage_used_bytes = max(0, owner.storage_used_bytes - reclaimed)

    db.commit()

    for bk in blob_keys:
        delete_stored_blob(bk)

    log_audit_event(
        action="file.permanently_deleted",
        category="file",
        severity="warning",
        actor=user,
        resource_type="file",
        resource_id=fid,
        resource_name=fname,
        request=request,
        details={"reclaimed_bytes": reclaimed, "shredded_keys": len(set(key_ids))},
    )
    return {"message": "File and encryption keys permanently erased.", "reclaimed_bytes": reclaimed}


@router.post("/{file_id}/restore", response_model=FileOut)
def restore_file(
    file_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.FILE_DELETE)),
    db: Session = Depends(get_db),
) -> FileOut:
    record = db.get(FileRecord, file_id)
    if not record or not record.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trashed file not found.")
    if record.owner_id != user.id and user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted.")

    record.is_deleted = False
    record.deleted_at = None
    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)

    log_audit_event(
        action="file.restored",
        category="file",
        actor=user,
        resource_type="file",
        resource_id=record.id,
        resource_name=record.name,
        request=request,
    )
    return _enrich_file_out(db, record)
