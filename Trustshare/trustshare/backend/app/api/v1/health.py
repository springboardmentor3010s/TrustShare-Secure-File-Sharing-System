"""System health and multi-datastore connectivity telemetry endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.db.mongo import check_mongo_health
from app.db.postgres import check_postgres_health
from app.db.redis_client import check_redis_health
from app.models.user import User

router = APIRouter(prefix="/health", tags=["System Health"])


@router.get("")
def liveness() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/datastores")
def datastore_telemetry(_user: User = Depends(get_current_user)) -> dict:
    settings = get_settings()
    pg = check_postgres_health()
    mongo = check_mongo_health()
    rd = check_redis_health()

    storage_dir = Path(settings.LOCAL_STORAGE_DIR)
    storage_dir.mkdir(parents=True, exist_ok=True)
    blob_count = sum(1 for p in storage_dir.rglob("*") if p.is_file())

    storage = {
        "service": "object_storage",
        "status": "connected",
        "mode": settings.STORAGE_BACKEND,
        "engine": (
            "Encrypted Local Vault (AWS S3 / Azure Blob adapter ready for M2)"
            if settings.STORAGE_BACKEND == "local"
            else f"Cloud Object Storage ({settings.STORAGE_BACKEND.upper()})"
        ),
        "encryption": (
            f"AES-256-GCM Envelope (KEK v{settings.MASTER_KEK_VERSION}, 64 KiB AEAD chunks)"
            if settings.ENCRYPTION_ENABLED
            else "Disabled"
        ),
        "stored_objects": blob_count,
        "max_upload_mb": settings.MAX_UPLOAD_SIZE_MB,
        "role": "Encrypted File Ciphertext Blobs (raw keys never stored alongside objects)",
    }

    overall = "healthy" if pg["status"] == "connected" else "degraded"
    return {
        "overall": overall,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "datastores": [pg, mongo, rd, storage],
    }
