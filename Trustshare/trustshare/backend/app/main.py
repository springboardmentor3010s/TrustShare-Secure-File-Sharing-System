"""
TrustShare FastAPI Backend Application Entrypoint.
Includes security headers, request correlation IDs, CORS, and automatic startup
checks for PostgreSQL, MongoDB, and Redis.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

import app.models  # noqa: F401
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.db.mongo import init_mongo
from app.db.postgres import Base, engine
from app.db.redis_client import init_redis

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Path(settings.LOCAL_STORAGE_DIR).mkdir(parents=True, exist_ok=True)
    # Ensure ORM tables exist (Alembic migrations manage versioned upgrades in production)
    Base.metadata.create_all(bind=engine)
    init_mongo()
    init_redis()
    yield


app = FastAPI(
    title="TrustShare — Secure File-Sharing & Collaboration API",
    description=(
        "Server-side AES-256-GCM envelope-encrypted file sharing, RBAC authentication, "
        "multi-factor TOTP, versioning, and immutable audit logging."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Content-SHA256", "X-TrustShare-Encrypted-At-Rest"],
)


@app.middleware("http")
async def security_headers_and_request_id(request: Request, call_next):
    req_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"])
def root() -> dict:
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": f"{settings.API_V1_PREFIX}/health",
    }
