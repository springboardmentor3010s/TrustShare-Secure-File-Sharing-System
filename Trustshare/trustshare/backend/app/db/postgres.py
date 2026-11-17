"""PostgreSQL connection, SQLAlchemy 2.0 declarative base, session dependency, and live health probe."""

from __future__ import annotations

import time
from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings

settings = get_settings()

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
engine_kwargs: dict[str, Any] = {"pool_pre_ping": True}
if _is_sqlite:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update({"pool_size": 10, "max_overflow": 20, "pool_recycle": 1800})

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_postgres_health() -> dict[str, Any]:
    start = time.perf_counter()
    try:
        with engine.connect() as conn:
            if _is_sqlite:
                ver = conn.execute(text("SELECT sqlite_version()")).scalar()
                engine_name = f"SQLite {ver}"
            else:
                ver = conn.execute(text("SHOW server_version")).scalar()
                engine_name = f"PostgreSQL {ver}"
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "service": "postgresql",
            "status": "connected",
            "mode": "primary",
            "engine": engine_name,
            "latency_ms": latency_ms,
            "role": "Users, RBAC, File Metadata, Versions, Wrapped DEKs, Share ACLs",
        }
    except Exception as exc:
        return {
            "service": "postgresql",
            "status": "error",
            "mode": "unavailable",
            "error": str(exc),
            "role": "Users, RBAC, File Metadata, Versions, Wrapped DEKs, Share ACLs",
        }
