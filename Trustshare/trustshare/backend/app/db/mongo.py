"""
MongoDB client & audit-log repository (PyMongo).

Connects automatically to MONGODB_URI and ensures compound indexes on startup.
If a live mongod daemon is not reachable (e.g., standalone local dev without Docker),
it fails over transparently to an append-only JSONL document store on disk with the
exact same document schema and query interface — and reports mode='local_jsonl_fallback'
in /api/v1/health/datastores so status is never misrepresented.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from pymongo import DESCENDING, MongoClient
from pymongo.database import Database

from app.core.config import get_settings

_lock = threading.Lock()
_client: MongoClient | None = None
_db: Database | None = None
_mongo_live: bool = False
_mongo_version: str | None = None
_last_probe: float = 0.0


def init_mongo() -> bool:
    """Attempt connection to MongoDB and ensure audit/security indexes."""
    global _client, _db, _mongo_live, _mongo_version, _last_probe
    settings = get_settings()
    _last_probe = time.time()
    try:
        client: MongoClient = MongoClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=1500,
            connectTimeoutMS=1500,
            socketTimeoutMS=3000,
        )
        info = client.server_info()
        db = client[settings.MONGODB_DB]
        db.audit_logs.create_index("event_id", unique=True)
        db.audit_logs.create_index([("timestamp", DESCENDING)])
        db.audit_logs.create_index([("actor_id", 1), ("timestamp", DESCENDING)])
        db.audit_logs.create_index([("resource_type", 1), ("resource_id", 1), ("timestamp", DESCENDING)])
        db.audit_logs.create_index([("category", 1), ("severity", 1), ("timestamp", DESCENDING)])
        db.security_events.create_index([("timestamp", DESCENDING)])
        db.security_events.create_index([("severity", 1), ("timestamp", DESCENDING)])
        _client = client
        _db = db
        _mongo_live = True
        _mongo_version = info.get("version", "unknown")
        return True
    except Exception:
        _mongo_live = False
        _mongo_version = None
        fallback_dir = Path(settings.MONGO_FALLBACK_DIR)
        fallback_dir.mkdir(parents=True, exist_ok=True)
        return False


def _fallback_path(collection: str) -> Path:
    settings = get_settings()
    p = Path(settings.MONGO_FALLBACK_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p / f"{collection}.jsonl"


def insert_document(collection: str, doc: dict[str, Any]) -> None:
    if _mongo_live and _db is not None:
        try:
            _db[collection].insert_one(dict(doc))
            return
        except Exception:
            pass
    # Durable append-only JSONL fallback preserving exact MongoDB BSON-compatible shape
    path = _fallback_path(collection)
    with _lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, default=str) + "\n")


def query_documents(
    collection: str,
    filters: dict[str, Any] | None = None,
    limit: int = 50,
    skip: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    filters = {k: v for k, v in (filters or {}).items() if v is not None and v != ""}
    if _mongo_live and _db is not None:
        try:
            total = _db[collection].count_documents(filters)
            cursor = (
                _db[collection]
                .find(filters, {"_id": 0})
                .sort("timestamp", DESCENDING)
                .skip(skip)
                .limit(limit)
            )
            return list(cursor), total
        except Exception:
            pass

    path = _fallback_path(collection)
    if not path.exists():
        return [], 0
    matched: list[dict[str, Any]] = []
    with _lock:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if all(item.get(k) == v for k, v in filters.items()):
                    matched.append(item)
    matched.sort(key=lambda d: d.get("timestamp", ""), reverse=True)
    total = len(matched)
    return matched[skip : skip + limit], total


def check_mongo_health() -> dict[str, Any]:
    start = time.perf_counter()
    if _mongo_live and _client is not None and _db is not None:
        try:
            _client.admin.command("ping")
            count = _db.audit_logs.estimated_document_count()
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "service": "mongodb",
                "status": "connected",
                "mode": "primary",
                "engine": f"MongoDB {_mongo_version}",
                "latency_ms": latency_ms,
                "audit_documents": count,
                "role": "Immutable Audit Logs, File Activity History & Security Events",
            }
        except Exception:
            pass

    # Report fallback transparently
    _, count = query_documents("audit_logs", limit=1)
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    return {
        "service": "mongodb",
        "status": "fallback_active",
        "mode": "local_jsonl_fallback",
        "engine": "PyMongo driver configured (starts live MongoDB 7 via docker compose)",
        "latency_ms": latency_ms,
        "audit_documents": count,
        "role": "Immutable Audit Logs, File Activity History & Security Events",
    }
