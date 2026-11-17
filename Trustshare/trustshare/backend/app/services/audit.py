"""Structured audit & security event logger backed by MongoDB."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from app.db.mongo import insert_document
from app.models.user import User


def get_client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def log_audit_event(
    *,
    action: str,
    category: str,
    status: str = "success",
    severity: str = "info",
    actor: User | None = None,
    actor_email_override: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    resource_name: str | None = None,
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    doc: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now,
        "actor_id": actor.id if actor else None,
        "actor_email": actor.email if actor else actor_email_override,
        "actor_role": actor.role if actor else None,
        "action": action,
        "category": category,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "status": status,
        "severity": severity,
        "ip_address": get_client_ip(request),
        "user_agent": (request.headers.get("user-agent", "")[:300] if request else None),
        "request_id": (getattr(request.state, "request_id", None) if request else None),
        "details": details or {},
    }
    insert_document("audit_logs", doc)

    # Mirror high-signal failures & security blocks into security_events collection
    if severity in {"warning", "critical"} or status in {"blocked", "failure"}:
        sec_doc = {**doc, "resolved": False}
        insert_document("security_events", sec_doc)

    return doc
