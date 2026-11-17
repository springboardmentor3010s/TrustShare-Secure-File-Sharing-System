"""Admin User Management, RBAC assignment, and Audit Log endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_permission, to_user_out
from app.core.rbac import (
    ROLE_DEFAULT_QUOTA_MB,
    Permission,
    Role,
    get_permissions_for_role,
    has_permission,
)
from app.db.mongo import check_mongo_health, query_documents
from app.db.postgres import get_db
from app.db.redis_client import revoke_cached_session
from app.models.user import User, UserSession
from app.schemas.auth import AdminUserUpdateRequest, UserOut
from app.schemas.file import AuditLogListResponse
from app.services.audit import log_audit_event

router = APIRouter(prefix="/users", tags=["Users, RBAC & Audit"])


@router.get("/roles/matrix")
def role_permission_matrix(_user: User = Depends(get_current_user)) -> dict:
    return {
        "roles": [
            {
                "role": r.value,
                "default_quota_mb": ROLE_DEFAULT_QUOTA_MB[r],
                "permissions": get_permissions_for_role(r),
            }
            for r in [Role.ADMIN, Role.MANAGER, Role.MEMBER, Role.GUEST]
        ]
    }


@router.get("", response_model=list[UserOut])
def list_users(
    _actor: User = Depends(require_permission(Permission.USER_READ_ALL)),
    db: Session = Depends(get_db),
) -> list[UserOut]:
    users = db.scalars(select(User).order_by(User.created_at.asc())).all()
    return [to_user_out(u) for u in users]


@router.patch("/{user_id}", response_model=UserOut)
def admin_update_user(
    user_id: str,
    payload: AdminUserUpdateRequest,
    request: Request,
    admin: User = Depends(require_permission(Permission.USER_MANAGE_ROLES)),
    db: Session = Depends(get_db),
) -> UserOut:
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    changes: dict = {}

    if payload.role is not None and payload.role != target.role:
        if target.id == admin.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot demote their own account.",
            )
        changes["old_role"] = target.role
        changes["new_role"] = payload.role
        target.role = payload.role
        if payload.storage_quota_mb is None:
            target.storage_quota_bytes = ROLE_DEFAULT_QUOTA_MB[Role(payload.role)] * 1024 * 1024

    if payload.is_active is not None and payload.is_active != target.is_active:
        if target.id == admin.id and not payload.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot suspend their own account.",
            )
        changes["is_active"] = payload.is_active
        target.is_active = payload.is_active
        if not payload.is_active:
            # Immediately terminate active sessions on suspension
            sessions = db.scalars(
                select(UserSession).where(
                    UserSession.user_id == target.id, UserSession.is_revoked.is_(False)
                )
            ).all()
            for s in sessions:
                s.is_revoked = True
                revoke_cached_session(s.id)

    if payload.storage_quota_mb is not None:
        new_quota = payload.storage_quota_mb * 1024 * 1024
        changes["storage_quota_mb"] = payload.storage_quota_mb
        target.storage_quota_bytes = new_quota

    db.commit()
    db.refresh(target)

    if changes:
        log_audit_event(
            action="admin.user_updated",
            category="admin",
            severity="warning" if "new_role" in changes or changes.get("is_active") is False else "info",
            actor=admin,
            resource_type="user",
            resource_id=target.id,
            resource_name=target.email,
            request=request,
            details=changes,
        )

    return to_user_out(target)


@router.get("/audit-logs", response_model=AuditLogListResponse)
def list_audit_logs(
    category: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    scope: str = Query(default="own", pattern="^(own|all)$"),
    limit: int = Query(default=50, ge=1, le=200),
    skip: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
) -> AuditLogListResponse:
    filters: dict = {}
    if category:
        filters["category"] = category
    if status_filter:
        filters["status"] = status_filter
    if severity:
        filters["severity"] = severity

    if scope == "all":
        if not has_permission(user.role, Permission.AUDIT_READ_ALL):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Admin and Manager roles can inspect organization-wide audit logs.",
            )
    else:
        filters["actor_id"] = user.id

    items, total = query_documents("audit_logs", filters=filters, limit=limit, skip=skip)
    mongo_info = check_mongo_health()
    return AuditLogListResponse(items=items, total=total, datastore_mode=mongo_info["mode"])
