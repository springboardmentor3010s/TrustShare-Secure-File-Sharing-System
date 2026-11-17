"""FastAPI authentication & RBAC dependencies."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.rbac import Permission, get_permissions_for_role, has_permission
from app.core.security import decode_token
from app.db.postgres import get_db
from app.db.redis_client import is_jti_blocklisted, is_session_revoked_in_cache
from app.models.user import User, UserSession
from app.schemas.auth import UserOut
from app.services.audit import log_audit_event

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class AuthContext:
    user: User
    session_id: str
    jti: str
    token_exp: int


def to_user_out(user: User) -> UserOut:
    data = UserOut.model_validate(user)
    data.permissions = get_permissions_for_role(user.role)
    return data


def get_auth_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(credentials.credentials, expected_type="access")
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti", "")
    session_id = payload.get("sid", "")
    user_id = payload.get("sub", "")

    if is_jti_blocklisted(jti) or is_session_revoked_in_cache(session_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked. Please sign in again.",
        )

    # Double-check Postgres session status for defense in depth
    sess = db.get(UserSession, session_id)
    if sess is None or sess.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is no longer active.",
        )

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled or unavailable.",
        )

    return AuthContext(
        user=user,
        session_id=session_id,
        jti=jti,
        token_exp=int(payload.get("exp", 0)),
    )


def get_current_user(ctx: AuthContext = Depends(get_auth_context)) -> User:
    return ctx.user


def require_permission(permission: Permission) -> Callable[..., User]:
    def _checker(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        if not has_permission(user.role, permission):
            log_audit_event(
                action="rbac.access_denied",
                category="security",
                status="blocked",
                severity="warning",
                actor=user,
                request=request,
                details={
                    "required_permission": permission.value,
                    "user_role": user.role,
                    "path": request.url.path,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' lacks required permission '{permission.value}'.",
            )
        return user

    return _checker
