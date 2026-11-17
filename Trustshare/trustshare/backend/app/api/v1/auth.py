"""
User Authentication Module (Module 1):
(i)   Registration & login (bcrypt + account status + brute-force Redis rate limiter)
(ii)  Multi-factor authentication (RFC 6238 TOTP enrollment, QR code, login step-up, disable)
(iii) Password recovery (Redis TTL reset token + password rotation + full session invalidation)
(iv)  Session management (PostgreSQL + Redis active sessions, per-device revocation)
(v)   JWT authentication (short-lived access token + rotated refresh token + JTI blocklist)
(vi)  OAuth2 integration (provider discovery & authorization URL flow for Google / GitHub)
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_current_user, to_user_out
from app.core.config import get_settings
from app.core.rbac import ROLE_DEFAULT_QUOTA_MB, Role
from app.core.security import (
    build_totp_uri,
    create_access_token,
    create_refresh_token,
    decode_token,
    decrypt_string_secret,
    encrypt_string_secret,
    generate_qr_data_uri,
    generate_secure_token,
    generate_totp_secret,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
    verify_totp_code,
)
from app.db.postgres import get_db
from app.db.redis_client import (
    blocklist_jti,
    cache_session,
    clear_failed_logins,
    clear_pending_mfa_secret,
    consume_mfa_challenge,
    consume_password_reset,
    get_pending_mfa_secret,
    is_login_rate_limited,
    record_failed_login,
    revoke_cached_session,
    store_mfa_challenge,
    store_password_reset,
    store_pending_mfa_secret,
)
from app.models.user import User, UserSession
from app.schemas.auth import (
    AuthResponse,
    LoginRequest,
    MFACodeRequest,
    MFADisableRequest,
    MFALoginVerifyRequest,
    MFASetupResponse,
    PasswordChangeRequest,
    PasswordForgotRequest,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    SessionOut,
    UserOut,
)
from app.services.audit import get_client_ip, log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication & Sessions"])


def _issue_session_tokens(db: Session, user: User, request: Request) -> AuthResponse:
    settings = get_settings()
    session_id = str(uuid.uuid4())
    refresh_token, refresh_jti, refresh_exp = create_refresh_token(user.id, session_id)
    access_token, _access_jti, access_ttl = create_access_token(
        user.id, user.email, user.role, session_id
    )

    ip_addr = get_client_ip(request)
    ua = request.headers.get("user-agent", "")[:500]
    now = datetime.now(timezone.utc)

    sess = UserSession(
        id=session_id,
        user_id=user.id,
        refresh_jti=refresh_jti,
        ip_address=ip_addr,
        user_agent=ua,
        is_revoked=False,
        expires_at=refresh_exp,
        last_seen_at=now,
    )
    user.last_login_at = now
    user.failed_login_count = 0
    db.add(sess)
    db.commit()
    db.refresh(user)

    cache_session(
        session_id,
        {"user_id": user.id, "role": user.role, "ip": ip_addr},
        ttl_sec=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )

    return AuthResponse(
        mfa_required=False,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=access_ttl,
        user=to_user_out(user),
    )


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AuthResponse:
    email_norm = payload.email.strip().lower()
    existing = db.scalar(select(User).where(User.email == email_norm))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    ok, msg = validate_password_strength(payload.password)
    if not ok:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)

    quota_bytes = ROLE_DEFAULT_QUOTA_MB[Role.MEMBER] * 1024 * 1024
    user = User(
        email=email_norm,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role=Role.MEMBER.value,
        storage_quota_bytes=quota_bytes,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        action="auth.register",
        category="auth",
        actor=user,
        resource_type="user",
        resource_id=user.id,
        resource_name=user.email,
        request=request,
        details={"assigned_role": user.role},
    )
    return _issue_session_tokens(db, user, request)


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AuthResponse:
    email_norm = payload.email.strip().lower()
    ip_addr = get_client_ip(request) or "unknown"
    rl_key = f"{ip_addr}:{email_norm}"

    if is_login_rate_limited(rl_key):
        log_audit_event(
            action="auth.login_rate_limited",
            category="security",
            status="blocked",
            severity="warning",
            actor_email_override=email_norm,
            request=request,
            details={"reason": "too_many_failed_attempts"},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait 5 minutes and try again.",
        )

    user = db.scalar(select(User).where(User.email == email_norm))
    if user is None or not verify_password(payload.password, user.password_hash):
        attempts, limited = record_failed_login(rl_key)
        if user is not None:
            user.failed_login_count += 1
            db.commit()
        log_audit_event(
            action="auth.login_failed",
            category="security",
            status="failure",
            severity="critical" if limited else "warning",
            actor=user,
            actor_email_override=email_norm,
            request=request,
            details={"attempts_in_window": attempts, "rate_limited": limited},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        log_audit_event(
            action="auth.login_disabled_account",
            category="security",
            status="blocked",
            severity="warning",
            actor=user,
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been suspended by an administrator.",
        )

    clear_failed_logins(rl_key)

    # Step-up to TOTP MFA if enabled on account
    if user.mfa_enabled and user.mfa_secret_encrypted:
        raw_challenge = generate_secure_token(32)
        store_mfa_challenge(hash_token(raw_challenge), {"user_id": user.id})
        log_audit_event(
            action="auth.mfa_challenge_issued",
            category="auth",
            actor=user,
            request=request,
        )
        return AuthResponse(mfa_required=True, mfa_token=raw_challenge)

    resp = _issue_session_tokens(db, user, request)
    log_audit_event(
        action="auth.login_success",
        category="auth",
        actor=user,
        request=request,
        details={"mfa_used": False},
    )
    return resp


@router.post("/mfa/verify-login", response_model=AuthResponse)
def verify_mfa_login(
    payload: MFALoginVerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AuthResponse:
    challenge = consume_mfa_challenge(hash_token(payload.mfa_token))
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA challenge expired or invalid. Please log in again.",
        )

    user = db.get(User, challenge["user_id"])
    if not user or not user.is_active or not user.mfa_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA state.")

    secret = decrypt_string_secret(user.mfa_secret_encrypted)
    if not verify_totp_code(secret, payload.code):
        # Allow retry by issuing a fresh short-lived challenge while recording failure
        log_audit_event(
            action="auth.mfa_verify_failed",
            category="security",
            status="failure",
            severity="warning",
            actor=user,
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 6-digit authenticator code. Please sign in and retry.",
        )

    resp = _issue_session_tokens(db, user, request)
    log_audit_event(
        action="auth.login_success",
        category="auth",
        actor=user,
        request=request,
        details={"mfa_used": True},
    )
    return resp


@router.post("/mfa/setup", response_model=MFASetupResponse)
def setup_mfa(user: User = Depends(get_current_user)) -> MFASetupResponse:
    secret = generate_totp_secret()
    store_pending_mfa_secret(user.id, encrypt_string_secret(secret))
    uri = build_totp_uri(secret, user.email)
    qr_uri = generate_qr_data_uri(uri)
    return MFASetupResponse(secret=secret, otpauth_uri=uri, qr_code_data_uri=qr_uri)


@router.post("/mfa/enable", response_model=UserOut)
def enable_mfa(
    payload: MFACodeRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserOut:
    encrypted_pending = get_pending_mfa_secret(user.id)
    if not encrypted_pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active MFA setup found. Call /auth/mfa/setup first.",
        )
    secret = decrypt_string_secret(encrypted_pending)
    if not verify_totp_code(secret, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit verification code.",
        )

    user.mfa_secret_encrypted = encrypted_pending
    user.mfa_enabled = True
    db.commit()
    db.refresh(user)
    clear_pending_mfa_secret(user.id)

    log_audit_event(
        action="auth.mfa_enabled",
        category="security",
        actor=user,
        request=request,
    )
    return to_user_out(user)


@router.post("/mfa/disable", response_model=UserOut)
def disable_mfa(
    payload: MFADisableRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserOut:
    if not user.mfa_enabled or not user.mfa_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled.")
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password.")
    secret = decrypt_string_secret(user.mfa_secret_encrypted)
    if not verify_totp_code(secret, payload.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 6-digit code.")

    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    db.commit()
    db.refresh(user)

    log_audit_event(
        action="auth.mfa_disabled",
        category="security",
        severity="warning",
        actor=user,
        request=request,
    )
    return to_user_out(user)


@router.post("/refresh", response_model=AuthResponse)
def refresh_tokens(
    payload: RefreshRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AuthResponse:
    try:
        decoded = decode_token(payload.refresh_token, expected_type="refresh")
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    session_id = decoded.get("sid", "")
    presented_jti = decoded.get("jti", "")
    sess = db.get(UserSession, session_id)

    if sess is None or sess.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked.")

    # Detect refresh-token replay: if JTI doesn't match, revoke the entire session immediately
    if sess.refresh_jti != presented_jti:
        sess.is_revoked = True
        db.commit()
        revoke_cached_session(session_id)
        log_audit_event(
            action="auth.refresh_token_reuse_detected",
            category="security",
            status="blocked",
            severity="critical",
            request=request,
            details={"session_id": session_id, "user_id": sess.user_id},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token reuse detected; session revoked for safety.",
        )

    user = db.get(User, sess.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account inactive.")

    # Rotate refresh token JTI
    new_refresh, new_rjti, new_exp = create_refresh_token(user.id, sess.id)
    new_access, _, access_ttl = create_access_token(user.id, user.email, user.role, sess.id)
    sess.refresh_jti = new_rjti
    sess.expires_at = new_exp
    sess.last_seen_at = datetime.now(timezone.utc)
    db.commit()

    return AuthResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=access_ttl,
        user=to_user_out(user),
    )


@router.post("/logout")
def logout(
    request: Request,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    remaining_ttl = max(1, ctx.token_exp - int(time.time()))
    blocklist_jti(ctx.jti, remaining_ttl)
    revoke_cached_session(ctx.session_id, remaining_ttl)

    sess = db.get(UserSession, ctx.session_id)
    if sess:
        sess.is_revoked = True
        db.commit()

    log_audit_event(
        action="auth.logout",
        category="auth",
        actor=ctx.user,
        request=request,
        details={"session_id": ctx.session_id},
    )
    return {"message": "Signed out and session revoked."}


@router.get("/me", response_model=UserOut)
def get_me(user: User = Depends(get_current_user)) -> UserOut:
    return to_user_out(user)


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[SessionOut]:
    rows = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == ctx.user.id, UserSession.is_revoked.is_(False))
        .order_by(UserSession.last_seen_at.desc())
    ).all()
    out: list[SessionOut] = []
    for s in rows:
        item = SessionOut.model_validate(s)
        item.is_current = s.id == ctx.session_id
        out.append(item)
    return out


@router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: str,
    request: Request,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    sess = db.get(UserSession, session_id)
    if not sess or sess.user_id != ctx.user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    sess.is_revoked = True
    db.commit()
    revoke_cached_session(session_id)

    log_audit_event(
        action="auth.session_revoked",
        category="security",
        actor=ctx.user,
        resource_type="session",
        resource_id=session_id,
        request=request,
    )
    return {"message": "Session revoked."}


@router.post("/password/change")
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    if not verify_password(payload.current_password, ctx.user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect.",
        )
    ok, msg = validate_password_strength(payload.new_password)
    if not ok:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)

    ctx.user.password_hash = hash_password(payload.new_password)
    # Revoke all OTHER active sessions upon password change
    other_sessions = db.scalars(
        select(UserSession).where(
            UserSession.user_id == ctx.user.id,
            UserSession.id != ctx.session_id,
            UserSession.is_revoked.is_(False),
        )
    ).all()
    for s in other_sessions:
        s.is_revoked = True
        revoke_cached_session(s.id)
    db.commit()

    log_audit_event(
        action="auth.password_changed",
        category="security",
        actor=ctx.user,
        request=request,
        details={"revoked_other_sessions": len(other_sessions)},
    )
    return {"message": "Password updated and other sessions revoked."}


@router.post("/password/forgot")
def forgot_password(
    payload: PasswordForgotRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    """
    Issues a single-use 15-minute password recovery token stored hashed in Redis.
    Returns a uniform message to prevent account enumeration. In development mode (before
    Milestone 3 SMTP/SendGrid integration), includes dev_reset_token for end-to-end testing.
    """
    settings = get_settings()
    email_norm = payload.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email_norm))
    response: dict = {
        "message": "If an account exists for that email, a 15-minute recovery link has been generated."
    }
    if user and user.is_active:
        raw_token = generate_secure_token(32)
        store_password_reset(hash_token(raw_token), user.id)
        log_audit_event(
            action="auth.password_reset_requested",
            category="security",
            severity="info",
            actor=user,
            request=request,
        )
        if settings.APP_ENV == "development":
            response["dev_reset_token"] = raw_token
    return response


@router.post("/password/reset")
def reset_password(
    payload: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    ok, msg = validate_password_strength(payload.new_password)
    if not ok:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)

    user_id = consume_password_reset(hash_token(payload.reset_token))
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid or expired.",
        )

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found.")

    user.password_hash = hash_password(payload.new_password)
    # Revoke all active sessions so compromised credentials lose access immediately
    sessions = db.scalars(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.is_revoked.is_(False))
    ).all()
    for s in sessions:
        s.is_revoked = True
        revoke_cached_session(s.id)
    db.commit()

    log_audit_event(
        action="auth.password_reset_completed",
        category="security",
        severity="warning",
        actor=user,
        request=request,
        details={"revoked_sessions": len(sessions)},
    )
    return {"message": "Password has been reset. Please sign in with your new password."}


@router.get("/oauth/{provider}/authorize")
def oauth_authorize(provider: str) -> dict:
    """Returns OAuth2 provider configuration status and standard authorization URL."""
    settings = get_settings()
    provider_lc = provider.lower()
    state = generate_secure_token(16)

    if provider_lc == "google":
        configured = bool(settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET)
        params = urlencode({
            "client_id": settings.GOOGLE_CLIENT_ID or "CONFIGURE_GOOGLE_CLIENT_ID",
            "redirect_uri": f"{settings.OAUTH_REDIRECT_BASE_URL}/api/v1/auth/oauth/google/callback",
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
        })
        return {
            "provider": "google",
            "configured": configured,
            "authorization_url": f"https://accounts.google.com/o/oauth2/v2/auth?{params}",
            "note": (
                "Ready"
                if configured
                else "Set GOOGLE_CLIENT_ID & GOOGLE_CLIENT_SECRET in .env to enable live Google SSO."
            ),
        }

    if provider_lc == "github":
        configured = bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET)
        params = urlencode({
            "client_id": settings.GITHUB_CLIENT_ID or "CONFIGURE_GITHUB_CLIENT_ID",
            "redirect_uri": f"{settings.OAUTH_REDIRECT_BASE_URL}/api/v1/auth/oauth/github/callback",
            "scope": "read:user user:email",
            "state": state,
        })
        return {
            "provider": "github",
            "configured": configured,
            "authorization_url": f"https://github.com/login/oauth/authorize?{params}",
            "note": (
                "Ready"
                if configured
                else "Set GITHUB_CLIENT_ID & GITHUB_CLIENT_SECRET in .env to enable live GitHub SSO."
            ),
        }

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unsupported OAuth2 provider.")
