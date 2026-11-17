"""Pydantic request/response schemas for Authentication, MFA, Sessions, and RBAC."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class MFALoginVerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=8)


class RefreshRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class PasswordForgotRequest(BaseModel):
    email: EmailStr


class PasswordResetRequest(BaseModel):
    reset_token: str
    new_password: str = Field(min_length=8, max_length=128)


class MFACodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MFADisableRequest(BaseModel):
    password: str
    code: str = Field(min_length=6, max_length=8)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: str
    role: str
    permissions: list[str] = []
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    storage_quota_bytes: int
    storage_used_bytes: int
    last_login_at: datetime | None = None
    created_at: datetime


class AuthResponse(BaseModel):
    mfa_required: bool = False
    mfa_token: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    user: UserOut | None = None


class MFASetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code_data_uri: str


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ip_address: str | None
    user_agent: str | None
    is_revoked: bool
    is_current: bool = False
    expires_at: datetime
    last_seen_at: datetime
    created_at: datetime


class AdminUserUpdateRequest(BaseModel):
    role: str | None = Field(default=None, pattern="^(admin|manager|member|guest)$")
    is_active: bool | None = None
    storage_quota_mb: int | None = Field(default=None, ge=0, le=102400)
