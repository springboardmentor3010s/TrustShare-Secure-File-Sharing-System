"""
Cryptographic and authentication primitives for TrustShare:
- bcrypt password hashing & strength policy validation
- Signed JWT access & refresh tokens with unique JTI (revocable via Redis)
- RFC 6238 TOTP Multi-Factor Authentication (compatible with Google Authenticator / Authy)
- QR code data-URI generator for MFA enrollment
- Envelope AES-256-GCM wrapping for sensitive secrets (per-file DEKs and MFA secrets)
- Cryptographically secure URL-safe tokens + SHA-256 token hashing
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import bcrypt
import jwt
import qrcode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings


# ---------------------------------------------------------------------------
# Password hashing & policy
# ---------------------------------------------------------------------------

PASSWORD_POLICY_MSG = (
    "Password must be at least 8 characters and include uppercase, lowercase, "
    "a digit, and a special character."
)


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, PASSWORD_POLICY_MSG
    if len(password) > 128:
        return False, "Password must not exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, PASSWORD_POLICY_MSG
    if not re.search(r"[a-z]", password):
        return False, PASSWORD_POLICY_MSG
    if not re.search(r"\d", password):
        return False, PASSWORD_POLICY_MSG
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, PASSWORD_POLICY_MSG
    return True, "ok"


def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# JWT Access & Refresh Tokens
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: str,
    email: str,
    role: str,
    session_id: str,
    expires_minutes: int | None = None,
) -> tuple[str, str, int]:
    """Returns (encoded_jwt, jti, ttl_seconds)."""
    settings = get_settings()
    ttl_min = expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl_min)
    jti = uuid.uuid4().hex
    payload: dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "role": role,
        "sid": session_id,
        "jti": jti,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, jti, ttl_min * 60


def create_refresh_token(
    user_id: str,
    session_id: str,
    expires_days: int | None = None,
) -> tuple[str, str, datetime]:
    """Returns (encoded_jwt, refresh_jti, expires_at)."""
    settings = get_settings()
    ttl_days = expires_days or settings.REFRESH_TOKEN_EXPIRE_DAYS
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=ttl_days)
    jti = uuid.uuid4().hex
    payload: dict[str, Any] = {
        "sub": user_id,
        "sid": session_id,
        "jti": jti,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, jti, exp


def decode_token(token: str, expected_type: str | None = None) -> dict[str, Any]:
    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
    if expected_type and payload.get("type") != expected_type:
        raise jwt.InvalidTokenError(f"Expected '{expected_type}' token.")
    return payload


# ---------------------------------------------------------------------------
# Secure Opaque Tokens (Share Links, MFA Challenges, Password Reset)
# ---------------------------------------------------------------------------

def generate_secure_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Root KEK & Envelope AES-256-GCM Secret Wrapping
# ---------------------------------------------------------------------------

def get_master_kek() -> bytes:
    settings = get_settings()
    raw = base64.b64decode(settings.MASTER_KEK_B64)
    if len(raw) != 32:
        # Derive exact 256-bit key deterministically if user configured a passphrase
        return hashlib.sha256(raw).digest()
    return raw


def wrap_key(raw_key: bytes, aad: bytes = b"trustshare:dek:v1") -> tuple[bytes, bytes]:
    """Encrypts a 256-bit DEK (or TOTP secret) under the root KEK using AES-256-GCM."""
    kek = get_master_kek()
    nonce = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(nonce, raw_key, aad)
    return wrapped, nonce


def unwrap_key(wrapped_key: bytes, nonce: bytes, aad: bytes = b"trustshare:dek:v1") -> bytes:
    """Decrypts a wrapped DEK (or TOTP secret) using the root KEK."""
    kek = get_master_kek()
    return AESGCM(kek).decrypt(nonce, wrapped_key, aad)


def encrypt_string_secret(plaintext: str) -> str:
    wrapped, nonce = wrap_key(plaintext.encode("utf-8"), aad=b"trustshare:mfa:v1")
    return base64.b64encode(nonce + wrapped).decode("ascii")


def decrypt_string_secret(encoded: str) -> str:
    blob = base64.b64decode(encoded)
    nonce, wrapped = blob[:12], blob[12:]
    return unwrap_key(wrapped, nonce, aad=b"trustshare:mfa:v1").decode("utf-8")


# ---------------------------------------------------------------------------
# RFC 6238 TOTP Multi-Factor Authentication
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_at(secret_b32: str, counter: int, digits: int = 6) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def current_totp_code(secret_b32: str, timestamp: float | None = None) -> str:
    ts = int(timestamp if timestamp is not None else time.time())
    return _totp_at(secret_b32, ts // 30)


def verify_totp_code(secret_b32: str, code: str, window: int = 1) -> bool:
    cleaned = code.strip().replace(" ", "")
    if not (len(cleaned) == 6 and cleaned.isdigit()):
        return False
    counter = int(time.time()) // 30
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_totp_at(secret_b32, counter + delta), cleaned):
            return True
    return False


def build_totp_uri(secret_b32: str, email: str, issuer: str = "TrustShare") -> str:
    label = quote(f"{issuer}:{email}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def generate_qr_data_uri(data: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"
