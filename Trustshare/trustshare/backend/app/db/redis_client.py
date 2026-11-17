"""
Redis client & ephemeral security state store:
- Active session cache (ts:sess:{session_id})
- Revoked JWT JTI blocklist (ts:jwt:deny:{jti})
- Login brute-force rate limiter (ts:rl:login:{subject})
- Short-lived MFA pre-auth challenges (ts:mfa:{token_hash})
- Short-lived password recovery tokens (ts:pwdreset:{token_hash})

Falls back safely to an in-process TTL cache only if Redis is temporarily unreachable,
while always preferring real Redis.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import redis

from app.core.config import get_settings

_redis_client: redis.Redis | None = None
_redis_live: bool = False
_redis_version: str | None = None

_mem_lock = threading.Lock()
_mem_store: dict[str, tuple[str, float]] = {}


def init_redis() -> bool:
    global _redis_client, _redis_live, _redis_version
    settings = get_settings()
    try:
        client = redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1.5,
            socket_timeout=2.0,
        )
        info = client.info("server")
        _redis_client = client
        _redis_live = True
        _redis_version = info.get("redis_version", "unknown")
        return True
    except Exception:
        _redis_live = False
        _redis_version = None
        return False


def _set(key: str, value: str, ttl_sec: int) -> None:
    if _redis_live and _redis_client is not None:
        try:
            _redis_client.set(key, value, ex=max(1, ttl_sec))
            return
        except Exception:
            pass
    with _mem_lock:
        _mem_store[key] = (value, time.time() + max(1, ttl_sec))


def _get(key: str) -> str | None:
    if _redis_live and _redis_client is not None:
        try:
            return _redis_client.get(key)
        except Exception:
            pass
    with _mem_lock:
        entry = _mem_store.get(key)
        if not entry:
            return None
        val, exp = entry
        if time.time() > exp:
            _mem_store.pop(key, None)
            return None
        return val


def _delete(key: str) -> None:
    if _redis_live and _redis_client is not None:
        try:
            _redis_client.delete(key)
            return
        except Exception:
            pass
    with _mem_lock:
        _mem_store.pop(key, None)


# --- JWT Denylist ---

def blocklist_jti(jti: str, ttl_sec: int) -> None:
    _set(f"ts:jwt:deny:{jti}", "1", max(1, ttl_sec))


def is_jti_blocklisted(jti: str) -> bool:
    return _get(f"ts:jwt:deny:{jti}") is not None


# --- Session Cache ---

def cache_session(session_id: str, data: dict[str, Any], ttl_sec: int) -> None:
    _set(f"ts:sess:{session_id}", json.dumps(data), ttl_sec)


def revoke_cached_session(session_id: str, ttl_sec: int = 3600) -> None:
    _delete(f"ts:sess:{session_id}")
    _set(f"ts:sess:revoked:{session_id}", "1", ttl_sec)


def is_session_revoked_in_cache(session_id: str) -> bool:
    return _get(f"ts:sess:revoked:{session_id}") is not None


# --- Brute-Force Login Rate Limiter ---

def record_failed_login(key_suffix: str) -> tuple[int, bool]:
    """Increments failure count for IP/email and returns (attempts, is_rate_limited)."""
    settings = get_settings()
    key = f"ts:rl:login:{key_suffix}"
    window = settings.LOGIN_RATE_LIMIT_WINDOW_SEC
    limit = settings.LOGIN_RATE_LIMIT_ATTEMPTS

    if _redis_live and _redis_client is not None:
        try:
            pipe = _redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window, nx=True)
            count, _ = pipe.execute()
            return int(count), int(count) >= limit
        except Exception:
            pass

    raw = _get(key)
    count = (int(raw) if raw else 0) + 1
    _set(key, str(count), window)
    return count, count >= limit


def is_login_rate_limited(key_suffix: str) -> bool:
    settings = get_settings()
    raw = _get(f"ts:rl:login:{key_suffix}")
    return raw is not None and int(raw) >= settings.LOGIN_RATE_LIMIT_ATTEMPTS


def clear_failed_logins(key_suffix: str) -> None:
    _delete(f"ts:rl:login:{key_suffix}")


# --- Short-Lived MFA Challenge & Password Reset Tokens ---

def store_mfa_challenge(token_hash: str, payload: dict[str, Any]) -> None:
    settings = get_settings()
    _set(f"ts:mfa:{token_hash}", json.dumps(payload), settings.MFA_CHALLENGE_TTL_SEC)


def consume_mfa_challenge(token_hash: str) -> dict[str, Any] | None:
    key = f"ts:mfa:{token_hash}"
    raw = _get(key)
    if not raw:
        return None
    _delete(key)
    return json.loads(raw)


def store_password_reset(token_hash: str, user_id: str) -> None:
    settings = get_settings()
    _set(f"ts:pwdreset:{token_hash}", user_id, settings.PASSWORD_RESET_TTL_SEC)


def consume_password_reset(token_hash: str) -> str | None:
    key = f"ts:pwdreset:{token_hash}"
    user_id = _get(key)
    if not user_id:
        return None
    _delete(key)
    return user_id


def store_pending_mfa_secret(user_id: str, encrypted_secret: str) -> None:
    _set(f"ts:mfa:setup:{user_id}", encrypted_secret, 600)


def get_pending_mfa_secret(user_id: str) -> str | None:
    return _get(f"ts:mfa:setup:{user_id}")


def clear_pending_mfa_secret(user_id: str) -> None:
    _delete(f"ts:mfa:setup:{user_id}")


# --- Health Check ---

def check_redis_health() -> dict[str, Any]:
    start = time.perf_counter()
    if _redis_live and _redis_client is not None:
        try:
            _redis_client.ping()
            dbsize = _redis_client.dbsize()
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "service": "redis",
                "status": "connected",
                "mode": "primary",
                "engine": f"Redis {_redis_version}",
                "latency_ms": latency_ms,
                "active_keys": dbsize,
                "role": "Sessions, JWT Revocation Denylist, MFA Challenges & Login Rate Limiting",
            }
        except Exception:
            pass
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    return {
        "service": "redis",
        "status": "fallback_active",
        "mode": "in_memory_ttl_fallback",
        "engine": "In-process TTL store (Redis unreachable)",
        "latency_ms": latency_ms,
        "active_keys": len(_mem_store),
        "role": "Sessions, JWT Revocation Denylist, MFA Challenges & Login Rate Limiting",
    }
