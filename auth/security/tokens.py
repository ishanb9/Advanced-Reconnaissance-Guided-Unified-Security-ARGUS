"""JWT access tokens + opaque refresh tokens.

Two-token pattern:

  • Access token  — short-lived (default 15min), JWT, sent on every API
    call.  Stateless: API workers can verify it without a DB lookup.
    Claims: sub (user_id), sid (session_id), tid (tenant_id), iat, exp,
    iss, aud, roles, mfa_at (when last MFA challenge was completed).

  • Refresh token — long-lived (default 14 days), OPAQUE random string,
    only the SHA-256 hash is stored.  Presented to /auth/refresh which
    rotates it: issue new pair, mark old refresh used, revoke family
    if a used token is presented again (theft signal — OAuth 2.1 §6.1).

Both tokens are bound to a Session row in the DB; revoking the session
revokes all tokens for the session.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from jwt import InvalidTokenError, ExpiredSignatureError

from auth.config import CONFIG

logger = logging.getLogger("argus.auth.tokens")


# ─────────────────────────────────────────────────────────────────
#  Access tokens (JWT)
# ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AccessTokenClaims:
    sub:     str                  # user_id
    sid:     str                  # session_id
    tid:     Optional[str]        # tenant_id
    roles:   list[str]
    mfa_at:  Optional[float]      # epoch seconds of last MFA pass
    iat:     int
    exp:     int


def issue_access_token(*, user_id: str, session_id: str,
                       tenant_id: Optional[str],
                       roles: list[str],
                       mfa_at: Optional[datetime] = None,
                       ttl_min: Optional[int] = None) -> str:
    """Issue a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    ttl = ttl_min if ttl_min is not None else CONFIG.jwt_access_ttl_min
    payload: Dict[str, Any] = {
        "iss":   CONFIG.jwt_issuer,
        "aud":   CONFIG.jwt_audience,
        "iat":   int(now.timestamp()),
        "exp":   int((now + timedelta(minutes=ttl)).timestamp()),
        "sub":   user_id,
        "sid":   session_id,
        "tid":   tenant_id,
        "roles": roles or [],
    }
    if mfa_at is not None:
        payload["mfa_at"] = int(mfa_at.timestamp())
    return jwt.encode(payload, CONFIG.jwt_secret, algorithm=CONFIG.jwt_algorithm)


def verify_access_token(token: str) -> AccessTokenClaims:
    """Verify + decode a JWT.  Raises InvalidTokenError on failure."""
    try:
        decoded = jwt.decode(
            token,
            CONFIG.jwt_secret,
            algorithms=[CONFIG.jwt_algorithm],
            audience=CONFIG.jwt_audience,
            issuer=CONFIG.jwt_issuer,
            options={"require": ["iat", "exp", "sub", "sid"]},
        )
    except ExpiredSignatureError:
        raise
    except InvalidTokenError:
        raise

    return AccessTokenClaims(
        sub    = decoded["sub"],
        sid    = decoded["sid"],
        tid    = decoded.get("tid"),
        roles  = list(decoded.get("roles") or []),
        mfa_at = decoded.get("mfa_at"),
        iat    = int(decoded["iat"]),
        exp    = int(decoded["exp"]),
    )


# ─────────────────────────────────────────────────────────────────
#  Refresh tokens (opaque, DB-backed)
# ─────────────────────────────────────────────────────────────────


def generate_refresh_token() -> str:
    """A high-entropy random string returned ONCE to the browser.

    Format: 64 bytes → URL-safe base64 (~86 ASCII chars).  This is
    delivered as an httpOnly Secure cookie; only the SHA-256 hash is
    persisted server-side.
    """
    return secrets.token_urlsafe(64)


def hash_refresh_token(token: str) -> str:
    """SHA-256 of a refresh token, for storage in `refresh_tokens.token_hash`.

    SHA-256 (not argon2) because:
      • Refresh tokens are themselves high-entropy (~512 bits) — no
        dictionary/brute-force advantage to slowing comparison.
      • Refresh ops happen on every API session and need to be fast.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


__all__ = [
    "AccessTokenClaims",
    "issue_access_token",
    "verify_access_token",
    "generate_refresh_token",
    "hash_refresh_token",
    "InvalidTokenError",
    "ExpiredSignatureError",
]
