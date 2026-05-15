"""DB-backed session manager.

A session row + a 1:1 session_state row + 1:N refresh-token rows survive
ARGUS reboots, browser closes, and even device switches — every state-
changing user action becomes part of the persistent audit trail.

Why DB-backed rather than pure JWT:
  • Immediate revocation (terminate from admin UI without waiting for
    short-lived JWT to expire).
  • Live "Active sessions" list per user — security review surface.
  • Tamper-evident: the session_id is the source of truth, not the JWT.
  • Survives JWT-secret rotation if we choose to keep sessions alive.

The frontend is given:
  • short-lived JWT access token (Authorization header)
  • opaque refresh token (httpOnly Secure cookie)
  • session cookie carrying the session_id (httpOnly Secure)
  • CSRF cookie carrying the csrf_token (readable by JS; double-submit)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from auth.config import CONFIG
from auth.models import (
    RefreshToken, Session as SessionRow, SessionState, User,
)
from auth.security.tokens import (
    generate_refresh_token, hash_refresh_token, issue_access_token,
)

logger = logging.getLogger("argus.auth.sessions")


def _as_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize DB-returned datetimes to tz-aware UTC.

    SQLite has no native datetime + tz column, so SQLAlchemy returns
    naive `datetime` instances even when columns are declared
    `DateTime(timezone=True)`.  PostgreSQL returns tz-aware values.
    This helper makes comparisons work on both.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ─────────────────────────────────────────────────────────────────
#  Return type
# ─────────────────────────────────────────────────────────────────


@dataclass
class IssuedSession:
    """Bundle returned by create_session() — what the route hands back
    to the browser (cookies + access token).
    """
    session: SessionRow
    access_token: str
    refresh_token_plain: str
    csrf_token: str

    @property
    def access_ttl_seconds(self) -> int:
        return CONFIG.jwt_access_ttl_min * 60

    @property
    def refresh_ttl_seconds(self) -> int:
        return CONFIG.jwt_refresh_ttl_days * 86400


# ─────────────────────────────────────────────────────────────────
#  Lifecycle
# ─────────────────────────────────────────────────────────────────


def create_session(db: DbSession, *,
                   user: User,
                   ip_address: Optional[str],
                   user_agent: Optional[str],
                   tenant_id: Optional[str] = None,
                   mfa_passed: bool = False) -> IssuedSession:
    """Create a brand-new session for a freshly-authenticated user.

    Issues:
      • SessionRow + 1:1 SessionState
      • Access token (JWT)
      • Refresh token (returned plaintext exactly once)
    """
    now = datetime.now(timezone.utc)
    idle_ttl = timedelta(hours=CONFIG.session_idle_timeout_hours)
    absolute_ttl = timedelta(hours=CONFIG.session_max_lifetime_hours)

    s = SessionRow(
        user_id=user.id,
        ip_address=ip_address,
        ip_address_seen=ip_address,
        user_agent=user_agent,
        created_at=now,
        last_seen_at=now,
        expires_at=now + idle_ttl,
        absolute_expires_at=now + absolute_ttl,
        current_tenant_id=tenant_id or user.tenant_id,
        last_mfa_at=now if mfa_passed else None,
    )
    db.add(s)
    db.flush()

    state = SessionState(session_id=s.id, state={})
    db.add(state)

    # Issue refresh token
    family_id = s.id      # initial family == session.id
    plain_refresh = generate_refresh_token()
    rt = RefreshToken(
        session_id=s.id,
        family_id=family_id,
        token_hash=hash_refresh_token(plain_refresh),
        expires_at=now + timedelta(days=CONFIG.jwt_refresh_ttl_days),
    )
    db.add(rt)
    db.flush()

    # Issue access token
    from auth.rbac import roles_of           # local import: cycle break
    access = issue_access_token(
        user_id=user.id,
        session_id=s.id,
        tenant_id=s.current_tenant_id,
        roles=[r.value for r in roles_of(user)],
        mfa_at=s.last_mfa_at,
    )

    db.commit()
    return IssuedSession(s, access, plain_refresh, s.csrf_token)


def touch_session(db: DbSession, session_row: SessionRow,
                  *, ip_address: Optional[str] = None) -> None:
    """Update last_seen_at + sliding idle expiry on every request.

    Bumps `expires_at` to now + idle_timeout but never past the
    absolute_expires_at hard cap.
    """
    now = datetime.now(timezone.utc)
    new_expiry = now + timedelta(hours=CONFIG.session_idle_timeout_hours)
    abs_exp = _as_aware(session_row.absolute_expires_at)
    if abs_exp and new_expiry > abs_exp:
        new_expiry = abs_exp
    session_row.last_seen_at = now
    session_row.expires_at = new_expiry
    if ip_address and ip_address != session_row.ip_address_seen:
        session_row.ip_address_seen = ip_address
    db.commit()


def load_active_session(db: DbSession, session_id: str) -> Optional[SessionRow]:
    """Return the session if active (not revoked + not expired)."""
    s = db.get(SessionRow, session_id)
    if not s:
        return None
    if s.revoked_at is not None:
        return None
    now = datetime.now(timezone.utc)
    exp = _as_aware(s.expires_at)
    abs_exp = _as_aware(s.absolute_expires_at)
    if (exp and exp <= now) or (abs_exp and abs_exp <= now):
        return None
    return s


def revoke_session(db: DbSession, session_id: str, *,
                   reason: str = "logout") -> None:
    """Mark session and all its refresh tokens revoked."""
    s = db.get(SessionRow, session_id)
    if s is None or s.revoked_at is not None:
        return
    now = datetime.now(timezone.utc)
    s.revoked_at = now
    s.revoked_reason = reason
    for rt in (s.refresh_tokens or []):
        if rt.revoked_at is None:
            rt.revoked_at = now
            rt.revoked_reason = reason
    db.commit()


def revoke_all_user_sessions(db: DbSession, user_id: str, *,
                              reason: str = "admin_terminate",
                              except_session_id: Optional[str] = None) -> int:
    """Revoke every active session of a user.  Returns count revoked."""
    now = datetime.now(timezone.utc)
    rows = db.execute(
        select(SessionRow).where(
            SessionRow.user_id == user_id,
            SessionRow.revoked_at.is_(None),
        )
    ).scalars().all()
    n = 0
    for s in rows:
        if except_session_id and s.id == except_session_id:
            continue
        s.revoked_at = now
        s.revoked_reason = reason
        for rt in (s.refresh_tokens or []):
            if rt.revoked_at is None:
                rt.revoked_at = now
                rt.revoked_reason = reason
        n += 1
    db.commit()
    return n


def list_active_sessions(db: DbSession, user_id: str) -> List[SessionRow]:
    return db.execute(
        select(SessionRow).where(
            SessionRow.user_id == user_id,
            SessionRow.revoked_at.is_(None),
            SessionRow.expires_at > datetime.now(timezone.utc),
        ).order_by(SessionRow.last_seen_at.desc())
    ).scalars().all()


# ─────────────────────────────────────────────────────────────────
#  Refresh-token rotation with theft detection
# ─────────────────────────────────────────────────────────────────


def rotate_refresh_token(db: DbSession, *,
                          presented_token: str) -> Optional[IssuedSession]:
    """Rotate a refresh token.

    Returns a new (access + refresh) pair OR None on failure.

    Theft detection: if the presented token's hash matches a token row
    that ALREADY has `used_at` set, treat as theft — revoke the whole
    family (chain of all rotations from that initial login).
    """
    th = hash_refresh_token(presented_token)
    rt = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == th)
    ).scalar_one_or_none()
    if rt is None:
        return None

    now = datetime.now(timezone.utc)
    s = db.get(SessionRow, rt.session_id)
    if s is None or s.revoked_at is not None:
        return None
    s_exp = _as_aware(s.expires_at)
    if s_exp and s_exp <= now:
        return None

    if rt.revoked_at is not None:
        return None
    rt_exp = _as_aware(rt.expires_at)
    if rt_exp and rt_exp <= now:
        return None

    if rt.used_at is not None:
        # Token reuse → theft response: revoke family + session
        logger.warning("refresh token reuse detected on session %s family %s",
                       s.id, rt.family_id)
        _revoke_family(db, rt.family_id, reason="refresh_reuse_detected")
        revoke_session(db, s.id, reason="refresh_reuse_detected")
        return None

    # Happy path — mark old used, issue new
    rt.used_at = now

    new_plain = generate_refresh_token()
    new_rt = RefreshToken(
        session_id=s.id,
        family_id=rt.family_id,
        token_hash=hash_refresh_token(new_plain),
        expires_at=now + timedelta(days=CONFIG.jwt_refresh_ttl_days),
    )
    db.add(new_rt)

    # Sliding idle bump on session
    touch_session(db, s)

    from auth.rbac import roles_of           # local import: cycle break
    user = db.get(User, s.user_id)
    access = issue_access_token(
        user_id=user.id,
        session_id=s.id,
        tenant_id=s.current_tenant_id,
        roles=[r.value for r in roles_of(user)],
        mfa_at=s.last_mfa_at,
    )
    db.commit()
    return IssuedSession(s, access, new_plain, s.csrf_token)


def _revoke_family(db: DbSession, family_id: str, *, reason: str) -> None:
    now = datetime.now(timezone.utc)
    rows = db.execute(
        select(RefreshToken).where(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        )
    ).scalars().all()
    for rt in rows:
        rt.revoked_at = now
        rt.revoked_reason = reason


# ─────────────────────────────────────────────────────────────────
#  Session state — UI persistence
# ─────────────────────────────────────────────────────────────────


def get_state(db: DbSession, session_id: str) -> Dict[str, Any]:
    st = db.get(SessionState, session_id)
    return (st.state or {}) if st else {}


def patch_state(db: DbSession, session_id: str,
                patch: Dict[str, Any]) -> Dict[str, Any]:
    """Shallow-merge `patch` into the persisted state for the session.

    The frontend writes through localStorage + PATCHes here so state
    survives reload, tab close, and reboot.
    """
    st = db.get(SessionState, session_id)
    if st is None:
        st = SessionState(session_id=session_id, state={})
        db.add(st)
    merged = dict(st.state or {})
    merged.update(patch or {})
    # Pull out the "pinned pentest session" reference into its column
    # for quick admin queries.
    pinned = merged.get("pinned_pentest_session_id")
    if pinned and isinstance(pinned, str):
        st.pinned_pentest_session_id = pinned
    st.state = merged
    db.commit()
    return merged


# ─────────────────────────────────────────────────────────────────
#  Sweep — periodic cleanup of expired sessions
# ─────────────────────────────────────────────────────────────────


def sweep_expired(db: DbSession) -> Tuple[int, int]:
    """Mark all idle-expired or absolute-expired sessions revoked.

    Run from a background task on a 5-minute cadence.  Returns
    (sessions_revoked, tokens_revoked).
    """
    # SA serializes the tz-aware datetime to the same ISO format SQLite
    # stored on insert, so DB-side comparisons work even when the
    # returned Python values are naive.
    now = datetime.now(timezone.utc)
    expired = db.execute(
        select(SessionRow).where(
            SessionRow.revoked_at.is_(None),
            (SessionRow.expires_at <= now) |
            (SessionRow.absolute_expires_at <= now),
        )
    ).scalars().all()
    n_sess = 0
    n_tok = 0
    for s in expired:
        s.revoked_at = now
        s.revoked_reason = "expired"
        for rt in (s.refresh_tokens or []):
            if rt.revoked_at is None:
                rt.revoked_at = now
                rt.revoked_reason = "expired"
                n_tok += 1
        n_sess += 1
    db.commit()
    return n_sess, n_tok


__all__ = [
    "IssuedSession",
    "create_session",
    "touch_session",
    "load_active_session",
    "revoke_session",
    "revoke_all_user_sessions",
    "list_active_sessions",
    "rotate_refresh_token",
    "get_state",
    "patch_state",
    "sweep_expired",
]
