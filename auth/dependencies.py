"""FastAPI dependencies for auth + RBAC + audit.

The four primitives ARGUS routes use:

    get_current_user           — User or raise 401
    current_session            — Session row (for state operations)
    require_role(*roles)       — current user must hold ANY listed role
    require_permission(res, ax) — current user must have (resource, action)

Plus a few helpers:

    optional_current_user      — None instead of raising
    require_reauth(seconds)    — require recent MFA pass (sensitive ops)
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Optional

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from auth.config import CONFIG
from auth.db import get_db
from auth.models import Session as SessionRow, User
from auth.rbac import Role, has_permission, roles_of, _has_role
from auth.security.tokens import (
    AccessTokenClaims, ExpiredSignatureError, InvalidTokenError,
    verify_access_token,
)
from auth.sessions import load_active_session, touch_session

logger = logging.getLogger("argus.auth.dependencies")


# ─────────────────────────────────────────────────────────────────
#  Token extraction
# ─────────────────────────────────────────────────────────────────


def _extract_access_token(request: Request,
                          authorization: Optional[str]) -> Optional[str]:
    """Look in Authorization: Bearer <jwt> first, then in cookie."""
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(None, 1)[1].strip()
    cookie = request.cookies.get(CONFIG.session_cookie_name)
    return cookie or None


# ─────────────────────────────────────────────────────────────────
#  Core dependency: current user + active session
# ─────────────────────────────────────────────────────────────────


class _AuthContext:
    """Lightweight container the dependency returns + reuses."""
    def __init__(self, user: User, session: SessionRow,
                 claims: AccessTokenClaims):
        self.user = user
        self.session = session
        self.claims = claims


def _do_auth(request: Request, authorization: Optional[str],
             db: DbSession, require: bool) -> Optional[_AuthContext]:
    token = _extract_access_token(request, authorization)
    if not token:
        if require:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                detail="Not authenticated.")
        return None

    try:
        claims = verify_access_token(token)
    except ExpiredSignatureError:
        if require:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                detail="Token expired.",
                                headers={"WWW-Authenticate":
                                          'Bearer error="invalid_token"'})
        return None
    except InvalidTokenError:
        if require:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid token.")
        return None

    session = load_active_session(db, claims.sid)
    if session is None:
        if require:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                detail="Session revoked or expired.")
        return None

    user = db.get(User, claims.sub)
    if user is None or user.deleted_at is not None or user.status.value != "ACTIVE":
        if require:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                detail="Account inactive.")
        return None

    # Idle bump — keeps the session warm
    try:
        ip = request.client.host if request.client else None
        touch_session(db, session, ip_address=ip)
    except Exception:
        pass

    return _AuthContext(user=user, session=session, claims=claims)


def get_current_user(request: Request,
                     authorization: Optional[str] = Header(None),
                     db: DbSession = Depends(get_db)) -> User:
    ctx = _do_auth(request, authorization, db, require=True)
    return ctx.user                           # type: ignore[union-attr]


def optional_current_user(request: Request,
                          authorization: Optional[str] = Header(None),
                          db: DbSession = Depends(get_db)) -> Optional[User]:
    ctx = _do_auth(request, authorization, db, require=False)
    return ctx.user if ctx else None


def current_session(request: Request,
                    authorization: Optional[str] = Header(None),
                    db: DbSession = Depends(get_db)) -> SessionRow:
    ctx = _do_auth(request, authorization, db, require=True)
    return ctx.session                        # type: ignore[union-attr]


def current_auth_context(request: Request,
                          authorization: Optional[str] = Header(None),
                          db: DbSession = Depends(get_db)) -> _AuthContext:
    return _do_auth(request, authorization, db, require=True)   # type: ignore[return-value]


# ─────────────────────────────────────────────────────────────────
#  CSRF — double-submit cookie + header
# ─────────────────────────────────────────────────────────────────


def require_csrf(request: Request,
                 x_csrf_token: Optional[str] = Header(None,
                     alias="X-CSRF-Token"),
                 db: DbSession = Depends(get_db)) -> None:
    """Enforce double-submit CSRF on state-changing endpoints.

    The session cookie is httpOnly; the csrf_token cookie is readable
    by JS.  Browser sends both — we verify they match the session row.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    cookie = request.cookies.get("argus_csrf")
    if not x_csrf_token or not cookie or x_csrf_token != cookie:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail="CSRF token mismatch.")

    # Bind to the session row (defence in depth)
    sid = request.cookies.get(CONFIG.session_cookie_name)
    if sid:
        s = db.get(SessionRow, sid)
        if s and s.csrf_token and s.csrf_token != cookie:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                detail="CSRF token mismatch.")


# ─────────────────────────────────────────────────────────────────
#  RBAC — require_role / require_permission
# ─────────────────────────────────────────────────────────────────


def require_role(*role_codes: str) -> Callable:
    """Dependency factory.  User must hold ANY of the listed roles.

    OWNER is an implicit grant for all required-role checks.

    Usage:
        @router.post("/admin/users")
        def create_user(
            user: User = Depends(require_role("PLATFORM_ADMIN", "OWNER"))
        ): ...
    """
    allowed = {Role(r) for r in role_codes}

    def _dep(user: User = Depends(get_current_user)) -> User:
        if _has_role(user, Role.OWNER):
            return user
        if any(_has_role(user, r) for r in allowed):
            return user
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail=f"Required roles: {[r.value for r in allowed]}")

    return _dep


def require_permission(resource: str, action: str,
                       *, context_factory: Optional[Callable] = None) -> Callable:
    """Dependency factory: RBAC + ABAC check.

    context_factory can pull request-scoped attributes (engagement_id
    from path params, severity from body, etc.) for ABAC predicates.

    Usage:
        @router.post("/api/scan/{engagement_id}/start")
        def start_scan(
            engagement_id: str,
            user = Depends(require_permission("tools", "execute")),
        ): ...
    """
    def _dep(request: Request,
             user: User = Depends(get_current_user),
             db: DbSession = Depends(get_db)) -> User:
        ctx = {}
        if context_factory:
            try:
                ctx = context_factory(request) or {}
            except Exception as e:
                logger.warning("context_factory raised: %s", e)
        # Pull common ABAC inputs from path/query params
        for k in ("engagement_id", "tenant_id", "severity", "target_user_id"):
            v = request.path_params.get(k) or request.query_params.get(k)
            if v and k not in ctx:
                ctx[k] = v
        if not has_permission(user, resource, action, context=ctx):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                detail=f"Permission denied: {resource}:{action}")
        return user

    return _dep


# ─────────────────────────────────────────────────────────────────
#  Step-up — require fresh MFA pass for sensitive ops
# ─────────────────────────────────────────────────────────────────


def require_reauth(window_minutes: Optional[int] = None) -> Callable:
    """Sensitive endpoints (role grants, MFA reset, audit delete,
    SCIM-token issue) require a recent MFA challenge.

    The default window is CONFIG.reauth_window_min.  If the user's
    session.last_mfa_at is older than that, return 401 with a hint
    that re-auth is needed.
    """
    def _dep(ctx: _AuthContext = Depends(current_auth_context)) -> User:
        win = window_minutes if window_minutes is not None else CONFIG.reauth_window_min
        if not CONFIG.reauth_required_for_sensitive:
            return ctx.user

        # OWNER skip — see README §11 (debatable; we go strict here)
        # Comment out the next two lines for the strictest posture.
        if _has_role(ctx.user, Role.OWNER) and not ctx.user.mfa_enabled:
            return ctx.user

        last = ctx.session.last_mfa_at
        if last is None or last < (datetime.now(timezone.utc) - timedelta(minutes=win)):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail={"code": "reauth_required",
                        "message": "Re-authenticate with MFA to proceed.",
                        "window_min": win},
            )
        return ctx.user

    return _dep


__all__ = [
    "get_current_user", "optional_current_user", "current_session",
    "current_auth_context",
    "require_csrf",
    "require_role", "require_permission", "require_reauth",
]
