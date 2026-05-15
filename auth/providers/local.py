"""Local username/password authentication provider.

Flow:
  1. Look up user by email (or username) in the current tenant.
  2. Constant-time verify password via argon2.
  3. Check account-lockout window.  On Nth failure, lock out for M min.
  4. Detect needs_rehash (argon2 params changed or pepper rotated).
  5. Return AuthResult; routes layer issues the session.

We never reveal whether email exists vs password was wrong — both
return the same generic "invalid credentials" message.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from auth.config import CONFIG
from auth.models import (
    AccountLockout, AuditSeverity, RoleCode,
    User, UserCredentialLocal, UserStatus,
)
from auth.providers.base import AuthError, AuthProvider, AuthResult
from auth.security.passwords import (
    constant_time_dummy_verify, hash_password, verify_password,
)

logger = logging.getLogger("argus.auth.providers.local")


class LocalAuthProvider(AuthProvider):
    name = "local"

    def __init__(self, db: DbSession):
        self.db = db

    # ───────────────────────────────────────────────────────────
    def authenticate(self, *, email: str, password: str,
                     tenant_slug: Optional[str] = None,
                     ip_address: Optional[str] = None) -> AuthResult:
        # Normalize
        email_norm = (email or "").strip().lower()
        if not email_norm or not password:
            constant_time_dummy_verify(password or "x")
            raise AuthError("Invalid credentials.", code="invalid_credentials")

        # Look up
        q = select(User).where(User.email == email_norm)
        if tenant_slug:
            from auth.models import Tenant
            q = q.join(Tenant).where(Tenant.slug == tenant_slug)
        user = self.db.execute(q).scalar_one_or_none()

        # Status checks (also done after password to keep timing constant
        # for the password verify path; here we early-out on hard NO
        # which leaks "user exists" only if the attacker already knew).
        if user is None:
            constant_time_dummy_verify(password)
            raise AuthError("Invalid credentials.", code="invalid_credentials")

        if user.status not in (UserStatus.ACTIVE, UserStatus.INVITED):
            constant_time_dummy_verify(password)
            self._record_failure(user, ip=ip_address, reason=f"status_{user.status.value}")
            raise AuthError("Account not active.", code="account_inactive", http_status=403)

        if self._is_locked_out(user):
            constant_time_dummy_verify(password)
            raise AuthError(
                "Account temporarily locked due to repeated failures. Try again later.",
                code="account_locked", http_status=429,
            )

        # Verify
        cred = user.credential
        if cred is None or not cred.password_hash:
            constant_time_dummy_verify(password)
            # User exists but has no local password — they're SSO-only.
            self._record_failure(user, ip=ip_address, reason="no_local_password")
            raise AuthError(
                "This account uses single sign-on. Please use SSO to log in.",
                code="sso_only", http_status=400,
            )

        ok, needs_rehash = verify_password(
            password, cred.password_hash, cred.pepper_version
        )
        if not ok:
            self._record_failure(user, ip=ip_address, reason="bad_password")
            raise AuthError("Invalid credentials.", code="invalid_credentials")

        # Success — clear lockout counter, transparent rehash on policy change
        self._clear_failures(user)
        if needs_rehash:
            try:
                new_hash, ver = hash_password(password)
                cred.password_hash = new_hash
                cred.pepper_version = ver
                self.db.commit()
            except Exception as e:
                logger.warning("transparent rehash failed for user %s: %s", user.id, e)

        # last_login_at update is done by sessions.create_session() so it
        # only ticks on full SSO completion (after MFA) — keep parity here.
        return AuthResult(
            user=user,
            requires_mfa=user.mfa_enabled or self._mfa_required_by_role(user),
            needs_password_rehash=needs_rehash,
        )

    # ───────────────────────────────────────────────────────────
    def _mfa_required_by_role(self, user: User) -> bool:
        required = set(CONFIG.mfa_required_roles)
        return any(a.role.value in required for a in (user.role_assigns or []))

    def _is_locked_out(self, user: User) -> bool:
        from auth.sessions import _as_aware
        now = datetime.now(timezone.utc)
        for lo in (user.lockouts or []):
            exp = _as_aware(lo.expires_at)
            if lo.lifted_at is None and (exp is None or exp > now):
                if lo.reason in ("brute_force", "admin_lock"):
                    return True
        return False

    def _record_failure(self, user: User, *, ip: Optional[str],
                        reason: str) -> None:
        """Track failed attempts in a sliding window.  On threshold,
        create a real lockout row.
        """
        from auth.sessions import _as_aware
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=CONFIG.lockout_window_min)

        # Find or create the active tracking row
        tracker = None
        for lo in (user.lockouts or []):
            locked = _as_aware(lo.locked_at)
            if (lo.lifted_at is None
                    and lo.reason == "failed_attempts"
                    and locked and locked >= window_start):
                tracker = lo
                break
        if tracker is None:
            tracker = AccountLockout(
                user_id=user.id, reason="failed_attempts",
                locked_at=now, failed_attempt_count=0,
            )
            self.db.add(tracker)
            self.db.flush()

        tracker.failed_attempt_count += 1
        if tracker.failed_attempt_count >= CONFIG.lockout_threshold:
            # Promote to actual lockout
            self.db.add(AccountLockout(
                user_id=user.id, reason="brute_force",
                locked_at=now,
                expires_at=now + timedelta(minutes=CONFIG.lockout_duration_min),
                failed_attempt_count=tracker.failed_attempt_count,
            ))
            tracker.lifted_at = now    # tracker rolled into lockout

        # Emit audit (best-effort) — pass our session so SQLite doesn't
        # deadlock on a nested writer transaction.
        try:
            from auth.audit import audit_log
            audit_log(action="auth.login_failed", actor=user,
                      severity=AuditSeverity.WARN,
                      status="failure", error_message=reason,
                      ip_address=ip, db=self.db)
        except Exception:
            pass

        self.db.commit()

    def _clear_failures(self, user: User) -> None:
        """On successful login, expire all open failed-attempt trackers."""
        now = datetime.now(timezone.utc)
        for lo in (user.lockouts or []):
            if lo.reason == "failed_attempts" and lo.lifted_at is None:
                lo.lifted_at = now
        self.db.commit()


__all__ = ["LocalAuthProvider"]
