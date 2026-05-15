"""Environment-based configuration for the ARGUS auth module.

Every tunable is exposed as an env var with a sensible default for
local dev.  Production deployments override these via env or a secret
manager.  No secrets are baked into the codebase.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from typing import List


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _int(name: str, default: int) -> int:
    v = os.environ.get(name)
    try:
        return int(v) if v is not None else default
    except ValueError:
        return default


def _list(name: str, default: List[str]) -> List[str]:
    v = os.environ.get(name)
    if not v:
        return list(default)
    return [x.strip() for x in v.split(",") if x.strip()]


@dataclass(frozen=True)
class AuthConfig:
    # ── Database ────────────────────────────────────────────────
    database_url: str = os.environ.get(
        "AUTH_DATABASE_URL", "sqlite:///argus_auth.db"
    )
    db_pool_size: int = _int("AUTH_DB_POOL_SIZE", 10)
    db_max_overflow: int = _int("AUTH_DB_MAX_OVERFLOW", 20)

    # ── JWT signing ─────────────────────────────────────────────
    # In production, set AUTH_JWT_SECRET to a long random string.
    # If unset in dev, we generate a per-process secret — this will
    # invalidate sessions on restart, which is the safe dev behavior.
    jwt_secret: str = os.environ.get("AUTH_JWT_SECRET") or secrets.token_urlsafe(64)
    jwt_algorithm: str = os.environ.get("AUTH_JWT_ALGORITHM", "HS256")
    jwt_access_ttl_min: int = _int("AUTH_JWT_ACCESS_TTL_MIN", 15)
    jwt_refresh_ttl_days: int = _int("AUTH_JWT_REFRESH_TTL_DAYS", 14)
    jwt_issuer: str = os.environ.get("AUTH_JWT_ISSUER", "argus")
    jwt_audience: str = os.environ.get("AUTH_JWT_AUDIENCE", "argus-api")

    # ── Sessions ────────────────────────────────────────────────
    session_idle_timeout_hours: int = _int("AUTH_SESSION_IDLE_TIMEOUT_HOURS", 12)
    session_max_lifetime_hours: int = _int("AUTH_SESSION_MAX_LIFETIME_HOURS", 168)
    session_cookie_name: str = os.environ.get("AUTH_SESSION_COOKIE", "argus_session")
    refresh_cookie_name: str = os.environ.get("AUTH_REFRESH_COOKIE", "argus_refresh")
    cookie_secure: bool = _bool("AUTH_COOKIE_SECURE", True)
    cookie_samesite: str = os.environ.get("AUTH_COOKIE_SAMESITE", "lax")
    cookie_domain: str = os.environ.get("AUTH_COOKIE_DOMAIN", "")
    cookie_path: str = os.environ.get("AUTH_COOKIE_PATH", "/")

    # ── Argon2 password hashing (RFC 9106 §4 recommended) ───────
    argon2_time_cost: int = _int("AUTH_ARGON2_TIME_COST", 3)
    argon2_memory_cost: int = _int("AUTH_ARGON2_MEMORY_COST", 64 * 1024)  # KiB
    argon2_parallelism: int = _int("AUTH_ARGON2_PARALLELISM", 4)
    # Per-deployment pepper layered on top of per-user salt; rotation
    # supported via PASSWORD_PEPPER + PASSWORD_PEPPER_OLD.
    password_pepper: str = os.environ.get("AUTH_PASSWORD_PEPPER", "")
    password_min_length: int = _int("AUTH_PASSWORD_MIN_LENGTH", 12)
    password_max_length: int = _int("AUTH_PASSWORD_MAX_LENGTH", 256)

    # ── MFA ─────────────────────────────────────────────────────
    # Roles for which MFA enrolment is REQUIRED before any session
    # can be issued.  Owner + admin by default; can also include
    # SECURITY_MANAGER for high-security tenants.
    mfa_required_roles: List[str] = field(default_factory=lambda: _list(
        "AUTH_MFA_REQUIRED_FOR", ["OWNER", "PLATFORM_ADMIN"]
    ))
    totp_issuer: str = os.environ.get("AUTH_TOTP_ISSUER", "ARGUS")
    totp_digits: int = _int("AUTH_TOTP_DIGITS", 6)
    totp_period_sec: int = _int("AUTH_TOTP_PERIOD_SEC", 30)
    totp_skew_steps: int = _int("AUTH_TOTP_SKEW_STEPS", 1)
    backup_code_count: int = _int("AUTH_BACKUP_CODE_COUNT", 10)

    # ── Account lockout ─────────────────────────────────────────
    lockout_threshold: int = _int("AUTH_LOCKOUT_THRESHOLD", 5)
    lockout_duration_min: int = _int("AUTH_LOCKOUT_DURATION_MIN", 15)
    # Sliding window over which failed attempts are counted
    lockout_window_min: int = _int("AUTH_LOCKOUT_WINDOW_MIN", 15)

    # ── Audit log ───────────────────────────────────────────────
    audit_max_rows: int = _int("AUTH_AUDIT_MAX_ROWS", 1_000_000)
    audit_max_age_days: int = _int("AUTH_AUDIT_MAX_AGE_DAYS", 730)
    audit_export_before_delete: bool = _bool("AUTH_AUDIT_EXPORT_BEFORE_DELETE", True)
    audit_export_dir: str = os.environ.get("AUTH_AUDIT_EXPORT_DIR", "audit_archive/")
    audit_hash_chain: bool = _bool("AUTH_AUDIT_HASH_CHAIN", False)

    # ── SCIM ────────────────────────────────────────────────────
    scim_token_ttl_days: int = _int("AUTH_SCIM_TOKEN_TTL_DAYS", 365)
    scim_default_role: str = os.environ.get("AUTH_SCIM_DEFAULT_ROLE", "ANALYST")
    scim_page_size: int = _int("AUTH_SCIM_PAGE_SIZE", 100)

    # ── Initial owner (CI/CD bootstrap) ─────────────────────────
    initial_owner_email: str = os.environ.get("AUTH_INITIAL_OWNER_EMAIL", "")
    initial_owner_password: str = os.environ.get("AUTH_INITIAL_OWNER_PASSWORD", "")

    # ── Misc ────────────────────────────────────────────────────
    # When true, sensitive endpoints (admin/*, audit/*) require the
    # user to have completed a recent MFA challenge (re-auth window).
    reauth_required_for_sensitive: bool = _bool("AUTH_REAUTH_REQUIRED", True)
    reauth_window_min: int = _int("AUTH_REAUTH_WINDOW_MIN", 5)

    # Env tag — used in audit log and shown in admin UI
    deployment_env: str = os.environ.get("AUTH_DEPLOYMENT_ENV", "dev")

    # Whether to print initial owner credentials to stderr on
    # auto-bootstrap.  ONLY for dev; ignored when deployment_env=prod.
    print_bootstrap_credentials: bool = _bool(
        "AUTH_PRINT_BOOTSTRAP_CREDENTIALS", True
    )


# Module-level singleton
CONFIG = AuthConfig()
