"""SQLAlchemy 2.0 ORM models for the ARGUS auth module.

Models live in dependency order so foreign keys resolve cleanly:

    Tenant ─ Owns users, engagements, IdPs, SCIM tokens
      │
      ├─ User
      │   ├─ UserCredentialLocal (1:1)  ← Argon2 hash + pepper version
      │   ├─ UserRoleAssignment  (M:N → Tenant)
      │   ├─ UserMfaFactor       (1:N)  ← TOTP / WebAuthn
      │   ├─ MfaBackupCode       (1:N)
      │   ├─ UserIdentity        (1:N)  ← SSO linkage (OIDC/SAML sub)
      │   ├─ Session             (1:N)
      │   │   ├─ SessionState   (1:1)  ← UI state survives reload/reboot
      │   │   └─ RefreshToken   (1:N)
      │   ├─ AuditLog           (1:N)  ← user_id may be NULL for sys actions
      │   ├─ PasswordResetToken (1:N)
      │   └─ AccountLockout     (1:N)
      │
      ├─ IdentityProvider  (per-tenant OIDC/SAML config)
      ├─ ScimBearerToken   (per-tenant SCIM auth)
      └─ Setting           (key/value system config)

Design notes:
  • Primary keys are UUID4 strings — portable, no enumeration attack
  • Timestamps are tz-aware (UTC) via `DateTime(timezone=True)`
  • JSON columns work in both SQLite (TEXT-backed) and PostgreSQL (JSONB)
  • Soft-delete via `deleted_at` on User; hard-delete only by OWNER
  • All FK relationships set `ondelete=...` for predictable cascade
"""
from __future__ import annotations

import enum
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────
#  Enumerations
# ─────────────────────────────────────────────────────────────────


class RoleCode(str, enum.Enum):
    """Hierarchical roles — see README §2 for the full matrix.

    Order (highest privilege first):
        OWNER > PLATFORM_ADMIN > SECURITY_MANAGER >
        OPERATOR > ANALYST > EXECUTIVE > AUDITOR > CLIENT
    """
    OWNER            = "OWNER"
    PLATFORM_ADMIN   = "PLATFORM_ADMIN"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    OPERATOR         = "OPERATOR"
    ANALYST          = "ANALYST"
    EXECUTIVE        = "EXECUTIVE"
    AUDITOR          = "AUDITOR"
    CLIENT           = "CLIENT"


class AuthMethod(str, enum.Enum):
    LOCAL = "LOCAL"
    OIDC  = "OIDC"
    SAML  = "SAML"
    SCIM  = "SCIM"   # provisioned, not yet authenticated


class MfaFactorType(str, enum.Enum):
    TOTP     = "TOTP"
    WEBAUTHN = "WEBAUTHN"


class IdentityProviderKind(str, enum.Enum):
    OIDC = "OIDC"
    SAML = "SAML"


class AuditSeverity(str, enum.Enum):
    INFO    = "INFO"
    NOTICE  = "NOTICE"     # privileged action
    WARN    = "WARN"       # failed login, lockout, denied
    SECURITY = "SECURITY"  # security-relevant (MFA change, role change)
    CRITICAL = "CRITICAL"  # data deletion, owner action


class UserStatus(str, enum.Enum):
    ACTIVE       = "ACTIVE"
    INVITED      = "INVITED"
    SUSPENDED    = "SUSPENDED"
    DEACTIVATED  = "DEACTIVATED"
    DELETED      = "DELETED"


# ─────────────────────────────────────────────────────────────────
#  Tenant — multi-tenant scoping unit
# ─────────────────────────────────────────────────────────────────


class Tenant(Base):
    __tablename__ = "auth_tenants"

    id:          Mapped[str]      = mapped_column(String(36), primary_key=True, default=_uuid)
    slug:        Mapped[str]      = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str]     = mapped_column(String(200), nullable=False)
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    is_default:  Mapped[bool]     = mapped_column(Boolean, default=False, nullable=False)

    users        = relationship("User",            back_populates="tenant",   cascade="all, delete-orphan")
    providers    = relationship("IdentityProvider",back_populates="tenant",   cascade="all, delete-orphan")
    scim_tokens  = relationship("ScimBearerToken", back_populates="tenant",   cascade="all, delete-orphan")
    role_assigns = relationship("UserRoleAssignment", back_populates="tenant", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────────
#  User
# ─────────────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "auth_users"

    id:          Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id:   Mapped[str] = mapped_column(String(36), ForeignKey("auth_tenants.id", ondelete="CASCADE"),
                                             nullable=False, index=True)

    email:       Mapped[str] = mapped_column(String(320), nullable=False)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    username:    Mapped[Optional[str]] = mapped_column(String(64))
    display_name: Mapped[Optional[str]] = mapped_column(String(200))

    status:      Mapped[UserStatus] = mapped_column(Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False)
    # The primary auth method for this user.  Local users have local
    # credentials AND optionally linked SSO identities.
    primary_auth_method: Mapped[AuthMethod] = mapped_column(
        Enum(AuthMethod), default=AuthMethod.LOCAL, nullable=False
    )

    # Optional external SCIM identifier — set by SCIM provisioning so
    # IdPs can map their internal user ID to ours.
    external_id: Mapped[Optional[str]] = mapped_column(String(255))

    # MFA — when enrolled, user MUST present a factor.  When the user
    # has any role in `MFA_REQUIRED_ROLES`, enrolment is forced before
    # any session can be issued.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Audit + lifecycle
    created_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    deleted_at:    Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Free-form attributes for ABAC predicates (department, clearance,
    # cost-center, etc.).  Propagated from SCIM `enterprise` extension.
    attributes:  Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships — explicit foreign_keys where multiple FKs point at auth_users
    tenant       = relationship("Tenant", back_populates="users")
    credential   = relationship("UserCredentialLocal", back_populates="user", uselist=False, cascade="all, delete-orphan")
    role_assigns = relationship("UserRoleAssignment",
                                foreign_keys="UserRoleAssignment.user_id",
                                back_populates="user",
                                cascade="all, delete-orphan")
    mfa_factors  = relationship("UserMfaFactor", back_populates="user", cascade="all, delete-orphan")
    backup_codes = relationship("MfaBackupCode", back_populates="user", cascade="all, delete-orphan")
    identities   = relationship("UserIdentity", back_populates="user", cascade="all, delete-orphan")
    sessions     = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    lockouts     = relationship("AccountLockout",
                                foreign_keys="AccountLockout.user_id",
                                back_populates="user",
                                cascade="all, delete-orphan")
    reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        UniqueConstraint("tenant_id", "username", name="uq_user_tenant_username"),
        Index("ix_user_external_id", "external_id"),
    )


class UserCredentialLocal(Base):
    """Argon2id password hash for local-auth users.

    Pepper version recorded so we can rotate the deployment-wide pepper
    by re-hashing on next successful login (transparent rehash).
    """
    __tablename__ = "auth_user_credentials_local"

    user_id:       Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                               primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    pepper_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    must_change:   Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    updated_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    # NIST 800-63B: no forced rotation, but track for compliance reports
    last_rotated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    user = relationship("User", back_populates="credential")


# ─────────────────────────────────────────────────────────────────
#  Roles — RBAC
# ─────────────────────────────────────────────────────────────────


class UserRoleAssignment(Base):
    """A user has zero or more (role, tenant) assignments.

    Granular scoping via the `attributes` JSON column lets an OPERATOR
    role be limited to specific engagements (`{"engagement_ids": [...]}`)
    without inventing per-resource ACL tables.
    """
    __tablename__ = "auth_user_role_assignments"

    id:         Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:    Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                            nullable=False, index=True)
    tenant_id:  Mapped[str] = mapped_column(String(36), ForeignKey("auth_tenants.id", ondelete="CASCADE"),
                                            nullable=False, index=True)
    role:       Mapped[RoleCode] = mapped_column(Enum(RoleCode), nullable=False)

    # ABAC scoping — empty dict means tenant-wide for this role
    attributes: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    granted_by_user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("auth_users.id"))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    user      = relationship("User", foreign_keys=[user_id],
                              back_populates="role_assigns")
    granted_by = relationship("User", foreign_keys=[granted_by_user_id])
    tenant    = relationship("Tenant", back_populates="role_assigns")

    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id", "role", name="uq_user_tenant_role"),
    )


# ─────────────────────────────────────────────────────────────────
#  MFA
# ─────────────────────────────────────────────────────────────────


class UserMfaFactor(Base):
    """One row per enrolled MFA factor.  Users may have multiple."""
    __tablename__ = "auth_user_mfa_factors"

    id:          Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:     Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                             nullable=False, index=True)
    factor_type: Mapped[MfaFactorType] = mapped_column(Enum(MfaFactorType), nullable=False)
    label:       Mapped[Optional[str]] = mapped_column(String(64))     # "iPhone Authy", "YubiKey blue"

    # TOTP: encrypted base32 secret.  Stored encrypted-at-rest using
    # AUTH_PASSWORD_PEPPER as the key (Fernet recommended; current
    # implementation in security/mfa.py uses pyotp + per-user salt).
    secret_encrypted: Mapped[Optional[str]] = mapped_column(Text)

    # WebAuthn: credential_id, public_key, sign_count
    credential_id:  Mapped[Optional[str]] = mapped_column(String(512))
    public_key:     Mapped[Optional[str]] = mapped_column(Text)
    sign_count:     Mapped[int]           = mapped_column(Integer, default=0, nullable=False)

    enrolled_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_used_at:   Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_primary:     Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="mfa_factors")


class MfaBackupCode(Base):
    """Single-use recovery codes for when a TOTP device is lost.

    Codes are stored hashed (argon2) — same as passwords — never as
    plaintext.  When the user redeems one, the row is marked used.
    """
    __tablename__ = "auth_mfa_backup_codes"

    id:        Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:   Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                           nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    used_at:   Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user = relationship("User", back_populates="backup_codes")


# ─────────────────────────────────────────────────────────────────
#  SSO identities
# ─────────────────────────────────────────────────────────────────


class IdentityProvider(Base):
    """Per-tenant SSO configuration (one per IdP)."""
    __tablename__ = "auth_identity_providers"

    id:          Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id:   Mapped[str] = mapped_column(String(36), ForeignKey("auth_tenants.id", ondelete="CASCADE"),
                                             nullable=False, index=True)
    name:        Mapped[str] = mapped_column(String(64), nullable=False)
    kind:        Mapped[IdentityProviderKind] = mapped_column(Enum(IdentityProviderKind), nullable=False)
    enabled:     Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # OIDC: {issuer, client_id, client_secret (encrypted), redirect_uri,
    #         scope, jwks_uri, authorization_endpoint, token_endpoint, ...}
    # SAML: {sp_entity_id, sp_acs_url, idp_entity_id, idp_sso_url,
    #         idp_x509_cert, want_assertions_signed, ...}
    config:      Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Group → role mapping table: {"Argus-Admins": "PLATFORM_ADMIN", ...}
    role_mapping: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # If true and a SSO claim arrives for an unknown user, auto-create
    # them with `default_role` instead of erroring.
    just_in_time_provisioning: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    default_role: Mapped[RoleCode] = mapped_column(Enum(RoleCode), default=RoleCode.ANALYST, nullable=False)

    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="providers")

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_idp_tenant_name"),
    )


class UserIdentity(Base):
    """Links a User to an IdP subject (NameID / sub claim).

    A user can have multiple linked identities (e.g. work Okta + personal
    Google).  We never use the email as the link key — only the IdP-
    provided immutable subject identifier.
    """
    __tablename__ = "auth_user_identities"

    id:          Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:     Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                             nullable=False, index=True)
    provider_id: Mapped[str] = mapped_column(String(36), ForeignKey("auth_identity_providers.id", ondelete="CASCADE"),
                                             nullable=False, index=True)
    subject:     Mapped[str] = mapped_column(String(512), nullable=False)
    email_at_linkage: Mapped[Optional[str]] = mapped_column(String(320))
    linked_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    raw_claims:  Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    user     = relationship("User", back_populates="identities")
    provider = relationship("IdentityProvider")

    __table_args__ = (
        UniqueConstraint("provider_id", "subject", name="uq_identity_provider_subject"),
    )


# ─────────────────────────────────────────────────────────────────
#  Sessions — DB-backed, with UI state survival
# ─────────────────────────────────────────────────────────────────


class Session(Base):
    """A live authenticated session.

    Reference is by opaque, high-entropy session_id (UUID).  The session
    cookie carries this ID; the access token is a short-lived JWT that
    encodes user_id + session_id for stateless rev-checking.

    Sessions survive process restarts because they're in the DB — when
    ARGUS reboots, every authenticated browser stays signed-in (subject
    to TTL).
    """
    __tablename__ = "auth_sessions"

    id:            Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:       Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                               nullable=False, index=True)

    # Fingerprint — IP + UA at create + last_seen (for anomaly checks)
    ip_address:    Mapped[Optional[str]] = mapped_column(String(64))
    user_agent:    Mapped[Optional[str]] = mapped_column(Text)
    ip_address_seen: Mapped[Optional[str]] = mapped_column(String(64))

    # Lifecycle
    created_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at:    Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(64))

    # CSRF double-submit secret (returned to browser as a cookie, also
    # required as a header on state-changing requests).
    csrf_token:    Mapped[str] = mapped_column(String(64), default=lambda: secrets.token_urlsafe(32),
                                                nullable=False)

    # Active workspace; multi-tenant users can switch via /auth/me/tenant
    current_tenant_id: Mapped[Optional[str]] = mapped_column(String(36),
        ForeignKey("auth_tenants.id"))

    # Last MFA challenge timestamp — used for re-auth windows
    last_mfa_at:   Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    user            = relationship("User",   back_populates="sessions")
    refresh_tokens  = relationship("RefreshToken", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_session_user_active", "user_id", "revoked_at"),
        Index("ix_session_expires", "expires_at"),
    )


class SessionState(Base):
    """Persistent UI / app state that follows the USER across reload,
    reboot, and device switch.

    Keyed by user_id (NOT session_id) so an operator who logs in on a
    different machine sees the same skin, audience mode, pinned pentest
    session, etc.  Written by the frontend via PATCH /auth/me/state.

    The `state` JSON blob's shape is documented in README §5.
    """
    __tablename__ = "auth_session_states"

    user_id:      Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                              primary_key=True)
    state:        Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    pinned_pentest_session_id: Mapped[Optional[str]] = mapped_column(String(64))
    updated_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)


class RefreshToken(Base):
    """Rotating refresh tokens.  Reuse triggers family revocation.

    `family_id` groups all tokens descended from a single login.  When
    a token is presented after it's been rotated (i.e. used twice),
    we treat it as theft and revoke the entire family (every active
    refresh token AND the session).
    """
    __tablename__ = "auth_refresh_tokens"

    id:          Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id:  Mapped[str] = mapped_column(String(36), ForeignKey("auth_sessions.id", ondelete="CASCADE"),
                                             nullable=False, index=True)
    family_id:   Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    token_hash:  Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at:     Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_at:  Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(64))

    session = relationship("Session", back_populates="refresh_tokens")


# ─────────────────────────────────────────────────────────────────
#  Audit log
# ─────────────────────────────────────────────────────────────────


class AuditLog(Base):
    """Append-only audit trail.

    Permission model (enforced in routes.py and rbac.py):
      • READ   — RBAC-scoped (admins see all, managers see tenant,
                 operators see their own actions)
      • CREATE — by `audit.log()` helper only (never via API)
      • UPDATE — never
      • DELETE — OWNER only, and only via /admin/audit/delete
                 with explicit reason
      • CONFIGURE retention — OWNER + PLATFORM_ADMIN
    """
    __tablename__ = "auth_audit_log"

    id:           Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ts:           Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)

    actor_user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("auth_users.id"), index=True)
    actor_session_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("auth_sessions.id"))
    impersonator_user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("auth_users.id"))
    tenant_id:    Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("auth_tenants.id"), index=True)

    action:       Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    resource_id:  Mapped[Optional[str]] = mapped_column(String(128), index=True)

    ip_address:   Mapped[Optional[str]] = mapped_column(String(64))
    user_agent:   Mapped[Optional[str]] = mapped_column(Text)

    severity:     Mapped[AuditSeverity] = mapped_column(Enum(AuditSeverity),
                                                          default=AuditSeverity.INFO, nullable=False)
    status:       Mapped[str] = mapped_column(String(16), default="success", nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Before/after snapshot for state-changing operations
    before_data:  Mapped[Optional[dict]] = mapped_column(JSON)
    after_data:   Mapped[Optional[dict]] = mapped_column(JSON)

    # Optional tamper-evidence chain — when AUDIT_HASH_CHAIN=true,
    # each row's hash = sha256(prev_hash || row_json)
    prev_hash:    Mapped[Optional[str]] = mapped_column(String(64))
    self_hash:    Mapped[Optional[str]] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_audit_ts_action", "ts", "action"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )


# ─────────────────────────────────────────────────────────────────
#  SCIM bearer tokens
# ─────────────────────────────────────────────────────────────────


class ScimBearerToken(Base):
    """Bearer tokens for SCIM endpoints.  One per IdP (or per-purpose).

    The token itself is shown ONCE at creation; only a hash is stored.
    Audit log records every SCIM operation by token_id.
    """
    __tablename__ = "auth_scim_bearer_tokens"

    id:           Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id:    Mapped[str] = mapped_column(String(36), ForeignKey("auth_tenants.id", ondelete="CASCADE"),
                                              nullable=False, index=True)
    description:  Mapped[str] = mapped_column(String(200), nullable=False)
    token_hash:   Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    created_by_user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("auth_users.id"))
    created_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at:   Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_used_ip: Mapped[Optional[str]] = mapped_column(String(64))

    tenant = relationship("Tenant", back_populates="scim_tokens")


# ─────────────────────────────────────────────────────────────────
#  Password reset + lockout
# ─────────────────────────────────────────────────────────────────


class PasswordResetToken(Base):
    __tablename__ = "auth_password_reset_tokens"

    id:         Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:    Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                            nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at:    Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    user = relationship("User", back_populates="reset_tokens")


class AccountLockout(Base):
    """Lockout records — both transient (failed-attempt window) and
    persistent (administrative lockout).

    A user is considered locked-out if any row has `expires_at > now`
    and `lifted_at is null`.
    """
    __tablename__ = "auth_account_lockouts"

    id:         Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:    Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.id", ondelete="CASCADE"),
                                            nullable=False, index=True)
    reason:     Mapped[str] = mapped_column(String(64), nullable=False)
    locked_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    lifted_at:  Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    lifted_by_user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("auth_users.id"))
    failed_attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    user      = relationship("User", foreign_keys=[user_id], back_populates="lockouts")
    lifted_by = relationship("User", foreign_keys=[lifted_by_user_id])


# ─────────────────────────────────────────────────────────────────
#  System settings — for retention, password policy, banner, etc.
# ─────────────────────────────────────────────────────────────────


class Setting(Base):
    """Key/value system config; admin-editable via /admin/settings.

    Examples:
        audit.max_rows         → "1000000"
        audit.max_age_days     → "730"
        password.min_length    → "12"
        ui.banner_text         → "Production · handle data accordingly"
    """
    __tablename__ = "auth_settings"

    key:        Mapped[str]      = mapped_column(String(128), primary_key=True)
    value:      Mapped[str]      = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
    updated_by_user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("auth_users.id"))


# ─────────────────────────────────────────────────────────────────
#  Helper functions (used elsewhere, kept here to avoid circular imports)
# ─────────────────────────────────────────────────────────────────


def all_roles_for_user(user: User) -> list[RoleCode]:
    """Flatten a user's role assignments into a deduplicated role list.

    Tenant scoping is preserved in the assignment rows themselves;
    this helper is for "does the user have ANY assignment of this
    role" style checks.
    """
    return list({a.role for a in (user.role_assigns or [])})


def has_role(user: User, role: RoleCode, tenant_id: Optional[str] = None) -> bool:
    for a in (user.role_assigns or []):
        if a.role != role:
            continue
        if tenant_id and a.tenant_id != tenant_id:
            continue
        if a.expires_at and a.expires_at < _utcnow():
            continue
        return True
    return False
