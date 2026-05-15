"""Pydantic request/response schemas for the /auth and /scim endpoints.

Kept in one file so the full API contract can be reviewed at a glance.
Naming: <Action><Resource>Request / <Resource>Response.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ─────────────────────────────────────────────────────────────────
#  Auth — login / MFA / refresh
# ─────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str = Field(min_length=1, max_length=512)


class LoginInitialResponse(BaseModel):
    """First-phase response when MFA is required.

    The browser stores `mfa_token` and submits it with the TOTP/backup
    code at POST /auth/mfa/verify.  This is a short-lived (5min) one-
    time challenge token bound to the user.
    """
    status:    str = Field(default="mfa_required")
    mfa_token: str
    factor_types: List[str] = Field(default_factory=list)
    expires_in: int


class MfaVerifyRequest(BaseModel):
    mfa_token:  str
    code:       str = Field(min_length=4, max_length=32)
    is_backup:  bool = False


class TokenResponse(BaseModel):
    """Issued after successful authentication.

    The access_token is also set as a Bearer-equivalent cookie; the
    refresh_token is set as httpOnly Secure.  Returning them in the
    body too is useful for SPA boot, where the JS holds the access
    token in memory for adding to Authorization headers.
    """
    access_token:    str
    refresh_token:   str
    token_type:      str = "Bearer"
    expires_in:      int               # access-token TTL in seconds
    refresh_expires_in: int            # refresh-token TTL in seconds
    csrf_token:      str
    user_id:         str
    roles:           List[str]
    must_change_password: bool = False


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None     # if not provided, read from cookie


# ─────────────────────────────────────────────────────────────────
#  Self-service /me
# ─────────────────────────────────────────────────────────────────


class MeResponse(BaseModel):
    id:           str
    email:        str
    username:     Optional[str]
    display_name: Optional[str]
    status:       str
    primary_auth_method: str
    mfa_enabled:  bool
    tenant_id:    str
    current_tenant_id: Optional[str]
    roles:        List[str]
    attributes:   Dict[str, Any]
    created_at:   datetime
    last_login_at: Optional[datetime]
    session_state: Dict[str, Any] = Field(default_factory=dict)


class PatchStateRequest(BaseModel):
    """The frontend sends a partial state object; it's shallow-merged."""
    state: Dict[str, Any]


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str = Field(min_length=12, max_length=256)


# ─────────────────────────────────────────────────────────────────
#  MFA enrolment
# ─────────────────────────────────────────────────────────────────


class TotpEnrolStartResponse(BaseModel):
    factor_id:        str
    secret_b32:       str           # shown ONCE; user can copy into app
    otpauth_uri:      str
    qr_data_uri:      str           # data:image/png;base64,...


class TotpEnrolConfirmRequest(BaseModel):
    factor_id: str
    code:      str = Field(min_length=4, max_length=12)


class BackupCodesResponse(BaseModel):
    codes: List[str]                # shown ONCE


# ─────────────────────────────────────────────────────────────────
#  Admin — user management
# ─────────────────────────────────────────────────────────────────


class CreateUserRequest(BaseModel):
    email:        EmailStr
    username:     Optional[str] = None
    display_name: Optional[str] = None
    initial_password: Optional[str] = None
    roles:        List[str] = Field(default_factory=list)
    attributes:   Dict[str, Any] = Field(default_factory=dict)
    send_invite:  bool = True

    @field_validator("roles")
    @classmethod
    def _normalize_roles(cls, v: List[str]) -> List[str]:
        return [r.upper() for r in v]


class UpdateUserRequest(BaseModel):
    display_name: Optional[str] = None
    username:     Optional[str] = None
    status:       Optional[str] = None
    attributes:   Optional[Dict[str, Any]] = None


class UserSummary(BaseModel):
    id:           str
    email:        str
    username:     Optional[str]
    display_name: Optional[str]
    status:       str
    mfa_enabled:  bool
    primary_auth_method: str
    roles:        List[str]
    created_at:   datetime
    last_login_at: Optional[datetime]


class RoleAssignmentRequest(BaseModel):
    role:         str
    tenant_id:    Optional[str] = None
    engagement_ids: Optional[List[str]] = None
    expires_at:   Optional[datetime] = None


# ─────────────────────────────────────────────────────────────────
#  Session-management
# ─────────────────────────────────────────────────────────────────


class SessionSummary(BaseModel):
    id:           str
    user_id:      str
    created_at:   datetime
    last_seen_at: datetime
    expires_at:   datetime
    ip_address:   Optional[str]
    user_agent:   Optional[str]
    current_tenant_id: Optional[str]
    revoked_at:   Optional[datetime] = None
    pinned_pentest_session_id: Optional[str] = None


# ─────────────────────────────────────────────────────────────────
#  Audit log
# ─────────────────────────────────────────────────────────────────


class AuditEntry(BaseModel):
    id:            str
    ts:            datetime
    actor_user_id: Optional[str]
    tenant_id:     Optional[str]
    action:        str
    resource_type: Optional[str]
    resource_id:   Optional[str]
    ip_address:    Optional[str]
    severity:      str
    status:        str
    error_message: Optional[str]
    before_data:   Optional[Dict[str, Any]] = None
    after_data:    Optional[Dict[str, Any]] = None


class SetRetentionRequest(BaseModel):
    max_rows:     Optional[int] = Field(default=None, ge=1000)
    max_age_days: Optional[int] = Field(default=None, ge=1)


class DeleteAuditRequest(BaseModel):
    ids:        Optional[List[str]] = None
    older_than: Optional[datetime] = None
    reason:     str = Field(min_length=10, max_length=1000)


# ─────────────────────────────────────────────────────────────────
#  Identity-provider config
# ─────────────────────────────────────────────────────────────────


class CreateIdentityProviderRequest(BaseModel):
    name:         str = Field(min_length=2, max_length=64)
    kind:         str          # "OIDC" or "SAML"
    enabled:      bool = True
    config:       Dict[str, Any] = Field(default_factory=dict)
    role_mapping: Dict[str, str] = Field(default_factory=dict)
    default_role: str = "ANALYST"
    just_in_time_provisioning: bool = True


class IdentityProviderResponse(BaseModel):
    id:           str
    tenant_id:    str
    name:         str
    kind:         str
    enabled:      bool
    config:       Dict[str, Any]
    role_mapping: Dict[str, str]
    default_role: str
    just_in_time_provisioning: bool
    created_at:   datetime
    updated_at:   datetime


# ─────────────────────────────────────────────────────────────────
#  SCIM bearer tokens
# ─────────────────────────────────────────────────────────────────


class CreateScimTokenRequest(BaseModel):
    description: str = Field(min_length=2, max_length=200)
    ttl_days:    Optional[int] = None


class ScimTokenIssued(BaseModel):
    id:          str
    token:       str           # shown ONCE
    description: str
    created_at:  datetime
    expires_at:  datetime


# ─────────────────────────────────────────────────────────────────
#  SCIM 2.0 — RFC 7644 wire types
# ─────────────────────────────────────────────────────────────────


class ScimName(BaseModel):
    formatted:    Optional[str] = None
    familyName:   Optional[str] = None
    givenName:    Optional[str] = None
    middleName:   Optional[str] = None


class ScimEmail(BaseModel):
    value:    str
    primary:  bool = True
    type:     Optional[str] = "work"


class ScimGroupRef(BaseModel):
    value:    str
    display:  Optional[str] = None


class ScimUser(BaseModel):
    schemas:     List[str] = Field(default_factory=lambda: [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
    ])
    id:          Optional[str] = None
    externalId:  Optional[str] = None
    userName:    str
    name:        Optional[ScimName] = None
    displayName: Optional[str] = None
    emails:      List[ScimEmail] = Field(default_factory=list)
    active:      bool = True
    groups:      List[ScimGroupRef] = Field(default_factory=list)
    meta:        Optional[Dict[str, Any]] = None
    # Enterprise extension
    enterprise:  Optional[Dict[str, Any]] = Field(default=None,
        alias="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")

    model_config = {"populate_by_name": True}


class ScimListResponse(BaseModel):
    schemas:      List[str] = Field(default_factory=lambda: [
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ])
    totalResults: int
    startIndex:   int = 1
    itemsPerPage: int
    Resources:    List[Dict[str, Any]] = Field(default_factory=list)


class ScimError(BaseModel):
    schemas:    List[str] = Field(default_factory=lambda: [
        "urn:ietf:params:scim:api:messages:2.0:Error"
    ])
    status:     str
    detail:     str
    scimType:   Optional[str] = None


__all__ = [
    # Auth
    "LoginRequest", "LoginInitialResponse", "MfaVerifyRequest",
    "TokenResponse", "RefreshRequest",
    # Me
    "MeResponse", "PatchStateRequest", "ChangePasswordRequest",
    # MFA
    "TotpEnrolStartResponse", "TotpEnrolConfirmRequest", "BackupCodesResponse",
    # Admin
    "CreateUserRequest", "UpdateUserRequest", "UserSummary",
    "RoleAssignmentRequest",
    # Session
    "SessionSummary",
    # Audit
    "AuditEntry", "SetRetentionRequest", "DeleteAuditRequest",
    # IdP
    "CreateIdentityProviderRequest", "IdentityProviderResponse",
    # SCIM tokens
    "CreateScimTokenRequest", "ScimTokenIssued",
    # SCIM wire types
    "ScimName", "ScimEmail", "ScimGroupRef", "ScimUser",
    "ScimListResponse", "ScimError",
]
