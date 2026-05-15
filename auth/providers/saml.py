"""SAML 2.0 authentication provider — SP-initiated + IdP-initiated.

Wraps `python3-saml` (OneLogin's library) which handles XML signature
validation, encryption, and XSW protections.  Per-tenant SP metadata
is exposed at `/auth/sso/saml/{idp_id}/metadata`.

Tested against Okta, Azure AD, Google Workspace, OneLogin, JumpCloud,
Auth0 SAML.

Required idp.config keys:
    sp_entity_id            — ARGUS-side entity ID
    sp_acs_url              — assertion consumer service URL
    sp_slo_url              — single-logout URL (optional)
    sp_x509_cert / sp_private_key  — for signed requests / decryption
    idp_entity_id           — IdP entity ID
    idp_sso_url             — IdP SSO endpoint
    idp_slo_url             — IdP SLO endpoint (optional)
    idp_x509_cert           — IdP signing certificate
    want_assertions_signed  — bool (default True)
    name_id_format          — urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
    attribute_mapping       — {"email": "http://schemas.xmlsoap.org/...",
                               "groups": "http://...", ...}
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from auth.models import (
    AuthMethod, IdentityProvider, IdentityProviderKind, RoleCode,
    User, UserIdentity, UserRoleAssignment, UserStatus,
)
from auth.providers.base import AuthError, AuthProvider, AuthResult

logger = logging.getLogger("argus.auth.providers.saml")


# ─────────────────────────────────────────────────────────────────


class SamlProvider(AuthProvider):
    name = "saml"

    def __init__(self, db: DbSession, idp_row: IdentityProvider):
        if idp_row.kind != IdentityProviderKind.SAML:
            raise ValueError(f"IdentityProvider {idp_row.id} is not SAML")
        if not idp_row.enabled:
            raise AuthError("Identity provider disabled.",
                            code="idp_disabled", http_status=403)
        self.db = db
        self.idp = idp_row
        self.config = idp_row.config or {}

    # ── Helpers ─────────────────────────────────────────────────
    def _build_settings_dict(self, http_request: Dict[str, Any]) -> Dict[str, Any]:
        """Build the dict python3-saml expects from our DB config.

        `http_request` is constructed in routes.py from the FastAPI
        Request — see python3-saml docs for the exact shape:
            { "https": "on"/"off", "http_host": "...",
              "server_port": ..., "script_name": "...",
              "get_data": dict, "post_data": dict }
        """
        cfg = self.config
        return {
            "strict": True,
            "debug":  False,
            "sp": {
                "entityId":                cfg.get("sp_entity_id"),
                "assertionConsumerService": {
                    "url":     cfg.get("sp_acs_url"),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "singleLogoutService": {
                    "url":     cfg.get("sp_slo_url") or "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "NameIDFormat": cfg.get(
                    "name_id_format",
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                ),
                "x509cert":  cfg.get("sp_x509_cert", ""),
                "privateKey": cfg.get("sp_private_key", ""),
            },
            "idp": {
                "entityId": cfg.get("idp_entity_id"),
                "singleSignOnService": {
                    "url":     cfg.get("idp_sso_url"),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "singleLogoutService": {
                    "url":     cfg.get("idp_slo_url") or "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": cfg.get("idp_x509_cert", ""),
            },
            "security": {
                "wantAssertionsSigned":    cfg.get("want_assertions_signed", True),
                "wantMessagesSigned":      cfg.get("want_messages_signed", False),
                "wantAssertionsEncrypted": cfg.get("want_assertions_encrypted", False),
                "wantNameIdEncrypted":     cfg.get("want_name_id_encrypted", False),
                "requestedAuthnContext":   cfg.get("requested_authn_context", True),
                "signMetadata":            False,
            },
        }

    def _build_auth(self, http_request: Dict[str, Any]):
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
        except ImportError as e:
            raise AuthError("python3-saml not installed.",
                            code="saml_missing", http_status=500) from e
        return OneLogin_Saml2_Auth(http_request, self._build_settings_dict(http_request))

    # ── Start (SP-initiated) ───────────────────────────────────
    def build_login_url(self, http_request: Dict[str, Any],
                        *, return_to: Optional[str] = None) -> str:
        auth = self._build_auth(http_request)
        return auth.login(return_to or "/")

    # ── Metadata ───────────────────────────────────────────────
    def get_sp_metadata(self, http_request: Dict[str, Any]) -> str:
        try:
            from onelogin.saml2.settings import OneLogin_Saml2_Settings
        except ImportError as e:
            raise AuthError("python3-saml not installed.",
                            code="saml_missing", http_status=500) from e
        settings = OneLogin_Saml2_Settings(self._build_settings_dict(http_request),
                                           sp_validation_only=True)
        meta = settings.get_sp_metadata()
        errors = settings.validate_metadata(meta)
        if errors:
            raise AuthError(f"Invalid SP metadata: {errors}",
                            code="saml_metadata_invalid", http_status=500)
        return meta

    # ── Callback (ACS) ─────────────────────────────────────────
    def process_acs(self, http_request: Dict[str, Any]) -> AuthResult:
        auth = self._build_auth(http_request)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            reason = auth.get_last_error_reason() or "; ".join(errors)
            logger.warning("SAML ACS errors on IdP %s: %s", self.idp.id, reason)
            raise AuthError(f"SAML response invalid: {reason}",
                            code="saml_invalid_response", http_status=400)
        if not auth.is_authenticated():
            raise AuthError("SAML response not authenticated.",
                            code="saml_not_auth", http_status=401)

        attrs = auth.get_attributes() or {}
        name_id = auth.get_nameid()
        session_index = auth.get_session_index()
        nameid_format = auth.get_nameid_format()
        return self._upsert_user_from_assertion(name_id, attrs,
                                                session_index, nameid_format)

    # ── User upsert ────────────────────────────────────────────
    def _upsert_user_from_assertion(self, name_id: str,
                                    attrs: Dict[str, list],
                                    session_index: Optional[str],
                                    nameid_format: Optional[str]) -> AuthResult:
        # Map attributes to canonical fields
        mapping = self.config.get("attribute_mapping", {})
        email = self._first(attrs, mapping.get("email", "email")) or (
            name_id if "@" in (name_id or "") else None
        )
        display_name = self._first(attrs, mapping.get("display_name", "displayName"))
        first_name = self._first(attrs, mapping.get("first_name", "givenName"))
        last_name = self._first(attrs, mapping.get("last_name", "sn"))
        groups = attrs.get(mapping.get("groups", "groups"), []) or []

        if not display_name and (first_name or last_name):
            display_name = " ".join([n for n in (first_name, last_name) if n])

        email = (email or "").strip().lower() or None
        sub = name_id

        if not sub:
            raise AuthError("SAML assertion missing NameID.",
                            code="saml_no_nameid")

        identity = self.db.execute(
            select(UserIdentity).where(
                UserIdentity.provider_id == self.idp.id,
                UserIdentity.subject == sub,
            )
        ).scalar_one_or_none()

        if identity is None:
            if not self.idp.just_in_time_provisioning:
                raise AuthError("Account not provisioned.",
                                code="user_not_provisioned", http_status=403)
            if not email:
                raise AuthError("SAML assertion missing email.",
                                code="saml_no_email")

            user = self.db.execute(
                select(User).where(
                    User.tenant_id == self.idp.tenant_id, User.email == email
                )
            ).scalar_one_or_none()

            if user is None:
                user = User(
                    tenant_id=self.idp.tenant_id,
                    email=email, display_name=display_name,
                    status=UserStatus.ACTIVE,
                    primary_auth_method=AuthMethod.SAML,
                    email_verified_at=datetime.now(timezone.utc),
                )
                self.db.add(user)
                self.db.flush()
                self.db.add(UserRoleAssignment(
                    user_id=user.id, tenant_id=self.idp.tenant_id,
                    role=self.idp.default_role,
                ))

            identity = UserIdentity(
                user_id=user.id, provider_id=self.idp.id, subject=sub,
                email_at_linkage=email,
                raw_claims={"attrs": attrs, "session_index": session_index,
                            "nameid_format": nameid_format},
            )
            self.db.add(identity)
        else:
            user = identity.user
            identity.last_login_at = datetime.now(timezone.utc)
            identity.raw_claims = {"attrs": attrs, "session_index": session_index,
                                   "nameid_format": nameid_format}

        # Role mapping
        self._apply_role_mapping(user, groups)

        if user.status not in (UserStatus.ACTIVE, UserStatus.INVITED):
            raise AuthError("Account is not active.",
                            code="account_inactive", http_status=403)
        if user.status == UserStatus.INVITED:
            user.status = UserStatus.ACTIVE

        self.db.commit()

        from auth.config import CONFIG
        mfa_required = (user.mfa_enabled or any(
            a.role.value in CONFIG.mfa_required_roles
            for a in (user.role_assigns or [])
        ))
        return AuthResult(user=user, requires_mfa=mfa_required,
                          raw_claims={"attrs": attrs}, provider_id=self.idp.id)

    @staticmethod
    def _first(attrs: Dict[str, list], key: str) -> Optional[str]:
        v = attrs.get(key)
        if isinstance(v, list) and v:
            return v[0]
        if isinstance(v, str):
            return v
        return None

    def _apply_role_mapping(self, user: User, groups: list) -> None:
        mapping = self.idp.role_mapping or {}
        for g in groups:
            target_role = mapping.get(g)
            if not target_role:
                continue
            try:
                role_enum = RoleCode(target_role)
            except ValueError:
                continue
            already = any(a.role == role_enum and a.tenant_id == self.idp.tenant_id
                          for a in (user.role_assigns or []))
            if not already:
                self.db.add(UserRoleAssignment(
                    user_id=user.id, tenant_id=self.idp.tenant_id,
                    role=role_enum,
                ))


__all__ = ["SamlProvider"]
