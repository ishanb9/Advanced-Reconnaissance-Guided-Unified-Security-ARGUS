"""OpenID Connect provider — RFC 6749 + RFC 8252 (PKCE for public clients).

Implements the standard Authorization Code + PKCE flow:

  1. /auth/sso/oidc/{idp_id}/start
       - generate state + PKCE verifier
       - store in a short-lived cookie OR signed JWT
       - redirect browser to IdP's authorization_endpoint

  2. /auth/sso/oidc/{idp_id}/callback?code=&state=
       - validate state
       - exchange code at token_endpoint (with PKCE verifier)
       - validate id_token signature against jwks_uri
       - verify nonce + aud + iss + exp
       - upsert user; link UserIdentity via (provider_id, sub)
       - apply role_mapping from id_token['groups'] (or 'roles')
       - issue ARGUS session (via sessions.create_session)

This file provides the building blocks; the wiring to FastAPI lives
in routes.py.  Using `authlib` for the heavy crypto so we don't roll
our own JWS / JWE / JWK validation.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from auth.models import (
    IdentityProvider, IdentityProviderKind, RoleCode,
    User, UserIdentity, UserRoleAssignment, UserStatus,
)
from auth.providers.base import AuthError, AuthProvider, AuthResult

logger = logging.getLogger("argus.auth.providers.oidc")


# ─────────────────────────────────────────────────────────────────
#  PKCE helpers
# ─────────────────────────────────────────────────────────────────


def _pkce_verifier() -> str:
    """RFC 7636 §4.1 — 43–128 chars from [A-Z][a-z][0-9]-._~"""
    return secrets.token_urlsafe(64)[:128]


def _pkce_challenge(verifier: str) -> str:
    digest = sha256(verifier.encode("ascii")).digest()
    import base64
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ─────────────────────────────────────────────────────────────────
#  Provider
# ─────────────────────────────────────────────────────────────────


class OidcProvider(AuthProvider):
    name = "oidc"

    def __init__(self, db: DbSession, idp_row: IdentityProvider):
        if idp_row.kind != IdentityProviderKind.OIDC:
            raise ValueError(f"IdentityProvider {idp_row.id} is not OIDC")
        if not idp_row.enabled:
            raise AuthError("Identity provider disabled.", code="idp_disabled", http_status=403)
        self.db = db
        self.idp = idp_row
        self.config = idp_row.config or {}

    # ── Authorization start ────────────────────────────────────
    def build_authorization_url(self, *, redirect_uri: str,
                                scope: str = "openid email profile",
                                ) -> Tuple[str, Dict[str, str]]:
        """Return (url, state_dict).  Caller stashes state_dict (in a
        signed cookie or DB row) for the callback to validate.
        """
        cfg = self.config
        ep = cfg.get("authorization_endpoint")
        client_id = cfg.get("client_id")
        if not ep or not client_id:
            raise AuthError("Identity provider not configured.", code="idp_misconfigured")

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = _pkce_verifier()
        challenge = _pkce_challenge(verifier)

        params = {
            "client_id":             client_id,
            "redirect_uri":          redirect_uri,
            "response_type":         "code",
            "scope":                 scope,
            "state":                 state,
            "nonce":                 nonce,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        }
        url = f"{ep}?{urlencode(params)}"

        return url, {
            "state":         state,
            "nonce":         nonce,
            "code_verifier": verifier,
            "redirect_uri":  redirect_uri,
        }

    # ── Callback exchange ──────────────────────────────────────
    def exchange_code(self, *, code: str, code_verifier: str,
                      redirect_uri: str) -> Dict[str, Any]:
        """Exchange the auth code for an id_token + access_token.

        Returns the parsed token response from the IdP — caller passes
        the id_token through validate_id_token().
        """
        try:
            from authlib.integrations.requests_client import OAuth2Session
        except ImportError as e:
            raise AuthError("authlib not installed.",
                            code="authlib_missing", http_status=500) from e

        cfg = self.config
        client_id = cfg.get("client_id")
        client_secret = cfg.get("client_secret")
        token_ep = cfg.get("token_endpoint")
        if not all((client_id, token_ep)):
            raise AuthError("Identity provider not configured.", code="idp_misconfigured")

        sess = OAuth2Session(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code_challenge_method="S256",
        )
        try:
            token = sess.fetch_token(
                token_ep,
                code=code,
                code_verifier=code_verifier,
                grant_type="authorization_code",
            )
        except Exception as e:
            logger.warning("oidc token exchange failed: %s", e)
            raise AuthError("Token exchange failed.", code="oidc_exchange_failed")
        return token

    def validate_id_token(self, id_token: str, *, nonce: str) -> Dict[str, Any]:
        """Validate signature, iss, aud, exp, nonce.  Return claims dict."""
        try:
            from authlib.jose import jwt as alib_jwt
            from authlib.jose.errors import JoseError
        except ImportError as e:
            raise AuthError("authlib not installed.",
                            code="authlib_missing", http_status=500) from e

        cfg = self.config
        jwks_uri = cfg.get("jwks_uri")
        issuer = cfg.get("issuer")
        client_id = cfg.get("client_id")
        if not all((jwks_uri, issuer, client_id)):
            raise AuthError("Identity provider not configured.", code="idp_misconfigured")

        # Fetch JWKS — for production deployments, cache this per-IdP
        # with a short TTL.  Inline here for clarity.
        try:
            import requests
            jwks = requests.get(jwks_uri, timeout=5).json()
        except Exception as e:
            raise AuthError("JWKS fetch failed.", code="oidc_jwks_failed") from e

        try:
            claims = alib_jwt.decode(id_token, jwks)
            claims.validate()
        except JoseError as e:
            raise AuthError(f"id_token validation failed: {e}",
                            code="oidc_id_token_invalid") from e

        # Manual aud / iss / nonce checks (authlib enforces exp)
        if claims.get("iss") != issuer:
            raise AuthError("id_token iss mismatch.", code="oidc_iss_mismatch")
        aud = claims.get("aud")
        if isinstance(aud, list):
            if client_id not in aud:
                raise AuthError("id_token aud mismatch.", code="oidc_aud_mismatch")
        elif aud != client_id:
            raise AuthError("id_token aud mismatch.", code="oidc_aud_mismatch")
        if claims.get("nonce") != nonce:
            raise AuthError("id_token nonce mismatch.", code="oidc_nonce_mismatch")

        return dict(claims)

    # ── User upsert ─────────────────────────────────────────────
    def upsert_user_from_claims(self, claims: Dict[str, Any]) -> AuthResult:
        """Find-or-create the local User from a validated id_token.

        Linkage is by (provider_id, sub).  Email is only used for
        display; never as the identity key.
        """
        sub = claims.get("sub")
        if not sub:
            raise AuthError("id_token missing sub.", code="oidc_no_sub")

        # Check existing link
        identity = self.db.execute(
            select(UserIdentity).where(
                UserIdentity.provider_id == self.idp.id,
                UserIdentity.subject == sub,
            )
        ).scalar_one_or_none()

        email = (claims.get("email") or "").strip().lower() or None
        display_name = claims.get("name") or claims.get("preferred_username")

        if identity is None:
            if not self.idp.just_in_time_provisioning:
                raise AuthError(
                    "Account not provisioned. Contact your administrator.",
                    code="user_not_provisioned", http_status=403,
                )
            if not email:
                raise AuthError("id_token missing email.", code="oidc_no_email")

            # JIT user creation
            user = self.db.execute(
                select(User).where(
                    User.tenant_id == self.idp.tenant_id, User.email == email
                )
            ).scalar_one_or_none()

            if user is None:
                from auth.models import AuthMethod
                user = User(
                    tenant_id=self.idp.tenant_id,
                    email=email, display_name=display_name,
                    status=UserStatus.ACTIVE,
                    primary_auth_method=AuthMethod.OIDC,
                    email_verified_at=datetime.now(timezone.utc),
                )
                self.db.add(user)
                self.db.flush()
                # Default role for this IdP
                self.db.add(UserRoleAssignment(
                    user_id=user.id, tenant_id=self.idp.tenant_id,
                    role=self.idp.default_role,
                ))

            identity = UserIdentity(
                user_id=user.id, provider_id=self.idp.id, subject=sub,
                email_at_linkage=email, raw_claims=claims,
            )
            self.db.add(identity)
        else:
            user = identity.user
            identity.last_login_at = datetime.now(timezone.utc)
            identity.raw_claims = claims

        # Apply role mapping from groups/roles claim
        self._apply_role_mapping(user, claims)

        if user.status not in (UserStatus.ACTIVE, UserStatus.INVITED):
            raise AuthError("Account is not active.", code="account_inactive",
                            http_status=403)

        # Promote INVITED → ACTIVE on first SSO login
        if user.status == UserStatus.INVITED:
            user.status = UserStatus.ACTIVE

        self.db.commit()

        from auth.config import CONFIG
        mfa_required = (user.mfa_enabled or any(
            a.role.value in CONFIG.mfa_required_roles for a in (user.role_assigns or [])
        ))
        return AuthResult(user=user, requires_mfa=mfa_required,
                          raw_claims=claims, provider_id=self.idp.id)

    # ── Helpers ─────────────────────────────────────────────────
    def _apply_role_mapping(self, user: User, claims: Dict[str, Any]) -> None:
        """Map IdP group/role claims to ARGUS roles via idp.role_mapping.

        Example role_mapping:
            {"Argus-Admins": "PLATFORM_ADMIN", "Pentest-Team": "OPERATOR"}

        We assign mapped roles (idempotent) but do NOT remove others
        unless idp.config["role_mapping_authoritative"] is True.
        """
        groups = claims.get("groups") or claims.get("roles") or []
        if isinstance(groups, str):
            groups = [groups]

        mapping = self.idp.role_mapping or {}
        for g in groups:
            target_role = mapping.get(g)
            if not target_role:
                continue
            try:
                role_enum = RoleCode(target_role)
            except ValueError:
                logger.warning("unknown role %s in role_mapping for IdP %s",
                               target_role, self.idp.id)
                continue
            # Idempotent: don't add duplicate
            already = any(a.role == role_enum and a.tenant_id == self.idp.tenant_id
                          for a in (user.role_assigns or []))
            if not already:
                self.db.add(UserRoleAssignment(
                    user_id=user.id, tenant_id=self.idp.tenant_id,
                    role=role_enum,
                ))

        if self.idp.config.get("role_mapping_authoritative"):
            # Remove any role NOT in mapped set
            mapped_roles = {RoleCode(v) for v in mapping.values()
                            if v in RoleCode.__members__}
            for a in list(user.role_assigns or []):
                if (a.tenant_id == self.idp.tenant_id
                        and a.role not in mapped_roles
                        and a.role != RoleCode.OWNER):
                    self.db.delete(a)


__all__ = ["OidcProvider"]
