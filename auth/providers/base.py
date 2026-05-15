"""Abstract base for authentication providers.

Every provider yields the same AuthResult so the routes layer can stay
provider-agnostic.  Providers are responsible for:

  • Verifying the supplied credential / SSO assertion
  • Locating (or just-in-time provisioning) the local User row
  • Applying any incoming role/attribute claims via role_mapping
  • Updating last_login_at and identity-link metadata

Providers do NOT issue sessions — that's sessions.create_session().
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from auth.models import User


class AuthError(Exception):
    """Raised when authentication fails.  Messages are SAFE to expose
    to end-users (no PII, no system internals).
    """
    def __init__(self, message: str = "Authentication failed",
                 code: str = "auth_failed", http_status: int = 401):
        super().__init__(message)
        self.message = message
        self.code = code
        self.http_status = http_status


@dataclass
class AuthResult:
    """Returned by every provider on success."""
    user:               User
    requires_mfa:       bool = False
    needs_password_rehash: bool = False
    raw_claims:         Dict[str, Any] = field(default_factory=dict)
    provider_id:        Optional[str] = None     # which IdP, if SSO


class AuthProvider:
    """Abstract interface implemented by every provider."""

    name: str = "base"

    def authenticate(self, *args, **kwargs) -> AuthResult:
        raise NotImplementedError
