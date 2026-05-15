"""Authentication providers — local, OIDC, SAML, SCIM.

Each provider implements the AuthProvider abstract base class and is
selectable by tenant via the identity_providers table.
"""
from auth.providers.base import AuthProvider, AuthResult, AuthError
from auth.providers.local import LocalAuthProvider

__all__ = ["AuthProvider", "AuthResult", "AuthError", "LocalAuthProvider"]
