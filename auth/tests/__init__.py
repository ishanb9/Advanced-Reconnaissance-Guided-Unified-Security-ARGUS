"""Adversarial test suite for the ARGUS auth module (Gap #8).

The SSO/SCIM/RBAC layer is the governance moat — so it must be the most-tested
code in the repo.  These tests attack it the way a real adversary would: SAML XSW
(XML signature wrapping), SCIM bearer-token authz fuzzing, refresh-token
replay/theft, and session fixation.

Run on Kali/CI where the auth dependencies (python3-saml, fastapi, sqlalchemy) are
installed:  pytest -q auth/tests/
Tests that need an optional dependency skip cleanly when it is absent.
"""
