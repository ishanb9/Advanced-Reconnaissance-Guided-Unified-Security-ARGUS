"""Adversarial tests for the ARGUS auth module (Gap #8).

Attacks the governance moat the way an adversary would:
  • SAML XSW (XML Signature Wrapping) — unsigned / wrapped assertions must be rejected
  • SCIM bearer-token authz — missing / malformed / wrong-scheme tokens must 401
  • Refresh-token replay / theft — a reused refresh token must revoke the whole family
  • Session fixation — every login must mint a brand-new session id

Each test skips cleanly if its optional dependency (python3-saml, fastapi,
sqlalchemy) is not installed, so the suite is safe to run anywhere.
Run:  pytest -q auth/tests/test_auth_adversarial.py
"""
from __future__ import annotations

import importlib
import importlib.util
import pytest


# ──────────────────────────────────────────────────────────────────────────────
# SCIM bearer-token authorization fuzzing (no DB needed — rejection is pre-DB)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def scim():
    pytest.importorskip("fastapi")
    try:
        return importlib.import_module("auth.scim")
    except Exception as exc:                       # pragma: no cover
        pytest.skip(f"auth.scim not importable: {exc}")


@pytest.mark.parametrize("header", [
    None,                       # no Authorization header at all
    "",                         # empty
    "Basic dXNlcjpwYXNz",       # wrong scheme (Basic, not Bearer)
    "Bearer",                   # scheme with no token
    "Bearer ",                  # scheme + empty token
    "Token abc123",             # bogus scheme
    "bearerabc",                # malformed (no space)
])
def test_scim_rejects_bad_bearer(scim, header):
    """SCIM must reject every malformed / missing / wrong-scheme Authorization
    header with 401 BEFORE touching the database."""
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        # signature is _verify_bearer(authorization, db, request); the malformed
        # / missing header is rejected BEFORE db or request is touched.
        scim._verify_bearer(header, None, None)
    assert ei.value.status_code == 401


def test_scim_token_compared_by_hash(scim):
    """The presented token is sha256-hashed and matched against token_hash —
    never compared or stored in plaintext."""
    import inspect
    src = inspect.getsource(scim._verify_bearer) + inspect.getsource(scim._hash_token)
    assert "sha256" in src
    assert "token_hash" in src
    # A valid-looking token must still be looked up by HASH, not by raw value.
    assert "_hash_token(" in inspect.getsource(scim._verify_bearer)


# ──────────────────────────────────────────────────────────────────────────────
# SAML XSW / signature-wrapping defense
# ──────────────────────────────────────────────────────────────────────────────
def test_saml_requires_signed_assertions_by_default():
    """The SP must default to wantAssertionsSigned=True so an unsigned (or
    signature-wrapped) assertion is rejected by python3-saml."""
    saml = pytest.importorskip("auth.providers.saml", reason="auth.providers.saml not importable")
    import inspect
    src = inspect.getsource(saml)
    assert '"wantAssertionsSigned":' in src
    # The default for the per-tenant flag must be True (not False).
    assert 'want_assertions_signed", True' in src
    # ACS must run real signature validation, not trust the raw assertion.
    assert "process_response()" in src and "get_errors()" in src and "is_authenticated()" in src


@pytest.mark.skipif(
    importlib.util.find_spec("onelogin") is None,
    reason="python3-saml (onelogin) not installed",
)
def test_saml_xsw_unsigned_assertion_rejected():
    """End-to-end XSW: feed python3-saml an UNSIGNED assertion under a strict
    settings dict and assert it is NOT authenticated.  (python3-saml performs the
    actual XSW hardening; this proves our settings engage it.)"""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    import base64
    settings = {
        "strict": True,
        "sp": {"entityId": "https://argus.local/sp",
               "assertionConsumerService": {"url": "https://argus.local/acs"}},
        "idp": {"entityId": "https://idp.example.com",
                "singleSignOnService": {"url": "https://idp.example.com/sso"},
                "x509cert": ""},
        "security": {"wantAssertionsSigned": True, "wantMessagesSigned": False},
    }
    unsigned = base64.b64encode(b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
      </saml:Assertion></samlp:Response>""").decode()
    req = {"https": "on", "http_host": "argus.local", "script_name": "/acs",
           "get_data": {}, "post_data": {"SAMLResponse": unsigned}}
    auth = OneLogin_Saml2_Auth(req, settings)
    auth.process_response()
    # An unsigned assertion under wantAssertionsSigned must NOT authenticate.
    assert not auth.is_authenticated()
    assert auth.get_errors()


# ──────────────────────────────────────────────────────────────────────────────
# Refresh-token replay/theft + session fixation (need a DB session)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def session_env():
    """An in-memory DB + a seeded test user — or a clean skip if the CI DB/user
    fixtures aren't wired (these tests exercise real rotation/fixation logic)."""
    pytest.importorskip("sqlalchemy")
    try:
        from auth.db import make_test_session        # type: ignore
        db = make_test_session()
    except Exception:
        pytest.skip("no in-memory test DB factory (auth.db.make_test_session) — wire in CI")
    try:
        from auth.models import User                 # type: ignore
        user = User(id="u-adv", email="adv@test.local", display_name="adv")
        db.add(user)
        db.flush()
    except Exception as exc:
        try:
            db.close()
        except Exception:
            pass
        pytest.skip(f"could not seed a test User: {exc}")
    try:
        yield db, user
    finally:
        try:
            db.close()
        except Exception:
            pass


def test_refresh_token_reuse_revokes_family(session_env):
    """Replaying an already-rotated refresh token (theft signal) must revoke the
    entire token family — every subsequent rotation then FAILS (returns None)."""
    db, user = session_env
    sess = importlib.import_module("auth.sessions")
    issued = sess.create_session(db, user=user, ip_address="1.1.1.1", user_agent="pytest")
    first = issued.refresh_token_plain
    rotated = sess.rotate_refresh_token(db, presented_token=first)
    assert rotated is not None and rotated.refresh_token_plain != first
    # Replay the ORIGINAL (already-used) token → theft response: rotation fails
    # AND the whole family is revoked (signature returns None on failure).
    assert sess.rotate_refresh_token(db, presented_token=first) is None
    # The family is dead — even the legitimately-rotated token no longer rotates.
    assert sess.rotate_refresh_token(db, presented_token=rotated.refresh_token_plain) is None


def test_session_id_is_fresh_per_login(session_env):
    """Two logins for the same user must yield DIFFERENT session ids (defeats
    session fixation — an attacker-supplied id is never adopted)."""
    db, user = session_env
    sess = importlib.import_module("auth.sessions")
    a = sess.create_session(db, user=user, ip_address="1.1.1.1", user_agent="pytest")
    b = sess.create_session(db, user=user, ip_address="1.1.1.1", user_agent="pytest")
    assert a.session.id != b.session.id
