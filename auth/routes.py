"""FastAPI router for /auth/* endpoints.

Routes:

    POST   /auth/login                        — local username + password
    POST   /auth/mfa/verify                   — finish login w/ TOTP
    POST   /auth/mfa/enrol/start              — begin TOTP enrolment
    POST   /auth/mfa/enrol/confirm            — confirm TOTP enrolment
    POST   /auth/mfa/backup-codes/regenerate  — re-roll backup codes
    POST   /auth/logout                       — revoke session
    POST   /auth/refresh                      — rotate refresh token

    GET    /auth/me                           — current user + state
    PATCH  /auth/me/state                     — patch UI state
    POST   /auth/me/change-password           — local password rotate

    GET    /auth/sessions                     — list own active sessions
    DELETE /auth/sessions/{id}                — revoke one of own
    POST   /auth/sessions/terminate-all       — kill all but current

    GET    /auth/sso/oidc/{idp_id}/start
    GET    /auth/sso/oidc/{idp_id}/callback
    GET    /auth/sso/saml/{idp_id}/metadata
    POST   /auth/sso/saml/{idp_id}/acs
    GET    /auth/sso/providers                — public list per tenant

    Admin (RBAC-gated):
    GET    /auth/admin/users
    POST   /auth/admin/users
    PATCH  /auth/admin/users/{id}
    POST   /auth/admin/users/{id}/role
    DELETE /auth/admin/users/{id}/role/{role_code}
    GET    /auth/admin/audit
    POST   /auth/admin/audit/retention
    POST   /auth/admin/audit/delete           — OWNER only
    GET    /auth/admin/sessions               — all sessions
    DELETE /auth/admin/sessions/{id}
    GET    /auth/admin/identity-providers
    POST   /auth/admin/identity-providers
    POST   /auth/admin/scim-tokens

This file is intentionally long — keeping all routes in one place makes
the API surface auditable.  Helpers live above the route handlers.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import (APIRouter, Depends, Header, HTTPException, Query, Request,
                     Response, status)
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from auth.audit import (audit_log, count_audit_logs, delete_audit_logs,
                         get_audit_logs, set_retention)
from auth.config import CONFIG
from auth.db import get_db
from auth.dependencies import (
    current_auth_context, current_session, get_current_user,
    require_csrf, require_permission, require_reauth, require_role,
)
from auth.models import (
    AuditSeverity, AuthMethod, IdentityProvider, IdentityProviderKind,
    MfaBackupCode, MfaFactorType, RoleCode, Setting,
    Tenant, User, UserCredentialLocal, UserIdentity, UserMfaFactor,
    UserRoleAssignment, UserStatus,
)
from auth.providers.local import LocalAuthProvider
from auth.providers.base import AuthError
from auth.rbac import (
    Role, role_can_be_granted_by, role_default_skin, roles_of,
)
from auth.scim import issue_scim_token
from auth.schemas import (
    AuditEntry, BackupCodesResponse, ChangePasswordRequest,
    CreateIdentityProviderRequest, CreateScimTokenRequest, CreateUserRequest,
    DeleteAuditRequest, IdentityProviderResponse, LoginInitialResponse,
    LoginRequest, MeResponse, MfaVerifyRequest, PatchStateRequest,
    RefreshRequest, RoleAssignmentRequest, ScimTokenIssued,
    SessionSummary, SetRetentionRequest, TokenResponse,
    TotpEnrolConfirmRequest, TotpEnrolStartResponse, UpdateUserRequest,
    UserSummary,
)
from auth.security.mfa import (
    decrypt_totp_secret, encrypt_totp_secret, generate_backup_codes,
    generate_totp_secret, hash_backup_code, totp_provisioning_uri,
    totp_qr_png_base64, verify_backup_code, verify_totp,
)
from auth.security.passwords import (
    hash_password, validate_policy, verify_password,
)
from auth.security.tokens import (
    generate_refresh_token, hash_refresh_token, issue_access_token,
)
from auth.sessions import (
    create_session, get_state, list_active_sessions, patch_state,
    revoke_all_user_sessions, revoke_session, rotate_refresh_token,
)

logger = logging.getLogger("argus.auth.routes")
router = APIRouter(prefix="/auth", tags=["auth"])


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────


# Short-lived MFA-challenge tokens — opaque, stored in-memory.  In prod
# move this to Redis or a DB table; for a single-process server the
# dict is fine and avoids a round-trip.
_MFA_CHALLENGES: Dict[str, Dict[str, Any]] = {}


def _issue_mfa_challenge(user_id: str, *, ttl_min: int = 5) -> Dict[str, Any]:
    tok = "mfa_" + secrets.token_urlsafe(48)
    record = {
        "user_id":   user_id,
        "expires":   datetime.now(timezone.utc) + timedelta(minutes=ttl_min),
        "attempts":  0,
    }
    _MFA_CHALLENGES[tok] = record
    return {"token": tok, "expires": record["expires"]}


def _consume_mfa_challenge(token: str) -> Optional[str]:
    record = _MFA_CHALLENGES.get(token)
    if not record:
        return None
    if record["expires"] < datetime.now(timezone.utc):
        _MFA_CHALLENGES.pop(token, None)
        return None
    if record["attempts"] >= 5:
        _MFA_CHALLENGES.pop(token, None)
        return None
    record["attempts"] += 1
    return record["user_id"]


def _set_session_cookies(response: Response, *,
                          access_token: str,
                          refresh_token: str,
                          session_id: str,
                          csrf_token: str) -> None:
    common = dict(
        secure=CONFIG.cookie_secure,
        httponly=True,
        samesite=CONFIG.cookie_samesite,
        path=CONFIG.cookie_path,
    )
    if CONFIG.cookie_domain:
        common["domain"] = CONFIG.cookie_domain

    response.set_cookie(
        CONFIG.session_cookie_name, session_id,
        max_age=CONFIG.session_max_lifetime_hours * 3600, **common,
    )
    response.set_cookie(
        CONFIG.refresh_cookie_name, refresh_token,
        max_age=CONFIG.jwt_refresh_ttl_days * 86400, **common,
    )
    # CSRF cookie is NOT httpOnly — JS reads it for the X-CSRF-Token header
    csrf_cookie = {**common, "httponly": False}
    response.set_cookie(
        "argus_csrf", csrf_token,
        max_age=CONFIG.session_max_lifetime_hours * 3600, **csrf_cookie,
    )


def _clear_session_cookies(response: Response) -> None:
    for name in (CONFIG.session_cookie_name, CONFIG.refresh_cookie_name, "argus_csrf"):
        response.delete_cookie(name, path=CONFIG.cookie_path,
                               domain=CONFIG.cookie_domain or None)


def _build_token_response(issued, user: User, *,
                          must_change_password: Optional[bool] = None) -> TokenResponse:
    # If caller didn't pass the flag explicitly, read it from the user's
    # credential row.  This surfaces the must-change bit set by either
    # admin password reset (CLI), forced rotation, or initial bootstrap.
    if must_change_password is None:
        must_change_password = bool(
            user.credential and user.credential.must_change
        )
    return TokenResponse(
        access_token=issued.access_token,
        refresh_token=issued.refresh_token_plain,
        expires_in=issued.access_ttl_seconds,
        refresh_expires_in=issued.refresh_ttl_seconds,
        csrf_token=issued.csrf_token,
        user_id=user.id,
        roles=[r.value for r in roles_of(user)],
        must_change_password=must_change_password,
    )


def _client_ip(request: Request) -> Optional[str]:
    # Prefer X-Forwarded-For when present (deployment behind proxy)
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


# ─────────────────────────────────────────────────────────────────
#  Login + MFA + Logout
# ─────────────────────────────────────────────────────────────────


@router.post("/login", response_model=None)
def login(body: LoginRequest, request: Request, response: Response,
          db: DbSession = Depends(get_db)):
    provider = LocalAuthProvider(db)
    ip = _client_ip(request)
    ua = request.headers.get("user-agent")
    try:
        result = provider.authenticate(
            email=body.email, password=body.password, ip_address=ip,
        )
    except AuthError as e:
        return Response(status_code=e.http_status,
                        content=f'{{"detail":"{e.message}","code":"{e.code}"}}',
                        media_type="application/json")

    user = result.user
    if result.requires_mfa:
        if not user.mfa_factors:
            # MFA required by role but not enrolled — block + force enrolment
            audit_log(action="auth.login_blocked_mfa_required",
                      actor=user, severity=AuditSeverity.SECURITY,
                      status="failure", ip_address=ip)
            return Response(status_code=403,
                            content='{"detail":"MFA enrolment required",'
                                    '"code":"mfa_enrolment_required"}',
                            media_type="application/json")

        chal = _issue_mfa_challenge(user.id)
        factor_types = list({f.factor_type.value for f in user.mfa_factors})
        audit_log(action="auth.login_mfa_challenge", actor=user,
                  ip_address=ip, user_agent=ua,
                  severity=AuditSeverity.INFO)
        return LoginInitialResponse(
            mfa_token=chal["token"], factor_types=factor_types,
            expires_in=300,
        )

    # No MFA — issue session directly
    issued = create_session(db, user=user, ip_address=ip, user_agent=ua,
                             mfa_passed=False)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    audit_log(action="auth.login_success", actor=user,
              actor_session_id=issued.session.id,
              ip_address=ip, user_agent=ua,
              severity=AuditSeverity.NOTICE)
    _set_session_cookies(response,
                          access_token=issued.access_token,
                          refresh_token=issued.refresh_token_plain,
                          session_id=issued.session.id,
                          csrf_token=issued.csrf_token)
    return _build_token_response(issued, user)


@router.post("/mfa/verify", response_model=TokenResponse)
def mfa_verify(body: MfaVerifyRequest, request: Request, response: Response,
               db: DbSession = Depends(get_db)):
    user_id = _consume_mfa_challenge(body.mfa_token)
    if not user_id:
        raise HTTPException(401, detail={"code": "mfa_token_invalid",
                                         "message": "Invalid or expired MFA token."})
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(401, detail={"code": "mfa_user_missing"})

    ip = _client_ip(request)
    ua = request.headers.get("user-agent")

    if body.is_backup:
        # Try each unused backup code
        ok = False
        for bc in (user.backup_codes or []):
            if bc.used_at is not None:
                continue
            if verify_backup_code(body.code, bc.code_hash):
                bc.used_at = datetime.now(timezone.utc)
                ok = True
                break
        if not ok:
            audit_log(action="auth.mfa_backup_failed", actor=user,
                      severity=AuditSeverity.SECURITY,
                      status="failure", ip_address=ip)
            db.commit()
            raise HTTPException(401, detail={"code": "mfa_bad_code"})
        audit_log(action="auth.mfa_backup_used", actor=user,
                  severity=AuditSeverity.SECURITY, ip_address=ip)
    else:
        # TOTP — try every enrolled factor; record `last_used_at`
        ok = False
        for f in (user.mfa_factors or []):
            if f.factor_type != MfaFactorType.TOTP or not f.secret_encrypted:
                continue
            secret = decrypt_totp_secret(f.secret_encrypted)
            if verify_totp(secret, body.code):
                f.last_used_at = datetime.now(timezone.utc)
                ok = True
                break
        if not ok:
            audit_log(action="auth.mfa_failed", actor=user,
                      severity=AuditSeverity.WARN,
                      status="failure", ip_address=ip)
            db.commit()
            raise HTTPException(401, detail={"code": "mfa_bad_code"})

    db.commit()
    issued = create_session(db, user=user, ip_address=ip, user_agent=ua,
                             mfa_passed=True)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    audit_log(action="auth.login_success_mfa", actor=user,
              actor_session_id=issued.session.id,
              ip_address=ip, user_agent=ua,
              severity=AuditSeverity.NOTICE)
    _set_session_cookies(response,
                          access_token=issued.access_token,
                          refresh_token=issued.refresh_token_plain,
                          session_id=issued.session.id,
                          csrf_token=issued.csrf_token)
    return _build_token_response(issued, user)


@router.post("/logout")
def logout(request: Request, response: Response,
           ctx = Depends(current_auth_context),
           db: DbSession = Depends(get_db)):
    revoke_session(db, ctx.session.id, reason="logout")
    audit_log(action="auth.logout", actor=ctx.user,
              actor_session_id=ctx.session.id,
              ip_address=_client_ip(request),
              severity=AuditSeverity.INFO)
    _clear_session_cookies(response)
    return {"ok": True}


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: Optional[RefreshRequest] = None, *,
            request: Request, response: Response,
            db: DbSession = Depends(get_db)):
    presented = (body and body.refresh_token) or request.cookies.get(CONFIG.refresh_cookie_name)
    if not presented:
        raise HTTPException(401, detail="Missing refresh token.")
    issued = rotate_refresh_token(db, presented_token=presented)
    if issued is None:
        _clear_session_cookies(response)
        raise HTTPException(401, detail="Refresh failed.")
    user = db.get(User, issued.session.user_id)
    _set_session_cookies(response,
                          access_token=issued.access_token,
                          refresh_token=issued.refresh_token_plain,
                          session_id=issued.session.id,
                          csrf_token=issued.csrf_token)
    return _build_token_response(issued, user)


# ─────────────────────────────────────────────────────────────────
#  MFA enrolment / management
# ─────────────────────────────────────────────────────────────────


@router.post("/mfa/enrol/start", response_model=TotpEnrolStartResponse)
def mfa_enrol_start(user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    secret = generate_totp_secret()
    factor = UserMfaFactor(
        user_id=user.id,
        factor_type=MfaFactorType.TOTP,
        label="Authenticator",
        secret_encrypted=encrypt_totp_secret(secret),
        is_primary=not user.mfa_factors,
    )
    db.add(factor)
    db.commit()
    return TotpEnrolStartResponse(
        factor_id=factor.id, secret_b32=secret,
        otpauth_uri=totp_provisioning_uri(secret, user.email),
        qr_data_uri=totp_qr_png_base64(secret, user.email),
    )


@router.post("/mfa/enrol/confirm", response_model=BackupCodesResponse)
def mfa_enrol_confirm(body: TotpEnrolConfirmRequest,
                      user: User = Depends(get_current_user),
                      _csrf=Depends(require_csrf),
                      db: DbSession = Depends(get_db)):
    factor = db.get(UserMfaFactor, body.factor_id)
    if factor is None or factor.user_id != user.id:
        raise HTTPException(404, detail="MFA factor not found.")
    secret = decrypt_totp_secret(factor.secret_encrypted or "")
    if not verify_totp(secret, body.code):
        raise HTTPException(400, detail={"code": "totp_invalid"})

    user.mfa_enabled = True
    factor.last_used_at = datetime.now(timezone.utc)

    # Issue backup codes — wipe any prior, hash and store new
    db.query(MfaBackupCode).filter(MfaBackupCode.user_id == user.id).delete()
    plain = generate_backup_codes()
    for code in plain:
        db.add(MfaBackupCode(user_id=user.id, code_hash=hash_backup_code(code)))
    db.commit()
    audit_log(action="auth.mfa_enroled", actor=user,
              severity=AuditSeverity.SECURITY)
    return BackupCodesResponse(codes=plain)


@router.post("/mfa/backup-codes/regenerate", response_model=BackupCodesResponse)
def mfa_regenerate_backup(user: User = Depends(require_reauth()),
                          _csrf=Depends(require_csrf),
                          db: DbSession = Depends(get_db)):
    db.query(MfaBackupCode).filter(MfaBackupCode.user_id == user.id).delete()
    plain = generate_backup_codes()
    for code in plain:
        db.add(MfaBackupCode(user_id=user.id, code_hash=hash_backup_code(code)))
    db.commit()
    audit_log(action="auth.mfa_backup_regenerated", actor=user,
              severity=AuditSeverity.SECURITY)
    return BackupCodesResponse(codes=plain)


@router.delete("/mfa/factor/{factor_id}")
def mfa_remove_factor(factor_id: str,
                       user: User = Depends(require_reauth()),
                       _csrf=Depends(require_csrf),
                       db: DbSession = Depends(get_db)):
    f = db.get(UserMfaFactor, factor_id)
    if f is None or f.user_id != user.id:
        raise HTTPException(404, detail="Factor not found.")
    db.delete(f)
    remaining = db.query(UserMfaFactor).filter(
        UserMfaFactor.user_id == user.id).count() - 1
    if remaining <= 0:
        user.mfa_enabled = False
    db.commit()
    audit_log(action="auth.mfa_factor_removed", actor=user,
              severity=AuditSeverity.SECURITY,
              after_data={"factor_id": factor_id})
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────
#  /me — self-service
# ─────────────────────────────────────────────────────────────────


@router.get("/me", response_model=MeResponse)
def me(ctx = Depends(current_auth_context),
       db: DbSession = Depends(get_db)):
    user = ctx.user
    return MeResponse(
        id=user.id, email=user.email, username=user.username,
        display_name=user.display_name, status=user.status.value,
        primary_auth_method=user.primary_auth_method.value,
        mfa_enabled=user.mfa_enabled,
        tenant_id=user.tenant_id,
        current_tenant_id=ctx.session.current_tenant_id,
        roles=[r.value for r in roles_of(user)],
        attributes=user.attributes or {},
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        session_state=get_state(db, ctx.user.id),
        must_change_password=bool(
            user.credential and user.credential.must_change
        ),
    )


@router.patch("/me/state")
def me_patch_state(body: PatchStateRequest,
                   _csrf=Depends(require_csrf),
                   ctx = Depends(current_auth_context),
                   db: DbSession = Depends(get_db)):
    merged = patch_state(db, ctx.user.id, body.state)
    return {"ok": True, "state": merged}


@router.post("/me/change-password")
def me_change_password(body: ChangePasswordRequest,
                       _csrf=Depends(require_csrf),
                       user: User = Depends(get_current_user),
                       db: DbSession = Depends(get_db)):
    cred = user.credential
    if cred is None:
        raise HTTPException(400, detail={"code": "no_local_password",
                                         "message": "SSO-only account."})
    ok, _ = verify_password(body.current_password, cred.password_hash,
                            cred.pepper_version)
    if not ok:
        audit_log(action="auth.password_change_failed", actor=user,
                  severity=AuditSeverity.SECURITY, status="failure")
        raise HTTPException(400, detail={"code": "current_password_wrong"})

    validate_policy(body.new_password, email=user.email, username=user.username)
    new_hash, ver = hash_password(body.new_password)
    cred.password_hash = new_hash
    cred.pepper_version = ver
    cred.must_change = False
    cred.last_rotated_at = datetime.now(timezone.utc)
    db.commit()

    # Revoke all OTHER sessions on password change (best practice)
    from auth.dependencies import current_session as _cs    # avoid cycle
    revoke_all_user_sessions(db, user.id, reason="password_change",
                              except_session_id=None)

    audit_log(action="auth.password_changed", actor=user,
              severity=AuditSeverity.SECURITY)
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────
#  Sessions — list / revoke own
# ─────────────────────────────────────────────────────────────────


@router.get("/sessions", response_model=List[SessionSummary])
def list_my_sessions(user: User = Depends(get_current_user),
                     db: DbSession = Depends(get_db)):
    rows = list_active_sessions(db, user.id)
    # Per-user pinned session lives in the user's SessionState row now
    user_state = db.get(__import__('auth.models', fromlist=['SessionState']).SessionState, user.id)
    pinned = user_state.pinned_pentest_session_id if user_state else None
    return [
        SessionSummary(
            id=s.id, user_id=s.user_id,
            created_at=s.created_at, last_seen_at=s.last_seen_at,
            expires_at=s.expires_at, ip_address=s.ip_address_seen,
            user_agent=s.user_agent,
            current_tenant_id=s.current_tenant_id,
            revoked_at=s.revoked_at,
            pinned_pentest_session_id=pinned,
        ) for s in rows
    ]


@router.delete("/sessions/{sid}")
def revoke_my_session(sid: str, _csrf=Depends(require_csrf),
                       user: User = Depends(get_current_user),
                       db: DbSession = Depends(get_db)):
    s = db.get(__import__('auth.models', fromlist=['Session']).Session, sid)
    if s is None or s.user_id != user.id:
        raise HTTPException(404)
    revoke_session(db, sid, reason="user_revoked")
    audit_log(action="auth.session_revoked", actor=user,
              actor_session_id=sid, severity=AuditSeverity.NOTICE,
              after_data={"reason": "user_revoked"})
    return {"ok": True}


@router.post("/sessions/terminate-all")
def revoke_all_my_sessions(_csrf=Depends(require_csrf),
                            ctx = Depends(current_auth_context),
                            db: DbSession = Depends(get_db)):
    n = revoke_all_user_sessions(db, ctx.user.id, reason="user_terminate_all",
                                  except_session_id=ctx.session.id)
    audit_log(action="auth.sessions_terminated_all", actor=ctx.user,
              actor_session_id=ctx.session.id,
              severity=AuditSeverity.SECURITY,
              after_data={"count": n})
    return {"ok": True, "revoked": n}


# ─────────────────────────────────────────────────────────────────
#  SSO
# ─────────────────────────────────────────────────────────────────


@router.get("/sso/providers")
def list_providers(tenant_slug: Optional[str] = Query(None),
                   db: DbSession = Depends(get_db)):
    """Public list of enabled IdPs per tenant — drives login page."""
    q = select(IdentityProvider).where(IdentityProvider.enabled == True)  # noqa: E712
    if tenant_slug:
        q = q.join(Tenant).where(Tenant.slug == tenant_slug)
    rows = db.execute(q).scalars().all()
    return [{"id": p.id, "name": p.name, "kind": p.kind.value} for p in rows]


@router.get("/sso/oidc/{idp_id}/start")
def oidc_start(idp_id: str, request: Request, response: Response,
               db: DbSession = Depends(get_db)):
    from auth.providers.oidc import OidcProvider
    idp = db.get(IdentityProvider, idp_id)
    if idp is None or idp.kind != IdentityProviderKind.OIDC:
        raise HTTPException(404, "OIDC provider not found.")
    redirect_uri = idp.config.get("redirect_uri") or str(request.url_for(
        "oidc_callback", idp_id=idp.id))
    prov = OidcProvider(db, idp)
    url, state = prov.build_authorization_url(redirect_uri=redirect_uri)

    # State stash — signed cookie (short-lived)
    response = RedirectResponse(url=url, status_code=302)
    response.set_cookie("argus_oidc_state", state["state"],
                        max_age=600, secure=CONFIG.cookie_secure,
                        httponly=True, samesite="lax")
    response.set_cookie("argus_oidc_nonce", state["nonce"],
                        max_age=600, secure=CONFIG.cookie_secure,
                        httponly=True, samesite="lax")
    response.set_cookie("argus_oidc_verifier", state["code_verifier"],
                        max_age=600, secure=CONFIG.cookie_secure,
                        httponly=True, samesite="lax")
    return response


@router.get("/sso/oidc/{idp_id}/callback", name="oidc_callback")
def oidc_callback(idp_id: str, request: Request, response: Response,
                  code: Optional[str] = Query(None),
                  state: Optional[str] = Query(None),
                  db: DbSession = Depends(get_db)):
    from auth.providers.oidc import OidcProvider
    idp = db.get(IdentityProvider, idp_id)
    if idp is None or idp.kind != IdentityProviderKind.OIDC:
        raise HTTPException(404, "OIDC provider not found.")

    saved_state = request.cookies.get("argus_oidc_state")
    saved_nonce = request.cookies.get("argus_oidc_nonce")
    verifier = request.cookies.get("argus_oidc_verifier")
    if not (saved_state and state and saved_state == state and verifier):
        raise HTTPException(400, "OIDC state/verifier missing or mismatch.")

    prov = OidcProvider(db, idp)
    redirect_uri = idp.config.get("redirect_uri") or str(request.url_for(
        "oidc_callback", idp_id=idp.id))
    try:
        tok = prov.exchange_code(code=code, code_verifier=verifier,
                                  redirect_uri=redirect_uri)
        id_token = tok.get("id_token")
        if not id_token:
            raise AuthError("Missing id_token.", code="oidc_no_id_token")
        claims = prov.validate_id_token(id_token, nonce=saved_nonce or "")
        result = prov.upsert_user_from_claims(claims)
    except AuthError as e:
        audit_log(action="auth.oidc_failed",
                  severity=AuditSeverity.WARN, status="failure",
                  error_message=e.code, after_data={"idp_id": idp_id},
                  ip_address=_client_ip(request))
        raise HTTPException(e.http_status, detail={"code": e.code,
                                                    "message": e.message})

    user = result.user
    ip = _client_ip(request)
    ua = request.headers.get("user-agent")
    if result.requires_mfa and user.mfa_factors:
        # SSO completed but role mandates MFA → second factor
        chal = _issue_mfa_challenge(user.id)
        audit_log(action="auth.oidc_mfa_challenge", actor=user,
                  severity=AuditSeverity.INFO,
                  after_data={"idp_id": idp_id})
        # Re-direct to a frontend MFA challenge page
        return RedirectResponse(
            url=f"/?mfa_token={chal['token']}", status_code=302
        )

    issued = create_session(db, user=user, ip_address=ip, user_agent=ua,
                             mfa_passed=False)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    audit_log(action="auth.oidc_login_success", actor=user,
              actor_session_id=issued.session.id,
              ip_address=ip, user_agent=ua,
              severity=AuditSeverity.NOTICE,
              after_data={"idp_id": idp_id})
    resp = RedirectResponse(url="/", status_code=302)
    _set_session_cookies(resp,
                          access_token=issued.access_token,
                          refresh_token=issued.refresh_token_plain,
                          session_id=issued.session.id,
                          csrf_token=issued.csrf_token)
    return resp


@router.get("/sso/saml/{idp_id}/metadata")
def saml_metadata(idp_id: str, request: Request, db: DbSession = Depends(get_db)):
    from auth.providers.saml import SamlProvider
    idp = db.get(IdentityProvider, idp_id)
    if idp is None or idp.kind != IdentityProviderKind.SAML:
        raise HTTPException(404)
    prov = SamlProvider(db, idp)
    http_req = _build_saml_http_request(request)
    return Response(content=prov.get_sp_metadata(http_req),
                    media_type="application/xml")


@router.post("/sso/saml/{idp_id}/acs")
async def saml_acs(idp_id: str, request: Request, response: Response,
                    db: DbSession = Depends(get_db)):
    from auth.providers.saml import SamlProvider
    idp = db.get(IdentityProvider, idp_id)
    if idp is None or idp.kind != IdentityProviderKind.SAML:
        raise HTTPException(404)
    prov = SamlProvider(db, idp)
    http_req = await _build_saml_http_request_async(request)
    try:
        result = prov.process_acs(http_req)
    except AuthError as e:
        audit_log(action="auth.saml_failed",
                  severity=AuditSeverity.WARN, status="failure",
                  error_message=e.code, after_data={"idp_id": idp_id})
        raise HTTPException(e.http_status, detail={"code": e.code,
                                                    "message": e.message})

    user = result.user
    ip = _client_ip(request)
    ua = request.headers.get("user-agent")
    issued = create_session(db, user=user, ip_address=ip, user_agent=ua,
                             mfa_passed=False)
    audit_log(action="auth.saml_login_success", actor=user,
              actor_session_id=issued.session.id,
              ip_address=ip, user_agent=ua,
              severity=AuditSeverity.NOTICE,
              after_data={"idp_id": idp_id})
    resp = RedirectResponse(url="/", status_code=302)
    _set_session_cookies(resp,
                          access_token=issued.access_token,
                          refresh_token=issued.refresh_token_plain,
                          session_id=issued.session.id,
                          csrf_token=issued.csrf_token)
    return resp


def _build_saml_http_request(request: Request) -> Dict[str, Any]:
    return {
        "https":       "on" if request.url.scheme == "https" else "off",
        "http_host":    request.url.hostname or "",
        "server_port":  request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name":  request.url.path,
        "get_data":     dict(request.query_params),
        "post_data":    {},
    }


async def _build_saml_http_request_async(request: Request) -> Dict[str, Any]:
    base = _build_saml_http_request(request)
    try:
        form = await request.form()
        base["post_data"] = dict(form)
    except Exception:
        base["post_data"] = {}
    return base


# ─────────────────────────────────────────────────────────────────
#  Admin — users
# ─────────────────────────────────────────────────────────────────


@router.get("/admin/users", response_model=List[UserSummary])
def admin_list_users(actor: User = Depends(require_permission("users", "read")),
                     db: DbSession = Depends(get_db),
                     limit: int = 100, offset: int = 0):
    rows = db.execute(
        select(User).where(User.tenant_id == actor.tenant_id,
                            User.deleted_at.is_(None))
        .order_by(User.created_at.desc())
        .limit(limit).offset(offset)
    ).scalars().all()
    return [
        UserSummary(
            id=u.id, email=u.email, username=u.username,
            display_name=u.display_name, status=u.status.value,
            mfa_enabled=u.mfa_enabled,
            primary_auth_method=u.primary_auth_method.value,
            roles=[r.value for r in roles_of(u)],
            created_at=u.created_at, last_login_at=u.last_login_at,
        ) for u in rows
    ]


@router.post("/admin/users", response_model=UserSummary, status_code=201)
def admin_create_user(body: CreateUserRequest,
                      _csrf=Depends(require_csrf),
                      actor: User = Depends(require_permission("users", "create")),
                      _reauth: User = Depends(require_reauth()),
                      db: DbSession = Depends(get_db)):
    email_norm = body.email.strip().lower()
    existing = db.execute(
        select(User).where(User.tenant_id == actor.tenant_id,
                            User.email == email_norm)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(409, "User already exists.")

    user = User(
        tenant_id=actor.tenant_id,
        email=email_norm, username=body.username,
        display_name=body.display_name,
        status=UserStatus.INVITED if body.send_invite else UserStatus.ACTIVE,
        primary_auth_method=AuthMethod.LOCAL,
        attributes=body.attributes or {},
    )
    db.add(user)
    db.flush()

    if body.initial_password:
        validate_policy(body.initial_password, email=email_norm,
                         username=body.username)
        h, ver = hash_password(body.initial_password)
        db.add(UserCredentialLocal(user_id=user.id, password_hash=h,
                                    pepper_version=ver, must_change=True))

    # Role assignments — apply hierarchical-grant check
    for r in body.roles or []:
        try:
            role_enum = Role(r)
        except ValueError:
            raise HTTPException(400, f"Unknown role: {r}")
        if not role_can_be_granted_by(actor, role_enum):
            raise HTTPException(403, f"You cannot grant role {r}.")
        db.add(UserRoleAssignment(
            user_id=user.id, tenant_id=actor.tenant_id, role=RoleCode(role_enum.value),
            granted_by_user_id=actor.id,
        ))

    db.commit()
    audit_log(action="admin.user_created", actor=actor,
              severity=AuditSeverity.SECURITY,
              resource_type="users", resource_id=user.id,
              after_data={"email": email_norm,
                          "roles": body.roles,
                          "send_invite": body.send_invite})
    return UserSummary(
        id=user.id, email=user.email, username=user.username,
        display_name=user.display_name, status=user.status.value,
        mfa_enabled=user.mfa_enabled,
        primary_auth_method=user.primary_auth_method.value,
        roles=[r.value for r in roles_of(user)],
        created_at=user.created_at, last_login_at=user.last_login_at,
    )


@router.patch("/admin/users/{uid}", response_model=UserSummary)
def admin_update_user(uid: str, body: UpdateUserRequest,
                      _csrf=Depends(require_csrf),
                      actor: User = Depends(require_permission("users", "update")),
                      db: DbSession = Depends(get_db)):
    user = db.get(User, uid)
    if user is None or user.tenant_id != actor.tenant_id:
        raise HTTPException(404)
    before = {"display_name": user.display_name,
              "username": user.username, "status": user.status.value}
    if body.display_name is not None: user.display_name = body.display_name
    if body.username is not None:     user.username     = body.username
    if body.status is not None:
        try:
            user.status = UserStatus(body.status)
        except ValueError:
            raise HTTPException(400, f"Unknown status: {body.status}")
    if body.attributes is not None:   user.attributes   = {**(user.attributes or {}),
                                                              **body.attributes}
    db.commit()
    audit_log(action="admin.user_updated", actor=actor,
              severity=AuditSeverity.NOTICE,
              resource_type="users", resource_id=user.id,
              before_data=before,
              after_data={"display_name": user.display_name,
                          "username": user.username,
                          "status": user.status.value})
    return UserSummary(
        id=user.id, email=user.email, username=user.username,
        display_name=user.display_name, status=user.status.value,
        mfa_enabled=user.mfa_enabled,
        primary_auth_method=user.primary_auth_method.value,
        roles=[r.value for r in roles_of(user)],
        created_at=user.created_at, last_login_at=user.last_login_at,
    )


@router.post("/admin/users/{uid}/role")
def admin_grant_role(uid: str, body: RoleAssignmentRequest,
                      _csrf=Depends(require_csrf),
                      actor: User = Depends(require_permission("roles", "assign")),
                      _reauth: User = Depends(require_reauth()),
                      db: DbSession = Depends(get_db)):
    user = db.get(User, uid)
    if user is None or user.tenant_id != actor.tenant_id:
        raise HTTPException(404)
    try:
        role_enum = Role(body.role)
    except ValueError:
        raise HTTPException(400, f"Unknown role: {body.role}")
    if not role_can_be_granted_by(actor, role_enum):
        raise HTTPException(403, f"You cannot grant role {role_enum.value}.")
    attrs = {}
    if body.engagement_ids is not None:
        attrs["engagement_ids"] = body.engagement_ids

    # Idempotency: if already granted with same scope, no-op
    existing = next((a for a in (user.role_assigns or [])
                     if a.role == RoleCode(role_enum.value)
                     and a.tenant_id == (body.tenant_id or actor.tenant_id)),
                    None)
    if existing is not None:
        existing.attributes = {**(existing.attributes or {}), **attrs}
        existing.expires_at = body.expires_at or existing.expires_at
    else:
        db.add(UserRoleAssignment(
            user_id=user.id,
            tenant_id=body.tenant_id or actor.tenant_id,
            role=RoleCode(role_enum.value),
            attributes=attrs,
            expires_at=body.expires_at,
            granted_by_user_id=actor.id,
        ))
    db.commit()
    audit_log(action="admin.role_granted", actor=actor,
              severity=AuditSeverity.SECURITY,
              resource_type="users", resource_id=user.id,
              after_data={"role": role_enum.value,
                          "engagement_ids": body.engagement_ids,
                          "expires_at": body.expires_at.isoformat() if body.expires_at else None})
    return {"ok": True}


@router.delete("/admin/users/{uid}/role/{role_code}")
def admin_revoke_role(uid: str, role_code: str,
                       _csrf=Depends(require_csrf),
                       actor: User = Depends(require_permission("roles", "assign")),
                       db: DbSession = Depends(get_db)):
    user = db.get(User, uid)
    if user is None or user.tenant_id != actor.tenant_id:
        raise HTTPException(404)
    try:
        role_enum = Role(role_code)
    except ValueError:
        raise HTTPException(400, f"Unknown role: {role_code}")
    # Cannot revoke OWNER unless you're OWNER, and never revoke the last OWNER
    if role_enum == Role.OWNER:
        owners = db.query(UserRoleAssignment).filter(
            UserRoleAssignment.role == RoleCode.OWNER,
            UserRoleAssignment.tenant_id == actor.tenant_id,
        ).count()
        from auth.rbac import _has_role
        if not _has_role(actor, Role.OWNER):
            raise HTTPException(403, "Only OWNER can revoke OWNER.")
        if owners <= 1:
            raise HTTPException(400, "Cannot revoke the last OWNER.")

    n = db.query(UserRoleAssignment).filter(
        UserRoleAssignment.user_id == user.id,
        UserRoleAssignment.role == RoleCode(role_enum.value),
    ).delete()
    db.commit()
    audit_log(action="admin.role_revoked", actor=actor,
              severity=AuditSeverity.SECURITY,
              resource_type="users", resource_id=user.id,
              after_data={"role": role_enum.value, "rows_removed": n})
    return {"ok": True, "removed": n}


# ─────────────────────────────────────────────────────────────────
#  Admin — audit
# ─────────────────────────────────────────────────────────────────


@router.get("/admin/audit", response_model=List[AuditEntry])
def admin_audit_list(actor: User = Depends(require_permission("audit_logs", "read")),
                     db: DbSession = Depends(get_db),
                     limit: int = 100, offset: int = 0,
                     action_prefix: Optional[str] = None,
                     resource_type: Optional[str] = None,
                     resource_id: Optional[str] = None):
    rows = get_audit_logs(db, tenant_id=actor.tenant_id,
                          action_prefix=action_prefix,
                          resource_type=resource_type,
                          resource_id=resource_id,
                          limit=limit, offset=offset)
    return [AuditEntry(
        id=r.id, ts=r.ts, actor_user_id=r.actor_user_id,
        tenant_id=r.tenant_id, action=r.action,
        resource_type=r.resource_type, resource_id=r.resource_id,
        ip_address=r.ip_address, severity=r.severity.value if r.severity else "INFO",
        status=r.status, error_message=r.error_message,
        before_data=r.before_data, after_data=r.after_data,
    ) for r in rows]


@router.post("/admin/audit/retention")
def admin_set_retention(body: SetRetentionRequest,
                         _csrf=Depends(require_csrf),
                         actor: User = Depends(require_permission("audit_logs", "configure")),
                         _reauth: User = Depends(require_reauth()),
                         db: DbSession = Depends(get_db)):
    set_retention(db, actor=actor,
                   max_rows=body.max_rows, max_age_days=body.max_age_days)
    return {"ok": True}


@router.post("/admin/audit/delete")
def admin_delete_audit(body: DeleteAuditRequest,
                        _csrf=Depends(require_csrf),
                        actor: User = Depends(require_role("OWNER")),
                        _reauth: User = Depends(require_reauth()),
                        db: DbSession = Depends(get_db)):
    n = delete_audit_logs(db, actor=actor, ids=body.ids,
                           older_than=body.older_than, reason=body.reason)
    return {"ok": True, "deleted": n}


# ─────────────────────────────────────────────────────────────────
#  Admin — identity providers
# ─────────────────────────────────────────────────────────────────


@router.get("/admin/identity-providers", response_model=List[IdentityProviderResponse])
def admin_list_idps(actor: User = Depends(require_permission("identity_providers", "read")),
                     db: DbSession = Depends(get_db)):
    rows = db.execute(
        select(IdentityProvider).where(IdentityProvider.tenant_id == actor.tenant_id)
    ).scalars().all()
    return [IdentityProviderResponse(
        id=p.id, tenant_id=p.tenant_id, name=p.name, kind=p.kind.value,
        enabled=p.enabled, config=_redact_secrets(p.config),
        role_mapping=p.role_mapping, default_role=p.default_role.value,
        just_in_time_provisioning=p.just_in_time_provisioning,
        created_at=p.created_at, updated_at=p.updated_at,
    ) for p in rows]


@router.post("/admin/identity-providers", response_model=IdentityProviderResponse, status_code=201)
def admin_create_idp(body: CreateIdentityProviderRequest,
                      _csrf=Depends(require_csrf),
                      actor: User = Depends(require_permission("identity_providers", "create")),
                      _reauth: User = Depends(require_reauth()),
                      db: DbSession = Depends(get_db)):
    try:
        kind = IdentityProviderKind(body.kind)
    except ValueError:
        raise HTTPException(400, f"Unknown IdP kind: {body.kind}")
    try:
        default_role = RoleCode(body.default_role)
    except ValueError:
        raise HTTPException(400, f"Unknown role: {body.default_role}")

    idp = IdentityProvider(
        tenant_id=actor.tenant_id,
        name=body.name, kind=kind, enabled=body.enabled,
        config=body.config or {},
        role_mapping=body.role_mapping or {},
        default_role=default_role,
        just_in_time_provisioning=body.just_in_time_provisioning,
    )
    db.add(idp)
    db.commit()
    audit_log(action="admin.idp_created", actor=actor,
              severity=AuditSeverity.SECURITY,
              resource_type="identity_providers", resource_id=idp.id,
              after_data={"name": idp.name, "kind": kind.value})
    return IdentityProviderResponse(
        id=idp.id, tenant_id=idp.tenant_id, name=idp.name, kind=idp.kind.value,
        enabled=idp.enabled, config=_redact_secrets(idp.config),
        role_mapping=idp.role_mapping, default_role=idp.default_role.value,
        just_in_time_provisioning=idp.just_in_time_provisioning,
        created_at=idp.created_at, updated_at=idp.updated_at,
    )


def _redact_secrets(cfg: Dict[str, Any]) -> Dict[str, Any]:
    redacted = dict(cfg or {})
    for key in ("client_secret", "sp_private_key"):
        if key in redacted:
            redacted[key] = "***REDACTED***"
    return redacted


# ─────────────────────────────────────────────────────────────────
#  Admin — SCIM tokens
# ─────────────────────────────────────────────────────────────────


@router.post("/admin/scim-tokens", response_model=ScimTokenIssued, status_code=201)
def admin_issue_scim_token(body: CreateScimTokenRequest,
                            _csrf=Depends(require_csrf),
                            actor: User = Depends(require_permission("scim_tokens", "create")),
                            _reauth: User = Depends(require_reauth()),
                            db: DbSession = Depends(get_db)):
    row, plain = issue_scim_token(db, tenant_id=actor.tenant_id,
                                    description=body.description,
                                    ttl_days=body.ttl_days,
                                    created_by_user_id=actor.id)
    audit_log(action="admin.scim_token_issued", actor=actor,
              severity=AuditSeverity.SECURITY,
              resource_type="scim_tokens", resource_id=row.id,
              after_data={"description": row.description,
                          "expires_at": row.expires_at.isoformat()})
    return ScimTokenIssued(
        id=row.id, token=plain, description=row.description,
        created_at=row.created_at, expires_at=row.expires_at,
    )


@router.delete("/admin/scim-tokens/{token_id}")
def admin_revoke_scim_token(token_id: str,
                             _csrf=Depends(require_csrf),
                             actor: User = Depends(require_permission("scim_tokens", "revoke")),
                             db: DbSession = Depends(get_db)):
    from auth.models import ScimBearerToken
    tok = db.get(ScimBearerToken, token_id)
    if tok is None or tok.tenant_id != actor.tenant_id:
        raise HTTPException(404)
    if tok.revoked_at is not None:
        return {"ok": True, "already_revoked": True}
    tok.revoked_at = datetime.now(timezone.utc)
    db.commit()
    audit_log(action="admin.scim_token_revoked", actor=actor,
              severity=AuditSeverity.SECURITY,
              resource_type="scim_tokens", resource_id=token_id)
    return {"ok": True}


__all__ = ["router"]
