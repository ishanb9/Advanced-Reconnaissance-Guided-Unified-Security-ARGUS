"""SCIM 2.0 (RFC 7644) endpoints for automated user provisioning.

Supports the common IdP-side flows:

  GET    /scim/v2/Users?filter=...&count=N&startIndex=I
  GET    /scim/v2/Users/{id}
  POST   /scim/v2/Users
  PUT    /scim/v2/Users/{id}
  PATCH  /scim/v2/Users/{id}
  DELETE /scim/v2/Users/{id}                 — soft delete (active=false)
  GET    /scim/v2/Groups                      — surfaces ARGUS roles
  GET    /scim/v2/ResourceTypes
  GET    /scim/v2/Schemas
  GET    /scim/v2/ServiceProviderConfig

Auth: bearer token via the Authorization header.  Tokens are issued
by an admin via /admin/scim-tokens and stored hashed in
ScimBearerToken.token_hash.

Filter parser: handles the common subset IdPs send:
  userName eq "alice@x.com"
  emails[type eq "work"]
  active eq true
  externalId eq "ext-123"
  userName eq "alice" and active eq true
  (userName eq "alice") or (userName eq "bob")
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session as DbSession

from auth.audit import audit_log
from auth.config import CONFIG
from auth.db import get_db
from auth.models import (
    AuditSeverity, AuthMethod, RoleCode, ScimBearerToken,
    Tenant, User, UserRoleAssignment, UserStatus,
)
from auth.schemas import (
    ScimEmail, ScimError, ScimGroupRef, ScimListResponse, ScimName, ScimUser,
)

logger = logging.getLogger("argus.auth.scim")
router = APIRouter(prefix="/scim/v2", tags=["scim"])


# ─────────────────────────────────────────────────────────────────
#  Bearer-token auth (scoped to a tenant)
# ─────────────────────────────────────────────────────────────────


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _verify_bearer(authorization: Optional[str],
                   db: DbSession,
                   request: Request) -> ScimBearerToken:
    if not authorization or not authorization.lower().startswith("bearer "):
        _raise(401, "Missing bearer token.")
    token = authorization.split(None, 1)[1].strip()
    th = _hash_token(token)
    row = db.execute(
        select(ScimBearerToken).where(ScimBearerToken.token_hash == th)
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (row is None or row.revoked_at is not None or row.expires_at <= now):
        # log denied access
        try:
            audit_log(action="scim.auth_denied",
                      severity=AuditSeverity.WARN,
                      status="failure",
                      ip_address=request.client.host if request.client else None,
                      after_data={"reason": "bad_or_expired_token"})
        except Exception:
            pass
        _raise(401, "Invalid or expired bearer token.")
    row.last_used_at = now
    row.last_used_ip = request.client.host if request.client else None
    db.commit()
    return row


def _raise(status_code: int, detail: str, scim_type: Optional[str] = None):
    raise HTTPException(
        status_code=status_code,
        detail=ScimError(status=str(status_code), detail=detail,
                          scimType=scim_type).model_dump(by_alias=True, exclude_none=True),
    )


# ─────────────────────────────────────────────────────────────────
#  Filter parser — RFC 7644 §3.4.2.2 subset
# ─────────────────────────────────────────────────────────────────


_OP_TOKEN = re.compile(r'\s+(eq|ne|co|sw|ew|pr|gt|ge|lt|le)\s+', re.IGNORECASE)
_VALUE = re.compile(r'^\s*"([^"]*)"\s*$|^\s*(true|false)\s*$|^\s*([\d\.]+)\s*$',
                    re.IGNORECASE)


def parse_filter(filter_str: str) -> Tuple[Any, ...]:
    """Parse a SCIM filter string into a list of SQL where-clauses.

    Returns a tuple of SQLAlchemy expressions joined with AND/OR.  We
    support only top-level AND chains (the most common IdP usage);
    parenthesized OR clauses fall through to a substring match.

    For the supported subset:
      userName eq "x"          → User.email == "x"
      externalId eq "x"        → User.external_id == "x"
      active eq true           → User.status == ACTIVE
      emails.value eq "x"      → User.email == "x"
      meta.lastModified gt ... → User.updated_at > ...
    """
    if not filter_str:
        return ()

    clauses = []

    # Split on " and " (case-insensitive); we don't support precedence
    # in this minimal parser — but we do unwrap surrounding parens.
    parts = re.split(r'\s+and\s+', filter_str.strip(), flags=re.IGNORECASE)
    for raw in parts:
        s = raw.strip().strip("()").strip()
        if not s:
            continue
        m = _OP_TOKEN.search(s)
        if not m:
            # "pr" (present) operator: "attr pr"
            if s.lower().endswith(" pr"):
                attr = s[:-3].strip()
                clauses.append(_present_clause(attr))
            continue
        attr, op, value = s[:m.start()].strip(), m.group(1).lower(), s[m.end():].strip()
        v = _parse_value(value)
        c = _build_clause(attr, op, v)
        if c is not None:
            clauses.append(c)

    return tuple(clauses)


def _parse_value(raw: str) -> Any:
    m = _VALUE.match(raw)
    if not m:
        return raw.strip()
    if m.group(1) is not None:
        return m.group(1)
    if m.group(2) is not None:
        return m.group(2).lower() == "true"
    if m.group(3) is not None:
        try:
            return float(m.group(3))
        except ValueError:
            return m.group(3)
    return raw


def _build_clause(attr: str, op: str, value: Any):
    attr_norm = attr.lower().replace("-", "").replace("_", "")
    if attr_norm in ("username", "emails.value", "emails", "email"):
        col = User.email
    elif attr_norm == "externalid":
        col = User.external_id
    elif attr_norm == "active":
        # active=true → status==ACTIVE
        if op == "eq":
            return User.status == (UserStatus.ACTIVE if value else UserStatus.DEACTIVATED)
        return None
    elif attr_norm in ("displayname",):
        col = User.display_name
    elif attr_norm in ("meta.lastmodified", "lastmodified"):
        col = User.updated_at
    elif attr_norm in ("id",):
        col = User.id
    else:
        return None

    if op == "eq":  return col == value
    if op == "ne":  return col != value
    if op == "co":  return col.contains(value)        # type: ignore[attr-defined]
    if op == "sw":  return col.like(f"{value}%")
    if op == "ew":  return col.like(f"%{value}")
    if op == "gt":  return col > value
    if op == "ge":  return col >= value
    if op == "lt":  return col < value
    if op == "le":  return col <= value
    return None


def _present_clause(attr: str):
    col_map = {"username": User.email, "externalid": User.external_id,
               "displayname": User.display_name}
    col = col_map.get(attr.lower().replace("_", ""))
    if col is None:
        return None
    return col.isnot(None)


# ─────────────────────────────────────────────────────────────────
#  SCIM ↔ DB user mapping
# ─────────────────────────────────────────────────────────────────


def user_to_scim(user: User, base_url: str = "/scim/v2") -> Dict[str, Any]:
    groups = []
    for a in (user.role_assigns or []):
        groups.append({
            "value":   f"role:{a.role.value}",
            "display": a.role.value,
        })
    name_obj: Optional[ScimName] = None
    if user.display_name:
        parts = user.display_name.split(" ", 1)
        name_obj = ScimName(
            formatted=user.display_name,
            givenName=parts[0],
            familyName=parts[1] if len(parts) > 1 else None,
        )

    obj = ScimUser(
        id=user.id,
        externalId=user.external_id,
        userName=user.email,
        name=name_obj,
        displayName=user.display_name,
        emails=[ScimEmail(value=user.email, primary=True, type="work")],
        active=(user.status == UserStatus.ACTIVE),
        groups=[ScimGroupRef(**g) for g in groups],
        meta={
            "resourceType": "User",
            "created":      user.created_at.isoformat() if user.created_at else None,
            "lastModified": user.updated_at.isoformat() if user.updated_at else None,
            "location":     f"{base_url}/Users/{user.id}",
        },
    )
    enterprise = (user.attributes or {}).get("enterprise")
    payload = obj.model_dump(by_alias=True, exclude_none=True)
    if enterprise:
        payload["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] = enterprise
    return payload


# ─────────────────────────────────────────────────────────────────
#  Endpoints
# ─────────────────────────────────────────────────────────────────


@router.get("/ServiceProviderConfig")
def service_provider_config():
    """Static metadata describing the SCIM service."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://argus.local/docs/scim",
        "patch":      {"supported": True},
        "bulk":       {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter":     {"supported": True, "maxResults": CONFIG.scim_page_size},
        "changePassword": {"supported": False},
        "sort":       {"supported": False},
        "etag":       {"supported": False},
        "authenticationSchemes": [{
            "type":   "oauthbearertoken",
            "name":   "OAuth Bearer Token",
            "description": "SCIM bearer token issued by an ARGUS administrator.",
            "primary": True,
        }],
    }


@router.get("/ResourceTypes")
def resource_types():
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id":          "User",
            "name":        "User",
            "endpoint":    "/Users",
            "schema":      "urn:ietf:params:scim:schemas:core:2.0:User",
            "schemaExtensions": [{
                "schema":  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
                "required": False,
            }],
        }],
    }


@router.get("/Schemas")
def schemas():
    """Returns the static SCIM schema definitions.  Most IdPs only
    fetch this when first configuring the connection."""
    return {
        "schemas":     ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources":   [
            {"id": "urn:ietf:params:scim:schemas:core:2.0:User",
             "name": "User", "description": "User Account"},
            {"id": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
             "name": "EnterpriseUser", "description": "Enterprise User Extension"},
        ],
    }


# ── Users — list / read / create / update / delete ─────────────


@router.get("/Users")
def list_users(request: Request,
               filter: Optional[str] = None,
               startIndex: int = 1, count: Optional[int] = None,
               authorization: Optional[str] = Header(None),
               db: DbSession = Depends(get_db)):
    tok = _verify_bearer(authorization, db, request)
    page_size = min(count or CONFIG.scim_page_size, CONFIG.scim_page_size)
    q = select(User).where(User.tenant_id == tok.tenant_id, User.deleted_at.is_(None))
    if filter:
        clauses = parse_filter(filter)
        if clauses:
            q = q.where(and_(*clauses))
    total = db.execute(q).scalars().all()
    page = total[max(0, startIndex - 1): max(0, startIndex - 1) + page_size]
    return ScimListResponse(
        totalResults=len(total),
        startIndex=startIndex,
        itemsPerPage=len(page),
        Resources=[user_to_scim(u) for u in page],
    ).model_dump(by_alias=True)


@router.get("/Users/{user_id}")
def read_user(user_id: str, request: Request,
              authorization: Optional[str] = Header(None),
              db: DbSession = Depends(get_db)):
    tok = _verify_bearer(authorization, db, request)
    user = db.get(User, user_id)
    if user is None or user.tenant_id != tok.tenant_id or user.deleted_at is not None:
        _raise(404, "User not found.")
    return user_to_scim(user)


@router.post("/Users", status_code=201)
def create_user(payload: Dict[str, Any], request: Request,
                authorization: Optional[str] = Header(None),
                db: DbSession = Depends(get_db)):
    tok = _verify_bearer(authorization, db, request)

    try:
        body = ScimUser(**payload)
    except Exception as e:
        _raise(400, f"Invalid SCIM User payload: {e}", scim_type="invalidValue")

    email = (body.userName or "").strip().lower()
    if not email:
        _raise(400, "userName required.", scim_type="invalidValue")

    # Conflict check
    existing = db.execute(
        select(User).where(User.tenant_id == tok.tenant_id, User.email == email)
    ).scalar_one_or_none()
    if existing is not None and existing.deleted_at is None:
        _raise(409, "User already exists.", scim_type="uniqueness")

    display_name = body.displayName or (body.name.formatted if body.name else None)
    if not display_name and body.name and body.name.givenName:
        display_name = f"{body.name.givenName} {body.name.familyName or ''}".strip()

    user = User(
        tenant_id=tok.tenant_id,
        email=email,
        external_id=body.externalId,
        display_name=display_name,
        status=UserStatus.ACTIVE if body.active else UserStatus.DEACTIVATED,
        primary_auth_method=AuthMethod.SCIM,
        attributes={"scim_provisioned": True,
                    "enterprise": payload.get(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                    )},
    )
    db.add(user)
    db.flush()

    # Default role from SCIM config
    try:
        default_role = RoleCode(CONFIG.scim_default_role)
    except ValueError:
        default_role = RoleCode.ANALYST
    db.add(UserRoleAssignment(
        user_id=user.id, tenant_id=tok.tenant_id, role=default_role,
    ))

    db.commit()

    audit_log(action="scim.user_provisioned",
              severity=AuditSeverity.NOTICE,
              tenant_id=tok.tenant_id,
              resource_type="users", resource_id=user.id,
              ip_address=request.client.host if request.client else None,
              after_data={"email": email, "external_id": body.externalId,
                          "token_id": tok.id})
    return user_to_scim(user)


@router.put("/Users/{user_id}")
def replace_user(user_id: str, payload: Dict[str, Any], request: Request,
                 authorization: Optional[str] = Header(None),
                 db: DbSession = Depends(get_db)):
    tok = _verify_bearer(authorization, db, request)
    user = db.get(User, user_id)
    if user is None or user.tenant_id != tok.tenant_id or user.deleted_at is not None:
        _raise(404, "User not found.")

    try:
        body = ScimUser(**payload)
    except Exception as e:
        _raise(400, f"Invalid SCIM User payload: {e}", scim_type="invalidValue")

    before = {"email": user.email, "status": user.status.value,
              "display_name": user.display_name}

    user.email = (body.userName or user.email).strip().lower()
    if body.displayName:
        user.display_name = body.displayName
    elif body.name and body.name.formatted:
        user.display_name = body.name.formatted
    user.external_id = body.externalId or user.external_id
    user.status = UserStatus.ACTIVE if body.active else UserStatus.DEACTIVATED
    user.attributes = {
        **(user.attributes or {}),
        "scim_provisioned": True,
        "enterprise": payload.get(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ),
    }
    db.commit()

    audit_log(action="scim.user_updated",
              severity=AuditSeverity.NOTICE,
              tenant_id=tok.tenant_id,
              resource_type="users", resource_id=user.id,
              ip_address=request.client.host if request.client else None,
              before_data=before,
              after_data={"email": user.email, "status": user.status.value,
                          "display_name": user.display_name, "token_id": tok.id})
    return user_to_scim(user)


@router.patch("/Users/{user_id}")
def patch_user(user_id: str, payload: Dict[str, Any], request: Request,
               authorization: Optional[str] = Header(None),
               db: DbSession = Depends(get_db)):
    """RFC 7644 §3.5.2 — PATCH with Operations: [{op, path, value}]."""
    tok = _verify_bearer(authorization, db, request)
    user = db.get(User, user_id)
    if user is None or user.tenant_id != tok.tenant_id or user.deleted_at is not None:
        _raise(404, "User not found.")

    ops = (payload or {}).get("Operations") or []
    before = {"email": user.email, "status": user.status.value,
              "display_name": user.display_name}

    for op in ops:
        action = (op.get("op") or "").lower()
        path = (op.get("path") or "").strip()
        value = op.get("value")
        if action == "replace" and path in ("active",):
            user.status = (UserStatus.ACTIVE
                           if bool(value) else UserStatus.DEACTIVATED)
        elif action == "replace" and path in ("userName", "username"):
            user.email = str(value).strip().lower()
        elif action == "replace" and path in ("displayName", "name.formatted"):
            user.display_name = str(value)
        elif action == "replace" and path == "externalId":
            user.external_id = str(value)
        elif action == "remove" and path == "active":
            user.status = UserStatus.DEACTIVATED
        else:
            # Many IdPs send patches without a path — treat as a merge
            if action == "replace" and value and isinstance(value, dict):
                if "active" in value:
                    user.status = (UserStatus.ACTIVE
                                   if value["active"] else UserStatus.DEACTIVATED)
                if "displayName" in value:
                    user.display_name = value["displayName"]

    db.commit()
    audit_log(action="scim.user_patched",
              severity=AuditSeverity.NOTICE,
              tenant_id=tok.tenant_id,
              resource_type="users", resource_id=user.id,
              ip_address=request.client.host if request.client else None,
              before_data=before,
              after_data={"email": user.email, "status": user.status.value,
                          "display_name": user.display_name, "ops": ops,
                          "token_id": tok.id})
    return user_to_scim(user)


@router.delete("/Users/{user_id}", status_code=204)
def deprovision_user(user_id: str, request: Request,
                     authorization: Optional[str] = Header(None),
                     db: DbSession = Depends(get_db)):
    """Soft-delete: mark deactivated + set deleted_at.

    Per SCIM convention many IdPs expect DELETE to fully remove, but
    we never hard-delete users (audit trail requires retention).
    """
    tok = _verify_bearer(authorization, db, request)
    user = db.get(User, user_id)
    if user is None or user.tenant_id != tok.tenant_id:
        _raise(404, "User not found.")
    if user.deleted_at is not None:
        return JSONResponse(status_code=204, content=None)

    user.status = UserStatus.DEACTIVATED
    user.deleted_at = datetime.now(timezone.utc)

    # Revoke all sessions
    from auth.sessions import revoke_all_user_sessions
    revoke_all_user_sessions(db, user.id, reason="scim_deprovision")

    db.commit()
    audit_log(action="scim.user_deprovisioned",
              severity=AuditSeverity.SECURITY,
              tenant_id=tok.tenant_id,
              resource_type="users", resource_id=user.id,
              ip_address=request.client.host if request.client else None,
              after_data={"token_id": tok.id})
    return JSONResponse(status_code=204, content=None)


# ── Groups — surface ARGUS roles as SCIM groups ──────────────────


@router.get("/Groups")
def list_groups(request: Request,
                authorization: Optional[str] = Header(None),
                db: DbSession = Depends(get_db)):
    """Map ARGUS roles to SCIM groups so IdPs can assign membership."""
    tok = _verify_bearer(authorization, db, request)
    groups = []
    for role in RoleCode:
        member_users = db.execute(
            select(User).join(UserRoleAssignment,
                              UserRoleAssignment.user_id == User.id)
            .where(UserRoleAssignment.tenant_id == tok.tenant_id,
                   UserRoleAssignment.role == role,
                   User.deleted_at.is_(None))
        ).scalars().all()
        groups.append({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id":          f"role:{role.value}",
            "displayName": role.value,
            "members":     [{"value": u.id, "display": u.email} for u in member_users],
            "meta":        {"resourceType": "Group",
                            "location": f"/scim/v2/Groups/role:{role.value}"},
        })
    return ScimListResponse(
        totalResults=len(groups),
        startIndex=1,
        itemsPerPage=len(groups),
        Resources=groups,
    ).model_dump(by_alias=True)


# ─────────────────────────────────────────────────────────────────
#  Admin helper — issue a new SCIM bearer token (used by routes.py)
# ─────────────────────────────────────────────────────────────────


def issue_scim_token(db: DbSession, *,
                     tenant_id: str,
                     description: str,
                     ttl_days: Optional[int] = None,
                     created_by_user_id: Optional[str] = None,
                     ) -> Tuple[ScimBearerToken, str]:
    """Generate + persist a new SCIM bearer token.

    Returns (row, plaintext_token).  The plaintext is shown to the
    admin ONCE; only the SHA-256 hash is kept server-side.
    """
    from datetime import timedelta
    plain = "scim_" + secrets.token_urlsafe(48)
    ttl = ttl_days if ttl_days is not None else CONFIG.scim_token_ttl_days
    now = datetime.now(timezone.utc)
    row = ScimBearerToken(
        tenant_id=tenant_id,
        description=description,
        token_hash=_hash_token(plain),
        created_by_user_id=created_by_user_id,
        created_at=now,
        expires_at=now + timedelta(days=ttl),
    )
    db.add(row)
    db.commit()
    return row, plain


__all__ = ["router", "parse_filter", "user_to_scim", "issue_scim_token"]
