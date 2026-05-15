"""RBAC + ABAC permission engine.

Authorization model:

  ROLE  →  set of (resource, action) permissions    (RBAC default grants)
  USER  →  one or more (role, tenant, attributes)   (RBAC assignment)
  ATTR  →  predicates over user + resource + ctx    (ABAC overlay)
  CHECK →  has_permission(user, "resource", "action", ctx)

The permission tuple is intentionally string-based rather than a hard
enum so downstream callers (ARGUS agents, custom integrations) can
register their own resources without modifying this file.

The OWNER role bypasses all checks (god-mode).  Every other role goes
through the normal RBAC → ABAC pipeline.

ABAC predicates compose:
    Allow  — explicit permit
    Deny   — explicit deny (overrides any Allow)
    Defer  — no opinion, fall through to next predicate

When all ABAC predicates Defer, the RBAC default decides.
"""
from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from auth.models import RoleCode, User

logger = logging.getLogger("argus.auth.rbac")


# ─────────────────────────────────────────────────────────────────
#  Public surface
# ─────────────────────────────────────────────────────────────────


class Role(str, enum.Enum):
    """Re-exports RoleCode for type-checking ergonomics."""
    OWNER            = "OWNER"
    PLATFORM_ADMIN   = "PLATFORM_ADMIN"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    OPERATOR         = "OPERATOR"
    ANALYST          = "ANALYST"
    EXECUTIVE        = "EXECUTIVE"
    AUDITOR          = "AUDITOR"
    CLIENT           = "CLIENT"


@dataclass(frozen=True)
class Permission:
    """A (resource, action) tuple.  Use string literals to add new ones.

    Conventions:
      resource is plural, lowercase, snake_case: "users", "audit_logs",
        "scan_sessions", "findings", "engagements", "reports", "tools",
        "settings", "identity_providers", "scim_tokens"
      action   is a verb, lowercase: "read", "create", "update",
        "delete", "execute", "assign", "configure", "validate"

    Special action wildcards:
      "*" — every action on the resource (used by OWNER + admin grants)
    """
    resource: str
    action:   str

    def __str__(self) -> str:
        return f"{self.resource}:{self.action}"


class Decision(enum.Enum):
    ALLOW = "allow"
    DENY  = "deny"
    DEFER = "defer"


# ABAC predicate signature: (user, resource_obj, action, ctx) -> Decision
AbacPredicate = Callable[["User", Optional[Any], str, Dict[str, Any]], Decision]


# ─────────────────────────────────────────────────────────────────
#  Default role-permission matrix
# ─────────────────────────────────────────────────────────────────


# Every concrete resource appears here exactly once.  Add new resources
# by appending to this dict.  Role grants use either "*" (every action)
# or explicit action sets.

RESOURCES: Tuple[str, ...] = (
    "users",
    "roles",
    "audit_logs",
    "settings",
    "identity_providers",
    "scim_tokens",
    "sessions",
    "tenants",
    "engagements",
    "findings",
    "tools",
    "agents",
    "reports",
    "credentials",
    "scan_results",
    "knowledge",
    "dashboards",
    "ai_observability",
)


# Role permission grants.  See README §2 for the rationale.
# Each role → dict of resource → set of actions (or {"*"} for every).
DEFAULT_PERMS: Dict[Role, Dict[str, Set[str]]] = {

    # ── OWNER — god mode; matrix below is for documentation only.
    Role.OWNER: {r: {"*"} for r in RESOURCES},

    # ── PLATFORM_ADMIN — manage platform & users, NOT engagement data
    Role.PLATFORM_ADMIN: {
        "users":              {"read", "create", "update", "deactivate", "invite", "assign_role"},
        "roles":              {"read", "assign"},  # cannot grant OWNER
        "audit_logs":         {"read", "configure"},  # NOT delete (owner-only)
        "settings":           {"read", "update"},
        "identity_providers": {"read", "create", "update", "delete"},
        "scim_tokens":        {"read", "create", "revoke"},
        "sessions":           {"read", "terminate"},
        "tenants":             {"read", "create", "update"},
    },

    # ── SECURITY_MANAGER — own engagements + assign operators
    Role.SECURITY_MANAGER: {
        "engagements":     {"read", "create", "update", "scope", "close"},
        "users":           {"read", "assign_to_engagement"},
        "findings":        {"read", "validate", "triage", "comment", "export"},
        "tools":           {"execute"},
        "agents":          {"dispatch", "configure"},
        "reports":         {"read", "generate", "export"},
        "credentials":     {"read", "store"},
        "scan_results":    {"read"},
        "knowledge":       {"read", "contribute"},
        "audit_logs":      {"read"},      # scoped to their engagements
        "dashboards":      {"read"},
        "ai_observability":{"read"},
    },

    # ── OPERATOR — practitioner; full red-team within assigned engagements
    Role.OPERATOR: {
        "engagements":  {"read", "update"},  # only assigned ones (ABAC enforced)
        "findings":     {"read", "create", "update", "comment"},
        "tools":        {"execute"},
        "agents":       {"dispatch"},
        "credentials":  {"read", "store"},
        "scan_results": {"read", "create"},
        "knowledge":    {"read", "contribute"},
        "reports":      {"read"},
        "sessions":     {"read", "terminate"},  # own only (ABAC)
        "audit_logs":   {"read"},               # own only (ABAC)
        "ai_observability":{"read"},
    },

    # ── ANALYST — validate findings, non-destructive tools only
    Role.ANALYST: {
        "engagements": {"read"},
        "findings":    {"read", "validate", "comment"},
        "tools":       {"execute_nondestructive"},
        "agents":      {"read"},
        "scan_results":{"read"},
        "credentials": {"read"},
        "knowledge":   {"read", "contribute"},
        "reports":     {"read"},
        "audit_logs":  {"read"},      # own only
        "ai_observability":{"read"},
    },

    # ── EXECUTIVE — dashboards + decisions; no tool execution
    Role.EXECUTIVE: {
        "engagements":     {"read"},
        "findings":        {"read"},               # severity-filtered (ABAC)
        "reports":         {"read", "generate"},
        "dashboards":      {"read"},
        "audit_logs":      {"read"},               # tenant-scoped
        "ai_observability":{"read"},
    },

    # ── AUDITOR — global read-only with evidence chain
    Role.AUDITOR: {r: {"read"} for r in RESOURCES},

    # ── CLIENT — scoped to specific engagement; severity-redacted
    Role.CLIENT: {
        "engagements": {"read"},
        "findings":    {"read"},
        "reports":     {"read"},
    },
}


# Reverse lookup: given a (resource, action), which roles have it by default?
def roles_with_permission(resource: str, action: str) -> Set[Role]:
    out: Set[Role] = set()
    for role, perms in DEFAULT_PERMS.items():
        actions = perms.get(resource, set())
        if "*" in actions or action in actions:
            out.add(role)
    return out


# ─────────────────────────────────────────────────────────────────
#  ABAC predicate registry
# ─────────────────────────────────────────────────────────────────


_ABAC_PREDICATES: List[AbacPredicate] = []


def register_abac(predicate: AbacPredicate) -> AbacPredicate:
    """Decorator to register an ABAC predicate.

    Example:
        @register_abac
        def operator_engagement_scope(user, obj, action, ctx):
            if user.has_role(Role.OPERATOR) and obj is not None:
                allowed = engagement_ids_for(user)
                if obj.engagement_id not in allowed:
                    return Decision.DENY
            return Decision.DEFER
    """
    _ABAC_PREDICATES.append(predicate)
    return predicate


# ─── Built-in ABAC predicates ─────────────────────────────────────


@register_abac
def _own_session_predicate(user, obj, action, ctx):
    """Sessions: a non-admin can only manage their own."""
    res = ctx.get("resource")
    if res != "sessions":
        return Decision.DEFER
    if _is_admin_or_owner(user):
        return Decision.DEFER
    target_user_id = ctx.get("target_user_id") or (obj.user_id if obj else None)
    if target_user_id and target_user_id != user.id:
        return Decision.DENY
    return Decision.DEFER


@register_abac
def _own_audit_predicate(user, obj, action, ctx):
    """Audit logs: regular users see only their own actions."""
    res = ctx.get("resource")
    if res != "audit_logs" or action != "read":
        return Decision.DEFER
    if _is_admin_or_owner(user):
        return Decision.DEFER
    if Role.SECURITY_MANAGER.value in [r.role.value for r in (user.role_assigns or [])]:
        # SM sees their tenant
        return Decision.DEFER
    target_user_id = ctx.get("target_user_id") or (obj.actor_user_id if obj else None)
    if target_user_id and target_user_id != user.id:
        return Decision.DENY
    return Decision.DEFER


@register_abac
def _engagement_scope_predicate(user, obj, action, ctx):
    """Operators/Analysts: limited to engagements they're assigned to.

    Assignment is encoded in the UserRoleAssignment.attributes JSON as
    `{"engagement_ids": [...]}`.  Empty list = no assigned engagement
    (no access); missing key = unrestricted within tenant.
    """
    res = ctx.get("resource")
    if res not in ("engagements", "findings", "scan_results", "agents", "tools"):
        return Decision.DEFER
    if _is_admin_or_owner(user):
        return Decision.DEFER

    target_eng_id = ctx.get("engagement_id") or (
        getattr(obj, "engagement_id", None) if obj else None
    )
    if not target_eng_id:
        return Decision.DEFER

    user_roles = [r for r in (user.role_assigns or [])
                  if r.role in (RoleCode.OPERATOR, RoleCode.ANALYST)]
    if not user_roles:
        return Decision.DEFER

    for assignment in user_roles:
        attrs = assignment.attributes or {}
        eng_ids = attrs.get("engagement_ids")
        if eng_ids is None:
            return Decision.DEFER         # unrestricted
        if target_eng_id in eng_ids:
            return Decision.DEFER
    return Decision.DENY


@register_abac
def _executive_severity_filter(user, obj, action, ctx):
    """Executives see findings of severity >= medium only."""
    res = ctx.get("resource")
    if res != "findings" or action != "read":
        return Decision.DEFER
    if _has_role(user, Role.EXECUTIVE) and not _is_admin_or_owner(user):
        sev = (ctx.get("severity") or getattr(obj, "severity", None) or "").upper()
        if sev in ("INFO", "LOW"):
            return Decision.DENY
    return Decision.DEFER


@register_abac
def _client_scope_predicate(user, obj, action, ctx):
    """Clients see ONLY their explicitly-shared engagement(s)."""
    if not _has_role(user, Role.CLIENT):
        return Decision.DEFER
    target_eng_id = ctx.get("engagement_id") or (
        getattr(obj, "engagement_id", None) if obj else None
    )
    if target_eng_id is None:
        # No engagement on the resource — clients can only read engagement-bound things
        return Decision.DENY
    for assignment in (user.role_assigns or []):
        if assignment.role != RoleCode.CLIENT:
            continue
        attrs = assignment.attributes or {}
        if target_eng_id in (attrs.get("engagement_ids") or []):
            return Decision.DEFER
    return Decision.DENY


@register_abac
def _expired_assignment_predicate(user, obj, action, ctx):
    """Role assignments with expires_at in the past don't count."""
    # Walk user's assignments; if EVERY assignment that could grant this
    # action is expired, deny.  Non-expired or unrelated — defer.
    now = datetime.now(timezone.utc)
    relevant = []
    for a in (user.role_assigns or []):
        perms = DEFAULT_PERMS.get(Role(a.role.value), {})
        actions = perms.get(ctx.get("resource", ""), set())
        if "*" in actions or ctx.get("action") in actions:
            relevant.append(a)
    if not relevant:
        return Decision.DEFER
    def _expired(a):
        exp = _aware(a.expires_at)
        return bool(exp and exp < now)
    if all(_expired(a) for a in relevant):
        return Decision.DENY
    return Decision.DEFER


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────


def _aware(dt):
    """Normalize naive DB datetimes to UTC-aware for comparison."""
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=timezone.utc)


def _has_role(user: User, role: Role, tenant_id: Optional[str] = None) -> bool:
    if user is None:
        return False
    now = datetime.now(timezone.utc)
    for a in (user.role_assigns or []):
        if a.role.value != role.value:
            continue
        if tenant_id and a.tenant_id != tenant_id:
            continue
        exp = _aware(a.expires_at)
        if exp and exp < now:
            continue
        return True
    return False


def _is_admin_or_owner(user: User, tenant_id: Optional[str] = None) -> bool:
    return _has_role(user, Role.OWNER) or _has_role(user, Role.PLATFORM_ADMIN, tenant_id)


def roles_of(user: User) -> List[Role]:
    """Active (non-expired) roles for a user.  Deduplicated."""
    if user is None:
        return []
    now = datetime.now(timezone.utc)
    out: Set[Role] = set()
    for a in (user.role_assigns or []):
        exp = _aware(a.expires_at)
        if exp and exp < now:
            continue
        try:
            out.add(Role(a.role.value))
        except ValueError:
            continue
    return list(out)


# ─────────────────────────────────────────────────────────────────
#  Permission check — the public API
# ─────────────────────────────────────────────────────────────────


def has_permission(user: User,
                   resource: str,
                   action: str,
                   *,
                   resource_obj: Optional[Any] = None,
                   tenant_id: Optional[str] = None,
                   context: Optional[Dict[str, Any]] = None) -> bool:
    """Return True if `user` may perform `action` on `resource`.

    Pipeline:
      1. OWNER — instant allow (god mode).
      2. Run all ABAC predicates.  Any DENY → instant reject.
         Any explicit ALLOW (a predicate that returned ALLOW) → permit.
      3. Fall through to RBAC default-grants: if any active role of
         the user has this (resource, action), permit.
      4. Otherwise deny.

    `context` is a free-form dict the caller can populate with:
      engagement_id, severity, target_user_id, ip_address, etc.
    The dict is augmented with `resource` and `action` for the
    convenience of ABAC predicates.
    """
    if user is None:
        return False
    if not getattr(user, "id", None):
        return False
    if user.status and user.status.value not in ("ACTIVE",):
        return False

    # Step 1 — OWNER bypass
    if _has_role(user, Role.OWNER):
        return True

    ctx = dict(context or {})
    ctx.setdefault("resource", resource)
    ctx.setdefault("action", action)

    # Step 2 — ABAC predicates
    explicit_allow = False
    for predicate in _ABAC_PREDICATES:
        try:
            d = predicate(user, resource_obj, action, ctx)
        except Exception as e:
            logger.exception("ABAC predicate %s raised: %s", predicate.__name__, e)
            d = Decision.DEFER
        if d == Decision.DENY:
            return False
        if d == Decision.ALLOW:
            explicit_allow = True
    if explicit_allow:
        return True

    # Step 3 — RBAC default grants
    for role in roles_of(user):
        perms = DEFAULT_PERMS.get(role, {})
        actions = perms.get(resource, set())
        if "*" in actions or action in actions:
            return True

    return False


def assert_permission(user: User, resource: str, action: str, **kw) -> None:
    """Same as has_permission but raises PermissionError instead of returning."""
    if not has_permission(user, resource, action, **kw):
        raise PermissionDenied(
            f"User {user.email if user else '?'} not permitted: "
            f"{resource}:{action}"
        )


class PermissionDenied(PermissionError):
    """Raised when an authenticated user lacks the requested permission."""


# ─────────────────────────────────────────────────────────────────
#  Role helpers — used by routes + frontend
# ─────────────────────────────────────────────────────────────────


def role_can_be_granted_by(grantor: User, grantee_role: Role) -> bool:
    """Hierarchical grant rules.

      OWNER         can grant any role (including OWNER)
      PLATFORM_ADMIN can grant any role EXCEPT OWNER
      SECURITY_MANAGER can grant OPERATOR, ANALYST, CLIENT
      Others        cannot grant
    """
    if _has_role(grantor, Role.OWNER):
        return True
    if _has_role(grantor, Role.PLATFORM_ADMIN):
        return grantee_role != Role.OWNER
    if _has_role(grantor, Role.SECURITY_MANAGER):
        return grantee_role in (Role.OPERATOR, Role.ANALYST, Role.CLIENT)
    return False


def role_is_higher_than(a: Role, b: Role) -> bool:
    """OWNER > PLATFORM_ADMIN > SECURITY_MANAGER > OPERATOR > ANALYST > EXECUTIVE > AUDITOR > CLIENT.

    Used to prevent privilege escalation via self-modification.
    """
    order = [
        Role.OWNER, Role.PLATFORM_ADMIN, Role.SECURITY_MANAGER,
        Role.OPERATOR, Role.ANALYST, Role.EXECUTIVE,
        Role.AUDITOR, Role.CLIENT,
    ]
    return order.index(a) < order.index(b)


def role_default_skin(role: Role) -> str:
    """Suggested skin per role — fed to the existing SkinChooser.

    The user can override at any time; this only affects the FIRST
    login default.
    """
    return {
        Role.OWNER:            "stellar",
        Role.PLATFORM_ADMIN:   "veteran",
        Role.SECURITY_MANAGER: "manager",
        Role.OPERATOR:         "redcell",
        Role.ANALYST:          "novice",
        Role.EXECUTIVE:        "executive",
        Role.AUDITOR:          "auditor",
        Role.CLIENT:           "editorial",
    }.get(role, "stellar")


__all__ = [
    "Role",
    "Permission",
    "Decision",
    "RESOURCES",
    "DEFAULT_PERMS",
    "register_abac",
    "roles_of",
    "roles_with_permission",
    "has_permission",
    "assert_permission",
    "PermissionDenied",
    "role_can_be_granted_by",
    "role_is_higher_than",
    "role_default_skin",
]
