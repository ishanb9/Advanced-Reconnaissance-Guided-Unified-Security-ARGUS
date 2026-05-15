"""Audit logging — append-only, owner-only deletion, configurable retention.

Public API:
  audit_log(action, ...)           — emit one log row
  get_audit_logs(...)              — scoped read (RBAC-checked by caller)
  delete_audit_logs(...)           — OWNER ONLY
  set_retention(...)               — OWNER or PLATFORM_ADMIN
  enforce_retention()              — periodic sweep (cron / async task)

Retention model:
  • audit.max_rows     — soft cap; oldest rows rotated when exceeded
  • audit.max_age_days — absolute time-based purge
  • audit.export_before_delete — emit JSON to disk so deletions are
    recoverable from cold storage

Optional tamper-evidence:
  Set AUTH_AUDIT_HASH_CHAIN=true.  Every new row's self_hash =
  sha256(prev_hash || canonical_json(row_fields)).  Verifying the chain
  on read makes silent tampering detectable.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import asc, desc, func, select
from sqlalchemy.orm import Session as DbSession

from auth.config import CONFIG
from auth.db import session_scope
from auth.models import AuditLog, AuditSeverity, RoleCode, Setting, User
from auth.rbac import Role, _has_role

logger = logging.getLogger("argus.auth.audit")


# ─────────────────────────────────────────────────────────────────
#  Settings facade — retention values can be overridden via admin UI
# ─────────────────────────────────────────────────────────────────


def _get_setting(db: DbSession, key: str, default: str) -> str:
    s = db.get(Setting, key)
    return s.value if s else default


def set_retention(db: DbSession,
                  *,
                  actor: User,
                  max_rows: Optional[int] = None,
                  max_age_days: Optional[int] = None) -> None:
    """OWNER or PLATFORM_ADMIN only.  Persist new retention thresholds."""
    if not (_has_role(actor, Role.OWNER) or _has_role(actor, Role.PLATFORM_ADMIN)):
        raise PermissionError("Only OWNER or PLATFORM_ADMIN can change retention.")

    if max_rows is not None:
        _upsert_setting(db, "audit.max_rows", str(int(max_rows)),
                        description="Soft cap on audit_log row count",
                        actor=actor)
    if max_age_days is not None:
        _upsert_setting(db, "audit.max_age_days", str(int(max_age_days)),
                        description="Absolute purge age in days",
                        actor=actor)
    db.commit()

    audit_log(action="audit.retention_changed", actor=actor,
              severity=AuditSeverity.SECURITY,
              after_data={"max_rows": max_rows, "max_age_days": max_age_days})


def _upsert_setting(db: DbSession, key: str, value: str,
                    *, description: str, actor: Optional[User]) -> None:
    s = db.get(Setting, key)
    if s is None:
        s = Setting(key=key, value=value, description=description,
                    updated_by_user_id=actor.id if actor else None)
        db.add(s)
    else:
        s.value = value
        s.updated_by_user_id = actor.id if actor else None


# ─────────────────────────────────────────────────────────────────
#  audit_log — the only legitimate way to add a row
# ─────────────────────────────────────────────────────────────────


def audit_log(*,
              action: str,
              actor: Optional[User] = None,
              actor_session_id: Optional[str] = None,
              tenant_id: Optional[str] = None,
              resource_type: Optional[str] = None,
              resource_id: Optional[str] = None,
              ip_address: Optional[str] = None,
              user_agent: Optional[str] = None,
              severity: AuditSeverity = AuditSeverity.INFO,
              status: str = "success",
              error_message: Optional[str] = None,
              before_data: Optional[Dict[str, Any]] = None,
              after_data: Optional[Dict[str, Any]] = None,
              impersonator_user_id: Optional[str] = None,
              db: Optional[DbSession] = None) -> str:
    """Write a single audit row.  Returns the new row's ID.

    Never raises — audit must be best-effort.  Logs to stderr on
    failure and returns an empty string.
    """
    actor_user_id = actor.id if actor else None
    actor_tenant_id = tenant_id or (actor.tenant_id if actor else None)

    def _do(db: DbSession) -> str:
        row = AuditLog(
            ts=datetime.now(timezone.utc),
            actor_user_id=actor_user_id,
            actor_session_id=actor_session_id,
            impersonator_user_id=impersonator_user_id,
            tenant_id=actor_tenant_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            severity=severity,
            status=status,
            error_message=error_message,
            before_data=before_data,
            after_data=after_data,
        )

        if CONFIG.audit_hash_chain:
            prev = db.execute(
                select(AuditLog.self_hash).order_by(desc(AuditLog.ts)).limit(1)
            ).scalar()
            row.prev_hash = prev or ""
            row.self_hash = _hash_row(row)

        db.add(row)
        db.commit()
        return row.id

    try:
        if db is not None:
            return _do(db)
        with session_scope() as scoped:
            return _do(scoped)
    except Exception as e:
        logger.error("audit log failed (%s): %s", action, e)
        return ""


def _hash_row(row: AuditLog) -> str:
    payload = {
        "ts":            row.ts.isoformat() if row.ts else None,
        "actor_user_id": row.actor_user_id,
        "tenant_id":     row.tenant_id,
        "action":        row.action,
        "resource_type": row.resource_type,
        "resource_id":   row.resource_id,
        "severity":      row.severity.value if row.severity else None,
        "status":        row.status,
        "before_data":   row.before_data,
        "after_data":    row.after_data,
        "prev_hash":     row.prev_hash,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ─────────────────────────────────────────────────────────────────
#  Read API — caller is responsible for RBAC scoping
# ─────────────────────────────────────────────────────────────────


def get_audit_logs(db: DbSession,
                   *,
                   actor_user_id: Optional[str] = None,
                   tenant_id: Optional[str] = None,
                   action_prefix: Optional[str] = None,
                   resource_type: Optional[str] = None,
                   resource_id: Optional[str] = None,
                   since: Optional[datetime] = None,
                   until: Optional[datetime] = None,
                   severity_at_least: Optional[AuditSeverity] = None,
                   limit: int = 100,
                   offset: int = 0,
                   ) -> List[AuditLog]:
    """Filtered read — caller MUST apply RBAC scoping before calling.

    See rbac.py predicates for the rules:
      OWNER / PLATFORM_ADMIN / AUDITOR    → unrestricted
      SECURITY_MANAGER                     → their tenant
      Others                               → only their own actor_user_id
    """
    q = select(AuditLog)
    if actor_user_id is not None:
        q = q.where(AuditLog.actor_user_id == actor_user_id)
    if tenant_id is not None:
        q = q.where(AuditLog.tenant_id == tenant_id)
    if action_prefix:
        q = q.where(AuditLog.action.like(f"{action_prefix}%"))
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    if resource_id:
        q = q.where(AuditLog.resource_id == resource_id)
    if since:
        q = q.where(AuditLog.ts >= since)
    if until:
        q = q.where(AuditLog.ts <= until)
    if severity_at_least:
        order = [AuditSeverity.INFO, AuditSeverity.NOTICE, AuditSeverity.WARN,
                 AuditSeverity.SECURITY, AuditSeverity.CRITICAL]
        min_idx = order.index(severity_at_least)
        allowed = [s for s in order[min_idx:]]
        q = q.where(AuditLog.severity.in_(allowed))
    q = q.order_by(desc(AuditLog.ts)).limit(limit).offset(offset)
    return list(db.execute(q).scalars().all())


def count_audit_logs(db: DbSession, **filters) -> int:
    q = select(func.count(AuditLog.id))
    # filters are name=value; only a small subset are supported here
    if filters.get("tenant_id"):
        q = q.where(AuditLog.tenant_id == filters["tenant_id"])
    if filters.get("actor_user_id"):
        q = q.where(AuditLog.actor_user_id == filters["actor_user_id"])
    return db.execute(q).scalar_one()


# ─────────────────────────────────────────────────────────────────
#  Delete API — OWNER ONLY
# ─────────────────────────────────────────────────────────────────


def delete_audit_logs(db: DbSession,
                      *,
                      actor: User,
                      ids: Optional[List[str]] = None,
                      older_than: Optional[datetime] = None,
                      reason: str) -> int:
    """OWNER-only deletion of audit rows.

    `reason` is required and recorded in a NEW audit entry that survives
    the deletion (it goes in BEFORE the rows are removed).

    If `audit.export_before_delete` is enabled, rows are first written
    to JSONL under `audit_export_dir/YYYY-MM-DD/<uuid>.jsonl`.
    """
    if not _has_role(actor, Role.OWNER):
        raise PermissionError("Only OWNER may delete audit log entries.")

    # Resolve target set
    q = select(AuditLog)
    if ids:
        q = q.where(AuditLog.id.in_(ids))
    if older_than:
        q = q.where(AuditLog.ts < older_than)
    if not ids and not older_than:
        raise ValueError("Must specify ids or older_than to delete audit logs.")

    rows = list(db.execute(q).scalars().all())
    if not rows:
        return 0

    # 1) Export to cold storage
    if CONFIG.audit_export_before_delete:
        _export_to_disk(rows)

    # 2) Write the deletion-audit row BEFORE the actual delete
    audit_log(action="audit.rows_deleted",
              actor=actor,
              severity=AuditSeverity.CRITICAL,
              after_data={"count": len(rows), "reason": reason,
                          "id_sample": [r.id for r in rows[:50]]},
              db=db)

    # 3) Perform delete
    for r in rows:
        db.delete(r)
    db.commit()
    return len(rows)


def _export_to_disk(rows: List[AuditLog]) -> Path:
    dir_ = Path(CONFIG.audit_export_dir)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_dir = dir_ / today
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"audit-export-{int(datetime.now(timezone.utc).timestamp())}.jsonl"
    with out_file.open("w", encoding="utf-8") as fh:
        for r in rows:
            obj = {
                "id":            r.id,
                "ts":            r.ts.isoformat() if r.ts else None,
                "actor_user_id": r.actor_user_id,
                "tenant_id":     r.tenant_id,
                "action":        r.action,
                "resource_type": r.resource_type,
                "resource_id":   r.resource_id,
                "ip_address":    r.ip_address,
                "user_agent":    r.user_agent,
                "severity":      r.severity.value if r.severity else None,
                "status":        r.status,
                "error_message": r.error_message,
                "before_data":   r.before_data,
                "after_data":    r.after_data,
                "prev_hash":     r.prev_hash,
                "self_hash":     r.self_hash,
            }
            fh.write(json.dumps(obj, default=str) + "\n")
    logger.info("audit: exported %d rows to %s", len(rows), out_file)
    return out_file


# ─────────────────────────────────────────────────────────────────
#  Retention sweep — call from a cron / asyncio task
# ─────────────────────────────────────────────────────────────────


def enforce_retention() -> Tuple[int, int]:
    """Apply current retention settings.  Returns (deleted_by_age, deleted_by_count)."""
    with session_scope() as db:
        max_rows = int(_get_setting(db, "audit.max_rows", str(CONFIG.audit_max_rows)))
        max_age_days = int(_get_setting(db, "audit.max_age_days", str(CONFIG.audit_max_age_days)))

        # ── by age
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        old = db.execute(
            select(AuditLog).where(AuditLog.ts < cutoff).order_by(asc(AuditLog.ts))
        ).scalars().all()
        deleted_age = 0
        if old:
            if CONFIG.audit_export_before_delete:
                _export_to_disk(old)
            for r in old:
                db.delete(r)
            deleted_age = len(old)

        # ── by row count
        total = db.execute(select(func.count(AuditLog.id))).scalar_one()
        deleted_count = 0
        if total > max_rows:
            n_to_delete = total - max_rows
            old_rows = db.execute(
                select(AuditLog).order_by(asc(AuditLog.ts)).limit(n_to_delete)
            ).scalars().all()
            if old_rows:
                if CONFIG.audit_export_before_delete:
                    _export_to_disk(old_rows)
                for r in old_rows:
                    db.delete(r)
                deleted_count = len(old_rows)

        db.commit()
        return deleted_age, deleted_count


# ─────────────────────────────────────────────────────────────────
#  Hash-chain verification — for "is the chain intact?" check
# ─────────────────────────────────────────────────────────────────


def verify_hash_chain(db: DbSession) -> Tuple[bool, Optional[str]]:
    """Walk the audit log in order; verify each row.self_hash.

    Returns (ok, first_broken_id_or_None).  Only meaningful when
    AUDIT_HASH_CHAIN=true.
    """
    if not CONFIG.audit_hash_chain:
        return True, None
    rows = db.execute(select(AuditLog).order_by(asc(AuditLog.ts))).scalars().all()
    prev = ""
    for r in rows:
        if r.prev_hash != prev:
            return False, r.id
        recomputed = _hash_row(r)
        if recomputed != r.self_hash:
            return False, r.id
        prev = r.self_hash
    return True, None


__all__ = [
    "audit_log",
    "get_audit_logs",
    "count_audit_logs",
    "delete_audit_logs",
    "set_retention",
    "enforce_retention",
    "verify_hash_chain",
]
