"""CLI utilities for first-run setup + ops:

    python -m auth.bootstrap migrate
        Create all tables.  Safe to re-run.

    python -m auth.bootstrap create-owner
        Interactive prompt to create the first OWNER.
        Or non-interactive via:
            --email owner@argus.local --password '...'

    python -m auth.bootstrap issue-scim-token --tenant-slug default --description "..."
        Mint a SCIM bearer token; prints the plaintext once.

    python -m auth.bootstrap rotate-jwt-key
        Print a new random JWT secret + remind the operator to set
        AUTH_JWT_SECRET and restart.

    python -m auth.bootstrap enforce-retention
        Run the audit-log retention sweep manually.

    python -m auth.bootstrap ensure-default-tenant
        Idempotent — create the "default" tenant if missing.

Auto-bootstrap: when integration.install_auth() runs, if no OWNER
exists AND `AUTH_INITIAL_OWNER_EMAIL`/`AUTH_INITIAL_OWNER_PASSWORD` are
set, this module creates the owner non-interactively.  In dev mode
(when the password is blank) it generates one and prints it to stderr
so a fresh checkout is usable in one command.
"""
from __future__ import annotations

import argparse
import getpass
import logging
import secrets
import sys
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from auth.audit import audit_log, enforce_retention
from auth.config import CONFIG
from auth.db import SessionLocal, init_db
from auth.models import (
    AuditSeverity, AuthMethod, RoleCode, Tenant, User,
    UserCredentialLocal, UserRoleAssignment, UserStatus,
)
from auth.scim import issue_scim_token
from auth.security.passwords import hash_password, validate_policy

logger = logging.getLogger("argus.auth.bootstrap")


# ─────────────────────────────────────────────────────────────────


def migrate() -> None:
    """Create all tables.  Idempotent."""
    init_db()
    print("auth: schema initialized", file=sys.stderr)


def ensure_default_tenant(db: DbSession, slug: str = "default") -> Tenant:
    t = db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none()
    if t is not None:
        return t
    t = Tenant(slug=slug, display_name=slug.title(), is_default=True)
    db.add(t)
    db.commit()
    print(f"auth: created default tenant '{slug}' ({t.id})", file=sys.stderr)
    return t


def create_owner(email: str, password: Optional[str] = None,
                 *, tenant_slug: str = "default") -> User:
    """Create the first OWNER account.  No-op if one already exists.

    Returns the existing OWNER's User row if one already exists.
    """
    init_db()
    db = SessionLocal()
    try:
        # Already have an owner?  Return them.
        existing = db.execute(
            select(User).join(UserRoleAssignment,
                              UserRoleAssignment.user_id == User.id)
            .where(UserRoleAssignment.role == RoleCode.OWNER)
            .order_by(User.created_at.asc()).limit(1)
        ).scalar_one_or_none()
        if existing is not None:
            print(f"auth: OWNER already exists ({existing.email})", file=sys.stderr)
            return existing

        tenant = ensure_default_tenant(db, tenant_slug)
        email = email.strip().lower()
        password = password or secrets.token_urlsafe(24)
        validate_policy(password, email=email)

        user = User(
            tenant_id=tenant.id, email=email,
            display_name="Platform Owner",
            status=UserStatus.ACTIVE,
            primary_auth_method=AuthMethod.LOCAL,
            email_verified_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.flush()

        h, ver = hash_password(password)
        db.add(UserCredentialLocal(user_id=user.id, password_hash=h,
                                    pepper_version=ver,
                                    must_change=True))
        db.add(UserRoleAssignment(
            user_id=user.id, tenant_id=tenant.id,
            role=RoleCode.OWNER,
        ))
        db.commit()
        audit_log(action="bootstrap.owner_created",
                  actor=None,
                  severity=AuditSeverity.CRITICAL,
                  after_data={"email": email, "tenant": tenant_slug},
                  db=db)
        return user
    finally:
        db.close()


def maybe_auto_bootstrap() -> None:
    """Called from integration.install_auth() — runs on first startup.

    Creates the default tenant + OWNER if neither exists.  Respects
    env vars for CI/CD.  In dev (no env vars set) prints a random
    password to stderr.
    """
    init_db()
    db = SessionLocal()
    try:
        owners = db.execute(
            select(func.count()).select_from(UserRoleAssignment)
            .where(UserRoleAssignment.role == RoleCode.OWNER)
        ).scalar_one()
        if owners > 0:
            return
        email = CONFIG.initial_owner_email or "owner@argus.local"
        password = CONFIG.initial_owner_password
        generated = False
        if not password:
            if CONFIG.deployment_env == "prod":
                logger.error(
                    "auth: no OWNER exists and AUTH_INITIAL_OWNER_PASSWORD is "
                    "not set in production. Run `python -m auth.bootstrap "
                    "create-owner` manually."
                )
                return
            password = secrets.token_urlsafe(24)
            generated = True
    finally:
        db.close()

    user = create_owner(email, password)
    if generated and CONFIG.print_bootstrap_credentials:
        print("=" * 68, file=sys.stderr)
        print("AUTH BOOTSTRAP — first-run OWNER credentials (shown ONCE):",
              file=sys.stderr)
        print(f"  email:    {email}", file=sys.stderr)
        print(f"  password: {password}", file=sys.stderr)
        print("Set AUTH_INITIAL_OWNER_EMAIL and AUTH_INITIAL_OWNER_PASSWORD",
              file=sys.stderr)
        print("in production to suppress this print.", file=sys.stderr)
        print("=" * 68, file=sys.stderr)


# ─────────────────────────────────────────────────────────────────


def cli_issue_scim_token(tenant_slug: str, description: str,
                         ttl_days: Optional[int]) -> None:
    init_db()
    db = SessionLocal()
    try:
        t = db.execute(select(Tenant).where(Tenant.slug == tenant_slug)
                       ).scalar_one_or_none()
        if t is None:
            print(f"auth: tenant '{tenant_slug}' not found", file=sys.stderr)
            sys.exit(2)
        row, plain = issue_scim_token(
            db, tenant_id=t.id, description=description, ttl_days=ttl_days,
        )
        print(plain)
        print(f"(token id: {row.id}, expires: {row.expires_at.isoformat()})",
              file=sys.stderr)
    finally:
        db.close()


def cli_rotate_jwt_key() -> None:
    new_secret = secrets.token_urlsafe(64)
    print(f"AUTH_JWT_SECRET={new_secret}")
    print("Set this env var and restart ARGUS. All sessions will require re-auth.",
          file=sys.stderr)


# ─────────────────────────────────────────────────────────────────
#  argparse main
# ─────────────────────────────────────────────────────────────────


def main(argv: Optional[list] = None) -> None:
    p = argparse.ArgumentParser(prog="auth.bootstrap",
                                description="ARGUS auth module CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("migrate", help="Create all tables (idempotent)")

    co = sub.add_parser("create-owner", help="Create the first OWNER")
    co.add_argument("--email", default=None)
    co.add_argument("--password", default=None)
    co.add_argument("--tenant-slug", default="default")

    sub.add_parser("ensure-default-tenant", help="Create the 'default' tenant if missing")

    st = sub.add_parser("issue-scim-token", help="Mint a SCIM bearer token")
    st.add_argument("--tenant-slug", default="default")
    st.add_argument("--description", required=True)
    st.add_argument("--ttl-days", type=int, default=None)

    sub.add_parser("rotate-jwt-key", help="Print a new AUTH_JWT_SECRET value")

    sub.add_parser("enforce-retention", help="Run the audit-log retention sweep")

    args = p.parse_args(argv)

    if args.cmd == "migrate":
        migrate()
    elif args.cmd == "create-owner":
        email = args.email
        if not email:
            email = input("Owner email: ").strip()
        password = args.password
        if not password:
            password = getpass.getpass("Owner password (min 12 chars): ")
        create_owner(email, password, tenant_slug=args.tenant_slug)
        print("ok", file=sys.stderr)
    elif args.cmd == "ensure-default-tenant":
        init_db()
        db = SessionLocal()
        try:
            ensure_default_tenant(db)
        finally:
            db.close()
    elif args.cmd == "issue-scim-token":
        cli_issue_scim_token(args.tenant_slug, args.description, args.ttl_days)
    elif args.cmd == "rotate-jwt-key":
        cli_rotate_jwt_key()
    elif args.cmd == "enforce-retention":
        init_db()
        deleted_age, deleted_count = enforce_retention()
        print(f"audit retention: {deleted_age} rows by age, "
              f"{deleted_count} rows by count", file=sys.stderr)


if __name__ == "__main__":
    main()
