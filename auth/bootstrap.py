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
import os
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


def cli_gen_password(length: int = 24) -> None:
    """Print a single strong random password.  No DB side effects.

    Length 24 → ~32 ASCII chars (URL-safe base64).  Caller can pipe to
    a password manager, paste into a secret store, or use as an
    AUTH_INITIAL_OWNER_PASSWORD value.
    """
    print(secrets.token_urlsafe(length))


def cli_quickstart(email: Optional[str], env_path: str,
                   write_env: bool, tenant_slug: str = "default") -> None:
    """One-shot first-time setup — the easiest possible onboarding.

    What it does (idempotent):
      1. Generates strong values for:
          • AUTH_JWT_SECRET        (64 bytes → ~86 char URL-safe)
          • AUTH_PASSWORD_PEPPER   (32 bytes → ~43 char URL-safe)
          • AUTH_INITIAL_OWNER_PASSWORD  (24 bytes → ~32 char URL-safe)
      2. Writes them to `.env.local` (or --env-path) as key=value pairs
         (safe to `source`, also compatible with python-dotenv, docker
         compose env_file, systemd EnvironmentFile, etc.)
      3. Sets the JWT secret + pepper in-process so the next two steps
         use the same values that ended up in the env file
      4. Runs migrate() to create all tables
      5. Creates the OWNER account with the generated password
      6. Prints a clean summary with the credentials + the next command

    After this, you start ARGUS with:
        source .env.local && uvicorn agent_server:app

    Or just rely on auto-bootstrap (the .env.local works for that too).
    """
    email = (email or "owner@argus.local").strip().lower()

    # 1. Generate
    jwt_secret = secrets.token_urlsafe(64)
    pepper     = secrets.token_urlsafe(32)
    password   = secrets.token_urlsafe(24)

    # 2. Write env file (if requested)
    written_to: Optional[str] = None
    if write_env:
        # Open in exclusive-create mode unless --force; we keep it
        # simple here — overwrite is fine because quickstart is meant
        # to be the FIRST step.  Existing operators are guarded by
        # the "OWNER already exists" check downstream.
        env_lines = [
            "# ARGUS auth module — generated by `python -m auth.bootstrap quickstart`",
            "# Treat this file as a secret.  Add to .gitignore.",
            "",
            f"AUTH_JWT_SECRET='{jwt_secret}'",
            f"AUTH_PASSWORD_PEPPER='{pepper}'",
            "",
            f"AUTH_INITIAL_OWNER_EMAIL='{email}'",
            f"AUTH_INITIAL_OWNER_PASSWORD='{password}'",
            "",
            "# Production: uncomment + flip this so the bootstrap will",
            "# refuse to auto-generate a password if one isn't set.",
            "# AUTH_DEPLOYMENT_ENV=prod",
            "",
            "# Once the owner has logged in once + rotated their",
            "# password, REMOVE the AUTH_INITIAL_OWNER_PASSWORD line.",
            "",
        ]
        try:
            with open(env_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(env_lines))
            os.chmod(env_path, 0o600)        # rw-------; ignored on Windows
            written_to = env_path
        except Exception as e:
            print(f"!! could not write env file ({env_path}): {e}", file=sys.stderr)

    # 3-4. Make sure the in-process bootstrap uses the SAME secret/pepper
    # we just wrote, so the password hash is verifiable on next start.
    os.environ["AUTH_JWT_SECRET"]      = jwt_secret
    os.environ["AUTH_PASSWORD_PEPPER"] = pepper
    # Re-import CONFIG with the freshly-set env so password hashing
    # picks up the new pepper.  (Module-level singleton; reload it.)
    import importlib, auth.config, auth.security.passwords
    importlib.reload(auth.config)
    importlib.reload(auth.security.passwords)

    migrate()

    # 5. Owner
    user = create_owner(email, password, tenant_slug=tenant_slug)
    is_new = user.email == email          # always true on first run

    # 6. Friendly summary
    line = "=" * 72
    print()
    print(line)
    print("  ARGUS first-time setup complete")
    print(line)
    print(f"  Owner email     :  {email}")
    print(f"  Owner password  :  {password}")
    print(f"  JWT secret      :  {jwt_secret[:14]}...  (full value in env file)")
    print(f"  Password pepper :  {pepper[:14]}...  (full value in env file)")
    if written_to:
        print(f"  Env file        :  {written_to}  (chmod 600)")
    print(line)
    print("  Next steps:")
    print()
    if written_to:
        print("    # Linux / macOS:")
        print(f"    set -a; source {written_to}; set +a")
        print("    uvicorn agent_server:app --host 0.0.0.0 --port 8000")
        print()
        print("    # Windows PowerShell:")
        print(f"    Get-Content {written_to} | ForEach-Object {{")
        print("        if ($_ -match \"^([^#=]+)='([^']*)'\") {")
        print("            [Environment]::SetEnvironmentVariable($matches[1], $matches[2])")
        print("        }")
        print("    }")
        print("    uvicorn agent_server:app --host 0.0.0.0 --port 8000")
    else:
        print("    Set the printed credentials in your env, then:")
        print("    uvicorn agent_server:app --host 0.0.0.0 --port 8000")
    print()
    print("  Then browse to http://localhost:8000 and sign in with the")
    print("  credentials above.  You'll be prompted to rotate the password")
    print("  on first login.")
    print(line)


# ─────────────────────────────────────────────────────────────────
#  argparse main
# ─────────────────────────────────────────────────────────────────


def main(argv: Optional[list] = None) -> None:
    p = argparse.ArgumentParser(prog="auth.bootstrap",
                                description="ARGUS auth module CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── EASIEST PATH — one command does everything ──
    qs = sub.add_parser("quickstart",
        help="One-shot: generate secrets + create owner + write .env.local")
    qs.add_argument("--email", default=None,
                     help="Owner email (default: owner@argus.local)")
    qs.add_argument("--env-path", default=".env.local",
                     help="Where to write the generated env file (default: .env.local)")
    qs.add_argument("--no-write-env", action="store_true",
                     help="Skip writing the env file; print values only")
    qs.add_argument("--tenant-slug", default="default")

    # ── Single-secret helpers ──
    gp = sub.add_parser("gen-password",
        help="Print a single strong random password (no DB side effects)")
    gp.add_argument("--length", type=int, default=24,
                     help="Bytes of entropy (default 24 → ~32 ASCII chars)")

    sub.add_parser("rotate-jwt-key", help="Print a new AUTH_JWT_SECRET value")

    # ── Lower-level building blocks ──
    sub.add_parser("migrate", help="Create all tables (idempotent)")

    co = sub.add_parser("create-owner",
        help="Create the first OWNER (interactive or via --email/--password)")
    co.add_argument("--email", default=None)
    co.add_argument("--password", default=None,
                     help="Owner password.  Omit + omit --generate to be prompted.")
    co.add_argument("--generate", action="store_true",
                     help="Generate a strong random password instead of prompting")
    co.add_argument("--tenant-slug", default="default")

    sub.add_parser("ensure-default-tenant", help="Create the 'default' tenant if missing")

    st = sub.add_parser("issue-scim-token", help="Mint a SCIM bearer token")
    st.add_argument("--tenant-slug", default="default")
    st.add_argument("--description", required=True)
    st.add_argument("--ttl-days", type=int, default=None)

    sub.add_parser("enforce-retention", help="Run the audit-log retention sweep")

    args = p.parse_args(argv)

    if args.cmd == "quickstart":
        cli_quickstart(
            email=args.email,
            env_path=args.env_path,
            write_env=(not args.no_write_env),
            tenant_slug=args.tenant_slug,
        )
    elif args.cmd == "gen-password":
        cli_gen_password(length=args.length)
    elif args.cmd == "migrate":
        migrate()
    elif args.cmd == "create-owner":
        email = args.email
        if not email:
            email = input("Owner email: ").strip()
        password = args.password
        if not password and args.generate:
            password = secrets.token_urlsafe(24)
            print(f"Generated password: {password}", file=sys.stderr)
        elif not password:
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
