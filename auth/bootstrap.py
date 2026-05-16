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


# -----------------------------------------------------------------


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


# -----------------------------------------------------------------


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


def cli_db_info() -> None:
    """Print a snapshot of what the auth module sees with the CURRENT env.

    Useful for spotting:
      * Wrong AUTH_DATABASE_URL (pointing at the wrong file)
      * Two terminals with different AUTH_PASSWORD_PEPPER
      * Auto-generated AUTH_JWT_SECRET (invalidates sessions on restart)
      * Stale OWNER rows or no OWNER at all
    """
    from auth.config import CONFIG
    from auth.db import SessionLocal
    from auth.models import RoleCode, User, UserRoleAssignment, AccountLockout
    from sqlalchemy import select
    from datetime import datetime, timezone

    print("=" * 72)
    print("  ARGUS auth — DB snapshot from THIS terminal's env")
    print("=" * 72)

    # -- Env / DB context --
    print(f"  cwd                  : {os.getcwd()}")
    print(f"  AUTH_DATABASE_URL    : {CONFIG.database_url}")
    if CONFIG.database_url.startswith("sqlite:///"):
        path = CONFIG.database_url.replace("sqlite:///", "")
        abs_path = os.path.abspath(path)
        exists = os.path.exists(abs_path)
        size = os.path.getsize(abs_path) if exists else None
        print(f"  resolved sqlite file : {abs_path}")
        print(f"  file exists          : {exists}")
        if exists:
            print(f"  file size            : {size:,} bytes")
    print(f"  AUTH_PASSWORD_PEPPER : "
          + (f"SET (length={len(CONFIG.password_pepper)})"
              if CONFIG.password_pepper else "NOT SET"))
    print(f"  AUTH_JWT_SECRET      : "
          + ("explicitly set" if os.environ.get("AUTH_JWT_SECRET")
             else "AUTO-GENERATED THIS RUN (sessions will invalidate on restart)"))
    print(f"  AUTH_MFA_REQUIRED_FOR: " + repr(CONFIG.mfa_required_roles))
    print(f"  AUTH_DEPLOYMENT_ENV  : {CONFIG.deployment_env}")
    print(f"  AUTH_COOKIE_SECURE   : {CONFIG.cookie_secure}"
          + ("   !! cookies will NOT stick on http:// -- set =false for "
             "local dev" if CONFIG.cookie_secure else ""))
    print(f"  AUTH_COOKIE_DOMAIN   : "
          + (CONFIG.cookie_domain if CONFIG.cookie_domain else "(unset)"))
    print()

    # -- DB content --
    try:
        init_db()
    except Exception as e:
        print(f"  !! could not initialize DB: {e}")
        return

    db = SessionLocal()
    try:
        users = db.execute(select(User)).scalars().all()
        owners = db.execute(
            select(User).join(UserRoleAssignment,
                               UserRoleAssignment.user_id == User.id)
            .where(UserRoleAssignment.role == RoleCode.OWNER)
        ).scalars().all()
        print(f"  Total users          : {len(users)}")
        print(f"  OWNERs               : {len(owners)}")
        now = datetime.now(timezone.utc)
        for u in owners:
            print()
            print(f"  --- OWNER {u.email} ------------------------------------")
            print(f"    user_id            : {u.id}")
            print(f"    status             : {u.status.value}")
            print(f"    primary auth       : {u.primary_auth_method.value}")
            print(f"    mfa_enabled        : {u.mfa_enabled}")
            print(f"    created_at         : {u.created_at}")
            print(f"    last_login_at      : {u.last_login_at}")

            if u.credential:
                print(f"    credential         : present")
                print(f"      password_hash    : {u.credential.password_hash[:18]}... "
                      f"(argon2id)")
                print(f"      pepper_version   : {u.credential.pepper_version}")
                print(f"      must_change      : {u.credential.must_change}")
                print(f"      last_rotated_at  : {u.credential.last_rotated_at}")
            else:
                print(f"    credential         : MISSING (SSO-only account)")

            # Lockouts
            open_lockouts = [lo for lo in (u.lockouts or [])
                              if lo.lifted_at is None
                              and (lo.expires_at is None
                                    or _as_aware(lo.expires_at) > now)]
            blocking_lockouts = [lo for lo in open_lockouts
                                  if lo.reason in ("brute_force", "admin_lock")]
            if blocking_lockouts:
                print(f"    !! LOCKED OUT      : {len(blocking_lockouts)} blocking "
                      f"lockout(s)  reasons={set(lo.reason for lo in blocking_lockouts)}")
                for lo in blocking_lockouts[:3]:
                    print(f"      - locked_at={lo.locked_at}  expires={lo.expires_at}")
            else:
                print(f"    lockouts           : none blocking "
                      f"({len(open_lockouts)} tracker rows)")

            # Sessions
            active = [s for s in (u.sessions or [])
                       if s.revoked_at is None
                       and _as_aware(s.expires_at) > now]
            print(f"    active sessions    : {len(active)}")

        if not owners:
            print()
            print("  !! NO OWNER exists in this DB.  Either:")
            print("     * This DB is empty.  Run quickstart to create one.")
            print("     * You're pointing at the wrong AUTH_DATABASE_URL.")
            print("     * Compare the resolved sqlite file above with the file")
            print("       the agent_server process is actually using.")
    finally:
        db.close()
    print("=" * 72)


def _as_aware(dt):
    """Helper: coerce naive datetimes (returned by SQLite) to UTC-aware."""
    from datetime import timezone
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=timezone.utc)


def cli_diagnose_login(*, email: str, password: str) -> None:
    """Take an email + password and explain in plain English why login is
    failing with the current env.

    This is the diagnostic to run when you've already reset the password
    and login STILL fails.  It will detect:
      * Wrong DB / no user
      * Account lockout
      * Pepper drift (most common — the password verifies against NO
        pepper but the current env has one set, or vice-versa)
      * Genuine password mismatch (copy-paste error, etc.)
      * Stale must_change_password flag
    """
    from auth.config import CONFIG
    from auth.db import SessionLocal
    from auth.models import User
    from sqlalchemy import select
    from datetime import datetime, timezone

    email_norm = email.strip().lower()
    print("=" * 72)
    print(f"  ARGUS auth — login diagnostic for {email_norm}")
    print("=" * 72)
    print(f"  Database URL         : {CONFIG.database_url}")
    print(f"  AUTH_PASSWORD_PEPPER : "
          + (f"SET (length={len(CONFIG.password_pepper)})"
              if CONFIG.password_pepper else "NOT SET"))
    print()

    init_db()
    db = SessionLocal()
    try:
        user = db.execute(
            select(User).where(User.email == email_norm)
        ).scalar_one_or_none()
        if user is None:
            print(f"  !! No user found with email '{email_norm}' in this DB.")
            print()
            print("  Diagnosis: wrong DB or wrong email.")
            print("  Run:  python -m auth.bootstrap db-info")
            print("  to see what's actually in this DB.")
            return

        print(f"  Found user           : {user.email}  ({user.status.value})")
        if user.credential is None:
            print(f"  !! No local credential — this account uses SSO only.")
            print(f"  Diagnosis: log in via SSO ('Continue with...' on the login page).")
            return

        # Check lockout
        now = datetime.now(timezone.utc)
        blocking = [lo for lo in (user.lockouts or [])
                     if lo.lifted_at is None
                     and lo.reason in ("brute_force", "admin_lock")
                     and (lo.expires_at is None
                           or _as_aware(lo.expires_at) > now)]
        if blocking:
            print(f"  !! Account is LOCKED OUT  ({len(blocking)} active lockout(s))")
            print()
            print("  Diagnosis: too many failed attempts.")
            print("  Run:  python -m auth.bootstrap reset-owner-password --generate")
            print("        (the reset clears lockouts automatically)")
            return

        # Helper: try a verify with an EXPLICIT pepper value (bypasses
        # the module-level CONFIG cache which may be stale).
        from auth.security.passwords import _HASHER, _apply_pepper
        def _try_pepper(explicit_pepper: str) -> bool:
            try:
                candidate = _apply_pepper(password, pepper=explicit_pepper)
                _HASHER.verify(user.credential.password_hash, candidate)
                return True
            except Exception:
                return False

        current_pepper = CONFIG.password_pepper or ""
        ok_current = _try_pepper(current_pepper)
        ok_no_pepper = _try_pepper("") if current_pepper else ok_current

        if ok_current:
            print(f"  OK Password VERIFIES with the current pepper config.")
            print()
            # Password is fine — surface the next-most-likely cause:
            # secure cookies + http://localhost combination.
            if CONFIG.cookie_secure:
                print("  +============================================================+")
                print("  |  LIKELY ROOT CAUSE: SECURE COOKIES ON http://localhost     |")
                print("  +============================================================+")
                print()
                print("  Password is correct.  But AUTH_COOKIE_SECURE is currently")
                print("  TRUE, which means the browser will refuse to store the")
                print("  argus_session cookie unless the page is served over HTTPS.")
                print()
                print("  Flow you're hitting:")
                print("    1. POST /auth/login  -> 200 OK with access_token")
                print("    2. Browser drops the Secure cookie silently")
                print("    3. Page reloads, GET /auth/me runs without the cookie")
                print("    4. /auth/me -> 401   (this is the 401 in your logs)")
                print("    5. Frontend bounces you back to the login page")
                print()
                print("  FIX for local dev: set AUTH_COOKIE_SECURE=false and")
                print("  restart agent_server in the same terminal:")
                print()
                print("    export AUTH_COOKIE_SECURE=false        # Linux/macOS")
                print("    $env:AUTH_COOKIE_SECURE = 'false'      # PowerShell")
                print("    set AUTH_COOKIE_SECURE=false           # cmd.exe")
                print()
                print("  Or set AUTH_DEPLOYMENT_ENV=dev (or leave unset) -- the")
                print("  default now matches that.  Then restart agent_server.")
                print()
                print("  For production, keep AUTH_COOKIE_SECURE=true and serve")
                print("  ARGUS only over HTTPS.")
                return
            print("  Diagnosis: nothing wrong here -- login should work.")
            print()
            print("  If your server still says 401, the SERVER process has a")
            print("  different env than THIS terminal.  Most common causes:")
            print("    * agent_server was started in a different shell with a")
            print("      different AUTH_PASSWORD_PEPPER")
            print("    * agent_server is reading a different .env / config")
            print("    * agent_server is pointing at a different argus_auth.db")
            print()
            print("  Compare the output of `db-info` between THIS shell and the")
            print("  shell where you launched agent_server.")
            return

        print(f"  !! Password did NOT verify with the current pepper config.")
        print()
        if ok_no_pepper:
            print("  +------------------------------------------------------------+")
            print("  |  ROOT CAUSE: PEPPER DRIFT                                  |")
            print("  +------------------------------------------------------------+")
            print()
            print("  The stored password hash was created WITHOUT a pepper,")
            print("  but your current environment has AUTH_PASSWORD_PEPPER set.")
            print("  → verify uses HMAC(pepper, password) instead of password")
            print("  → bytes don't match the stored hash → 401.")
            print()
            print("  FIX — pick ONE:")
            print()
            print("    (a) Unset AUTH_PASSWORD_PEPPER in this shell AND the")
            print("        agent_server shell, then restart agent_server:")
            print("            unset AUTH_PASSWORD_PEPPER")
            print("            uvicorn agent_server:app ...")
            print()
            print("    (b) Re-reset the password — the reset will hash WITH")
            print("        the current pepper, so future verifies match:")
            print("            python -m auth.bootstrap reset-owner-password --generate")
            print("        Then make sure agent_server runs in the SAME shell")
            print("        (or with the same AUTH_PASSWORD_PEPPER) as the reset.")
        else:
            print("  Tried hashing with NO pepper too — still doesn't match.")
            print()
            print("  +------------------------------------------------------------+")
            print("  |  ROOT CAUSE: password text mismatch                        |")
            print("  +------------------------------------------------------------+")
            print()
            print("  Likely causes:")
            print("    * Copy-paste error (URL-safe base64 contains `-` and `_`")
            print("      which sometimes get mangled by terminals or paste filters)")
            print("    * The password you typed doesn't match what was reset")
            print("    * An invisible whitespace got included on copy")
            print()
            print("  FIX: reset again and copy carefully, or use `--password`")
            print("       to set a password you can type without copy-paste:")
            print()
            print("    python -m auth.bootstrap reset-owner-password \\")
            print("        --password 'YourMemorablePass!2026'")
    finally:
        db.close()
    print("=" * 72)


def cli_reset_owner_password(*,
                              email: Optional[str] = None,
                              password: Optional[str] = None,
                              generate: bool = False,
                              clear_lockouts: bool = True,
                              revoke_sessions: bool = True) -> None:
    """Break-glass: reset the OWNER's password locally.

    Why this exists
    ---------------
    On a fresh deploy the auto-bootstrap path prints the OWNER's password
    to stderr exactly once.  If you missed it, OR if the password hash
    is no longer verifiable (most commonly because AUTH_PASSWORD_PEPPER
    drifted between the hash-time and verify-time runs), you need a
    one-command recovery path that doesn't require the user to know
    SQL or open a Python REPL.

    Behavior:
      * Finds the OWNER row (first one, or by --email)
      * Rotates their password — generated if --generate, or interactive
      * Re-hashes with the CURRENT pepper, so subsequent verifies work
      * Marks must_change=True so the new password is rotated on next login
      * Clears any open lockouts (--clear-lockouts default True)
      * Revokes all active sessions for that OWNER (--revoke-sessions default True)
      * Writes a CRITICAL audit log entry

    This is a LOCAL-ONLY command — it requires direct filesystem access
    to the auth DB, which is already a high security bar.  There is no
    HTTP API exposure of this.
    """
    init_db()
    db = SessionLocal()
    try:
        # 1. Find the OWNER
        if email:
            email_norm = email.strip().lower()
            user = db.execute(
                select(User).where(User.email == email_norm)
            ).scalar_one_or_none()
            if user is None:
                print(f"auth: no user found with email '{email_norm}'",
                       file=sys.stderr)
                sys.exit(2)
            is_owner = any(a.role == RoleCode.OWNER
                            for a in (user.role_assigns or []))
            if not is_owner:
                print(f"auth: user '{email_norm}' is not an OWNER",
                       file=sys.stderr)
                sys.exit(2)
        else:
            user = db.execute(
                select(User).join(UserRoleAssignment,
                                   UserRoleAssignment.user_id == User.id)
                .where(UserRoleAssignment.role == RoleCode.OWNER)
                .order_by(User.created_at.asc()).limit(1)
            ).scalar_one_or_none()
            if user is None:
                print("auth: no OWNER account found — run quickstart or "
                      "create-owner instead.", file=sys.stderr)
                sys.exit(2)

        # 2. Determine the new password
        if password is None:
            if generate:
                password = secrets.token_urlsafe(24)
            else:
                password = getpass.getpass(
                    f"New password for {user.email} (min 12 chars): "
                )
                if not password:
                    print("auth: no password supplied — use --generate "
                           "to auto-generate.", file=sys.stderr)
                    sys.exit(2)
        from auth.security.passwords import validate_policy
        validate_policy(password, email=user.email)

        # 3. Re-hash with the current config (pepper + argon2 params)
        from auth.security.passwords import hash_password
        new_hash, pepper_ver = hash_password(password)

        # 4. Update credential row
        if user.credential is None:
            from auth.models import UserCredentialLocal
            db.add(UserCredentialLocal(
                user_id=user.id, password_hash=new_hash,
                pepper_version=pepper_ver, must_change=True,
            ))
        else:
            user.credential.password_hash = new_hash
            user.credential.pepper_version = pepper_ver
            user.credential.must_change = True
            user.credential.last_rotated_at = datetime.now(timezone.utc)

        # 5. Clear lockouts so the user isn't blocked by stale 5-fail records
        cleared_lockouts = 0
        if clear_lockouts:
            from auth.models import AccountLockout
            now = datetime.now(timezone.utc)
            open_lockouts = [lo for lo in (user.lockouts or [])
                              if lo.lifted_at is None]
            for lo in open_lockouts:
                lo.lifted_at = now
            cleared_lockouts = len(open_lockouts)

        # 6. Revoke all active sessions so the new password takes effect
        revoked_sessions = 0
        if revoke_sessions:
            from auth.sessions import revoke_all_user_sessions
            revoked_sessions = revoke_all_user_sessions(
                db, user.id, reason="admin_password_reset",
            )

        # 7. Commit + audit
        db.commit()
        from auth.audit import audit_log, AuditSeverity
        audit_log(action="admin.owner_password_reset_via_cli",
                   actor=user, severity=AuditSeverity.CRITICAL,
                   resource_type="users", resource_id=user.id,
                   after_data={
                       "email": user.email,
                       "lockouts_cleared": cleared_lockouts,
                       "sessions_revoked": revoked_sessions,
                       "must_change_password": True,
                       "pepper_version": pepper_ver,
                   },
                   db=db)

        # 8. Friendly summary
        line = "=" * 72
        pepper_state = ("SET (length={})".format(len(CONFIG.password_pepper))
                         if CONFIG.password_pepper else "NOT SET")
        sqlite_resolved = ""
        if CONFIG.database_url.startswith("sqlite:///"):
            sqlite_resolved = os.path.abspath(
                CONFIG.database_url.replace("sqlite:///", "")
            )
        print()
        print(line)
        print("  ARGUS OWNER password reset")
        print(line)
        print(f"  Account            :  {user.email}")
        print(f"  New password       :  {password}")
        print(f"  Lockouts cleared   :  {cleared_lockouts}")
        print(f"  Sessions revoked   :  {revoked_sessions}")
        print(f"  Must change on next login: yes")
        print(line)
        print(f"  Database URL       :  {CONFIG.database_url}")
        if sqlite_resolved:
            print(f"  Resolved DB file   :  {sqlite_resolved}")
        print(f"  Pepper             :  {pepper_state}")
        print(line)
        print("  IMPORTANT — env-var alignment:")
        print()
        print("  The password was hashed with the env vars currently in")
        print("  THIS terminal.  For login to verify, your agent_server")
        print("  process MUST see the same:")
        print(f"    AUTH_DATABASE_URL    = {CONFIG.database_url}")
        print(f"    AUTH_PASSWORD_PEPPER = {pepper_state}")
        print()
        print("  Simplest path: restart agent_server in THIS same terminal,")
        print("  or `source .env.local` in both shells before starting it.")
        print()
        print("  If login still fails, run:")
        print("    python -m auth.bootstrap diagnose-login --email "
              + user.email)
        print(line)
    finally:
        db.close()


def cli_quickstart(email: Optional[str], env_path: str,
                   write_env: bool, tenant_slug: str = "default") -> None:
    """One-shot first-time setup — the easiest possible onboarding.

    What it does (idempotent):
      1. Generates strong values for:
          * AUTH_JWT_SECRET        (64 bytes → ~86 char URL-safe)
          * AUTH_PASSWORD_PEPPER   (32 bytes → ~43 char URL-safe)
          * AUTH_INITIAL_OWNER_PASSWORD  (24 bytes → ~32 char URL-safe)
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


# -----------------------------------------------------------------
#  argparse main
# -----------------------------------------------------------------


def main(argv: Optional[list] = None) -> None:
    p = argparse.ArgumentParser(prog="auth.bootstrap",
                                description="ARGUS auth module CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # -- EASIEST PATH — one command does everything --
    qs = sub.add_parser("quickstart",
        help="One-shot: generate secrets + create owner + write .env.local")
    qs.add_argument("--email", default=None,
                     help="Owner email (default: owner@argus.local)")
    qs.add_argument("--env-path", default=".env.local",
                     help="Where to write the generated env file (default: .env.local)")
    qs.add_argument("--no-write-env", action="store_true",
                     help="Skip writing the env file; print values only")
    qs.add_argument("--tenant-slug", default="default")

    # -- Break-glass: reset an OWNER's password locally --
    rp = sub.add_parser("reset-owner-password",
        help="Reset the OWNER password locally (recovery from lost password)")
    rp.add_argument("--email", default=None,
                     help="Specific OWNER email (default: first OWNER)")
    rp.add_argument("--password", default=None,
                     help="New password; omit + omit --generate to be prompted")
    rp.add_argument("--generate", action="store_true",
                     help="Generate a strong random password and print it")
    rp.add_argument("--keep-sessions", action="store_true",
                     help="Don't revoke existing sessions (default: revoke all)")
    rp.add_argument("--keep-lockouts", action="store_true",
                     help="Don't clear stale lockouts (default: clear)")

    # -- Diagnostics: figure out WHY login isn't working --
    sub.add_parser("db-info",
        help="Print a snapshot of the auth DB visible to THIS terminal's env")

    dl = sub.add_parser("diagnose-login",
        help="Take email+password and explain why login is failing")
    dl.add_argument("--email", required=True, help="Email to diagnose")
    dl.add_argument("--password", default=None,
                     help="Password to test (prompted hidden if omitted)")

    # -- Single-secret helpers --
    gp = sub.add_parser("gen-password",
        help="Print a single strong random password (no DB side effects)")
    gp.add_argument("--length", type=int, default=24,
                     help="Bytes of entropy (default 24 → ~32 ASCII chars)")

    sub.add_parser("rotate-jwt-key", help="Print a new AUTH_JWT_SECRET value")

    # -- Lower-level building blocks --
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
    elif args.cmd == "reset-owner-password":
        cli_reset_owner_password(
            email=args.email,
            password=args.password,
            generate=args.generate,
            clear_lockouts=(not args.keep_lockouts),
            revoke_sessions=(not args.keep_sessions),
        )
    elif args.cmd == "db-info":
        cli_db_info()
    elif args.cmd == "diagnose-login":
        pw = args.password
        if pw is None:
            pw = getpass.getpass(f"Password to test for {args.email}: ")
        cli_diagnose_login(email=args.email, password=pw)
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
