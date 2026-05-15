# ARGUS · Deployment Guide

End-to-end deployment guide focused on first-login, owner password
configuration, and integration with the enterprise auth module.

For deeper architecture detail see `auth/README.md`.

---

## 1 · Quick start (60 seconds — one command)

```bash
# 1. Install
pip install -r requirements.txt -r auth/requirements.txt

# 2. ONE command does everything: generate secrets, create owner, write env file
python -m auth.bootstrap quickstart --email admin@yourdomain.com

# 3. Source the generated env file and start ARGUS
set -a; source .env.local; set +a
uvicorn agent_server:app --host 0.0.0.0 --port 8000

# 4. Browse to http://localhost:8000 — sign in with the credentials
#    that `quickstart` printed to your terminal.
```

`quickstart` does five things atomically:
1. Generates a strong `AUTH_JWT_SECRET` (64 bytes)
2. Generates an `AUTH_PASSWORD_PEPPER` (32 bytes)
3. Generates an `AUTH_INITIAL_OWNER_PASSWORD` (24 bytes, ~32 chars)
4. Writes them to `.env.local` (chmod 600)
5. Creates the auth tables + OWNER account using the SAME generated secrets

The owner account is created with `must_change_password=true`, so the
first login forces a password rotation.

> **After first login, delete `AUTH_INITIAL_OWNER_PASSWORD` from your
> env file.** The owner's real password is now hashed in the DB; the
> env entry was only a bootstrap seed.

### Even-simpler dev mode (zero arguments)

If you don't care about choosing the owner email or where the env
file goes, you can just run ARGUS — the auth module auto-generates
a password and prints it to stderr on first boot:

```bash
pip install -r requirements.txt -r auth/requirements.txt
uvicorn agent_server:app
```

```
====================================================================
AUTH BOOTSTRAP — first-run OWNER credentials (shown ONCE):
  email:    owner@argus.local
  password: bV3z9Kp_xQmF2NhR-tD8wA1Lc4Y6sE7H
Set AUTH_INITIAL_OWNER_EMAIL and AUTH_INITIAL_OWNER_PASSWORD
in production to suppress this print.
====================================================================
```

Copy that password before you hit Ctrl-L. (In `prod` mode the
auto-generated path is disabled — `quickstart` or explicit env vars
are required.)

### Manual mode (still supported)

If you'd rather pick your own password or you can't run interactive
commands:

```bash
# Generate just the password
python -m auth.bootstrap gen-password
# Prints: K8rN3pXqV9zL2mWyT4fJ8x7QwAhS2dGc

# Use it
export AUTH_INITIAL_OWNER_EMAIL='admin@yourdomain.com'
export AUTH_INITIAL_OWNER_PASSWORD='K8rN3pXqV9zL2mWyT4fJ8x7QwAhS2dGc'
export AUTH_JWT_SECRET=$(python -m auth.bootstrap rotate-jwt-key | grep = | cut -d= -f2-)
uvicorn agent_server:app
```

Or fully interactive (CI-unfriendly):

```bash
python -m auth.bootstrap create-owner
# Prompts:  Owner email:  ...   Owner password (min 12 chars):  ...
```

---

## 2 · First login — what to expect

### What the OWNER sees on first sign-in

| Step | Screen | What happens |
|------|--------|--------------|
| 1 | Cinematic login page | Animated particle network + gradient mesh + glowing ARGUS wordmark. Top status strip shows MCP / Vector DB / TLS / Build / Env. |
| 2 | Submit `owner@yourdomain.com` + initial password | POST `/auth/login`. No MFA enrolled yet → straight through. |
| 3 | (If `OWNER` is in `AUTH_MFA_REQUIRED_FOR`) MFA enrolment prompt | The system blocks the session until TOTP is enrolled. |
| 4 | Cockpit loads — Risk Dashboard by default | UserChip in top-right shows the OWNER's initials. |
| 5 | First action: rotate the password | Per the `must_change_password=true` flag set at bootstrap. |

### What if the env vars weren't set?

The auth bootstrap will:

- **In dev** (`AUTH_DEPLOYMENT_ENV` unset or `dev`) — generate a random
  24-byte URL-safe password and **print it once to stderr**:

  ```
  ====================================================================
  AUTH BOOTSTRAP — first-run OWNER credentials (shown ONCE):
    email:    owner@argus.local
    password: bV3z9Kp_xQmF2NhR-tD8wA1Lc4Y6sE7H
  Set AUTH_INITIAL_OWNER_EMAIL and AUTH_INITIAL_OWNER_PASSWORD
  in production to suppress this print.
  ====================================================================
  ```

- **In prod** (`AUTH_DEPLOYMENT_ENV=prod`) — refuse to auto-bootstrap.
  You must either set the env vars or run the CLI manually:

  ```bash
  python -m auth.bootstrap create-owner
  # Prompts: Owner email:  ...   Owner password (min 12 chars): ...
  ```

If you missed the printed password and the DB already has an OWNER,
**reset it via the CLI**:

```bash
# Easiest — drop the DB and re-bootstrap (LOSES ALL auth state including
# existing users, audit logs, SCIM tokens, IdPs)
rm argus_auth.db
export AUTH_INITIAL_OWNER_EMAIL='owner@yourdomain.com'
export AUTH_INITIAL_OWNER_PASSWORD='NewLongPass!1234'
python -m auth.bootstrap migrate           # then restart ARGUS

# Safer — keep data, rotate just the OWNER's password
python -c "
from auth.db import SessionLocal
from auth.models import User, UserCredentialLocal
from auth.security.passwords import hash_password
db = SessionLocal()
u = db.query(User).filter(User.email == 'owner@yourdomain.com').one()
h, v = hash_password('NewLongPass!1234')
u.credential.password_hash = h
u.credential.pepper_version = v
u.credential.must_change = True
db.commit()
print('OK')
"
```

---

## 3 · Environment-variable reference

All settings are 12-factor — env-var with sensible defaults.

### Required in production

| Var | Purpose | Generate |
|-----|---------|----------|
| `AUTH_JWT_SECRET` | HMAC key for access tokens. Without this, sessions invalidate on every process restart. | `openssl rand -base64 64` |
| `AUTH_INITIAL_OWNER_EMAIL` | First OWNER's email | your IT admin |
| `AUTH_INITIAL_OWNER_PASSWORD` | First OWNER's password (≥12 chars) | `openssl rand -base64 24` |
| `AUTH_PASSWORD_PEPPER` | Per-deployment HMAC pepper layered on top of per-user salt | `openssl rand -base64 32` |
| `AUTH_DEPLOYMENT_ENV` | `prod` blocks the dev auto-generated password path | `prod` |

### Recommended

| Var | Default | Notes |
|-----|---------|-------|
| `AUTH_DATABASE_URL` | `sqlite:///argus_auth.db` | Use `postgresql://...` for HA |
| `AUTH_COOKIE_SECURE` | `true` | Require HTTPS for cookies |
| `AUTH_COOKIE_SAMESITE` | `lax` | `strict` if no cross-site embeds |
| `AUTH_COOKIE_DOMAIN` | (empty) | Set when behind a reverse proxy on a subdomain |
| `AUTH_MFA_REQUIRED_FOR` | `OWNER,PLATFORM_ADMIN` | Comma-sep roles required to enrol MFA |
| `AUTH_LOCKOUT_THRESHOLD` | `5` | Failed attempts before lockout |
| `AUTH_LOCKOUT_DURATION_MIN` | `15` | Minutes locked |
| `AUTH_SESSION_IDLE_TIMEOUT_HOURS` | `12` | Idle timeout |
| `AUTH_SESSION_MAX_LIFETIME_HOURS` | `168` | Absolute lifetime cap (7d) |
| `AUTH_JWT_ACCESS_TTL_MIN` | `15` | Access-token TTL |
| `AUTH_JWT_REFRESH_TTL_DAYS` | `14` | Refresh-token TTL |
| `AUTH_AUDIT_MAX_ROWS` | `1000000` | Soft cap |
| `AUTH_AUDIT_MAX_AGE_DAYS` | `730` | Hard purge after 2 years |
| `AUTH_AUDIT_HASH_CHAIN` | `false` | Set `true` for tamper-evident audit log |
| `AUTH_REAUTH_REQUIRED` | `true` | Sensitive ops require fresh MFA |
| `AUTH_REAUTH_WINDOW_MIN` | `5` | Re-auth validity window |
| `AUTH_SCIM_TOKEN_TTL_DAYS` | `365` | SCIM bearer-token TTL |
| `AUTH_SCIM_DEFAULT_ROLE` | `ANALYST` | Role for JIT-provisioned users |

### Production env template (`.env.prod`)

```dotenv
# Database
AUTH_DATABASE_URL=postgresql://argus:CHANGEME@db.internal:5432/argus_auth
AUTH_DB_POOL_SIZE=10
AUTH_DB_MAX_OVERFLOW=20

# Crypto — generate ONCE; rotate via maintenance window
AUTH_JWT_SECRET=<openssl rand -base64 64>
AUTH_PASSWORD_PEPPER=<openssl rand -base64 32>
AUTH_JWT_ALGORITHM=HS256

# Cookies (over HTTPS only)
AUTH_COOKIE_SECURE=true
AUTH_COOKIE_SAMESITE=lax
AUTH_COOKIE_DOMAIN=argus.example.com

# Posture
AUTH_DEPLOYMENT_ENV=prod
AUTH_MFA_REQUIRED_FOR=OWNER,PLATFORM_ADMIN,SECURITY_MANAGER
AUTH_AUDIT_HASH_CHAIN=true
AUTH_REAUTH_REQUIRED=true

# Initial owner — clear AFTER first successful bootstrap
AUTH_INITIAL_OWNER_EMAIL=admin@example.com
AUTH_INITIAL_OWNER_PASSWORD=<openssl rand -base64 24>
AUTH_PRINT_BOOTSTRAP_CREDENTIALS=false

# Audit retention
AUTH_AUDIT_MAX_ROWS=5000000
AUTH_AUDIT_MAX_AGE_DAYS=2555            # 7 years for SOX
AUTH_AUDIT_EXPORT_BEFORE_DELETE=true
AUTH_AUDIT_EXPORT_DIR=/var/argus/audit_archive
```

> **After first successful boot, REMOVE `AUTH_INITIAL_OWNER_PASSWORD`
> from your env.**  Keeping it in env is fine, but if it leaks the
> attacker can re-create the OWNER on a fresh DB.

---

## 4 · Bootstrap CLI

```bash
# ── EASIEST PATH — one command does everything ───────────────────
python -m auth.bootstrap quickstart --email admin@yourdomain.com
# Generates AUTH_JWT_SECRET + AUTH_PASSWORD_PEPPER + owner password,
# writes them to .env.local (chmod 600), creates tables, creates OWNER.
# Prints the credentials + next-step command.

# Custom env-file path
python -m auth.bootstrap quickstart \
    --email admin@yourdomain.com \
    --env-path /etc/argus/argus.env

# Print to terminal only, no env file
python -m auth.bootstrap quickstart \
    --email admin@yourdomain.com \
    --no-write-env

# ── Single-secret helpers ───────────────────────────────────────
# Strong random password
python -m auth.bootstrap gen-password           # 24 bytes → ~32 chars
python -m auth.bootstrap gen-password --length 32   # longer
python -m auth.bootstrap gen-password --length 12   # shorter

# JWT signing key
python -m auth.bootstrap rotate-jwt-key
# Prints AUTH_JWT_SECRET=... — set in env + restart to invalidate sessions

# ── Lower-level building blocks ─────────────────────────────────
# Create all tables (idempotent)
python -m auth.bootstrap migrate

# Create OWNER interactively
python -m auth.bootstrap create-owner

# Create OWNER non-interactively (CI/CD)
python -m auth.bootstrap create-owner \
    --email owner@yourdomain.com \
    --password 'YourLongPass!1234'

# Create OWNER with auto-generated password (prints it)
python -m auth.bootstrap create-owner --email owner@yourdomain.com --generate

# Mint a SCIM bearer token (for Okta / Azure AD / OneLogin)
python -m auth.bootstrap issue-scim-token \
    --tenant-slug default \
    --description 'Okta production'

# Run audit-log retention sweep manually
python -m auth.bootstrap enforce-retention

# Ensure the default tenant exists (called by `migrate` already)
python -m auth.bootstrap ensure-default-tenant
```

---

## 5 · Role & default-skin mapping

The first OWNER → all subsequent users.  See `auth/README.md §2` for
the full hierarchy.  The auth module suggests a default skin for each
role on first login (user can override anytime via the SkinChooser):

| Role | Default skin | Cockpit feel |
|------|--------------|--------------|
| `OWNER` | stellar | Default cosmic-blue |
| `PLATFORM_ADMIN` | veteran | Terminal-dense |
| `SECURITY_MANAGER` | manager | PM dashboard |
| `OPERATOR` | redcell | Blood-red ops |
| `ANALYST` | novice | Friendly hints |
| `EXECUTIVE` | executive | Boardroom · ONE big number |
| `AUDITOR` | auditor | Read-only evidence |
| `CLIENT` | editorial | Magazine layout |

---

## 6 · Identity-provider setup

### Okta (OIDC)

1. Sign in to Okta admin → Applications → Create App Integration
2. Type: OIDC · Web Application
3. Sign-in redirect URI: `https://argus.example.com/auth/sso/oidc/<idp_id>/callback`
   (You won't know `<idp_id>` until step 5; use a placeholder, fix after.)
4. Grant types: Authorization Code · Refresh Token
5. In ARGUS, log in as OWNER → Users & Access → Identity Providers → Add:
   ```json
   {
     "name": "Okta",
     "kind": "OIDC",
     "enabled": true,
     "default_role": "ANALYST",
     "just_in_time_provisioning": true,
     "config": {
       "issuer": "https://yourorg.okta.com",
       "client_id": "<from Okta>",
       "client_secret": "<from Okta>",
       "authorization_endpoint": "https://yourorg.okta.com/oauth2/v1/authorize",
       "token_endpoint":         "https://yourorg.okta.com/oauth2/v1/token",
       "jwks_uri":               "https://yourorg.okta.com/oauth2/v1/keys"
     },
     "role_mapping": {
       "Argus-Operators": "OPERATOR",
       "Argus-Admins":    "PLATFORM_ADMIN"
     }
   }
   ```
6. Copy the IdP id back to Okta as the redirect URI.

### Okta (SCIM)

1. In ARGUS: Users & Access → SCIM Tokens → Issue Token → copy the
   plaintext.
2. In Okta: same app → Provisioning tab → Configure API integration
   - Base URL: `https://argus.example.com/scim/v2`
   - API token: the plaintext from step 1
3. Enable Push: Create/Update/Deactivate users + Push Groups
4. Map Okta groups to ARGUS roles via the `role_mapping` in your IdP
   config (or use SCIM groups directly).

### Azure AD (OIDC + SCIM)

Same pattern.  Endpoints:
- Authorize: `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize`
- Token: `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`
- JWKS: `https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`

### Google Workspace, OneLogin, JumpCloud, Auth0

All follow the same OIDC pattern with their respective endpoints.
The role_mapping → group claim is provider-specific:
- Okta: `groups`
- Azure: `groups` or `wids`
- Google: `groups` (requires Workspace Admin SDK)

---

## 7 · Production checklist

- [ ] `AUTH_JWT_SECRET` set to a long random value (`openssl rand -base64 64`)
- [ ] `AUTH_PASSWORD_PEPPER` set (defence-in-depth for password storage)
- [ ] `AUTH_DEPLOYMENT_ENV=prod`
- [ ] `AUTH_INITIAL_OWNER_PASSWORD` removed from env after first boot
- [ ] HTTPS terminated (cookies require Secure)
- [ ] `AUTH_COOKIE_DOMAIN` set if behind a subdomain proxy
- [ ] PostgreSQL (not SQLite) for `AUTH_DATABASE_URL` if > 5 users
- [ ] MFA enrolment forced for OWNER + PLATFORM_ADMIN minimum
- [ ] Audit log retention reviewed (SOX = 7 years, SOC 2 = 1 year, PCI = 1 year)
- [ ] `AUTH_AUDIT_HASH_CHAIN=true` for tamper evidence
- [ ] Audit-export directory has rotation + cold-storage backup
- [ ] Reverse-proxy passes `X-Forwarded-For` so client IPs are accurate
- [ ] First OWNER rotated their password on first login
- [ ] Backup OWNER created (in case primary loses MFA + backup codes)
- [ ] DR-test runbook exercised: restore from `argus_auth.db` backup
- [ ] SCIM tokens issued per IdP; reviewed quarterly

### Backup OWNER pattern

```bash
# After first boot, log in as primary OWNER, then:
# 1. Go to Users & Access → Add user
# 2. Email: backup-owner@yourdomain.com
# 3. Role: OWNER
# 4. Use a SEPARATE TOTP device + store backup codes in a sealed envelope
# This protects against the primary OWNER losing their MFA device.
```

---

## 8 · Common deployment topologies

### Single-process dev

```bash
uvicorn agent_server:app --port 8000 --reload
```

Auth runs in-process.  SQLite for everything.

### Behind a reverse proxy (nginx / Caddy)

```nginx
upstream argus { server 127.0.0.1:8000; }

server {
    listen 443 ssl http2;
    server_name argus.example.com;
    ssl_certificate /etc/letsencrypt/live/argus.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/argus.example.com/privkey.pem;

    # WebSocket support for ARGUS live events
    location / {
        proxy_pass http://argus;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```

Add to ARGUS env:
```
AUTH_COOKIE_DOMAIN=argus.example.com
AUTH_COOKIE_SECURE=true
```

### Multi-process behind a load balancer

Use **PostgreSQL** as `AUTH_DATABASE_URL` so all processes share the
same session/audit/user state.  Ensure all workers see the SAME
`AUTH_JWT_SECRET` (otherwise tokens from one worker won't validate on
another).

### Docker

```Dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt auth/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r auth/requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "agent_server:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# docker-compose.yml
services:
  argus:
    build: .
    ports: ["8000:8000"]
    environment:
      AUTH_DATABASE_URL: postgresql://argus:argus@db:5432/argus_auth
      AUTH_JWT_SECRET:   ${AUTH_JWT_SECRET}
      AUTH_PASSWORD_PEPPER: ${AUTH_PASSWORD_PEPPER}
      AUTH_DEPLOYMENT_ENV: prod
      AUTH_INITIAL_OWNER_EMAIL:    ${AUTH_INITIAL_OWNER_EMAIL}
      AUTH_INITIAL_OWNER_PASSWORD: ${AUTH_INITIAL_OWNER_PASSWORD}
      AUTH_COOKIE_DOMAIN: ${AUTH_COOKIE_DOMAIN}
    depends_on: [db]
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: argus
      POSTGRES_PASSWORD: argus
      POSTGRES_DB: argus_auth
    volumes: ["pgdata:/var/lib/postgresql/data"]
volumes: { pgdata: }
```

---

## 9 · Troubleshooting

### "I can't log in — the login page just spins"

Check:
1. `curl -i http://localhost:8000/auth/me` — should return 401 (good).
2. `curl http://localhost:8000/healthz/auth` — should return 200.
3. Browser console — look for CORS or `auth-stage` rendering errors.
4. `static/js/pages/LoginPage.jsx` must be served (look in Network tab).

### "I lost the OWNER password and there's no reset email yet"

The auth module doesn't ship an email reset flow in v1 (deliberately —
SMTP infrastructure is deployment-specific). Two recovery paths:

**Path A — reset via Python REPL** (preserves all state):
```bash
python -c "
from auth.db import SessionLocal
from auth.models import User
from auth.security.passwords import hash_password
db = SessionLocal()
u = db.query(User).filter(User.email == '<your-owner-email>').one()
h, v = hash_password('NewLongPass!1234')
u.credential.password_hash = h
u.credential.pepper_version = v
u.credential.must_change = True
db.commit(); print('OK')
"
```

**Path B — nuke + rebuild** (loses all auth state):
```bash
rm argus_auth.db
export AUTH_INITIAL_OWNER_EMAIL=owner@yourdomain.com
export AUTH_INITIAL_OWNER_PASSWORD=NewLongPass!1234
python -m auth.bootstrap migrate
# Restart ARGUS
```

### "I locked my MFA device — how do I get back in?"

Use a backup code (the 10 codes printed during enrolment).  Click
"Lost your device? Use a backup code" on the MFA challenge screen.

If you've also lost the backup codes: the OWNER (or another
PLATFORM_ADMIN) can:
```sql
-- Drop the user's MFA factors so they can re-enrol
DELETE FROM auth_user_mfa_factors WHERE user_id = '...';
DELETE FROM auth_mfa_backup_codes WHERE user_id = '...';
UPDATE auth_users SET mfa_enabled = false WHERE id = '...';
```
This action is auditable — emits a `SECURITY` row in `auth_audit_log`.

### "SAML callback fails with `python3-saml not installed`"

`python3-saml` requires native libraries:
```bash
# Debian/Ubuntu
sudo apt install libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config

# macOS
brew install libxml2 libxmlsec1

# Then:
pip install python3-saml
```

### "SQLite says 'database is locked' under load"

You're running multiple workers against SQLite.  Migrate to
PostgreSQL — change `AUTH_DATABASE_URL` and re-run `migrate`.  (The
schema is portable; no other changes required.)

### "JWT errors: 'token is invalid' after restart"

`AUTH_JWT_SECRET` is regenerated per-process when unset.  Set it in
env so all workers + restarts share the same key.

### "Refresh token reuse detected" appears in logs

This is the OAuth 2.1 §6.1 token-theft response triggering.  Either:
- A legitimate user clicked their browser's Back button after refresh
  (rare but possible), OR
- An attacker stole a refresh token and the legitimate user just
  presented a previously-rotated token.

The session is automatically revoked.  The user must sign in again.
Inspect `auth_audit_log` rows around the time for forensics.

### "I want to see what the OWNER did yesterday"

Users & Access → Audit Log (admin tab).  OR via API:
```bash
curl -sH "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/auth/admin/audit?limit=200" | jq
```

---

## 10 · Upgrade / migration paths

The auth schema is created via `Base.metadata.create_all()` and is
idempotent — schema changes between releases are additive.  For
breaking changes:

```bash
# 1. Back up the auth DB
cp argus_auth.db argus_auth.$(date +%Y%m%d).bak.db
# OR: pg_dump argus_auth > argus_auth.$(date +%Y%m%d).bak.sql

# 2. Pull the new release

# 3. Apply migrations
python -m auth.bootstrap migrate
```

For PostgreSQL with breaking changes, future releases will ship Alembic
migrations.  Until then, additive changes are safe and destructive
changes are documented in `auth/CHANGELOG.md` (TBD).

---

## 11 · Compliance notes

| Framework | Relevant capabilities |
|-----------|----------------------|
| **SOC 2** | Audit log (CC7.1), access reviews (CC6.3), MFA (CC6.1), session-rev on role change (CC6.6) |
| **ISO 27001** | A.5.16 (identity), A.5.17 (auth info), A.8.5 (secure auth), A.8.15 (logging) |
| **NIST 800-53** | AC-2, AC-3, AU-2, AU-3, AU-9, AU-11, IA-2, IA-5, SC-23 |
| **NIST 800-63B** | Memorized-secret rules (§5.1.1) implemented in `passwords.py:validate_policy` |
| **PCI DSS 4.0** | 8.2 (identification), 8.3 (MFA for non-console admin), 8.4 (account lockout), 10.2 (audit), 10.3 (audit content) |
| **HIPAA** | §164.312(a)(1) (access control), §164.312(b) (audit), §164.312(d) (authentication) |
| **GDPR** | Art. 32 (security of processing), Art. 25 (data protection by design) |
| **SOX** | Audit trail with 7-year retention via `AUTH_AUDIT_MAX_AGE_DAYS=2555` + hash chain |

The hash-chain mode (`AUTH_AUDIT_HASH_CHAIN=true`) provides tamper
evidence sufficient for SOX §404 ITGC + PCI 10.5.5 requirements.

---

## 12 · Where to go next

- `auth/README.md` — full architecture, RBAC matrix, ABAC predicates, flows
- `auth/security/passwords.py` — Argon2id parameters + pepper rotation
- `auth/security/mfa.py` — TOTP + backup-code internals
- `auth/providers/oidc.py` and `saml.py` — IdP integration internals
- `auth/scim.py` — SCIM 2.0 endpoint details + filter parser
- `auth/audit.py` — audit log retention + hash-chain verification
- `auth/rbac.py` — extend the permission model + add ABAC predicates
