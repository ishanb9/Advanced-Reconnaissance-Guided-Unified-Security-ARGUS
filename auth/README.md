# ARGUS · Enterprise Auth Module

Enterprise-grade user management, authentication, authorization, and
audit for ARGUS.  Designed to NIST 800-53 / ISO 27001 / SOC 2 / SOX
expectations.

This module is **purely additive**.  It does not modify any existing
ARGUS file (agents, knowledge, db, agent_server, schemas, mcp-server).
Integration is a single line:

```python
from auth.integration import install_auth
install_auth(app)              # one-line mount on the FastAPI/aiohttp app
```

---

## 1 · Capabilities

| Surface | Status | Notes |
|---------|--------|-------|
| Local username/password | ✅ | Argon2id hashing (RFC 9106), per-user pepper |
| MFA — TOTP (RFC 6238) | ✅ | `pyotp`, 8-char backup codes, QR enrolment |
| MFA — WebAuthn / FIDO2 | 🟡 stub | Interface ready, `webauthn` lib bind documented |
| SSO — OIDC (RFC 6749/8252) | ✅ | `authlib`, multi-tenant IdP table, PKCE enforced |
| SSO — SAML 2.0 | ✅ | `python3-saml`, SP-initiated + IdP-initiated |
| SCIM 2.0 (RFC 7644) | ✅ | `/scim/v2/Users` + `/scim/v2/Groups`, filter parser, bearer auth |
| RBAC + ABAC | ✅ | 8 hierarchical roles, attribute scoping per engagement/tenant |
| DB-backed sessions | ✅ | UI state, scan refs, settings survive reload + reboot |
| Audit log | ✅ | Append-only, owner-only delete, configurable retention |
| Password policy | ✅ | NIST 800-63B compliant (no rotation, length-first) |
| Breached-password check | 🟡 stub | k-anon API call documented (HIBP Pwned Passwords) |
| Account lockout | ✅ | Rate limit + temporary lockout on N failed attempts |
| Refresh tokens | ✅ | Rotating refresh tokens, family revocation on theft |
| CSRF protection | ✅ | Double-submit cookie + Origin check |

---

## 2 · Role Hierarchy

The task asked for **renaming per global best practices**.  The names
below match what Okta, Auth0, AWS IAM, GitHub Enterprise, Google
Workspace, and major SaaS platforms converge on — clearer separation
between platform-administration vs. engagement-execution roles.

| Code | Display Name | Bypass RBAC | Scope | Notes |
|------|--------------|-------------|-------|-------|
| `OWNER` | Platform Owner | ✅ yes | global | God-mode. Cannot be deleted. Cannot be demoted by anyone except themselves. Transferable. |
| `PLATFORM_ADMIN` | Platform Administrator | no | global | Manages users, SSO, SCIM, config, retention. Cannot view engagement data unless explicitly granted. |
| `SECURITY_MANAGER` | Security Manager | no | tenant | Owns engagements: scoping, operator assignment, validation, reporting. Replaces "Manager" with the industry-correct title. |
| `OPERATOR` | Operator | no | engagement | Full red-team capability within assigned engagements. Dispatches agents, runs tools, creates findings. |
| `ANALYST` | Analyst | no | engagement | Validation, manual non-destructive tool runs, finding triage. Replaces "Manager (validation)" with clearer separation. |
| `EXECUTIVE` | Executive | no | tenant | Risk dashboards, decision packets, generates board reports. No tool execution. |
| `AUDITOR` | Auditor | no | global | Read-only across everything, with evidence chain + citation visibility. |
| `CLIENT` | Client | no | engagement (scoped) | External user, sees one engagement's report only. Severity-redacted by default. |

**Why this set is the right shape:**

1. `SECURITY_MANAGER` separates engagement-management from
   platform-administration — most enterprises split these because the
   skill sets diverge (PM/scope/billing vs. user/SSO/SCIM).
2. `OPERATOR` + `ANALYST` separates destructive offensive ops from
   non-destructive validation — supports the "two-person rule" pattern
   common in mature SOC operations.
3. `EXECUTIVE` is a first-class persona, not just "manager with extra
   dashboard widgets".
4. `AUDITOR` is global read-only — independent third parties and
   internal compliance auditors share this role.
5. `CLIENT` is engagement-scoped — sustains multi-tenant SaaS pricing
   models without changing the data model.

### Permission grants (defaults — overridable via UI)

```
                       findings   tools     users    audit    settings   roles
OWNER                  *          *         *        *        *          *
PLATFORM_ADMIN         -          -         CRUD     R        R-W        assign
SECURITY_MANAGER       R-W (own)  EXEC      R        R (own)  -          assign-op
OPERATOR               R-W (asg)  EXEC      R-self   R-self   -          -
ANALYST                R-V (asg)  EXEC-ND   R-self   R-self   -          -
EXECUTIVE              R (≥med)   -         R        R (own)  -          -
AUDITOR                R          -         R        R        R          R
CLIENT                 R-scoped   -         -        -        -          -

* = all actions      EXEC-ND = execute non-destructive only
R-V = read + validate    asg = assigned engagements only
```

### Role-suggested skin (ties into the existing skin chooser)

| Role | Default skin |
|------|--------------|
| OWNER | stellar (free choice) |
| PLATFORM_ADMIN | veteran |
| SECURITY_MANAGER | manager |
| OPERATOR | redcell (or operator's prior choice) |
| ANALYST | novice |
| EXECUTIVE | executive |
| AUDITOR | auditor |
| CLIENT | editorial |

The skin choice is still per-user — the role only suggests an initial
default on first login.

---

## 3 · Architecture

```
                ┌────────────────────────────────────────────────┐
                │             FastAPI app (ARGUS)                │
                │                                                │
                │   ┌──────────────────────────────────────┐     │
                │   │   install_auth(app)  ← one line      │     │
                │   └──────────────┬───────────────────────┘     │
                │                  │ mounts                       │
                │   ┌──────────────▼───────────────────────┐     │
                │   │  /auth/*       /scim/v2/*            │     │
                │   │   • login        • Users             │     │
                │   │   • logout       • Groups            │     │
                │   │   • refresh                          │     │
                │   │   • mfa/*                            │     │
                │   │   • sso/oidc/{provider}              │     │
                │   │   • sso/saml/{provider}              │     │
                │   │   • me / me/state                    │     │
                │   │   • admin/users (RBAC-gated)         │     │
                │   │   • admin/audit (RBAC-gated)         │     │
                │   └──────────────────────────────────────┘     │
                │                                                │
                │   Dependencies:                                │
                │   • get_current_user()                         │
                │   • require_role(...)                          │
                │   • require_permission(...)                    │
                │   • current_session()                          │
                │   • current_tenant()                           │
                └────────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────┐
                  │  Persistence (SQLAlchemy 2.0)            │
                  │  SQLite for dev · PostgreSQL for prod    │
                  │                                          │
                  │  tenants  identity_providers             │
                  │  users    user_credentials_local         │
                  │  user_mfa_factors  mfa_backup_codes      │
                  │  user_roles (M:N) user_identities (SSO)  │
                  │  sessions session_state (1:1)            │
                  │  refresh_tokens (rotating)               │
                  │  audit_log (append-only)                 │
                  │  scim_bearer_tokens                      │
                  │  password_reset_tokens                   │
                  │  account_lockouts                        │
                  │  settings (system config + retention)    │
                  └──────────────────────────────────────────┘
```

### Why two persistence layers?

ARGUS already has an operational DB (`db/`) for scan results,
findings, agents.  The auth module uses a **separate** DB connection
(default: `argus_auth.db` next to ARGUS's main DB, or shared via
config) so:

1. Auth schema migrations don't touch operational tables
2. Auth can use PostgreSQL while ARGUS keeps SQLite, or vice versa
3. Auth tables can be backed up + audited on a different cadence
4. Operational rollback won't lose user accounts

For small teams, `AUTH_DATABASE_URL` can point to the same SQLite file
as ARGUS — the tables are namespaced.

---

## 4 · Authentication flows

### 4.1 Local (username + password + MFA)

```
Browser                          /auth/login                       DB
  │                                  │                              │
  │ POST {username, password}        │                              │
  ├─────────────────────────────────►│                              │
  │                                  │  SELECT users WHERE ...      │
  │                                  ├─────────────────────────────►│
  │                                  │                              │
  │                                  │  argon2.verify(password)     │
  │                                  │  ┌── lockout check ──┐       │
  │                                  │  ├── audit log entry ┤       │
  │                                  │                              │
  │  if MFA enrolled:                │                              │
  │ ◄────────────  202 + mfa_token ──┤                              │
  │                                  │                              │
  │ POST /auth/mfa/verify {totp}     │                              │
  ├─────────────────────────────────►│                              │
  │                                  │  pyotp.verify(totp)          │
  │                                  │  INSERT sessions             │
  │                                  ├─────────────────────────────►│
  │ ◄── 200 + session_cookie +       │                              │
  │      refresh_token (httpOnly)    │                              │
```

### 4.2 OIDC SSO

```
Browser           ARGUS                 IdP (Okta/AzureAD/Google)
  │ /auth/sso/oidc/{tid} │              │
  ├─────────────────────►│  build authz │
  │                      │  URL w/ PKCE │
  │ ◄─ 302 to IdP ───────┤              │
  │                                     │
  │ /authorize ──────────────────────►  │
  │                                     │ user logs in
  │ ◄── 302 + code ───────────────────  │
  │ /auth/sso/oidc/{tid}/callback?code= │
  ├─────────────────────►│              │
  │                      │ exchange code│
  │                      ├─────────────►│
  │                      │ ◄─ id_token ─┤
  │                      │ validate sig │
  │                      │ upsert user  │
  │                      │ create sess  │
  │ ◄── 302 to /app ─────┤              │
```

### 4.3 SAML 2.0 SSO

Standard SP-initiated flow via python3-saml.  Per-tenant SP metadata
exposed at `/auth/sso/saml/{tenant_id}/metadata`.  Per-tenant SSO URL
at `/auth/sso/saml/{tenant_id}/login`.

### 4.4 SCIM provisioning

`POST /scim/v2/Users` with Okta/Azure-style payload creates the user,
assigns roles from `groups` mapping, and emits an audit log.  Bearer
token auth (rotating, stored in `scim_bearer_tokens`).  Filter parser
supports `eq`, `ne`, `co`, `sw`, `ew`, `pr`, `and` per RFC 7644 §3.4.

---

## 5 · Stateful sessions

Each successful authentication creates a row in `sessions` with:

| Column | Purpose |
|--------|---------|
| `id` | UUID, primary key |
| `user_id` | FK |
| `created_at` / `last_seen_at` / `expires_at` | lifecycle |
| `ip_address` / `user_agent` | audit + anomaly |
| `revoked_at` | manual termination |
| `csrf_token` | per-session double-submit secret |
| `current_tenant_id` | active workspace |

A separate `session_state` table (1:1) stores **UI state that survives
reload, reboot, and even device switch**:

```json
{
  "skin": "redcell",
  "audience_mode": "OPERATOR",
  "sidebar_collapsed": false,
  "current_hub": "exploit",
  "current_tab": "chains",
  "hub_tab_memory": { "risk": "summary", "findings": "all" },
  "pinned_pentest_session_id": "sess_abc123",
  "open_finding_ids": ["f_1", "f_2", "f_7"],
  "filters": { "severity": [">=", "medium"], "phase": "post-ex" },
  "client_brand": { "name": "Acme", "color": "#1F4D8B" },
  "preferences": { "dense_tables": true, "auto_scroll_logs": false }
}
```

Frontend writes to `localStorage` as a write-through cache + offline
fallback, but **the DB is source of truth**.  On boot, `GET /auth/me`
returns the user + their `session_state` so any device sees the same
cockpit.  When a user resumes a session, the active **pentest session**
referenced by `pinned_pentest_session_id` is automatically re-attached
via the existing ARGUS session pin mechanism.

Sessions auto-expire after `SESSION_IDLE_TIMEOUT_HOURS` (default 12)
of inactivity or `SESSION_MAX_LIFETIME_HOURS` (default 168 = 7 days)
absolute.  Refresh tokens rotate on every use; reuse triggers family
revocation (token theft response per OAuth 2.1 §6.1).

---

## 6 · Audit logging

Every state-changing action emits an audit log row:

```sql
INSERT INTO audit_log
  (id, ts, user_id, session_id, tenant_id,
   action, resource_type, resource_id,
   ip_address, user_agent,
   before_data, after_data, status, error_message, severity)
VALUES (...);
```

**Retention policy** (configurable by `PLATFORM_ADMIN` or `OWNER`):

- `audit.max_rows` — soft cap, oldest rotated out when exceeded
- `audit.max_age_days` — absolute time-based purge
- `audit.export_before_delete` — emit JSON to disk before rotation

**Deletion permissions:**

- `audit_logs:delete` — granted ONLY to `OWNER`
- `audit_logs:configure` — granted to `OWNER` + `PLATFORM_ADMIN`
- `audit_logs:read` — granted by RBAC per scope (admins see all,
  managers see their tenant, operators see their own actions)

The audit log table can optionally be made **append-only at the DB
level** with a per-row hash chain (`prev_hash` column) for tamper
evidence — enable via `AUDIT_HASH_CHAIN=true`.

---

## 7 · Integration

```python
# In agent_server.py — add ONE import + ONE call:
from auth.integration import install_auth

app = FastAPI()
# ... existing ARGUS setup ...
install_auth(app)              # mounts /auth/* and /scim/v2/*
```

That's it.  The auth module:

- Creates its tables on first import (idempotent)
- Auto-runs `bootstrap.py` if no `OWNER` exists (in dev mode prints
  one-time credentials; in prod requires `AUTH_INITIAL_OWNER_EMAIL` +
  `AUTH_INITIAL_OWNER_PASSWORD` env vars)
- Adds `get_current_user` / `require_permission` deps that existing
  routes can opt into:

```python
from auth.dependencies import require_permission, current_user

@app.post("/api/scan/start")
async def start_scan(
    target: ScanRequest,
    user = Depends(require_permission("tools", "execute"))
):
    audit.log(user, action="scan.start", resource_type="engagement",
              resource_id=target.engagement_id, after_data={...})
    ...
```

ARGUS routes that don't add the dep keep working unchanged.

---

## 8 · CLI

```bash
# Create the first owner (interactive)
python -m auth.bootstrap create-owner

# Create owner non-interactively (CI/CD)
python -m auth.bootstrap create-owner \
    --email owner@argus.local \
    --password '$(openssl rand -base64 32)'

# Issue a SCIM bearer token for an IdP
python -m auth.bootstrap issue-scim-token --tenant-id default --description "Okta prod"

# Run migrations (creates tables; safe to re-run)
python -m auth.bootstrap migrate

# Rotate the JWT signing key (forces all sessions to re-auth)
python -m auth.bootstrap rotate-jwt-key
```

---

## 9 · Configuration

All config via environment variables (12-factor):

```bash
# Database
AUTH_DATABASE_URL=sqlite:///argus_auth.db   # or postgresql://...

# JWT
AUTH_JWT_SECRET=<openssl rand -base64 64>
AUTH_JWT_ALGORITHM=HS256                     # HS256 or RS256
AUTH_JWT_ACCESS_TTL_MIN=15
AUTH_JWT_REFRESH_TTL_DAYS=14

# Sessions
AUTH_SESSION_IDLE_TIMEOUT_HOURS=12
AUTH_SESSION_MAX_LIFETIME_HOURS=168
AUTH_COOKIE_SECURE=true
AUTH_COOKIE_SAMESITE=lax
AUTH_COOKIE_DOMAIN=                          # optional

# MFA
AUTH_MFA_REQUIRED_FOR=OWNER,PLATFORM_ADMIN   # comma-sep roles
AUTH_TOTP_ISSUER=ARGUS

# Account lockout
AUTH_LOCKOUT_THRESHOLD=5
AUTH_LOCKOUT_DURATION_MIN=15

# Audit
AUTH_AUDIT_MAX_ROWS=1000000
AUTH_AUDIT_MAX_AGE_DAYS=730                  # 2 years
AUTH_AUDIT_HASH_CHAIN=false                  # tamper-evidence

# OIDC (per-provider via /admin/identity-providers endpoint)
# SAML (per-provider via same admin endpoint)

# SCIM
AUTH_SCIM_TOKEN_TTL_DAYS=365

# Initial owner (CI/CD)
AUTH_INITIAL_OWNER_EMAIL=
AUTH_INITIAL_OWNER_PASSWORD=
```

---

## 10 · Dependencies

```
sqlalchemy>=2.0,<3
argon2-cffi>=23.1
pyotp>=2.9
qrcode[pil]>=7.4
pyjwt[crypto]>=2.8
authlib>=1.3                         # OIDC
python3-saml>=1.16                   # SAML 2.0
pydantic>=2.5
email-validator>=2.1
python-multipart>=0.0.6
```

Add to ARGUS's `requirements.txt`.

---

## 11 · Security posture

| Concern | Mitigation |
|---------|------------|
| Password storage | Argon2id, m=64MiB t=3 p=4 (RFC 9106 §4) + per-user pepper |
| Brute force | Per-account lockout (5 fails / 15min) + global rate limit |
| Session theft | httpOnly + Secure + SameSite=Lax cookies, CSRF token, IP/UA fingerprint |
| Refresh-token theft | Rotating tokens; reuse → family revocation |
| MFA bypass | Reauth required for sensitive ops (role change, MFA enrol) |
| Privilege escalation | Owner-only role grants for OWNER + PLATFORM_ADMIN |
| Audit-log tampering | Append-only by design; optional hash chain |
| OIDC code injection | PKCE enforced (`code_challenge_method=S256`) |
| SAML XSW attacks | python3-saml ≥ 1.16 mitigates known XML-signature wrapping |
| SCIM token leak | Hashed at rest, rotation API, audit on every use |
| Timing oracle | Constant-time argon2 verify + dummy-hash for unknown users |

---

## 12 · What's NOT here (future)

- **WebAuthn / FIDO2** — interface stubbed in `security/mfa.py`,
  bind `webauthn` library + register/authenticate routes
- **Risk-based auth** — anomaly detection on geo / device / velocity
- **Just-in-time access requests** — temporary role elevation with
  approval flow
- **DLP** — sensitive-data classification + redaction on export
- **Customer-managed keys** — BYOK for credential storage encryption
- **HSM / KMS integration** — JWT signing keys in AWS KMS / Azure KV

Each of these has a clear extension point in the existing code.

---

## 13 · File map

```
auth/
├── README.md                       ← this file
├── __init__.py
├── config.py                       ← env-based settings
├── db.py                           ← SQLAlchemy engine + session
├── models.py                       ← all ORM models
├── schemas.py                      ← Pydantic request/response models
├── rbac.py                         ← RBAC + ABAC engine
├── audit.py                        ← audit logger + retention
├── sessions.py                     ← DB-backed session manager
├── scim.py                         ← SCIM 2.0 endpoints
├── routes.py                       ← /auth/* router
├── dependencies.py                 ← FastAPI Depends
├── integration.py                  ← install_auth(app) one-liner
├── bootstrap.py                    ← first-run CLI
├── requirements.txt
├── security/
│   ├── __init__.py
│   ├── passwords.py                ← Argon2id wrapper
│   ├── mfa.py                      ← TOTP + backup codes + WebAuthn stub
│   └── tokens.py                   ← JWT + refresh tokens
└── providers/
    ├── __init__.py
    ├── base.py                     ← abstract IdentityProvider
    ├── local.py                    ← username/password
    ├── oidc.py                     ← OIDC via authlib
    └── saml.py                     ← SAML 2.0 via python3-saml
```
