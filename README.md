# ARGUS

**Advanced Reconnaissance & Guided Unified Security**

An AI-driven autonomous penetration testing platform with enterprise
identity, granular RBAC/ABAC, full SCIM 2.0 + SSO, 18 visual skins
spanning operator + management personas, and a fleet of specialist
agents orchestrated by a local LLM.

> ARGUS turns a single operator into a senior red team. The platform
> plans the engagement, runs the tools, validates the findings, scores
> the risk, and writes the report — under the supervision of role-
> appropriate humans.

```
        ┌──────────────────────────────────────────────────────────────┐
        │   First impression                                           │
        │     Cinematic login page · 18 runtime-switchable skins       │
        │     Apollo · Tactical · Bloomberg · Glass · Editorial · …    │
        ├──────────────────────────────────────────────────────────────┤
        │   Enterprise identity                                        │
        │     Local + OIDC + SAML 2.0 + SCIM 2.0 · TOTP MFA            │
        │     8 hierarchical roles · RBAC + ABAC · DB-backed sessions  │
        │     Append-only audit log · 7-year retention · hash-chain    │
        ├──────────────────────────────────────────────────────────────┤
        │   Pentest core                                               │
        │     MasterAgent + 23 specialist agent folders · MITRE T-IDs  │
        │     RAG-powered reasoning · CVSS scoring · attack graph      │
        │     Manual override · pause/resume · live PTY shells         │
        └──────────────────────────────────────────────────────────────┘
```

---

## 60-second quick start

```bash
# 1. Install everything (one unified requirements file)
pip install -r requirements.txt

# 2. One command does ALL first-time setup
python -m auth.bootstrap quickstart --email admin@yourdomain.com
#   ▸ Generates AUTH_JWT_SECRET + AUTH_PASSWORD_PEPPER + OWNER password
#   ▸ Writes .env.local (chmod 600)
#   ▸ Creates auth DB tables + the OWNER account

# 3. Source the generated env file and start ARGUS
set -a; source .env.local; set +a
uvicorn agent_server:app --host 0.0.0.0 --port 8000

# 4. Browse to http://localhost:8000  →  sign in with the credentials
#    that quickstart printed.  You'll be forced to rotate the password
#    on first login.
```

For everything that follows (production deployment, Docker, SSO,
SCIM, retention, troubleshooting) see [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## What ARGUS is — three pillars

```
┌──────────────────────────────────────────────────────────────────┐
│  PILLAR 1 · Pentest core                       see agents/README │
│  ──────────────────────────────────────────────────────────────  │
│  MasterAgent (LLM-driven) → AgentBus → 23 specialist agents      │
│    recon · osint · vuln · web · exploit · privesc · lateral      │
│    post · evasion · c2 · cloud · container · iot · wireless      │
│    traffic · forensics · evidence · reasoning · campaign · …     │
│  Tooling via MCP server · MITRE ATT&CK techniques on every step  │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│  PILLAR 2 · Enterprise auth                      see auth/README │
│  ──────────────────────────────────────────────────────────────  │
│  Local username + password (Argon2id RFC 9106 + per-user pepper) │
│  TOTP MFA + backup codes + WebAuthn-ready                        │
│  OIDC (PKCE-S256) + SAML 2.0 + SCIM 2.0 (Okta, Azure, Google, …) │
│  8 roles · RBAC + ABAC · DB-backed sessions · rotating refresh   │
│  Tamper-evident audit log · OWNER-only deletion · 7yr retention  │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│  PILLAR 3 · Operator UI                        see static/README │
│  ──────────────────────────────────────────────────────────────  │
│  React via Babel-standalone — no build step                      │
│  18 runtime-switchable skins across 3 families:                  │
│    Aesthetic   (Stellar, Apollo, Tactical, Bloomberg, Glass, …)  │
│    Operator    (Veteran, Novice, GenZ, RedCell, Hunter, CTF)     │
│    Management  (Auditor, Manager, Executive, CFO, Legal)         │
│  Cinematic login · live attack graph · PTY shells · WebSocket    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Documentation map

| Document | Purpose |
|----------|---------|
| **[README.md](README.md)** *(this file)* | Front page · architecture · doc index |
| **[CHANGELOG.md](CHANGELOG.md)** | User-facing changes · behavior changes · migration notes |
| **[DEPLOYMENT.md](DEPLOYMENT.md)** | Quickstart · first-login · env vars · Docker · SSO setup · troubleshooting · compliance |
| **[auth/README.md](auth/README.md)** | Enterprise auth architecture · role matrix · RBAC/ABAC engine · audit log · sessions |
| **[agents/README.md](agents/README.md)** | Agent fleet · dispatch pattern · adding a new specialist |
| **[static/README.md](static/README.md)** | Frontend architecture · React-via-Babel · components · pages |
| **[static/css/skins/README.md](static/css/skins/README.md)** | 18-skin catalogue · how to author a new skin |
| **[knowledge/README.md](knowledge/README.md)** | RAG knowledge base · 4-tier retriever · playbook layer |
| **[knowledge/PLAYBOOK_GUIDE.md](knowledge/PLAYBOOK_GUIDE.md)** | Authoring deterministic playbooks |
| **[knowledge/TROUBLESHOOTING.md](knowledge/TROUBLESHOOTING.md)** | RAG ingestion + retrieval troubleshooting |
| **[db/README.md](db/README.md)** | Data stores · Mongo · Neo4j · cache |
| **[utils/README.md](utils/README.md)** | Small utility helpers · CVSS · LLM provider abstraction |
| **[docs/README.md](docs/README.md)** | Design specs + implementation plans |

---

## Architecture

```
                  ┌──────────────────────────────────────────────────┐
                  │                React Frontend                    │
                  │  Cinematic LoginPage · 18 skins · UserAdminPage  │
                  │  Cockpit: MissionControl · FindingsBoard · …     │
                  │  AttackGraph · ReasoningEngine · LateralPostPage │
                  └────────────────────┬─────────────────────────────┘
                                       │  REST + WebSocket
                                       │  Cookie session + Bearer JWT
                  ┌────────────────────▼─────────────────────────────┐
                  │  agent_server.py  (FastAPI · port 8000)          │
                  │                                                  │
                  │  • install_auth(app)   ← /auth/* + /scim/v2/*    │
                  │  • Session WebSocket   ← live events             │
                  │  • Shell PTY proxy     ← interactive ops         │
                  │  • Tool MCP gateway    ← nmap, sqlmap, etc.      │
                  └─┬───────────────┬──────────────┬─────────────────┘
                    │               │              │
        ┌───────────▼──┐    ┌───────▼──────┐  ┌────▼─────────────┐
        │ MasterAgent  │    │ AuthModule   │  │ KnowledgeBase    │
        │  (LLM-led)   │    │ (RBAC+ABAC)  │  │ (RAG · 4-tier)   │
        └──────┬───────┘    └──────────────┘  └──────────────────┘
               │
               │  AgentBus (typed Instructions, pub/sub)
               ▼
        ┌──────────────────────────────────────────────────────┐
        │  23 specialist agent folders                         │
        │  recon · osint · vuln · web · exploit · privesc      │
        │  lateral · post · evasion · c2 · cloud · container   │
        │  iot · wireless · traffic · forensics · reasoning …  │
        └──────────────────────────────────────────────────────┘
               │
               ▼
        ┌──────────────────────────────────────────────────────┐
        │  Data layer (see db/README.md)                       │
        │   MongoDB    — engagement state + findings           │
        │   Neo4j      — semantic attack graph (optional)      │
        │   SQLite/PG  — auth tables (users, sessions, audit)  │
        │   ChromaDB   — RAG embeddings + corpus               │
        │   filesystem — session loot, reports, audit exports  │
        └──────────────────────────────────────────────────────┘
```

---

## Capability surfaces (compact)

| Surface | Highlights |
|---------|-----------|
| **Agents** | Reconnaissance · OSINT · vulnerability scan · web (WSTG) · exploit · privilege escalation · lateral movement · post-exploitation · evasion (AV bypass) · C2 (Sliver) · cloud (AWS/Azure/GCP) · container/K8s · IoT · wireless · network traffic · digital forensics · evidence chain · campaign mgmt · reasoning loop · meta-agents · training |
| **Reasoning** | Hypothesis-driven tree · LLM-led plan-execute-validate loop · MITRE ATT&CK technique annotation on every action · per-finding evidence chain · explainable next-step suggestions |
| **Authentication** | Local (Argon2id RFC 9106 + per-deployment pepper) · OIDC w/ PKCE-S256 · SAML 2.0 (XSW-resistant via python3-saml) · SCIM 2.0 RFC 7644 (Okta + Azure + Google + OneLogin + JumpCloud + Auth0) |
| **MFA** | TOTP (RFC 6238, ±1 step skew, Fernet-encrypted secrets) · 10 single-use backup codes (argon2-hashed) · WebAuthn interface ready |
| **RBAC + ABAC** | 8 hierarchical roles: OWNER · PLATFORM_ADMIN · SECURITY_MANAGER · OPERATOR · ANALYST · EXECUTIVE · AUDITOR · CLIENT · ABAC predicates for engagement scoping + severity filters + client-redaction |
| **Sessions** | DB-backed (SQLite/PG) · rotating refresh tokens · OAuth 2.1 §6.1 theft detection · idle + absolute TTL · per-user UI state survives reload + reboot + device switch |
| **Audit log** | Append-only by design · OWNER-only deletion w/ reason · admin-configurable retention · optional SHA-256 hash chain · JSONL export before purge |
| **Visual skins** | 18 runtime-switchable skins across 3 families · live preview · per-user persistence · WebGL skin lazy-loads Three.js scene · all use free fonts (Google Fonts + Press Start 2P + IBM Plex) |
| **Audience modes** | OPERATOR / BRIEFING / PRESENT / CLIENT — F1–F4 hotkeys · hub visibility per mode · severity-redaction for CLIENT |
| **Knowledge base** | 4-tier RAG retriever · ~1.1 GB embedder + reranker · YAML-authored deterministic playbooks · auto-ingestion of scan outputs |
| **Pentest tooling** | Via MCP tool gateway — nmap, masscan, rustscan, nuclei, sqlmap, gobuster, ffuf, hydra, crackmapexec, impacket, metasploit, bloodhound, mimikatz, sliver, evil-winrm, … (full list in `mcp-server.js`) |

---

## Tech stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11+ · FastAPI 0.111 · Uvicorn · SQLAlchemy 2.0 · asyncio |
| Frontend | React 18 via Babel-standalone · pure ES2019 · no build step |
| Data — operational | MongoDB (engagement state) · Neo4j (attack graph, optional) |
| Data — auth | SQLite (dev) · PostgreSQL (prod) · same SQLAlchemy code |
| Data — RAG | ChromaDB · sentence-transformers (bge-small) |
| Crypto | argon2-cffi · cryptography · PyJWT[crypto] · pyotp |
| SSO | authlib (OIDC) · python3-saml (SAML 2.0) |
| LLM | Ollama (local) · pluggable via `utils/llm_providers.py` |
| Tooling gateway | Node MCP server (`mcp-server.js`) bridging pentest tools |

---

## Pentest methodology

8-phase lifecycle, each phase driven by the MasterAgent in conversation
with the LLM and the knowledge base:

1. **Reconnaissance** — scope discovery, host enumeration, OSINT
2. **Scanning** — port + service + version detection (nmap, masscan, rustscan)
3. **Enumeration** — deep service interrogation per protocol
4. **Vulnerability assessment** — nuclei + version-CVE correlation + CVSS scoring
5. **Exploitation** — chained payloads, attack-graph traversal, evasion ladders
6. **Post-exploitation** — credential harvest, privilege escalation, persistence
7. **Lateral movement** — pivoting, AD enumeration, kerberoasting, NTLM relay
8. **Reporting** — exec summary · technical detail · evidence chain · MITRE mapping

Each phase emits findings into the operational DB with full provenance
(tool · raw output · CVSS · MITRE technique · timestamp · operator).
The reasoning agent stitches them into a hypothesis tree visible in the
cockpit.

---

## Installation

### Quickest path (development)

```bash
pip install -r requirements.txt
python -m auth.bootstrap quickstart --email admin@yourdomain.com
set -a; source .env.local; set +a
uvicorn agent_server:app --host 0.0.0.0 --port 8000
```

### Production

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for:

- Environment-variable reference (40+ tunables)
- Docker + Compose templates
- Reverse-proxy (nginx) recipe
- PostgreSQL for multi-process deployment
- SSO setup (Okta, Azure AD, Google Workspace)
- SCIM provisioning
- Production checklist
- Backup OWNER pattern
- Compliance mapping (SOC 2, ISO 27001, NIST 800-53/63B, PCI DSS, HIPAA, GDPR, SOX)
- Troubleshooting (locked accounts, lost MFA, refresh-token theft, SQLite locking)

### Prerequisites

| Component | Version | Required for |
|-----------|---------|--------------|
| Python | 3.11+ | Backend + auth + RAG |
| Node.js | 18+ | MCP tool gateway (`mcp-server.js`) |
| MongoDB | 6.x | Operational engagement state |
| Ollama | latest | Local LLM provider (or set `OLLAMA_HOST` to a remote) |
| Neo4j | 5.x | *Optional* — semantic attack graph |
| libxml2 + libxmlsec1 | system pkg | *Optional* — SAML 2.0 SSO (Debian/Ubuntu only) |

---

## Configuration

ARGUS is 12-factor — every tunable is exposed as an environment
variable. See:

- **[`auth/config.py`](auth/config.py)** — auth-module knobs (40+)
- **[`DEPLOYMENT.md §3`](DEPLOYMENT.md#3--environment-variable-reference)** — full reference
- **MCP server config** — `mcp-server.js`
- **Knowledge base config** — `knowledge/README.md`

The `quickstart` command generates the security-critical secrets
automatically and writes them to `.env.local`; you only need to
hand-tune for production (cookie domain, retention windows, IdP config,
PostgreSQL URL).

---

## Security posture

| Concern | Mitigation |
|---------|------------|
| Password storage | Argon2id m=64MiB t=3 p=4 (RFC 9106 §4) + per-deployment HMAC pepper |
| Brute force | Per-account 5-fail / 15-min sliding-window lockout + global rate limit |
| Session theft | httpOnly + Secure + SameSite=Lax cookies · CSRF double-submit · IP+UA fingerprint |
| Refresh-token theft | Rotating tokens; reuse triggers OAuth 2.1 §6.1 family revocation |
| MFA bypass | Step-up re-auth required for sensitive ops (role grant, audit delete, SCIM-token issue) |
| Privilege escalation | OWNER-only for OWNER + PLATFORM_ADMIN grants · hierarchical grant rules |
| Audit-log tampering | Append-only by design · optional SHA-256 hash chain · JSONL export before purge |
| OIDC code injection | PKCE-S256 enforced |
| SAML XSW | python3-saml ≥ 1.16 mitigates known XML-signature wrapping |
| SCIM token leak | Hashed at rest · rotation API · audit on every use |
| Timing oracles | Constant-time argon2 verify + dummy-hash for unknown users |

Full audit-evidence-chain options + tamper proofs are documented in
**[`auth/audit.py`](auth/audit.py)** and **[`DEPLOYMENT.md §11`](DEPLOYMENT.md#11--compliance-notes)**.

---

## API surface

All endpoints return JSON unless noted.

| Group | Endpoint | Notes |
|-------|----------|-------|
| Health | `GET /healthz/auth` | Auth-DB reachability |
| Auth | `POST /auth/login` | Local credentials → access + refresh + csrf |
| Auth | `POST /auth/mfa/verify` | TOTP / backup-code second factor |
| Auth | `POST /auth/refresh` | Rotating refresh-token exchange |
| Auth | `POST /auth/logout` | Revoke session |
| SSO | `GET /auth/sso/oidc/{idp}/start` | OIDC authz with PKCE |
| SSO | `GET /auth/sso/oidc/{idp}/callback` | OIDC code exchange |
| SSO | `POST /auth/sso/saml/{idp}/acs` | SAML 2.0 assertion consumer |
| SSO | `GET /auth/sso/saml/{idp}/metadata` | SP metadata XML |
| Me | `GET /auth/me` | Current user + persisted UI state |
| Me | `PATCH /auth/me/state` | Update UI state (skin, audience mode, …) |
| Me | `POST /auth/me/change-password` | Rotate own password |
| Sessions | `GET /auth/sessions` | List own active sessions |
| Sessions | `DELETE /auth/sessions/{id}` | Revoke own session |
| Admin | `GET /auth/admin/users` | RBAC: `users:read` |
| Admin | `POST /auth/admin/users` | RBAC: `users:create` |
| Admin | `POST /auth/admin/users/{id}/role` | Hierarchical grant rules apply |
| Admin | `GET /auth/admin/audit` | Audit log (scoped per RBAC) |
| Admin | `POST /auth/admin/audit/delete` | OWNER-only |
| Admin | `POST /auth/admin/scim-tokens` | Issue SCIM bearer |
| SCIM | `GET /scim/v2/Users` | RFC 7644 with filter parser |
| SCIM | `POST /scim/v2/Users` | Just-in-time provisioning |
| SCIM | `PATCH /scim/v2/Users/{id}` | Activate / deactivate / rename |
| SCIM | `GET /scim/v2/Groups` | ARGUS roles surface as SCIM groups |
| Engagement | `POST /api/scan/start` | Begin a new pentest engagement |
| Engagement | `GET /api/sessions/{id}` | Engagement state |
| Engagement | `WS /api/ws/{session_id}` | Live event stream |

Full OpenAPI surface auto-generated by FastAPI at `/docs` once
ARGUS is running.

---

## CLI

```bash
# ── Bootstrap & secrets (auth module) ──
python -m auth.bootstrap quickstart            # full first-time setup
python -m auth.bootstrap reset-owner-password --generate  # break-glass recovery
python -m auth.bootstrap gen-password          # one strong password
python -m auth.bootstrap rotate-jwt-key        # new JWT secret
python -m auth.bootstrap migrate               # create auth tables
python -m auth.bootstrap create-owner          # interactive
python -m auth.bootstrap issue-scim-token --description "Okta"
python -m auth.bootstrap enforce-retention     # audit-log sweep

# ── Knowledge base ──
python knowledge/build_kb.py                   # build / rebuild RAG index
python knowledge/dedupe_kb.py                  # dedupe corpus
python knowledge/auto_ingest_scans.py          # ingest fresh scan output

# ── Engagement-time ──
uvicorn agent_server:app --host 0.0.0.0 --port 8000
node mcp-server.js                             # start tool gateway (separate process)
```

---

## Project layout

```
ARGUS/
├── README.md                  ← you are here
├── DEPLOYMENT.md              ← production deployment guide
├── requirements.txt           ← unified Python deps
│
├── agent_server.py            ← FastAPI app entry + install_auth()
├── schemas.py                 ← root engagement schemas
├── mcp-server.js              ← Node tool gateway
│
├── agents/                    ← MasterAgent + 23 specialist folders
│   ├── README.md
│   ├── master_agent.py
│   ├── base_agent.py
│   ├── base_subagent.py
│   ├── recon/  osint/  vuln/  web/  exploit/  privesc/  lateral/
│   ├── post/   evasion/  c2/   cloud/  container/  iot/  wireless/
│   ├── traffic/  forensics/  evidence/  reasoning/  campaign/
│   ├── mission/  meta/   playbook/  training/
│   └── …
│
├── auth/                      ← Enterprise auth (additive module)
│   ├── README.md              ← architecture + role matrix + flows
│   ├── config.py · db.py · models.py · schemas.py
│   ├── rbac.py · sessions.py · audit.py · scim.py
│   ├── dependencies.py · routes.py · bootstrap.py · integration.py
│   ├── security/  ← passwords (Argon2id) · MFA (TOTP/WebAuthn) · tokens
│   └── providers/ ← local · OIDC · SAML
│
├── static/                    ← Frontend assets (no build step)
│   ├── README.md
│   ├── api.js · app.jsx · store.js
│   ├── components/            ← StatusBadge, LiveTerminal, FindingCard, …
│   ├── pages/                 ← MissionControl, FindingsBoard, LoginPage, …
│   ├── css/
│   │   ├── main.css           ← base + token system
│   │   └── skins/             ← 18 skins
│   │       ├── README.md
│   │       ├── apollo.css · tactical.css · bloomberg.css · …
│   │       └── …
│   ├── js/skins/webgl_scene.js
│   └── vendor/                ← React, antd, dayjs, d3, xterm, babel
│
├── templates/index.html       ← cockpit HTML shell
│
├── knowledge/                 ← RAG knowledge base
│   ├── README.md · PLAYBOOK_GUIDE.md · TROUBLESHOOTING.md
│   ├── build_kb.py · knowledge_base.py · dedupe_kb.py · …
│   └── data/                  ← 300+ corpus files (PDFs, MDs, playbooks)
│
├── db/                        ← Data-store adapters
│   ├── README.md
│   ├── mongo_client.py · neo4j_client.py · cache.py · schemas.py
│   └── __init__.py
│
├── utils/                     ← Cross-cutting helpers
│   ├── README.md
│   ├── llm_providers.py · cvss_scorer.py · opsec_profiles.py · …
│   └── __init__.py
│
└── docs/                      ← Design specs + plans
    ├── README.md
    ├── superpowers/specs/     ← design docs
    ├── superpowers/plans/     ← implementation plans
    └── project-state/         ← progress logs
```

---

## Roles, in one screen

8 hierarchical roles. The auth module enforces every action via RBAC +
ABAC. See [`auth/README.md §2`](auth/README.md#2--role-hierarchy) for
the full permission matrix.

| Code | Display | Bypass RBAC | Scope | Default skin |
|------|---------|-------------|-------|--------------|
| `OWNER` | Platform Owner | ✅ god-mode | global | stellar |
| `PLATFORM_ADMIN` | Platform Administrator | no | global · IT mgmt + SSO + SCIM + retention | veteran |
| `SECURITY_MANAGER` | Security Manager | no | tenant · engagements + assignment | manager |
| `OPERATOR` | Operator | no | engagement · full red-team capability | redcell |
| `ANALYST` | Analyst | no | engagement · validation + non-destructive tools | novice |
| `EXECUTIVE` | Executive | no | tenant · dashboards + decisions, no exec | executive |
| `AUDITOR` | Auditor | no | global · read-only with evidence chain | auditor |
| `CLIENT` | Client | no | scoped engagement · severity-redacted | editorial |

---

## Visual skins

ARGUS ships **18 runtime-switchable skins**. Operators / managers /
auditors pick whichever fits the moment. See
[`static/css/skins/README.md`](static/css/skins/README.md) for the
full catalogue and a guide to authoring new skins.

```
Aesthetic   (7) ── Stellar · Apollo · Tactical · Bloomberg · Glass · Editorial · Spatial 3D
Operator    (6) ── Veteran · Novice · GenZ · RedCell · Hunter · CTF
Management  (5) ── Auditor · Manager · Executive · CFO · Legal
```

The chooser sits in the header. The choice persists per-user in the
auth DB (`session_state`) and follows the operator across devices.
The WebGL skin lazy-loads its Three.js scene only when selected.

---

## License & disclaimer

ARGUS is intended for **authorized penetration testing only**. Use only
against systems you own or have explicit written permission to test.
Unauthorized use against third-party systems is illegal in most
jurisdictions.

The maintainers are not responsible for misuse. Default deployments
include an authorization-and-scope acknowledgement step before any
engagement starts.

---

## Contributing

Read the relevant per-folder README first:

- New agent type → [`agents/README.md`](agents/README.md)
- New skin → [`static/css/skins/README.md`](static/css/skins/README.md)
- Frontend page or component → [`static/README.md`](static/README.md)
- Auth feature (MFA factor, IdP, SCIM ext.) → [`auth/README.md`](auth/README.md)
- Knowledge-base corpus addition → [`knowledge/README.md`](knowledge/README.md)
- Design specs / implementation plans → [`docs/README.md`](docs/README.md)

Then keep this README's "Documentation map" in sync with anything new.

---

*"You don't grep your way to a finding. You think your way there.
ARGUS is what that thinking looks like, at machine speed, supervised
by the right humans."*
