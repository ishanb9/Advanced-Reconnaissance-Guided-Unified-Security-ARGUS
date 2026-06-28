# ARGUS

**Advanced Reconnaissance & Guided Unified Security**

An AI-driven autonomous penetration-testing platform. A tiered-LLM **operator** drives
the whole engagement — recon → exploit → post-exploit → report — backed by a
committed-exploitation loop that *develops and proves* custom exploits, a
fuzzing-to-exploit workshop, smart adaptive brute-forcing, an operational severity
model that grades by demonstrated impact, and AI/LLM red-teaming. All of it is wrapped
in enterprise identity (granular RBAC/ABAC, full SCIM 2.0 + SSO), 18 visual skins, and a
fleet of 28 specialist agent folders.

> ARGUS turns a single operator into a senior red team. The operator LLM plans the
> engagement, runs the tools, *develops and proves* exploits, validates the findings,
> grades them by what was actually demonstrated, and writes the report — under the
> supervision of role-appropriate humans.

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
        │     LLM operator + MasterAgent + 28 specialist folders       │
        │     Committed exploitation · fuzz→exploit · smart brute      │
        │     Operational severity · AI red-team · live PTY shells     │
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
│  PILLAR 1 · Autonomous engagement engine       see agents/README │
│  ──────────────────────────────────────────────────────────────  │
│  Tiered-LLM OPERATOR drives run_tool directly · MasterAgent runs │
│  the phase machine · 28 specialist agent folders:                │
│    recon · osint · vuln · web · exploit · privesc · lateral      │
│    post · evasion · c2 · cloud · container · iot · ot · wireless  │
│    fuzzing · ai_red_team · reasoning · campaign · operator_agent  │
│  Committed-exploit loop · fuzz→develop→PROVE · MITRE every step  │
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

## The autonomous engagement engine

ARGUS is **operator-driven**: a tiered-LLM operator (primary → secondary fallback on
every call) reasons over live intel and calls tools directly, while the MasterAgent runs
the phase machine (RECON → ENUM → VULN_ID → WEB → EXPLOIT → POST → PRIVESC → REPORT) and
the RAG knowledge base feeds it grounded technique guidance. Beyond "run the scanners,"
the engine adds:

| Capability | What it does |
|------------|--------------|
| **Committed exploitation loop** | On a high-confidence candidate (fingerprinted app + matched public CVE/PoC, or a verified injection) ARGUS *locks on* and runs a bounded **develop → run → verify → refine** loop — adapting parameters until a deterministic oracle (`uid=` / canary / OOB callback) proves execution — instead of thrashing across CVEs. `agents/operator_agent/committed_exploit.py` |
| **Fuzzing → custom-exploit workshop** | A parallel **SELECT → GENERATE → FUZZ → TRIAGE → DEVELOP → GATE → PROVE → RECORD** campaign across six engines — **web · api · network · file-format · binary (AFL++/honggfuzz) · AI/LLM** — turning anomalies into LLM-synthesised PoCs proven by deterministic oracles. Driven from the **Fuzzing Lab** (live status, chance-of-success meter, stop button) or auto, ceiling-gated. `agents/fuzzing/` |
| **Operational severity model** | Findings graded by **what was demonstrated**, not raw CVSS: CRITICAL only for proven compromise (or a validated critical CVE), unproven RCE capped pending proof, service-discovery → INFO, tool-noise dropped — one canonical verdict, identical across every report theme. `knowledge/severity_policy.py` |
| **Smart adaptive brute-forcing** | Brute / heavy-enum tools run in the **background** (never block the scan) and **escalate** — fast curated lists → larger lists → rainbow tables / offline hash-cracking with rules, plus technique changes (password-spray, AS-REP roast, Kerberoast) — feeding creds back when ready. `knowledge/brute_strategy.py` |
| **AI / LLM red-teaming** | Treats an LLM endpoint as a target: prompt-injection, jailbreak, system-prompt leak and the rest of the OWASP LLM Top 10. `agents/ai_red_team/` |
| **Universal tech coverage + self-learning** | A knowledge-driven **skill registry** matches the target's tech (IT / OT / IoT) to deterministic playbooks; a learning loop distils lessons into per-skill weights over time. `knowledge/skill_registry.py` |
| **Execution-boundary safety governor** | Every `run_tool` / MCP call is gated on **scope · RBAC · intrusiveness ceiling · argument validation** — fail-closed, OT-safe by default. `knowledge/safety_governor.py` |
| **Technique search** | Grounds the operator in an offensive corpus (HackTricks / PayloadsAllTheThings) at decision time. `knowledge/technique_search.py` |
| **Independent verification** | Headless-browser (Playwright) verification of web findings, an independent **reproduction loop** with captured PoC artifacts, and a `reproduce_status` gate so the report only claims what re-runs. |
| **Engagement integrity** | Per-finding provenance stamping, scrub-on-seed and cross-session boundary filters so a prior engagement's data can never bleed into this one's report. |
| **Capability benchmark** | `evals/` scores ARGUS against deterministic targets so capability regressions are caught per change. |

Every engagement renders through **five professional report themes** (executive ·
compliance · editorial · operator-dark · threat-intel) from one normalized finding set —
severity-sorted, stable IDs, single headline rating — with WeasyPrint PDF export.

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
| **[evals/README.md](evals/README.md)** | Capability benchmark · scored targets · regression baseline |
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
        │  LLM operator (operator_agent) + 28 specialist folders│
        │  recon · osint · vuln · web · exploit · privesc       │
        │  lateral · post · evasion · c2 · cloud · container    │
        │  iot · ot · wireless · traffic · forensics · reasoning│
        │  fuzzing · ai_red_team · campaign · mission · meta …  │
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
| **Agents (28 folders)** | Reconnaissance · OSINT · vulnerability scan · web (WSTG) · exploit · privilege escalation · lateral movement · post-exploitation · evasion (AV bypass) · C2 (Sliver) · cloud (AWS/Azure/GCP) · container/K8s · IoT · **OT/ICS** (Modbus/BACnet/OPC-UA/S7/Crestron) · wireless · network traffic · digital forensics · evidence chain · campaign · mission · **fuzzing** · **ai_red_team** · **operator_agent** · reasoning · meta · playbook · training |
| **Engine** | Tiered-LLM **operator** drives `run_tool` directly · MasterAgent phase machine · committed-exploitation loop · parallel fuzz→exploit campaigns · background smart brute-forcing · per-target LLM-token budget with human extend/cutoff |
| **Reasoning** | Hypothesis-driven tree · LLM-led plan-execute-validate loop · MITRE ATT&CK technique annotation on every action · per-finding evidence chain · technique-search grounding · explainable next-step suggestions |
| **Exploit development** | Verify-or-refine PoC loop · deterministic proof oracles (`uid=` / canary / OOB callback) · public-PoC reflex (version→CVE→GitHub PoC) · governor-gated, fail-closed PoC execution |
| **Fuzzing workshop** | OWASP application/protocol/file-format fuzzing · six engines (web/api/network/file/binary/AI) · AFL++ · radamsa · zzuf · honggfuzz · boofuzz · schemathesis · LLM-synthesised PoCs · ceiling-gated weaponisation |
| **Severity & reporting** | Operational severity (graded by demonstrated impact) · single canonical verdict · noise filtering · five themed reports (executive/compliance/editorial/operator-dark/threat-intel) · WeasyPrint PDF · engagement-integrity / cross-session isolation |
| **AI red-team** | OWASP LLM Top 10 against an LLM endpoint: prompt injection · jailbreak · system-prompt leak · insecure output · excessive agency |
| **Safety** | Execution-boundary governor (scope · RBAC · intrusiveness ceiling · arg validation) · OT-safe-by-default · authorization-and-scope acknowledgement before any engagement |
| **Authentication** | Local (Argon2id RFC 9106 + per-deployment pepper) · OIDC w/ PKCE-S256 · SAML 2.0 (XSW-resistant via python3-saml) · SCIM 2.0 RFC 7644 (Okta + Azure + Google + OneLogin + JumpCloud + Auth0) |
| **MFA** | TOTP (RFC 6238, ±1 step skew, Fernet-encrypted secrets) · 10 single-use backup codes (argon2-hashed) · WebAuthn interface ready |
| **RBAC + ABAC** | 8 hierarchical roles: OWNER · PLATFORM_ADMIN · SECURITY_MANAGER · OPERATOR · ANALYST · EXECUTIVE · AUDITOR · CLIENT · ABAC predicates for engagement scoping + severity filters + client-redaction |
| **Sessions** | DB-backed (SQLite/PG) · rotating refresh tokens · OAuth 2.1 §6.1 theft detection · idle + absolute TTL · per-user UI state survives reload + reboot + device switch |
| **Audit log** | Append-only by design · OWNER-only deletion w/ reason · admin-configurable retention · optional SHA-256 hash chain · JSONL export before purge |
| **Visual skins** | 18 runtime-switchable skins across 3 families · live preview · per-user persistence · WebGL skin lazy-loads Three.js scene · all use free fonts (Google Fonts + Press Start 2P + IBM Plex) |
| **Audience modes** | OPERATOR / BRIEFING / PRESENT / CLIENT — F1–F4 hotkeys · hub visibility per mode · severity-redaction for CLIENT |
| **Knowledge base** | 4-tier RAG retriever · ~1.1 GB embedder + reranker · YAML playbooks · skill registry (IT/OT/IoT) · severity policy · brute strategy · safety governor · technique search · self-learning lesson loop · auto-ingestion of scan outputs · RAG observability |
| **Pentest tooling** | Via MCP tool gateway — nmap, masscan, rustscan, nuclei, sqlmap, gobuster, ffuf, hydra, kerbrute, crackmapexec/netexec, impacket, metasploit, bloodhound, mimikatz, sliver, evil-winrm, hashcat, **AFL++, radamsa, zzuf, honggfuzz, boofuzz, schemathesis**, … (full list in `mcp-server.js` / `requirements-kali.txt`) |

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
| LLM | Tiered operator (primary → secondary fallback) · Ollama (local) · pluggable via `utils/llm_providers.py` |
| Tooling gateway | Node MCP server (`mcp-server.js`) bridging pentest tools |
| Reporting | Jinja2 themes (×5) · WeasyPrint (PDF) |
| Verification | Playwright (headless-browser finding verification) · deterministic proof oracles |
| Fuzzing | AFL++ · honggfuzz · radamsa · zzuf · boofuzz · schemathesis |

---

## Pentest methodology

8-phase lifecycle. The **LLM operator** drives each phase — reasoning over live intel,
calling tools directly, and committing to exploits — while the MasterAgent advances the
phase machine and the knowledge base grounds every decision:

1. **Reconnaissance** — scope discovery, host enumeration, OSINT
2. **Scanning** — port + service + version detection (nmap, masscan, rustscan)
3. **Enumeration** — deep service interrogation per protocol (background, smart brute-forcing)
4. **Vulnerability assessment** — nuclei + version→CVE→public-PoC reflex + CVSS scoring
5. **Exploitation** — committed develop→run→**PROVE** loop · attack-graph traversal · evasion · parallel fuzz→exploit campaigns
6. **Post-exploitation** — credential harvest, privilege escalation, persistence
7. **Lateral movement** — pivoting, AD enumeration, AS-REP roast / Kerberoast, NTLM relay
8. **Reporting** — operational severity · five themed reports · evidence chain · MITRE mapping

Each phase emits findings into the operational DB with full provenance
(tool · raw output · CVSS · operational severity · MITRE technique · timestamp ·
`reproduce_status`). Findings are graded by **what was demonstrated**, deterministic
oracles confirm exploitation, and an engagement-integrity layer keeps each session's
data isolated. The reasoning agent stitches everything into a hypothesis tree visible
in the cockpit.

---

## Installation

### Quickest path (development)

```bash
pip install -r requirements.txt                 # Python deps
sudo bash install-kali-tools.sh                 # Kali attack tools (see requirements-kali.txt)
python -m auth.bootstrap quickstart --email admin@yourdomain.com
set -a; source .env.local; set +a
uvicorn agent_server:app --host 0.0.0.0 --port 8000
```

> **Kali tooling.** ARGUS shells out to ~356 external binaries (the MCP registry in
> `mcp-server.js`). `requirements-kali.txt` is the canonical inventory; run
> `sudo bash install-kali-tools.sh` to install them (apt + go + pipx + git + downloads),
> or `bash install-kali-tools.sh --verify` to list exactly which tools are still missing.
> On a stock Kali box, `sudo apt install -y kali-linux-everything seclists` covers most of it.

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
| Fuzzing | `POST /fuzz/campaign/start` | Launch a fuzz→develop→prove campaign (standalone or alongside a scan) |
| Fuzzing | `POST /fuzz/campaign/stop` | Operator stop for a running campaign |
| Fuzzing | `GET /fuzz/campaigns` | Live campaign status · stage · chance-of-success |
| Fuzzing | `GET /fuzz/engines` | Fuzz modalities + installed-tool availability |
| Report | `GET /report/{session_id}?theme=` | Themed report (executive/compliance/editorial/operator-dark/threat-intel) · HTML or PDF |

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

# ── Tests & capability benchmark ──
python -X utf8 agents/test_architecture_integration.py   # architecture harness → RESULT: PASS
#   evals/  — capability benchmark library (run_benchmark / compare_to_baseline); see evals/README.md
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
├── agents/                    ← LLM operator + MasterAgent + 28 specialist folders
│   ├── README.md
│   ├── master_agent.py · base_agent.py · base_subagent.py
│   ├── operator_agent/        ← LLM operator core + committed_exploit + tool catalog
│   ├── fuzzing/               ← fuzz→develop→PROVE workshop (campaign + 6 engines)
│   ├── ai_red_team/           ← OWASP LLM Top 10 against an LLM endpoint
│   ├── recon/  osint/  vuln/  web/  exploit/  privesc/  lateral/
│   ├── post/   evasion/  c2/   cloud/  container/  iot/  ot/  wireless/
│   ├── traffic/  forensics/  evidence/  reasoning/  campaign/  avot/
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
├── knowledge/                 ← RAG knowledge base + decision "brains"
│   ├── README.md · PLAYBOOK_GUIDE.md · TROUBLESHOOTING.md
│   ├── build_kb.py · knowledge_base.py · dedupe_kb.py · …
│   ├── severity_policy.py · brute_strategy.py · safety_governor.py
│   ├── technique_search.py · skill_registry.py · skill_telemetry.py · fuzz_targeting.py
│   ├── skills/                ← IT / OT / IoT skill files (deterministic playbooks)
│   └── data/                  ← 300+ corpus files (PDFs, MDs, playbooks)
│
├── report/                    ← Themed report generator (5 themes + WeasyPrint PDF)
│   ├── generator.py
│   └── themes/                ← executive · compliance · editorial · operator_dark · threat_intel
│
├── evals/                     ← Capability benchmark (deterministic scored targets)
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
