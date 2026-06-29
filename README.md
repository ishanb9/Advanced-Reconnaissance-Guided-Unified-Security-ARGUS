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
│  PILLAR 1 · Autonomous engagement engine                        │
│  ──────────────────────────────────────────────────────────────  │
│  Tiered-LLM OPERATOR drives run_tool directly · MasterAgent runs │
│  the phase machine · 28 specialist agent folders:                │
│    recon · osint · vuln · web · exploit · privesc · lateral      │
│    post · evasion · c2 · cloud · container · iot · ot · wireless  │
│    fuzzing · ai_red_team · reasoning · campaign · operator_agent  │
│  Committed-exploit loop · fuzz→develop→PROVE · MITRE every step  │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│  PILLAR 2 · Enterprise auth                                     │
│  ──────────────────────────────────────────────────────────────  │
│  Local username + password (Argon2id RFC 9106 + per-user pepper) │
│  TOTP MFA + backup codes + WebAuthn-ready                        │
│  OIDC (PKCE-S256) + SAML 2.0 + SCIM 2.0 (Okta, Azure, Google, …) │
│  8 roles · RBAC + ABAC · DB-backed sessions · rotating refresh   │
│  Tamper-evident audit log · OWNER-only deletion · 7yr retention  │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│  PILLAR 3 · Operator UI                                         │
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
| **Goal-conditioned, value-driven planning** | Each engagement carries a **mission brief** with explicit `win_conditions`; the reasoning loop scores candidate actions by **value-of-information** (decisions are stamped `[VoI=…]`) and maintains a **goal timeline** (emits `goal_timeline_updated` — "win condition met at step N"), so the operator thinks *toward the objective* instead of running tools blindly. `db/schemas.py::MissionBrief` · `agents/reasoning/decision_engine.py` · `agents/reasoning/goal_timeline.py` |

Every engagement renders through **five professional report themes** (executive ·
compliance · editorial · operator-dark · threat-intel) from one normalized finding set —
severity-sorted, stable IDs, single headline rating — with WeasyPrint PDF export.

---

## Contents

Everything is in this one README, plus two companion files —
**[CHANGELOG.md](CHANGELOG.md)** (user-facing changes + migration notes) and
**[DEPLOYMENT.md](DEPLOYMENT.md)** (production · Docker · SSO · troubleshooting · compliance).

**Overview** ·
[Autonomous engine](#the-autonomous-engagement-engine) ·
[Architecture](#architecture) ·
[Capability surfaces](#capability-surfaces-compact) ·
[Tech stack](#tech-stack) ·
[Methodology](#pentest-methodology) ·
[Installation](#installation) ·
[Configuration](#configuration) ·
[Security posture](#security-posture) ·
[API surface](#api-surface) ·
[CLI](#cli) ·
[Project layout](#project-layout) ·
[Roles](#roles-in-one-screen) ·
[Sovereign LLM stack](#sovereign-llm-stack) ·
[Production-safety model](#production-safety-model)

**Component reference** (folded in from the former per-folder READMEs) ·
[Enterprise authentication](#enterprise-authentication) ·
[Agents & the autonomous engine](#agents--the-autonomous-engine) ·
[Frontend & visual skins](#frontend--visual-skins) ·
[Knowledge base & RAG](#knowledge-base--rag) ·
[Authoring playbooks & skills](#authoring-playbooks--skills) ·
[RAG troubleshooting](#rag-troubleshooting) ·
[Data layer](#data-layer) ·
[Utilities](#utilities) ·
[Capability benchmark](#capability-benchmark) ·
[Design docs](#design-docs)

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
        │  Data layer                                          │
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
| **Agents (28 folders)** | Reconnaissance · OSINT · vulnerability scan · web (WSTG) · exploit · privilege escalation · lateral movement · post-exploitation · evasion (AV bypass) · C2 (Sliver) · cloud (AWS/Azure/GCP) · container/K8s · IoT · **OT/ICS** (Modbus/BACnet/OPC-UA/S7) · **AV/OT control systems** · wireless · network traffic · digital forensics · evidence chain · campaign · mission · **fuzzing** · **ai_red_team** · **operator_agent** · reasoning · meta · playbook · training |
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

## Sovereign LLM stack

**Frontier when you can, fully local when you must — with automatic failover.** ARGUS
is *not* tied to one model or a phone-home API. One provider abstraction
(`utils/llm_providers.py`) drives every LLM call through five interchangeable backends:

| Backend | Use |
|---------|-----|
| **Anthropic** (Claude) · **Gemini** · **OpenAI-compatible** (vLLM · Groq · OpenRouter · LM Studio · llama.cpp · TGI) | Frontier capability where connectivity + policy allow |
| **Claude Code subscription** (`claude_code`) | Frontier Claude via a Pro/Max OAuth session — no API key |
| **Ollama** (local) | 100% offline / air-gapped — nothing leaves the box |

Selection is one env var (`LLM_PROVIDER`, default `auto`). A **tiered chain**
(`provider_chain` → `stream_tiered`) runs a primary model and **fails over** to a backup —
including an implicit local-Ollama fallback — on outage, auth failure, a zero-token
completion, or a **frontier policy refusal** (`looks_like_refusal` re-routes the same prompt
to the local model). Every call is primary→secondary by construction.

This dual-mode design is the **sovereignty differentiator** a frontier-only competitor
structurally cannot match: run frontier Claude where it's allowed, degrade gracefully to a
local model on a refusal or outage, and run **completely offline** in an air-gapped /
regulated / OT enclave.

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

> **Kali tooling.** ARGUS shells out to ~380 external binaries (the MCP registry in
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
- **Knowledge base config** — see [Knowledge base & RAG](#knowledge-base--rag)

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

## Production-safety model

Autonomy that can reach a live target needs guardrails that are **part of the engine, not
optional**. ARGUS gates every action and bounds every loop:

| Control | Mechanism |
|---------|-----------|
| **Execution-boundary governor** | `knowledge/safety_governor.py::evaluate` runs at the `run_tool`/MCP boundary *and* again in `agents/fuzzing/poc_runner.py` — checks scope · RBAC · intrusiveness ceiling · argument validation · life-safety before a tool executes |
| **Bounded exploitation** | the committed-exploit loop (`committed_exploit.py`) and fuzz campaigns (`agents/fuzzing/campaign.py`) cap adaptations · wall-clock · early-exit — no unbounded hammering |
| **OT-safe by default** | OT/ICS modules are read-only; the AV/OT path is **dry-run by default**, requires `--authorized` + an allowlisted scope, and trips an OT **circuit breaker** on repeated faults |
| **Non-blocking brute / heavy enum** | runs in the background under a generous ceiling and escalates smartly (`knowledge/brute_strategy.py`) — never stalls or floods the engagement |
| **Noise throttle** | `utils/opsec_profiles.py` (`fast`/`quiet`/`stealth`/`paranoid`) strips loud flags; a parallel fuzz campaign yields LLM/tool budget to a live scan |
| **Connectivity gate** | a preflight + circuit-breaker pauses for a human instead of thrashing a dead route |
| **Budgeted** | per-target LLM-token / wall-clock budget with human extend / cut-off |

Every gated decision is an auditable event, and findings are graded by **demonstrated
impact** (`knowledge/severity_policy.py`) — a service banner is never a "critical." On the
roadmap: a **fail-closed** governor mode for OT engagements and a per-engagement
**blast-radius report** rolled up from these governor events.

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
| Engagement | `POST /sessions` | Begin a new pentest engagement |
| Engagement | `GET /sessions/{session_id}` | Engagement state |
| Engagement | `GET /sessions/{session_id}/findings` | Findings · hosts · flags · graph (sibling routes) |
| Engagement | `WS /ws/{session_id}` | Live event stream |
| Fuzzing | `POST /fuzz/campaign/start` | Launch a fuzz→develop→prove campaign (standalone or alongside a scan) |
| Fuzzing | `POST /fuzz/campaign/stop` | Operator stop for a running campaign |
| Fuzzing | `GET /fuzz/campaigns` | Live campaign status · stage · chance-of-success |
| Fuzzing | `GET /fuzz/engines` | Fuzz modalities + installed-tool availability |
| Report | `GET /sessions/{session_id}/report?theme=&format=` | Themed report (executive/compliance/editorial/operator-dark/threat-intel) · HTML or PDF |
| Report | `GET /report/themes` | List available report themes |

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
#   evals/  — capability benchmark library (run_benchmark / compare_to_baseline); see the Capability benchmark section
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
│   ├── config.py · db.py · models.py · schemas.py
│   ├── rbac.py · sessions.py · audit.py · scim.py
│   ├── dependencies.py · routes.py · bootstrap.py · integration.py
│   ├── security/  ← passwords (Argon2id) · MFA (TOTP/WebAuthn) · tokens
│   └── providers/ ← local · OIDC · SAML
│
├── static/                    ← Frontend assets (no build step)
│   ├── api.js · app.jsx · store.js
│   ├── components/            ← StatusBadge, LiveTerminal, FindingCard, …
│   ├── pages/                 ← MissionControl, FindingsBoard, LoginPage, …
│   ├── css/
│   │   ├── main.css           ← base + token system
│   │   └── skins/             ← 18 skins
│   │       ├── apollo.css · tactical.css · bloomberg.css · …
│   │       └── …
│   ├── js/skins/webgl_scene.js
│   └── vendor/                ← React, antd, dayjs, d3, xterm, babel
│
├── templates/index.html       ← cockpit HTML shell
│
├── knowledge/                 ← RAG knowledge base + decision "brains"
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
│   ├── mongo_client.py · neo4j_client.py · cache.py · schemas.py
│   └── __init__.py
│
├── utils/                     ← Cross-cutting helpers
│   ├── llm_providers.py · cvss_scorer.py · opsec_profiles.py · …
│   └── __init__.py
│
└── docs/                      ← Design specs + plans
    └── superpowers/
        ├── specs/             ← design docs
        ├── plans/             ← implementation plans
        ├── research/          ← research notes
        └── report-options/    ← report-design mockups
```

---

## Roles, in one screen

8 hierarchical roles. The auth module enforces every action via RBAC +
ABAC. See [Enterprise authentication](#enterprise-authentication) for the
RBAC/ABAC engine, sessions, and audit detail.

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

## Enterprise authentication

Purely-additive enterprise identity module under `auth/` — user management, authN/authZ, audit, and DB-backed sessions aligned to NIST 800-53 / ISO 27001 / SOC 2 / SOX. It touches no existing ARGUS file; mount it with one line in `agent_server.py`:

```python
from auth.integration import install_auth
install_auth(app)   # mounts /auth/* and /scim/v2/*
```

On first import it creates its tables (idempotent) and bootstraps an `OWNER` (dev prints one-time creds; prod requires `AUTH_INITIAL_OWNER_EMAIL` + `AUTH_INITIAL_OWNER_PASSWORD`). Existing routes opt into protection via `Depends(require_permission("tools", "execute"))` / `get_current_user`; routes that don't add the dep keep working.

**Capabilities** · local username/password (Argon2id, RFC 9106, per-user pepper) · MFA TOTP (RFC 6238, backup codes, QR enrolment; WebAuthn/FIDO2 stubbed) · SSO via OIDC (`authlib`, PKCE-enforced) and SAML 2.0 (`python3-saml`) · SCIM 2.0 provisioning (`/scim/v2/Users`+`/Groups`, bearer auth) · RBAC+ABAC · rotating refresh tokens with family revocation · append-only audit log · NIST 800-63B password policy · account lockout · CSRF double-submit.

**Eight hierarchical roles** — `OWNER` · `PLATFORM_ADMIN` · `SECURITY_MANAGER` · `OPERATOR` · `ANALYST` · `EXECUTIVE` · `AUDITOR` · `CLIENT`. Codes live in both `rbac.py::Role` and `models.py::RoleCode` (keep them in sync); the full scope + default-skin matrix is in [Roles, in one screen](#roles-in-one-screen).

**Stateful sessions** · the `sessions` row carries CSRF token, IP/UA, and `current_tenant_id`; a 1:1 `session_state` table persists UI state (skin, audience mode, open hub/tab, pinned pentest session, filters) so any device resumes the same cockpit. The frontend treats `localStorage` as a write-through cache — **the DB is source of truth**. Idle timeout 12h, absolute lifetime 7d; refresh-token reuse triggers family revocation (OAuth 2.1).

**Persistence** · separate SQLAlchemy 2.0 DB (`AUTH_DATABASE_URL`, SQLite dev / PostgreSQL prod) so auth migrations, backups, and rollback never touch operational tables; small teams may point it at the same SQLite file (tables are namespaced).

**Key files** · `routes.py` (`/auth/*`) · `scim.py` · `rbac.py` · `audit.py` (optional `AUDIT_HASH_CHAIN` tamper-evidence; `audit_logs:delete` is OWNER-only) · `sessions.py` · `dependencies.py` · `integration.py` · `security/{passwords,mfa,tokens}.py` · `providers/{local,oidc,saml}.py`.

**CLI** · `python -m auth.bootstrap <cmd>` — `quickstart`, `create-owner`, `migrate`, `issue-scim-token`, `rotate-jwt-key`, `enforce-retention`, `db-info`, `diagnose-login`. Tenant-scoped commands use `--tenant-slug` (default `default`), never `--tenant-id`.

**Gotcha** · OIDC/SAML providers are keyed by `idp_id` in `identity_providers`, not by tenant — one tenant may register multiple IdPs.

---

## Agents & the autonomous engine

The `agents/` fleet is ARGUS's offensive heart: ~244 Python files across 28 specialist folders plus 21 top-level orchestration agents. Two brains drive it. The **MasterAgent** (`agents/master_agent.py`) runs the engagement phase state machine and owns the centralized token budget. For each phase it either hands control to the tiered-LLM **OPERATOR** (`agents/operator_agent/`, 10 files) — a ReAct loop in `operator_core.py` that reasons with the LLM and calls `run_tool` directly — or dispatches typed `Instruction` objects to deterministic specialist workers over the **AgentBus**. If the operator is unavailable, the MasterAgent emits `operator_core_fallback` and the deterministic machine takes over.

Two architectural rules keep this tractable: the LLM lives behind a few callers (MasterAgent, OperatorCore, `attack_graph_agent.py`, `fuzzing/`) — most specialists stay deterministic; and **specialists never talk to each other directly** — all inter-agent traffic goes through the bus (publish/subscribe, topics named by `agent_name`, correlation-id response matching). The OperatorCore bypasses the bus for its own tool calls but uses the same safety guards.

**Specialist folders** (`.py` counts) span the kill chain: `recon/` (8) · `osint/` (23) · `vuln/` (8) · `web/` (17, OWASP WSTG) · `exploit/` (13) · `privesc/` (7) · `lateral/` (6) · `post/` (6) · `evasion/` (5) · `cloud/` · `container/` · `iot/` · `wireless/` · `traffic/` · `forensics/` · `evidence/` · `ot/` · `reasoning/` (30, the hypothesis loop) · plus the capability modules below. Findings carry operational severity, CVSS, and MITRE T-IDs, and flow to MongoDB · Neo4j · the UI WebSocket.

**Base classes & protocol.** Top-level agents extend `BaseAgent` (`agents/base_agent.py`: `run`/`handle_instruction`/`teardown` + `store_finding`/`emit_event`/`collect_tool`). Phase workers extend `BaseSubagent` (`agents/base_subagent.py`: just `run(target, **kwargs) -> SubagentResult`). `Instruction` is the typed bus message (target phase, optional subagent, target, payload, ttl, priority, correlation).

**Fuzzing workshop** (`agents/fuzzing/`, 9 modules): a fuzz → develop → **PROVE** pipeline — it fuzzes, builds a working exploit from any crash, then requires a reproducible PoC before the finding counts. `engines/` holds 6 modality engines (`binary_cov` AFL++/honggfuzz · `file_fmt` radamsa/zzuf · `live_http` schemathesis · `live_proto` boofuzz · `tool_engine` · `ai_target`) selected via `_REGISTRY`. Heavy deps are lazy-loaded, so a missing tool degrades gracefully via each engine's `supports()` check.

**Capability modules** plug domain knowledge in without touching `master_agent`/`operator_core` — the engine just calls generic `detect(intel)` / `finding_for(detection)` helpers:

- **AI red-team** (`agents/ai_red_team/`, 9 files) — the `target_type="ai"` path. Probes are **DATA**, not code: catalog YAML lives in `knowledge/data/ai_security/` (one list per OWASP-LLM class); adding an attack = adding a YAML entry. `harness.py` runs probes with a dual scorer (`scorer.py`: deterministic detectors or LLM-judge → ASR), `target_adapter.py` covers http_chat/agentic/single_endpoint shapes, and findings map to OWASP-LLM / MITRE-ATLAS. `discovery.py` does shadow-AI fingerprinting during *normal* network engagements (exposed Ollama/vLLM/MCP surfaces → governance finding), and `reproducibility.py` exports the catalog to Promptfoo/garak/PyRIT. Destructive/jailbreak probes are gated (`destructive: true` + `ARGUS_AI_REDTEAM_AGGRESSIVE=1`); the whole path sits behind `ARGUS_AI_REDTEAM`.
- **AV/OT control systems** (`agents/avot/`) — `recon.py` fingerprints networked AV/OT control systems (proprietary control protocols on dedicated ports, banner signatures → MITRE `T0846`); `sast/` is a heuristic control-language static analyzer (embedded control source) with 9 rules, runnable as a CI gate (`--fail-on HIGH --json`); `fuzz/` is a dependency-free, field-aware control-protocol fuzzer (`--scope-allow`/`--scope-deny` CIDR guards, `--seed-corpus`, and `--advisory` to emit a vendor-ready PSIRT minimal-repro stub). The pattern is vendor-agnostic — each supported control ecosystem is a self-contained recon+SAST+fuzz triad under `agents/avot/`. **Lab use only** — it is **dry-run by default**; sending requires `--authorized` *and* an allowlisted `--scope-allow` CIDR (with `--scope-deny` to fence off production ranges), and an OT circuit breaker (`--max-consec-fail`) halts on repeated crashes. **Hardware-safety preflight** (this gear bricks easily): isolated VLAN, an out-of-band serial console + a known power-cycle method, low `--max-consec-fail`, dry-run first, and a config/firmware backup. Findings go to the vendor PSIRT via **coordinated disclosure — never a public 0-day drop**. Graduate real campaigns into the shared `agents/fuzzing/` workshop.

**Conventions & gotchas.** Files are `*_subagent.py` / `*_agent.py`; classes end `Subagent`/`Agent`; `AGENT_NAME` is lowercase. Always spawn tools via `asyncio.create_subprocess_exec(*argv)` — never a shell string (`collect_tool`/`run_tool` enforce this). Score with `utils.cvss_scorer.score()`, grade severity through `knowledge.severity_policy.grade()` (outcome-driven — a demonstrated compromise outranks a public-PoC CVE; do not invent ad-hoc severities), and set `mitre_technique` so the attack-graph builder can use it. The `opsec_profiles` knob (`fast`/`quiet`/`stealth`/`paranoid`, default from `ARGUS_OPSEC`) strips noisy default flags from tool argv and throttles behaviour; `paranoid` is the quietest. `knowledge/safety_governor.py` gates intrusive actions against scope/RoE before any tool runs. Reports render to 5 themes in `report/themes/`; `evals/` benchmarks the fleet.

**Add a specialist:** create `agents/<phase>/<name>_subagent.py` extending `BaseSubagent`, register it in the phase `__init__.py`'s `SUBAGENTS` map, optionally add it to `master_agent.py`'s phase-plan list and to `operator_agent/tool_catalog.py` (so `technique_search` surfaces it to the OPERATOR), then wire a dispatch button in the UI.

---

## Frontend & visual skins

The operator cockpit is a **React 18 single-page app with no build step** — served by the FastAPI backend at `/`, it ships Babel-standalone which compiles JSX in-browser on first load (~1s once, then cached). This trades a small first-paint cost for zero-friction deploys on air-gapped ops VMs: `git pull && uvicorn agent_server:app`, no Node, no `npm install`, no bundling. Every vendor lib is committed under `static/vendor/` (React · antd · dayjs · d3 · xterm · babel).

**Layout** (`static/`): `app.jsx` (router + `AuthBoundary` + shell) · `store.js` (global state via `useReducer` + Context, not Redux) · `api.js` (fetch wrapper) · `pages/` (24 top-level views) · `components/` (13 shared widgets, e.g. `SkinChooser`, `LiveTerminal`, `MfaChallenge`, `FindingCard`) · `css/` (`main.css` tokens + default skin, `skins/` overlays) · `skins/webgl_scene.js` (lazy Three.js scene).

**Bootstrap order matters.** `templates/index.html` loads scripts in DOM order and each file exposes `window.<X>`; a file must load **before** its first consumer (components → `SkinChooser`/`MfaChallenge` → `LoginPage` → other pages → `app.jsx` last). Every `<script>` has a `?v=N` cache buster — **bump it when you change a file** or browsers serve stale JSX.

**Pages & modes.** A page mounts via the `HUBS[]` array (sidebar entry → tabs) plus a `COMP_FOR` getter map (`MyPage: () => window.MyPage`) in `app.jsx`. The header `ModePicker` (F1–F4) drives 4 audience modes — `OPERATOR` (full), `BRIEFING` (trimmed), `PRESENT` (9-slide deck), `CLIENT` (findings/reports only, brand ribbon, tool names defanged via `defangToolName()`). Per-hub visibility lives in `HUB_MODE_VISIBILITY`.

**Skins.** 18 runtime-switchable visual treatments — pure CSS overlays, zero backend touch — in 3 families: **Aesthetic** (stellar, apollo, tactical, bloomberg, glass, editorial, webgl), **Operator** (veteran, novice, genz, redcell, hunter, ctf), **Management** (auditor, manager, executive, cfo, legal). The default `stellar` skin lives in `main.css`; the other 17 are single CSS files in `css/skins/` that re-theme via design tokens (`--accent`, `--bg-base`, severity `--critical`…`--info`, etc.). Switching is instant and reload-free: `ArgusSkin.apply('bloomberg')` swaps the `<link id="argus-skin">` href + `<html data-skin>` attr, then persists.

To **add a skin**: copy an existing file in `css/skins/`, override tokens in `:root[data-skin="<id>"]`, then register it in the `SKINS` array in `components/SkinChooser.jsx` (with `family`/`swatches`) and bump that script's `?v=N`. Keep skins under ~500 lines, all 5 severity tints distinct, tap targets ≥36px, and respect `prefers-reduced-motion`. The `webgl` skin lazy-loads its Three.js scene only when selected.

**State & persistence.** All UI prefs (skin, audience mode, sidebar, current hub/tab) are **per-user**, written through `localStorage` and mirrored to the auth DB via `PATCH /auth/me/state` (debounced ~800ms), so state follows the operator across devices. `AuthBoundary` gates the cockpit: `GET /auth/me` → login (401) · cockpit (200) · dev bypass (404), hydrating the saved skin before first render to avoid a flash.

**Gotcha:** `color-mix()` and `backdrop-filter` are heavily used; Safari <16 / IE11 degrade or aren't supported. Tier-1 browsers are Chrome/Edge ≥100, Firefox ≥100, Safari ≥16.

---

## Knowledge base & RAG

`knowledge/` is the retrieval-augmented brain ARGUS queries during an engagement ("SMB on 445, OS=Windows — what now?"). It returns curated playbooks that match live intel exactly plus semantically-retrieved chunks from your writeups/docs, merged and fed into the agent's prompt. Everything runs locally (ChromaDB + local embedder) — no data leaves the box.

**Three layers:**

| Layer | Path | How it works |
|---|---|---|
| Drop zone | `knowledge/data/` | Drop `.pdf .md .txt .html .mhtml .json .yaml` anywhere; chunked + embedded into `knowledge/db/`. The single place you add reference content. |
| Playbooks | `knowledge/data/playbooks/` | 44 curated YAMLs (`id`/`trigger`/`steps`). **Not embedded** — loaded fresh at query time and returned verbatim when `trigger` overlaps live intel. No rebuild needed to add one. |
| Skill cards | `knowledge/skills/<category>/*.md` | 165 cards across 11 categories (ot · iot · marine · webapp · aviation · os · scada · security · home · it · network). YAML front-matter + Markdown guidance; auto-loaded, matched against recon, and ingested into RAG. |

**Build / use the index:**

```bash
pip install -r requirements.txt          # one-time: chromadb, sentence-transformers, …
python knowledge/build_kb.py             # incremental ingest (re-run anytime; only changed files re-embed)
python knowledge/build_kb.py --reset     # wipe + rebuild (required after changing the embedder)
python knowledge/build_kb.py --stats     # chunk/source counts + model names
python knowledge/build_kb.py --search "apache 2.4.49 path traversal"
bash knowledge/fetch_sources.sh          # optional: bulk-clone HackTricks, PayloadsAllTheThings, nuclei-templates, …
```

Retrieval runs in tiers: Tier 0 playbook lookup (token-overlap, <50 ms) → Tier 1 hybrid dense-vector + BM25/FTS5 with Reciprocal Rank Fusion → Tier 2 optional HyDE rewrite (LLM) → Tier 3 cross-encoder rerank + MMR diversity → Tier 4 outcome × recency boost. Defaults are env-overridable: `KB_EMBED_MODEL` (`BAAI/bge-small-en-v1.5`, 384-dim), `KB_RERANK_MODEL` (`ms-marco-MiniLM-L-6-v2`, set `""` to disable), `KB_MMR_LAMBDA` (`0.65`), `KB_DB_PATH` (scope to a per-engagement index). HyDE/rerank are skipped silently when no LLM is wired in. Budget ~2 GB RAM and 5–30 min for a first build on the default models.

**Skill cards drive an active safety gate.** Each card's `domain` (OT/IoT/IT) and per-`quick_win` `safety` class (safe/intrusive/disruptive) are checked against the human-set scan-intrusiveness ceiling: only at-or-below-ceiling quick-wins auto-surface to the operator, OT targets are clamped to `safe` unless explicitly authorized, and `life_safety: true` actions never auto-run. `match.ports` uses **dedicated ports only** — shared ports (80/443/8080/…) are ignored for port-only matches by an FP guard, so rely on banners/markers there. `scripts/update_skills.py` (run weekly) refreshes CVE references from CISA KEV and authors new schema-valid cards.

Alongside retrieval, `knowledge/` ships deterministic decision modules the agents import directly (no embeddings): `severity_policy.py` (canonical per-finding verdict), `safety_governor.py` (intrusiveness + scope guardrails), `brute_strategy.py`, `technique_search.py` (standalone FTS5), `skill_registry.py` + `skill_telemetry.py` (load/match/rank cards + self-learning), and `fuzz_targeting.py` (surface scoring for `agents/fuzzing/`).

**Gotchas:** never drop secrets/credentials into `data/` — the KB is searchable by any agent process. Changing `KB_EMBED_MODEL` requires `--reset` (vector dims differ). Only one ingest at a time (concurrent reads are fine; concurrent writes are not); stop `agent_server.py` if `chroma.sqlite3` is locked. Deleted source files leave their chunks in `db/` until the next `--reset`.

---

## Authoring playbooks & skills

ARGUS turns tribal knowledge into two authored, retrievable formats that beat fuzzy semantic search. **Playbooks** are deterministic command chains keyed on live intel; **skills** are free-text methodology the agent reads rather than executes. When intel matches a playbook trigger, that playbook is returned *verbatim, in order, above* any vector-search result.

**Playbooks** live as YAML under `knowledge/data/playbooks/<id>.yml` (44 today). The loader (`knowledge/build_kb.py::load_playbooks`) scans recursively and treats any YAML with the three required top-level keys — `id`, `trigger`, `steps` — as a playbook. No re-ingest needed: save the file and it's live on the next retrieval.

```yaml
id: service_redis_unauth          # snake_case, category-prefixed (service_/tech_/ad_/web_/cloud_…)
title: "Redis unauth → RCE"
phase: exploit                    # recon|exploit|privesc|web|post|lateral
mitre: ["T1210"]
trigger:                          # facets are OR-overlap vs intel; empty facet = wildcard
  services: ["redis"]; ports: [6379]; os_any: []; technologies: []; cves: []
keywords: ["redis", "authorized_keys"]
steps:                            # returned VERBATIM, in order
  - {tool: redis-cli, cmd: "redis-cli -h {target} config set dir /root/.ssh", why: "stage key write"}
expected_outcome: "SSH as root"   # tells agent when to stop; optional: preconditions, fallbacks, references
```

**Trigger scoring** (`_rag_trigger_score`): per-match weights — cves +1.00 · technologies +0.45 · services +0.40 · ports +0.30 · os_any +0.20 · mitre +0.15 · keywords +0.20 (cap 5) · phase +0.10; raw score normalised by 2.0. CVE/tech/mitre match exact, ports numeric-exact (`80` ≠ `8080`), services token-Jaccard ≥ 0.5, os_any substring. `min_score=0.20` filters the tail.

**Critical gotcha — the specificity gate:** a playbook matching *only* on generic facets (services/ports/os_any) with no CVE, technology, MITRE, or query-keyword signal is multiplied by **0.35** and usually filtered out. To rank, give it at least one specific signal — a real CVE/tech the intel carries, an overlapping MITRE ID, or a keyword hit. Also quote any `cmd` containing `:`/`{`/`}` (else YAML breaks), use `{placeholder}` not hardcoded targets, and keep steps in execution order. Don't write a playbook for one-off tricks or unvalidated guesses — those belong in tips. Validate with `load_playbooks(force_reload=True)` and test that your `id` ranks #1 via `retrieve(...)`.

**Skills** are markdown under `knowledge/skills/<category>/<id>.md` (165 files across 11 categories: ot, iot, marine, webapp, aviation, os, scada, security, home, it, network). `skill_registry.py` walks the tree with `rglob`, groups by each file's front-matter `category` field (authoritative over the folder name), and exposes `load_skills()` / `match_skills()` / `finding_for()`. Skills feed the self-learning loop — telemetry records which fired and which produced findings. Use a **playbook** for a deterministic intel-keyed command chain; use a **skill** for domain context and guidance the agent reasons over.

---

## RAG troubleshooting

Diagnosis for the ARGUS knowledge base (ChromaDB + sentence-transformers). Index lives at `knowledge/db/` (vectors in `chroma.sqlite3`, incremental state in `ingest_manifest.json`). Build/search with `python knowledge/build_kb.py` (`--reset`, `--force`, `--search "…"`, `--stats`). Defaults are set in `knowledge/knowledge_base.py` and `build_kb.py`: embedder `BAAI/bge-small-en-v1.5` (384-dim, ~300 MB RAM), reranker `cross-encoder/ms-marco-MiniLM-L-6-v2`, `RERANK_FETCH=25`.

| Symptom | Cause · fix |
|---|---|
| `No module named chromadb/sentence_transformers` | Deps missing — `pip install -r requirements.txt`; on Kali use a venv or `--break-system-packages` |
| `torch` install fails | Old pip, <3 GB disk, or blocked `download.pytorch.org` — upgrade pip or use `--index-url …/whl/cpu` |
| HF 401 / download stalls | Proxy breaks auth — `export HF_ENDPOINT=https://hf-mirror.com`; air-gap by copying `~/.cache/huggingface/` |
| `Total chunks: 0` | Empty/unsupported `knowledge/data/` (`.pdf .md .html .txt .json .yaml`), or all YAML were playbooks (not embedded) |
| Re-ingests every file | Manifest deleted/corrupt, `--force` set, or varying absolute paths (manifest keys are absolute) |
| PDF Unicode garbage / ingest hangs | Bad PDF extraction — convert via `marker-pdf`/`pymupdf4llm` or `ocrmypdf`; move the offending file (logged before processing) aside |
| `Out of memory` / CUDA/MPS OOM | You opted up to `bge-m3` — set `KB_EMBED_MODEL=BAAI/bge-small-en-v1.5` (or force CPU via `CUDA_VISIBLE_DEVICES=""`) |
| `(no results found)` | Empty index (check `--stats`), `KB_MIN_RELEVANCE` too high, or query too generic (use 4+ tokens) |
| Reranker slow (>5 s) | Set `KB_RERANK_MODEL=""` or pass `use_rerank=False`; lower `RERANK_FETCH` in code; GPU auto-detected |
| Wrong/zero-relevance playbook | Trigger too broad/narrow — tune `services`/`ports`/`keywords`/`cves`; `matched_on` from `retrieve()` shows matched facets |
| Playbook YAML ignored | Needs top-level `id`+`trigger`+`steps` anywhere under `knowledge/data/`; quote values with `: { } [ ] # & * ?`; reload via `load_playbooks(force_reload=True)` |
| `database is locked` | ChromaDB has no concurrent writes — `pkill -f agent_server.py` before `--reset`, or `flock` ingest jobs |
| Deleted file still in index | No reverse-prune yet — full rebuild with `--reset` |

**Critical gotcha:** changing the embed model changes vector dimensions, so it **requires `--reset`** — the whole collection must share one dimension. Per-engagement isolation via `export KB_DB_PATH=/path/engagement-XYZ/db`; query-time de-dup via `KB_MMR_LAMBDA` (default 0.65, lower = more diverse). Full reset: `rm -rf knowledge/db/` then `python knowledge/build_kb.py --reset`.

---

## Data layer

ARGUS spreads engagement state across purpose-fit stores, abstracted so callers never need to know which one holds what. The `db/` module owns four of them; the **auth module** (`auth/db.py`, SQLAlchemy 2.0 over SQLite/PostgreSQL) manages a fifth independently, and `knowledge/` adds a ChromaDB vector store for RAG.

| Store | Client | Holds |
|-------|--------|-------|
| **MongoDB** (`argus_pentest`) | `db/mongo_client.py` | Document-shaped engagement state — sessions, findings, tool outputs, agent logs, shells, credentials, payloads, attack graph, checkpoints/archives, plus reasoning/self-learning collections |
| **Neo4j** *(optional)* | `db/neo4j_client.py` | Semantic attack graph (hosts/services/creds/vulns as nodes; `PIVOTS_TO`, `VULNERABLE_TO`, … as edges) |
| **In-process cache** | `db/cache.py` | Hot read-model lookups — no Redis, no persistence |

**Files:** `mongo_client.py` (async Motor CRUD + `setup()`/`ensure_setup()`/`teardown()`/`get_db()`) · `neo4j_client.py` (async driver wrapper) · `cache.py` (async TTL+LRU caches) · `schemas.py` (Pydantic models — the source of truth for document shape). `__init__.py` is **empty**: import submodules directly, conventionally `import db.mongo_client as db` and `import db.neo4j_client as neo4j`.

**Usage.** Always build documents through the `schemas.py` model, never raw dicts — it validates enums (`FindingSeverity` ∈ `{critical, high, medium, low, info}`, **lowercase**) and round-trips datetimes:

```python
from db.schemas import Finding
doc = Finding(session_id=sid, title="SQLi in /login", severity="high").model_dump(mode="json")
```

`setup()` runs from `agent_server.py`'s lifespan, connects, and builds all indexes idempotently. Caches are named singletons (`findings_cache`, `graph_cache`, `tool_outputs_cache`, `session_meta_cache`) — `get()` returns `(hit, value)`; capacities are fixed in `cache.py` (e.g. `findings_cache` = 256 entries / 20 s TTL), not env-configurable.

**Config:** `MONGO_URI` (default `mongodb://localhost:27017`; DB name fixed at `argus_pentest`) · `NEO4J_URI`/`NEO4J_USER`/`NEO4J_PASSWORD` · `AUTH_DATABASE_URL`.

**Gotchas.** Neo4j is fully optional — every call silently no-ops when the driver is missing or unreachable, so MongoDB's flat `attack_graph_nodes`/`attack_graph_edges` remain the fallback graph. The session model is `Session` (not `ScanSession`); there is no `scan_results`/`shells`/`reports` collection — use `tool_outputs`, `shell_sessions`, `agent_logs`. The five stores have no cross-store transactions; back them up together (`mongodump`, `neo4j-admin database dump`, copy/`pg_dump` the auth DB — cache rebuilds itself).

---

## Utilities

`utils/` holds small, single-purpose, cross-cutting helpers. Every module imports with **no side effects** and depends only on the standard library plus root `requirements.txt` — no extra pip installs.

| Module | What it does |
|--------|--------------|
| `llm_providers.py` | Tiered LLM backend abstraction — one interface over Ollama, OpenAI-compatible APIs (vLLM, LM Studio, Groq, OpenRouter, …), Anthropic, Gemini, and the Claude Code CLI subscription backend, with an automatic fallback chain. |
| `cvss_scorer.py` | CVSS 3.1 base scores from finding metadata (CWE, exploitability, scope); ranks chains; scores AI/LLM findings with an AIVSS-style band. |
| `json_tolerant.py` | Forgiving JSON parser for LLM output (trailing commas, comments, unquoted keys, code-fence wrappers, smart quotes, Python literals). |
| `model_capability.py` | Probes a local Ollama model's real tool-calling / context-length support and gates features; also validates CVE IDs. |
| `opsec_profiles.py` | Profiles `fast` / `quiet` / `stealth` / `paranoid` that strip noisy default flags from tool argv and throttle behaviour. |
| `target_normalizer.py` | Classifies operator strings (IP, CIDR, hostname, URL, IPv6, host:port, app-mode hints) into a `NormalisedTarget`. |
| `scan_logger.py` | Per-session forensic bundle writer to `logs/<ts>_<session_id>/` — tool calls, LLM calls, phases, findings, real per-provider token usage. |
| `replay_mode.py` | Re-streams a finished session's WebSocket events for demos + debugging. |

**Backend selection:** `LLM_PROVIDER` (default `auto`) chooses the provider — `auto` tries Claude Code CLI → Ollama → any configured hosted provider; explicit values are `ollama`, `openai-compat`, `anthropic`, `gemini`, `claude_code`. `stream_tiered()` / `stream_with_fallback()` retry down `provider_chain()`, using `looks_like_refusal()` to fail over.

**Extending:** keep new helpers side-effect-free and stdlib-only. Orchestration logic stays in `agents/` — these modules only expose the backends, scoring, logging, and normalisation that agents need. `opsec_profiles` defaults to the `ARGUS_OPSEC` env var (else `fast`).

---

## Capability benchmark

`evals/` is a deterministic, scored benchmark for ARGUS's offensive capability — it catches a code change that quietly makes ARGUS *worse* at finding or exploiting things before it reaches a client engagement. Modelled on XBOW's reproducible-proof approach: each **exploit** case points ARGUS at a known-vulnerable target whose proof of compromise is a build-time-injected flag token, so a pass is **un-fakeable** — a model can't talk its way past it. **Detect** cases (e.g. a TLS weakness, where exfiltrating a flag isn't the right proof) pass on a finding signature: expected CVE · title keywords · minimum severity.

| Path | Responsibility |
|------|----------------|
| `evals/catalog.py` | Benchmark cases + per-run flag minting (`mint_run_flag`) |
| `evals/scorer.py` | Pure scoring of one run → `CaseResult{exploited, detected, passed, score}` |
| `evals/runner.py` | Orchestrates a run (`run_benchmark`, mode `live`\|`replay`) + `compare_to_baseline` |
| `evals/targets/manifest.json` | Dockerised target definitions for the live runner |
| `evals/fixtures/replay_sample.json` | Recorded transcript for the offline scoring path |
| `evals/baseline.json` | Last-known-good scores; the per-commit regression compares against this |

**Offline / CI** — `run_benchmark(mode="replay", transcripts=…, nonce="baseline")`, then `compare_to_baseline(report, load_baseline(...))` and assert `not delta["regressed"]`; no targets needed. **Live** (Kali/CI with Docker) — pass `mode="live"` and a `run_fn` that stands up each target with `ARGUS_EVAL_FLAG`, runs ARGUS, and returns `findings`/`flags_found`/`loot`. When a change legitimately improves coverage, regenerate via `save_baseline(...)` and review the diff.

**Gotchas:** a live case that errors (no Docker, target down) is **skipped**, never a hard failure — the benchmark is additive and never blocks ARGUS itself. In review, an *unexpected* drop in `passed`/`score_sum` is exactly the regression this exists to surface.

---

## Design docs

Long-form specs, plans, research, and report mockups live under `docs/superpowers/` — the brainstorm → spec → plan → implementation workflow the maintainers use ("superpowers" is a naming convention, not a code dependency). Files are ISO-date-prefixed (`YYYY-MM-DD-<slug>.md`) so each folder sorts chronologically.

| Folder | Contents |
|--------|----------|
| `docs/superpowers/specs/` | 19 design docs — the *what + why* (motivation · goals · non-goals · design · alternatives · risks). Stable once approved. |
| `docs/superpowers/plans/` | 8 implementation plans — *how + when*, a checklist of ~30-min tasks with file paths, snippets, and test commands. |
| `docs/superpowers/research/` | 2 background notes (technology-coverage surveys) that inform specs. |
| `docs/superpowers/report-options/` | 10 static HTML mockups (5 options + 5 previews) driving the 5 shipped themes in `report/themes/`. |

To add a spec: drop `specs/$(date +%F)-<slug>-design.md` (6 sections: motivation · goals · non-goals · design · alternatives · risks — copy any existing spec in `docs/superpowers/specs/` as a template); after maintainer sign-off, derive `plans/$(date +%F)-<slug>.md`. **Gotcha:** plans go stale once shipped — never edit an old plan, write a new spec. Not every spec gets a standalone plan (some ship integrated into an existing loop).

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

All component documentation now lives in this README — read the relevant
section before you start:

- New agent type → [Agents & the autonomous engine](#agents--the-autonomous-engine)
- New skin or frontend page → [Frontend & visual skins](#frontend--visual-skins)
- Auth feature (MFA factor, IdP, SCIM ext.) → [Enterprise authentication](#enterprise-authentication)
- Knowledge-base corpus / playbook / skill → [Knowledge base & RAG](#knowledge-base--rag) · [Authoring playbooks & skills](#authoring-playbooks--skills)
- Design specs / implementation plans → [Design docs](#design-docs)

Update the matching section here when you add something — there are no
per-folder READMEs to keep in sync anymore.

---

*"You don't grep your way to a finding. You think your way there.
ARGUS is what that thinking looks like, at machine speed, supervised
by the right humans."*
