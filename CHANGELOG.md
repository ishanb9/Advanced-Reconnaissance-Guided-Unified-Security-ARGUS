# ARGUS Changelog

Notable user-facing changes to the platform.  Follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.  Dates
are UTC.

The format is grouped by:
* **Added** — new features
* **Changed** — changes to existing behavior (read these carefully if upgrading)
* **Fixed** — bug fixes
* **Security** — changes that affect the security posture
* **Migration** — actions required when upgrading

---

## Unreleased

### Changed — One canonical report (theme consolidation)

- **The 5 selectable report themes were consolidated into a single canonical
  report** (`report/themes/argus.html.j2`): a "dark hero + light body" design
  carrying every section — executive summary, engagement dashboard, per-finding
  reproduction steps, the compromise-basis block, findings register + detailed
  cards, coverage/attempts, MITRE mapping, detection map, loot/evidence, AI/LLM
  security, methodology, and reasoning journal.
- **New server-side inline-SVG chart engine** (`report/charts.py`): severity
  donut, risk gauge, coverage-outcome bars, MITRE tactic coverage, and the
  attack-path kill-chain — rendered as pure SVG (WeasyPrint runs no JavaScript),
  authored at true render width so text stays crisp.
- **Primary PDF engine is now headless Chromium (Playwright)** for browser-grade
  fidelity, with WeasyPrint kept as the pure-python fallback and wkhtmltopdf last.
  Both run off the event loop; page numbering is drawn via the engine's native
  footer. **Premium fonts** (`fonts-inter`, `fonts-jetbrains-mono`,
  `fonts-noto-core`) are embedded when installed (theme falls back to system fonts).
- The report now also surfaces the **attack-surface / services table**, **observed
  (unvalidated) issues**, captured **flags**, **exploit modules / PoCs considered**,
  **tool-chain coverage**, and **win conditions** — data that was previously collected
  but not shown.
- The report **theme picker was removed** from the UI (nothing to pick).
- **Backward-compat:** `GET /sessions/{id}/report?theme=…` still returns HTTP
  200 — any theme value now renders the single `argus` report; `/report/themes`
  returns the single entry; the legacy `report/` template remains the fallback.

### Added — Autonomous engagement engine

- **Tiered-LLM OPERATOR engine** (`agents/operator_agent/`) — an
  LLM-driven operator that calls `run_tool` directly through its own
  decision loop (`operator_core._do_run_tool`) rather than waiting on a
  fixed phase script.  It uses two model tiers — `tier="bulk"` for
  high-volume work and `tier="reason"` for planning/judgement — and
  rebuilds a live surface model + objective-aware hypotheses between
  steps.  `MasterAgent` (`agents/master_agent.py`) still runs the
  LLM-consulted phase machine; the two cooperate.
- **28 specialist agent folders** under `agents/` — including
  `ai_red_team/`, `avot/`, `c2/`, `campaign/`, `cloud/`, `container/`,
  `evasion/`, `evidence/`, `exploit/`, `forensics/`, `fuzzing/`,
  `iot/`, `lateral/`, `meta/`, `mission/`, `operator_agent/`, `osint/`,
  `ot/`, `playbook/`, `post/`, `privesc/`, `reasoning/`, `recon/`,
  `traffic/`, `training/`, `vuln/`, `web/`, and `wireless/`.
- **Committed-exploitation loop**
  (`agents/operator_agent/committed_exploit.py`) — drives an exploit
  attempt to a definitive outcome instead of bailing after one probe,
  recording only flags/creds the model explicitly submits in-band (no
  fabricated success).
- **Fuzz → develop → PROVE workshop** (`agents/fuzzing/`) — a
  campaign that fuzzes a target, develops an exploit, and proves it
  (`fuzz_lab.py`, `campaign.py`, `exploit_dev.py`, `oracle.py`,
  `proof.py`, `poc_runner.py`).  Wraps **6 fuzz engines** — AFL++,
  honggfuzz, radamsa, zzuf, boofuzz, and schemathesis — behind a
  common `FuzzEngine` base (binary-coverage, file-format, live-HTTP,
  live-protocol, tool, and AI-target engine classes).
- **Operational severity model** (`knowledge/severity_policy.py`) —
  `grade(signals)` returns one canonical, deterministic verdict
  (critical/high/medium/low/info) keyed to what ARGUS actually proved
  on the target, with `merge_signals`, `is_escalation`, `is_noise`,
  and `normalize_finding` helpers.
- **5 report themes** under `report/themes/` — `compliance`,
  `editorial`, `executive`, `operator_dark`, and `threat_intel`
  (`.html.j2`), rendered by `report/generator.py`.
- **Smart background brute-forcing** (`knowledge/brute_strategy.py`) —
  picks credential/wordlist strategy and runs it as a background
  effort rather than blocking the main loop.
- **Safety governor** (`knowledge/safety_governor.py`) — gates
  potentially destructive actions before they execute.
- **`technique_search`** (`knowledge/technique_search.py`) — technique
  lookup consumed by the operator and the fuzzing/exploit-dev path.
- **Self-learning skill registry** (`knowledge/skill_registry.py`) —
  scores detections by severity × exploitability × CVE-recency ×
  learned weight, where the learned weight is updated from engagement
  telemetry.
- **Browser verification subagent**
  (`agents/web/browser_verify_subagent.py`) — Playwright-driven
  confirmation of web findings in a real browser.
- **Evaluation harness** (`evals/`) — `runner.py`, `scorer.py`,
  `catalog.py`, `baseline.json`, plus `fixtures/` and `targets/` for
  benchmarking agent behavior against known cases.

### Changed
- **Default value of `AUTH_COOKIE_SECURE` is now derived from
  `AUTH_DEPLOYMENT_ENV`.**  Previously it was hard-coded to `true`,
  which silently broke login on `http://localhost` deployments
  (cookies were dropped → `/auth/me` 401'd → login bounced back).
  Now:
  * `AUTH_DEPLOYMENT_ENV=prod` → defaults to `true` (HTTPS required)
  * Anything else → defaults to `false` (works on `http://localhost`)
  * An explicit `AUTH_COOKIE_SECURE=true|false` still overrides
- Default value of `AUTH_MFA_REQUIRED_FOR` changed from
  `OWNER,PLATFORM_ADMIN` to empty (MFA is now opt-in).  Existing users
  with TOTP enrolled still see the prompt every login; new users can
  opt in via `POST /auth/mfa/enrol/start`.  To restore the old behavior,
  set `AUTH_MFA_REQUIRED_FOR=OWNER,PLATFORM_ADMIN`.

### Added
- **`python -m auth.bootstrap quickstart`** — one command does everything:
  generates strong values for `AUTH_JWT_SECRET`, `AUTH_PASSWORD_PEPPER`,
  and the initial owner password, writes them to `.env.local` (chmod 600),
  creates the auth DB tables, and creates the OWNER account.  Replaces
  the multi-step `openssl rand` + manual env-var dance.
- **`python -m auth.bootstrap reset-owner-password --generate`** — break-glass
  recovery for a lost or mismatched OWNER password.  Re-hashes with the
  current pepper, clears stale lockouts, revokes active sessions, marks
  `must_change=True`, writes a `CRITICAL` audit-log entry.
- **`python -m auth.bootstrap diagnose-login --email <e>`** — explains in
  plain English why a login is failing.  Detects:
  * pepper drift between hash-time and verify-time
  * password text mismatch (copy-paste errors)
  * account lockout
  * wrong DB / wrong email
  * the secure-cookie + http://localhost gotcha (when password verifies
    but cookies can't stick)
- **`python -m auth.bootstrap db-info`** — snapshot of what the auth
  module sees from the current terminal's env.  Useful for spotting
  env drift between the reset shell and the agent-server shell.
- **`python -m auth.bootstrap gen-password`** — print a single strong
  random password (no DB side effects).
- **Frontend Bearer-header fallback.**  `AuthBoundary` now sends
  `Authorization: Bearer <localStorage access_token>` on `/auth/me`
  and `PATCH /auth/me/state` calls.  Belt-and-braces resilience for
  environments where session cookies can't be set (corporate proxies
  that strip cookies, HTTP-only dev servers, etc.).
- **18 runtime-switchable visual skins** across 3 family tabs
  (Aesthetic / Operator / Management) — 17 skin override files under
  `static/css/skins/` plus the default "Stellar" skin in `main.css` —
  see the README's **Frontend & visual skins** section.
- **Cinematic LoginPage** with canvas particle network, animated
  gradient mesh, RGB-chromatic-split wordmark, status telemetry strip
  — see the README's **Frontend & visual skins** section.
- **Enterprise auth module** under `auth/` — local + OIDC + SAML 2.0
  + SCIM 2.0, TOTP MFA + backup codes, 8 hierarchical roles, RBAC +
  ABAC engine, DB-backed sessions with refresh-token rotation +
  theft detection, append-only audit log with optional hash chain
  + OWNER-only deletion — see the README's **Enterprise authentication** section.
- **Consolidated documentation** — every per-folder README and the two
  knowledge guides folded into sections in the main `README.md`; only
  `README.md`, `CHANGELOG.md`, and `DEPLOYMENT.md` remain as top-level docs.
- **`DEPLOYMENT.md`** — complete deployment guide covering quickstart,
  first-login, env-var reference, Docker, reverse proxy, PostgreSQL,
  SSO setup, compliance mapping, and troubleshooting.

### Fixed
- **Login fails with 401 on `http://localhost` even with correct
  password.**  Root cause: `AUTH_COOKIE_SECURE=true` (the old default)
  caused browsers to silently drop the `argus_session` cookie on HTTP
  pages, so `GET /auth/me` returned 401 immediately after a successful
  `POST /auth/login`.  Fixed via the changed default + the frontend
  Bearer-header fallback.
- `SessionState` was incorrectly keyed by `session_id`, which meant
  the user's UI state (skin, audience mode, pinned engagement) was
  reset on every login.  Now keyed by `user_id`, so state persists
  across sessions and devices.
- `dependencies._extract_access_token` treated cookies as JWTs and
  failed to verify session-id-bearing cookies.  Split into two paths
  (`_resolve_via_jwt` for Bearer headers, `_resolve_via_cookie` for
  the session cookie).  Browser cookie auth now works correctly.
- SQLite "database is locked" deadlock when `LocalAuthProvider`
  audit-logged a failed login attempt — fixed by passing the active
  session to `audit_log()` instead of opening a nested writer.
- Multiple tz-naive vs tz-aware datetime comparison errors when reading
  from SQLite (which strips tzinfo from `DateTime(timezone=True)`
  columns).  Coerced via `_as_aware()` helper at every comparison site.
- Ambiguous `foreign_keys` in `UserRoleAssignment` and `AccountLockout`
  relationships caused SQLAlchemy to refuse to load them.  Explicit
  `foreign_keys=` on the relationship definitions.
- `EmailStr` rejected `.local` / `.test` / `.internal` / `.lan` /
  `.corp` TLDs (per RFC 6761), breaking enterprise intranet email
  addresses.  Replaced with an RFC 5321 structural validator.
- `auth/bootstrap.py` CLI output used Unicode box-drawing characters
  (`─`, `┌`, …) which Windows cp1252 consoles can't render.  All
  CLI strings now use ASCII (`-`, `+`, …).
- `must_change_password=True` was set in the DB on bootstrap and
  password reset but the login response always returned `false`,
  preventing the frontend from prompting the user to rotate.

### Security
- All auth-related state moved to SQLAlchemy + a dedicated DB
  (`argus_auth.db` for SQLite dev, PostgreSQL recommended for prod).
  Operational engagement data in MongoDB is unaffected.
- Refresh tokens rotate on every use; reuse detection triggers OAuth
  2.1 §6.1 family revocation.
- CSRF double-submit cookie pattern enforced on state-changing
  endpoints; `Origin` header optional.
- Argon2id (RFC 9106 §4) for password storage with per-deployment
  HMAC pepper layered on top of per-user salt.
- Audit log is append-only by design.  Deletion requires OWNER role,
  CLI-only, with a CRITICAL audit row written *before* the delete.
  Optional SHA-256 hash chain (`AUTH_AUDIT_HASH_CHAIN=true`) for
  tamper-evidence sufficient for SOX §404 ITGC + PCI 10.5.5.
- **Safety governor** (`knowledge/safety_governor.py`) gates
  destructive operator actions before they run.

### Migration

If you're upgrading from a pre-auth-module ARGUS deployment:

1. **Install the new deps** — `pip install -r requirements.txt` now
   covers everything (auth, RAG, MFA, SSO).  The old
   `auth/requirements.txt` is now a stub pointing at the root file.

2. **Add one line to `agent_server.py`** (already done in this repo):
   ```python
   from auth.integration import install_auth
   install_auth(app)
   ```

3. **First boot** — see [`DEPLOYMENT.md §1`](DEPLOYMENT.md).  The
   easiest path is `python -m auth.bootstrap quickstart`.

4. **Existing operators** — if you set `AUTH_COOKIE_SECURE=true`
   anywhere in your config and you're on HTTP, either remove it or
   change it to `false`.  Otherwise the browser will drop the session
   cookie and login will fail.  See
   [`DEPLOYMENT.md §9`](DEPLOYMENT.md#login-works-in-diagnose-login-but-the-web-ui-401s-every-time).

5. **Existing OWNERs with no MFA factor** — previously you'd have been
   forced to enrol on next login.  Now MFA is opt-in.  To restore
   forced enrolment, set:
   ```
   AUTH_MFA_REQUIRED_FOR=OWNER,PLATFORM_ADMIN
   ```

6. **Existing frontend assets** — bump every JSX `?v=N` query string
   that you customized so users don't run on stale cached JS.

---

## Earlier history

The platform predates this changelog file.  Earlier work is captured in:

- [`docs/superpowers/specs/`](docs/superpowers/specs/) — design specs
- [`docs/superpowers/plans/`](docs/superpowers/plans/) — implementation plans
- Git history
