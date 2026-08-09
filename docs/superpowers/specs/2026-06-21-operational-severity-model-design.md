# Operational Severity Model — Design

**Goal:** ARGUS assigns finding severity by *what it operationally demonstrated/assessed* (red-team convention), not by raw CVSS. One central, deterministic policy is the single source of truth; severity re-grades in place as evidence accrues; CVSS is retained only as a reference score.

**Status:** approved (brainstorm 2026-06-21). Supersedes the scattered CVSS-band severity logic.

---

## 1. The rubric (operational, outcome-based)

| Tier | Meaning |
|------|---------|
| **Critical** | ARGUS demonstrated **compromise**: root/admin or domain-admin, **or** equivalent catastrophic demonstrated impact — full unauthenticated data exfiltration (`total_data`) or control of an OT/safety system (`ot_control`). |
| **High** | A **public exploit is available** for a confirmed product+version (whether or not ARGUS ran it), **or** ARGUS demonstrated a **partial/non-root foothold**, **or** a **confirmed directly-exploitable** weakness (no public exploit needed, e.g. anonymous data-store) that is not catastrophic. Definite risk, high chaining probability. |
| **Medium** | A **confirmed** weakness with **no** applicable public exploit and not directly exploitable alone, **but chainable** with other vulns/misconfigs. (Also: a public exploit exists for the product but the vulnerable **version is unconfirmed**.) |
| **Low** | A confirmed minor issue / information leak — not directly exploitable, weak/remote chaining value, useful mainly for recon. |
| **Info** | Bare detection / harmless information — attack surface, not exploitable. (`inherent_risk` metadata still drives prioritisation.) |

Evaluation is **top-down, first match wins** — a finding lands at the highest tier its evidence justifies.

## 2. Evidence signal contract

Every finding carries `signals` (stored in `extra.severity_signals`), all derived from data ARGUS already produces:

| Signal | Type | Source |
|--------|------|--------|
| `compromise` | `none\|foothold\|user_rce\|root_admin\|domain_admin\|total_data\|ot_control` | operator compromise-state, shell_agent, loot/flag hunter |
| `exploit_available` | bool | KEV / ExploitDB / GitHub-PoC / searchsploit (matched to confirmed version) |
| `version_confirmed` | bool (default true) | the CVE/version match |
| `confirmed` | bool | the probe/subagent that proved a real weakness |
| `directly_exploitable` | bool | confirmed no-auth/anon/misconfig |
| `chainable` | bool | finding class (auth/cred/info-leak/misconfig) **or** AttackGraph path membership |
| `info_leak_only` | bool | recon/fingerprint classes |
| `detection_only` | bool | capability/skill detections |
| `inherent_risk` | str | prioritisation only — never affects severity |
| `cvss_base` | float | reference only |

## 3. The policy engine — `knowledge/severity_policy.py`

Pure, dependency-free. `grade(signals) -> {severity, rationale, evidence_tag, factors}`:

- `severity` ∈ critical/high/medium/low/info
- `rationale` — one human-readable line (so the report always explains *why*)
- `evidence_tag` ∈ DEMONSTRATED / CONFIRMED / PUBLIC-EXPLOIT / OBSERVED (replaces the misleading "VERIFIED" badge)
- `factors` — the signals that drove the decision (audit trail)

`merge_signals(old, new)` — additive merge (compromise takes the strongest level) used by re-grade.

## 4. Integration — `store_finding(signals=…)`

`store_finding` is the single chokepoint. When a caller passes `signals`, the policy computes the headline severity and **overrides** the `severity` argument; `severity_signals` + `severity_rationale` + `evidence_tag` are stored in `extra`. When `signals` is absent, behaviour is unchanged (legacy callers unaffected — safe, incremental migration). CVSS is still computed (with the INFO-cap fix) and stored as a reference number; it never drives the headline severity.

## 5. Dynamic re-grade

`regrade_findings_for_host(host, new_signals, match, reason)` (base_agent) + `regrade_finding(id, …)` (mongo_client):
- Triggered by evidence events: **compromise reached** (foothold→root, domain-admin, total-data, OT-control), **exploit-availability confirmed**, **attack-graph path discovered**.
- Reads the host's findings, matches by `(host, cve)` then `(host, port, service)`, merges the new signal into the stored `severity_signals`, re-runs `grade()`, and if the severity changed: updates the DB record + emits a `finding_regraded` WS event + appends to the rationale.
- Deterministic recompute from merged signals → order-independent, escalates as evidence accrues, never flaps.

## 6. Call-site migration

| Site | Signals passed |
|------|----------------|
| capability/skill detections (master) | `detection_only=true`, `inherent_risk=<class>` → Info |
| `cve_lookup_subagent` | `confirmed`, `exploit_available`, `version_confirmed` → High / Medium (replaces "any CVSS-9 = Critical") |
| `service_banner_subagent` (no-auth/anon/null) | `confirmed`, `directly_exploitable`, impact (`total_data` for full dump) → Critical/High |
| `exploit_agent` (shell/foothold) | `compromise=root_admin\|foothold` → Critical/High **and** fires a re-grade of the enabling vuln finding |
| cloud-enum verified access | `confirmed`, impact |
| `web_fingerprint` (WAF/CMS) | `info_leak_only`/`detection_only` |

Legacy `severity=` still honoured where signals are not yet wired.

## 7. Report

- Overall-risk rollup = highest **operational** severity present (any Critical now genuinely means demonstrated compromise).
- The "VERIFIED" badge → the `evidence_tag` (DEMONSTRATED / CONFIRMED / PUBLIC-EXPLOIT / OBSERVED).
- Each finding shows: operational severity + one-line rationale + CVSS reference score.

## 8. Testing

- Table-driven unit tests on `grade()` for all 5 tiers + both edge cases (directly-exploitable-no-exploit; exploit-exists-version-unconfirmed).
- Re-grade test: a finding at High (exploit_available) escalates to Critical when `compromise=root_admin` arrives.
- Per-call-site tests produce the expected tier for representative inputs.
- Harness stays `RESULT: PASS`; the detection→INFO tests remain green.
