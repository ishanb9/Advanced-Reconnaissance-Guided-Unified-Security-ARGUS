# Engagement Integrity — Design Spec

> Sub-project #1 of the 2026-06-19 ARGUS enhancement program (order: **1 Integrity → 2 Report → 3 Crestron → 4 AI-engine**).
> Status: approved in brainstorming; pending spec review → writing-plans.

## 1. Problem

Two field-observed failures make ARGUS's output untrustworthy, plus a dead-weight meta-agent cluster and a missing findings quality-gate.

1. **Phantom loot / prior-engagement context bleed.** In run `20260618-191247` (target `192.168.40.38`) the operator's compacted engagement-state carried a *different earlier engagement's* findings (Tridium Niagara / Fox 1911, CVE-2017-16744/48, credential spray). The Red-Team Expert then broadcast them as **current** progress (`mission_phase: "Initial Access — Niagara Fox banner captured"`, `progress 22%`) although this run never touched a Niagara device. Vector: intel seeded at run start (`master_agent.py` checkpoint merge `self._intel.update(cp.get("intel_snapshot", {}))`) → operator transcript → summarized into `"ENGAGEMENT STATE SO FAR (compacted)"` (`operator_core.py:2984`) → Expert synthesis (`expert_agent.py:207`). `_add_loot` (`operator_core.py:1287`) does no origin check and no dedup.

2. **Unsurfaced infrastructure blocker.** In the same run the VPN tunnel `tun0` was DOWN / NO-CARRIER — every packet to `192.168.40.0/24` returned *"Network is unreachable."* ARGUS *diagnosed it correctly* but kept launching doomed subagents for ~145s (30% tool-error rate, 0 findings) and never told the operator — the human had to cancel. No connectivity gate, no circuit-breaker on "network unreachable."

3. **Dead meta-agents.** Under the default operator engine, only **Error Analyzer** and **Red-Team Expert** run. **Master Checker** and **Issue Validator** are force-nulled (`master_agent.py:986-988`, in-code comment: "DEAD WEIGHT … they never fire").

4. **No findings quality-gate.** The findings→report path has *zero* validation: the operator's `_store_finding_safe` takes an optional, never-checked `evidence` arg (`operator_core.py:1253-1277`); `db.store_finding` persists whatever it is handed; `base_subagent.store_finding` (`base_subagent.py:1231`) raw-inserts with **no dedup**; `get_findings` (`mongo_client.py:843`) applies no predicate; `report/generator.py:_build_context` renders every row. `verified` is written `False` and never read. An LLM-declared "Critical" with empty tool output ships into the PDF.

## 2. Goals / Non-goals

**Goals**
- No evidence (finding/loot/flag/progress) from another engagement is ever recorded or presented as current. Hard per-(session+target) isolation.
- A target that is unreachable raises a prominent blocker and **pauses for the human** instead of burning the run; a run that ends under a blocker reports the blocker as its outcome, not "0 findings — complete."
- Loot/credentials/flags are recorded only when backed by a concrete current-session observation, and deduplicated.
- Remove the dead **Master Checker** from backend + GUI.
- Rebuild **Issue Validator** into a real gate: faulty findings (ungrounded / phantom / wrong-severity / duplicate) are **kept internally (flag + downgrade + audit) but excluded from the report**.

**Non-goals**
- Re-architecting the shared-by-reference `self._intel` object (too invasive; rejected approach B).
- Touching cross-session *learning* (RAG / lesson-distiller) — that legitimately persists and is never presented as current evidence.
- Plan-auditing capability (Master Checker's function) — not requested, no consumer under the operator.
- The Report Overhaul, Crestron, and AI-engine sub-projects (separate specs).

## 3. Hard constraints (apply to every component)

- **Additive only / no regression.** When the target is reachable and nothing bled, behavior is byte-for-byte unchanged. Every new behavior is guarded by an env toggle, default-on, revertible.
- **Engine modules carry zero hardcoded vuln content** (guarded by `test_no_hardcoded_attack_content`). Connectivity markers ("Network is unreachable", "100% packet loss", route-down) are *network diagnostics*, not vuln/attack content — keep them in a clearly-labelled network-diagnostic constant.
- **Harness:** `python -X utf8 agents/test_architecture_integration.py` (not pytest) must stay green; every component adds guard tests registered in `main()`.
- **Frontend:** edits to `static/js/**` must pass `babel`; bump the relevant cache-bust `?v=` in `templates/index.html`.
- **Delivery:** edits are made on Windows and copied manually to Kali; every response ends with the edited-file list. Do not commit unless asked.

## 4. Components

### A. Evidence provenance + scrub-on-seed + boundary filters

**A1 — Origin stamp.** Add `OperatorCore._engagement_origin()` → `{"session_id": self._session_id, "target": self._intel.get("target_host") or self._intel.get("target")}`, and a mirror on `MasterAgent`. Stamp `_origin` onto every evidence item at record time: loot (`_add_loot`), credential (`_emit_credential`), flag (`submit_flag`), finding (`_record_operator_success` / the store path). Add predicate `_origin_matches(item, current)` → `True` when the item's `_origin` equals the current origin. Items recorded during this run are always stamped with the current origin.

**A2 — Scrub-on-seed.** In `MasterAgent.run()` immediately after intel is seeded (checkpoint restore at `master_agent.py:1055`, engagement_context, operator_notes), call `_scrub_foreign_evidence(self._intel, current_origin)`: drop entries in evidence collections (`loot`, `findings`, carried `open_ports`/`services`, `mission_brief` progress, any carried `engagement_state` text) whose `_origin` ≠ current. Guard the checkpoint merge so an `intel_snapshot` only seeds evidence when the checkpoint's origin == current (session+target): a legitimate **resume** matches and is kept; a foreign engagement is dropped. Cross-session knowledge/lessons are untouched.

**A3 — Boundary filters (present-time).**
- *Operator seed / compaction:* `_maybe_compact` (`operator_core.py:2954`) summary and any "established state" seed are built only from current-origin evidence. Because the transcript is this-run-only and intel is scrubbed at seed, the compaction is naturally clean; add a defensive guard that the seed text excludes foreign-origin items.
- *Expert advisor broadcast:* the Expert synthesizes `mission_phase`/`progress` only from current-origin findings/loot (its input is the scrubbed intel; add a defensive filter on the items it summarizes).
- *Report:* `report/generator._build_context` filters loot/findings/flags to the current session + origin so phantoms never reach the deliverable.

### B. Connectivity blocker gate

Mirrors the existing token-budget gate exactly (`_token_budget_gate` `operator_core.py:1999`, module registry `operator_core.py:131`, `resolve_token_decision` `:152`, `apply_token_decision` `:2064`, loop call `:484`).

- **Pre-flight** (`MasterAgent.run()` before phases, when `ARGUS_PREFLIGHT_REACHABILITY != "0"`): a content-agnostic reachability probe of the resolved target (quick TCP connect to candidate ports + OS route/ping sanity) plus detection of route-down markers (`tun*` NO-CARRIER/linkdown, `Network is unreachable`). On failure → emit `engagement_blocker` (`kind="unreachable"`, detail) + pause.
- **Mid-run circuit-breaker:** a detector `_connectivity_signal(text)` scans each tool result's stdout/stderr for unreachable markers (`Network is unreachable`, `No route to host`, `100% packet loss`, `Connection timed out`, all-ports-filtered). Track consecutive matches; after `ARGUS_BLOCKER_MAX_CONSEC` (default 3) → emit `engagement_blocker` + halt the doomed phase + pause.
- **Human gate:** module-level registry keyed by (session,target); `resolve_blocker_decision(session_id, action, target)` WS entry (`resume` → re-check reachability and continue; `abort` → end honestly); `apply_blocker_decision`. Loop calls `await self._connectivity_gate()` beside `_token_budget_gate()` / `_maybe_pause()`.
- **Toggles:** `ARGUS_CONNECTIVITY_GATE` (default "1"), `ARGUS_PREFLIGHT_REACHABILITY` (default "1"), `ARGUS_BLOCKER_MAX_CONSEC` (default 3).
- **Honest status:** a run that ends under a blocker records the blocker as its outcome ("Engagement halted: target unreachable — VPN/route down"); the report shows the blocker prominently instead of an empty "complete" scan.

### C. Loot rule

In the loot recorders (`_add_loot`, `_emit_credential`, `submit_flag`, `_record_operator_success`): record a loot/credential/flag only when backed by a concrete observation captured **this session** (callers already pass the observation/source — gate on a non-empty current-session source; drop narrative-only assertions). Dedup by fingerprint (reuse `credential_pipeline.fingerprint` for creds; a normalized key for generic loot/flags). Stamp `_origin` (A1).

### D. Remove Master Checker (backend + GUI)

Full removal, done as one atomic change so the module still imports and the legacy fallback (`ARGUS_OPERATOR=0`) still executes phases (it simply loses advisory plan-auditing).

**Backend surfaces** (verify exact lines at implementation time):
- Delete `agents/meta/master_checker_agent.py`.
- `master_agent.py`: remove the `MasterCheckerAgent` import (~line 88), the `self._master_checker` declaration (~343), and the `_op_driver` fork that nulls/constructs it (~986-996) — keeping the Issue-Validator handling that becomes the rebuild.
- `master_agent.py`: remove the `pre_phase_review` / `post_phase_review` call sites + their `if self._master_checker and self._meta_agents_enabled` guards (~4720, 4732, 4997, 5005, 5095, 5120, 5151).
- `reasoning_loop.py`: remove the `mc = getattr(... "_master_checker" ...)` lookup + `mc is not None` guards (~2557, 2580) and the `mc.pre_phase_review` / `mc.post_phase_review` blocks in `_safe_phase` (~2604-2655), preserving the validate-findings block (migrated/removed per E).
- `db/schemas.py`: remove `AgentName.MASTER_CHECKER` (~62) only after confirming no other reader; historical `meta_corrections` with that source must still deserialize (treat unknown source as generic).
- `test_architecture_integration.py`: update/remove the tests asserting `self._master_checker = None` and any Master-Checker construction.

**GUI surfaces:**
- `static/js/components/MetaAgentsPanel.jsx`: delete the `checker` sub-panel (~484-490) and **all** `checkerState` references in the header/totals/status-dot (~315, 319, 323-326, 330, 333, 437-443) and the checker Summary cells (~275-279) — together, or the panel throws on undefined.
- `static/js/store.js`: delete the `metaCheckerState` slice (~211-217), the `META_CHECKER_PHASE_DONE` reducer (~1312-1321), the checker branch in the shared `META_AGENT_*` routing (~1265-1310), and the `meta_checker_pre_phase` / `meta_checker_post_phase` WS dispatch cases (~3527-3533, 3588-3596).
- Keep `CorrectionCard.jsx`, `LiveTerminal`, and `templates/index.html` script tags (still used by Issue-Validator / Error-Analyzer / Expert). Bump cache-bust for `MetaAgentsPanel.jsx` + `store.js`.
- `AgentConsole.jsx` does not list Master Checker — no roster change.

### E. Rebuild Issue Validator (real gate)

Rebuilt **in place** (file + the existing `metaValidatorState` GUI panel stay), to the working Error-Analyzer pattern (`error_analyzer_agent.py`), composing with A (provenance) and C (loot). **Gating policy: exclude from report, keep internally** — a faulty finding is persisted with `verified=False` + `gated_reason`, excluded from the report, and remains visible in the live UI + logs for audit/override.

**E1 — Agent shape.** Convert from `evaluate()`-driven to an event-driven background queue consumer: `ingest_finding(...)` → `asyncio.Queue(maxsize=200)`; long-lived `run()` loop + `_handle` that dedups within a window, fast-paths obvious accept/reject without an LLM call, otherwise calls `think_with_history` with a strict-JSON verdict prompt. Per-session registry (`_GLOBAL_REGISTRY` / `register_validator` / `get_validator` / `unregister_validator`). `_agent_name_str → "issue_validator"`; Correction `source="issue_validator"` so `store.js` routes to `metaValidatorState`.

**E2 — Two enforcement points** (the load-bearing change):
1. **Write-time gate — deterministic, no LLM in the hot path.** Synchronous `validate_finding(finding) → Verdict{grounded, severity_ok, origin_ok, duplicate, reason}` called inside `agents/base_agent.store_finding` (covers the operator/default path) **before** `db.store_finding`; the bypassing `base_subagent.store_finding` raw-insert (`base_subagent.py:1231`) is routed through the same gate. Reuse the existing regex hard-gate `validate_grounding` / `EVIDENCE_PATTERNS` / `FAILURE_PATTERNS` (`agents/reasoning/issue_validator.py`) as the deterministic core. On reject: still persist, but with `verified=False` + `gated_reason` (per policy).
2. **Read-time gate — the backstop.** `get_findings` (`mongo_client.py:843`) gains a `validated_only` predicate (and/or `get_findings_for_report`); `report/generator._build_context` (`:1363`) uses it so ungrounded/phantom/foreign-origin/duplicate findings never render. Validated findings only in the report.

**E3 — Checks (deterministic first, LLM second):** (1) grounding — raw tool output matches evidence patterns for the inferred class and not failure patterns; reject "critical" with empty/errored output; (2) provenance — evidence carries current session+target stamp (A); missing-stamp degrades to "unknown" (not auto-reject) until A lands; (3) dedup — extended `_finding_fingerprint`, including the subagent path; (4) severity sanity — downgrade severity the evidence doesn't support; (5) optional budget-capped LLM pass (like Error Analyzer's 40-call cap) for nuanced false-positive judgment, off the hot path.

**E4 — Lifecycle.** Construct + `register_validator` + background `run()` task next to the Error Analyzer on the **default operator path** (`master_agent.py:2879-2888`); **remove** the `_op_driver → self._issue_validator = None` short-circuit (`master_agent.py:988`). Add `request_stop()` + `unregister_validator(session_id)` to teardown beside the analyzer (~1658-1663).

**E5 — Live broadcast + GUI.** Keep `emit_correction` (`meta_correction` event → `metaValidatorState`). For each reject, also push a Correction onto `master._pending_corrections` (`master_agent.py:346`) — the operator already drains it (`operator_core.py:2544`) and injects it into the transcript, so the operator sees "finding X rejected as ungrounded" live. Emit a `validation_analysis` WS event with accepted/rejected stats (model on `error_analysis`). GUI: the `validator` sub-panel + `metaValidatorState` already exist; add the `validation_analysis → META_VALIDATOR_STATS` dispatch/reducer and wire the existing-but-unfed `meta_validator_tool` / `meta_validator_phase` events to their reducers. Bump cache-bust.

**E6 — Safety rails:** prefer flag+downgrade over hard-delete (done, per policy); log every rejection with the raw evidence; env kill-switch `ARGUS_ISSUE_VALIDATOR` (default "1") mirroring `ARGUS_OPERATOR`; the write-time gate stays deterministic to avoid hot-path latency; `increment_session_stats` still fires only on first insert so the gate's persist-then-flag does not skew counters.

## 5. Data model

- Findings gain `_origin {session_id, target}`, and on reject `verified=False` + `gated_reason` (string). `verified` becomes a **read** field (report + `get_findings(validated_only=...)`).
- Loot/credential/flag items gain `_origin`.
- No schema migration required (additive fields; absent `_origin` treated as "unknown"). `AgentName.MASTER_CHECKER` removed (D) with unknown-source tolerance for historical docs.

## 6. Testing (harness + frontend)

New guard tests in `agents/test_architecture_integration.py`, registered in `main()`:
- A: `_engagement_origin` stamps; `_scrub_foreign_evidence` drops foreign-origin and keeps current; checkpoint merge guarded by origin; report context excludes foreign-origin loot/findings.
- B: `_connectivity_signal` matches each marker and not benign output; `_connectivity_gate` pauses; `resolve_blocker_decision` resume/abort; pre-flight failure raises `engagement_blocker`.
- C: loot dedup; narrative-only loot dropped; current-session loot kept + stamped.
- D: Master Checker import/construction gone; module still imports; legacy fallback under `ARGUS_OPERATOR=0` still runs phases; no `metaCheckerState` references remain (string-grep guard on store.js / MetaAgentsPanel.jsx).
- E: `validate_finding` accepts grounded / rejects ungrounded / phantom / foreign-origin / severity-mismatch / duplicate fixtures; `store_finding` (operator path **and** subagent path) flags ungrounded as `verified=False`; `get_findings(validated_only)` excludes rejected; integration — a faulty operator-declared finding never appears in `_build_context` output; validator started under the operator core + torn down; `meta_correction` + `_pending_corrections` + `validation_analysis` emitted; **false-negative tests** — a genuine RCE / SQLi / credential finding MUST pass the gate.
- Regression: `test_no_hardcoded_attack_content` stays green (network markers are diagnostics, not vuln content).

Frontend: `babel` parse for `store.js`, `MetaAgentsPanel.jsx`, `MissionControl.jsx`; cache-bust bumps in `templates/index.html`.

## 7. Files touched (map)

- `agents/operator_agent/operator_core.py` — A1/A3 (origin, compaction filter), B (connectivity gate + registry + resolve), C (loot rule).
- `agents/master_agent.py` — A2 (scrub-on-seed, guarded checkpoint merge, origin mirror), B (pre-flight, honest status), D (Master Checker removal), E4 (Issue Validator lifecycle on default path), E2 (write-time gate in `store_finding`).
- `agents/base_agent.py` — E2 write-time gate choke-point.
- `agents/base_subagent.py` — E2 route raw insert through the gate.
- `agents/meta/issue_validator_agent.py` — E1/E3/E5 rebuild.
- `agents/meta/expert_agent.py` — A3 defensive current-origin filter on broadcast inputs.
- `agents/reasoning/reasoning_loop.py` — D (remove Master Checker hooks; migrate/remove validate block).
- `agents/reasoning/issue_validator.py` — E3 reuse/extend deterministic grounding helpers.
- `agents/credential_pipeline.py` — C dedup fingerprint reuse (read-only or minor extension).
- `db/mongo_client.py` — E2 `get_findings(validated_only)` / `get_findings_for_report`; `verified`/`gated_reason`/`_origin` persistence.
- `db/schemas.py` — D remove `AgentName.MASTER_CHECKER`.
- `report/generator.py` — A3 + E2 report read-path uses validated-only + origin filter.
- `agent_server.py` — WS routes for `engagement_blocker` / `resolve_blocker_decision` and `validation_analysis` (additive).
- `static/js/store.js` — D (remove checker slice/reducers/dispatch), B (`engagement_blocker` + resolve handler), E5 (`META_VALIDATOR_STATS` + wire validator events).
- `static/js/components/MetaAgentsPanel.jsx` — D (remove checker sub-panel), E5 (validator stats cells).
- `static/js/pages/MissionControl.jsx` — B (blocker card).
- `templates/index.html` — cache-bust bumps.
- `agents/test_architecture_integration.py` — all guard tests.

## 8. Rollout / revertibility

All behavior gated by env toggles, default-on: `ARGUS_CONNECTIVITY_GATE`, `ARGUS_PREFLIGHT_REACHABILITY`, `ARGUS_BLOCKER_MAX_CONSEC`, `ARGUS_ISSUE_VALIDATOR`. Setting any to its off value restores prior behavior for that component. Master Checker removal is the only non-toggle change; the legacy fallback continues to run phases without it.

## 9. Risks

- **Over-blocking (highest product risk):** a too-aggressive validator swallows real findings. Mitigated by flag+downgrade (not delete), the read-time report filter as the visible gate, full rejection logging, the kill-switch, and mandatory false-negative tests.
- **Legacy-fallback regression** from Master Checker removal: remove call sites + guards atomically; verify `ARGUS_OPERATOR=0` still marches phases.
- **Hot-path latency:** write-time gate is deterministic only; LLM judgment is async + read-time.
- **Provenance coupling:** the validator's origin check degrades to "unknown ⇒ allow" until A lands, so E can ship independently if needed (but A should land first).
- **Stat skew / enum deserialization:** `increment_session_stats` only on first insert; unknown `AgentName` source tolerated for historical docs.
