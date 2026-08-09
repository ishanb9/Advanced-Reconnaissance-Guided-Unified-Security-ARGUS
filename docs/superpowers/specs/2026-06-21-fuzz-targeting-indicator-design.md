# Fuzz-Targeting Indicator ("Where to Fuzz") — Design

**Goal:** ARGUS surfaces a transparent, ranked **per-fuzz-surface "novel-bug-likelihood / fuzz-yield"** indicator so the human operator knows where to point the (human-controlled) Fuzzing Lab for the best chance of a *previously-unknown* bug. Grounded in adversarially-verified deep research.

**Status:** approved (brainstorm 2026-06-21).

## Cardinal invariant — side-car, never a dependency
The indicator + Fuzzing Lab are an **additive parallel service**. They MUST NOT gate, block, or change the engagement:
- The scorer is a **pure, read-only** computation over an `intel` snapshot, computed **on demand** (endpoint/UI poll), never inside the engagement loop. No auto-fuzz.
- Engagement **completion / win-conditions / objectives are fuzz-independent**. ARGUS finishes its normal flow whether or not fuzzing ever runs or succeeds.
- **Best-effort everywhere:** any scorer error → empty list; any fuzz run failure/absence → a `fuzz_status` error in the lab only, zero engagement impact.
- If a fuzz run **succeeds**, ARGUS exploits/proves it and reports it (below). If it fails/doesn't run, the report simply has no fuzz findings — nothing is marked incomplete.

## Research guardrails (verified)
USE: fuzzable surface = structured-input handlers (parsers/file-format/protocol-state-machines/deserialization/upload/API); novelty DOMINATED by OSS-vs-proprietary + CVE-history; reachability + input-controllability necessary; memory-unsafe language only a WEAK prior; crash ≠ vuln.
DO NOT (refuted): static call-graph danger-score; directly-reachable-only; sink-function concentration; firmware/version *age* as a 0-day proxy; "old version = more 0-days"; treating generic mainstream web apps as high-novelty. No calibrated formula exists → ship a **transparent heuristic prior**, factors shown, labeled estimated.

## Component 1 — `knowledge/fuzz_targeting.py` (pure)
- `enumerate_surfaces(intel) -> [surface]`: derive fuzz surfaces from existing intel. services/ports → network/ot/iot; web upload/API/endpoints → web/api; skill-registry OT/IoT → protocol. Each: `{host, port, service, surface_type, input_kind, fuzzer_id|None, evidence}`. Maps to a Fuzzing Lab CATALOG fuzzer (or `None` = "manual").
- Curated tables: `_FUZZED_OSS` (OSS-Fuzz roster + hardened daemons), `_NATIVE_HINTS` (likely C/C++), `_SURFACE_BY_SERVICE` (service→surface_type + input_kind).
- `score_surface(surface, *, has_cve=False, in_kev=False) -> {score, tier, factors, rationale}`:
  `fuzz_yield = gate × (0.50·novelty + 0.35·surface_fuzzability + 0.15·mem_unsafe_prior) × 100`
  - `gate` ∈ {0,1}: reachable + input-controllable (else excluded).
  - `novelty` ∈ [0,1]: fuzzed-OSS 0.15 · common 0.40 · unknown/niche 0.70 · OT/IoT/embedded 0.90; +0.10 if complex & no CVE history, −0.15 if heavy KEV/CVE (well-trodden); clamp.
  - `surface_fuzzability` ∈ [0,1]: file-format/upload 0.9 · protocol-state-machine 0.85 · deserialization 0.8 · api 0.6 · generic-web 0.4 · text 0.2.
  - `mem_unsafe_prior` ∈ [0,1] (WEAK): native C/C++ 0.8 · managed 0.3 · unknown 0.5.
  - tiers: High ≥ 60, Medium ≥ 35, Low < 35.
- `rank_targets(intel) -> {targets:[…sorted], by_host:{host:max}}`.

## Component 2 — Backend
- `GET /fuzz/targets?session=` → `rank_targets(scope intel)` using `active_agents[session]` (reuses `scope_for_agent`). Best-effort; `[]` on any error. CVE/KEV per surface from intel.cves + `is_kev`.

## Component 3 — Fuzz hit → exploit → prove → report (parallel, best-effort)
Extend the existing `_fuzz_feedback_for(session)` callback (already records finding + cascade signal): when a hit arrives, ALSO inject a guidance advisory to the operator — *"Fuzzing surfaced &lt;hit&gt; on host:port — reproduce and prove exploitability."* — via the master's guidance queue. ARGUS's operator/exploit path then attempts to prove it; the finding's severity follows the **operational severity policy + dynamic re-grade**: unproven crash/anomaly → Info/Low (crash≠vuln), confirmed → Medium/High, demonstrated compromise → Critical (proof attached). Guidance injection is wrapped best-effort; failure never affects the engagement.

## Component 4 — Frontend
- `FuzzingLabPage`: a **"Where to Fuzz"** panel fetching `/fuzz/targets`; each row = tier badge + score + factor chips + rationale + a **"Fuzz this"** button that pre-fills the config form (tech_type, target, port, fuzzer) for that surface.
- `MissionControl`: compact **"🎯 N high-yield fuzz targets"** badge + a feed event when targets exist. Advisory only.
- store.js: `fuzzTargets` state + fetch; no engagement coupling.

## Component 5 — Testing + self-audit
- Unit: `enumerate_surfaces` shapes; `score_surface` tier boundaries + factor transparency; novelty classifier (fuzzed-OSS→low, OT/IoT/unknown→high); refuted signals absent; prove-pipeline routing + grading (unproven vs proven). 
- **Side-car invariant test**: a scorer/fuzz failure leaves engagement completion/objective evaluation untouched.
- Harness stays `RESULT: PASS`; an adversarial regression self-audit (Workflow) confirms no existing functionality broke.
