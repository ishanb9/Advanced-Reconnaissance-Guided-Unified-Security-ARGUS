# CIDR Parallel Triage → Prioritized Exploit + Per-Host Visibility — Design

**Goal:** When ARGUS scans a multi-host subnet, cover **every** live host (not just the
first 5), then deep-dive and exploit the most promising ones — and let the operator
**see and drill into each host** in Mission Control.

**Architecture:** A two-phase CIDR orchestration (breadth-first triage of all hosts in
parallel → prioritized, bounded, hand-off-on-no-progress deep exploitation), plus a
Mission Control overview grid with per-host drill-down. Both are **additive** and the
multi-host change is revertible via an env flag; single-IP and single-host paths are
untouched.

**Tech stack:** Python (`agents/cidr_orchestrator.py`, `agents/master_agent.py`), the
existing per-host host-tagged WebSocket broadcast, React/Redux frontend
(`static/js/store.js`, `static/js/pages/MissionControl.jsx`), the no-pytest harness
`agents/test_architecture_integration.py`.

---

## 1. Problem (observed)

Run `20260616-175258` against a ~14-host subnet: only 5 hosts (`.1, .4, .13, .8, .2`)
were ever worked; the other ~9 never started. Root cause —
`CIDROrchestrator.run()` uses `asyncio.Semaphore(max_parallel_hosts=5)` and each
`_run_host()` runs a **full** `master.run()` to completion before releasing its slot.
A full per-host engagement runs 70+ min (progress-gated budget keeps it going), so 5
slots stay occupied for the whole window and the remaining hosts queue forever. It is
depth-first on 5 hosts, never breadth across all. Separately, Mission Control's
per-host view is incomplete — only the attack-phase panel is host-scoped; there is no
multi-host overview and no full per-host drill-down.

## 2. Cardinal constraint

**Do not break existing, working functionality.** Specifically:
- Single-IP fast path (`CIDROrchestrator.run()` `len(candidates) == 1`) — unchanged.
- Single-host scans (`SessionMode.SINGLE`, which bypass the orchestrator) — unchanged.
- The new two-phase multi-host flow is the default but is gated by
  `ARGUS_CIDR_TWO_PHASE` (default `"1"`); setting it to `"0"` reverts to today's
  single-phase semaphore model exactly.
- Engine modules stay free of hardcoded vuln content (CVE ids / product / payload
  literals) — the promise score uses only generic port/service/CVE-count signals.
- Harness `python -X utf8 agents/test_architecture_integration.py` stays green; each
  change gets a guard assertion.

---

## 3. Component A — Two-phase orchestration (`agents/cidr_orchestrator.py`)

Replaces the multi-host body of `run()` (Step 4) with a two-phase flow when
`ARGUS_CIDR_TWO_PHASE != "0"`. Discovery (Steps 1–3) and the single-IP fast path are
unchanged.

### 3.1 Phase A — Triage (breadth, high parallelism)

- For **every** live host, run a recon-only engagement
  `master.run(session_id, host, phases=<TRIAGE_PHASES>, **kwargs)` through a
  `triage_parallel` semaphore.
  - `TRIAGE_PHASES = ["recon"]` (recon/scan/fingerprint) — reuses the existing recon
    pipeline, so triage quality == today's recon quality; no new recon code.
  - `triage_parallel = max(1, int(os.environ.get("ARGUS_CIDR_TRIAGE_PARALLEL", "8")))`.
  - Per-host triage wall-clock cap `ARGUS_CIDR_TRIAGE_TIMEOUT_SEC` (default 300) via
    `asyncio.wait_for`; on timeout the host is still triaged with whatever intel exists.
- After each host's triage, compute a **promise score** (`_score_host(intel) -> float`):
  generic, content-agnostic signal sum — count of open ports, presence of high-value
  service classes (web / SMB / SSH / RDP / DB / admin panels), number of version→CVE
  leads in intel, and presence of an auth surface. No CVE/product/payload literals.
- Emit `host_triage_complete` (host_id-tagged) per host with
  `{host, open_ports, services, os_guess, promise_score, surface_summary}` so the UI
  grid fills immediately. Persist score/surface on the discovered-host record
  (`db.update_discovered_host` or equivalent; add the helper if absent).
- Triage failures never block the batch (return a zero-score triaged record).

### 3.2 Phase B — Exploit (prioritized depth, bounded + hand-off)

- Rank triaged hosts by `promise_score` desc (stable tiebreak on host).
- Dispatch full `master.run()` engagements through an `exploit_parallel` semaphore
  (`ARGUS_CIDR_EXPLOIT_PARALLEL`, default 3), **in ranked order**, so the highest-promise
  hosts start first and slots recycle to the next-ranked pending host as they free.
- **Hand-off on no progress:** each host's engagement ends (freeing its slot) when it
  finishes naturally, OR when the operator's existing progress-gated budget expires for
  a host making no real progress. To guarantee slots recycle in multi-host depth, pass a
  bounded per-host depth budget `ARGUS_CIDR_EXPLOIT_HOST_SEC` (default 1800). This threads
  through as an additive `max_seconds` kwarg on `master.run()` forwarded to
  `OperatorCore(max_seconds=...)` (which today only reads the env default) — the operator
  already treats that budget as ADVISORY once real progress (foothold/cred/flag) exists,
  so a *succeeding* host is never cut, but a *stalled* host releases its slot. Reuses
  `OperatorCore`'s `_has_progress_signal`-gated budget; no new budget logic.
- Emit existing host-tagged `host_scan_start` / phase / finding / `host_scan_complete`
  events so the UI tracks each host's status. Add a `host_status` field progression
  (`triaging → queued → exploiting → foothold → done`) surfaced via the existing
  host-tagged events (no new event type required beyond `host_triage_complete`).

### 3.3 Reuse & isolation

- `_make_host_broadcast(host)`, per-host `master.run()`, `_active_masters`, pause/stop,
  and resume-skip (`hosts_completed`) are reused unchanged.
- New helpers are small and isolated: `_triage_host(host, sem)`, `_score_host(intel)`,
  `_run_two_phase(pending_hosts)`. The old single-phase body is kept as
  `_run_single_phase(pending_hosts)` for the `ARGUS_CIDR_TWO_PHASE=0` fallback.

---

## 4. Component B — Per-host overview grid + drill-down (UI)

### 4.1 Store (`static/js/store.js`)

- ADD a richer per-host map `hostData[host] = { status, score, phase, hypothesis, steps,
  findings, toolLines, creds, ports, services }` ALONGSIDE the existing `hostPlans` map
  (do NOT remove `hostPlans`; the attack-phase panel keeps reading it, so that working
  fix is untouched — `hostData` carries the additional per-host detail).
- New reducer `HOST_DATA_UPDATE` merges per-host fields. WS routing dispatches it (in
  addition to the existing global dispatches, so single-host is unchanged) when an event
  carries `msg.host_id`, for: `host_triage_complete` (score/ports/services/status),
  phase events (phase/status), findings (bucket by `finding.host || msg.host_id`), and
  tool/agent output lines (bucket by `host_id`).
- Discovered-host records gain `score` + `status` from `host_triage_complete`.

### 4.2 Mission Control (`static/js/pages/MissionControl.jsx`)

- **Overview grid** (rendered when multi-host and no host is drilled in): one card per
  `discoveredHosts` entry — IP, status badge, current phase, findings count + severity
  dots, promise score, 🚩/🔓 indicators — sorted by score desc. Clicking a card sets
  `hostFilter` (drill in).
- **Drill-down** (when `hostFilter` set): the detail view scopes to that host. Extend the
  host-aware selection already added for the attack-phase panel to ALSO scope findings,
  tool/terminal output, agents, and credentials, reading `hostData[hostFilter]`. A
  "← All hosts" control clears `hostFilter` back to the grid.
- "ALL" / single-host scans keep today's global view unchanged.

### 4.3 Cache-bust

Bump `store.js` and `MissionControl.jsx` versions in `templates/index.html`; update the
corresponding test pins.

---

## 5. Data flow

```
discover live hosts
   │
   ├─ Phase A: triage_parallel × _triage_host(h)  ──emit host_triage_complete(host_id)──▶ store hostData[h].{score,ports,services,status=triaged}  ──▶ grid card
   │            └─ _score_host(intel) → promise_score
   │
   └─ rank by score desc
        │
        └─ Phase B: exploit_parallel × master.run(h, bounded depth)
                     └─ host-tagged phase/finding/foothold events ──▶ store hostData[h].{phase,findings,status} ──▶ grid + drill-down
```

## 6. Error handling

- Triage timeout/exception → host triaged with score 0, batch continues.
- Depth engagement error → slot released via existing `try/finally`; next-ranked host runs.
- No live hosts / single IP → existing behavior.
- `ARGUS_CIDR_TWO_PHASE=0` → exact old single-phase semaphore path.
- UI: a host with no `hostData` yet renders a "queued / awaiting triage" card; drill-down
  on an un-triaged host shows "awaiting this host's data".

## 7. Testing (harness guards)

- Orchestrator: `_run_two_phase` / `_triage_host` / `_score_host` exist; ranked dispatch;
  bounded `exploit_parallel`; env toggles (`ARGUS_CIDR_TWO_PHASE`, `*_TRIAGE_PARALLEL`,
  `*_EXPLOIT_PARALLEL`, `*_EXPLOIT_HOST_SEC`); single-phase fallback retained.
- `_score_host` behavioral: more ports / high-value services / CVE leads → higher score;
  empty intel → 0; no CVE/product/payload literals (guard-clean).
- Store: `hostData` + `HOST_DATA_UPDATE`; per-host bucketing of triage/findings/phase.
- MissionControl: host grid renders; drill-down scopes findings/tools/agents to host;
  "← All hosts" control present.
- Cache-bust pins updated; full harness green; `test_no_hardcoded_attack_content` green.

## 8. Out of scope (improvise later, per operator)

- Cross-host correlation / lateral pivoting between subnet hosts.
- Adaptive re-triage (re-scoring hosts mid-run).
- Per-host token budget UI in the grid (the token-budget modal already covers per-target).
- Gantt/timeline across hosts.
