# CIDR Parallel Triage → Prioritized Exploit + Per-Host Visibility — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a multi-host/CIDR scan triage *every* live host in parallel, then exploit them in promise-rank order with bounded concurrency and hand-off when a host stalls — and give Mission Control a per-host overview grid + drill-down.

**Architecture:** Two-phase `CIDROrchestrator` (Phase A: recon-only triage of all hosts via a high-concurrency semaphore + a content-agnostic promise score; Phase B: full `master.run()` on ranked hosts via a small semaphore, each bounded by the operator's existing progress-gated `max_seconds` so stalled hosts release their slot). Frontend gains a `hostData` per-host store map and an overview-grid/drill-down in Mission Control. All additive; the two-phase path is revertible via `ARGUS_CIDR_TWO_PHASE=0`; single-IP and single-host paths are untouched.

**Tech Stack:** Python (`agents/cidr_orchestrator.py`, `agents/master_agent.py`, `agents/operator_agent/operator_core.py`, `db/mongo_client.py`), React/Redux (`static/js/store.js`, `static/js/pages/MissionControl.jsx`), harness `agents/test_architecture_integration.py`.

---

## Conventions for THIS repo (read first)

- **Tests are NOT pytest.** They live in `agents/test_architecture_integration.py` as plain functions using `_section(...)` + `_assert(cond, label, detail="")`, and are registered in `main()`'s `tests=[...]` list. "Run the test" always means:
  `python -X utf8 agents/test_architecture_integration.py` (expects final line `RESULT: PASS`).
- A failing new test means: add the test function + register it, run the harness, and confirm it reports the new assertion as `[FAIL]` *before* implementing.
- **Commits are optional** in this repo's manual-copy workflow (files are copied to the Kali box by hand). Commit steps are included for the subagent-driven flow; if not committing, at minimum keep the harness green after each task.
- **Guard:** never add CVE-id / product / payload literals to engine modules — `test_no_hardcoded_attack_content` scans for them. The promise score uses only generic port/service/CVE-count signals.

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `agents/cidr_orchestrator.py` | Multi-host orchestration | Add `_score_host`, `_triage_host`, `_run_two_phase`, `_run_single_phase`; branch `run()` Step 4 on `ARGUS_CIDR_TWO_PHASE` |
| `agents/master_agent.py` | Per-host engagement entry | Add `max_seconds` kwarg to `run()`, forward to `OperatorCore` |
| `agents/operator_agent/operator_core.py` | (no change) | Already accepts `max_seconds`; verify only |
| `db/mongo_client.py` | Session/host persistence | Add `set_host_triage(session_id, host, score, status, surface)` |
| `static/js/store.js` | Redux state | Add `hostData` + `HOST_DATA_UPDATE` + WS routing for `host_triage_complete` + per-host bucketing |
| `static/js/pages/MissionControl.jsx` | Mission Control UI | Host overview grid + drill-down scoping |
| `templates/index.html` | Asset cache-bust | Bump `store.js`, `MissionControl.jsx` |
| `agents/test_architecture_integration.py` | Harness | Guard tests + pin updates |

---

### Task 1: Promise score (`_score_host`)

**Files:**
- Modify: `agents/cidr_orchestrator.py` (add method to `CIDROrchestrator`)
- Test: `agents/test_architecture_integration.py`

- [ ] **Step 1: Write the failing test** — add before `def main()`:

```python
def test_cidr_promise_score():
    _section("Test — CIDR triage promise score (generic, content-agnostic ranking)")
    from agents.cidr_orchestrator import CIDROrchestrator
    async def _bc(_m): pass
    orc = CIDROrchestrator(session_id="s", target_input="10.0.0.0/24",
                           broadcast=_bc, session_kwargs={})
    empty = orc._score_host({})
    web   = orc._score_host({"open_ports": [80, 443],
                             "services": {"80": {"service": "http"}, "443": {"service": "https"}}})
    rich  = orc._score_host({"open_ports": [22, 80, 445, 3306],
                             "services": {"445": {"service": "smb"}, "3306": {"service": "mysql"},
                                          "80": {"service": "http"}, "22": {"service": "ssh"}},
                             "cves": [{"cve": "x"}, {"cve": "y"}]})
    _assert(empty == 0.0, "a host with no surface scores 0")
    _assert(rich > web > 0, "more ports + high-value services + CVE leads → strictly higher score")
    _assert(isinstance(web, float), "score is a float")
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -X utf8 agents/test_architecture_integration.py`
(register it first — see Step 5; expected `[FAIL] ... AttributeError: ... _score_host` until implemented)

- [ ] **Step 3: Implement** — add to `CIDROrchestrator` (e.g. just after `_make_host_broadcast`):

```python
    # ── Triage scoring ──────────────────────────────────────────────────────────
    def _score_host(self, intel: dict) -> float:
        """Content-agnostic 'promise' score for ranking which host to exploit first.

        Derived ONLY from generic surface signals (open-port count, high-value
        service CLASSES, count of version→CVE leads, presence of an auth surface) —
        never from any CVE id / product / payload literal, so the engine stays
        clean against the no-hardcoded-content guard.  Higher = more promising."""
        if not isinstance(intel, dict):
            return 0.0
        ports = intel.get("open_ports") or []
        services = intel.get("services") or {}
        score = 0.0
        # Each open port is a little signal.
        score += 1.0 * len(ports) if isinstance(ports, (list, tuple)) else 0.0
        # High-value service CLASSES (generic — not products).
        _HIGH_VALUE = ("http", "https", "smb", "ssh", "rdp", "ftp", "mysql",
                       "postgres", "mssql", "mongodb", "redis", "ldap", "vnc", "telnet")
        svc_blob = " ".join(
            str((v.get("service") if isinstance(v, dict) else v) or "").lower()
            for v in (services.values() if isinstance(services, dict) else [])
        )
        for cls in _HIGH_VALUE:
            if cls in svc_blob:
                score += 2.0
        # Version→CVE leads already correlated in intel.
        cves = intel.get("cves") or []
        score += 1.5 * len(cves) if isinstance(cves, (list, tuple)) else 0.0
        # An auth/login surface is worth probing.
        if intel.get("login_pages") or "login" in svc_blob:
            score += 1.0
        return float(round(score, 2))
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -X utf8 agents/test_architecture_integration.py` → `RESULT: PASS`

- [ ] **Step 5: Register the test** — in `main()`'s `tests=[...]` add `test_cidr_promise_score,` (with the others added in later tasks).

- [ ] **Step 6: Commit (optional)**

```bash
git add agents/cidr_orchestrator.py agents/test_architecture_integration.py
git commit -m "feat(cidr): content-agnostic per-host promise score for triage ranking"
```

---

### Task 2: Thread a per-host depth budget (`max_seconds`) through `master.run()`

**Files:**
- Modify: `agents/master_agent.py` (the `run()` signature + the `OperatorCore(...)` construction)
- Test: `agents/test_architecture_integration.py`

Context: `OperatorCore.__init__` already accepts `max_seconds`; `master.run()` does not forward it. Phase B needs to pass a bounded per-host depth budget so a stalled host releases its slot (the operator already treats it as advisory once real progress exists).

- [ ] **Step 1: Write the failing test**:

```python
def test_master_run_forwards_max_seconds():
    _section("Test — master.run forwards a per-host depth budget to the operator")
    from pathlib import Path as _P
    _ms = (_P(__file__).resolve().parent.parent / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("max_seconds:" in _ms and "max_seconds=" in _ms,
            "master.run accepts max_seconds and forwards it to OperatorCore")
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min(), max_seconds=1800)
    _assert(op.max_seconds == 1800, "OperatorCore honours an explicit max_seconds (depth budget)")
```

- [ ] **Step 2: Run to verify it fails** (`max_seconds=` not yet in master.run).

- [ ] **Step 3: Implement** — in `agents/master_agent.py`, add the kwarg to `run()` (next to `token_budget_per_target`):

```python
        token_budget_per_target: int = 0,            # human-set LLM-token cap for THIS target (0 = unlimited)
        max_seconds: int = 0,                         # per-host depth budget (0 = use operator default)
        **kwargs
```

Store it near the token-budget handling:

```python
        try:
            self._operator_max_seconds = max(0, int(max_seconds or 0))
        except Exception:
            self._operator_max_seconds = 0
```

And at the `OperatorCore(...)` construction, forward it (only when set, so single-host default is unchanged):

```python
                    _op_kwargs = dict(autonomy=autonomy,
                                      token_budget=getattr(self, "_token_budget_per_target", 0))
                    if getattr(self, "_operator_max_seconds", 0) > 0:
                        _op_kwargs["max_seconds"] = self._operator_max_seconds
                    op = OperatorCore(self, **_op_kwargs)
                    self._operator_core_inst = op
```

(Replace the existing `op = OperatorCore(self, autonomy=autonomy, token_budget=...)` line with the block above.)

- [ ] **Step 4: Run to verify it passes** → `RESULT: PASS`

- [ ] **Step 5: Register** `test_master_run_forwards_max_seconds,` in `main()`.

- [ ] **Step 6: Commit (optional)**

```bash
git add agents/master_agent.py agents/test_architecture_integration.py
git commit -m "feat(master): forward per-host depth budget (max_seconds) to OperatorCore"
```

---

### Task 3: Persist per-host triage (`set_host_triage`)

**Files:**
- Modify: `db/mongo_client.py` (add an async helper near `add_discovered_host`)
- Test: `agents/test_architecture_integration.py`

- [ ] **Step 1: Write the failing test** (text-level — DB calls need Mongo, so assert the helper exists + is wired):

```python
def test_db_set_host_triage_exists():
    _section("Test — db.set_host_triage persists per-host triage score/status")
    from pathlib import Path as _P
    _mc = (_P(__file__).resolve().parent.parent / "db" / "mongo_client.py").read_text(encoding="utf-8")
    _assert("async def set_host_triage" in _mc and "promise_score" in _mc,
            "mongo_client exposes set_host_triage with a promise_score field")
    import db.mongo_client as _db
    _assert(callable(getattr(_db, "set_host_triage", None)), "set_host_triage is importable")
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** — in `db/mongo_client.py`, add after `add_discovered_host`:

```python
async def set_host_triage(session_id: str, host: str, promise_score: float,
                          status: str = "triaged", surface: Optional[Dict] = None) -> None:
    """Record a per-host triage result (promise score + status + surface summary)
    on the session's discovered-host list so the UI grid can rank/badge hosts.
    Best-effort; never raises into the orchestrator."""
    db = get_db()
    try:
        await db.sessions.update_one(
            {"_id": session_id, "discovered_hosts.ip": host},
            {"$set": {
                "discovered_hosts.$.promise_score": float(promise_score),
                "discovered_hosts.$.triage_status": status,
                "discovered_hosts.$.surface": surface or {},
            }},
        )
    except Exception as exc:   # noqa: BLE001
        logger.warning("set_host_triage failed for %s/%s: %s", session_id, host, exc)
```

> NOTE: confirm `add_discovered_host` stores hosts as `discovered_hosts: [{ip: ...}]`. If it stores plain strings, first normalise there to `{"ip": host}` (and update any reader) — check `add_discovered_host` and `get_hosts_for_session` before implementing. If the shape differs, adjust the `$set` path to match (e.g. store a parallel `host_triage: {host: {...}}` dict instead). The orchestrator + UI only need score+status keyed by host; pick whichever matches the existing shape.

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Register** `test_db_set_host_triage_exists,`.

- [ ] **Step 6: Commit (optional)**

```bash
git add db/mongo_client.py agents/test_architecture_integration.py
git commit -m "feat(db): set_host_triage — persist per-host promise score + status"
```

---

### Task 4: Two-phase orchestration (triage all → ranked bounded exploit) + fallback

**Files:**
- Modify: `agents/cidr_orchestrator.py` (`run()` Step 4 branch; add `_triage_host`, `_run_two_phase`, `_run_single_phase`)
- Test: `agents/test_architecture_integration.py`

- [ ] **Step 1: Write the failing test**:

```python
def test_cidr_two_phase_orchestration():
    _section("Test — CIDR two-phase triage→ranked-exploit orchestration (+ fallback)")
    from pathlib import Path as _P
    _co = (_P(__file__).resolve().parent.parent / "agents" / "cidr_orchestrator.py").read_text(encoding="utf-8")
    _assert("async def _triage_host" in _co and "async def _run_two_phase" in _co
            and "async def _run_single_phase" in _co,
            "orchestrator has triage + two-phase + single-phase fallback")
    _assert("ARGUS_CIDR_TWO_PHASE" in _co and "ARGUS_CIDR_TRIAGE_PARALLEL" in _co
            and "ARGUS_CIDR_EXPLOIT_PARALLEL" in _co and "ARGUS_CIDR_EXPLOIT_HOST_SEC" in _co,
            "two-phase model + concurrency/budget are env-tunable; reverts via TWO_PHASE=0")
    _assert("host_triage_complete" in _co and "_score_host" in _co,
            "Phase A emits host_triage_complete with the promise score")
    _assert("key=lambda" in _co and "promise_score" in _co and "reverse=True" in _co,
            "Phase B runs hosts in promise-rank (highest first)")
    _assert('phases=["recon"]' in _co or "phases=['recon']" in _co
            or "TRIAGE_PHASES" in _co,
            "triage is recon-only (reuses the recon pipeline, not a full engagement)")
    _assert("max_seconds=" in _co,
            "Phase B passes a bounded per-host depth budget so stalled hosts hand off")
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement.** In `agents/cidr_orchestrator.py`:

(3a) Add the triage runner + two helpers (after `_run_host`):

```python
    # ── Two-phase triage → prioritized exploit ──────────────────────────────────
    TRIAGE_PHASES = ["recon"]

    async def _triage_host(self, host: str, sem: asyncio.Semaphore) -> dict:
        """Phase A: a LIGHT, recon-only pass on one host (bounded by `sem`), so
        EVERY live host gets covered quickly.  Reuses the recon pipeline via
        master.run(phases=recon).  Returns {host, intel, score}; never raises."""
        await self._pause_event.wait()
        async with sem:
            if self._stop:
                return {"host": host, "intel": {}, "score": 0.0}
            timeout = float(os.environ.get("ARGUS_CIDR_TRIAGE_TIMEOUT_SEC", "300"))
            master = MasterAgent(broadcast=self._make_host_broadcast(host))
            self._active_masters.append(master)
            intel = {}
            try:
                kw = dict(self.session_kwargs)
                kw["phases"] = self.TRIAGE_PHASES
                await asyncio.wait_for(
                    master.run(session_id=self.session_id, target=host, **kw),
                    timeout=timeout)
                intel = getattr(master, "_intel", {}) or {}
            except asyncio.TimeoutError:
                intel = getattr(master, "_intel", {}) or {}
            except Exception as exc:   # noqa: BLE001
                logger.warning("[CIDR] triage %s failed: %s", host, exc)
                intel = getattr(master, "_intel", {}) or {}
            finally:
                try:
                    self._active_masters.remove(master)
                except ValueError:
                    pass
            score = self._score_host(intel)
            surface = {"open_ports": intel.get("open_ports") or [],
                       "services": list((intel.get("services") or {}).keys())}
            try:
                await _db.set_host_triage(self.session_id, host, score, "triaged", surface)
            except Exception:
                pass
            await self._emit("host_triage_complete", {
                "host": host, "promise_score": score,
                "open_ports": surface["open_ports"], "services": surface["services"],
                "os_guess": intel.get("os_guess", ""),
                "surface_summary": f"{len(surface['open_ports'])} ports, "
                                   f"{len(surface['services'])} services",
            }, host_id=host)
            return {"host": host, "intel": intel, "score": score}

    async def _run_two_phase(self, pending_hosts: List[str]) -> Dict:
        """Phase A: triage ALL hosts in parallel (high concurrency).  Phase B:
        run full engagements on hosts in promise-rank order through a small
        semaphore, each bounded by a per-host depth budget so a stalled host
        releases its slot to the next-ranked host."""
        triage_parallel = max(1, int(os.environ.get("ARGUS_CIDR_TRIAGE_PARALLEL", "8")))
        exploit_parallel = max(1, int(os.environ.get("ARGUS_CIDR_EXPLOIT_PARALLEL", "3")))
        host_sec = max(0, int(os.environ.get("ARGUS_CIDR_EXPLOIT_HOST_SEC", "1800")))

        # ── Phase A — triage every host ──
        await self._emit("cidr_phase", {"phase": "triage", "hosts": len(pending_hosts),
                                        "message": f"Triaging {len(pending_hosts)} hosts in parallel"})
        tsem = asyncio.Semaphore(triage_parallel)
        triaged = await asyncio.gather(
            *[self._triage_host(h, tsem) for h in pending_hosts],
            return_exceptions=True)
        scored = []
        for r in triaged:
            if isinstance(r, dict):
                scored.append(r)
        # Highest promise first (stable tiebreak on host string).
        scored.sort(key=lambda r: (r.get("score", 0.0), r.get("host", "")), reverse=True)
        ranked_hosts = [r["host"] for r in scored]
        await self._emit("cidr_phase", {
            "phase": "exploit", "hosts": len(ranked_hosts),
            "ranking": [{"host": r["host"], "score": r["score"]} for r in scored],
            "message": f"Exploiting {len(ranked_hosts)} hosts in promise order"})

        # ── Phase B — bounded, ranked deep exploitation with hand-off ──
        esem = asyncio.Semaphore(exploit_parallel)

        async def _deep(host: str) -> Any:
            await self._pause_event.wait()
            async with esem:
                if self._stop:
                    return "stopped"
                await self._emit("host_scan_start",
                                 {"host": host, "message": f"Exploiting {host}"}, host_id=host)
                master = MasterAgent(broadcast=self._make_host_broadcast(host))
                self._active_masters.append(master)
                try:
                    kw = dict(self.session_kwargs)
                    if host_sec > 0:
                        kw["max_seconds"] = host_sec   # progress-gated: only stalls hand off
                    result = await master.run(session_id=self.session_id, target=host, **kw)
                except Exception as exc:   # noqa: BLE001
                    logger.warning("[CIDR] exploit %s failed: %s", host, exc)
                    result = {"error": str(exc)}
                finally:
                    try:
                        self._active_masters.remove(master)
                    except ValueError:
                        pass
                await _db.mark_host_complete(self.session_id, host)
                await self._emit("host_scan_complete",
                                 {"host": host, "message": f"Done {host}"}, host_id=host)
                return result

        # Dispatch in ranked order; the semaphore recycles slots to the next host.
        results = await asyncio.gather(*[_deep(h) for h in ranked_hosts],
                                       return_exceptions=True)
        return {h: (r if not isinstance(r, Exception) else str(r))
                for h, r in zip(ranked_hosts, results)}

    async def _run_single_phase(self, pending_hosts: List[str]) -> Dict:
        """Legacy model (ARGUS_CIDR_TWO_PHASE=0): bounded full engagements, no
        triage/ranking — preserved verbatim as the revert path."""
        semaphore = asyncio.Semaphore(self.max_parallel_hosts)
        results = await asyncio.gather(
            *[self._run_host(h, semaphore) for h in pending_hosts],
            return_exceptions=True)
        return {h: (r if not isinstance(r, Exception) else str(r))
                for h, r in zip(pending_hosts, results)}
```

(3b) Replace the Step-4 body in `run()` (currently lines ~206–223, from `# ── Step 4: Bounded parallel execution ─` through the `return summary`) with:

```python
        # ── Step 4: Execute ───────────────────────────────────────────────────
        two_phase = os.environ.get("ARGUS_CIDR_TWO_PHASE", "1") != "0"
        if two_phase:
            summary = await self._run_two_phase(pending_hosts)
        else:
            summary = await self._run_single_phase(pending_hosts)

        await self._emit("cidr_scan_complete", {
            "hosts_tested": len(summary),
            "message":      f"All {len(summary)} hosts tested",
        })
        return summary
```

- [ ] **Step 4: Run to verify it passes** → `RESULT: PASS`

- [ ] **Step 5: Register** `test_cidr_two_phase_orchestration,`.

- [ ] **Step 6: Commit (optional)**

```bash
git add agents/cidr_orchestrator.py agents/test_architecture_integration.py
git commit -m "feat(cidr): two-phase triage->ranked-exploit with hand-off (revertible)"
```

---

### Task 5: Store — `hostData` map + `HOST_DATA_UPDATE` + WS bucketing

**Files:**
- Modify: `static/js/store.js`
- Test: `agents/test_architecture_integration.py`

- [ ] **Step 1: Write the failing test**:

```python
def test_store_hostdata_bucketing():
    _section("Test — store buckets per-host data (triage/findings/phase) for the grid + drill-down")
    from pathlib import Path as _P
    _sj = (_P(__file__).resolve().parent.parent / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("hostData:" in _sj and "HOST_DATA_UPDATE" in _sj,
            "store has a hostData map + reducer")
    _assert("case 'host_triage_complete'" in _sj,
            "store handles the host_triage_complete event")
    _assert(_sj.count("type: 'HOST_DATA_UPDATE'") >= 3,
            "triage + findings + phase are bucketed per host_id")
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** in `static/js/store.js`:

(5a) State init — next to `hostPlans: {}`:

```javascript
  hostData:          {},        // { host: {status, score, phase, findings, toolLines, creds, ports, services} }
```

(5b) Reducer — next to `HOST_PLAN_UPDATE`:

```javascript
    case 'HOST_DATA_UPDATE': {
      const p = action.payload || {};
      const host = p.host;
      if (!host) return state;
      const prev = state.hostData[host] || { findings: [], toolLines: [] };
      const next = { ...prev };
      if (p.status != null) next.status = p.status;
      if (p.score != null) next.score = p.score;
      if (p.phase) next.phase = p.phase;
      if (Array.isArray(p.ports)) next.ports = p.ports;
      if (Array.isArray(p.services)) next.services = p.services;
      if (p.finding) next.findings = [p.finding, ...(prev.findings || [])].slice(0, 200);
      if (p.toolLine) next.toolLines = [...(prev.toolLines || []), p.toolLine].slice(-400);
      if (p.cred) next.creds = [p.cred, ...(prev.creds || [])].slice(0, 100);
      return { ...state, hostData: { ...state.hostData, [host]: next } };
    }
```

(5c) WS routing — add a `host_triage_complete` case (near `host_scan_start`):

```javascript
    case 'host_triage_complete': {
      const t = data || msg;
      const h = t.host || msg.host_id;
      if (h) {
        dispatch({ type: 'HOST_DATA_UPDATE', payload: {
          host: h, status: 'triaged', score: t.promise_score || 0,
          ports: t.open_ports || [], services: t.services || [] } });
        dispatch({ type: 'FEED_ENTRY', payload: {
          ts, agent: 'orchestrator', eventType: 'host_triage_complete',
          message: `🔭 Triaged ${h} — score ${t.promise_score || 0} (${t.surface_summary || ''})`,
          data: t, host: h } });
      }
      break;
    }
```

(5d) In the existing `phase_change`/`phase_start` host block, also push status+phase to `hostData` (add next to the `HOST_PLAN_UPDATE` dispatch already there):

```javascript
      if (msg.host_id) {
        dispatch({ type: 'HOST_PLAN_UPDATE', payload: {
          host: msg.host_id, phase: normalizePhase(data.phase) } });
        dispatch({ type: 'HOST_DATA_UPDATE', payload: {
          host: msg.host_id, phase: normalizePhase(data.phase), status: 'exploiting' } });
      }
```

(5e) In the finding handler(s), bucket the finding per host. Find where findings dispatch (the handler that computes `findingHost`/`sfHost = finding.host || msg.host_id`) and add alongside the existing dispatch:

```javascript
      if (sfHost) {
        dispatch({ type: 'HOST_DATA_UPDATE', payload: { host: sfHost, finding: finding } });
      }
```

(Use the variable already in scope — `findingHost` at the `subagent_finding`/`finding` case, `sfHost` at the structured-finding case. Apply to whichever finding handlers exist.)

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Register** `test_store_hostdata_bucketing,`.

- [ ] **Step 6: Commit (optional)**

```bash
git add static/js/store.js agents/test_architecture_integration.py
git commit -m "feat(ui-store): per-host hostData bucket (triage/findings/phase) for multi-host view"
```

---

### Task 6: Mission Control — overview grid + drill-down

**Files:**
- Modify: `static/js/pages/MissionControl.jsx`
- Test: `agents/test_architecture_integration.py`

- [ ] **Step 1: Write the failing test**:

```python
def test_missioncontrol_host_grid_and_drilldown():
    _section("Test — Mission Control host overview grid + per-host drill-down")
    from pathlib import Path as _P
    _mc = (_P(__file__).resolve().parent.parent / "static" / "js" / "pages" / "MissionControl.jsx").read_text(encoding="utf-8")
    _assert("function HostOverviewGrid" in _mc and "hostData" in _mc,
            "a multi-host overview grid component reads hostData")
    _assert("promise" in _mc.lower() and "sort" in _mc.lower(),
            "grid cards are sorted by promise score")
    _assert("All hosts" in _mc or "← All" in _mc,
            "a back-to-grid control exists for drill-down")
    _assert("hostFilter" in _mc,
            "drill-down keys off the selected host (hostFilter)")
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** in `static/js/pages/MissionControl.jsx`:

(6a) Add a `HostOverviewGrid` component (near the other small components, e.g. before `function MissionControl`):

```javascript
function HostOverviewGrid({ discoveredHosts, hostData, dispatch }) {
  const hosts = (discoveredHosts || []).map(h => {
    const d = (hostData && hostData[h.ip]) || {};
    return {
      ip: h.ip,
      status: d.status || h.triage_status || h.status || 'queued',
      score: (d.score != null ? d.score : (h.promise_score || 0)),
      phase: d.phase || '',
      findings: (d.findings || []).length || h.findings_count || 0,
      foothold: !!d.foothold,
    };
  }).sort((a, b) => (b.score - a.score) || a.ip.localeCompare(b.ip));
  if (!hosts.length) return null;
  const color = (s) => s === 'exploiting' ? 'var(--cyan)'
                : s === 'foothold' ? 'var(--green)'
                : s === 'done' ? 'var(--text-muted)'
                : s === 'triaged' ? 'var(--amber)' : 'var(--text-dim)';
  return React.createElement('div', {
    style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
             gap: 10, marginBottom: 14 }
  },
    hosts.map(h => React.createElement('div', {
      key: h.ip,
      onClick: () => dispatch({ type: 'SET_HOST_FILTER', payload: h.ip }),
      style: { cursor: 'pointer', borderRadius: 10, padding: '11px 13px',
               background: 'var(--bg-surface)', border: '1px solid var(--border)' }
    },
      React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } },
        React.createElement('span', { style: { fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 12 } }, h.ip),
        React.createElement('span', { style: { fontSize: 9, color: color(h.status), textTransform: 'uppercase', letterSpacing: 0.6 } }, h.status)
      ),
      React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', marginTop: 8, fontSize: 10, color: 'var(--text-muted)' } },
        React.createElement('span', null, `score ${h.score}`),
        React.createElement('span', null, h.phase ? h.phase.toUpperCase() : '—'),
        React.createElement('span', null, `${h.findings} find`)
      ),
      h.foothold && React.createElement('div', { style: { marginTop: 6, fontSize: 10, color: 'var(--green)' } }, '🔓 foothold')
    ))
  );
}
```

(6b) Destructure `hostData` in the `MissionControl` component (next to `hostPlans`):

```javascript
    agentComms, reasoningLog, hostPlans, hostData,
```

(6c) Render the grid + a back control. In the render, where the host selector / attack panel is, gate the grid vs. drill-down on `hostFilter` and whether it's multi-host (`discoveredHosts.length > 1`). Add just below the `HostSelector` render:

```javascript
    // Multi-host overview grid (shown until a host is drilled into).
    (discoveredHosts && discoveredHosts.length > 1 && !hostFilter)
      && React.createElement(HostOverviewGrid, { discoveredHosts, hostData, dispatch }),

    // Back-to-grid control when drilled into a host.
    (discoveredHosts && discoveredHosts.length > 1 && hostFilter)
      && React.createElement('div', {
           onClick: () => dispatch({ type: 'SET_HOST_FILTER', payload: null }),
           style: { cursor: 'pointer', display: 'inline-block', marginBottom: 10, fontSize: 11,
                    color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }
         }, `← All hosts  ·  viewing ${hostFilter}`),
```

(6d) Drill-down scoping for findings/tools (extends the attack-phase scoping already in place). Where findings/tool output are rendered, prefer `hostData[hostFilter]` when `hostFilter` is set. Add near the existing `_viewSteps`/`_viewPhase` derivations:

```javascript
  const _hd = (hostFilter && hostData && hostData[hostFilter]) || null;
  const _viewFindings = _hd ? (_hd.findings || []) : null;   // null = use global findings
  const _viewToolLines = _hd ? (_hd.toolLines || []) : null;
```

Then in the findings list render, use `(_viewFindings || globalFindings)`; in the terminal/tool render, use `(_viewToolLines || focusedLines)` when a host is drilled in. (Apply at the existing findings + tool-output render sites; fall back to the current global arrays when `_hd` is null.)

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Register** `test_missioncontrol_host_grid_and_drilldown,`.

- [ ] **Step 6: Commit (optional)**

```bash
git add static/js/pages/MissionControl.jsx agents/test_architecture_integration.py
git commit -m "feat(ui): multi-host overview grid + per-host drill-down in Mission Control"
```

---

### Task 7: Cache-bust + full validation + file list

**Files:**
- Modify: `templates/index.html`, `agents/test_architecture_integration.py`

- [ ] **Step 1: Bump cache-bust** in `templates/index.html`: `store.js?v=42` → `v=43`, `MissionControl.jsx?v=18` → `v=19`.

- [ ] **Step 2: Update test pins** — in `agents/test_architecture_integration.py` change every `store.js?v=42` → `v=43` and `MissionControl.jsx?v=18` → `v=19` (there are pins around lines 3447, 5620, 5691).

- [ ] **Step 3: Babel-check the JS**

```bash
node -e "const fs=require('fs'),b=require('./static/vendor/babel.min.js');for(const f of ['static/js/store.js','static/js/pages/MissionControl.jsx']){b.transform(fs.readFileSync(f,'utf8'),{presets:['react']});console.log('OK '+f);}"
```
Expected: `OK static/js/store.js` / `OK static/js/pages/MissionControl.jsx`

- [ ] **Step 4: Compile backend**

```bash
python -X utf8 -m py_compile agents/cidr_orchestrator.py agents/master_agent.py db/mongo_client.py
```
Expected: no output (success).

- [ ] **Step 5: Run full harness**

Run: `python -X utf8 agents/test_architecture_integration.py`
Expected: `RESULT: PASS — all assertions green` (count grows by ~6 new tests; `test_no_hardcoded_attack_content` still green).

- [ ] **Step 6: Commit (optional) + produce the file-copy list**

```bash
git add templates/index.html agents/test_architecture_integration.py
git commit -m "chore: cache-bust + regression guards for CIDR two-phase + per-host view"
```

Files to copy to the Kali box:
```
agents/cidr_orchestrator.py
agents/master_agent.py
db/mongo_client.py
static/js/store.js
static/js/pages/MissionControl.jsx
templates/index.html
agents/test_architecture_integration.py
```

---

## Self-Review

**Spec coverage:** Phase A triage (Task 4), promise score (Task 1), Phase B ranked bounded exploit + hand-off (Tasks 2+4), env toggles + single-phase fallback (Task 4), DB persist (Task 3), `hostData` store bucketing (Task 5), overview grid + drill-down (Task 6), cache-bust/guards (Task 7), no-hardcoded-content (Task 1 score is generic). All spec sections map to a task.

**Placeholder scan:** Task 3 contains a "confirm the discovered-host shape" investigation note (not a placeholder — it's a required check with two concrete options). Task 6 step 6d points at "existing findings/tool render sites" — the implementer must locate them; the fallback contract (`_viewFindings || global`) is fully specified. No TBD/TODO.

**Type/name consistency:** `_score_host(intel)->float`, `_triage_host(host, sem)`, `_run_two_phase`/`_run_single_phase`, `set_host_triage(session_id, host, promise_score, status, surface)`, store `HOST_DATA_UPDATE` payload keys (`host/status/score/phase/ports/services/finding/toolLine/cred`), `HostOverviewGrid({discoveredHosts, hostData, dispatch})`, event `host_triage_complete{host, promise_score, open_ports, services, surface_summary}` — consistent across tasks. Env vars: `ARGUS_CIDR_TWO_PHASE`, `ARGUS_CIDR_TRIAGE_PARALLEL`, `ARGUS_CIDR_TRIAGE_TIMEOUT_SEC`, `ARGUS_CIDR_EXPLOIT_PARALLEL`, `ARGUS_CIDR_EXPLOIT_HOST_SEC` — consistent.
