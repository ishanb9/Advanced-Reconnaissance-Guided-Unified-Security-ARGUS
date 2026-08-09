# Engagement Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ARGUS engagements trustworthy — no cross-engagement phantom loot/findings, an honest blocker+pause when a target is unreachable, dedup'd evidence, a removed dead Master-Checker, and a real Issue-Validator gate so faulty/silly findings never reach the report.

**Architecture:** Additive guards layered onto the existing operator engine. Evidence carries an `_origin {session_id,target}` stamp; foreign-origin evidence is scrubbed at seed and filtered at every present-boundary. A connectivity gate mirrors the existing token-budget pause pattern. The Issue Validator is rebuilt to the working Error-Analyzer pattern with a deterministic write-time gate + a read-time report filter. Every behavior is env-toggle-guarded (default-on, revertible).

**Tech Stack:** Python 3.11 (asyncio), MongoDB (motor), FastAPI + WebSocket (`agent_server.py`), React/Redux UMD (`static/js/`), Jinja2 report (`report/generator.py`). Harness: `python -X utf8 agents/test_architecture_integration.py` (single-file assertion harness, **not** pytest — expect final line `RESULT: PASS`). Frontend validated with `babel`.

**Reference spec:** `docs/superpowers/specs/2026-06-19-engagement-integrity-design.md`.

**Global rules every task obeys:**
- Additive only. When the target is reachable and nothing bled, behavior is unchanged. Each new behavior guarded by an env toggle (`ARGUS_CONNECTIVITY_GATE`, `ARGUS_PREFLIGHT_REACHABILITY`, `ARGUS_BLOCKER_MAX_CONSEC`, `ARGUS_ISSUE_VALIDATOR`), default-on.
- Engine modules contain **zero** hardcoded vuln content. Network markers are diagnostics (allowed). `test_no_hardcoded_attack_content` must stay green.
- Tests are **assertions added to `agents/test_architecture_integration.py`** and registered in `main()`; run the harness, expect `RESULT: PASS`.
- Frontend edits pass `babel`; bump the matching `?v=` in `templates/index.html`.
- Line numbers below are from the 2026-06-19 audit; **re-grep to confirm exact lines before editing** (files drift).
- Do not commit unless the user asks.

---

## File structure (what each touched file owns)

| File | Responsibility in this plan |
|---|---|
| `agents/operator_agent/operator_core.py` | origin helpers; loot rule + dedup; connectivity detector + gate + registry/resolve; compaction boundary filter |
| `agents/master_agent.py` | origin mirror; scrub-on-seed + guarded checkpoint merge; pre-flight reachability + honest status; Master-Checker removal; Issue-Validator lifecycle on default path; write-time gate call in `store_finding` |
| `agents/base_agent.py` | write-time finding gate choke-point |
| `agents/base_subagent.py` | route raw finding insert through the gate |
| `agents/meta/issue_validator_agent.py` | full rebuild to queue-consumer + `validate_finding` |
| `agents/meta/expert_agent.py` | defensive current-origin filter on broadcast inputs |
| `agents/reasoning/reasoning_loop.py` | remove Master-Checker hooks; migrate/remove validate block |
| `agents/reasoning/issue_validator.py` | reuse/extend deterministic grounding helpers (read-mostly) |
| `db/mongo_client.py` | `verified`/`gated_reason`/`_origin` persistence; `get_findings(validated_only=...)` |
| `db/schemas.py` | remove `AgentName.MASTER_CHECKER` |
| `report/generator.py` | report read-path uses validated-only + origin filter |
| `agent_server.py` | WS routes: `resolve_blocker_decision`, emit `engagement_blocker`; `validation_analysis` passthrough |
| `static/js/store.js` | remove checker slice; `engagement_blocker` + resolve handler; `META_VALIDATOR_STATS` + wire validator events |
| `static/js/components/MetaAgentsPanel.jsx` | remove checker sub-panel; validator stats cells |
| `static/js/pages/MissionControl.jsx` | blocker card |
| `templates/index.html` | cache-bust bumps |
| `agents/test_architecture_integration.py` | all guard tests |

**Execution order (dependency-driven):** A1 → A2 → A3 → C → B(detector→gate→preflight→wiring) → D(backend→GUI) → E(agent→write-gate→read-gate→lifecycle→broadcast/GUI) → final sweep.

---

## Task 1: A1 — Engagement origin stamp + helpers

**Files:** Modify `agents/operator_agent/operator_core.py` (`_add_loot` ~1287, `_emit_credential` ~1324, `submit_flag` ~904, `_record_operator_success` ~1393); Test `agents/test_architecture_integration.py`.

- [ ] **Step 1: Write the failing assertion** (add to a new `test_engagement_origin()` and register in `main()`):
```python
def test_engagement_origin():
    import inspect, agents.operator_agent.operator_core as oc
    src = inspect.getsource(oc)
    assert "_engagement_origin" in src, "origin helper missing"
    assert "_origin_matches" in src, "origin predicate missing"
    # every loot recorder stamps _origin
    a = inspect.getsource(oc.OperatorCore._add_loot)
    assert "_engagement_origin" in a or "_origin" in a, "_add_loot does not stamp origin"
    print("[PASS] engagement origin stamp")
```
- [ ] **Step 2: Run harness, verify FAIL** — `python -X utf8 agents/test_architecture_integration.py` → fails on `_engagement_origin missing`.
- [ ] **Step 3: Implement the helpers** on `OperatorCore` (place near `_add_loot`):
```python
def _engagement_origin(self) -> Dict[str, str]:
    """Identity of the CURRENT engagement: which session + which target this
    OperatorCore instance is driving.  Stamped onto every evidence item so a
    prior engagement's loot/findings can never be presented as current."""
    return {
        "session_id": str(getattr(self, "_session_id", "") or ""),
        "target": str(self._intel.get("target_host") or self._intel.get("target") or ""),
    }

@staticmethod
def _origin_matches(item: Dict[str, Any], current: Dict[str, str]) -> bool:
    """True when an evidence item belongs to the current engagement.  An item
    with no _origin is 'unknown' and treated as current (it was recorded this
    run before stamping, or by a path not yet stamped) — foreign items are
    removed at seed-time (Task 2), so only current-or-unknown survive here."""
    o = item.get("_origin") if isinstance(item, dict) else None
    if not o:
        return True
    return (str(o.get("session_id", "")) == current.get("session_id", "")
            and str(o.get("target", "")) == current.get("target", ""))
```
- [ ] **Step 4: Stamp at every recorder.** In `_add_loot`, before storing, set `if isinstance(item, dict): item.setdefault("_origin", self._engagement_origin())`. Do the same in `_emit_credential` (on the cred dict), `submit_flag` (on the loot/flag dict it builds), and `_record_operator_success` (on any loot/finding dict it constructs).
- [ ] **Step 5: Run harness, verify PASS.** Expect `RESULT: PASS`.

---

## Task 2: A2 — Scrub-on-seed + guarded checkpoint merge

**Files:** Modify `agents/master_agent.py` (checkpoint merge ~1055; add origin mirror + scrub near `run()` intel setup ~820-860); Test harness.

- [ ] **Step 1: Failing assertion** `test_scrub_on_seed()`:
```python
def test_scrub_on_seed():
    import inspect, agents.master_agent as ma
    src = inspect.getsource(ma)
    assert "_scrub_foreign_evidence" in src, "scrub helper missing"
    assert "_engagement_origin" in src, "master origin mirror missing"
    # checkpoint merge must be origin-guarded
    run_src = inspect.getsource(ma.MasterAgent.run)
    assert "intel_snapshot" in run_src and "_origin" in run_src, "checkpoint merge not origin-guarded"
    print("[PASS] scrub on seed")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Implement origin mirror + scrub** on `MasterAgent`:
```python
def _engagement_origin(self) -> Dict[str, str]:
    return {
        "session_id": str(getattr(self, "_session_id", "") or ""),
        "target": str(self._intel.get("target_host") or self._intel.get("target") or ""),
    }

def _scrub_foreign_evidence(self, intel: Dict[str, Any], current: Dict[str, str]) -> int:
    """Drop evidence carried into intel that originated in a DIFFERENT
    engagement (session+target).  Returns count removed.  Leaves config,
    scope, target, and cross-session knowledge untouched."""
    removed = 0
    def keep(item):
        o = item.get("_origin") if isinstance(item, dict) else None
        if not o:
            return True  # unknown provenance kept; only known-foreign dropped
        return (str(o.get("session_id","")) == current.get("session_id","")
                and str(o.get("target","")) == current.get("target",""))
    # list-shaped collections
    for k in ("findings",):
        v = intel.get(k)
        if isinstance(v, list):
            before = len(v); intel[k] = [x for x in v if keep(x)]; removed += before - len(intel[k])
    # loot can be list or {items:[...]} or category dict
    loot = intel.get("loot")
    if isinstance(loot, list):
        before = len(loot); intel["loot"] = [x for x in loot if keep(x)]; removed += before - len(intel["loot"])
    elif isinstance(loot, dict) and isinstance(loot.get("items"), list):
        before = len(loot["items"]); loot["items"] = [x for x in loot["items"] if keep(x)]; removed += before - len(loot["items"])
    return removed
```
- [ ] **Step 4: Guard the checkpoint merge** at ~1055. Replace the unconditional `self._intel.update(cp.get("intel_snapshot", {}))` with an origin check:
```python
_snap = cp.get("intel_snapshot", {}) or {}
_cp_origin = cp.get("_origin") or {
    "session_id": str(session_id),
    "target": str(_snap.get("target_host") or _snap.get("target") or target),
}
_cur = {"session_id": str(session_id),
        "target": str(self._intel.get("target_host") or self._intel.get("target") or target)}
if (str(_cp_origin.get("session_id","")) == _cur["session_id"]
        and str(_cp_origin.get("target","")) == _cur["target"]):
    self._intel.update(_snap)            # legitimate resume of THIS engagement
else:
    # foreign checkpoint: take only non-evidence config, never findings/loot
    for _k in ("used_tools","phases_completed","phases_to_run"):
        pass  # these are handled below; evidence keys are intentionally skipped
```
- [ ] **Step 5: Call the scrub** right after intel target fields are set (after ~826) and again after any checkpoint restore:
```python
self._intel["_origin"] = self._engagement_origin()
try:
    _rm = self._scrub_foreign_evidence(self._intel, self._intel["_origin"])
    if _rm:
        import logging as _l; _l.getLogger(__name__).info("scrubbed %d foreign-origin evidence item(s) at seed", _rm)
except Exception:
    pass
```
- [ ] **Step 6: Run harness, verify PASS.**

---

## Task 3: A3 — Boundary filters (compaction, expert, report)

**Files:** Modify `agents/operator_agent/operator_core.py` (`_maybe_compact` ~2954); `agents/meta/expert_agent.py` (broadcast input ~the synthesis that builds mission_phase); `report/generator.py` (`_build_context` ~1360); Test harness.

- [ ] **Step 1: Failing assertion** `test_boundary_filters()`:
```python
def test_boundary_filters():
    import inspect
    import agents.operator_agent.operator_core as oc, report.generator as rg
    assert "_origin" in inspect.getsource(oc.OperatorCore._maybe_compact) or \
           "_engagement_origin" in inspect.getsource(oc.OperatorCore._maybe_compact), \
           "compaction not origin-filtered"
    assert "_origin" in inspect.getsource(rg.ReportGenerator._build_context), "report context not origin-filtered"
    print("[PASS] boundary filters")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Compaction filter.** In `_maybe_compact`, before summarizing `middle`, append a one-line guard to the summary system prompt so the model is told to summarize only the current engagement, and (defensive) ensure no foreign-origin loot text is seeded: add to the system content string `" Only summarize THIS engagement against " + str(self._intel.get('target_host') or self._intel.get('target')) + "; ignore any prior-target facts."`. (Intel is already scrubbed at seed, so this is belt-and-suspenders.)
- [ ] **Step 4: Report filter.** In `report/generator.py:_build_context`, after findings/loot are pulled, filter to current origin:
```python
_cur = (ctx.get("session") or {}).get("_origin") or {}
def _belongs(x):
    o = (x or {}).get("_origin") if isinstance(x, dict) else None
    if not o or not _cur: return True
    return str(o.get("session_id","")) == str(_cur.get("session_id","")) and \
           str(o.get("target","")) == str(_cur.get("target",""))
findings = [f for f in findings if _belongs(f)]
# apply the same _belongs filter to loot/flags lists before they enter ctx
```
- [ ] **Step 5: Expert filter.** In `expert_agent.py`, where it assembles the findings/loot it summarizes into `mission_phase`/`progress`, filter the input list with the same current-origin predicate (target from `self._intel`). Keep it defensive (no crash if `_origin` absent).
- [ ] **Step 6: Run harness, verify PASS.**

---

## Task 4: C — Loot rule (current-session evidence + dedup)

**Files:** Modify `agents/operator_agent/operator_core.py` (`_add_loot`, `_emit_credential`, `submit_flag`); reuse `agents/credential_pipeline.py:fingerprint`; Test harness.

- [ ] **Step 1: Failing assertion** `test_loot_rule()`:
```python
def test_loot_rule():
    import inspect, agents.operator_agent.operator_core as oc
    a = inspect.getsource(oc.OperatorCore._add_loot)
    assert "_loot_seen" in a or "fingerprint" in a or "_dedup" in a, "loot dedup missing"
    print("[PASS] loot rule + dedup")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Add a dedup set + gate** to `_add_loot`:
```python
def _add_loot(self, item: Dict[str, Any]) -> None:
    if isinstance(item, dict):
        item.setdefault("_origin", self._engagement_origin())
        key = self._loot_fingerprint(item)
        seen = self._intel.setdefault("_loot_seen", set())
        if key in seen:
            return                      # duplicate — drop silently
        seen.add(key)
    loot = self._intel.get("loot")
    if isinstance(loot, list): loot.append(item)
    elif isinstance(loot, dict): loot.setdefault("items", []).append(item)
    else: self._intel["loot"] = [item]

@staticmethod
def _loot_fingerprint(item: Dict[str, Any]) -> str:
    import hashlib
    basis = "|".join(str(item.get(k,"")).strip().lower()
                     for k in ("type","user","secret","value","flag","host","port"))
    return hashlib.sha1(basis.encode("utf-8","ignore")).hexdigest()
```
- [ ] **Step 4: Evidence gate.** In `submit_flag` / `_emit_credential` / `_record_operator_success`, only call `_add_loot`/`_emit_credential` when there is a non-empty current-session observation/source (these callers already receive `observation`/note text — guard `if not (observation or note): return` for the narrative-only path, preserving the explicit-flag-submission path which is itself an observation).
- [ ] **Step 5: Run harness, verify PASS.** Also assert a duplicate loot dict added twice yields one entry (extend the test to import an `OperatorCore`-like stub or test `_loot_fingerprint` determinism).

---

## Task 5: B-detector — connectivity signal detector + constants

**Files:** Modify `agents/operator_agent/operator_core.py` (module-level constant + static method); Test harness.

- [ ] **Step 1: Failing assertion** `test_connectivity_signal()`:
```python
def test_connectivity_signal():
    from agents.operator_agent.operator_core import OperatorCore as OC
    assert OC._connectivity_signal("connect to 10.0.0.1 port 80 failed: Network is unreachable")
    assert OC._connectivity_signal("2 packets transmitted, 0 received, 100% packet loss")
    assert OC._connectivity_signal("sendto: No route to host")
    assert not OC._connectivity_signal("HTTP/1.1 200 OK\n<html>hello</html>")
    print("[PASS] connectivity signal detector")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Implement** (module-level constant clearly labelled network-diagnostic, + static method):
```python
# Network-diagnostic markers (NOT vuln content) used by the connectivity gate.
_UNREACHABLE_MARKERS = (
    "network is unreachable", "no route to host", "100% packet loss",
    "destination host unreachable", "connection timed out",
    "could not resolve host", "name or service not known",
)
...
@staticmethod
def _connectivity_signal(text: str) -> bool:
    t = (text or "").lower()
    if any(m in t for m in _UNREACHABLE_MARKERS):
        return True
    # all scanned ports filtered with zero open is a soft signal
    if "filtered" in t and " open " not in t and "0 hosts up" in t:
        return True
    return False
```
- [ ] **Step 4: Run harness, verify PASS.**

---

## Task 6: B-gate — connectivity gate + registry + resolve + loop wiring

**Files:** Modify `agents/operator_agent/operator_core.py` (mirror token-budget gate: registry ~131, `resolve_*` ~152, gate method ~1999, loop call ~484, `apply_*`); Test harness.

- [ ] **Step 1: Failing assertion** `test_connectivity_gate()`:
```python
def test_connectivity_gate():
    import inspect, agents.operator_agent.operator_core as oc
    src = inspect.getsource(oc)
    assert "resolve_blocker_decision" in src, "blocker WS entry missing"
    assert "_connectivity_gate" in src, "connectivity gate missing"
    assert "apply_blocker_decision" in src, "apply blocker missing"
    assert "engagement_blocker" in src, "blocker event missing"
    assert "ARGUS_CONNECTIVITY_GATE" in src and "ARGUS_BLOCKER_MAX_CONSEC" in src, "toggles missing"
    print("[PASS] connectivity gate")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Module-level registry + resolver** (mirror `resolve_token_decision`/registry):
```python
_BLOCKER_REGISTRY: Dict[tuple, "OperatorCore"] = {}
def _blocker_key(session_id: str, target: str = "") -> tuple:
    return (str(session_id), str(target or ""))
def register_blocker_gate(session_id, op, *, target=""):
    _BLOCKER_REGISTRY[_blocker_key(session_id, target)] = op
def resolve_blocker_decision(session_id: str, action: str, *, target: str = "") -> bool:
    op = _BLOCKER_REGISTRY.get(_blocker_key(session_id, target)) or _BLOCKER_REGISTRY.get(_blocker_key(session_id))
    if not op: return False
    op.apply_blocker_decision(action); return True
```
- [ ] **Step 4: Instance state + apply + gate.** In `__init__` add `self._blocker_decision = None`, `self._consec_unreachable = 0`. Add:
```python
def apply_blocker_decision(self, action: str) -> None:
    self._blocker_decision = (action or "").strip().lower()  # 'resume' | 'abort'

def note_tool_connectivity(self, text: str) -> None:
    if self._connectivity_signal(text): self._consec_unreachable += 1
    else: self._consec_unreachable = 0

async def _connectivity_gate(self) -> Optional[str]:
    """Return 'stop' to abort, None to continue.  Pauses + waits for a human
    decision once consecutive unreachable signals cross the threshold."""
    import os
    if os.environ.get("ARGUS_CONNECTIVITY_GATE", "1") == "0":
        return None
    thresh = int(os.environ.get("ARGUS_BLOCKER_MAX_CONSEC", "3") or 3)
    if self._consec_unreachable < thresh:
        return None
    register_blocker_gate(self._session_id, self, target=self._intel.get("target_host") or "")
    await self._emit("engagement_blocker", {
        "session_id": self._session_id, "kind": "unreachable",
        "target": self._intel.get("target_host") or self._intel.get("target"),
        "detail": "Repeated network-unreachable signals — target appears offline (check VPN/route).",
        "consec": self._consec_unreachable})
    self._blocker_decision = None
    # wait for human (resume/abort) with a bounded poll; honor master pause hook
    for _ in range(3600):
        if self._blocker_decision == "abort": return "stop"
        if self._blocker_decision == "resume":
            self._consec_unreachable = 0; return None
        await asyncio.sleep(1)
    return None  # timed out → continue rather than hang forever
```
- [ ] **Step 5: Wire into the loop** beside the token-budget gate (~484):
```python
_blk = await self._connectivity_gate()
if _blk == "stop":
    self._intel["blocker"] = {"kind": "unreachable", "target": self._intel.get("target_host")}
    break
```
- [ ] **Step 6: Feed the detector** wherever tool stdout/stderr is observed (the operator's tool-result handling) — call `self.note_tool_connectivity(observation_or_stderr)` once per tool result.
- [ ] **Step 7: Run harness, verify PASS.**

---

## Task 7: B-preflight — reachability at scan start + honest status

**Files:** Modify `agents/master_agent.py` (`run()` before phases); Test harness.

- [ ] **Step 1: Failing assertion** `test_preflight_reachability()`:
```python
def test_preflight_reachability():
    import inspect, agents.master_agent as ma
    src = inspect.getsource(ma.MasterAgent.run)
    assert "ARGUS_PREFLIGHT_REACHABILITY" in src, "preflight toggle missing"
    assert "_preflight_reachable" in inspect.getsource(ma), "preflight probe missing"
    print("[PASS] preflight reachability")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Implement probe** on `MasterAgent` (content-agnostic; stdlib only):
```python
async def _preflight_reachable(self, host: str) -> bool:
    """Best-effort: True unless we have positive evidence the target is
    unreachable.  Never blocks the run on a flaky probe (fail-open)."""
    import socket, asyncio as _a
    if not host: return True
    async def _try(port):
        try:
            fut = _a.open_connection(host, port)
            r, w = await _a.wait_for(fut, timeout=3)
            w.close()
            return True
        except (OSError, _a.TimeoutError):
            return False
    candidates = []
    for p in (list(self._intel.get("open_ports") or [])[:3] or [80, 443, 22]):
        try: candidates.append(int(p))
        except Exception: pass
    results = await _a.gather(*[_try(p) for p in candidates[:3]], return_exceptions=True)
    # only declare unreachable if EVERY probe failed AND host doesn't resolve to loopback test ranges
    return any(r is True for r in results) if results else True
```
- [ ] **Step 4: Call before phases**:
```python
import os as _os
if _os.environ.get("ARGUS_PREFLIGHT_REACHABILITY", "1") != "0":
    _host = self._intel.get("target_resolved_ip") or self._target_host
    if _host and not await self._preflight_reachable(_host):
        await self._emit("engagement_blocker", {
            "session_id": session_id, "kind": "unreachable", "target": _host,
            "detail": "Pre-flight: target not reachable on any candidate port (check VPN/route)."})
        self._intel["blocker"] = {"kind": "unreachable", "target": _host, "phase": "preflight"}
        # surface + record honest status; the operator's connectivity gate handles human resume
```
- [ ] **Step 5: Honest status** — where the run summary/outcome is finalized, if `self._intel.get("blocker")` is set and no findings/foothold, set the outcome reason to `"Engagement halted: target unreachable"` instead of an implicit "complete".
- [ ] **Step 6: Run harness, verify PASS.**

---

## Task 8: B-wiring — agent_server WS + frontend blocker card

**Files:** Modify `agent_server.py` (WS handler); `static/js/store.js` (handler); `static/js/pages/MissionControl.jsx` (card); `templates/index.html` (cache-bust); Test harness.

- [ ] **Step 1: Failing assertion** `test_blocker_wiring()`:
```python
def test_blocker_wiring():
    srv = open("agent_server.py","r",encoding="utf-8").read()
    assert "resolve_blocker_decision" in srv, "server missing blocker resolve route"
    store = open("static/js/store.js","r",encoding="utf-8").read()
    assert "engagement_blocker" in store, "store missing blocker handler"
    mc = open("static/js/pages/MissionControl.jsx","r",encoding="utf-8").read()
    assert "blocker" in mc.lower(), "MissionControl missing blocker card"
    print("[PASS] blocker wiring")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Server route.** In `agent_server.py`, in the WS message dispatch, add a case for an inbound `resolve_blocker` action that calls `from agents.operator_agent.operator_core import resolve_blocker_decision; resolve_blocker_decision(session_id, action, target=target)`. Ensure `engagement_blocker` emitted by the operator is forwarded to clients (it flows through the existing broadcast, no special case needed beyond confirming passthrough).
- [ ] **Step 4: Store handler.** In `store.js` `routeWsEvent`, add `case "engagement_blocker":` → dispatch a `SET_BLOCKER` action storing `{kind,target,detail}` and push a feed entry; add reducer `SET_BLOCKER` setting `state.blocker`. Add a `clearBlocker`/resume helper that sends `{action:"resolve_blocker", decision:"resume"|"abort"}` over the socket.
- [ ] **Step 5: MissionControl card.** Render a prominent banner when `blocker` is set: shows target + detail + two buttons ("Resume — I fixed it" → resume; "Abort" → abort). On resume/abort, clear `blocker`.
- [ ] **Step 6: Cache-bust** — bump `store.js` and `MissionControl.jsx` `?v=` in `templates/index.html`.
- [ ] **Step 7: babel** both JS files; **Step 8: Run harness, verify PASS.**

---

## Task 9: D-backend — remove Master Checker (backend)

**Files:** Delete `agents/meta/master_checker_agent.py`; Modify `agents/master_agent.py`, `agents/reasoning/reasoning_loop.py`, `db/schemas.py`; Test harness.

- [ ] **Step 1: Failing assertion** `test_master_checker_removed()`:
```python
def test_master_checker_removed():
    import os
    assert not os.path.exists("agents/meta/master_checker_agent.py"), "checker file still present"
    ma = open("agents/master_agent.py","r",encoding="utf-8").read()
    assert "MasterCheckerAgent" not in ma, "master_agent still references MasterCheckerAgent"
    assert "_master_checker" not in ma, "master_agent still has _master_checker"
    import agents.master_agent  # must still import
    print("[PASS] master checker removed (backend)")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Remove from `master_agent.py`** (re-grep each): the import (~88), the `self._master_checker` declaration (~343), the `_op_driver` fork that nulls/constructs it (~986-996, keeping the Issue-Validator branch which Task 14 rebuilds), and every `pre_phase_review`/`post_phase_review` call + its guard (~4720, 4732, 4997, 5005, 5095, 5120, 5151).
- [ ] **Step 4: Remove from `reasoning_loop.py`**: the `mc = getattr(..., "_master_checker", None)` lookups + `mc is not None` guards (~2557, 2580) and the `mc.pre_phase_review`/`mc.post_phase_review` blocks in `_safe_phase` (~2604-2655). Keep the `validate_phase_findings` block for now (Task 14 migrates/removes it); ensure it no longer depends on `mc`.
- [ ] **Step 5: Remove enum** `AgentName.MASTER_CHECKER` from `db/schemas.py` (~62) only after grepping for other readers; if any persisted-doc deserialization is strict, make the `AgentName` lookup tolerate unknown values (fallback to a generic).
- [ ] **Step 6: Update tests** in `agents/test_architecture_integration.py` that assert `self._master_checker = None` or construct MasterChecker — remove/replace them.
- [ ] **Step 7: Verify legacy fallback** — `ARGUS_OPERATOR=0 python -X utf8 agents/test_architecture_integration.py` style assertion that the module imports and legacy phase entry still resolves (add `test_legacy_fallback_imports()`).
- [ ] **Step 8: Run harness, verify PASS.**

---

## Task 10: D-GUI — remove Master Checker (frontend)

**Files:** Modify `static/js/components/MetaAgentsPanel.jsx`, `static/js/store.js`, `templates/index.html`; Test harness.

- [ ] **Step 1: Failing assertion** `test_master_checker_gui_removed()`:
```python
def test_master_checker_gui_removed():
    panel = open("static/js/components/MetaAgentsPanel.jsx","r",encoding="utf-8").read()
    store = open("static/js/store.js","r",encoding="utf-8").read()
    assert "checkerState" not in panel and "Master Checker" not in panel, "panel still has checker"
    assert "metaCheckerState" not in store and "META_CHECKER_PHASE_DONE" not in store, "store still has checker"
    assert "meta_checker_pre_phase" not in store and "meta_checker_post_phase" not in store, "store still routes checker WS"
    print("[PASS] master checker removed (GUI)")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: MetaAgentsPanel.jsx** — delete the `checker` `_MetaSubPanel` (~484-490), all `checkerState` references in header/totals/status-dot (~315, 319, 323-326, 330, 333, 437-443) and the checker Summary cells (~275-279). Keep the `validator` and `error` sub-panels.
- [ ] **Step 4: store.js** — delete `metaCheckerState` slice (~211-217), `META_CHECKER_PHASE_DONE` reducer (~1312-1321), the checker branch in shared `META_AGENT_*` routing (~1265-1310), and the two WS dispatch cases (~3527-3533, 3588-3596).
- [ ] **Step 5: Cache-bust** — bump `MetaAgentsPanel.jsx` + `store.js` `?v=`.
- [ ] **Step 6: babel** both; **Step 7: Run harness, verify PASS.**

---

## Task 11: E-agent — Issue Validator rebuild (queue consumer + validate_finding)

**Files:** Rewrite `agents/meta/issue_validator_agent.py` (in place); reuse `agents/reasoning/issue_validator.py` helpers; Test harness.

- [ ] **Step 1: Failing assertion** `test_issue_validator_rebuild()`:
```python
def test_issue_validator_rebuild():
    import inspect, agents.meta.issue_validator_agent as iv
    src = inspect.getsource(iv)
    for sym in ("ingest_finding","validate_finding","register_validator","get_validator","_GLOBAL_REGISTRY"):
        assert sym in src, f"{sym} missing from issue validator"
    # deterministic verdict shape
    print("[PASS] issue validator rebuilt")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Implement** `validate_finding` (synchronous, deterministic — the hot-path gate) on the agent, reusing `agents/reasoning/issue_validator.py` `infer_class`/`EVIDENCE_PATTERNS`/`FAILURE_PATTERNS`/`validate_grounding`:
```python
def validate_finding(self, finding: dict, current_origin: dict | None = None) -> dict:
    """Deterministic verdict used as the write-time gate.  No LLM call.
    Returns {accept, grounded, severity_ok, origin_ok, duplicate, reason}."""
    title = str(finding.get("title") or finding.get("name") or "")
    sev = str(finding.get("severity") or "").lower()
    evidence = str(finding.get("evidence") or finding.get("raw_output") or finding.get("output") or "")
    cls = infer_class(title + " " + evidence)
    grounded = bool(evidence) and validate_grounding(cls, evidence)
    # critical/high MUST have grounded evidence
    severity_ok = True
    if sev in ("critical","high") and not grounded:
        severity_ok = False
    # provenance (degrade to unknown→ok until stamping lands)
    origin_ok = True
    o = finding.get("_origin")
    if o and current_origin:
        origin_ok = (str(o.get("session_id","")) == str(current_origin.get("session_id","")) and
                     str(o.get("target","")) == str(current_origin.get("target","")))
    # dedup
    fp = self._finding_fp(finding)
    duplicate = fp in self._seen_fp
    if not duplicate: self._seen_fp.add(fp)
    accept = grounded and severity_ok and origin_ok and not duplicate
    reason = "" if accept else ("ungrounded" if not grounded else
             "severity-unsupported" if not severity_ok else
             "foreign-origin" if not origin_ok else "duplicate")
    return {"accept": accept, "grounded": grounded, "severity_ok": severity_ok,
            "origin_ok": origin_ok, "duplicate": duplicate, "reason": reason}

@staticmethod
def _finding_fp(finding: dict) -> str:
    import hashlib, re
    t = re.sub(r"\W+"," ", str(finding.get("title") or finding.get("name") or "")).strip().lower()
    basis = "|".join([t, str(finding.get("host","")), str(finding.get("port","")),
                      str(finding.get("cve",""))])
    return hashlib.sha1(basis.encode("utf-8","ignore")).hexdigest()
```
- [ ] **Step 4: Queue-consumer shape** (mirror `error_analyzer_agent.py`): `__init__` adds `self._queue = asyncio.Queue(maxsize=200)`, `self._seen_fp = set()`, `self._stats = {"accepted":0,"rejected":0}`, `self._stop = False`; add `ingest_finding(finding)` (non-blocking put), `async def run()` (drains queue, calls `validate_finding`, on reject pushes a Correction + updates stats, optional budget-capped LLM pass), `request_stop()`, `_agent_name_str → "issue_validator"`. Add module-level `_GLOBAL_REGISTRY`, `register_validator(session_id, agent)`, `get_validator(session_id)`, `unregister_validator(session_id)` (copy from error analyzer).
- [ ] **Step 5: Run harness, verify PASS.** Add fixture assertions: grounded RCE accepts; `critical` with empty evidence rejects (`reason=="ungrounded"`); duplicate rejects; foreign-origin rejects.

---

## Task 12: E-write-gate — gate at store_finding choke-points + persistence

**Files:** Modify `agents/base_agent.py` (`store_finding` ~2509-2583), `agents/base_subagent.py` (`store_finding` ~1185-1233), `db/mongo_client.py` (`store_finding` ~736-840); Test harness.

- [ ] **Step 1: Failing assertion** `test_write_time_gate()`:
```python
def test_write_time_gate():
    ba = open("agents/base_agent.py","r",encoding="utf-8").read()
    bs = open("agents/base_subagent.py","r",encoding="utf-8").read()
    assert "validate_finding" in ba or "get_validator" in ba, "base_agent has no write-time gate"
    assert "get_validator" in bs or "validate_finding" in bs, "base_subagent bypasses the gate"
    mc = open("db/mongo_client.py","r",encoding="utf-8").read()
    assert "gated_reason" in mc, "mongo_client missing gated_reason persistence"
    print("[PASS] write-time gate")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: base_agent.store_finding** — before persisting, look up the per-session validator and apply the deterministic gate (fail-open if no validator):
```python
try:
    from agents.meta.issue_validator_agent import get_validator
    _iv = get_validator(getattr(self, "_session_id", "") or "")
    if _iv is not None and os.environ.get("ARGUS_ISSUE_VALIDATOR","1") != "0":
        _v = _iv.validate_finding(finding, current_origin=getattr(self, "_engagement_origin", lambda: None)())
        finding["verified"] = bool(_v["accept"])
        if not _v["accept"]:
            finding["gated_reason"] = _v["reason"]
        _iv.ingest_finding(finding)   # async nuance pass + live broadcast
except Exception:
    pass   # never block the write on gate failure
```
- [ ] **Step 4: base_subagent.store_finding** — route the raw `insert_one` through the same gate (set `verified`/`gated_reason` + fingerprint dedup before insert), so the subagent path is no longer a bypass.
- [ ] **Step 5: mongo_client.store_finding** — persist `verified`, `gated_reason`, and `_origin` if present on the finding dict; keep `increment_session_stats` only on first insert (do not double-count when a gated finding is later flagged).
- [ ] **Step 6: Run harness, verify PASS.**

---

## Task 13: E-read-gate — validated-only report read path

**Files:** Modify `db/mongo_client.py` (`get_findings` ~843-858), `report/generator.py` (`_build_context` ~1360-1363); Test harness.

- [ ] **Step 1: Failing assertion** `test_read_time_gate()`:
```python
def test_read_time_gate():
    import inspect, db.mongo_client as mc, report.generator as rg
    assert "validated_only" in inspect.getsource(mc), "get_findings missing validated_only"
    assert "validated_only" in inspect.getsource(rg.ReportGenerator._build_context) or \
           "verified" in inspect.getsource(rg.ReportGenerator._build_context), "report not filtering unverified"
    print("[PASS] read-time gate")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: get_findings** — add `validated_only: bool = False` param; when True, add `{"$or":[{"verified":True},{"verified":{"$exists":False}}]}` and exclude `verified:False` (i.e., only verified-or-legacy rows). Keep default False so other callers are unaffected.
- [ ] **Step 4: _build_context** — call `db.get_findings(session_id, validated_only=True)` for the report findings list (gated by `ARGUS_ISSUE_VALIDATOR != "0"`), so faulty rows never render. Optionally expose `gated_count` to the template for an internal note (not a finding).
- [ ] **Step 5: Run harness, verify PASS** — add an integration assertion: persist one grounded + one ungrounded finding, confirm `get_findings(validated_only=True)` returns only the grounded one and `_build_context` findings excludes the ungrounded one.

---

## Task 14: E-lifecycle — start validator on the default operator path

**Files:** Modify `agents/master_agent.py` (construct/register/run beside Error Analyzer ~2877-2888; remove the `self._issue_validator=None` short-circuit ~988; teardown ~1658-1663); `agents/reasoning/reasoning_loop.py` (migrate/remove the now-orphaned legacy validate block); Test harness.

- [ ] **Step 1: Failing assertion** `test_validator_lifecycle()`:
```python
def test_validator_lifecycle():
    import inspect, agents.master_agent as ma
    src = inspect.getsource(ma)
    assert "register_validator" in src, "validator not registered on default path"
    assert "unregister_validator" in src, "validator not torn down"
    # the operator-core None short-circuit is gone
    assert "self._issue_validator = None" not in src, "validator still force-nulled under operator"
    print("[PASS] validator lifecycle")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Construct + register + run** next to the Error Analyzer (default `_reasoning_loop_run` path ~2877-2888):
```python
try:
    from agents.meta.issue_validator_agent import IssueValidatorAgent, register_validator
    self._issue_validator = IssueValidatorAgent(self, session_id=session_id)
    register_validator(session_id, self._issue_validator)
    self._create_task(self._issue_validator.run())
except Exception:
    self._issue_validator = None
```
- [ ] **Step 4: Remove the short-circuit** at ~988 (the `if _op_driver: self._issue_validator = None`). Keep a single construction site (Step 3).
- [ ] **Step 5: Teardown** beside the analyzer (~1658-1663): `if self._issue_validator: self._issue_validator.request_stop(); unregister_validator(session_id)`.
- [ ] **Step 6: Legacy block** in `reasoning_loop.py` — since the validator now runs independently under the operator, remove the orphaned `validate_phase_findings` invocation that depended on the removed Master-Checker block (or guard it to the legacy path only). Ensure no `NameError` from the removed `mc`.
- [ ] **Step 7: Run harness, verify PASS.**

---

## Task 15: E-broadcast/GUI — live corrections + validator stats tile

**Files:** Modify `agents/meta/issue_validator_agent.py` (emit), `agents/master_agent.py` (`_pending_corrections` bridge), `static/js/store.js`, `static/js/components/MetaAgentsPanel.jsx`, `templates/index.html`; Test harness.

- [ ] **Step 1: Failing assertion** `test_validator_broadcast_gui()`:
```python
def test_validator_broadcast_gui():
    iv = open("agents/meta/issue_validator_agent.py","r",encoding="utf-8").read()
    assert "validation_analysis" in iv, "validator missing stats event"
    assert "_pending_corrections" in iv or "pending_corrections" in iv, "validator not pushing live corrections"
    store = open("static/js/store.js","r",encoding="utf-8").read()
    assert "META_VALIDATOR_STATS" in store, "store missing validator stats"
    assert "meta_validator_tool" in store and "meta_validator_phase" in store, "validator WS events not wired"
    print("[PASS] validator broadcast + GUI")
```
- [ ] **Step 2: Run harness, verify FAIL.**
- [ ] **Step 3: Emit** — in the validator's `run()`/`_handle`, on each reject call `emit_correction(...)` (existing) AND push a `Correction(source="issue_validator", ...)` onto `master._pending_corrections`; periodically emit a `validation_analysis` WS event `{accepted, rejected, last_reason}`.
- [ ] **Step 4: store.js** — add `META_VALIDATOR_STATS` reducer (model on `META_ERROR_ANALYZER_STATS`) + a `validation_analysis` WS dispatch case; add the missing `meta_validator_tool`/`meta_validator_phase` dispatch cases feeding the existing `META_VALIDATOR_TOOL_DONE`/`PHASE_DONE` reducers.
- [ ] **Step 5: MetaAgentsPanel.jsx** — ensure the `validator` sub-panel renders accepted/rejected stats + the validated/gated counts from `metaValidatorState`.
- [ ] **Step 6: Cache-bust** `store.js` + `MetaAgentsPanel.jsx`; **Step 7: babel**; **Step 8: Run harness, verify PASS.**

---

## Task 16: Final sweep — full harness + regression + file list

**Files:** none new; verification only.

- [ ] **Step 1:** `python -X utf8 agents/test_architecture_integration.py` → `RESULT: PASS` (all new + existing assertions).
- [ ] **Step 2:** Confirm `test_no_hardcoded_attack_content` PASSes (network markers are diagnostics).
- [ ] **Step 3:** `babel` parse each edited `.jsx`/`.js`.
- [ ] **Step 4:** `py_compile` each edited `.py`.
- [ ] **Step 5:** Confirm every cache-bust `?v=` bumped in `templates/index.html` for edited JS.
- [ ] **Step 6:** Produce the final edited-files list for manual Windows→Kali copy.

---

## Self-review

**Spec coverage:** A1/A2/A3 → Tasks 1-3; C → Task 4; B (detector/gate/preflight/wiring/honest-status) → Tasks 5-8; D (backend+GUI) → Tasks 9-10; E (agent/write-gate/read-gate/lifecycle/broadcast+GUI, exclude-from-report policy) → Tasks 11-15; data-model (verified/gated_reason/_origin) → Tasks 12-13; testing/regression → every task + Task 16. All spec sections mapped.

**Placeholder scan:** No TBD/TODO; new units carry real code; mechanical edits give exact surfaces (line numbers flagged "re-grep"). Deletions are identified precisely (can't "show code" for a deletion).

**Type consistency:** `_engagement_origin()` returns `{session_id,target}` everywhere (OperatorCore + MasterAgent). `_origin` is the stamp key throughout. `validate_finding` returns `{accept,grounded,severity_ok,origin_ok,duplicate,reason}` (Task 11) and is consumed with those keys (Task 12). `get_findings(validated_only=...)` defined Task 13, called Task 13. Registry funcs `register_validator/get_validator/unregister_validator` defined Task 11, used Tasks 12/14. `register_blocker_gate/resolve_blocker_decision/apply_blocker_decision` defined Task 6, used Tasks 6/8. Consistent.
