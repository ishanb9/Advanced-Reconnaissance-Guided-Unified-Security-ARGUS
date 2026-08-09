"""agents/graph/engine.py — graph topology, the flag, and the G7 rollback to the loop.

The graph engine is an ADDITIVE, FLAG-GATED alternative to the existing loop engine
(Z1 strangler fig).  ``ARGUS_GRAPH_ENGINE`` defaults to "0": with the flag off NOTHING
in this module runs and the loop path is byte-for-byte unchanged.

G7 — mid-scan rollback.  The graph engine is new code; new code fails.  When it does,
the engagement must degrade to the WORKING loop path rather than die or (far worse)
emit an empty "success" — the exact failure mode that silently produced 0 findings on
27 hosts.  The rollback is a SAFETY NET, NOT A BUG-HIDER: every fallback is latched,
snapshotted, loudly surfaced and marked DEGRADED end to end.
"""
from __future__ import annotations

import logging
import os
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agents.graph.nodes import NodeContext, make_nodes
from agents.graph.runtime import (TERMINAL, EngineFailure, GraphRunner, GraphSpec,
                                  GraphValidationError, NodeSpec, render_edges,
                                  validate_graph)
from agents.graph.state import EngagementState

logger = logging.getLogger(__name__)

# ── Flags ────────────────────────────────────────────────────────────────────
ENV_ENGINE   = "ARGUS_GRAPH_ENGINE"        # "1" opts a run into the graph path
ENV_KILL     = "ARGUS_GRAPH_KILL"          # "1" forces the LOOP for every host, now
ENV_MAX_NODE = "ARGUS_GRAPH_MAX_NODES"


def graph_engine_enabled() -> bool:
    """DEFAULT OFF.  The global kill switch wins over the opt-in so ops can force the
    loop engine for every host with no code change and no redeploy."""
    if str(os.environ.get(ENV_KILL, "0")).strip().lower() in ("1", "true", "yes", "on"):
        return False
    return str(os.environ.get(ENV_ENGINE, "0")).strip().lower() in ("1", "true", "yes", "on")


def kill_switch_engaged() -> bool:
    return str(os.environ.get(ENV_KILL, "0")).strip().lower() in ("1", "true", "yes", "on")


# ══════════════════════════════════════════════════════════════════════════════
#  TOPOLOGY (G3 — invariants as SHAPE)
# ══════════════════════════════════════════════════════════════════════════════
def _blocked(state: EngagementState, host: str) -> bool:
    hs = state.host_state(host)
    return str((hs.selected or {}).get("gate_decision") or "") in ("deny", "require_approval")


def _validated(state: EngagementState, host: str) -> bool:
    hs = state.host_state(host)
    ev = state.evidence.get(str((hs.selected or {}).get("evidence_id") or ""))
    return bool(ev and ev.validated)


def _is_terminal(state: EngagementState, host: str) -> bool:
    return bool(state.host_state(host).terminal_reason)


def build_graph(ctx: NodeContext) -> GraphSpec:
    """The first vertical slice as an explicit graph.

    recon_plan -> safety_gate -> tool_execute -> evidence_capture -> fingerprint ->
    classify -> evidence_validate -(validated)-> finding_promote -> hypothesize ->
    rank -> select -(terminal)-> report_handoff -> TERMINAL, with select looping back
    into safety_gate for the next action.

    The two prize invariants are structural, not conventional:
      * ``tool_execute`` has exactly ONE inbound edge — from ``safety_gate``;
      * ``finding_promote`` has exactly ONE inbound edge — from ``evidence_validate``.
    ``validate_graph`` fails the build (and the test suite) if that ever stops holding.
    """
    fns = make_nodes(ctx)
    spec = GraphSpec(entry="recon_plan")
    spec.guarded_inbound = {
        "tool_execute":    {"safety_gate"},
        "finding_promote": {"evidence_validate"},
    }

    spec.add_node(NodeSpec("recon_plan",       fns["recon_plan"],       timeout=30))
    spec.add_node(NodeSpec("safety_gate",      fns["safety_gate"],      timeout=30,  structural=True))
    spec.add_node(NodeSpec("tool_execute",     fns["tool_execute"],     timeout=600, retries=1,
                           fallback="select"))       # a dead tool must not wedge the walk
    spec.add_node(NodeSpec("evidence_capture", fns["evidence_capture"], timeout=60))
    spec.add_node(NodeSpec("fingerprint",      fns["fingerprint"],      timeout=60))
    spec.add_node(NodeSpec("classify",         fns["classify"],         timeout=60))
    spec.add_node(NodeSpec("evidence_validate", fns["evidence_validate"], timeout=120, structural=True))
    spec.add_node(NodeSpec("finding_promote",  fns["finding_promote"],  timeout=120, structural=True))
    spec.add_node(NodeSpec("hypothesize",      fns["hypothesize"],      timeout=300, retries=1))
    spec.add_node(NodeSpec("rank",             fns["rank"],             timeout=300, retries=1))
    spec.add_node(NodeSpec("select",           fns["select"],           timeout=120, structural=True))
    spec.add_node(NodeSpec("report_handoff",   fns["report_handoff"],   timeout=120))

    spec.add_edge("recon_plan", "safety_gate")
    spec.add_edge("safety_gate", "select", predicate=_blocked, label="blocked")
    spec.add_edge("safety_gate", "tool_execute")                       # default: allowed
    spec.add_edge("tool_execute", "evidence_capture")
    spec.add_edge("evidence_capture", "fingerprint")
    spec.add_edge("fingerprint", "classify")
    spec.add_edge("classify", "evidence_validate")
    spec.add_edge("evidence_validate", "finding_promote", predicate=_validated, label="validated")
    spec.add_edge("evidence_validate", "hypothesize")                  # default: not promoted
    spec.add_edge("finding_promote", "hypothesize")
    spec.add_edge("hypothesize", "rank")
    spec.add_edge("rank", "select")
    spec.add_edge("select", "report_handoff", predicate=_is_terminal, label="terminal")
    spec.add_edge("select", "safety_gate")                             # default: next action
    spec.add_edge("report_handoff", TERMINAL)
    return spec


# ══════════════════════════════════════════════════════════════════════════════
#  G7 — ROLLBACK
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class RollbackPolicy:
    """Explicit thresholds separating a NORMAL node failure from an ENGINE failure.

    NORMAL (never rolls back): a tool timed out, a host was unreachable, an optional
    analysis node raised — absorbed by the node's own retry/fallback policy.

    ENGINE (rolls back): the runtime itself raised; state/checkpoint corruption;
    retry-exhaustion on a STRUCTURAL node (safety_gate / evidence_validate /
    finding_promote / select); N consecutive node failures; or no observable progress
    across M consecutive nodes.  These are enforced inside GraphRunner and surface
    here as EngineFailure.
    """
    consecutive_node_failures: int = 3
    stall_nodes:               int = 6
    max_fallbacks_per_host:    int = 1      # LATCH — never ping-pong between engines


@dataclass
class RollbackOutcome:
    """What the caller must do next for this host."""
    rolled_back:  bool
    reason:       str = ""
    failed_node:  str = ""
    traceback:    str = ""
    handoff_intel: Dict[str, Any] = field(default_factory=dict)
    checkpoint_id: str = ""


def state_to_intel(state: EngagementState, host: str) -> Dict[str, Any]:
    """STATE HANDOFF — project the typed state into the intel dict shape the LOOP
    engine consumes, so the loop RESUMES from work already done instead of restarting.

    Carries across, intact:
      * captured recon (services / open ports / classification);
      * every VALIDATED, promoted finding (with its evidence) — no lost work;
      * the executed-tool ledger, so the loop does not re-run a completed call;
      * hypotheses / ranked paths, so planning continues rather than restarting;
      * the degraded provenance, so the report can say what happened.
    """
    hs = state.host_state(host)
    executed = {c.call_id: {"tool": c.tool, "args": c.args, "exit_code": c.exit_code}
                for c in state.tool_calls.values() if c.host == host and c.executed}
    findings = []
    for f in state.findings.values():
        if f.host != host or not f.promoted:
            continue
        ev = state.evidence.get(f.evidence_id)
        findings.append({
            "finding_id": f.finding_id, "title": f.title, "severity": f.severity,
            "description": f.description, "host": host,
            "evidence": (ev.artifact[:4000] if ev else ""),
            "_origin": {"engine": "graph", "session_id": state.session_id},
        })
    return {
        "services":       dict(hs.intel.get("services") or {}),
        "open_ports":     list(hs.intel.get("open_ports") or []),
        "device_classification": hs.intel.get("device_classification") or {},
        "hypotheses":     list(hs.hypotheses or []),
        "ranked_attack_paths": list(hs.ranked_paths or []),
        # Findings already PROVEN by the graph — the loop must not re-derive or
        # double-count these; they are carried, not re-created.
        "graph_findings": findings,
        # Dedupe ledger: {call_id: {...}} plus a flat tool-count map the master's
        # own `_used_tools` bookkeeping understands.
        "_graph_executed_calls": executed,
        "_graph_used_tools": _tool_counts(executed),
        "_graph_degraded": {
            "degraded": True, "host": host,
            "reason": hs.degraded_reason, "at_node": hs.degraded_at_node,
            "engine_from": "graph", "engine_to": "loop", "ts": time.time(),
        },
        "_graph_tally": state.tally(),
    }


def _tool_counts(executed: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for rec in executed.values():
        t = str(rec.get("tool") or "")
        if t:
            counts[t] = counts.get(t, 0) + 1
    return counts


def apply_handoff_to_master(master: Any, intel: Dict[str, Any]) -> Dict[str, int]:
    """Merge the handoff into the live MasterAgent so the LOOP resumes with the
    graph's work: intel, findings, and the executed-tool ledger (no double work).
    Returns a small applied-counts dict for the telemetry/test assertions."""
    applied = {"findings": 0, "tools": 0, "services": 0}
    if master is None or not isinstance(getattr(master, "_intel", None), dict):
        return applied
    it = master._intel
    svc = dict(it.get("services") or {})
    svc.update(intel.get("services") or {})
    it["services"] = svc
    applied["services"] = len(svc)
    it["open_ports"] = sorted(set(it.get("open_ports") or []) | set(intel.get("open_ports") or []))
    if intel.get("device_classification"):
        it.setdefault("device_classification", intel["device_classification"])
    for key in ("hypotheses", "ranked_attack_paths"):
        if intel.get(key):
            it[key] = intel[key]

    # Findings: carry across WITHOUT double-counting — dedupe on finding_id.
    existing = it.setdefault("findings", [])
    seen = {str((f or {}).get("finding_id") or "") for f in existing if isinstance(f, dict)}
    for f in intel.get("graph_findings") or []:
        if str(f.get("finding_id")) in seen:
            continue
        existing.append(f)
        seen.add(str(f.get("finding_id")))
        applied["findings"] += 1

    # Executed-tool ledger: seed the master's dedupe map so the loop skips completed
    # calls instead of re-running them.
    ledger = it.setdefault("_graph_executed_calls", {})
    ledger.update(intel.get("_graph_executed_calls") or {})
    used = getattr(master, "_used_tools", None)
    if isinstance(used, dict):
        for tool, n in (intel.get("_graph_used_tools") or {}).items():
            used[tool] = used.get(tool, 0) + int(n)
            applied["tools"] += int(n)
    it["_graph_degraded"] = intel.get("_graph_degraded") or {}
    return applied


class GraphEngine:
    """Runs the graph slice for one host and owns the rollback decision."""

    def __init__(
        self,
        ctx: NodeContext,
        *,
        checkpointer: Any = None,
        policy: Optional[RollbackPolicy] = None,
        emit: Any = None,
        master: Any = None,
    ) -> None:
        self.ctx = ctx
        self.checkpointer = checkpointer
        self.policy = policy or RollbackPolicy()
        self._emit = emit
        self.master = master if master is not None else ctx.master
        self.spec = build_graph(ctx)
        errs = validate_graph(self.spec)
        if errs:
            raise GraphValidationError("; ".join(errs))

    def edge_map(self) -> str:
        return render_edges(self.spec)

    async def _emit_event(self, event: str, data: Dict[str, Any]) -> None:
        try:
            if self._emit is not None:
                await self._emit(event, data)
            elif self.master is not None and hasattr(self.master, "_emit"):
                await self.master._emit(event, data)
        except Exception:                                    # noqa: BLE001
            pass

    async def run_host(self, state: EngagementState, host: str,
                       start_at: Optional[str] = None) -> RollbackOutcome:
        """Walk the graph for ``host``.  On an ENGINE failure, degrade to the loop
        exactly once (latched) and hand the accumulated state over."""
        hs = state.host_state(host)
        try:
            max_nodes = int(os.environ.get(ENV_MAX_NODE, "0") or 0)
            if max_nodes > 0:
                state.budgets.max_nodes = max_nodes
        except (TypeError, ValueError):
            pass

        runner = GraphRunner(
            self.spec, checkpointer=self.checkpointer, emit=self._emit_wrapper(),
            consecutive_failure_limit=self.policy.consecutive_node_failures,
            stall_limit=self.policy.stall_nodes)
        try:
            await runner.run(state, host, start_at=start_at)
            hs.engine = "graph"
            return RollbackOutcome(rolled_back=False, reason=hs.terminal_reason)
        except Exception as exc:                             # noqa: BLE001
            # EVERY escape from the runner is an ENGINE failure by construction:
            # normal node failures are absorbed inside GraphRunner by retry/fallback.
            return await self._rollback(state, host, exc)

    def _emit_wrapper(self):
        async def _e(event: str, data: Dict[str, Any]) -> None:
            await self._emit_event(event, data)
        return _e

    async def _rollback(self, state: EngagementState, host: str,
                        exc: BaseException) -> RollbackOutcome:
        hs = state.host_state(host)
        tb = traceback.format_exc()
        failed_node = hs.visited[-1] if hs.visited else "(none)"
        reason = f"{type(exc).__name__}: {exc}"

        # ── LATCH: at most ONE fallback per host; never ping-pong between engines.
        if hs.fallback_count >= self.policy.max_fallbacks_per_host:
            logger.error("[graph] host=%s already fell back once — refusing to "
                         "ping-pong; failing LOUD. node=%s err=%s\n%s",
                         host, failed_node, reason, tb)
            await self._emit_event("graph_engine_failed_after_fallback", {
                "host": host, "node": failed_node, "error": reason,
                "message": ("Graph engine failed again after its single permitted "
                            "fallback — this host is NOT silently continuing.")})
            raise EngineFailure(
                f"graph engine failed after fallback latch on {host}: {reason}") from exc

        # ── SNAPSHOT FIRST — forensics + resumability before any handoff.
        ckpt_id = ""
        if self.checkpointer is not None:
            try:
                state.record_decision(failed_node, "rollback", reason)
                ckpt_id = await self.checkpointer.save(
                    state, node=failed_node,
                    reason=f"pre-rollback: {reason}") or ""
            except Exception as ck_exc:                       # noqa: BLE001
                logger.error("[graph] pre-rollback checkpoint FAILED for %s: %s", host, ck_exc)

        # ── Mark DEGRADED on the state (report/summary/status all read this).
        hs.degraded = True
        hs.degraded_reason = reason
        hs.degraded_at_node = failed_node
        hs.fallback_count += 1
        hs.engine = "loop"

        # ── LOUD: full traceback, distinct event, summary counter, session status.
        logger.error("[graph] ENGINE FAILURE on host=%s at node=%s -> rolling back to the "
                     "loop engine. reason=%s\n%s", host, failed_node, reason, tb)
        await self._emit_event("graph_engine_rollback", {
            "host": host, "node": failed_node, "reason": reason,
            "traceback": tb[-2000:], "checkpoint_id": ckpt_id,
            "engine_from": "graph", "engine_to": "loop", "degraded": True,
            "message": (f"Graph engine failed on {host} at node '{failed_node}' — the "
                        "engagement is continuing on the LEGACY LOOP engine. This host "
                        "is DEGRADED, not clean.")})
        self._mark_degraded_telemetry(host, failed_node, reason)

        handoff = state_to_intel(state, host)
        applied = apply_handoff_to_master(self.master, handoff)
        logger.error("[graph] handoff to loop for %s: %d finding(s), %d executed tool call(s) "
                     "carried; loop will RESUME, not restart.", host,
                     applied.get("findings", 0), len(handoff.get("_graph_executed_calls") or {}))
        return RollbackOutcome(rolled_back=True, reason=reason, failed_node=failed_node,
                               traceback=tb, handoff_intel=handoff, checkpoint_id=ckpt_id)

    def _mark_degraded_telemetry(self, host: str, node: str, reason: str) -> None:
        """summary.json counter + DEGRADED session status + report provenance.
        An operator must never mistake a degraded run for a clean one."""
        master = self.master
        try:
            slog = getattr(master, "_scan_logger", None)
            if slog is not None:
                slog.counters["graph_rollbacks"] = int(
                    slog.counters.get("graph_rollbacks", 0)) + 1
                slog.log_error("graph_engine_rollback",
                               message=f"host={host} node={node}: {reason}")
        except Exception:                                     # noqa: BLE001
            pass
        try:
            if master is not None and isinstance(getattr(master, "_intel", None), dict):
                prov = master._intel.setdefault("degraded_hosts", [])
                prov.append({"host": host, "at_node": node, "reason": reason,
                             "engine_from": "graph", "engine_to": "loop"})
                master._intel["engagement_degraded"] = True
                master._intel["session_status"] = "DEGRADED"
        except Exception:                                     # noqa: BLE001
            pass


def make_engagement_state(session_id: str, targets: List[str],
                          scope_hosts: Optional[List[str]] = None) -> EngagementState:
    st = EngagementState(session_id=session_id, targets=list(targets or []),
                         scope_hosts=list(scope_hosts or targets or []))
    for t in targets or []:
        st.host_state(t)
    return st
