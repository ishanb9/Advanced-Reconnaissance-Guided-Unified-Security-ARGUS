"""agents/graph/nodes.py — G5: the first vertical slice, end to end, for ONE host.

recon -> fingerprint -> classify -> hypothesize -> rank -> select -> safety_gate ->
tool_execute -> evidence_capture -> evidence_validate -> finding_promote -> report

Z3 (REUSE, DON'T REIMPLEMENT): every node body CALLS existing ARGUS code —
  safety_gate       -> knowledge.safety_governor.evaluate
  tool_execute      -> BaseAgent.run_tool (the existing MCP execution chokepoint)
  classify          -> agents.reasoning.device_classifier.classify_device
  hypothesize/rank  -> HypothesisEngine / AttackPlanner (+ path_inference, neo4j)
  select            -> DecisionEngine
  evidence_validate -> agents.reasoning.issue_validator.validate_grounding
                       + knowledge.severity_policy (contradiction / noise / normalize)
  finding_promote   -> MasterAgent.store_finding
Nothing here re-implements an agent, a tool, or a validator.

Every node is injectable through ``NodeContext`` so the whole slice is unit-testable
with MOCKED tool responses and no network — that is how the gate-blocked,
claim-rejected, resume and fault-injection proofs run deterministically.
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from agents.graph.runtime import NodeFailure
from agents.graph.state import (EngagementState, EvidenceRecord, FindingRecord,
                                ToolCallRecord, call_key)
from agents.base_agent import safety_domain as _safety_domain

logger = logging.getLogger(__name__)

MAX_ARTIFACT = 20000            # captured stdout kept per tool call


@dataclass
class NodeContext:
    """Everything the nodes need, injectable for tests."""
    session_id:  str = ""
    scope_hosts: List[str] = field(default_factory=list)
    master:      Any = None                  # MasterAgent (optional in tests)
    # Injectables — default to the real implementations when master is present.
    run_tool_fn:   Optional[Callable[..., Awaitable[Dict[str, Any]]]] = None
    emit_fn:       Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None
    hypothesis_engine: Any = None
    attack_planner:    Any = None
    decision_engine:   Any = None
    negative_memory:   Any = None
    graph_sink:    Optional[Callable[..., Awaitable[None]]] = None   # neo4j upsert
    authorized:    bool = False              # operator-granted intrusive authorization
    ceiling:       str = "intrusive"

    async def run_tool(self, tool: str, args: str, host: str) -> Dict[str, Any]:
        if self.run_tool_fn is not None:
            return await self.run_tool_fn(tool_name=tool, args=args, target=host)
        if self.master is not None and hasattr(self.master, "run_tool"):
            return await self.master.run_tool(tool, args, target=host)
        raise NodeFailure("no tool executor available (no run_tool_fn and no master)")

    async def emit(self, event: str, data: Dict[str, Any]) -> None:
        try:
            if self.emit_fn is not None:
                await self.emit_fn(event, data)
            elif self.master is not None and hasattr(self.master, "_emit"):
                await self.master._emit(event, data)
        except Exception:                                    # noqa: BLE001
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  small deterministic parsers (no LLM — evidence must never be model-authored)
# ══════════════════════════════════════════════════════════════════════════════
_PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", re.M)
_FAIL_MARKERS = ("connection refused", "no route to host", "network is unreachable",
                 "host seems down", "0 hosts up", "permission denied", "timed out")


def parse_services(artifact: str) -> Dict[str, Dict[str, str]]:
    """Deterministically lift open ports/services out of a captured nmap artifact."""
    out: Dict[str, Dict[str, str]] = {}
    for m in _PORT_RE.finditer(artifact or ""):
        port, proto, svc, banner = m.group(1), m.group(2), m.group(3), (m.group(4) or "")
        out[port] = {"port": port, "proto": proto, "service": svc, "banner": banner.strip()}
    return out


def artifact_is_usable(artifact: str, exit_code: Optional[int]) -> "tuple[bool, str]":
    """A CAPTURED artifact counts only when it is non-empty, the command did not hard
    fail, and it does not self-negate.  Mirrors the audit's evidence rule."""
    blob = (artifact or "").strip()
    if not blob:
        return False, "empty tool output"
    if exit_code is not None and exit_code not in (0, None):
        return False, f"tool exited {exit_code}"
    low = blob.lower()
    for mark in _FAIL_MARKERS:
        if mark in low:
            return False, f"self-negating output: {mark!r}"
    return True, ""


# ══════════════════════════════════════════════════════════════════════════════
#  NODES
# ══════════════════════════════════════════════════════════════════════════════
def make_nodes(ctx: NodeContext) -> Dict[str, Callable[..., Any]]:
    """Bind the node bodies to a context.  Returns {node_name: fn(state, host)}."""

    # ── recon_plan ─────────────────────────────────────────────────────────
    async def recon_plan(state: EngagementState, host: str) -> Dict[str, Any]:
        """PLANS the opening recon action.  Deliberately does NOT execute it — no node
        may touch a tool except through safety_gate -> tool_execute (G3)."""
        hs = state.host_state(host)
        hs.selected = {
            "tool": "nmap",
            "args": f"-sV -Pn --top-ports 200 {host}",
            "purpose": "opening service discovery",
            "claim": "open ports and service versions on the target",
        }
        return {"planned": hs.selected["tool"]}

    # ── safety_gate (STRUCTURAL) ───────────────────────────────────────────
    async def safety_gate(state: EngagementState, host: str) -> Dict[str, Any]:
        """THE only gateway into tool_execute.  Delegates the actual decision to the
        existing execution-boundary governor — this node adds topology, not policy."""
        from knowledge.safety_governor import evaluate as _gov_evaluate

        hs = state.host_state(host)
        action = hs.selected or {}
        tool, args = str(action.get("tool") or ""), str(action.get("args") or "")
        if not tool:
            hs.selected = None
            return {"gate": "no_action"}

        verdict = _gov_evaluate(
            {"tool_name": tool, "args": args, "target_host": host,
             "scope_hosts": list(state.scope_hosts or []),
             "ceiling": ctx.ceiling, "authorized": bool(ctx.authorized),
             "domain": _safety_domain(hs.intel or {}),
             "life_safety": bool((hs.intel or {}).get("life_safety"))},
            enforce=("scope", "destructive", "arg_validation", "ot_life_safety"))
        decision = str(verdict.get("decision") or "allow")
        reason = str(verdict.get("reason") or "")
        if decision == "rewrite" and verdict.get("rewritten_args") is not None:
            args = str(verdict["rewritten_args"])
            hs.selected["args"] = args

        cid = call_key(tool, args, host)
        rec = state.tool_calls.get(cid) or ToolCallRecord(
            call_id=cid, tool=tool, args=args, host=host, node="safety_gate")
        rec.gate_decision, rec.gate_reason = decision, reason
        state.tool_calls[cid] = rec
        hs.selected["call_id"] = cid
        hs.selected["gate_decision"] = decision
        state.record_decision("safety_gate", "gate", f"{tool} -> {decision}: {reason}")
        await ctx.emit("graph_safety_gate", {
            "host": host, "tool": tool, "decision": decision, "reason": reason})
        if decision in ("deny", "require_approval"):
            logger.warning("[graph] safety_gate BLOCKED %s on %s: %s", tool, host, reason)
        return {"decision": decision, "tool": tool}

    # ── tool_execute ───────────────────────────────────────────────────────
    async def tool_execute(state: EngagementState, host: str) -> Dict[str, Any]:
        """Runs the gated action through the EXISTING run_tool chokepoint.  Skips any
        invocation already executed (dedupe survives a graph->loop rollback)."""
        hs = state.host_state(host)
        action = hs.selected or {}
        tool, args = str(action.get("tool") or ""), str(action.get("args") or "")
        cid = str(action.get("call_id") or call_key(tool, args, host))
        rec = state.tool_calls.get(cid)
        if rec is None:
            # Reaching execute without a gate record would mean the topology was
            # bypassed — refuse rather than send un-gated traffic.
            raise NodeFailure(f"no gate record for {tool} — refusing to execute un-gated")
        if rec.gate_decision in ("deny", "require_approval"):
            raise NodeFailure(f"blocked action reached tool_execute: {rec.gate_reason}")
        if rec.executed:
            return {"skipped": "already executed", "call_id": cid}

        t0 = time.time()
        try:
            res = await ctx.run_tool(tool, args, host)
        except Exception as exc:                              # noqa: BLE001
            raise NodeFailure(f"{tool} failed: {type(exc).__name__}: {exc}") from exc
        rec.executed = True
        rec.exit_code = res.get("exit_code")
        rec.stdout = str(res.get("stdout") or "")[:MAX_ARTIFACT]
        rec.stderr = str(res.get("stderr") or "")[:4000]
        rec.duration_sec = round(time.time() - t0, 3)
        rec.node = "tool_execute"
        state.tool_calls[cid] = rec
        return {"tool": tool, "exit_code": rec.exit_code, "bytes": len(rec.stdout)}

    # ── evidence_capture ───────────────────────────────────────────────────
    async def evidence_capture(state: EngagementState, host: str) -> Dict[str, Any]:
        """Turns the captured tool artifact into an EvidenceRecord.  Captures the raw
        artifact only — never a model's description of one."""
        hs = state.host_state(host)
        action = hs.selected or {}
        cid = str(action.get("call_id") or "")
        rec = state.tool_calls.get(cid)
        if rec is None or not rec.executed:
            return {"captured": False, "reason": "no executed tool call"}
        artifact = rec.stdout or rec.stderr
        ok, why = artifact_is_usable(artifact, rec.exit_code)
        eid = f"ev-{uuid.uuid4().hex[:12]}"
        state.evidence[eid] = EvidenceRecord(
            evidence_id=eid, tool_call_id=cid, host=host,
            claim=str(action.get("claim") or ""), artifact=artifact[:MAX_ARTIFACT],
            captured=ok, reason="" if ok else why)
        action["evidence_id"] = eid
        return {"evidence_id": eid, "captured": ok, "reason": why}

    # ── fingerprint ────────────────────────────────────────────────────────
    async def fingerprint(state: EngagementState, host: str) -> Dict[str, Any]:
        """Deterministically lift ports/services from captured artifacts into intel."""
        hs = state.host_state(host)
        merged: Dict[str, Dict[str, str]] = dict(hs.intel.get("services") or {})
        for ev in state.evidence.values():
            if ev.host == host and ev.captured:
                merged.update(parse_services(ev.artifact))
        hs.intel["services"] = merged
        hs.intel["open_ports"] = sorted({int(p) for p in merged if str(p).isdigit()})
        return {"open_ports": len(hs.intel["open_ports"])}

    # ── classify ───────────────────────────────────────────────────────────
    async def classify(state: EngagementState, host: str) -> Dict[str, Any]:
        """Reuses the existing device classifier (no new taxonomy)."""
        from agents.reasoning.device_classifier import classify_device
        hs = state.host_state(host)
        svc = hs.intel.get("services") or {}
        cls = classify_device(
            open_ports=list(hs.intel.get("open_ports") or []),
            services=svc,
            banners={k: v.get("banner", "") for k, v in svc.items() if isinstance(v, dict)},
            raw_target=host)
        payload = cls.to_dict() if hasattr(cls, "to_dict") else {"kind": str(cls)}
        hs.intel["device_classification"] = payload
        return {"kind": str(payload.get("kind") or payload.get("device_kind") or "unknown")}

    # ── hypothesize ────────────────────────────────────────────────────────
    async def hypothesize(state: EngagementState, host: str) -> Dict[str, Any]:
        """Reuses HypothesisEngine when wired; otherwise derives deterministic
        service-driven hypotheses so the slice runs without an LLM."""
        hs = state.host_state(host)
        if ctx.hypothesis_engine is not None:
            try:
                hyps = await ctx.hypothesis_engine.generate_hypotheses(
                    intel=dict(hs.intel), negative_memory=ctx.negative_memory,
                    iteration=hs.cycles)
                hs.hypotheses = [h.to_dict() if hasattr(h, "to_dict") else dict(h)
                                 for h in (hyps or [])]
                return {"hypotheses": len(hs.hypotheses), "source": "engine"}
            except Exception as exc:                          # noqa: BLE001
                logger.warning("[graph] hypothesis engine failed, using deterministic: %s", exc)
        svc = hs.intel.get("services") or {}
        tried = {c.tool for c in state.tool_calls.values() if c.host == host}
        hyps: List[Dict[str, Any]] = []
        for port, info in sorted(svc.items()):
            name = str((info or {}).get("service") or "").lower()
            if name.startswith("http") and "whatweb" not in tried:
                hyps.append({"id": f"h-http-{port}", "statement":
                             f"HTTP service on {port} exposes fingerprintable technology",
                             "tool": "whatweb", "args": f"http://{host}:{port}", "port": port})
            elif name in ("ssh",) and "ssh-audit" not in tried:
                hyps.append({"id": f"h-ssh-{port}", "statement":
                             f"SSH on {port} exposes version/algorithm posture",
                             "tool": "ssh-audit", "args": f"{host} -p {port}", "port": port})
        hs.hypotheses = hyps
        return {"hypotheses": len(hyps), "source": "deterministic"}

    # ── rank (G4: the attack graph IS the planning substrate) ──────────────
    async def rank(state: EngagementState, host: str) -> Dict[str, Any]:
        """Ranks hypotheses into paths and PERSISTS them to the existing attack graph
        (neo4j) — one graph concept, read and written by the executor."""
        hs = state.host_state(host)
        if ctx.attack_planner is not None and hs.hypotheses:
            try:
                paths = await ctx.attack_planner.rank_paths(
                    intel=dict(hs.intel), hypotheses=[], negative_memory=ctx.negative_memory,
                    iteration=hs.cycles)
                hs.ranked_paths = [p.to_dict() if hasattr(p, "to_dict") else dict(p)
                                   for p in (paths or [])]
            except Exception as exc:                          # noqa: BLE001
                logger.warning("[graph] attack planner failed, ranking locally: %s", exc)
        if not hs.ranked_paths:
            hs.ranked_paths = [{"id": h["id"], "statement": h["statement"],
                                "score": 1.0 - (i * 0.1), "tool": h.get("tool"),
                                "args": h.get("args")}
                               for i, h in enumerate(hs.hypotheses)]
        # Persist into the SAME attack graph the rest of ARGUS reads (best-effort).
        if ctx.graph_sink is not None:
            for p in hs.ranked_paths[:10]:
                try:
                    await ctx.graph_sink(session_id=ctx.session_id, node_id=str(p.get("id")),
                                         label="AttackPath", props={"host": host, **p})
                except Exception:                             # noqa: BLE001
                    pass
        return {"paths": len(hs.ranked_paths)}

    # ── select (STRUCTURAL) ────────────────────────────────────────────────
    async def select(state: EngagementState, host: str) -> Dict[str, Any]:
        """Chooses the next action, or declares a TERMINAL reason.  Terminal reasons
        are explicit and enumerable: convergence, budget, no viable hypotheses."""
        hs = state.host_state(host)
        hs.cycles += 1
        hs.selected = None

        if hs.cycles > state.budgets.max_cycles:
            hs.terminal_reason = "convergence: cycle budget reached"
        elif len(state.tool_calls) >= state.budgets.max_tool_calls:
            hs.terminal_reason = "budget: tool-call budget reached"
        else:
            untried = [p for p in hs.ranked_paths
                       if p.get("tool") and not state.already_executed(
                           str(p.get("tool")), str(p.get("args") or ""), host)]
            if not untried:
                hs.terminal_reason = "no viable hypotheses remain"
            else:
                best = untried[0]
                if ctx.decision_engine is not None:
                    try:
                        chosen = await ctx.decision_engine.select_action(
                            hypotheses=[], ranked_paths=hs.ranked_paths, intel=dict(hs.intel))
                        if isinstance(chosen, dict) and chosen.get("tool"):
                            best = chosen
                    except Exception as exc:                  # noqa: BLE001
                        logger.warning("[graph] decision engine failed, using rank order: %s", exc)
                hs.selected = {"tool": str(best.get("tool")), "args": str(best.get("args") or ""),
                               "claim": str(best.get("statement") or ""),
                               "hypothesis_id": str(best.get("id") or "")}
        if hs.terminal_reason:
            state.record_decision("select", "terminal", hs.terminal_reason)
        return {"selected": (hs.selected or {}).get("tool"), "terminal": hs.terminal_reason}

    # ── evidence_validate (STRUCTURAL) ─────────────────────────────────────
    async def evidence_validate(state: EngagementState, host: str) -> Dict[str, Any]:
        """THE only path to finding_promote.  Reuses the existing grounding validator
        and the severity policy's contradiction check — an LLM-authored claim with no
        successful captured artifact CANNOT pass here."""
        from agents.reasoning.issue_validator import validate_grounding
        from knowledge.severity_policy import evidence_contradicts_claim

        hs = state.host_state(host)
        eid = str((hs.selected or {}).get("evidence_id") or "")
        ev = state.evidence.get(eid)
        if ev is None:
            # Nothing new to validate this lap — a legitimate, non-failing outcome.
            return {"validated": False, "reason": "no evidence this cycle"}

        if not ev.captured:
            ev.validated = False
            ev.reason = ev.reason or "no usable captured artifact"
            return {"validated": False, "reason": ev.reason, "evidence_id": eid}

        rec = state.tool_calls.get(ev.tool_call_id)
        iv = validate_grounding(statement=ev.claim, tool=(rec.tool if rec else ""),
                                stdout=ev.artifact, exit_code=(rec.exit_code if rec else 0) or 0)
        contradicted, why = evidence_contradicts_claim(
            {"title": ev.claim, "description": ev.claim, "evidence": ev.artifact,
             "severity": "medium"})
        ev.issue_class = getattr(iv, "issue_class", "") or ""
        if contradicted:
            ev.validated, ev.reason = False, f"evidence contradicts the claim: {why}"
        elif not getattr(iv, "grounded", False):
            ev.validated = False
            ev.reason = getattr(iv, "reason", "") or "not grounded in captured evidence"
        else:
            ev.validated, ev.reason = True, "grounded in captured evidence"
        state.evidence[eid] = ev
        state.record_decision("evidence_validate", "gate",
                              f"{eid}: validated={ev.validated} ({ev.reason})")
        if not ev.validated:
            logger.info("[graph] evidence_validate REJECTED %s: %s", eid, ev.reason)
        return {"validated": ev.validated, "reason": ev.reason, "evidence_id": eid}

    # ── finding_promote (STRUCTURAL) ───────────────────────────────────────
    async def finding_promote(state: EngagementState, host: str) -> Dict[str, Any]:
        """Promotes VALIDATED evidence into a finding and mirrors it to the existing
        store.  Re-checks validation defensively: reaching here without it would be a
        topology break, and this node refuses rather than trusting its caller."""
        from knowledge.severity_policy import normalize_finding

        hs = state.host_state(host)
        eid = str((hs.selected or {}).get("evidence_id") or "")
        ev = state.evidence.get(eid)
        if ev is None or not ev.validated:
            raise NodeFailure(
                f"finding_promote reached without validated evidence (id={eid!r}) — refusing")

        rec = state.tool_calls.get(ev.tool_call_id)
        raw = {"title": ev.claim or f"Observation on {host}",
               "description": ev.claim, "host": host, "severity": "info",
               "evidence": ev.artifact[:4000],
               "commands": [f"{rec.tool} {rec.args}"] if rec else []}
        try:
            norm = normalize_finding(dict(raw))
        except Exception:                                     # noqa: BLE001
            norm = raw
        fid = f"fnd-{uuid.uuid4().hex[:12]}"
        state.findings[fid] = FindingRecord(
            finding_id=fid, host=host, title=str(norm.get("title") or raw["title"]),
            severity=str(norm.get("severity") or "info").lower(),
            description=str(norm.get("description") or ""), evidence_id=eid,
            promoted=True, source_engine="graph")
        # Mirror into the existing store so the dashboard/report see it (same tally).
        if ctx.master is not None and hasattr(ctx.master, "store_finding"):
            try:
                await ctx.master.store_finding(
                    severity=state.findings[fid].severity,
                    title=state.findings[fid].title,
                    description=state.findings[fid].description,
                    host=host, evidence=ev.artifact[:2000])
            except Exception as exc:                          # noqa: BLE001
                logger.warning("[graph] store_finding mirror failed: %s", exc)
        await ctx.emit("graph_finding_promoted", {
            "host": host, "finding_id": fid, "severity": state.findings[fid].severity,
            "title": state.findings[fid].title})
        return {"finding_id": fid, "severity": state.findings[fid].severity}

    # ── report_handoff ─────────────────────────────────────────────────────
    async def report_handoff(state: EngagementState, host: str) -> Dict[str, Any]:
        """Publishes the typed state into the master's intel so the EXISTING evidence
        collection + report phases consume it unchanged."""
        hs = state.host_state(host)
        tally = state.tally()
        if ctx.master is not None and isinstance(getattr(ctx.master, "_intel", None), dict):
            it = ctx.master._intel
            it.setdefault("services", {}).update(hs.intel.get("services") or {})
            existing_ports = set(it.get("open_ports") or [])
            it["open_ports"] = sorted(existing_ports | set(hs.intel.get("open_ports") or []))
            it["graph_engine"] = {
                "used": True, "host": host, "tally": tally,
                "terminal_reason": hs.terminal_reason,
                "degraded": hs.degraded, "degraded_reason": hs.degraded_reason,
                "visited": list(hs.visited),
            }
        await ctx.emit("graph_report_handoff", {"host": host, "tally": tally,
                                                "terminal_reason": hs.terminal_reason})
        return {"tally": tally}

    return {
        "recon_plan": recon_plan,
        "safety_gate": safety_gate,
        "tool_execute": tool_execute,
        "evidence_capture": evidence_capture,
        "fingerprint": fingerprint,
        "classify": classify,
        "hypothesize": hypothesize,
        "rank": rank,
        "select": select,
        "evidence_validate": evidence_validate,
        "finding_promote": finding_promote,
        "report_handoff": report_handoff,
    }
