"""agents/graph/state.py — G1: the TYPED ENGAGEMENT STATE.

ONE pydantic model is the single source of truth for a graph-orchestrated session.
Every node reads and writes it; nothing else is authoritative.  That collapses the
audit's "counts don't reconcile" class of bug into ONE state with ONE tally: the
store, the dashboard and the report all read `EngagementState.tally()`.

Design rules
------------
* Serializable + versioned (``schema_version``) so a checkpoint written by an older
  build is detectable rather than silently mis-read.
* Tool calls are keyed by a DETERMINISTIC ``call_id`` = sha1(tool|args|host).  That
  key is what makes the graph->loop handoff (G7) able to prove "already executed,
  do not re-run" without guessing.
* A finding is only counted once it is ``promoted``.  Promotion is gated
  topologically (only ``evidence_validate`` may reach ``finding_promote``), so an
  unvalidated/LLM-authored claim can never enter the tally.
* No LLM output is trusted as evidence: an EvidenceRecord carries the CAPTURED tool
  artifact and its validation verdict, never a model's narration of one.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# Bump when a field's MEANING changes (not for additive optional fields).
STATE_SCHEMA_VERSION = 1


def call_key(tool: str, args: str, host: str) -> str:
    """Deterministic identity of a tool invocation — the dedupe key shared by the
    graph engine and the loop engine after a rollback (G7: 'no double work')."""
    raw = f"{(tool or '').strip()}|{(args or '').strip()}|{(host or '').strip()}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


class ToolCallRecord(BaseModel):
    """One executed (or gate-blocked) tool invocation.  The ONLY place captured
    output enters the state."""
    call_id:      str
    tool:         str
    args:         str = ""
    host:         str = ""
    phase:        str = ""
    node:         str = ""                 # graph node that produced it
    gate_decision: str = "allow"           # allow | deny | rewrite | require_approval
    gate_reason:  str = ""
    executed:     bool = False             # False for a gate DENY (no traffic sent)
    exit_code:    Optional[int] = None
    stdout:       str = ""                 # captured artifact (truncated by the node)
    stderr:       str = ""
    duration_sec: float = 0.0
    ts:           float = Field(default_factory=time.time)


class EvidenceRecord(BaseModel):
    """A captured artifact plus its validation verdict.  ``validated`` is set ONLY by
    the evidence_validate node via the existing issue_validator grounding gate."""
    evidence_id:  str
    tool_call_id: str
    host:         str = ""
    claim:        str = ""                 # what the engine THINKS this shows
    artifact:     str = ""                 # captured stdout/stderr — never LLM prose
    captured:     bool = False             # a real, non-empty tool artifact exists
    validated:    bool = False             # grounded per issue_validator
    issue_class:  str = ""
    reason:       str = ""
    ts:           float = Field(default_factory=time.time)


class FindingRecord(BaseModel):
    """A finding.  Counted in the tally ONLY when ``promoted`` is True."""
    finding_id:  str
    host:        str = ""
    title:       str = ""
    severity:    str = "info"
    description: str = ""
    evidence_id: str = ""
    promoted:    bool = False
    rejected_reason: str = ""              # set when evidence_validate refused it
    source_engine:  str = "graph"          # graph | loop — provenance across rollback
    ts:          float = Field(default_factory=time.time)


class HostState(BaseModel):
    """Per-host slice: intel, planning substrate, node progress, engine provenance."""
    host:          str
    intel:         Dict[str, Any] = Field(default_factory=dict)
    hypotheses:    List[Dict[str, Any]] = Field(default_factory=list)
    ranked_paths:  List[Dict[str, Any]] = Field(default_factory=list)
    selected:      Optional[Dict[str, Any]] = None    # the action chosen this cycle
    node_status:   Dict[str, str] = Field(default_factory=dict)   # node -> ok|failed|skipped
    visited:       List[str] = Field(default_factory=list)        # execution order
    cycles:        int = 0                 # completed select->execute->validate laps
    # ── engine provenance / rollback (G7) ──
    engine:         str  = "graph"         # graph | loop
    degraded:       bool = False
    degraded_reason: str = ""
    degraded_at_node: str = ""
    fallback_count: int  = 0               # LATCH: >=1 means never fall back again
    terminal_reason: str = ""              # convergence | budget | no_hypotheses | scope_complete


class Budgets(BaseModel):
    """Hard halt guarantees — the runtime's belt to the topology's braces."""
    max_nodes:      int = 200
    nodes_executed: int = 0
    max_seconds:    float = 1800.0
    started_at:     float = Field(default_factory=time.time)
    max_tool_calls: int = 60
    max_cycles:     int = 8                # select->execute->validate laps per host

    def exhausted(self) -> "tuple[bool, str]":
        if self.nodes_executed >= self.max_nodes:
            return True, f"node budget exhausted ({self.nodes_executed}/{self.max_nodes})"
        if (time.time() - self.started_at) >= self.max_seconds:
            return True, f"wall-clock budget exhausted ({self.max_seconds:.0f}s)"
        return False, ""


class Decision(BaseModel):
    """An auditable routing/gate decision — why the graph went where it went."""
    node:   str
    kind:   str            # edge | gate | terminal | rollback | retry
    detail: str = ""
    ts:     float = Field(default_factory=time.time)


class EngagementState(BaseModel):
    """THE single source of truth for one graph-orchestrated engagement."""
    schema_version: int = STATE_SCHEMA_VERSION
    session_id:     str = ""
    scope_hosts:    List[str] = Field(default_factory=list)
    targets:        List[str] = Field(default_factory=list)

    hosts:      Dict[str, HostState]     = Field(default_factory=dict)
    tool_calls: Dict[str, ToolCallRecord] = Field(default_factory=dict)  # call_id -> record
    evidence:   Dict[str, EvidenceRecord] = Field(default_factory=dict)
    findings:   Dict[str, FindingRecord]  = Field(default_factory=dict)

    budgets:   Budgets        = Field(default_factory=Budgets)
    decisions: List[Decision] = Field(default_factory=list)

    # ── helpers (pure) ────────────────────────────────────────────────────
    def host_state(self, host: str) -> HostState:
        hs = self.hosts.get(host)
        if hs is None:
            hs = HostState(host=host)
            self.hosts[host] = hs
        return hs

    def already_executed(self, tool: str, args: str, host: str) -> bool:
        """True if this exact invocation already RAN (dedupe across engines).  A
        gate-DENIED call is NOT 'executed' — the loop may legitimately re-gate it."""
        rec = self.tool_calls.get(call_key(tool, args, host))
        return bool(rec and rec.executed)

    def record_decision(self, node: str, kind: str, detail: str = "") -> None:
        self.decisions.append(Decision(node=node, kind=kind, detail=detail[:500]))

    def tally(self) -> Dict[str, int]:
        """THE reconciliation point — store == dashboard == report all read this.
        Only PROMOTED findings count; rejected claims are reported separately so a
        gap is visible rather than silent."""
        promoted = [f for f in self.findings.values() if f.promoted]
        by_sev: Dict[str, int] = {}
        for f in promoted:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "findings":            len(promoted),
            "findings_rejected":   sum(1 for f in self.findings.values() if not f.promoted),
            "tool_calls":          sum(1 for t in self.tool_calls.values() if t.executed),
            "tool_calls_blocked":  sum(1 for t in self.tool_calls.values()
                                       if t.gate_decision in ("deny", "require_approval")),
            "evidence_captured":   sum(1 for e in self.evidence.values() if e.captured),
            "evidence_validated":  sum(1 for e in self.evidence.values() if e.validated),
            "hosts_degraded":      sum(1 for h in self.hosts.values() if h.degraded),
            **{f"sev_{k}": v for k, v in sorted(by_sev.items())},
        }

    # ── serialization (checkpoint payload) ────────────────────────────────
    def to_checkpoint(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_checkpoint(cls, payload: Dict[str, Any]) -> "EngagementState":
        """Rehydrate.  Raises on a corrupt/incompatible payload — the caller treats
        that as an ENGINE failure (G7 trigger), never as an empty success."""
        if not isinstance(payload, dict):
            raise ValueError("checkpoint payload is not a dict")
        ver = int(payload.get("schema_version") or 0)
        if ver != STATE_SCHEMA_VERSION:
            raise ValueError(
                f"state schema mismatch: checkpoint v{ver} != runtime v{STATE_SCHEMA_VERSION}")
        return cls.model_validate(payload)
