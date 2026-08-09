"""agents/graph/runtime.py — G2/G3: a small in-repo graph control plane.

NO new dependencies (Z2): reachability, SCC/cycle detection and path enumeration over
a small edge map are plain Python here — importing an orchestration framework for
~30 lines of graph theory would be the wrong trade in a repo that already carries one
218 KB god-module.

What this provides
------------------
* a node registry + typed node contract (state -> delta), sync and async;
* static edges plus conditional (predicate) edges, and explicit TERMINAL edges;
* per-node execution policy: timeout, retry, fallback, fail-LOUD (never fail-silent);
* a checkpointer interface (backed by the existing Mongo checkpoint collection);
* per-node start/end/failure events onto the existing WS/event stream;
* ``validate_graph`` — the STATIC VALIDATOR that turns structural invariants into
  graph shape (G3): guarded inbound edges, no orphans, provable halt.

Failure taxonomy (drives G7 rollback):
    NodeFailure   — a NORMAL failure inside a node body (tool timed out, host
                    unreachable).  Handled by retry/fallback.  NOT a rollback.
    EngineFailure — the RUNTIME itself broke (bad graph, corrupt state, retry
                    exhausted on a structural node).  This is what triggers rollback.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Set

from agents.graph.state import EngagementState

logger = logging.getLogger(__name__)

# A node returns a DELTA description (free-form dict) after mutating state in place.
NodeFn = Callable[[EngagementState, str], Any]      # (state, host) -> dict | awaitable
Predicate = Callable[[EngagementState, str], bool]  # (state, host) -> take this edge?

TERMINAL = "__terminal__"      # the single sink every path must be able to reach


class NodeFailure(Exception):
    """A normal, expected failure inside a node body — retry/fallback territory."""


class EngineFailure(Exception):
    """The graph RUNTIME failed (not a node's subject matter).  Triggers rollback."""


class GraphValidationError(EngineFailure):
    """The graph's SHAPE violates a structural invariant.  Fails tests loudly."""


@dataclass
class NodeSpec:
    name:      str
    fn:        NodeFn
    timeout:   float = 300.0
    retries:   int   = 0            # additional attempts after the first
    fallback:  Optional[str] = None # node to route to when this node exhausts retries
    # STRUCTURAL nodes carry the engine's guarantees (gate/validate/promote/select).
    # Retry-exhaustion on one of these is an ENGINE failure, not a normal miss.
    structural: bool = False


@dataclass
class Edge:
    src:       str
    dst:       str
    predicate: Optional[Predicate] = None   # None => static (unconditional) edge
    label:     str = ""

    @property
    def is_conditional(self) -> bool:
        return self.predicate is not None


@dataclass
class GraphSpec:
    entry: str
    nodes: Dict[str, NodeSpec] = field(default_factory=dict)
    edges: List[Edge]          = field(default_factory=list)
    # G3 topology contracts: node -> the ONLY node names allowed to point at it.
    guarded_inbound: Dict[str, Set[str]] = field(default_factory=dict)

    def add_node(self, spec: NodeSpec) -> "GraphSpec":
        if spec.name in self.nodes:
            raise GraphValidationError(f"duplicate node '{spec.name}'")
        self.nodes[spec.name] = spec
        return self

    def add_edge(self, src: str, dst: str,
                 predicate: Optional[Predicate] = None, label: str = "") -> "GraphSpec":
        self.edges.append(Edge(src=src, dst=dst, predicate=predicate, label=label))
        return self

    def out_edges(self, node: str) -> List[Edge]:
        return [e for e in self.edges if e.src == node]

    def in_edges(self, node: str) -> List[Edge]:
        return [e for e in self.edges if e.dst == node]


# ══════════════════════════════════════════════════════════════════════════════
#  STATIC VALIDATOR (G3) — invariants enforced by SHAPE, checked in tests
# ══════════════════════════════════════════════════════════════════════════════
def _reachable_from(spec: GraphSpec, start: str) -> Set[str]:
    seen, stack = {start}, [start]
    while stack:
        cur = stack.pop()
        for e in spec.out_edges(cur):
            if e.dst not in seen:
                seen.add(e.dst)
                stack.append(e.dst)
    return seen


def _can_reach_terminal(spec: GraphSpec, start: str) -> bool:
    return TERMINAL in _reachable_from(spec, start)


def _sccs(spec: GraphSpec) -> List[List[str]]:
    """Tarjan strongly-connected components (iterative — no recursion limit risk)."""
    index: Dict[str, int] = {}
    low: Dict[str, int] = {}
    on_stack: Dict[str, bool] = {}
    stack: List[str] = []
    out: List[List[str]] = []
    counter = [0]
    nodes = list(spec.nodes.keys())

    for root in nodes:
        if root in index:
            continue
        work = [(root, 0)]
        while work:
            v, pi = work[-1]
            if pi == 0:
                index[v] = low[v] = counter[0]
                counter[0] += 1
                stack.append(v)
                on_stack[v] = True
            succs = [e.dst for e in spec.out_edges(v) if e.dst in spec.nodes]
            if pi < len(succs):
                work[-1] = (v, pi + 1)
                w = succs[pi]
                if w not in index:
                    work.append((w, 0))
                elif on_stack.get(w):
                    low[v] = min(low[v], index[w])
            else:
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on_stack[w] = False
                        comp.append(w)
                        if w == v:
                            break
                    out.append(comp)
                work.pop()
                if work:
                    u = work[-1][0]
                    low[u] = min(low[u], low[v])
    return out


def validate_graph(spec: GraphSpec) -> List[str]:
    """Return a list of structural violations (empty == valid).

    Enforces, as SHAPE rather than as a convention someone must remember:
      1. every edge endpoint exists (TERMINAL is the sink);
      2. GUARDED INBOUND — e.g. the only edge into ``tool_execute`` is from
         ``safety_gate``, and the only edge into ``finding_promote`` is from
         ``evidence_validate``;
      3. no orphan/unreachable node;
      4. every node can still reach TERMINAL (the graph provably halts);
      5. no trap SCC — a cycle with no edge leaving it would spin forever.
    """
    errs: List[str] = []
    names = set(spec.nodes)

    if spec.entry not in names:
        errs.append(f"entry node '{spec.entry}' is not registered")

    for e in spec.edges:
        if e.src not in names:
            errs.append(f"edge source '{e.src}' is not a registered node")
        if e.dst not in names and e.dst != TERMINAL:
            errs.append(f"edge target '{e.dst}' is not a registered node or TERMINAL")

    # (2) guarded inbound — the main prize
    for guarded, allowed in (spec.guarded_inbound or {}).items():
        if guarded not in names:
            errs.append(f"guarded node '{guarded}' is not registered")
            continue
        for e in spec.in_edges(guarded):
            if e.src not in allowed:
                errs.append(
                    f"INVARIANT VIOLATION: '{e.src}' -> '{guarded}' — the only allowed "
                    f"predecessor(s) of '{guarded}' are {sorted(allowed)}")
        if not spec.in_edges(guarded):
            errs.append(f"guarded node '{guarded}' is unreachable (no inbound edge)")

    if spec.entry in names:
        reach = _reachable_from(spec, spec.entry)
        # (3) orphans
        for n in sorted(names - reach):
            errs.append(f"node '{n}' is unreachable from entry '{spec.entry}' (orphan)")
        # (4) halting: every reachable node must still be able to reach TERMINAL
        for n in sorted(reach & names):
            if not _can_reach_terminal(spec, n):
                errs.append(f"node '{n}' cannot reach TERMINAL — the graph may not halt")

    # (5) trap SCCs
    for comp in _sccs(spec):
        if len(comp) < 2 and not any(e.src == comp[0] and e.dst == comp[0]
                                     for e in spec.edges):
            continue                      # trivial, non-self-looping component
        members = set(comp)
        escapes = any(e.dst not in members
                      for n in comp for e in spec.out_edges(n))
        if not escapes:
            errs.append(f"non-terminating cycle with no exit edge: {sorted(comp)}")
    return errs


# ══════════════════════════════════════════════════════════════════════════════
#  CHECKPOINTER
# ══════════════════════════════════════════════════════════════════════════════
class Checkpointer(Protocol):
    async def save(self, state: EngagementState, *, node: str, reason: str = "") -> Optional[str]: ...
    async def load(self, session_id: str) -> Optional[EngagementState]: ...


class InMemoryCheckpointer:
    """Test/CI checkpointer.  Same contract as the Mongo one."""
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}
        self.saves: List[str] = []

    async def save(self, state: EngagementState, *, node: str, reason: str = "") -> Optional[str]:
        self._store[state.session_id] = state.to_checkpoint()
        self.saves.append(node)
        return f"mem:{state.session_id}:{len(self.saves)}"

    async def load(self, session_id: str) -> Optional[EngagementState]:
        payload = self._store.get(session_id)
        return EngagementState.from_checkpoint(payload) if payload else None


class MongoCheckpointer:
    """Durable checkpointer over the EXISTING ``session_checkpoints`` collection —
    no new store, no new schema (Z3).  The typed state rides in ``intel_snapshot``
    under a namespaced key so a loop-engine checkpoint is never confused for one."""
    KEY = "_graph_state"

    def __init__(self, session_id: str, host: str = "", parent_session_id: str = "") -> None:
        self.session_id = session_id
        self.host = host
        self.parent_session_id = parent_session_id

    async def save(self, state: EngagementState, *, node: str, reason: str = "") -> Optional[str]:
        try:
            import db.mongo_client as _db
            return await _db.store_checkpoint(
                session_id       = self.session_id,
                host             = self.host,
                checkpoint_type  = "auto",
                state_machine    = "graph",
                current_phase    = node,
                intel_snapshot   = {self.KEY: state.to_checkpoint(),
                                    "_graph_checkpoint_reason": reason,
                                    "_graph_node": node},
                parent_session_id= self.parent_session_id or None,
            )
        except Exception as exc:                       # noqa: BLE001
            # A checkpoint we cannot write is a real problem, but it must not be the
            # thing that kills a live engagement — log LOUD and continue.
            logger.error("[graph] checkpoint save failed at node=%s: %s", node, exc)
            return None

    async def load(self, session_id: str) -> Optional[EngagementState]:
        import db.mongo_client as _db
        doc = await _db.get_latest_checkpoint(session_id)
        if not doc:
            return None
        payload = (doc.get("intel_snapshot") or {}).get(self.KEY)
        if not payload:
            return None
        # Deliberately NOT wrapped: a corrupt payload must raise so the caller can
        # classify it as an ENGINE failure (G7) instead of silently starting empty.
        return EngagementState.from_checkpoint(payload)


# ══════════════════════════════════════════════════════════════════════════════
#  RUNNER
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class RunResult:
    terminal_reason: str
    visited:         List[str]
    failed_node:     str = ""
    error:           str = ""


class GraphRunner:
    """Walks the graph for ONE host.  Never swallows: a node that cannot be retried
    or fallen back to raises, and the caller decides (retry / rollback / fail)."""

    def __init__(
        self,
        spec: GraphSpec,
        *,
        checkpointer: Optional[Checkpointer] = None,
        emit: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
        checkpoint_every: int = 1,
        consecutive_failure_limit: int = 3,
        stall_limit: int = 6,
    ) -> None:
        errs = validate_graph(spec)
        if errs:
            # A malformed graph must never run — this is the fail-loud entry point.
            raise GraphValidationError("; ".join(errs))
        self.spec = spec
        self.checkpointer = checkpointer
        self._emit_fn = emit
        self.checkpoint_every = max(1, int(checkpoint_every))
        self.consecutive_failure_limit = max(1, int(consecutive_failure_limit))
        self.stall_limit = max(1, int(stall_limit))

    async def _emit(self, event: str, data: Dict[str, Any]) -> None:
        if self._emit_fn is None:
            return
        try:
            await self._emit_fn(event, data)
        except Exception:                              # noqa: BLE001
            pass          # observability must never break execution

    async def _run_node(self, spec: NodeSpec, state: EngagementState, host: str) -> Any:
        """Execute one node under its policy.  Raises NodeFailure when the body fails
        after all retries; raises EngineFailure when a STRUCTURAL node does."""
        attempts = spec.retries + 1
        last_exc: Optional[BaseException] = None
        for attempt in range(1, attempts + 1):
            t0 = time.time()
            await self._emit("graph_node_start", {
                "node": spec.name, "host": host, "attempt": attempt})
            try:
                res = spec.fn(state, host)
                if inspect.isawaitable(res):
                    res = await asyncio.wait_for(res, timeout=spec.timeout)
                await self._emit("graph_node_end", {
                    "node": spec.name, "host": host, "attempt": attempt,
                    "duration_sec": round(time.time() - t0, 3),
                    "delta": res if isinstance(res, dict) else {}})
                return res
            except asyncio.CancelledError:
                raise                                   # operator stop — never swallow
            except Exception as exc:                    # noqa: BLE001
                last_exc = exc
                await self._emit("graph_node_failed", {
                    "node": spec.name, "host": host, "attempt": attempt,
                    "error": f"{type(exc).__name__}: {exc}",
                    "will_retry": attempt < attempts,
                    "traceback": traceback.format_exc()[-1500:]})
                logger.warning("[graph] node=%s host=%s attempt=%d/%d failed: %s",
                               spec.name, host, attempt, attempts, exc)
        detail = f"{type(last_exc).__name__}: {last_exc}"
        if spec.structural:
            # Retry-exhausted on a node that carries a guarantee => ENGINE failure.
            raise EngineFailure(
                f"structural node '{spec.name}' exhausted {attempts} attempt(s): {detail}")
        raise NodeFailure(f"node '{spec.name}' exhausted {attempts} attempt(s): {detail}")

    def _next_node(self, current: str, state: EngagementState, host: str) -> str:
        """Pick the outgoing edge.  Conditional edges are evaluated in declaration
        order; the first static edge is the default.  A node with no viable edge is
        a GRAPH bug (the validator should have caught it) -> EngineFailure."""
        static_edge: Optional[Edge] = None
        for e in self.spec.out_edges(current):
            if not e.is_conditional:
                if static_edge is None:
                    static_edge = e
                continue
            try:
                take = bool(e.predicate(state, host))   # type: ignore[misc]
            except Exception as exc:                    # noqa: BLE001
                raise EngineFailure(
                    f"edge predicate {current}->{e.dst} raised: "
                    f"{type(exc).__name__}: {exc}") from exc
            if take:
                state.record_decision(current, "edge", f"-> {e.dst} ({e.label or 'conditional'})")
                return e.dst
        if static_edge is not None:
            state.record_decision(current, "edge", f"-> {static_edge.dst} (default)")
            return static_edge.dst
        raise EngineFailure(f"node '{current}' has no viable outgoing edge")

    async def run(self, state: EngagementState, host: str,
                  start_at: Optional[str] = None) -> RunResult:
        """Walk from ``start_at`` (or the entry) until TERMINAL.  Resume = pass the
        last completed node's successor as ``start_at``."""
        hs = state.host_state(host)
        current = start_at or self.spec.entry
        consecutive_failures = 0
        stall = 0
        steps_since_ckpt = 0
        # Stall is measured per REVISIT of a node, not per consecutive node: between
        # two tool executions the graph legitimately walks ~7 analysis nodes that add
        # no tool call / evidence / finding, and counting those as "no progress"
        # falsely trips the rollback on a perfectly healthy run.  Returning to the
        # SAME node with an unchanged progress fingerprint is a genuinely wasted lap.
        last_fp_at_node: Dict[str, tuple] = {}

        while current != TERMINAL:
            exhausted, why = state.budgets.exhausted()
            if exhausted:
                hs.terminal_reason = hs.terminal_reason or f"budget: {why}"
                state.record_decision(current, "terminal", why)
                await self._emit("graph_terminal", {"host": host, "reason": why})
                return RunResult(terminal_reason=hs.terminal_reason, visited=list(hs.visited))

            spec = self.spec.nodes.get(current)
            if spec is None:
                raise EngineFailure(f"routed to unregistered node '{current}'")

            fingerprint = (len(state.tool_calls), len(state.evidence), len(state.findings))
            try:
                await self._run_node(spec, state, host)
                hs.node_status[current] = "ok"
                consecutive_failures = 0
            except NodeFailure as nf:
                # NORMAL failure: mark, take the declared fallback if any, keep going.
                hs.node_status[current] = "failed"
                consecutive_failures += 1
                state.record_decision(current, "retry", str(nf)[:300])
                if consecutive_failures >= self.consecutive_failure_limit:
                    raise EngineFailure(
                        f"{consecutive_failures} consecutive node failures "
                        f"(last: {current}) — engine is not making progress") from nf
                if spec.fallback:
                    state.record_decision(current, "edge", f"-> {spec.fallback} (fallback)")
                    hs.visited.append(current)
                    state.budgets.nodes_executed += 1
                    current = spec.fallback
                    continue
                # No fallback declared: fall through to normal routing so a failed
                # optional node cannot wedge the walk.
            finally:
                hs.visited.append(current)
                state.budgets.nodes_executed += 1

            # stall detection — a REVISIT to this node with an unchanged progress
            # fingerprint means the last lap accomplished nothing.
            now_fp = (len(state.tool_calls), len(state.evidence), len(state.findings))
            if current in last_fp_at_node and last_fp_at_node[current] == now_fp:
                stall += 1
                if stall >= self.stall_limit:
                    raise EngineFailure(
                        f"no progress across {stall} laps (node '{current}' revisited "
                        f"with an unchanged state fingerprint)")
            elif now_fp != fingerprint:
                stall = 0          # real forward progress resets the counter
            last_fp_at_node[current] = now_fp

            steps_since_ckpt += 1
            if self.checkpointer is not None and steps_since_ckpt >= self.checkpoint_every:
                steps_since_ckpt = 0
                await self.checkpointer.save(state, node=current, reason="step")

            current = self._next_node(current, state, host)

        hs.terminal_reason = hs.terminal_reason or "graph_complete"
        await self._emit("graph_terminal", {"host": host, "reason": hs.terminal_reason})
        if self.checkpointer is not None:
            await self.checkpointer.save(state, node=TERMINAL, reason="terminal")
        return RunResult(terminal_reason=hs.terminal_reason, visited=list(hs.visited))


def render_edges(spec: GraphSpec) -> str:
    """Human-readable edge list (used in tests/docs and the node/edge map)."""
    lines = [f"entry: {spec.entry}"]
    for e in spec.edges:
        arrow = "-->" if not e.is_conditional else f"--[{e.label or 'cond'}]-->"
        lines.append(f"  {e.src} {arrow} {e.dst}")
    return "\n".join(lines)
