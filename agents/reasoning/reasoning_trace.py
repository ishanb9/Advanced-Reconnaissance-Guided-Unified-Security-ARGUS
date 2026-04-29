"""\"Why?\" panel — reasoning chain trace (Improvement #17).

The reasoning loop already emits a fire-hose of WS events: hypothesis
updates, plan steps, validation verdicts, gate decisions, findings.
What it does **not** emit is the *causal chain* connecting any one of
those to its triggers.  When an operator looks at a confirmed
SQL-injection finding and asks "why did we even try sqlmap on this
endpoint?", the answer requires walking back through:

  observation: nmap reported port 80 open & whatweb saw php
  → hypothesis: T1190 SQLi on /search.php?id=
  → ranked: top-1 (score 0.71)
  → gates passed: dry-run risky/proceed, noise 60≤budget, critique proceed
  → executed: sqlmap --batch -u http://target/search.php?id=1
  → validated: grounded by [dbms fingerprint] & [error-based oracle]
  → finding: emitted as 'high'

Every one of those is a ``ReasoningStep`` with a parent pointer; the
trace is an append-only ring buffer (per session, capped at 1024 steps
to keep RAM bounded).  ``chain_for(step_id)`` walks ``parent_id``
backwards to the root and returns an ordered list — that's the
"Why?" payload.

The trace is also broadcast incrementally (one ``reasoning_trace_step``
WS event per record) and the most recent chain is rendered in
``MasterAgent._intel_summary`` so the LLM can self-reference its
prior reasoning when planning the next move.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import count
from typing import Any, Deque, Dict, List, Optional


logger = logging.getLogger(__name__)


__all__ = [
    "ReasoningStep", "ReasoningTrace", "STEP_KINDS",
]


# Recognised step kinds (free-form is allowed but these are the canonical set)
STEP_KINDS = (
    "observation",     # raw intel ingestion (port found, banner seen, …)
    "hypothesis",      # hypothesis generated / updated
    "rank",            # attack-path ranking refreshed
    "select",          # decision engine chose an action
    "gate",            # dry-run / noise / critique / scope decision
    "execute",         # action fired
    "validate",        # post-execute validation verdict
    "finding",         # finding promoted out of validation
    "pivot",           # opportunistic pivot fired
)


_STEP_ID_COUNTER = count(1)
_COUNTER_LOCK = threading.Lock()


def _next_step_id() -> str:
    with _COUNTER_LOCK:
        n = next(_STEP_ID_COUNTER)
    return f"rs-{n:06d}"


# ── Dataclass ──────────────────────────────────────────────────────────

@dataclass
class ReasoningStep:
    step_id:    str
    kind:       str
    summary:    str
    parent_id:  Optional[str] = None
    refs:       Dict[str, str] = field(default_factory=dict)
                # cross-ref keys: hypothesis_id, action_id, finding_id,
                # path_id, target, tool, ...
    payload:    Dict[str, Any] = field(default_factory=dict)
    iteration:  int = 0
    ts:         str = ""

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id":   self.step_id,
            "kind":      self.kind,
            "summary":   self.summary,
            "parent_id": self.parent_id,
            "refs":      dict(self.refs),
            "payload":   dict(self.payload),
            "iteration": self.iteration,
            "ts":        self.ts,
        }


# ── Trace ──────────────────────────────────────────────────────────────

class ReasoningTrace:
    """Append-only ring buffer of reasoning steps for a single session.

    Cap defaults to 1024 entries; older entries are evicted FIFO.  All
    methods are threadsafe (the reasoning loop is single-task but the
    master broadcaster lives elsewhere).
    """

    DEFAULT_CAP = 1024

    def __init__(self, *, session_id: str = "", cap: int = DEFAULT_CAP) -> None:
        self.session_id = session_id
        self.cap        = max(64, int(cap))
        self._steps: Deque[ReasoningStep] = deque(maxlen=self.cap)
        self._by_id:  Dict[str, ReasoningStep] = {}
        # Cross-ref indexes: ref-key (e.g., "action_id:abc") → list[step_id]
        self._index: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    # ── Mutation ────────────────────────────────────────────────────
    def record(
        self,
        *, kind: str,
        summary: str,
        parent_id: Optional[str] = None,
        refs: Optional[Dict[str, str]] = None,
        payload: Optional[Dict[str, Any]] = None,
        iteration: int = 0,
    ) -> ReasoningStep:
        step = ReasoningStep(
            step_id   = _next_step_id(),
            kind      = (kind or "observation").lower(),
            summary   = (summary or "").strip()[:240],
            parent_id = parent_id,
            refs      = dict(refs or {}),
            payload   = dict(payload or {}),
            iteration = int(iteration),
        )
        with self._lock:
            # If we are about to evict, also drop its index entries.
            if len(self._steps) == self._steps.maxlen:
                evicted = self._steps[0]
                self._by_id.pop(evicted.step_id, None)
                for k, v in list(self._index.items()):
                    if evicted.step_id in v:
                        v.remove(evicted.step_id)
                        if not v:
                            del self._index[k]
            self._steps.append(step)
            self._by_id[step.step_id] = step
            for k, val in step.refs.items():
                if not val:
                    continue
                key = f"{k}:{val}"
                self._index.setdefault(key, []).append(step.step_id)
        return step

    # ── Query ───────────────────────────────────────────────────────
    def get(self, step_id: str) -> Optional[ReasoningStep]:
        with self._lock:
            return self._by_id.get(step_id)

    def chain_for(self, step_id: str, *, max_depth: int = 24) -> List[ReasoningStep]:
        """Walk parent_id chain from ``step_id`` back to root."""
        with self._lock:
            seen: set = set()
            out:  List[ReasoningStep] = []
            cur = self._by_id.get(step_id)
            depth = 0
            while cur and cur.step_id not in seen and depth < max_depth:
                seen.add(cur.step_id)
                out.append(cur)
                if not cur.parent_id:
                    break
                cur = self._by_id.get(cur.parent_id)
                depth += 1
        return list(reversed(out))   # root → leaf

    def latest_step_for(self, ref_key: str, ref_value: str) -> Optional[ReasoningStep]:
        with self._lock:
            ids = self._index.get(f"{ref_key}:{ref_value}") or []
            if not ids:
                return None
            return self._by_id.get(ids[-1])

    def chain_for_ref(self, ref_key: str, ref_value: str) -> List[ReasoningStep]:
        latest = self.latest_step_for(ref_key, ref_value)
        if not latest:
            return []
        return self.chain_for(latest.step_id)

    def recent(self, n: int = 20) -> List[ReasoningStep]:
        with self._lock:
            return list(self._steps)[-n:]

    def to_dict_list(self, *, n: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._lock:
            steps = list(self._steps)
        if n is not None:
            steps = steps[-int(n):]
        return [s.to_dict() for s in steps]

    def __len__(self) -> int:
        with self._lock:
            return len(self._steps)


# ── Prompt rendering ───────────────────────────────────────────────────

def render_chain_for_prompt(chain: List[Any]) -> str:
    """Render a chain (root→leaf) as a compact prompt block."""
    if not chain:
        return ""
    lines = ["--- Last reasoning chain (why we just did what we did) ---"]
    for s in chain:
        if hasattr(s, "to_dict"):
            d = s.to_dict()
        else:
            d = dict(s)
        kind   = d.get("kind", "?")
        summ   = (d.get("summary") or "")[:140]
        it     = d.get("iteration", "?")
        lines.append(f"  [it={it}] {kind:11s}: {summ}")
    lines.append("---")
    return "\n".join(lines)
