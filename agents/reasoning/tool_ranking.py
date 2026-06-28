"""agents/reasoning/tool_ranking.py — consume tool-reliability telemetry (Gap #7).

ARGUS already WRITES per-tool reliability telemetry (success/failure counts under the
``tool_reliability`` memory type).  Nothing READ it back, so a tool that keeps failing
in the current environment kept getting picked.  This module is the read side: it
turns that telemetry into a soft re-ranking of candidate actions.

Design — deliberately conservative so it never hijacks the planner:
  • It only RE-ORDERS candidates; it never drops one (the chosen action can still be a
    low-reliability tool if it is the only option).
  • A high Value-of-Information score still wins — reliability is a TIE-BREAKER among
    comparable actions.
  • The one hard signal: a tool that has been tried enough times and NEVER succeeded
    this engagement ("dead") is pushed below tools that still might work.

All functions are pure and unit-testable.
"""
from __future__ import annotations

from typing import Any, Dict, List

#: Attempts before a 0-success tool is treated as "dead" for this engagement.
MIN_DEAD_SAMPLES = 4


def reliability_weight(stats: Dict[str, Any]) -> float:
    """Laplace-smoothed success rate in [0, 1].  No data → 0.5 (neutral), so an
    unproven tool is neither favoured nor punished."""
    stats = stats or {}
    try:
        s = max(0, int(stats.get("success", 0) or 0))
        f = max(0, int(stats.get("fail", stats.get("failure", 0)) or 0))
    except (TypeError, ValueError):
        return 0.5
    return (s + 1) / (s + f + 2)


def _stats_for(tool: str, telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """Look up a tool's stats, tolerating 'tool args…' by also trying the bare tool."""
    if tool in telemetry:
        return telemetry[tool] or {}
    head = tool.split()[0] if tool else ""
    return (telemetry.get(head) or {}) if head else {}


def apply_reliability(ranked: List[Dict[str, Any]],
                      telemetry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Annotate and re-order candidate actions by tool reliability.  Each candidate is
    a dict carrying at least ``tool`` (and optionally ``voi_score``).  Returns a new
    list, stably re-sorted: live tools before dead ones, then by VoI (desc), then by
    reliability (desc).  Never drops a candidate."""
    if not ranked:
        return ranked
    telemetry = telemetry or {}
    enriched: List[Dict[str, Any]] = []
    for c in ranked:
        tool = str(c.get("tool") or "")
        stats = _stats_for(tool, telemetry)
        try:
            s = max(0, int(stats.get("success", 0) or 0))
            f = max(0, int(stats.get("fail", stats.get("failure", 0)) or 0))
        except (TypeError, ValueError):
            s = f = 0
        attempts = s + f
        c2 = dict(c)
        c2["tool_reliability"] = round(reliability_weight({"success": s, "fail": f}), 3)
        c2["tool_attempts"] = attempts
        c2["tool_dead"] = bool(attempts >= MIN_DEAD_SAMPLES and s == 0)
        enriched.append(c2)

    enriched.sort(key=lambda c: (
        1 if c.get("tool_dead") else 0,                 # dead tools sink to the bottom
        -float(c.get("voi_score") or 0.0),              # VoI still leads
        -float(c.get("tool_reliability") or 0.5),       # reliability breaks the tie
    ))
    return enriched
