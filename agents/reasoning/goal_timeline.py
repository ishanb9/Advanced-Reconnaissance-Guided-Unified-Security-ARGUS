"""Live goal-progress timeline (Improvement #18).

The mission brief (#1) defines win conditions; the win-condition tracker
(#2) flips each one to ``achieved=True`` once its evaluator fires.  What
we lack is a *temporal* view of progress — when each goal entered each
state, which goal is the next likely flip, and how many more iterations
the velocity model expects until completion.

This module is a thin layer on top of the win-condition snapshot.  It
maintains, per goal:

* **state**          — pending → probing → partial → met (or → blocked)
* **progress_pct**   — heuristic 0..100 even before the binary flip
* **milestones**     — ordered list of state-transition events with ts
                       and iteration markers, so the UI can draw a real
                       timeline
* **eta_iterations** — velocity-based estimate (mean iterations between
                       the last two transitions, applied to remaining
                       goals)
* **last_evidence**  — the evidence string from the win tracker

A goal is considered **probing** when at least one related signal has
appeared in intel (e.g. a ``user_flag`` goal becomes probing when any
``flag{...}`` regex hit lands), **partial** when concrete progress is
present but the binary check hasn't tripped yet (e.g. credentials
captured but no shell yet for an ``initial_access`` goal), **met** when
the win-tracker flips it.

The timeline is refreshed in the per-iteration chain alongside scan
profile / technique chains / inferred paths / posture.  On material
state changes we emit ``goal_timeline_updated`` and append a milestone.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


__all__ = [
    "GoalProgress", "GoalTimeline", "Milestone",
    "GOAL_STATES", "build_timeline_from_snapshot",
]


GOAL_STATES = ("pending", "probing", "partial", "met", "blocked")


# Substring → progress signals: which intel keys, when non-empty, push a
# matching goal from "pending" toward "partial".
_GOAL_SIGNAL_HINTS: List[Tuple[str, List[str]]] = [
    # (substring of goal name, list of intel keys that count as progress)
    ("shell",         ["shell_access", "shell_id", "current_user"]),
    ("initial_access",["credentials", "shell_access", "exploit_modules"]),
    ("user_flag",     ["user_flag", "flags"]),
    ("root_flag",     ["root_flag", "flags"]),
    ("flag",          ["user_flag", "root_flag", "flags"]),
    ("cred",          ["credentials"]),
    ("domain_admin",  ["credentials", "current_user", "shell_access"]),
    ("dcsync",        ["credentials"]),
    ("lateral",       ["lateral_targets", "pivot_paths", "credentials"]),
    ("persist",       ["persistence_artifacts"]),
    ("exfil",         ["exfil_targets", "exfil_data"]),
    ("privesc",       ["privesc_vectors", "current_user"]),
]


def _has_intel_signal(intel: Dict[str, Any], keys: List[str]) -> bool:
    if not isinstance(intel, dict):
        return False
    for k in keys:
        v = intel.get(k)
        if isinstance(v, (list, tuple, set, dict)):
            if len(v) > 0:
                return True
        elif isinstance(v, str):
            if v.strip():
                return True
        elif v:
            return True
    return False


def _pct_for_state(state: str, intel_signals_count: int = 0) -> int:
    """Heuristic 0..100 progress per state."""
    base = {
        "pending":  0,
        "probing":  20,
        "partial":  55,
        "met":      100,
        "blocked":  10,
    }.get(state, 0)
    if state in ("probing", "partial") and intel_signals_count > 1:
        base = min(95, base + 10 * intel_signals_count)
    return base


# ── Milestone ──────────────────────────────────────────────────────────

@dataclass
class Milestone:
    ts:         str = ""
    iteration:  int = 0
    kind:       str = "transition"   # "transition" | "evidence" | "blocked"
    from_state: str = ""
    to_state:   str = ""
    note:       str = ""

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts":         self.ts,
            "iteration":  self.iteration,
            "kind":       self.kind,
            "from_state": self.from_state,
            "to_state":   self.to_state,
            "note":       self.note,
        }


# ── Per-goal record ────────────────────────────────────────────────────

@dataclass
class GoalProgress:
    goal_id:       str = ""
    label:         str = ""
    description:   str = ""
    state:         str = "pending"
    progress_pct:  int  = 0
    last_evidence: str  = ""
    milestones:    List[Milestone] = field(default_factory=list)
    achieved_at:   Optional[float] = None
    achieved_iteration: Optional[int] = None
    last_iteration: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal_id":            self.goal_id,
            "label":              self.label,
            "description":        self.description,
            "state":              self.state,
            "progress_pct":       self.progress_pct,
            "last_evidence":      self.last_evidence,
            "milestones":         [m.to_dict() for m in self.milestones[-12:]],
            "achieved_at":        self.achieved_at,
            "achieved_iteration": self.achieved_iteration,
            "last_iteration":     self.last_iteration,
        }


# ── Timeline ───────────────────────────────────────────────────────────

class GoalTimeline:
    """Per-session goal-progress tracker."""

    def __init__(self) -> None:
        self.goals: Dict[str, GoalProgress] = {}
        self._created_at = time.time()

    # ── Update ──────────────────────────────────────────────────────
    def update(
        self,
        *, win_snapshot: Optional[Dict[str, Any]],
        intel:        Optional[Dict[str, Any]] = None,
        iteration:    int = 0,
    ) -> Tuple[bool, List[Milestone]]:
        """Reconcile current win-condition snapshot against tracked goals.

        Returns ``(changed, new_milestones)``.  ``changed`` is True when
        any goal transitioned state, gained evidence, or progress_pct
        moved enough to redraw.
        """
        intel = intel or {}
        new_milestones: List[Milestone] = []
        changed = False

        if not win_snapshot:
            return False, []

        conds = win_snapshot.get("conditions") or []
        if not isinstance(conds, list):
            return False, []

        seen_ids: set = set()
        for c in conds:
            if not isinstance(c, dict):
                continue
            name = str(c.get("name") or "").strip()
            if not name:
                continue
            goal_id = name.lower()
            seen_ids.add(goal_id)

            achieved = bool(c.get("achieved"))
            evidence = str(c.get("evidence") or "")

            # New goal — register
            if goal_id not in self.goals:
                gp = GoalProgress(
                    goal_id     = goal_id,
                    label       = name,
                    description = str(c.get("description") or ""),
                    state       = "pending",
                    progress_pct= 0,
                    last_iteration = iteration,
                )
                gp.milestones.append(Milestone(
                    iteration = iteration, kind = "transition",
                    from_state = "", to_state = "pending",
                    note = "goal registered",
                ))
                self.goals[goal_id] = gp
                changed = True
                new_milestones.append(gp.milestones[-1])

            gp = self.goals[goal_id]
            prior_state = gp.state
            new_state   = prior_state
            note        = ""

            if achieved:
                new_state = "met"
                if prior_state != "met":
                    gp.achieved_at        = time.time()
                    gp.achieved_iteration = iteration
                    gp.last_evidence      = evidence
                    note = f"WIN-CONDITION MET — {evidence[:80]}"
            else:
                # Heuristic state machine using intel signals.
                signals: List[str] = []
                for substr, keys in _GOAL_SIGNAL_HINTS:
                    if substr in goal_id:
                        signals.extend(k for k in keys if _has_intel_signal(intel, [k]))
                signals = sorted(set(signals))
                if signals:
                    # Two or more independent signals → "partial"; one → "probing"
                    new_state = "partial" if len(signals) >= 2 else "probing"
                    note = (f"signals: {', '.join(signals[:4])}" if signals else "")
                else:
                    new_state = "pending" if prior_state in ("pending", "blocked") else prior_state

            # Compute progress_pct
            sig_count = len([s for s in (note.split(":")[-1].split(",") if note else []) if s.strip()])
            gp.progress_pct = _pct_for_state(new_state, sig_count)

            if new_state != prior_state:
                m = Milestone(
                    iteration  = iteration,
                    kind       = "transition",
                    from_state = prior_state,
                    to_state   = new_state,
                    note       = note or f"{prior_state} → {new_state}",
                )
                gp.milestones.append(m)
                new_milestones.append(m)
                gp.state = new_state
                changed = True
            elif note and (not gp.last_evidence or note != gp.last_evidence):
                # Same state but new evidence — record as evidence milestone
                m = Milestone(
                    iteration = iteration, kind = "evidence",
                    from_state = prior_state, to_state = prior_state,
                    note = note,
                )
                gp.milestones.append(m)
                new_milestones.append(m)
                changed = True

            if evidence and evidence != gp.last_evidence:
                gp.last_evidence = evidence
                changed = True

            gp.last_iteration = iteration

        return changed, new_milestones

    # ── Velocity / ETA ──────────────────────────────────────────────
    def estimate_eta(self) -> Dict[str, Any]:
        """Estimate remaining iterations from observed transition velocity."""
        achieved_iters: List[int] = sorted(
            g.achieved_iteration for g in self.goals.values()
            if g.achieved_iteration is not None
        )
        total = len(self.goals)
        met   = len(achieved_iters)
        remaining = total - met

        if remaining == 0:
            return {"met": met, "total": total, "remaining": 0,
                    "iters_per_goal": 0.0, "eta_iterations": 0}

        if len(achieved_iters) >= 2:
            gaps = [achieved_iters[i] - achieved_iters[i-1]
                    for i in range(1, len(achieved_iters))]
            avg = max(1.0, sum(gaps) / len(gaps))
        elif len(achieved_iters) == 1:
            # First win at iter N → assume same gap from now on.
            avg = max(1.0, float(achieved_iters[0]))
        else:
            avg = 0.0   # no data yet

        eta = int(round(avg * remaining)) if avg else 0
        return {
            "met":           met,
            "total":         total,
            "remaining":     remaining,
            "iters_per_goal": round(avg, 2),
            "eta_iterations": eta,
        }

    # ── Serialisation ───────────────────────────────────────────────
    def to_dict(self, *, iteration: int = 0) -> Dict[str, Any]:
        eta = self.estimate_eta()
        # Order goals by state priority: met → partial → probing → blocked → pending
        priority = {"met": 0, "partial": 1, "probing": 2, "blocked": 3, "pending": 4}
        ordered = sorted(
            self.goals.values(),
            key=lambda g: (priority.get(g.state, 9), g.label),
        )
        return {
            "iteration":     iteration,
            "summary":       eta,
            "goals":         [g.to_dict() for g in ordered],
            "all_met":       eta["remaining"] == 0 and eta["total"] > 0,
        }

    def signature(self) -> Tuple[Tuple[str, str, int], ...]:
        """Stable identity for change-detection (state + progress only)."""
        return tuple(sorted(
            (g.goal_id, g.state, g.progress_pct) for g in self.goals.values()
        ))


# ── Helpers ─────────────────────────────────────────────────────────────

def build_timeline_from_snapshot(
    snapshot: Dict[str, Any],
    *, intel: Optional[Dict[str, Any]] = None,
    iteration: int = 0,
    prior: Optional[GoalTimeline] = None,
) -> Tuple[GoalTimeline, bool, List[Milestone]]:
    """Convenience: take a win-conditions snapshot, return (timeline, changed, milestones)."""
    tl = prior or GoalTimeline()
    changed, ms = tl.update(win_snapshot=snapshot, intel=intel, iteration=iteration)
    return tl, changed, ms


def render_timeline_for_prompt(tl: Optional[GoalTimeline]) -> str:
    """Compact LLM-prompt block.  Empty if no goals registered."""
    if tl is None or not tl.goals:
        return ""
    payload = tl.to_dict()
    eta = payload["summary"]
    lines = [
        "=== GOAL TIMELINE ===",
        f"  progress : {eta['met']}/{eta['total']} met"
        + (f"  · ETA ≈ {eta['eta_iterations']} iters "
           f"(avg {eta['iters_per_goal']}/goal)" if eta.get("eta_iterations") else ""),
    ]
    icon = {"met": "✓", "partial": "◐", "probing": "·", "blocked": "✗", "pending": "○"}
    for g in payload["goals"][:8]:
        ic = icon.get(g["state"], "?")
        bar_len = 20
        filled = int(round(bar_len * g["progress_pct"] / 100.0))
        bar = "█" * filled + "·" * (bar_len - filled)
        line = f"  {ic} {g['label']:24s} [{bar}] {g['progress_pct']:3d}%  {g['state']}"
        if g.get("last_evidence"):
            line += f"  — {g['last_evidence'][:80]}"
        lines.append(line)
    if payload["all_met"]:
        lines.append("  → ALL WIN CONDITIONS MET — engagement objective achieved.")
    lines.append("=== END GOAL TIMELINE ===")
    return "\n".join(lines)
