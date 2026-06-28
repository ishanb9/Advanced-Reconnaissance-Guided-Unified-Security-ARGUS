"""Episodic memory across engagements (Improvement #8).

Each completed session is distilled into a small ``episode`` document and
persisted to ``db.engagement_episodes``.  When a new session starts, we
recall the most-relevant past episodes (matched by target_type / shared
services / shared CVEs) and inject them as a compact prompt block so the
LLM planners can benefit from prior lessons learned — what worked, what
was a dead-end, which chains paid off.

This module is a thin wrapper over the db functions in
``db.mongo_client``: it knows how to extract an episode payload from a
master agent's intel state, and how to render recalled episodes for
prompt injection.

The recall is intentionally a *hint* (rendered in `_intel_summary`),
never a hard filter — a fresh engagement should still gather first-hand
evidence and only use prior episodes to bias scan/exploit ordering.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


__all__ = [
    "build_episode_payload",
    "render_recall_block",
    "MAX_RECALL_FOR_PROMPT",
]


MAX_RECALL_FOR_PROMPT = 3   # how many recalled episodes to render in a prompt
_MAX_LESSONS_PER_EP   = 3
_MAX_CHARS_PER_FIELD  = 240


def _truncate(s: Any, n: int = _MAX_CHARS_PER_FIELD) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _extract_services(intel: Dict[str, Any]) -> List[str]:
    """Pull service names from intel.services dict and intel.technologies."""
    out: List[str] = []
    seen = set()
    svcs = intel.get("services") or {}
    if isinstance(svcs, dict):
        for v in svcs.values():
            if isinstance(v, dict):
                name = (v.get("name") or v.get("service") or "").lower()
            else:
                name = str(v).lower()
            if name and name not in seen:
                seen.add(name)
                out.append(name)
    for t in intel.get("technologies", []) or []:
        name = str(t).lower()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out[:20]


def _extract_cves(intel: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    seen = set()
    for c in intel.get("cves", []) or []:
        s = str(c).upper()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out[:20]


def _extract_validated_lessons(hypotheses: List[Any]) -> List[str]:
    """Pull short lesson strings from validated/invalidated hypotheses."""
    lessons: List[str] = []
    for h in hypotheses or []:
        if isinstance(h, dict):
            stmt = h.get("statement", "")
            valid = h.get("validated")
            invalid = h.get("invalidated")
        else:
            stmt = getattr(h, "statement", "")
            valid = getattr(h, "validated", False)
            invalid = getattr(h, "invalidated", False)
        if not stmt:
            continue
        if valid:
            lessons.append("✓ worked: " + _truncate(stmt))
        elif invalid:
            lessons.append("✗ dead-end: " + _truncate(stmt))
    return lessons[:_MAX_LESSONS_PER_EP * 2]


def build_episode_payload(
    *,
    session_id:    str,
    target:        str,
    target_type:   str,
    intel:         Dict[str, Any],
    hypotheses:    Optional[List[Any]]   = None,
    ranked_paths:  Optional[List[Any]]   = None,
    mission_brief: Optional[Any]         = None,
) -> Dict[str, Any]:
    """Distil current session state into an episode document for storage."""
    intel = intel or {}
    services = _extract_services(intel)
    cves     = _extract_cves(intel)
    lessons  = _extract_validated_lessons(hypotheses or [])

    # Best chain (from ranked_paths if available, else attack_path)
    best_chain: List[str] = []
    if ranked_paths:
        first = ranked_paths[0]
        if hasattr(first, "to_dict"):
            first = first.to_dict()
        if isinstance(first, dict):
            steps = first.get("steps") or first.get("nodes") or []
            for s in steps[:8]:
                if isinstance(s, dict):
                    best_chain.append(_truncate(s.get("description") or s.get("statement") or s, 120))
                else:
                    best_chain.append(_truncate(s, 120))
    if not best_chain:
        for step in (intel.get("attack_path") or [])[:8]:
            if isinstance(step, dict):
                best_chain.append(
                    f"[{step.get('phase','?')}] " + _truncate(step.get("result") or step.get("description") or "", 120)
                )

    objectives = []
    if mission_brief is not None:
        if hasattr(mission_brief, "model_dump"):
            mb = mission_brief.model_dump()
        elif hasattr(mission_brief, "dict"):
            mb = mission_brief.dict()
        elif isinstance(mission_brief, dict):
            mb = mission_brief
        else:
            mb = {}
        objectives = mb.get("objectives") or mb.get("primary_objectives") or []

    return {
        "session_id":   session_id,
        "target":       _truncate(target, 120),
        "target_type":  (target_type or "unknown").lower(),
        "objectives":   [_truncate(o, 160) for o in objectives][:6],
        "services":     services,
        "cves":         cves,
        "open_ports":   list(intel.get("open_ports") or [])[:30],
        "shell_obtained": bool(intel.get("shell_access")),
        "user_flag":    bool(intel.get("user_flag")),
        "root_flag":    bool(intel.get("root_flag")),
        "creds_count":  len(intel.get("credentials") or []),
        "lessons":      lessons[: _MAX_LESSONS_PER_EP * 2],
        "best_chain":   best_chain,
        "summary":      _truncate(
            f"{target_type} {target}: "
            f"{len(services)} svcs, {len(cves)} CVEs, "
            f"shell={'Y' if intel.get('shell_access') else 'N'}, "
            f"creds={len(intel.get('credentials') or [])}",
            300,
        ),
    }


def render_recall_block(episodes: List[Dict[str, Any]]) -> str:
    """Render a compact prompt block summarising recalled past engagements."""
    if not episodes:
        return ""
    eps = episodes[:MAX_RECALL_FOR_PROMPT]
    # These are OTHER, PRIOR engagements recalled as reference PATTERNS only — they are
    # NOT this target.  Label them unmistakably so neither the model nor the report ever
    # presents another box's hosts/CVEs/findings as facts about the current target.
    lines = ["=== EPISODIC MEMORY — OTHER PRIOR ENGAGEMENTS (reference patterns only; "
             "NOT this target — never cite as a finding here) ==="]
    for i, ep in enumerate(eps, 1):
        head = f"  [{i}] OTHER ENGAGEMENT: {ep.get('target_type','?')} → {ep.get('target','?')}"
        meta = []
        if ep.get("services"):
            meta.append(f"svcs={','.join(ep['services'][:5])}")
        if ep.get("cves"):
            meta.append(f"CVEs={','.join(ep['cves'][:3])}")
        if ep.get("shell_obtained"):
            meta.append("shell=Y")
        if meta:
            head += "  (" + " · ".join(meta) + ")"
        lines.append(head)
        for lesson in (ep.get("lessons") or [])[:_MAX_LESSONS_PER_EP]:
            lines.append("      " + _truncate(lesson, 200))
        chain = (ep.get("best_chain") or [])[:3]
        if chain:
            lines.append("      chain: " + " → ".join(_truncate(c, 60) for c in chain))
    lines.append(
        "Use these as priors; verify with first-hand evidence before acting."
    )
    return "\n".join(lines)
