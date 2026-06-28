"""skill_telemetry.py — effectiveness telemetry + learned weights for the skill registry.

Records, per skill, what actually happened on real engagements:
  - ``fired``        : the skill matched recon intel
  - ``findings``     : a genuine finding was attributed to it
  - ``qw_attempts`` / ``qw_success`` : a safe quick-win was auto-dispatched and
    (did / did not) produce usable output

From that it derives a **learned weight** (a prioritisation multiplier) and a
``needs_review`` flag for skills that keep firing but never yield — turning the
catalog from *self-updating* into *self-learning*.  Backs #1 (learning loop),
#2 (prioritisation), and #5 (effectiveness report).

Best-effort + offline: a JSON file under ``knowledge/skills/`` (override with
``ARGUS_SKILL_TELEMETRY_PATH``).  Never raises into the engagement.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_PATH = Path(__file__).resolve().parent / "skills" / ".telemetry.json"
# A skill that fired this many times with zero findings is flagged for review.
_REVIEW_AFTER = 5
_WEIGHT_MIN, _WEIGHT_MAX = 0.4, 3.0
_SEV_KEYS = ("critical", "high", "medium", "low", "info")


def _path() -> Path:
    return Path(os.environ.get("ARGUS_SKILL_TELEMETRY_PATH") or _DEFAULT_PATH)


def _load() -> Dict[str, Any]:
    try:
        p = _path()
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    return {}


def _save(data: Dict[str, Any]) -> None:
    try:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _entry(data: Dict[str, Any], skill_id: str) -> Dict[str, Any]:
    e = data.get(skill_id)
    if not isinstance(e, dict):
        e = {"fired": 0, "findings": 0, "qw_attempts": 0, "qw_success": 0,
             "weight": 1.0, "needs_review": False, "sev": {}}
        data[skill_id] = e
    e.setdefault("fired", 0); e.setdefault("findings", 0)
    e.setdefault("qw_attempts", 0); e.setdefault("qw_success", 0)
    e.setdefault("weight", 1.0); e.setdefault("needs_review", False)
    e.setdefault("sev", {})
    return e


def record_fired(skill_id: str) -> None:
    if not skill_id:
        return
    data = _load()
    e = _entry(data, skill_id)
    e["fired"] += 1
    _recompute_entry(e)   # keep weight + needs_review current even for fire-only skills
    _save(data)


def record_finding(skill_id: str, severity: str = "") -> None:
    if not skill_id:
        return
    data = _load()
    e = _entry(data, skill_id)
    e["findings"] += 1
    sev = str(severity or "").lower().replace("findingseverity.", "")
    if sev in _SEV_KEYS:
        e["sev"][sev] = e["sev"].get(sev, 0) + 1
    _recompute_entry(e)
    _save(data)


def record_quick_win(skill_id: str, success: bool) -> None:
    if not skill_id:
        return
    data = _load()
    e = _entry(data, skill_id)
    e["qw_attempts"] += 1
    if success:
        e["qw_success"] += 1
    _recompute_entry(e)
    _save(data)


def _recompute_entry(e: Dict[str, Any]) -> None:
    fired = max(int(e.get("fired", 0)), 0)
    findings = int(e.get("findings", 0))
    qa = int(e.get("qw_attempts", 0))
    qs = int(e.get("qw_success", 0))
    hit_rate = (findings / fired) if fired else 0.0
    qw_rate = (qs / qa) if qa else 0.0
    # Baseline 1.0; reward demonstrated yield, gently penalise fire-but-no-yield.
    weight = 1.0 + min(hit_rate, 1.0) + 0.5 * qw_rate
    if fired >= _REVIEW_AFTER and findings == 0 and qs == 0:
        weight *= 0.6
        e["needs_review"] = True
    else:
        e["needs_review"] = False
    e["weight"] = round(max(_WEIGHT_MIN, min(_WEIGHT_MAX, weight)), 3)


def learned_weight(skill_id: str) -> float:
    """Prioritisation multiplier for a skill (1.0 until it has a track record)."""
    if not skill_id:
        return 1.0
    e = _load().get(skill_id)
    try:
        return float(e.get("weight", 1.0)) if isinstance(e, dict) else 1.0
    except Exception:
        return 1.0


def recompute_weights() -> Dict[str, Any]:
    data = _load()
    for e in data.values():
        if isinstance(e, dict):
            _recompute_entry(e)
    _save(data)
    return data


def learn_from_engagement(fired_ids: List[str], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """At engagement end: attribute genuine findings to the skills that fired
    (keyword match against finding title/description), then refresh weights +
    review flags.  Returns a summary.  Best-effort; never raises."""
    try:
        data = _load()
        fired_ids = [str(i) for i in (fired_ids or []) if i]
        # Build a lowercase haystack of the engagement's non-detection findings.
        attributed = 0
        for fid in set(fired_ids):
            e = _entry(data, fid)
            kws = {t for t in re.split(r"[^a-z0-9]+", fid.lower()) if len(t) >= 3}
            for f in (findings or []):
                if not isinstance(f, dict):
                    continue
                # Skip the skill's own "<tech> detected" record — we want REAL yield.
                if str(f.get("tool_used", "")) in ("skill_registry", "capability"):
                    continue
                hay = f"{f.get('title','')} {f.get('description','')}".lower()
                if kws and any(k in hay for k in kws):
                    e["findings"] += 1
                    attributed += 1
                    sev = str(f.get("severity", "")).lower().replace("findingseverity.", "")
                    if sev in _SEV_KEYS:
                        e["sev"][sev] = e["sev"].get(sev, 0) + 1
                    break
            _recompute_entry(e)
        _save(data)
        flagged = [k for k, v in data.items() if isinstance(v, dict) and v.get("needs_review")]
        return {"fired": len(set(fired_ids)), "attributed": attributed,
                "needs_review": flagged}
    except Exception:
        return {"fired": 0, "attributed": 0, "needs_review": []}


def stats(skill_id: str) -> Dict[str, Any]:
    return dict(_load().get(skill_id) or {})


def all_stats() -> Dict[str, Any]:
    return _load()


def effectiveness_report(top: Optional[int] = None) -> List[Dict[str, Any]]:
    """Per-skill effectiveness, highest-yield first — the 'what's working' view."""
    rows: List[Dict[str, Any]] = []
    for sid, e in _load().items():
        if not isinstance(e, dict):
            continue
        fired = int(e.get("fired", 0))
        findings = int(e.get("findings", 0))
        qa = int(e.get("qw_attempts", 0))
        qs = int(e.get("qw_success", 0))
        rows.append({
            "id": sid, "fired": fired, "findings": findings,
            "hit_rate": round((findings / fired), 3) if fired else 0.0,
            "qw_attempts": qa, "qw_success": qs,
            "qw_rate": round((qs / qa), 3) if qa else 0.0,
            "weight": float(e.get("weight", 1.0)),
            "needs_review": bool(e.get("needs_review")),
        })
    rows.sort(key=lambda r: (r["weight"], r["findings"], r["hit_rate"]), reverse=True)
    return rows[:top] if top else rows


def reset() -> None:
    """Clear the store (used by tests)."""
    try:
        p = _path()
        if p.exists():
            p.unlink()
    except Exception:
        pass


__all__ = ["record_fired", "record_finding", "record_quick_win", "learned_weight",
           "recompute_weights", "learn_from_engagement", "stats", "all_stats",
           "effectiveness_report", "reset"]
