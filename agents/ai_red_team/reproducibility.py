"""reproducibility.py — export ARGUS AI probe runs to external red-team tools.

So a third party can independently reproduce ARGUS's AI findings, this maps the
knowledge-driven probe catalog into the config shapes of the common open-source
LLM red-team tools:

  - Promptfoo  (``promptfoo eval``)         → providers + prompts + tests/asserts
  - garak      (NVIDIA generative red-team) → probe/detector manifest
  - PyRIT      (Microsoft red-team)         → objectives + seed prompts + scorers

Content-agnostic: it reads the catalog (data) — adding an attack is still a YAML
entry, and it shows up in every export automatically.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def _assert_from_detector(d: str) -> Optional[Dict[str, str]]:
    """Map an ARGUS detector ("contains:X" / "regex:X") to a promptfoo assert."""
    if not d:
        return None
    if d.startswith("contains:"):
        return {"type": "icontains", "value": d[len("contains:"):]}
    if d.startswith("regex:"):
        return {"type": "regex", "value": d[len("regex:"):]}
    return {"type": "icontains", "value": d}


def to_promptfoo(catalog: List[Dict[str, Any]],
                 target_cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Promptfoo eval config (as a dict; dump to YAML/JSON to run with promptfoo)."""
    cfg = target_cfg or {}
    provider = cfg.get("model") or cfg.get("url") or "openai:gpt-4o-mini"
    tests: List[Dict[str, Any]] = []
    for p in catalog:
        detectors = (p.get("success") or {}).get("detectors") or []
        asserts = [a for a in (_assert_from_detector(d) for d in detectors) if a]
        for payload in (p.get("payloads") or []):
            tests.append({
                "vars": {"prompt": payload},
                "assert": asserts or [{"type": "llm-rubric",
                                       "value": (p.get("success") or {}).get("judge", "attack succeeded")}],
                "metadata": {"id": p.get("id"), "category": p.get("category"),
                             "owasp_llm": p.get("owasp_llm"), "atlas": p.get("atlas")},
            })
    return {
        "description": "ARGUS AI red-team export (promptfoo)",
        "providers": [provider],
        "prompts": ["{{prompt}}"],
        "tests": tests,
    }


def to_garak(catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    """garak-style probe/detector manifest."""
    probes = []
    for p in catalog:
        probes.append({
            "name": p.get("id"),
            "category": p.get("category"),
            "owasp_llm": p.get("owasp_llm"),
            "atlas": p.get("atlas"),
            "goal": p.get("goal", ""),
            "prompts": list(p.get("payloads") or []),
            "detectors": list((p.get("success") or {}).get("detectors") or []),
            "judge": (p.get("success") or {}).get("judge", ""),
            "destructive": bool(p.get("destructive")),
        })
    return {"argus_export": "garak", "version": 1, "probes": probes}


def to_pyrit(catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    """PyRIT-style objectives + seed prompts + scorers."""
    objectives = []
    for p in catalog:
        objectives.append({
            "name": p.get("id"),
            "objective": p.get("goal", "") or f"{p.get('category')} attack",
            "category": p.get("category"),
            "owasp_llm": p.get("owasp_llm"),
            "atlas": p.get("atlas"),
            "seed_prompts": list(p.get("payloads") or []),
            "success_detectors": list((p.get("success") or {}).get("detectors") or []),
            "judge_question": (p.get("success") or {}).get("judge", ""),
            "trials": int(p.get("trials", 3) or 3),
        })
    return {"argus_export": "pyrit", "version": 1, "objectives": objectives}


_EXPORTERS = {"promptfoo": to_promptfoo, "garak": to_garak, "pyrit": to_pyrit}


def export(catalog: List[Dict[str, Any]], fmt: str = "promptfoo",
           target_cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Dispatch to the requested exporter ('promptfoo'|'garak'|'pyrit')."""
    fn = _EXPORTERS.get((fmt or "").lower())
    if fn is None:
        raise ValueError(f"unknown reproducibility format: {fmt!r} "
                         f"(expected one of {sorted(_EXPORTERS)})")
    if fn is to_promptfoo:
        return fn(catalog, target_cfg)
    return fn(catalog)


def export_json(catalog: List[Dict[str, Any]], fmt: str = "promptfoo",
                target_cfg: Optional[Dict[str, Any]] = None) -> str:
    """Convenience: export(...) serialized to a JSON string."""
    return json.dumps(export(catalog, fmt, target_cfg), indent=2, ensure_ascii=False)


__all__ = ["to_promptfoo", "to_garak", "to_pyrit", "export", "export_json"]
