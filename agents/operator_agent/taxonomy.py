"""Weakness-taxonomy loader.

The taxonomy is DATA (``knowledge/weakness_taxonomy.json``): weakness CLASSES,
never specific vulns / CVEs / products / payloads. Engine code reads it; it never
hardcodes the content. JSON (stdlib) is used instead of YAML so there is no
third-party dependency to install on the target host.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict, List

_TAXONOMY_PATH = os.environ.get(
    "ARGUS_TAXONOMY_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "weakness_taxonomy.json"),
)


@lru_cache(maxsize=1)
def load_taxonomy() -> tuple:
    """Return the validated weakness-class table as a tuple of dicts (cached)."""
    try:
        with open(os.path.abspath(_TAXONOMY_PATH), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return tuple()
    if not isinstance(data, list):
        return tuple()
    out: List[Dict] = []
    for c in data:
        if isinstance(c, dict) and c.get("id") and c.get("name"):
            c.setdefault("triggering_capabilities", [])
            c.setdefault("generic_test_strategy", "")
            c.setdefault("confirm_signal", "")
            c.setdefault("objective_relevance", [])
            out.append(c)
    return tuple(out)


def classes_for_capabilities(capabilities: List[str], objective_kinds: List[str] = None) -> List[Dict]:
    """Weakness classes whose ``triggering_capabilities`` intersect a node's
    capabilities. Optionally narrow to classes relevant to the objective."""
    caps = set(capabilities or [])
    res: List[Dict] = []
    for c in load_taxonomy():
        if caps & set(c.get("triggering_capabilities", [])):
            if objective_kinds:
                if not (set(objective_kinds) & set(c.get("objective_relevance", []))):
                    continue
            res.append(dict(c))
    return res


def taxonomy_brief(max_classes: int = 60) -> str:
    """Compact 'id: name — strategy' list for injection into the operator's
    doctrine, so the prompt carries the taxonomy from DATA rather than hardcoded
    technique examples."""
    lines: List[str] = []
    for c in load_taxonomy()[:max_classes]:
        strat = (c.get("generic_test_strategy") or "").strip().replace("\n", " ")
        lines.append(f"- {c['id']}: {c['name']} — {strat[:160]}")
    return "\n".join(lines)
