"""probe_catalog.py — load the knowledge-driven AI red-team probe catalog.

The catalog is DATA, not code: each attack class is a YAML list of probes under
``knowledge/data/ai_security/``.  Adding an attack = adding a YAML entry — no
Python per payload.  All AI attack *content* lives in that data dir + this
capability module, never in the guarded operator doctrine spine.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_DIR = (Path(__file__).resolve().parent.parent.parent
                / "knowledge" / "data" / "ai_security")

_REQUIRED = ("id", "category", "payloads")


def _coerce(p: Dict[str, Any]) -> Dict[str, Any]:
    """Fill defaults so every probe has a uniform shape for the harness."""
    p.setdefault("owasp_llm", "")
    p.setdefault("atlas", "")
    p.setdefault("severity", "medium")
    p.setdefault("vectors", [])
    p.setdefault("goal", "")
    succ = p.get("success")
    if not isinstance(succ, dict):
        succ = {}
    succ.setdefault("detectors", [])
    succ.setdefault("judge", "")
    p["success"] = succ
    try:
        p["trials"] = max(1, int(p.get("trials", 3) or 3))
    except Exception:
        p["trials"] = 3
    p["adaptive"] = bool(p.get("adaptive", False))
    p["destructive"] = bool(p.get("destructive", False))
    if not isinstance(p.get("payloads"), list):
        p["payloads"] = [str(p.get("payloads"))]
    return p


def load_catalog(root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all valid probes across every YAML class file (or [] on any
    problem — never raises)."""
    try:
        import yaml  # pyyaml is already an ARGUS dependency
    except Exception:
        return []
    d = Path(root) if root else _DEFAULT_DIR
    out: List[Dict[str, Any]] = []
    if not d.exists():
        return out
    for f in sorted(d.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for item in data:
            if isinstance(item, dict) and all(k in item for k in _REQUIRED) and item.get("payloads"):
                out.append(_coerce(dict(item)))
    return out


def categories(catalog: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    cat = catalog if catalog is not None else load_catalog()
    return sorted({str(p.get("category", "")) for p in cat if p.get("category")})
