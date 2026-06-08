"""Playbooks as DATA, keyed by weakness CLASS.

Each playbook is a list of GENERIC procedure steps the operator instantiates
against the concrete target — never a box-specific script, never a hardcoded
payload in engine code. Stored as JSON (stdlib, no dependency) under
``knowledge/playbooks/``.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict, Optional

_DIR = os.environ.get(
    "ARGUS_PLAYBOOKS_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "playbooks"),
)


@lru_cache(maxsize=1)
def _load_all() -> dict:
    out: Dict[str, dict] = {}
    try:
        d = os.path.abspath(_DIR)
        for fn in os.listdir(d):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(d, fn), "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
            except Exception:
                continue
            if isinstance(doc, dict) and doc.get("weakness_class"):
                out[doc["weakness_class"]] = doc
    except Exception:
        return {}
    return out


def playbook_for(weakness_class: str) -> Optional[Dict]:
    return _load_all().get(weakness_class)
