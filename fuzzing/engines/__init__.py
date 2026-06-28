"""agents/fuzzing/engines — modality engines for the Fuzz Campaign.

``get_engine(modality)`` returns a ready FuzzEngine.  Heavy/optional engines (binary,
ai) are imported lazily so the spine never hard-depends on AFL++/angr/ai_red_team.
"""
from __future__ import annotations

import logging
from typing import Optional

from agents.fuzzing.engines.base import (Anomaly, CampaignCtx, FuzzEngine,
                                         Observation, PoC, Verdict)

logger = logging.getLogger("argus.fuzz.engines")

# modality → "module:Class"  (lazy so optional deps don't break import)
_REGISTRY = {
    "web":     "agents.fuzzing.engines.live_http:LiveHttpEngine",
    "api":     "agents.fuzzing.engines.live_http:LiveHttpEngine",
    "network": "agents.fuzzing.engines.live_proto:LiveProtoEngine",
    "file":    "agents.fuzzing.engines.file_fmt:FileFmtEngine",       # OWASP file-format fuzzing
    "tool":    "agents.fuzzing.engines.tool_engine:ToolEngine",
    "binary":  "agents.fuzzing.engines.binary_cov:BinaryCovEngine",   # Slice 2
    "ai":      "agents.fuzzing.engines.ai_target:AiTargetEngine",     # Slice 3
}


def available_modalities() -> list:
    return sorted(_REGISTRY.keys())


def get_engine(modality: str) -> Optional[FuzzEngine]:
    """Instantiate the engine for ``modality`` (web/api/network/tool/binary/ai), or None
    when the engine module isn't present yet (a future slice)."""
    spec = _REGISTRY.get(str(modality or "").lower())
    if not spec:
        return None
    mod_name, _, cls_name = spec.partition(":")
    try:
        import importlib
        mod = importlib.import_module(mod_name)
        return getattr(mod, cls_name)()
    except Exception as exc:   # noqa: BLE001
        logger.debug("engine %s unavailable: %s", modality, exc)
        return None


__all__ = ["FuzzEngine", "CampaignCtx", "Observation", "Anomaly", "PoC", "Verdict",
           "get_engine", "available_modalities"]
