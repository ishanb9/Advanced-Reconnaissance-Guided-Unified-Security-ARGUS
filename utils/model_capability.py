"""utils/model_capability.py — model-capability detection + CVE-fabrication filter (Gap #4).

Two additive guards that make ARGUS honest about the LLM driving it:

1. CAPABILITY DETECTION (the higher-value half).  A local/self-hosted model that
   cannot do native tool-calling, or has a tiny context window, will silently FAIL
   at agentic work far more often than it fabricates.  Before relying on such a
   model, ARGUS inspects it (Ollama's ``/api/show``, the same data ``ollama show``
   prints) and surfaces a clear warning so the operator can switch models instead of
   watching the engagement quietly degrade.

2. CVE-FABRICATION FILTER (the lower-value half).  Classifies CVE IDs an LLM emits
   into well-formed-and-plausible vs structurally-bogus, and (when a local NVD mirror
   is configured) verified vs unverified — so a hallucinated ``CVE-2099-99999`` never
   reaches a client report dressed as fact.

Everything here is pure and unit-testable except ``detect_capabilities`` (one
best-effort HTTP call); that call degrades to ``unknown`` and never raises.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("argus.model_capability")

_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$", re.I)
_MIN_CONTEXT = 8192          # below this, long engagements risk truncation
_FIRST_CVE_YEAR = 1999


# ── 1. Capability detection ───────────────────────────────────────────────────
def parse_ollama_show(show: Dict[str, Any]) -> Dict[str, Any]:
    """Parse an Ollama ``/api/show`` response into a normalised capability dict:
    {tool_calling, context_length, family, parameter_size, vision, raw_capabilities}.
    ``tool_calling``/``vision`` are True/False, or None when undeterminable.  Pure."""
    show = show or {}
    caps_list = [str(c).lower() for c in (show.get("capabilities") or [])]
    details = show.get("details") or {}
    info = show.get("model_info") or {}
    template = str(show.get("template") or "")

    tool_calling: Optional[bool]
    vision: Optional[bool]
    if caps_list:                                    # modern Ollama exposes this directly
        tool_calling = "tools" in caps_list
        vision = "vision" in caps_list
    elif template:                                   # older: infer from the chat template
        low = template.lower()
        tool_calling = ("tools" in low) or (".tool" in low) or ("tool_call" in low)
        vision = None
    else:
        tool_calling = None
        vision = None

    # Context length lives under a family-specific key, e.g. "llama.context_length".
    context_length = None
    for k, v in info.items():
        if str(k).endswith("context_length"):
            try:
                context_length = int(v)
                break
            except (TypeError, ValueError):
                pass

    return {
        "tool_calling": tool_calling,
        "context_length": context_length,
        "family": details.get("family") or show.get("family"),
        "parameter_size": details.get("parameter_size"),
        "vision": vision,
        "raw_capabilities": caps_list,
    }


def capability_gate(caps: Dict[str, Any]) -> Dict[str, Any]:
    """Turn a capability dict into an operator-facing verdict
    {ok, degraded, tool_calling, warnings[]}.  Pure.  ``degraded`` is True only when
    we KNOW the model can't do native tool-calling (the failure mode that matters)."""
    caps = caps or {}
    warnings: List[str] = []
    tc = caps.get("tool_calling")
    ctx = caps.get("context_length")

    if tc is False:
        warnings.append("model does NOT advertise native tool-calling — agentic "
                        "tool-use will be unreliable; prefer a tools-capable model")
    elif tc is None:
        warnings.append("could not determine tool-calling support for this model")
    if isinstance(ctx, int) and ctx and ctx < _MIN_CONTEXT:
        warnings.append(f"small context window ({ctx} tokens) — long engagements may "
                        f"truncate; {_MIN_CONTEXT}+ recommended")

    degraded = (tc is False)
    return {"ok": not degraded, "degraded": degraded,
            "tool_calling": tc, "warnings": warnings}


async def detect_capabilities(model: str, base_url: str = "http://localhost:11434",
                              timeout: float = 6.0) -> Dict[str, Any]:
    """Best-effort live probe of an Ollama model's capabilities via ``/api/show``.
    Returns ``parse_ollama_show`` output plus {available, error}.  Never raises."""
    result = {"tool_calling": None, "context_length": None, "available": False}
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{base_url.rstrip('/')}/api/show",
                                     json={"name": model})
            resp.raise_for_status()
            caps = parse_ollama_show(resp.json() or {})
            caps["available"] = True
            return caps
    except Exception as exc:                          # no server / not ollama / offline
        logger.debug("capability probe failed for %s: %s", model, exc)
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result


# ── 2. CVE-fabrication filter ─────────────────────────────────────────────────
def _current_cve_ceiling() -> int:
    try:
        return datetime.now(timezone.utc).year + 1     # NVD pre-assigns next-year IDs
    except Exception:
        return 2027


def load_known_cves(path: Optional[str] = None) -> set:
    """Load a set of known-valid CVE IDs from a local NVD mirror, if one is
    configured (``path`` or the NVD_LOCAL_DB env var).  Accepts a JSON list, a JSON
    object keyed by CVE id, or a newline-delimited file.  Empty set if none."""
    path = path or os.environ.get("NVD_LOCAL_DB", "")
    if not path or not os.path.exists(path):
        return set()
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return set()
    ids = set(m.group(0).upper() for m in re.finditer(r"CVE-\d{4}-\d{4,7}", text, re.I))
    return ids


def validate_cve_ids(cve_ids: Iterable[str],
                     known: Optional[set] = None) -> Dict[str, List[str]]:
    """Classify CVE IDs an LLM produced into:
        malformed  — not a valid CVE-YYYY-NNNN id, or an implausible year (fabricated)
        verified   — present in the local NVD mirror (high confidence) [if one is loaded]
        unverified — well-formed + plausible, but not in the local mirror (needs a live
                     NVD lookup before being reported as fact)
    Pure.  With no local mirror, everything well-formed lands in ``unverified``."""
    known = known if known is not None else set()
    ceiling = _current_cve_ceiling()
    malformed: List[str] = []
    verified: List[str] = []
    unverified: List[str] = []
    seen = set()
    for raw in (cve_ids or []):
        cid = str(raw or "").strip().upper()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        m = _CVE_RE.match(cid)
        if not m or not (_FIRST_CVE_YEAR <= int(m.group(1)) <= ceiling):
            malformed.append(cid)
        elif cid in known:
            verified.append(cid)
        else:
            unverified.append(cid)
    return {"malformed": malformed, "verified": verified, "unverified": unverified}
