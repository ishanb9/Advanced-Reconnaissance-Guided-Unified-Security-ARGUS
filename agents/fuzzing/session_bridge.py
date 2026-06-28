"""agents/fuzzing/session_bridge.py — wire a live session into a CampaignCtx.

Builds the ``CampaignCtx`` an endpoint needs from a running session's agent: the tiered
LLM (the master's ``converse``, which already does primary→secondary fallback), the
bounded PoC runner, the OOB callback URL, the scope hosts, and a fresh canary.  Kept out
of agent_server.py so the wiring is small + testable.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, List, Optional

from agents.fuzzing import proof as _proof
from agents.fuzzing.engines.base import CampaignCtx, PoC
from agents.fuzzing.poc_runner import run_poc as _run_poc

logger = logging.getLogger("argus.fuzz.bridge")


def _scope_hosts(agent: Any) -> List[str]:
    try:
        from agents.fuzzing import scope_for_agent
        sc = scope_for_agent(agent)
        return list(sc.get("hosts") or [])
    except Exception:
        return []


def _make_llm(agent: Any) -> Callable[..., Any]:
    """An async (prompt, system) → str using the master's tiered converse where possible,
    else a direct provider call.  Honours the primary→secondary fallback requirement."""
    async def generate(prompt: str, system: str) -> str:
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": prompt}]
        conv = getattr(agent, "converse", None)
        if callable(conv):
            try:
                return str(await conv(messages) or "")
            except Exception as exc:   # noqa: BLE001
                logger.debug("master.converse failed, falling back: %s", exc)
        # Fallback: a direct provider stream (primary tier only).
        try:
            from utils.llm_providers import get_provider
            prov = get_provider()
            buf: List[str] = []
            async for tok in prov.stream(messages):
                buf.append(tok)
            return "".join(buf)
        except Exception as exc:   # noqa: BLE001
            logger.debug("provider fallback failed: %s", exc)
            return ""
    return generate


def build_ctx(*, session_id: str, agent: Any, target: str, modality: str,
              surface: Optional[Dict[str, Any]], ceiling: str, domain: str,
              authorized: bool, emit: Callable[..., Any]) -> CampaignCtx:
    ctx = CampaignCtx(session_id=session_id, target=target, modality=modality,
                      surface=dict(surface or {}), ceiling=ceiling or "intrusive",
                      domain=domain or "IT", authorized=bool(authorized))
    ctx.canary = _proof.new_canary()
    token = _proof.new_oob_token()
    _proof.arm_oob(token)
    ctx.oob_url = _proof.oob_url(os.environ.get("ARGUS_OOB_BASE", ""), token)
    ctx.scope_hosts = _scope_hosts(agent)
    # Throttle this campaign when a LIVE scan is running (agent present) so the
    # engagement gets LLM/tool priority; a standalone campaign (no agent) runs full speed.
    ctx.throttle = agent is not None
    try:
        ctx.fuzzability = int(((getattr(agent, "_intel", None) or {}).get("fuzzability_score")) or 0)
    except Exception:
        ctx.fuzzability = 0
    ctx.emit = emit
    ctx.llm_generate = _make_llm(agent)

    async def _runner(poc: PoC) -> Dict[str, Any]:
        return await _run_poc(poc, ctx)
    ctx.run_poc = _runner
    return ctx
