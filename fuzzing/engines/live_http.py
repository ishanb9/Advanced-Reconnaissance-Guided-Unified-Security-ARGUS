"""agents/fuzzing/engines/live_http.py — black-box HTTP/web mutational fuzzing engine.

Baselines a target endpoint, then sends each tagged payload (from payloadgen) into a
query parameter and streams an ``Observation`` per case to the campaign's sink, which
feeds the oracle.  No regex-hit shortcuts — the oracle decides what is anomalous from the
status / latency / body relative to the baseline.  Scope is already enforced upstream;
this engine only ever touches ``ctx.target``.  Missing ``httpx`` → reported unavailable.
"""
from __future__ import annotations

import logging
import time
import urllib.parse
from typing import Any, Awaitable, Callable, Dict

from agents.fuzzing.engines.base import CampaignCtx, FuzzEngine, Observation

logger = logging.getLogger("argus.fuzz.engine.http")


class LiveHttpEngine(FuzzEngine):
    modality = "web"

    def is_available(self):
        try:
            import httpx  # noqa: F401
            return True, ""
        except Exception:
            return False, "httpx not installed"

    def _base_url(self, ctx: CampaignCtx) -> str:
        url = str(ctx.surface.get("url") or "")
        if url:
            return url
        t = ctx.target
        if not t.startswith("http"):
            t = f"http://{t}"
        return t

    async def run(self, ctx: CampaignCtx,
                  sink: Callable[[Observation], Awaitable[None]]) -> None:
        try:
            import httpx
        except Exception:
            return
        url = self._base_url(ctx)
        param = str(ctx.surface.get("param") or "q")
        payloads = ctx.surface.get("payloads") or []
        timeout = float(ctx.surface.get("req_timeout") or 10.0)

        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout,
                                         follow_redirects=True) as client:
                # ── Baseline (a benign value) ──
                base_obs = await self._send(client, url, param, "argusbaseline", None, "0")
                base_obs.signal["baseline"] = True
                await sink(base_obs)

                # ── Each tagged payload ──
                for i, p in enumerate(payloads):
                    if ctx.modality not in ("web", "api"):
                        break
                    val = p.get("value")
                    if isinstance(val, (bytes, bytearray)):
                        continue                       # binary payloads are for live_proto
                    obs = await self._send(client, url, param, str(val), p, str(i + 1))
                    await sink(obs)
        except Exception as exc:   # noqa: BLE001
            logger.debug("live_http run error: %s", exc)

    async def _send(self, client, url: str, param: str, value: str,
                    payload: Dict[str, Any] | None, case_id: str) -> Observation:
        sep = "&" if ("?" in url) else "?"
        full = f"{url}{sep}{param}={urllib.parse.quote(value, safe='')}"
        t0 = time.time()
        signal: Dict[str, Any] = {}
        body = ""
        try:
            r = await client.get(full)
            body = r.text or ""
            signal.update(status=r.status_code, body_len=len(body),
                          latency=round(time.time() - t0, 3))
        except Exception as exc:   # noqa: BLE001
            signal.update(status=None, error=type(exc).__name__,
                          latency=round(time.time() - t0, 3),
                          timeout=("Timeout" in type(exc).__name__))
        if payload:
            signal["family"] = payload.get("family")
            signal["marker"] = payload.get("marker")
        return Observation(case_id=f"http-{case_id}", input=payload or value,
                           signal=signal, raw=body[:2000])
