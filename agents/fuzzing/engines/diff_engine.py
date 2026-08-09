"""agents/fuzzing/engines/diff_engine.py — differential-testing fuzz engine (Slice 3).

Sends the SAME request to an authorized target AND an operator-supplied REFERENCE
implementation, then asks ``DifferentialOracle`` whether the two normalised responses
diverge.  Silent logic / parsing divergences (request smuggling, cert-validation bypass,
SQL-semantic, parser confusion) never crash or reflect a marker, so the single-target
oracle in ``oracle.py`` can't see them — only a side-by-side comparison can.

Lab-only and default-OFF: this engine refuses unless ``ctx.authorized`` is True and the
surface carries a ``reference`` endpoint.  BOTH ``ctx.target`` and the reference must be
operator-supplied authorized lab endpoints — there is no network reach beyond those two.
The HTTP transport mirrors ``live_http.py`` (same httpx AsyncClient + timeouts) so the
two engines send identical requests.  Additive, defensive: never raises out (log + return).
"""
from __future__ import annotations

import logging
import os
import time
import urllib.parse
from typing import Any, Awaitable, Callable, Dict, List, Optional

from agents.fuzzing.engines.base import (Anomaly, CampaignCtx, FuzzEngine,
                                         Observation)

logger = logging.getLogger("argus.fuzz.engine.diff")

#: How often to stream a periodic status Observation while comparing cases.
_STATUS_EVERY = int(os.environ.get("ARGUS_FUZZ_DIFF_STATUS_EVERY", "10"))
#: When a live scan runs alongside, yield briefly so the engagement keeps priority.
_THROTTLE_DELAY_SEC = float(os.environ.get("ARGUS_FUZZ_THROTTLE_DELAY", "3"))

#: A small built-in probe set used when the surface carries no payloads.  These are the
#: classic differential triggers (smuggling header soup, ambiguous encodings, parser edge
#: cases) — benign to send, interesting only when target and reference disagree.
_BUILTIN_PROBES: List[Dict[str, str]] = [
    {"family": "diff", "value": "", "marker": "", "where": "param"},
    {"family": "diff", "value": "0", "marker": "", "where": "param"},
    {"family": "diff", "value": "%2e%2e%2f", "marker": "", "where": "param"},
    {"family": "diff", "value": "..%2f..%2f", "marker": "", "where": "param"},
    {"family": "diff", "value": "%00", "marker": "", "where": "param"},
    {"family": "diff", "value": "a%20b", "marker": "", "where": "param"},
    {"family": "diff", "value": "1 OR 1=1", "marker": "", "where": "param"},
    {"family": "diff", "value": "true", "marker": "", "where": "param"},
    {"family": "diff", "value": "%c0%ae%c0%ae", "marker": "", "where": "param"},
    {"family": "diff", "value": "x" * 4096, "marker": "", "where": "param"},
]


class DiffEngine(FuzzEngine):
    """Differential engine: target vs reference, divergence → Anomaly."""

    modality = "differential"

    def is_available(self) -> "tuple[bool, str]":
        # The real gate (authorized + a reference endpoint) is checked in ``run`` where the
        # ctx is available; report available here so the campaign can SELECT this modality.
        return True, ""

    # ── URL helpers (mirror live_http so identical requests reach both ends) ──
    def _base_url(self, target: str, override: str = "") -> str:
        url = str(override or target or "")
        if not url:
            return ""
        if not url.startswith("http"):
            url = f"http://{url}"
        return url

    def _full(self, base: str, param: str, value: str) -> str:
        sep = "&" if ("?" in base) else "?"
        return f"{base}{sep}{param}={urllib.parse.quote(value, safe='')}"

    async def run(self, ctx: CampaignCtx,
                  sink: Callable[[Observation], Awaitable[None]]) -> None:
        try:
            # ── Lab gate: authorized + an operator-supplied reference endpoint ──
            if not ctx.authorized:
                logger.debug("diff engine: refused — campaign is not authorized (lab-only)")
                return
            ref = str(ctx.surface.get("reference") or "").strip()
            if not ref:
                logger.debug("diff engine: refused — no surface['reference'] endpoint supplied")
                return

            try:
                import httpx
            except Exception:
                logger.debug("diff engine: httpx not installed")
                return

            # The oracle lives in a sibling Slice-3 module; import defensively so a missing
            # file fails safe (engine no-ops) rather than crashing the campaign.
            try:
                from agents.fuzzing.diff_oracle import DifferentialOracle
            except Exception as exc:   # noqa: BLE001
                logger.debug("diff engine: DifferentialOracle unavailable: %s", exc)
                return

            target_url = self._base_url(ctx.target, str(ctx.surface.get("url") or ""))
            ref_url = self._base_url(ref)
            if not target_url or not ref_url:
                logger.debug("diff engine: could not resolve target/reference URLs")
                return

            param = str(ctx.surface.get("param") or "q")
            timeout = float(ctx.surface.get("req_timeout") or 10.0)
            payloads = ctx.surface.get("payloads") or _BUILTIN_PROBES

            oracle = DifferentialOracle(ref_url)
            seen: set = set()
            sent = 0

            async with httpx.AsyncClient(verify=False, timeout=timeout,
                                         follow_redirects=True) as client:
                # A leading status Observation so the operator sees the diff run start.
                await self._status(sink, sent, len(payloads),
                                   f"differential run started: target vs {ref_url}")

                for i, p in enumerate(payloads):
                    val = p.get("value") if isinstance(p, dict) else p
                    if isinstance(val, (bytes, bytearray)):
                        # Binary payloads aren't sendable over this query-param transport.
                        continue
                    sval = "" if val is None else str(val)

                    await self._throttle_yield(ctx)
                    primary_obs = await self._send(client, target_url, param, sval,
                                                   p if isinstance(p, dict) else None,
                                                   f"diff-t-{i}")
                    reference_obs = await self._send(client, ref_url, param, sval,
                                                     p if isinstance(p, dict) else None,
                                                     f"diff-r-{i}")
                    sent += 1

                    # Stream the primary Observation for visibility (signal-only; the
                    # standard oracle won't flag it — the DifferentialOracle decides).
                    await self._safe_sink(sink, primary_obs)

                    anomaly = self._classify(oracle, ctx.modality, primary_obs, reference_obs)
                    if anomaly is not None and anomaly.signature not in seen:
                        seen.add(anomaly.signature)
                        await self._emit_anomaly(ctx, sink, anomaly, primary_obs)

                    if _STATUS_EVERY and sent % _STATUS_EVERY == 0:
                        await self._status(sink, sent, len(payloads),
                                           f"compared {sent} cases — {len(seen)} divergence(s)")

                await self._status(sink, sent, len(payloads),
                                   f"differential run complete — {len(seen)} divergence(s)")
        except Exception as exc:   # noqa: BLE001
            logger.debug("diff engine run error: %s", exc)

    # ── Transport (identical shape to live_http._send) ──
    async def _send(self, client, base: str, param: str, value: str,
                    payload: Optional[Dict[str, Any]], case_id: str) -> Observation:
        full = self._full(base, param, value)
        t0 = time.time()
        signal: Dict[str, Any] = {}
        body = ""
        headers: Dict[str, str] = {}
        try:
            r = await client.get(full)
            body = r.text or ""
            try:
                headers = {str(k).lower(): str(v) for k, v in r.headers.items()}
            except Exception:
                headers = {}
            signal.update(status=r.status_code, body_len=len(body),
                          latency=round(time.time() - t0, 3), headers=headers)
        except Exception as exc:   # noqa: BLE001
            signal.update(status=None, error=type(exc).__name__,
                          latency=round(time.time() - t0, 3),
                          timeout=("Timeout" in type(exc).__name__))
        if payload:
            signal["family"] = payload.get("family")
            signal["marker"] = payload.get("marker")
        return Observation(case_id=case_id, input=payload or value,
                           signal=signal, raw=body[:2000])

    def _classify(self, oracle, modality: str, primary_obs: Observation,
                  reference_obs: Observation) -> Optional[Anomaly]:
        try:
            return oracle.classify(modality, primary_obs, reference_obs)
        except Exception as exc:   # noqa: BLE001
            logger.debug("diff oracle classify error: %s", exc)
            return None

    async def _emit_anomaly(self, ctx: CampaignCtx,
                            sink: Callable[[Observation], Awaitable[None]],
                            anomaly: Anomaly, primary_obs: Observation) -> None:
        # Surface the divergence two ways: a fuzz_anomaly event (the campaign + UI listen for
        # it) and an Observation carrying the anomaly so downstream consumers can record it.
        await ctx.emit_event("fuzz_anomaly", anomaly.to_dict())
        marker_obs = Observation(
            case_id=primary_obs.case_id,
            input=primary_obs.input,
            signal={**primary_obs.signal, "differential": True,
                    "anomaly": anomaly.to_dict()},
            raw=primary_obs.raw)
        await self._safe_sink(sink, marker_obs)

    async def _status(self, sink: Callable[[Observation], Awaitable[None]],
                      sent: int, total: int, note: str) -> None:
        await self._safe_sink(sink, Observation(
            case_id=f"diff-status-{sent}", input=note,
            signal={"status_update": True, "compared": sent, "total": total, "note": note},
            raw=note))

    async def _throttle_yield(self, ctx: CampaignCtx) -> None:
        if getattr(ctx, "throttle", False):
            try:
                import asyncio
                await asyncio.sleep(_THROTTLE_DELAY_SEC)
            except Exception:
                pass

    async def _safe_sink(self, sink: Callable[[Observation], Awaitable[None]],
                         obs: Observation) -> None:
        try:
            await sink(obs)
        except Exception as exc:   # noqa: BLE001
            logger.debug("diff engine sink error: %s", exc)
