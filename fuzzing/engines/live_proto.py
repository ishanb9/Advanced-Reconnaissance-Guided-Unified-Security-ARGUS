"""agents/fuzzing/engines/live_proto.py — black-box network-protocol mutational fuzzing.

Connects to a TCP service, captures a baseline response, then sends each mutated message
(oversize / format / boundary / null) and observes whether the service resets, hangs, or
desyncs — the remote signals of a memory-corruption / DoS bug.  Uses only asyncio sockets
(no extra deps).  Best-effort; never raises out.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable, Dict

from agents.fuzzing.engines.base import CampaignCtx, FuzzEngine, Observation

logger = logging.getLogger("argus.fuzz.engine.proto")


class LiveProtoEngine(FuzzEngine):
    modality = "network"

    def _host_port(self, ctx: CampaignCtx):
        host = str(ctx.surface.get("host") or ctx.target).split("/")[0]
        port = ctx.surface.get("port")
        if ":" in host and port is None:
            host, _, port = host.partition(":")
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = 0
        return host, port

    async def run(self, ctx: CampaignCtx,
                  sink: Callable[[Observation], Awaitable[None]]) -> None:
        host, port = self._host_port(ctx)
        if not host or not port:
            return
        timeout = float(ctx.surface.get("req_timeout") or 6.0)
        probe = ctx.surface.get("probe")
        probe_b = probe.encode() if isinstance(probe, str) else (probe or b"\r\n")

        base = await self._exchange(host, port, probe_b, timeout)
        base.signal["baseline"] = True
        await sink(base)

        for i, p in enumerate(ctx.surface.get("payloads") or []):
            val = p.get("value")
            msg = val if isinstance(val, (bytes, bytearray)) else str(val).encode("latin-1", "ignore")
            obs = await self._exchange(host, port, bytes(msg), timeout, case_id=str(i + 1))
            obs.signal["family"] = p.get("family")
            await sink(obs)

    async def _exchange(self, host: str, port: int, payload: bytes, timeout: float,
                        case_id: str = "0") -> Observation:
        signal: Dict[str, object] = {}
        data = b""
        t0 = time.time()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
            writer.write(payload)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                signal["resp_len"] = len(data)
                if not data:
                    signal["no_response"] = True
            except asyncio.TimeoutError:
                signal["hang"] = True
            signal["latency"] = round(time.time() - t0, 3)
        except (ConnectionResetError, BrokenPipeError):
            signal["conn_reset"] = True
        except asyncio.TimeoutError:
            signal["hang"] = True
        except Exception as exc:   # noqa: BLE001
            signal["error"] = type(exc).__name__
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
        return Observation(case_id=f"proto-{case_id}", input=payload[:64],
                           signal=signal, raw=data[:512].hex())
