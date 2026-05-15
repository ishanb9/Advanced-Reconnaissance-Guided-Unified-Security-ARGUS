"""
replay_mode.py - re-stream a finished scan's WebSocket events for demos / debug.

Why this exists
---------------
The hardest part of a deliverable is showing the client a "live" scan
on the same UI without actually running attacks against their prod
infra again.  Once a scan is finished and its events.jsonl + ws_events
streams are archived, this module replays them at configurable speed
through the broadcast layer so the existing UI renders the scan as if
it were happening in real-time.

Three modes
-----------
- demo:   1-10x speed, capped per-event delay so demos stay under the
          attention span; auto-skips long no-event gaps
- debug:  1x speed, full fidelity; useful for reproducing UI bugs
- fast:   instant (no delays); useful for re-hydrating UI state in tests

Replay is read-only: it generates ZERO traffic to the target.

Operation
---------
This module produces an async iterator over (event_type, payload, delay)
tuples.  The caller (agent_server or a CLI) feeds them into whatever
WebSocketManager broadcasts to subscribed clients.

Operator can pause/seek/cancel via the operator_directive channel:
  pause / resume      - sticky
  set_opsec replay_speed=0.5 - jitter the play speed

The replay session_id is the original scan's session_id with a
"-replay-<n>" suffix so the UI distinguishes the two.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ReplayConfig:
    speed:       float = 1.0          # 1.0 = realtime, 10 = 10x faster
    max_delay:   float = 5.0          # cap any single inter-event delay
    skip_gaps:   bool  = True         # collapse silence longer than max_delay
    mode:        str   = "demo"


def _load_events(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not path.exists():
        return out
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except (OSError, IOError) as exc:
        logger.warning("[replay] failed to load %s: %s", path, exc)
    return out


def _parse_ts(rec: Dict[str, Any]) -> Optional[float]:
    """Pull a unix-epoch timestamp from a record."""
    ts = rec.get("ts") or rec.get("timestamp")
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return None
    return None


# ── Iterator ────────────────────────────────────────────────────────────

async def stream_replay(
    session_dir: Path,
    config: Optional[ReplayConfig] = None,
) -> AsyncIterator[Tuple[str, Dict[str, Any]]]:
    """Async-iterate over (event_type, payload) tuples from a scan.

    The iterator sleeps between events according to config.  Caller
    just `async for et, payload in stream_replay(...)` and broadcasts.
    """
    cfg = config or ReplayConfig()

    # Prefer ws_events.jsonl (full WS-event capture); fall back to events.jsonl
    ws_path = session_dir / "ws_events.jsonl"
    ev_path = session_dir / "events.jsonl"
    src = ws_path if ws_path.exists() else ev_path

    events = _load_events(src)
    if not events:
        logger.info("[replay] no events to replay from %s", session_dir)
        return

    last_ts: Optional[float] = None

    for ev in events:
        ts = _parse_ts(ev)
        if ts is not None:
            if last_ts is not None:
                gap = ts - last_ts
                if gap > 0:
                    delay = gap / max(cfg.speed, 0.01)
                    if cfg.skip_gaps:
                        delay = min(delay, cfg.max_delay)
                    if cfg.mode == "fast":
                        delay = 0
                    if delay > 0:
                        await asyncio.sleep(delay)
            last_ts = ts

        et = str(ev.get("type") or ev.get("event") or "unknown")
        payload = ev.get("data") if "data" in ev else ev
        if not isinstance(payload, dict):
            payload = {"raw": str(payload)}
        # Tag replayed events so the UI / store can distinguish from live
        payload = dict(payload)
        payload.setdefault("__replay", True)
        yield et, payload


async def replay_into_broadcast(
    session_dir: Path,
    broadcast: Any,
    replay_session_id: str,
    config: Optional[ReplayConfig] = None,
) -> int:
    """Pull events from `session_dir` and call broadcast.broadcast_raw().

    `broadcast` is anything with `broadcast_raw(session_id, type, data)`
    matching the WebSocketManager signature already in agent_server.py.

    Returns the number of events replayed.
    """
    count = 0
    async for et, payload in stream_replay(session_dir, config):
        try:
            await broadcast.broadcast_raw(replay_session_id, et, payload)
            count += 1
        except Exception as exc:
            logger.debug("[replay] broadcast error on %s: %s", et, exc)
    return count


# ── CLI ─────────────────────────────────────────────────────────────────

def _cli() -> int:
    import argparse, sys
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("session_dir")
    p.add_argument("--speed", type=float, default=1.0)
    p.add_argument("--mode",  default="demo", choices=("demo", "debug", "fast"))
    p.add_argument("--max-delay", type=float, default=5.0)
    args = p.parse_args()

    cfg = ReplayConfig(speed=args.speed, max_delay=args.max_delay,
                       mode=args.mode, skip_gaps=(args.mode == "demo"))

    async def main():
        sd = Path(args.session_dir)
        count = 0
        async for et, payload in stream_replay(sd, cfg):
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {et:30s}  {json.dumps(payload, default=str)[:160]}")
            count += 1
        print(f"\nreplayed {count} events from {sd}")

    asyncio.run(main())
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli())


__all__ = ["ReplayConfig", "stream_replay", "replay_into_broadcast"]
