"""agents/fuzzing/poc_runner.py — execute a synthesised PoC under hard limits.

Runs an LLM-generated proof-of-concept (the DEVELOP/PROVE step) in a bounded subprocess
and returns ``{stdout, stderr, elapsed}`` for the deterministic oracle to judge.  This is
the one place that actually *fires* a candidate exploit, so it:
  • runs argv-style (no shell) under a wall-clock timeout,
  • routes any shell-style PoC through the safety governor (scope + destructive guard),
  • never raises — a broken PoC returns captured stderr, not an exception.

The human's campaign-start press + the ceiling gate upstream are the authorization; this
module is the bounded executor.
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
from asyncio import create_subprocess_exec as _spawn   # argv-style, no shell
from typing import Any, Dict

from agents.fuzzing.engines.base import CampaignCtx, PoC

logger = logging.getLogger("argus.fuzz.poc_runner")

_TIMEOUT = int(os.environ.get("ARGUS_POC_TIMEOUT_SEC", "30"))


def _governor_ok(code: str, ctx: CampaignCtx) -> "tuple[bool, str]":
    """Block a PoC that the safety governor would deny (out-of-scope / host-destructive)."""
    try:
        from knowledge import safety_governor as gov
        enforce = ["destructive", "ot_life_safety"]
        if ctx.scope_hosts:
            enforce.insert(0, "scope")
        v = gov.evaluate({"tool_name": "bash", "args": code, "target_host": ctx.target,
                          "scope_hosts": ctx.scope_hosts, "domain": ctx.domain,
                          "ceiling": ctx.ceiling, "authorized": ctx.authorized}, enforce=enforce)
        # Block BOTH an out-of-scope deny AND a host-destructive "rewrite": a PoC the
        # governor wants to neuter (rm -rf /, shutdown, VPN teardown …) must not run at
        # all — we can't safely rewrite an arbitrary PoC, so we refuse it.
        if v.get("decision") in ("deny", "rewrite"):
            return False, str(v.get("reason"))
    except Exception as exc:   # noqa: BLE001
        # FAIL-SAFE: if the safety governor can't be consulted, REFUSE to run the PoC.
        # Only this single PoC is blocked (the campaign records the anomaly unverified);
        # the engagement loop is unaffected. Allowing on error would let an out-of-scope
        # or host-destructive PoC execute whenever the governor is broken/missing.
        logger.warning("safety governor unavailable — refusing to run PoC (fail-safe): %s", exc)
        return False, f"safety governor unavailable: {type(exc).__name__}"
    return True, ""


async def run_poc(poc: PoC, ctx: CampaignCtx) -> Dict[str, Any]:
    """Execute ``poc`` and capture output.  Best-effort + bounded; never raises."""
    if poc is None or not (poc.code or "").strip():
        return {"stdout": "", "stderr": "empty PoC", "elapsed": 0.0}

    ok, why = _governor_ok(poc.code, ctx)
    if not ok:
        return {"stdout": "", "stderr": f"[safety-governor] PoC blocked: {why}", "elapsed": 0.0}

    kind = (poc.kind or "python").lower()
    t0 = time.time()
    tmp = None
    try:
        if kind == "python":
            fd, tmp = tempfile.mkstemp(suffix=".py", prefix="argus_poc_")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(poc.code)
            argv = ["python", "-I", tmp]
        else:
            # A shell-style PoC: run the bytes through /bin/sh -c is avoided; instead
            # write to a file and execute with sh in a bounded subprocess.
            fd, tmp = tempfile.mkstemp(suffix=".sh", prefix="argus_poc_")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(poc.code)
            argv = ["sh", tmp]

        proc = await _spawn(*argv, stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=_TIMEOUT)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"stdout": "", "stderr": "PoC timed out", "elapsed": round(time.time() - t0, 2),
                    "threshold": 5.0}
        return {"stdout": (out or b"").decode("utf-8", "ignore")[:8000],
                "stderr": (err or b"").decode("utf-8", "ignore")[:4000],
                "elapsed": round(time.time() - t0, 2), "threshold": 5.0}
    except FileNotFoundError as exc:
        return {"stdout": "", "stderr": f"runner missing: {exc}", "elapsed": round(time.time() - t0, 2)}
    except Exception as exc:   # noqa: BLE001
        logger.debug("poc run error: %s", exc)
        return {"stdout": "", "stderr": f"{type(exc).__name__}: {exc}", "elapsed": round(time.time() - t0, 2)}
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except Exception:
                pass
