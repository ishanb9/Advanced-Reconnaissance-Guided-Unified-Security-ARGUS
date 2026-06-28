"""agents/fuzzing/engines/tool_engine.py — back-compat catalog-tool engine.

Wraps an external fuzzer (nuclei / ffuf etc.) as a campaign engine so the classic
catalog runs become one engine among several: it streams the tool's stdout lines as
``Observation``s whose ``raw`` text the oracle inspects (SQL errors, stack leaks, etc.).
The tool is launched argv-style with no shell (``create_subprocess_exec``), so a
scope-validated target can never become an injection vector.  A missing binary is
reported cleanly, never a crash.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from asyncio import create_subprocess_exec as _spawn   # argv-style, no shell
from typing import Awaitable, Callable, List

from agents.fuzzing.engines.base import CampaignCtx, FuzzEngine, Observation

logger = logging.getLogger("argus.fuzz.engine.tool")

_MAX_LINES = 4000


class ToolEngine(FuzzEngine):
    modality = "tool"

    def _argv(self, ctx: CampaignCtx) -> List[str]:
        argv = ctx.surface.get("tool_argv")
        if isinstance(argv, list) and argv:
            return [str(a) for a in argv]
        # Default: a nuclei DAST pass against the URL.
        url = str(ctx.surface.get("url") or ctx.target)
        if not url.startswith("http"):
            url = f"http://{url}"
        return ["nuclei", "-u", url, "-dast", "-silent"]

    def is_available(self):
        # The concrete binary is target-specific; checked again in run().
        return True, ""

    async def run(self, ctx: CampaignCtx,
                  sink: Callable[[Observation], Awaitable[None]]) -> None:
        argv = self._argv(ctx)
        if not shutil.which(argv[0]):
            logger.debug("tool engine binary missing: %s", argv[0])
            return
        try:
            proc = await _spawn(*argv, stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.STDOUT)
        except Exception as exc:   # noqa: BLE001
            logger.debug("tool engine spawn failed: %s", exc)
            return
        n = 0
        try:
            assert proc.stdout is not None
            async for raw in proc.stdout:
                n += 1
                if n > _MAX_LINES:
                    break
                line = raw.decode("utf-8", "ignore").rstrip()
                if not line:
                    continue
                await sink(Observation(case_id=f"tool-{n}", input={"family": "tool"},
                                       signal={"tool": argv[0]}, raw=line))
        except Exception as exc:   # noqa: BLE001
            logger.debug("tool engine read error: %s", exc)
        finally:
            try:
                proc.kill()
            except Exception:
                pass
