"""agents/fuzzing/engines/binary_greybox.py — closed-source greybox fuzzing (Slice 1).

The ``binary_blackbox`` modality: AFL++ in QEMU user-mode (``-Q``) over an *unmodified*
target binary — no source, no recompilation — with QASan/ASan as the crash oracle.  This
is the sovereign / air-gapped 0-day path: point it at a closed-source ELF and let AFL++'s
QEMU instrumentation drive coverage-guided mutation while a sanitizer turns silent memory
corruption into a loud, triageable crash.

Each NEW file AFL++ drops into the crashes dir is re-run through
``agents.fuzzing.crash_triage.triage`` (sanitizer parse + stack hash) and streamed to the
campaign as an ``Anomaly(exploit_class="memory_corruption")`` — weaponisation of which is
HUMAN-GATED upstream (the campaign's approval card).  Periodic status ``Observation``s
(execs/sec + crash count parsed from ``fuzzer_stats``) keep the Fuzzing Lab UI live.

Defensive / additive by construction: missing ``afl-fuzz`` / ``afl-qemu-trace`` is reported
via ``is_available`` (never crashes the lab); the loop honours ``ctx`` budget / stop /
throttle, terminates the AFL process on exit, and NEVER raises out (log + return).  This
engine is lab-gated — the autonomous engine never selects ``binary_blackbox``.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
import time
from asyncio import create_subprocess_exec as _spawn   # argv-style, no shell
from typing import Awaitable, Callable, Optional

from agents.fuzzing.engines.base import Anomaly, CampaignCtx, FuzzEngine, Observation

logger = logging.getLogger("argus.fuzz.engine.greybox")

# Reuse the SAME wall-clock budget source the coverage engine uses, so both binary
# engines share one operator-tunable ceiling.
_RUN_SEC = int(os.environ.get("ARGUS_BINFUZZ_SEC", "300"))
# How often we scan the crashes dir + refresh status (seconds).
_POLL_SEC = 5.0
# Extra back-off applied per poll while the campaign is throttled (yields to a live scan).
_THROTTLE_SEC = 10.0


class BinaryGreyboxEngine(FuzzEngine):
    """AFL++ QEMU user-mode greybox fuzzing of a closed-source binary."""

    modality = "binary_blackbox"

    def is_available(self) -> "tuple[bool, str]":
        if not shutil.which("afl-fuzz"):
            return False, "afl-fuzz not on PATH (install AFL++ for greybox fuzzing)"
        if not shutil.which("afl-qemu-trace"):
            return False, "afl-qemu-trace not on PATH (AFL++ QEMU-mode required for -Q)"
        return True, ""

    async def run(self, ctx: CampaignCtx,
                  sink: Callable[[Observation], Awaitable[None]]) -> None:
        try:
            await self._run(ctx, sink)
        except Exception as exc:   # noqa: BLE001 — never raise out of the engine loop
            logger.warning("greybox engine aborted: %s", exc)
            return

    # ── internals ───────────────────────────────────────────────────────────────
    async def _run(self, ctx: CampaignCtx,
                   sink: Callable[[Observation], Awaitable[None]]) -> None:
        target_bin = str(ctx.surface.get("binary") or "")
        if not target_bin or not os.path.exists(target_bin):
            logger.debug("greybox engine: no target binary provided")
            return

        afl = shutil.which("afl-fuzz")
        if not afl:
            logger.debug("greybox engine: afl-fuzz vanished from PATH")
            return

        # Seeds: caller-supplied dir, else a throwaway dir holding one 1-byte seed
        # (AFL refuses to start with an empty input corpus).
        seeds = str(ctx.surface.get("seeds_path") or "")
        tmp_seed: Optional[tempfile.TemporaryDirectory] = None
        if not seeds or not os.path.isdir(seeds):
            tmp_seed = tempfile.TemporaryDirectory(prefix="argus_greybox_in_")
            seeds = tmp_seed.name
            try:
                with open(os.path.join(seeds, "seed0"), "wb") as fh:
                    fh.write(b"\x00")
            except Exception as exc:   # noqa: BLE001
                logger.debug("greybox engine: could not write seed: %s", exc)

        out_tmp = tempfile.TemporaryDirectory(prefix="argus_greybox_out_")
        out = out_tmp.name

        argv = [afl, "-Q", "-i", seeds, "-o", out, "--", target_bin, "@@"]
        env = {
            **os.environ,
            "AFL_USE_QASAN": "1",
            "AFL_NO_UI": "1",
            "AFL_BENCH_UNTIL_CRASH": "1",
            "AFL_SKIP_CPUFREQ": "1",          # don't hard-fail on a non-tuned dev box
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        }

        try:
            proc = await _spawn(*argv, env=env,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE)
        except Exception as exc:   # noqa: BLE001
            logger.warning("greybox engine: afl-fuzz spawn failed: %s", exc)
            self._cleanup(tmp_seed, out_tmp)
            return

        await ctx.emit_event("greybox_started", {
            "target": target_bin, "out": out, "budget_sec": _RUN_SEC})

        seen: set = set()
        deadline = time.time() + _RUN_SEC
        crash_dirs = [os.path.join(out, "default", "crashes"),
                      os.path.join(out, "crashes")]
        stats_path = os.path.join(out, "default", "fuzzer_stats")
        try:
            while True:
                if time.time() >= deadline:
                    logger.debug("greybox engine: budget %ds reached", _RUN_SEC)
                    break
                if self._stopped(ctx):
                    logger.debug("greybox engine: stop requested")
                    break
                if proc.returncode is not None:
                    logger.debug("greybox engine: afl-fuzz exited (%s)", proc.returncode)
                    await self._harvest(ctx, crash_dirs, target_bin, env, seen, sink)
                    break

                # Throttle: when a live scan is running we yield capacity by polling
                # far less aggressively.
                nap = _POLL_SEC + (_THROTTLE_SEC if getattr(ctx, "throttle", False) else 0.0)
                await asyncio.sleep(nap)

                await self._harvest(ctx, crash_dirs, target_bin, env, seen, sink)
                await self._emit_status(ctx, stats_path, len(seen), sink)
        finally:
            await self._terminate(proc)
            # Final sweep — a crash may have landed during the last interval.
            try:
                await self._harvest(ctx, crash_dirs, target_bin, env, seen, sink)
            except Exception as exc:   # noqa: BLE001
                logger.debug("greybox engine: final harvest failed: %s", exc)
            self._cleanup(tmp_seed, out_tmp)
            await ctx.emit_event("greybox_finished",
                                 {"target": target_bin, "crashes": len(seen)})

    async def _harvest(self, ctx: CampaignCtx, crash_dirs, target_bin: str,
                       env: dict, seen: set,
                       sink: Callable[[Observation], Awaitable[None]]) -> None:
        """Scan AFL's crash dirs for NEW inputs; triage + stream each as an Anomaly."""
        for cdir in crash_dirs:
            try:
                names = os.listdir(cdir)
            except Exception:
                continue
            for name in names:
                if name in seen or name.startswith("README"):
                    continue
                seen.add(name)
                crash_path = os.path.join(cdir, name)
                await self._report_crash(ctx, crash_path, target_bin, env, sink)

    async def _report_crash(self, ctx: CampaignCtx, crash_path: str, target_bin: str,
                            env: dict,
                            sink: Callable[[Observation], Awaitable[None]]) -> None:
        try:
            from agents.fuzzing import crash_triage
            t = crash_triage.triage(crash_path, target_bin, env)
        except Exception as exc:   # noqa: BLE001
            logger.debug("greybox engine: triage failed for %s: %s", crash_path, exc)
            t = {}
        t = t if isinstance(t, dict) else {}

        sanitizer = str(t.get("sanitizer") or "")
        summary = str(t.get("summary") or "")
        stack_hash = str(t.get("stack_hash") or "")
        if not stack_hash:
            # Stable fallback dedup key so a triage miss still de-duplicates per-file.
            stack_hash = "file:" + os.path.basename(crash_path)

        anomaly = Anomaly(
            type="asan" if sanitizer else "crash",
            exploit_class="memory_corruption",
            severity_hint="high",
            evidence=(summary or f"AFL++ crash input: {os.path.basename(crash_path)}")[:400],
            case_id=f"greybox-{os.path.basename(crash_path)}",
            signature=f"greybox:{stack_hash}",
            detail={"input_path": crash_path, "sanitizer": sanitizer,
                    "frames": t.get("frames") or [], "target": target_bin},
        )
        try:
            await sink(anomaly)
        except Exception as exc:   # noqa: BLE001
            logger.debug("greybox engine: sink(anomaly) failed: %s", exc)

    async def _emit_status(self, ctx: CampaignCtx, stats_path: str, crashes: int,
                           sink: Callable[[Observation], Awaitable[None]]) -> None:
        """Stream a periodic status Observation (execs/sec + crash count) for the UI."""
        execs_per_sec = 0.0
        total_execs = 0
        try:
            with open(stats_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if ":" not in line:
                        continue
                    key, _, val = line.partition(":")
                    key, val = key.strip(), val.strip()
                    if key == "execs_per_sec":
                        try:
                            execs_per_sec = float(val)
                        except ValueError:
                            pass
                    elif key == "execs_done":
                        try:
                            total_execs = int(val)
                        except ValueError:
                            pass
        except Exception:
            # fuzzer_stats not written yet (AFL still calibrating) — emit what we have.
            pass

        obs = Observation(
            case_id="greybox-status",
            input="",
            signal={"status": "running", "execs_per_sec": execs_per_sec,
                    "execs_done": total_execs, "crashes": crashes},
            raw="",
        )
        try:
            await sink(obs)
        except Exception as exc:   # noqa: BLE001
            logger.debug("greybox engine: sink(status) failed: %s", exc)

    @staticmethod
    def _stopped(ctx: CampaignCtx) -> bool:
        """Best-effort stop check (ctx.stop may be a bool, an Event, or absent)."""
        stop = getattr(ctx, "stop", None)
        if stop is None:
            return False
        try:
            is_set = getattr(stop, "is_set", None)
            if callable(is_set):
                return bool(is_set())
            if callable(stop):
                return bool(stop())
            return bool(stop)
        except Exception:
            return False

    @staticmethod
    async def _terminate(proc) -> None:
        if proc is None or proc.returncode is not None:
            return
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    @staticmethod
    def _cleanup(*tmps) -> None:
        for t in tmps:
            if t is None:
                continue
            try:
                t.cleanup()
            except Exception:
                pass
