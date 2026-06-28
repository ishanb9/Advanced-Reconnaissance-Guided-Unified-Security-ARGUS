"""agents/fuzzing/engines/file_fmt.py — file-format mutational fuzzing (OWASP type).

The fuzzing type OWASP calls "file format fuzzing": take a valid sample file, produce
malformed variants, feed each to the parser/codec, and watch for a crash.  Uses Radamsa
or zzuf when present (smart, well-distributed mutations); always falls back to a built-in
byte mutator so "dumb" fuzzing works with zero external tools.  A crash (process killed by
a signal, or a sanitizer report) becomes a memory-corruption ``Observation`` — whose
weaponisation stays human-gated upstream.

Surface inputs:
  sample_file : path to a valid seed file to mutate
  parse_cmd   : argv list with a ``{input}`` placeholder for the mutated file
                (e.g. ["pdfinfo", "{input}"] or ["./parser", "{input}"])
  iterations  : how many mutated samples to try (default 200, env-capped)
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import tempfile
from asyncio import create_subprocess_exec as _spawn   # argv-style, no shell
from typing import Awaitable, Callable, List, Optional

from agents.fuzzing.engines.base import CampaignCtx, FuzzEngine, Observation

logger = logging.getLogger("argus.fuzz.engine.file")

_MAX_ITERS = int(os.environ.get("ARGUS_FILEFUZZ_ITERS", "200"))
_CASE_TIMEOUT = int(os.environ.get("ARGUS_FILEFUZZ_CASE_SEC", "10"))
_SANITIZER = ("AddressSanitizer", "SUMMARY: ", "SEGV", "heap-buffer-overflow",
              "stack-overflow", "use-after-free", "UndefinedBehaviorSanitizer")


class FileFmtEngine(FuzzEngine):
    modality = "file"

    def is_available(self):
        # Always available: the built-in byte mutator needs no external tool.
        return True, ("" if (shutil.which("radamsa") or shutil.which("zzuf"))
                      else "radamsa/zzuf not found — using the built-in byte mutator (dumb fuzzing)")

    async def run(self, ctx: CampaignCtx,
                  sink: Callable[[Observation], Awaitable[None]]) -> None:
        seed_path = str(ctx.surface.get("sample_file") or "")
        parse_cmd = ctx.surface.get("parse_cmd")
        if not seed_path or not os.path.exists(seed_path) or not isinstance(parse_cmd, list) or not parse_cmd:
            logger.debug("file engine: need sample_file + parse_cmd with {input}")
            return
        try:
            seed = open(seed_path, "rb").read()
        except Exception:
            return
        iters = min(int(ctx.surface.get("iterations") or _MAX_ITERS), _MAX_ITERS)
        seen: set = set()
        for i in range(iters):
            data = await self._mutate(seed, i)
            await self._run_case(parse_cmd, data, i, seen, sink)

    async def _mutate(self, seed: bytes, i: int) -> bytes:
        if shutil.which("radamsa"):
            try:
                proc = await _spawn("radamsa", "-s", str(i),
                                    stdin=asyncio.subprocess.PIPE,
                                    stdout=asyncio.subprocess.PIPE,
                                    stderr=asyncio.subprocess.DEVNULL)
                out, _ = await asyncio.wait_for(proc.communicate(seed), timeout=_CASE_TIMEOUT)
                if out:
                    return out
            except Exception:
                pass
        return _byteflip(seed, i)

    async def _run_case(self, parse_cmd: List[str], data: bytes, i: int,
                        seen: set, sink: Callable[[Observation], Awaitable[None]]) -> None:
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix="argus_filefuzz_")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            argv = [str(a).replace("{input}", tmp) for a in parse_cmd]
            env = dict(os.environ, ASAN_OPTIONS="abort_on_error=1:exitcode=99")
            try:
                proc = await _spawn(*argv, stdout=asyncio.subprocess.DEVNULL,
                                    stderr=asyncio.subprocess.PIPE, env=env)
                _, err = await asyncio.wait_for(proc.communicate(), timeout=_CASE_TIMEOUT)
                rc = proc.returncode
            except asyncio.TimeoutError:
                return                                       # a hang is not a crash here
            err_s = (err or b"").decode("utf-8", "ignore")
            crashed = (rc is not None and rc < 0) or rc == 99 or any(s in err_s for s in _SANITIZER)
            if not crashed:
                return
            stack_hash = hashlib.sha1(data[:512]).hexdigest()[:12]
            if stack_hash in seen:
                return
            seen.add(stack_hash)
            asan = next((s for s in _SANITIZER if s in err_s), "")
            await sink(Observation(
                case_id=f"file-{i}", input=data[:64],
                signal={"crash": True, "asan": asan or None, "stack_hash": stack_hash,
                        "returncode": rc, "input_len": len(data)},
                raw=(err_s[:500] or data[:256].hex())))
        except Exception as exc:   # noqa: BLE001
            logger.debug("file case error: %s", exc)
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass


def _byteflip(seed: bytes, i: int) -> bytes:
    """Deterministic built-in mutator (no deps): flip/insert/truncate by a seeded index.
    Crude 'dumb' fuzzing, but enough to shake out brittle parsers without radamsa."""
    if not seed:
        return b"\xff" * (i + 1)
    b = bytearray(seed)
    n = len(b)
    pos = (i * 2654435761) % n
    op = i % 4
    if op == 0:                              # bit-flip
        b[pos] ^= 0x80 >> (i % 8)
    elif op == 1:                            # set to a boundary byte
        b[pos] = (0xff, 0x00, 0x7f, 0x80)[i % 4]
    elif op == 2:                            # insert a run of bytes
        b[pos:pos] = b"\xff" * 16
    else:                                    # truncate
        b = b[: max(1, pos)]
    return bytes(b)
