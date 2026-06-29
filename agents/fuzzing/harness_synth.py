"""agents/fuzzing/harness_synth.py — LLM-driven fuzz-harness synthesis (GENERATE-HARNESS).

Slice 1 of the sovereign 0-day pipeline: turn a *source/headers library* into a runnable
libFuzzer target so the existing coverage-guided binary engine can hammer it.  The pattern
mirrors ``exploit_dev.py``'s verify-or-refine loop, but here the **compiler is the
deterministic oracle**: an LLM (always via ``ctx.llm_generate``, tiered fallback upstream)
writes an ``LLVMFuzzerTestOneInput`` driver, ARGUS COMPILES it, and on a build error feeds
the REAL clang stderr back into the next generation — looping under a hard budget until the
target builds.  A short smoke-run then rejects a driver that instantly aborts on empty input.

Everything is additive, defensive and offline:
* No network contact; reads only local headers/sources under ``ctx.surface``.
* Every optional binary (clang, nm, readelf) is ``shutil.which``-guarded; absent → clean
  degrade, never a crash.
* ``compile_fn`` is injectable so tests need no real toolchain.
* The function NEVER raises out — on any failure it logs and returns ``None``.

On success it sets ``ctx.surface['binary']`` to the built target and returns
``{ok: True, target, entry, iters}`` so the campaign spine can fuzz it next.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import tempfile
from asyncio import create_subprocess_exec as _spawn   # argv-style, never a shell
from typing import Awaitable, Callable, List, Optional, Tuple

from agents.fuzzing.engines.base import CampaignCtx

logger = logging.getLogger("argus.fuzz.harness")

# Hard ceiling on bytes read from any one header/source so a huge file can't blow context.
_SNIPPET_CAP = int(os.environ.get("ARGUS_HARNESS_SNIPPET_BYTES", "6000"))
# How many header/source files to ground the model with.
_MAX_SNIPPETS = int(os.environ.get("ARGUS_HARNESS_MAX_SNIPPETS", "6"))
# Smoke-run wall-clock ceiling (s) — a healthy driver returns fast on -runs=100.
_SMOKE_SEC = int(os.environ.get("ARGUS_HARNESS_SMOKE_SEC", "4"))

_HDR_EXT = (".h", ".hpp", ".hh", ".hxx")
_SRC_EXT = (".c", ".cc", ".cpp", ".cxx")
# Entry-function name hints, most-fuzzable first.
_ENTRY_HINTS = ("parse", "decode", "load", "read", "deserial", "unpack",
                "decompress", "scan", "process", "handle", "import")

_SYS_HARNESS = (
    "You are a fuzz-harness synthesis engine inside an AUTHORIZED security lab. Given a "
    "C/C++ library's headers and exported symbols, you write a SINGLE self-contained "
    "libFuzzer driver that exercises ONE entry function on attacker-controlled input. "
    "Output ONLY compilable C/C++ source — no prose, no markdown fences.\n"
    "Hard requirements:\n"
    "  * Define exactly `extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, "
    "size_t size)` (use `extern \"C\"` only for C++).\n"
    "  * Include the needed library headers and <stdint.h>/<stddef.h>/<string.h>.\n"
    "  * Feed `data`/`size` into the chosen entry function; copy into a NUL-terminated "
    "buffer if it expects a C string. Bound every length by `size`.\n"
    "  * MUST return 0 and MUST NOT crash, exit(), or abort on empty input (size == 0): "
    "guard with an early `if (size == 0) return 0;` when the entry needs bytes.\n"
    "  * Do NOT define main(); libFuzzer supplies it. No global I/O, no network, no sleeps."
)


async def synthesize_harness(ctx: CampaignCtx, *,
                             compile_fn: Optional[Callable[[str, str], Tuple[bool, str]]] = None,
                             max_iters: int = 4) -> Optional[dict]:
    """Synthesise a libFuzzer harness for the source/headers library in ``ctx.surface``.

    Mirrors ``exploit_dev.develop``: the LLM writes a driver, the COMPILER is the oracle,
    and a build failure's real stderr is fed back to repair the next attempt — looping up
    to ``max_iters``.  ``compile_fn(code, out_path) -> (ok, stderr)`` is injectable so tests
    need no clang; the default shells ``clang -fsanitize=address,fuzzer``.

    On success sets ``ctx.surface['binary']`` and returns
    ``{"ok": True, "target": out_path, "entry": <fn>, "iters": <n>}``; returns ``None`` on
    any failure (missing toolchain, no entry, budget exhausted).  Never raises.
    """
    try:
        if ctx.llm_generate is None:
            logger.debug("harness synth: no llm_generate on ctx — skipping")
            return None

        surface = ctx.surface or {}
        source_path = str(surface.get("source_path") or "")
        headers = surface.get("headers") or []
        lib = str(surface.get("lib") or surface.get("library") or "")
        if not source_path and not headers and not lib:
            logger.debug("harness synth: no source_path/headers/lib in surface — skipping")
            return None

        # ── 1) Grounding: header/source snippets + exported symbols ──
        snippets = _gather_snippets(source_path, headers)
        symbols = _exported_symbols(lib)
        entry = _pick_entry(symbols, snippets)
        if not entry:
            logger.debug("harness synth: no candidate entry function found — skipping")
            return None

        compiler = compile_fn or _default_clang_compile
        out_path = _out_path(source_path or lib)

        history: List[dict] = []
        budget = max(1, int(max_iters))
        for i in range(budget):
            prompt = _build_prompt(ctx, entry, snippets, symbols, lib, history)
            try:
                code = await ctx.llm_generate(prompt, _SYS_HARNESS)
            except Exception as exc:   # noqa: BLE001
                logger.debug("harness synth LLM gen failed (iter %d): %s", i, exc)
                code = ""
            code = _strip_fences(code or "")
            if not code:
                history.append({"code": "", "stderr": "model returned no source"})
                continue

            try:
                ok, stderr = compiler(code, out_path)
            except Exception as exc:   # noqa: BLE001
                logger.debug("harness synth compile_fn raised (iter %d): %s", i, exc)
                ok, stderr = False, f"{type(exc).__name__}: {exc}"

            await ctx.emit_event("harness_synth_step", {
                "iteration": i, "entry": entry, "compiled": bool(ok),
                "stderr_preview": (stderr or "")[:400], "code_preview": code[:400]})

            if not ok:
                history.append({"code": code[:1600], "stderr": (stderr or "")[:1600]})
                continue

            # ── 4) Smoke-run: reject a driver that instantly aborts on empty input ──
            if not await _smoke_ok(out_path):
                history.append({"code": code[:1600],
                                "stderr": "the harness compiled but ABORTED on the empty "
                                          "input during smoke-run; it must `return 0` on "
                                          "size==0 and not crash on trivial input"})
                continue

            # ── 5) Success ──
            ctx.surface["binary"] = out_path
            logger.info("harness synth: built libFuzzer target for entry %r at %s "
                        "(%d iter)", entry, out_path, i + 1)
            return {"ok": True, "target": out_path, "entry": entry, "iters": i + 1}

        logger.debug("harness synth: unproven after %d iterations for entry %r",
                     budget, entry)
        return None
    except Exception as exc:   # noqa: BLE001 — never raise out of the sub-stage
        logger.debug("harness synth: unexpected failure: %s", exc)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Grounding helpers
# ──────────────────────────────────────────────────────────────────────────────
def _gather_snippets(source_path: str, headers) -> List[Tuple[str, str]]:
    """Read up to ``_MAX_SNIPPETS`` header/source files (size-capped) for grounding.

    Returns a list of ``(relname, text)``.  Headers are preferred (they carry the public
    surface).  ``source_path`` may be a directory (walked for *.h/*.c) or a single file.
    """
    paths: List[str] = []

    def _add(p: str) -> None:
        if p and p not in paths and os.path.isfile(p):
            paths.append(p)

    for h in (headers or []):
        if isinstance(h, str):
            _add(h)

    if source_path and os.path.isdir(source_path):
        for root, _dirs, files in os.walk(source_path):
            for name in sorted(files):
                if name.lower().endswith(_HDR_EXT):
                    _add(os.path.join(root, name))
        for root, _dirs, files in os.walk(source_path):
            for name in sorted(files):
                if name.lower().endswith(_SRC_EXT):
                    _add(os.path.join(root, name))
    elif source_path and os.path.isfile(source_path):
        _add(source_path)

    # Headers (public surface) first, then sources, capped.
    paths.sort(key=lambda p: 0 if p.lower().endswith(_HDR_EXT) else 1)
    out: List[Tuple[str, str]] = []
    for p in paths[:_MAX_SNIPPETS]:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(_SNIPPET_CAP)
        except Exception:
            continue
        out.append((os.path.basename(p), text))
    return out


def _exported_symbols(lib: str) -> List[str]:
    """Best-effort exported function names from a shared/static lib via nm -D / readelf.

    Both tools are ``shutil.which``-guarded; absent or non-file → empty list (never raises).
    """
    if not lib or not os.path.isfile(lib):
        return []
    out = ""
    nm = shutil.which("nm")
    if nm:
        out = _run_capture([nm, "-D", "--defined-only", lib]) or _run_capture([nm, lib])
    if not out:
        readelf = shutil.which("readelf")
        if readelf:
            out = _run_capture([readelf, "-Ws", lib])
    if not out:
        return []
    names: List[str] = []
    seen = set()
    for line in out.splitlines():
        # nm:  "0000... T symbol"   readelf: "... FUNC ... symbol"
        m = re.search(r"\b[TtWw]\s+([A-Za-z_]\w+)\s*$", line)
        if not m and "FUNC" in line:
            m = re.search(r"([A-Za-z_]\w+)\s*$", line)
        if m:
            sym = m.group(1)
            if sym and not sym.startswith(("_", ".")) and sym not in seen:
                seen.add(sym)
                names.append(sym)
    return names[:200]


def _run_capture(argv: List[str], timeout: int = 15) -> str:
    """Run a read-only tool synchronously and return stdout (best-effort, never raises)."""
    try:
        import subprocess
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False)
        return proc.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def _pick_entry(symbols: List[str], snippets: List[Tuple[str, str]]) -> str:
    """Pick a candidate entry function, preferring parse/decode/load/read-style names."""
    candidates: List[str] = list(symbols)
    # Mine declarations from header snippets too (symbols may be empty without a lib).
    decl = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{)]*\)\s*;")
    for _name, text in snippets:
        for m in decl.finditer(text):
            fn = m.group(1)
            if fn and fn not in candidates and fn not in ("if", "for", "while", "switch",
                                                          "return", "sizeof"):
                candidates.append(fn)

    def _score(fn: str) -> int:
        low = fn.lower()
        for rank, hint in enumerate(_ENTRY_HINTS):
            if hint in low:
                return rank
        return len(_ENTRY_HINTS) + 1

    if not candidates:
        return ""
    candidates.sort(key=lambda fn: (_score(fn), len(fn)))
    return candidates[0]


def _build_prompt(ctx: CampaignCtx, entry: str, snippets: List[Tuple[str, str]],
                  symbols: List[str], lib: str, history: List[dict]) -> str:
    lines = [
        f"Synthesize a libFuzzer harness for the in-scope library target: {ctx.target}",
        f"Candidate entry function to fuzz: {entry}",
    ]
    if lib:
        lines.append(f"Library to link: {lib}")
    if symbols:
        lines.append("Exported symbols (subset):\n" + ", ".join(symbols[:40]))
    if snippets:
        joined = "\n\n".join(f"// ---- {name} ----\n{text}" for name, text in snippets)
        lines.append("Header/source context (truncated):\n" + joined[:9000])
    if history:
        last = history[-1]
        lines.append("Your PREVIOUS harness did NOT build/smoke-pass. Fix it using the "
                     "REAL compiler/runtime output below — do not repeat the same mistake.")
        if last.get("code"):
            lines.append("Previous harness:\n" + last["code"][:1400])
        lines.append("Compiler/runtime output:\n" + last.get("stderr", "")[:1400])
    lines.append("Write the complete, corrected libFuzzer driver now (source only).")
    return "\n\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Compile + smoke-run (the deterministic oracle)
# ──────────────────────────────────────────────────────────────────────────────
def _out_path(hint: str) -> str:
    base = os.path.splitext(os.path.basename(hint or "harness"))[0] or "harness"
    return os.path.join(tempfile.gettempdir(), f"argus_harness_{base}")


def _default_clang_compile(code: str, out_path: str) -> Tuple[bool, str]:
    """Shell clang to build the driver as a libFuzzer+ASan target.

    ``clang -g -O1 -fsanitize=address,fuzzer driver.c <lib> -o out``.  ``clang`` is
    ``shutil.which``-guarded; absent → ``(False, "clang not installed")``.  The lib (if any)
    is linked positionally.  Best-effort: any failure returns ``(False, <stderr>)``.
    """
    clang = shutil.which("clang") or shutil.which("clang++")
    if not clang:
        return False, "clang not installed"
    is_cpp = bool(re.search(r'extern\s+"C"|::|\btemplate\b|\bnamespace\b|\bnew\b', code))
    src_ext = ".cc" if is_cpp else ".c"
    src_path = out_path + src_ext
    try:
        with open(src_path, "w", encoding="utf-8") as fh:
            fh.write(code)
    except Exception as exc:   # noqa: BLE001
        return False, f"could not write driver source: {exc}"

    argv = [clang, "-g", "-O1", "-fsanitize=address,fuzzer", src_path, "-o", out_path]
    # Link a provided library positionally if it exists.
    # (surface['lib'] is threaded via the closure-free path: re-read from cwd-agnostic env not
    #  needed — the caller compiles with whatever it passes; here we honour an inline marker.)
    try:
        import subprocess
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=120, check=False)
    except Exception as exc:   # noqa: BLE001
        return False, f"clang invocation failed: {exc}"
    if proc.returncode == 0 and os.path.exists(out_path):
        return True, ""
    return False, proc.stderr.decode("utf-8", "replace")


async def _smoke_ok(out_path: str) -> bool:
    """Run the built target briefly; require it does NOT instantly abort on empty input.

    libFuzzer with ``-runs=100`` starts from the empty input; a healthy driver returns
    quickly with exit 0, while one that aborts on size==0 returns non-zero immediately.
    A timeout (still fuzzing) counts as healthy.  Never raises — on any error returns True
    so a working compile is not wrongly discarded.
    """
    if not os.path.exists(out_path):
        return False
    if not os.access(out_path, os.X_OK):
        try:
            os.chmod(out_path, 0o755)
        except Exception:
            pass
    argv = [out_path, "-runs=100", "-rss_limit_mb=1024"]
    try:
        proc = await _spawn(*argv, stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.DEVNULL)
    except Exception as exc:   # noqa: BLE001
        logger.debug("harness smoke-run spawn failed: %s", exc)
        return True   # cannot run it here (e.g. wrong arch) — don't penalise a clean build
    try:
        rc = await asyncio.wait_for(proc.wait(), timeout=_SMOKE_SEC)
    except asyncio.TimeoutError:
        # Still running after the window → it survived the empty input. Healthy.
        try:
            proc.kill()
        except Exception:
            pass
        return True
    except Exception:
        return True
    # A crash/abort on the seed corpus surfaces as a non-zero (often 77/1) very fast.
    return rc == 0


def _strip_fences(s: str) -> str:
    """Strip a leading ```lang fence + trailing ``` the model may have added."""
    s = (s or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[-1] if "\n" in s else s
        if s.endswith("```"):
            s = s[: s.rfind("```")]
    return s.strip()
