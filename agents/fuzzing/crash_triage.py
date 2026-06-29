"""agents/fuzzing/crash_triage.py — re-run ONE crashing input under the sanitized
target and parse its ASan/QASan report (the "what kind of bug is this" stage).

This is the leaf crash-classification helper for the sovereign 0-day pipeline (Slice 1).
It is deliberately **synchronous** and stdlib-only: it processes a single, already-found
crashing input *post-hoc*, so a blocking ``subprocess.run`` with a timeout is the right
shape (no event loop to share).  ``binary_cov.py`` imports it to revive its ASan oracle.

What it does
------------
* Re-execute ``target_bin`` on the crashing ``crash_input`` (argv-style — NEVER a shell
  string), capturing stderr where AddressSanitizer/QASan prints its report.
* Parse that report with :func:`_parse_asan` (module-level so a test can feed a CANNED
  fixture string with no binary): pull the sanitizer class (heap-buffer-overflow /
  heap-use-after-free / stack-buffer-overflow / global-buffer-overflow / double-free /
  SEGV …), the ``SUMMARY:`` line, and the top stack frames.
* Compute a stable ``stack_hash`` = sha1 of the normalized top-5 frame FUNCTION names
  (hex addresses / offsets / build paths stripped) so the same bug dedups to one cluster.

Contract
--------
``triage(...)`` returns ``{crash, sanitizer, summary, stack_hash, frames, input_path}``
and **never raises** — any error (missing binary, spawn failure, decode error) yields a
best-effort ``{crash: False, ...}`` result.  ``crash`` is True when the target died:
non-zero exit, a sanitizer report, or a timeout.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("argus.fuzz.crash_triage")

# ── ASan/QASan report fingerprints ───────────────────────────────────────────
# "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
_ERROR_RE = re.compile(
    r"(?:ERROR|WARNING):\s*(?:Address|Hardware-assisted Address|Leak|Thread|"
    r"Memory|UndefinedBehavior)?Sanitizer:\s*([A-Za-z0-9_\-]+)", re.I)
# "SUMMARY: AddressSanitizer: heap-use-after-free /src/foo.c:42 in parse"
_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*\w*Sanitizer:\s*([A-Za-z0-9_\-]+)(.*)", re.I)
# A stack frame line: "    #0 0x55ab12 in parse_header /src/foo.c:42:7"
_FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+(.*)$")
# Bare "SEGV"/"SIGSEGV"/"SIGABRT" surfaced by QASan or the kernel.
_SIGNAL_RE = re.compile(r"\b(SEGV|SIGSEGV|SIGABRT|SIGBUS|SIGFPE|SIGILL)\b")

# How many top frames feed the dedup hash.
_HASH_FRAMES = 5
# Cap captured stderr so a verbose sanitizer cannot blow up memory.
_MAX_STDERR = 64 * 1024


def triage(crash_input: str, target_bin: str, env: Optional[dict] = None,
           *, timeout: int = 20) -> Dict[str, Any]:
    """Re-run ONE crashing input under the sanitized target; parse ASan/QASan output.

    Returns ``{crash, sanitizer, summary, stack_hash, frames, input_path}``.  Never
    raises — returns ``crash=False`` (best-effort) on any error.
    """
    result: Dict[str, Any] = {
        "crash": False, "sanitizer": "", "summary": "", "stack_hash": "",
        "frames": [], "input_path": crash_input,
    }
    try:
        if not target_bin or not shutil.which(target_bin) and not os.path.exists(target_bin):
            logger.debug("crash_triage: target binary missing: %r", target_bin)
            return result
        if not crash_input or not os.path.exists(crash_input):
            logger.debug("crash_triage: crash input missing: %r", crash_input)
            return result

        # Sanitizer options: keep the report human/parseable + abort on the first error.
        run_env = dict(os.environ)
        if env:
            run_env.update({str(k): str(v) for k, v in env.items()})
        run_env.setdefault("ASAN_OPTIONS",
                           "abort_on_error=1:symbolize=1:detect_leaks=0:exitcode=99")

        argv = [target_bin, crash_input]   # argv-style — NEVER a shell string
        try:
            proc = subprocess.run(
                argv, capture_output=True, timeout=max(1, int(timeout)),
                env=run_env, check=False)
        except subprocess.TimeoutExpired as exc:
            # A hang IS a crash signal (the target died on this input).
            stderr = _decode(getattr(exc, "stderr", b"") or b"")
            parsed = _parse_asan(stderr)
            parsed["crash"] = True
            if not parsed.get("summary"):
                parsed["summary"] = "target hung (timeout)"
            parsed["input_path"] = crash_input
            return parsed
        except (FileNotFoundError, PermissionError, OSError) as exc:
            logger.debug("crash_triage: spawn failed: %s", exc)
            return result

        stderr = _decode(proc.stderr or b"")
        parsed = _parse_asan(stderr)
        parsed["input_path"] = crash_input
        # crash = sanitizer report OR the process died abnormally (nonzero / killed by signal).
        if parsed.get("sanitizer"):
            parsed["crash"] = True
        elif proc.returncode is not None and proc.returncode != 0:
            parsed["crash"] = True
            if not parsed.get("summary"):
                parsed["summary"] = _exit_summary(proc.returncode)
        return parsed
    except Exception as exc:   # noqa: BLE001  (never raise out)
        logger.debug("crash_triage: unexpected error: %s", exc)
        return result


def _parse_asan(text: str) -> Dict[str, Any]:
    """Parse an ASan/QASan report string into the triage shape (no binary needed).

    Exposed at module level so a test can feed a CANNED fixture string directly.
    Returns ``{crash, sanitizer, summary, stack_hash, frames, input_path}`` — ``crash``
    is True when a sanitizer class (or a SEGV/abort signal) was detected in the text.
    """
    out: Dict[str, Any] = {
        "crash": False, "sanitizer": "", "summary": "", "stack_hash": "",
        "frames": [], "input_path": "",
    }
    if not text:
        return out
    text = text[-_MAX_STDERR:] if len(text) > _MAX_STDERR else text

    sanitizer = ""
    summary = ""

    m = _ERROR_RE.search(text)
    if m:
        sanitizer = m.group(1).strip().lower()

    sm = _SUMMARY_RE.search(text)
    if sm:
        summary = ("SUMMARY:" + sm.group(0).split("SUMMARY:", 1)[-1]).strip()
        if not sanitizer:
            sanitizer = sm.group(1).strip().lower()

    # QASan / kernel may only surface a bare signal name.
    if not sanitizer:
        sig = _SIGNAL_RE.search(text)
        if sig:
            sanitizer = "segv" if sig.group(1).upper() in ("SEGV", "SIGSEGV") else \
                sig.group(1).lower()

    frames = _collect_frames(text)

    out["sanitizer"] = sanitizer
    out["summary"] = summary or (frames[0] if frames else "")
    out["frames"] = frames
    out["stack_hash"] = _stack_hash(frames) if frames else (
        hashlib.sha1(sanitizer.encode("utf-8", "replace")).hexdigest()[:16]
        if sanitizer else "")
    out["crash"] = bool(sanitizer)
    return out


def _collect_frames(text: str) -> List[str]:
    """Collect ordered top stack frames ("    #0 …", "    #1 …", …) from the FIRST
    backtrace in the report (the faulting one), stripping leading hex addresses."""
    frames: List[str] = []
    started = False
    for line in text.splitlines():
        fm = _FRAME_RE.match(line)
        if fm:
            started = True
            idx = int(fm.group(1))
            # Stop at the next backtrace block (frame index resets to 0).
            if idx == 0 and frames:
                break
            frames.append(fm.group(2).strip())
        elif started and frames:
            # A non-frame line after we began the backtrace ends this block.
            break
    return frames


def _frame_func(frame: str) -> str:
    """Normalize a frame to its FUNCTION name for stable hashing — strip hex
    addresses / offsets / source paths / line:col / build-id noise."""
    s = frame.strip()
    # "in parse_header /src/foo.c:42:7"  →  function token after "in "
    m = re.match(r"in\s+([^\s(]+)", s)
    if m:
        func = m.group(1)
    else:
        # "(/lib/libc.so.6+0x29d8f)" or a raw symbol+offset — take the first token.
        func = re.split(r"[\s(]", s, 1)[0]
    # Drop trailing +0x.. offset and any residual hex.
    func = re.sub(r"\+0x[0-9a-fA-F]+$", "", func)
    func = re.sub(r"0x[0-9a-fA-F]+", "", func)
    return func.strip("+@ ")


def _stack_hash(frames: List[str]) -> str:
    """sha1 of the normalized top-5 frame function names → stable dedup signature."""
    funcs = [_frame_func(f) for f in frames[:_HASH_FRAMES]]
    funcs = [f for f in funcs if f]
    if not funcs:
        return ""
    norm = "|".join(funcs)
    return hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()[:16]


def _exit_summary(returncode: int) -> str:
    if returncode is None:
        return "target terminated"
    if returncode < 0:
        return f"target killed by signal {-returncode}"
    return f"target exited nonzero ({returncode})"


def _decode(data: Any) -> str:
    if isinstance(data, str):
        return data
    try:
        return bytes(data).decode("utf-8", "replace")
    except Exception:
        return ""
