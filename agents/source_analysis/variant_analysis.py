"""agents/source_analysis/variant_analysis.py - LLM-guided bug-class variant pass (Slice 2).

The rigid static rules (semgrep/bandit/graudit, normalized in ``taint_scan.scan_source``) catch
the instances they have signatures for - but they routinely MISS *siblings*: the same bug class,
the same untrusted-input -> dangerous-sink shape, copy-pasted a few files over or written in a
slightly different idiom the rule never anticipated.

This module is the small SOTA force-multiplier on top of that: for the highest-severity
``CandidateSink``s we ask the tiered model to propose WHERE ELSE to look - either a concrete
grep/ripgrep regex or a list of sibling code locations exhibiting the SAME class - and then we
let an actual ``ripgrep``/``grep`` over the operator-supplied source tree CONFIRM the matches.
The LLM proposes; grep proves. Confirmed, deduped matches become NEW ``CandidateSink`` records.

Strictly additive + defensive: every model call goes through ``ctx.llm_generate`` (tiered
fallback upstream); the binary is ``shutil.which``-guarded; everything is offline / air-gap safe;
and any failure (no LLM, no grep, bad JSON, timeout) degrades to ``[]``. Never raises.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Cap how much we let the model drive the search so a pathological response can't fan out.
_MAX_PATTERNS = 6
_MAX_MATCHES_PER_PATTERN = 40
_MAX_NEW_SINKS = 50
_GREP_TIMEOUT = 30

_SYSTEM = (
    "You are a source-code vulnerability auditor performing a VARIANT ANALYSIS pass. "
    "A static scanner already found one instance of a bug class; your job is to point at "
    "where MORE instances of the SAME class likely live in this codebase - places where "
    "untrusted input reaches the same kind of dangerous sink. "
    "Respond ONLY with a single JSON object, no prose."
)

# ripgrep result line shape: "<path>:<line>:<text>"  (run with --no-heading -n).
_RG_LINE = re.compile(r"^(?P<file>.+?):(?P<line>\d+):(?P<text>.*)$")
# A few obviously-unsafe regex constructs we refuse to hand to grep verbatim.
_REGEX_REJECT = re.compile(r"\\[0-9]|\(\?R\)|\(\?<")


# ----------------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------------
async def expand_variants(
    sinks: List[Any],
    ctx: Any,
    *,
    top_n: int = 5,
    grep_fn: Optional[Callable[..., List[Dict[str, Any]]]] = None,
) -> List[Any]:
    """Expand the highest-severity ``CandidateSink``s with LLM-proposed, grep-confirmed siblings.

    For the ``top_n`` highest-severity input sinks, ask the tiered model
    (``await ctx.llm_generate(prompt, system)``) for a ripgrep/grep pattern OR a list of sibling
    locations that exhibit the SAME bug class. Each proposed pattern is confirmed by ``grep_fn``
    (injectable; defaults to a ``ripgrep``/``grep`` argv-subprocess over
    ``ctx.surface["source_path"]``, ``shutil.which``-guarded). Confirmed matches become NEW
    ``CandidateSink`` records (reusing ``taint_scan.CandidateSink``), deduped against the input
    sinks by ``(file, line)``.

    Best-effort: returns ``[]`` if ``ctx.llm_generate`` is None, the source path is missing, the
    grep binary is absent, or anything else fails. Never raises.
    """
    try:
        llm = getattr(ctx, "llm_generate", None)
        if llm is None or not callable(llm):
            return []
        if not isinstance(sinks, list) or not sinks:
            return []

        sink_cls = _candidate_sink_cls()
        if sink_cls is None:
            return []

        source_path = _source_path(ctx)
        if not source_path or not os.path.isdir(source_path):
            return []

        grep = grep_fn or _default_grep_fn
        if grep_fn is None and not _grep_binary():
            # No injectable grep and no real binary on this host -> nothing to confirm with.
            return []

        try:
            top_n = max(1, int(top_n))
        except Exception:
            top_n = 5

        ranked = _rank_by_severity(sinks)[:top_n]
        if not ranked:
            return []

        # Dedup index seeded with the existing sinks so we never re-emit a known location.
        seen = {_key(getattr(s, "file", ""), getattr(s, "line", 0)) for s in sinks}
        new_sinks: List[Any] = []

        for sink in ranked:
            if len(new_sinks) >= _MAX_NEW_SINKS:
                break
            try:
                produced = await _expand_one(sink, llm, ctx, grep, source_path, sink_cls, seen)
            except Exception as exc:  # one sink failing must not abort the rest
                logger.debug("variant_analysis: sink expansion failed: %s", exc)
                continue
            for ns in produced:
                if ns is None:
                    continue
                if len(new_sinks) >= _MAX_NEW_SINKS:
                    break
                new_sinks.append(ns)

        logger.info("variant_analysis: %d new sibling sink(s) from %d seed(s)",
                    len(new_sinks), len(ranked))
        return new_sinks
    except Exception as exc:  # pure-additive contract: never raise out
        logger.debug("variant_analysis.expand_variants degraded: %s", exc)
        return []


# ----------------------------------------------------------------------------------
# Per-sink expansion
# ----------------------------------------------------------------------------------
async def _expand_one(sink, llm, ctx, grep, source_path, sink_cls, seen) -> List[Any]:
    """Ask the model for variants of ONE sink's bug class, grep-confirm, build new sinks."""
    prompt = _build_prompt(sink)
    try:
        raw = await llm(prompt, _SYSTEM)
    except TypeError:
        # Some llm_generate stubs take a single positional arg.
        raw = await llm(prompt)
    spec = _parse_llm(raw)
    if not spec:
        return []

    bug_class = str(spec.get("bug_class") or getattr(sink, "exploit_class", "") or "info")
    cwe = str(spec.get("cwe") or getattr(sink, "cwe", "") or "")
    patterns = _clean_patterns(spec.get("patterns") or spec.get("grep") or [])

    out: List[Any] = []
    for pattern in patterns[:_MAX_PATTERNS]:
        try:
            matches = await _confirm(grep, pattern, source_path)
        except Exception as exc:
            logger.debug("variant_analysis: grep confirm failed for %r: %s", pattern, exc)
            continue
        for m in matches[:_MAX_MATCHES_PER_PATTERN]:
            f = str(m.get("file") or "")
            ln = _to_int(m.get("line"))
            if not f or ln <= 0:
                continue
            key = _key(f, ln)
            if key in seen:
                continue
            seen.add(key)
            out.append(_make_sink(sink_cls, sink, file=f, line=ln, pattern=pattern,
                                  bug_class=bug_class, cwe=cwe, snippet=str(m.get("text") or "")))
    return out


def _build_prompt(sink: Any) -> str:
    """One-shot prompt anchored on the concrete seed sink."""
    sd = _sink_view(sink)
    return (
        "A static scanner found ONE instance of a vulnerability class in a source tree.\n"
        "Find MORE instances of the SAME class - places where untrusted input reaches a "
        "sink like this one.\n\n"
        "SEED FINDING:\n"
        f"  file: {sd['file']}:{sd['line']}\n"
        f"  bug_class / exploit_class: {sd['exploit_class']}\n"
        f"  cwe: {sd['cwe']}\n"
        f"  language: {sd['language']}\n"
        f"  rule: {sd['rule']}\n"
        f"  source(taint origin): {sd['source']}\n"
        f"  sink(dangerous call): {sd['sink']}\n"
        f"  message: {sd['message']}\n\n"
        "Propose ripgrep-compatible regular expressions that would LOCATE sibling instances of "
        "this same bug class elsewhere in the codebase (e.g. the same dangerous sink call, or "
        "the same untrusted-input pattern). Prefer specific patterns over broad ones.\n\n"
        "Return ONLY this JSON object:\n"
        '{"bug_class": "<short class>", "cwe": "<CWE-xxx or empty>", '
        '"patterns": ["<rg regex>", "..."]}'
    )


# ----------------------------------------------------------------------------------
# Grep confirmation (default impl = ripgrep/grep over the source tree, argv list)
# ----------------------------------------------------------------------------------
async def _confirm(grep, pattern: str, source_path: str) -> List[Dict[str, Any]]:
    """Run the (possibly injected) grep_fn; tolerate sync or async, normalize the result."""
    res = grep(pattern, source_path)
    if asyncio.iscoroutine(res) or hasattr(res, "__await__"):
        res = await res
    if not isinstance(res, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in res:
        if isinstance(item, dict) and item.get("file"):
            out.append(item)
    return out


async def _default_grep_fn(pattern: str, source_path: str) -> List[Dict[str, Any]]:
    """Confirm a pattern with a real ripgrep/grep over ``source_path`` via an argv subprocess.

    NEVER a shell string - argv list only. ``shutil.which``-guarded; offline; returns ``[]``
    (never raises) on a missing binary, timeout, or any error.
    """
    binary, kind = _grep_binary_kind()
    if not binary:
        return []
    if kind == "rg":
        argv = [binary, "--no-heading", "--line-number", "--color", "never",
                "--max-count", str(_MAX_MATCHES_PER_PATTERN), "-e", pattern, source_path]
    else:  # POSIX grep
        argv = [binary, "-rnI", "-E", "-e", pattern, source_path]

    spawn = asyncio.create_subprocess_exec  # argv-list spawn; no shell involved
    try:
        proc = await spawn(*argv, stdout=asyncio.subprocess.PIPE,
                           stderr=asyncio.subprocess.DEVNULL)
    except Exception as exc:
        logger.debug("variant_analysis: failed to spawn grep: %s", exc)
        return []

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=_GREP_TIMEOUT)
    except asyncio.TimeoutError:
        logger.debug("variant_analysis: grep timed out")
        try:
            proc.kill()
        except Exception:
            pass
        return []
    except Exception as exc:
        logger.debug("variant_analysis: grep communicate failed: %s", exc)
        return []

    return _parse_grep_stdout(stdout, source_path)


def _parse_grep_stdout(stdout: bytes, source_path: str) -> List[Dict[str, Any]]:
    """Parse ``path:line:text`` lines from rg/grep into normalized match dicts."""
    out: List[Dict[str, Any]] = []
    try:
        text = (stdout or b"").decode("utf-8", "replace")
    except Exception:
        return out
    for raw in text.splitlines():
        m = _RG_LINE.match(raw)
        if not m:
            continue
        f = m.group("file")
        # Make the path relative to the source root for stable, portable dedup keys.
        try:
            rel = os.path.relpath(f, source_path)
        except Exception:
            rel = f
        out.append({"file": rel.replace("\\", "/"),
                    "line": _to_int(m.group("line")),
                    "text": (m.group("text") or "").strip()[:300]})
        if len(out) >= _MAX_MATCHES_PER_PATTERN:
            break
    return out


def _grep_binary_kind():
    rg = shutil.which("rg")
    if rg:
        return rg, "rg"
    g = shutil.which("grep")
    if g:
        return g, "grep"
    return None, ""


def _grep_binary() -> Optional[str]:
    return _grep_binary_kind()[0]


# ----------------------------------------------------------------------------------
# CandidateSink construction (reuse taint_scan.CandidateSink)
# ----------------------------------------------------------------------------------
def _candidate_sink_cls() -> Optional[Any]:
    """Import the canonical CandidateSink lazily so this module imports even mid-build."""
    try:
        from agents.source_analysis.taint_scan import CandidateSink
        return CandidateSink
    except Exception as exc:
        logger.debug("variant_analysis: CandidateSink unavailable: %s", exc)
        return None


def _make_sink(sink_cls, seed, *, file, line, pattern, bug_class, cwe, snippet):
    """Build a new CandidateSink for a grep-confirmed sibling, inheriting seed metadata."""
    msg = f"variant of {getattr(seed, 'rule', '') or bug_class} (LLM-proposed, grep-confirmed)"
    if snippet:
        msg = f"{msg}: {snippet}"
    kwargs = {
        "file": file,
        "line": line,
        "rule": f"variant:{getattr(seed, 'rule', '') or bug_class}",
        "cwe": cwe or getattr(seed, "cwe", ""),
        "severity": getattr(seed, "severity", "medium"),
        "language": getattr(seed, "language", ""),
        "exploit_class": bug_class or getattr(seed, "exploit_class", "info"),
        "source": getattr(seed, "source", ""),
        "sink": pattern,
        "message": msg[:400],
    }
    try:
        return sink_cls(**kwargs)
    except TypeError:
        # Be forgiving if the dataclass signature drifts - file+line are the contract.
        try:
            return sink_cls(file=file, line=line)
        except Exception:
            return None


# ----------------------------------------------------------------------------------
# Parsing / ranking / small helpers
# ----------------------------------------------------------------------------------
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _rank_by_severity(sinks: List[Any]) -> List[Any]:
    """Highest-severity first; stable for equal severities."""
    def _w(s: Any) -> int:
        return _SEV_RANK.get(str(getattr(s, "severity", "medium")).lower(), 2)
    return sorted([s for s in sinks if s is not None], key=_w, reverse=True)


def _parse_llm(raw: Any) -> Optional[Dict[str, Any]]:
    """Extract the JSON object from a model response; tolerate fences / surrounding prose."""
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    text = str(raw)
    # Strip code fences if present.
    fence = re.search(r"`{3}(?:json)?\s*(.+?)`{3}", text, re.S)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except Exception:
        pass
    # Fall back to the first balanced-looking object.
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _clean_patterns(raw: Any) -> List[str]:
    """Normalize the proposed patterns into a small list of safe, compilable regexes."""
    items: List[str] = []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    for p in raw:
        if isinstance(p, dict):  # tolerate [{"pattern": "..."}]
            p = p.get("pattern") or p.get("regex") or p.get("grep")
        if not isinstance(p, str):
            continue
        p = p.strip()
        if not p or len(p) > 400:
            continue
        if _REGEX_REJECT.search(p):  # backrefs / recursion not supported by rg/grep -E
            continue
        try:
            re.compile(p)  # reject patterns grep would also choke on
        except Exception:
            continue
        if p not in items:
            items.append(p)
        if len(items) >= _MAX_PATTERNS:
            break
    return items


def _source_path(ctx: Any) -> str:
    try:
        surface = getattr(ctx, "surface", None) or {}
        if isinstance(surface, dict):
            return str(surface.get("source_path") or "").strip()
    except Exception:
        pass
    return ""


def _sink_view(sink: Any) -> Dict[str, str]:
    g = lambda k, d="": str(getattr(sink, k, d) or d)
    return {
        "file": g("file"), "line": g("line", "0"),
        "exploit_class": g("exploit_class", "info"), "cwe": g("cwe"),
        "language": g("language"), "rule": g("rule"),
        "source": g("source"), "sink": g("sink"), "message": g("message"),
    }


def _key(file: Any, line: Any) -> str:
    return f"{str(file).replace(chr(92), '/').strip().lower()}:{_to_int(line)}"


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0
