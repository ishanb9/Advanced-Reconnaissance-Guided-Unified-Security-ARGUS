"""agents/reasoning/code_hypothesis_engine.py — Big-Sleep / Naptime code-reasoning loop.

Slice 2 of the source-available 0-day pipeline.  Where Slice 1 reasons over a black-box
binary, this module reasons over *code*: it takes the normalized ``CandidateSink``s produced
by the source-taint scanners and walks Project-Naptime's first two steps —

  1. **NAVIGATE** (``navigate``) — rank the candidate sinks so the expensive LLM step only
     looks at the most promising few.  The score combines the sink's *severity*, the
     ``knowledge.fuzz_targeting.novelty_score`` term (which DOWN-weights heavily-fuzzed
     mainstream OSS — a 0-day in libxml2 is far harder than in a niche proprietary parser),
     and a *reachability / input-controllability* factor derived from
     ``knowledge.reach_controllability.controllability_signals``.

  2. **HYPOTHESISE** (``hypothesize``) — read the code slice around a sink, ask the tiered
     model (via an injected ``think_json_fn`` or ``ctx``'s think-json / ``llm_generate``) for
     a strict-JSON ``CodeVulnHypothesis`` describing the source→sink dataflow, and DROP it
     unless the model judges the input both *attacker-controllable* AND *reachable* — that
     gate is the core of the Big-Sleep loop (a finding nobody can drive is noise).

The TRIGGER+VERIFY step is delegated to ``prove_source_hypothesis``, which — for a
memory-safety (C/C++) hypothesis only — reuses Slice 1 *entirely*: it narrows a copy of the
surface to the hypothesized file/dir, calls ``harness_synth.synthesize_harness`` to build a
libFuzzer driver for the function, runs the existing greybox engine against it under a short
wall-clock, and reports an ASan-confirmed crash as a PROVEN ``PoC``.  ``exploit_dev`` is NOT
called here — everything that can't be proven this way is an honest **OBSERVED lead**.

Everything is additive, defensive and offline:
  * No network contact; reads only local source under the surface's ``source_path``.
  * Optional knowledge helpers are imported locally + best-effort (a failure falls back to a
    severity-only ranking, never an exception).
  * Every model call goes through the injected ``think_json_fn`` / ``ctx`` — no provider is
    imported directly.
  * No function raises out — on any error it logs and returns a safe default (``[]`` / ``None``).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional

from agents.fuzzing.engines.base import Anomaly, CampaignCtx, PoC

logger = logging.getLogger("argus.reasoning.code_hypothesis")

# How many lines of context to read on each side of a sink line when grounding the model.
_SLICE_CONTEXT = int(os.environ.get("ARGUS_SOURCE_SLICE_LINES", "18"))
# Hard cap on bytes of the code slice fed to the model (a single huge line can't blow context).
_SLICE_CAP = int(os.environ.get("ARGUS_SOURCE_SLICE_BYTES", "4000"))
# Wall-clock ceiling (s) on the greybox PROVE run — short by design (CI/air-gap returns fast).
_PROVE_SEC = int(os.environ.get("ARGUS_SOURCE_PROVE_SEC", "30"))

# Severity → weight (the deterministic half of the navigate score).
_SEVERITY_WEIGHT = {
    "critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35, "info": 0.15,
}
# Memory-safety exploit classes — the ONLY ones we can PROVE here by reusing Slice 1.
_MEMSAFE_CLASSES = {"memory_corruption", "memory_safety", "memsafe"}

_SYS_HYPOTHESIS = (
    "You are a vulnerability-reasoning engine inside an AUTHORIZED security lab, running "
    "Project-Naptime's HYPOTHESISE step over source code. Given a code slice around a "
    "static-analysis sink, you decide whether a real, attacker-drivable vulnerability "
    "exists by tracing the source->sink dataflow. You are CONSERVATIVE: only call an input "
    "attacker_controllable when a concrete external input (request param/body, file/upload, "
    "CLI arg, network message, env) actually reaches the sink, and only call it reachable "
    "when the function is plausibly invoked on that path. Output ONLY a single JSON object "
    "with EXACTLY these keys: file (string), line (integer), function (string), "
    "exploit_class (one of: memory_corruption, cmd_injection, sqli_exfil, ssti, "
    "deserialization, ssrf, lfi, auth_bypass, redos, dos, info), rationale (string: the "
    "concrete source->sink dataflow), attacker_controllable (boolean), reachable (boolean), "
    "suggested_trigger (string: a concrete input shape that would exercise it), "
    "confidence (number 0..1). No prose, no markdown fences."
)


@dataclass
class CodeVulnHypothesis:
    """A model-reasoned, source→sink vulnerability hypothesis for one candidate sink."""
    file: str
    line: int
    function: str = ""
    exploit_class: str = "memory_corruption"
    rationale: str = ""                       # the source->sink dataflow narrative
    attacker_controllable: bool = False
    reachable: bool = False
    suggested_trigger: str = ""
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file, "line": self.line, "function": self.function,
            "exploit_class": self.exploit_class, "rationale": self.rationale[:1200],
            "attacker_controllable": bool(self.attacker_controllable),
            "reachable": bool(self.reachable),
            "suggested_trigger": self.suggested_trigger[:600],
            "confidence": round(float(self.confidence or 0.0), 3),
        }


# ──────────────────────────────────────────────────────────────────────────────
# 1) NAVIGATE — rank candidate sinks; only the top-N reach the LLM step.
# ──────────────────────────────────────────────────────────────────────────────
def navigate(sinks: List[Any], intel: Optional[Dict[str, Any]] = None,
             *, top_n: int = 8) -> List[Any]:
    """Rank ``CandidateSink``s and return the most promising ``top_n`` to reason about.

    The score is ``severity_weight × novelty_score × reach_factor``:

      * **severity_weight** — the static analyzer's severity (deterministic prior).
      * **novelty_score** — ``knowledge.fuzz_targeting.novelty_score`` down-weights heavily-
        fuzzed mainstream OSS (a 0-day there is hard) and up-weights niche/proprietary code.
      * **reach_factor** — ``knowledge.reach_controllability.controllability_signals`` over a
        small surface dict built from the sink; an attacker-drivable, reachable sink ranks
        higher than dead code.

    Both knowledge helpers are imported locally + best-effort: if either is missing or errors
    the term degrades to a neutral factor, so navigate always returns a severity-ranked list
    rather than raising.  Never raises.
    """
    if not sinks:
        return []
    cap = max(1, int(top_n or 1))
    intel = intel if isinstance(intel, dict) else {}

    # Resolve optional knowledge helpers once, best-effort.
    novelty_fn = _maybe_novelty_fn()
    reach_fn = _maybe_reach_fn()

    scored: List[tuple] = []
    for idx, sink in enumerate(sinks):
        try:
            score = _score_sink(sink, intel, novelty_fn, reach_fn)
        except Exception as exc:   # noqa: BLE001 — one bad sink never sinks the ranking
            logger.debug("navigate: scoring sink %d failed: %s", idx, exc)
            score = _severity_weight(_get(sink, "severity", "medium"))
        # idx as a stable tiebreaker keeps the sort deterministic + total-orderable.
        scored.append((score, -idx, sink))

    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [s for _score, _idx, s in scored[:cap]]


def _score_sink(sink: Any, intel: Dict[str, Any],
                novelty_fn: Optional[Callable], reach_fn: Optional[Callable]) -> float:
    sev = _severity_weight(_get(sink, "severity", "medium"))

    # Novelty: treat the sink's language/file/rule as the "service" hint for the OSS prior.
    nov = 1.0
    if novelty_fn is not None:
        try:
            hint = str(_get(sink, "language", "") or _get(sink, "rule", "")
                       or _get(sink, "file", ""))
            nov = float(novelty_fn(hint, "code"))
        except Exception as exc:   # noqa: BLE001
            logger.debug("navigate: novelty_score failed: %s", exc)
            nov = 1.0
    nov = _clamp(nov, 0.05, 1.0)

    # Reach / input-controllability: build a tiny surface dict from the sink + intel.
    reach = 1.0
    if reach_fn is not None:
        try:
            surf = _sink_surface(sink)
            sig = reach_fn(surf, intel) or {}
            controllability = float(sig.get("controllability", 0.0) or 0.0)
            reachable = bool(sig.get("reachable", True))
            controllable = bool(sig.get("input_controllable", True))
            # A concrete attacker-drivable + reachable sink keeps full weight; otherwise it is
            # dampened toward a floor (we still let it through — the LLM gate decides later).
            gate = 1.0 if (reachable and controllable) else 0.4
            reach = _clamp(gate * (0.5 + 0.5 * controllability), 0.2, 1.0)
        except Exception as exc:   # noqa: BLE001
            logger.debug("navigate: controllability_signals failed: %s", exc)
            reach = 1.0

    return sev * nov * reach


def _sink_surface(sink: Any) -> Dict[str, Any]:
    """Build the small surface dict ``controllability_signals`` consumes from a sink."""
    return {
        "surface_type": "code",
        "service": str(_get(sink, "language", "")),
        "input_kind": str(_get(sink, "source", "")),
        "endpoint": str(_get(sink, "file", "")),
        "evidence": str(_get(sink, "message", "")),
        "exploit_class": str(_get(sink, "exploit_class", "info")),
        "dataflow_path": _get(sink, "dataflow_path", []) or [],
    }


def _maybe_novelty_fn() -> Optional[Callable]:
    try:
        from knowledge.fuzz_targeting import novelty_score   # local, best-effort
        return novelty_score
    except Exception as exc:   # noqa: BLE001
        logger.debug("navigate: fuzz_targeting.novelty_score unavailable: %s", exc)
        return None


def _maybe_reach_fn() -> Optional[Callable]:
    try:
        from knowledge.reach_controllability import controllability_signals  # local, best-effort
        return controllability_signals
    except Exception as exc:   # noqa: BLE001
        logger.debug("navigate: reach_controllability unavailable: %s", exc)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# 2) HYPOTHESISE — read the code slice, emit a gated CodeVulnHypothesis.
# ──────────────────────────────────────────────────────────────────────────────
async def hypothesize(sink: Any, ctx: CampaignCtx,
                      *, think_json_fn: Optional[Callable[..., Awaitable[Any]]] = None
                      ) -> Optional[CodeVulnHypothesis]:
    """Reason about one candidate sink and emit a gated ``CodeVulnHypothesis``.

    Reads a small, size-capped code slice around ``sink.file:sink.line``, builds a strict-JSON
    prompt, and calls the model through ``think_json_fn`` (injectable for tests) or — if not
    supplied — a think-json callable resolved from ``ctx`` (``ctx.think_json`` or a JSON wrapper
    around ``ctx.llm_generate``).  The reply is parsed tolerantly into a ``CodeVulnHypothesis``.

    Returns ``None`` when the model judges the input NOT attacker-controllable OR NOT reachable
    — Big-Sleep's core gate — or on any failure.  Never raises.
    """
    try:
        think = think_json_fn or _resolve_think_json(ctx)
        if think is None:
            logger.debug("hypothesize: no think_json / llm_generate available — skipping")
            return None

        file = str(_get(sink, "file", "") or "")
        line = _to_int(_get(sink, "line", 0))
        slice_text = _read_code_slice(file, line)
        prompt = _build_hypothesis_prompt(sink, file, line, slice_text)

        try:
            raw = await think(prompt, _SYS_HYPOTHESIS)
        except TypeError:
            # A think_json that doesn't accept a system arg (positional-only prompt).
            raw = await think(prompt)
        except Exception as exc:   # noqa: BLE001
            logger.debug("hypothesize: model call failed: %s", exc)
            return None

        data = _coerce_json(raw)
        if not isinstance(data, dict) or not data:
            logger.debug("hypothesize: model returned no usable JSON")
            return None

        hyp = _hypothesis_from(data, sink, file, line)
        # ── Big-Sleep core gate: drop anything no attacker can actually drive/reach ──
        if not hyp.attacker_controllable or not hyp.reachable:
            logger.debug("hypothesize: dropped %s:%s (controllable=%s reachable=%s)",
                         file, line, hyp.attacker_controllable, hyp.reachable)
            return None
        return hyp
    except Exception as exc:   # noqa: BLE001 — never raise out of the reasoning step
        logger.debug("hypothesize: unexpected failure: %s", exc)
        return None


def _resolve_think_json(ctx: CampaignCtx) -> Optional[Callable[..., Awaitable[Any]]]:
    """Pick a tiered think-json callable from ctx: a ctx-provided ``think_json``, else a thin
    JSON wrapper over ``ctx.llm_generate`` (which is itself the tiered-fallback entrypoint)."""
    if ctx is None:
        return None
    think = getattr(ctx, "think_json", None)
    if callable(think):
        return think
    llm = getattr(ctx, "llm_generate", None)
    if callable(llm):
        async def _wrap(prompt: str, system: str = "") -> Any:
            return await llm(prompt, system)
        return _wrap
    return None


def _build_hypothesis_prompt(sink: Any, file: str, line: int, slice_text: str) -> str:
    lines = [
        "Decide whether the source->sink dataflow at this static-analysis finding is a real, "
        "attacker-drivable vulnerability. Be conservative; honest negatives are valued.",
        f"file: {file}",
        f"line: {line}",
        f"static_rule: {_get(sink, 'rule', '')}",
        f"cwe: {_get(sink, 'cwe', '')}",
        f"reported_class: {_get(sink, 'exploit_class', 'info')}",
        f"language: {_get(sink, 'language', '')}",
        f"analyzer_message: {str(_get(sink, 'message', ''))[:400]}",
    ]
    src = str(_get(sink, "source", ""))
    snk = str(_get(sink, "sink", ""))
    if src or snk:
        lines.append(f"taint_source: {src}\ntaint_sink: {snk}")
    path = _get(sink, "dataflow_path", []) or []
    if path:
        try:
            lines.append("dataflow_path:\n" + "\n".join(f"  - {p}" for p in path[:12]))
        except Exception:
            pass
    if slice_text:
        lines.append("code slice (around the sink line):\n" + slice_text)
    lines.append("Respond with the single JSON object now.")
    return "\n".join(lines)


def _read_code_slice(file: str, line: int) -> str:
    """Read a few lines of context around ``line`` from ``file`` (size-capped, best-effort)."""
    if not file or not os.path.isfile(file):
        return ""
    try:
        with open(file, "r", encoding="utf-8", errors="replace") as fh:
            all_lines = fh.readlines()
    except Exception as exc:   # noqa: BLE001
        logger.debug("hypothesize: could not read %s: %s", file, exc)
        return ""
    if not all_lines:
        return ""
    n = len(all_lines)
    centre = max(1, int(line or 1))
    lo = max(0, centre - 1 - _SLICE_CONTEXT)
    hi = min(n, centre + _SLICE_CONTEXT)
    out: List[str] = []
    for i in range(lo, hi):
        out.append(f"{i + 1:>6}\t{all_lines[i].rstrip(chr(10))}")
    text = "\n".join(out)
    return text[:_SLICE_CAP]


def _hypothesis_from(data: Dict[str, Any], sink: Any, file: str, line: int
                     ) -> CodeVulnHypothesis:
    """Build a ``CodeVulnHypothesis`` from the parsed model dict, defaulting from the sink."""
    return CodeVulnHypothesis(
        file=str(data.get("file") or file),
        line=_to_int(data.get("line", line)),
        function=str(data.get("function") or _get(sink, "function", "") or ""),
        exploit_class=str(data.get("exploit_class")
                          or _get(sink, "exploit_class", "memory_corruption")),
        rationale=str(data.get("rationale") or ""),
        attacker_controllable=_to_bool(data.get("attacker_controllable")),
        reachable=_to_bool(data.get("reachable")),
        suggested_trigger=str(data.get("suggested_trigger") or ""),
        confidence=_to_float(data.get("confidence")),
    )


# ──────────────────────────────────────────────────────────────────────────────
# 3) TRIGGER + VERIFY — prove a memory-safety hypothesis by reusing Slice 1.
# ──────────────────────────────────────────────────────────────────────────────
async def prove_source_hypothesis(anomaly: Anomaly, ctx: CampaignCtx) -> Optional[PoC]:
    """For a memory-safety (C/C++) source hypothesis, PROVE it by reusing Slice 1 end-to-end.

    Steps (only for ``exploit_class`` in the memory-safety set — every other class returns
    ``None`` → it stays an OBSERVED lead):

      1. Narrow a COPY of ``ctx.surface`` to the hypothesized file/dir (sets ``source_path``),
         leaving the live campaign's surface untouched.
      2. ``harness_synth.synthesize_harness(sub_ctx)`` — LLM-writes + COMPILES a libFuzzer
         driver for the function.  If it returns ``None`` (e.g. no clang in CI / air-gap),
         return ``None`` → an honest OBSERVED lead.
      3. Otherwise run ``BinaryGreyboxEngine`` against the freshly-built binary under a SHORT
         wall-clock (``ARGUS_SOURCE_PROVE_SEC``, ~30s), collecting anomalies through a local
         async sink.  An ASan/memory-corruption crash → a PROVEN ``PoC``; a clean run →
         ``PoC(proven=False)`` (it built but didn't crash).

    ``exploit_dev`` is NOT called.  Never raises — any error returns ``None``.
    """
    try:
        if anomaly is None or ctx is None:
            return None
        exploit_class = str(getattr(anomaly, "exploit_class", "") or "").lower()
        if exploit_class not in _MEMSAFE_CLASSES:
            logger.debug("prove_source: non-memsafe class %r — OBSERVED lead only",
                         exploit_class)
            return None

        sub_ctx = _narrow_ctx(anomaly, ctx)
        if sub_ctx is None:
            return None

        # ── Step 2: synthesize + compile the harness (the compiler is the oracle) ──
        try:
            from agents.fuzzing import harness_synth
            built = await harness_synth.synthesize_harness(sub_ctx)
        except Exception as exc:   # noqa: BLE001
            logger.debug("prove_source: harness_synth raised: %s", exc)
            return None
        if not built or not isinstance(built, dict) or not built.get("ok"):
            logger.debug("prove_source: harness did not build — OBSERVED lead")
            return None

        target = str(sub_ctx.surface.get("binary") or built.get("target") or "")
        entry = str(built.get("entry") or "")
        if not target:
            return None

        # ── Step 3: short greybox run against the built binary, ASan as the oracle ──
        crash = await _run_short_greybox(sub_ctx)

        harness_ref = f"harness={target} entry={entry}"
        if crash is not None:
            crash_input = str((crash.detail or {}).get("input_path") or "")
            sanitizer = str((crash.detail or {}).get("sanitizer") or "")
            verdict = {
                "proven": True, "method": "harness_synth+greybox+asan",
                "reason": "ASan-confirmed memory-corruption crash on a synthesized harness",
                "sanitizer": sanitizer, "crash_input": crash_input, "entry": entry,
            }
            return PoC(
                exploit_class="memory_corruption",
                kind="payload",
                code=(f"# crashing input: {crash_input}\n# {harness_ref}\n"
                      f"# {(crash.evidence or '')[:600]}"),
                proven=True,
                verdict=verdict,
                explanation=(crash.evidence or "memory-corruption crash reproduced via a "
                             "synthesized libFuzzer harness")[:600],
            )

        # Built but did not crash in the (short) window → honest unproven lead.
        return PoC(
            exploit_class="memory_corruption",
            kind="payload",
            code=f"# {harness_ref}\n# no crash within {_PROVE_SEC}s short proof window",
            proven=False,
            verdict={"proven": False, "method": "harness_synth+greybox",
                     "reason": f"harness built ({harness_ref}) but no ASan crash within "
                               f"{_PROVE_SEC}s", "entry": entry},
            explanation="Harness built and ran; no memory-corruption crash within the short "
                        "proof window — remains an OBSERVED lead pending deeper fuzzing.",
        )
    except Exception as exc:   # noqa: BLE001 — never raise out of the prove path
        logger.debug("prove_source: unexpected failure: %s", exc)
        return None


def _narrow_ctx(anomaly: Anomaly, ctx: CampaignCtx) -> Optional[CampaignCtx]:
    """Build a sub-context whose surface is narrowed to the hypothesized file/dir.

    Copies ctx (so the live campaign surface is untouched), points ``source_path`` at the
    hypothesized file's directory (preferred — harness_synth walks a dir for the function's
    declaration) and clears any stale pre-built ``binary``.  Returns ``None`` if there is no
    usable file in the anomaly detail.
    """
    detail = getattr(anomaly, "detail", None) or {}
    file = str(detail.get("file") or "")
    if not file:
        logger.debug("prove_source: anomaly has no source file in detail")
        return None

    base_surface = dict(getattr(ctx, "surface", None) or {})
    source_path = file
    if os.path.isfile(file):
        source_path = os.path.dirname(file) or file
    elif not os.path.exists(file):
        # Honour the campaign's own source_path as the root if the bare path doesn't resolve.
        root = str(base_surface.get("source_path") or "")
        if root and os.path.isdir(root):
            source_path = root

    sub_surface = dict(base_surface)
    sub_surface["source_path"] = source_path
    sub_surface["entry_hint"] = str(detail.get("function") or "")
    sub_surface.pop("binary", None)          # force a fresh build for THIS function
    sub_surface.pop("seeds_path", None)

    try:
        from dataclasses import replace as _dc_replace
        return _dc_replace(ctx, surface=sub_surface)
    except Exception:
        # Not a dataclass instance (e.g. a test stub) — copy attributes onto a shallow shim.
        try:
            import copy
            shim = copy.copy(ctx)
            try:
                shim.surface = sub_surface
            except Exception:
                return None
            return shim
        except Exception as exc:   # noqa: BLE001
            logger.debug("prove_source: could not narrow ctx: %s", exc)
            return None


async def _run_short_greybox(sub_ctx: CampaignCtx) -> Optional[Anomaly]:
    """Run the existing greybox engine against the built binary under a short wall-clock.

    Collects streamed anomalies through a local async sink and returns the FIRST
    memory-corruption / ASan crash (or ``None`` if none within the window / on any error).
    Bounds the whole run with ``asyncio.wait_for`` so a stuck engine can never hang the prove
    path.  The engine reports its own availability and never raises out.
    """
    # The greybox engine reads its budget from ARGUS_BINFUZZ_SEC at import; align it to our
    # SHORT proof window for this run (restored afterward so the live campaign is unaffected).
    prev_budget = os.environ.get("ARGUS_BINFUZZ_SEC")
    os.environ["ARGUS_BINFUZZ_SEC"] = str(_PROVE_SEC)
    try:
        try:
            from agents.fuzzing.engines.binary_greybox import BinaryGreyboxEngine
        except Exception as exc:   # noqa: BLE001
            logger.debug("prove_source: greybox engine import failed: %s", exc)
            return None

        engine = BinaryGreyboxEngine()
        # Keep the engine's module-level budget in sync even though it was read at import time.
        try:
            import agents.fuzzing.engines.binary_greybox as _bg
            _bg._RUN_SEC = _PROVE_SEC
        except Exception:
            pass

        ok, reason = engine.is_available()
        if not ok:
            logger.debug("prove_source: greybox unavailable (%s) — OBSERVED lead", reason)
            return None

        found: List[Anomaly] = []

        async def _sink(item: Any) -> None:
            # The engine streams both status Observations and Anomalies through one sink.
            if isinstance(item, Anomaly):
                cls = str(getattr(item, "exploit_class", "") or "").lower()
                typ = str(getattr(item, "type", "") or "").lower()
                if cls in _MEMSAFE_CLASSES or typ in ("asan", "crash"):
                    found.append(item)
            return None

        try:
            # Hard outer bound — the engine self-limits, but never trust it to.
            await asyncio.wait_for(engine.run(sub_ctx, _sink), timeout=_PROVE_SEC + 10)
        except asyncio.TimeoutError:
            logger.debug("prove_source: greybox run hit the hard %ds bound", _PROVE_SEC + 10)
        except Exception as exc:   # noqa: BLE001
            logger.debug("prove_source: greybox run failed: %s", exc)

        return found[0] if found else None
    finally:
        if prev_budget is None:
            os.environ.pop("ARGUS_BINFUZZ_SEC", None)
        else:
            os.environ["ARGUS_BINFUZZ_SEC"] = prev_budget


# ──────────────────────────────────────────────────────────────────────────────
# small helpers
# ──────────────────────────────────────────────────────────────────────────────
def _coerce_json(raw: Any) -> Dict[str, Any]:
    """Turn a think-json reply (already-a-dict OR a JSON-ish string) into a dict, tolerantly."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        try:
            raw = str(raw or "")
        except Exception:
            return {}
    if not raw.strip():
        return {}
    # Prefer the repo's forgiving parser when present; fall back to strict json.
    try:
        from utils.json_tolerant import parse_lossy
        parsed, _repairs = parse_lossy(raw)
        if isinstance(parsed, dict):
            return parsed
    except Exception as exc:   # noqa: BLE001
        logger.debug("hypothesize: json_tolerant unavailable: %s", exc)
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _get(obj: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a dataclass/attr OR a dict, falling back to ``default``."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _severity_weight(sev: Any) -> float:
    return _SEVERITY_WEIGHT.get(str(sev or "medium").lower(), 0.6)


def _clamp(v: float, lo: float, hi: float) -> float:
    try:
        return max(lo, min(hi, float(v)))
    except Exception:
        return lo


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        try:
            return int(float(v))
        except Exception:
            return 0


def _to_float(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("true", "yes", "1", "y")
    return bool(v)


__all__ = ["CodeVulnHypothesis", "navigate", "hypothesize", "prove_source_hypothesis"]
