"""agents/fuzzing/engines/source_engine.py — source-available code-audit engine (Slice 2).

The ``source`` modality: reason over *code* instead of a black-box binary.  Point it at a
checked-out repo / decompiled source / an OSS dependency (``surface['source_path']``) and it
mirrors Slice 1's spine — but the "interesting result" is a *hypothesis about a vulnerability*
grounded in a real taint path, not a live crash.  The pipeline:

  (1) TAINT     — ``source_analysis.taint_scan.scan_source`` runs semgrep (taint) + bandit (py)
                  + graudit over the tree (each ``shutil.which``-guarded, offline) → normalized
                  ``CandidateSink``s.
  (2) REACH     — ``knowledge.reach_controllability.controllability_signals`` derives
                  reachable / input_controllable for each sink from recon evidence ARGUS
                  already has (no live traffic).
  (3) NAVIGATE  — ``reasoning.code_hypothesis_engine.navigate`` ranks sinks
                  (``fuzz_targeting.novelty_score`` down-weights heavily-fuzzed OSS) and caps.
  (4) VARIANTS  — opt-in (``surface['variant_analysis']``): an LLM "find more instances of this
                  bug class" pass expands + re-navigates the ranked set.
  (5) HYPOTHESISE— opt-in (``surface['code_reasoning']``): a Big-Sleep/Naptime ``think_json``
                  loop reads the code slice and emits a ``CodeVulnHypothesis`` (dropped unless
                  attacker-controllable AND reachable).  Without the flag, a minimal hypothesis
                  is synthesized straight from the sink so leads still surface.
  (6) EMIT      — each surviving hypothesis is streamed to the campaign as an
                  ``Anomaly(type="source_hypothesis")`` whose evidence is the rationale + the
                  ``file:line`` + the taint dataflow.  The campaign's guarded DEVELOP branch
                  may then PROVE a C/C++ memory-safety lead via Slice 1
                  (``code_hypothesis_engine.prove_source_hypothesis``); everything else is a
                  ranked OBSERVED lead.

Strictly additive + defensive by construction: every step is guarded and every sibling module
is imported lazily, so a missing module / binary degrades cleanly to fewer results (never an
exception).  All model calls go through ``ctx.llm_generate`` (tiered fallback upstream) inside
the called modules — this engine imports no provider.  The loop honours ``ctx`` budget / stop /
throttle, caps the number of LLM hypotheses (``ARGUS_SOURCE_MAX_HYP``) so cost is bounded, and
NEVER raises out (log + return).  Lab-gated — the autonomous engine never selects ``source``.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

from agents.fuzzing.engines.base import Anomaly, CampaignCtx, FuzzEngine, Observation

logger = logging.getLogger("argus.fuzz.engine.source")

# Wall-clock budget for the whole audit (taint scan dominates; LLM passes are capped).
_RUN_SEC = int(os.environ.get("ARGUS_SOURCE_SEC", "600"))
# Hard cap on LLM hypotheses so cost is bounded even on a huge sink list.
_MAX_HYP = max(1, int(os.environ.get("ARGUS_SOURCE_MAX_HYP", "8")))
# Per-sink throttle nap (seconds) applied while a live scan is running alongside.
_THROTTLE_SEC = 1.0

# severity-token → Anomaly severity_hint (CandidateSink.severity is semgrep/bandit-ish text).
_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "error": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium",
    "low": "low", "minor": "low", "info": "info", "note": "info",
}

# Optional source-audit tools — any one present makes the modality usable.
_TOOLS = ("semgrep", "bandit", "graudit")


class SourceEngine(FuzzEngine):
    """Source-available code-audit engine: taint → navigate → hypothesise → emit leads."""

    modality = "source"

    def is_available(self) -> "tuple[bool, str]":
        present = [t for t in _TOOLS if shutil.which(t)]
        if present:
            return True, ""
        return False, ("no source-audit tool on PATH (install one of "
                       + ", ".join(_TOOLS) + " for the source modality)")

    async def run(self, ctx: CampaignCtx,
                  sink: Callable[[Anomaly], Awaitable[None]]) -> None:
        try:
            await self._run(ctx, sink)
        except Exception as exc:   # noqa: BLE001 — never raise out of the engine loop
            logger.warning("source engine aborted: %s", exc)
            return

    # ── internals ───────────────────────────────────────────────────────────────
    async def _run(self, ctx: CampaignCtx,
                   sink: Callable[[Anomaly], Awaitable[None]]) -> None:
        src = str((ctx.surface or {}).get("source_path") or "")
        if not src or not os.path.exists(src):
            logger.debug("source engine: no source_path provided (surface['source_path'])")
            return

        deadline = time.time() + _RUN_SEC
        langs = (ctx.surface or {}).get("langs") or (ctx.surface or {}).get("languages")

        await ctx.emit_event("source_started", {"source_path": src, "budget_sec": _RUN_SEC})

        # (1) TAINT — normalize semgrep/bandit/graudit findings to CandidateSinks.
        sinks = self._scan_source(src, langs)
        await self._emit_status(ctx, sink, {"stage": "taint", "sinks": len(sinks)})
        if not sinks:
            logger.debug("source engine: taint scan produced no candidate sinks")
            await ctx.emit_event("source_finished", {"source_path": src, "leads": 0})
            return

        # (2) REACH — derive reachable / input_controllable per sink from recon evidence.
        for s in sinks:
            self._set_reach(s, ctx)

        # (3) NAVIGATE — rank sinks (novelty × severity × reach) and cap.
        ranked = self._navigate(sinks, ctx)
        await self._emit_status(ctx, sink, {"stage": "navigate", "ranked": len(ranked)})

        # (4) VARIANTS — opt-in LLM "find more instances of this class" expansion.
        if (ctx.surface or {}).get("variant_analysis") and not self._budget_done(ctx, deadline):
            ranked = await self._expand_variants(ranked, ctx)
            await self._emit_status(ctx, sink, {"stage": "variants", "ranked": len(ranked)})

        # (5/6) HYPOTHESISE + EMIT — bounded LLM reasoning per top sink, else a minimal lead.
        code_reasoning = bool((ctx.surface or {}).get("code_reasoning"))
        kept = 0
        hyp_used = 0
        seen: set = set()
        for s in ranked:
            if self._budget_done(ctx, deadline):
                logger.debug("source engine: budget/stop reached during hypothesise")
                break
            if getattr(ctx, "throttle", False):
                await asyncio.sleep(_THROTTLE_SEC)

            hyp = None
            if code_reasoning and hyp_used < _MAX_HYP:
                hyp_used += 1
                hyp = await self._hypothesize(s, ctx)
                if hyp is None:
                    # Big-Sleep core gate: not attacker-controllable / reachable → drop.
                    continue
            elif not code_reasoning:
                hyp = self._synthesize_hypothesis(s)
                if hyp is None:
                    continue
            else:
                # code_reasoning requested but the LLM budget is spent: fall back to a
                # minimal lead so a ranked sink still surfaces (never silently dropped).
                hyp = self._synthesize_hypothesis(s)
                if hyp is None:
                    continue

            anomaly = self._anomaly_for(s, hyp)
            if anomaly.signature in seen:
                continue
            seen.add(anomaly.signature)
            try:
                await sink(anomaly)
                kept += 1
            except Exception as exc:   # noqa: BLE001
                logger.debug("source engine: sink(anomaly) failed: %s", exc)

        await self._emit_status(ctx, sink, {"stage": "hypothesize", "kept": kept})
        await ctx.emit_event("source_finished", {"source_path": src, "leads": kept})

    # ── step wrappers (each guarded; lazy import so a missing module degrades) ────
    def _scan_source(self, src: str, langs) -> List[Any]:
        try:
            from agents.source_analysis import taint_scan
            res = taint_scan.scan_source(src, langs=langs)
            return list(res) if res else []
        except Exception as exc:   # noqa: BLE001
            logger.debug("source engine: taint_scan unavailable: %s", exc)
            return []

    def _set_reach(self, s: Any, ctx: CampaignCtx) -> None:
        """Build a tiny surface dict for the sink + set reach/controllability on it."""
        try:
            from knowledge import reach_controllability
            mini = {
                "surface_type": "source",
                "endpoint": _attr(s, "file"),
                "language": _attr(s, "language"),
                "input_kind": _attr(s, "exploit_class"),
                # carry through any operator-supplied surface evidence (web params/uploads…)
                **{k: v for k, v in (ctx.surface or {}).items()
                   if k in ("web_paths", "params", "forms", "uploads", "api", "endpoints",
                            "protocols", "reachable", "input_controllable")},
            }
            sig = reach_controllability.controllability_signals(mini, ctx.intel)
            sig = sig if isinstance(sig, dict) else {}
            _setattr(s, "reachable", bool(sig.get("reachable", True)))
            _setattr(s, "input_controllable", bool(sig.get("input_controllable", True)))
            _setattr(s, "controllability", float(sig.get("controllability", 0.0) or 0.0))
        except Exception as exc:   # noqa: BLE001
            logger.debug("source engine: reach_controllability unavailable: %s", exc)

    def _navigate(self, sinks: List[Any], ctx: CampaignCtx) -> List[Any]:
        try:
            from agents.reasoning import code_hypothesis_engine as che
            ranked = che.navigate(sinks, ctx.intel)
            return list(ranked) if ranked else []
        except Exception as exc:   # noqa: BLE001
            logger.debug("source engine: navigate unavailable (using unranked): %s", exc)
            # Degrade to the raw sink list (capped) so the pipeline still produces leads.
            return list(sinks)[:_MAX_HYP]

    async def _expand_variants(self, ranked: List[Any], ctx: CampaignCtx) -> List[Any]:
        try:
            from agents.source_analysis import variant_analysis
            extra = await variant_analysis.expand_variants(ranked, ctx)
            extra = list(extra) if extra else []
            if not extra:
                return ranked
            for s in extra:
                self._set_reach(s, ctx)
            merged = self._dedup(list(ranked) + extra)
            # Re-navigate the expanded set and re-cap.
            return self._navigate(merged, ctx)
        except Exception as exc:   # noqa: BLE001
            logger.debug("source engine: variant expansion failed: %s", exc)
            return ranked

    async def _hypothesize(self, s: Any, ctx: CampaignCtx) -> Optional[Any]:
        try:
            from agents.reasoning import code_hypothesis_engine as che
            return await che.hypothesize(s, ctx)
        except Exception as exc:   # noqa: BLE001
            logger.debug("source engine: hypothesize failed: %s", exc)
            return None

    # ── hypothesis synthesis + anomaly shaping ──────────────────────────────────
    def _synthesize_hypothesis(self, s: Any) -> Optional[Any]:
        """Build a minimal CodeVulnHypothesis straight from a sink (no LLM).  Returns a
        lightweight object exposing ``to_dict`` + the fields the anomaly reads; falls back to
        a plain dict-backed shim if the dataclass can't be imported."""
        rationale = (_attr(s, "message")
                     or f"{_attr(s, 'rule') or 'taint'} sink "
                        f"({_attr(s, 'exploit_class') or 'info'}) at "
                        f"{_attr(s, 'file')}:{_attr(s, 'line')}")
        fields = {
            "file": _attr(s, "file"),
            "line": _int(_attr(s, "line")),
            "function": _attr(s, "function") or _attr(s, "sink"),
            "exploit_class": _attr(s, "exploit_class") or "info",
            "rationale": rationale,
            "attacker_controllable": bool(_attr(s, "input_controllable", True)),
            "reachable": bool(_attr(s, "reachable", True)),
            "suggested_trigger": "",
            "confidence": 0.0,
        }
        try:
            from agents.reasoning.code_hypothesis_engine import CodeVulnHypothesis
            return CodeVulnHypothesis(**{k: v for k, v in fields.items()
                                         if k in CodeVulnHypothesis.__dataclass_fields__})
        except Exception:
            return _DictHypothesis(fields)

    def _anomaly_for(self, s: Any, hyp: Optional[Any]) -> Anomaly:
        file_ = _attr(s, "file")
        line_ = _attr(s, "line")
        func_ = _attr(s, "function") or _attr(s, "sink")
        lang_ = _attr(s, "language")
        exploit_class = (_attr(hyp, "exploit_class") if hyp is not None else "") \
            or _attr(s, "exploit_class") or "info"
        severity = _SEVERITY_MAP.get(str(_attr(s, "severity") or "medium").lower(), "medium")

        rationale = (_attr(hyp, "rationale") if hyp is not None else "") \
            or _attr(s, "message") or ""
        dataflow = _dataflow_str(s)
        evidence = "; ".join(p for p in (
            rationale.strip(),
            f"{file_}:{line_}" if file_ else "",
            ("dataflow: " + dataflow) if dataflow else "",
        ) if p)[:400]

        signature = "src:" + hashlib.sha1(
            f"{file_}:{line_}:{exploit_class}".encode("utf-8", "replace")
        ).hexdigest()[:12]

        return Anomaly(
            type="source_hypothesis",
            exploit_class=str(exploit_class),
            severity_hint=severity,
            evidence=evidence or f"source-audit lead at {file_}:{line_}",
            case_id=f"source-{file_}:{line_}",
            signature=signature,
            detail={
                "file": file_,
                "line": _int(line_),
                "function": func_,
                "language": lang_,
                "rule": _attr(s, "rule"),
                "cwe": _attr(s, "cwe"),
                "dataflow_path": _attr(s, "dataflow_path") or [],
                "hypothesis": _to_dict(hyp) if hyp is not None else None,
            },
        )

    # ── status / budget helpers (mirror the greybox engine) ─────────────────────
    async def _emit_status(self, ctx: CampaignCtx,
                           sink: Callable[[Anomaly], Awaitable[None]],
                           signal: Dict[str, Any]) -> None:
        """Stream a stage-status Observation so the Fuzzing Lab UI updates live."""
        obs = Observation(case_id="source-status", input="",
                          signal={"status": "running", **signal}, raw="")
        try:
            await sink(obs)
        except Exception as exc:   # noqa: BLE001
            logger.debug("source engine: sink(status) failed: %s", exc)

    def _budget_done(self, ctx: CampaignCtx, deadline: float) -> bool:
        return time.time() >= deadline or self._stopped(ctx)

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
    def _dedup(items: List[Any]) -> List[Any]:
        out: List[Any] = []
        seen: set = set()
        for s in items:
            key = (_attr(s, "file"), _int(_attr(s, "line")), _attr(s, "exploit_class"))
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
        return out


class _DictHypothesis:
    """Tiny stand-in when ``CodeVulnHypothesis`` can't be imported, so anomaly emission still
    works.  Exposes the read fields as attributes + a ``to_dict``."""

    __slots__ = ("_d",)

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = dict(d)

    def __getattr__(self, name: str) -> Any:
        return self._d.get(name)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._d)


# ── module-level field accessors (sinks may be dataclasses OR dicts) ────────────
def _attr(obj: Any, name: str, default: Any = "") -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        val = obj.get(name, default)
    else:
        val = getattr(obj, name, default)
    return default if val is None else val


def _setattr(obj: Any, name: str, value: Any) -> None:
    try:
        if isinstance(obj, dict):
            obj[name] = value
        else:
            setattr(obj, name, value)
    except Exception:
        pass


def _to_dict(obj: Any) -> Any:
    if obj is None:
        return None
    fn = getattr(obj, "to_dict", None)
    if callable(fn):
        try:
            return fn()
        except Exception:
            pass
    if isinstance(obj, dict):
        return dict(obj)
    return {k: v for k, v in getattr(obj, "__dict__", {}).items()}


def _int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def _dataflow_str(s: Any) -> str:
    """Render a sink's dataflow path (source → … → sink) as a compact string."""
    src = _attr(s, "source")
    snk = _attr(s, "sink")
    path = _attr(s, "dataflow_path") or []
    parts: List[str] = []
    if src:
        parts.append(str(src))
    if isinstance(path, (list, tuple)):
        for step in path:
            try:
                parts.append(str(step))
            except Exception:
                continue
    if snk:
        parts.append(str(snk))
    return " -> ".join(parts)[:300]
