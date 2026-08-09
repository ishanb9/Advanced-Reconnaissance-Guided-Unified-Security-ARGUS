"""evals/runner.py — orchestrate a benchmark run + per-commit regression (Gap #6).

Two modes:
  • replay — score pre-recorded ARGUS outputs (offline; CI-friendly; deterministic)
  • live   — call a ``run_fn(case, run_flag)`` that stands up the target, runs ARGUS
             against it, and returns its output.  Best-effort: a case whose live run
             errors (no Docker, target down) is SKIPPED, never a hard failure.

``compare_to_baseline`` turns the run into a per-commit regression signal: any case
that was passing in the baseline and now fails is a regression.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from evals.catalog import BenchmarkCase, load_catalog, mint_run_flag
from evals.scorer import CaseResult, score_case

logger = logging.getLogger("argus.evals")

_SKIPPED = "no run output (skipped)"


@dataclass
class BenchmarkReport:
    mode: str
    total: int
    passed: int
    skipped: int
    score_sum: float
    score_pct: float
    # [109] % of catalog cases that were actually SCORED (not skipped).  score_pct is
    # averaged over scored cases only, so without this a run that silently skips 2/5
    # capability classes still reports score_pct=100 — masking the coverage gap.
    coverage_pct: float = 100.0
    cases: List[Dict[str, Any]] = field(default_factory=list)
    run_at: Optional[str] = None       # caller-supplied timestamp (kept out of logic)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def run_benchmark(cases: Optional[List[BenchmarkCase]] = None, *,
                  mode: str = "replay",
                  run_fn: Optional[Callable[[BenchmarkCase, str], Dict[str, Any]]] = None,
                  transcripts: Optional[Dict[str, Dict[str, Any]]] = None,
                  nonce: str = "static",
                  run_at: Optional[str] = None) -> BenchmarkReport:
    """Run the benchmark and return a scored report.  ``score_pct`` is averaged over
    the cases that actually produced output (skips do not dilute the capability
    score, but they ARE counted in ``skipped`` so silent gaps are visible)."""
    cases = cases if cases is not None else load_catalog()
    results: List[CaseResult] = []
    skipped = 0

    for case in cases:
        run_flag = mint_run_flag(case, nonce)
        out: Optional[Dict[str, Any]] = None
        if mode == "replay":
            out = (transcripts or {}).get(case.id)
        elif mode == "live" and run_fn is not None:
            try:
                out = run_fn(case, run_flag)
            except Exception as exc:        # best-effort: a broken target never fails the run
                logger.warning("eval live run failed for %s: %s", case.id, exc)
                out = None

        if out is None:
            skipped += 1
            results.append(CaseResult(case_id=case.id, pass_mode=case.pass_mode,
                                      exploited=False, detected=False, passed=False,
                                      score=0.0, reasons=[_SKIPPED]))
            continue
        results.append(score_case(case, out, run_flag=run_flag or None))

    scored = [r for r in results if _SKIPPED not in r.reasons]
    score_sum = sum(r.score for r in results)
    denom = len(scored) or 1
    return BenchmarkReport(
        mode=mode,
        total=len(results),
        passed=sum(1 for r in results if r.passed),
        skipped=skipped,
        score_sum=round(score_sum, 3),
        score_pct=round(100.0 * score_sum / denom, 1),
        coverage_pct=round(100.0 * len(scored) / (len(results) or 1), 1),
        cases=[r.to_dict() for r in results],
        run_at=run_at,
    )


def load_baseline(path: str) -> Dict[str, Any]:
    """Load a saved baseline report, or {} if none exists yet (first run)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_baseline(report: BenchmarkReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, sort_keys=True)


def compare_to_baseline(report: BenchmarkReport, baseline: Dict[str, Any]) -> Dict[str, Any]:
    """Per-commit regression signal.  A regression = a case that PASSED in the
    baseline and now fails.  An improvement = a newly-passing case.  ``regressed``
    is the boolean a CI gate should fail on."""
    base_cases = {c.get("case_id"): c for c in (baseline.get("cases") or [])}
    regressions: List[str] = []
    improvements: List[str] = []
    for c in report.cases:
        cid = c.get("case_id")
        was_pass = bool(base_cases.get(cid, {}).get("passed"))
        now_pass = bool(c.get("passed"))
        if was_pass and not now_pass:
            regressions.append(cid)
        elif now_pass and not was_pass:
            improvements.append(cid)
    return {
        "regressions": regressions,
        "improvements": improvements,
        "regressed": bool(regressions),
        "score_delta": round(report.score_sum - float(baseline.get("score_sum") or 0.0), 3),
    }
