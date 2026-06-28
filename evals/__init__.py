"""evals/ — ARGUS capability benchmark (Gap #6).

A deterministic, scored benchmark for ARGUS's offensive capability, modelled on
XBOW's reproducible-proof approach: each case points ARGUS at a KNOWN-vulnerable
target whose proof of compromise is a build-time-INJECTED flag token.  ARGUS can
only surface that token by actually exploiting the target, so the score is
un-fakeable.  Softer "detect" cases pass on a finding signature (CVE / title /
severity) where an exploit flag is not the right proof.

Layers (all additive — nothing in ARGUS depends on this package):
  • catalog  — the benchmark case definitions + per-run flag minting
  • scorer   — PURE, deterministic scoring of one run's output
  • runner   — orchestrates a run (live | replay) + per-commit regression vs baseline

The catalog/scorer/runner are import-light and unit-testable with no live target;
the live runner stands up the Dockerised targets and needs Docker on Kali/CI.
"""
from evals.catalog import (
    BenchmarkCase,
    CATALOG,
    case_by_id,
    load_catalog,
    mint_run_flag,
)
from evals.scorer import CaseResult, score_case
from evals.runner import (
    BenchmarkReport,
    compare_to_baseline,
    load_baseline,
    run_benchmark,
    save_baseline,
)

__all__ = [
    "BenchmarkCase", "CATALOG", "case_by_id", "load_catalog", "mint_run_flag",
    "CaseResult", "score_case",
    "BenchmarkReport", "run_benchmark", "compare_to_baseline",
    "load_baseline", "save_baseline",
]
