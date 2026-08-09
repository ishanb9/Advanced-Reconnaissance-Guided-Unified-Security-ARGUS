# Gap #6 — Capability Benchmark (`evals/`) Design

**Date:** 2026-06-22
**Status:** Implemented
**Gap:** #6 of the competitive-audit correctness program — "no deterministic, scored
benchmark proving ARGUS's offensive capability or catching capability regressions."

## Problem

ARGUS had no way to answer "did this commit make ARGUS *worse* at finding/exploiting
things?" A subtle change (a prompt tweak, a tool-dispatch reorder, a severity-gate
edit) could quietly degrade real capability and only surface in a client engagement.
Competitors (XBOW) run their agent against a fixed set of containerised targets with
**build-time-injected flags** and score reproducibly per commit.

## Approach

A new, fully **additive** `evals/` package — nothing in ARGUS imports it, so it can
never break an engagement. Two proof modes:

- **exploit** — the case proves compromise only when ARGUS surfaces a unique,
  **build-time-injected flag token**. The token is minted per-run (`catalog flag +
  nonce`) and written into the live target at build; ARGUS can obtain it *only* by
  actually exploiting the target. This makes the score **un-fakeable** — a model
  cannot reason or hallucinate its way to a pass, and cannot pass by memorising a
  static catalog flag (the nonce differs each run).
- **detect** — where exfiltrating a flag isn't the right proof (e.g. a TLS
  weakness), the case passes on a **finding signature**: expected CVE(s), required
  title keyword(s), and a minimum severity.

## Components (one responsibility each)

| File | Responsibility |
|------|----------------|
| `evals/catalog.py` | `BenchmarkCase` + the `CATALOG` + `load_catalog`/`case_by_id` + `mint_run_flag` (nonce binding) |
| `evals/scorer.py` | **Pure** `score_case` → `CaseResult{exploited, detected, passed, score}`. Reads the flag from `flags_found` / `loot` / `flags[].value` / finding evidence+title |
| `evals/runner.py` | `run_benchmark(mode=replay\|live)` + `compare_to_baseline` (regression = was-passing-now-failing) + `load`/`save_baseline` |
| `evals/targets/manifest.json` | Dockerised target definitions for the live runner |
| `evals/fixtures/replay_sample.json` | Recorded transcript for the offline scoring path |
| `evals/baseline.json` | Last-known-good scores; the per-commit regression compares against this |

## Data flow

1. `run_benchmark` iterates cases; for each it mints `run_flag = mint_run_flag(case, nonce)`.
2. **replay** mode reads a recorded `run_output` from `transcripts[case.id]`; **live**
   mode calls `run_fn(case, run_flag)` which stands the target up (injecting `run_flag`),
   runs ARGUS, and returns `{findings, flags_found, loot, flags}`.
3. `score_case` decides `exploited`/`detected`/`passed`/`score`.
4. `compare_to_baseline` turns the report into a CI regression signal (`regressed`).

## Error handling / safety

- A live target that errors (no Docker, target down) is **skipped**, never a hard
  failure. Skips are counted and visible; they are never treated as passes.
- `score_pct` is averaged over **scored** cases only (skips don't dilute capability),
  with a divide-by-zero guard.
- Scoring is deterministic — no clock/RNG — so the same inputs always score identically.

## Testing

`test_eval_benchmark` in the always-run harness asserts: catalog load+filter; the
**un-fakeable** property (an exploit case cannot pass on a finding alone); flag
recovery from each output field; detect-mode pass/fail; replay counts (3 passed / 2
skipped); no-regression vs the committed baseline; regression detection when a proof
is dropped; and best-effort live skip on a raising `run_fn`. The deep live runs
(Docker targets) execute on Kali/CI.

## Out of scope (YAGNI)

Standing up the actual Docker target images, a CI workflow file, and a public
leaderboard. The manifest documents the target contract; building the images is a
follow-on once the scoring spine is proven.
