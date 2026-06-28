# ARGUS Capability Benchmark (`evals/`)

A deterministic, scored benchmark for ARGUS's offensive capability — so a code
change that quietly makes ARGUS *worse* at finding/exploiting things is caught
before it ships, not in a client engagement.

Modelled on XBOW's reproducible-proof approach: every **exploit** case points
ARGUS at a known-vulnerable target whose proof of compromise is a
**build-time-injected flag token**. ARGUS can only surface that exact token by
actually exploiting the target, so the score is **un-fakeable** — a model cannot
talk its way to a pass. **Detect** cases (e.g. a TLS weakness, where exfiltrating
a flag isn't the right proof) pass on a finding signature: an expected CVE, title
keywords, and a minimum severity.

## Layout

| File | Responsibility |
|------|----------------|
| `catalog.py` | The benchmark cases + per-run flag minting (`mint_run_flag`) |
| `scorer.py`  | **Pure** scoring of one run's output → `CaseResult{exploited, detected, passed, score}` |
| `runner.py`  | Orchestrates a run (`live` \| `replay`) + `compare_to_baseline` regression signal |
| `targets/manifest.json` | Dockerised target definitions for the live runner |
| `fixtures/replay_sample.json` | A recorded transcript for the offline scoring path |
| `baseline.json` | Last-known-good scores; the per-commit regression compares against this |

## Running it

**Offline / CI (no targets needed)** — score a recorded transcript and check for
regression against the committed baseline:

```python
import json
from evals.runner import run_benchmark, load_baseline, compare_to_baseline

transcripts = json.load(open("evals/fixtures/replay_sample.json"))
report = run_benchmark(mode="replay", transcripts=transcripts, nonce="baseline")
delta = compare_to_baseline(report, load_baseline("evals/baseline.json"))
assert not delta["regressed"], f"capability regression: {delta['regressions']}"
print(report.score_pct, "%", "passed", report.passed, "/", report.total)
```

**Live (Kali/CI with Docker)** — stand up each target, inject a fresh per-run
flag, run ARGUS, score the exact token back:

```python
def run_fn(case, run_flag):
    # 1. docker compose up the target in case.target["compose"], passing
    #    ARGUS_EVAL_FLAG=run_flag as a build arg (written into case.target["flag_file"]).
    # 2. run ARGUS against case.target["entrypoint"].
    # 3. return {"findings": [...], "flags_found": [...], "loot": [...]}.
    ...

report = run_benchmark(mode="live", run_fn=run_fn, nonce="<fresh-random>")
```

A case whose live run errors (no Docker, target down) is **skipped**, never a hard
failure — the benchmark is additive and never blocks ARGUS itself.

## Updating the baseline

When a change legitimately improves coverage, regenerate the baseline:

```python
from evals.runner import run_benchmark, save_baseline
save_baseline(run_benchmark(mode="replay", transcripts=..., nonce="baseline"),
              "evals/baseline.json")
```

Review the diff in code review — an *unexpected* drop in `passed`/`score_sum` is
exactly the regression this benchmark exists to surface.
