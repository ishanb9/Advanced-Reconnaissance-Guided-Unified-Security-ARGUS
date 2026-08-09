# Sovereign / OT Zero-Day Pipeline — Slice 1 Design Spec

> **Status:** Approved by operator (2026-06-29). Additive enhancement to the fuzzing workshop.
> **Author:** ARGUS dev session, 2026-06-29.

## Goal

Give ARGUS a genuine *novel-bug / 0-day discovery* capability for the sovereign / air-gapped
/ OT market, built as three additive units that feed the **existing** fuzz proof spine
(`agents/fuzzing/campaign.py` SELECT→…→PROVE, `oracle.py`, `exploit_dev.py`, `proof.py`):

1. **Closed-source greybox fuzzing** — AFL++ QEMU user-mode + an ASan/QASan crash oracle, as a
   new `binary_blackbox` modality engine.
2. **LLM-driven fuzz harness synthesis** — turn a source/headers library into a runnable
   libFuzzer target; the **compiler is the deterministic oracle** (build-or-repair loop).
3. **Triage → exploitability → novelty/dedup gate** — modality-general, opt-in, enrich-only;
   lets ARGUS honestly say "no known public CVE matches this" (never auto-asserts "0-day").

## Hard constraints (non-negotiable)

- **Strictly additive.** New files + one new `_REGISTRY` key + guarded sub-stage calls + additive
  API params + additive UI. A campaign with none of the new flags runs the *current* code path
  byte-for-byte.
- **Default OFF.** Each behavior is a per-campaign opt-in flag; greybox/harness require
  `ctx.authorized=True` and a **local file target** (no network contact).
- **Lab-gated.** `binary_blackbox` is never selectable by the autonomous engine — only via an
  explicit Fuzzing Lab campaign.
- **Air-gapped.** Novelty check is offline (`searchsploit` ExploitDB + `known_cve.json` +
  optional local-NVD feed). Harness toolchain (clang/libFuzzer) is local.
- **Tiered LLM.** Every model call goes through `ctx.llm_generate` (primary→secondary fallback).
- **Harness stays green.** `python -X utf8 agents/test_architecture_integration.py` → `RESULT: PASS`.
  New tests are offline/stubbed (no AFL++/clang required in CI). Existing tests untouched.
- **Novelty policy = conservative / evidence-tiered** (operator decision Q1).
- **Greybox reach = QEMU user-mode first** (Q2). **UI = full Fuzzing Lab** (Q3).

## Module interfaces (exact contracts)

### `agents/fuzzing/crash_triage.py` (new, leaf — stdlib only)
```python
def triage(crash_input: str, target_bin: str, env: dict | None = None, *, timeout: int = 20) -> dict:
    """Re-run ONE crashing input under the sanitized target; parse ASan/QASan output.
    Returns {crash: bool, sanitizer: str, summary: str, stack_hash: str, frames: list[str], input_path: str}.
    Never raises (best-effort: returns crash=False on any error)."""
```
Also imported by `binary_cov.py` to revive its dead ASan oracle (pure addition).

### `agents/fuzzing/engines/binary_greybox.py` (new)
```python
class BinaryGreyboxEngine(FuzzEngine):
    modality = "binary_blackbox"
    def is_available(self) -> tuple[bool, str]:   # needs afl-fuzz AND afl-qemu-trace (shutil.which)
    async def run(self, ctx: CampaignCtx, sink) -> None:
        # afl-fuzz -Q -i <seeds> -o <out> -- <bin> @@   (env AFL_USE_QASAN=1, AFL_NO_UI=1)
        # honours ctx budget/stop/throttle; streams execs/sec + crash count to sink;
        # per crash -> crash_triage.triage(...) -> sink(Anomaly(type="asan",
        #   exploit_class="memory_corruption", severity_hint="high", signature=<stack_hash>, ...))
        # never raises out (log + return)
```

### `agents/fuzzing/harness_synth.py` (new — GENERATE-HARNESS sub-stage)
```python
async def synthesize_harness(ctx: CampaignCtx, *, compile_fn=None, max_iters: int = 4) -> dict | None:
    """Read headers/exported symbols or source from ctx.surface['source_path']/['headers'];
    LLM (ctx.llm_generate) writes an LLVMFuzzerTestOneInput driver; compile-repair loop feeds
    real compiler stderr back until it builds or budget exhausts; smoke-run a few seconds.
    compile_fn(driver_code, out_path) -> (ok: bool, stderr: str)  # injectable for tests; default = clang
    On success: sets ctx.surface['binary'] and returns {ok, target, entry, iters}; else None."""
```

### `knowledge/crash_ledger.py` (new, leaf — on-disk dedup, JSON)
```python
class CrashLedger:
    def __init__(self, path: str | None = None): ...        # default logs/crash_ledger.json
    def seen(self, target: str, stack_hash: str) -> bool: ...
    def record(self, target: str, stack_hash: str, meta: dict | None = None) -> str:  # returns cluster_id
```

### `knowledge/novelty_check.py` (new, leaf — offline)
```python
def assess(component: str, version: str, exploit_class: str, *,
           searchsploit_fn=None, known_cves=None, nvd_dir=None) -> dict:
    """Offline novelty correlation. searchsploit_fn injectable for tests (default shells searchsploit -j).
    Returns {label: 'known-nday'|'no-known-public-match'|'undetermined', evidence: str, matches: list}.
    'no-known-public-match' is a CANDIDATE-NOVEL flag (human-confirm), never an asserted 0-day."""
```

### `agents/fuzzing/triage.py` (new — TRIAGE-PLUS sub-stage, modality-general)
```python
@dataclass
class CrashTriage:
    cluster_id: str = ""; is_duplicate: bool = False
    exploitability: str = "unknown"     # probable|likely|unlikely|unknown
    novelty_label: str = "undetermined"; novelty_evidence: str = ""
    component: str = ""; version: str = ""
    def to_dict(self) -> dict: ...

def triage_crash(anomaly, ctx: CampaignCtx, run_output: str = "", *, ledger=None) -> CrashTriage:
    """Dedup (crash_ledger via anomaly.signature/casr) + exploitability table
    (sanitizer class / exploit_class -> band) + novelty_check.assess(). Pure/deterministic,
    no LLM. Returns CrashTriage; caller merges to_dict() into the finding as optional keys.
    NEVER blocks or drops a finding."""
```

## Campaign wiring (`agents/fuzzing/campaign.py` — guarded, additive)

- **GENERATE-HARNESS** (after SELECT): `if ctx.surface.get("source_path") and ctx.surface.get("synthesize_harness") and not ctx.surface.get("binary"): await harness_synth.synthesize_harness(ctx)`. No-op otherwise.
- **TRIAGE-PLUS** (between TRIAGE and DEVELOP): `if ctx.surface.get("triage"): t = triage.triage_crash(anomaly, ctx, out); finding.update(t.to_dict())`. No-op otherwise; enrich-only.
- GATE/PROVE/RECORD unchanged. `memory_corruption` already forces human approval (`needs_approval`).

## API (`agent_server.py` — additive)

- `/fuzz/campaign/start` accepts `modality="binary_blackbox"` + `surface` flags (`binary_path`,
  `source_path`, `greybox_mode`, `synthesize_harness`, `triage`, `seeds_path`). Existing params unchanged.
- `/fuzz/engines` reports the new engine + tool availability (`afl-fuzz`, `afl-qemu-trace`, `clang`, `casr`).
- `POST /fuzz/lab/upload` (new, lab-gated): stage an uploaded binary/source to a per-session dir; returns its path.

## UI (`static/js/pages/FuzzingLabPage.jsx`, `store.js`, `templates/index.html`)

- New "Binary / 0-day lab" campaign mode → `binary_blackbox`; target path or upload; toggles
  (greybox_mode, synthesize_harness, triage); required "authorized lab target" checkbox → `authorized:true`.
- Live counters (execs/sec, crashes, unique clusters) + a per-finding triage/novelty card.
- Cache-bust `?v=N` bumped.

## Tests (`agents/test_architecture_integration.py` — new, offline)

Registry resolves `binary_blackbox`; `is_available()` clean-false without afl; `crash_triage` parses a
canned ASan fixture; `harness_synth` compile-repair with injected fake compiler (retry-then-succeed +
budget-exhaust→None); `triage_crash` dedup across two calls + exploitability table + `novelty_check`
known-vs-unknown; **regression**: no-flag campaign byte-identical, `triage:true` enriches without dropping.

## Files

New (6): `agents/fuzzing/crash_triage.py`, `agents/fuzzing/engines/binary_greybox.py`,
`agents/fuzzing/harness_synth.py`, `agents/fuzzing/triage.py`, `knowledge/crash_ledger.py`,
`knowledge/novelty_check.py`.
Edited: `agents/fuzzing/engines/__init__.py`, `agents/fuzzing/campaign.py`,
`agents/fuzzing/engines/binary_cov.py`, `agent_server.py`, `static/js/pages/FuzzingLabPage.jsx`,
`static/js/store.js`, `templates/index.html`, `agents/test_architecture_integration.py`.
