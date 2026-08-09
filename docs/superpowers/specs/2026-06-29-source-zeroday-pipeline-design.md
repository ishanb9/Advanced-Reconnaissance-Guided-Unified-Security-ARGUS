# Source-Available Zero-Day Pipeline — Slice 2 Design Spec

> **Status:** Approved by operator (2026-06-29). Additive enhancement; extends Slice 1.
> **Author:** ARGUS dev session, 2026-06-29.

## Goal

Extend ARGUS's novel-bug discovery to **source-available targets** (a checked-out repo,
decompiled source, an OSS dependency) — mirroring Slice 1 but reasoning over *code* instead
of a black-box binary. Three additive units feeding the EXISTING spine, exposed as a new
`source` fuzz modality:

1. **Source taint / variant analysis** (`agents/source_analysis/`) — run semgrep/bandit/graudit
   (all already provisioned, offline) → normalized `CandidateSink`s; an LLM "find more instances
   of this bug class" variant pass expands them.
2. **Big-Sleep / Naptime code-reasoning loop** (`agents/reasoning/code_hypothesis_engine.py`) —
   NAVIGATE (rank sinks; down-weight heavily-fuzzed OSS via `fuzz_targeting.novelty_score`) →
   HYPOTHESISE (`think_json` → `CodeVulnHypothesis`, dropped unless `attacker_controllable` AND
   `reachable`) → TRIGGER+VERIFY.
3. **Reachability / input-controllability** (`knowledge/reach_controllability.py`) — populate the
   already-wired (but defaulted-True) `fuzz_targeting.score_surface` gate from recon evidence.

**Prove path (operator decision):** a memory-safety hypothesis in C/C++ is PROVEN by reusing
Slice 1 — `harness_synth` (targeting the hypothesized function) → greybox → ASan proof oracle →
`DEMONSTRATED`. Everything else (other languages, injection classes) is a ranked **OBSERVED
lead** (taint path + hypothesis as evidence). `exploit_dev` is *not* used here, so it stays
genuinely untouched.

## Hard constraints

- **Strictly additive.** New modules + one new `_REGISTRY` key (`source`) + a guarded DEVELOP
  branch + opt-in surface flags, default OFF. A campaign with none of the new flags is
  byte-identical.
- **Lab-gated + source-tree-only.** `source` modality requires `ctx.authorized=True` and an
  operator-supplied `source_path`; never auto-run by the autonomous engine against a live target.
- **Air-gap safe.** semgrep/bandit/graudit are local; clang/AFL local. No network.
- **Tiered LLM.** Every model call via `ctx.llm_generate` / injected `think_json_fn`.
- **Conservative novelty.** Only a proof-oracle-PROVEN trigger is a `DEMONSTRATED` finding
  (`reproduce_status='reproduced'`); everything else is an `OBSERVED` lead. Memory-corruption
  rides the EXISTING human-approval GATE.
- **Harness green.** `python -X utf8 agents/test_architecture_integration.py` → `RESULT: PASS`;
  new tests offline/stubbed (no semgrep/clang needed in CI). Existing tests untouched.

## Module interfaces (exact contracts)

### `knowledge/reach_controllability.py` (new, leaf)
```python
def controllability_signals(surface: dict, intel: dict | None = None) -> dict:
    """Derive reachability + input-controllability from recon evidence ARGUS already has
    (NO live traffic). Returns {input_controllable: bool, reachable: bool,
    controllability: float, sink_proximity: float, evidence: list[str]}.
    Conservative: input_controllable=True only with a concrete attacker-drivable input
    (web param/form/upload/api-body, or a protocol handler). Never raises."""
```

### `agents/source_analysis/taint_scan.py` (new)
```python
@dataclass
class CandidateSink:
    file: str; line: int; rule: str = ""; cwe: str = ""; severity: str = "medium"
    language: str = ""; exploit_class: str = "info"; source: str = ""; sink: str = ""
    dataflow_path: list = field(default_factory=list); message: str = ""
    def to_dict(self) -> dict: ...

def scan_source(source_path: str, *, langs=None, semgrep_fn=None, bandit_fn=None,
                graudit_fn=None, timeout: int = 300) -> list[CandidateSink]:
    """Run semgrep (taint) + bandit (py) + graudit over a source tree; normalize to
    CandidateSink. Each tool shutil.which-guarded + injectable for tests. Offline. Never raises."""
```

### `agents/source_analysis/variant_analysis.py` (new)
```python
async def expand_variants(sinks: list, ctx, *, top_n: int = 5, grep_fn=None) -> list:
    """LLM 'find more instances of this bug class' over the source tree via ctx.llm_generate
    (tiered). Returns additional deduped CandidateSinks. Best-effort; [] on any failure."""
```

### `agents/reasoning/code_hypothesis_engine.py` (new)
```python
@dataclass
class CodeVulnHypothesis:
    file: str; line: int; function: str = ""; exploit_class: str = "memory_corruption"
    rationale: str = ""; attacker_controllable: bool = False; reachable: bool = False
    suggested_trigger: str = ""; confidence: float = 0.0
    def to_dict(self) -> dict: ...

def navigate(sinks: list, intel: dict | None = None, *, top_n: int = 8) -> list:
    """Rank sinks: fuzz_targeting.novelty_score (down-weight heavily-fuzzed OSS) × severity ×
    reach_controllability. Return top-N to reason about."""

async def hypothesize(sink, ctx, *, think_json_fn=None) -> "Optional[CodeVulnHypothesis]":
    """Read the code slice around the sink; emit a structured CodeVulnHypothesis via think_json
    (tiered). Return None when attacker_controllable/reachable is false (Big-Sleep's core gate)."""

async def prove_source_hypothesis(anomaly, ctx) -> "Optional[PoC]":
    """For a memory-safety source hypothesis (C/C++): harness_synth (entry = the function) →
    short greybox run → proof oracle. Returns a PoC(proven=True) on an ASan-confirmed crash,
    a PoC(proven=False) when it built but didn't crash, or None when it couldn't build
    (→ OBSERVED lead). Reuses Slice 1 entirely; exploit_dev is NOT called. Never raises."""
```

### `agents/fuzzing/engines/source_engine.py` (new)
```python
class SourceEngine(FuzzEngine):
    modality = "source"
    def is_available(self) -> tuple[bool, str]:   # needs semgrep OR bandit OR graudit
    async def run(self, ctx, sink) -> None:
        # taint_scan(source_path) → set reach/controllability on each → navigate(rank) →
        # (variant_analysis.expand if surface['variant_analysis']) → hypothesize per top sink
        # → emit Anomaly(type="source_hypothesis", exploit_class=<class>, severity_hint=...,
        #   evidence=<rationale + taint path>, detail={file,line,function,language}) via sink.
        # honours ctx budget/stop/throttle; never raises out.
```

## Campaign wiring (`agents/fuzzing/campaign.py` — one guarded branch)

In `_develop_and_prove`, BEFORE the `exploit_dev.develop` call, add:
```python
if anomaly.type == "source_hypothesis":
    from agents.reasoning import code_hypothesis_engine as _che
    poc = await _che.prove_source_hypothesis(anomaly, self.ctx)   # harness_synth→greybox→proof
    # then fall through to the EXISTING gate + record path with this poc
```
No-op for every other anomaly type (existing flow untouched). The `memory_corruption` GATE and
the `_record` honesty (proven→high/DEMONSTRATED, else OBSERVED) are reused unchanged. TRIAGE-PLUS
(Slice 1) still attaches dedup/exploitability/novelty when `surface['triage']`.

## reach_controllability hook (`knowledge/fuzz_targeting.py` — guarded, default-preserving)

Where a surface is built/scored, call `reach_controllability.controllability_signals(surface,
intel)` and set `surface['reachable']`/`['input_controllable']` ONLY when concrete evidence
exists; otherwise leave the current `True` defaults → existing scores byte-identical.

## API (`agent_server.py` — additive)

Add `source` to the `/fuzz/engines` meta (label "Source / code audit"; tools semgrep, bandit,
graudit, clang). `/fuzz/campaign/start` already passes modality+surface+authorized generically;
`/fuzz/lab/upload` already stages an uploaded source archive. No other server change.

## UI (`FuzzingLabPage.jsx`, `templates/index.html`)

New "Source / code audit" campaign mode (`source`): source path / upload; optional language
hints; toggles (`variant_analysis`, `code_reasoning`); the required "authorized lab target"
checkbox (reused from Slice 1). Render each hypothesis/lead with its taint path + the Slice-1
triage/novelty card. Cache-bust `?v=7`.

## Tests (`agents/test_architecture_integration.py` — new, offline)

`test_source_zeroday_pipeline`: `source` modality resolves + clean-degrades without semgrep;
`scan_source` normalizes an injected semgrep-JSON fixture into CandidateSinks; `navigate` ranks
+ caps; `hypothesize` drops a not-attacker-controllable hypothesis (stub think_json) and keeps a
controllable one; `reach_controllability` returns input_controllable=False for a bare static
path and True for a param-bearing surface; `prove_source_hypothesis` returns an OBSERVED lead
(None/unproven) when harness can't build (injected); **regression**: a campaign without
`source` modality / flags is byte-identical, and a `source_hypothesis` anomaly never calls
`exploit_dev`.

## Files

New (6): `agents/source_analysis/__init__.py`, `agents/source_analysis/taint_scan.py`,
`agents/source_analysis/variant_analysis.py`, `agents/reasoning/code_hypothesis_engine.py`,
`agents/fuzzing/engines/source_engine.py`, `knowledge/reach_controllability.py`.
Edited: `agents/fuzzing/engines/__init__.py`, `agents/fuzzing/campaign.py`,
`knowledge/fuzz_targeting.py`, `agent_server.py`, `static/js/pages/FuzzingLabPage.jsx`,
`templates/index.html`, `agents/test_architecture_integration.py`.
