# Depth-Multiplier Fuzzing — Slice 3 Design Spec

> **Status:** Approved by operator (2026-06-29, "finish slice 3 entirely"). Additive; extends Slices 1–2.
> **Author:** ARGUS dev session, 2026-06-29.

## Goal

Three depth multipliers that find bugs blind mutation + single-target oracles miss — all
additive, default-OFF, lab-gated where they touch a target, feeding the existing proof spine:

1. **Grammar-aware fuzzing** — `knowledge/grammar_infer.py`: an LLM infers an input model
   (grammar) from a few observed samples; a deterministic structure-aware mutator generates
   valid-but-novel inputs that reach deep parser/protocol states. Wired as an **opt-in payload
   enricher** in the existing GENERATE stage (reuses every transport engine — no new transport).
2. **Differential testing** — `agents/fuzzing/diff_oracle.py` + a new `differential` engine:
   send the same input to the target AND a reference implementation; flag silent logic/parsing
   divergences (request smuggling, cert-validation bypass, SQL-semantic, parser confusion) that
   never crash or reflect a marker.
3. **Deep-continuous lab mode** — `agents/fuzzing/corpus_store.py` + guarded campaign params:
   a LAB-ONLY long-running campaign with a persistent corpus, OFF by default, never applied to a
   live engagement.

## Hard constraints

- **Strictly additive / default-OFF.** New modules + one new `_REGISTRY` key (`differential`) +
  guarded GENERATE/campaign hooks + opt-in env/surface flags. No-flag campaigns are byte-identical.
- **Lab-gated.** `differential` and `deep` require `ctx.authorized=True`; deep mode is never
  selected by the autonomous engine and never runs against a live engagement (refuses unless
  `authorized` and not throttled-by-a-live-scan).
- **Air-gap safe.** Grammar inference + mutation are local (LLM via `ctx.llm_generate`, tiered).
  Differential needs an operator-supplied reference endpoint (local lab).
- **Deterministic.** The mutator takes an explicit `rng_seed` (no `Math.random`/clock) so a
  finding reproduces.
- **Harness green.** `python -X utf8 agents/test_architecture_integration.py` → `RESULT: PASS`;
  new tests offline (no live targets). Existing tests untouched.

## Module interfaces (exact contracts)

### `knowledge/grammar_infer.py` (new)
```python
@dataclass
class GrammarModel:
    fields: list          # ordered: {name, type: magic|length|enum|int|str|bytes, value?, options?, len_of?}
    kind: str = "generic" # http|proto|file|generic
    notes: str = ""
    def to_dict(self) -> dict: ...

async def infer_grammar(samples: list, *, llm_generate, hint: str = "") -> "Optional[GrammarModel]":
    """Feed 3-10 observed samples (bytes/str) to the LLM (tiered) → a JSON input model.
    Returns GrammarModel or None (no llm / parse fail). Never raises."""

def mutate(model: "GrammarModel", *, n: int = 32, rng_seed: int = 0) -> list:
    """Generate n valid-but-novel inputs from the model — honour magic/length/enum fields,
    fuzz the free fields. DETERMINISTIC given rng_seed (seeded random.Random; no clock).
    Returns list[bytes]. Never raises (returns [] on bad model)."""
```

### `agents/fuzzing/diff_oracle.py` (new)
```python
class DifferentialOracle:
    def __init__(self, reference: str): ...
    def classify(self, modality: str, primary_obs, reference_obs) -> "Optional[Anomaly]":
        """Flag a type='differential_divergence' anomaly (exploit_class='logic_divergence', or
        family-specific request_smuggling/cert_bypass/sql_semantic) when normalised primary vs
        reference outputs differ (status/body/headers/length, normalised). Never raises."""
```

### `agents/fuzzing/engines/diff_engine.py` (new)
```python
class DiffEngine(FuzzEngine):
    modality = "differential"
    def is_available(self) -> tuple[bool, str]:   # ok only if ctx will carry a reference (checked in run)
    async def run(self, ctx, sink) -> None:
        # require ctx.authorized + ctx.surface['reference']; for each payload send to BOTH target
        # and reference (reuse the http client), build primary/reference Observations, run
        # DifferentialOracle.classify → emit divergence Anomalies. honour budget/stop; never raise.
```

### `agents/fuzzing/corpus_store.py` (new)
```python
class CorpusStore:
    def __init__(self, key: str, base: str | None = None): ...   # default logs/fuzz_corpus/<key>/
    def load(self) -> list[bytes]: ...                            # seeds from prior deep runs
    def add(self, inputs: list) -> int: ...                       # persist interesting inputs (dedup by hash)
```

## Wiring (all guarded, additive)

- **`agents/fuzzing/payloadgen.py`** — after the normal payloads are built, if
  `ctx.surface.get("grammar")` and samples are available, append structure-aware payloads from
  `grammar_infer.infer_grammar(...).mutate(...)`. No-op unless flagged.
- **`agents/fuzzing/engines/__init__.py`** — register `"differential": ...DiffEngine`.
- **`agents/fuzzing/campaign.py`** — deep-continuous mode: if `ctx.surface.get("deep")` AND
  `ctx.authorized` AND not `ctx.throttle`, seed the engine from `CorpusStore.load()` and persist
  interesting inputs at the end via `CorpusStore.add()`, and allow a longer `max_sec` ceiling
  (`ARGUS_FUZZ_DEEP_MAX_SEC`). Guarded — default path unchanged.
- **`agent_server.py`** — `differential` entry in `/fuzz/engines`; pass `grammar`/`deep`/
  `reference` surface flags through (already generic).
- **UI** (`FuzzingLabPage.jsx`, `templates/index.html`) — a "grammar-aware" toggle, a
  "Differential" mode with a reference-endpoint field, and a "Deep continuous (lab)" toggle
  gated behind the authorized checkbox. Cache-bust `?v=8`.

## Tests (`agents/test_architecture_integration.py` — new, offline)

`test_depth_fuzzing`: `differential` modality resolves; `grammar_infer.mutate` is deterministic
for a fixed seed + honours magic/length fields (stub model, no LLM); `infer_grammar` returns a
GrammarModel from a stubbed `llm_generate` and None when llm is None; `DifferentialOracle.classify`
flags a divergence on differing obs and returns None on identical obs; `CorpusStore` round-trips +
dedups; **regression**: a no-flag campaign is byte-identical and `payloadgen` adds no grammar
payloads without the flag.

## Files

New (4): `knowledge/grammar_infer.py`, `agents/fuzzing/diff_oracle.py`,
`agents/fuzzing/engines/diff_engine.py`, `agents/fuzzing/corpus_store.py`.
Edited: `agents/fuzzing/engines/__init__.py`, `agents/fuzzing/payloadgen.py`,
`agents/fuzzing/campaign.py`, `agent_server.py`, `static/js/pages/FuzzingLabPage.jsx`,
`templates/index.html`, `agents/test_architecture_integration.py`.
