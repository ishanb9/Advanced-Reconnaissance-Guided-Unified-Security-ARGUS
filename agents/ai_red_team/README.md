# agents/ai_red_team — AI / Agentic Security capability module

ARGUS's `target_type="ai"` engagement path: red-team an LLM / agentic target with
a **knowledge-driven probe catalog** and produce OWASP-LLM / MITRE-ATLAS findings
through the normal pipeline → the report themes.

## Shape
- `target_adapter.py` — one `send(messages)` over three target shapes
  (`http_chat` OpenAI/Ollama/generic · `agentic` tool-using/MCP · `single_endpoint`
  raw template). Human picks + configures at target-config time.
- `probe_catalog.py` — loads the catalog as DATA from `knowledge/data/ai_security/*.yaml`
  (one YAML list per OWASP-LLM attack class). **Adding an attack = adding a YAML
  entry, not code.**
- `harness.py` — the single generic runner: multi-attempt + adaptive trials, the
  dual scorer, and safe-by-default gating of `destructive: true` probes.
- `scorer.py` — dual scorer: deterministic detectors **OR** an LLM-judge → ASR.
- `finding_mapper.py` — probe verdict → `store_finding` record (ASR / model /
  OWASP-LLM / ATLAS in `extra`).
- `engine.py` — `AIRedTeamEngine`, invoked from `master_agent.run()` for an AI target.

## Safety & authorization
- **Authorized testing only.** Aggressive / state-changing / jailbreak probes are
  `destructive: true` and gated behind approval (`ARGUS_AI_REDTEAM_AGGRESSIVE=1`
  or the operator approval hook). Non-destructive probes run by default.
- Rate-limited; transcripts redacted in findings; the whole path is behind
  `ARGUS_AI_REDTEAM` (default on) so a non-AI engagement never reaches it.

## Run (conceptual)
Configure an AI target in Target Configuration (adapter + URL/auth/model/template),
start the engagement; ARGUS loads the catalog, runs each probe, scores ASR, and
records findings. The probe catalog lives in `knowledge/data/ai_security/`.
