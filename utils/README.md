# ARGUS Utilities

Cross-cutting helpers used throughout the platform. Each module is
intentionally small + single-purpose so it can be imported without
pulling in heavy dependencies.

| File | Purpose | Used by |
|------|---------|---------|
| `cvss_scorer.py` | Estimates CVSS 3.1 base scores from a Finding's metadata (CWE, exploitability, scope). Also computes chain-level risk. | `agents/*`, attack-graph builder |
| `json_tolerant.py` | Forgiving JSON parser for LLM responses (trailing commas, unquoted keys, code-fence wrappers, single quotes). | `agents/master_agent.py`, every LLM-talking module |
| `llm_providers.py` | Pluggable LLM backend abstraction. One interface for Ollama, OpenAI-compatible APIs (vLLM, LM Studio, LocalAI), Anthropic, OpenAI. | `agents/master_agent.py`, reasoning subagents |
| `opsec_profiles.py` | Three opsec profiles (`loud` / `stealth` / `silent`) that throttle tools, jitter timing, rotate UAs, and skip telemetry-emitting tools. | Every tool-running subagent |
| `replay_mode.py` | Re-streams a finished session's WebSocket events for demos + debugging. Reads the audit-log scan bundle and replays it at configurable speed. | Demo mode + `pytest` fixtures |
| `scan_logger.py` | Per-session forensic-grade bundle writer. Appends every tool invocation + raw output to `logs/<ts>_<session_id>/`. | `agents/base_agent.py:collect_tool()` |
| `target_normalizer.py` | One-stop target classification — turns operator-supplied strings into `(kind, normalized_value, scope_hints)`. Handles IPs, CIDRs, hostnames, URLs, IPv6, ports-with-host, ASNs. | Engagement-start handler |

---

## Conventions

- Every module is importable with **no side effects** at import time.
- No module here calls the LLM directly — that's `agents/master_agent.py`'s
  job. `llm_providers.py` only defines the abstraction.
- Standard library + the deps listed in the root `requirements.txt`
  only. No additional pip-installs.

---

## Examples

### CVSS scoring

```python
from utils.cvss_scorer import score
from schemas import Finding

f = Finding(
    title="SQL injection on /search",
    cwe="CWE-89",
    exploit_available=True,
    authenticated=False,
    network_accessible=True,
)
cvss = score(f)
# CvssScore(base=9.8, severity="CRITICAL", vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

### Pluggable LLM backend

```python
from utils.llm_providers import get_provider

llm = get_provider()           # auto-detects from env
reply = await llm.chat([
    {"role": "system", "content": "You are a senior pentester."},
    {"role": "user",   "content": "Suggest next steps."},
])
```

Backend selected by env vars:

| Env | Effect |
|-----|--------|
| `LLM_PROVIDER=ollama` (default) | Talks to `OLLAMA_HOST` (default `http://localhost:11434`) |
| `LLM_PROVIDER=openai_compatible` | Talks to `LLM_BASE_URL` with `LLM_API_KEY` (vLLM, LM Studio, LocalAI) |
| `LLM_PROVIDER=anthropic` | Anthropic Messages API |
| `LLM_PROVIDER=openai` | OpenAI ChatCompletions |

### Opsec profile

```python
from utils.opsec_profiles import OpsecProfile, current_profile

if current_profile() == OpsecProfile.SILENT:
    return     # skip this loud subagent

# Throttle a tool to the active profile's rate
from utils.opsec_profiles import rate_limited
await rate_limited("masscan", coro)
```

### Tolerant JSON parsing

```python
from utils.json_tolerant import loads_tolerant

raw = """
```json
{ next_steps: [
    "enumerate AD", "kerberoast",   // unquoted, trailing comma
]}
```
"""
parsed = loads_tolerant(raw)
# {"next_steps": ["enumerate AD", "kerberoast"]}
```

### Target normalization

```python
from utils.target_normalizer import normalize

normalize("https://target.example.com:8443/api")
# Target(kind="url", host="target.example.com", port=8443, path="/api", scheme="https")

normalize("192.168.0.0/24")
# Target(kind="cidr", cidr="192.168.0.0/24", host_count=254)

normalize("AS15169")
# Target(kind="asn", asn=15169)
```

---

## Further reading

- [`../README.md`](../README.md) — project front page
- [`../agents/README.md`](../agents/README.md) — how `collect_tool()` integrates `scan_logger` + `opsec_profiles`
- [`../auth/security/passwords.py`](../auth/security/passwords.py) — uses similar utility-style abstractions for crypto
