# ARGUS — Question Engine & Context-Aware Findings Design

**Date:** 2026-04-17  
**Status:** Approved  
**Scope:** Replace fragile LLM-only answer extraction with a 3-layer deterministic + LLM + tool-dispatch pipeline, add dual-mode (CTF vs pentest) operation, and wire mid-session question input through guidance box and MissionControl Ask bar.

---

## Problem Statement

The current `_extract_ctf_answers` pipeline in `reasoning_loop.py` relies entirely on a single LLM call to extract answers from tool output. When the LLM misses an answer that is clearly present in the data (e.g., counting open ports, reading a version string), the finding is never emitted and the objective stays unanswered. Additionally:

- There is no way to ask ad-hoc questions mid-scan via the guidance box or UI
- Real pentest mode (no predefined objectives) gets no automatic discovery findings from tool outputs unless a hypothesis is first validated
- Multi-step puzzle chains (find hash → crack → use cred → read flag) have no dedicated orchestration

---

## Architecture

### New Files

| File | Role |
|------|------|
| `agents/reasoning/deterministic_extractor.py` | Layer 1 — regex/heuristic extraction and discovery |
| `agents/reasoning/question_engine.py` | Orchestrates Layers 1–3 per question; dual-mode aware |

### Modified Files

| File | What changes |
|------|-------------|
| `agents/reasoning/reasoning_loop.py` | `_extract_ctf_answers` and `_extract_answers_from_intel` delegate to `QuestionEngine` |
| `agents/master_agent.py` | `_apply_pending_guidance` detects question intent; routes to `QuestionEngine` |
| `agent_server.py` | New `POST /sessions/{id}/ask` endpoint; question intent detection in guidance handler |
| `static/` (frontend) | MissionControl gets lightweight "Ask" input bar wired to `/ask` endpoint |

---

## Dual-Mode Operation

### Mode 1 — Objective Mode
**Triggers when:** `engagement_type` ∈ `{ctf, forensics, compliance, network_analysis, malware_analysis}`

- Questions are predefined as objectives at session start (existing `ctf_objectives` field)
- 3-layer pipeline runs after every tool execution hunting for answers to unanswered objectives
- State tracked per-objective in `intel["question_states"]`: `PENDING → SEARCHING → ANSWERED`
- Findings titled with question: `[Q1] How many open ports? → Answer: 3`
- Ad-hoc mid-session questions also accepted and processed identically

### Mode 2 — Discovery Mode
**Triggers when:** `engagement_type` ∈ `{pentest, red_team, bug_bounty}` or unset

- No predefined questions required
- **Discovery Pass** runs after every tool execution — surfaces noteworthy facts as findings automatically without waiting for hypothesis validation
- Ad-hoc questions from guidance box or Ask bar trigger the 3-layer pipeline on-demand
- Existing hypothesis-validated findings (`_emit_finding` in reasoning loop) are preserved and untouched

---

## The 3-Layer Pipeline

### Layer 1 — Deterministic Extractor (`deterministic_extractor.py`)

Runs first. No LLM call. Pattern-matched against all gathered intel and raw tool output.

**Question answering patterns:**
- `how many.*port` → count `intel["open_ports"]`
- `what.*version|which.*version` → extract version string from service banners
- `flag{.*}` / `FLAG{.*}` → regex scan of output
- IP address questions → extract from nmap/tool output
- Username / credential questions → scan `intel["credentials"]`
- OS / technology questions → scan `intel["os_guess"]`, `intel["technologies"]`
- File path questions → regex for absolute paths in output

**Discovery patterns (Mode 2 only):**
- Version strings (Apache, nginx, OpenSSH, etc.) → Finding: "Service version identified"
- CVE-pattern strings → Finding: "CVE reference in output"
- Cleartext credentials in output → Finding: "Possible credential exposure"
- Flag patterns → Finding: "Flag pattern detected"
- Interesting paths (`.git`, `/admin`, `/backup`) → Finding: "Sensitive path discovered"

Returns: `ExtractorResult(answer: str | None, evidence: str, confidence: float)`

---

### Layer 2 — LLM Extraction (improved)

Runs only if Layer 1 returns no answer. Key improvements over current `_extract_ctf_answers`:

1. **Answer-type hint injected into prompt** — derived from question keywords (`count`, `version`, `flag`, `ip`, `path`, `name`)
2. **Few-shot examples** — 2–3 examples of the expected answer format included in system prompt
3. **Strict JSON validation** — response is validated against schema before acceptance; malformed responses are retried once with a simpler prompt
4. **Context window management** — output chunked to 4000 chars (down from 8000) with the most relevant section prioritised based on question keywords
5. **Confidence gating** — answers with `confidence < 0.5` are not accepted; Layer 3 is tried instead

---

### Layer 3 — Targeted Tool Dispatch

Runs only if Layers 1 and 2 fail. Picks the minimal tool needed to answer the question:

| Question type | Tool dispatched |
|---------------|----------------|
| Port / service info | `nmap -sV -p- {target}` |
| Web server version | `whatweb {target}` / `curl -I` |
| OS fingerprint | `nmap -O {target}` |
| Directory / path | `gobuster dir` |
| Credential / hash | `hashcat` / `john` |
| File content | `cat` / `strings` via shell |
| Network traffic | `tshark` |
| Flag in web app | `curl` targeted request |

After the tool runs, Layers 1 and 2 are re-run against the fresh output.  
If still unanswered, the question is marked `UNANSWERABLE` and a finding is emitted with status `[Inconclusive]`.

---

## Question State Machine

Stored in `intel["question_states"][question_id]`:

```
PENDING → SEARCHING (Layer 1 running)
        → ANSWERED  (any layer succeeded)
        → UNANSWERABLE (all 3 layers exhausted)
```

State survives pause/resume checkpoints. Already-answered questions are never re-extracted.

---

## Mid-Session Question Input

### Via Guidance Text Box
`_apply_pending_guidance` in `master_agent.py` detects question intent:
- Text ends with `?`
- Text starts with `what`, `how`, `which`, `find`, `where`, `who`, `is there`, `does`

Detected questions are immediately passed to `QuestionEngine.answer_async()` which runs against current intel first (instant response from cached data), then dispatches tools if needed.

### Via MissionControl Ask Bar
- New lightweight input bar at the top of MissionControl: `[Ask ARGUS...] [Send]`
- Calls `POST /sessions/{id}/ask` with `{ "question": "..." }`
- Response streamed back as a `question_answered` WebSocket event
- Answer displayed inline under the Ask bar and also emitted as a Finding

### API Endpoint
```
POST /sessions/{id}/ask
Body: { "question": "what web server is running?", "context": "optional extra context" }
Response: { "answer": "...", "evidence": "...", "layer_used": 1|2|3, "finding_id": "..." }
```

---

## Findings Schema

All answers and discoveries use the existing finding schema with additions:

| Field | CTF / Objective Mode | Discovery Mode |
|-------|---------------------|----------------|
| `title` | `[Q{n}] {question}` | `[Discovery] {fact}` |
| `description` | `Answer: {answer}\nEvidence: {evidence}` | `{description}\nSource: {tool}` |
| `severity` | `high` (answered) / `info` (inconclusive) | Based on finding type |
| `phase` | `exploit` | Phase tool was running in |
| `tag` | `question_answered` / `unanswerable` | `auto_discovery` |

---

## Multi-Step Chain Support

When a question cannot be answered in one step, `QuestionEngine` decomposes it:

1. LLM is asked: *"What prerequisite information is needed to answer: {question}?"*
2. Each prerequisite becomes a sub-question, processed through the same 3-layer pipeline
3. When all prerequisites are answered, the original question is re-attempted
4. Max chain depth: 3 (prevents infinite decomposition)

Example: *"What is the user flag?"*  
→ Sub-question 1: *"Is there a shell on the target?"* → Layer 3 dispatches exploit  
→ Sub-question 2: *"What is the home directory of the current user?"* → Layer 1 from shell output  
→ Original: *"cat /home/{user}/user.txt"* → Layer 3 dispatches shell command

---

## Backward Compatibility

- `use_reasoning_loop: false` (default) — `QuestionEngine` is NOT activated; zero behaviour change
- `use_reasoning_loop: true` — `QuestionEngine` replaces `_extract_ctf_answers` calls only
- Existing `_emit_finding` calls in the reasoning loop are untouched
- All new code wrapped in `try/except` with graceful degradation
- `QuestionEngine` import guarded by `_REASONING_AVAILABLE` flag (same as existing pattern)
