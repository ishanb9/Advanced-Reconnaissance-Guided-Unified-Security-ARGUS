# ARGUS Meta-Agents Design
**Date:** 2026-04-21  
**Status:** Approved  
**Scope:** MasterCheckerAgent + IssueValidatorAgent + frontend live visibility

---

## 1. Overview

Two new *meta-agents* are added to ARGUS: **MasterCheckerAgent** (audits the master's plan and execution) and **IssueValidatorAgent** (validates tool outputs and findings accuracy). Both have their own persistent LLM conversation thread for the full duration of a scan, reason independently, and feed structured corrections back to the master. The master applies corrections in a tiered manner — blocking (high confidence) or advisory (low confidence).

These agents are peers to MasterAgent, not standard subagents. They extend a new thin `BaseMetaAgent` base class and have no tool-execution capability.

---

## 2. New Base Class — `BaseMetaAgent`

**File:** `agents/meta/base_meta_agent.py`

Extends `BaseAgent` (inherits `think()`, `think_json()`, `check_llm_available()`). Adds:

### 2.1 Persistent Conversation Thread
- `_history: List[Dict[str, str]]` — full `[{role, content}, ...]` message list
- Bounded by `MAX_HISTORY_TURNS` (default 50, overridable via `ARGUS_META_MAX_HISTORY` env var)
- Sliding window: oldest turns drop when limit is reached
- `clear_history()` — resets thread for scan restart

### 2.2 LLM Invocation
- `async think_with_history(prompt: str) -> str`
  - Appends `{role: "user", content: prompt}` to `_history`
  - Calls Ollama with full history as messages array
  - Appends `{role: "assistant", content: response}` to `_history`
  - Emits `meta_agent_thinking` WS event with each streamed chunk
  - Returns full response string

### 2.3 Correction Output
- `emit_correction(correction: Correction)` — persists to MongoDB `meta_corrections` collection and emits `meta_correction` WS event
- Returns corrections directly from `evaluate()` as well (both paths available)

### 2.4 Extension Hooks (abstract)
- `_build_system_prompt() -> str` — each subclass defines its persona and instructions
- `async evaluate(**kwargs) -> List[Correction]` — primary entry point for each subclass

### 2.5 Lifecycle
- `_enabled: bool` — flag to disable agent entirely (fast/debug scan modes)
- `reset()` — clears history and resets stats; called on scan restart
- No tool-execution methods; `run_tool`/`collect_tool` calls will raise `NotImplementedError`

---

## 3. Correction Dataclass

**File:** `agents/meta/correction.py`

```
Correction:
  source: str                    # "master_checker" | "issue_validator"
  scan_id: str
  phase: str
  confidence: float              # 0.0–1.0
  tier: str                      # "blocking" | "advisory" — derived at creation
  issue_type: str                # see Issue Types below
  description: str               # human-readable explanation
  recommended_action: str        # directly injectable into LLM planning prompt
  affected_finding_ids: List[str]
  metadata: Dict[str, Any]       # extensible — tool name, raw snippet, etc.
  timestamp: float
```

**Issue Types (extensible enum):**
`plan_deviation`, `missed_attack_surface`, `skipped_tool`, `false_positive`, `wrong_severity`, `missing_cve_ref`, `missing_mitre_ref`, `duplicate_finding`, `objective_not_covered`, `tool_failure_unhandled`, `phase_goal_unmet`

**Tier derivation:**
`BLOCKING_THRESHOLD = 0.8` (overridable via `ARGUS_META_BLOCKING_THRESHOLD` env var).  
`confidence >= threshold → tier = "blocking"`, else `tier = "advisory"`.

---

## 4. MasterCheckerAgent

**File:** `agents/meta/master_checker_agent.py`  
**Extends:** `BaseMetaAgent`

**Persona (system prompt):** Senior red team lead reviewing a junior operator's plan and execution. Critical, not a rubber-stamp. Knows ARGUS phase model, offensive tooling, and common pentesting gaps.

### 4.1 Entry Points

**`async pre_phase_review(phase, instructions, intel_snapshot) -> List[Correction]`**
- Called *before* phase executes
- Receives: `phase: str`, `instructions: List[Instruction]`, `intel_snapshot: Dict`
- LLM asked: Are the right tools being used? Is anything skipped that the intel warrants? Is ordering sensible?
- Example corrections: "HTTP/8080 open but no web tools targeting it", "SMB exposed but no lateral movement check planned"
- Emits `meta_checker_pre_phase` WS event on completion

**`async post_phase_review(phase, executed_tools, findings, intel_delta) -> List[Correction]`**
- Called *after* phase completes
- Receives: tools that ran, findings produced, new intel delta
- LLM asked: Were phase objectives met? Any missed follow-ups? Any tool to re-run?
- Example: "nikto found login form; no auth bypass tool was scheduled"
- Emits `meta_checker_post_phase` WS event on completion

### 4.2 Conversation Continuity
By Phase 4 (EXPLOIT), history contains prior reviews of RECON, VULN_ID, WEB_TESTING. LLM can cross-reference: "In Phase 2 I flagged unpatched OpenSSH; Phase 4 has not attempted exploitation."

---

## 5. IssueValidatorAgent

**File:** `agents/meta/issue_validator_agent.py`  
**Extends:** `BaseMetaAgent`

**Persona (system prompt):** Senior security analyst reviewing a pentest report for accuracy, completeness, and client-readiness. Knows CVE/CVSS scoring, MITRE ATT&CK, OWASP Top 10, and common tool output formats (nmap, nikto, nuclei, sqlmap, ZAP, Burp, etc.). Flag false positives aggressively. Surface missed severity escalations.

### 5.1 Entry Points

**`async validate_tool_output(tool_name, raw_output, stored_findings, target) -> List[Correction]`**
- Triggered *per tool* via background event listener on `subagent_complete` broadcast
- Receives: tool name, raw string output, findings ARGUS stored from it, target
- LLM asked: Is anything in the raw output missing from stored findings? Any clear false positives? Any severity miscalibrations?
- Example: sqlmap confirms injection stored as MEDIUM → correction to CRITICAL
- Emits `meta_validator_tool` WS event on completion

**`async validate_phase_findings(phase, all_findings, scan_objectives) -> List[Correction]`**
- Called *after all tools in a phase complete*, by master explicitly
- Receives: full finding set for the phase, original user scan objectives
- LLM asked: Duplicates? Conflicting severities for same host/port? Implied vulnerabilities no tool explicitly caught? Objectives coverage?
- Example: outdated TLS + weak cipher + self-signed cert → implied MITM exposure flagged
- Emits `meta_validator_phase` WS event on completion

### 5.2 No Direct Finding Mutation
Validator never writes to MongoDB directly. All corrections route through master's `_handle_corrections()`. Full audit trail maintained.

---

## 6. Master Integration

### 6.1 Instantiation
Both agents created once in `MasterAgent.__init__`:
```python
self._master_checker   = MasterCheckerAgent(session_id=..., broadcast=..., db=...)
self._issue_validator  = IssueValidatorAgent(session_id=..., broadcast=..., db=...)
self._meta_agents_enabled = True   # disable via scan config or env
self._pending_corrections: asyncio.Queue = asyncio.Queue()
self._meta_advisory_context: List[str] = []   # rolling buffer, max 20 entries
```

### 6.2 Phase Loop Wiring (`_execute_phases`)
```
1. pre_phase_review()              ← MasterChecker
2. _handle_corrections()           ← blocking → re-plan (max 2 retries)
3. [phase tools execute]
4. post_phase_review()             ← MasterChecker
5. validate_phase_findings()       ← IssueValidator
6. _handle_corrections()           ← all pending corrections merged + handled
7. next phase
```

### 6.3 Per-Tool Validation (Background Task)
A `asyncio.Task` started at scan init subscribes to `subagent_complete` broadcast events and calls `validate_tool_output()` for each. Corrections enqueued into `self._pending_corrections`. Drained at post-phase `_handle_corrections()`. Background task has independent error handling — crashes are logged and do not affect scan execution.

### 6.4 `_handle_corrections(corrections)`
Single method, all correction logic here:

- **Blocking** (confidence ≥ threshold):
  - Injected as `MANDATORY CORRECTION` block into master's next `think()` prompt
  - Pre-phase: master re-runs planning LLM call with correction in context (max 2 retries)
  - Emits `meta_correction` WS event with `tier: "blocking"`
  - Persisted to MongoDB `meta_corrections`

- **Advisory** (confidence < threshold):
  - Appended to `_meta_advisory_context` (rolling buffer, max 20)
  - Prepended to every subsequent planning prompt as soft context
  - Emits `meta_correction` WS event with `tier: "advisory"`
  - Persisted to MongoDB `meta_corrections`

### 6.5 Configuration
| Parameter | Default | Env Override |
|---|---|---|
| `BLOCKING_THRESHOLD` | `0.8` | `ARGUS_META_BLOCKING_THRESHOLD` |
| `MAX_HISTORY_TURNS` | `50` | `ARGUS_META_MAX_HISTORY` |
| `MAX_ADVISORY_CONTEXT` | `20` | `ARGUS_META_MAX_ADVISORY` |
| `MAX_REPLAN_RETRIES` | `2` | `ARGUS_META_MAX_RETRIES` |
| `meta_agents_enabled` | `True` | scan config payload field |

---

## 7. New WebSocket Events

| Event | Source | Payload |
|---|---|---|
| `meta_agent_thinking` | Either agent, per LLM chunk | `{agent, phase, chunk, thought_id}` |
| `meta_agent_status` | Either agent, status transitions | `{agent, status, phase}` |
| `meta_correction` | Either agent, per correction | `{agent, tier, confidence, issue_type, description, recommended_action, affected_finding_ids, phase}` |
| `meta_checker_pre_phase` | MasterChecker | `{phase, correction_count, summary}` |
| `meta_checker_post_phase` | MasterChecker | `{phase, correction_count, summary}` |
| `meta_validator_tool` | IssueValidator | `{tool, phase, confirmed, flagged, summary}` |
| `meta_validator_phase` | IssueValidator | `{phase, correction_count, objectives_coverage, summary}` |

---

## 8. Frontend Changes

### 8.1 Store (`store.js`)
Two new state slices:
```javascript
metaCheckerState:   { status, phase, history: [], corrections: [], stats: {} }
metaValidatorState: { status, phase, history: [], corrections: [], stats: {} }
```
Three new reducer actions: `META_AGENT_THINKING`, `META_AGENT_CORRECTION`, `META_AGENT_STATUS`.

New event routing in `routeWsEvent()` for all 7 new event types above.

Inline feed entries for all meta-agent events, colour-coded purple, prepended with agent icon:
- `🔎 Master Checker [pre-RECON]: reviewing plan — 3 instructions queued`
- `⛔ BLOCKING correction [master_checker]: HTTP/8080 open but no web tools targeting it [0.91]`
- `🔍 Issue Validator [nmap]: 4 confirmed, 1 upgraded HIGH→CRITICAL`
- `💡 Advisory [issue_validator]: Login form detected — no auth bypass tool scheduled`

### 8.2 New Component — `MetaAgentsPanel.jsx`
Ant Design `Collapse` panel added to scan page, collapsed by default. Two nested sub-panels (one per agent), each with three tabs:

**Tab 1 — Thought Stream:** `LiveTerminal`-style scrolling view of LLM conversation. Prompts in dim grey, responses in white. Streams live via `meta_agent_thinking` chunks.

**Tab 2 — Corrections:** Chronological list of `CorrectionCard` components.
- Blocking: red left border, ⛔ icon
- Advisory: yellow left border, 💡 icon
- Each card expandable to show full `recommended_action` and `affected_finding_ids`

**Tab 3 — Summary:** Running stats — total corrections, blocking vs advisory split, phases reviewed, findings validated/upgraded/flagged.

### 8.3 New Component — `CorrectionCard.jsx`
Small, reusable expandable card. Props: `correction` object. Visual tier indicator. Used in MetaAgentsPanel and potentially in FindingsPage for traceability.

---

## 9. File Manifest

### New files
```
agents/meta/__init__.py
agents/meta/base_meta_agent.py
agents/meta/correction.py
agents/meta/master_checker_agent.py
agents/meta/issue_validator_agent.py
static/js/components/MetaAgentsPanel.jsx
static/js/components/CorrectionCard.jsx
```

### Modified files
```
agents/master_agent.py          — instantiation, phase loop wiring, _handle_corrections()
static/js/store.js              — new state slices, actions, routeWsEvent handlers
static/js/pages/ScanPage.jsx    — add MetaAgentsPanel to layout
```

---

## 10. Non-Goals
- Meta-agents do not directly mutate findings in MongoDB
- Meta-agents do not run tools
- Meta-agents do not communicate with each other (no cross-agent coordination)
- No separate process/service — all in-process async tasks
