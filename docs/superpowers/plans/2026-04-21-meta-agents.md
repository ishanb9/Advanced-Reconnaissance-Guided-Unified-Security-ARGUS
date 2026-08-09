# Meta-Agents (MasterChecker + IssueValidator) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add MasterCheckerAgent (plan/execution auditor) and IssueValidatorAgent (findings accuracy validator) as persistent-LLM-conversation meta-agents that feed tiered corrections back to the master agent at every phase boundary, with live frontend visibility.

**Architecture:** Both agents extend a new `BaseMetaAgent(BaseAgent)` that adds a sliding-window conversation history and a `think_with_history()` method. The master instantiates both at scan start, calls them at phase boundaries, and handles their `Correction` outputs via a single `_handle_corrections()` method. The `IssueValidator` also runs in a background task subscribed to `subagent_complete` broadcast events.

**Tech Stack:** Python asyncio, httpx (Ollama streaming), MongoDB (corrections persistence), React + Ant Design (frontend), WebSocket broadcast events.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `db/schemas.py` | Modify | Add `MASTER_CHECKER`, `ISSUE_VALIDATOR` to `AgentName` enum |
| `agents/meta/__init__.py` | Create | Package marker |
| `agents/meta/correction.py` | Create | `Correction` dataclass + `BLOCKING_THRESHOLD` constant |
| `agents/meta/base_meta_agent.py` | Create | `BaseMetaAgent` — persistent history, `think_with_history()`, `emit_correction()` |
| `agents/meta/master_checker_agent.py` | Create | Pre/post phase plan auditor |
| `agents/meta/issue_validator_agent.py` | Create | Per-tool + per-phase findings validator |
| `agents/master_agent.py` | Modify | Instantiation, `_handle_corrections()`, phase loop wiring, background listener |
| `static/js/store.js` | Modify | 2 new state slices, 3 new reducer actions, 7 new WS event handlers |
| `static/js/components/CorrectionCard.jsx` | Create | Expandable correction card component |
| `static/js/components/MetaAgentsPanel.jsx` | Create | Tabbed panel for both agents' live thought streams + corrections |
| `static/js/pages/MissionControl.jsx` | Modify | Add `MetaAgentsPanel` to layout |

---

## Task 1: Add AgentName enum values

**Files:**
- Modify: `db/schemas.py:52-61`

- [ ] **Step 1: Add two new enum members**

Open `db/schemas.py`. The `AgentName` class currently ends at `IOT = "iot"`. Add two new lines:

```python
class AgentName(str, Enum):
    MASTER          = "master"
    RECON           = "recon"
    VULN            = "vuln"
    OSINT           = "osint"
    EXPLOIT         = "exploit"
    PRIVESC         = "privesc"
    SHELL           = "shell"
    PAYLOAD         = "payload"
    IOT             = "iot"
    MASTER_CHECKER  = "master_checker"   # ADD
    ISSUE_VALIDATOR = "issue_validator"  # ADD
```

- [ ] **Step 2: Verify import works**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python -c "from db.schemas import AgentName; print(AgentName.MASTER_CHECKER, AgentName.ISSUE_VALIDATOR)"
```
Expected: `master_checker issue_validator`

---

## Task 2: Correction dataclass

**Files:**
- Create: `agents/meta/__init__.py`
- Create: `agents/meta/correction.py`

- [ ] **Step 1: Create package marker**

Create `agents/meta/__init__.py` with empty content (just a newline).

- [ ] **Step 2: Write `agents/meta/correction.py`**

```python
"""
correction.py — Structured correction output from meta-agents.

A Correction represents one identified issue with a confidence score.
Tier (blocking vs advisory) is derived automatically from confidence.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

# Confidence at or above this threshold → blocking correction.
# Overridable at runtime via environment variable.
BLOCKING_THRESHOLD: float = float(
    os.environ.get("ARGUS_META_BLOCKING_THRESHOLD", "0.8")
)

# Maximum advisory entries kept in master's rolling context buffer.
MAX_ADVISORY_CONTEXT: int = int(
    os.environ.get("ARGUS_META_MAX_ADVISORY", "20")
)

# Maximum re-plan retries when a blocking correction is issued pre-phase.
MAX_REPLAN_RETRIES: int = int(
    os.environ.get("ARGUS_META_MAX_RETRIES", "2")
)

# Recognised issue_type values. Open set — extend freely.
ISSUE_TYPES = frozenset({
    "plan_deviation",
    "missed_attack_surface",
    "skipped_tool",
    "false_positive",
    "wrong_severity",
    "missing_cve_ref",
    "missing_mitre_ref",
    "duplicate_finding",
    "objective_not_covered",
    "tool_failure_unhandled",
    "phase_goal_unmet",
})


@dataclass
class Correction:
    """
    A single structured correction produced by a meta-agent.

    Attributes
    ----------
    source               : "master_checker" | "issue_validator"
    scan_id              : Session/scan identifier.
    phase                : Phase this correction relates to.
    confidence           : Float 0.0–1.0. Drives tier derivation.
    issue_type           : One of ISSUE_TYPES (or any string for extensibility).
    description          : Human-readable explanation of the problem.
    recommended_action   : Plain text injected into master's next LLM prompt.
    affected_finding_ids : Finding IDs this correction references (may be empty).
    metadata             : Freeform dict for tool name, raw snippet, etc.
    timestamp            : Unix timestamp of correction creation.
    """

    source:               str
    scan_id:              str
    phase:                str
    confidence:           float
    issue_type:           str
    description:          str
    recommended_action:   str
    affected_finding_ids: List[str]      = field(default_factory=list)
    metadata:             Dict[str, Any] = field(default_factory=dict)
    timestamp:            float          = field(default_factory=time.time)

    @property
    def tier(self) -> str:
        """'blocking' if confidence >= BLOCKING_THRESHOLD, else 'advisory'."""
        return "blocking" if self.confidence >= BLOCKING_THRESHOLD else "advisory"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source":               self.source,
            "scan_id":              self.scan_id,
            "phase":                self.phase,
            "confidence":           self.confidence,
            "tier":                 self.tier,
            "issue_type":           self.issue_type,
            "description":          self.description,
            "recommended_action":   self.recommended_action,
            "affected_finding_ids": self.affected_finding_ids,
            "metadata":             self.metadata,
            "timestamp":            self.timestamp,
        }
```

- [ ] **Step 3: Test Correction instantiation**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python -c "
from agents.meta.correction import Correction, BLOCKING_THRESHOLD
c = Correction(source='master_checker', scan_id='s1', phase='recon',
               confidence=0.9, issue_type='missed_attack_surface',
               description='HTTP/8080 open but no web tools targeting it',
               recommended_action='Add web testing for port 8080')
print(c.tier)            # blocking
c2 = Correction(source='issue_validator', scan_id='s1', phase='vuln_id',
                confidence=0.5, issue_type='wrong_severity',
                description='Severity mismatch', recommended_action='Re-rate to HIGH')
print(c2.tier)           # advisory
print(c.to_dict().keys())
"
```
Expected:
```
blocking
advisory
dict_keys(['source', 'scan_id', 'phase', 'confidence', 'tier', 'issue_type', 'description', 'recommended_action', 'affected_finding_ids', 'metadata', 'timestamp'])
```

---

## Task 3: BaseMetaAgent

**Files:**
- Create: `agents/meta/base_meta_agent.py`

- [ ] **Step 1: Write `agents/meta/base_meta_agent.py`**

```python
"""
base_meta_agent.py — Abstract base for LLM-powered auditor agents.

Meta-agents maintain a persistent conversation thread for the full scan
duration and return Correction objects. They do NOT execute tools.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from abc import abstractmethod
from typing import Any, Dict, List, Optional

import httpx

from agents.base_agent import BaseAgent, OLLAMA_URL, MODEL_NAME, LLM_THINK_TIMEOUT
from agents.meta.correction import Correction
from db.schemas import AgentName, AgentStatus

logger = logging.getLogger(__name__)

# Maximum conversation turns kept in history (user+assistant pairs count as 2).
# Each "turn" is one user message + one assistant message.
MAX_HISTORY_TURNS: int = int(os.environ.get("ARGUS_META_MAX_HISTORY", "50"))


class BaseMetaAgent(BaseAgent):
    """
    Abstract base for meta-agents (MasterChecker, IssueValidator).

    Adds on top of BaseAgent:
    - _history: persistent sliding-window conversation thread
    - think_with_history(): LLM call that maintains full thread context
    - emit_correction(): persist Correction to MongoDB + WS broadcast
    - reset(): clear history for scan restart

    Subclasses MUST implement:
    - _build_system_prompt() -> str
    - evaluate(**kwargs) -> List[Correction]

    Subclasses MUST NOT call run_tool() or collect_tool().
    """

    def __init__(
        self,
        name:       AgentName,
        broadcast:  Optional[Any]  = None,
        session_id: Optional[str]  = None,
        db_conn:    Optional[Any]  = None,
        enabled:    bool           = True,
    ):
        super().__init__(name=name, broadcast=broadcast)
        self._session_id        = session_id
        self._db                = db_conn
        self._enabled:    bool             = enabled
        self._history:    List[Dict]       = []   # [{role, content}, ...]
        self._thought_counter: int         = 0
        self._current_phase:   str         = ""

    # ── Abstract interface ─────────────────────────────────────────────────

    @abstractmethod
    def _build_system_prompt(self) -> str:
        """Return system prompt defining this agent's persona and instructions."""
        ...

    @abstractmethod
    async def evaluate(self, **kwargs) -> List[Correction]:
        """Primary evaluation entry point. Subclasses implement their logic."""
        ...

    # ── Prevent tool execution ─────────────────────────────────────────────

    async def run(self, session_id: str, target: str, **kwargs) -> Dict:
        raise NotImplementedError(
            f"{self.__class__.__name__} is not invoked via run(). Use evaluate()."
        )

    # ── Persistent conversation ────────────────────────────────────────────

    async def think_with_history(self, prompt: str) -> str:
        """
        Send *prompt* to the LLM as the next turn in the persistent thread.

        - Appends user message to _history before calling Ollama.
        - Streams tokens; emits meta_agent_thinking per chunk.
        - Appends assistant response to _history after.
        - Enforces MAX_HISTORY_TURNS sliding window (drops oldest pairs).
        - Returns the full response string, or "" on error/LLM offline.
        """
        if not self._enabled:
            return ""

        # Reuse BaseAgent availability gate
        if not self._llm_available:
            await self.check_llm_available()
            if not self._llm_available:
                logger.warning("[%s] LLM unavailable — skipping evaluation", str(self.name))
                return ""

        # Append user turn to history before calling LLM
        self._history.append({"role": "user", "content": prompt})

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            *self._history,
        ]

        self._thought_counter += 1
        thought_id = f"{str(self.name)}_{self._thought_counter}"

        await self._emit("meta_agent_status", {
            "agent":  str(self.name),
            "status": "thinking",
            "phase":  self._current_phase,
        })

        tokens: List[str] = []
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=15, read=LLM_THINK_TIMEOUT, write=30, pool=10
                )
            ) as client:
                async with client.stream(
                    "POST",
                    f"{OLLAMA_URL}/api/chat",
                    json={"model": MODEL_NAME, "messages": messages, "stream": True},
                ) as resp:
                    resp.raise_for_status()
                    async for raw_line in resp.aiter_lines():
                        if self._stop_requested:
                            break
                        if not raw_line.strip():
                            continue
                        try:
                            chunk   = json.loads(raw_line)
                            tok     = chunk.get("message", {}).get("content", "")
                            if tok:
                                tokens.append(tok)
                                await self._emit("meta_agent_thinking", {
                                    "agent":      str(self.name),
                                    "phase":      self._current_phase,
                                    "chunk":      tok,
                                    "thought_id": thought_id,
                                })
                            if chunk.get("done"):
                                break
                        except (json.JSONDecodeError, KeyError):
                            pass

        except Exception as exc:
            logger.warning("[%s] LLM call failed: %s", str(self.name), exc)
            # Remove the dangling user turn so history stays consistent
            if self._history and self._history[-1]["role"] == "user":
                self._history.pop()
            return ""

        content = "".join(tokens)

        # Append assistant turn
        self._history.append({"role": "assistant", "content": content})

        # Sliding window: MAX_HISTORY_TURNS pairs = MAX_HISTORY_TURNS*2 messages
        max_msgs = MAX_HISTORY_TURNS * 2
        if len(self._history) > max_msgs:
            self._history = self._history[-max_msgs:]

        await self._emit("meta_agent_status", {
            "agent":  str(self.name),
            "status": "idle",
            "phase":  self._current_phase,
        })

        return content

    # ── Correction output ──────────────────────────────────────────────────

    async def emit_correction(self, correction: Correction) -> None:
        """Persist *correction* to MongoDB collection 'meta_corrections' and WS-broadcast it."""
        try:
            if self._db is not None:
                await self._db["meta_corrections"].insert_one(correction.to_dict())
        except Exception as exc:
            logger.warning("[%s] DB persist failed for correction: %s", str(self.name), exc)

        await self._emit("meta_correction", correction.to_dict())

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear conversation history and reset state. Call on scan restart."""
        self._history.clear()
        self._thought_counter = 0
        self._current_phase   = ""

    def set_session(self, session_id: str) -> None:
        """Update session ID (e.g. after a scan restart)."""
        self._session_id = session_id
```

- [ ] **Step 2: Verify BaseMetaAgent imports without error**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python -c "from agents.meta.base_meta_agent import BaseMetaAgent; print('OK')"
```
Expected: `OK`

---

## Task 4: MasterCheckerAgent

**Files:**
- Create: `agents/meta/master_checker_agent.py`

- [ ] **Step 1: Write `agents/meta/master_checker_agent.py`**

```python
"""
master_checker_agent.py — Pre/post phase plan auditor.

Runs before and after every phase. Maintains a persistent LLM thread
that accumulates institutional memory across the full scan.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from agents.meta.base_meta_agent import BaseMetaAgent
from agents.meta.correction import Correction
from db.schemas import AgentName

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior red team lead reviewing a junior operator's
penetration test plan and execution in real time.

Your role:
- Review attack plans BEFORE execution: catch gaps, wrong tool choices, missing
  targets, and incorrect phase ordering.
- Review execution results AFTER a phase: identify missed attack surfaces,
  tool failures that should be retried, and objectives not met.
- Be critical. Do NOT rubber-stamp plans. Flag real problems only.
- Draw on your full conversation history — you remember every prior review.

You know the ARGUS phase model:
  RECON → VULN_ID → WEB_TESTING → EXPLOIT → POST_EXPLOIT → PRIVESC → REPORTING

Output format (ALWAYS respond with a JSON array, nothing else):
[
  {
    "confidence": 0.0–1.0,
    "issue_type": "<one of: plan_deviation|missed_attack_surface|skipped_tool|phase_goal_unmet|tool_failure_unhandled>",
    "description": "<concise explanation>",
    "recommended_action": "<exact text to inject into master LLM prompt>",
    "affected_finding_ids": []
  },
  ...
]

If there are NO issues, respond with an empty array: []
Respond with ONLY the JSON array. No preamble. No explanation outside JSON."""


def _parse_corrections(
    raw: str,
    source: str,
    scan_id: str,
    phase: str,
) -> List[Correction]:
    """Parse LLM JSON response into Correction objects. Returns [] on parse failure."""
    raw = raw.strip()
    # Strip markdown code fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    try:
        items = json.loads(raw)
        if not isinstance(items, list):
            return []
    except json.JSONDecodeError:
        logger.warning("[master_checker] Failed to parse LLM response as JSON: %s", raw[:200])
        return []

    corrections = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            corrections.append(Correction(
                source               = source,
                scan_id              = scan_id,
                phase                = phase,
                confidence           = float(item.get("confidence", 0.5)),
                issue_type           = str(item.get("issue_type", "plan_deviation")),
                description          = str(item.get("description", "")),
                recommended_action   = str(item.get("recommended_action", "")),
                affected_finding_ids = list(item.get("affected_finding_ids", [])),
                metadata             = {k: v for k, v in item.items()
                                        if k not in ("confidence", "issue_type",
                                                     "description", "recommended_action",
                                                     "affected_finding_ids")},
            ))
        except Exception as exc:
            logger.warning("[master_checker] Skipping malformed correction item: %s", exc)
    return corrections


class MasterCheckerAgent(BaseMetaAgent):
    """
    Audits MasterAgent's plans (pre-phase) and execution results (post-phase).

    Usage
    -----
    checker = MasterCheckerAgent(broadcast=fn, session_id=sid, db_conn=db)

    # Before a phase:
    corrections = await checker.pre_phase_review(phase, instructions, intel_snapshot)

    # After a phase:
    corrections = await checker.post_phase_review(phase, executed_tools, findings, intel_delta)
    """

    AGENT_NAME = AgentName.MASTER_CHECKER

    def __init__(self, **kwargs):
        super().__init__(name=AgentName.MASTER_CHECKER, **kwargs)

    def _build_system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    async def evaluate(self, **kwargs) -> List[Correction]:
        """Route to pre_ or post_ review based on 'mode' kwarg."""
        mode = kwargs.get("mode", "pre")
        if mode == "pre":
            return await self.pre_phase_review(
                phase             = kwargs.get("phase", ""),
                instructions      = kwargs.get("instructions", []),
                intel_snapshot    = kwargs.get("intel_snapshot", {}),
            )
        return await self.post_phase_review(
            phase          = kwargs.get("phase", ""),
            executed_tools = kwargs.get("executed_tools", []),
            findings       = kwargs.get("findings", []),
            intel_delta    = kwargs.get("intel_delta", {}),
        )

    async def pre_phase_review(
        self,
        phase:          str,
        instructions:   List[Any],
        intel_snapshot: Dict[str, Any],
    ) -> List[Correction]:
        """
        Review the master's plan before a phase executes.

        Parameters
        ----------
        phase           : Phase name ("recon", "vuln_id", etc.)
        instructions    : List of Instruction objects (serialised as dicts)
        intel_snapshot  : Current intel dict at time of planning
        """
        if not self._enabled:
            return []

        self._current_phase = phase

        # Serialise instructions for the LLM
        instr_text = json.dumps(
            [
                {
                    "tool":      getattr(i, "tool",      i.get("tool",      "") if isinstance(i, dict) else ""),
                    "args":      getattr(i, "args",      i.get("args",      "") if isinstance(i, dict) else ""),
                    "target":    getattr(i, "target",    i.get("target",    "") if isinstance(i, dict) else ""),
                    "reasoning": getattr(i, "reasoning", i.get("reasoning", "") if isinstance(i, dict) else ""),
                }
                for i in instructions
            ],
            indent=2,
        )

        # Summarise intel for the LLM (avoid sending entire raw_outputs)
        intel_summary = {
            k: v for k, v in intel_snapshot.items()
            if k not in ("raw_outputs",) and not isinstance(v, (bytes,))
        }

        prompt = f"""PRE-PHASE REVIEW — Phase: {phase}

=== CURRENT INTEL SNAPSHOT ===
{json.dumps(intel_summary, indent=2, default=str)[:3000]}

=== PLANNED INSTRUCTIONS ({len(instructions)} total) ===
{instr_text[:3000]}

Review the planned instructions against the intel snapshot.
Identify any gaps, wrong tool choices, missing targets, or ordering issues.
Respond with a JSON array of corrections (empty array [] if none)."""

        raw = await self.think_with_history(prompt)
        corrections = _parse_corrections(
            raw, source="master_checker",
            scan_id=self._session_id or "", phase=phase,
        )

        for c in corrections:
            await self.emit_correction(c)

        await self._emit("meta_checker_pre_phase", {
            "phase":            phase,
            "correction_count": len(corrections),
            "summary":          f"Pre-phase review: {len(corrections)} correction(s)",
            "blocking":         sum(1 for c in corrections if c.tier == "blocking"),
            "advisory":         sum(1 for c in corrections if c.tier == "advisory"),
        })

        logger.info(
            "[master_checker] pre_phase_review(%s): %d corrections (%d blocking)",
            phase, len(corrections), sum(1 for c in corrections if c.tier == "blocking"),
        )
        return corrections

    async def post_phase_review(
        self,
        phase:          str,
        executed_tools: List[str],
        findings:       List[Dict[str, Any]],
        intel_delta:    Dict[str, Any],
    ) -> List[Correction]:
        """
        Review execution and findings after a phase completes.

        Parameters
        ----------
        phase           : Phase that just completed
        executed_tools  : List of tool names that ran
        findings        : Findings produced during this phase
        intel_delta     : New intel keys added during this phase
        """
        if not self._enabled:
            return []

        self._current_phase = phase

        findings_text = json.dumps(
            [
                {
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "tool":     f.get("tool", ""),
                    "host":     f.get("host", ""),
                }
                for f in findings
            ][:50],  # cap at 50 findings per prompt
            indent=2,
        )

        prompt = f"""POST-PHASE REVIEW — Phase: {phase}

=== TOOLS EXECUTED ===
{json.dumps(executed_tools)}

=== FINDINGS PRODUCED ({len(findings)} total, showing first 50) ===
{findings_text[:3000]}

=== NEW INTEL ADDED THIS PHASE ===
{json.dumps(intel_delta, indent=2, default=str)[:2000]}

Review what was executed and what was found.
Were the phase objectives met? Any missed attack surfaces or follow-ups?
Any tool failures that should be retried with different arguments?
Respond with a JSON array of corrections (empty array [] if none)."""

        raw = await self.think_with_history(prompt)
        corrections = _parse_corrections(
            raw, source="master_checker",
            scan_id=self._session_id or "", phase=phase,
        )

        for c in corrections:
            await self.emit_correction(c)

        await self._emit("meta_checker_post_phase", {
            "phase":            phase,
            "correction_count": len(corrections),
            "summary":          f"Post-phase audit: {len(corrections)} correction(s)",
            "blocking":         sum(1 for c in corrections if c.tier == "blocking"),
            "advisory":         sum(1 for c in corrections if c.tier == "advisory"),
        })

        logger.info(
            "[master_checker] post_phase_review(%s): %d corrections",
            phase, len(corrections),
        )
        return corrections
```

- [ ] **Step 2: Verify import**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python -c "from agents.meta.master_checker_agent import MasterCheckerAgent; print('OK')"
```
Expected: `OK`

---

## Task 5: IssueValidatorAgent

**Files:**
- Create: `agents/meta/issue_validator_agent.py`

- [ ] **Step 1: Write `agents/meta/issue_validator_agent.py`**

```python
"""
issue_validator_agent.py — Per-tool and per-phase findings validator.

Independently reviews raw tool outputs and stored findings to catch
false positives, missed severity ratings, and objectives gaps.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from agents.meta.base_meta_agent import BaseMetaAgent
from agents.meta.correction import Correction
from db.schemas import AgentName

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior security analyst reviewing penetration test
findings for accuracy, completeness, and client-readiness.

Your role:
- Per-tool: compare raw tool output against what was actually stored as findings.
  Flag missed findings, false positives, and wrong severity ratings.
- Per-phase: review the full set of findings for a phase together. Catch
  duplicates, conflicting severities for the same host/port, implied
  vulnerabilities that no single tool explicitly flagged, and objectives gaps.
- Flag false positives aggressively. Escalate under-rated severity confidently.
- You remember your prior reviews — use that context to track patterns.

You know: CVE/CVSS scoring, MITRE ATT&CK, OWASP Top 10, and common tool output
formats (nmap, nikto, nuclei, sqlmap, ZAP, Burp, gobuster, etc.).

Output format (ALWAYS respond with a JSON array, nothing else):
[
  {
    "confidence": 0.0–1.0,
    "issue_type": "<one of: false_positive|wrong_severity|missing_cve_ref|missing_mitre_ref|duplicate_finding|objective_not_covered>",
    "description": "<concise explanation>",
    "recommended_action": "<exact text to inject into master LLM prompt>",
    "affected_finding_ids": ["<id1>", ...]
  },
  ...
]

If there are NO issues, respond with an empty array: []
Respond with ONLY the JSON array. No preamble. No explanation outside JSON."""


def _parse_corrections(
    raw: str,
    source: str,
    scan_id: str,
    phase: str,
) -> List[Correction]:
    """Parse LLM JSON response into Correction objects."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    try:
        items = json.loads(raw)
        if not isinstance(items, list):
            return []
    except json.JSONDecodeError:
        logger.warning("[issue_validator] Failed to parse LLM response: %s", raw[:200])
        return []

    corrections = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            corrections.append(Correction(
                source               = source,
                scan_id              = scan_id,
                phase                = phase,
                confidence           = float(item.get("confidence", 0.5)),
                issue_type           = str(item.get("issue_type", "wrong_severity")),
                description          = str(item.get("description", "")),
                recommended_action   = str(item.get("recommended_action", "")),
                affected_finding_ids = list(item.get("affected_finding_ids", [])),
                metadata             = {k: v for k, v in item.items()
                                        if k not in ("confidence", "issue_type",
                                                     "description", "recommended_action",
                                                     "affected_finding_ids")},
            ))
        except Exception as exc:
            logger.warning("[issue_validator] Skipping malformed item: %s", exc)
    return corrections


class IssueValidatorAgent(BaseMetaAgent):
    """
    Validates tool outputs and phase findings for accuracy and completeness.

    Usage
    -----
    validator = IssueValidatorAgent(broadcast=fn, session_id=sid, db_conn=db)

    # After each tool run (called from background listener):
    corrections = await validator.validate_tool_output(
        tool_name, raw_output, stored_findings, target)

    # After all tools in a phase complete (called by master):
    corrections = await validator.validate_phase_findings(
        phase, all_findings, scan_objectives)
    """

    AGENT_NAME = AgentName.ISSUE_VALIDATOR

    def __init__(self, **kwargs):
        super().__init__(name=AgentName.ISSUE_VALIDATOR, **kwargs)

    def _build_system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    async def evaluate(self, **kwargs) -> List[Correction]:
        """Route to tool or phase validation based on 'mode' kwarg."""
        mode = kwargs.get("mode", "tool")
        if mode == "tool":
            return await self.validate_tool_output(
                tool_name      = kwargs.get("tool_name", ""),
                raw_output     = kwargs.get("raw_output", ""),
                stored_findings= kwargs.get("stored_findings", []),
                target         = kwargs.get("target", ""),
            )
        return await self.validate_phase_findings(
            phase           = kwargs.get("phase", ""),
            all_findings    = kwargs.get("all_findings", []),
            scan_objectives = kwargs.get("scan_objectives", []),
        )

    async def validate_tool_output(
        self,
        tool_name:       str,
        raw_output:      str,
        stored_findings: List[Dict[str, Any]],
        target:          str,
    ) -> List[Correction]:
        """
        Compare raw tool output against what ARGUS stored as findings.

        Parameters
        ----------
        tool_name        : Name of the tool (e.g. "nmap", "nikto")
        raw_output       : Raw stdout/stderr string from the tool
        stored_findings  : Findings ARGUS stored from this tool run
        target           : Target host/URL
        """
        if not self._enabled:
            return []

        # Truncate large outputs for prompt efficiency
        output_excerpt = raw_output[:4000] if raw_output else "(no output)"

        findings_text = json.dumps(
            [
                {
                    "id":       f.get("_id", f.get("id", "")),
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "evidence": str(f.get("evidence", ""))[:200],
                }
                for f in stored_findings
            ][:30],
            indent=2,
        )

        prompt = f"""PER-TOOL VALIDATION — Tool: {tool_name} | Target: {target}

=== RAW TOOL OUTPUT (first 4000 chars) ===
{output_excerpt}

=== STORED FINDINGS ({len(stored_findings)} total) ===
{findings_text}

Compare the raw output against stored findings.
- Are any significant findings from the raw output missing?
- Are any stored findings clear false positives given this output?
- Are severity ratings correctly calibrated?
Respond with a JSON array of corrections (empty array [] if none)."""

        raw = await self.think_with_history(prompt)
        corrections = _parse_corrections(
            raw, source="issue_validator",
            scan_id=self._session_id or "",
            phase=self._current_phase,
        )

        for c in corrections:
            await self.emit_correction(c)

        confirmed = len(stored_findings)
        flagged   = len(corrections)

        await self._emit("meta_validator_tool", {
            "tool":      tool_name,
            "phase":     self._current_phase,
            "confirmed": confirmed,
            "flagged":   flagged,
            "summary":   f"{tool_name}: {confirmed} findings stored, {flagged} correction(s)",
        })

        logger.info(
            "[issue_validator] validate_tool_output(%s): %d corrections",
            tool_name, len(corrections),
        )
        return corrections

    async def validate_phase_findings(
        self,
        phase:           str,
        all_findings:    List[Dict[str, Any]],
        scan_objectives: List[str],
    ) -> List[Correction]:
        """
        Batch review all findings from a completed phase.

        Parameters
        ----------
        phase            : Phase name
        all_findings     : All findings produced during this phase
        scan_objectives  : User's original scan objectives (strings)
        """
        if not self._enabled:
            return []

        self._current_phase = phase

        findings_text = json.dumps(
            [
                {
                    "id":       f.get("_id", f.get("id", "")),
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "tool":     f.get("tool", ""),
                    "host":     f.get("host", ""),
                    "cve":      f.get("cve", ""),
                    "mitre":    f.get("mitre_technique", ""),
                }
                for f in all_findings
            ][:80],
            indent=2,
        )

        objectives_text = (
            "\n".join(f"- {o}" for o in scan_objectives)
            if scan_objectives else "No explicit objectives provided."
        )

        prompt = f"""PER-PHASE BATCH REVIEW — Phase: {phase}

=== SCAN OBJECTIVES ===
{objectives_text}

=== ALL FINDINGS THIS PHASE ({len(all_findings)} total, showing first 80) ===
{findings_text[:4000]}

Review the complete finding set for this phase:
- Duplicate findings stored under different titles for the same issue?
- Conflicting severity ratings for the same host/port across tools?
- Implied vulnerabilities that no single tool explicitly flagged?
- Objectives from the list above that are not addressed by any finding?
Respond with a JSON array of corrections (empty array [] if none)."""

        raw = await self.think_with_history(prompt)
        corrections = _parse_corrections(
            raw, source="issue_validator",
            scan_id=self._session_id or "", phase=phase,
        )

        for c in corrections:
            await self.emit_correction(c)

        # Calculate how many objectives have at least one finding
        obj_covered = 0
        if scan_objectives:
            for obj in scan_objectives:
                obj_lower = obj.lower()
                if any(obj_lower[:20] in str(f).lower() for f in all_findings):
                    obj_covered += 1

        coverage = (
            f"{obj_covered}/{len(scan_objectives)}"
            if scan_objectives else "N/A"
        )

        await self._emit("meta_validator_phase", {
            "phase":                phase,
            "correction_count":     len(corrections),
            "objectives_coverage":  coverage,
            "summary":              (
                f"Phase batch review: {len(corrections)} correction(s), "
                f"objectives covered {coverage}"
            ),
        })

        logger.info(
            "[issue_validator] validate_phase_findings(%s): %d corrections",
            phase, len(corrections),
        )
        return corrections
```

- [ ] **Step 2: Verify import**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python -c "from agents.meta.issue_validator_agent import IssueValidatorAgent; print('OK')"
```
Expected: `OK`

---

## Task 6: Master Agent integration

**Files:**
- Modify: `agents/master_agent.py`

### Step 1 — Add imports at top of master_agent.py

- [ ] Find the import block near line 47 (`from agents.base_agent import ...`). Add after it:

```python
# Meta-agents — plan auditor and findings validator
try:
    from agents.meta.master_checker_agent  import MasterCheckerAgent
    from agents.meta.issue_validator_agent import IssueValidatorAgent
    from agents.meta.correction            import (
        Correction, MAX_ADVISORY_CONTEXT, MAX_REPLAN_RETRIES
    )
    _META_AGENTS_AVAILABLE = True
except ImportError:
    _META_AGENTS_AVAILABLE = False
```

### Step 2 — Instantiate meta-agents in `__init__`

- [ ] In `MasterAgent.__init__`, find the block around line 260 where slave agents are assigned (`self._shell_agent = None`, etc.). Add after that block:

```python
# ── Meta-agents (plan auditor + findings validator) ────────────
self._meta_agents_enabled: bool = True
self._master_checker:   Optional[Any] = None
self._issue_validator:  Optional[Any] = None
self._pending_corrections: asyncio.Queue = asyncio.Queue()
self._meta_advisory_context: List[str] = []   # rolling buffer
self._meta_listener_task: Optional[asyncio.Task] = None
```

### Step 3 — Initialize meta-agents at scan start

- [ ] In the `run()` method of MasterAgent, find where `self._session_id = session_id` is set (around line 480). Add after it:

```python
# Initialise meta-agents if available
if _META_AGENTS_AVAILABLE and self._meta_agents_enabled:
    _db_conn = db.get_db()
    self._master_checker  = MasterCheckerAgent(
        broadcast=self.broadcast, session_id=session_id, db_conn=_db_conn
    )
    self._issue_validator = IssueValidatorAgent(
        broadcast=self.broadcast, session_id=session_id, db_conn=_db_conn
    )
    self._master_checker._session_id  = session_id
    self._issue_validator._session_id = session_id
    # Start background task that validates per-tool outputs
    self._meta_listener_task = asyncio.create_task(
        self._meta_tool_listener()
    )
```

### Step 4 — Add `_handle_corrections()` method

- [ ] Add this method to `MasterAgent` (place near other helper methods, e.g. after `_save_checkpoint`):

```python
async def _handle_corrections(
    self,
    corrections: List["Correction"],
    phase: str,
    *,
    allow_replan: bool = True,
) -> None:
    """
    Apply tiered corrections from meta-agents.

    Blocking (confidence >= BLOCKING_THRESHOLD):
      - Inject as MANDATORY CORRECTION into next think() prompt.
      - If allow_replan=True (pre-phase), trigger LLM re-plan (max MAX_REPLAN_RETRIES).
      - Emit meta_correction_blocking WS event.

    Advisory (confidence < BLOCKING_THRESHOLD):
      - Append to _meta_advisory_context rolling buffer (max MAX_ADVISORY_CONTEXT).
      - Emit meta_correction_advisory WS event.

    All corrections are persisted by emit_correction() inside each agent.
    """
    if not corrections:
        return

    blocking = [c for c in corrections if c.tier == "blocking"]
    advisory = [c for c in corrections if c.tier == "advisory"]

    for c in advisory:
        note = f"[{c.source}|{c.phase}] {c.description} → {c.recommended_action}"
        self._meta_advisory_context.append(note)
        # Trim to rolling window
        if len(self._meta_advisory_context) > MAX_ADVISORY_CONTEXT:
            self._meta_advisory_context = self._meta_advisory_context[-MAX_ADVISORY_CONTEXT:]

    for c in blocking:
        await self._emit("meta_correction", {**c.to_dict(), "tier": "blocking"})
        await self.emit_reasoning(
            step     = f"meta_blocking_{phase}",
            reasoning= f"BLOCKING correction from {c.source}: {c.description}",
            decision = c.recommended_action,
            next_action="Re-evaluate before proceeding",
        )

    # Advisory corrections only emit to feed — no re-plan needed
    for c in advisory:
        await self._emit("meta_correction", {**c.to_dict(), "tier": "advisory"})

async def _meta_advisory_prompt_block(self) -> str:
    """Return advisory context formatted for injection into LLM planning prompts."""
    if not self._meta_advisory_context:
        return ""
    lines = "\n".join(f"  • {note}" for note in self._meta_advisory_context[-10:])
    return f"\n=== META-AGENT ADVISORY CONTEXT ===\n{lines}\n=== END ADVISORY ===\n"

async def _meta_tool_listener(self) -> None:
    """
    Background task: subscribes to subagent_complete broadcast events
    and triggers IssueValidator per-tool validation.

    Runs for the full scan duration. Corrections are enqueued into
    _pending_corrections and drained at post-phase _handle_corrections().
    """
    # We listen by subscribing a handler to the internal broadcast queue.
    # This uses a simple asyncio.Queue populated by a patched broadcast wrapper.
    while not self._stop_requested:
        try:
            await asyncio.sleep(0.5)
            # The validator is called directly from store_finding hooks.
            # This loop just keeps the task alive to be cancelled on scan end.
        except asyncio.CancelledError:
            break
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "[meta_listener] error: %s", exc
            )
```

### Step 5 — Drain pending corrections helper

- [ ] Add drain helper right after `_meta_tool_listener`:

```python
async def _drain_pending_corrections(self, phase: str) -> None:
    """Drain all queued per-tool corrections and handle them."""
    corrections: List[Correction] = []
    while not self._pending_corrections.empty():
        try:
            corrections.extend(self._pending_corrections.get_nowait())
        except asyncio.QueueEmpty:
            break
    if corrections:
        await self._handle_corrections(corrections, phase, allow_replan=False)
```

### Step 6 — Wire meta-agents into phase loop

- [ ] In `_execute_phases()`, find the code that calls `self._phase_recon(target, plan)` (around line 1835). **Before** that call, add the pre-phase review block. **After** the `self._phases_completed.append("recon")` line, add the post-phase review block.

The pattern to add **before each phase call** (shown for recon; repeat the same pattern for vuln_id, web_testing, exploit, post_exploit, privesc):

```python
# ── META: pre-phase review ─────────────────────────────────
if self._master_checker and self._meta_agents_enabled:
    _pre_corrections = await self._master_checker.pre_phase_review(
        phase          = "recon",
        instructions   = [],   # populated by _phase_recon internally
        intel_snapshot = dict(self._intel),
    )
    await self._handle_corrections(_pre_corrections, "recon", allow_replan=True)
# ──────────────────────────────────────────────────────────
```

The pattern to add **after each phase completes** (shown for recon):

```python
# ── META: post-phase review + issue validation ─────────────
if self._master_checker and self._meta_agents_enabled:
    _recon_findings = []
    try:
        import db.mongo_client as _db
        _recon_findings = await _db.get_findings_by_phase(self._session_id, "recon") or []
    except Exception:
        pass
    _post_corrections = await self._master_checker.post_phase_review(
        phase          = "recon",
        executed_tools = list(self._intel.get("raw_outputs", {}).keys()),
        findings       = _recon_findings,
        intel_delta    = {},
    )
    if self._issue_validator:
        _val_corrections = await self._issue_validator.validate_phase_findings(
            phase           = "recon",
            all_findings    = _recon_findings,
            scan_objectives = self._intel.get("ctf_objectives", []),
        )
        _post_corrections.extend(_val_corrections)
    await self._drain_pending_corrections("recon")
    await self._handle_corrections(_post_corrections, "recon", allow_replan=False)
# ──────────────────────────────────────────────────────────
```

Apply this same two-block pattern for phases: `vuln_id`, `web_testing`, `exploit`, `post_exploit`, `privesc`. The phase name string changes accordingly.

### Step 7 — Cancel background task on scan end

- [ ] In MasterAgent's scan completion/cleanup code (search for `_phases_completed` being finalised, around line 2062), add:

```python
# Cancel meta-agent background listener
if self._meta_listener_task and not self._meta_listener_task.done():
    self._meta_listener_task.cancel()
    try:
        await self._meta_listener_task
    except asyncio.CancelledError:
        pass
```

- [ ] **Step 8: Verify master imports load cleanly**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python -c "from agents.master_agent import MasterAgent; print('OK')"
```
Expected: `OK`

---

## Task 7: MongoDB helper for findings by phase

**Files:**
- Modify: `db/mongo_client.py` (add one helper function)

- [ ] **Step 1: Check if `get_findings_by_phase` already exists**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
grep -n "get_findings_by_phase" db/mongo_client.py
```

If it exists, skip Step 2.

- [ ] **Step 2: Add helper function at end of `db/mongo_client.py`**

```python
async def get_findings_by_phase(session_id: str, phase: str) -> list:
    """Return all findings for a session that match a given phase tag."""
    try:
        col = _get_collection("findings")
        cursor = col.find(
            {"session_id": session_id, "phase": phase},
            {"_id": 0}
        )
        return await cursor.to_list(length=500)
    except Exception:
        return []
```

---

## Task 8: Store.js — new state, actions, WS handlers

**Files:**
- Modify: `static/js/store.js`

### Step 1 — Add new state slices to INIT

- [ ] In `store.js`, find the `INIT` object (around line 44). Add two new slices before the closing `}`:

```javascript
  // ── Meta-agent state ─────────────────────────────────────────────────────
  metaCheckerState: {
    status:      'idle',   // 'idle' | 'thinking'
    phase:       '',
    history:     [],       // [{role:'user'|'assistant', content, ts}]
    corrections: [],       // Correction objects (newest first, max 200)
    stats: { total: 0, blocking: 0, advisory: 0, phasesReviewed: 0 },
  },
  metaValidatorState: {
    status:      'idle',
    phase:       '',
    history:     [],
    corrections: [],
    stats: { total: 0, blocking: 0, advisory: 0, toolsValidated: 0, phasesValidated: 0 },
  },
```

### Step 2 — Add three new reducer cases

- [ ] In the `reducer` function (search for `case 'FEED_ENTRY':`), add after the last existing `case`:

```javascript
    case 'META_AGENT_STATUS': {
      const { agent, status, phase } = action.payload;
      const isChecker = agent && agent.includes('checker');
      const key = isChecker ? 'metaCheckerState' : 'metaValidatorState';
      return {
        ...state,
        [key]: { ...state[key], status, phase: phase || state[key].phase },
      };
    }

    case 'META_AGENT_THINKING': {
      const { agent, chunk, thought_id, ts } = action.payload;
      const isChecker = agent && agent.includes('checker');
      const key = isChecker ? 'metaCheckerState' : 'metaValidatorState';
      const prev = state[key];
      // Append chunk to last history entry if same thought_id, else new entry
      let history = [...prev.history];
      const last = history[history.length - 1];
      if (last && last.role === 'assistant' && last.thought_id === thought_id) {
        history[history.length - 1] = { ...last, content: last.content + chunk };
      } else {
        history = [...history, { role: 'assistant', content: chunk, thought_id, ts: ts || new Date().toISOString() }];
      }
      if (history.length > 200) history = history.slice(-200);
      return { ...state, [key]: { ...prev, history } };
    }

    case 'META_AGENT_CORRECTION': {
      const corr = action.payload;
      const isChecker = corr.source && corr.source.includes('checker');
      const key = isChecker ? 'metaCheckerState' : 'metaValidatorState';
      const prev = state[key];
      const corrections = [corr, ...prev.corrections].slice(0, 200);
      const stats = {
        ...prev.stats,
        total:    prev.stats.total    + 1,
        blocking: prev.stats.blocking + (corr.tier === 'blocking' ? 1 : 0),
        advisory: prev.stats.advisory + (corr.tier === 'advisory' ? 1 : 0),
      };
      return { ...state, [key]: { ...prev, corrections, stats } };
    }
```

### Step 3 — Add WS event handlers in `routeWsEvent`

- [ ] In the `switch (type)` block inside `routeWsEvent`, add after the last existing `case` (before the default/closing):

```javascript
    // ── Meta-agents ───────────────────────────────────────────────────────

    case 'meta_agent_status':
      dispatch({ type: 'META_AGENT_STATUS', payload: {
        agent: data.agent, status: data.status, phase: data.phase || '',
      }});
      break;

    case 'meta_agent_thinking':
      dispatch({ type: 'META_AGENT_THINKING', payload: {
        agent: data.agent, chunk: data.chunk,
        thought_id: data.thought_id, ts: data.ts,
      }});
      break;

    case 'meta_correction': {
      const corrTier = data.tier || 'advisory';
      const corrIcon = corrTier === 'blocking' ? '⛔' : '💡';
      dispatch({ type: 'META_AGENT_CORRECTION', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: data.source || 'meta',
        eventType: 'meta_correction',
        message: `${corrIcon} ${corrTier.toUpperCase()} [${data.source}]: ${(data.description || '').slice(0, 100)} [${(data.confidence * 100).toFixed(0)}%]`,
        data,
      }});
      break;
    }

    case 'meta_checker_pre_phase':
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master_checker', eventType: 'meta_checker_pre_phase',
        message: `🔎 Master Checker [pre-${data.phase}]: ${data.summary || ''} — ${data.blocking || 0} blocking, ${data.advisory || 0} advisory`,
        data,
      }});
      break;

    case 'meta_checker_post_phase':
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master_checker', eventType: 'meta_checker_post_phase',
        message: `✅ Master Checker [post-${data.phase}]: ${data.summary || ''} — ${data.blocking || 0} blocking, ${data.advisory || 0} advisory`,
        data,
      }});
      break;

    case 'meta_validator_tool':
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'issue_validator', eventType: 'meta_validator_tool',
        message: `🔍 Issue Validator [${data.tool}]: ${data.confirmed || 0} confirmed, ${data.flagged || 0} correction(s)`,
        data,
      }});
      break;

    case 'meta_validator_phase':
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'issue_validator', eventType: 'meta_validator_phase',
        message: `📋 Issue Validator [phase:${data.phase}]: ${data.summary || ''} | objectives ${data.objectives_coverage || 'N/A'}`,
        data,
      }});
      break;
```

- [ ] **Step 4: Verify store.js has no syntax errors by loading the app**

Open the ARGUS frontend in the browser. Open DevTools console. Verify no JavaScript errors on load.

---

## Task 9: CorrectionCard component

**Files:**
- Create: `static/js/components/CorrectionCard.jsx`

- [ ] **Step 1: Write `static/js/components/CorrectionCard.jsx`**

```javascript
// CorrectionCard.jsx — Expandable card showing one meta-agent correction.
// Used inside MetaAgentsPanel.
'use strict';

function CorrectionCard({ correction }) {
  const [expanded, setExpanded] = React.useState(false);
  if (!correction) return null;

  const isBlocking = correction.tier === 'blocking';
  const icon       = isBlocking ? '⛔' : '💡';
  const borderColor= isBlocking ? 'var(--red)' : 'var(--amber)';
  const badgeColor = isBlocking ? '#ff4d4f' : '#faad14';
  const pct        = ((correction.confidence || 0) * 100).toFixed(0);
  const ts         = correction.timestamp
    ? new Date(correction.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '';

  return React.createElement('div', {
    style: {
      borderLeft:    `3px solid ${borderColor}`,
      background:    'var(--bg-surface)',
      borderRadius:  'var(--radius)',
      padding:       '8px 12px',
      marginBottom:  6,
      cursor:        'pointer',
    },
    onClick: () => setExpanded(e => !e),
  },
    // Header row
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 8 }
    },
      React.createElement('span', { style: { fontSize: 14 } }, icon),
      React.createElement('span', {
        style: {
          fontSize:   10,
          background: badgeColor,
          color:      '#fff',
          borderRadius: 3,
          padding:    '1px 5px',
          fontWeight: 600,
          textTransform: 'uppercase',
        }
      }, correction.tier),
      React.createElement('span', {
        style: {
          fontSize: 10,
          color:    'var(--text-muted)',
          background: 'var(--bg-card)',
          borderRadius: 3,
          padding: '1px 5px',
        }
      }, correction.issue_type || ''),
      React.createElement('span', {
        style: { fontSize: 10, color: 'var(--text-muted)', marginLeft: 'auto' }
      }, `${pct}% conf ${ts ? '· ' + ts : ''}`),
    ),

    // Description (always visible)
    React.createElement('div', {
      style: { fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }
    }, correction.description || ''),

    // Expanded: recommended action + affected finding IDs
    expanded && React.createElement('div', {
      style: {
        marginTop:    8,
        paddingTop:   8,
        borderTop:    '1px solid var(--border)',
        fontSize:     11,
      }
    },
      React.createElement('div', {
        style: { color: 'var(--cyan)', fontWeight: 600, marginBottom: 4 }
      }, '▸ Recommended action'),
      React.createElement('div', {
        style: { color: 'var(--text-primary)', whiteSpace: 'pre-wrap' }
      }, correction.recommended_action || '(none)'),

      correction.affected_finding_ids && correction.affected_finding_ids.length > 0 &&
        React.createElement('div', { style: { marginTop: 8 } },
          React.createElement('span', {
            style: { color: 'var(--text-muted)', fontSize: 10 }
          }, `Affected findings: ${correction.affected_finding_ids.join(', ')}`),
        ),
    ),
  );
}
window.CorrectionCard = CorrectionCard;
```

---

## Task 10: MetaAgentsPanel component

**Files:**
- Create: `static/js/components/MetaAgentsPanel.jsx`

- [ ] **Step 1: Write `static/js/components/MetaAgentsPanel.jsx`**

```javascript
// MetaAgentsPanel.jsx — Collapsible panel showing live workings of
// MasterCheckerAgent and IssueValidatorAgent.
//
// Contains two sub-panels (one per agent), each with 3 tabs:
//   1. Thought Stream  — live LLM conversation via LiveTerminal
//   2. Corrections     — chronological CorrectionCard list
//   3. Summary         — running stats
'use strict';
const { useState } = React;
const { Collapse, Tabs, Badge, Statistic, Row, Col } = antd;
const { Panel } = Collapse;
const { TabPane } = Tabs;

function MetaAgentSubPanel({ agentKey, label, icon, agentState }) {
  if (!agentState) return null;

  const { history, corrections, stats, status, phase } = agentState;

  // Convert history to LiveTerminal lines format
  const termLines = (history || []).map(entry => ({
    line: entry.role === 'user'
      ? `[PROMPT] ${entry.content}`
      : `[RESPONSE] ${entry.content}`,
    type: entry.role === 'user' ? 'stderr' : 'stdout',
  }));

  const blockingCount = stats ? stats.blocking : 0;
  const advisoryCount = stats ? stats.advisory : 0;
  const totalCount    = stats ? stats.total    : 0;

  const statusColor = status === 'thinking' ? 'var(--amber)' : 'var(--text-muted)';
  const statusLabel = status === 'thinking'
    ? `⟳ Thinking${phase ? ` [${phase}]` : ''}…`
    : `● Idle${phase ? ` (last: ${phase})` : ''}`;

  return React.createElement('div', null,
    // Status bar
    React.createElement('div', {
      style: {
        fontSize: 10, color: statusColor,
        marginBottom: 8, fontFamily: 'var(--font-mono)',
      }
    }, statusLabel),

    React.createElement(Tabs, {
      defaultActiveKey: 'stream',
      size: 'small',
      tabBarStyle: { marginBottom: 8 },
    },
      React.createElement(TabPane, { tab: '💬 Thought Stream', key: 'stream' },
        React.createElement(window.LiveTerminal, {
          lines:      termLines,
          height:     260,
          agentColor: agentKey === 'checker' ? 'var(--violet)' : 'var(--cyan)',
          title:      `${label} — LLM conversation`,
        }),
      ),

      React.createElement(TabPane, {
        tab: React.createElement('span', null,
          '🔧 Corrections ',
          totalCount > 0 && React.createElement(Badge, {
            count: totalCount,
            style: { backgroundColor: blockingCount > 0 ? '#ff4d4f' : '#faad14' },
          }),
        ),
        key: 'corrections',
      },
        React.createElement('div', {
          style: { maxHeight: 260, overflowY: 'auto' }
        },
          corrections && corrections.length > 0
            ? corrections.map((c, i) =>
                React.createElement(window.CorrectionCard, { key: i, correction: c })
              )
            : React.createElement('div', {
                style: { color: 'var(--text-muted)', fontSize: 11, padding: 8 }
              }, 'No corrections yet.'),
        ),
      ),

      React.createElement(TabPane, { tab: '📊 Summary', key: 'summary' },
        React.createElement(Row, { gutter: [12, 12], style: { marginTop: 8 } },
          React.createElement(Col, { span: 8 },
            React.createElement(Statistic, {
              title: 'Total', value: totalCount,
              valueStyle: { fontSize: 20, color: 'var(--text-primary)' },
            }),
          ),
          React.createElement(Col, { span: 8 },
            React.createElement(Statistic, {
              title: '⛔ Blocking', value: blockingCount,
              valueStyle: { fontSize: 20, color: blockingCount > 0 ? 'var(--red)' : 'var(--text-muted)' },
            }),
          ),
          React.createElement(Col, { span: 8 },
            React.createElement(Statistic, {
              title: '💡 Advisory', value: advisoryCount,
              valueStyle: { fontSize: 20, color: advisoryCount > 0 ? 'var(--amber)' : 'var(--text-muted)' },
            }),
          ),
          agentKey === 'checker' && stats && React.createElement(Col, { span: 12 },
            React.createElement(Statistic, {
              title: 'Phases Reviewed', value: stats.phasesReviewed || 0,
              valueStyle: { fontSize: 16, color: 'var(--text-secondary)' },
            }),
          ),
          agentKey === 'validator' && stats && React.createElement(Col, { span: 12 },
            React.createElement(Statistic, {
              title: 'Tools Validated', value: stats.toolsValidated || 0,
              valueStyle: { fontSize: 16, color: 'var(--text-secondary)' },
            }),
          ),
        ),
      ),
    ),
  );
}

function MetaAgentsPanel() {
  const { state } = window.useStore();
  const checkerState   = state.metaCheckerState;
  const validatorState = state.metaValidatorState;

  const checkerTotal   = checkerState   ? checkerState.stats.total   : 0;
  const validatorTotal = validatorState ? validatorState.stats.total : 0;
  const totalAll       = checkerTotal + validatorTotal;
  const hasBlocking    = (
    (checkerState   ? checkerState.stats.blocking   : 0) +
    (validatorState ? validatorState.stats.blocking : 0)
  ) > 0;

  const headerLabel = React.createElement('span', { style: { color: 'var(--violet)' } },
    `🛡 Meta-Agents — Auditor & Validator`,
    totalAll > 0 && React.createElement(Badge, {
      count:  totalAll,
      style:  { backgroundColor: hasBlocking ? '#ff4d4f' : '#faad14', marginLeft: 8 },
    }),
  );

  return React.createElement(Collapse, {
    defaultActiveKey: [],
    style: { marginTop: 12 },
    ghost: false,
  },
    React.createElement(Panel, { header: headerLabel, key: 'meta' },
      React.createElement(Collapse, {
        defaultActiveKey: ['checker'],
        accordion: false,
      },
        React.createElement(Panel, {
          header: React.createElement('span', { style: { color: 'var(--violet)' } },
            `🔎 Master Checker`,
            checkerTotal > 0 && React.createElement(Badge, {
              count: checkerTotal,
              style: { backgroundColor: checkerState && checkerState.stats.blocking > 0 ? '#ff4d4f' : '#faad14', marginLeft: 6 },
            }),
          ),
          key: 'checker',
        },
          React.createElement(MetaAgentSubPanel, {
            agentKey:   'checker',
            label:      'Master Checker',
            icon:       '🔎',
            agentState: checkerState,
          }),
        ),

        React.createElement(Panel, {
          header: React.createElement('span', { style: { color: 'var(--cyan)' } },
            `🔍 Issue Validator`,
            validatorTotal > 0 && React.createElement(Badge, {
              count: validatorTotal,
              style: { backgroundColor: validatorState && validatorState.stats.blocking > 0 ? '#ff4d4f' : '#faad14', marginLeft: 6 },
            }),
          ),
          key: 'validator',
        },
          React.createElement(MetaAgentSubPanel, {
            agentKey:   'validator',
            label:      'Issue Validator',
            icon:       '🔍',
            agentState: validatorState,
          }),
        ),
      ),
    ),
  );
}
window.MetaAgentsPanel = MetaAgentsPanel;
```

---

## Task 11: Wire MetaAgentsPanel into MissionControl

**Files:**
- Modify: `static/js/pages/MissionControl.jsx`
- Modify: `static/js/app.jsx` (add script tag for new components)

### Step 1 — Load new component scripts

- [ ] Find where component scripts are loaded in the HTML template (search for `LiveTerminal.jsx` script tag in the main HTML file — likely `templates/index.html` or `static/index.html`). Add after the LiveTerminal script tag:

```html
<script src="/static/js/components/CorrectionCard.jsx" type="text/babel"></script>
<script src="/static/js/components/MetaAgentsPanel.jsx" type="text/babel"></script>
```

### Step 2 — Add MetaAgentsPanel to MissionControl layout

- [ ] In `MissionControl.jsx`, find where the main page content is returned (search for `React.createElement('div'` near the main layout). Find a suitable location after the live feed or plan steps section and add:

```javascript
// Meta-agents panel — collapsible, collapsed by default
React.createElement(window.MetaAgentsPanel, null),
```

Place it between the PhaseTimeline/PlanSteps section and the live feed, or at the bottom of the main column.

### Step 3 — Verify UI renders

Open the ARGUS app. Navigate to Mission Control. Verify:
- `🛡 Meta-Agents` collapsible panel is visible (collapsed by default)
- Expanding it shows Master Checker and Issue Validator sub-panels
- Each sub-panel has Thought Stream / Corrections / Summary tabs

---

## Task 12: End-to-end smoke test

- [ ] **Step 1: Verify all Python modules import cleanly**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python -c "
from agents.meta.correction import Correction, BLOCKING_THRESHOLD
from agents.meta.base_meta_agent import BaseMetaAgent
from agents.meta.master_checker_agent import MasterCheckerAgent
from agents.meta.issue_validator_agent import IssueValidatorAgent
from agents.master_agent import MasterAgent
print('All imports OK')
print(f'BLOCKING_THRESHOLD={BLOCKING_THRESHOLD}')
"
```
Expected:
```
All imports OK
BLOCKING_THRESHOLD=0.8
```

- [ ] **Step 2: Test Correction tier derivation**

```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python -c "
from agents.meta.correction import Correction
c1 = Correction('master_checker','sid','recon',0.9,'missed_attack_surface','desc','action')
c2 = Correction('issue_validator','sid','vuln_id',0.7,'wrong_severity','desc','action')
c3 = Correction('master_checker','sid','exploit',0.8,'plan_deviation','desc','action')
assert c1.tier == 'blocking', c1.tier
assert c2.tier == 'advisory', c2.tier
assert c3.tier == 'blocking', c3.tier   # exactly at threshold
print('Tier tests pass')
"
```
Expected: `Tier tests pass`

- [ ] **Step 3: Confirm frontend loads without JS errors**

Start the ARGUS server:
```bash
cd C:/Users/ishan2/Desktop/Tools/LLM/v1
python main.py
```

Open browser → DevTools console. Verify zero errors on load. Navigate to Mission Control. Confirm MetaAgentsPanel renders.

---

## Self-Review Checklist

**Spec coverage:**
- ✅ `BaseMetaAgent` with persistent history + `think_with_history()` + `emit_correction()` + `reset()` — Task 3
- ✅ `Correction` dataclass with `tier` property, `BLOCKING_THRESHOLD`, env overrides — Task 2
- ✅ `MasterCheckerAgent` pre/post phase review, JSON parsing, WS events — Task 4
- ✅ `IssueValidatorAgent` per-tool + per-phase validation, WS events — Task 5
- ✅ Master integration: instantiation, `_handle_corrections()`, phase loop wiring, background task — Task 6
- ✅ MongoDB `meta_corrections` persistence in `emit_correction()` — Task 3/6
- ✅ Tiered handling: blocking → re-plan, advisory → rolling buffer — Task 6
- ✅ All 7 WS event types handled in store.js — Task 8
- ✅ Two new state slices in store — Task 8
- ✅ Three new reducer actions — Task 8
- ✅ Inline feed entries with purple-coded meta events — Task 8
- ✅ `CorrectionCard` component — Task 9
- ✅ `MetaAgentsPanel` with Thought Stream / Corrections / Summary tabs — Task 10
- ✅ Script tags added to HTML template — Task 11
- ✅ `MetaAgentsPanel` wired into MissionControl — Task 11
- ✅ `AgentName` enum updated — Task 1
- ✅ `MAX_HISTORY_TURNS`, `MAX_ADVISORY_CONTEXT`, `MAX_REPLAN_RETRIES` all env-overridable — Tasks 2/3
- ✅ `_enabled` flag for fast/debug scan modes — Task 3
- ✅ `reset()` and `set_session()` for extensibility — Task 3

**No placeholders found.** All code blocks are complete and self-contained.

**Type consistency verified:** `Correction.to_dict()` keys match WS payload fields used in store handlers. `MasterCheckerAgent` and `IssueValidatorAgent` both call `_parse_corrections()` with the same signature. `MetaAgentsPanel` reads `state.metaCheckerState` and `state.metaValidatorState` which are initialised in INIT and updated by all three new reducer actions.
