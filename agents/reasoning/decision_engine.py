"""
agents/reasoning/decision_engine.py

Converts ranked hypotheses into justified, executable actions.

Before executing ANY tool the DecisionEngine:
  1. Checks the hypothesis meets the confidence threshold
  2. Verifies the tool+service has not already failed (NegativeMemory)
  3. Forces the LLM to produce a PreExecutionPlan (objective + actions + fallbacks)
  4. Returns a JustifiedAction with reason/expected_outcome/success_criteria

This is the component that replaces "run every tool" with
"run the minimum action necessary to test the best hypothesis".

Scoring
-------
  +10  validated foothold (shell or flag obtained)
  +5   high-confidence finding confirmed
  +2   hypothesis partially validated
  -3   redundant scan (tool already run on same target)
  -5   irrelevant exploit attempt (confidence < 0.4 but ran anyway)
  -10  repeated failed action (same tool+service tried again)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from agents.reasoning.hypothesis_engine import Hypothesis
from agents.reasoning.attack_planner    import RankedAttackPath
from agents.reasoning.negative_memory   import NegativeMemory


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PreExecutionPlan:
    """
    Mandatory plan produced before any tool runs.
    Forces the LLM to reason about *why* an action is being taken.
    """
    objective:         str
    current_best_path: str
    required_actions:  List[str] = field(default_factory=list)
    fallback_paths:    List[str] = field(default_factory=list)
    risk_assessment:   str       = "medium"  # low|medium|high|critical

    def to_dict(self) -> dict:
        return {
            "objective":         self.objective,
            "current_best_path": self.current_best_path,
            "required_actions":  list(self.required_actions),
            "fallback_paths":    list(self.fallback_paths),
            "risk_assessment":   self.risk_assessment,
        }


@dataclass
class JustifiedAction:
    """
    A single executable action that has been approved by the DecisionEngine.
    Carries the full reasoning chain so the operator can audit every decision.
    """
    action_id:            str
    tool:                 str
    args:                 str
    target_service:       str
    reason:               str
    expected_outcome:     str
    success_criteria:     str
    hypothesis_id:        str
    confidence:           float
    requires_confirmation: bool = False
    plan:                 Optional[PreExecutionPlan] = None
    created_at:           str  = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "action_id":            self.action_id,
            "tool":                 self.tool,
            "args":                 self.args,
            "target_service":       self.target_service,
            "reason":               self.reason,
            "expected_outcome":     self.expected_outcome,
            "success_criteria":     self.success_criteria,
            "hypothesis_id":        self.hypothesis_id,
            "confidence":           self.confidence,
            "requires_confirmation": self.requires_confirmation,
            "plan":                 self.plan.to_dict() if self.plan else None,
            "created_at":           self.created_at,
        }


# Scoring deltas
_SCORE_FOOTHOLD:          int = +10
_SCORE_HIGH_CONF_FINDING: int = +5
_SCORE_PARTIAL_VALID:     int = +2
_SCORE_REDUNDANT_SCAN:    int = -3
_SCORE_IRRELEVANT_EXPLOIT: int = -5
_SCORE_REPEATED_FAILURE:  int = -10


# ---------------------------------------------------------------------------
# DecisionEngine
# ---------------------------------------------------------------------------

class DecisionEngine:
    """
    Selects the next action to execute based on ranked hypotheses.

    Parameters
    ----------
    think_json_fn:
        Async callable matching BaseAgent.think_json(prompt, system) → dict.
    emit_fn:
        Async broadcast callable — used to emit reasoning events to frontend.
    session_id:
        Active session identifier.
    auto_execute_threshold:
        Confidence floor for automatic execution (default 0.70).
        Actions below this threshold set requires_confirmation=True.
    """

    AUTO_EXECUTE_THRESHOLD: float = 0.70

    def __init__(
        self,
        think_json_fn:          Callable[..., Coroutine],
        emit_fn:                Callable[..., Any],
        session_id:             str,
        auto_execute_threshold: float = 0.70,
    ) -> None:
        self._think_json  = think_json_fn
        self._emit        = emit_fn
        self._session_id  = session_id
        self._threshold   = auto_execute_threshold
        self._action_score: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def select_action(
        self,
        hypotheses:      List[Hypothesis],
        intel:           dict,
        used_tools:      Dict[str, int],
        negative_memory: NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """
        Select the best actionable hypothesis and return a JustifiedAction.

        Returns None when:
          - No actionable hypotheses exist (all invalidated or empty)
          - The best hypothesis has no recommended_next_actions

        Sets requires_confirmation=True when confidence < threshold.

        Parameters
        ----------
        hypotheses:
            Sorted by confidence descending (from HypothesisEngine).
        intel:
            Current master agent _intel dict.
        used_tools:
            {tool_name: run_count} tracking for redundancy detection.
        negative_memory:
            Failed attempts registry for quick pre-flight checks.
        """
        target = intel.get("target", "")

        for hypothesis in hypotheses:
            if hypothesis.invalidated:
                continue
            if not hypothesis.recommended_next_actions:
                continue

            # Pick the first recommended action that hasn't been exhausted
            for action_str in hypothesis.recommended_next_actions:
                # Skip blank / malformed action strings from LLM output
                if not action_str or not action_str.strip():
                    continue

                tool, args, target_service = self._parse_action_str(
                    action_str, target
                )

                # Skip the sentinel "unknown" tool — unparseable LLM output
                if tool == "unknown":
                    continue

                # Skip if this exact tool+service combination already failed
                if negative_memory.has_failed_before(tool, target_service):
                    count = negative_memory.attempt_count(tool, target_service)
                    await self._emit_reasoning(
                        f"Skipping {tool} on {target_service} — failed {count}x previously"
                    )
                    continue

                # Detect redundant scan (same tool run 3+ times on same target)
                tool_key = f"{tool}:{target_service}"
                if used_tools.get(tool_key, 0) >= 3:
                    await self._emit_reasoning(
                        f"Skipping redundant scan: {tool} on {target_service} "
                        f"already run {used_tools[tool_key]}x"
                    )
                    continue

                # Build pre-execution plan
                plan = await self.build_pre_execution_plan(hypothesis, intel)

                action = JustifiedAction(
                    action_id            = str(uuid.uuid4()),
                    tool                 = tool,
                    args                 = args,
                    target_service       = target_service,
                    reason               = self._build_reason(hypothesis),
                    expected_outcome     = hypothesis.recommended_next_actions[0],
                    success_criteria     = self._build_success_criteria(hypothesis),
                    hypothesis_id        = hypothesis.hypothesis_id,
                    confidence           = hypothesis.confidence,
                    requires_confirmation = hypothesis.confidence < self._threshold,
                    plan                 = plan,
                )

                await self._emit_action(action)
                return action

        return None

    async def build_pre_execution_plan(
        self,
        hypothesis: Hypothesis,
        intel:      dict,
    ) -> PreExecutionPlan:
        """
        Force the LLM to produce an explicit plan before any tool runs.

        Returns a safe fallback plan on LLM failure.
        """
        system = (
            "You are a penetration tester about to execute an attack step. "
            "Before running any tool you must articulate your objective, the "
            "specific path you are following, the ordered actions required, and "
            "fallback options if the primary path fails. "
            "Respond ONLY with valid JSON. No markdown."
        )

        target = intel.get("target", "unknown")
        shell  = "YES" if intel.get("shell_access") else "NO"

        prompt = (
            f"Target: {target}\n"
            f"Shell access: {shell}\n"
            f"Hypothesis: {hypothesis.statement}\n"
            f"Confidence: {hypothesis.confidence:.2f}\n"
            f"Supporting evidence: {', '.join(hypothesis.evidence_supporting[:3])}\n"
            f"Next actions proposed: {', '.join(hypothesis.recommended_next_actions[:3])}\n\n"
            "Produce a pre-execution plan in EXACTLY this JSON format:\n"
            "{\n"
            '  "objective": "specific goal of this action",\n'
            '  "current_best_path": "brief description of the attack path",\n'
            '  "required_actions": ["ordered list of exact tool commands"],\n'
            '  "fallback_paths": ["alternative approaches if primary fails"],\n'
            '  "risk_assessment": "low|medium|high|critical"\n'
            "}"
        )

        try:
            raw = await self._think_json(prompt, system)
            if raw and isinstance(raw, dict):
                return PreExecutionPlan(
                    objective         = str(raw.get("objective", hypothesis.statement)),
                    current_best_path = str(raw.get("current_best_path", "")),
                    required_actions  = [
                        str(a) for a in (raw.get("required_actions") or [])
                    ],
                    fallback_paths    = [
                        str(f) for f in (raw.get("fallback_paths") or [])
                    ],
                    risk_assessment   = str(raw.get("risk_assessment", "medium")),
                )
        except Exception:
            pass

        # Safe fallback
        return PreExecutionPlan(
            objective         = hypothesis.statement,
            current_best_path = hypothesis.statement,
            required_actions  = list(hypothesis.recommended_next_actions[:3]),
            fallback_paths    = [],
            risk_assessment   = "medium",
        )

    async def score_action_result(
        self,
        action:       JustifiedAction,
        result:       dict,
        validated:    bool,
        intel:        dict,
    ) -> Tuple[int, str]:
        """
        Apply scoring rules and return (new_total_score, reason_string).

        Called by ReasoningLoop._update() after every tool execution.
        """
        delta  = 0
        reason = ""

        # Foothold obtained
        if intel.get("shell_access") and not result.get("_was_shell_before", False):
            delta  += _SCORE_FOOTHOLD
            reason  = "Foothold obtained — shell access confirmed"

        # Flag captured
        elif intel.get("user_flag") or intel.get("root_flag"):
            delta  += _SCORE_FOOTHOLD
            reason  = "Flag captured"

        # High-confidence finding validated
        elif validated and action.confidence >= 0.7:
            delta  += _SCORE_HIGH_CONF_FINDING
            reason  = f"High-confidence finding validated (conf={action.confidence:.2f})"

        # Partial validation
        elif validated:
            delta  += _SCORE_PARTIAL_VALID
            reason  = "Hypothesis partially validated"

        # Repeated failure (negative memory already had this)
        elif not validated and action.confidence < 0.4:
            delta  += _SCORE_IRRELEVANT_EXPLOIT
            reason  = f"Low-confidence exploit attempt failed (conf={action.confidence:.2f})"

        # Not validated — neutral, no penalty for honest attempts
        else:
            reason = "Action executed — hypothesis not yet validated"

        self._action_score += delta
        return self._action_score, reason

    def get_score(self) -> int:
        """Return the current cumulative engagement score."""
        return self._action_score

    def set_score(self, score: int) -> None:
        """Restore score from checkpoint."""
        self._action_score = score

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_action_str(
        self,
        action_str: str,
        target:     str,
    ) -> Tuple[str, str, str]:
        """
        Parse an action string like "sqlmap -u http://TARGET/login" into
        (tool, args, target_service).

        Falls back gracefully when the string is not a recognisable command.
        """
        action_str = action_str.strip()
        parts      = action_str.split(None, 1)  # split on first whitespace
        tool       = parts[0].lower() if parts else "unknown"
        args       = parts[1] if len(parts) > 1 else ""

        # Derive a target_service identifier from the args or tool name
        target_service = self._infer_target_service(tool, args, target)

        return tool, args, target_service

    def _infer_target_service(self, tool: str, args: str, target: str) -> str:
        """
        Attempt to derive a "service:port" identifier from tool and args.
        Used for NegativeMemory dedup and redundancy detection.
        """
        combined = (args or "").lower()

        # Port patterns
        import re
        port_match = re.search(r':(\d{2,5})', combined)
        if port_match:
            port = port_match.group(1)
            # Guess service from port
            service_map = {
                "21": "ftp", "22": "ssh", "23": "telnet",
                "25": "smtp", "53": "dns", "80": "http",
                "110": "pop3", "143": "imap", "389": "ldap",
                "443": "https", "445": "smb", "1433": "mssql",
                "1521": "oracle", "3306": "mysql", "3389": "rdp",
                "5432": "postgresql", "5900": "vnc", "6379": "redis",
                "8080": "http", "8443": "https", "8888": "http",
            }
            svc = service_map.get(port, "tcp")
            return f"{svc}:{port}"

        # Tool → service inference
        tool_service = {
            "sqlmap":     f"http:80",
            "hydra":      f"ssh:22",
            "crackmapexec": f"smb:445",
            "nmap":       f"scan:{target}",
            "gobuster":   f"http:80",
            "ffuf":       f"http:80",
            "nikto":      f"http:80",
            "dirb":       f"http:80",
            "wpscan":     f"http:80",
            "msfconsole": f"exploit:{target}",
            "searchsploit": f"exploit:{target}",
            "impacket-secretsdump": f"smb:445",
            "evil-winrm": f"winrm:5985",
            "bloodhound-python": f"ldap:389",
        }
        return tool_service.get(tool, f"{tool}:{target}")

    def _build_reason(self, hypothesis: Hypothesis) -> str:
        """Format a justification string from a hypothesis."""
        evidence = " | ".join(hypothesis.evidence_supporting[:2])
        return (
            f"Hypothesis: {hypothesis.statement[:80]}. "
            f"Confidence: {hypothesis.confidence:.2f}. "
            f"Evidence: {evidence}"
        )

    def _build_success_criteria(self, hypothesis: Hypothesis) -> str:
        """Derive success criteria from the hypothesis required_evidence."""
        if hypothesis.required_evidence:
            return "Confirm: " + " AND ".join(hypothesis.required_evidence[:2])
        return "Hypothesis validated — action produced expected output"

    async def _emit_reasoning(self, message: str) -> None:
        """Emit a reasoning trace event to the frontend."""
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       "reasoning_decision",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       {"message": message, "component": "decision_engine"},
                })
        except Exception:
            pass

    async def _emit_action(self, action: JustifiedAction) -> None:
        """Emit a justified_action event to the frontend."""
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       "justified_action",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       action.to_dict(),
                })
        except Exception:
            pass
