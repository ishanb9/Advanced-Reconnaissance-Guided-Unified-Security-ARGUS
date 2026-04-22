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
    "confidence": 0.0-1.0,
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
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
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
                phase          = kwargs.get("phase", ""),
                instructions   = kwargs.get("instructions", []),
                intel_snapshot = kwargs.get("intel_snapshot", {}),
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
        instructions    : List of Instruction objects (or dicts)
        intel_snapshot  : Current intel dict at time of planning
        """
        if not self._enabled:
            return []

        self._current_phase = phase

        # Serialise instructions for the LLM
        instr_list = []
        for i in instructions:
            if isinstance(i, dict):
                instr_list.append({
                    "tool":      i.get("tool", ""),
                    "args":      i.get("args", ""),
                    "target":    i.get("target", ""),
                    "reasoning": i.get("reasoning", ""),
                })
            else:
                instr_list.append({
                    "tool":      getattr(i, "tool", ""),
                    "args":      getattr(i, "args", ""),
                    "target":    getattr(i, "target", ""),
                    "reasoning": getattr(i, "reasoning", ""),
                })
        instr_text = json.dumps(instr_list, indent=2)

        # Summarise intel (avoid sending raw_outputs blob)
        intel_summary = {
            k: v for k, v in intel_snapshot.items()
            if k not in ("raw_outputs",) and not isinstance(v, bytes)
        }

        prompt = (
            f"PRE-PHASE REVIEW — Phase: {phase}\n\n"
            f"=== CURRENT INTEL SNAPSHOT ===\n"
            f"{json.dumps(intel_summary, indent=2, default=str)[:3000]}\n\n"
            f"=== PLANNED INSTRUCTIONS ({len(instructions)} total) ===\n"
            f"{instr_text[:3000]}\n\n"
            f"Review the planned instructions against the intel snapshot.\n"
            f"Identify any gaps, wrong tool choices, missing targets, or ordering issues.\n"
            f"Respond with a JSON array of corrections (empty array [] if none)."
        )

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
            ][:50],
            indent=2,
        )

        prompt = (
            f"POST-PHASE REVIEW — Phase: {phase}\n\n"
            f"=== TOOLS EXECUTED ===\n"
            f"{json.dumps(executed_tools)}\n\n"
            f"=== FINDINGS PRODUCED ({len(findings)} total, showing first 50) ===\n"
            f"{findings_text[:3000]}\n\n"
            f"=== NEW INTEL ADDED THIS PHASE ===\n"
            f"{json.dumps(intel_delta, indent=2, default=str)[:2000]}\n\n"
            f"Review what was executed and what was found.\n"
            f"Were the phase objectives met? Any missed attack surfaces or follow-ups?\n"
            f"Any tool failures that should be retried with different arguments?\n"
            f"Respond with a JSON array of corrections (empty array [] if none)."
        )

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
