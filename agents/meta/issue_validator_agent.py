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
    "confidence": 0.0-1.0,
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
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    items = None
    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        try:
            from utils.json_tolerant import parse_lossy
            parsed, repairs = parse_lossy(raw)
            if parsed is not None:
                items = parsed
                if repairs:
                    logger.info(
                        "[issue_validator] recovered JSON via repairs: %s",
                        ", ".join(repairs[-3:]),
                    )
        except Exception:
            pass
    if not isinstance(items, list):
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
                tool_name       = kwargs.get("tool_name", ""),
                raw_output      = kwargs.get("raw_output", ""),
                stored_findings = kwargs.get("stored_findings", []),
                target          = kwargs.get("target", ""),
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
                    "id":       str(f.get("_id", f.get("id", ""))),
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "evidence": str(f.get("evidence", ""))[:200],
                }
                for f in stored_findings
            ][:30],
            indent=2,
        )

        prompt = (
            f"PER-TOOL VALIDATION — Tool: {tool_name} | Target: {target}\n\n"
            f"=== RAW TOOL OUTPUT (first 4000 chars) ===\n"
            f"{output_excerpt}\n\n"
            f"=== STORED FINDINGS ({len(stored_findings)} total) ===\n"
            f"{findings_text}\n\n"
            f"Compare the raw output against stored findings.\n"
            f"- Are any significant findings from the raw output missing?\n"
            f"- Are any stored findings clear false positives given this output?\n"
            f"- Are severity ratings correctly calibrated?\n"
            f"Respond with a JSON array of corrections (empty array [] if none)."
        )

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
                    "id":       str(f.get("_id", f.get("id", ""))),
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

        prompt = (
            f"PER-PHASE BATCH REVIEW — Phase: {phase}\n\n"
            f"=== SCAN OBJECTIVES ===\n"
            f"{objectives_text}\n\n"
            f"=== ALL FINDINGS THIS PHASE ({len(all_findings)} total, showing first 80) ===\n"
            f"{findings_text[:4000]}\n\n"
            f"Review the complete finding set for this phase:\n"
            f"- Duplicate findings stored under different titles for the same issue?\n"
            f"- Conflicting severity ratings for the same host/port across tools?\n"
            f"- Implied vulnerabilities that no single tool explicitly flagged?\n"
            f"- Objectives from the list above that are not addressed by any finding?\n"
            f"Respond with a JSON array of corrections (empty array [] if none)."
        )

        raw = await self.think_with_history(prompt)
        corrections = _parse_corrections(
            raw, source="issue_validator",
            scan_id=self._session_id or "", phase=phase,
        )

        for c in corrections:
            await self.emit_correction(c)

        # Calculate objectives coverage
        obj_covered = 0
        if scan_objectives:
            for obj in scan_objectives:
                obj_lower = obj.lower()[:20]
                if any(obj_lower in str(f).lower() for f in all_findings):
                    obj_covered += 1

        coverage = (
            f"{obj_covered}/{len(scan_objectives)}"
            if scan_objectives else "N/A"
        )

        await self._emit("meta_validator_phase", {
            "phase":               phase,
            "correction_count":    len(corrections),
            "objectives_coverage": coverage,
            "summary": (
                f"Phase batch review: {len(corrections)} correction(s), "
                f"objectives covered {coverage}"
            ),
        })

        logger.info(
            "[issue_validator] validate_phase_findings(%s): %d corrections",
            phase, len(corrections),
        )
        return corrections
