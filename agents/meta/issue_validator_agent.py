"""
issue_validator_agent.py — Per-tool and per-phase findings validator.

Independently reviews raw tool outputs and stored findings to catch
false positives, missed severity ratings, and objectives gaps.
"""
from __future__ import annotations

import asyncio
import hashlib
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
        # ── Real finding GATE (event-driven, mirrors ErrorAnalyzer) ──────
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._stop_requested: bool = False
        self._seen_fp: set = set()
        self._master = None
        self._stats = {"total": 0, "accepted": 0, "rejected": 0,
                       "blocking": 0, "advisory": 0}

    def bind_master(self, master) -> None:
        """Back-ref so the gate can surface rejects to the operator transcript
        via master._pending_corrections (the channel the operator drains)."""
        self._master = master

    def _build_system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    # ── Deterministic WRITE-TIME gate (no LLM; safe in the hot path) ──────
    @staticmethod
    def _finding_fp(finding: Dict[str, Any]) -> str:
        import re as _re
        t = _re.sub(r"\W+", " ", str(finding.get("title") or finding.get("name") or "")).strip().lower()
        basis = "|".join([t, str(finding.get("host", "")), str(finding.get("port", "")),
                          str(finding.get("cve", ""))])
        return hashlib.sha1(basis.encode("utf-8", "ignore")).hexdigest()

    def validate_finding(self, finding: Dict[str, Any],
                         current_origin: Optional[Dict[str, str]] = None,
                         has_raw_output: bool = True) -> Dict[str, Any]:
        """Synchronous, deterministic verdict used as the WRITE-TIME gate.

        Rejects (a) a high/critical claim NOT backed by concrete evidence (or
        whose 'evidence' is actually a tool error), (b) a finding from a
        DIFFERENT engagement (foreign origin), (c) a duplicate.  Low / info /
        generic findings are ACCEPTED — the goal is to stop FAULTY high-severity
        trophies (the 'silly critical with no evidence' case), not to swallow
        legitimate low findings.

        ``has_raw_output`` MUST be False for operator/prose findings (whose
        'evidence' is a human-readable summary, not raw tool stdout).  When
        False the narrow raw-output grounding regexes are NOT applied — a
        high/critical is accepted as long as it carries *some* evidence — so
        real RCE/foothold/credential findings declared in prose are never
        hidden from the report.  Only with real tool stdout do we regex-ground."""
        title    = str(finding.get("title") or finding.get("name") or "")
        sev      = str(finding.get("severity") or "").lower()
        evidence = str(finding.get("evidence") or finding.get("raw_output")
                       or finding.get("output") or finding.get("description") or "")
        tool     = str(finding.get("tool") or "")
        mitre    = str(finding.get("mitre_technique") or finding.get("mitre") or "")
        cls = "generic"
        grounded = bool(evidence.strip())
        failure = False
        try:
            from agents.reasoning.issue_validator import validate_grounding, infer_class
            cls = infer_class(statement=title, mitre=mitre, tool=tool)
            _iv = validate_grounding(statement=title, mitre=mitre, tool=tool,
                                     stdout=evidence, issue_class=cls)
            grounded = bool(_iv.grounded)
            failure = bool(_iv.failure_signal)
        except Exception:
            pass
        # severity sanity — a high/critical MUST be evidence-backed
        if sev in ("critical", "high"):
            if not has_raw_output:
                # Operator/prose finding: no raw tool stdout to regex-ground.
                # Require SOME evidence (catches a totally bare 'Critical RCE')
                # but never apply the narrow raw-output regexes to prose, else
                # real RCE/foothold/cred findings would be hidden from the report.
                severity_ok = bool(evidence.strip())
            elif failure:
                severity_ok = False
            elif cls != "generic":
                severity_ok = grounded
            else:
                severity_ok = bool(evidence.strip())
        else:
            severity_ok = True
        # provenance — STRICT: when the current engagement origin is known, a finding MUST
        # carry a matching current-SESSION stamp.  A missing stamp or a PRIOR session's stamp
        # is stale/foreign → REJECTED, so no finding from a previous scan reaches the report.
        # (base_agent.store_finding now stamps every fresh finding with the live session, so a
        # genuine current finding always passes; only recalled/persisted stale items fail.)
        origin_ok = True
        _cur_sid = str((current_origin or {}).get("session_id", "") or "")
        if _cur_sid:
            o = finding.get("_origin") or {}
            origin_ok = str(o.get("session_id", "") or "") == _cur_sid
        # dedup
        fp = self._finding_fp(finding)
        duplicate = fp in self._seen_fp
        if not duplicate:
            self._seen_fp.add(fp)
        accept = severity_ok and origin_ok and not duplicate
        # Canonical, machine-readable reason codes — consumed verbatim by the
        # write-time gates (base_agent / base_subagent compare against these exact
        # strings), so they MUST stay short and stable.  "foreign-origin" covers
        # both a prior scan's stamp and a missing stamp when the current origin is
        # known (stale/foreign — must never reach the client report).
        reason = ("" if accept else
                  ("ungrounded" if not severity_ok else
                   "foreign-origin" if not origin_ok else
                   "duplicate"))
        return {"accept": accept, "grounded": grounded, "severity_ok": severity_ok,
                "origin_ok": origin_ok, "duplicate": duplicate, "cls": cls, "reason": reason}

    # ── Async queue consumer (stats + live broadcast off the hot path) ───
    def ingest_finding(self, finding: Dict[str, Any],
                       verdict: Optional[Dict[str, Any]] = None) -> None:
        """Non-blocking — hand a (finding, verdict) to the background loop for
        stats + live broadcast.  Safe to call from the write-time gate."""
        if not self._enabled:
            return
        try:
            self._queue.put_nowait((finding, verdict or {}))
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait(); self._queue.task_done()
                self._queue.put_nowait((finding, verdict or {}))
            except Exception:
                pass
        except Exception:
            pass

    def request_stop(self) -> None:
        self._stop_requested = True

    async def run(self) -> None:
        """Background loop — spawned at engagement start on the operator path."""
        if not self._enabled:
            return
        logger.info("[issue_validator] started for session %s", self._session_id)
        while not self._stop_requested:
            try:
                finding, verdict = await asyncio.wait_for(self._queue.get(), timeout=10.0)
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue
            try:
                await self._handle_finding(finding, verdict)
            except Exception as exc:                               # noqa: BLE001
                logger.warning("[issue_validator] handler error: %s", exc)
            finally:
                self._queue.task_done()
        logger.info("[issue_validator] stopped for session %s", self._session_id)

    async def _handle_finding(self, finding: Dict[str, Any], verdict: Dict[str, Any]) -> None:
        accept = bool(verdict.get("accept", True))
        reason = str(verdict.get("reason", ""))
        self._stats["total"] += 1
        if accept:
            self._stats["accepted"] += 1
        else:
            self._stats["rejected"] += 1
            self._stats["advisory"] += 1
            title = str(finding.get("title") or finding.get("name") or "finding")
            corr = None
            try:
                corr = Correction(
                    source="issue_validator", scan_id=self._session_id or "",
                    phase=self._current_phase or "", confidence=0.9,
                    issue_type="false_positive",
                    description=f"Finding gated out of the report ({reason}): {title}",
                    recommended_action=(f"Excluded from the client report ({reason}). "
                                        "Re-confirm with concrete current-session evidence "
                                        "before this is reported."),
                    affected_finding_ids=[str(finding.get("_id") or finding.get("id") or "")],
                )
                await self.emit_correction(corr)
                # Keep a rolling snapshot so the GUI can reconstruct the
                # corrections list even if an individual meta_correction WS
                # event is missed (the badge count + the list must agree).
                self._recent_corrections = ([corr.to_dict()]
                                            + list(getattr(self, "_recent_corrections", [])))[:60]
            except Exception:
                pass
            # live bridge: surface the rejection to the operator transcript.
            # master._pending_corrections is an asyncio.Queue (drained via
            # get_nowait), so push with put_nowait — NOT append.
            m = getattr(self, "_master", None)
            if corr is not None and m is not None and hasattr(m, "_pending_corrections"):
                try:
                    m._pending_corrections.put_nowait(corr)
                except Exception:
                    pass
        try:
            await self._emit("validation_analysis", {
                "agent":       "issue_validator",
                "accepted":    self._stats["accepted"],
                "rejected":    self._stats["rejected"],
                "last_reason": reason,
                "stats":       dict(self._stats),
                # Self-contained snapshot of the gated findings so the Corrections
                # tab is populated even if a per-item event was dropped.
                "corrections": list(getattr(self, "_recent_corrections", []))[:60],
            })
        except Exception:
            pass

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


# ── Per-session registry (mirrors error_analyzer) ───────────────────────
# Lets the write-time finding gate (base_agent.store_finding) look up THIS
# session's validator without threading it through constructors.
_GLOBAL_REGISTRY: Dict[str, "IssueValidatorAgent"] = {}


def register_validator(session_id: str, agent: "IssueValidatorAgent") -> None:
    if agent is None or not session_id:
        return
    _GLOBAL_REGISTRY[str(session_id)] = agent


def get_validator(session_id: str) -> Optional["IssueValidatorAgent"]:
    return _GLOBAL_REGISTRY.get(str(session_id or ""))


def unregister_validator(session_id: str) -> None:
    _GLOBAL_REGISTRY.pop(str(session_id or ""), None)


__all__ = [
    "IssueValidatorAgent",
    "register_validator", "get_validator", "unregister_validator",
    "_GLOBAL_REGISTRY",
]
