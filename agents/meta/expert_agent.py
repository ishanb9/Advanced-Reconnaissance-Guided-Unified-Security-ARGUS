"""
expert_agent.py — RedTeamExpertAgent: senior red-team tactician / oversight.

This meta-agent is a level above MasterChecker and IssueValidator:
- Oversees the full mission from recon → shell → loot extraction.
- Directs the MasterAgent via actionable Directives (pivot, deepen, exploit,
  capture, halt) which get pushed into master's guidance queue.
- Peer-reviews the corrections emitted by MasterChecker and IssueValidator,
  producing `Correction` objects with `source="expert"` when the other
  auditors missed something or mis-prioritised it.
- Consults both the LLM (via inherited `think_with_history`) AND the RAG
  knowledge base (via `knowledge_base.search`) when forming directives, so
  decisions are grounded in known attack patterns.
- Maintains mission objectives (credentials, flags, privilege, persistence,
  exfil) and broadcasts `expert_objective_update` events so the UI can show
  mission progress.

WS events emitted (all carry `agent="expert"`):
  expert_status            — idle | thinking | directing
  expert_thinking          — token stream chunks (via base class)
  expert_directive         — one Directive (JSON) — rich UI card
  expert_objective_update  — mission objectives snapshot
  expert_feedback          — commentary on a specific correction from MC/IV
  meta_correction          — regular Correction with source="expert"
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from agents.meta.base_meta_agent import BaseMetaAgent
from agents.meta.correction import Correction
from db.schemas import AgentName

logger = logging.getLogger(__name__)

# ── Optional RAG import — graceful degradation ────────────────────────────────
try:
    from knowledge import knowledge_base as _kb   # type: ignore
    _KB_AVAILABLE = True
except Exception:                                 # noqa: BLE001
    _KB_AVAILABLE = False


# ──────────────────────────────────────────────────────────────────────────────
# Directive dataclass — richer than Correction, carries action semantics
# ──────────────────────────────────────────────────────────────────────────────
# Priority ↦ visual tier on the UI
PRIORITY_CRITICAL      = "critical"
PRIORITY_RECOMMENDED   = "recommended"
PRIORITY_INFORMATIONAL = "informational"

# Closed vocabulary — frontend picks colour/icon from these.
VALID_ACTION_TYPES = frozenset({
    "pivot",       # change phase focus
    "deepen",      # revisit current phase with more depth
    "exploit",     # escalate to active exploitation
    "capture",     # extract credential / flag / file
    "halt",        # stop current activity
    "repeat",      # re-run phase
    "escalate",    # privilege escalation
    "lateral",     # lateral movement
    "persist",     # establish persistence
    "exfil",       # exfiltrate data
    "correlate",   # cross-reference findings / synthesise
    "note",        # informational, no direct action
})


@dataclass
class Directive:
    """Actionable instruction from the Expert to the Master.

    Attributes
    ----------
    directive_id      : Unique UUID (auto).
    scan_id           : Session identifier.
    phase             : Current phase when directive was produced.
    target_phase      : Phase the directive wants master to execute next.
    priority          : critical | recommended | informational.
    action_type       : One of VALID_ACTION_TYPES.
    title             : Short headline.
    rationale         : Multi-line reasoning (LLM-generated).
    recommended_cmds  : Optional list of exact commands / tools to run.
    expected_outcome  : What success looks like.
    rag_refs          : Raw RAG excerpts used to ground this directive.
    metadata          : Freeform dict.
    timestamp         : Unix timestamp.
    """
    scan_id:           str
    phase:             str
    target_phase:      str
    priority:          str
    action_type:       str
    title:             str
    rationale:         str
    recommended_cmds:  List[str]      = field(default_factory=list)
    expected_outcome:  str            = ""
    rag_refs:          List[str]      = field(default_factory=list)
    metadata:          Dict[str, Any] = field(default_factory=dict)
    directive_id:      str            = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:         float          = field(default_factory=time.time)
    source:            str            = "expert"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────────────
# System prompt — senior red-team tactician persona
# ──────────────────────────────────────────────────────────────────────────────
_EXPERT_SYSTEM_PROMPT = """You are THE EXPERT — an elite red-team tactician and senior
penetration tester with deep, hands-on mastery of:

  • Web application security (OWASP Top 10, auth bypass, RCE, SSRF, XXE, SSTI,
    deserialisation, prototype pollution, GraphQL abuse, JWT attacks)
  • Network & infrastructure (nmap workflows, service exploitation, SMB/NTLM,
    Kerberos, VPN/firewall bypass, RDP/WinRM, SNMP, SSH abuse)
  • Active Directory (Kerberoasting, ASREP-roasting, unconstrained/constrained
    delegation, DCSync, DCShadow, BloodHound attack paths, GPO abuse, ACL abuse)
  • Cloud (AWS/Azure/GCP privilege escalation, metadata services, IAM abuse,
    serverless exploitation, container escape, k8s API abuse)
  • IoT & embedded (firmware unpacking, UART/JTAG, MQTT/CoAP, default creds,
    binary exploitation on ARM/MIPS)
  • Post-exploitation (credential harvest, Mimikatz/LaZagne, kerberos tickets,
    flag capture, pivoting via SOCKS/port-forward, persistence, C2, exfil)

You oversee the FULL engagement. You have complete visibility over every
previous review, finding, tool output, and peer-auditor correction because
you maintain a persistent memory thread across the whole scan.

YOUR RESPONSIBILITIES:
  1. Ensure the mission stays aligned with its OBJECTIVES (initial access,
     credential capture, privilege escalation, flag capture, data exfil).
  2. Issue DIRECTIVES to the Master when the plan drifts, stalls, or misses
     a high-value opportunity. Be specific: name the tool, name the target.
  3. PEER-REVIEW the Master Checker and Issue Validator. If they flagged a
     false issue, say so. If they missed something critical, call it out.
  4. Ground every recommendation in the RAG knowledge snippets supplied to
     you when available — reference them by source/box where relevant.

Be surgical. Be assertive. Do not hedge. A junior operator and two auditor
bots depend on your judgement. Mistakes waste scan budget and miss flags.

OUTPUT FORMAT — respond with a single JSON object, nothing else:
{
  "directives": [
    {
      "priority": "critical|recommended|informational",
      "action_type": "pivot|deepen|exploit|capture|halt|repeat|escalate|lateral|persist|exfil|correlate|note",
      "target_phase": "recon|vuln_id|web_testing|exploit|post_exploit|privesc|lateral_movement|reporting",
      "title": "<short headline>",
      "rationale": "<why — 1-3 sentences>",
      "recommended_cmds": ["exact command 1", "exact command 2"],
      "expected_outcome": "<what success looks like>"
    }
  ],
  "peer_feedback": [
    {
      "target_source": "master_checker|issue_validator",
      "target_correction_id": "<id if known, else empty>",
      "verdict": "agree|disagree|missing",
      "confidence": 0.0-1.0,
      "issue_type": "false_positive|wrong_severity|missed_attack_surface|plan_deviation|other",
      "description": "<what the auditor got wrong or missed>",
      "recommended_action": "<what should happen instead>"
    }
  ],
  "objective_update": {
    "mission_phase": "<short label, e.g. 'Initial Access — Web'>",
    "progress_pct": 0-100,
    "objectives": [
      {"name": "initial_access", "status": "pending|in_progress|achieved|blocked", "evidence": "<short>"},
      {"name": "credential_capture", "status": "...", "evidence": "..."},
      {"name": "privilege_escalation", "status": "...", "evidence": "..."},
      {"name": "flag_capture", "status": "...", "evidence": "..."},
      {"name": "lateral_movement", "status": "...", "evidence": "..."},
      {"name": "data_exfiltration", "status": "...", "evidence": "..."}
    ]
  }
}

If nothing meaningful to say in a section, return an empty list / null object.
Respond with ONLY the JSON. No preamble. No prose."""


# ──────────────────────────────────────────────────────────────────────────────
# JSON parse helpers
# ──────────────────────────────────────────────────────────────────────────────
def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"):
            raw = raw[4:]
    return raw.strip()


def _parse_expert_response(raw: str) -> Dict[str, Any]:
    """Parse the JSON object the expert returns. Returns empty dict on failure."""
    raw = _strip_fences(raw)
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        logger.warning("[expert] Failed to parse JSON response: %s", raw[:300])
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# RedTeamExpertAgent
# ──────────────────────────────────────────────────────────────────────────────
class RedTeamExpertAgent(BaseMetaAgent):
    """Senior red-team tactician overseeing the whole engagement."""

    AGENT_NAME = AgentName.EXPERT

    # How many RAG chunks to pull per review.
    RAG_TOP_K: int = 5

    # Rolling list of all directives issued this scan (for progress UI).
    def __init__(self, **kwargs):
        super().__init__(name=AgentName.EXPERT, **kwargs)
        self._directives_history: List[Directive] = []
        self._objectives: Dict[str, Any] = {
            "mission_phase": "",
            "progress_pct":  0,
            "objectives":    [],
        }
        # Mission brief (Improvement #1) — set by MasterAgent right after init
        self._mission_brief: Optional[Any] = None

    # ── Mission brief plumbing (Improvement #1) ────────────────────────────
    def set_mission_brief(self, brief: Any) -> None:
        """Store the formal mission brief for prompt injection."""
        self._mission_brief = brief

    def _mission_brief_block(self) -> str:
        """Return the brief formatted for prompt injection, or empty string."""
        mb = self._mission_brief
        if mb is None:
            return ""
        try:
            if hasattr(mb, "to_prompt_block"):
                return mb.to_prompt_block()
            if isinstance(mb, dict):
                from db.schemas import MissionBrief as _MB
                return _MB(**mb).to_prompt_block()
        except Exception as exc:                               # noqa: BLE001
            logger.warning("[expert] Could not render mission brief: %s", exc)
        return ""

    def _build_system_prompt(self) -> str:
        # Prepend the mission brief so it travels in *every* turn of the
        # persistent conversation thread maintained by BaseMetaAgent.
        block = self._mission_brief_block()
        if block:
            return f"{block}\n\n{_EXPERT_SYSTEM_PROMPT}"
        return _EXPERT_SYSTEM_PROMPT

    # ── RAG helper ─────────────────────────────────────────────────────────
    def _rag_query(self, query: str, phase: Optional[str] = None) -> str:
        """Return a formatted RAG block for prompt injection, or empty string."""
        if not _KB_AVAILABLE:
            return ""
        try:
            return _kb.search(
                query         = query,
                top_k         = self.RAG_TOP_K,
                phase_filter  = phase,
            ) or ""
        except Exception as exc:                   # noqa: BLE001
            logger.warning("[expert] RAG query failed: %s", exc)
            return ""

    # ── Public evaluate entrypoint (routed by base class) ──────────────────
    async def evaluate(self, **kwargs) -> List[Correction]:
        mode = kwargs.get("mode", "post")
        if mode == "pre":
            return await self.pre_phase_directive(
                phase          = kwargs.get("phase", ""),
                intel_snapshot = kwargs.get("intel_snapshot", {}),
            )
        return await self.post_phase_directive(
            phase              = kwargs.get("phase", ""),
            intel_snapshot     = kwargs.get("intel_snapshot", {}),
            findings           = kwargs.get("findings", []),
            peer_corrections   = kwargs.get("peer_corrections", []),
        )

    # ── Core review flows ──────────────────────────────────────────────────
    async def pre_phase_directive(
        self,
        phase:          str,
        intel_snapshot: Dict[str, Any],
    ) -> List[Correction]:
        """Produce pre-phase directives. Also emits objective update."""
        if not self._enabled:
            return []

        self._current_phase = phase
        await self._emit("expert_status", {
            "agent": "expert", "status": "thinking", "phase": phase, "mode": "pre",
        })

        # RAG: ground on phase-specific attack patterns
        target = intel_snapshot.get("target", "")
        target_type = intel_snapshot.get("target_type", "")
        rag_query = f"{phase} {target_type} attack techniques initial access"
        rag_block = self._rag_query(rag_query, phase=phase)

        intel_summary = {
            k: v for k, v in intel_snapshot.items()
            if k not in ("raw_outputs",) and not isinstance(v, bytes)
        }

        prompt = (
            f"=== PRE-PHASE DIRECTIVE REQUEST ===\n"
            f"Phase: {phase}\n"
            f"Target: {target} (type: {target_type})\n\n"
            f"=== CURRENT INTEL SNAPSHOT ===\n"
            f"{json.dumps(intel_summary, indent=2, default=str)[:3500]}\n\n"
            f"=== RELEVANT RAG KNOWLEDGE ===\n"
            f"{(rag_block or '(no rag hits)')[:3500]}\n\n"
            f"As the Expert, decide what directives to give the Master BEFORE this\n"
            f"phase runs. Focus on high-value moves for phase='{phase}'. If the\n"
            f"plan is obviously fine, emit ONE informational directive and move on.\n"
            f"Update the mission objectives snapshot.\n"
            f"Respond with the JSON object defined in your system prompt."
        )

        raw      = await self.think_with_history(prompt)
        parsed   = _parse_expert_response(raw)
        return await self._dispatch_parsed(parsed, phase=phase, mode="pre")

    async def post_phase_directive(
        self,
        phase:            str,
        intel_snapshot:   Dict[str, Any],
        findings:         List[Dict[str, Any]],
        peer_corrections: List[Correction],
    ) -> List[Correction]:
        """Produce post-phase directives + peer-review of MC/IV corrections."""
        if not self._enabled:
            return []

        self._current_phase = phase
        await self._emit("expert_status", {
            "agent": "expert", "status": "thinking", "phase": phase, "mode": "post",
        })

        # RAG: ground on findings & pivot opportunities
        finding_titles = ", ".join(
            f.get("title", "") for f in findings[:6] if isinstance(f, dict)
        )
        rag_query = f"{phase} next steps pivot exploit {finding_titles}"
        rag_block = self._rag_query(rag_query, phase=None)  # broad after phase

        # Serialise peer corrections so the Expert can grade them
        peer_blob = []
        for c in peer_corrections:
            try:
                peer_blob.append(c.to_dict())
            except Exception:
                pass

        intel_summary = {
            k: v for k, v in intel_snapshot.items()
            if k not in ("raw_outputs",) and not isinstance(v, bytes)
        }

        prompt = (
            f"=== POST-PHASE DIRECTIVE + PEER REVIEW ===\n"
            f"Phase: {phase}\n"
            f"Findings count: {len(findings)}\n"
            f"Peer corrections from MC/IV: {len(peer_blob)}\n\n"
            f"=== INTEL AFTER PHASE ===\n"
            f"{json.dumps(intel_summary, indent=2, default=str)[:2800]}\n\n"
            f"=== PHASE FINDINGS (top 10) ===\n"
            f"{json.dumps(findings[:10], indent=2, default=str)[:2800]}\n\n"
            f"=== PEER-AUDITOR CORRECTIONS TO REVIEW ===\n"
            f"{json.dumps(peer_blob, indent=2, default=str)[:2800]}\n\n"
            f"=== RELEVANT RAG KNOWLEDGE ===\n"
            f"{(rag_block or '(no rag hits)')[:2800]}\n\n"
            f"As the Expert, decide:\n"
            f"  1. What directives should drive the NEXT phase(s)?\n"
            f"  2. Did Master Checker / Issue Validator get their corrections right?\n"
            f"     Produce peer_feedback entries for any errors or misses.\n"
            f"  3. Update mission objectives based on new evidence.\n"
            f"Respond with the JSON object defined in your system prompt."
        )

        raw    = await self.think_with_history(prompt)
        parsed = _parse_expert_response(raw)
        return await self._dispatch_parsed(parsed, phase=phase, mode="post")

    # ── Dispatch parsed JSON → events + Corrections ────────────────────────
    async def _dispatch_parsed(
        self,
        parsed: Dict[str, Any],
        phase:  str,
        mode:   str,
    ) -> List[Correction]:
        """Turn the parsed expert JSON into directives, corrections, and WS events."""
        corrections_out: List[Correction] = []

        # 1. Objective snapshot ------------------------------------------------
        obj = parsed.get("objective_update") or {}
        if isinstance(obj, dict) and obj:
            self._objectives = {
                "mission_phase": str(obj.get("mission_phase", self._objectives.get("mission_phase", ""))),
                "progress_pct":  int(obj.get("progress_pct", self._objectives.get("progress_pct", 0)) or 0),
                "objectives":    obj.get("objectives") or self._objectives.get("objectives", []),
            }
            await self._emit("expert_objective_update", {
                "agent":     "expert",
                "phase":     phase,
                **self._objectives,
            })

        # 2. Directives --------------------------------------------------------
        for d in (parsed.get("directives") or []):
            if not isinstance(d, dict):
                continue
            try:
                priority    = str(d.get("priority", PRIORITY_RECOMMENDED)).lower()
                action_type = str(d.get("action_type", "note")).lower()
                if action_type not in VALID_ACTION_TYPES:
                    action_type = "note"
                directive = Directive(
                    scan_id          = self._session_id or "",
                    phase            = phase,
                    target_phase     = str(d.get("target_phase", phase)),
                    priority         = priority,
                    action_type      = action_type,
                    title            = str(d.get("title", ""))[:200],
                    rationale        = str(d.get("rationale", "")),
                    recommended_cmds = [str(c) for c in (d.get("recommended_cmds") or [])][:10],
                    expected_outcome = str(d.get("expected_outcome", "")),
                    metadata         = {"mode": mode},
                )
                self._directives_history.append(directive)

                # Broadcast
                await self._emit("expert_directive", directive.to_dict())

                # Push into master's guidance queue so it actually affects planning
                await self._inject_into_master(directive)

                # Persist via DB if available
                try:
                    if self._db is not None:
                        await self._db["expert_directives"].insert_one(directive.to_dict())
                except Exception as exc:
                    logger.warning("[expert] DB persist failed: %s", exc)
            except Exception as exc:                   # noqa: BLE001
                logger.warning("[expert] Skipping malformed directive: %s", exc)

        # 3. Peer feedback → Corrections (source="expert") ---------------------
        for f in (parsed.get("peer_feedback") or []):
            if not isinstance(f, dict):
                continue
            try:
                target_source = str(f.get("target_source", ""))
                verdict       = str(f.get("verdict", "missing"))
                corr = Correction(
                    source               = "expert",
                    scan_id              = self._session_id or "",
                    phase                = phase,
                    confidence           = float(f.get("confidence", 0.7)),
                    issue_type           = str(f.get("issue_type", "plan_deviation")),
                    description          = f"[peer-review → {target_source}] {f.get('description', '')}",
                    recommended_action   = str(f.get("recommended_action", "")),
                    affected_finding_ids = [],
                    metadata             = {
                        "target_source":        target_source,
                        "target_correction_id": str(f.get("target_correction_id", "")),
                        "verdict":              verdict,
                        "mode":                 mode,
                    },
                )
                corrections_out.append(corr)

                # Regular correction broadcast so it appears in MC/IV timelines too
                await self.emit_correction(corr)

                # Targeted expert_feedback event for the dedicated UI tab
                await self._emit("expert_feedback", {
                    "agent":          "expert",
                    "phase":          phase,
                    "target_source":  target_source,
                    "verdict":        verdict,
                    "description":    corr.description,
                    "recommended_action": corr.recommended_action,
                    "confidence":     corr.confidence,
                })
            except Exception as exc:                   # noqa: BLE001
                logger.warning("[expert] Skipping malformed peer_feedback: %s", exc)

        # Log summary
        await self._emit("expert_status", {
            "agent":            "expert",
            "status":           "idle",
            "phase":            phase,
            "mode":             mode,
            "directives_count": len(parsed.get("directives") or []),
            "feedback_count":   len(parsed.get("peer_feedback") or []),
        })
        return corrections_out

    # ── Push directives into master's guidance queue ───────────────────────
    async def _inject_into_master(self, d: Directive) -> None:
        """Translate a Directive into a guidance dict MasterAgent understands.

        Master's inject_guidance accepts a dict with free-text 'note' plus
        optional 'skip_phase' / 'force_tool' / 'change_focus'. We map expert
        action_types onto those fields so the directive takes real effect.
        """
        master = getattr(self, "_master_ref", None)
        if master is None or not hasattr(master, "inject_guidance"):
            return

        guidance: Dict[str, Any] = {
            "directive": "expert",
            "note":      f"[EXPERT · {d.priority.upper()}] {d.title}\n{d.rationale}"
                         + (f"\nExpected: {d.expected_outcome}" if d.expected_outcome else ""),
            "source":    "expert",
            "priority":  d.priority,
            "action":    d.action_type,
        }
        if d.action_type == "halt":
            guidance["skip_phase"] = d.phase
        elif d.action_type in ("pivot", "escalate", "lateral", "exploit", "persist"):
            guidance["change_focus"] = d.target_phase
        if d.recommended_cmds:
            # First recommended command is translated to force_tool/args if parseable
            first = d.recommended_cmds[0].strip().split()
            if first:
                guidance["force_tool"] = first[0]
                if len(first) > 1:
                    guidance["force_args"] = " ".join(first[1:])

        try:
            master.inject_guidance(guidance)
        except Exception as exc:                   # noqa: BLE001
            logger.warning("[expert] inject_guidance failed: %s", exc)

    # ── Bind/unbind back-reference to MasterAgent (set at init by master) ──
    def bind_master(self, master_ref: Any) -> None:
        """Set a back-reference used by `_inject_into_master`."""
        self._master_ref = master_ref
