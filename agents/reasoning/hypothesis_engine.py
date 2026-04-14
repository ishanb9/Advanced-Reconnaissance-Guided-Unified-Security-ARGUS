"""
agents/reasoning/hypothesis_engine.py

Converts accumulated pentest evidence into ranked, actionable hypotheses
via a structured LLM call. Each hypothesis describes a possible attack path,
its confidence level, what evidence supports it, what is still missing, and
what to do next to either validate or invalidate it.

This is the core component that transforms the system from "run every tool"
into "form a theory, then gather the minimum evidence to test it".

Usage
-----
    engine = HypothesisEngine(
        think_json_fn = master_agent.think_json,
        kb_fn         = master_agent._kb_context,
        session_id    = session_id,
    )
    hypotheses = await engine.generate_hypotheses(intel, negative_memory)
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, List, Optional

from agents.reasoning.negative_memory import NegativeMemory


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class Hypothesis:
    """A single testable attack theory with associated evidence and actions."""

    hypothesis_id:            str
    statement:                str    # e.g. "Apache 2.4.49 is exploitable via CVE-2021-41773"
    confidence:               float  # 0.0–1.0 from LLM assessment
    evidence_supporting:      List[str] = field(default_factory=list)
    required_evidence:        List[str] = field(default_factory=list)
    recommended_next_actions: List[str] = field(default_factory=list)
    attack_phase:             str       = "initial_access"
    mitre_technique:          Optional[str] = None
    validated:                bool      = False
    invalidated:              bool      = False
    iteration_number:         int       = 0
    created_at:               str       = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "hypothesis_id":            self.hypothesis_id,
            "statement":                self.statement,
            "confidence":               self.confidence,
            "evidence_supporting":      list(self.evidence_supporting),
            "required_evidence":        list(self.required_evidence),
            "recommended_next_actions": list(self.recommended_next_actions),
            "attack_phase":             self.attack_phase,
            "mitre_technique":          self.mitre_technique,
            "validated":                self.validated,
            "invalidated":              self.invalidated,
            "iteration_number":         self.iteration_number,
            "created_at":               self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Hypothesis":
        return cls(
            hypothesis_id            = d.get("hypothesis_id", str(uuid.uuid4())),
            statement                = d.get("statement", ""),
            confidence               = float(d.get("confidence", 0.5)),
            evidence_supporting      = list(d.get("evidence_supporting", [])),
            required_evidence        = list(d.get("required_evidence", [])),
            recommended_next_actions = list(d.get("recommended_next_actions", [])),
            attack_phase             = d.get("attack_phase", "initial_access"),
            mitre_technique          = d.get("mitre_technique"),
            validated                = bool(d.get("validated", False)),
            invalidated              = bool(d.get("invalidated", False)),
            iteration_number         = int(d.get("iteration_number", 0)),
            created_at               = d.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


# ---------------------------------------------------------------------------
# HypothesisEngine
# ---------------------------------------------------------------------------

class HypothesisEngine:
    """
    Generates ranked attack hypotheses from current pentest evidence.

    The engine makes a single structured LLM call that returns a JSON array
    of hypotheses. Hypotheses are sorted by confidence descending so the
    DecisionEngine can trivially pick the highest-confidence path.

    Parameters
    ----------
    think_json_fn:
        Async callable matching BaseAgent.think_json(prompt, system) → dict.
        All LLM calls go through this function so rate-limiting and retries
        are handled by the existing infrastructure.
    kb_fn:
        Async or sync callable matching _kb_context(query, ...) → str.
        Injects domain knowledge (playbooks) into the prompt.
    session_id:
        Active session identifier (for logging only).
    """

    # How many tokens to budget for the evidence summary
    _EVIDENCE_MAX_CHARS: int = 3000
    # How many tokens to budget for the negative-memory block
    _NEG_MEM_MAX_CHARS:  int = 1500

    def __init__(
        self,
        think_json_fn: Callable[..., Coroutine],
        kb_fn:         Callable[..., Any],
        session_id:    str,
    ) -> None:
        self._think_json  = think_json_fn
        self._kb          = kb_fn
        self._session_id  = session_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_hypotheses(
        self,
        intel:           dict,
        negative_memory: NegativeMemory,
        max_hypotheses:  int = 8,
        iteration:       int = 0,
    ) -> List[Hypothesis]:
        """
        Generate ranked attack hypotheses from current evidence.

        Parameters
        ----------
        intel:
            The master agent's _intel dict (current observation state).
        negative_memory:
            Registry of failed attempts — injected so the LLM never
            re-proposes exhausted paths.
        max_hypotheses:
            Upper bound on returned hypotheses.
        iteration:
            Current reasoning loop iteration number (for logging).

        Returns
        -------
        List[Hypothesis]
            Sorted by confidence descending. Empty list on LLM failure.
        """
        # ── Load engagement context (LLM-derived, replaces ctf_mode flag) ────
        eng_ctx_dict   = intel.get("engagement_context") or {}
        eng_type       = eng_ctx_dict.get("engagement_type", "pentest")
        objectives     = eng_ctx_dict.get("objectives") or intel.get("ctf_objectives") or []
        constraints    = eng_ctx_dict.get("constraints") or []
        approach       = eng_ctx_dict.get("approach_summary") or ""
        ctx_summary    = eng_ctx_dict.get("context_summary") or ""
        tools_excl     = set((eng_ctx_dict.get("tools_excluded") or []))
        obj_answers    = intel.get("ctf_answers") or {}

        evidence_summary = self._build_evidence_summary(intel)
        neg_mem_block    = negative_memory.to_context_block()
        kb_context       = await self._get_kb_context(intel)

        system_prompt = self._build_system_prompt(
            eng_type=eng_type,
            ctx_summary=ctx_summary,
            approach=approach,
            objectives=objectives,
            obj_answers=obj_answers,
            constraints=constraints,
        )
        user_prompt   = self._build_user_prompt(
            evidence_summary, neg_mem_block, kb_context, max_hypotheses,
            eng_type=eng_type,
            objectives=objectives,
            obj_answers=obj_answers,
            tools_excluded=tools_excl,
        )

        try:
            raw = await self._think_json(user_prompt, system_prompt)
        except Exception:
            return []

        hypotheses = self._parse_hypotheses(raw, iteration)
        # Sort by confidence descending
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses[:max_hypotheses]

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------

    # ── Per-engagement-type expert personas ──────────────────────────────────
    _PERSONAS: dict = {
        "pentest": (
            "You are an elite penetration tester with deep expertise in vulnerability "
            "research, exploit development, and offensive security. "
            "Think like a red team operator: correlate weak signals, identify the most "
            "likely path to compromise based on specific service versions and configurations. "
            "Prioritise hypotheses by realistic likelihood of success, not textbook severity."
        ),
        "ctf": (
            "You are an expert CTF (Capture The Flag) solver. "
            "Your mission is to answer specific challenge questions in order by running "
            "the minimum tools necessary. Think like a CTF player: look carefully for "
            "hidden flags (flag{...}), usernames, passwords, and paths in tool output, "
            "FTP servers, web directories, and config files. "
            "Map every hypothesis to the specific objective number it will answer."
        ),
        "forensics": (
            "You are a digital forensics expert and incident responder. "
            "Your role is to extract evidence, build timelines, and identify IOCs from "
            "files, disk images, memory dumps, or logs — WITHOUT modifying the evidence. "
            "Think like an investigator: identify artifacts, recover deleted data, "
            "analyse metadata, and correlate timestamps. "
            "Never suggest exploitation tools — this is a read-only analysis."
        ),
        "network_analysis": (
            "You are a network security analyst specialising in packet capture analysis. "
            "Your role is to identify anomalies, suspicious traffic patterns, protocol "
            "violations, C2 beacons, data exfiltration, and lateral movement in pcap files. "
            "Use tshark/Wireshark filters, protocol dissection, and statistical analysis. "
            "Never suggest port scanning or exploitation — analyse what you have."
        ),
        "malware_analysis": (
            "You are a malware analyst with expertise in reverse engineering and threat intelligence. "
            "Your role is to analyse suspicious files to identify capabilities, persistence "
            "mechanisms, C2 infrastructure, IOCs, and MITRE ATT&CK techniques. "
            "Use static analysis (strings, binwalk, xxd, file) and dynamic analysis indicators. "
            "Never execute the sample against live systems without isolation."
        ),
        "compliance": (
            "You are a security compliance auditor with expertise in CIS benchmarks, "
            "PCI-DSS, SOC2, ISO 27001, and NIST frameworks. "
            "Your role is to check specific controls, identify misconfigurations, "
            "and verify security baselines — passively and without exploitation. "
            "Map findings to specific compliance controls."
        ),
        "bug_bounty": (
            "You are a bug bounty hunter specialising in web and API security. "
            "Focus on OWASP Top 10, business logic flaws, authentication bypasses, "
            "and high-impact vulnerabilities. Work within the defined scope only. "
            "Think like an attacker but document clearly for triage."
        ),
        "red_team": (
            "You are a red team operator running a full adversary simulation. "
            "Think like an APT: use living-off-the-land techniques, maintain stealth, "
            "establish persistence, and move laterally to reach the crown jewels. "
            "Prioritise detection evasion and operational security."
        ),
        "custom": (
            "You are an adaptive security analyst. "
            "Follow the operator's specific instructions precisely. "
            "Derive your approach from the engagement objectives provided."
        ),
    }

    def _build_system_prompt(
        self,
        eng_type:    str   = "pentest",
        ctx_summary: str   = "",
        approach:    str   = "",
        objectives:  list  = None,
        obj_answers: dict  = None,
        constraints: list  = None,
    ) -> str:
        persona     = self._PERSONAS.get(eng_type, self._PERSONAS["custom"])
        obj_answers = obj_answers or {}
        objectives  = objectives  or []
        constraints = constraints or []

        parts = [persona]

        if ctx_summary:
            parts.append(f"\nENGAGEMENT CONTEXT:\n{ctx_summary}")

        if approach:
            parts.append(f"\nAPPROACH:\n{approach}")

        if constraints:
            parts.append("\nCONSTRAINTS (must follow):\n" + "\n".join(f"- {c}" for c in constraints))

        if objectives:
            answered = len(obj_answers)
            total    = len(objectives)
            parts.append(f"\nOBJECTIVES PROGRESS: {answered}/{total} completed")
            # Show first unanswered
            for i, obj in enumerate(objectives):
                if str(i) not in obj_answers:
                    q = obj.get("task") or obj.get("question") or str(obj)
                    sec = obj.get("section", "") if isinstance(obj, dict) else ""
                    parts.append(f"NEXT OBJECTIVE [{i+1}]: {(sec + ' — ') if sec else ''}{q}")
                    break

        parts.append(
            "\nYou must respond ONLY with valid JSON. No markdown fences. No prose."
        )
        return "\n".join(parts)

    def _build_user_prompt(
        self,
        evidence_summary: str,
        neg_mem_block:    str,
        kb_context:       str,
        max_hypotheses:   int,
        eng_type:         str  = "pentest",
        objectives:       list = None,
        obj_answers:      dict = None,
        tools_excluded:   set  = None,
    ) -> str:
        objectives    = objectives    or []
        obj_answers   = obj_answers   or {}
        tools_excluded= tools_excluded or set()

        sections = [
            f"=== CURRENT EVIDENCE ({eng_type.upper()}) ===",
            evidence_summary,
        ]

        # ── Objectives checklist (works for any engagement type) ──────────────
        if objectives:
            obj_lines = [f"=== OBJECTIVES ({len(obj_answers)}/{len(objectives)} complete) ==="]
            for i, obj in enumerate(objectives):
                q   = obj.get("task") or obj.get("question") or str(obj)
                sec = obj.get("section", "") if isinstance(obj, dict) else ""
                ans_data = obj_answers.get(str(i))
                if ans_data:
                    ans = ans_data.get("answer", "") if isinstance(ans_data, dict) else str(ans_data)
                    obj_lines.append(f"  [{i+1}] ✓ {q} → {ans}")
                else:
                    obj_lines.append(f"  [{i+1}] ○ {('(' + sec + ') ') if sec else ''}{q}")
            sections += ["", "\n".join(obj_lines)]

        if neg_mem_block:
            sections += ["", neg_mem_block]

        if kb_context:
            sections += ["", "=== RELEVANT KNOWLEDGE ===", kb_context]

        # ── Tool exclusion reminder ───────────────────────────────────────────
        if tools_excluded:
            sections += [
                "",
                "=== EXCLUDED TOOLS (DO NOT USE) ===",
                ", ".join(sorted(tools_excluded)),
            ]

        # ── Objective-first instruction (when objectives exist) ──────────────
        if objectives:
            first_pending = None
            for i, obj in enumerate(objectives):
                if str(i) not in obj_answers:
                    q = obj.get("task") or obj.get("question") or str(obj)
                    first_pending = f"[{i+1}] {q}"
                    break

            action_label = {
                "ctf":              "answer CTF objectives",
                "forensics":        "extract the requested evidence/artifacts",
                "network_analysis": "identify the requested network anomalies/IOCs",
                "malware_analysis": "extract the requested malware indicators",
                "compliance":       "verify the requested compliance controls",
            }.get(eng_type, "complete the requested objectives")

            sections += [
                "",
                f"Generate up to {max_hypotheses} hypotheses to {action_label}.",
                f"IMMEDIATE PRIORITY: {first_pending}" if first_pending else "All objectives complete — consider deeper investigation.",
                "",
                "Each hypothesis statement MUST reference the objective number it targets.",
                "recommended_next_actions must be EXACT tool commands — no vague descriptions.",
            ]
        else:
            sections += [
                "",
                f"Generate up to {max_hypotheses} hypotheses about the best next action.",
                "Prioritise actions most likely to advance the engagement given the evidence.",
            ]

        sections += [
            "",
            "Respond with a JSON object in EXACTLY this format:",
            "{",
            '  "hypotheses": [',
            '    {',
            '      "statement": "Objective [N]: <specific theory or approach>",',
            '      "confidence": 0.85,',
            '      "evidence_supporting": ["facts that support this approach"],',
            '      "required_evidence": ["what the tool output must show to confirm this"],',
            '      "recommended_next_actions": ["exact command, e.g. tshark -r file.pcap -Y http"],',
            '      "attack_phase": "initial_access|privesc|lateral|post_exploit|exfil|analysis|forensics",',
            '      "mitre_technique": "T1046"',
            '    }',
            '  ]',
            "}",
            "",
            "RULES:",
            "- confidence is a float 0.0–1.0",
            "- Do NOT repeat techniques in FAILED ATTEMPTS unless new evidence changes the approach",
            "- recommended_next_actions are verbatim shell commands",
            "- attack_phase for forensics/analysis: use 'analysis' or 'forensics'",
            "- Rank highest-confidence first",
        ]

        if tools_excluded:
            sections.append(f"- NEVER suggest these tools: {', '.join(sorted(tools_excluded))}")

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Evidence summarisation
    # ------------------------------------------------------------------

    def _build_evidence_summary(self, intel: dict) -> str:
        """
        Build a compact evidence digest for LLM injection.
        Stays under _EVIDENCE_MAX_CHARS to avoid context overflow.
        """
        lines = []

        target = intel.get("target", "unknown")
        lines.append(f"Target: {target}")

        # Engagement context header — always at top so LLM stays oriented
        eng_ctx  = intel.get("engagement_context") or {}
        eng_type = eng_ctx.get("engagement_type", "")
        if eng_type:
            lines.append(f"Engagement type: {eng_type.upper()}")
        # Objectives progress
        objectives  = eng_ctx.get("objectives") or intel.get("ctf_objectives") or []
        obj_answers = intel.get("ctf_answers") or {}
        if objectives:
            answered = len(obj_answers)
            total    = len(objectives)
            lines.append(f"Objectives: {answered}/{total} completed")
            for i, obj in enumerate(objectives):
                if str(i) not in obj_answers:
                    q = obj.get("task") or obj.get("question") or str(obj)
                    lines.append(f"Next: [{i+1}] {q}")
                    break

        # Open ports and services
        ports = intel.get("open_ports", [])
        if ports:
            port_strs = []
            for p in ports[:20]:
                if isinstance(p, dict):
                    port_num = p.get("port", "?")
                    svc      = p.get("service", "") or p.get("name", "")
                    ver      = p.get("version", "")
                    entry    = f"{port_num}"
                    if svc:
                        entry += f"/{svc}"
                    if ver:
                        entry += f" ({ver})"
                    port_strs.append(entry)
                else:
                    port_strs.append(str(p))
            lines.append(f"Open ports: {', '.join(port_strs)}")
        else:
            lines.append("Open ports: none yet")

        # Services
        services = intel.get("services", {})
        if services:
            svc_parts = []
            for port, svc in list(services.items())[:10]:
                if isinstance(svc, dict):
                    name = svc.get("name", "") or svc.get("service", "")
                    ver  = svc.get("version", "")
                    svc_parts.append(f"port {port}: {name} {ver}".strip())
                else:
                    svc_parts.append(f"port {port}: {svc}")
            lines.append("Services: " + " | ".join(svc_parts))

        # OS guess
        os_guess = intel.get("os_guess", "") or intel.get("os_info", {})
        if isinstance(os_guess, dict):
            os_str = os_guess.get("type", "") or os_guess.get("os", "")
        else:
            os_str = str(os_guess) if os_guess else ""
        if os_str and os_str not in ("unknown", ""):
            lines.append(f"OS: {os_str}")

        # Technologies
        techs = intel.get("technologies", [])
        if techs:
            lines.append(f"Technologies: {', '.join(str(t) for t in techs[:10])}")

        # Web
        web_paths = intel.get("web_paths", [])
        web_targets = intel.get("web_targets", [])
        all_web = list(web_targets) + [p for p in web_paths if p not in web_targets]
        if all_web:
            lines.append(f"Web endpoints: {', '.join(str(w) for w in all_web[:8])}")

        # Vulnerabilities
        vulns = intel.get("vulnerabilities", [])
        if vulns:
            lines.append(f"Vulnerabilities found: {len(vulns)}")
            for v in vulns[:5]:
                if isinstance(v, dict):
                    sev   = v.get("severity", "?")
                    title = v.get("title", v.get("name", str(v)))[:60]
                    lines.append(f"  [{sev}] {title}")

        # CVEs
        cves = intel.get("cves", [])
        if cves:
            lines.append(f"CVEs identified: {', '.join(str(c) for c in cves[:8])}")

        # Credentials
        creds = intel.get("credentials", [])
        if creds:
            lines.append(f"Credentials: {len(creds)} found")

        # Shell access
        if intel.get("shell_access"):
            user = intel.get("current_user", "unknown")
            lines.append(f"Shell access: YES (user={user})")
        else:
            lines.append("Shell access: NO")

        # Web vulns
        web_vulns = intel.get("web_vulns", [])
        if web_vulns:
            lines.append(f"Web vulns: {len(web_vulns)} found")
            for wv in web_vulns[:3]:
                if isinstance(wv, dict):
                    lines.append(f"  {wv.get('type','?')} — {wv.get('url','')[:50]}")

        # AD / domain
        domain_info = intel.get("domain_info", {})
        if isinstance(domain_info, dict) and domain_info.get("domain"):
            lines.append(
                f"AD Domain: {domain_info['domain']} | "
                f"DC: {domain_info.get('dc_ip','')} | "
                f"Users: {len(domain_info.get('users', []))}"
            )

        # Flags
        user_flag = intel.get("user_flag")
        root_flag = intel.get("root_flag")
        if user_flag:
            lines.append(f"User flag: CAPTURED")
        if root_flag:
            lines.append(f"Root flag: CAPTURED")

        summary = "\n".join(lines)
        if len(summary) > self._EVIDENCE_MAX_CHARS:
            summary = summary[:self._EVIDENCE_MAX_CHARS] + "\n[... truncated ...]"
        return summary

    # ------------------------------------------------------------------
    # KB context
    # ------------------------------------------------------------------

    async def _get_kb_context(self, intel: dict) -> str:
        """Build a relevant KB query from current evidence and fetch context."""
        try:
            # Build query from top services and technologies
            services  = intel.get("services", {})
            techs     = intel.get("technologies", [])
            cves      = intel.get("cves", [])

            query_parts = []
            for svc in list(services.values())[:3]:
                if isinstance(svc, dict):
                    name = svc.get("name", "") or svc.get("service", "")
                    ver  = svc.get("version", "")
                    if name:
                        query_parts.append(f"{name} {ver}".strip())
                elif svc:
                    query_parts.append(str(svc))

            query_parts.extend(str(t) for t in techs[:2])
            query_parts.extend(str(c) for c in cves[:2])

            if not query_parts:
                query_parts = ["penetration testing initial access exploit"]

            query = " ".join(query_parts)[:200]

            # Await coroutine if kb_fn is async, otherwise call directly
            import inspect
            result = self._kb(query, top_k=3)
            if inspect.iscoroutine(result):
                result = await result

            kb_str = result if isinstance(result, str) else ""
            if len(kb_str) > self._NEG_MEM_MAX_CHARS:
                kb_str = kb_str[:self._NEG_MEM_MAX_CHARS] + "\n[... truncated ...]"
            return kb_str
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_hypotheses(self, raw: Any, iteration: int) -> List[Hypothesis]:
        """
        Parse the LLM JSON response into Hypothesis objects.
        Gracefully handles malformed responses.
        """
        hypotheses: List[Hypothesis] = []

        if not raw:
            return hypotheses

        # Unwrap {"hypotheses": [...]} or bare list
        if isinstance(raw, dict):
            items = raw.get("hypotheses", raw.get("hypothesis", []))
            if isinstance(items, dict):
                items = [items]
        elif isinstance(raw, list):
            items = raw
        else:
            return hypotheses

        for item in items:
            if not isinstance(item, dict):
                continue
            statement = (item.get("statement") or "").strip()
            if not statement:
                continue

            try:
                confidence = float(item.get("confidence", 0.5))
                confidence = max(0.0, min(1.0, confidence))
            except (TypeError, ValueError):
                confidence = 0.5

            h = Hypothesis(
                hypothesis_id            = str(uuid.uuid4()),
                statement                = statement,
                confidence               = confidence,
                evidence_supporting      = [
                    str(e) for e in (item.get("evidence_supporting") or [])
                ],
                required_evidence        = [
                    str(e) for e in (item.get("required_evidence") or [])
                ],
                recommended_next_actions = [
                    str(a) for a in (item.get("recommended_next_actions") or [])
                ],
                attack_phase             = str(
                    item.get("attack_phase") or "initial_access"
                ),
                mitre_technique          = item.get("mitre_technique"),
                iteration_number         = iteration,
            )
            hypotheses.append(h)

        return hypotheses
