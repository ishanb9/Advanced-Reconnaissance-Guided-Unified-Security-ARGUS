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
    # Recommendation G — multi-step action sequencing
    step_index:               int       = 0     # 1-based position in plan
    depends_on_step:          Optional[int] = None
    parent_hypothesis_id:     Optional[str] = None
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
            "step_index":               self.step_index,
            "depends_on_step":          self.depends_on_step,
            "parent_hypothesis_id":     self.parent_hypothesis_id,
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
            step_index               = int(d.get("step_index", 0) or 0),
            depends_on_step          = d.get("depends_on_step"),
            parent_hypothesis_id     = d.get("parent_hypothesis_id"),
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
    _EVIDENCE_MAX_CHARS: int = 4000
    # How many tokens to budget for the negative-memory block
    _NEG_MEM_MAX_CHARS:  int = 2000
    # How many tokens to budget for state summary (prev actions + collected items)
    _STATE_MAX_CHARS:    int = 1500

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
        state_summary    = self._build_state_summary(intel)

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
            state_summary=state_summary,
        )

        try:
            raw = await self._think_json(user_prompt, system_prompt)
        except Exception:
            return []

        hypotheses = self._parse_hypotheses(raw, iteration, intel=intel)
        # Sort by confidence descending
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses[:max_hypotheses]

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------

    # ── Engagement-type flavour additions (injected into base persona) ─────────
    _ENG_ADDENDUM: dict = {
        "forensics": (
            "\nFORENSICS MODE: Analyse evidence WITHOUT modifying it. "
            "Focus on file metadata, deleted data recovery, timestamps, and IOC correlation. "
            "Never suggest exploitation tools — read-only analysis only."
        ),
        "network_analysis": (
            "\nNETWORK ANALYSIS MODE: Analyse pcap/traffic only. "
            "Use tshark/Wireshark filters, protocol dissection, and statistical analysis. "
            "Do NOT suggest port scanning or exploitation."
        ),
        "malware_analysis": (
            "\nMALWARE ANALYSIS MODE: Static analysis only (strings, binwalk, xxd, file, objdump). "
            "Identify capabilities, C2 infrastructure, IOCs, MITRE ATT&CK techniques. "
            "Do NOT execute the sample against live systems."
        ),
        "compliance": (
            "\nCOMPLIANCE MODE: Passively check controls against CIS/PCI-DSS/NIST. "
            "Map findings to specific compliance controls. No exploitation."
        ),
        "red_team": (
            "\nRED TEAM MODE: Think like an APT. "
            "Use living-off-the-land techniques, maintain stealth, prioritise detection evasion."
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
        obj_answers = obj_answers or {}
        objectives  = objectives  or []
        constraints = constraints or []

        parts = [
            "You are an expert penetration tester and CTF solver.",
            "",
            "Your objective is NOT to run tools blindly. Your objective is to THINK, REASON, "
            "and PROGRESS toward a foothold and final compromise using minimal, high-value actions.",
            "You must behave like a human penetration tester, not an automated scanner.",
            "",
            "GROUND-TRUTH RULES (MANDATORY — violation invalidates the proposal):",
            "G1. Only target services / ports / paths / technologies that appear in the",
            "    DISCOVERED INTEL section of this prompt. If WordPress was not detected,",
            "    do NOT run wpscan / wp-admin probes. If port 80 is filtered, do NOT run",
            "    HTTP enumeration on it.",
            "G2. Past-experience or knowledge-base hints are ADVISORY ONLY. They never",
            "    override the current scan's open_ports / services / web_tech_tags.",
            "G3. Do NOT propose actions whose target requires a service that the scan",
            "    has not yet observed. Wait for evidence first.",
            "G4. Output ONLY runnable shell commands or the special tokens 'unknown' /",
            "    'skip'. Never output prose, conditional pseudo-code (`if X then Y`),",
            "    English explanations, markdown, or step-by-step plans. The dispatcher",
            "    parses the FIRST WORD as the tool name — anything else is rejected.",
            "G5. Each suggested action must be a single command. Do NOT chain with `;`,",
            "    `&&`, `||`, or pipe to additional tools the dispatcher won't see.",
            "",
            "CORE RULES:",
            "1. Never suggest tools without specific reasoning backed by evidence.",
            "2. Always base every action on observable facts from the current state.",
            "3. Prioritize high-probability attack paths over exhaustive scanning.",
            "4. Never repeat failed techniques — check FAILED ATTEMPTS before proposing.",
            "5. Think in terms of footholds and pivots, not sequential phases.",
            "6. Correlate findings across services — a username on FTP may work on SSH.",
            "7. Revisit previously discovered paths when new credentials or access is gained.",
            "8. Treat engagements as puzzles — hidden clues, narrative hints, and correlations matter.",
            "",
            "TOOL DISCIPLINE:",
            "- Run nmap ONCE for initial discovery — do not repeat broad port scans.",
            "- Run directory brute force ONLY if a web service is confirmed.",
            "- Run brute force ONLY if specific credential indicators exist (usernames, hash format).",
            "- Prefer targeted single-tool commands over parallel scanner storms.",
            "- A single focused gobuster is worth more than 10 unfocused nmap scripts.",
            "",
            "CTF & PUZZLE BEHAVIOR (always apply when objectives are given):",
            "- Look for hidden files, directories, comments in source, and steganography.",
            "- Interpret narrative hints — names, items, story elements often encode clues.",
            "- Correlate collected items (keys, tokens, emblems) with services that accept them.",
            "- Revisit earlier access points after gaining new credentials or artifacts.",
            "- Many answers require reading output carefully, not running more tools.",
            "- A flag may be in a file, a web comment, an FTP file, or a service banner.",
        ]

        # Engagement-type specific addendum
        if eng_type in self._ENG_ADDENDUM:
            parts.append(self._ENG_ADDENDUM[eng_type])

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
            for i, obj in enumerate(objectives):
                if str(i) not in obj_answers:
                    q = obj.get("task") or obj.get("question") or str(obj)
                    sec = obj.get("section", "") if isinstance(obj, dict) else ""
                    parts.append(f"NEXT OBJECTIVE [{i+1}]: {(sec + ' — ') if sec else ''}{q}")
                    break

        parts.append(
            "\nYou MUST respond ONLY with valid JSON in the exact format specified. "
            "No markdown fences. No prose. No explanations outside the JSON."
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
        state_summary:    str  = "",
    ) -> str:
        objectives     = objectives     or []
        obj_answers    = obj_answers    or {}
        tools_excluded = tools_excluded or set()

        # ── Section 1: Current State ─────────────────────────────────────────
        sections = [
            f"=== TARGET STATE ({eng_type.upper()}) ===",
            evidence_summary,
        ]

        # ── Section 2: Objectives checklist ──────────────────────────────────
        if objectives:
            obj_lines = [f"\n=== OBJECTIVES ({len(obj_answers)}/{len(objectives)} complete) ==="]
            for i, obj in enumerate(objectives):
                q        = obj.get("task") or obj.get("question") or str(obj)
                sec      = obj.get("section", "") if isinstance(obj, dict) else ""
                ans_data = obj_answers.get(str(i))
                if ans_data:
                    ans = ans_data.get("answer", "") if isinstance(ans_data, dict) else str(ans_data)
                    obj_lines.append(f"  [{i+1}] ✓ {q} → {ans}")
                else:
                    obj_lines.append(f"  [{i+1}] ○ {('(' + sec + ') ') if sec else ''}{q}")
            sections += ["\n".join(obj_lines)]

        # ── Section 3: State awareness (previous actions + collected items) ──
        if state_summary:
            sections += ["", state_summary]

        # ── Section 4: Failed attempts ───────────────────────────────────────
        if neg_mem_block:
            sections += ["", "=== FAILED ATTEMPTS (DO NOT REPEAT THESE) ===", neg_mem_block]

        # ── Section 5: Excluded tools ─────────────────────────────────────────
        if tools_excluded:
            sections += [
                "",
                "=== EXCLUDED TOOLS (NEVER USE) ===",
                ", ".join(sorted(tools_excluded)),
            ]

        # ── Section 6: Knowledge base context ────────────────────────────────
        if kb_context:
            sections += ["", "=== RELEVANT KNOWLEDGE ===", kb_context]

        # ── Section 7: Immediate priority objective ───────────────────────────
        first_pending = None
        if objectives:
            for i, obj in enumerate(objectives):
                if str(i) not in obj_answers:
                    q = obj.get("task") or obj.get("question") or str(obj)
                    first_pending = f"[{i+1}] {q}"
                    break

        # ── Section 8: Required reasoning loop + output format ───────────────
        sections += [
            "",
            "=== REQUIRED REASONING LOOP ===",
            "Follow this exact 7-step methodology:",
            "",
            "1. OBSERVE   — Summarize ALL known information (ports, services, technologies,",
            "               findings, credentials, files, banners, hints).",
            "2. INTERPRET — Explain what the findings mean in a real-world pentesting context.",
            "               What attack surface does this expose? What is unusual?",
            "3. HYPOTHESIZE — Generate 2–3 specific foothold/answer paths based ONLY on evidence.",
            "               Each must be tied to a specific finding, not a generic idea.",
            "4. PRIORITIZE — Rank hypotheses by realistic probability of success.",
            "               Consider: service version, known vulns, objective alignment.",
            "5. DECIDE    — Choose ONLY 1 or 2 next actions. No more.",
            "               Each must directly test the top hypothesis.",
            "6. JUSTIFY   — Explain exactly WHY each action was chosen over alternatives.",
            "7. SUCCESS   — Define precisely what result would confirm success.",
        ]

        if first_pending:
            sections += [
                "",
                f"IMMEDIATE PRIORITY: Answer objective {first_pending}",
                "Your next_actions MUST directly progress toward answering this objective.",
            ]

        sections += [
            "",
            "=== STRICT OUTPUT FORMAT ===",
            "Return ONLY this JSON object. No other text:",
            "{",
            '  "observation": "complete summary of what you know right now — ports, services, banners, files, creds, flags",',
            '  "interpretation": "what these findings mean as attack surface — be specific, not generic",',
            '  "hypotheses": [',
            '    {',
            '      "idea": "specific attack or enumeration path tied to a real finding",',
            '      "confidence": 0.85,',
            '      "reason": "why this path is likely — cite specific evidence"',
            '    }',
            '  ],',
            '  "priority": [',
            '    "highest confidence hypothesis statement",',
            '    "second hypothesis statement"',
            '  ],',
            '  "next_actions": [',
            '    {',
            '      "action": "EXACT complete shell command with real IP/URL — e.g. gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt",',
            '      "tool": "tool name only — e.g. gobuster",',
            '      "target": "specific host/URL/service — e.g. http://10.10.10.5:80",',
            '      "mitre_technique": "ATT&CK ID covering this action — e.g. T1190, T1110.001, T1078, T1059.004 (REQUIRED — best-fit technique, sub-technique if applicable)",',
            '      "reason": "why this specific command tests the top hypothesis",',
            '      "expected_result": "what the output will look like on success",',
            '      "success_criteria": "exact string, file, or output that confirms the hypothesis"',
            '    }',
            '  ],',
            '  "avoid": [',
            '    "specific tool/technique to avoid and the reason — e.g. do not run nmap again, already have port map"',
            '  ]',
            "}",
            "",
            "HARD RULES FOR next_actions:",
            "- MAXIMUM 5 actions ordered by execution sequence (Recommendation G).",
            "- The 'action' field MUST be a complete executable shell command with actual IPs/URLs substituted in.",
            "- Do NOT use placeholder text like TARGET or VICTIM — use the real IP from the target state.",
            "- Do NOT repeat any tool+target combo that appears in FAILED ATTEMPTS.",
            "- Each action must test a different hypothesis (no redundant tool runs) UNLESS it is a follow-up step that depends on an earlier action's success.",
            "- If objectives are pending, at least one action must target answering the next objective.",
            "- The 'mitre_technique' field is REQUIRED. Use the most specific ATT&CK ID that covers the action (e.g. T1190 for public-facing exploit, T1110.001 for password brute force, T1078.001 for default credentials, T1059.004 for unix shell, T1003 for credential dumping).",
            "- If an action depends on a previous action succeeding (e.g. 'use captured creds to ssh in'), set 'depends_on_step' to that earlier step's index (1-based). Otherwise omit it.",
            "",
            "AVAILABLE KALI TOOLS:",
            "  Recon:    nmap, rustscan, masscan, whatweb, dnsrecon, dig, whois, curl",
            "  Web:      gobuster, ffuf, dirb, nikto, wpscan, droopescan, joomscan, davtest, wapiti",
            "  Exploit:  sqlmap, commix, dalfox, wfuzz, arjun, nuclei",
            "  Auth:     hydra, medusa, crackmapexec, evil-winrm, impacket-psexec",
            "  Enum:     enum4linux, smbmap, smbclient, snmpwalk, ldapsearch, rpcclient, smtp-user-enum",
            "  Post:     linpeas, winpeas, pspy, bloodhound-python, find, id, cat, ls",
            "  Crypto:   john, hashcat, openssl",
            "  Analysis: tshark, strings, binwalk, foremost, xxd, file, exiftool",
            "",
            "GOOD EXAMPLES:",
            "  'gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/big.txt -x php,txt,html'",
            "  'curl -s http://10.10.10.5/robots.txt'",
            "  'enum4linux -a 10.10.10.5'",
            "  'hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.5 ftp'",
            "  'nmap --script smb-vuln-ms17-010 -p 445 10.10.10.5'",
            "  'sqlmap -u http://10.10.10.5/login.php --data=\"user=a&pass=b\" --batch --level=3'",
        ]

        if tools_excluded:
            sections.append(
                f"\nNEVER suggest these tools under any circumstances: {', '.join(sorted(tools_excluded))}"
            )

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
    # State awareness helper
    # ------------------------------------------------------------------

    def _build_state_summary(self, intel: dict) -> str:
        """
        Build a compact STATE AWARENESS block for the prompt.
        Includes: last N reasoning journal entries (previous actions) and
        collected items (flags, credentials, interesting files, artifacts).
        """
        lines: List[str] = []

        # Previous actions from reasoning journal (last 5 entries)
        journal = intel.get("reasoning_journal", [])
        if journal:
            lines.append("=== PREVIOUS ACTIONS ===")
            for entry in journal[-5:]:
                lines.append(f"  {str(entry)[:120]}")

        # Collected items
        collected: List[str] = []

        # Flags and objective answers
        if intel.get("user_flag"):
            collected.append(f"user_flag captured: {intel['user_flag']}")
        if intel.get("root_flag"):
            collected.append(f"root_flag captured: {intel['root_flag']}")
        for k, v in (intel.get("ctf_answers") or {}).items():
            ans = v.get("answer", "") if isinstance(v, dict) else str(v)
            if ans:
                collected.append(f"objective_{k} answered: {ans[:60]}")

        # Credentials
        for c in (intel.get("credentials") or [])[:5]:
            if isinstance(c, dict):
                u = c.get("username", "") or c.get("user", "")
                p = c.get("password", "") or c.get("pass", "")
                if u or p:
                    collected.append(f"credential: {u}:{p[:30]}")
            elif c:
                collected.append(f"credential: {str(c)[:60]}")

        # Interesting files
        for f in (intel.get("interesting_files") or [])[:4]:
            collected.append(f"found_file: {str(f)[:60]}")

        # Shell access
        if intel.get("shell_access"):
            user = intel.get("current_user", "unknown")
            collected.append(f"shell_access: YES (user={user})")

        if collected:
            if lines:
                lines.append("")
            lines.append("=== COLLECTED ITEMS ===")
            for item in collected:
                lines.append(f"  {item}")

        summary = "\n".join(lines)
        if len(summary) > self._STATE_MAX_CHARS:
            summary = summary[:self._STATE_MAX_CHARS] + "\n[... truncated ...]"
        return summary

    # ------------------------------------------------------------------
    # Attack phase inference
    # ------------------------------------------------------------------

    def _infer_attack_phase(self, tool: str) -> str:
        """Infer MITRE-aligned attack phase from tool name."""
        t = (tool or "").lower().split()[0]  # first word of command
        if t in {"linpeas", "winpeas", "pspy", "sudo", "find", "id", "uname"}:
            return "privesc"
        if t in {"bloodhound-python", "impacket-secretsdump", "impacket-psexec",
                 "mimikatz", "rubeus", "kerbrute", "crackmapexec", "evil-winrm"}:
            return "lateral"
        if t in {"msfconsole", "msfvenom", "sqlmap", "commix", "dalfox",
                 "hydra", "medusa", "xsstrike", "wfuzz"}:
            return "initial_access"
        if t in {"tshark", "wireshark", "strings", "binwalk", "foremost",
                 "xxd", "file", "exiftool", "volatility"}:
            return "forensics"
        if t in {"cat", "ls", "wget", "curl", "nc", "python3", "bash", "sh"}:
            return "post_exploit"
        # Default: reconnaissance / initial access
        return "initial_access"

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_hypotheses(
        self,
        raw:       Any,
        iteration: int,
        intel:     dict = None,
    ) -> List[Hypothesis]:
        """
        Parse the LLM JSON response into Hypothesis objects.

        Handles both the new expert-methodology format:
            {observation, interpretation, hypotheses[], priority[], next_actions[], avoid[]}
        and the legacy format:
            {hypotheses: [{statement, confidence, recommended_next_actions, ...}]}

        Each next_action becomes one Hypothesis so the DecisionEngine can
        pick them sequentially (max 2 from the new format).
        """
        hypotheses: List[Hypothesis] = []

        if not raw:
            return hypotheses

        # ── New expert format ────────────────────────────────────────────────
        if isinstance(raw, dict) and (
            "next_actions" in raw or "observation" in raw or "avoid" in raw
        ):
            observation    = str(raw.get("observation")    or "").strip()
            interpretation = str(raw.get("interpretation") or "").strip()
            avoid_list     = [str(a) for a in (raw.get("avoid") or [])]
            hyp_list       = raw.get("hypotheses") or []
            next_actions   = raw.get("next_actions") or []

            # Store temporary context into intel for the reasoning loop to emit
            if intel is not None:
                if observation:
                    intel["_tmp_observation"]    = observation
                if interpretation:
                    intel["_tmp_interpretation"] = interpretation
                if avoid_list:
                    intel["_tmp_avoid"]          = avoid_list

            # Build confidence map: hypothesis idea → confidence
            hyp_conf: dict = {}
            for h in hyp_list:
                if isinstance(h, dict):
                    idea = (h.get("idea") or "").strip().lower()
                    try:
                        conf = float(h.get("confidence", 0.75))
                    except (TypeError, ValueError):
                        conf = 0.75
                    if idea:
                        hyp_conf[idea] = max(0.0, min(1.0, conf))

            # Default confidence from top hypothesis
            default_conf = max(hyp_conf.values()) if hyp_conf else 0.75

            # Recommendation G — accept 5-step plans with depends_on_step.
            # Each next_action becomes one Hypothesis but the dependency
            # graph is preserved on the Hypothesis so the DecisionEngine
            # can defer dependent steps until their parent has been
            # validated.  Steps with depends_on_step=N stay invalidated=
            # False but flagged ``_pending_step_dep`` so the engine skips
            # them this iteration (they fire next iteration once the
            # parent shows up validated).
            for idx, act in enumerate(next_actions[:5]):   # cap: 5 actions
                if not isinstance(act, dict):
                    continue

                action_cmd = str(act.get("action") or "").strip()
                tool_name  = str(act.get("tool")   or "").strip()
                target_str = str(act.get("target") or "").strip()
                reason     = str(act.get("reason") or "").strip()
                expected   = str(act.get("expected_result")  or "").strip()
                success_c  = str(act.get("success_criteria") or "").strip()
                # Recommendation F — MITRE technique restored to the
                # parser path so the Issue Validator (#14) gets its
                # strongest signal back.  Accept either field name; the
                # validator strips sub-techniques itself.
                mitre_id   = str(
                    act.get("mitre_technique")
                    or act.get("mitre")
                    or act.get("attack_technique")
                    or ""
                ).strip()
                # Recommendation G — depends_on_step is a 1-based index
                # into next_actions; the engine defers dependent steps
                # until their parent has been validated.
                dep_raw    = act.get("depends_on_step", act.get("depends_on"))
                try:
                    dep_step = int(dep_raw) if dep_raw not in (None, "", 0) else None
                except (TypeError, ValueError):
                    dep_step = None
                # Sanity: a step can only depend on a strictly earlier step.
                if dep_step is not None and (dep_step < 1 or dep_step > idx):
                    dep_step = None

                # Require at minimum a command or a tool
                if not action_cmd and not tool_name:
                    continue

                # Build the executable command
                cmd = action_cmd if action_cmd else f"{tool_name} {target_str}".strip()
                if not cmd:
                    continue

                # Extract tool from command if tool_name blank
                if not tool_name:
                    tool_name = cmd.split()[0]

                # Determine confidence — try to match to a hypothesis idea
                conf = default_conf * (0.95 ** idx)
                for idea, c in hyp_conf.items():
                    if (
                        tool_name.lower() in idea
                        or (reason and reason.lower()[:40] in idea)
                    ):
                        conf = c
                        break
                # First action gets a small priority bump
                if idx == 0:
                    conf = min(0.95, conf + 0.02)

                # Statement from reason, trimmed
                stmt = (reason or f"Run {tool_name} on {target_str}")[:160]

                # Evidence from observation + interpretation
                evidence: List[str] = []
                if observation:
                    evidence.append(observation[:200])
                if interpretation:
                    evidence.append(interpretation[:200])

                # Map 1-based dep step → parent hypothesis_id (resolved
                # after the loop because parents may be later in iteration
                # order than their dependents… but the schema says a step
                # can only depend on EARLIER steps, so by-index lookup is
                # safe to fill at append time).
                parent_id = None
                if dep_step is not None and 1 <= dep_step <= len(hypotheses):
                    parent_id = hypotheses[dep_step - 1].hypothesis_id

                h = Hypothesis(
                    hypothesis_id            = str(uuid.uuid4()),
                    statement                = stmt,
                    confidence               = max(0.0, min(1.0, conf)),
                    evidence_supporting      = evidence,
                    required_evidence        = [success_c] if success_c else [],
                    recommended_next_actions = [cmd],
                    attack_phase             = self._infer_attack_phase(tool_name),
                    mitre_technique          = mitre_id or None,
                    iteration_number         = iteration,
                    step_index               = idx + 1,           # 1-based
                    depends_on_step          = dep_step,
                    parent_hypothesis_id     = parent_id,
                )
                hypotheses.append(h)

            # If no next_actions provided, fall back to converting hypotheses[]
            # (gives the decision engine something to work with)
            if not hypotheses:
                for h_dict in hyp_list[:2]:
                    if not isinstance(h_dict, dict):
                        continue
                    idea = str(h_dict.get("idea") or "").strip()
                    if not idea:
                        continue
                    try:
                        conf = float(h_dict.get("confidence", 0.5))
                    except (TypeError, ValueError):
                        conf = 0.5
                    h = Hypothesis(
                        hypothesis_id            = str(uuid.uuid4()),
                        statement                = idea[:160],
                        confidence               = max(0.0, min(1.0, conf)),
                        evidence_supporting      = [observation] if observation else [],
                        required_evidence        = [],
                        recommended_next_actions = [],
                        attack_phase             = "initial_access",
                        mitre_technique          = None,
                        iteration_number         = iteration,
                    )
                    hypotheses.append(h)

            return hypotheses

        # ── Legacy format: {"hypotheses": [...]} or bare list ────────────────
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
