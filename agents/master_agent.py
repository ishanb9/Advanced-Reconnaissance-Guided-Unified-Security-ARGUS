"""
ARGUS — Master Agent

Architecture:
  MasterAgent is the SOLE agent that communicates with the LLM.
  It does NOT execute tools directly. It:
    1. Checks LLM availability (halts if offline)
    2. Consults LLM to plan each phase
    3. Issues typed Instructions to specialist slave agents
    4. Receives results back via AgentBus
    5. Re-consults LLM to decide next steps based on results
    6. Broadcasts all reasoning to frontend so users see every decision

Pentest Methodology (OSCP/OSWE inspired):
  RECON → ENUM → VULN_ID → WEB_TESTING → EXPLOIT → POST_EXPLOIT → PRIVESC → REPORTING
  
  Each phase is LLM-driven: master asks "given these results, what should I try next?"
  If LLM is unresponsive at ANY point, testing stops and user is notified.
"""

import asyncio
import json
import os
import re
import sys
from typing import Optional, Dict, List
from datetime import datetime

from agents.base_agent import BaseAgent, Instruction, agent_bus, BroadcastFn
from db.schemas import (
    AgentName, AgentStatus, AttackPhase, FindingSeverity,
    SessionStatus, WebSocketMessage
)
import db.mongo_client as db

# ── RAG Knowledge Base (graceful degradation if not installed) ─────────────────
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "knowledge"))
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "knowledge"))
    import knowledge_base as _kb
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False

def _kb_context(
    query: str,
    phase: str = None,
    outcome: str = None,
    phase_filter: str = None,
    outcome_filter: str = None,
    chunk_type_filter: str = None,
    top_k: int = 4
) -> str:
    """Return KB context string ready for LLM injection, or '' if KB not available/empty.
    Accepts both phase=/outcome= and phase_filter=/outcome_filter= naming conventions.
    chunk_type_filter: one of 'command', 'script', 'procedure', 'technique', 'tip', 'finding'
    """
    if not _KB_AVAILABLE:
        return ""
    _phase   = phase_filter or phase or None
    _outcome = outcome_filter or outcome or None
    try:
        return _kb.search(
            query,
            top_k=top_k,
            phase_filter=_phase,
            outcome_filter=_outcome,
            chunk_type_filter=chunk_type_filter,
        )
    except Exception:
        return ""


def _kb_commands(query: str, top_k: int = 4) -> str:
    """
    Fetch command-type KB chunks for the query and format them for LLM injection.
    Returns specific tool invocations, command-line examples, and exploit commands.
    Falls back to any chunk type if no command chunks found.
    """
    if not _KB_AVAILABLE:
        return ""
    try:
        commands = _kb.search_commands(query, top_k=top_k)
        if not commands:
            return ""
        lines = [
            "=== RELEVANT COMMANDS FROM KNOWLEDGE BASE ===",
        ]
        for i, cmd in enumerate(commands, 1):
            lines.append(f"[Example {i}]\n{cmd.strip()}")
        lines.append("=== END COMMANDS ===")
        lines.append("Adapt the above commands to your current target.")
        return "\n\n".join(lines)
    except Exception:
        return ""


def _kb_procedures(query: str, top_k: int = 3) -> str:
    """
    Fetch procedure-type KB chunks (step-by-step attack procedures).
    Returns numbered step sequences from writeups/reports.
    """
    if not _KB_AVAILABLE:
        return ""
    try:
        procs = _kb.search_procedures(query, top_k=top_k)
        if not procs:
            return ""
        lines = [
            "=== RELEVANT ATTACK PROCEDURES FROM KNOWLEDGE BASE ===",
        ]
        for i, proc in enumerate(procs, 1):
            lines.append(f"[Procedure {i}]\n{proc.strip()}")
        lines.append("=== END PROCEDURES ===")
        return "\n\n".join(lines)
    except Exception:
        return ""


def _fmt_svc(svc) -> str:
    """Convert a service value (dict OR str) to a readable string."""
    if isinstance(svc, dict):
        parts = []
        if svc.get("port"):
            parts.append(f"{svc['port']}/{svc.get('protocol','tcp')}")
        if svc.get("service"):
            parts.append(svc["service"])
        if svc.get("version"):
            parts.append(svc["version"])
        return " ".join(parts) if parts else str(svc)
    return str(svc) if svc else ""


def _fmt_svcs(svcs_dict, limit: int = 8) -> str:
    """Convert a services dict {port: dict|str} to a joined string for LLM prompts."""
    return " | ".join(
        _fmt_svc(v) for v in list(svcs_dict.values())[:limit]
    )


def _fmt_list(lst, limit: int = 8) -> str:
    """Safely convert any list of str|dict items to a joined string."""
    return " | ".join(
        (_fmt_svc(v) if isinstance(v, dict) else str(v))
        for v in list(lst)[:limit]
        if v
    )


def _safe_join(lst, sep: str = " ") -> str:
    """Join any list safely — handles str, dict, int, or mixed items.
    Used wherever LLM-returned lists are joined (LLM may return dicts instead of strings).
    """
    parts = []
    for item in (lst or []):
        if isinstance(item, dict):
            val = (item.get("name") or item.get("service") or item.get("title") or
                   item.get("type") or item.get("key") or item.get("value") or str(item))
            parts.append(str(val))
        else:
            parts.append(str(item))
    return sep.join(parts)


def _safe_list(val, default=None) -> list:
    """
    Return val as a list, or default/[] if val is None/non-list.
    Fixes 'NoneType not subscriptable' when LLM returns null for a list field.
    LLM JSON: {"steps": null} → .get("steps", []) returns None (key exists!)
    This wrapper ensures we always get an iterable.
    """
    if val is None:
        return default if default is not None else []
    if isinstance(val, list):
        return val
    if isinstance(val, dict):
        return [val]  # single dict → wrap in list
    return []


def _safe_str(val, default: str = "") -> str:
    """Return val as str, or default if None. Prevents None[:N] crashes."""
    if val is None:
        return default
    return str(val)


def _safe_dict(val) -> dict:
    """Return val as dict, or {} if val is None/non-dict (e.g. LLM returned list)."""
    if isinstance(val, dict):
        return val
    return {}


def _dedup_strings(lst) -> list:
    """
    Deduplicate a list of strings safely.
    Converts any non-string items (e.g. dicts returned by LLM) to strings first.
    Replaces list(set(lst)) which crashes on unhashable dict items.
    """
    seen = []
    out  = []
    for item in (lst or []):
        # Normalise to string so dicts never reach set()
        s = str(item) if not isinstance(item, str) else item
        if s not in seen:
            seen.append(s)
            out.append(s)
    return out


def _merge_string_lists(a: list, b: list) -> list:
    """
    Merge two lists of strings, deduplicating safely.
    Safe replacement for list(set(a + b)) when items might be dicts.
    """
    return _dedup_strings((a or []) + (b or []))


class MasterAgent(BaseAgent):
    """
    LLM-driven orchestrator. Only agent that thinks.
    Issues Instructions to slave agents and reacts to their results.
    """

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.MASTER, broadcast)
        self.phase = AttackPhase.RECON

        # Child agents (created lazily)
        self._recon_agent   = None
        self._vuln_agent    = None
        self._web_agent     = None
        self._osint_agent   = None
        self._exploit_agent = None
        self._privesc_agent = None
        self._shell_agent         = None
        self._payload_agent       = None
        self._attack_graph_agent  = None   # background chain analyzer

        # Session config
        self._target:        str  = ""
        self._target_type:   str  = "unknown"
        self._auto_exploit:  bool = False
        self._phases_to_run: List[str] = []

        # Accumulated intelligence — updated throughout pentest
        self._intel: Dict = {
            "target":          "",
            "target_type":     "unknown",
            "open_ports":      [],
            "services":        {},     # {port: {service, version, protocol}}
            "os_guess":        "unknown",
            "web_paths":       [],
            "subdomains":      [],
            "technologies":    [],
            "vulnerabilities": [],
            "cves":            [],
            "exploit_modules": [],
            "credentials":     [],
            "web_vulns":       [],     # OWASP findings
            "shell_access":    False,
            "current_user":    None,
            "user_flag":       None,
            "root_flag":       None,
            "shell_id":        None,
            "attack_path":     [],     # Chronological attack steps taken
            # ── Extended fields for real pentest depth ──────────
            "users":              [],  # discovered usernames
            "shares":             [],  # SMB/NFS shares found
            "banners":            {},  # {port: raw banner string}
            "login_pages":        [],  # HTTP login forms found
            "interesting_files":  [],  # sensitive files/dirs found
            "service_versions":   {},  # {port: "Apache 2.4.49"}
            "raw_outputs":        {},  # {tool: last 2000 chars of stdout}
            "enum_findings":      [],  # structured findings from enumeration
            "default_creds_tried": [], # list of {service, user, pass, result}
            "open_services_detail": [], # human readable service descriptions
            "attack_surface_notes": "", # LLM's assessment of attack surface
            "operator_notes":     [],  # guidance injected by operator
            # ── Next-gen architecture fields ────────────────────
            "attack_tree":        None, # generated attack plan (nodes+edges+optimal_path)
            "mitre_techniques":   [],   # [{"id": "T1190", "name": "...", "tactic": "..."}]
            "lateral_targets":    [],   # IPs/hosts discovered post-exploitation
            "pivot_paths":        [],   # [{src, dst, method, creds}]
            "evidence":           [],   # captured evidence items
            "long_term_hits":     [],   # memories recalled and used this session
            "state":              "INIT",  # current state machine state
        }

        # ── Pentest State Machine ────────────────────────────
        # INIT → RECON → INTELLIGENCE_AGGREGATION → VULNERABILITY_ANALYSIS
        # → ATTACK_PLANNING → EXPLOITATION → POST_EXPLOITATION
        # → PRIVILEGE_ESCALATION → LATERAL_MOVEMENT → EVIDENCE_COLLECTION
        # → REPORT_GENERATION → COMPLETE
        self._state_transitions = {
            "INIT":                      "RECON",
            "RECON":                     "INTELLIGENCE_AGGREGATION",
            "INTELLIGENCE_AGGREGATION":  "VULNERABILITY_ANALYSIS",
            "VULNERABILITY_ANALYSIS":    "ATTACK_PLANNING",
            "ATTACK_PLANNING":           "EXPLOITATION",
            "EXPLOITATION":              "POST_EXPLOITATION",
            "POST_EXPLOITATION":         "PRIVILEGE_ESCALATION",
            "PRIVILEGE_ESCALATION":      "LATERAL_MOVEMENT",
            "LATERAL_MOVEMENT":          "EVIDENCE_COLLECTION",
            "EVIDENCE_COLLECTION":       "REPORT_GENERATION",
            "REPORT_GENERATION":         "COMPLETE",
        }

        # Confirmation events (for exploitation gating)
        self._confirm_events: Dict[str, asyncio.Event] = {}

        # Track which tools have already been run (prevents repetition)
        self._used_tools: Dict[str, int] = {}   # tool_name → run count

        # Operator notes and scope (set at run() start)
        self._notes: str = ""
        self._scope: str = ""

        # User guidance queue — injected mid-run from frontend
        self._guidance_queue: asyncio.Queue = asyncio.Queue()

        # Results cache — avoids re-running identical instructions
        self._instruction_cache: Dict[str, Dict] = {}  # hash(tool+args) → result

        # Background tasks — fire-and-forget asyncio.Task objects.
        # Tracked here so _wait_for_agents_idle can properly drain them before
        # report generation begins.
        self._background_tasks: List[asyncio.Task] = []

    # ─── Async KB Helpers ─────────────────────────────────────
    # Offload CPU-bound embedding/reranking to thread pool so the async
    # event loop is never blocked.  Also emit rag_query WS events so the
    # Agent Console Comms tab shows every RAG query and its result.

    async def _kb(self, query: str, **kw) -> str:
        """Non-blocking KB context search. Runs in thread pool, emits rag_query."""
        if not _KB_AVAILABLE:
            return ""
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _kb_context(query, **kw))
        if result:
            await self._emit("rag_query", {
                "agent": str(self.name),
                "phase": str(self.phase or ""),
                "query": query[:200],
                "result": result[:1000],
                "found": True,
            })
        return result

    async def _kbc(self, query: str, top_k: int = 4) -> str:
        """Non-blocking KB commands search. Runs in thread pool, emits rag_query."""
        if not _KB_AVAILABLE:
            return ""
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _kb_commands(query, top_k=top_k))
        if result:
            await self._emit("rag_query", {
                "agent": str(self.name),
                "phase": str(self.phase or ""),
                "query": f"[cmds] {query[:180]}",
                "result": result[:1000],
                "found": True,
            })
        return result

    async def _kbp(self, query: str, top_k: int = 3) -> str:
        """Non-blocking KB procedures search. Runs in thread pool, emits rag_query."""
        if not _KB_AVAILABLE:
            return ""
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _kb_procedures(query, top_k=top_k))
        if result:
            await self._emit("rag_query", {
                "agent": str(self.name),
                "phase": str(self.phase or ""),
                "query": f"[procs] {query[:180]}",
                "result": result[:1000],
                "found": True,
            })
        return result

    # ─── Main Entry Point ─────────────────────────────────────

    async def run(
        self,
        session_id:        str,
        target:            str,
        target_type:       str  = "unknown",
        auto_exploit:      bool = False,
        threading_enabled: bool = False,
        max_threads:       int  = 3,
        phases:            List[str] = None,
        notes:             str  = "",
        scope:             str  = "",
        **kwargs
    ) -> Dict:
        self._session_id     = session_id
        self._target         = target
        self._target_type    = target_type
        self._auto_exploit   = auto_exploit
        self._intel["target"]      = target
        self._intel["target_type"] = target_type
        self._phases_to_run  = phases or [p.value for p in AttackPhase]

        # Store operator notes and scope for all planning prompts
        self._notes = notes.strip() if notes else ""
        self._scope = scope.strip() if scope else ""
        if self._notes:
            self._intel["operator_notes"].append({
                "note": f"[OPERATOR GUIDANCE] {self._notes}",
                "ts":   datetime.utcnow().isoformat()
            })
        if self._scope:
            self._intel["operator_notes"].append({
                "note": f"[SCOPE/FOCUS] {self._scope}",
                "ts":   datetime.utcnow().isoformat()
            })

        # ── Step 1: LLM GATE — halt immediately if offline ────
        await self.set_status(AgentStatus.RUNNING, f"Initialising pentest on {target}")
        llm_ok = await self.check_llm_available()
        if not llm_ok:
            await db.update_session(session_id, {"status": SessionStatus.PAUSED})
            return {
                "status":  "halted",
                "reason":  "LLM offline",
                "message": f"Cannot start pentest — LLM not reachable at {self._llm_available}"
            }

        # Initial node in attack graph
        target_node = f"target_{target.replace('.', '_').replace('/', '_')}"
        await self.add_node(
            node_id  = target_node,
            type     = "host",
            label    = target,
            host     = target,
            metadata = {"role": "primary_target", "type": target_type}
        )

        # ── Step 2: LLM creates master plan ───────────────────
        try:
            plan = self._safe_llm_result(await self._create_master_plan(target, target_type))
        except RuntimeError as e:
            await self._emit("llm_halt", {"reason": str(e)})
            return {"status": "halted", "reason": str(e)}

        await self._emit("master_plan", {"plan": plan, "target": target})
        await self.emit_reasoning(
            step       = "master_plan_created",
            reasoning  = plan.get("rationale", "Initial pentest plan created"),
            decision   = f"Assessment type: {plan.get('assessment_type', 'full')}",
            next_action= "Begin reconnaissance phase",
            data       = plan
        )

        # ── Emit skeleton plan steps immediately so UI shows progress from second 1 ──
        # Full attack tree comes later after recon; this gives instant visibility
        phases_in_plan = _safe_list(plan.get("phases", []))
        skeleton_steps = []

        # Phase steps from master plan
        phase_icons = {
            "recon":        ("🔍", "Reconnaissance",          "nmap, whatweb, enum4linux"),
            "vuln_id":      ("🔬", "Vulnerability ID",         "nmap --script vuln, searchsploit, nikto"),
            "web_testing":  ("🌐", "Web App Testing",          "gobuster, sqlmap, nikto"),
            "osint":        ("🕵", "OSINT / ExploitDB",        "searchsploit, CVE lookup"),
            "exploit":      ("💥", "Exploitation",             "Based on findings — TBD after recon"),
            "post_exploit": ("🎭", "Post Exploitation",        "Credential harvest, network map"),
            "privesc":      ("⬆",  "Privilege Escalation",     "linPEAS, sudo, SUID, cron"),
            "reporting":    ("📄", "Report Generation",        "Full findings report"),
            # ── Specialist phases ──────────────────────────────
            "lateral":      ("↔",  "Lateral Movement",         "ad_enum, kerberoast, ntlm_capture"),
            "cloud":        ("☁",  "Cloud Enumeration",        "aws_enum, azure_enum, gcp_enum"),
            "container":    ("🐳", "Container Audit",          "docker_audit, k8s_audit"),
            "evasion":      ("👻", "AV/EDR Evasion",           "defense_enum, av_evasion, amsi_bypass"),
            "traffic":      ("📡", "Traffic Analysis",         "pcap_capture, credential_sniff"),
            "evidence":     ("📷", "Evidence Collection",      "screenshot, flag_capture"),
            "forensics":    ("🔎", "Digital Forensics",        "artifact_collect, timeline, memory_analysis"),
            "wireless":     ("📶", "Wireless Assessment",      "wifi_scan, wpa2_crack, evil_twin"),
            "iot":          ("📟", "IoT Assessment",           "iot_device_scan, iot_default_creds, iot_protocol, iot_firmware"),
        }

        # Build from plan phases if available, else use defaults
        seen_phases = set()
        for ph in phases_in_plan:
            phase_key = str(ph.get("phase","")).lower()
            if phase_key in phase_icons and phase_key not in seen_phases:
                icon, label, tools_hint = phase_icons[phase_key]
                plan_tools = ph.get("tools", [])
                skeleton_steps.append({
                    "id":          phase_key,
                    "label":       label,
                    "icon":        icon,
                    "phase":       phase_key,
                    "tool":        ", ".join(plan_tools[:3]) if plan_tools else tools_hint,
                    "status":      "pending",
                    "result":      "",
                    "detail":      ph.get("reasoning",""),
                    "probability": None,
                })
                seen_phases.add(phase_key)

        # Fill in any missing standard phases
        for phase_key, (icon, label, tools_hint) in phase_icons.items():
            if phase_key not in seen_phases:
                skeleton_steps.append({
                    "id":          phase_key,
                    "label":       label,
                    "icon":        icon,
                    "phase":       phase_key,
                    "tool":        tools_hint,
                    "status":      "pending",
                    "result":      "",
                    "detail":      "",
                    "probability": None,
                })

        # Add hypothesis as a pinned note
        hypothesis = plan.get("attack_hypothesis","")
        await self._emit("plan_skeleton", {
            "steps":      skeleton_steps,
            "hypothesis": hypothesis,
            "assessment_type": plan.get("assessment_type","unknown"),
            "target":     target,
            "ts":         datetime.utcnow().isoformat()
        })

        # ── Step 3: Start Attack Graph Agent (background, runs whole session) ──
        try:
            from agents.attack_graph_agent import AttackGraphAgent
            import db.mongo_client as _db_mod
            _aga = AttackGraphAgent(
                session_id = session_id,
                target     = target,
                broadcast  = self.broadcast,
                db         = _db_mod.get_db(),
                services   = self._intel.get("services", {}),
            )
            self._create_task(_aga.run_analysis_loop())
            # Keep reference so we can push updated services later
            self._attack_graph_agent = _aga
        except Exception as _aga_err:
            import logging as _l
            _l.getLogger(__name__).warning("AttackGraphAgent failed to start: %s", _aga_err)

        # ── Step 4: Execute phases ─────────────────────────────
        try:
            await self._execute_phases(session_id, target, plan)
        except RuntimeError as e:
            # LLM went offline mid-pentest
            await self._emit("llm_halt", {
                "reason":  str(e),
                "message": "Pentest paused — LLM became unavailable. Restart when LLM is back online."
            })
            await db.update_session(session_id, {"status": SessionStatus.PAUSED})
            return {"status": "halted", "reason": str(e)}
        except asyncio.CancelledError:
            await self.set_status(AgentStatus.IDLE, "Pentest cancelled by user")
            await db.update_session(session_id, {"status": SessionStatus.PAUSED})
            return {"status": "cancelled"}
        except Exception as e:
            await self.set_status(AgentStatus.ERROR, f"Unexpected error: {e}")
            return {"status": "error", "error": str(e)}

        # Complete
        await self.set_status(AgentStatus.DONE, "Pentest lifecycle complete")
        await db.update_session(session_id, {
            "status":       SessionStatus.COMPLETED,
            "completed_at": datetime.utcnow()
        })
        await self._emit("pentest_complete", {
            "session_id": session_id,
            "intel":      self._intel,
            "message":    "Pentest complete — review Findings Board and generate report."
        })
        return {"status": "done", "intel": self._intel}

    # ─── State Machine ────────────────────────────────────────

    async def _transition_state(self, new_state: str):
        """Advance the pentest state machine to a new state."""
        old = self._intel.get("state", "INIT")
        self._intel["state"] = new_state
        await self._emit("state_change", {
            "from":    old,
            "to":      new_state,
            "ts":      datetime.utcnow().isoformat()
        })
        await self.emit_reasoning(
            step       = "state_transition",
            reasoning  = f"Advancing from {old} → {new_state}",
            decision   = f"State machine: {new_state}",
            next_action= f"Execute {new_state.lower().replace('_',' ')} phase",
        )

    # ─── Long-Term Memory ─────────────────────────────────────

    async def _recall_relevant_memories(self, target_type: str, tags: List[str]) -> str:
        """
        Query long-term memory for patterns relevant to this target.
        Returns a formatted string for LLM injection.
        """
        try:
            memories = await db.recall_memory(
                target_type=target_type,
                tags=tags,
                min_confidence=0.6,
                limit=5
            )
            if not memories:
                return ""
            lines = ["=== LONG-TERM MEMORY (from previous engagements) ==="]
            for m in memories:
                mtype   = m.get("memory_type", "?")
                content = m.get("content", {})
                conf    = m.get("confidence", 0)
                lines.append(f"[{mtype} | confidence={conf:.1f}]")
                if isinstance(content, dict):
                    for k, v in list(content.items())[:4]:
                        lines.append(f"  {k}: {str(v)[:120]}")
                else:
                    lines.append(f"  {str(content)[:200]}")
            lines.append("=== END MEMORY ===")
            self._intel["long_term_hits"] = memories
            return "\n".join(lines)
        except Exception:
            return ""

    async def _store_success_memory(self, memory_type: str, content: Dict, tags: List[str]):
        """
        Store a successful attack pattern to long-term memory.
        Called whenever exploitation/privesc succeeds.
        """
        try:
            await db.store_memory(
                memory_type  = memory_type,
                target_type  = self._intel.get("target_type", "unknown"),
                content      = content,
                tags         = tags,
                success      = True,
                confidence   = 0.85
            )
        except Exception as e:
            pass  # memory storage failure should never break the pentest

    # ─── MITRE ATT&CK Mapping ─────────────────────────────────

    # Mapping from tool/technique to MITRE technique IDs
    _MITRE_MAP = {
        "nmap":          ("T1046",  "Network Service Discovery",       "Discovery"),
        "gobuster":      ("T1083",  "File and Directory Discovery",    "Discovery"),
        "enum4linux":    ("T1087",  "Account Discovery",               "Discovery"),
        "nikto":         ("T1190",  "Exploit Public-Facing Application","Initial Access"),
        "sqlmap":        ("T1190",  "Exploit Public-Facing Application","Initial Access"),
        "hydra":         ("T1110",  "Brute Force",                     "Credential Access"),
        "metasploit":    ("T1203",  "Exploitation for Client Execution","Execution"),
        "msfconsole":    ("T1203",  "Exploitation for Client Execution","Execution"),
        "searchsploit":  ("T1588",  "Obtain Capabilities",             "Resource Development"),
        "smbclient":     ("T1021",  "Remote Services",                 "Lateral Movement"),
        "linpeas":       ("T1078",  "Valid Accounts",                  "Privilege Escalation"),
        "sudo":          ("T1548",  "Abuse Elevation Control Mechanism","Privilege Escalation"),
        "find":          ("T1083",  "File and Directory Discovery",    "Discovery"),
        "curl":          ("T1071",  "Application Layer Protocol",      "Command and Control"),
        "wget":          ("T1071",  "Application Layer Protocol",      "Command and Control"),
        "ssh":           ("T1021",  "Remote Services",                 "Lateral Movement"),
        "crackmapexec":  ("T1021",  "Remote Services",                 "Lateral Movement"),
        "impacket":      ("T1557",  "Adversary-in-the-Middle",         "Credential Access"),
    }

    async def _map_mitre(self, tool: str, success: bool = False, host: Optional[str] = None):
        """Auto-map a tool run to a MITRE ATT&CK technique."""
        tool_lower = tool.lower()
        entry = None
        for key, val in self._MITRE_MAP.items():
            if key in tool_lower:
                entry = val
                break
        if not entry:
            return
        tech_id, tech_name, tactic = entry
        # Add to in-memory intel
        technique = {"id": tech_id, "name": tech_name, "tactic": tactic, "tool": tool}
        if technique not in self._intel["mitre_techniques"]:
            self._intel["mitre_techniques"].append(technique)
        # Persist
        if self._session_id:
            try:
                await db.store_mitre_mapping(
                    session_id     = self._session_id,
                    technique_id   = tech_id,
                    technique_name = tech_name,
                    tactic         = tactic,
                    tool_used      = tool,
                    host           = host or self._target,
                    success        = success
                )
            except Exception:
                pass

    # ─── Evidence Collection Helper ──────────────────────────

    async def _capture_evidence(
        self,
        phase:         str,
        evidence_type: str,
        title:         str,
        content:       str,
        tool_used:     str = "",
        severity:      str = "info",
        mitre_tech:    str = None
    ):
        """
        Capture structured evidence during any phase.
        Automatically persists to DB and adds to intel.
        """
        if not content or len(content.strip()) < 10:
            return
        item = {
            "phase":           phase,
            "evidence_type":   evidence_type,
            "title":           title,
            "content":         content[:3000],
            "tool_used":       tool_used,
            "severity":        severity,
            "mitre_technique": mitre_tech,
            "captured_at":     datetime.utcnow().isoformat()
        }
        self._intel["evidence"].append(item)
        if self._session_id:
            try:
                await db.store_evidence(
                    session_id     = self._session_id,
                    phase          = phase,
                    evidence_type  = evidence_type,
                    title          = title,
                    content        = content[:3000],
                    host           = self._target,
                    tool_used      = tool_used,
                    severity       = severity,
                    mitre_technique= mitre_tech
                )
            except Exception:
                pass

    # ─── Phase Orchestration ──────────────────────────────────

    def _create_task(self, coro) -> asyncio.Task:
        """
        Wrapper around asyncio.create_task() that registers the task in
        _background_tasks so _wait_for_agents_idle() can drain them before
        report generation begins.  Completed tasks are automatically pruned
        from the list via a done-callback to avoid unbounded growth.
        """
        task = asyncio.create_task(coro)
        self._background_tasks.append(task)

        def _prune(t):
            try:
                self._background_tasks.remove(t)
            except ValueError:
                pass

        task.add_done_callback(_prune)
        return task

    async def _run_phase_subagents(self, phase: str, target: str, **kwargs) -> None:
        """
        Launch the subagent orchestrator(s) for *phase* in a fire-and-forget task.

        Called after each phase's execute_tasks() so that fine-grained subagent
        findings, WS events, and SubagentConsolePage state are all populated even
        during the autonomous pentest — not just when subagents are run manually.

        Each orchestrator runs independently in the background; exceptions are
        swallowed so a subagent crash never blocks the main pentest flow.
        """
        import db.mongo_client as _db

        sa_broadcast = self._make_sa_broadcast()
        sid          = self._session_id or ""

        async def _safe(coro):
            try:
                await coro
            except Exception as exc:
                await self.emit_reasoning(
                    step       = f"subagent_err_{phase}",
                    reasoning  = f"Subagent phase '{phase}' error (non-fatal): {exc}",
                    decision   = "Continuing pentest — subagent result not required",
                    next_action= "Main flow unaffected",
                )

        if phase == "recon":
            from agents.recon.network_scan_subagent    import NetworkScanSubagent
            from agents.recon.dns_recon_subagent        import DnsReconSubagent
            from agents.recon.service_banner_subagent   import ServiceBannerSubagent
            from agents.recon.web_fingerprint_subagent  import WebFingerprintSubagent
            kw  = dict(session_id=sid, target=target, broadcast=sa_broadcast, db=_db.get_db())
            coros = [
                NetworkScanSubagent(**kw).execute(),
                DnsReconSubagent(**kw).execute(),
                ServiceBannerSubagent(**kw).execute(
                    ports=self._intel.get("open_ports", []),
                    services=self._intel.get("services", {}),
                ),
            ]
            # Add web fingerprint subagents for each detected HTTP service
            for port, svc in list(self._intel.get("services", {}).items())[:3]:
                svc_name = (svc.get("service","") if isinstance(svc, dict) else str(svc)).lower()
                if any(x in svc_name for x in ("http", "https")):
                    proto = "https" if int(str(port)) in (443, 8443) else "http"
                    coros.append(WebFingerprintSubagent(**kw).execute(
                        url=f"{proto}://{target}:{port}"
                    ))
            self._create_task(_safe(asyncio.gather(*coros, return_exceptions=True)))

        elif phase == "vuln":
            from agents.vuln.cve_lookup_subagent    import CveLookupSubagent
            from agents.vuln.ssl_audit_subagent      import SslAuditSubagent
            from agents.vuln.smb_vuln_subagent       import SmbVulnSubagent
            from agents.vuln.service_vuln_subagent   import ServiceVulnSubagent
            kw    = dict(session_id=sid, target=target, broadcast=sa_broadcast, db=_db.get_db())
            coros = [
                CveLookupSubagent(**kw).execute(
                    services=self._intel.get("services", {}),
                    cves=self._intel.get("cves", []),
                ),
                ServiceVulnSubagent(**kw).execute(services=self._intel.get("services", {})),
            ]
            ports = set(str(p) for p in self._intel.get("open_ports", []))
            if ports & {"443", "8443", "8080", "80"}:
                coros.append(SslAuditSubagent(**kw).execute())
            if ports & {"445", "139"}:
                coros.append(SmbVulnSubagent(**kw).execute())
            self._create_task(_safe(asyncio.gather(*coros, return_exceptions=True)))

        elif phase == "exploit":
            from agents.exploit.exploit_orchestrator  import ExploitOrchestrator
            orch = ExploitOrchestrator(broadcast=sa_broadcast)
            orch._session_id = sid
            self._create_task(_safe(orch.run(
                session_id   = sid,
                target       = target,
                db           = _db.get_db(),
                services     = list(self._intel.get("services", {}).values()),
                cves         = self._intel.get("cves", []),
                open_ports   = self._intel.get("open_ports", []),
                web_urls     = [
                    f"http{'s' if int(str(p)) in (443,8443) else ''}://{target}:{p}"
                    for p, s in self._intel.get("services",{}).items()
                    if any(x in (s.get("service","") if isinstance(s,dict) else str(s)).lower()
                           for x in ("http","https"))
                ][:3],
                lhost        = kwargs.get("lhost", "LHOST"),
                lport        = kwargs.get("lport", 4444),
            )))

        elif phase == "privesc":
            from agents.privesc.linux_enum_subagent    import LinuxEnumSubagent
            from agents.privesc.windows_enum_subagent  import WindowsEnumSubagent
            kw    = dict(session_id=sid, target=target, broadcast=sa_broadcast, db=_db.get_db())
            os_guess = self._intel.get("os_guess", "").lower()
            if "windows" in os_guess:
                self._create_task(_safe(WindowsEnumSubagent(**kw).execute()))
            else:
                self._create_task(_safe(LinuxEnumSubagent(**kw).execute()))

        elif phase == "web":
            from agents.web.dir_fuzz_subagent                  import DirFuzzSubagent
            from agents.web.web_vuln_scan_subagent             import WebVulnScanSubagent
            from agents.web.sqli_subagent                      import SqliSubagent
            from agents.web.xss_subagent                       import XssSubagent
            from agents.web.ssrf_subagent                      import SsrfSubagent
            from agents.web.broken_access_control_subagent     import BrokenAccessControlSubagent
            from agents.web.crypto_failures_subagent           import CryptoFailuresSubagent
            from agents.web.insecure_design_subagent           import InsecureDesignSubagent
            from agents.web.data_integrity_subagent            import DataIntegritySubagent
            from agents.web.injection_subagent                 import InjectionSubagent
            from agents.web.auth_bypass_subagent               import AuthBypassSubagent
            from agents.web.cms_subagent                       import CmsSubagent
            from agents.web.burp_subagent                      import BurpSubagent
            kw = dict(session_id=sid, target=target, broadcast=sa_broadcast, db=_db.get_db())
            web_urls = kwargs.get("web_urls", [])
            # Build URL list from intel if not passed explicitly
            if not web_urls:
                web_urls = [
                    f"http{'s' if int(str(p)) in (443, 8443) else ''}://{target}:{p}"
                    for p, s in self._intel.get("services", {}).items()
                    if any(x in (s.get("service", "") if isinstance(s, dict) else str(s)).lower()
                           for x in ("http", "https"))
                ][:4]
            # Always ensure at least one URL to test — fall back to plain http/https on target
            if not web_urls:
                web_urls = [f"http://{target}", f"https://{target}"]
            coros = []
            for url in web_urls[:3]:
                coros += [
                    DirFuzzSubagent(**kw).execute(url=url),
                    WebVulnScanSubagent(**kw).execute(url=url),
                    SqliSubagent(**kw).execute(url=url),
                    XssSubagent(**kw).execute(url=url),
                    InjectionSubagent(**kw).execute(url=url),
                    AuthBypassSubagent(**kw).execute(url=url),
                    CmsSubagent(**kw).execute(url=url),
                    BrokenAccessControlSubagent(**kw).execute(url=url),
                    CryptoFailuresSubagent(**kw).execute(url=url),
                    InsecureDesignSubagent(**kw).execute(url=url),
                    DataIntegritySubagent(**kw).execute(url=url),
                ]
                if url.startswith("https"):
                    coros.append(SsrfSubagent(**kw).execute(url=url))
            # Burp Suite runs once per URL (uses URL as scan target; falls back to Nikto if API unavailable)
            for url in web_urls[:2]:
                burp_kw = dict(kw, target=url)
                coros.append(BurpSubagent(**burp_kw).execute())
            if coros:
                self._create_task(_safe(asyncio.gather(*coros, return_exceptions=True)))

        elif phase == "post":
            from agents.post.local_cred_harvest_subagent import LocalCredHarvestSubagent
            from agents.post.data_exfil_subagent         import DataExfilSubagent
            from agents.post.persistence_subagent        import PersistenceSubagent
            from agents.post.log_evasion_subagent        import LogEvasionSubagent
            kw = dict(session_id=sid, target=target, broadcast=sa_broadcast, db=_db.get_db())
            shells = self._intel.get("shells", [])
            shell_id = shells[0].get("id") if shells else kwargs.get("shell_id")
            coros = [
                LocalCredHarvestSubagent(**kw).execute(shell_id=shell_id),
                DataExfilSubagent(**kw).execute(shell_id=shell_id),
            ]
            # Persistence and evasion only if root/admin obtained
            current_user = self._intel.get("current_user", "")
            if current_user in ("root", "SYSTEM", "Administrator") or self._intel.get("root_flag"):
                coros += [
                    PersistenceSubagent(**kw).execute(shell_id=shell_id),
                    LogEvasionSubagent(**kw).execute(shell_id=shell_id),
                ]
            self._create_task(_safe(asyncio.gather(*coros, return_exceptions=True)))

        elif phase == "lateral":
            from agents.lateral.ad_enum_subagent      import AdEnumSubagent
            from agents.lateral.kerberos_subagent     import KerberosSubagent
            from agents.lateral.ntlm_capture_subagent import NtlmCaptureSubagent
            kw = dict(session_id=sid, target=target, broadcast=sa_broadcast, db=_db.get_db())
            coros = [AdEnumSubagent(**kw).execute()]
            # Kerberos + NTLM only if domain context found
            if self._intel.get("domain") or self._intel.get("dc_ip"):
                coros += [
                    KerberosSubagent(**kw).execute(
                        domain=self._intel.get("domain", ""),
                        dc_ip=self._intel.get("dc_ip", target),
                    ),
                    NtlmCaptureSubagent(**kw).execute(),
                ]
            self._create_task(_safe(asyncio.gather(*coros, return_exceptions=True)))

    async def _execute_phases(self, session_id: str, target: str, plan: Dict):
        """
        Execute all enabled phases driven by the state machine.
        Phases 1-4 (recon/vuln/web/osint) run IN PARALLEL for speed.
        Attack planning runs after intelligence aggregation.
        """
        phases = self._phases_to_run

        def phase_enabled(p: str) -> bool:
            if not phases:
                return True
            if p in phases:
                return True
            try:
                return AttackPhase(p) in phases or p.upper() in [str(ph).upper() for ph in phases]
            except (ValueError, KeyError):
                return False

        # ── Pull long-term memories relevant to this target ───
        await self._transition_state("RECON")
        mem_ctx = await self._recall_relevant_memories(
            target_type = self._intel.get("target_type", "unknown"),
            tags        = ["recon", "initial_access", plan.get("assessment_type", "")]
        )
        if mem_ctx:
            self._intel.setdefault("operator_notes", []).append({
                "note": f"Long-term memory context loaded for {self._intel.get('target_type','?')} targets",
                "ts":   datetime.utcnow().isoformat()
            })
            await self.emit_reasoning(
                step       = "memory_loaded",
                reasoning  = "Retrieved relevant patterns from previous engagements",
                decision   = f"Loaded {len(self._intel['long_term_hits'])} memories",
                next_action= "Inject memory context into planning prompts"
            )

        # ── PHASE 1: RECON (always first, sequential) ─────────
        if phase_enabled("recon"):
            await self._phase_recon(target, plan)

        # ── PHASE 2: PARALLEL intelligence gathering ──────────
        # Run vuln scan + web testing + OSINT simultaneously
        await self._transition_state("INTELLIGENCE_AGGREGATION")

        parallel_coros = []
        if phase_enabled("vuln_id") or phase_enabled("scan"):
            parallel_coros.append(("vuln", self._phase_vuln_id(target)))

        web_ports = []
        for port, svc in self._intel["services"].items():
            svc_name = (svc.get("service","") if isinstance(svc,dict) else str(svc)).lower()
            if svc_name in ("http","https","http-alt","http-proxy","ssl/http","http?"):
                web_ports.append(port)
        if web_ports:
            parallel_coros.append(("web", self._phase_web_testing(target, web_ports)))

        if phase_enabled("osint"):
            parallel_coros.append(("osint", self._phase_osint(target)))

        # ── Optional specialist phases run alongside vuln/web/osint ──
        # Cloud: if cloud metadata port (80/443) or IMDS hints in scan results
        _svcs_str = _fmt_svcs(self._intel.get("services", {})).lower()
        _os_str   = self._intel.get("os_guess", "").lower()
        if phase_enabled("cloud") and (
            "169.254.169.254" in str(self._intel) or
            any(k in _svcs_str for k in ("aws", "azure", "gcp", "cloud", "metadata")) or
            self._intel.get("target_type", "") in ("cloud", "aws", "azure", "gcp")
        ):
            parallel_coros.append(("cloud", self._phase_cloud(target)))

        # Container: if docker (2375/2376) or k8s (6443/8443/10250) ports open
        _open_ports = set(str(p) for p in self._intel.get("open_ports", []))
        if phase_enabled("container") and (
            _open_ports & {"2375", "2376", "6443", "8443", "10250", "10255"} or
            any(k in _svcs_str for k in ("docker", "kubernetes", "k8s"))
        ):
            parallel_coros.append(("container", self._phase_container(target)))

        # Traffic: passive capture runs alongside other recon phases
        if phase_enabled("traffic"):
            parallel_coros.append(("traffic", self._phase_traffic(target)))

        if parallel_coros:
            phase_names = ', '.join(n for n, _ in parallel_coros)
            await self.emit_reasoning(
                step       = "parallel_intel",
                reasoning  = f"Master dispatching {len(parallel_coros)} agents simultaneously: {phase_names}",
                decision   = f"Parallel execution: {phase_names}",
                next_action= "All agents execute concurrently — Master waits for all results"
            )
            # Broadcast parallel start event so UI shows all agents active
            await self._emit("parallel_intel", {
                "agents":  [n for n, _ in parallel_coros],
                "decision": f"Running in parallel: {phase_names}",
                "next_action": "Agents executing simultaneously"
            })
            # Run all simultaneously — exceptions caught individually
            results = await asyncio.gather(
                *[coro for _, coro in parallel_coros],
                return_exceptions=True
            )
            for (name, _), result in zip(parallel_coros, results):
                if isinstance(result, Exception):
                    await self.emit_reasoning(
                        step       = f"parallel_{name}_error",
                        reasoning  = f"{name} agent error: {result}",
                        decision   = "Continuing with remaining agents",
                        next_action= "Use available intel for planning"
                    )
            await self.emit_reasoning(
                step       = "parallel_intel_done",
                reasoning  = f"All {len(parallel_coros)} parallel agents completed",
                decision   = "Aggregating results from all agents",
                next_action= "Master analyzes combined intelligence"
            )

            # Sync gate: ensure all parallel agents are truly done before continuing
            await self._wait_for_agents_idle(timeout=120.0)

        # Capture all enumeration as evidence
        if self._intel.get("open_ports"):
            await self._capture_evidence(
                phase        = "recon",
                evidence_type= "command_transcript",
                title        = f"Port scan results — {len(self._intel['open_ports'])} ports open",
                content      = f"Open ports: {self._intel['open_ports']}\nServices: {_fmt_svcs(self._intel['services'])}\nOS: {self._intel.get('os_guess','unknown')}",
                severity     = "info",
                mitre_tech   = "T1046"
            )
            await self._map_mitre("nmap", success=True)

        # ── PHASE 3: VULNERABILITY ANALYSIS ───────────────────
        await self._transition_state("VULNERABILITY_ANALYSIS")
        if self._intel.get("cves") or self._intel.get("vulnerabilities"):
            await self._capture_evidence(
                phase        = "vuln_id",
                evidence_type= "command_transcript",
                title        = f"Vulnerability analysis — {len(self._intel.get('cves',[]))} CVEs found",
                content      = f"CVEs: {self._intel.get('cves',[])}\nVulns: {str(self._intel.get('vulnerabilities',[]))[:500]}",
                severity     = "high" if self._intel.get("cves") else "medium"
            )

        # ── PHASE 4: ATTACK PLANNING (new) ────────────────────
        await self._transition_state("ATTACK_PLANNING")
        attack_tree = await self._phase_attack_planning(target)
        if attack_tree:
            self._intel["attack_tree"] = attack_tree

        # ── PHASE 5: EXPLOITATION ─────────────────────────────
        await self._transition_state("EXPLOITATION")
        if phase_enabled("exploit"):
            if self._auto_exploit:
                await self._phase_exploit(target)
            else:
                await self._emit("awaiting_confirmation", {
                    "phase":   "exploit",
                    "message": "Attack plan ready. Confirm to begin exploitation.",
                    "intel":   self._intel,
                    "attack_tree": attack_tree
                })
                confirmed = await self._wait_for_confirmation("exploit", timeout=3600)
                if confirmed:
                    await self._phase_exploit(target)
                else:
                    await self._emit("phase_skipped", {"phase": "exploit"})

        # ── PHASE 6: POST-EXPLOITATION + PRIVESC ──────────────
        if self._intel["shell_access"]:
            await self._transition_state("POST_EXPLOITATION")
            if phase_enabled("post_exploit"):
                await self._phase_post_exploit(target)

            await self._transition_state("PRIVILEGE_ESCALATION")
            if phase_enabled("privesc"):
                await self._phase_privesc(target)
                # Store privesc success in long-term memory
                if self._intel.get("root_flag") or self._intel.get("current_user") == "root":
                    await self._store_success_memory(
                        memory_type = "privesc_pattern",
                        content     = {
                            "os":      self._intel.get("os_guess","?"),
                            "method":  "See attack path",
                            "vectors": self._intel.get("attack_path", [])[-3:]
                        },
                        tags = ["privesc", self._intel.get("os_guess","unknown").lower()]
                    )

            # ── PHASE 6b: EVASION (when shell active) ─────────
            # Run defense enumeration + AV evasion after initial access
            if phase_enabled("evasion"):
                await self._phase_evasion(target)

            # ── PHASE 7: LATERAL MOVEMENT ─────────────────────
            await self._transition_state("LATERAL_MOVEMENT")
            if phase_enabled("lateral"):
                await self._phase_lateral_movement(target)
            elif phase_enabled("exploit") and self._intel.get("lateral_targets"):
                # Legacy: also trigger if exploit phase found lateral targets
                await self._phase_lateral_movement(target)

        # ── PHASE 7b: WIRELESS (optional standalone phase) ────
        if phase_enabled("wireless") or self._intel.get("wireless_config"):
            await self._phase_wireless(target)

        # ── PHASE 7c: IoT ASSESSMENT (auto-detected or explicit) ──────────────
        if phase_enabled("iot") or self._intel.get("_iot_detected"):
            await self._phase_iot(target)

        # ── PHASE 8: EVIDENCE COLLECTION ─────────────────────
        # Sync gate: every agent must be IDLE before evidence is collected.
        # This ensures exploit/privesc/post-exploit LLM parse steps are done.
        await self.emit_reasoning(
            step       = "pre_evidence_sync",
            reasoning  = "Waiting for all active agents to finish before evidence collection",
            decision   = "Master holding until all agents confirm idle",
            next_action= "Evidence collection starts once all agents are done"
        )
        await self._wait_for_agents_idle(timeout=300.0)
        await self._transition_state("EVIDENCE_COLLECTION")

        # ── Enhanced evidence: screenshot + flag capture (EvidenceAgent) ──
        if self._intel.get("shell_access") and phase_enabled("evidence"):
            await self._phase_evidence_enhanced(target)

        # ── Forensics deep-dive: timeline + artifacts + memory ────────────
        if phase_enabled("forensics"):
            await self._phase_forensics_deep(target)

        await self._phase_evidence_collection(session_id, target)

        # ── PHASE 9: REPORT GENERATION ────────────────────────
        # Final sync gate: report must never start while any agent is still active.
        # This is the definitive guard that prevents the original bug.
        await self.emit_reasoning(
            step       = "pre_report_sync",
            reasoning  = "All agents must be idle before report generation can begin",
            decision   = "Master confirming all agents idle before writing report",
            next_action= "Report generation starts once all agents confirm done"
        )
        await self._wait_for_agents_idle(timeout=120.0)
        await self._emit("plan_step_update", {
            "step_id": "reporting", "status": "active",
            "result":  "Generating penetration test report",
            "detail":  "", "found": None, "ts": datetime.utcnow().isoformat()
        })
        await self._transition_state("REPORT_GENERATION")
        await self._phase_reporting(session_id, target)
        await self._emit("plan_step_update", {
            "step_id": "reporting", "status": "done",
            "result":  "Penetration test report ready",
            "detail":  f"Findings: {self._intel.get('findingsSummary',{})} | Flags: {len([self._intel.get('user_flag'), self._intel.get('root_flag')])}",
            "found":   True, "ts": datetime.utcnow().isoformat()
        })
        await self._transition_state("COMPLETE")

    # ─── Agent Sync Gate ──────────────────────────────────────

    async def _wait_for_agents_idle(self, timeout: float = 300.0):
        """
        Block until ALL specialist agents AND all fire-and-forget background
        tasks have finished.

        Two-tier check:
          1. Named agent objects (recon, vuln, web, osint, exploit, privesc) —
             checked via their .status field.
          2. Background asyncio.Task objects registered via _create_task() —
             checked via task.done().

        Called before any phase transition that must only start after all
        previously dispatched agents have completed — specifically before
        REPORTING so we never generate a report while subagents are still running.
        """
        import asyncio as _asyncio

        agent_objects = [
            ("recon",   self._recon_agent),
            ("vuln",    self._vuln_agent),
            ("web",     self._web_agent),
            ("osint",   self._osint_agent),
            ("exploit", self._exploit_agent),
            ("privesc", self._privesc_agent),
        ]

        deadline = _asyncio.get_event_loop().time() + timeout
        while _asyncio.get_event_loop().time() < deadline:
            busy = []

            # Check named agent statuses
            for name, agent in agent_objects:
                if agent is None:
                    continue
                status = str(agent.status).lower()
                if any(s in status for s in ("running", "thinking")):
                    busy.append(name)

            # Check background tasks registered via _create_task()
            pending_tasks = [t for t in self._background_tasks if not t.done()]
            if pending_tasks:
                busy.append(f"{len(pending_tasks)} background task(s)")

            if not busy:
                # All agents idle and all background tasks done — safe to proceed
                await self.emit_reasoning(
                    step       = "agents_sync",
                    reasoning  = "All agents and background tasks confirmed idle",
                    decision   = "Agent sync gate passed — proceeding",
                    next_action= "Continue to next phase"
                )
                return

            await self.emit_reasoning(
                step       = "agents_sync_waiting",
                reasoning  = f"Waiting for agents/tasks to finish: {busy}",
                decision   = f"{len(busy)} item(s) still active — Master waiting",
                next_action= "Check again in 2 seconds"
            )
            await _asyncio.sleep(2.0)

        # Timeout — force-set all busy agents to IDLE, cancel pending tasks, and continue
        still_busy = []
        for name, agent in agent_objects:
            if agent is None:
                continue
            status = str(agent.status).lower()
            if any(s in status for s in ("running", "thinking")):
                still_busy.append(name)
                try:
                    await agent.set_status(AgentStatus.IDLE, "Sync timeout — Master proceeding")
                except Exception:
                    pass

        # Cancel any remaining background tasks
        for task in list(self._background_tasks):
            if not task.done():
                still_busy.append("background_task")
                task.cancel()

        if still_busy:
            await self.emit_reasoning(
                step       = "agents_sync_timeout",
                reasoning  = f"Sync timeout reached. Forcing idle: {still_busy}",
                decision   = "Proceeding despite agents not confirming idle",
                next_action= "Continue — agent results already captured in intel"
            )

    # ─── PHASE: Reconnaissance ────────────────────────────────

    async def _phase_recon(self, target: str, plan: Dict):
        """Master plans every recon task. Agent executes + extracts findings."""
        await self._advance_phase(AttackPhase.RECON)
        await self._emit("plan_step_update", {
            "step_id": "recon", "status": "active",
            "result":  f"Master planning reconnaissance for {target}",
            "detail":  "", "found": None, "ts": datetime.utcnow().isoformat()
        })

        from agents.recon_agent import ReconAgent
        agent = ReconAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id
        self._recon_agent = agent

        # ── Round 1: Master plans initial scan ────────────────
        recon_plan = self._safe_llm_result(await self._llm_plan_recon(target, plan))
        await self.emit_reasoning(
            step       = "recon_planning",
            reasoning  = recon_plan.get("reasoning",""),
            decision   = f"Strategy: {recon_plan.get('strategy','')}",
            next_action= f"{len(recon_plan.get('steps',[]))} tasks in parallel"
        )
        tasks = [
            {"tool": s["tool"], "args": s.get("args",target),
             "purpose": s.get("purpose",""), "timeout": s.get("timeout",300),
             "can_parallel": True}
            for s in _safe_list(recon_plan.get("steps")) if s.get("tool")
        ] or [
            {"tool":"nmap","args":f"-sS -sV -sC --open -p- --min-rate 3000 {target}",
             "purpose":"Full port scan","timeout":600,"can_parallel":True},
            {"tool":"whatweb","args":f"-a 3 http://{target}",
             "purpose":"Web tech detection","timeout":60,"can_parallel":True},
        ]
        result = await agent.execute_tasks(target, tasks, "RECON", self._intel)

        self._intel["open_ports"]  = result.get("open_ports",[])
        self._intel["services"]    = result.get("services",{})
        self._intel["os_guess"]    = result.get("os_guess","unknown") or "unknown"
        self._intel["web_paths"]   = result.get("web_paths",[])
        self._intel["service_versions"].update(result.get("service_versions",{}))
        for u in result.get("users",[]):
            if u not in self._intel["users"]: self._intel["users"].append(u)
        self._intel["raw_outputs"].update(result.get("raw_outputs",{}))

        # ── Auto-detect IoT target from discovered ports ───────
        from agents.iot.iot_agent import is_iot_target
        if is_iot_target(self._target_type, self._intel["open_ports"]):
            if not self._intel.get("_iot_detected"):
                self._intel["_iot_detected"] = True
                await self.emit_reasoning(
                    step       = "iot_autodetect",
                    reasoning  = f"IoT-characteristic ports detected on {self._target}. Enabling IoT assessment phase.",
                    decision   = "Auto-enable IoT phase",
                    next_action= "IoT testing will run after exploitation phase"
                )

        # ── Round 2: Master plans service-specific enumeration ─
        ports = self._intel["open_ports"]
        svcs  = self._intel["services"]
        enum_tasks = []
        http_ports, smb_ports, ftp_ports, ssh_ports = [], [], [], []
        for port, svc in svcs.items():
            sn = (svc.get("service","") if isinstance(svc,dict) else str(svc)).lower()
            if any(x in sn for x in ("http","https","http-alt","ssl/http")): http_ports.append(port)
            elif any(x in sn for x in ("smb","microsoft-ds","netbios")):    smb_ports.append(port)
            elif "ftp" in sn:  ftp_ports.append(port)
            elif "ssh" in sn:  ssh_ports.append(port)

        for port in http_ports[:2]:
            proto = "https" if int(str(port)) in (443,8443) else "http"
            base  = f"{proto}://{target}:{port}"
            enum_tasks += [
                {"tool":"gobuster","timeout":240,"can_parallel":True,
                 "args":f"dir -u {base} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 40 -q --no-error",
                 "purpose":f"Directory enum on {base}"},
                {"tool":"curl","timeout":15,"can_parallel":True,
                 "args":f"-sk -I {base}/ --max-time 10",
                 "purpose":f"HTTP headers from {base}"},
            ]
        if smb_ports or 445 in ports or 139 in ports:
            enum_tasks += [
                {"tool":"enum4linux","args":f"-a {target}","timeout":120,"can_parallel":True,
                 "purpose":"SMB/NetBIOS full enumeration"},
                {"tool":"smbclient","args":f"-L //{target}/ -N","timeout":30,"can_parallel":True,
                 "purpose":"List SMB shares anonymously"},
            ]
        if ftp_ports or 21 in ports:
            enum_tasks.append({"tool":"nmap","timeout":60,"can_parallel":True,
                "args":f"-sV -p 21 --script ftp-anon,ftp-syst {target}",
                "purpose":"FTP anonymous login check"})
        if ssh_ports or 22 in ports:
            enum_tasks.append({"tool":"nmap","timeout":30,"can_parallel":True,
                "args":f"-p 22 --script ssh-auth-methods,ssh-hostkey {target}",
                "purpose":"SSH auth methods"})

        if enum_tasks:
            await self.emit_reasoning(
                step       = "recon_enum",
                reasoning  = f"HTTP={http_ports}, SMB={smb_ports}, FTP={ftp_ports}, SSH={ssh_ports}",
                decision   = f"Running {len(enum_tasks)} service-specific tasks in parallel",
                next_action= ", ".join(t["tool"] for t in enum_tasks[:5])
            )
            enum_r = await agent.execute_tasks(target, enum_tasks, "RECON_ENUM", self._intel)
            for k in ("login_pages","users","shares","interesting_files","web_paths"):
                for v in enum_r.get(k,[]):
                    if v not in self._intel[k]: self._intel[k].append(v)
            self._intel["service_versions"].update(enum_r.get("service_versions",{}))
            self._intel["raw_outputs"].update(enum_r.get("raw_outputs",{}))
            # merge enum_r into result for interpretation
            # Uses _dedup_strings for string lists, direct extend for other lists
            _STRING_KEYS = {"open_ports","cves","web_paths","users","shares",
                            "interesting_files","login_pages","technologies","subdomains"}
            for k, v in enum_r.items():
                if isinstance(v, list):
                    if k in _STRING_KEYS:
                        # Safe dedup — items must be strings, not dicts
                        result[k] = _merge_string_lists(result.get(k,[]), v)
                    else:
                        # List of dicts (credentials, findings, etc.) — just extend, no set()
                        existing = result.get(k, [])
                        if isinstance(existing, list):
                            result[k] = existing + [i for i in v if i not in existing]
                        else:
                            result[k] = v
                elif isinstance(v, dict):
                    result.setdefault(k, {}).update(v)

        # ── Fire recon subagents in background (SubagentConsolePage + findings DB) ──
        await self._run_phase_subagents("recon", target)

        # ── Master interprets all findings ────────────────────
        interp = self._safe_llm_result(await self._llm_interpret_recon(target, {
            **result,
            "login_pages":       self._intel["login_pages"],
            "users":             self._intel["users"],
            "shares":            self._intel["shares"],
            "service_versions":  self._intel["service_versions"],
            "interesting_files": self._intel["interesting_files"],
        }))
        self._intel["attack_surface_notes"] = interp.get("assessment","")
        await self.emit_reasoning(
            step       = "recon_complete",
            reasoning  = interp.get("summary","Recon complete"),
            decision   = interp.get("assessment",""),
            next_action= interp.get("next_phase_focus",""),
            data       = {"ports": self._intel["open_ports"],
                          "login_pages": self._intel["login_pages"]}
        )
        self._intel["attack_path"].append({
            "phase":"recon", "result": interp.get("summary",""),
            "ts": datetime.utcnow().isoformat()
        })
        await self._emit("plan_step_update", {
            "step_id":  "recon",
            "status":   "done",
            "result":   interp.get("summary",""),
            "detail":   f"Ports: {self._intel.get('open_ports',[])} | OS: {self._intel.get('os_guess','?')} | Services: {len(self._intel.get('services',{}))}",
            "found":    len(self._intel.get("open_ports",[])) > 0,
            "ts":       datetime.utcnow().isoformat()
        })

    # ─── PHASE: Vulnerability Identification ──────────────────

    async def _phase_vuln_id(self, target: str):
        """Master decides every vuln check. Agent executes + extracts CVEs."""
        await self._advance_phase(AttackPhase.VULN_ID)
        await self._emit("plan_step_update", {
            "step_id": "vuln_id", "status": "active",
            "result":  "Master planning vulnerability assessment",
            "detail":  "", "found": None, "ts": datetime.utcnow().isoformat()
        })

        from agents.vuln_agent import VulnAgent
        agent = VulnAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id
        self._vuln_agent  = agent

        vuln_plan = self._safe_llm_result(await self._llm_plan_vuln_scan(target))
        await self.emit_reasoning(
            step       = "vuln_planning",
            reasoning  = vuln_plan.get("reasoning",""),
            decision   = f"Running {len(vuln_plan.get('checks',[]))} checks in parallel",
            next_action= "Targeted vuln scan based on exact service versions"
        )
        tasks = [
            {"tool": c["tool"], "args": c.get("args",""),
             "purpose": c.get("purpose",""), "timeout": c.get("timeout",300),
             "can_parallel": True}
            for c in _safe_list(vuln_plan.get("checks")) if c.get("tool")
        ]
        ports_str = ",".join(str(p) for p in self._intel.get("open_ports",[])[:30])
        if not tasks and ports_str:
            tasks = [
                {"tool":"nmap","args":f"--script vuln,safe -sV -p {ports_str} {target}",
                 "purpose":"NSE vuln scripts","timeout":600,"can_parallel":True},
                {"tool":"searchsploit","args":self._intel.get("os_guess","linux"),
                 "purpose":"ExploitDB OS search","timeout":30,"can_parallel":True},
            ]

        result = await agent.execute_tasks(target, tasks, "VULN_ID", self._intel)

        if result.get("cves"):
            self._intel["cves"] = _merge_string_lists(self._intel["cves"], result.get("cves",[]))
        self._intel["raw_outputs"].update(result.get("raw_outputs",{}))

        # ── Fire vuln subagents in background ──────────────────
        await self._run_phase_subagents("vuln", target)

        vuln_analysis = self._safe_llm_result(await self._llm_prioritise_vulns(target, result))
        await self.emit_reasoning(
            step       = "vuln_analysis",
            reasoning  = vuln_analysis.get("reasoning",""),
            decision   = f"Priority: {vuln_analysis.get('priority_targets',[])}",
            next_action= vuln_analysis.get("exploit_recommendation",""),
            data       = vuln_analysis
        )
        self._intel["exploit_modules"] = vuln_analysis.get("exploit_modules",[])
        self._intel["attack_path"].append({
            "phase":"vuln_id",
            "result": f"CVEs: {self._intel['cves'][:5]} | Modules: {len(self._intel['exploit_modules'])}",
            "ts": datetime.utcnow().isoformat()
        })
        await self._emit("plan_step_update", {
            "step_id": "vuln_id",
            "status":  "done",
            "result":  vuln_analysis.get("reasoning","Vuln scan complete"),
            "detail":  f"CVEs: {self._intel['cves'][:5]} | Modules: {len(self._intel['exploit_modules'])}",
            "found":   len(self._intel.get("cves",[])) > 0,
            "ts":      datetime.utcnow().isoformat()
        })

    # ─── PHASE: Web Application Testing ──────────────────────

    async def _phase_web_testing(self, target: str, web_ports: List[int]):
        """Master plans all web tests. Agent executes + extracts paths/vulns."""
        await self._advance_phase(AttackPhase.VULN_ID)
        await self._emit("phase_start", {"phase":"WEB_TESTING",
            "message": f"Web testing on ports: {web_ports}"})
        await self._emit("plan_step_update", {
            "step_id": "web_testing", "status": "active",
            "result":  f"Web testing on ports: {web_ports}",
            "detail":  "", "found": None, "ts": datetime.utcnow().isoformat()
        })

        from agents.web_agent import WebAgent
        agent = WebAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id
        self._web_agent   = agent

        web_plan = self._safe_llm_result(await self._llm_plan_web_testing(target, web_ports))
        await self.emit_reasoning(
            step       = "web_planning",
            reasoning  = web_plan.get("reasoning",""),
            decision   = f"OWASP checks: {web_plan.get('owasp_checks',[])}",
            next_action= f"{len(web_plan.get('tools',[]))} web tools in parallel"
        )
        tasks = [
            {"tool": t["tool"], "args": t.get("args",""),
             "purpose": t.get("purpose",""), "timeout": t.get("timeout",300),
             "can_parallel": True}
            for t in _safe_list(web_plan.get("tools")) if t.get("tool")
        ]
        if not tasks:
            port0 = web_ports[0] if web_ports else 80
            tasks = [
                {"tool":"gobuster","timeout":180,"can_parallel":True,
                 "args":f"dir -u http://{target}:{port0} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 40 -q --no-error",
                 "purpose":"Directory enumeration"},
                {"tool":"nikto","timeout":150,"can_parallel":True,
                 "args":f"-h http://{target}:{port0} -C all -maxtime 120",
                 "purpose":"Web misconfiguration scan"},
            ]

        result = await agent.execute_tasks(target, tasks, "WEB_TESTING", self._intel)

        for p in result.get("web_paths",result.get("paths",[])):
            if p not in self._intel["web_paths"]: self._intel["web_paths"].append(p)
        for p in result.get("login_pages",[]):
            if p not in self._intel["login_pages"]: self._intel["login_pages"].append(p)
        self._intel["raw_outputs"].update(result.get("raw_outputs",{}))

        web_analysis = self._safe_llm_result(await self._llm_analyse_web_results(target, result))
        await self.emit_reasoning(
            step       = "web_analysis",
            reasoning  = web_analysis.get("reasoning",""),
            decision   = web_analysis.get("critical_findings",""),
            next_action= web_analysis.get("exploit_recommendation",""),
            data       = web_analysis
        )
        self._intel["attack_path"].append({
            "phase":"web_testing",
            "result": web_analysis.get("critical_findings","") or
                      f"Paths: {len(self._intel['web_paths'])} | Logins: {len(self._intel['login_pages'])}",
            "ts": datetime.utcnow().isoformat()
        })
        await self._emit("plan_step_update", {
            "step_id": "web_testing",
            "status":  "done",
            "result":  web_analysis.get("critical_findings","") or "Web testing complete",
            "detail":  f"Paths: {len(self._intel.get('web_paths',[]))} | Login pages: {self._intel.get('login_pages',[])}",
            "found":   len(self._intel.get("web_paths",[])) > 0 or len(self._intel.get("login_pages",[])) > 0,
            "ts":      datetime.utcnow().isoformat()
        })

        # ── Fire web subagents for deep fuzzing / injection testing ────
        web_urls = [
            f"http{'s' if int(str(p)) in (443, 8443) else ''}://{target}:{p}"
            for p in web_ports
        ]
        await self._run_phase_subagents("web", target, web_urls=web_urls)

    # ─── PHASE: OSINT ─────────────────────────────────────────

    async def _phase_osint(self, target: str):
        """Master plans all OSINT tasks. Agent executes + extracts modules."""
        await self._advance_phase(AttackPhase.OSINT)
        await self._emit("plan_step_update", {
            "step_id": "osint", "status": "active",
            "result":  "Searching ExploitDB and CVE databases",
            "detail":  "", "found": None, "ts": datetime.utcnow().isoformat()
        })

        from agents.osint_agent import OsintAgent
        agent = OsintAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id
        self._osint_agent = agent

        osint_plan = self._safe_llm_result(await self._llm_plan_osint(target))
        await self.emit_reasoning(
            step       = "osint_planning",
            reasoning  = osint_plan.get("reasoning",""),
            decision   = f"OSINT tasks: {len(osint_plan.get('searches',[]))}",
            next_action= "searchsploit per service version + external intel"
        )
        tasks = [
            {"tool": s["tool"], "args": s.get("args",target),
             "purpose": s.get("purpose",""), "timeout": s.get("timeout",60),
             "can_parallel": True}
            for s in _safe_list(osint_plan.get("searches")) if s.get("tool")
        ]
        if not tasks:
            tasks = [{"tool":"searchsploit","args":self._intel.get("os_guess","linux"),
                      "purpose":"OS exploit search","timeout":30,"can_parallel":True}]

        result = await agent.execute_tasks(target, tasks, "OSINT", self._intel)

        if result.get("cves"):
            self._intel["cves"] = _merge_string_lists(self._intel["cves"], result.get("cves",[]))
        self._intel["exploit_modules"] += result.get("exploit_modules",[])
        self._intel["raw_outputs"].update(result.get("raw_outputs",{}))
        self._intel["attack_path"].append({
            "phase":"osint",
            "result": f"Modules: {len(self._intel['exploit_modules'])} | CVEs: {len(self._intel['cves'])}",
            "ts": datetime.utcnow().isoformat()
        })
        await self._emit("plan_step_update", {
            "step_id": "osint",
            "status":  "done",
            "result":  f"ExploitDB modules: {self._intel.get('exploit_modules',[])[:3]}",
            "detail":  f"CVEs: {len(self._intel.get('cves',[]))} | Modules: {len(self._intel.get('exploit_modules',[]))}",
            "found":   len(self._intel.get("exploit_modules",[])) > 0,
            "ts":      datetime.utcnow().isoformat()
        })

    # ─── PHASE: Exploitation ──────────────────────────────────

    async def _phase_exploit(self, target: str):
        """
        Master-directed exploitation.
        Master LLM plans each attack vector based on all gathered intel.
        ExploitAgent executes exactly what Master specifies, uses LLM only
        to extract findings from output. Master evaluates and plans next vector.
        """
        await self._advance_phase(AttackPhase.EXPLOIT)
        await self._emit("plan_step_update", {
            "step_id": "exploit", "status": "active",
            "result":  f"Master planning exploitation for {target}",
            "detail":  "", "found": None, "ts": datetime.utcnow().isoformat()
        })

        from agents.exploit_agent import ExploitAgent
        agent = ExploitAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id
        self._exploit_agent = agent

        exploit_plan = self._safe_llm_result(await self._llm_plan_exploitation(target))
        await self.emit_reasoning(
            step       = "exploit_planning",
            reasoning  = exploit_plan.get("reasoning",""),
            decision   = f"Strategy: {exploit_plan.get('primary_strategy','')}",
            next_action= f"{len(exploit_plan.get('attack_vectors',[]))} attack vectors queued"
        )

        for i, vector in enumerate(_safe_list(exploit_plan.get("attack_vectors"))[:10]):
            if self._stop_requested or self._intel["shell_access"]:
                break

            # Master builds exact command
            vi = self._safe_llm_result(await self._llm_build_exploit_command(target, vector))
            if not vi.get("tool"):
                continue

            vec_label = f"{vi.get('tool',vector.get('type','?'))} — {vector.get('description','')[:60]}"
            await self._emit("plan_step_update", {
                "step_id":  f"exploit_v{i+1}",
                "label":    vec_label,
                "icon":     "💥",
                "status":   "active",
                "result":   f"Trying: {vec_label}",
                "detail":   f"Command: {vi.get('command',vi.get('args','')[:120])}",
                "found":    None,
                "ts":       datetime.utcnow().isoformat()
            })
            await self.emit_reasoning(
                step       = f"exploit_v{i+1}",
                reasoning  = vector.get("rationale",""),
                decision   = f"{vector.get('type','')} — {vector.get('description','')}",
                next_action= vi.get("command","")
            )

            # Single task: Master specified exactly one tool + args
            result = await agent.execute_tasks(
                target,
                [{"tool": vi["tool"], "args": vi.get("args",""),
                  "purpose": vector.get("description",""),
                  "timeout": vector.get("timeout",300), "can_parallel": False}],
                f"EXPLOIT_V{i+1}", self._intel
            )

            # Master evaluates the result
            eval_r = self._safe_llm_result(
                await self._llm_evaluate_exploit_result(target, vector, result))
            await self.emit_reasoning(
                step       = f"exploit_eval_{i+1}",
                reasoning  = eval_r.get("reasoning",""),
                decision   = f"Shell: {eval_r.get('shell_obtained',False)}",
                next_action= eval_r.get("next_step","Try next vector"),
                data       = eval_r
            )

            # Extract credentials / files from eval
            for c in _safe_list(eval_r.get("credentials_found")):
                if isinstance(c, dict):
                    entry = {"service": c.get("service", vector.get("type","")),
                             "user": c.get("user",""), "pass": c.get("pass",""),
                             "result": "valid"}
                    if entry not in self._intel["default_creds_tried"]:
                        self._intel["default_creds_tried"].append(entry)
            for f in _safe_list(eval_r.get("files_accessible")):
                if f not in self._intel["interesting_files"]:
                    self._intel["interesting_files"].append(f)
            if eval_r.get("useful_info"):
                self._intel["enum_findings"].append(
                    f"[{vi.get('tool','')}] {_safe_str(eval_r.get('useful_info'))[:200]}")

            if eval_r.get("store_finding") and eval_r.get("finding_title"):
                sev_map = {"critical": FindingSeverity.CRITICAL,"high": FindingSeverity.HIGH,
                           "medium": FindingSeverity.MEDIUM,"low": FindingSeverity.LOW}
                await self.store_finding(
                    severity    = sev_map.get(eval_r.get("finding_severity","medium"), FindingSeverity.MEDIUM),
                    title       = _safe_str(eval_r.get("finding_title")),
                    description = eval_r.get("reasoning","")[:500],
                    host        = target, tool_used = vi.get("tool",""),
                    evidence    = result.get("stdout","")[:1000]
                )

            if eval_r.get("shell_obtained"):
                self._intel["shell_access"]  = True
                self._intel["current_user"]  = eval_r.get("user") or "unknown"
                self._intel["attack_path"].append({
                    "phase":"exploit",
                    "result": f"Shell as {self._intel['current_user']} via {vi.get('tool','')}",
                    "ts": datetime.utcnow().isoformat()
                })
                await self._emit("plan_step_update", {
                    "step_id": "exploit",
                    "status":  "done",
                    "result":  f"Shell obtained as {self._intel['current_user']} via {vi.get('tool','')}",
                    "detail":  eval_r.get("reasoning","")[:200],
                    "found":   True,
                    "ts":      datetime.utcnow().isoformat()
                })
                if eval_r.get("user_flag"):
                    self._intel["user_flag"] = str(eval_r["user_flag"])
                    await self.store_flag("user", str(eval_r["user_flag"]), "/home/*/user.txt")
                await self._store_success_memory("exploit_pattern", {
                    "os": self._intel.get("os_guess","?"),
                    "services": _fmt_svcs(self._intel.get("services",{}))[:200],
                    "vector": vector.get("description","")[:200]
                }, ["exploit","shell",self._intel.get("os_guess","unknown").lower()])
                break
            else:
                fail_result = f"{vi.get('tool','')} → {eval_r.get('reasoning','')[:120]}"
                self._intel["attack_path"].append({
                    "phase":"exploit",
                    "result": fail_result,
                    "ts": datetime.utcnow().isoformat()
                })
                await self._emit("plan_step_update", {
                    "step_id": f"exploit_v{i+1}",
                    "label":   vec_label,
                    "icon":    "💥",
                    "status":  "failed",
                    "result":  fail_result,
                    "detail":  eval_r.get("reasoning","")[:200],
                    "found":   False,
                    "ts":      datetime.utcnow().isoformat()
                })

        if not self._intel["shell_access"]:
            # Store partial wins
            for c in [c for c in self._intel.get("default_creds_tried",[])
                      if c.get("result","").lower() in ("success","valid")]:
                await self.store_finding(
                    severity=FindingSeverity.HIGH,
                    title=f"Valid Credentials: {c.get('service','?')} — {c.get('user','?')}",
                    description=f"Credentials: {c.get('user','')}:{c.get('pass','')}",
                    host=target, tool_used="exploit_phase")
            for s in [s for s in self._intel.get("shares",[])
                      if "READ" in s.upper() or "OK" in s.upper()]:
                await self.store_finding(
                    severity=FindingSeverity.MEDIUM,
                    title=f"Readable SMB Share: {s}",
                    description="Accessible without authentication",
                    host=target, tool_used="smbclient")
            await self.emit_reasoning(
                step="exploit_complete", reasoning="All vectors exhausted",
                decision="No shell obtained — partial findings stored",
                next_action="Review findings board")

        # ── Fire exploit subagents in background (ExploitOrchestrator) ──
        # Passes gathered intel as prior context so subagents target
        # the best vectors without re-running from scratch.
        await self._run_phase_subagents("exploit", target)

    # ─── PHASE: Post-Exploitation ─────────────────────────────

    async def _phase_post_exploit(self, target: str):
        """Master plans post-exploit enumeration. Agent executes."""
        await self._advance_phase(AttackPhase.POST_EXPLOIT)
        await self._emit("plan_step_update", {
            "step_id": "post_exploit", "status": "active",
            "result":  f"Harvesting credentials and mapping network as {self._intel.get('current_user','?')}",
            "detail":  "", "found": None, "ts": datetime.utcnow().isoformat()
        })

        from agents.privesc_agent import PrivescAgent
        agent = PrivescAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id

        post_plan = self._safe_llm_result(await self._llm_plan_post_exploit(target))
        await self.emit_reasoning(
            step       = "post_exploit_planning",
            reasoning  = post_plan.get("reasoning",""),
            decision   = f"Goals: {post_plan.get('goals',[])}",
            next_action= "Enumerate system, harvest credentials, map network"
        )
        tasks = [
            {"tool": s["tool"], "args": s.get("args",""),
             "purpose": s.get("purpose",""), "timeout": s.get("timeout",60),
             "can_parallel": True}
            for s in _safe_list(post_plan.get("steps")) if s.get("tool")
        ] or [
            {"tool":"id","args":"","purpose":"Current user","timeout":5,"can_parallel":True},
            {"tool":"cat","args":"/etc/passwd","purpose":"User list","timeout":5,"can_parallel":True},
            {"tool":"find","args":"/ -name '*.conf' -readable 2>/dev/null | head -20",
             "purpose":"Config files","timeout":30,"can_parallel":True},
        ]

        result = await agent.execute_tasks(target, tasks, "POST_EXPLOIT", self._intel)
        for cred in result.get("credentials",[]):
            if cred not in self._intel["credentials"]: self._intel["credentials"].append(cred)
        for u in result.get("users",[]):
            if u not in self._intel["users"]: self._intel["users"].append(u)
        for f in result.get("interesting_files",[]):
            if f not in self._intel["interesting_files"]: self._intel["interesting_files"].append(f)
        self._intel["raw_outputs"].update(result.get("raw_outputs",{}))
        self._intel["attack_path"].append({
            "phase":"post_exploit",
            "result": f"Creds: {len(result.get('credentials',[]))} | Files: {len(result.get('interesting_files',[]))}",
            "ts": datetime.utcnow().isoformat()
        })

        # ── Fire post-exploit subagents (cred harvest, exfil, persistence) ──
        await self._run_phase_subagents("post", target)

    # ─── PHASE: Privilege Escalation ──────────────────────────

    async def _phase_privesc(self, target: str):
        """
        Master-directed privilege escalation.
        Master plans each privesc vector. PrivescAgent executes exactly
        what Master specifies and extracts findings. Master evaluates
        and plans next step. Continues until root or vectors exhausted.
        """
        await self._advance_phase(AttackPhase.PRIVESC)
        await self._emit("plan_step_update", {
            "step_id": "privesc", "status": "active",
            "result":  f"Attempting privilege escalation as {self._intel.get('current_user','unknown')}",
            "detail":  "", "found": None, "ts": datetime.utcnow().isoformat()
        })

        from agents.privesc_agent import PrivescAgent
        agent = PrivescAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id
        self._privesc_agent = agent

        # ── Round 1: Master plans initial enumeration ─────────
        privesc_plan = self._safe_llm_result(await self._llm_plan_privesc(target))
        await self.emit_reasoning(
            step       = "privesc_planning",
            reasoning  = privesc_plan.get("reasoning",""),
            decision   = f"Vectors: {privesc_plan.get('vectors',[])}",
            next_action= f"{len(privesc_plan.get('steps',[]))} tasks"
        )
        tasks = [
            {"tool": s["tool"], "args": s.get("args",""),
             "purpose": s.get("purpose",""), "timeout": s.get("timeout",120),
             "can_parallel": True}
            for s in _safe_list(privesc_plan.get("steps")) if s.get("tool")
        ] or [
            {"tool":"sudo","args":"-l","purpose":"Check sudo rights","timeout":10,"can_parallel":True},
            {"tool":"find","args":"/ -perm -u=s -type f 2>/dev/null","purpose":"SUID binaries","timeout":60,"can_parallel":True},
            {"tool":"uname","args":"-a","purpose":"Kernel version","timeout":5,"can_parallel":True},
            {"tool":"getcap","args":"-r / 2>/dev/null","purpose":"Capabilities","timeout":30,"can_parallel":True},
        ]

        result = await agent.execute_tasks(target, tasks, "PRIVESC", self._intel)
        self._intel["raw_outputs"].update(result.get("raw_outputs",{}))

        # ── Master evaluates and may run a second round ───────
        privesc_eval = self._safe_llm_result(await self._llm_evaluate_privesc(target, result))
        await self.emit_reasoning(
            step       = "privesc_eval_1",
            reasoning  = privesc_eval.get("reasoning",""),
            decision   = f"Root: {privesc_eval.get('root_obtained',False)}",
            next_action= privesc_eval.get("next_step",""),
            data       = privesc_eval
        )

        if not privesc_eval.get("root_obtained") and privesc_eval.get("next_step"):
            # Master plans follow-up exploitation of specific vectors
            followup_plan = self._safe_llm_result(await self.think_json(
                f"""Based on this privesc enumeration for {target}:
SUID binaries: {result.get('suid_files',[])}
Sudo rights: {result.get('sudo_rights','')}
Kernel: {result.get('kernel','')}
GTFOBins candidates: {privesc_eval.get('gtfobins_candidates',[])}
Next step suggested: {privesc_eval.get('next_step','')}

Plan the exact exploitation command(s) to escalate privileges.
Return JSON:
{{
  "tasks": [
    {{"tool":"tool_name","args":"exact args","purpose":"what this does","timeout":30,"can_parallel":false}}
  ]
}}"""
            ))
            followup_tasks = [
                {"tool": t["tool"], "args": t.get("args",""),
                 "purpose": t.get("purpose",""), "timeout": t.get("timeout",60),
                 "can_parallel": False}
                for t in _safe_list(followup_plan.get("tasks")) if t.get("tool")
            ]
            if followup_tasks:
                await self.emit_reasoning(
                    step       = "privesc_exploit_attempt",
                    reasoning  = privesc_eval.get("next_step",""),
                    decision   = f"Executing {len(followup_tasks)} privesc exploit tasks",
                    next_action= followup_tasks[0].get("purpose","")
                )
                result2 = await agent.execute_tasks(target, followup_tasks, "PRIVESC_EXPLOIT", self._intel)
                self._intel["raw_outputs"].update(result2.get("raw_outputs",{}))

                privesc_eval2 = self._safe_llm_result(await self._llm_evaluate_privesc(target, result2))
                await self.emit_reasoning(
                    step       = "privesc_eval_2",
                    reasoning  = privesc_eval2.get("reasoning",""),
                    decision   = f"Root: {privesc_eval2.get('root_obtained',False)}",
                    next_action= privesc_eval2.get("next_step","")
                )
                privesc_eval = privesc_eval2

        if privesc_eval.get("root_obtained"):
            self._intel["current_user"] = "root"
            await self._store_success_memory("privesc_pattern", {
                "os": self._intel.get("os_guess","?"),
                "method": privesc_eval.get("reasoning","")[:200]
            }, ["privesc","root",self._intel.get("os_guess","linux").lower()])

        rf = privesc_eval.get("root_flag") or result.get("root_flag")
        if rf:
            self._intel["root_flag"] = str(rf)
            await self.store_flag("root", str(rf), "/root/root.txt")
        privesc_result = ("Root obtained via " + privesc_eval.get("reasoning","")[:100])             if privesc_eval.get("root_obtained") else "PrivEsc attempted — no root"
        self._intel["attack_path"].append({
            "phase":"privesc",
            "result": privesc_result,
            "ts": datetime.utcnow().isoformat()
        })
        await self._emit("plan_step_update", {
            "step_id": "privesc",
            "status":  "done" if privesc_eval.get("root_obtained") else "failed",
            "result":  privesc_result,
            "detail":  privesc_eval.get("reasoning","")[:200],
            "found":   bool(privesc_eval.get("root_obtained")),
            "ts":      datetime.utcnow().isoformat()
        })

        # ── Fire privesc subagents in background ───────────────
        await self._run_phase_subagents("privesc", target)

    # ─── PHASE: Attack Planning (Attack Planner Agent) ──────

    async def _phase_attack_planning(self, target: str) -> Optional[Dict]:
        """
        Attack Planner: generates an attack tree, ranks exploit paths,
        and picks the optimal chain based on all gathered intel.
        Returns the attack tree dict or None if planning fails.
        """
        await self.set_status(AgentStatus.THINKING, "Attack Planner: generating attack tree")

        # Pull long-term memories for this target type + discovered services
        svc_tags = []
        for svc in self._intel.get("services", {}).values():
            svc_name = svc.get("service","") if isinstance(svc, dict) else str(svc)
            if svc_name:
                svc_tags.append(svc_name.lower().split("/")[0])

        mem_ctx = await self._recall_relevant_memories(
            target_type = self._intel.get("target_type", "unknown"),
            tags        = _dedup_strings(svc_tags[:5] + ["exploit", "initial_access"])
        )

        intel_ctx   = self._intel_summary()
        kb          = await self._kb(
            f"attack tree exploit chain {_fmt_svcs(self._intel.get('services',{}))} "
            f"{_safe_join(self._intel.get('cves',[])[:5])}",
            top_k=4
        )

        prompt = f"""You are an expert Attack Planner for penetration testing.
Your job is to generate a structured attack tree — a ranked set of exploit chains
from initial access through to objective (root/data/flags).

{intel_ctx}

{mem_ctx}

{kb}

ATTACK TREE REQUIREMENTS:
- Each node represents one step in the attack
- Rank paths by probability of success (0.0 to 1.0)
- The optimal_path should be the highest-probability complete chain
- Use ONLY techniques applicable to the discovered services and versions
- Include MITRE ATT&CK technique IDs for each node

Return JSON:
{{
  "assessment_summary": "One paragraph: what was found and overall attack surface",
  "attack_nodes": [
    {{
      "id": "n1",
      "step": "Initial Access",
      "technique": "Exploit Apache 2.4.49 CVE-2021-41773",
      "tool": "curl",
      "mitre_id": "T1190",
      "mitre_name": "Exploit Public-Facing Application",
      "probability": 0.85,
      "requires": [],
      "produces": "RCE as www-data"
    }},
    {{
      "id": "n2",
      "step": "Privilege Escalation",
      "technique": "sudo misconfiguration",
      "tool": "sudo -l then GTFOBins",
      "mitre_id": "T1548",
      "mitre_name": "Abuse Elevation Control Mechanism",
      "probability": 0.7,
      "requires": ["n1"],
      "produces": "root shell"
    }}
  ],
  "attack_chains": [
    {{
      "chain_id": "c1",
      "path": ["n1", "n2"],
      "description": "Apache RCE → sudo privesc",
      "combined_probability": 0.6,
      "entry_point": "port 80/443",
      "objective": "root"
    }}
  ],
  "optimal_path": ["n1", "n2"],
  "optimal_chain_id": "c1",
  "reasoning": "Why this path is most likely to succeed",
  "alternative_paths": ["c2: FTP anon → writable cron"],
  "immediate_actions": [
    "1. Test CVE-2021-41773 on port 80",
    "2. If successful, check sudo -l"
  ]
}}"""

        try:
            tree = await self.think_json(prompt)
        except Exception as e:
            await self.emit_reasoning(
                step       = "attack_planning_failed",
                reasoning  = f"Attack planner error: {e}",
                decision   = "Proceeding without formal attack tree",
                next_action= "Use intel-guided exploitation"
            )
            return None

        if tree.get("parse_error"):
            return None

        # Persist attack tree to DB
        if self._session_id:
            try:
                await db.store_attack_tree(self._session_id, tree)
            except Exception:
                pass

        # Map MITRE techniques from the tree
        for node in _safe_list(tree.get("attack_nodes")):
            if node.get("mitre_id") and node.get("mitre_name"):
                self._intel["mitre_techniques"].append({
                    "id":     node["mitre_id"],
                    "name":   node["mitre_name"],
                    "tactic": node.get("step",""),
                    "tool":   node.get("tool","")
                })

        await self.emit_reasoning(
            step       = "attack_tree_generated",
            reasoning  = tree.get("assessment_summary", "Attack tree generated"),
            decision   = f"Optimal path: {' → '.join(tree.get('optimal_path', []))}",
            next_action= "\n".join(_safe_list(tree.get("immediate_actions"))[:3]),
            data       = {
                "nodes":    len(tree.get("attack_nodes", [])),
                "chains":   len(tree.get("attack_chains", [])),
                "optimal":  tree.get("optimal_chain_id"),
            }
        )

        await self._emit("attack_tree_ready", {
            "tree":    tree,
            "session": self._session_id
        })

        self._intel["attack_path"].append({
            "phase":  "attack_planning",
            "result": f"Attack tree: {len(tree.get('attack_nodes',[]))} nodes, optimal: {tree.get('optimal_chain_id','')}",
            "ts":     datetime.utcnow().isoformat()
        })

        return tree

    # ─── PHASE: Lateral Movement ──────────────────────────────

    async def _phase_lateral_movement(self, target: str):
        """
        Lateral Movement: AD/domain enumeration, Kerberos attacks, NTLM relay/capture.
        Uses LateralAgent (AdEnumSubagent → KerberosSubagent + NtlmCaptureSubagent).
        Falls back to basic internal network scan if no domain context.
        """
        await self._advance_phase(AttackPhase.POST_EXPLOIT)
        await self.emit_reasoning(
            step       = "lateral_movement_start",
            reasoning  = f"Shell obtained as {self._intel.get('current_user','?')}. Pivoting to lateral movement — AD enum, Kerberos, NTLM capture.",
            decision   = "Run LateralAgent: AD enumeration → Kerberos attacks + NTLM relay in parallel",
            next_action= "LateralAgent dispatching subagents"
        )

        # ── Pull domain context from intel ────────────────────────────
        domain   = self._intel.get("domain", "")
        dc_ip    = self._intel.get("dc_ip", "")
        username = ""
        password = ""
        hashes   = ""
        creds = self._intel.get("credentials", []) + [
            c for c in self._intel.get("default_creds_tried", [])
            if c.get("result", "") in ("success", "valid")
        ]
        if creds:
            best = creds[0]
            username = best.get("username", "") or best.get("user", "")
            password = best.get("password", "") or best.get("pass", "")
            hashes   = best.get("hashes", "") or best.get("hash", "")

        interface = self._intel.get("interface", "eth0")

        from agents.lateral.lateral_agent import LateralAgent
        agent = LateralAgent(broadcast=self.broadcast)
        try:
            await agent.run(
                session_id = self._session_id,
                target     = target,
                domain     = domain,
                dc_ip      = dc_ip,
                username   = username,
                password   = password,
                hashes     = hashes,
                interface  = interface,
            )
        except Exception as exc:
            await self.emit_reasoning(
                step       = "lateral_agent_error",
                reasoning  = f"LateralAgent error: {exc}",
                decision   = "Continuing with available intel",
                next_action= "Proceed to evidence collection"
            )

        # ── Attach any lateral targets discovered to attack graph ─────
        new_hosts = self._intel.get("lateral_targets", [])
        if new_hosts:
            await self.emit_reasoning(
                step       = "lateral_hosts_found",
                reasoning  = f"Lateral movement phase found {len(new_hosts)} additional host(s)",
                decision   = f"Pivot targets: {new_hosts[:5]}",
                next_action= "Attack graph updated"
            )
            for host in new_hosts[:10]:
                await self.add_node(
                    node_id  = f"lateral_{host.replace('.','_')}",
                    type     = "host",
                    label    = host,
                    host     = host,
                    metadata = {"role": "lateral_target", "discovered_from": target}
                )
                await self.add_edge(
                    source = f"target_{target.replace('.','_').replace('/','_')}",
                    target = f"lateral_{host.replace('.','_')}",
                    label  = "lateral_movement",
                    tool   = "lateral_agent"
                )
            await self._capture_evidence(
                phase        = "lateral_movement",
                evidence_type= "command_transcript",
                title        = f"Lateral movement: {len(new_hosts)} pivot target(s)",
                content      = f"Target: {target}\nDomain: {domain or 'N/A'}\nPivot hosts: {new_hosts}",
                severity     = "high",
                mitre_tech   = "T1021"
            )
        else:
            await self.emit_reasoning(
                step       = "lateral_movement_complete",
                reasoning  = "Lateral movement phase complete — no additional pivot targets identified",
                decision   = "Single-host or non-domain environment",
                next_action= "Proceed to evidence collection"
            )

        await self._map_mitre("lateral_agent", success=bool(new_hosts), host=target)
        self._intel["attack_path"].append({
            "phase":  "lateral_movement",
            "result": f"LateralAgent: {len(new_hosts)} pivot targets; domain={domain or 'none'}",
            "ts":     datetime.utcnow().isoformat()
        })

        # ── Fire lateral subagents in background ────────────────────
        await self._run_phase_subagents("lateral", target)

    # ─── PHASE: Cloud Infrastructure ─────────────────────────

    async def _phase_cloud(self, target: str):
        """Cloud infrastructure enumeration — AWS, Azure, GCP."""
        await self.emit_reasoning(
            step       = "cloud_enum_start",
            reasoning  = "Cloud services detected. Enumerating AWS/Azure/GCP metadata and misconfigurations.",
            decision   = "Run CloudAgent: AwsEnum + AzureEnum + GcpEnum in parallel",
            next_action= "CloudAgent dispatching subagents"
        )
        from agents.cloud.cloud_agent import CloudAgent
        agent = CloudAgent(broadcast=self.broadcast)
        try:
            await agent.run(session_id=self._session_id, target=target)
        except Exception as exc:
            await self.emit_reasoning(
                step="cloud_agent_error", reasoning=f"CloudAgent error: {exc}",
                decision="Continuing", next_action="Cloud phase skipped"
            )
        self._intel["attack_path"].append({
            "phase": "cloud", "result": "CloudAgent executed",
            "ts": datetime.utcnow().isoformat()
        })

    # ─── PHASE: Container Security ────────────────────────────

    async def _phase_container(self, target: str):
        """Docker / Kubernetes security audit."""
        await self.emit_reasoning(
            step       = "container_audit_start",
            reasoning  = "Container platform detected. Auditing Docker and Kubernetes security posture.",
            decision   = "Run ContainerAgent: DockerAudit + K8sAudit",
            next_action= "ContainerAgent dispatching subagents"
        )
        from agents.container.container_agent import ContainerAgent
        agent = ContainerAgent(broadcast=self.broadcast)
        try:
            await agent.run(session_id=self._session_id, target=target)
        except Exception as exc:
            await self.emit_reasoning(
                step="container_agent_error", reasoning=f"ContainerAgent error: {exc}",
                decision="Continuing", next_action="Container phase skipped"
            )
        self._intel["attack_path"].append({
            "phase": "container", "result": "ContainerAgent executed",
            "ts": datetime.utcnow().isoformat()
        })

    # ─── PHASE: AV/EDR Evasion ────────────────────────────────

    async def _phase_evasion(self, target: str):
        """AV/EDR defense enumeration and evasion techniques."""
        os_type = "windows" if "windows" in self._intel.get("os_guess", "").lower() else "linux"
        lhost   = self._intel.get("lhost", "LHOST")
        lport   = int(self._intel.get("lport", 4444))
        await self.emit_reasoning(
            step       = "evasion_start",
            reasoning  = f"Shell obtained on {os_type.upper()} system. Enumerating defenses and applying evasion.",
            decision   = "Run EvasionAgent: DefenseEnum → AvEvasion + (AMSI bypass on Windows)",
            next_action= "EvasionAgent dispatching subagents"
        )
        from agents.evasion.evasion_agent import EvasionAgent
        agent = EvasionAgent(broadcast=self.broadcast)
        try:
            await agent.run(
                session_id=self._session_id, target=target,
                os_type=os_type, lhost=lhost, lport=lport
            )
        except Exception as exc:
            await self.emit_reasoning(
                step="evasion_agent_error", reasoning=f"EvasionAgent error: {exc}",
                decision="Continuing", next_action="Evasion phase skipped"
            )
        self._intel["attack_path"].append({
            "phase": "evasion", "result": f"EvasionAgent executed (os={os_type})",
            "ts": datetime.utcnow().isoformat()
        })

    # ─── PHASE: Traffic Analysis ──────────────────────────────

    async def _phase_traffic(self, target: str):
        """Passive traffic capture and credential sniffing."""
        interface = self._intel.get("interface", "eth0")
        await self.emit_reasoning(
            step       = "traffic_analysis_start",
            reasoning  = "Starting passive traffic capture for credential sniffing and protocol analysis.",
            decision   = "Run TrafficAgent: PcapCapture + CredentialSniff in parallel",
            next_action= "TrafficAgent dispatching subagents"
        )
        from agents.traffic.traffic_agent import TrafficAgent
        agent = TrafficAgent(broadcast=self.broadcast)
        try:
            await agent.run(
                session_id=self._session_id, target=target,
                interface=interface, duration=30
            )
        except Exception as exc:
            await self.emit_reasoning(
                step="traffic_agent_error", reasoning=f"TrafficAgent error: {exc}",
                decision="Continuing", next_action="Traffic phase skipped"
            )
        self._intel["attack_path"].append({
            "phase": "traffic", "result": "TrafficAgent executed",
            "ts": datetime.utcnow().isoformat()
        })

    # ─── PHASE: Forensics (deep evidence) ────────────────────

    async def _phase_forensics_deep(self, target: str):
        """Digital forensics — artifact collection, timeline, memory analysis."""
        os_type      = "windows" if "windows" in self._intel.get("os_guess", "").lower() else "linux"
        attack_start = self._intel.get("session_start", "")
        await self.emit_reasoning(
            step       = "forensics_start",
            reasoning  = f"Running forensic collection on {os_type.upper()} target for artifact preservation.",
            decision   = "Run ForensicsAgent: ArtifactCollect → Timeline + MemoryAnalysis",
            next_action= "ForensicsAgent dispatching subagents"
        )
        from agents.forensics.forensics_agent import ForensicsAgent
        agent = ForensicsAgent(broadcast=self.broadcast)
        try:
            await agent.run(
                session_id=self._session_id, target=target,
                os_type=os_type, attack_start=attack_start
            )
        except Exception as exc:
            await self.emit_reasoning(
                step="forensics_agent_error", reasoning=f"ForensicsAgent error: {exc}",
                decision="Continuing", next_action="Forensics phase skipped"
            )
        self._intel["attack_path"].append({
            "phase": "forensics", "result": "ForensicsAgent executed",
            "ts": datetime.utcnow().isoformat()
        })

    # ─── PHASE: Enhanced Evidence Collection ──────────────────

    async def _phase_evidence_enhanced(self, target: str):
        """Screenshot capture and flag/proof harvesting via EvidenceAgent."""
        os_type = "windows" if "windows" in self._intel.get("os_guess", "").lower() else "linux"
        web_ports = [p for p, s in self._intel.get("services", {}).items()
                     if ("http" in str(s).lower())]
        web_urls  = [f"http://{target}:{p}" for p in web_ports[:3]]
        await self.emit_reasoning(
            step       = "evidence_enhanced_start",
            reasoning  = f"Harvesting screenshots and flags from {os_type.upper()} target.",
            decision   = "Run EvidenceAgent: Screenshot + FlagCapture in parallel",
            next_action= "EvidenceAgent dispatching subagents"
        )
        from agents.evidence.evidence_agent import EvidenceAgent
        agent = EvidenceAgent(broadcast=self.broadcast)
        try:
            await agent.run(
                session_id=self._session_id, target=target,
                os_type=os_type, web_urls=web_urls
            )
        except Exception as exc:
            await self.emit_reasoning(
                step="evidence_agent_error", reasoning=f"EvidenceAgent error: {exc}",
                decision="Continuing", next_action="Enhanced evidence phase skipped"
            )
        self._intel["attack_path"].append({
            "phase": "evidence_enhanced", "result": "EvidenceAgent executed",
            "ts": datetime.utcnow().isoformat()
        })

    # ─── PHASE: Wireless Assessment ───────────────────────────

    async def _phase_wireless(self, target: str):
        """Wireless security assessment — WiFi scan, WPA2 crack, evil twin."""
        wireless_cfg = self._intel.get("wireless_config", {})
        await self.emit_reasoning(
            step       = "wireless_start",
            reasoning  = "Wireless assessment requested. Running WiFi enumeration and attack modules.",
            decision   = "Run WirelessAgent: WifiScan → Wpa2Crack (+ EvilTwin if configured)",
            next_action= "WirelessAgent dispatching subagents"
        )
        from agents.wireless.wireless_agent import WirelessAgent
        agent = WirelessAgent(broadcast=self.broadcast)
        try:
            await agent.run(
                session_id   = self._session_id,
                target       = target,
                interface    = wireless_cfg.get("interface", "wlan0"),
                target_bssid = wireless_cfg.get("bssid", ""),
                target_ssid  = wireless_cfg.get("ssid", ""),
                channel      = int(wireless_cfg.get("channel", 6)),
                wordlist     = wireless_cfg.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
                do_evil_twin = wireless_cfg.get("evil_twin", False),
            )
        except Exception as exc:
            await self.emit_reasoning(
                step="wireless_agent_error", reasoning=f"WirelessAgent error: {exc}",
                decision="Continuing", next_action="Wireless phase skipped"
            )
        self._intel["attack_path"].append({
            "phase": "wireless", "result": "WirelessAgent executed",
            "ts": datetime.utcnow().isoformat()
        })

    # ─── PHASE: IoT Assessment ────────────────────────────────

    async def _phase_iot(self, target: str):
        """IoT device fingerprinting, default cred testing, protocol analysis and firmware CVEs."""
        await self.emit_reasoning(
            step       = "iot_start",
            reasoning  = (
                f"IoT assessment triggered for {target}. "
                "Will fingerprint device, test default credentials, probe IoT protocols "
                "(MQTT/CoAP/Modbus/RTSP/TR-069/UPnP), and correlate firmware CVEs."
            ),
            decision   = "Run IoTAgent: DeviceScan → DefaultCreds → ProtocolTest → FirmwareAnalysis",
            next_action= "IoTAgent dispatching subagents"
        )
        from agents.iot.iot_agent import IoTAgent
        agent = IoTAgent(
            session_id = self._session_id,
            target     = target,
            broadcast  = self.broadcast,
            db         = db.get_db(),
        )
        try:
            summary = await agent.run(
                open_ports = self._intel.get("open_ports", []),
                services   = self._intel.get("services", {}),
            )
            self._intel["attack_path"].append({
                "phase": "iot", "result": f"IoTAgent complete: {summary}",
                "ts": datetime.utcnow().isoformat()
            })
        except Exception as exc:
            await self.emit_reasoning(
                step="iot_agent_error", reasoning=f"IoTAgent error: {exc}",
                decision="Continuing", next_action="IoT phase skipped"
            )

    def _extract_internal_hosts(self, text: str) -> List[str]:
        """Extract internal IP addresses from nmap -sn output."""
        hosts = []
        for m in re.finditer(
            r'Nmap scan report for (?:\S+\s+)?\(?((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\)?',
            text
        ):
            hosts.append(m.group(1))
        return list(set(hosts))

    # ─── PHASE: Evidence Collection ──────────────────────────

    async def _phase_evidence_collection(self, session_id: str, target: str):
        """
        Automated evidence collection: consolidates all captured evidence,
        captures final shell proof if shell was obtained,
        and structures everything for the report.
        """
        await self.set_status(AgentStatus.THINKING, "Collecting and structuring evidence")

        evidence_count = len(self._intel.get("evidence", []))

        # Capture attack path as narrative evidence
        attack_path = self._intel.get("attack_path", [])
        if attack_path:
            narrative = "\n".join(
                f"[{i+1}] [{s.get('phase','?').upper()}] {s.get('result','')}"
                for i, s in enumerate(attack_path)
            )
            await self._capture_evidence(
                phase        = "evidence_collection",
                evidence_type= "command_transcript",
                title        = "Complete Attack Narrative",
                content      = narrative,
                severity     = "info"
            )

        # Capture credentials found
        all_creds = self._intel.get("credentials", []) + [
            c for c in self._intel.get("default_creds_tried", [])
            if c.get("result","") in ("success","valid")
        ]
        if all_creds:
            cred_text = "\n".join(
                f"{c.get('username','?') or c.get('user','?')}:"
                f"{c.get('password','?') or c.get('pass','?')} "
                f"[{c.get('service','?')}]"
                for c in all_creds[:20]
            )
            await self._capture_evidence(
                phase        = "evidence_collection",
                evidence_type= "credential",
                title        = f"Credentials Harvested ({len(all_creds)} total)",
                content      = cred_text,
                severity     = "critical",
                mitre_tech   = "T1003"
            )

        # Capture flags as evidence
        flags_found = []
        if self._intel.get("user_flag"):
            flags_found.append(f"user.txt: {self._intel['user_flag']}")
            await self._capture_evidence(
                phase        = "evidence_collection",
                evidence_type= "shell_output",
                title        = "User Flag Captured",
                content      = self._intel["user_flag"],
                severity     = "critical",
                mitre_tech   = "T1005"
            )
        if self._intel.get("root_flag"):
            flags_found.append(f"root.txt: {self._intel['root_flag']}")
            await self._capture_evidence(
                phase        = "evidence_collection",
                evidence_type= "shell_output",
                title        = "Root Flag Captured",
                content      = self._intel["root_flag"],
                severity     = "critical",
                mitre_tech   = "T1005"
            )

        # Capture interesting files found
        ifiles = self._intel.get("interesting_files", [])
        if ifiles:
            await self._capture_evidence(
                phase        = "evidence_collection",
                evidence_type= "file_content",
                title        = f"Sensitive Files Discovered ({len(ifiles)})",
                content      = "\n".join(ifiles[:30]),
                severity     = "high",
                mitre_tech   = "T1083"
            )

        # Capture MITRE technique summary
        techniques = self._intel.get("mitre_techniques", [])
        if techniques:
            mitre_text = "\n".join(
                f"{t.get('id','?')} | {t.get('tactic','?')} | {t.get('name','?')} [{t.get('tool','')}]"
                for t in techniques
            )
            await self._capture_evidence(
                phase        = "evidence_collection",
                evidence_type= "command_transcript",
                title        = f"MITRE ATT&CK Techniques Used ({len(techniques)})",
                content      = mitre_text,
                severity     = "info"
            )

        new_count = len(self._intel.get("evidence", []))
        await self.emit_reasoning(
            step       = "evidence_collected",
            reasoning  = f"Evidence collection complete. {new_count - evidence_count} new items captured.",
            decision   = f"Total evidence: {new_count} items across all phases",
            next_action= "Generate comprehensive report",
            data       = {
                "total_evidence": new_count,
                "flags":          len(flags_found),
                "credentials":    len(all_creds),
                "mitre_techs":    len(techniques),
            }
        )

    # ─── PHASE: Reporting ────────────────────────────────────

    async def _phase_reporting(self, session_id: str, target: str):
        await self._advance_phase(AttackPhase.REPORTING)
        await self.set_status(AgentStatus.THINKING, "Generating executive report")

        findings = await db.get_findings(session_id)
        flags    = await db.get_flags(session_id)
        summary  = await db.get_findings_summary(session_id)

        # Build structured finding details for the LLM
        finding_details = []
        for f in findings[:12]:
            sev   = f.get("severity", "?").upper()
            title = f.get("title", "?")
            host  = f.get("host", target)
            port  = f.get("port", "")
            svc   = f.get("service", "")
            cves  = ", ".join(f.get("cves", [])[:3])
            desc  = f.get("description", "")[:200]
            rem   = (f.get("extra") or {}).get("remediation", "")[:150]
            line  = f"[{sev}] {title}"
            if port: line += f" — {host}:{port}"
            if svc:  line += f" ({svc})"
            if cves: line += f" — CVEs: {cves}"
            if desc: line += f"\n       Description: {desc}"
            if rem:  line += f"\n       Remediation: {rem}"
            finding_details.append(line)

        flag_lines = []
        for fl in flags:
            flag_lines.append(f"  [{fl.get('flag_type','?').upper()}] {fl.get('value','?')} "
                              f"(found at {fl.get('location','?')})")

        attack_path_lines = []
        for i, step in enumerate(self._intel.get("attack_path", []), 1):
            attack_path_lines.append(
                f"  {i}. [{step.get('phase','?').upper()}] {step.get('result','')}"
            )

        intel_ctx = self._intel_summary()
        kb = await self._kb(
            f"penetration test report {self._intel.get('os_guess','')} "
            f"{_fmt_svcs(self._intel.get('services',{}))}",
            top_k=3
        )

        # Load evidence and MITRE data for richer report
        evidence_items = []
        mitre_mappings = []
        try:
            evidence_items = await db.get_evidence(session_id)
            mitre_mappings = await db.get_mitre_mappings(session_id)
        except Exception:
            evidence_items = self._intel.get("evidence", [])
            mitre_mappings = self._intel.get("mitre_techniques", [])

        # Build MITRE ATT&CK table
        mitre_lines = []
        seen_techniques = set()
        for t in mitre_mappings:
            tid = t.get("technique_id") or t.get("id","?")
            if tid not in seen_techniques:
                seen_techniques.add(tid)
                tname  = t.get("technique_name") or t.get("name","?")
                tactic = t.get("tactic","?")
                tool   = t.get("tool_used") or t.get("tool","?")
                mitre_lines.append(f"  {tid} | {tactic} | {tname} | [{tool}]")

        # Build evidence summary
        evidence_lines = []
        for ev in evidence_items[:15]:
            etype   = ev.get("evidence_type","?")
            etitle  = ev.get("title","?")
            ephase  = ev.get("phase","?")
            evidence_lines.append(f"  [{ephase}] [{etype}] {etitle}")

        # Attack tree summary
        attack_tree = self._intel.get("attack_tree") or {}
        tree_summary = ""
        if attack_tree:
            opt = attack_tree.get("optimal_path",[])
            nodes = {n["id"]: n for n in attack_tree.get("attack_nodes",[])}
            if opt:
                chain = " → ".join(nodes.get(nid,{}).get("technique",nid) for nid in opt)
                tree_summary = f"Optimal attack chain: {chain}"

        report_prompt = f"""You are a senior penetration tester writing a detailed engagement report.
You MUST base every statement on the actual findings provided below.
Do NOT invent findings. Do NOT use generic filler text.

{intel_ctx}

FINDINGS ({summary.get('total',0)} total):
  Critical: {summary.get('critical',0)} | High: {summary.get('high',0)} | Medium: {summary.get('medium',0)} | Low: {summary.get('low',0)}

DETAILED FINDINGS:
{chr(10).join(finding_details) if finding_details else "  No findings recorded."}

FLAGS CAPTURED:
{chr(10).join(flag_lines) if flag_lines else "  No flags captured."}

ATTACK PATH TAKEN:
{chr(10).join(attack_path_lines) if attack_path_lines else "  No attack path recorded."}

SHELL ACCESS: {'YES — compromised as: ' + str(self._intel.get('current_user','?')) if self._intel.get('shell_access') else 'No shell obtained'}

ATTACK TREE ASSESSMENT:
{tree_summary if tree_summary else "  Not available"}

EVIDENCE COLLECTED:
{chr(10).join(evidence_lines) if evidence_lines else "  No structured evidence"}

MITRE ATT&CK TECHNIQUES USED:
  ID      | Tactic                  | Technique                        | Tool
{chr(10).join(mitre_lines) if mitre_lines else "  None mapped"}

LATERAL MOVEMENT:
  Additional hosts found: {self._intel.get('lateral_targets', [])}
  Pivot paths: {len(self._intel.get('pivot_paths',[]))} identified
{kb}

Write a professional penetration test report. Reference SPECIFIC findings, ports, CVEs, and services by name.
Use the EXACT data above — do not generalise or invent.

Structure your response EXACTLY as:

## EXECUTIVE SUMMARY
(2-3 paragraphs for non-technical management. Name the target, what was found, business risk.)

## CRITICAL FINDINGS
(For each critical/high finding: exact port/service/CVE, proof of exploitation, business impact.)

## ATTACK NARRATIVE
(Step-by-step story of the engagement. Use the attack path. Name specific tools and findings.)

## MITRE ATT&CK COVERAGE
(Table: Tactic | Technique ID | Technique Name | Tool Used | Outcome)

## EVIDENCE SUMMARY
(List key evidence items captured during the engagement.)

## REMEDIATION ROADMAP
(Top 5 prioritised fixes. Priority level | What to fix | Exact remediation | Timeline)

## RISK RATING
Overall risk: [Critical/High/Medium/Low] — one paragraph justification based on findings."""

        try:
            report_text = await self.think(report_prompt)
        except RuntimeError:
            report_text = "LLM unavailable — manual report generation required."

        await self._emit("report_ready", {
            "summary":     report_text,
            "findings":    summary,
            "flags":       flags,
            "intel":       self._intel,
            "attack_path": self._intel.get("attack_path", [])
        })

    # ─── LLM Planning Methods ─────────────────────────────────

    def _safe_llm_result(self, result: any, default: dict = None) -> dict:
        """
        Ensure any think_json result is a usable dict.
        Handles: None return, list return (LLM wrapped in []), parse_error dicts.
        Also normalises all null-valued list fields to empty lists.
        """
        if result is None:
            return default or {}
        if isinstance(result, list):
            # LLM returned a JSON array - try to use first element if it's a dict
            if result and isinstance(result[0], dict):
                result = result[0]
            else:
                return default or {}
        if not isinstance(result, dict):
            return default or {}
        # Normalise: replace None values for known list fields with []
        LIST_FIELDS = [
            "steps", "checks", "tools", "searches", "attack_vectors",
            "attack_nodes", "attack_chains", "optimal_path", "phases",
            "priority_services", "high_value_services", "immediate_wins",
            "priority_attack_paths", "immediate_actions", "goals",
            "vectors", "manual_checks", "owasp_checks", "exploits",
            "exploit_modules", "manual_exploits", "expected_vulns",
            "priority_targets", "credentials_found", "files_accessible",
            "gtfobins_candidates", "alternative_paths",
        ]
        for field in LIST_FIELDS:
            if field in result and result[field] is None:
                result[field] = []
        # Normalise: replace None for known string fields with ""
        STR_FIELDS = [
            "reasoning", "summary", "assessment", "strategy", "rationale",
            "exploit_recommendation", "next_phase_focus", "next_step",
            "decision", "useful_info", "finding_title", "finding_severity",
            "attack_surface", "primary_strategy", "optimal_chain_id",
            "assessment_summary", "current_user", "user_flag", "shell_id",
        ]
        for field in STR_FIELDS:
            if field in result and result[field] is None:
                result[field] = ""
        return result

    async def _create_master_plan(self, target: str, target_type: str) -> Dict:
        kb = await self._kb(f"pentest {target_type} attack plan methodology", top_k=3)
        intel_ctx = self._intel_summary()
        operator_guidance = ""
        if getattr(self, '_notes', ''):
            operator_guidance += f"\nOPERATOR NOTES (MUST follow these instructions): {self._notes}"
        if getattr(self, '_scope', ''):
            operator_guidance += f"\nSCOPE/FOCUS (prioritize these areas): {self._scope}"

        prompt = f"""You are a master penetration tester. Create a DETAILED, SPECIFIC structured plan for testing:
Target: {target}
Type: {target_type}{operator_guidance}
{intel_ctx}
{kb}

PLANNING REQUIREMENTS:
- If operator notes specify a focus area (e.g., "focus on web app port 80"), prioritize those tools first
- For web targets: ALWAYS include OWASP Top 10 testing phases (injection, broken access control, auth failures, etc.)
- For network targets: Include service-specific enumeration and CVE-targeted exploitation
- Be SPECIFIC about which tools and techniques to use for this target type
- Include web-specific phases if ANY HTTP/HTTPS ports are likely present

Return JSON:
{{
  "assessment_type": "network|web|ctf|ad|fullscope",
  "rationale": "specific reasoning for this assessment type based on target",
  "target_profile": "what you expect to find and why",
  "operator_guidance_followed": "how operator notes are being incorporated",
  "phases": [
    {{"phase": "recon", "tools": ["nmap -sV -sC", "whatweb", "gobuster"], "reasoning": "comprehensive service and tech detection"}},
    {{"phase": "vuln_id", "tools": ["nikto", "searchsploit", "nmap --script vuln"], "reasoning": "targeted vulnerability identification"}},
    {{"phase": "web_testing", "tools": ["gobuster", "sqlmap", "ffuf"], "reasoning": "OWASP Top 10 coverage if web services found"}}
  ],
  "attack_hypothesis": "most specific likely attack path based on target type",
  "priority_services": ["http", "smb"],
  "owasp_focus": ["A01-BrokenAccessControl", "A03-Injection", "A05-Injection"],
  "ctf_flags_expected": true,
  "requires_web_testing": true,
  "risk_level": "high|medium|low"
}}"""
        return await self.think_json(prompt)

    async def _llm_plan_recon(self, target: str, plan: Dict) -> Dict:
        already_run = list(self._used_tools.keys())
        _svc_hint = _safe_join(plan.get("priority_services", []))
        kb = await self._kb(
            f"recon reconnaissance {plan.get('assessment_type','')} {_svc_hint}",
            phase="recon", top_k=3
        )
        intel_ctx = self._intel_summary()
        prompt = f"""Plan the reconnaissance phase for target: {target}
Assessment type: {plan.get('assessment_type', 'unknown')}
Priority services: {plan.get('priority_services', [])}
{f"OPERATOR GUIDANCE: {self._notes}" if getattr(self, '_notes', '') else ""}
{f"SCOPE FOCUS: {self._scope}" if getattr(self, '_scope', '') else ""}
Tools already used this session (DO NOT repeat these): {already_run}
{intel_ctx}
{kb}
Pick DIFFERENT tools from: nmap, masscan, rustscan, fping, whatweb, wafw00f, dnsrecon, fierce, amass, enum4linux, smbmap, onesixtyone, snmpwalk

Return JSON with SPECIFIC nmap flags, tool commands, and reasoning.
Use at most 4 steps — prefer speed over exhaustiveness:
{{
  "strategy": "passive|active|aggressive",
  "reasoning": "why this strategy",
  "steps": [
    {{
      "tool": "nmap",
      "args": "-sS -sV --open -p- --min-rate 5000 {target}",
      "purpose": "Full TCP scan with service detection",
      "timeout": 300
    }},
    {{
      "tool": "whatweb",
      "args": "-a 3 http://{target}",
      "purpose": "Web technology detection",
      "timeout": 30
    }}
  ]
}}"""
        return await self.think_json(prompt)

    async def _llm_interpret_recon(self, target: str, result: Dict) -> Dict:
        ports    = result.get("open_ports", [])
        svcs     = result.get("services", {})
        _svc_str = _fmt_svcs(svcs)
        _os      = result.get("os_guess", "unknown")
        svc_vers = result.get("service_versions", {})
        login_pg = result.get("login_pages", [])
        users    = result.get("users", [])
        shares   = result.get("shares", [])
        ifiles   = result.get("interesting_files", [])

        kb = await self._kb(
            f"recon results {_svc_str} {_os} attack surface enumeration",
            top_k=3,
        )

        # Build a rich service version block for the LLM
        svc_detail_lines = []
        for port, ver in list(svc_vers.items())[:10]:
            svc_detail_lines.append(f"  port {port}: {ver}")

        prompt = f"""You are a senior penetration tester. Analyse these reconnaissance results for {target}
and identify the most promising attack vectors. Be SPECIFIC — name exact services, versions, and attack paths.

TARGET PROFILE:
- OS: {_os}
- Open ports: {sorted(ports)}
- Service versions:
{chr(10).join(svc_detail_lines) if svc_detail_lines else "  (none extracted yet)"}

ENUMERATION FINDINGS:
- Web paths found: {result.get('web_paths', [])[:15]}
- Login pages: {login_pg}
- Interesting files: {ifiles[:10]}
- Users discovered: {users}
- SMB shares: {shares}
- Technologies: {result.get('technologies', [])[:8]}

{kb}

Based on the above, identify:
1. Which services are most likely vulnerable and WHY (name specific version CVEs if applicable)
2. Which login pages exist and what credential attacks to try
3. Whether SMB shares are accessible and what they contain
4. What the most efficient path to initial access looks like

Return JSON:
{{
  "summary": "Specific description of what was found — name exact services, versions, interesting paths",
  "assessment": "Detailed attack surface description with specific vulnerabilities likely present",
  "interesting_ports": [most interesting port numbers as integers],
  "attack_surface": "network|web|smb|mixed|ftp",
  "next_phase_focus": "exact focus for vuln scan based on what was found",
  "high_value_services": ["service:port eg apache:80", "smb:445"],
  "immediate_wins": ["list of quick wins to try — default creds, anon FTP, readable shares etc"],
  "priority_attack_paths": [
    "1. Check FTP anonymous login on port 21",
    "2. Test login page at /admin with default creds",
    "3. Enumerate SMB share BACKUP for sensitive files"
  ]
}}"""
        return await self.think_json(prompt)

    async def _llm_plan_vuln_scan(self, target: str) -> Dict:
        ports = self._intel.get("open_ports", [])
        svcs  = self._intel.get("services", {})
        already_run = list(self._used_tools.keys())
        ports_str = ",".join(str(p) for p in ports[:30])
        _svc_str  = _fmt_svcs(svcs)
        _os       = self._intel.get("os_guess", "unknown")
        kb = await self._kb(
            f"vulnerability scan {_svc_str} {_os} CVE exploit",
            top_k=4
        )
        svc_versions = self._intel.get("service_versions", {})
        svc_ver_lines = [f"  {p}: {v}" for p,v in list(svc_versions.items())[:10]]
        login_pages  = self._intel.get("login_pages", [])
        users        = self._intel.get("users", [])
        intel_ctx    = self._intel_summary()

        prompt = f"""Plan TARGETED vulnerability scanning for {target}.
Use the EXACT service versions below to search for known CVEs and exploits.
Do NOT run generic scans — each check must target a specific service or version found.

{intel_ctx}
{kb}

EXACT SERVICE VERSIONS TO INVESTIGATE:
{chr(10).join(svc_ver_lines) if svc_ver_lines else "  Run nmap -sV first to get versions"}

LOGIN PAGES FOUND (test for auth bypass, default creds, SQLi):
{login_pages if login_pages else "  None found yet"}

Tools already run (DO NOT repeat): {already_run}

AVAILABLE TOOLS AND WHEN TO USE THEM:
- searchsploit: ALWAYS run for each exact service version found (e.g. "Apache 2.4.49", "vsftpd 2.3.4")
- nmap --script vuln: for open ports with known vuln scripts
- nikto: for HTTP services — finds misconfigurations, default files, known CVEs
- sslscan: ONLY if HTTPS/TLS found
- wpscan: ONLY if WordPress detected
- enum4linux / smbmap: ONLY if SMB found and not yet enumerated
- hydra: ONLY if login pages or SSH/FTP found AND usernames are known

Max 4 checks. Pick what gives the most signal for THIS specific target.
{f"OPERATOR NOTES: {self._notes}" if getattr(self, '_notes', '') else ""}

For WEB targets specifically, ensure OWASP Top 10 coverage:
- A01: Test IDOR and path traversal (feroxbuster, manual curl)
- A03: SQL injection (sqlmap), Command injection (commix)
- A05: Security misconfiguration (nikto, headers check)
- A07: Authentication brute force (hydra on login pages)

Return JSON:
{{
  "reasoning": "why these specific checks target the services/versions found",
  "checks": [
    {{
      "tool": "searchsploit",
      "args": "Apache 2.4.49",
      "purpose": "Find public exploits for exact Apache version",
      "timeout": 30
    }}
  ],
  "expected_vulns": ["CVE-XXXX-XXXXX: description", "..."]
}}"""
        return await self.think_json(prompt)

    async def _llm_prioritise_vulns(self, target: str, result: Dict) -> Dict:
        vulns = result.get("vulnerabilities", [])
        cves  = result.get("cves", [])
        _cve_str = _safe_join(cves[:8])
        _svc_str = _fmt_svcs(self._intel.get("services", {}))
        kb = await self._kb(
            f"exploit {_cve_str} {_svc_str} metasploit initial access",
            outcome_filter="shell obtained",
            top_k=4,
        )
        prompt = f"""Prioritise these vulnerabilities for exploitation on {target}:
Vulnerabilities: {vulns[:10]}
CVEs found: {cves}
Exploit modules from searchsploit: {result.get('exploits', [])}
{kb}
Return JSON:
{{
  "reasoning": "which vulns are most exploitable and why, using past experience",
  "priority_targets": ["vuln1", "vuln2"],
  "exploit_modules": [
    {{"module": "exploit/...", "target_port": 80, "reliability": "excellent|good|normal"}}
  ],
  "exploit_recommendation": "best path to initial access",
  "manual_exploits": ["CVE-xxx python exploit script"]
}}"""
        return await self.think_json(prompt)

    async def _llm_plan_web_testing(self, target: str, web_ports: List[int]) -> Dict:
        techs = self._intel.get("technologies", [])
        paths = self._intel.get("web_paths", [])
        already_run = list(self._used_tools.keys())
        port0 = web_ports[0] if web_ports else 80
        _tech_str = _safe_join(techs[:5])
        kb = await self._kb(
            f"web application exploit {_tech_str} sqli lfi upload rce shell",
            phase="exploit", top_k=4
        )
        kb_cmds = await self._kbc(
            f"web exploit {_tech_str} gobuster ffuf sqlmap nikto command",
            top_k=3,
        )
        intel_ctx = self._intel_summary()
        prompt = f"""Plan OWASP-based web application testing for {target}.
Web ports: {web_ports}
Detected technologies: {techs}
Known paths: {paths[:10]}
Tools already run (DO NOT repeat): {already_run}
{intel_ctx}
{kb}
{kb_cmds}
Available web tools: nikto, gobuster, ffuf, sqlmap, wfuzz, commix, wapiti, dirb, wpscan, davtest, wafw00f
Pick tools NOT already used. Max 4 tools.

Return JSON:
{{
  "reasoning": "what web vulns are most likely given the tech stack",
  "owasp_checks": ["A01:Broken Access Control", "A03:Injection"],
  "tools": [
    {{
      "tool": "gobuster",
      "args": "dir -u http://{target}:{port0} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 50 -q --no-error",
      "purpose": "Directory enumeration",
      "timeout": 180
    }},
    {{
      "tool": "nikto",
      "args": "-h http://{target}:{port0} -C all -maxtime 120",
      "purpose": "Web misconfiguration scan",
      "timeout": 150
    }}
  ],
  "manual_checks": ["check login forms", "test file upload"]
}}"""
        return await self.think_json(prompt)

    async def _llm_analyse_web_results(self, target: str, result: Dict) -> Dict:
        _techs   = result.get('technologies', [])
        _wv      = result.get('web_vulns', [])[:5]
        _paths   = result.get('paths', [])[:10]
        _tech_str = _safe_join(_techs[:5])
        _wv_str   = _safe_join(_wv)
        kb = await self._kb(
            f"web vuln {_tech_str} {_wv_str} exploit path traversal sqli upload",
            outcome_filter="shell obtained",
            top_k=3,
        )
        prompt = f"""Analyse web application testing results for {target}:
Paths found: {_paths}
Web vulns: {_wv}
Technologies: {_techs}
{kb}
Return JSON:
{{
  "reasoning": "what was found, severity, and how past experience informs exploitation",
  "critical_findings": "description of most critical web vulns",
  "exploit_recommendation": "best web exploitation path",
  "sqli_found": true|false,
  "xss_found": true|false,
  "lfi_found": true|false,
  "upload_bypass": true|false
}}"""
        return await self.think_json(prompt)

    async def _llm_plan_osint(self, target: str) -> Dict:
        _svcs = [_fmt_svc(v) for v in list(self._intel["services"].values())[:5]]
        _os   = self._intel.get('os_guess', 'unknown')
        _svc_str = " ".join(_svcs)
        kb = await self._kb(
            f"OSINT CVE searchsploit {_svc_str} {_os} exploit database",
            top_k=3,
        )
        prompt = f"""Plan OSINT for target: {target}
Known services: {_svcs}
OS: {_os}
{kb}
Return JSON:
{{
  "reasoning": "what intel would help exploitation",
  "searches": [
    {{
      "tool": "searchsploit",
      "args": "{self._intel.get('os_guess', '')}",
      "purpose": "Find OS exploits",
      "timeout": 30
    }}
  ]
}}"""
        return await self.think_json(prompt)

    async def _llm_plan_exploitation(self, target: str) -> Dict:
        ports     = self._intel.get("open_ports", [])
        svcs      = self._intel.get("services", {})
        vulns     = self._intel.get("vulnerabilities", [])
        mods      = self._intel.get("exploit_modules", [])
        web_vulns = self._intel.get("web_vulns", [])
        cves      = self._intel.get("cves", [])
        _os       = self._intel.get("os_guess", "unknown")
        _svc_str  = _fmt_svcs(svcs)
        _cve_str  = _safe_join(cves[:5])
        _wv_str   = _safe_join(web_vulns[:3])

        # Query KB specifically for successful exploitation against this profile
        kb = await self._kb(
            f"exploit shell {_svc_str} {_cve_str} {_wv_str} {_os} initial access",
            outcome_filter="shell obtained",
            top_k=5,
        )
        # Also fetch any relevant exploit examples without outcome filter (broader)
        kb_broad = await self._kb(
            f"exploit {_svc_str} {_os} {_cve_str}",
            top_k=3,
        )
        # Fetch specific exploit commands used against similar services
        kb_cmds = await self._kbc(
            f"exploit {_svc_str} {_os} shell command",
            top_k=4,
        )

        intel_ctx = self._intel_summary()

        # Build service-specific context for exploitation
        svc_detail = []
        for port, ver in list(self._intel.get("service_versions", {}).items())[:10]:
            svc_detail.append(f"  {port}: {ver}")
        login_pages = self._intel.get("login_pages", [])
        users       = self._intel.get("users", [])
        shares      = self._intel.get("shares", [])
        ifiles      = self._intel.get("interesting_files", [])

        prompt = f"""You are an expert penetration tester planning targeted exploitation for {target}.
DO NOT just try generic exploits. Use EXACTLY what the recon phase found to drive your plan.

{intel_ctx}

{kb}
{kb_broad}
{kb_cmds}

EXPLOITATION METHODOLOGY — follow this priority order:
1. IMMEDIATE WINS first: default/weak credentials on discovered login pages and services
2. KNOWN CVE exploits for exact versions found (use service_versions above)
3. SERVICE MISCONFIGURATIONS: anonymous FTP, readable SMB shares, open databases
4. WEB APPLICATION ATTACKS on discovered paths: SQLi on login forms, LFI on file params, upload bypass
5. BRUTE FORCE: only if specific usernames were found AND service is appropriate
6. METASPLOIT: only for reliable modules matching exact CVEs found

SPECIFIC TARGETS FROM RECON:
- Login pages to attack: {login_pages if login_pages else "none found — check web paths"}
- Usernames to use: {users if users else "try common: admin, root, guest, user, test"}
- SMB shares to check: {shares if shares else "none enumerated"}
- Interesting files found: {ifiles[:5] if ifiles else "none"}
- Service versions: {chr(10).join(svc_detail) if svc_detail else "  see intel summary above"}

IMPORTANT: For each attack vector, explain EXACTLY:
- What specific endpoint/service/path you are targeting
- What exact credentials or payload you are using
- What output will confirm success (not just "shell obtained" — be specific)

Return JSON:
{{
  "primary_strategy": "web|network|smb|credential|ftp|mixed",
  "reasoning": "which specific findings from recon make this the best path",
  "attack_vectors": [
    {{
      "type": "default_creds|web_sqli|web_upload|web_lfi|ftp_anon|smb_read|cve_exploit|hydra|metasploit",
      "description": "exactly what you are targeting — e.g. admin login at /manager/html",
      "rationale": "why this specific target is exploitable based on recon findings",
      "tool": "exact tool name",
      "args": "complete args string with real values from intel — no placeholders",
      "timeout": 120,
      "success_indicator": "exact string in output that confirms success"
    }}
  ]
}}"""
        return await self.think_json(prompt)

    async def _llm_build_exploit_command(self, target: str, vector: Dict) -> Dict:
        _tool = vector.get('tool', '')
        _type = vector.get('type', '')
        _desc = vector.get('description', '')
        # Fetch command-type chunks specifically — these are actual tool invocations from writeups
        kb = await self._kbc(
            f"{_tool} {_type} {_desc} command flags",
            top_k=4,
        )
        # Also fetch technique context
        kb_tech = await self._kb(
            f"{_tool} {_type} {_desc} exploit technique",
            top_k=2,
        )
        svc_versions = self._intel.get("service_versions", {})
        login_pages  = self._intel.get("login_pages", [])
        users        = self._intel.get("users", [])
        web_paths    = self._intel.get("web_paths", [])
        shares       = self._intel.get("shares", [])

        prompt = f"""Build the EXACT runnable command for this exploitation step against {target}.
Use REAL values from the intelligence gathered — NO placeholders like <target> or <wordlist>.

ATTACK VECTOR:
- Type: {_type}
- Description: {_desc}
- Suggested tool: {_tool}

AVAILABLE INTELLIGENCE TO USE IN THE COMMAND:
- Web paths found: {web_paths[:10]}
- Login pages: {login_pages}
- Known users: {users if users else ["admin", "root", "guest", "test", "user"]}
- Service versions: {list(svc_versions.items())[:8]}
- SMB shares: {shares}
- CVEs confirmed: {self._intel.get('cves', [])[:5]}
- Target OS: {self._intel.get('os_guess', 'unknown')}

{kb}

{kb_tech}

COMMAND BUILDING RULES:
- For hydra: use -L with common usernames or discovered usernames, target specific port and service
- For sqlmap: use actual login page URL found, add --forms or specific parameter
- For gobuster: use the most appropriate wordlist for the tech stack
- For searchsploit: use the exact version string (e.g. "vsftpd 2.3.4" not just "vsftpd")
- For curl: use actual paths found, include relevant headers
- Do NOT use placeholders — if you need a wordlist, use the actual Kali path

Return JSON:
{{
  "tool": "exact_tool_name",
  "args": "complete args with real target IP and actual paths — no <placeholders>",
  "command": "tool + full args as single string for display",
  "lhost": "attacker IP if reverse shell needed, else null",
  "lport": "listener port if needed, else null",
  "pre_command": "any setup command needed first (e.g. start listener), else null"
}}"""
        return await self.think_json(prompt)

    async def _llm_evaluate_exploit_result(self, target: str, vector: Dict, result: Dict) -> Dict:
        stdout   = result.get("stdout", "")[:2000]
        _tool    = vector.get('tool', '')
        _desc    = vector.get('description', '')
        _exit    = result.get('exit_code', -1)
        # Only query KB if exploit failed — to suggest what to try next
        kb = ""
        if _exit != 0 or "error" in stdout.lower() or "failed" in stdout.lower():
            _svc_str = _fmt_svcs(self._intel.get("services", {}))
            kb = await self._kb(
                f"{_tool} failed next step alternative {_svc_str}",
                top_k=3,
            )
            # Also get alternative command examples
            kb_alt_cmds = await self._kbc(
                f"alternative exploit {_svc_str} {_tool} failed bypass",
                top_k=3,
            )
            if kb_alt_cmds:
                kb = kb + "\n" + kb_alt_cmds
        prompt = f"""Evaluate this penetration testing attempt and extract ALL useful findings.
Do NOT only look for shells — extract ANY information that helps the attack.

Tool: {_tool}
Command: {vector.get('args', '')}
Exit code: {_exit}
Intended target: {_desc}

OUTPUT:
{stdout}

{kb}

Analyse the output carefully for:
1. Shell/code execution (obvious success)
2. Valid credentials confirmed (login success messages, session tokens)
3. Files/directories accessible (readable files, directory listings)
4. Service information (version strings, error messages revealing tech stack)
5. Usernames or email addresses in output
6. Error messages revealing the application framework or backend

Return JSON:
{{
  "shell_obtained": true or false,
  "reasoning": "exactly what happened — be specific, quote relevant output",
  "user": "username if shell obtained, else null",
  "shell_id": "session ID if metasploit, else null",
  "user_flag": "HTB/CTF flag value if found in output (format: flag{{...}} or hex string), else null",
  "credentials_found": [{{"user": "x", "pass": "y", "service": "z"}}],
  "files_accessible": ["list of files or dirs confirmed accessible"],
  "useful_info": "any other useful information extracted from output",
  "next_step": "most logical next step based on what was found",
  "store_finding": true or false,
  "finding_severity": "critical|high|medium|low",
  "finding_title": "short title if worth storing as a finding"
}}"""
        return await self.think_json(prompt)

    async def _llm_plan_privesc(self, target: str) -> Dict:
        _os   = self._intel.get("os_guess", "unknown")
        _user = self._intel.get("current_user", "unknown")
        # Query KB for privesc that achieved root on this OS (technique context)
        kb = await self._kb(
            f"privilege escalation {_os} sudo suid cron kernel root",
            phase_filter="privesc",
            outcome_filter="root",
            top_k=5,
        )
        # Fetch specific privesc command examples from writeups
        kb_cmds = await self._kbc(
            f"privesc {_os} sudo suid GTFOBins linpeas command",
            top_k=4,
        )
        # Fetch step-by-step privesc procedures
        kb_procs = await self._kbp(
            f"privilege escalation {_os} methodology steps",
            top_k=2,
        )
        # Broader fallback if no root-filtered results
        kb_broad = await self._kb(
            f"privesc {_os} {_user} GTFOBins linpeas",
            top_k=3,
        )
        intel_ctx = self._intel_summary()
        prompt = f"""Plan privilege escalation for {target}.
{intel_ctx}
{kb}
{kb_cmds}
{kb_procs}
{kb_broad}
Use the knowledge base above to prioritise vectors that succeeded on similar systems.

Using standard privesc methodology:
1. Automated enumeration (linPEAS)
2. Check sudo -l misconfigurations
3. SUID binaries → GTFOBins
4. Writable cron jobs
5. Kernel exploits (last resort)
6. PATH hijacking, wildcard injection

Return JSON:
{{
  "reasoning": "most likely privesc vectors given the OS and past experience",
  "vectors": ["sudo misconfiguration", "suid binaries", "..."],
  "steps": [
    {{
      "tool": "find",
      "args": "/ -perm -u=s -type f 2>/dev/null",
      "purpose": "Find SUID binaries",
      "timeout": 60
    }},
    {{
      "tool": "sudo",
      "args": "-l",
      "purpose": "Check sudo rights",
      "timeout": 10
    }}
  ]
}}"""
        return await self.think_json(prompt)

    async def _llm_evaluate_privesc(self, target: str, result: Dict) -> Dict:
        _suid   = result.get('suid_files', [])[:10]
        _sudo   = result.get('sudo_rights', '')
        _kernel = result.get('kernel', '')
        _root   = result.get('root_flag')
        # Only query KB if not rooted yet
        kb = ""
        kb_cmds = ""
        if not _root:
            _os = self._intel.get("os_guess", "unknown")
            _suid_str = " ".join(str(s) for s in _suid[:5])
            kb = await self._kb(
                f"privesc {_os} {_kernel} {_suid_str} {_sudo} GTFOBins root",
                phase_filter="privesc",
                top_k=4,
            )
            # Get specific GTFOBins/privesc commands for the discovered binaries
            if _suid or _sudo:
                kb_cmds = await self._kbc(
                    f"GTFOBins {_suid_str} {_sudo} exploit root shell command",
                    top_k=3,
                )
        prompt = f"""Evaluate privilege escalation results:
SUID binaries: {_suid}
Sudo rights: {_sudo}
Kernel: {_kernel}
Root flag: {_root}
LinPEAS output summary: {result.get('linpeas_summary', '')[:1000]}
{kb}
{kb_cmds}
Return JSON:
{{
  "root_obtained": true|false,
  "reasoning": "what worked or best vectors to try next",
  "gtfobins_candidates": ["binary1", "binary2"],
  "next_step": "if not root yet, most promising path based on intel and past experience"
}}"""
        return await self.think_json(prompt)

    async def _llm_plan_post_exploit(self, target: str) -> Dict:
        prompt = f"""Plan post-exploitation for {target}.
Current user: {self._intel.get('current_user', 'unknown')}
Return JSON with enumeration goals: {{
  "reasoning": "...",
  "goals": ["harvest credentials", "map network", "persistence"],
  "steps": []
}}"""
        return await self.think_json(prompt)

    # ─── Instruction Builders ─────────────────────────────────

    def _build_recon_instructions(self, target: str, plan: Dict) -> List[Instruction]:
        instructions = []
        for step in _safe_list(plan.get("steps")):
            if not step.get("tool"):
                continue
            instructions.append(Instruction(
                tool      = step["tool"],
                args      = step.get("args", target),
                target    = target,
                reasoning = step.get("purpose", "Recon step"),
                phase     = AttackPhase.RECON,
                timeout   = step.get("timeout", 300)
            ))
        # Fallback if LLM gave empty plan
        if not instructions:
            instructions = [
                Instruction("nmap", f"-sS -sV -sC -O --open -p- --min-rate 3000 {target}", target,
                            "Full port scan with service detection", AttackPhase.RECON, 600),
                Instruction("whatweb", f"-a 3 http://{target}", target,
                            "Web technology fingerprinting", AttackPhase.RECON, 60),
            ]
        return instructions

    def _build_vuln_instructions(self, target: str, plan: Dict) -> List[Instruction]:
        instructions = []
        ports_str = ",".join(str(p) for p in self._intel.get("open_ports", [])[:30])
        for check in _safe_list(plan.get("checks")):
            if not check.get("tool"):
                continue
            instructions.append(Instruction(
                tool      = check["tool"],
                args      = check.get("args", ""),
                target    = target,
                reasoning = check.get("purpose", "Vulnerability check"),
                phase     = AttackPhase.VULN_ID,
                timeout   = check.get("timeout", 300)
            ))
        if not instructions and ports_str:
            instructions = [
                Instruction("nmap", f"--script vuln,safe -sV -p {ports_str} {target}", target,
                            "NSE vulnerability scripts", AttackPhase.VULN_ID, 600),
                Instruction("searchsploit", self._intel.get("os_guess", "linux"), target,
                            "Search ExploitDB for OS exploits", AttackPhase.VULN_ID, 30),
            ]
        return instructions

    def _build_web_instructions(self, target: str, web_ports: List[int], plan: Dict) -> List[Instruction]:
        instructions = []
        for tool_cfg in _safe_list(plan.get("tools")):
            if not tool_cfg.get("tool"):
                continue
            instructions.append(Instruction(
                tool      = tool_cfg["tool"],
                args      = tool_cfg.get("args", ""),
                target    = target,
                reasoning = tool_cfg.get("purpose", "Web testing"),
                phase     = AttackPhase.VULN_ID,
                timeout   = tool_cfg.get("timeout", 300)
            ))
        return instructions

    def _build_osint_instructions(self, target: str, plan: Dict) -> List[Instruction]:
        instructions = []
        for step in _safe_list(plan.get("searches")):
            if not step.get("tool"):
                continue
            instructions.append(Instruction(
                tool      = step["tool"],
                args      = step.get("args", target),
                target    = target,
                reasoning = step.get("purpose", "OSINT"),
                phase     = AttackPhase.OSINT,
                timeout   = step.get("timeout", 60)
            ))
        return instructions

    def _build_privesc_instructions(self, target: str, plan: Dict) -> List[Instruction]:
        instructions = []
        for step in _safe_list(plan.get("steps")):
            if not step.get("tool"):
                continue
            instructions.append(Instruction(
                tool      = step["tool"],
                args      = step.get("args", ""),
                target    = target,
                reasoning = step.get("purpose", "PrivEsc check"),
                phase     = AttackPhase.PRIVESC,
                timeout   = step.get("timeout", 120)
            ))
        if not instructions:
            instructions = [
                Instruction("sudo", "-l", target, "Check sudo rights", AttackPhase.PRIVESC, 10),
                Instruction("find", "/ -perm -u=s -type f 2>/dev/null", target, "SUID files", AttackPhase.PRIVESC, 60),
                Instruction("uname", "-a", target, "Kernel version", AttackPhase.PRIVESC, 5),
                Instruction("getcap", "-r / 2>/dev/null", target, "Capabilities", AttackPhase.PRIVESC, 30),
            ]
        return instructions

    # ─── Task Builders (Master → Agent) ─────────────────────────

    def _build_tasks_from_instructions(self, instructions: List) -> List[Dict]:
        """Convert Instruction objects to task dicts for execute_tasks."""
        tasks = []
        seen = set()
        for instr in (instructions or []):
            if not instr.tool:
                continue
            cache_key = f"{instr.tool}:{instr.args}"
            if cache_key in seen:
                continue
            seen.add(cache_key)
            tasks.append({
                "tool":         instr.tool,
                "args":         instr.args,
                "purpose":      instr.reasoning,
                "timeout":      instr.timeout,
                "can_parallel": True,  # all instructions run in parallel by default
            })
        return tasks

    def _build_tasks_from_attack_vectors(self, vectors: List[Dict], target: str) -> List[Dict]:
        """Convert LLM attack_vectors to task dicts, building exact commands."""
        tasks = []
        seen  = set()
        for v in (vectors or []):
            tool = (v.get("tool") or "").strip()
            args = (v.get("args") or "").strip()
            if not tool or not args:
                continue
            cache_key = f"{tool}:{args}"
            if cache_key in seen:
                continue
            seen.add(cache_key)
            tasks.append({
                "tool":         tool,
                "args":         args,
                "purpose":      v.get("description") or v.get("rationale",""),
                "timeout":      int(v.get("timeout") or 300),
                "can_parallel": True,
            })
        return tasks

    def _build_tasks_from_steps(self, steps: List[Dict], target: str, phase) -> List[Dict]:
        """Convert LLM steps list to task dicts."""
        tasks = []
        seen  = set()
        for s in (steps or []):
            tool = (s.get("tool") or "").strip()
            args = (s.get("args") or "").strip()
            if not tool:
                continue
            cache_key = f"{tool}:{args}"
            if cache_key in seen:
                continue
            seen.add(cache_key)
            tasks.append({
                "tool":         tool,
                "args":         args,
                "purpose":      s.get("purpose") or s.get("reasoning",""),
                "timeout":      int(s.get("timeout") or 120),
                "can_parallel": True,
            })
        return tasks

    # ─── Instruction Dispatch ─────────────────────────────────

    async def _dispatch_and_collect(
        self,
        agent:        "BaseAgent",
        instructions: List[Instruction],
        phase_label:  str,
        parallel:     bool = False
    ) -> Dict:
        """
        Issue instructions to a slave agent.
        - Deduplicates tools already run in this session
        - Skips cached identical commands
        - Checks user guidance queue before each tool
        - After every tool result, emits a concise status broadcast
        - parallel=True runs independent tools concurrently
        """
        combined = {
            "open_ports": [], "services": {}, "os_guess": "unknown",
            "web_paths":  [], "subdomains": [], "technologies": [],
            "vulnerabilities": [], "cves": [], "exploits": [],
            "web_vulns": [], "paths": [], "suid_files": [],
            "sudo_rights": "", "kernel": "", "linpeas_summary": "",
            "exploit_modules": [], "credentials": [], "stdout": "",
            "exit_code": 0
        }

        # Prepend any operator-forced tools (from guidance queue)
        forced = getattr(self, "_forced_instructions", [])
        if forced:
            self._forced_instructions = []
            for fi in forced:
                instructions.insert(0, Instruction(
                    tool      = fi["tool"],
                    args      = fi.get("args", self._intel.get("target", "")),
                    target    = self._intel.get("target", ""),
                    reasoning = fi.get("reasoning", "Operator-forced instruction"),
                    phase     = self.phase,
                    timeout   = fi.get("timeout", 300)
                ))

        # Filter: skip ONLY exact duplicate (same tool + same args)
        # Tools can run as many times as needed with DIFFERENT args.
        # The LLM and agents decide relevance — we do not cap.
        filtered = []
        for instr in instructions:
            cache_key = f"{instr.tool}:{instr.args}"
            if cache_key in self._instruction_cache:
                await self.emit_reasoning(
                    step       = f"{phase_label.lower()}_skip",
                    reasoning  = f"{instr.tool} with identical args already run — using cache",
                    decision   = "Using cached result for identical command",
                    next_action= "Next instruction",
                    data       = {"tool": instr.tool}
                )
                self._merge_result(combined, self._instruction_cache[cache_key], instr, agent)
                continue
            filtered.append(instr)

        if not filtered:
            return combined

        async def _run_one(instr: Instruction) -> tuple:
            """Execute a single instruction and return (instr, result)."""
            if self._stop_requested:
                return (instr, {"stdout": "", "stderr": "", "exit_code": -1})

            # Check guidance queue before running
            await self._apply_pending_guidance()

            await self.emit_reasoning(
                step       = f"{phase_label.lower()}_dispatch",
                reasoning  = instr.reasoning,
                decision   = f"→ {agent.name} running {instr.tool}",
                next_action= f"{instr.tool} {instr.args[:120]}",
                data       = {"tool": instr.tool, "phase": phase_label}
            )
            result = await agent.execute_instruction(instr)
            self._used_tools[instr.tool] = self._used_tools.get(instr.tool, 0) + 1
            self._instruction_cache[f"{instr.tool}:{instr.args}"] = result
            # Auto-map every tool to MITRE ATT&CK
            await self._map_mitre(instr.tool, success=(result.get("exit_code",1)==0))

            # Immediately broadcast what the tool found
            stdout = result.get("stdout", "")
            quick_ports = agent._extract_ports(stdout)
            quick_cves  = agent._extract_cves(stdout)
            await self._emit("tool_findings", {
                "tool":      instr.tool,
                "phase":     phase_label,
                "ports":     quick_ports,
                "cves":      quick_cves,
                "exit_code": result.get("exit_code", -1),
                "lines":     len(stdout.splitlines())
            })
            return (instr, result)

        # Always run all independent tools in parallel.
        # Master passes parallel=False ONLY for strict sequential dependencies
        # (e.g. must get ports before scanning them).
        if parallel or len(filtered) > 1:
            raw_results = await asyncio.gather(*[_run_one(i) for i in filtered], return_exceptions=True)
            pairs = [r for r in raw_results if isinstance(r, tuple) and len(r) == 2
                     and not isinstance(r[1], Exception)]
        else:
            pairs = []
            for instr in filtered:
                instr_result = await _run_one(instr)
                if isinstance(instr_result, tuple):
                    pairs.append(instr_result)

        # Merge all results into combined dict
        for (instr, result) in pairs:
            if isinstance(result, Exception):
                continue
            self._merge_result(combined, result, instr, agent)

        # After all tools run, add discovered services to attack graph
        for (instr, result) in pairs:
            if isinstance(result, Exception):
                continue
            stdout = result.get("stdout", "")
            new_services = agent._extract_services(stdout)
            for port, svc in new_services.items():
                await self.add_node(
                    node_id  = f"port_{port}_{svc.get('service', '')}",
                    type     = "service",
                    label    = f"{svc.get('service','?')}:{port}",
                    host     = instr.target,
                    port     = port,
                    metadata = svc
                )
                target_node = f"target_{instr.target.replace('.','_').replace('/','_')}"
                await self.add_edge(
                    source = target_node,
                    target = f"port_{port}_{svc.get('service', 'unknown')}",
                    label  = instr.tool,
                    tool   = instr.tool
                )

        return combined

    def _merge_result(self, combined: Dict, result: Dict, instr: "Instruction", agent: "BaseAgent"):
        """Extract structured data from a single tool result and merge into combined dict.
        Wrapped in try/except so one bad tool result never kills the phase.
        """
        try:
            stdout = result.get("stdout", "") or ""

            # Append raw stdout
            combined["stdout"] = combined.get("stdout", "") + "\n" + stdout

            # Ports and services
            new_ports = agent._extract_ports(stdout)
            combined["open_ports"] = list(set(combined["open_ports"] + [p for p in new_ports if isinstance(p, int)]))
            new_services = agent._extract_services(stdout)
            if isinstance(new_services, dict):
                combined["services"].update(new_services)

            # OS detection
            if combined["os_guess"] == "unknown":
                if re.search(r'\blinux\b', stdout, re.IGNORECASE):
                    combined["os_guess"] = "Linux"
                elif re.search(r'\bwindows\b', stdout, re.IGNORECASE):
                    combined["os_guess"] = "Windows"

            # CVEs
            cves = agent._extract_cves(stdout)
            combined["cves"] = _merge_string_lists(combined["cves"], cves)

            # Web paths
            paths = agent._extract_web_paths(stdout)
            combined["web_paths"].extend(p for p in paths if p not in combined["web_paths"])
            combined["paths"].extend(p for p in paths if p not in combined["paths"])

            # Credentials
            creds = agent._extract_credentials(stdout)
            combined["credentials"].extend(creds)

            # PrivEsc specific
            if instr.tool.lower() == "sudo" or "-l" in instr.args:
                combined["sudo_rights"] = stdout[:1000]
            if instr.tool == "find" and "perm" in instr.args:
                combined["suid_files"] = [l.strip() for l in stdout.splitlines() if l.strip()]
            if instr.tool == "uname":
                combined["kernel"] = stdout.strip()
            if "linpeas" in instr.tool.lower():
                combined["linpeas_summary"] = stdout[:3000]
            if result.get("exit_code", 1) == 0:
                combined["exit_code"] = 0

            # ── Extended extraction ──────────────────────────
            # Store raw output per tool for LLM context
            combined.setdefault("raw_outputs", {})[instr.tool] = stdout[-2000:]

            # Extract service version strings from nmap -sV output
            for m in re.finditer(
                r'(\d+)/(?:tcp|udp)\s+open\s+\S+\s+(.{5,80})', stdout
            ):
                port_num = int(m.group(1))
                version  = m.group(2).strip()
                combined.setdefault("service_versions", {})[port_num] = version
                # Also build human-readable service description
                desc = f"{port_num}: {version}"
                if desc not in combined.setdefault("open_services_detail", []):
                    combined["open_services_detail"].append(desc)

            # Extract usernames from various tools
            for m in re.finditer(
                r'(?:user(?:name)?[:\s]+|account[:\s]+|login[:\s]+)([a-zA-Z0-9_\-\.]{2,32})',
                stdout, re.IGNORECASE
            ):
                u = m.group(1).strip()
                if u.lower() not in ('anonymous', 'none', 'null', 'root', 'admin') and                    u not in combined.setdefault("users", []):
                    combined["users"].append(u)

            # Extract SMB/NFS shares
            for m in re.finditer(
                r'(?:Disk|IPC|SYSVOL|NETLOGON|[A-Za-z$][A-Za-z0-9_$\-]{0,30})\s+(?:READ|WRITE|OK|NO ACCESS)',
                stdout, re.IGNORECASE
            ):
                share = m.group(0).split()[0]
                if share not in combined.setdefault("shares", []):
                    combined["shares"].append(share)

            # Extract HTTP login pages
            if instr.tool in ("gobuster", "ffuf", "dirb", "dirsearch", "feroxbuster"):
                for m in re.finditer(
                    r'(/[^\s]*(?:login|signin|auth|admin|wp-login|console|dashboard)[^\s]*)',
                    stdout, re.IGNORECASE
                ):
                    path = m.group(1).strip()
                    if path not in combined.setdefault("login_pages", []):
                        combined["login_pages"].append(path)

            # Extract interesting files
            for m in re.finditer(
                r'(/[^\s]*(?:config|passwd|shadow|\.env|backup|\.bak|\.zip|\.tar|id_rsa|\.xml|\.conf)[^\s]*)',
                stdout, re.IGNORECASE
            ):
                f_path = m.group(1).strip()
                if f_path not in combined.setdefault("interesting_files", []):
                    combined["interesting_files"].append(f_path)

            # Extract service banners (first 200 chars of banner-like lines)
            if instr.tool in ("nmap", "netcat", "nc", "curl"):
                for m in re.finditer(
                    r'(?:Server:|X-Powered-By:|Banner:|Version:)\s*(.{5,100})',
                    stdout, re.IGNORECASE
                ):
                    banner = m.group(1).strip()
                    combined.setdefault("banners", {})[instr.tool] = banner

        except Exception as _merge_err:
            # Never let a single bad result kill the whole phase
            import logging
            logging.getLogger("master_agent").warning(
                f"_merge_result error for {instr.tool}: {_merge_err}"
            )

    # ─── Phase helpers ────────────────────────────────────────

    async def _advance_phase(self, phase: AttackPhase):
        self.phase = phase
        await db.update_session_phase(self._session_id, phase)
        await self._emit("phase_change", {
            "phase":   str(phase),
            "message": f"→ {str(phase).upper().replace('_',' ')}",
            "ts":      datetime.utcnow().isoformat()
        })

    async def _wait_for_confirmation(self, phase: str, timeout: int = 3600) -> bool:
        evt = asyncio.Event()
        self._confirm_events[f"confirm_{phase}"] = evt
        try:
            await asyncio.wait_for(evt.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def _apply_pending_guidance(self):
        """
        Check if user has injected guidance and apply it before the next tool runs.
        Non-blocking — returns immediately if nothing queued.
        Handles: skip_phase, force_tool, note (context injection into next LLM call).
        """
        try:
            guidance = self._guidance_queue.get_nowait()
        except asyncio.QueueEmpty:
            return

        directive  = guidance.get("directive", "")
        skip_phase = guidance.get("skip_phase", "")
        force_tool = guidance.get("force_tool", "")
        force_args = guidance.get("force_args", "")
        note       = guidance.get("note", "")

        await self.emit_reasoning(
            step       = "user_guidance_applied",
            reasoning  = f"User guidance received: {note or directive or 'no message'}",
            decision   = (
                f"Skipping phase: {skip_phase}" if skip_phase else
                f"Forcing tool: {force_tool} {force_args}" if force_tool else
                f"Context note injected: {note}"
            ),
            next_action= force_tool or ("Continue — note will inform next LLM call" if note else "Continue"),
            data       = guidance
        )
        await self._emit("guidance_applied", {
            "directive": directive,
            "message":   f"Guidance applied: {note or directive or force_tool or skip_phase}"
        })

        # 1. Skip an entire phase
        if skip_phase:
            self._phases_to_run = [p for p in self._phases_to_run if p != skip_phase]
            await self.emit_reasoning(
                step       = "phase_skip_applied",
                reasoning  = f"User requested skipping phase: {skip_phase}",
                decision   = f"Removed {skip_phase} from remaining phases",
                next_action= "Proceed to next phase",
                data       = {"skipped": skip_phase, "remaining": self._phases_to_run}
            )

        # 2. Force-run a specific tool immediately
        if force_tool:
            # Store in pending forced instructions — picked up by _dispatch_and_collect
            if not hasattr(self, "_forced_instructions"):
                self._forced_instructions = []
            self._forced_instructions.append({
                "tool": force_tool,
                "args": force_args or self._intel.get("target", ""),
                "reasoning": f"User-forced: {note or 'Manual guidance from operator'}"
            })
            await self.emit_reasoning(
                step       = "force_tool_queued",
                reasoning  = f"Operator forced tool execution: {force_tool}",
                decision   = f"Will run: {force_tool} {force_args}",
                next_action= f"Execute {force_tool} before next planned step",
                data       = {"tool": force_tool, "args": force_args}
            )

        # 3. Note — injected into _intel so next LLM call sees it
        if note:
            existing = self._intel.get("operator_notes", [])
            existing.append({"note": note, "ts": datetime.utcnow().isoformat()})
            self._intel["operator_notes"] = existing[-5:]  # keep last 5

        # 4. DNS entry — hostname→IP mapping for better web testing
        dns_host = guidance.get("dns_host", "")
        dns_ip   = guidance.get("dns_ip", "")
        if dns_host and dns_ip:
            dns_map = self._intel.get("dns_overrides", {})
            dns_map[dns_host] = dns_ip
            self._intel["dns_overrides"] = dns_map
            await self.emit_reasoning(
                step       = "dns_override_applied",
                reasoning  = f"Operator added DNS mapping: {dns_host} → {dns_ip}",
                decision   = "Stored in intel — subagents will use this hostname in tool args",
                next_action= "Inject hostname into next web/recon tool calls",
                data       = {"dns_host": dns_host, "dns_ip": dns_ip}
            )

    def inject_guidance(self, guidance: Dict):
        """
        Called from agent_server when user sends guidance via WS or API.
        guidance = {
          "directive": "skip|force_tool|add_note|change_focus",
          "skip_phase": "vuln_id",         # optional — skip entire phase
          "force_tool": "nikto",           # optional — add this tool next
          "force_args": "-h http://...",   # optional — args for forced tool
          "note": "Free text note for master to consider",
          "target_override": "192.168.1.5" # optional — change target
        }
        """
        self._guidance_queue.put_nowait(guidance)

    def confirm_action(self, phase: str):
        evt = self._confirm_events.get(f"confirm_{phase}")
        if evt:
            evt.set()

    def stop_all_agents(self):
        for agent in [self._recon_agent, self._vuln_agent, self._web_agent,
                      self._osint_agent, self._exploit_agent, self._privesc_agent,
                      self._shell_agent, self._payload_agent]:
            if agent:
                agent.request_stop()
        self.request_stop()

    async def get_status(self) -> Dict:
        return {
            "master_status": str(self.status),
            "current_phase": str(self.phase),
            "llm_available": self._llm_available,
            "intel":         self._intel
        }

    def _intel_summary(self) -> str:
        """
        Returns a compact, human-readable summary of everything discovered so far.
        Injected into every LLM planning call so the model reasons with full context
        instead of only the data passed to each individual method.
        """
        i = self._intel
        lines = ["=== CURRENT PENTEST INTELLIGENCE ==="]

        lines.append(f"Target      : {i.get('target','?')} ({i.get('target_type','unknown')})")
        lines.append(f"OS          : {i.get('os_guess','unknown')}")

        ports = i.get('open_ports', [])
        if ports:
            lines.append(f"Open ports  : {', '.join(str(p) for p in sorted(ports)[:20])}")

        svcs = i.get('services', {})
        if svcs:
            svc_strs = [_fmt_svc(v) for v in list(svcs.values())[:8]]
            lines.append(f"Services    : {' | '.join(svc_strs)}")

        techs = i.get('technologies', [])
        if techs:
            lines.append(f"Technologies: {_safe_join(techs[:8])}")

        cves = i.get('cves', [])
        if cves:
            lines.append(f"CVEs found  : {', '.join(cves[:10])}")

        vulns = i.get('vulnerabilities', [])
        if vulns:
            v_strs = [str(v.get('title', v)) if isinstance(v, dict) else str(v) for v in vulns[:5]]
            lines.append(f"Vulns found : {' | '.join(v_strs)}")

        web_vulns = i.get('web_vulns', [])
        if web_vulns:
            wv_strs = [str(v.get('type','?') + ':' + v.get('url','')) if isinstance(v,dict) else str(v)
                       for v in web_vulns[:5]]
            lines.append(f"Web vulns   : {' | '.join(wv_strs)}")

        web_paths = i.get('web_paths', [])
        if web_paths:
            lines.append(f"Web paths   : {', '.join(web_paths[:10])}")

        mods = i.get('exploit_modules', [])
        if mods:
            m_strs = [str(m.get('module', m)) if isinstance(m, dict) else str(m) for m in mods[:5]]
            lines.append(f"Exploit mods: {' | '.join(m_strs)}")

        creds = i.get('credentials', [])
        if creds:
            c_strs = [f"{c.get('username','?')}:{c.get('password','?')}" if isinstance(c,dict) else str(c)
                      for c in creds[:3]]
            lines.append(f"Credentials : {' | '.join(c_strs)}")

        if i.get('shell_access'):
            lines.append(f"Shell access: YES — user: {i.get('current_user','unknown')}")

        attack_path = i.get('attack_path', [])
        if attack_path:
            lines.append("Attack path :")
            for step in attack_path[-5:]:  # last 5 steps
                phase  = step.get('phase', '?')
                result = step.get('result', '')[:120]
                lines.append(f"  [{phase}] {result}")

        # Service version details (nmap -sV output)
        svc_versions = i.get("service_versions", {})
        if svc_versions:
            lines.append("Service versions:")
            for port, ver in list(svc_versions.items())[:10]:
                lines.append(f"  port {port}: {ver}")

        # Login pages found
        login_pages = i.get("login_pages", [])
        if login_pages:
            lines.append(f"Login pages  : {', '.join(login_pages[:8])}")

        # Interesting files
        ifiles = i.get("interesting_files", [])
        if ifiles:
            lines.append(f"Interesting  : {', '.join(ifiles[:8])}")

        # Users discovered
        users = i.get("users", [])
        if users:
            lines.append(f"Users found  : {', '.join(users[:10])}")

        # SMB/NFS shares
        shares = i.get("shares", [])
        if shares:
            lines.append(f"Shares found : {', '.join(shares[:8])}")

        # Default creds tried
        creds_tried = i.get("default_creds_tried", [])
        if creds_tried:
            lines.append("Creds tried  :")
            for c in creds_tried[-5:]:
                lines.append(f"  {c.get('service','?')} {c.get('user','?')}:{c.get('pass','?')} → {c.get('result','?')}")

        # Banners
        banners = i.get("banners", {})
        if banners:
            for tool, banner in banners.items():
                lines.append(f"Banner ({tool}): {banner[:100]}")

        # Enumeration findings (structured)
        enum_findings = i.get("enum_findings", [])
        if enum_findings:
            lines.append("Enum findings:")
            for ef in enum_findings[:8]:
                lines.append(f"  • {ef}")

        # Attack surface assessment
        if i.get("attack_surface_notes"):
            lines.append(f"Attack surface: {i['attack_surface_notes'][:200]}")

        # Raw tool outputs (last 500 chars per tool, most recent 3 tools)
        raw = i.get("raw_outputs", {})
        if raw:
            lines.append("Recent tool output snippets:")
            for tool, output in list(raw.items())[-3:]:
                snippet = output[-500:].replace("\n", " ").strip()
                if snippet:
                    lines.append(f"  [{tool}]: {snippet[:200]}")

        notes = i.get("operator_notes", [])
        if notes:
            lines.append("Operator notes (FOLLOW THESE — high priority):")
            for n in notes:
                lines.append(f"  → {n.get('note','')}")

        lines.append("=== END INTELLIGENCE ===")
        return "\n".join(lines)
