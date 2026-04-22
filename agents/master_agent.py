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

# Phase 4 — bounded instruction cache (replaces unbounded plain dict)
try:
    from db.cache import BoundedInstructionCache as _BIC
    _BOUNDED_CACHE = True
except ImportError:
    _BOUNDED_CACHE = False

# Phase 5 — Hypothesis-driven reasoning engine (opt-in, graceful degradation)
try:
    from agents.reasoning.hypothesis_engine import HypothesisEngine
    from agents.reasoning.attack_planner    import AttackPlanner
    from agents.reasoning.decision_engine   import DecisionEngine
    from agents.reasoning.negative_memory   import NegativeMemory
    from agents.reasoning.reasoning_loop    import ReasoningLoop
    _REASONING_AVAILABLE = True
except ImportError:
    _REASONING_AVAILABLE = False

from agents.base_agent import BaseAgent, Instruction, agent_bus, BroadcastFn
from db.schemas import (
    AgentName, AgentStatus, AttackPhase, FindingSeverity,
    SessionStatus, WebSocketMessage
)
import db.mongo_client as db

# Per-session end-to-end scan logger (file-based). Never raises.
from utils.scan_logger import (
    start_scan_logger, close_scan_logger, get_scan_logger,
)

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

        # ── Meta-agents (plan auditor + findings validator) ────────────
        self._meta_agents_enabled:   bool                    = True
        self._master_checker:        Optional[Any]           = None
        self._issue_validator:       Optional[Any]           = None
        self._pending_corrections:   asyncio.Queue           = asyncio.Queue()
        self._meta_advisory_context: List[str]               = []
        self._meta_listener_task:    Optional[asyncio.Task]  = None

        # Session config
        self._target:             str  = ""
        self._target_type:        str  = "unknown"
        self._auto_exploit:       bool = False
        self._confirm_web:        bool = False   # Gate web testing behind a confirmation popup
        self._web_phase_timeout:  int  = 600     # Seconds; 0 = unlimited
        self._phases_to_run:      List[str] = []

        # MCP tool catalog cache — fetched once per session, injected into LLM
        # planning prompts so the model can pick from the full Kali arsenal
        # rather than the small hardcoded hints embedded in each prompt.
        self._tool_catalog:       Dict[str, Dict] = {}     # {name: {bin, category, description}}
        self._tool_catalog_text:  str = ""                  # pre-formatted for prompt injection

        # Phase extension events — SET = user granted extension; cleared on each wait
        self._extend_events: Dict[str, asyncio.Event] = {}

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
            # ── Phase 5 reasoning engine fields (safe defaults) ────
            "hypotheses":          [],    # list[dict] — Hypothesis objects
            "negative_memory":     [],    # list[dict] — FailedAttempt objects
            "confidence_scores":   {},    # {hypothesis_id: float}
            "action_score":        0,     # running engagement score
            "failed_attempts":     {},    # {"tool:service": count}
            "ranked_attack_paths": [],    # list[dict] — RankedAttackPath objects
            "reasoning_journal":   [],    # list[str] — situation assessments
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
        # Phase 4: bounded to 500 entries with 4-hour TTL to prevent memory bloat
        # on long engagements.  Falls back to plain dict if db.cache unavailable.
        self._instruction_cache = _BIC(maxsize=500, ttl=14_400.0) if _BOUNDED_CACHE \
                                   else {}  # type: ignore[assignment]

        # ── Phase 5: Hypothesis-driven reasoning engine ──────────────────
        # All fields default to None / False so the existing linear path is
        # completely unaffected when use_reasoning_loop=False (the default).
        self._use_reasoning_loop:  bool = False
        self._reasoning_loop_inst: Optional[ReasoningLoop] = None  # type: ignore[name-defined]
        self._hypothesis_engine:   Optional[HypothesisEngine] = None   # type: ignore[name-defined]
        self._decision_engine:     Optional[DecisionEngine] = None     # type: ignore[name-defined]
        self._attack_planner:      Optional[AttackPlanner] = None      # type: ignore[name-defined]
        self._negative_memory:     Optional[NegativeMemory] = None     # type: ignore[name-defined]

        # Background tasks — fire-and-forget asyncio.Task objects.
        # Tracked here so _wait_for_agents_idle can properly drain them before
        # report generation begins.
        self._background_tasks: List[asyncio.Task] = []

        # Pause / Resume support
        # _pause_event is SET (True) while the scan is running.
        # Calling pause() clears it; resume() sets it again.
        # Every phase boundary calls _check_pause() which awaits this event.
        self._pause_event: asyncio.Event = asyncio.Event()
        self._pause_event.set()   # start in running state

        # Ordered list of phases that have already completed — used to skip
        # already-done phases when resuming from a checkpoint.
        self._phases_completed: List[str] = []

        # Master run-config snapshot — saved into checkpoints so resume() can
        # restore the full MasterAgent configuration.
        self._master_config: Dict = {}

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
        session_id:         str,
        target:             str,
        target_type:        str  = "unknown",
        auto_exploit:       bool = False,
        confirm_web:        bool = False,
        web_phase_timeout:  int  = 600,
        threading_enabled:  bool = False,
        max_threads:        int  = 3,
        phases:             List[str] = None,
        notes:              str  = "",
        scope:              str  = "",
        checkpoint_id:      Optional[str] = None,   # resume from checkpoint
        use_reasoning_loop: bool = False,            # enable hypothesis-driven engine
        **kwargs
    ) -> Dict:
        self._use_reasoning_loop = _REASONING_AVAILABLE  # Always use reasoning if available
        self._session_id     = session_id
        self._target         = target
        self._target_type    = target_type
        self._auto_exploit        = auto_exploit
        self._confirm_web         = confirm_web
        self._web_phase_timeout   = web_phase_timeout
        self._intel["target"]     = target
        self._intel["target_type"] = target_type
        self._phases_to_run  = phases or [p.value for p in AttackPhase]

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
            # Start background task that keeps the listener alive
            self._meta_listener_task = asyncio.create_task(
                self._meta_tool_listener()
            )

        # Snapshot run config for checkpoint restore
        self._master_config = {
            "target_type":        target_type,
            "auto_exploit":       auto_exploit,
            "threading_enabled":  threading_enabled,
            "max_threads":        max_threads,
            "phases":             list(self._phases_to_run),
            "notes":              notes,
            "scope":              scope,
            "use_reasoning_loop": use_reasoning_loop,
        }

        # ── Restore from checkpoint if resuming ──────────────────────────
        resume_from_phase: Optional[str] = None
        if checkpoint_id:
            try:
                cp = await db.get_latest_checkpoint(session_id)
                if cp:
                    self._intel.update(cp.get("intel_snapshot", {}))
                    self._used_tools       = cp.get("used_tools", {})
                    self._phases_completed = cp.get("phases_completed", [])
                    self._phases_to_run    = cp.get("phases_to_run") or self._phases_to_run
                    resume_from_phase      = cp.get("current_phase")
                    self._intel["state"]   = cp.get("state_machine", "INIT")
                    await self.emit_reasoning(
                        step       = "checkpoint_restored",
                        reasoning  = f"Restored state from checkpoint {checkpoint_id}",
                        decision   = f"Resuming after phase: {resume_from_phase}",
                        next_action= "Skipping completed phases"
                    )
                    await self._emit("checkpoint_restored", {
                        "checkpoint_id":    checkpoint_id,
                        "resume_after":     resume_from_phase,
                        "phases_completed": self._phases_completed,
                    })
            except Exception as _ce:
                import logging as _l
                _l.getLogger(__name__).warning("Checkpoint restore failed: %s", _ce)

        # ── Shared tool-result cache injected into intel so execute_tasks()
        # on ANY slave agent can check it and avoid re-running the same tool
        # with the same args.  Using a single dict object (by reference) means
        # every agent that receives self._intel automatically shares the cache.
        self._intel["_tool_cache"] = self._instruction_cache

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

        # ── Per-session file logger — captures every tool call, LLM call,
        # phase transition, finding and error into logs/<timestamp>_<sid>/
        # for post-scan troubleshooting.  Never raises.
        self._scan_logger = start_scan_logger(
            session_id      = session_id,
            target          = target,
            engagement_type = target_type,
        )
        try:
            self._scan_logger.log_info(
                "session_init",
                f"target={target} type={target_type} auto_exploit={auto_exploit} "
                f"reasoning_loop={self._use_reasoning_loop}",
            )
        except Exception:
            pass

        # ── Fetch the full MCP tool catalog once — makes every subsequent
        # LLM planning prompt aware of the complete Kali arsenal exposed by
        # mcp-server.js (hydra, sqlmap, gobuster, john, hashcat, wfuzz,
        # nikto, wpscan, smbclient, enum4linux, crackmapexec, impacket-*,
        # ffuf, medusa, ncrack, responder, bloodhound, …).
        await self._load_tool_catalog()

        # ── Step 1: LLM check — warn if offline but NEVER halt ───
        # Scan always starts regardless of LLM state.  Each phase has hardcoded
        # fallback tool lists so recon/vuln/web phases run even without an LLM.
        # LLM-guided planning kicks in as soon as Ollama becomes available.
        await self.set_status(AgentStatus.RUNNING, f"Initialising pentest on {target}")
        llm_ok = await self.check_llm_available()
        if not llm_ok:
            await self._emit("llm_status", {
                "available": False,
                "url":       OLLAMA_URL if hasattr(self, '_target') else "",
                "message":   (
                    "LLM not reachable — scan will run with built-in defaults. "
                    "AI-guided planning will engage automatically once Ollama responds."
                )
            })

        # Initial node in attack graph
        target_node = f"target_{target.replace('.', '_').replace('/', '_')}"
        await self.add_node(
            node_id  = target_node,
            type     = "host",
            label    = target,
            host     = target,
            metadata = {"role": "primary_target", "type": target_type}
        )

        # ── Phase icon/label catalogue (shared by fresh start and resume) ───
        _PHASE_ICONS = {
            "recon":        ("🔍", "Reconnaissance",      "nmap, whatweb, enum4linux"),
            "vuln_id":      ("🔬", "Vulnerability ID",    "nmap --script vuln, searchsploit, nikto"),
            "web_testing":  ("🌐", "Web App Testing",     "gobuster, sqlmap, nikto"),
            "osint":        ("🕵", "OSINT / ExploitDB",   "searchsploit, CVE lookup"),
            "exploit":      ("💥", "Exploitation",        "Based on findings — TBD after recon"),
            "post_exploit": ("🎭", "Post Exploitation",   "Credential harvest, network map"),
            "privesc":      ("⬆",  "Privilege Escalation","linPEAS, sudo, SUID, cron"),
            "reporting":    ("📄", "Report Generation",   "Full findings report"),
            "lateral":      ("↔",  "Lateral Movement",    "ad_enum, kerberoast, ntlm_capture"),
            "cloud":        ("☁",  "Cloud Enumeration",   "aws_enum, azure_enum, gcp_enum"),
            "container":    ("🐳", "Container Audit",     "docker_audit, k8s_audit"),
            "evasion":      ("👻", "AV/EDR Evasion",      "defense_enum, av_evasion, amsi_bypass"),
            "traffic":      ("📡", "Traffic Analysis",    "pcap_capture, credential_sniff"),
            "evidence":     ("📷", "Evidence Collection", "screenshot, flag_capture"),
            "forensics":    ("🔎", "Digital Forensics",   "artifact_collect, timeline, memory_analysis"),
            "wireless":     ("📶", "Wireless Assessment", "wifi_scan, wpa2_crack, evil_twin"),
            "iot":          ("📟", "IoT Assessment",      "iot_device_scan, iot_default_creds, iot_protocol, iot_firmware"),
        }

        # ── Step 2: master plan — skip LLM call on resume ─────
        _is_resume = bool(resume_from_phase)

        if _is_resume:
            # Reuse the plan saved in intel by the original run — no LLM call needed.
            plan = self._intel.get("_master_plan") or {
                "phases":           [{"phase": p} for p in self._phases_to_run],
                "assessment_type":  self._intel.get("target_type", "resumed"),
                "attack_hypothesis": self._intel.get("attack_surface_notes", "Resuming from checkpoint"),
                "rationale":        "Resumed from checkpoint — plan reconstructed from saved intel",
            }
            await self.emit_reasoning(
                step       = "plan_restored",
                reasoning  = "Resuming from checkpoint — skipping LLM plan creation",
                decision   = f"Using saved plan, resuming after: {resume_from_phase}",
                next_action= f"Skipping {len(self._phases_completed)} completed phase(s)"
            )
        else:
            # Fresh start — ask LLM to create the plan (never halts on failure)
            try:
                plan = self._safe_llm_result(await self._create_master_plan(target, target_type))
            except Exception as e:
                # Any planning error → warn and use empty plan; phases run with defaults
                await self._emit("llm_status", {
                    "available": False,
                    "message":   f"Master plan unavailable ({e}) — running all phases with built-in defaults."
                })
                plan = {}

            # Persist plan in intel so future resumes can reuse it without an LLM call
            self._intel["_master_plan"] = plan

            await self._emit("master_plan", {"plan": plan, "target": target})
            await self.emit_reasoning(
                step       = "master_plan_created",
                reasoning  = plan.get("rationale", "Initial pentest plan created"),
                decision   = f"Assessment type: {plan.get('assessment_type', 'full')}",
                next_action= "Begin reconnaissance phase",
                data       = plan
            )

        # ── Build skeleton steps ───────────────────────────────
        phases_in_plan = _safe_list(plan.get("phases", []))
        skeleton_steps = []
        seen_phases    = set()
        done_set       = set(self._phases_completed)

        for ph in phases_in_plan:
            phase_key = str(ph.get("phase","")).lower()
            if phase_key in _PHASE_ICONS and phase_key not in seen_phases:
                icon, lbl, tools_hint = _PHASE_ICONS[phase_key]
                plan_tools = ph.get("tools", [])
                step_status = "done" if phase_key in done_set else "pending"
                skeleton_steps.append({
                    "id":          phase_key,
                    "label":       lbl,
                    "icon":        icon,
                    "phase":       phase_key,
                    "tool":        ", ".join(plan_tools[:3]) if plan_tools else tools_hint,
                    "status":      step_status,
                    "result":      "Completed before pause" if step_status == "done" else "",
                    "detail":      ph.get("reasoning",""),
                    "probability": None,
                })
                seen_phases.add(phase_key)

        for phase_key, (icon, lbl, tools_hint) in _PHASE_ICONS.items():
            if phase_key not in seen_phases:
                step_status = "done" if phase_key in done_set else "pending"
                skeleton_steps.append({
                    "id":          phase_key,
                    "label":       lbl,
                    "icon":        icon,
                    "phase":       phase_key,
                    "tool":        tools_hint,
                    "status":      step_status,
                    "result":      "Completed before pause" if step_status == "done" else "",
                    "detail":      "",
                    "probability": None,
                })

        hypothesis = plan.get("attack_hypothesis","")

        if _is_resume:
            # Restore event — frontend merges into existing steps preserving richer data
            await self._emit("plan_skeleton_restore", {
                "steps":            skeleton_steps,
                "hypothesis":       hypothesis,
                "assessment_type":  plan.get("assessment_type", "resumed"),
                "target":           target,
                "phases_completed": list(done_set),
                "resume_after":     resume_from_phase,
                "ts":               datetime.utcnow().isoformat(),
            })
        else:
            await self._emit("plan_skeleton", {
                "steps":           skeleton_steps,
                "hypothesis":      hypothesis,
                "assessment_type": plan.get("assessment_type", "unknown"),
                "target":          target,
                "ts":              datetime.utcnow().isoformat(),
            })

        # ── Step 3: Start Attack Graph Agent (background, runs whole session) ──
        # On resume, skip restarting the agent — the graph already exists in DB and
        # will be served from there.  Starting it fresh would trigger a _wait_for_agents_idle()
        # stall ("1 item still active") while it re-crawls an already-complete graph.
        if not _is_resume:
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
            await self._execute_phases(session_id, target, plan, resume_from=resume_from_phase)
        except asyncio.CancelledError:
            # Explicit user cancellation (tool_stop / request_stop) — respect it
            await self.set_status(AgentStatus.IDLE, "Pentest cancelled by user")
            await db.update_session(session_id, {"status": SessionStatus.PAUSED})
            try:
                if getattr(self, "_scan_logger", None):
                    self._scan_logger.log_info("session_cancel", "User cancelled scan")
            except Exception:
                pass
            close_scan_logger(session_id)
            return {"status": "cancelled"}
        except Exception as e:
            # Any other error (including any stray RuntimeError) — log and continue
            # to the completion block so a partial scan is still saved.
            import traceback as _tb
            tb_str = _tb.format_exc()
            # Extract the innermost frame so the operator sees WHICH line blew up.
            _last_frame = ""
            try:
                frames = _tb.extract_tb(e.__traceback__)
                if frames:
                    f = frames[-1]
                    _last_frame = f"{f.filename}:{f.lineno} in {f.name}"
            except Exception:
                pass
            await self._emit("scan_error", {
                "error":     str(e),
                "error_type": type(e).__name__,
                "where":     _last_frame,
                "traceback": tb_str[-2000:],
                "message":   f"Non-fatal error during phases: {e} at {_last_frame} — saving partial results."
            })
            import logging as _log
            _log.getLogger(__name__).error("_execute_phases error (non-fatal): %s\n%s", e, tb_str)
            try:
                if getattr(self, "_scan_logger", None):
                    self._scan_logger.log_error("_execute_phases", exc=e)
            except Exception:
                pass

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
        # Flush and close the per-session scan log
        try:
            close_scan_logger(session_id)
        except Exception:
            pass
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

    # ─── Pause / Resume ───────────────────────────────────────

    async def pause(self) -> str:
        """
        Request a graceful pause.  The scan stops at the next phase boundary
        (not mid-tool), saves a manual_pause checkpoint, and sets session
        status to PAUSED.  Returns the checkpoint_id.
        """
        self._pause_event.clear()
        await self._emit("scan_paused", {
            "message":  "Pause requested — scan will stop after current phase",
            "phase":    str(self.phase or ""),
            "ts":       datetime.utcnow().isoformat()
        })
        # The actual checkpoint is written by _check_pause() at the next boundary.
        # Return empty string here — callers should read the session's
        # last_checkpoint_id from the DB after the boundary is reached.
        return ""

    async def resume(self) -> bool:
        """
        Resume a paused scan.  Sets the pause event so _check_pause() unblocks.
        Returns True if the scan was actually paused, False if it was already running.
        """
        if self._pause_event.is_set():
            return False   # already running
        self._pause_event.set()
        await self._emit("scan_resumed", {
            "message": "Scan resumed",
            "phase":   str(self.phase or ""),
            "ts":      datetime.utcnow().isoformat()
        })
        return True

    # ══════════════════════════════════════════════════════════════════════════
    #  META-AGENT HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    async def _handle_corrections(
        self,
        corrections: List,
        phase: str,
        *,
        allow_replan: bool = True,
    ) -> None:
        """
        Apply tiered corrections from meta-agents.

        Blocking (confidence >= BLOCKING_THRESHOLD):
          - Inject as MANDATORY CORRECTION into next planning context.
          - Emit meta_correction WS event.

        Advisory (confidence < BLOCKING_THRESHOLD):
          - Append to _meta_advisory_context rolling buffer.
          - Emit meta_correction WS event.
        """
        if not corrections:
            return

        blocking = [c for c in corrections if c.tier == "blocking"]
        advisory = [c for c in corrections if c.tier == "advisory"]

        for c in advisory:
            note = f"[{c.source}|{c.phase}] {c.description} → {c.recommended_action}"
            self._meta_advisory_context.append(note)
            if _META_AGENTS_AVAILABLE and len(self._meta_advisory_context) > MAX_ADVISORY_CONTEXT:
                self._meta_advisory_context = self._meta_advisory_context[-MAX_ADVISORY_CONTEXT:]
            await self._emit("meta_correction", {**c.to_dict(), "tier": "advisory"})

        for c in blocking:
            await self._emit("meta_correction", {**c.to_dict(), "tier": "blocking"})
            try:
                await self.emit_reasoning(
                    step      = f"meta_blocking_{phase}",
                    reasoning = f"BLOCKING correction from {c.source}: {c.description}",
                    decision  = c.recommended_action,
                    next_action="Re-evaluate before proceeding",
                )
            except Exception:
                pass

    async def _meta_advisory_prompt_block(self) -> str:
        """Return advisory context formatted for injection into LLM planning prompts."""
        if not self._meta_advisory_context:
            return ""
        lines = "\n".join(f"  • {note}" for note in self._meta_advisory_context[-10:])
        return f"\n=== META-AGENT ADVISORY CONTEXT ===\n{lines}\n=== END ADVISORY ===\n"

    async def _meta_tool_listener(self) -> None:
        """
        Background task: keeps alive for the full scan duration.
        Per-tool validation corrections are enqueued by subagent store_finding hooks
        and drained at post-phase _handle_corrections().
        """
        while not self._stop_requested:
            try:
                await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                import logging as _log
                _log.getLogger(__name__).warning("[meta_listener] error: %s", exc)

    async def _drain_pending_corrections(self, phase: str) -> None:
        """Drain all queued per-tool corrections and handle them."""
        corrections: List = []
        while not self._pending_corrections.empty():
            try:
                item = self._pending_corrections.get_nowait()
                if isinstance(item, list):
                    corrections.extend(item)
                else:
                    corrections.append(item)
            except asyncio.QueueEmpty:
                break
        if corrections:
            await self._handle_corrections(corrections, phase, allow_replan=False)

    # ══════════════════════════════════════════════════════════════════════════

    async def _save_checkpoint(self, checkpoint_type: str = "auto") -> Optional[str]:
        """
        Serialise current MasterAgent state to session_checkpoints collection.
        Returns the checkpoint_id, or None if no session_id is set.
        """
        if not self._session_id:
            return None
        try:
            # MongoDB requires all document keys to be strings. The services dict
            # uses port numbers as keys (e.g. {21: {...}, 80: {...}}); stringify them.
            _intel_snap = dict(self._intel)
            if isinstance(_intel_snap.get("services"), dict):
                _intel_snap["services"] = {
                    str(k): v for k, v in _intel_snap["services"].items()
                }
            cid = await db.store_checkpoint(
                session_id            = self._session_id,
                host                  = self._target,
                checkpoint_type       = checkpoint_type,
                state_machine         = self._intel.get("state", "INIT"),
                current_phase         = str(self.phase or ""),
                phases_completed      = list(self._phases_completed),
                phases_to_run         = list(self._phases_to_run),
                intel_snapshot        = _intel_snap,
                used_tools            = dict(self._used_tools),
                pending_confirmations = list(self._confirm_events.keys()),
                in_flight_subagents   = [
                    t for t in self._background_tasks if not t.done()
                    # we can't serialise Task objects; store count placeholder
                ] and [],
                master_config         = dict(self._master_config),
            )
            return cid
        except Exception as _e:
            import logging as _l
            _l.getLogger(__name__).warning("Checkpoint save failed: %s", _e)
            return None

    async def _check_pause(self, phase_label: str = "") -> None:
        """
        Called at every phase boundary.  If a pause has been requested,
        saves a manual_pause checkpoint and blocks until resume() is called.
        Also saves an auto checkpoint when called normally (not paused).
        """
        if not self._pause_event.is_set():
            # Operator requested pause — save checkpoint then wait
            await self.emit_reasoning(
                step       = "paused",
                reasoning  = f"Scan paused by operator after phase: {phase_label}",
                decision   = "Saving checkpoint and waiting for resume",
                next_action= "Call POST /sessions/{id}/resume to continue"
            )
            await self._save_checkpoint("manual_pause")
            await db.update_session(self._session_id, {"status": "paused"})
            # Block until resume() sets the event
            await self._pause_event.wait()
            await db.update_session(self._session_id, {"status": "active"})
            await self.emit_reasoning(
                step       = "resumed",
                reasoning  = "Scan resumed by operator",
                decision   = "Continuing from next phase",
                next_action= f"Proceeding after: {phase_label}"
            )
        else:
            # Normal path — save auto checkpoint at this boundary
            await self._save_checkpoint("auto")

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

            # NetworkScanSubagent's parsed_data is the authoritative port list.
            # Sync its findings back to self._intel once it completes so later
            # phases / hypothesis engine don't show "no open ports" when the
            # LLM-planned master scan missed any.
            async def _run_network_scan_and_sync():
                try:
                    res = await NetworkScanSubagent(**kw).execute()
                    pd  = getattr(res, "parsed_data", {}) or {}
                    new_ports = pd.get("open_ports") or []
                    if new_ports:
                        existing = self._intel.get("open_ports") or []
                        merged = list(dict.fromkeys(list(existing) + list(new_ports)))
                        self._intel["open_ports"] = merged
                    for p in pd.get("ports") or []:
                        if isinstance(p, dict) and p.get("port") is not None:
                            self._intel.setdefault("services", {})[p["port"]] = {
                                "service":  p.get("service", ""),
                                "version":  p.get("version", ""),
                                "protocol": p.get("protocol", "tcp"),
                                "port":     p["port"],
                                "banner":   p.get("banner", ""),
                            }
                    if pd.get("os_guess") and pd["os_guess"] != "unknown":
                        if self._intel.get("os_guess", "unknown") in ("", "unknown"):
                            self._intel["os_guess"] = pd["os_guess"]
                except Exception as exc:
                    await self.emit_reasoning(
                        step       = "subagent_err_recon_network_scan",
                        reasoning  = f"NetworkScanSubagent error (non-fatal): {exc}",
                        decision   = "Continuing pentest",
                        next_action= "Main flow unaffected",
                    )

            coros = [
                _run_network_scan_and_sync(),
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
            # Transform intel services dict {port: {service, version, ...}} into
            # list of dicts expected by CveLookup / ServiceVuln subagents.
            _svc_map = self._intel.get("services", {}) or {}
            _svc_list: list[dict] = []
            for _p, _s in _svc_map.items():
                if isinstance(_s, dict):
                    _entry = dict(_s)
                    _entry.setdefault("port", _p)
                    _svc_list.append(_entry)
                else:
                    _svc_list.append({"port": _p, "service": str(_s), "version": ""})
            coros = [
                CveLookupSubagent(**kw).execute(
                    services_list=_svc_list,
                    cves=self._intel.get("cves", []),
                ),
                ServiceVulnSubagent(**kw).execute(services_list=_svc_list),
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
            # Pass all remaining URLs as extra_urls so Burp's passive scanner covers the full scope
            for idx, url in enumerate(web_urls[:2]):
                other_urls = [u for u in web_urls if u != url]
                burp_kw = dict(kw, target=url)
                coros.append(BurpSubagent(**burp_kw).execute(extra_urls=other_urls))
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

    async def _guidance_drain_loop(self):
        """
        Background task: drain the guidance queue every 2 seconds independently
        of what the main scan coroutine is doing.

        This is the fix for guidance hanging the scan. Without this task, guidance
        only gets processed at explicit _apply_pending_guidance() checkpoints. If the
        main coroutine is blocked inside a long think() call or a slow DB write,
        those checkpoints never run and guidance sits in the queue indefinitely.

        By running this as a separate asyncio task, guidance is always processed
        within ~2 seconds of arrival regardless of LLM/DB latency.
        """
        while not self._stop_requested:
            try:
                # Drain ALL queued guidance items (not just one)
                while not self._guidance_queue.empty():
                    await self._apply_pending_guidance()
            except Exception:
                pass   # never crash the drain loop
            await asyncio.sleep(2.0)

    # ═══════════════════════════════════════════════════════════════
    #  PHASE 5 — REASONING ENGINE METHODS
    #  These methods are only called when use_reasoning_loop=True.
    #  They have zero effect on the existing code paths.
    # ═══════════════════════════════════════════════════════════════

    async def _init_reasoning_components(
        self,
        session_id: str,
        target:     str,
    ) -> None:
        """
        Instantiate all reasoning-engine components.
        Called once at the start of _execute_phases when the loop is enabled.
        Loads negative_memory from DB on session resume.
        """
        if not _REASONING_AVAILABLE:
            return

        # NegativeMemory — loads from DB to restore after pause/resume
        self._negative_memory = NegativeMemory(
            session_id  = session_id,
            db_store_fn = db.store_negative_memory,
            db_load_fn  = db.load_negative_memory,
        )
        await self._negative_memory.load_from_db()

        # Restore from intel snapshot if this is a resume
        stored_nm = self._intel.get("negative_memory", [])
        if stored_nm and len(self._negative_memory) == 0:
            for attempt_dict in stored_nm:
                from agents.reasoning.negative_memory import FailedAttempt
                attempt = FailedAttempt.from_dict(attempt_dict)
                self._negative_memory._attempts.append(attempt)
                key = f"{attempt.tool}:{attempt.target_service}"
                self._negative_memory._index[key] = attempt.attempt_count

        # HypothesisEngine — uses master's think_json and KB
        self._hypothesis_engine = HypothesisEngine(
            think_json_fn = self.think_json,
            kb_fn         = _kb_context,
            session_id    = session_id,
        )

        # AttackPlanner — uses master's think_json and KB
        self._attack_planner = AttackPlanner(
            think_json_fn = self.think_json,
            kb_fn         = _kb_context,
            session_id    = session_id,
        )
        # Restore ranked paths from checkpoint
        stored_paths = self._intel.get("ranked_attack_paths", [])
        if stored_paths:
            self._attack_planner.restore_from_dicts(stored_paths)

        # DecisionEngine — uses master's think_json and broadcast
        self._decision_engine = DecisionEngine(
            think_json_fn          = self.think_json,
            emit_fn                = self._broadcast_raw,
            session_id             = session_id,
            auto_execute_threshold = 0.70,
        )
        # Restore score from checkpoint
        self._decision_engine.set_score(self._intel.get("action_score", 0))

    async def _reasoning_loop_run(
        self,
        session_id:  str,
        target:      str,
        plan:        Dict,
        resume_from: Optional[str] = None,
    ) -> None:
        """
        Run the hypothesis-driven reasoning loop.
        Called from _execute_phases() when use_reasoning_loop=True.
        Propagates final intel back to self._intel for reporting.
        """
        if not _REASONING_AVAILABLE:
            return

        loop = ReasoningLoop(
            master_agent       = self,
            session_id         = session_id,
            target             = target,
            intel              = self._intel,
            hypothesis_engine  = self._hypothesis_engine,
            decision_engine    = self._decision_engine,
            attack_planner     = self._attack_planner,
            negative_memory    = self._negative_memory,
            emit_fn            = self._broadcast_raw,
            check_pause_fn     = self._check_pause_requested,
            save_checkpoint_fn = self._save_reasoning_checkpoint,
        )
        self._reasoning_loop_inst = loop
        # Expose QuestionEngine on master for guidance-question routing
        self._question_engine = loop._question_engine

        # Run the loop — returns updated intel
        final_intel = await loop.run()

        # Merge final reasoning state back into self._intel
        for key in [
            "hypotheses", "negative_memory", "confidence_scores",
            "action_score", "failed_attempts", "ranked_attack_paths",
            "reasoning_journal",
        ]:
            if key in final_intel:
                self._intel[key] = final_intel[key]

        # After loop: run reporting phase
        await self._emit("phase_update", {
            "phase":  "reporting",
            "status": "active",
            "label":  "Report Generation",
        })

    # ── Tool-to-phase classification tables ──────────────────────────────────
    _RECON_TOOLS: frozenset = frozenset({
        "nmap", "masscan", "rustscan", "whatweb", "wkhtmltoimage",
        "dnsrecon", "dnsx", "subfinder", "amass", "dig", "host",
        "ping", "traceroute", "whois", "wafw00f", "testssl", "sslscan",
        "enum4linux", "enum4linux-ng", "smbclient", "rpcclient", "smbmap",
        "nbtscan", "snmpwalk", "snmpcheck", "onesixtyone", "ldapsearch",
    })
    _WEB_TOOLS: frozenset = frozenset({
        "sqlmap", "nuclei", "wfuzz", "feroxbuster", "gobuster", "dirsearch",
        "ffuf", "nikto", "xsstrike", "dalfox", "arjun", "jwt_tool",
        "wapiti", "zap", "zaproxy", "commix", "burpsuite", "dirb", "wpscan",
        "droopescan", "joomscan", "cmseek",
    })
    _VULN_TOOLS: frozenset = frozenset({
        "openvas", "gvm-cli", "gvm-start", "openvas-scanner",
        "openvas-nasl", "nessus", "vulners", "vulscan",
        "smtp-user-enum", "finger", "ident-user-enum",
    })
    _EXPLOIT_TOOLS: frozenset = frozenset({
        "msfconsole", "msfvenom", "metasploit", "searchsploit",
        "hydra", "medusa", "ncrack", "patator",
        "crackmapexec", "cme", "evil-winrm", "impacket",
        "responder", "john", "hashcat",
    })
    _PRIVESC_TOOLS: frozenset = frozenset({
        "linpeas", "winpeas", "pspy", "linenum", "les", "lse", "les2",
        "suid3num", "sudo_killer", "deepce", "wesng", "powerup",
        "sherlock", "beroot", "privesccheck",
    })
    def _classify_tool_to_phase(self, tool: str) -> str:
        """Map a tool name to the phase agent that should execute it."""
        tl = tool.lower().split()[0]      # normalise: strip args if present
        if tl in self._RECON_TOOLS:        return "recon"
        if tl in self._WEB_TOOLS:          return "web"
        if tl in self._EXPLOIT_TOOLS:      return "exploit"
        if tl in self._PRIVESC_TOOLS:      return "privesc"
        if tl in self._VULN_TOOLS:         return "vuln"
        # Heuristic fallbacks
        if any(k in tl for k in ("scan", "map", "enum", "recon", "dns", "whois")):
            return "recon"
        if any(k in tl for k in ("fuzz", "brute", "spider", "crawl", "web", "http")):
            return "web"
        if any(k in tl for k in ("exploit", "payload", "shell", "msf", "msfconsole")):
            return "exploit"
        if any(k in tl for k in ("priv", "esc", "peas", "enum_linux")):
            return "privesc"
        return "generic"

    async def _dispatch_to_agent(
        self,
        tool:    str,
        args:    str,
        purpose: str,
        phase:   str,
        timeout: int = 300,
    ) -> dict:
        """
        Route a single tool execution through the appropriate specialist agent.
        This ensures ALL agent events (tool_start, tool_output, finding,
        graph_node, graph_edge) flow to the frontend dashboards exactly as
        they do during normal phase execution.

        Returns a dict with: stdout, stderr, exit_code, output_id.
        """
        agent_type = self._classify_tool_to_phase(tool)
        task = {
            "tool":         tool,
            "args":         args or self._target,
            "purpose":      purpose or f"Reasoning engine: {tool}",
            "timeout":      timeout,
            "can_parallel": False,
        }

        try:
            if agent_type == "recon":
                from agents.recon_agent import ReconAgent
                agent_obj = ReconAgent(broadcast=self.broadcast)
                agent_obj._session_id = self._session_id
                result = await agent_obj.execute_tasks(
                    self._target, [task], "RECON", self._intel
                )
                # Merge recon findings into intel
                for key in ("open_ports", "services", "os_guess", "web_paths",
                            "technologies", "domain_info", "web_targets"):
                    if result.get(key) is not None:
                        self._intel[key] = result[key]
                return {
                    "stdout":    str(result.get("raw_output", result))[:65536],
                    "stderr":    "",
                    "exit_code": 0,
                    "output_id": "",
                    "tool":      tool,
                    "args":      args,
                    "findings":  result.get("findings", []),
                }

            elif agent_type == "vuln":
                from agents.vuln_agent import VulnAgent
                agent_obj = VulnAgent(broadcast=self.broadcast)
                agent_obj._session_id = self._session_id
                result = await agent_obj.execute_tasks(
                    self._target, [task], "VULN_ID", self._intel
                )
                for key in ("vulnerabilities", "cves", "exploits"):
                    if result.get(key) is not None:
                        existing = self._intel.get(key, [])
                        if isinstance(result[key], list):
                            # Deduplicate by converting dicts to frozensets for set operations
                            merged = list(existing)
                            existing_strs = {str(e) for e in existing}
                            for item in result[key]:
                                if str(item) not in existing_strs:
                                    merged.append(item)
                            self._intel[key] = merged
                        else:
                            self._intel[key] = result[key]
                return {
                    "stdout":    str(result.get("raw_output", result))[:65536],
                    "stderr":    "",
                    "exit_code": 0,
                    "output_id": "",
                    "tool":      tool,
                    "args":      args,
                }

            elif agent_type == "web":
                from agents.web_agent import WebAgent
                agent_obj = WebAgent(broadcast=self.broadcast)
                agent_obj._session_id = self._session_id
                result = await agent_obj.execute_tasks(
                    self._target, [task], "WEB_TESTING", self._intel
                )
                for key in ("web_vulns", "web_paths", "web_targets", "paths",
                            "technologies", "interesting_files", "credentials"):
                    if result.get(key) is not None:
                        existing = self._intel.get(key, [])
                        if isinstance(result[key], list) and isinstance(existing, list):
                            merged = list(existing)
                            existing_strs = {str(e) for e in existing}
                            for item in result[key]:
                                if str(item) not in existing_strs:
                                    merged.append(item)
                            self._intel[key] = merged
                        else:
                            self._intel[key] = result[key]
                return {
                    "stdout":    str(result.get("raw_output", result))[:65536],
                    "stderr":    "",
                    "exit_code": 0,
                    "output_id": "",
                    "tool":      tool,
                    "args":      args,
                }

            elif agent_type == "exploit":
                from agents.exploit_agent import ExploitAgent
                agent_obj = ExploitAgent(broadcast=self.broadcast)
                agent_obj._session_id = self._session_id
                result = await agent_obj.execute_tasks(
                    self._target, [task], "EXPLOITATION", self._intel
                )
                for key in ("shells", "credentials", "shell_access"):
                    if result.get(key) is not None:
                        self._intel[key] = result[key]
                return {
                    "stdout":    str(result.get("raw_output", result))[:65536],
                    "stderr":    "",
                    "exit_code": 0 if result.get("shell_access") else 1,
                    "output_id": "",
                    "tool":      tool,
                    "args":      args,
                }

            elif agent_type == "privesc":
                from agents.privesc_agent import PrivescAgent
                agent_obj = PrivescAgent(broadcast=self.broadcast)
                agent_obj._session_id = self._session_id
                result = await agent_obj.execute_tasks(
                    self._target, [task], "PRIVILEGE_ESCALATION", self._intel
                )
                for key in ("current_user", "root_flag", "elevated_shell"):
                    if result.get(key) is not None:
                        self._intel[key] = result[key]
                return {
                    "stdout":    str(result.get("raw_output", result))[:65536],
                    "stderr":    "",
                    "exit_code": 0 if result.get("elevated_shell") else 1,
                    "output_id": "",
                    "tool":      tool,
                    "args":      args,
                }

            else:
                # Generic fallback — route via recon agent (most tools are recon-adjacent)
                from agents.recon_agent import ReconAgent
                agent_obj = ReconAgent(broadcast=self.broadcast)
                agent_obj._session_id = self._session_id
                result = await agent_obj.execute_tasks(
                    self._target, [task], phase or "RECON", self._intel
                )
                return {
                    "stdout":    str(result.get("raw_output", result))[:65536],
                    "stderr":    "",
                    "exit_code": 0,
                    "output_id": "",
                    "tool":      tool,
                    "args":      args,
                }

        except Exception as e:
            import logging as _log
            _log.getLogger(__name__).warning("_dispatch_to_agent error (%s): %s", tool, e)
            return {
                "stdout":    "",
                "stderr":    str(e),
                "exit_code": -1,
                "output_id": "",
                "error":     str(e),
            }

    async def _check_pause_requested(self) -> bool:
        """Return True if the operator has requested a pause."""
        return not self._pause_event.is_set()

    async def _save_reasoning_checkpoint(self, iteration: int) -> None:
        """Save a checkpoint with reasoning engine state included."""
        try:
            # Merge reasoning state into intel before saving
            if self._reasoning_loop_inst:
                state = self._reasoning_loop_inst.serialize_state()
                self._intel.update(state)
            # Tag iteration in intel so it survives the checkpoint round-trip
            self._intel["reasoning_iteration"] = iteration
            await self._save_checkpoint("auto")
        except Exception:
            pass

    async def _broadcast_raw(self, event: dict) -> None:
        """
        Emit a raw event dict to the WebSocket broadcast system.
        Used by reasoning components which build their own event dicts.
        """
        try:
            event_type = event.get("type", "reasoning_event")
            data       = event.get("data", event)
            await self._emit(event_type, data)
        except Exception:
            pass

    async def _db_update_hypothesis(
        self,
        session_id:    str,
        hypothesis_id: str,
        validated:     bool  = None,
        invalidated:   bool  = None,
        confidence:    float = None,
    ) -> None:
        """Update hypothesis status in MongoDB. Called by ReasoningLoop._update()."""
        try:
            await db.update_hypothesis_status(
                session_id    = session_id,
                hypothesis_id = hypothesis_id,
                validated     = validated,
                invalidated   = invalidated,
                confidence    = confidence,
            )
        except Exception:
            pass

    async def _execute_phases(
        self,
        session_id:   str,
        target:       str,
        plan:         Dict,
        resume_from:  Optional[str] = None
    ):
        """
        Execute all enabled phases driven by the state machine.
        Phases 1-4 (recon/vuln/web/osint) run IN PARALLEL for speed.
        Attack planning runs after intelligence aggregation.

        resume_from: if set, skip every phase that appears in _phases_completed
                     until we reach the phase AFTER resume_from.

        Phase 5: when use_reasoning_loop=True, delegates to _reasoning_loop_run()
        which replaces linear phase execution with hypothesis-driven evidence loop.
        """
        # ── REASONING LOOP ROUTING ──────────────────────────────────────────
        # When the reasoning engine is enabled, skip the linear phase executor
        # and use the hypothesis-driven loop instead.
        # Default (use_reasoning_loop=False) runs the original code unchanged.
        if self._use_reasoning_loop and _REASONING_AVAILABLE:
            # ── Parse operator context via LLM (replaces regex CTF parser) ──
            # Only parse if notes or scope provided and not already parsed
            if not self._intel.get("engagement_context"):
                ctx = await self._parse_operator_context(
                    notes       = self._notes,
                    scope       = self._scope,
                    target_type = self._target_type,
                )
                self._intel["engagement_context"] = ctx.to_dict()
                # Back-compat: also populate ctf_objectives/ctf_answers for
                # any code that still reads those keys
                if ctx.has_objectives:
                    self._intel["ctf_objectives"] = ctx.objectives
                    self._intel.setdefault("ctf_answers", {})
                # Broadcast context to frontend so dashboards know the type
                await self._emit("engagement_context", {
                    "engagement_type":     ctx.engagement_type,
                    "title":               ctx.title,
                    "context_summary":     ctx.context_summary,
                    "objectives_count":    len(ctx.objectives),
                    "approach_summary":    ctx.approach_summary,
                    "clarifying_questions": ctx.clarifying_questions,
                })
                # If LLM needs clarification, ask the operator without blocking
                if ctx.needs_clarification:
                    await self._emit("operator_question", {
                        "questions":       ctx.clarifying_questions,
                        "context_so_far":  ctx.context_summary,
                        "engagement_type": ctx.engagement_type,
                        "note":            "Scan is proceeding with best-guess assumptions. Answer to improve accuracy.",
                    })

            await self._init_reasoning_components(session_id, target)
            await self._reasoning_loop_run(session_id, target, plan, resume_from)
            return
        # ── END REASONING LOOP ROUTING ──────────────────────────────────────
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

        def already_done(p: str) -> bool:
            """True if this phase was completed before this resume."""
            return p in self._phases_completed

        # ── Background guidance drain task ────────────────────
        # Processes guidance within 2 s regardless of LLM/DB latency in main flow.
        _drain_task = asyncio.create_task(self._guidance_drain_loop())

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
        await self._apply_pending_guidance()   # drain any queued guidance before recon
        if phase_enabled("recon") and not already_done("recon"):
            # META: pre-phase review
            if self._master_checker and self._meta_agents_enabled:
                _pre_c = await self._master_checker.pre_phase_review(
                    phase="recon", instructions=[], intel_snapshot=dict(self._intel))
                await self._handle_corrections(_pre_c, "recon", allow_replan=True)
            await self._phase_recon(target, plan)
            self._phases_completed.append("recon")
            # META: post-phase review + issue validation
            if self._master_checker and self._meta_agents_enabled:
                _recon_findings = []
                try:
                    _recon_findings = await db.get_findings_by_phase(self._session_id, "recon") or []
                except Exception:
                    pass
                _post_c = await self._master_checker.post_phase_review(
                    phase="recon",
                    executed_tools=list(self._intel.get("raw_outputs", {}).keys()),
                    findings=_recon_findings, intel_delta={})
                if self._issue_validator:
                    _val_c = await self._issue_validator.validate_phase_findings(
                        phase="recon", all_findings=_recon_findings,
                        scan_objectives=self._intel.get("ctf_objectives", []))
                    _post_c.extend(_val_c)
                await self._drain_pending_corrections("recon")
                await self._handle_corrections(_post_c, "recon", allow_replan=False)
        elif already_done("recon"):
            await self.emit_reasoning(
                step="recon_skipped", reasoning="Recon already completed before pause",
                decision="Skipping recon phase", next_action="Continue from next phase"
            )

        # ── AUTO-CHECKPOINT 1: after recon ────────────────────
        await self._check_pause("recon")

        # ── PHASE 2: PARALLEL intelligence gathering ──────────
        # Run vuln scan + web testing + OSINT simultaneously
        await self._apply_pending_guidance()   # drain before parallel phase starts
        await self._transition_state("INTELLIGENCE_AGGREGATION")

        parallel_coros = []
        if (phase_enabled("vuln_id") or phase_enabled("scan")) and not already_done("vuln_id"):
            parallel_coros.append(("vuln", self._phase_vuln_id(target)))

        web_ports = []
        _COMMON_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 9000, 8181, 4443, 7443}
        for port, svc in self._intel["services"].items():
            svc_name = (svc.get("service","") if isinstance(svc,dict) else str(svc)).lower()
            is_web_svc = any(x in svc_name for x in ("http", "https", "web", "ssl/http", "http?", "www"))
            is_web_port = int(str(port).split("/")[0]) in _COMMON_WEB_PORTS
            if is_web_svc or is_web_port:
                web_ports.append(port)
        # Deduplicate and sort
        web_ports = sorted(set(int(str(p).split("/")[0]) for p in web_ports))
        if web_ports and not already_done("web_testing"):
            parallel_coros.append(("web", self._phase_web_testing(target, web_ports)))

        if phase_enabled("osint") and not already_done("osint"):
            parallel_coros.append(("osint", self._phase_osint(target)))

        # ── Optional specialist phases run alongside vuln/web/osint ──
        # Cloud: if cloud metadata port (80/443) or IMDS hints in scan results
        _svcs_str = _fmt_svcs(self._intel.get("services", {})).lower()
        _os_str   = self._intel.get("os_guess", "").lower()
        if phase_enabled("cloud") and not already_done("cloud") and (
            "169.254.169.254" in str(self._intel) or
            any(k in _svcs_str for k in ("aws", "azure", "gcp", "cloud", "metadata")) or
            self._intel.get("target_type", "") in ("cloud", "aws", "azure", "gcp")
        ):
            parallel_coros.append(("cloud", self._phase_cloud(target)))

        # Container: if docker (2375/2376) or k8s (6443/8443/10250) ports open
        _open_ports = set(str(p) for p in self._intel.get("open_ports", []))
        if phase_enabled("container") and not already_done("container") and (
            _open_ports & {"2375", "2376", "6443", "8443", "10250", "10255"} or
            any(k in _svcs_str for k in ("docker", "kubernetes", "k8s"))
        ):
            parallel_coros.append(("container", self._phase_container(target)))

        # Traffic: passive capture runs alongside other recon phases
        if phase_enabled("traffic") and not already_done("traffic"):
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
                else:
                    if name not in self._phases_completed:
                        self._phases_completed.append(name)
            await self.emit_reasoning(
                step       = "parallel_intel_done",
                reasoning  = f"All {len(parallel_coros)} parallel agents completed",
                decision   = "Aggregating results from all agents",
                next_action= "Master analyzes combined intelligence"
            )

            # Sync gate: ensure all parallel agents are truly done before continuing
            await self._wait_for_agents_idle(timeout=120.0)

            # META: post-parallel phase review (vuln_id + web_testing combined)
            if self._master_checker and self._meta_agents_enabled:
                _para_findings = []
                try:
                    for _pname in [n for n, _ in parallel_coros]:
                        _pf = await db.get_findings_by_phase(self._session_id, _pname) or []
                        _para_findings.extend(_pf)
                except Exception:
                    pass
                _post_c2 = await self._master_checker.post_phase_review(
                    phase="intelligence_aggregation",
                    executed_tools=[n for n, _ in parallel_coros],
                    findings=_para_findings, intel_delta={})
                if self._issue_validator and _para_findings:
                    _val_c2 = await self._issue_validator.validate_phase_findings(
                        phase="intelligence_aggregation", all_findings=_para_findings,
                        scan_objectives=self._intel.get("ctf_objectives", []))
                    _post_c2.extend(_val_c2)
                await self._drain_pending_corrections("intelligence_aggregation")
                await self._handle_corrections(_post_c2, "intelligence_aggregation", allow_replan=False)

        # ── AUTO-CHECKPOINT 2: after parallel intel ───────────
        await self._check_pause("parallel_intel")

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
        if not already_done("attack_planning"):
            attack_tree = await self._phase_attack_planning(target)
            if attack_tree:
                self._intel["attack_tree"] = attack_tree
            self._phases_completed.append("attack_planning")
        else:
            attack_tree = self._intel.get("attack_tree")

        # ── PHASE 5: EXPLOITATION ─────────────────────────────
        await self._apply_pending_guidance()   # drain before exploit gate
        await self._transition_state("EXPLOITATION")
        if phase_enabled("exploit") and not already_done("exploit"):
            # META: pre-phase review
            if self._master_checker and self._meta_agents_enabled:
                _pre_exp = await self._master_checker.pre_phase_review(
                    phase="exploit", instructions=[], intel_snapshot=dict(self._intel))
                await self._handle_corrections(_pre_exp, "exploit", allow_replan=True)
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
                    self._phases_completed.append("exploit")
                else:
                    await self._emit("phase_skipped", {"phase": "exploit"})
            # META: post-phase review
            if self._master_checker and self._meta_agents_enabled:
                _exp_findings = []
                try:
                    _exp_findings = await db.get_findings_by_phase(self._session_id, "exploit") or []
                except Exception:
                    pass
                _post_exp = await self._master_checker.post_phase_review(
                    phase="exploit", executed_tools=[], findings=_exp_findings, intel_delta={})
                if self._issue_validator and _exp_findings:
                    _val_exp = await self._issue_validator.validate_phase_findings(
                        phase="exploit", all_findings=_exp_findings,
                        scan_objectives=self._intel.get("ctf_objectives", []))
                    _post_exp.extend(_val_exp)
                await self._drain_pending_corrections("exploit")
                await self._handle_corrections(_post_exp, "exploit", allow_replan=False)
        elif already_done("exploit"):
            await self.emit_reasoning(
                step="exploit_skipped", reasoning="Exploit phase completed before pause",
                decision="Skipping exploit phase", next_action="Continue to post-exploit"
            )

        # ── AUTO-CHECKPOINT 3: after exploitation ─────────────
        await self._check_pause("exploit")

        # ── PHASE 6: POST-EXPLOITATION + PRIVESC ──────────────
        if self._intel["shell_access"]:
            await self._transition_state("POST_EXPLOITATION")
            if phase_enabled("post_exploit") and not already_done("post_exploit"):
                await self._phase_post_exploit(target)
                self._phases_completed.append("post_exploit")
                # META: post-exploit review
                if self._master_checker and self._meta_agents_enabled:
                    _pe_findings = []
                    try:
                        _pe_findings = await db.get_findings_by_phase(self._session_id, "post_exploit") or []
                    except Exception:
                        pass
                    _post_pe = await self._master_checker.post_phase_review(
                        phase="post_exploit", executed_tools=[], findings=_pe_findings, intel_delta={})
                    await self._drain_pending_corrections("post_exploit")
                    await self._handle_corrections(_post_pe, "post_exploit", allow_replan=False)

            await self._transition_state("PRIVILEGE_ESCALATION")
            if phase_enabled("privesc") and not already_done("privesc"):
                await self._phase_privesc(target)
                self._phases_completed.append("privesc")
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
            if phase_enabled("evasion") and not already_done("evasion"):
                await self._phase_evasion(target)
                self._phases_completed.append("evasion")

            # ── PHASE 7: LATERAL MOVEMENT ─────────────────────
            await self._transition_state("LATERAL_MOVEMENT")
            if phase_enabled("lateral") and not already_done("lateral"):
                await self._phase_lateral_movement(target)
                self._phases_completed.append("lateral")
            elif phase_enabled("exploit") and self._intel.get("lateral_targets") and not already_done("lateral"):
                # Legacy: also trigger if exploit phase found lateral targets
                await self._phase_lateral_movement(target)
                self._phases_completed.append("lateral")

        # ── PHASE 7b: WIRELESS (optional standalone phase) ────
        if (phase_enabled("wireless") or self._intel.get("wireless_config")) and not already_done("wireless"):
            await self._phase_wireless(target)
            self._phases_completed.append("wireless")

        # ── PHASE 7c: IoT ASSESSMENT (auto-detected or explicit) ──────────────
        if (phase_enabled("iot") or self._intel.get("_iot_detected")) and not already_done("iot"):
            await self._phase_iot(target)
            self._phases_completed.append("iot")

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
        if self._intel.get("shell_access") and phase_enabled("evidence") and not already_done("evidence"):
            await self._phase_evidence_enhanced(target)
            self._phases_completed.append("evidence")

        # ── Forensics deep-dive: timeline + artifacts + memory ────────────
        if phase_enabled("forensics") and not already_done("forensics"):
            await self._phase_forensics_deep(target)
            self._phases_completed.append("forensics")

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

        # Cancel the background guidance drain task — scan is complete
        _drain_task.cancel()
        try:
            await _drain_task
        except asyncio.CancelledError:
            pass

        # Cancel meta-agent background listener
        if self._meta_listener_task and not self._meta_listener_task.done():
            self._meta_listener_task.cancel()
            try:
                await self._meta_listener_task
            except asyncio.CancelledError:
                pass

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
            # Drain guidance queue while waiting so operator input is never blocked
            await self._apply_pending_guidance()
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
        await self._apply_pending_guidance()
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
        # GUARANTEE a port scan runs. If the LLM's plan omitted nmap/masscan,
        # findings and intel stay empty → hypothesis engine shows "no open
        # ports" even when subagents later find them. Always prepend a full
        # scan when no scanner is in the plan.
        _has_port_scanner = any(
            (t.get("tool") or "").lower() in ("nmap", "masscan", "rustscan", "naabu")
            for t in tasks
        )
        if not _has_port_scanner:
            tasks.insert(0, {
                "tool":    "nmap",
                "args":    f"-sS -sV -sC --open -p- --min-rate 3000 {target}",
                "purpose": "Mandatory full port scan (LLM plan missed one)",
                "timeout": 600,
                "can_parallel": True,
            })
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
        if is_iot_target(self._target_type, self._intel["open_ports"],
                         self._intel.get("os_guess", "")):
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
            _os_guess = self._intel.get("os_guess", "").lower()
            _is_windows = "windows" in _os_guess
            if not _is_windows:
                # enum4linux queries Linux/Samba hosts — skip for confirmed Windows targets.
                # "linux_only" flag lets execute_tasks re-check os_guess at runtime
                # so a late nmap OS detection can still suppress it.
                enum_tasks.append(
                    {"tool":"enum4linux","args":f"-a {target}","timeout":120,"can_parallel":True,
                     "purpose":"SMB/NetBIOS full enumeration (Linux/Samba)","linux_only":True},
                )
            enum_tasks += [
                {"tool":"smbclient","args":f"-L //{target}/ -N","timeout":30,"can_parallel":True,
                 "purpose":"List SMB shares anonymously"},
                {"tool":"nmap","args":f"-p 445,139 --script smb-security-mode,smb2-security-mode,smb-os-discovery,smb-enum-shares {target}","timeout":60,"can_parallel":True,
                 "purpose":"SMB security mode and share discovery (Windows-compatible)"},
            ]
            if _is_windows:
                # Windows-specific SMB enumeration
                enum_tasks.append(
                    {"tool":"crackmapexec","args":f"smb {target} --shares","timeout":60,"can_parallel":True,
                     "purpose":"Windows SMB share and user enumeration"},
                )
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
        await self._apply_pending_guidance()
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
        """
        Adaptive, staged web application testing.

        Stage 1 — Fingerprint : whatweb, headers, robots.txt, sitemap
        Stage 2 — Discovery   : tech-aware gobuster, CMS tools
        Stage 3 — Analysis    : classify paths (login/API/upload/forms)
        Stage 4 — Targeted    : SQLi, auth, SSRF, SSL, CMS exploits
        Stage 5 — Deep scan   : nikto, LFI, WebDAV, upload bypass

        Each stage feeds the next; no fire-and-forget background tasks.
        All tool output is visible in the event feed in real time.
        """
        # Defensive coercion — callers (bootstrap, reasoning_loop) occasionally
        # pass a set/tuple. Slicing/indexing below requires a list.
        if not isinstance(web_ports, list):
            try:
                web_ports = sorted(int(str(p).split("/")[0]) for p in (web_ports or []))
            except Exception:
                web_ports = list(web_ports or [])
        await self._advance_phase(AttackPhase.VULN_ID)
        await self._emit("phase_start", {
            "phase":   "WEB_TESTING",
            "message": f"Adaptive web testing starting on {len(web_ports)} port(s): {web_ports[:5]}"
        })

        # ── Optional confirmation gate ───────────────────────────────────
        if self._confirm_web:
            await self._emit("awaiting_confirmation", {
                "phase":   "web_testing",
                "message": "Web application testing ready. Confirm to proceed.",
                "ports":   web_ports,
            })
            confirmed = await self._wait_for_confirmation("web_testing", timeout=3600)
            if not confirmed:
                await self._emit("phase_skipped", {"phase": "web_testing", "reason": "Not confirmed by operator"})
                return

        await self._apply_pending_guidance()

        from agents.web_agent import WebAgent
        agent = WebAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id
        self._web_agent   = agent

        os_guess     = self._intel.get("os_guess", "unknown").lower()
        technologies = list(self._intel.get("technologies", []))
        known_paths  = list(self._intel.get("web_paths", []))
        all_findings = []

        for port in web_ports[:3]:   # cap at 3 ports
            port_int = int(str(port).split("/")[0])
            proto    = "https" if port_int in (443, 8443, 4443, 7443) else "http"
            base_url = f"{proto}://{target}:{port_int}"

            # ── Stage 1: Fingerprint ─────────────────────────────────────
            await self._emit("plan_step_update", {
                "step_id": f"web_fp_{port_int}",
                "status":  "active",
                "result":  f"[Stage 1] Fingerprinting {base_url}",
                "detail":  "Detecting tech stack, server, CMS, framework",
                "found":   None,
                "ts":      datetime.utcnow().isoformat()
            })
            await self.emit_reasoning(
                step       = f"web_fingerprint_{port_int}",
                reasoning  = f"Fingerprinting {base_url} before testing — determines wordlists, extensions, and which tools to run",
                decision   = "Run whatweb + curl headers + robots.txt + sitemap",
                next_action= "Detect: CMS, framework, server type, authentication method"
            )
            fp_tasks = [
                {"tool": "whatweb",  "args": f"-a 3 --colour=never {base_url}",
                 "purpose": "Technology fingerprint", "timeout": 30, "can_parallel": True},
                {"tool": "curl",     "args": f"-sI -m 10 --max-redirs 3 {base_url}",
                 "purpose": "HTTP response headers", "timeout": 15, "can_parallel": True},
                {"tool": "curl",     "args": f"-s -m 8 --max-redirs 2 {base_url}/robots.txt",
                 "purpose": "robots.txt discovery", "timeout": 10, "can_parallel": True},
                {"tool": "curl",     "args": f"-s -m 8 --max-redirs 2 {base_url}/sitemap.xml",
                 "purpose": "Sitemap structure", "timeout": 10, "can_parallel": True},
                {"tool": "curl",     "args": f"-s -m 8 {base_url}/.well-known/security.txt",
                 "purpose": "Security policy", "timeout": 8, "can_parallel": True},
            ]
            fp_result = await agent.execute_tasks(target, fp_tasks, "WEB_FINGERPRINT", self._intel)
            fp_raw = " ".join((fp_result.get("raw_outputs") or {}).values()).lower()

            # Detect technologies from fingerprint output
            is_wordpress = any(k in fp_raw for k in ("wordpress", "wp-content", "wp-login", "wp-json"))
            is_drupal    = "drupal" in fp_raw
            is_joomla    = any(k in fp_raw for k in ("joomla", "/components/", "/modules/"))
            is_django    = "django" in fp_raw
            is_dotnet    = any(k in fp_raw for k in ("asp.net", "x-aspnet", "aspnetcore", ".aspx", "viewstate"))
            is_php       = any(k in fp_raw for k in ("php", "x-php", "phpsessid"))
            is_java      = any(k in fp_raw for k in ("java", "jsessionid", "servlet", "spring", "j2ee"))
            is_nodejs    = any(k in fp_raw for k in ("node.js", "express", "nodejs", "x-powered-by: express"))
            is_iis       = any(k in fp_raw for k in ("iis", "microsoft-iis", "x-powered-by: asp.net"))
            is_apache    = "apache" in fp_raw
            is_nginx     = "nginx" in fp_raw
            is_win_web   = is_iis or is_dotnet or "windows" in os_guess

            # Enrich intel with detected tech
            for tech, flag in [("wordpress", is_wordpress), ("drupal", is_drupal),
                                ("joomla", is_joomla), ("django", is_django),
                                ("asp.net", is_dotnet), ("iis", is_iis)]:
                if flag and tech not in technologies:
                    technologies.append(tech)
                    if tech not in self._intel.get("technologies", []):
                        self._intel.setdefault("technologies", []).append(tech)

            await self._emit("plan_step_update", {
                "step_id": f"web_fp_{port_int}",
                "status":  "done",
                "result":  f"[Stage 1] Fingerprint complete — detected: {', '.join(technologies) or 'generic web'}",
                "found":   bool(technologies),
                "ts":      datetime.utcnow().isoformat()
            })

            # ── Stage 2: Discovery ───────────────────────────────────────
            await self._emit("plan_step_update", {
                "step_id": f"web_disc_{port_int}",
                "status":  "active",
                "result":  f"[Stage 2] Discovering endpoints on {base_url}",
                "detail":  "Directory enum with tech-appropriate wordlists",
                "found":   None,
                "ts":      datetime.utcnow().isoformat()
            })
            await self.emit_reasoning(
                step       = f"web_discovery_{port_int}",
                reasoning  = f"Discovery phase: enumerate paths, find login pages, APIs, upload endpoints",
                decision   = f"Using {'Windows/IIS' if is_win_web else 'CMS-specific' if any([is_wordpress,is_drupal,is_joomla]) else 'generic'} wordlist strategy",
                next_action= f"gobuster dir on {base_url}"
            )
            # Choose wordlist and extensions based on detected tech
            if is_win_web:
                wordlist   = "/usr/share/wordlists/dirb/common.txt"
                extensions = "asp,aspx,ashx,asmx,config,xml,html,bak,old,zip"
            elif is_wordpress:
                wordlist   = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
                extensions = "php,html,txt,bak,zip,sql,xml"
            elif is_java:
                wordlist   = "/usr/share/wordlists/dirb/common.txt"
                extensions = "jsp,jspx,do,action,xml,properties,html,bak"
            elif is_php:
                wordlist   = "/usr/share/wordlists/dirb/common.txt"
                extensions = "php,php5,php7,html,txt,bak,old,zip,sql,conf,xml,json"
            else:
                wordlist   = "/usr/share/wordlists/dirb/common.txt"
                extensions = "html,txt,bak,old,zip,conf,xml,json,js,yaml,yml"

            disc_tasks = [
                {"tool": "gobuster",
                 "args": f"dir -u {base_url} -w {wordlist} -x {extensions} "
                         f"-t 30 -q --no-error --timeout 10s -s 200,204,301,302,307,401,403",
                 "purpose": f"Directory enumeration ({extensions[:40]}...)",
                 "timeout": 180, "can_parallel": False},
            ]
            # CMS-specific tools run alongside gobuster if applicable
            if is_wordpress:
                disc_tasks.append({
                    "tool": "wpscan",
                    "args": f"--url {base_url} --enumerate p,t,u,vp --plugins-detection mixed "
                            f"--no-banner --format cli-no-color",
                    "purpose": "WordPress plugin/theme/user enumeration",
                    "timeout": 180, "can_parallel": True
                })
            elif is_drupal:
                disc_tasks.append({
                    "tool": "nmap",
                    "args": f"--script http-drupal-enum,http-vuln-cve2014-3704 -p {port_int} {target}",
                    "purpose": "Drupal vulnerability check",
                    "timeout": 60, "can_parallel": True
                })
            elif is_joomla:
                disc_tasks.append({
                    "tool": "curl",
                    "args": f"-s -m 10 {base_url}/administrator/ {base_url}/components/ {base_url}/modules/",
                    "purpose": "Joomla admin and component enumeration",
                    "timeout": 20, "can_parallel": True
                })

            disc_result = await agent.execute_tasks(target, disc_tasks, "WEB_DISCOVERY", self._intel)

            # Collect and classify discovered paths
            raw_paths = disc_result.get("web_paths", []) + disc_result.get("paths", []) + known_paths
            for p in raw_paths:
                if p not in self._intel["web_paths"]:
                    self._intel["web_paths"].append(p)

            login_paths  = [p for p in raw_paths if any(k in p.lower() for k in
                ["login", "signin", "admin", "auth", "dashboard", "portal",
                 "wp-admin", "wp-login", "manager", "console", "account", "user"])]
            upload_paths = [p for p in raw_paths if any(k in p.lower() for k in
                ["upload", "file", "image", "media", "attachment", "avatar", "import"])]
            api_paths    = [p for p in raw_paths if any(k in p.lower() for k in
                ["api", "rest", "graphql", "v1", "v2", "v3", "swagger", "openapi",
                 "json", "xml", "endpoint"])]
            form_paths   = [p for p in raw_paths if "?" in p]

            # Update intel with login pages
            for lp in login_paths:
                full_lp = f"{base_url}{lp}"
                if full_lp not in self._intel.get("login_pages", []):
                    self._intel.setdefault("login_pages", []).append(full_lp)

            await self._emit("plan_step_update", {
                "step_id": f"web_disc_{port_int}",
                "status":  "done",
                "result":  (f"[Stage 2] Discovery complete: {len(raw_paths)} paths found — "
                            f"{len(login_paths)} logins, {len(api_paths)} APIs, "
                            f"{len(upload_paths)} upload endpoints"),
                "found":   bool(raw_paths),
                "ts":      datetime.utcnow().isoformat()
            })
            await self.emit_reasoning(
                step       = f"web_discovery_result_{port_int}",
                reasoning  = f"Discovered {len(raw_paths)} paths: {len(login_paths)} login pages, {len(api_paths)} API endpoints, {len(upload_paths)} file upload endpoints",
                decision   = "Select targeted tests based on attack surface",
                next_action= (f"Auth testing: {bool(login_paths)} | "
                              f"SQLi: {bool(form_paths or True)} | "
                              f"API fuzzing: {bool(api_paths)} | "
                              f"Upload bypass: {bool(upload_paths)}")
            )

            # ── Stage 3: Baseline Scans (always run) ────────────────────
            await self._emit("plan_step_update", {
                "step_id": f"web_base_{port_int}",
                "status":  "active",
                "result":  f"[Stage 3] Running baseline scans on {base_url}",
                "detail":  "nikto + security headers + SSL check",
                "found":   None,
                "ts":      datetime.utcnow().isoformat()
            })
            baseline_tasks = [
                {"tool": "nikto",
                 "args": f"-h {base_url} -C all -maxtime 120 -Format txt -nointeractive",
                 "purpose": "Comprehensive server misconfiguration scan (A05)", "timeout": 150, "can_parallel": True},
                {"tool": "curl",
                 "args": f"-sI -m 10 --max-redirs 2 {base_url}",
                 "purpose": "Security headers audit (HSTS/CSP/X-Frame)", "timeout": 15, "can_parallel": True},
            ]
            if proto == "https":
                baseline_tasks.append({
                    "tool": "sslscan",
                    "args": f"--no-colour {target}:{port_int}",
                    "purpose": "TLS/SSL cipher and certificate audit", "timeout": 60, "can_parallel": True
                })
            if is_win_web:
                baseline_tasks.extend([
                    {"tool": "nmap",
                     "args": f"--script http-iis-webdav-vuln,http-iis-short-name-brute -p {port_int} {target}",
                     "purpose": "IIS WebDAV and short-name vulnerability check", "timeout": 60, "can_parallel": True},
                    {"tool": "nmap",
                     "args": f"--script http-auth-finder,http-ntlm-info -p {port_int} {target}",
                     "purpose": "Windows NTLM auth detection", "timeout": 30, "can_parallel": True},
                ])

            baseline_result = await agent.execute_tasks(target, baseline_tasks, "WEB_BASELINE", self._intel)
            all_findings.extend(baseline_result.get("vulnerabilities", []))

            # ── Stage 4: Targeted Attacks (finding-driven) ───────────────
            await self._emit("plan_step_update", {
                "step_id": f"web_atk_{port_int}",
                "status":  "active",
                "result":  f"[Stage 4] Targeted attacks on {base_url}",
                "detail":  "SQLi / Auth / SSRF / Upload / API — based on discovered surface",
                "found":   None,
                "ts":      datetime.utcnow().isoformat()
            })
            targeted_tasks = []

            # ◆ SQL Injection — always try; if params found target those specifically
            sqli_target = (f"{base_url}{form_paths[0]}" if form_paths
                           else f"{base_url}/ --crawl=2 --forms")
            targeted_tasks.append({
                "tool": "sqlmap",
                "args": (f"-u '{base_url}{form_paths[0]}' --batch --level=2 --risk=2 --dbs --timeout=20"
                         if form_paths else
                         f"-u '{base_url}/' --crawl=2 --batch --level=2 --risk=2 --forms --dbs --timeout=20"),
                "purpose": f"SQL injection test (A03) — {'param targeting' if form_paths else 'crawl mode'}",
                "timeout": 130, "can_parallel": True
            })

            # ◆ Authentication — only if login pages found
            if login_paths:
                lp = login_paths[0]
                targeted_tasks.extend([
                    {"tool": "hydra",
                     "args": (f"-L /usr/share/wordlists/metasploit/http_default_users.txt "
                              f"-P /usr/share/wordlists/metasploit/http_default_pass.txt "
                              f"-s {port_int} {target} http-post-form "
                              f"'{lp}:username=^USER^&password=^PASS^:incorrect'"),
                     "purpose": f"Default credential brute-force on {lp} (A07)",
                     "timeout": 60, "can_parallel": True},
                    {"tool": "curl",
                     "args": (f"-s -X POST -d \"username=' OR '1'='1&password=x\" "
                              f"-c /tmp/cookies_{port_int}.txt -L {base_url}{lp}"),
                     "purpose": f"SQL auth bypass test on {lp}",
                     "timeout": 15, "can_parallel": True},
                ])

            # ◆ SSRF — check URL parameters
            ssrf_params = ["url", "redirect", "next", "return", "goto", "target", "fetch", "proxy", "load"]
            ssrf_paths_found = [p for p in raw_paths
                                if any(f"?{param}=" in p or f"&{param}=" in p for param in ssrf_params)]
            if ssrf_paths_found:
                targeted_tasks.append({
                    "tool": "curl",
                    "args": (f"-s -m 10 '{base_url}{ssrf_paths_found[0]}' "
                             f"--data 'url=http://127.0.0.1:22/'"),
                    "purpose": f"SSRF probe on {ssrf_paths_found[0]} (A10)",
                    "timeout": 15, "can_parallel": True
                })

            # ◆ File upload bypass — only if upload endpoints exist
            if upload_paths:
                targeted_tasks.append({
                    "tool": "curl",
                    "args": (f"-s -X POST "
                             f"-F 'file=@/dev/urandom;filename=test.php;type=image/jpeg' "
                             f"{base_url}{upload_paths[0]}"),
                    "purpose": f"File upload MIME bypass test on {upload_paths[0]} (A08)",
                    "timeout": 15, "can_parallel": True
                })

            # ◆ API enumeration — if API paths found
            if api_paths:
                targeted_tasks.append({
                    "tool": "ffuf",
                    "args": (f"-u {base_url}{api_paths[0]}/FUZZ "
                             f"-w /usr/share/wordlists/dirb/common.txt "
                             f"-mc 200,201,204,400,401,403 -t 20 -timeout 5"),
                    "purpose": f"API endpoint fuzzing on {api_paths[0]}",
                    "timeout": 60, "can_parallel": True
                })

            # ◆ LFI check if any paths found
            targeted_tasks.append({
                "tool": "wfuzz",
                "args": (f"-c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt "
                         f"--hc 404,400,500 {base_url}/FUZZ"),
                "purpose": "Local file inclusion probe (A01)",
                "timeout": 60, "can_parallel": True
            })

            # ◆ Command injection via commix on forms
            if form_paths or not is_win_web:
                targeted_tasks.append({
                    "tool": "commix",
                    "args": (f"--url={base_url}/ --crawl=1 --batch --level=2 "
                             f"--output-dir=/tmp/commix_{port_int}"),
                    "purpose": "OS command injection scan (A03)",
                    "timeout": 90, "can_parallel": True
                })

            # ◆ WebDAV write access
            targeted_tasks.append({
                "tool": "davtest",
                "args": f"-url {base_url}",
                "purpose": "WebDAV write access check",
                "timeout": 30, "can_parallel": True
            })

            targeted_result = await self._run_web_tasks_with_timeout(agent, target, targeted_tasks)
            all_findings.extend(targeted_result.get("vulnerabilities", []))
            for p in targeted_result.get("web_paths", []):
                if p not in self._intel["web_paths"]:
                    self._intel["web_paths"].append(p)

            # ── Set adaptive flags based on findings ─────────────────────
            if targeted_result.get("sqli_found") or any(
                    "sqli" in str(v).lower() or "sql injection" in str(v).lower()
                    for v in all_findings):
                self._intel["critical_web_vulns"] = True
                self._intel["sqli_confirmed"]     = True
                await self.emit_reasoning(
                    step       = "web_sqli_found",
                    reasoning  = "SQL injection confirmed — high-priority exploit path available",
                    decision   = "Flag for exploitation phase prioritisation",
                    next_action= "Exploit phase will target this SQLi for data exfil / shell"
                )

            await self._emit("plan_step_update", {
                "step_id": f"web_atk_{port_int}",
                "status":  "done",
                "result":  (f"[Stage 4] Targeted attacks complete on port {port_int}: "
                            f"{len(targeted_result.get('vulnerabilities', []))} vulnerabilities found"),
                "found":   bool(targeted_result.get("vulnerabilities")),
                "ts":      datetime.utcnow().isoformat()
            })

        # ── Final LLM analysis across all ports ─────────────────────────
        web_analysis = self._safe_llm_result(await self._llm_analyse_web_results(target, {
            "web_vulns":   all_findings,
            "web_paths":   self._intel["web_paths"],
            "login_pages": self._intel.get("login_pages", []),
            "technologies": technologies,
            "sqli_confirmed": self._intel.get("sqli_confirmed", False),
        }))
        await self.emit_reasoning(
            step       = "web_final_analysis",
            reasoning  = web_analysis.get("reasoning", ""),
            decision   = web_analysis.get("critical_findings", ""),
            next_action= web_analysis.get("exploit_recommendation", ""),
            data       = web_analysis
        )

        # Adaptive: if critical web vulns found, ensure exploit phase knows
        if web_analysis.get("critical_findings"):
            self._intel.setdefault("attack_path", []).append({
                "phase":  "web_testing",
                "result": web_analysis.get("critical_findings", ""),
                "ts":     datetime.utcnow().isoformat()
            })
            self._intel["critical_web_vulns"] = True

        await self._emit("plan_step_update", {
            "step_id": "web_testing",
            "status":  "done",
            "result":  (web_analysis.get("critical_findings")
                        or f"Web testing complete: {len(all_findings)} findings"),
            "detail":  (f"Paths: {len(self._intel.get('web_paths', []))} | "
                        f"Login pages: {len(self._intel.get('login_pages', []))} | "
                        f"Technologies: {', '.join(technologies[:5])}"),
            "found":   len(all_findings) > 0,
            "ts":      datetime.utcnow().isoformat()
        })

    async def _run_web_tasks_with_timeout(self, agent, target: str, tasks: List) -> Dict:
        """
        Runs web execute_tasks with an optional time-extension popup.
        If web_phase_timeout > 0 and the tasks don't finish in time, we emit
        awaiting_time_extension so the frontend shows the "Extend / Stop" dialog.
        The operator can extend multiple times; each extension grants the same
        extra period again.  Clicking "Stop" cancels the agent gracefully.
        """
        timeout_secs = self._web_phase_timeout

        if timeout_secs <= 0:
            # No time limit — run to completion
            return await agent.execute_tasks(target, tasks, "WEB_TESTING", self._intel)

        extension_key = "extend_web_testing"

        while True:
            try:
                result = await asyncio.wait_for(
                    agent.execute_tasks(target, tasks, "WEB_TESTING", self._intel),
                    timeout=float(timeout_secs)
                )
                return result
            except asyncio.TimeoutError:
                # Emit time-extension popup to frontend
                await self._emit("awaiting_time_extension", {
                    "phase":          "web_testing",
                    "timeout_secs":   timeout_secs,
                    "message": (
                        f"Web testing has been running for {timeout_secs}s. "
                        "Extend to continue or stop web testing now."
                    ),
                })

                # Prepare the extend event
                if extension_key not in self._extend_events:
                    self._extend_events[extension_key] = asyncio.Event()
                else:
                    self._extend_events[extension_key].clear()

                # Wait up to 5 minutes for the operator to respond
                try:
                    await asyncio.wait_for(
                        self._extend_events[extension_key].wait(),
                        timeout=300.0
                    )
                    # Operator clicked "Extend" — loop back and run again
                    await self._emit("phase_extended", {
                        "phase":   "web_testing",
                        "message": "Web testing time extended by operator",
                    })
                    await self._apply_pending_guidance()
                    # Reset agent state so it continues from where tools left off
                    # (execute_tasks with remaining tasks only — already-run tools cached)
                    continue
                except asyncio.TimeoutError:
                    # No response — stop web testing gracefully
                    agent.request_stop()
                    await self._emit("phase_stopped", {
                        "phase":   "web_testing",
                        "message": "Web testing stopped — no response to time extension request",
                    })
                    return {"web_paths": [], "paths": [], "login_pages": [],
                            "web_vulns": [], "raw_outputs": {}}

    # ─── PHASE: OSINT ─────────────────────────────────────────

    async def _phase_osint(self, target: str):
        """Master plans all OSINT tasks. Agent executes + extracts modules."""
        await self._apply_pending_guidance()
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

    async def _parse_operator_context(
        self,
        notes:       str,
        scope:       str,
        target_type: str = "unknown",
    ):
        """
        Use the LLM to understand operator intent from free-form notes.

        Returns an EngagementContext with:
          - engagement_type  (pentest / ctf / forensics / network_analysis / …)
          - objectives       (ordered list of tasks/questions)
          - constraints      (rules of engagement)
          - tools_preferred / tools_excluded
          - approach_summary (how to tackle this)
          - clarifying_questions (ask operator if ambiguous)

        Falls back to a default pentest context if LLM is unavailable.
        """
        from agents.reasoning.engagement_context import EngagementContext

        all_text = "\n".join(filter(None, [notes, scope]))
        if not all_text.strip():
            return EngagementContext.default_pentest()

        prompt = f"""You are an intelligent engagement planner for ARGUS, an adaptive security operations platform.
Analyze the operator's notes and derive a precise, structured engagement context.

=== OPERATOR NOTES ===
{notes or "(none)"}

=== SCOPE / ADDITIONAL CONTEXT ===
{scope or "(none)"}

=== TARGET TYPE ===
{target_type}

Determine:
1. What TYPE of engagement this is
2. What SPECIFIC objectives need to be achieved (ordered by priority)
3. What TOOLS make sense vs. should be avoided
4. What APPROACH to take
5. Any CLARIFYING QUESTIONS needed (only if genuinely ambiguous — max 3)

Respond with JSON only — no markdown, no prose:
{{
  "engagement_type": "pentest|ctf|forensics|network_analysis|malware_analysis|compliance|bug_bounty|red_team|custom",
  "title": "One-line description of this engagement",
  "context_summary": "2-3 sentence explanation of what the operator wants",
  "objectives": [
    {{"task": "Specific task or question to answer", "section": "Optional phase label", "priority": 1}}
  ],
  "constraints": ["Any rules of engagement, scope limits, or restrictions mentioned"],
  "tools_preferred": ["Tools that are appropriate for this engagement"],
  "tools_excluded": ["Tools that must NOT be used"],
  "approach_summary": "How ARGUS should approach this — what to look for, in what order",
  "clarifying_questions": ["Question if critical info is missing"]
}}

RULES:
- engagement_type MUST be one of the listed values
- For CTF: extract every question/flag/puzzle as a separate objective, preserve order and section groupings
- For forensics: objectives = artifacts to extract, timeline events, IOCs to find
- For network_analysis: objectives = anomalies, suspicious hosts/protocols, C2 indicators
- For malware_analysis: objectives = capabilities, IOCs, persistence mechanisms, C2
- For compliance: objectives = specific controls to check
- tools_excluded for forensics/malware/network_analysis MUST include: nmap, metasploit, hydra, sqlmap, gobuster
- tools_excluded for compliance MUST include: metasploit, sqlmap, hydra
- Only include clarifying_questions if the engagement type or a key objective is genuinely unclear"""

        system = (
            "You are an expert security engagement planner. "
            "Read operator instructions precisely and produce structured JSON. "
            "JSON only — no markdown fences, no prose."
        )

        import logging as _log
        try:
            raw = await self.think_json(prompt, system)
            if raw and isinstance(raw, dict):
                ctx = EngagementContext.from_dict(raw)
                _log.getLogger(__name__).info(
                    "Engagement context: type=%s, objectives=%d, questions=%d",
                    ctx.engagement_type, len(ctx.objectives), len(ctx.clarifying_questions)
                )
                return ctx
        except Exception as e:
            _log.getLogger(__name__).warning("Operator context parsing failed: %s", e)

        # Fallback: try basic regex extraction so we never return empty for CTF notes
        return EngagementContext.default_pentest()

    def answer_operator_question(self, answers: dict) -> None:
        """
        Called when the operator submits answers to clarifying questions.
        Injects the answers as operator guidance so the reasoning loop picks them up.
        answers = {"0": "answer to question 0", "1": "answer to question 1", ...}
        """
        ctx_dict = self._intel.get("engagement_context", {})
        questions = ctx_dict.get("clarifying_questions", [])
        if not questions:
            return

        note_parts = ["Operator answered clarifying questions:"]
        for idx_str, answer in answers.items():
            try:
                q = questions[int(idx_str)]
                note_parts.append(f"  Q: {q}")
                note_parts.append(f"  A: {answer}")
            except (IndexError, ValueError):
                note_parts.append(f"  Additional note: {answer}")

        # Clear questions so the banner disappears
        ctx_dict["clarifying_questions"] = []
        self._intel["engagement_context"] = ctx_dict

        # Inject as high-priority guidance
        self.inject_guidance({
            "directive": "add_note",
            "note":      "\n".join(note_parts),
        })

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

    # ─────────────────────────────────────────────────────────────────
    #  MCP TOOL CATALOG LOADER
    # ─────────────────────────────────────────────────────────────────

    async def _load_tool_catalog(self) -> None:
        """Fetch the full tool list from mcp-server.js and cache it.

        Populates ``self._tool_catalog`` (dict) and ``self._tool_catalog_text``
        (pre-formatted string ready to drop into LLM planning prompts).
        Called once at session start.  Failure is non-fatal — planning
        prompts fall back to their hardcoded hint lists if the catalog is
        empty.
        """
        import httpx
        try:
            from agents.base_agent import MCP_URL
        except Exception:
            MCP_URL = "http://localhost:3000"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{MCP_URL}/tools/list")
                data = r.json() if r.status_code == 200 else {}
        except Exception as exc:
            await self.emit_reasoning(
                step="tool_catalog_load",
                reasoning=f"MCP catalog unreachable: {exc}",
                decision="Planning prompts will use hardcoded tool hints",
                next_action="Continue without full catalog"
            )
            return

        # MCP /tools/list returns {"tools": [{name, bin, category, description}, ...]}
        raw = data.get("tools") or data if isinstance(data, (list, dict)) else []
        if isinstance(raw, dict):
            raw = raw.get("tools", [])
        self._tool_catalog = {
            (t.get("name") or "").strip(): t
            for t in raw if isinstance(t, dict) and t.get("name")
        }

        # Group by category for compact LLM context
        by_cat: Dict[str, List[str]] = {}
        for name, meta in self._tool_catalog.items():
            cat = (meta.get("category") or "misc").lower()
            by_cat.setdefault(cat, []).append(name)
        lines = [f"AVAILABLE KALI TOOLS ({len(self._tool_catalog)} total, via MCP server):"]
        for cat in sorted(by_cat):
            tools = sorted(by_cat[cat])
            lines.append(f"  [{cat}] " + ", ".join(tools))
        self._tool_catalog_text = "\n".join(lines)

        await self.emit_reasoning(
            step="tool_catalog_loaded",
            reasoning=f"Loaded {len(self._tool_catalog)} tools across {len(by_cat)} categories",
            decision="LLM planners will see the full Kali arsenal",
            next_action="Proceed to pentest phases",
            data={"tool_count": len(self._tool_catalog), "categories": sorted(by_cat.keys())}
        )

    def _tools_hint(self, max_chars: int = 3500) -> str:
        """Return the cached tool catalog text, truncated for prompt safety."""
        if not self._tool_catalog_text:
            return ""
        txt = self._tool_catalog_text
        if len(txt) > max_chars:
            txt = txt[:max_chars] + "\n  ... (truncated — full list available)"
        return txt

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
Pick DIFFERENT tools from: nmap, masscan, rustscan, fping, whatweb, wafw00f, dnsrecon, fierce, amass, smbmap, onesixtyone, snmpwalk
OS-AWARE RULES (current os_guess: {self._intel.get('os_guess','unknown')}):
- If target is Windows: use crackmapexec, nmap smb scripts, smbmap — DO NOT use enum4linux (Linux/Samba only)
- If target is Linux/unknown: enum4linux is allowed for SMB ports

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

{self._tools_hint()}

TOOL-SELECTION HINTS (pick from the catalog above — you are NOT limited to these):
- searchsploit: ALWAYS run for each exact service version found (e.g. "Apache 2.4.49", "vsftpd 2.3.4")
- nmap --script vuln: for open ports with known vuln scripts
- nikto: for HTTP services — finds misconfigurations, default files, known CVEs
- sslscan / testssl.sh: ONLY if HTTPS/TLS found
- wpscan: ONLY if WordPress detected
- enum4linux / smbmap / crackmapexec: ONLY if SMB found
- hydra / medusa / ncrack: ONLY if login pages or SSH/FTP found AND usernames are known
- wfuzz / ffuf / feroxbuster / gobuster: for web content discovery
- sqlmap / commix: for injection testing
- impacket-secretsdump / bloodhound: for AD enumeration
- any other tool listed in the catalog is fair game — use the best one for the job

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
{self._tools_hint()}

Pick from the catalog above — common picks for web: nikto, gobuster, ffuf, feroxbuster, sqlmap,
wfuzz, commix, wapiti, dirb, wpscan, nuclei, dalfox, davtest, wafw00f, whatweb, katana, arjun.
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
        # Pull ALL relevant recon/vuln/web artefacts so OSINT planning is
        # discovery-driven, not a generic "search the target IP" exercise.
        intel = self._intel or {}
        _svcs = [_fmt_svc(v) for v in list(intel.get("services", {}).values())[:8]]
        _svc_versions = []
        for p, v in (intel.get("service_versions", {}) or {}).items():
            if isinstance(v, str) and v.strip():
                _svc_versions.append(f"{p}:{v}")
        _os         = intel.get("os_guess", "unknown")
        _hostnames  = list(dict.fromkeys((intel.get("hostnames") or []) +
                                         (intel.get("subdomains") or []) +
                                         (intel.get("virtual_hosts") or [])))[:15]
        _ssl_cns    = list(dict.fromkeys((intel.get("ssl_cns") or []) +
                                         (intel.get("ssl_sans") or [])))[:15]
        _web_tech   = list(dict.fromkeys(intel.get("web_tech") or
                                         intel.get("technologies") or []))[:15]
        _titles     = list(dict.fromkeys(intel.get("http_titles") or []))[:8]
        _logins     = list(dict.fromkeys(intel.get("login_pages") or []))[:8]
        _emails     = list(dict.fromkeys(intel.get("emails") or []))[:10]
        _users      = list(dict.fromkeys(intel.get("users") or []))[:10]
        _org        = intel.get("org") or intel.get("organization") or ""

        _svc_str = " ".join(_svcs)
        kb = await self._kb(
            f"OSINT CVE searchsploit {_svc_str} {_os} exploit database",
            top_k=3,
        )

        prompt = f"""You are the OSINT planner for an ACTIVE penetration test.
Your job is to turn RECON DISCOVERIES into targeted intelligence queries —
NOT to do a generic Google search for the target string.

Target: {target}
OS guess: {_os}
Org: {_org or 'unknown'}

──── DISCOVERED ARTEFACTS (use these to drive searches) ────
Services (port → product/version):
  {_svcs or 'none'}
Service versions: {_svc_versions or 'none'}
Hostnames / subdomains / vhosts: {_hostnames or 'none'}
SSL certificate CNs / SANs: {_ssl_cns or 'none'}
Web technologies: {_web_tech or 'none'}
HTTP titles: {_titles or 'none'}
Login pages: {_logins or 'none'}
Emails already harvested: {_emails or 'none'}
Usernames already discovered: {_users or 'none'}

{kb}

──── PLANNING GUIDANCE ────
Produce searches that PIVOT on the artefacts above. Prefer, in priority order:
1. CVE lookup per `product version` pair — one searchsploit/NVD query per pair.
2. Subdomain enumeration using discovered hostnames/SSL SANs as seeds.
3. Tech-stack-specific dorks (e.g. "site:{{domain}} inurl:wp-admin" if WordPress
   in web_tech).
4. Breach lookups for discovered emails / usernames (HIBP).
5. Org-level pivots using SSL CN / org name (Shodan org:, Censys autonomous_system).
6. Historical URLs via Wayback for each discovered subdomain.
7. GitHub/pastebin dorks on org name, domain, and distinctive banner strings.
Do NOT simply "search {target}" — every search should mention a CONCRETE artefact
from the list above.

Return JSON with this exact shape:
{{
  "reasoning": "1-3 sentences on which artefacts drove your choices",
  "searches": [
    {{
      "tool":    "searchsploit|nvd|shodan|google_dorks|wayback|theharvester|recon_ng|builtwith|security_trails|censys|bgpview|spiderfoot|hibp",
      "args":    "concrete search string (product+version, subdomain, email, CN, tech name)",
      "purpose": "what vuln/intel this is expected to surface",
      "timeout": 30
    }}
  ]
}}
Emit between 4 and 10 searches — quality over quantity."""
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

{self._tools_hint()}

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

{self._tools_hint()}

ATTACK VECTOR:
- Type: {_type}
- Description: {_desc}
- Suggested tool (must be a name from the catalog above): {_tool}

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
        try:
            slog = get_scan_logger(self._session_id)
            if slog:
                slog.log_phase(str(phase), "start")
        except Exception:
            pass

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

        Design note: state mutations (phases_to_run, forced_instructions, intel) happen
        IMMEDIATELY and synchronously. The emit_reasoning / DB-write calls are fired as
        background tasks so they never block guidance processing.
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

        # Fire WS notification immediately (fast — no DB write)
        await self._emit("guidance_applied", {
            "directive": directive,
            "message":   f"Guidance applied: {note or directive or force_tool or skip_phase}"
        })

        # Emit reasoning as a fire-and-forget task so a slow DB write
        # never blocks the guidance state changes below
        asyncio.create_task(self.emit_reasoning(
            step       = "user_guidance_applied",
            reasoning  = f"User guidance received: {note or directive or 'no message'}",
            decision   = (
                f"Skipping phase: {skip_phase}" if skip_phase else
                f"Forcing tool: {force_tool} {force_args}" if force_tool else
                f"Context note injected: {note}"
            ),
            next_action= force_tool or ("Continue — note will inform next LLM call" if note else "Continue"),
            data       = guidance
        ))

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
            # ── Question intent detection ──────────────────────────────────
            # If the note looks like a question, route it through QuestionEngine
            # for immediate 3-layer extraction against current intel.
            _qe = getattr(self, "_question_engine", None)
            if _qe is None and _REASONING_AVAILABLE:
                # QuestionEngine may live on ReasoningLoop — try to get it
                _rl = getattr(self, "_reasoning_loop_instance", None)
                if _rl is not None:
                    _qe = getattr(_rl, "_question_engine", None)

            if _qe is not None and _qe.is_question(note):
                asyncio.create_task(self._answer_question_from_guidance(note, _qe))
            else:
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
            # Fire-and-forget — DB write must not block the guidance state change
            asyncio.create_task(self.emit_reasoning(
                step       = "dns_override_applied",
                reasoning  = f"Operator added DNS mapping: {dns_host} → {dns_ip}",
                decision   = "Stored in intel — subagents will use this hostname in tool args",
                next_action= "Inject hostname into next web/recon tool calls",
                data       = {"dns_host": dns_host, "dns_ip": dns_ip}
            ))

    async def _answer_question_from_guidance(self, question: str, qe) -> None:
        """
        Fire-and-forget coroutine: run the 3-layer QuestionEngine pipeline
        for a question detected in the operator guidance text.
        Emits a question_answered finding visible in FindingsBoard.
        """
        try:
            await self.emit_reasoning(
                step       = "question_from_guidance",
                reasoning  = f"Operator question detected: {question}",
                decision   = "Running 3-layer extraction against current intel",
                next_action= "Emit answer as finding",
                data       = {"question": question},
            )
            q_obj = await qe.answer_single(question, self._intel, "")
            if q_obj.state.value == "answered":
                await self.emit_reasoning(
                    step       = "question_answered",
                    reasoning  = f"Answer found: {q_obj.answer}",
                    decision   = f"Layer {q_obj.layer_used} ({q_obj.layer_used})",
                    next_action= "Displayed as finding in FindingsBoard",
                    data       = {"answer": q_obj.answer, "layer": q_obj.layer_used},
                )
            else:
                await self.emit_reasoning(
                    step       = "question_unanswerable",
                    reasoning  = f"Could not answer: {question}",
                    decision   = "All 3 layers exhausted",
                    next_action= "Continue scan — more data may answer later",
                    data       = {"question": question},
                )
        except Exception as e:
            pass  # never crash guidance processing

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

    def extend_phase(self, phase: str):
        """
        Called by agent_server when operator clicks 'Extend' in the time-extension dialog.
        Sets the extend event for the given phase so _phase_web_testing() (or any other
        timed phase) can resume.  Also works as the confirmation gate for confirm_web.
        """
        key = f"extend_{phase}"
        if key not in self._extend_events:
            self._extend_events[key] = asyncio.Event()
        self._extend_events[key].set()

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
