"""
KALI PENTEST PLATFORM v3 — Base Agent

Key improvements over v2:
  1. LLM GATE: All agents check Ollama is responsive before proceeding.
     If LLM is down, testing halts with clear user notification.
  2. STRUCTURED REASONING: Every decision emits a reasoning event that
     is visible in the UI — what the agent is thinking, why, next step.
  3. MASTER-ONLY LLM PROTOCOL: Only master agent calls think().
     Slave agents receive typed instructions via InstructionSet and execute.
  4. PERSISTENT LOGGING: Every tool run, finding, reasoning step stored in DB.
  5. ATTACK GRAPH: Proper node/edge population on every discovery.
"""

import asyncio
import json
import os
import re
import signal as _signal
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Callable, Awaitable
from datetime import datetime

import httpx

from db.schemas import (
    AgentName, AgentStatus, AttackPhase,
    FindingSeverity, WebSocketMessage
)
import db.mongo_client as db

def _kill_proc_tree(proc) -> None:
    """Kill a subprocess AND all its children.

    Cross-platform:
    - POSIX: killpg() → SIGKILL to the entire process group so bash + nikto
      + any pipeline children all die.
    - Windows: taskkill /T /F to recursively kill the process tree, since
      os.getpgid / os.killpg / SIGKILL do not exist there.

    Always falls back to proc.kill() at the end so the asyncio Process object
    transitions to a terminated state and drain readers unblock.
    """
    # ── POSIX: process-group kill ──────────────────────────────
    if hasattr(os, "getpgid") and hasattr(os, "killpg") and hasattr(_signal, "SIGKILL"):
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, _signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    # ── Windows: recursive taskkill ────────────────────────────
    elif sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass
    # ── Always: final kill on the asyncio Process so drain unblocks ─
    try:
        proc.kill()
    except Exception:
        pass


# Per-session scan logger proxies — safe no-op if no active session logger.
try:
    from utils.scan_logger import (
        log_tool_call as _slog_tool,
        log_llm       as _slog_llm,
        log_error     as _slog_error,
    )
except Exception:  # pragma: no cover
    def _slog_tool(*a, **kw):  pass
    def _slog_llm(*a, **kw):   pass
    def _slog_error(*a, **kw): pass

# ── Neo4j semantic graph (optional) ──────────────────────────────────────────
try:
    import db.neo4j_client as _neo4j
    _NEO4J_AVAILABLE = True
except ImportError:
    _neo4j = None
    _NEO4J_AVAILABLE = False

# ── Knowledge-graph semantic inference (optional) ─────────────────────────────
try:
    from agents.knowledge_graph import infer_and_write as _kg_infer
    _KG_AVAILABLE = True
except ImportError:
    _kg_infer = None
    _KG_AVAILABLE = False

# ── Auto-ingest to RAG KB (optional) ─────────────────────────────────────────
try:
    _auto_ingest_dir = os.path.join(os.path.dirname(__file__), "..", "knowledge")
    sys.path.insert(0, _auto_ingest_dir)
    from auto_ingest import capture_finding as _capture_finding
    _AUTO_INGEST_AVAILABLE = True
except ImportError:
    _capture_finding = None
    _AUTO_INGEST_AVAILABLE = False

# ── RAG Knowledge Base (shared by all agents) ─────────────────────────────────
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "knowledge"))
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "knowledge"))
    import knowledge_base as _kb
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False


def _kb_context(query: str, phase: str = None, outcome: str = None,
                phase_filter: str = None, outcome_filter: str = None,
                chunk_type_filter: str = None, top_k: int = 4) -> str:
    if not _KB_AVAILABLE:
        return ""
    try:
        return _kb.search(query, top_k=top_k,
                          phase_filter=phase_filter or phase,
                          outcome_filter=outcome_filter or outcome,
                          chunk_type_filter=chunk_type_filter)
    except Exception:
        return ""


def _kb_commands(query: str, top_k: int = 4) -> str:
    if not _KB_AVAILABLE:
        return ""
    try:
        commands = _kb.search_commands(query, top_k=top_k)
        if not commands:
            return ""
        lines = ["=== RELEVANT COMMANDS FROM KNOWLEDGE BASE ==="]
        for i, cmd in enumerate(commands, 1):
            lines.append(f"[Example {i}]\n{cmd.strip()}")
        lines += ["=== END COMMANDS ===", "Adapt the above commands to your current target."]
        return "\n\n".join(lines)
    except Exception:
        return ""


def _kb_procedures(query: str, top_k: int = 3) -> str:
    if not _KB_AVAILABLE:
        return ""
    try:
        procs = _kb.search_procedures(query, top_k=top_k)
        if not procs:
            return ""
        lines = ["=== ATTACK PROCEDURES FROM KNOWLEDGE BASE ==="]
        for i, p in enumerate(procs, 1):
            lines.append(f"[Procedure {i}]\n{p.strip()}")
        lines.append("=== END PROCEDURES ===")
        return "\n\n".join(lines)
    except Exception:
        return ""


# ─── Configuration ────────────────────────────────────────────
MCP_URL    = os.environ.get("MCP_URL",      "http://localhost:3000")
OLLAMA_URL = os.environ.get("OLLAMA_URL",   "http://192.168.0.101:11434")
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "deepseek-v3.1:671b-cloud")

LLM_CHECK_TIMEOUT  = 10   # Seconds to wait for Ollama health check
LLM_THINK_TIMEOUT  = 600  # Per-chunk read timeout when streaming (tokens arrive continuously)
_LLM_MAX_RETRIES   = 2    # Retry attempts before giving up on a single think() call

# B1 — circuit breaker for Ollama HTTP 500 storms.
# When Ollama is hammered or the model is overloaded it returns intermittent
# 500s.  Without backoff the platform retries in tight loops, wasting time
# and producing 0-tool-call sessions.  We track consecutive 5xx responses
# at module scope (shared across all BaseAgent instances) so the breaker
# is global to the engagement.
class _LLMCircuitState:
    consecutive_5xx:  int   = 0       # current run of 5xx responses
    open_until_ts:    float = 0.0     # epoch seconds — refuse calls before this
    last_500_at:      float = 0.0     # for stats / dashboards

# Tunables — relatively conservative defaults that keep the platform alive
# during transient Ollama hiccups without thrashing the server.
_LLM_5XX_BACKOFF_BASE     = 5.0       # base sleep after the first 5xx
_LLM_5XX_BACKOFF_FACTOR   = 2.0       # exponential multiplier per retry
_LLM_5XX_BACKOFF_MAX      = 60.0      # cap on per-attempt sleep
_LLM_CIRCUIT_TRIP_AT      = 6         # consecutive 5xx → open the breaker
_LLM_CIRCUIT_OPEN_FOR     = 90.0      # seconds the breaker stays open

# ─── Type aliases ────────────────────────────────────────────
BroadcastFn = Callable[[WebSocketMessage], Awaitable[None]]


# ═══════════════════════════════════════════════════════════════
#  INSTRUCTION SET — structured commands master → slave
# ═══════════════════════════════════════════════════════════════

class Instruction:
    """
    Typed instruction from MasterAgent to a slave agent.
    All slave agent actions must originate from an Instruction.
    """
    def __init__(
        self,
        tool:       str,
        args:       str,
        target:     str,
        reasoning:  str,
        phase:      AttackPhase,
        timeout:    int  = 300,
        priority:   int  = 5,       # 1 (highest) to 10 (lowest)
        depends_on: List[str] = None  # instruction IDs this depends on
    ):
        self.id         = f"instr_{datetime.utcnow().strftime('%H%M%S%f')}"
        self.tool       = tool
        self.args       = args
        self.target     = target
        self.reasoning  = reasoning
        self.phase      = phase
        self.timeout    = timeout
        self.priority   = priority
        self.depends_on = depends_on or []
        self.result     = None
        self.status     = "pending"


# ═══════════════════════════════════════════════════════════════
#  AGENT BUS — in-process message passing
# ═══════════════════════════════════════════════════════════════

class AgentBus:
    """Singleton message bus for inter-agent communication."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._handlers: Dict[str, List[Callable]] = {}
            cls._instance._master_queue: asyncio.Queue = asyncio.Queue()
        return cls._instance

    def register(self, agent_name: str, handler: Callable):
        self._handlers.setdefault(agent_name, []).append(handler)

    async def send(self, to: str, message: Dict):
        for h in self._handlers.get(to, []):
            asyncio.create_task(h(message))

    async def send_to_master(self, message: Dict):
        await self._master_queue.put(message)

    async def receive_from_agents(self, timeout: float = 1.0) -> Optional[Dict]:
        try:
            return await asyncio.wait_for(self._master_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None


agent_bus = AgentBus()

# ── Global agent registry — mirrors base_subagent._SUBAGENT_REGISTRY ──────────
# Allows agent_server tool_extend / tool_stop WS handlers to reach BaseAgent
# instances by their agent name string (e.g. "recon", "web", "vuln").
_AGENT_REGISTRY: Dict[str, "BaseAgent"] = {}


def get_agent(name: str) -> "Optional[BaseAgent]":
    """Return the live BaseAgent instance registered under *name*, or None."""
    return _AGENT_REGISTRY.get(name)


# ── Neo4j relationship type helper ────────────────────────────────────────────

def _label_to_rel_type(label: str) -> str:
    """Convert a human-readable edge label to a Neo4j relationship type."""
    import re as _re
    low = (label or "").lower()
    if any(k in low for k in ("vuln", "vulnerable", "exploit")):
        return "VULNERABLE_TO"
    if any(k in low for k in ("cve", "references", "ref")):
        return "REFERENCES"
    if any(k in low for k in ("leads", "enable", "allow", "grant")):
        return "LEADS_TO"
    if any(k in low for k in ("credential", "password", "hash")):
        return "HAS_CREDENTIAL"
    if any(k in low for k in ("compromis", "pwned", "breach")):
        return "COMPROMISED_VIA"
    if any(k in low for k in ("escalat", "privesc")):
        return "ESCALATES_TO"
    if any(k in low for k in ("pivot", "lateral")):
        return "PIVOTS_TO"
    if any(k in low for k in ("exposes", "open port", "port")):
        return "EXPOSES"
    if any(k in low for k in ("runs", "serves", "hosts")):
        return "RUNS"
    if any(k in low for k in ("finding", "has", "affect")):
        return "AFFECTS"
    # fallback: UPPER_SNAKE from label
    return _re.sub(r"[^a-z0-9]+", "_", low).upper().strip("_") or "RELATED_TO"


# ═══════════════════════════════════════════════════════════════
#  BASE AGENT
# ═══════════════════════════════════════════════════════════════

class BaseAgent(ABC):
    """
    Abstract base for all pentest agents.

    Architecture:
    - MasterAgent: talks to LLM, plans, issues Instructions to slaves
    - Slave agents: execute Instructions (run tools), report results
    - All agents: store to DB, emit WebSocket events, update attack graph

    Slave agents must NOT call think() or think_json() directly.
    They receive Instruction objects and call execute_instruction().
    """

    def __init__(self, name: AgentName, broadcast: Optional[BroadcastFn] = None):
        self.name             = name
        self.status           = AgentStatus.IDLE
        self.phase            = AttackPhase.RECON
        self.broadcast        = broadcast
        self._stop_requested  = False
        self._session_id: Optional[str] = None
        self._llm_available   = None   # None = unchecked, True/False = checked
        # Tool timeout watchdog state (mirrors base_subagent pattern)
        self._tool_run_start:    float = 0.0
        self._tool_deadline_sec: float = 600.0   # default 10 minutes per tool
        self._current_tool_name: str   = ""
        # Parallel-safe: track ALL active procs/tasks so kill_current_tool()
        # can terminate every tool running concurrently in asyncio.gather().
        self._active_procs: set       = set()   # asyncio subprocess handles
        self._active_tool_tasks: set  = set()   # asyncio.Tasks for MCP streams
        self._kill_current_tool_flag: bool = False  # one-shot: kill all running tools

        agent_bus.register(str(name), self._handle_bus_message)
        # Register in global registry so agent_server can reach us by name
        _AGENT_REGISTRY[str(name)] = self

    # ─── Abstract ─────────────────────────────────────────────

    @abstractmethod
    async def run(self, session_id: str, target: str, **kwargs) -> Dict:
        ...

    # ─── LLM Gate ─────────────────────────────────────────────

    async def check_llm_available(self) -> bool:
        """
        Test if Ollama is reachable AND the configured model exists.
        Result is cached for the session. Emits clear status to frontend.
        MASTER AGENT must call this before any planning.
        If this returns False, testing should NOT proceed.
        """
        try:
            async with httpx.AsyncClient(timeout=LLM_CHECK_TIMEOUT) as client:
                resp = await client.get(f"{OLLAMA_URL}/api/tags")
                if resp.status_code == 200:
                    # Also verify the specific model is present so we get a
                    # clear "model not found" error rather than a cryptic
                    # HTTPStatusError on every think() call.
                    try:
                        body = resp.json()
                        available = [m.get("name", "") for m in body.get("models", [])]
                        model_base = MODEL_NAME.split(":")[0]
                        model_found = (
                            MODEL_NAME in available or
                            any(m == MODEL_NAME or m.split(":")[0] == model_base
                                for m in available)
                        )
                    except Exception:
                        model_found = True   # can't parse — assume ok, fail later if wrong

                    if not model_found:
                        self._llm_available = False
                        avail_str = ", ".join(available[:10]) or "(none pulled)"
                        msg = (
                            f"Model '{MODEL_NAME}' not found on Ollama at {OLLAMA_URL}. "
                            f"Available: {avail_str}. "
                            f"Run: ollama pull {MODEL_NAME}"
                        )
                        await self._emit("llm_status", {
                            "available":       False,
                            "url":             OLLAMA_URL,
                            "model":           MODEL_NAME,
                            "available_models": available,
                            "message":         msg,
                            "error":           "model_not_found",
                        })
                        await self.set_status(AgentStatus.ERROR, msg)
                        return False

                    self._llm_available = True
                    await self._emit("llm_status", {
                        "available": True,
                        "url":       OLLAMA_URL,
                        "model":     MODEL_NAME,
                        "message":   f"LLM online — {MODEL_NAME} at {OLLAMA_URL}"
                    })
                    return True
        except Exception:
            pass

        self._llm_available = False
        msg = f"LLM OFFLINE — Cannot reach Ollama at {OLLAMA_URL}. Pentest HALTED. Start Ollama and retry."
        await self._emit("llm_status", {
            "available": False,
            "url":       OLLAMA_URL,
            "model":     MODEL_NAME,
            "message":   msg,
            "error":     "connection_refused",
        })
        await self.set_status(AgentStatus.ERROR, msg)
        return False

    async def _assert_llm(self):
        """Raise if LLM is not available. Call before any think() in master."""
        if self._llm_available is None:
            await self.check_llm_available()
        if not self._llm_available:
            raise RuntimeError(
                f"LLM unavailable at {OLLAMA_URL}. Testing cannot proceed without LLM guidance."
            )

    # ─── Status ───────────────────────────────────────────────

    async def set_status(self, status: AgentStatus, message: str = "", tool: Optional[str] = None):
        self.status = status
        await self._log_action(
            action    = f"status:{status}",
            reasoning = message or f"Status → {status}",
            status    = status,
            tool      = tool
        )
        await self._emit("agent_status", {
            "agent":   str(self.name),
            "status":  str(status),
            "phase":   str(self.phase),
            "message": message,
            "tool":    tool,
            "ts":      datetime.utcnow().isoformat()
        })

    def request_stop(self):
        self._stop_requested = True
        # Kill ALL active subprocesses via process-group kill (parallel-safe)
        for proc in list(self._active_procs):
            _kill_proc_tree(proc)
        # Cancel ALL active MCP streaming tasks
        for task in list(self._active_tool_tasks):
            if not task.done():
                task.cancel()

    def kill_current_tool(self) -> None:
        """Kill ALL currently running tools without stopping the agent.

        Parallel-safe: when execute_tasks() runs 7 tools via asyncio.gather,
        this kills every active subprocess and cancels every MCP streaming
        task so readline/aiter_lines unblock immediately and gather returns.
        Uses killpg() so child processes (e.g. nikto spawned by bash) are
        killed along with the parent shell rather than orphaned.
        The one-shot flag is cleared at the start of the next run_tool() call.
        """
        self._kill_current_tool_flag = True
        # Kill ALL local subprocesses via process-group kill
        for proc in list(self._active_procs):
            _kill_proc_tree(proc)
        # Cancel ALL MCP streaming tasks
        for task in list(self._active_tool_tasks):
            if not task.done():
                task.cancel()

    def extend_tool(self, extra_sec: float) -> None:
        """Extend the running tool's deadline by *extra_sec* seconds."""
        self._tool_deadline_sec += extra_sec

    async def _tool_watchdog(self, tool_name: str) -> None:
        """Emit tool_timeout_warning when tool exceeds its 10-min deadline.

        Mirrors base_subagent._tool_watchdog exactly — fires every 30 s after
        the deadline until the operator extends or the tool finishes.
        """
        try:
            # Phase 1: sleep until first deadline
            while not self._stop_requested and not self._kill_current_tool_flag:
                elapsed   = time.monotonic() - self._tool_run_start
                remaining = self._tool_deadline_sec - elapsed
                if remaining <= 0:
                    break
                await asyncio.sleep(min(remaining, 10.0))

            # Phase 2: deadline exceeded — emit warning every 30 s
            while not self._stop_requested and not self._kill_current_tool_flag:
                elapsed   = time.monotonic() - self._tool_run_start
                remaining = self._tool_deadline_sec - elapsed

                if remaining > 0:
                    # Operator extended — wait for new deadline
                    await asyncio.sleep(min(remaining, 10.0))
                    continue

                await self._emit("tool_timeout_warning", {
                    "tool":         tool_name,
                    "subagent":     str(self.name),
                    "elapsed_sec":  round(elapsed),
                    "deadline_sec": round(self._tool_deadline_sec),
                })
                # Wait 30 s before next warning, checking flags every second
                # so a cancel clears the watchdog promptly rather than after 30 s.
                for _ in range(30):
                    if self._stop_requested or self._kill_current_tool_flag:
                        return
                    await asyncio.sleep(1.0)

        except asyncio.CancelledError:
            pass


    def reset_stop(self):
        self._stop_requested = False

    # ─── Subagent-compatible broadcast adapter ────────────────

    def _make_sa_broadcast(self):
        """Return a broadcast callable compatible with BaseSubagent._emit().

        BaseSubagent._emit() passes a raw ``dict`` to the broadcast callback
        (keys: type, session_id, agent, subagent, timestamp, **payload).
        BaseAgent.broadcast expects a ``WebSocketMessage`` object.

        This adapter converts the raw dict to a WebSocketMessage so subagents
        launched from within agent phase methods work correctly — their events
        appear in the WS stream and the SubagentConsolePage.
        """
        parent = self.broadcast

        async def _sa_bcast(event):
            if not parent:
                return
            if isinstance(event, WebSocketMessage):
                await parent(event)
                return
            if not isinstance(event, dict):
                return
            # Flat dict from BaseSubagent — promote subagent-specific fields into
            # the WebSocketMessage.data envelope so the frontend can read them via
            # msg.data.subagent, msg.data.target, etc.
            inner = {k: v for k, v in event.items()
                     if k not in ("type", "session_id", "agent", "phase", "timestamp")}
            try:
                msg = WebSocketMessage(
                    type=event.get("type", "subagent_event"),
                    session_id=event.get("session_id", self._session_id or ""),
                    agent=event.get("agent", str(self.name)),
                    phase=event.get("phase", str(self.phase)),
                    data=inner,
                )
                await parent(msg)
            except Exception as exc:
                import logging as _log
                _log.getLogger(__name__).warning("_sa_bcast convert error: %s", exc)

        return _sa_bcast

    # ─── Reasoning Broadcast ──────────────────────────────────

    async def emit_reasoning(
        self,
        step:      str,
        reasoning: str,
        decision:  str,
        next_action: str = "",
        data:      Dict = None
    ):
        """
        Broadcast a visible reasoning step to the UI.
        Every significant decision must call this so users understand
        exactly what the agent is thinking and why.
        """
        payload = {
            "agent":       str(self.name),
            "phase":       str(self.phase),
            "step":        step,
            "reasoning":   reasoning,
            "decision":    decision,
            "next_action": next_action,
            "data":        data or {},
            "ts":          datetime.utcnow().isoformat()
        }
        await self._emit("agent_reasoning", payload)
        # Also persist to DB
        if self._session_id:
            await db.log_agent_action(
                session_id  = self._session_id,
                agent       = str(self.name),
                phase       = str(self.phase),
                action      = f"reasoning:{step}",
                reasoning   = reasoning,
                new_status  = self.status,
                prev_status = None,
                message     = f"Decision: {decision} | Next: {next_action}"
            )

    # ─── RAG Knowledge Base queries (available to all agents) ────────────

    async def _kb(self, query: str, phase: str = None, top_k: int = 4) -> str:
        """Query KB for context; emits rag_query WS event."""
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _kb_context(query, phase=phase or str(self.phase), top_k=top_k)
        )
        found = bool(result and result.strip())
        await self._emit("rag_query", {
            "agent": str(self.name), "query": query,
            "result": result[:500] if result else "", "found": found,
            "phase": str(self.phase), "ts": datetime.utcnow().isoformat()
        })
        return result

    async def _kbc(self, query: str, top_k: int = 4) -> str:
        """Query KB for command examples."""
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _kb_commands(query, top_k=top_k)
        )
        found = bool(result and result.strip())
        await self._emit("rag_query", {
            "agent": str(self.name), "query": f"[commands] {query}",
            "result": result[:500] if result else "", "found": found,
            "phase": str(self.phase), "ts": datetime.utcnow().isoformat()
        })
        return result

    async def _kbp(self, query: str, top_k: int = 3) -> str:
        """Query KB for step-by-step procedures."""
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _kb_procedures(query, top_k=top_k)
        )
        found = bool(result and result.strip())
        await self._emit("rag_query", {
            "agent": str(self.name), "query": f"[procedures] {query}",
            "result": result[:500] if result else "", "found": found,
            "phase": str(self.phase), "ts": datetime.utcnow().isoformat()
        })
        return result

    # ─── Master-Directed Execution Loop ──────────────────────

    async def execute_tasks(
        self,
        target:       str,
        tasks:        list,   # from Master: [{"tool":..,"args":..,"purpose":..,"timeout":..,"can_parallel":bool}]
        phase_label:  str,
        context:      dict,   # intel snapshot passed by Master
    ) -> dict:
        """
        Execute a list of tasks given by Master, in parallel where safe.

        Agents do NOT decide what to run. Master provides every task explicitly.
        After executing each tool, the agent uses LLM ONLY to:
          - Extract structured findings from the raw output
          - Identify interesting results worth flagging as findings
        The agent does NOT decide what to run next. That is always Master's job.

        Returns accumulated findings dict back to Master.
        """
        import re as _re

        accumulated = {
            "open_ports": [], "services": {}, "cves": [], "web_paths": [],
            "vulnerabilities": [], "technologies": [], "credentials": [],
            "users": [], "shares": [], "interesting_files": [], "login_pages": [],
            "service_versions": {}, "raw_outputs": {}, "enum_findings": [],
            "stdout": "", "findings": []
        }

        if not tasks:
            return accumulated

        # Signal RUNNING immediately so UI shows agent active
        tool_names = ", ".join(t.get("tool","?") for t in tasks[:3])
        await self.set_status(
            AgentStatus.RUNNING,
            f"{phase_label}: running {len(tasks)} task(s) — {tool_names}{'...' if len(tasks) > 3 else ''}"
        )

        # Split tasks by parallelism flag
        parallel_tasks   = [t for t in tasks if t.get("can_parallel", True)]
        sequential_tasks = [t for t in tasks if not t.get("can_parallel", True)]

        async def _run_task(task: dict) -> tuple:
            if self._stop_requested:
                return (task, None)
            tool_name = (task.get("tool") or "").strip()
            tool_args = task.get("args", "")
            purpose   = task.get("purpose", "")
            timeout   = int(task.get("timeout") or 120)
            if not tool_name:
                return (task, None)

            # Runtime OS guard: skip Linux-only tools when target is confirmed Windows.
            # Checked at execution time (not build time) so the initial nmap scan's
            # OS detection has a chance to update context["os_guess"] first.
            if task.get("linux_only") and "windows" in (context.get("os_guess", "")).lower():
                skipped = {"stdout": f"[SKIPPED] {tool_name} is Linux-only — target is Windows",
                           "stderr": "", "exit_code": 0, "output_id": None}
                return (task, skipped)

            # ── Shared cross-agent tool cache ──────────────────────────────
            # MasterAgent injects self._instruction_cache into intel["_tool_cache"]
            # so every slave agent can check it before re-running a tool.
            # This prevents gobuster/nmap/nikto from running twice when both
            # recon and vuln agents plan the same command.
            _tool_cache = context.get("_tool_cache")
            if _tool_cache is not None:
                _cache_key = f"{tool_name}:{tool_args}"
                if _cache_key in _tool_cache:
                    cached = _tool_cache[_cache_key]
                    await self.emit_reasoning(
                        step       = f"{phase_label}_cache_hit",
                        reasoning  = f"{tool_name} with identical args already ran — reusing cached result",
                        decision   = "Skip duplicate execution, return cached output",
                        next_action= "Next task",
                        data       = {"tool": tool_name, "cached": True}
                    )
                    return (task, cached)

            # Update status for each tool so UI shows what's running
            await self.set_status(AgentStatus.RUNNING, f"▶ {tool_name}", tool=tool_name)
            await self.emit_reasoning(
                step       = f"{phase_label}_run",
                reasoning  = purpose,
                decision   = f"Executing {tool_name} as directed by Master",
                next_action= f"{tool_name} {str(tool_args)[:100]}",
                data       = {"tool": tool_name}
            )
            instr = Instruction(
                tool      = tool_name,
                args      = tool_args,
                target    = target,
                reasoning = purpose,
                phase     = self.phase,
                timeout   = timeout
            )
            result = await self.execute_instruction(instr)

            # Store result in shared cross-agent cache so other agents skip this tool
            if _tool_cache is not None and result is not None:
                _tool_cache[f"{tool_name}:{tool_args}"] = result

            # ── Fire-and-forget semantic triple extraction to Neo4j ────────
            if _KG_AVAILABLE and result and isinstance(result, str) and len(result) > 50:
                try:
                    _target = context.get("target") or getattr(self, "_target", "unknown")
                    _llm_url   = getattr(self, "_llm_url",   OLLAMA_URL)
                    _llm_model = getattr(self, "_llm_model", MODEL_NAME)
                    asyncio.create_task(_kg_infer(
                        session_id = self._session_id,
                        tool_name  = tool_name,
                        target     = str(_target),
                        raw_output = result,
                        llm_url    = _llm_url,
                        llm_model  = _llm_model,
                    ))
                except Exception:
                    pass  # never block on inference failure

            return (task, result)

        # Run parallel batch
        if parallel_tasks:
            par_results = await asyncio.gather(
                *[_run_task(t) for t in parallel_tasks],
                return_exceptions=True
            )
        else:
            par_results = []

        # Run sequential batch
        seq_results = []
        for t in sequential_tasks:
            pair = await _run_task(t)
            seq_results.append(pair)

        # Collect valid results
        all_pairs = []
        for item in list(par_results) + seq_results:
            if isinstance(item, Exception):
                continue
            if isinstance(item, tuple) and len(item) == 2:
                task, result = item
                if result is not None and isinstance(result, dict):
                    all_pairs.append((task, result))

        # ── Process each result ─────────────────────────────────
        for task, result in all_pairs:
            stdout = result.get("stdout", "") or ""
            tool   = task.get("tool", "unknown")
            exit_c = result.get("exit_code", -1)

            accumulated["stdout"]           += f"\n[{tool}]\n{stdout}"
            accumulated["raw_outputs"][tool]  = stdout[-2000:]

            # Regex extractions — fast, no LLM needed for structural data
            for port in self._extract_ports(stdout):
                if port not in accumulated["open_ports"]:
                    accumulated["open_ports"].append(port)
            for cve in self._extract_cves(stdout):
                if cve not in accumulated["cves"]:
                    accumulated["cves"].append(cve)
            for path in self._extract_web_paths(stdout):
                if path not in accumulated["web_paths"]:
                    accumulated["web_paths"].append(path)
            for cred in self._extract_credentials(stdout):
                accumulated["credentials"].append(cred)
            accumulated["services"].update(self._extract_services(stdout))

            for m in _re.finditer(r"(\d+)/(?:tcp|udp)\s+open\s+\S+\s+(.{5,80})", stdout):
                try:
                    accumulated["service_versions"][int(m.group(1))] = m.group(2).strip()
                except ValueError:
                    pass

            for m in _re.finditer(
                r"(/[^\s]*(?:login|signin|auth|admin|wp-login|console|dashboard)[^\s]*)",
                stdout, _re.IGNORECASE
            ):
                p = m.group(1).strip()
                if p not in accumulated["login_pages"]:
                    accumulated["login_pages"].append(p)

            for m in _re.finditer(
                r"(?:user(?:name)?[:\s]+|account[:\s]+)([a-zA-Z0-9_\-\.]{2,32})",
                stdout, _re.IGNORECASE
            ):
                u = m.group(1)
                if u not in accumulated["users"]:
                    accumulated["users"].append(u)

            for m in _re.finditer(
                r"(?:Disk|IPC|SYSVOL|NETLOGON|[A-Za-z$][A-Za-z0-9_$\-]{0,30})\s+(?:READ|WRITE|OK)",
                stdout, _re.IGNORECASE
            ):
                share = m.group(0).split()[0]
                if share not in accumulated["shares"]:
                    accumulated["shares"].append(share)

            for m in _re.finditer(
                r"(/[^\s]*(?:config|passwd|shadow|\.env|backup|\.bak|\.zip|id_rsa|\.xml|\.conf)[^\s]*)",
                stdout, _re.IGNORECASE
            ):
                fp = m.group(1)
                if fp not in accumulated["interesting_files"]:
                    accumulated["interesting_files"].append(fp)

            # ── LLM: extract structured findings from THIS tool output ──
            # Scope is narrow: parse what this specific tool found.
            # The agent does NOT plan next steps — only extracts data.
            if exit_c == 0 and len(stdout.strip()) > 50:
                try:
                    parse_prompt = f"""You ran {tool} on {target}. Extract structured findings from the output below.
Only extract what is EXPLICITLY present. Do not infer or invent anything.

Tool purpose: {task.get("purpose", "")}
Output:
{stdout[-2500:]}

Return JSON:
{{
  "interesting": true or false,
  "summary": "one sentence: what was found (specific — name versions, paths, users)",
  "new_users": ["usernames found in output"],
  "new_shares": ["shares or accessible directories"],
  "new_paths": ["web paths or files discovered"],
  "new_cves": ["CVE-IDs mentioned"],
  "new_versions": {{"port": "service version string"}},
  "credentials": [{{"user": "x", "pass": "y"}}],
  "finding_severity": "critical|high|medium|low|info",
  "finding_title": "short title if noteworthy, else null"
}}"""
                    parsed = await self.think_json(parse_prompt)
                    if isinstance(parsed, dict) and not parsed.get("parse_error"):
                        for u in (parsed.get("new_users") or []):
                            if u and u not in accumulated["users"]:
                                accumulated["users"].append(u)
                        for s in (parsed.get("new_shares") or []):
                            if s and s not in accumulated["shares"]:
                                accumulated["shares"].append(s)
                        for p in (parsed.get("new_paths") or []):
                            if p and p not in accumulated["web_paths"]:
                                accumulated["web_paths"].append(p)
                        for c in (parsed.get("new_cves") or []):
                            if c and c not in accumulated["cves"]:
                                accumulated["cves"].append(c)
                        for cred in (parsed.get("credentials") or []):
                            if isinstance(cred, dict):
                                accumulated["credentials"].append(cred)
                        for ps, ver in (parsed.get("new_versions") or {}).items():
                            try:
                                accumulated["service_versions"][int(ps)] = str(ver)
                            except (ValueError, TypeError):
                                pass
                        if parsed.get("summary"):
                            accumulated["enum_findings"].append(f"[{tool}] {parsed['summary']}")
                        # Store as DB finding only when genuinely notable
                        sev_str = (parsed.get("finding_severity") or "info").lower()
                        if parsed.get("finding_title") and sev_str not in ("info","null",""):
                            sev_map = {
                                "critical": FindingSeverity.CRITICAL,
                                "high":     FindingSeverity.HIGH,
                                "medium":   FindingSeverity.MEDIUM,
                                "low":      FindingSeverity.LOW,
                            }
                            finding = await self.store_finding(
                                severity   = sev_map.get(sev_str, FindingSeverity.LOW),
                                title      = parsed["finding_title"],
                                description= parsed.get("summary",""),
                                host       = target,
                                tool_used  = tool,
                                raw_output = stdout[:2000]
                            )
                            accumulated["findings"].append(finding)
                        await self.emit_reasoning(
                            step       = f"{phase_label}_result",
                            reasoning  = parsed.get("summary", f"{tool} complete"),
                            decision   = f"Notable: {parsed.get('interesting', False)} | {parsed.get('finding_title','')}",
                            next_action= "Returning results to Master",
                            data       = {"tool": tool}
                        )
                except Exception:
                    pass  # parse failure never breaks execution

        # ── All done — set IDLE so Master knows this agent finished ──
        await self.set_status(
            AgentStatus.IDLE,
            f"{phase_label} complete — {len(all_pairs)} task(s) finished"
        )
        return accumulated

    # ─── Instruction Execution (slave agents) ─────────────────

    async def execute_instruction(self, instruction: Instruction) -> Dict:
        """
        Execute a typed instruction from MasterAgent.
        This is how slave agents receive work — they do NOT call think().
        """
        await self.emit_reasoning(
            step       = "execute_instruction",
            reasoning  = instruction.reasoning,
            decision   = f"Running {instruction.tool} as instructed by Master",
            next_action= f"{instruction.tool} {instruction.args}",
            data       = {"tool": instruction.tool, "args": instruction.args}
        )
        instruction.status = "running"
        result = await self.run_tool(
            tool_name = instruction.tool,
            args      = instruction.args,
            target    = instruction.target,
            phase     = instruction.phase,
            timeout   = instruction.timeout
        )
        instruction.result = result
        instruction.status = "done" if result["exit_code"] == 0 else "failed"

        # Report back to master via bus
        await agent_bus.send_to_master({
            "type":          "instruction_result",
            "instruction_id": instruction.id,
            "agent":         str(self.name),
            "tool":          instruction.tool,
            "exit_code":     result["exit_code"],
            "stdout_len":    len(result.get("stdout", "")),
            "result":        result
        })
        return result

    # ─── Tool Execution ───────────────────────────────────────

    async def run_tool(
        self,
        tool_name: str,
        args:      str,
        target:    Optional[str] = None,
        phase:     Optional[AttackPhase] = None,
        timeout:   int = 300,
        thread_id: Optional[str] = None
    ) -> Dict:
        """
        Execute a Kali tool via MCP server.
        Streams output line by line to frontend, stores full output in DB.
        """
        if self._stop_requested:
            return {"stdout": "", "stderr": "Stop requested", "exit_code": -1, "output_id": None}

        phase_to_use = phase or self.phase
        full_cmd     = f"{tool_name} {args}".strip()

        await self.set_status(AgentStatus.RUNNING, f"→ {full_cmd}", tool=tool_name)

        # Create DB record immediately (so UI can see pending tool)
        output_id = await db.store_tool_output(
            session_id = self._session_id,
            agent      = str(self.name),
            phase      = str(phase_to_use),
            tool_name  = tool_name,
            command    = full_cmd,
            target     = target,
            thread_id  = thread_id
        )

        await self._emit("tool_start", {
            "agent":     str(self.name),
            "tool":      tool_name,
            "command":   full_cmd,
            "target":    target,
            "output_id": str(output_id) if output_id else None,
            "ts":        datetime.utcnow().isoformat()
        })

        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        exit_code = 0

        # ── Watchdog setup (10-min deadline, operator can extend via WS) ────
        self._kill_current_tool_flag = False   # clear one-shot kill from previous tool
        self._current_tool_name = tool_name
        self._tool_run_start    = time.monotonic()
        self._tool_deadline_sec = 600.0   # reset fresh for each tool call
        watchdog = asyncio.create_task(self._tool_watchdog(tool_name))

        # Improvement #6 — information-entropy abandonment.
        from agents.reasoning.entropy_sampler import EntropySampler
        entropy = EntropySampler()
        entropy_killed = {"v": False}   # closure-mutable flag

        # Tools that must run locally (not via MCP) because MCP does not expose
        # a generic shell executor.  The full_cmd is already assembled above.
        _LOCAL_TOOLS = {"bash", "sh", "zsh", "cmd", "powershell", "python", "python3", "perl", "ruby"}

        async def _emit_line(line: str, ltype: str = "stdout"):
            lst = stdout_lines if ltype == "stdout" else stderr_lines
            lst.append(line)
            await self._emit("tool_output", {
                "agent":     str(self.name),
                "tool":      tool_name,
                "output_id": str(output_id) if output_id else None,
                "line":      line,
                "type":      ltype,
            })
            # Improvement #6 — entropy-based abandonment
            entropy.feed(line)
            if not entropy_killed["v"]:
                reason = entropy.should_abandon(
                    time.monotonic() - self._tool_run_start
                )
                if reason:
                    entropy_killed["v"] = True
                    await self._emit("tool_abandoned_low_entropy", {
                        "agent":        str(self.name),
                        "tool":         tool_name,
                        "elapsed_sec":  round(time.monotonic() - self._tool_run_start),
                        "reason":       reason,
                        "stats":        entropy.stats(),
                    })
                    logger.info(
                        "[%s] tool '%s' abandoned: %s",
                        self.name, tool_name, reason,
                    )
                    try:
                        self.kill_current_tool()
                    except Exception:
                        pass

        async def _run_local() -> int:
            """Run full_cmd in a local subprocess and stream output."""
            proc = await asyncio.create_subprocess_shell(
                full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024,  # 1 MB read buffer
                # New process group so killpg() kills bash AND all its children
                # (e.g. nikto, sqlmap, any pipeline element spawned inside bash).
                start_new_session=True,
            )
            self._active_procs.add(proc)
            try:
                async def _drain(stream, ltype):
                    while True:
                        line_b = await stream.readline()
                        if not line_b:
                            break
                        decoded = line_b.decode(errors="replace").rstrip()
                        if decoded:
                            await _emit_line(decoded, ltype)

                # Wrap the drain gather in a Task and register it in _active_tool_tasks.
                # This is critical: kill_current_tool() cancels _active_tool_tasks, which
                # immediately unblocks the drain even if readline() hasn't returned EOF yet.
                # Without this, killing the process (proc.kill()) may not release the pipe
                # quickly (child procs holding it open, Windows buffering, etc.) and the
                # scan hangs waiting for drain to finish.
                # asyncio.gather() returns a Future, not a coroutine.
                # create_task() only accepts coroutines — wrap in an async def.
                async def _drain_both():
                    await asyncio.gather(
                        _drain(proc.stdout, "stdout"),
                        _drain(proc.stderr, "stderr"),
                        return_exceptions=True,
                    )
                drain_task = asyncio.create_task(_drain_both())
                self._active_tool_tasks.add(drain_task)
                try:
                    await drain_task
                except asyncio.CancelledError:
                    # kill_current_tool() cancelled us — note it and exit cleanly
                    pass
                finally:
                    self._active_tool_tasks.discard(drain_task)

                # Process was killed by kill_current_tool() → flag is set
                if self._kill_current_tool_flag:
                    await _emit_line(f"[CANCELLED] Tool '{tool_name}' stopped by operator", "stderr")
                    # Kill process group to ensure all children die (not just bash)
                    _kill_proc_tree(proc)
                    return -2
                await proc.wait()
                return proc.returncode or 0
            finally:
                self._active_procs.discard(proc)

        async def _run_via_mcp() -> int:
            """Run tool via MCP SSE endpoint and stream output. Returns exit_code.

            Bug-fix (post-mortem of v2 crash 2026-04-19): the orchestrator was
            posting to ``/tools/call`` with a flat ``{tool,arguments}`` body,
            which the live MCP server rejects with HTTP 400.  The actual
            protocol — confirmed by the working ``base_subagent`` calls in
            the same scan — is JSON-RPC over POST ``/`` with method
            ``tools/call`` and ``params={name, arguments}``.  Event types in
            the SSE stream carry their payload in a ``data`` field (not
            ``output``/``line``/``message``); error events with "Unknown
            tool" mean the registry doesn't have it, so callers should fall
            back to local execution by raising HTTPStatusError-equivalent.
            """
            mcp_endpoint = f"{MCP_URL}/"
            payload = {
                "method": "tools/call",
                "params": {
                    "name":      tool_name,
                    "arguments": {"target": target or "", "options": args},
                },
            }
            not_in_registry = False
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
                async with client.stream(
                    "POST", mcp_endpoint, json=payload,
                    headers={"Accept": "text/event-stream"},
                ) as resp:
                    resp.raise_for_status()   # raises HTTPStatusError on 4xx/5xx
                    async for raw in resp.aiter_lines():
                        if self._stop_requested or self._kill_current_tool_flag:
                            break
                        if not raw:
                            continue
                        content = raw[5:].strip() if raw.startswith("data:") else raw.strip()
                        if not content:
                            continue
                        try:
                            event = json.loads(content)
                            etype = event.get("type", "")
                            # Subagent dialect uses "data"; legacy fallbacks
                            # accepted for forward compatibility.
                            chunk = (event.get("data")    or event.get("message") or
                                     event.get("output")  or event.get("line")    or "")
                            if etype == "stdout" or etype == "":
                                if chunk:
                                    await _emit_line(chunk, "stdout")
                            elif etype == "stderr":
                                if chunk:
                                    await _emit_line(f"[STDERR] {chunk}", "stderr")
                            elif etype == "exit":
                                return int(event.get("code", 0))
                            elif etype == "error":
                                msg = event.get("message") or event.get("data") or ""
                                if msg and "Unknown tool" in msg:
                                    not_in_registry = True
                                await _emit_line(f"[MCP ERROR] {msg or chunk}", "stderr")
                            elif etype == "info":
                                if chunk:
                                    await _emit_line(f"[INFO] {chunk}", "stdout")
                            else:
                                # Unknown event type — surface the payload as stdout.
                                if chunk:
                                    await _emit_line(chunk, "stdout")
                        except (json.JSONDecodeError, ValueError):
                            if content:
                                await _emit_line(content, "stdout")
            # Tool not in MCP registry — signal caller via a synthetic
            # 404-ish HTTPStatusError so the existing fallback branch
            # (line 1180-ish) runs the tool locally.
            if not_in_registry:
                raise httpx.HTTPStatusError(
                    f"MCP registry missing tool '{tool_name}'",
                    request  = None,    # type: ignore[arg-type]
                    response = httpx.Response(404),
                )
            return 0

        try:
            if tool_name.lower() in _LOCAL_TOOLS:
                # Generic shell commands always run locally — MCP has no bash tool
                exit_code = await _run_local()
            else:
                # Wrap MCP execution in a Task so kill_current_tool() can cancel it
                # immediately even while aiter_lines() is blocked mid-read.
                mcp_task = asyncio.create_task(_run_via_mcp())
                self._active_tool_tasks.add(mcp_task)
                try:
                    exit_code = await mcp_task
                except asyncio.CancelledError:
                    if self._kill_current_tool_flag:
                        # Tool kill — record cancellation, let scan continue
                        await _emit_line(
                            f"[CANCELLED] Tool '{tool_name}' stopped by operator", "stderr"
                        )
                        exit_code = -2
                    else:
                        raise   # Full scan cancellation — propagate upward
                except httpx.HTTPStatusError as exc:
                    # MCP returned 4xx (tool not registered, bad args, etc.)
                    # Fall back to local subprocess so the pentest continues
                    stderr_lines.append(
                        f"[MCP {exc.response.status_code}] Tool '{tool_name}' not found in MCP — "
                        f"running locally"
                    )
                    exit_code = await _run_local()
                except httpx.ConnectError:
                    stderr_lines.append(
                        f"[MCP OFFLINE] Cannot reach MCP at {MCP_URL} — running '{tool_name}' locally"
                    )
                    exit_code = await _run_local()
                finally:
                    self._active_tool_tasks.discard(mcp_task)

        except asyncio.TimeoutError:
            stderr_lines.append(f"[TIMEOUT] {tool_name} timed out after {timeout}s")
            exit_code = -1
        except Exception as e:
            stderr_lines.append(f"[AGENT ERROR] {type(e).__name__}: {str(e)}")
            exit_code = -1
        finally:
            # Always cancel the watchdog — tool has finished (or errored)
            watchdog.cancel()
            try:
                await watchdog
            except asyncio.CancelledError:
                pass

        stdout = "\n".join(stdout_lines)
        stderr = "\n".join(stderr_lines)

        # Persist full output
        await db.finalize_tool_output(output_id, stdout, stderr, exit_code)

        await self._emit("tool_done", {
            "agent":     str(self.name),
            "tool":      tool_name,
            "output_id": str(output_id) if output_id else None,
            "exit_code": exit_code,
            "lines":     len(stdout_lines),
            "ts":        datetime.utcnow().isoformat()
        })

        # ── Per-session scan log ───────────────────────────────────────
        try:
            _source = "mcp"
            if stderr and "[MCP OFFLINE]" in stderr:
                _source = "local"
            elif stderr and "not found in MCP" in stderr:
                _source = "local"
            _duration = time.monotonic() - self._tool_run_start
            _slog_tool(
                self._session_id,
                tool_name,
                args,
                duration    = _duration,
                exit_code   = exit_code,
                stdout_tail = stdout,
                stderr_tail = stderr,
                source      = _source,
                target      = target or "",
                phase       = str(phase_to_use) if phase_to_use else "",
            )
        except Exception:
            pass

        return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code, "output_id": output_id}

    # ─── LLM Reasoning (Master Agent Only) ────────────────────

    async def think(self, prompt: str, system_context: str = "", timeout: int = LLM_THINK_TIMEOUT) -> str:
        """
        Query the LLM via STREAMING so no wall-clock timeout ever fires.

        With stream=True Ollama sends one JSON line per token. httpx's per-chunk
        read timeout (default 600 s) applies to the gap between *tokens*, not the
        entire generation. A model that generates at even 0.1 tok/s will never
        trigger a timeout, so slow local models on CPU are fully supported.

        Availability rules
        ──────────────────
        • _llm_available = True   → proceed immediately
        • _llm_available = None   → first use; call check_llm_available()
        • _llm_available = False  → was offline; auto-recheck before giving up
          (Ollama may have restarted since the last failure)

        Error handling
        ──────────────
        • ConnectError  → Ollama is genuinely down; set _llm_available=False; raise
        • TimeoutError  → Ollama is slow but running; emit llm_slow warning; retry;
                          after _LLM_MAX_RETRIES return "" so caller uses defaults —
                          NEVER sets _llm_available=False (scan continues)
        • Other errors  → raise RuntimeError with context
        """
        # ── Availability gate ───────────────────────────────────
        # B1 — Circuit breaker pre-check.  When Ollama has been returning
        # 5xx storms, refuse to attempt new LLM calls until the cooldown
        # expires.  This prevents the platform from burning entire scan
        # windows hammering a dead model and lets the deterministic
        # primer chains drive progress in the meantime.
        import time as _t
        if _LLMCircuitState.open_until_ts and _t.time() < _LLMCircuitState.open_until_ts:
            remaining = _LLMCircuitState.open_until_ts - _t.time()
            await self._emit("llm_slow", {
                "agent":   str(self.name),
                "message": (
                    f"Ollama circuit breaker OPEN ({remaining:.0f}s until retry, "
                    f"after {_LLMCircuitState.consecutive_5xx} consecutive 5xx). "
                    f"Step using deterministic defaults."
                ),
                "circuit_open": True,
                "remaining_sec": int(remaining),
            })
            return ""
        # Breaker has expired — give Ollama another chance, but reset counter
        # so a single new failure doesn't immediately re-trip.
        if _LLMCircuitState.open_until_ts and _t.time() >= _LLMCircuitState.open_until_ts:
            _LLMCircuitState.open_until_ts   = 0.0
            _LLMCircuitState.consecutive_5xx = 0

        if not self._llm_available:   # covers both None and False
            await self.check_llm_available()
            if not self._llm_available:
                # LLM is offline — emit warning and return "" so the scan
                # continues with built-in fallback defaults.  We NEVER halt.
                await self._emit("llm_slow", {
                    "agent":   str(self.name),
                    "message": (
                        f"LLM unreachable at {OLLAMA_URL} — "
                        "this step will use built-in defaults. "
                        "Start Ollama to enable AI-guided planning."
                    )
                })
                return ""

        await self.set_status(AgentStatus.THINKING, "Consulting LLM...")
        await self._emit("agent_thinking", {
            "agent":  str(self.name),
            "prompt": prompt[:300],
            "ts":     datetime.utcnow().isoformat()
        })

        # Each agent type gets a domain-specific system prompt
        _agent_systems = {
            "agentname.master":   "You are the Master Penetration Testing AI. You orchestrate the engagement, plan phases, and interpret results. Follow OSCP/OSWE methodology. Be strategic and specific.",
            "agentname.recon":    "You are the Recon Specialist AI. Your job is deep reconnaissance: port scanning, service fingerprinting, enumeration, banner grabbing. You decide what to scan next based on what you find. Always go deeper.",
            "agentname.vuln":     "You are the Vulnerability Assessment AI. You identify vulnerabilities in exact service versions, run targeted NSE scripts, search ExploitDB, and assess exploitability. Be thorough and specific.",
            "agentname.web":      "You are the Web Application Testing AI. You follow OWASP methodology: directory bruteforce, injection testing, authentication bypass, file inclusion. You adapt your testing based on what each response reveals.",
            "agentname.osint":    "You are the OSINT Intelligence AI. You gather external intelligence: CVE databases, public exploits, service fingerprints. You translate discoveries into actionable exploit paths.",
            "agentname.exploit":  "You are the Exploitation AI. You select and execute the most promising exploits based on discovered vulnerabilities. You adapt when exploits fail and try alternatives. You document every attempt.",
            "agentname.privesc":  "You are the Privilege Escalation AI. Once inside, you systematically check every escalation vector: SUID, sudo, cron, capabilities, kernel exploits, path hijacking. You are thorough and persistent.",
            "agentname.shell":    "You are the Shell Management AI. You manage interactive shells, execute commands, harvest credentials and flags.",
            "agentname.payload":  "You are the Payload Generation AI. You craft payloads appropriate for the target platform and bypasses.",
        }
        agent_key = str(self.name).lower()
        system = system_context or _agent_systems.get(
            agent_key,
            f"You are a specialist penetration testing AI ({agent_key}). "
            f"Phase: {self.phase}. Target: {getattr(self, '_target', 'unknown')}. "
            f"Be specific, technical, and use OSCP/OSWE methodology."
        )

        # ── Scope-guard preamble (Improvement #16) ──────────────────────
        # Prepended to every system prompt so the LLM hard-refuses any
        # plan against out-of-scope assets.  When _scope_guard is empty
        # we still prepend a generic refusal directive.
        scope_guard_text = getattr(self, "_scope_guard", "") or ""
        if scope_guard_text and "=== SCOPE GUARD" not in system:
            system = f"{scope_guard_text}\n{system}"

        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt}
        ]

        # ── Retry loop ──────────────────────────────────────────
        for attempt in range(1, _LLM_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(
                    # connect: max time to establish TCP connection
                    # read:    max time between consecutive *tokens* (not full response)
                    #          600 s gives plenty of slack even for slow CPU inference
                    # write:   max time to send the request body
                    timeout=httpx.Timeout(connect=15, read=timeout, write=30, pool=10)
                ) as client:
                    tokens: list[str] = []
                    # stream=True: Ollama sends one JSON obj per line per token
                    async with client.stream(
                        "POST",
                        f"{OLLAMA_URL}/api/chat",
                        json={"model": MODEL_NAME, "messages": messages, "stream": True},
                    ) as resp:
                        resp.raise_for_status()
                        async for raw_line in resp.aiter_lines():
                            # Respect a scan-stop request even mid-generation
                            if self._stop_requested:
                                break
                            if not raw_line.strip():
                                continue
                            try:
                                chunk = json.loads(raw_line)
                                tok = chunk.get("message", {}).get("content", "")
                                if tok:
                                    tokens.append(tok)
                                if chunk.get("done"):
                                    break
                            except (json.JSONDecodeError, KeyError):
                                pass

                content = "".join(tokens)
                self._llm_available = True   # confirmed responsive
                # B1 — successful response → clear the circuit-breaker counter
                _LLMCircuitState.consecutive_5xx = 0

                _phase = str(self.phase) if hasattr(self, "phase") and self.phase else ""
                await self._emit("llm_response", {
                    "agent":    str(self.name),
                    "response": content,
                    "ts":       datetime.utcnow().isoformat()
                })
                await self._emit("llm_comm", {
                    "agent":    str(self.name),
                    "phase":    _phase,
                    "prompt":   prompt,
                    "response": content,
                    "model":    MODEL_NAME,
                    "ts":       datetime.utcnow().isoformat()
                })
                return content

            except httpx.ConnectError:
                # Ollama is genuinely unreachable — mark offline and retry
                self._llm_available = False
                await self._emit("llm_slow", {
                    "agent":   str(self.name),
                    "attempt": attempt,
                    "of":      _LLM_MAX_RETRIES,
                    "message": (
                        f"LLM connection failed (attempt {attempt}/{_LLM_MAX_RETRIES}) — "
                        f"retrying in 10 s…" if attempt < _LLM_MAX_RETRIES else
                        f"LLM offline ({OLLAMA_URL}) — using built-in defaults for this step."
                    )
                })
                if attempt < _LLM_MAX_RETRIES:
                    await asyncio.sleep(10)
                    # Recheck — allows recovery if Ollama restarted between attempts
                    await self.check_llm_available()
                    if self._llm_available:
                        continue
                # Exhausted retries — return "" so scan continues with fallback defaults.
                # We NEVER raise here; scan resilience is more important than LLM planning.
                return ""

            except (httpx.TimeoutException, asyncio.TimeoutError):
                # Ollama is running but hasn't produced a token in `timeout` seconds.
                # Do NOT set _llm_available=False — the server is up, just busy.
                await self._emit("llm_slow", {
                    "agent":   str(self.name),
                    "attempt": attempt,
                    "of":      _LLM_MAX_RETRIES,
                    "timeout": timeout,
                    "message": (
                        f"LLM token timeout (attempt {attempt}/{_LLM_MAX_RETRIES}) — "
                        f"no token received in {timeout}s. Retrying..."
                        if attempt < _LLM_MAX_RETRIES else
                        "LLM unresponsive after all retries — scan continues with built-in defaults for this step."
                    )
                })
                if attempt < _LLM_MAX_RETRIES:
                    await asyncio.sleep(5)
                    continue
                # Exhausted retries — return "" so think_json → _safe_llm_result → {}
                # and each phase method falls through to its hardcoded fallback task list.
                return ""

            except httpx.HTTPStatusError as exc:
                # Ollama returned a non-2xx response.  Differentiate:
                #   404      → model not pulled — bail, retrying won't fix it
                #   4xx      → request error — bail, retrying won't fix it
                #   5xx      → server-side hiccup — RETRY with exponential
                #              backoff; trip the circuit breaker after N
                #              consecutive failures (B1 fix).
                status_code = exc.response.status_code
                import logging as _llm_log
                import time as _t

                if status_code == 404:
                    self._llm_available = False
                    msg = (
                        f"Model '{MODEL_NAME}' not found on Ollama (HTTP 404). "
                        f"Run: ollama pull {MODEL_NAME}"
                    )
                    _llm_log.getLogger(__name__).error("think() HTTP error: %s", msg)
                    await self._emit("llm_status", {
                        "available": False, "url": OLLAMA_URL, "model": MODEL_NAME,
                        "message":   msg, "error": "http_404",
                    })
                    return ""

                if 400 <= status_code < 500:
                    # Client error (bad request body, oversized prompt) —
                    # one-shot, no retry.
                    msg = (
                        f"Ollama returned HTTP {status_code} (client error) "
                        f"for model '{MODEL_NAME}'. Response: {exc.response.text[:200]}"
                    )
                    _llm_log.getLogger(__name__).error("think() HTTP error: %s", msg)
                    await self._emit("llm_status", {
                        "available": False, "url": OLLAMA_URL, "model": MODEL_NAME,
                        "message":   msg, "error": f"http_{status_code}",
                    })
                    return ""

                # === 5xx path — server-side, retryable ===
                _LLMCircuitState.consecutive_5xx += 1
                _LLMCircuitState.last_500_at      = _t.time()

                # Trip the breaker once we've seen too many in a row
                if _LLMCircuitState.consecutive_5xx >= _LLM_CIRCUIT_TRIP_AT:
                    _LLMCircuitState.open_until_ts = _t.time() + _LLM_CIRCUIT_OPEN_FOR
                    _llm_log.getLogger(__name__).error(
                        "think() Ollama circuit breaker OPEN — %d consecutive 5xx, "
                        "rejecting LLM calls for %.0fs (until %s)",
                        _LLMCircuitState.consecutive_5xx,
                        _LLM_CIRCUIT_OPEN_FOR,
                        datetime.fromtimestamp(_LLMCircuitState.open_until_ts).isoformat(),
                    )
                    await self._emit("llm_status", {
                        "available": False, "url": OLLAMA_URL, "model": MODEL_NAME,
                        "message": (
                            f"Ollama returning HTTP 5xx repeatedly — "
                            f"circuit breaker open for {_LLM_CIRCUIT_OPEN_FOR:.0f}s. "
                            f"Reasoning loop will use deterministic primers + cached defaults."
                        ),
                        "error": f"circuit_open_5xx_{_LLMCircuitState.consecutive_5xx}",
                    })
                    self._llm_available = False
                    return ""

                # Per-attempt exponential backoff
                if attempt < _LLM_MAX_RETRIES:
                    sleep_s = min(
                        _LLM_5XX_BACKOFF_MAX,
                        _LLM_5XX_BACKOFF_BASE * (_LLM_5XX_BACKOFF_FACTOR ** (attempt - 1)),
                    )
                    _llm_log.getLogger(__name__).warning(
                        "think() Ollama HTTP %d (consecutive_5xx=%d) — backing off %.1fs (attempt %d/%d)",
                        status_code, _LLMCircuitState.consecutive_5xx,
                        sleep_s, attempt, _LLM_MAX_RETRIES,
                    )
                    await self._emit("llm_slow", {
                        "agent":    str(self.name),
                        "attempt":  attempt,
                        "of":       _LLM_MAX_RETRIES,
                        "http":     status_code,
                        "consecutive_5xx": _LLMCircuitState.consecutive_5xx,
                        "message":  f"Ollama HTTP {status_code} — retrying in {sleep_s:.1f}s",
                    })
                    await asyncio.sleep(sleep_s)
                    continue

                # Exhausted retries on this call — return "" so caller falls
                # back to defaults.  Breaker may still trip later.
                msg = (
                    f"Ollama returned HTTP {status_code} for model '{MODEL_NAME}' "
                    f"(consecutive_5xx={_LLMCircuitState.consecutive_5xx}). "
                    f"Response: {exc.response.text[:200]}"
                )
                _llm_log.getLogger(__name__).error("think() HTTP error: %s", msg)
                await self._emit("llm_status", {
                    "available": True,  # could still recover — don't kill platform
                    "url":       OLLAMA_URL,
                    "model":     MODEL_NAME,
                    "message":   msg,
                    "error":     f"http_{status_code}",
                })
                return ""

            except Exception as exc:
                # Unexpected error (bad response format, etc.) — log and return ""
                # so the scan continues.  Never raise here.
                import logging as _llm_log
                _llm_log.getLogger(__name__).warning(
                    "think() unexpected error (attempt %d): %s: %s",
                    attempt, type(exc).__name__, exc
                )
                await self._emit("llm_slow", {
                    "agent":   str(self.name),
                    "message": f"LLM unexpected error ({type(exc).__name__}) — using built-in defaults for this step."
                })
                if attempt < _LLM_MAX_RETRIES:
                    await asyncio.sleep(5)
                    continue
                return ""

        return ""   # unreachable but satisfies type checker

    async def think_json(self, prompt: str, system_context: str = "", timeout: int = LLM_THINK_TIMEOUT) -> Dict:
        """Query LLM expecting a JSON response. Extracts and parses JSON."""
        _t0 = time.monotonic()
        raw = await self.think(prompt + "\n\nRespond ONLY with valid JSON. No markdown, no explanation.", system_context, timeout)
        _latency = time.monotonic() - _t0
        # Derive a short step label from the first line of the prompt
        _step_label = ""
        try:
            first_line = (prompt.strip().splitlines() or [""])[0]
            _step_label = first_line[:60]
        except Exception:
            pass

        def _log(result: Dict, parse_error: bool) -> Dict:
            try:
                decision = (
                    result.get("decision")
                    or result.get("primary_strategy")
                    or result.get("reasoning", "")[:200]
                ) if isinstance(result, dict) else ""
                _slog_llm(
                    self._session_id,
                    _step_label or "think_json",
                    prompt_chars   = len(prompt),
                    response_chars = len(raw),
                    latency        = _latency,
                    model          = MODEL_NAME,
                    decision       = str(decision),
                    reasoning      = str(result.get("reasoning", "")) if isinstance(result, dict) else "",
                    parse_error    = parse_error,
                )
            except Exception:
                pass
            return result

        # Try direct parse
        try:
            return _log(json.loads(raw), False)
        except json.JSONDecodeError:
            pass
        # Extract from code block
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
        if m:
            try:
                return _log(json.loads(m.group(1)), False)
            except json.JSONDecodeError:
                pass
        # Extract first { ... }
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            try:
                return _log(json.loads(m.group()), False)
            except json.JSONDecodeError:
                pass
        return _log({"raw_response": raw, "parse_error": True}, True)

    # ─── Finding Storage ──────────────────────────────────────

    async def store_finding(
        self,
        severity:    FindingSeverity,
        title:       str,
        description: str,
        host:        str,
        port:        Optional[int]  = None,
        service:     Optional[str]  = None,
        cves:        List[str]      = None,
        exploits:    List[str]      = None,
        tool_used:   Optional[str]  = None,
        raw_output:  Optional[str]  = None,
        extra:       Dict           = None,
        evidence:    Optional[str]  = None,
        remediation: Optional[str]  = None
    ) -> Dict:
        """Store a finding to DB and broadcast to frontend."""
        finding = await db.store_finding(
            session_id  = self._session_id,
            agent       = str(self.name),
            phase       = str(self.phase),
            severity    = severity,
            title       = title,
            description = description,
            host        = host,
            port        = port,
            service     = service,
            cves        = cves or [],
            exploits    = exploits or [],
            tool_used   = tool_used,
            raw_output  = raw_output,
            extra       = {**(extra or {}), "evidence": evidence, "remediation": remediation}
        )
        await self._emit("finding", {"agent": str(self.name), "finding": finding})

        # Add finding to attack graph in real-time
        try:
            fid      = finding.get("id") or str(finding.get("_id",""))
            sev_str  = str(severity).lower().replace("findingseverity.","")
            node_type = "vulnerability" if sev_str in ("critical","high") else "finding"
            node_id   = f"finding_{fid}" if fid else f"finding_{title[:20].replace(' ','_')}"
            host_id   = f"host_{(host or 'unknown').replace('.','_')}"
            svc_id    = f"svc_{(host or 'unknown').replace('.','_')}_{port}" if port else host_id

            await self.add_node(
                node_id  = node_id,
                type     = node_type,
                label    = title[:40],
                host     = host,
                port     = port,
                severity = sev_str,
                metadata = {
                    "description": description[:200] if description else "",
                    "cves":        cves or [],
                    "tool":        tool_used or "",
                    "phase":       str(self.phase),
                }
            )
            await self.add_edge(
                source = svc_id,
                target = node_id,
                label  = f"{sev_str} finding",
                tool   = tool_used or ""
            )
            # CVE nodes
            for cve in (cves or [])[:3]:
                cve_id = f"cve_{cve.replace('-','_')}"
                await self.add_node(
                    node_id  = cve_id,
                    type     = "vulnerability",
                    label    = cve,
                    host     = host,
                    severity = "high",
                    metadata = {"cve_id": cve}
                )
                await self.add_edge(
                    source = node_id,
                    target = cve_id,
                    label  = "references",
                    tool   = "searchsploit"
                )
        except Exception:
            pass  # graph update failure never blocks finding storage

        # ── Auto-ingest high/critical findings into RAG KB ────────────────
        if _AUTO_INGEST_AVAILABLE:
            try:
                asyncio.create_task(_capture_finding(
                    finding    = finding,
                    session_id = self._session_id,
                    phase      = str(self.phase),
                ))
            except Exception:
                pass  # never block on auto-ingest failure

        return finding

    async def store_flag(self, flag_type: str, value: str, location: str, context: Optional[str] = None) -> Dict:
        flag = await db.store_flag(
            session_id = self._session_id,
            flag_type  = flag_type,
            value      = value,
            location   = location,
            found_by   = str(self.name),
            context    = context
        )
        await self._emit("flag_found", {
            "agent":     str(self.name),
            "flag_type": flag_type,
            "value":     value,
            "location":  location
        })
        # Add flag as access node in graph
        try:
            flag_node_id = f"flag_{flag_type}_{str(flag.get('id',''))}"
            target_ip = getattr(self, '_target', 'unknown')
            await self.add_node(
                node_id  = flag_node_id,
                type     = "access",
                label    = f"{'Root' if flag_type=='root' else 'User'} flag",
                host     = target_ip,
                severity = "critical",
                metadata = {"flag_type": flag_type, "location": location, "value": value[:20]}
            )
            host_node_id = f"target_{target_ip.replace('.','_').replace('/','_')}"
            await self.add_edge(
                source = host_node_id,
                target = flag_node_id,
                label  = f"compromised → {flag_type}",
                tool   = "shell"
            )
        except Exception:
            pass
        return flag

    # ─── Attack Graph ─────────────────────────────────────────

    async def add_node(
        self,
        node_id:  str,
        type:     str,
        label:    str,
        host:     Optional[str] = None,
        port:     Optional[int] = None,
        severity: Optional[str] = None,
        metadata: Dict = None
    ):
        """Add a node to the attack graph (stored in DB, sent to frontend)."""
        await db.add_attack_node(
            session_id = self._session_id,
            node_id    = node_id,
            node_type  = type,
            label      = label,
            phase      = str(self.phase),
            host       = host,
            port       = port,
            severity   = severity,
            metadata   = metadata or {}
        )
        await self._emit("graph_node", {
            "node_id":   node_id,
            "type":      type,       # kept for backward compat
            "node_type": type,       # canonical field used by AttackGraph.jsx
            "label":     label,
            "host":      host,
            "port":      port,
            "severity":  severity,
            "phase":     str(self.phase),
            "metadata":  metadata or {}
        })
        # ── dual-write to Neo4j ───────────────────────────────────────────
        if _NEO4J_AVAILABLE:
            try:
                props = {**(metadata or {}), "host": host, "port": port,
                         "severity": severity, "phase": str(self.phase)}
                await _neo4j.upsert_node(
                    session_id = self._session_id,
                    node_id    = node_id,
                    node_type  = type,
                    label      = label,
                    properties = {k: v for k, v in props.items() if v is not None},
                )
            except Exception:
                pass

    async def add_edge(self, source: str, target: str, label: str, tool: Optional[str] = None):
        """Add an edge between nodes in attack graph."""
        edge_id = f"{source}->{target}"
        await db.add_attack_edge(
            session_id = self._session_id,
            edge_id    = edge_id,
            source     = source,
            target     = target,
            label      = label,
            tool       = tool
        )
        await self._emit("graph_edge", {
            "edge_id": edge_id,
            "source":  source,
            "target":  target,
            "label":   label,
            "tool":    tool
        })
        # ── dual-write to Neo4j ───────────────────────────────────────────
        if _NEO4J_AVAILABLE:
            try:
                rel_type = _label_to_rel_type(label)
                await _neo4j.upsert_edge(
                    session_id = self._session_id,
                    source_id  = source,
                    target_id  = target,
                    rel_type   = rel_type,
                    properties = {"label": label, "tool": tool or ""},
                )
            except Exception:
                pass

    # ─── Utility Parsers ──────────────────────────────────────

    def _extract_ports(self, text: str) -> List[int]:
        ports = []
        for m in re.finditer(r'\b(\d{1,5})/(?:tcp|udp)\s+open', text, re.IGNORECASE):
            p = int(m.group(1))
            if 1 <= p <= 65535:
                ports.append(p)
        return sorted(list(set(ports)))

    def _extract_ips(self, text: str) -> List[str]:
        return list(set(re.findall(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            text
        )))

    def _extract_cves(self, text: str) -> List[str]:
        return list(set(re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)))

    def _extract_urls(self, text: str) -> List[str]:
        return list(set(re.findall(r'https?://[^\s\'"<>]+', text)))

    def _extract_credentials(self, text: str) -> List[Dict]:
        """Extract username:password patterns from tool output."""
        creds = []
        patterns = [
            r'(?:username|user|login):\s*([^\s]+)\s+(?:password|pass|pwd):\s*([^\s]+)',
            r'([a-zA-Z0-9_\-\.]+):([^\s:]{4,})\s+(?:login successful|authenticated|valid)',
            r'\[SUCCESS\].*?([a-zA-Z0-9_\-\.]+):([^\s]+)',
        ]
        for pat in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                creds.append({"username": m.group(1), "password": m.group(2)})
        return creds

    def _extract_services(self, nmap_output: str) -> Dict:
        """Parse nmap -sV output into {port: {service, version, protocol}} dict."""
        services = {}
        for line in nmap_output.splitlines():
            m = re.match(
                r'\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)',
                line, re.IGNORECASE
            )
            if m:
                port    = int(m.group(1))
                proto   = m.group(2)
                service = m.group(3)
                version = m.group(4).strip()
                services[port] = {
                    "service":  service,
                    "version":  version,
                    "protocol": proto,
                    "port":     port
                }
        return services

    def _extract_web_paths(self, tool_output: str) -> List[str]:
        """Extract discovered web paths from gobuster/dirb/ffuf output."""
        paths = []
        for m in re.finditer(r'(/[a-zA-Z0-9/_\-\.%?=&]+)\s+\(Status:\s*(\d+)', tool_output):
            status = int(m.group(2))
            if status not in (404, 400, 403):
                paths.append(m.group(1))
        # Also catch ffuf format
        for m in re.finditer(r':: Progress.*\n.*?(\/[^\s]+)', tool_output):
            paths.append(m.group(1))
        return list(set(paths))

    def _estimate_severity(self, title: str, description: str) -> FindingSeverity:
        """Estimate finding severity from keywords."""
        text = (title + " " + description).lower()
        if any(k in text for k in ["rce", "remote code execution", "command injection", "metasploit",
                                    "root", "administrator", "sql injection", "sqli", "xxe",
                                    "deserialization", "eternalblue", "ms17-010"]):
            return FindingSeverity.CRITICAL
        if any(k in text for k in ["xss", "csrf", "ssrf", "lfi", "rfi", "file inclusion",
                                    "privilege escalation", "privesc", "suid", "sudo misconfiguration",
                                    "weak password", "default credential"]):
            return FindingSeverity.HIGH
        if any(k in text for k in ["information disclosure", "directory listing", "exposed",
                                    "weak cipher", "ssl", "tls", "outdated", "version disclosure"]):
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW

    # ─── Internal ─────────────────────────────────────────────

    async def _emit(self, event_type: str, data: Dict):
        if not self.broadcast or not self._session_id:
            return
        msg = WebSocketMessage(
            type       = event_type,
            session_id = self._session_id,
            agent      = str(self.name),
            data       = data
        )
        try:
            await self.broadcast(msg)
        except Exception as e:
            print(f"[BROADCAST ERROR] {e}")

    async def _log_action(
        self,
        action:    str,
        reasoning: str,
        status:    AgentStatus,
        tool:      Optional[str] = None,
        message:   Optional[str] = None
    ):
        if not self._session_id:
            return
        try:
            await db.log_agent_action(
                session_id  = self._session_id,
                agent       = str(self.name),
                phase       = str(self.phase),
                action      = action,
                reasoning   = reasoning,
                new_status  = status,
                prev_status = None,
                tool        = tool,
                message     = message
            )
        except Exception as e:
            print(f"[DB LOG ERROR] {e}")

    async def _handle_bus_message(self, message: Dict):
        """Override in subclass to handle inbound bus messages."""
        pass

    async def check_tool_available(self, tool_name: str) -> Dict:
        """Check if a tool binary exists on the system."""
        result = subprocess.run(["which", tool_name], capture_output=True, text=True)
        if result.returncode == 0:
            return {"available": True, "path": result.stdout.strip()}
        return {"available": False, "path": "", "install_cmd": f"apt install {tool_name} -y"}
