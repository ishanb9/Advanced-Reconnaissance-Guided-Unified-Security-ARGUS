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
MCP_URL    = "http://localhost:3000"
OLLAMA_URL = "http://192.168.0.100:11434"   # ← Ollama host
MODEL_NAME = "glm-5:cloud"          # ← Update to your model name

LLM_CHECK_TIMEOUT = 10   # Seconds to wait for Ollama health check
LLM_THINK_TIMEOUT = 120  # Seconds to wait for LLM response

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
        self._current_proc: Optional[Any] = None  # asyncio subprocess handle

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
        Test if Ollama LLM is reachable and responding.
        Result is cached for the session. Emits clear status to frontend.
        MASTER AGENT must call this before any planning.
        If this returns False, testing should NOT proceed.
        """
        try:
            async with httpx.AsyncClient(timeout=LLM_CHECK_TIMEOUT) as client:
                resp = await client.get(f"{OLLAMA_URL}/api/tags")
                if resp.status_code == 200:
                    self._llm_available = True
                    await self._emit("llm_status", {
                        "available": True,
                        "url":       OLLAMA_URL,
                        "model":     MODEL_NAME,
                        "message":   f"LLM online — {MODEL_NAME} at {OLLAMA_URL}"
                    })
                    return True
        except Exception as e:
            pass

        self._llm_available = False
        msg = f"LLM OFFLINE — Cannot reach Ollama at {OLLAMA_URL}. Pentest HALTED. Start Ollama and retry."
        await self._emit("llm_status", {
            "available": False,
            "url":       OLLAMA_URL,
            "model":     MODEL_NAME,
            "message":   msg,
            "error":     "Connection refused or timeout"
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
        if self._current_proc is not None:
            try:
                self._current_proc.kill()
            except Exception:
                pass

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
            while not self._stop_requested:
                elapsed   = time.monotonic() - self._tool_run_start
                remaining = self._tool_deadline_sec - elapsed
                if remaining <= 0:
                    break
                await asyncio.sleep(min(remaining, 10.0))

            # Phase 2: deadline exceeded — emit warning every 30 s
            while not self._stop_requested:
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
                await asyncio.sleep(30.0)

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
        self._current_tool_name = tool_name
        self._tool_run_start    = time.monotonic()
        self._tool_deadline_sec = 600.0   # reset fresh for each tool call
        watchdog = asyncio.create_task(self._tool_watchdog(tool_name))

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

        async def _run_local() -> int:
            """Run full_cmd in a local subprocess and stream output."""
            proc = await asyncio.create_subprocess_shell(
                full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024,  # 1 MB read buffer
            )
            self._current_proc = proc
            async def _drain(stream, ltype):
                while True:
                    line_b = await stream.readline()
                    if not line_b:
                        break
                    decoded = line_b.decode(errors="replace").rstrip()
                    if decoded:
                        await _emit_line(decoded, ltype)
            await asyncio.gather(
                _drain(proc.stdout, "stdout"),
                _drain(proc.stderr, "stderr"),
            )
            await proc.wait()
            self._current_proc = None
            return proc.returncode or 0

        async def _run_via_mcp() -> int:
            """Run tool via MCP SSE endpoint and stream output. Returns exit_code."""
            # Use the same REST format and endpoint as base_subagent.py
            mcp_endpoint = f"{MCP_URL}/tools/call"
            payload = {
                "tool":      tool_name,
                "arguments": {"target": target or "", "options": args},
            }
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
                async with client.stream(
                    "POST", mcp_endpoint, json=payload,
                    headers={"Accept": "text/event-stream"},
                ) as resp:
                    resp.raise_for_status()   # raises HTTPStatusError on 4xx/5xx
                    async for raw in resp.aiter_lines():
                        if self._stop_requested:
                            break
                        if not raw:
                            continue
                        content = raw[5:].strip() if raw.startswith("data:") else raw.strip()
                        try:
                            event = json.loads(content)
                            etype = event.get("type", "")
                            chunk = (event.get("output") or event.get("line") or
                                     event.get("data")   or event.get("message") or "")
                            if etype in ("stdout", "output", ""):
                                if chunk:
                                    await _emit_line(chunk, "stdout")
                            elif etype == "stderr":
                                if chunk:
                                    await _emit_line(chunk, "stderr")
                            elif etype == "exit":
                                return int(event.get("code", 0))
                            elif etype == "error":
                                await _emit_line(f"[MCP ERROR] {chunk}", "stderr")
                        except (json.JSONDecodeError, ValueError):
                            if content:
                                await _emit_line(content, "stdout")
            return 0

        try:
            if tool_name.lower() in _LOCAL_TOOLS:
                # Generic shell commands always run locally — MCP has no bash tool
                exit_code = await _run_local()
            else:
                try:
                    exit_code = await _run_via_mcp()
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

        return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code, "output_id": output_id}

    # ─── LLM Reasoning (Master Agent Only) ────────────────────

    async def think(self, prompt: str, system_context: str = "", timeout: int = LLM_THINK_TIMEOUT) -> str:
        """
        Query the LLM. Called by ANY agent — master OR specialist.
        Each agent has its own domain-specific system prompt.
        Raises RuntimeError if LLM is unavailable.
        """
        # Ensure LLM availability is checked (cached after first check)
        if self._llm_available is None:
            await self.check_llm_available()
        if not self._llm_available:
            raise RuntimeError(
                f"LLM unavailable at {OLLAMA_URL}. Cannot proceed."
            )

        await self.set_status(AgentStatus.THINKING, "Consulting LLM...")
        await self._emit("agent_thinking", {
            "agent":  str(self.name),
            "prompt": prompt,
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

        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt}
        ]

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
                resp = await client.post(
                    f"{OLLAMA_URL}/api/chat",
                    json={"model": MODEL_NAME, "messages": messages, "stream": False}
                )
                resp.raise_for_status()
                content = resp.json()["message"]["content"]
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
        except httpx.TimeoutException:
            self._llm_available = False
            raise RuntimeError(f"LLM timed out after {timeout}s. Pentest halted.")
        except httpx.ConnectError:
            self._llm_available = False
            raise RuntimeError(f"LLM connection lost. Check Ollama at {OLLAMA_URL}.")
        except Exception as e:
            raise RuntimeError(f"LLM error: {type(e).__name__}: {e}")

    async def think_json(self, prompt: str, system_context: str = "", timeout: int = LLM_THINK_TIMEOUT) -> Dict:
        """Query LLM expecting a JSON response. Extracts and parses JSON."""
        raw = await self.think(prompt + "\n\nRespond ONLY with valid JSON. No markdown, no explanation.", system_context, timeout)
        # Try direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
        # Extract from code block
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        # Extract first { ... }
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        return {"raw_response": raw, "parse_error": True}

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
