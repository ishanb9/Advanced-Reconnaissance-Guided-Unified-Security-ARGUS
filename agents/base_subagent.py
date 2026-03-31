"""
base_subagent.py — Base class for all subagents in the Kali Linux pentest platform.

Architecture overview
---------------------
Subagents are pure tool executors. They have NO LLM access whatsoever. Each
subagent receives a session_id, a target, a broadcast coroutine, and a Motor
(async MongoDB) database reference. Subagents call tools via the MCP HTTP SSE
endpoint at http://localhost:3000, stream output line-by-line, emit WebSocket
events for every tool line and every finding, and store results in MongoDB.

Every concrete subagent must:
  1. Set the class variables AGENT_NAME and SUBAGENT_NAME.
  2. Implement the abstract coroutine ``run(target, **kwargs) → SubagentResult``.

WebSocket event shapes
----------------------
  subagent_start      — emitted when run() begins
  subagent_tool_line  — one line of raw tool output
  subagent_finding    — a structured finding
  subagent_complete   — run() finished successfully
  subagent_error      — an exception escaped run()

MongoDB collections used
------------------------
  findings            — one document per Finding
  subagent_results    — one document per SubagentResult (per subagent run)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Callable, Coroutine, Optional

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

# ── Global subagent registry — allows agent_server to cancel by name ──────────
_SUBAGENT_REGISTRY: dict[str, "BaseSubagent"] = {}


def get_subagent(name: str) -> "Optional[BaseSubagent]":
    """Return the live subagent instance registered under *name*, or None."""
    return _SUBAGENT_REGISTRY.get(name)


def list_running_subagents() -> list[str]:
    """Return names of all subagents currently marked as running."""
    return [n for n, sa in _SUBAGENT_REGISTRY.items() if not sa._stop_requested]


# ── RAG Knowledge Base (subagents can query for command hints) ─────────────────
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "knowledge"))
    import knowledge_base as _kb_sa
    _KB_SA_AVAILABLE = True
except ImportError:
    _KB_SA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MCP_BASE_URL: str = "http://localhost:3000"
MCP_SSE_ENDPOINT: str = f"{MCP_BASE_URL}/sse"
MCP_TOOL_ENDPOINT: str = f"{MCP_BASE_URL}/"   # MCP accepts POST / (not /tools/call)

# Keyword maps used by parse_severity
_CRITICAL_KEYWORDS = frozenset({
    "critical", "rce", "remote code execution", "unauthenticated rce",
    "command injection", "sql injection", "sqlinjection", "log4shell",
    "log4j", "shellshock", "heartbleed", "eternalblue", "ms17-010",
    "zero-day", "0day", "cvss 9", "cvss 10",
})
_HIGH_KEYWORDS = frozenset({
    "high", "privilege escalation", "privesc", "lpe", "lfi", "rfi",
    "file inclusion", "xxe", "ssrf", "deserialization", "buffer overflow",
    "heap overflow", "use after free", "format string", "arbitrary write",
    "authentication bypass", "auth bypass", "sudo", "suid", "sgid",
    "password hash", "ntlm hash", "pass-the-hash", "token impersonation",
    "credential", "cve", "cvss 7", "cvss 8",
})
_MEDIUM_KEYWORDS = frozenset({
    "medium", "xss", "csrf", "open redirect", "clickjacking",
    "information disclosure", "directory listing", "path traversal",
    "default credential", "weak password", "plaintext", "cleartext",
    "self-signed", "outdated", "deprecated", "misconfiguration",
    "misconfig", "cvss 4", "cvss 5", "cvss 6",
})
_LOW_KEYWORDS = frozenset({
    "low", "verbose", "debug", "banner", "version disclosure",
    "missing header", "cookie", "http only", "secure flag", "hsts",
    "csp", "cors", "fingerprint", "cvss 1", "cvss 2", "cvss 3",
})


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single security finding produced by a subagent tool run.

    Attributes
    ----------
    title:
        Short human-readable title, e.g. "Open SSH Port 22".
    description:
        Full description of what was found and why it matters.
    severity:
        One of CRITICAL / HIGH / MEDIUM / LOW / INFO.
    evidence:
        Raw evidence string (command output snippet, request/response, etc.).
    tool:
        Name of the MCP tool that produced this finding.
    host:
        Target host (IP or hostname).
    port:
        TCP/UDP port number, or None if not applicable.
    cve:
        CVE identifier(s) if known, e.g. "CVE-2021-44228".
    mitre_technique:
        MITRE ATT&CK technique ID, e.g. "T1190".
    exploit_suggestion:
        Brief suggested exploitation path or remediation note.
    finding_id:
        Auto-generated UUID for this finding.
    timestamp:
        UTC datetime of discovery.
    """

    title: str
    description: str
    severity: str = "INFO"
    evidence: str = ""
    tool: str = ""
    host: str = ""
    port: Optional[int] = None
    cve: Optional[str] = None
    mitre_technique: Optional[str] = None
    exploit_suggestion: Optional[str] = None
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        if self.severity not in valid:
            self.severity = "INFO"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class SubagentResult:
    """Aggregated result returned by a subagent after its run() completes.

    Attributes
    ----------
    findings:
        All Finding objects discovered during the run.
    tool_outputs:
        Mapping of tool_name → full concatenated stdout collected during the
        run (for tools called with collect_tool).
    raw_output:
        Catch-all raw output string (optional).
    duration_seconds:
        Wall-clock time of the run() invocation.
    error:
        Exception message if run() raised; None on success.
    session_id:
        Inherited from the owning BaseSubagent.
    subagent_name:
        Inherited from the owning BaseSubagent.
    target:
        Target that was scanned.
    result_id:
        Auto-generated UUID for this result document.
    timestamp:
        UTC datetime when the result was produced.
    """

    findings: list[Finding] = field(default_factory=list)
    tool_outputs: dict[str, str] = field(default_factory=dict)
    raw_output: str = ""
    duration_seconds: float = 0.0
    error: Optional[str] = None
    session_id: str = ""
    subagent_name: str = ""
    target: str = ""
    result_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Structured parsed data produced by individual subagents (e.g. port lists,
    # web targets, DNS records).  Declared here so asdict() serialises it to
    # MongoDB; subagents may leave it as None if they produce no extra structure.
    parsed_data: Optional[dict] = field(default=None)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


# ---------------------------------------------------------------------------
# Base subagent
# ---------------------------------------------------------------------------

class BaseSubagent(ABC):
    """Abstract base class for all 83 pentest subagents.

    Subagents are pure tool executors — they contain no LLM inference and make
    no decisions beyond simple keyword-based severity parsing. All intelligence
    lives in the orchestrating agents that instantiate and await subagents.

    Class variables (must be overridden by every concrete subagent)
    --------------------------------------------------------------
    AGENT_NAME:
        Name of the parent agent phase, e.g. "ReconAgent".
    SUBAGENT_NAME:
        Unique name for this subagent, e.g. "NmapPortScanner".

    Parameters
    ----------
    session_id:
        Unique identifier for the pentest session.
    target:
        Primary scan target (IP, hostname, CIDR, or URL).
    broadcast:
        Async callable ``(event: dict) → None`` that fans the event out to all
        connected WebSocket clients for this session.
    db:
        Motor async MongoDB database handle.
    """

    AGENT_NAME: str = "BaseAgent"
    SUBAGENT_NAME: str = "BaseSubagent"

    def __init__(
        self,
        session_id: str,
        target: str,
        broadcast: Callable[[dict], Coroutine[Any, Any, None]],
        db: AsyncIOMotorDatabase,
    ) -> None:
        self.session_id = session_id
        self.target = target
        self.broadcast = broadcast
        self.db = db
        self._findings: list[Finding] = []
        self._tool_outputs: dict[str, str] = {}
        self._http_client: Optional[httpx.AsyncClient] = None
        self._stop_requested: bool = False
        self._rag_hint: str = ""   # populated by RAG before run() is called
        # Tool timeout watchdog state
        self._tool_run_start: float = 0.0
        self._tool_deadline_sec: float = 600.0   # default 10 minutes
        self._current_tool_name: str = ""
        self._current_proc: Optional[Any] = None   # asyncio.subprocess.Process
        # Register in global registry keyed by SUBAGENT_NAME
        _SUBAGENT_REGISTRY[self.SUBAGENT_NAME] = self

    def request_stop(self) -> None:
        """Signal this subagent to stop after the current tool line."""
        self._stop_requested = True
        # If a local subprocess is running, kill it immediately
        if self._current_proc is not None:
            try:
                self._current_proc.kill()
            except Exception:
                pass

    def extend_tool(self, extra_sec: float) -> None:
        """Extend the running tool's deadline by *extra_sec* seconds."""
        self._tool_deadline_sec += extra_sec
        logger.info(
            "[%s] tool '%s' deadline extended by %gs → new deadline %gs elapsed",
            self.SUBAGENT_NAME, self._current_tool_name,
            extra_sec, self._tool_deadline_sec,
        )

    async def _tool_watchdog(self, tool_name: str) -> None:
        """Emit tool_timeout_warning when the tool exceeds its deadline.

        Waits until the deadline is first reached, then emits a warning every
        30 s until the tool finishes, the user extends the deadline
        (which resets the remaining time), or the user stops the tool.
        """
        try:
            # ── Phase 1: sleep until first deadline ───────────────────────
            while not self._stop_requested:
                elapsed   = time.monotonic() - self._tool_run_start
                remaining = self._tool_deadline_sec - elapsed
                if remaining <= 0:
                    break
                # Wake up frequently enough to notice an extension quickly
                await asyncio.sleep(min(remaining, 10.0))

            # ── Phase 2: deadline exceeded — emit warning every 30 s ──────
            while not self._stop_requested:
                elapsed   = time.monotonic() - self._tool_run_start
                remaining = self._tool_deadline_sec - elapsed

                if remaining > 0:
                    # User extended the deadline — wait for the new deadline
                    await asyncio.sleep(min(remaining, 10.0))
                    continue

                await self._emit("tool_timeout_warning", {
                    "tool":         tool_name,
                    "subagent":     self.SUBAGENT_NAME,
                    "elapsed_sec":  round(elapsed),
                    "deadline_sec": round(self._tool_deadline_sec),
                })
                # Wait 30 s before the next warning (gives the operator time to respond)
                await asyncio.sleep(30.0)

        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Internal helpers — WebSocket event emitters
    # ------------------------------------------------------------------

    async def _emit(self, event_type: str, payload: dict) -> None:
        """Broadcast a WebSocket event to all session clients."""
        event = {
            "type": event_type,
            "session_id": self.session_id,
            "agent": self.AGENT_NAME,
            "subagent": self.SUBAGENT_NAME,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        try:
            await self.broadcast(event)
        except Exception as exc:  # noqa: BLE001
            logger.warning("broadcast failed for event %s: %s", event_type, exc)

    async def _emit_tool_line(self, tool_name: str, line: str) -> None:
        await self._emit(
            "subagent_tool_line",
            {"tool": tool_name, "line": line},
        )

    async def _emit_finding(self, finding: Finding) -> None:
        await self._emit("subagent_finding", {"finding": finding.to_dict()})

    async def _emit_start(self) -> None:
        await self._emit("subagent_start", {"target": self.target})

    async def _emit_complete(self, result: SubagentResult) -> None:
        await self._emit(
            "subagent_complete",
            {
                "target": self.target,
                "duration_seconds": result.duration_seconds,
                "finding_count": len(result.findings),
                "error": result.error,
            },
        )

    async def _emit_error(self, error: str) -> None:
        await self._emit("subagent_error", {"target": self.target, "error": error})

    # ------------------------------------------------------------------
    # RAG Knowledge Base access
    # ------------------------------------------------------------------

    async def _kb_search(self, query: str, top_k: int = 3) -> str:
        """Query the knowledge base for relevant commands/techniques.

        Returns formatted KB context string, or '' if KB unavailable.
        Emits a rag_query WS event so the AI Observability page shows it.
        """
        if not _KB_SA_AVAILABLE:
            return ""
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _kb_sa.search_commands(query, top_k=top_k)
            )
            found = bool(result)
            ctx = ""
            if result:
                lines = [f"[KB Example {i+1}] {cmd.strip()}" for i, cmd in enumerate(result)]
                ctx = "\n".join(lines)
            await self._emit("rag_query", {
                "agent":   self.AGENT_NAME,
                "query":   query,
                "result":  ctx[:400] if ctx else "",
                "found":   found,
                "ts":      datetime.now(timezone.utc).isoformat(),
            })
            return ctx
        except Exception as exc:
            logger.debug("_kb_search failed: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # MCP tool execution
    # ------------------------------------------------------------------

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Return a shared async HTTP client, creating it lazily."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=httpx.Timeout(None))
        return self._http_client

    async def run_tool(
        self,
        tool_name: str,
        target: str,
        options: Optional[dict] = None,
    ) -> AsyncGenerator[str, None]:
        """Execute an MCP tool via HTTP SSE streaming.

        Sends a POST to the MCP tool endpoint and yields each line of output
        as it arrives over the SSE stream. Every line is also fanned out as a
        ``subagent_tool_line`` WebSocket event.

        Parameters
        ----------
        tool_name:
            Name of the MCP tool to invoke, e.g. ``"nmap"``.
        target:
            Scan target passed to the tool.
        options:
            Optional dict of additional tool parameters.

        Yields
        ------
        str
            Each line of tool output, stripped of trailing newline.
        """
        if options is None:
            options = {}

        # Tools that must always run locally — MCP has no generic shell executor
        _LOCAL_SHELL_TOOLS = {"bash", "sh", "zsh", "cmd", "powershell",
                              "python", "python3", "perl", "ruby"}

        # Build the shell command string for local fallback.
        # Subagents always use {"options": "<flags> <target>"} — the target is
        # embedded inside the options string, so we must NOT prepend it again.
        # e.g. tool="nmap", options={"options": "-sV -p 80 10.0.0.1"}
        # → "nmap -sV -p 80 10.0.0.1"
        def _build_cmd() -> str:
            _opts = options or {}
            # Full command override (bash/sh/python calls)
            if "command" in _opts:
                return str(_opts["command"])
            # Standard pattern: options key holds full flag string with target embedded
            if "options" in _opts:
                raw = str(_opts["options"]).strip()
                return f"{tool_name} {raw}".strip() if raw else tool_name
            # Fallback: build from parts; target appended last
            parts = [tool_name]
            for k, v in _opts.items():
                if v and k not in ("target", "stdin"):
                    flag = k if k.startswith("-") else f"--{k}"
                    parts.extend([flag, str(v)])
            if target:
                parts.append(target)
            return " ".join(parts)

        async def _run_local_gen():
            """Yield output lines from a local subprocess."""
            import asyncio as _asyncio
            cmd = _build_cmd()
            logger.debug("run_tool LOCAL: %s", cmd)
            proc = await _asyncio.create_subprocess_shell(
                cmd,
                stdout=_asyncio.subprocess.PIPE,
                stderr=_asyncio.subprocess.PIPE,
                limit=1024 * 1024,
            )
            self._current_proc = proc

            async def _drain(stream, prefix=""):
                while True:
                    if self._stop_requested:
                        break
                    line_b = await stream.readline()
                    if not line_b:
                        break
                    decoded = line_b.decode(errors="replace").rstrip()
                    if decoded:
                        await self._emit_tool_line(tool_name, f"{prefix}{decoded}")
                        yield f"{prefix}{decoded}"

            async for ln in _drain(proc.stdout):
                if self._stop_requested:
                    break
                yield ln
            if not self._stop_requested:
                async for ln in _drain(proc.stderr, "[STDERR] "):
                    yield ln

            if self._stop_requested:
                try:
                    proc.kill()
                except Exception:
                    pass
                cancelled_line = f"[CANCELLED] Tool '{tool_name}' stopped by operator"
                await self._emit_tool_line(tool_name, cancelled_line)
                yield cancelled_line
                await self._emit("subagent_tool_exit", {
                    "tool": tool_name, "exit_code": -2, "success": False, "cancelled": True,
                })
                self._current_proc = None
                return

            await proc.wait()
            self._current_proc = None
            exit_code = proc.returncode or 0
            exit_line = f"[EXIT {exit_code}]"
            await self._emit_tool_line(tool_name, exit_line)
            yield exit_line
            await self._emit("subagent_tool_exit", {
                "tool": tool_name, "exit_code": exit_code, "success": exit_code == 0,
            })

        async def _run_mcp_gen():
            """Yield output lines from the MCP SSE endpoint.

            Protocol (POST /):
              Request:  {"method":"tools/call","params":{"name":"nmap","arguments":{"target":"...","options":"..."}}}
              SSE stream: data: {"type":"stdout","data":"line"}
                          data: {"type":"stderr","data":"line"}
                          data: {"type":"exit",  "code":0}
                          data: {"type":"error", "message":"..."}
                          data: {"type":"info",  "message":"..."}

            Raises RuntimeError when MCP reports tool is not in its registry,
            so the caller can fall back to local execution.
            """
            payload = {
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {"target": target, **(options or {})},
                },
            }
            client = await self._get_http_client()
            logger.debug("run_tool MCP: POST %s body=%s", MCP_TOOL_ENDPOINT, payload)
            exit_code: Optional[int] = None
            not_in_registry = False
            async with client.stream(
                "POST",
                MCP_TOOL_ENDPOINT,
                json=payload,
                headers={"Accept": "text/event-stream"},
            ) as response:
                response.raise_for_status()
                async for raw_line in response.aiter_lines():
                    if not raw_line:
                        continue
                    content = raw_line[5:].strip() if raw_line.startswith("data:") else raw_line.strip()
                    if not content:
                        continue
                    try:
                        obj = json.loads(content)
                        if isinstance(obj, dict):
                            event_type = obj.get("type", "")
                            if event_type == "exit":
                                exit_code = obj.get("code", 0)
                                exit_line = f"[EXIT {exit_code}]"
                                await self._emit_tool_line(tool_name, exit_line)
                                yield exit_line
                                continue
                            elif event_type == "stdout":
                                line = obj.get("data", "")
                            elif event_type == "stderr":
                                raw_data = obj.get("data", "")
                                line = f"[STDERR] {raw_data}" if raw_data else ""
                            elif event_type == "error":
                                msg = obj.get("message", "") or obj.get("data", "")
                                # MCP reports "Unknown tool: <name>" when not registered
                                if msg and "Unknown tool" in msg:
                                    not_in_registry = True
                                line = f"[ERROR] {msg}" if msg else ""
                            elif event_type == "info":
                                line = obj.get("message", "") or obj.get("data", "")
                            else:
                                line = obj.get("data") or obj.get("message") or content
                        else:
                            line = content
                    except json.JSONDecodeError:
                        line = content
                    if line:
                        await self._emit_tool_line(tool_name, line)
                        yield line
                    # Check stop flag after each line
                    if self._stop_requested:
                        cancelled_line = f"[CANCELLED] Tool '{tool_name}' stopped by operator"
                        await self._emit_tool_line(tool_name, cancelled_line)
                        yield cancelled_line
                        await self._emit("subagent_tool_exit", {
                            "tool": tool_name, "exit_code": -2, "success": False, "cancelled": True,
                        })
                        return

            # If tool not in MCP registry, raise so caller falls back to local
            if not_in_registry:
                raise RuntimeError(f"Tool '{tool_name}' not in MCP registry")

            # Emit exit code event after stream closes
            if exit_code is not None:
                await self._emit("subagent_tool_exit", {
                    "tool": tool_name, "exit_code": exit_code, "success": exit_code == 0,
                })

        # ── Dispatch: local shell tools bypass MCP entirely ──────
        if tool_name.lower() in _LOCAL_SHELL_TOOLS:
            async for ln in _run_local_gen():
                yield ln
            return

        # ── Try MCP first; fall back to local subprocess on 400/connect error ──
        try:
            async for ln in _run_mcp_gen():
                yield ln

        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            logger.warning(
                "MCP tool '%s' returned HTTP %s — falling back to local execution",
                tool_name, status,
            )
            warn = (f"[MCP {status}] Tool '{tool_name}' not in MCP registry — "
                    f"running locally")
            await self._emit_tool_line(tool_name, warn)
            yield warn
            async for ln in _run_local_gen():
                yield ln

        except httpx.RequestError as exc:
            logger.warning("MCP connection error for '%s': %s — running locally", tool_name, exc)
            warn = f"[MCP OFFLINE] Cannot reach MCP — running '{tool_name}' locally"
            await self._emit_tool_line(tool_name, warn)
            yield warn
            async for ln in _run_local_gen():
                yield ln

        except RuntimeError as exc:
            # Tool not registered in MCP — run locally
            logger.warning("MCP: %s — falling back to local execution", exc)
            warn = f"[MCP UNREGISTERED] '{tool_name}' not in MCP registry — running locally"
            await self._emit_tool_line(tool_name, warn)
            yield warn
            async for ln in _run_local_gen():
                yield ln

    async def collect_tool(
        self,
        tool_name: str,
        target: str,
        options: Optional[dict] = None,
    ) -> str:
        """Run a tool and collect all output into a single string.

        Internally calls :meth:`run_tool` (so every line still triggers a WS
        event) and joins the lines with newlines.  A background watchdog fires
        ``tool_timeout_warning`` WS events if the tool exceeds its deadline
        (default 10 min); the deadline can be extended via :meth:`extend_tool`.

        Parameters
        ----------
        tool_name:
            MCP tool name.
        target:
            Scan target.
        options:
            Optional extra parameters.

        Returns
        -------
        str
            Full tool output as a single string.
        """
        # ── Watchdog setup ────────────────────────────────────────────────
        self._current_tool_name = tool_name
        self._tool_run_start    = time.monotonic()
        self._tool_deadline_sec = 600.0   # reset to 10 min for each tool call

        watchdog = asyncio.create_task(self._tool_watchdog(tool_name))
        try:
            lines: list[str] = []
            async for line in self.run_tool(tool_name, target, options):
                lines.append(line)
                if self._stop_requested:
                    break
            output = "\n".join(lines)
            self._tool_outputs[tool_name] = output
            return output
        finally:
            watchdog.cancel()
            try:
                await watchdog
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # Finding helpers
    # ------------------------------------------------------------------

    def parse_severity(self, text: str) -> str:
        """Infer a CVSS-like severity label from raw text.

        Searches ``text`` (case-insensitive) for known severity keywords and
        returns the highest matching severity.

        Parameters
        ----------
        text:
            Raw tool output or finding description to analyse.

        Returns
        -------
        str
            One of ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``,
            ``"INFO"``.
        """
        lower = text.lower()
        for keyword in _CRITICAL_KEYWORDS:
            if keyword in lower:
                return "CRITICAL"
        for keyword in _HIGH_KEYWORDS:
            if keyword in lower:
                return "HIGH"
        for keyword in _MEDIUM_KEYWORDS:
            if keyword in lower:
                return "MEDIUM"
        for keyword in _LOW_KEYWORDS:
            if keyword in lower:
                return "LOW"
        return "INFO"

    async def store_finding(self, finding: Finding) -> None:
        """Persist a Finding to MongoDB and emit a WebSocket event.

        The document is inserted into the ``findings`` collection with the
        current session_id attached. The finding is also appended to the
        in-memory list so it can be included in the final SubagentResult.

        Parameters
        ----------
        finding:
            The Finding object to persist.
        """
        self._findings.append(finding)
        doc = finding.to_dict()
        doc["session_id"] = self.session_id
        doc["agent"] = self.AGENT_NAME
        doc["subagent"] = self.SUBAGENT_NAME
        try:
            await self.db["findings"].insert_one(doc)
        except Exception as exc:  # noqa: BLE001
            logger.error("MongoDB insert failed for finding %s: %s", finding.finding_id, exc)
        await self._emit_finding(finding)

    # ------------------------------------------------------------------
    # Result persistence
    # ------------------------------------------------------------------

    async def _store_result(self, result: SubagentResult) -> None:
        """Persist the full SubagentResult to the ``subagent_results`` collection."""
        doc = result.to_dict()
        doc["agent"] = self.AGENT_NAME
        try:
            await self.db["subagent_results"].insert_one(doc)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "MongoDB insert failed for SubagentResult %s: %s",
                result.result_id,
                exc,
            )

    # ------------------------------------------------------------------
    # Public execution entry point
    # ------------------------------------------------------------------

    async def execute(self, **kwargs: Any) -> SubagentResult:
        """Invoke the subagent, wrapping run() with lifecycle events.

        Emits ``subagent_start``, calls :meth:`run`, emits
        ``subagent_complete`` (or ``subagent_error`` on exception), and
        persists the result to MongoDB.

        Returns
        -------
        SubagentResult
            The aggregated result from the run.
        """
        await self._emit_start()
        start_time = time.monotonic()
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=self.target,
        )
        try:
            # Pre-run RAG lookup — gives subagents tool command examples
            query = f"{self.SUBAGENT_NAME} {self.target} techniques commands"
            self._rag_hint = await self._kb_search(query, top_k=2)
            result = await self.run(self.target, **kwargs)
            result.session_id = self.session_id
            result.subagent_name = self.SUBAGENT_NAME
            result.target = self.target
            # Merge any findings accumulated via store_finding
            existing_ids = {f.finding_id for f in result.findings}
            for f in self._findings:
                if f.finding_id not in existing_ids:
                    result.findings.append(f)
            # Merge tool outputs
            for tool, output in self._tool_outputs.items():
                if tool not in result.tool_outputs:
                    result.tool_outputs[tool] = output
        except Exception as exc:  # noqa: BLE001
            error_msg = f"{type(exc).__name__}: {exc}"
            logger.exception("Subagent %s raised an error", self.SUBAGENT_NAME)
            result.error = error_msg
            result.findings = self._findings
            result.tool_outputs = self._tool_outputs
            await self._emit_error(error_msg)
        finally:
            result.duration_seconds = time.monotonic() - start_time
            if self._http_client and not self._http_client.is_closed:
                await self._http_client.aclose()

        await self._store_result(result)
        await self._emit_complete(result)
        return result

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> SubagentResult:
        """Execute this subagent's specific toolchain against *target*.

        Concrete subagents must implement this method. They should:

        - Call :meth:`run_tool` or :meth:`collect_tool` for each tool.
        - Call :meth:`store_finding` for each discovered finding.
        - Build and return a :class:`SubagentResult` containing all findings
          and tool output collected during the run.

        Parameters
        ----------
        target:
            The scan target (IP, hostname, CIDR, URL, etc.).
        **kwargs:
            Phase-specific keyword arguments forwarded by the orchestrator.

        Returns
        -------
        SubagentResult
            Aggregated result for this subagent invocation.
        """
        ...  # pragma: no cover

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"agent={self.AGENT_NAME!r} "
            f"subagent={self.SUBAGENT_NAME!r} "
            f"session={self.session_id!r} "
            f"target={self.target!r}>"
        )
