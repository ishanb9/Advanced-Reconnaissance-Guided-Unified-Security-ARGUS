"""
operator_interrupts.py - in-flight directive channel from operator -> agents.

Why this exists
---------------
ARGUS UI shows what the master is doing.  It doesn't let the operator
redirect.  When the operator notices the master is wasting time on SMB
when the obvious target is the exposed Spring app, today they have to
stop the scan and restart with new operator-notes.  That throws away
all the recon state.

This module is the missing input channel.  WebSocket clients can send
operator_directive messages mid-scan; the master agent and reasoning
loop check for queued directives at every iteration boundary and
honour them.

Directive types
---------------
focus_phase     {phase: "recon|vuln|web|exploit|privesc|..."}
                Bias the next planning iteration toward this phase.

skip_phase      {phase: "..."}
                Mark the phase complete without running it.

stop_tool       {tool: "..."}
                Cancel the current tool dispatch and don't re-propose
                it for this scan (adds to ToolBlacklist).

focus_host      {host: "10.0.0.1"}
                In multi-host scans, prioritise this host.

inject_hint     {hint: "the dev said it's a Spring app on port 8080"}
                Free-form hint added to the next LLM planning context.

pause           {}
                Suspend agent dispatch until resume directive.

resume          {}
                Resume after pause.

force_playbook  {playbook_id: "spring_actuator", target: "...", port: 8080}
                Manually trigger a specific playbook regardless of trigger match.

skip_meta       {}
                Disable Expert/MasterChecker/IssueValidator reviews
                for the remainder of this scan (operator decides
                they're slowing things down).

set_opsec       {profile: "stealth"}
                Hot-swap the OPSEC profile mid-scan.

WS message format
-----------------
Client -> Server:
  {"type": "operator_directive",
   "session_id": "...",
   "directive": "focus_phase",
   "payload": {"phase": "exploit"}}

Server emits acknowledgement:
  {"type": "operator_directive_ack",
   "directive": "focus_phase",
   "queued": true,
   "directive_id": "..."}

Server emits when consumed:
  {"type": "operator_directive_consumed",
   "directive_id": "...",
   "outcome": "applied" | "ignored" | "error",
   "detail": "..."}
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)


VALID_DIRECTIVES = frozenset({
    "focus_phase",
    "skip_phase",
    "stop_tool",
    "focus_host",
    "inject_hint",
    "pause",
    "resume",
    "force_playbook",
    "skip_meta",
    "set_opsec",
})


@dataclass
class Directive:
    directive:   str
    payload:     Dict[str, Any] = field(default_factory=dict)
    session_id:  Optional[str]  = None
    directive_id: str            = field(default_factory=lambda: str(uuid.uuid4())[:12])
    queued_at:   float           = field(default_factory=time.time)
    consumed_at: Optional[float] = None
    outcome:     Optional[str]   = None      # applied / ignored / error
    detail:      Optional[str]   = None


class OperatorDirectiveQueue:
    """Per-session FIFO of pending operator directives + sticky flags.

    The queue is process-wide singleton, keyed by session_id.  Master
    agents and reasoning loops call drain() at every iteration boundary;
    UI clients post via the agent_server WS handler.

    Sticky state (pause, hints, opsec_profile) survives drain() calls
    so the agent can read current state any time without consuming.
    """

    def __init__(self) -> None:
        self._queues:   Dict[str, Deque[Directive]] = {}
        self._sticky:   Dict[str, Dict[str, Any]] = {}
        self._listeners: Dict[str, List[Callable[[Directive], Awaitable[None]]]] = {}
        self._lock = asyncio.Lock()

    # ── Submit (called by agent_server WS handler) ─────────────────────
    async def submit(
        self,
        directive: str,
        payload:   Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        emit:       Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
    ) -> Directive:
        """Add a directive to the session's queue.  Returns the Directive
        object so the caller can echo back the directive_id."""
        if directive not in VALID_DIRECTIVES:
            d = Directive(directive=directive, payload=payload or {},
                          session_id=session_id, outcome="error",
                          detail=f"unknown directive: {directive}")
            d.consumed_at = time.time()
            if emit is not None:
                try:
                    await emit("operator_directive_ack", {
                        "directive_id": d.directive_id,
                        "directive":    directive,
                        "queued":       False,
                        "error":        d.detail,
                    })
                except Exception:
                    pass
            return d
        d = Directive(directive=directive, payload=dict(payload or {}),
                      session_id=session_id)
        async with self._lock:
            self._queues.setdefault(session_id or "", deque()).append(d)
            # Update sticky state mirrors
            sticky = self._sticky.setdefault(session_id or "", {})
            if directive == "pause":
                sticky["paused"] = True
            elif directive == "resume":
                sticky["paused"] = False
            elif directive == "skip_meta":
                sticky["skip_meta"] = True
            elif directive == "set_opsec":
                sticky["opsec_profile"] = str(payload.get("profile") or "fast").lower()
            elif directive == "inject_hint":
                sticky.setdefault("hints", []).append(str(payload.get("hint") or ""))
            elif directive == "focus_phase":
                sticky["focus_phase"] = str(payload.get("phase") or "")
            elif directive == "focus_host":
                sticky["focus_host"] = str(payload.get("host") or "")
        if emit is not None:
            try:
                await emit("operator_directive_ack", {
                    "directive_id": d.directive_id,
                    "directive":    directive,
                    "queued":       True,
                    "session_id":   session_id,
                })
            except Exception:
                pass
        return d

    # ── Drain (called by master / reasoning loop) ──────────────────────
    async def drain(
        self,
        session_id: str,
        emit: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
    ) -> List[Directive]:
        """Pop ALL pending directives for this session.

        Each returned Directive's `outcome` field starts None; the caller
        is responsible for marking it "applied" / "ignored" / "error"
        before discarding.
        """
        async with self._lock:
            q = self._queues.get(session_id) or deque()
            drained = list(q)
            q.clear()
        return drained

    # ── Sticky read accessors ──────────────────────────────────────────
    def is_paused(self, session_id: str) -> bool:
        return bool(self._sticky.get(session_id, {}).get("paused"))

    def meta_disabled(self, session_id: str) -> bool:
        return bool(self._sticky.get(session_id, {}).get("skip_meta"))

    def current_opsec(self, session_id: str) -> Optional[str]:
        return self._sticky.get(session_id, {}).get("opsec_profile")

    def hints(self, session_id: str) -> List[str]:
        return list(self._sticky.get(session_id, {}).get("hints") or [])

    def focus_phase(self, session_id: str) -> Optional[str]:
        return self._sticky.get(session_id, {}).get("focus_phase") or None

    def focus_host(self, session_id: str) -> Optional[str]:
        return self._sticky.get(session_id, {}).get("focus_host") or None

    # ── Mark consumed ──────────────────────────────────────────────────
    async def mark_consumed(
        self,
        d: Directive,
        outcome: str,
        detail: str = "",
        emit: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
    ) -> None:
        d.consumed_at = time.time()
        d.outcome     = outcome
        d.detail      = detail
        if emit is not None:
            try:
                await emit("operator_directive_consumed", {
                    "directive_id": d.directive_id,
                    "directive":    d.directive,
                    "outcome":      outcome,
                    "detail":       detail,
                })
            except Exception:
                pass

    # ── Wait helpers ───────────────────────────────────────────────────
    async def wait_while_paused(self, session_id: str, poll_sec: float = 1.0) -> None:
        """Block until the session is not paused.  Use at iteration boundaries."""
        while self.is_paused(session_id):
            await asyncio.sleep(poll_sec)


_QUEUE: Optional[OperatorDirectiveQueue] = None


def get_queue() -> OperatorDirectiveQueue:
    global _QUEUE
    if _QUEUE is None:
        _QUEUE = OperatorDirectiveQueue()
    return _QUEUE


__all__ = [
    "Directive", "OperatorDirectiveQueue", "get_queue",
    "VALID_DIRECTIVES",
]
