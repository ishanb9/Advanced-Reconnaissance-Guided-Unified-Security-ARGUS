"""
base_meta_agent.py — Abstract base for LLM-powered auditor agents.

Meta-agents maintain a persistent conversation thread for the full scan
duration and return Correction objects. They do NOT execute tools.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from abc import abstractmethod
from typing import Any, Dict, List, Optional

import httpx

from agents.base_agent import BaseAgent, OLLAMA_URL, MODEL_NAME, LLM_THINK_TIMEOUT
from agents.meta.correction import Correction
from db.schemas import AgentName, AgentStatus

logger = logging.getLogger(__name__)

# Maximum conversation turns kept in history (user+assistant pairs count as 2).
# Each "turn" is one user message + one assistant message.
MAX_HISTORY_TURNS: int = int(os.environ.get("ARGUS_META_MAX_HISTORY", "50"))


class BaseMetaAgent(BaseAgent):
    """
    Abstract base for meta-agents (MasterChecker, IssueValidator).

    Adds on top of BaseAgent:
    - _history: persistent sliding-window conversation thread
    - think_with_history(): LLM call that maintains full thread context
    - emit_correction(): persist Correction to MongoDB + WS broadcast
    - reset(): clear history for scan restart

    Subclasses MUST implement:
    - _build_system_prompt() -> str
    - evaluate(**kwargs) -> List[Correction]

    Subclasses MUST NOT call run_tool() or collect_tool().
    """

    def __init__(
        self,
        name:       AgentName,
        broadcast:  Optional[Any]  = None,
        session_id: Optional[str]  = None,
        db_conn:    Optional[Any]  = None,
        enabled:    bool           = True,
    ):
        super().__init__(name=name, broadcast=broadcast)
        self._session_id        = session_id
        self._db                = db_conn
        self._enabled:    bool             = enabled
        self._history:    List[Dict]       = []   # [{role, content}, ...]
        self._thought_counter: int         = 0
        self._current_phase:   str         = ""

    # ── Name helper ────────────────────────────────────────────────────────
    @property
    def _agent_name_str(self) -> str:
        """Return the lowercase string value of the agent name (e.g. 'master_checker').

        Using ``self._agent_name_str`` on a regular ``Enum`` yields ``'AgentName.MASTER_CHECKER'``,
        which breaks frontend routing that inspects the agent identifier.
        This helper always returns the underlying ``.value`` when available.
        """
        n = self.name
        return getattr(n, "value", None) or str(n)

    # ── Abstract interface ─────────────────────────────────────────────────

    @abstractmethod
    def _build_system_prompt(self) -> str:
        """Return system prompt defining this agent's persona and instructions."""
        ...

    @abstractmethod
    async def evaluate(self, **kwargs) -> List[Correction]:
        """Primary evaluation entry point. Subclasses implement their logic."""
        ...

    # ── Prevent tool execution ─────────────────────────────────────────────

    async def run(self, session_id: str, target: str, **kwargs) -> Dict:
        raise NotImplementedError(
            f"{self.__class__.__name__} is not invoked via run(). Use evaluate()."
        )

    # ── Persistent conversation ────────────────────────────────────────────

    async def think_with_history(self, prompt: str) -> str:
        """
        Send *prompt* to the LLM as the next turn in the persistent thread.

        - Appends user message to _history before calling Ollama.
        - Streams tokens; emits meta_agent_thinking per chunk.
        - Appends assistant response to _history after.
        - Enforces MAX_HISTORY_TURNS sliding window (drops oldest pairs).
        - Returns the full response string, or "" on error/LLM offline.
        """
        if not self._enabled:
            return ""

        # Reuse BaseAgent availability gate
        if not self._llm_available:
            await self.check_llm_available()
            if not self._llm_available:
                logger.warning("[%s] LLM unavailable — skipping evaluation", self._agent_name_str)
                return ""

        # Append user turn to history before calling LLM
        self._history.append({"role": "user", "content": prompt})

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            *self._history,
        ]

        self._thought_counter += 1
        thought_id = f"{self._agent_name_str}_{self._thought_counter}"

        await self._emit("meta_agent_status", {
            "agent":  self._agent_name_str,
            "status": "thinking",
            "phase":  self._current_phase,
        })

        tokens: List[str] = []
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=15, read=LLM_THINK_TIMEOUT, write=30, pool=10
                )
            ) as client:
                async with client.stream(
                    "POST",
                    f"{OLLAMA_URL}/api/chat",
                    json={"model": MODEL_NAME, "messages": messages, "stream": True},
                ) as resp:
                    resp.raise_for_status()
                    async for raw_line in resp.aiter_lines():
                        if self._stop_requested:
                            break
                        if not raw_line.strip():
                            continue
                        try:
                            chunk   = json.loads(raw_line)
                            tok     = chunk.get("message", {}).get("content", "")
                            if tok:
                                tokens.append(tok)
                                await self._emit("meta_agent_thinking", {
                                    "agent":      self._agent_name_str,
                                    "phase":      self._current_phase,
                                    "chunk":      tok,
                                    "thought_id": thought_id,
                                })
                            if chunk.get("done"):
                                break
                        except (json.JSONDecodeError, KeyError):
                            pass

        except Exception as exc:
            logger.warning("[%s] LLM call failed: %s", self._agent_name_str, exc)
            # Remove the dangling user turn so history stays consistent
            if self._history and self._history[-1]["role"] == "user":
                self._history.pop()
            # Always return to idle so the frontend status dot doesn't get stuck
            await self._emit("meta_agent_status", {
                "agent":  self._agent_name_str,
                "status": "idle",
                "phase":  self._current_phase,
            })
            return ""

        content = "".join(tokens)

        # Append assistant turn
        self._history.append({"role": "assistant", "content": content})

        # Sliding window: MAX_HISTORY_TURNS pairs = MAX_HISTORY_TURNS*2 messages
        max_msgs = MAX_HISTORY_TURNS * 2
        if len(self._history) > max_msgs:
            self._history = self._history[-max_msgs:]

        await self._emit("meta_agent_status", {
            "agent":  self._agent_name_str,
            "status": "idle",
            "phase":  self._current_phase,
        })

        return content

    # ── Correction output ──────────────────────────────────────────────────

    async def emit_correction(self, correction: Correction) -> None:
        """Persist *correction* to MongoDB collection 'meta_corrections' and WS-broadcast it."""
        try:
            if self._db is not None:
                await self._db["meta_corrections"].insert_one(correction.to_dict())
        except Exception as exc:
            logger.warning("[%s] DB persist failed for correction: %s", self._agent_name_str, exc)

        await self._emit("meta_correction", correction.to_dict())

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear conversation history and reset state. Call on scan restart."""
        self._history.clear()
        self._thought_counter = 0
        self._current_phase   = ""

    def set_session(self, session_id: str) -> None:
        """Update session ID (e.g. after a scan restart)."""
        self._session_id = session_id
