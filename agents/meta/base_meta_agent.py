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

        Now provider-aware: routes through utils.llm_providers.get_provider()
        so the same retry / circuit-breaker / model-selection logic that
        applies to MasterAgent.think() applies to meta-agents too.  Before
        this rewrite, meta-agents hard-coded Ollama at OLLAMA_URL and could
        not see Anthropic / OpenAI-compat / Gemini / Claude Code backends —
        meaning a transient blip on Ollama silently disabled every meta-
        agent for the rest of the scan.

        Behavior:
          - Appends user message to _history before calling the LLM.
          - Streams tokens via provider.stream(); emits meta_agent_thinking.
          - Up to 2 retries with exponential back-off on transient errors.
          - Appends assistant response to _history after.
          - Enforces MAX_HISTORY_TURNS sliding window (drops oldest pairs).
          - Returns the full response string, or "" on persistent failure.
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

        # ── Provider-aware streaming with retry ─────────────────────
        # Routes through utils.llm_providers so the meta-agent picks up
        # whichever backend the operator configured (Ollama by default;
        # Anthropic / OpenAI-compat / Gemini / Claude Code if env vars
        # are set).  Two retries with exponential back-off so a single
        # transient connect error doesn't silently disable the entire
        # meta-agent layer.
        from utils.llm_providers import get_provider

        MAX_RETRIES = 2
        content     = ""
        last_exc:   Optional[BaseException] = None
        status_code_msg = ""

        for attempt in range(1, MAX_RETRIES + 1):
            provider = get_provider()
            tokens: List[str] = []
            try:
                async for tok in provider.stream(messages, timeout=LLM_THINK_TIMEOUT):
                    if self._stop_requested:
                        break
                    if tok:
                        tokens.append(tok)
                        await self._emit("meta_agent_thinking", {
                            "agent":      self._agent_name_str,
                            "phase":      self._current_phase,
                            "chunk":      tok,
                            "thought_id": thought_id,
                        })
                content = "".join(tokens)
                if content:
                    last_exc = None
                    break
                # Empty content from provider — treat as failure and retry
                last_exc = RuntimeError("provider returned empty response")
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                status_code = exc.response.status_code
                if status_code == 404:
                    status_code_msg = (
                        f"Model '{provider.model}' not found on {provider.name}"
                    )
                else:
                    try:
                        body = exc.response.text[:200]
                    except Exception:
                        body = ""
                    status_code_msg = f"{provider.name} HTTP {status_code}: {body}"
                logger.error(
                    "[%s] LLM HTTP error (attempt %d/%d): %s",
                    self._agent_name_str, attempt, MAX_RETRIES, status_code_msg,
                )
                # 4xx errors won't fix on retry; bail immediately
                if 400 <= status_code < 500 and status_code != 429:
                    break
            except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadTimeout) as exc:
                last_exc = exc
                logger.warning(
                    "[%s] LLM transient error (attempt %d/%d): %s",
                    self._agent_name_str, attempt, MAX_RETRIES, exc,
                )
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "[%s] LLM call failed (attempt %d/%d): %s",
                    self._agent_name_str, attempt, MAX_RETRIES, exc,
                )

            # Back-off before the next attempt
            if attempt < MAX_RETRIES:
                await asyncio.sleep(2 ** attempt)

        if not content:
            # All attempts failed.  Pop the dangling user turn so history
            # stays consistent, emit status, return empty.
            if self._history and self._history[-1]["role"] == "user":
                self._history.pop()
            if status_code_msg:
                await self._emit("llm_status", {
                    "available": False,
                    "model":     provider.model,
                    "provider":  provider.name,
                    "message":   status_code_msg,
                    "error":     "meta_agent_llm_failed",
                })
            await self._emit("meta_agent_status", {
                "agent":  self._agent_name_str,
                "status": "idle",
                "phase":  self._current_phase,
            })
            return ""

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
