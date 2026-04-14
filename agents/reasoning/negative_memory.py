"""
agents/reasoning/negative_memory.py

Tracks every failed exploitation attempt within a session so the
HypothesisEngine can explicitly avoid re-proposing the same dead ends.

Key contract
------------
  record_failure()       — call after any tool execution that did not
                           advance the hypothesis.
  has_failed_before()    — quick O(1) check used by DecisionEngine.
  to_context_block()     — formatted string injected into LLM prompts so
                           the model never proposes already-exhausted paths.
  to_dict_list()         — serialisation for checkpoint intel_snapshot.
  load_from_db()         — restore state on session resume.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, List, Optional


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class FailedAttempt:
    """One record for a tool+service combination that was tried and failed."""
    attempt_id:     str
    tool:           str
    args:           str
    target_service: str       # e.g. "http:80", "ssh:22", "smb:445"
    failure_reason: str       # human-readable reason from tool output
    evidence:       str       # raw output snippet confirming failure (max 500 chars)
    hypothesis_id:  str       # which hypothesis this attempt was testing
    attempt_count:  int       = 1
    session_id:     str       = ""
    created_at:     str       = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "attempt_id":     self.attempt_id,
            "tool":           self.tool,
            "args":           self.args,
            "target_service": self.target_service,
            "failure_reason": self.failure_reason,
            "evidence":       self.evidence,
            "hypothesis_id":  self.hypothesis_id,
            "attempt_count":  self.attempt_count,
            "session_id":     self.session_id,
            "created_at":     self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FailedAttempt":
        return cls(
            attempt_id     = d.get("attempt_id", str(uuid.uuid4())),
            tool           = d.get("tool", ""),
            args           = d.get("args", ""),
            target_service = d.get("target_service", ""),
            failure_reason = d.get("failure_reason", ""),
            evidence       = d.get("evidence", ""),
            hypothesis_id  = d.get("hypothesis_id", ""),
            attempt_count  = d.get("attempt_count", 1),
            session_id     = d.get("session_id", ""),
            created_at     = d.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


# ---------------------------------------------------------------------------
# NegativeMemory
# ---------------------------------------------------------------------------

class NegativeMemory:
    """
    In-memory + MongoDB-backed registry of failed penetration attempts.

    The store and load callables are injected at construction time so this
    class has zero direct dependency on the db layer (testable in isolation).

    Parameters
    ----------
    session_id:
        The active pentest session identifier.
    db_store_fn:
        Coroutine callable matching db.store_negative_memory signature.
    db_load_fn:
        Coroutine callable matching db.load_negative_memory signature.
    """

    # Maximum number of failure entries to include in LLM context block.
    _MAX_CONTEXT_ENTRIES: int = 12

    def __init__(
        self,
        session_id: str,
        db_store_fn: Callable[..., Coroutine],
        db_load_fn:  Callable[..., Coroutine],
    ) -> None:
        self._session_id  = session_id
        self._db_store    = db_store_fn
        self._db_load     = db_load_fn
        self._attempts:   List[FailedAttempt] = []
        # Fast dedup index: "tool:target_service" → attempt count
        self._index:      dict[str, int] = {}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def load_from_db(self) -> None:
        """
        Populate in-memory state from MongoDB.
        Call this once during session resume before any other method.
        """
        try:
            docs = await self._db_load(self._session_id)
            for doc in docs:
                attempt = FailedAttempt.from_dict(doc)
                attempt.session_id = self._session_id
                self._attempts.append(attempt)
                key = f"{attempt.tool}:{attempt.target_service}"
                self._index[key] = attempt.attempt_count
        except Exception:
            pass  # non-fatal; start with empty memory

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    async def record_failure(
        self,
        tool:           str,
        args:           str,
        target_service: str,
        failure_reason: str,
        evidence:       str       = "",
        hypothesis_id:  str       = "",
        host:           str       = "",
    ) -> FailedAttempt:
        """
        Record a failed attempt.

        If the same (tool, target_service) has been tried before, increments
        the attempt_count instead of creating a duplicate entry.

        Parameters
        ----------
        tool:           Tool name, e.g. "sqlmap", "hydra", "metasploit".
        args:           Command arguments used (for audit trail).
        target_service: Service identifier, e.g. "http:80", "smb:445".
        failure_reason: Short reason string from output parsing.
        evidence:       Raw output snippet (truncated to 500 chars).
        hypothesis_id:  ID of the hypothesis this attempt was testing.
        host:           Target host IP/hostname.

        Returns
        -------
        FailedAttempt
            The created or updated attempt record.
        """
        key = f"{tool}:{target_service}"
        self._index[key] = self._index.get(key, 0) + 1

        # Find existing record or create new
        existing = next(
            (a for a in self._attempts
             if a.tool == tool and a.target_service == target_service),
            None
        )

        if existing:
            existing.attempt_count = self._index[key]
            existing.failure_reason = failure_reason
            existing.evidence       = (evidence or "")[:500]
            attempt = existing
        else:
            attempt = FailedAttempt(
                attempt_id     = str(uuid.uuid4()),
                tool           = tool,
                args           = args,
                target_service = target_service,
                failure_reason = failure_reason,
                evidence       = (evidence or "")[:500],
                hypothesis_id  = hypothesis_id,
                attempt_count  = 1,
                session_id     = self._session_id,
            )
            self._attempts.append(attempt)

        # Persist asynchronously (non-blocking; failure is non-fatal)
        try:
            await self._db_store(
                session_id     = self._session_id,
                host           = host or "",
                attempt_id     = attempt.attempt_id,
                tool           = tool,
                args           = args,
                target_service = target_service,
                failure_reason = failure_reason,
                evidence       = evidence,
                hypothesis_id  = hypothesis_id,
            )
        except Exception:
            pass

        return attempt

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def has_failed_before(self, tool: str, target_service: str) -> bool:
        """
        Return True if this (tool, target_service) combination has failed
        at least once this session.

        Used by DecisionEngine as a fast pre-flight check before spending
        tokens on a plan that is known to not work.
        """
        return f"{tool}:{target_service}" in self._index

    def attempt_count(self, tool: str, target_service: str) -> int:
        """Return how many times a specific (tool, service) has been tried."""
        return self._index.get(f"{tool}:{target_service}", 0)

    def get_all(self) -> List[FailedAttempt]:
        """Return all recorded failed attempts."""
        return list(self._attempts)

    def to_context_block(self, max_entries: int = _MAX_CONTEXT_ENTRIES) -> str:
        """
        Produce a compact text block for LLM context injection.

        The block explicitly instructs the model NOT to repeat any of the
        listed tool/service combinations unless new evidence appears.

        Returns empty string if no failures have been recorded.
        """
        if not self._attempts:
            return ""

        # Sort by attempt_count descending (most-tried first)
        sorted_attempts = sorted(
            self._attempts,
            key=lambda a: a.attempt_count,
            reverse=True,
        )[:max_entries]

        lines = [
            "=== FAILED ATTEMPTS — DO NOT REPEAT WITHOUT NEW EVIDENCE ===",
        ]
        for a in sorted_attempts:
            count_str = f" (×{a.attempt_count})" if a.attempt_count > 1 else ""
            lines.append(
                f"  FAILED{count_str}: {a.tool} on {a.target_service} — "
                f"{a.failure_reason}"
            )
        lines.append(
            "Do NOT propose any of the above tool+service combinations again "
            "unless you have new evidence that changes the situation."
        )
        lines.append("=== END FAILED ATTEMPTS ===")
        return "\n".join(lines)

    def to_dict_list(self) -> List[dict]:
        """Serialise all attempts for checkpoint intel_snapshot storage."""
        return [a.to_dict() for a in self._attempts]

    def __len__(self) -> int:
        return len(self._attempts)

    def __repr__(self) -> str:
        return (
            f"<NegativeMemory session={self._session_id!r} "
            f"failures={len(self._attempts)}>"
        )
