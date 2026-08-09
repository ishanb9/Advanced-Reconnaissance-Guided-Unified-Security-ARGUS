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

import inspect
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, List, Optional

logger = logging.getLogger(__name__)


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
    args_signature: str       = ""    # Recommendation D — fine-grained ban key
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
            "args_signature": self.args_signature,
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
            args_signature = d.get("args_signature", ""),
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
        on_record=None,
    ) -> None:
        self._session_id  = session_id
        self._db_store    = db_store_fn
        self._db_load     = db_load_fn
        # [79] Optional async callback fired when a failure is recorded, so the
        # UI's "Negative Memory" panel (which consumes a negative_memory_added WS
        # event nothing ever emitted) can populate live.
        self._on_record   = on_record
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

        Recommendation D — keys now include an *args_signature* derived
        from the args string (URL path, parameter name, wordlist token,
        payload family, port).  Failure on
        ``sqlmap -u http://x/login.php?user=foo`` now bans only that
        specific (tool, service, sig) triple — leaving sqlmap free to
        try ``--data`` POST, a different parameter, a different
        endpoint, or a different wordlist.

        The legacy ``(tool, target_service)`` key is still tracked under
        ``self._coarse_index`` so callers that just want a "has this
        general combo been tried at all?" check can still get it.

        Parameters
        ----------
        tool:           Tool name, e.g. "sqlmap", "hydra", "metasploit".
        args:           Command arguments used (for audit trail).
        target_service: Service identifier, e.g. "http:80", "smb:445".
        failure_reason: Short reason string from output parsing.
        evidence:       Raw output snippet (truncated to 500 chars).
        hypothesis_id:  ID of the hypothesis this attempt was testing.
        host:           Target host IP/hostname.
        """
        sig  = self._args_signature(tool, args)
        key  = f"{tool}:{target_service}:{sig}"
        coarse_key = f"{tool}:{target_service}"
        self._index[key] = self._index.get(key, 0) + 1
        if not hasattr(self, "_coarse_index"):
            self._coarse_index = {}
        self._coarse_index[coarse_key] = self._coarse_index.get(coarse_key, 0) + 1

        # Find existing record or create new
        existing = next(
            (a for a in self._attempts
             if a.tool == tool
             and a.target_service == target_service
             and getattr(a, "args_signature", "") == sig),
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
            try:
                attempt.args_signature = sig    # type: ignore[attr-defined]
            except Exception:
                pass
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

        # [79] Notify the live UI (best-effort; never blocks the record path).
        # Best-effort must NOT mean invisible: a broken emitter used to fail here in
        # total silence, so the "Negative Memory" panel simply stayed empty with no
        # diagnostic anywhere — the same silent-swallow pattern that let a dead engine
        # look like a clean scan.  Now: accept sync OR async callbacks, and LOG the
        # failure (first one at WARNING, then throttled) while still never raising.
        if self._on_record is not None:
            try:
                _res = self._on_record({
                    "tool": tool, "target_service": target_service,
                    "failure_reason": failure_reason, "host": host or ""})
                if inspect.isawaitable(_res):
                    await _res
            except Exception as _cb_exc:                      # noqa: BLE001
                self._on_record_errors = getattr(self, "_on_record_errors", 0) + 1
                _n = self._on_record_errors
                _msg = ("[negative_memory] on_record callback failed (#%d) — the "
                        "negative_memory_added UI event was NOT delivered: %s: %s")
                if _n == 1 or _n % 20 == 0:
                    logger.warning(_msg, _n, type(_cb_exc).__name__, _cb_exc)
                else:
                    logger.debug(_msg, _n, type(_cb_exc).__name__, _cb_exc)

        return attempt

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    # ── B-9 — success memory (mirrors negative-memory shape) ──────────
    # Tracks (tool, service, args_signature) tuples that have already run
    # successfully so primer dispatchers don't re-fire a step the LLM
    # already ran.  Stored in-memory only — successes are durable in the
    # findings store; we only need this lookup index per session.
    _success_index: Dict[str, int] = None  # type: ignore  (init in __init__ below)

    def record_success(
        self,
        tool:           str,
        target_service: str,
        args:           Optional[str] = None,
    ) -> None:
        """B-9 — Record a successful (tool, service[, args]) execution.

        Mirrors the dedup keys used by ``has_failed_before`` so primer
        dispatchers can call ``has_succeeded_before`` to skip steps the
        LLM-driven path already executed successfully.
        """
        if not hasattr(self, "_success_index") or self._success_index is None:
            self._success_index = {}   # lazy-init for back-compat with old instances
        sig = self._args_signature(tool, args or "") if args is not None else ""
        fine_key = f"{tool}:{target_service}:{sig}" if sig else f"{tool}:{target_service}"
        self._success_index[fine_key] = self._success_index.get(fine_key, 0) + 1
        # Also record the coarse pair so `has_succeeded_before(args=None)` works.
        coarse_key = f"{tool}:{target_service}"
        self._success_index[coarse_key] = self._success_index.get(coarse_key, 0) + 1

    def has_succeeded_before(
        self,
        tool:           str,
        target_service: str,
        args:           Optional[str] = None,
    ) -> bool:
        """B-9 — return True when this (tool, service[, args]) tuple has
        already executed successfully in the current session.  Primer
        dispatchers consult this before proposing a step that the LLM
        path may have already run successfully."""
        if not hasattr(self, "_success_index") or self._success_index is None:
            return False
        if args is not None:
            sig = self._args_signature(tool, args)
            fine_key = f"{tool}:{target_service}:{sig}"
            if fine_key in self._success_index:
                return True
        return f"{tool}:{target_service}" in self._success_index

    def has_failed_before(
        self,
        tool:           str,
        target_service: str,
        args:           Optional[str] = None,
    ) -> bool:
        """
        Recommendation D — refined ban semantics.

        * If ``args`` is provided, returns True only when that exact
          *(tool, target_service, args_signature)* triple has failed —
          letting sqlmap try a different parameter / wordlist after one
          failure on a single endpoint.
        * If ``args`` is None, falls back to the legacy coarse-grained
          check (any failure on the (tool, service) pair).  Callers that
          do their own redundancy bookkeeping can use the coarse form;
          the DecisionEngine should always pass ``args``.
        * Even with ``args``, after ``COARSE_BAN_THRESHOLD`` total
          failures on the (tool, service) pair we fall back to a ban,
          so an LLM that keeps re-proposing variants of the same broken
          attack still gets stopped eventually.
        """
        if args is not None:
            sig = self._args_signature(tool, args)
            fine_key = f"{tool}:{target_service}:{sig}"
            if fine_key in self._index:
                return True
            # Soft cap on coarse failures — after N distinct args have
            # all failed against the same (tool, service), assume the
            # service is genuinely unreachable for that tool family.
            if hasattr(self, "_coarse_index"):
                if self._coarse_index.get(f"{tool}:{target_service}", 0) >= self.COARSE_BAN_THRESHOLD:
                    return True
            return False
        return f"{tool}:{target_service}" in (
            getattr(self, "_coarse_index", None) or self._index
        )

    def attempt_count(
        self,
        tool:           str,
        target_service: str,
        args:           Optional[str] = None,
    ) -> int:
        """Return how many times this (tool, service[, args_signature]) has been tried."""
        if args is not None:
            sig = self._args_signature(tool, args)
            return self._index.get(f"{tool}:{target_service}:{sig}", 0)
        return (getattr(self, "_coarse_index", None) or self._index).get(
            f"{tool}:{target_service}", 0
        )

    # Coarse failure threshold beyond which we ban the whole (tool, service)
    # pair regardless of args_signature — prevents the LLM from cycling
    # through pointless variants forever.
    COARSE_BAN_THRESHOLD = 5

    @staticmethod
    def _args_signature(tool: str, args: str) -> str:
        """Compute a stable, low-cardinality signature of ``args``.

        The goal is to bucket "the same attack with cosmetic differences"
        together while keeping "different attack on the same service"
        distinct.  Tracked tokens, in order of priority:

        * ``-u <url>`` / ``-h <host>`` path component
        * URL query parameter NAME (``?id=…`` → ``param=id``)
        * ``--data`` mode (POST vs GET)
        * Wordlist filename (basename only, no path)
        * Payload family (e.g. ``windows/x64/meterpreter`` → ``meterpreter``)
        * Port number from ``:NNNN`` if present
        * SQLmap level/risk; hydra/medusa thread; nmap script family
        """
        if not args:
            return f"{tool}:noargs"

        import re as _re
        a = (args or "").lower()
        bits: List[str] = []

        # URL path (sqlmap -u, curl -X, gobuster -u)
        m = _re.search(r"https?://[^/\s]+(/[^\s?#]*)", a)
        if m:
            path = m.group(1).strip("/").split("?")[0]
            if path:
                # Keep only the last 2 path segments — cosmetic ones flap.
                segments = [s for s in path.split("/") if s][-2:]
                if segments:
                    bits.append("path=" + ".".join(segments))

        # Query parameter NAME
        for m in _re.finditer(r"[?&]([a-z_][a-z0-9_]*)=", a):
            bits.append(f"param={m.group(1)}")
            break  # one is enough

        # POST vs GET
        if "--data" in a or " -X post" in a or "post-form" in a:
            bits.append("method=post")

        # Wordlist basename
        m = _re.search(r"(?:-w|-W|-P|-L|--wordlist[= ])\s*(\S+)", a)
        if m:
            wl = m.group(1).split("/")[-1].split("\\")[-1]
            bits.append(f"wordlist={wl[:32]}")

        # Payload family
        m = _re.search(r"(?:-p|--payload\s+|set\s+payload\s+)\s*(\S+)", a)
        if m:
            payload = m.group(1)
            # Reduce to last segment (e.g. windows/x64/meterpreter/reverse_tcp → reverse_tcp)
            tail = payload.rstrip("/").rsplit("/", 1)[-1]
            bits.append(f"payload={tail[:32]}")

        # Port
        m = _re.search(r":(\d{2,5})\b", a)
        if m:
            bits.append(f"port={m.group(1)}")

        # SQLmap risk/level
        for flag, name in (("--level", "level"), ("--risk", "risk")):
            m = _re.search(rf"{flag}[= ]\s*(\d)", a)
            if m:
                bits.append(f"{name}={m.group(1)}")

        # NSE script family
        m = _re.search(r"--script[= ]\s*([a-z][a-z0-9-]*)", a)
        if m:
            bits.append(f"nse={m.group(1)}")

        # MSF module
        m = _re.search(r"\b(use|exploit)\s+(?:exploit|auxiliary|post)/([a-z0-9_/-]+)", a)
        if m:
            mod = m.group(2).split("/")[-1][:40]
            bits.append(f"module={mod}")

        if not bits:
            # Fallback: hash a short prefix so different arg-strings still
            # bucket distinctly, but cosmetic spacing differences fold.
            import hashlib
            digest = hashlib.md5(a[:200].encode("utf-8", "replace")).hexdigest()[:10]
            return f"h={digest}"

        return "|".join(sorted(bits))

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
