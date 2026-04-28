"""Information-entropy abandonment helper for tool watchdogs.

Improvement #6 — many pentest tools degenerate into low-information output
streams: progress bars, repeated "scanning…" status lines, identical
"connection refused" rejections, etc.  Continuing to wait the full
deadline burns time and obscures more useful signals.

This module provides :class:`EntropySampler`, a small rolling window that
measures how *informative* a tool's recent output is.  When the signal
collapses (very few unique lines, or one prefix dominates) and we've
already given the tool a fair grace period, ``should_abandon`` returns a
short reason string — the watchdog uses that to kill the tool early.

The sampler is intentionally conservative: it requires both a minimum
runtime and a minimum line count before considering abandonment, so a
genuinely slow but eventually-useful tool is never cut off prematurely.
"""

from __future__ import annotations

from collections import Counter, deque
from typing import Deque, Optional


__all__ = ["EntropySampler"]


# ── Tuning knobs (conservative defaults) ──────────────────────────────────
_WINDOW          = 200      # rolling window of recent lines
_MIN_LINES       = 80       # need at least this many lines before judging
_MIN_GRACE_SEC   = 120.0    # never abandon before 2 min elapsed
_UNIQUE_RATIO    = 0.05     # ≤5% unique lines in window → repetitive
_PREFIX_DOM      = 0.85     # ≥85% share of one 16-char prefix → spam
_PREFIX_LEN      = 16
_CHECK_EVERY     = 25       # only run check every N feeds (cheap)


class EntropySampler:
    """Rolling sampler that flags low-information output streams."""

    __slots__ = ("_window", "_total", "_since_check", "_prefix_len",
                 "_min_lines", "_min_grace_sec", "_unique_ratio",
                 "_prefix_dom", "_check_every")

    def __init__(
        self,
        window: int = _WINDOW,
        min_lines: int = _MIN_LINES,
        min_grace_sec: float = _MIN_GRACE_SEC,
        unique_ratio: float = _UNIQUE_RATIO,
        prefix_dom: float = _PREFIX_DOM,
        prefix_len: int = _PREFIX_LEN,
        check_every: int = _CHECK_EVERY,
    ) -> None:
        self._window: Deque[str] = deque(maxlen=window)
        self._total = 0
        self._since_check = 0
        self._prefix_len = prefix_len
        self._min_lines = min_lines
        self._min_grace_sec = min_grace_sec
        self._unique_ratio = unique_ratio
        self._prefix_dom = prefix_dom
        self._check_every = check_every

    def feed(self, line: str) -> None:
        """Add one output line to the rolling window."""
        if line is None:
            return
        # Strip leading/trailing whitespace and collapse runs of spaces so
        # progress bars that only differ by spacing still hash identically.
        norm = " ".join(line.strip().split())
        if not norm:
            return
        self._window.append(norm)
        self._total += 1
        self._since_check += 1

    def should_abandon(self, elapsed_sec: float) -> Optional[str]:
        """Return a reason string if the tool should be killed, else None.

        Only checked every ``check_every`` feeds to keep cost negligible.
        """
        # Rate-limit the actual computation
        if self._since_check < self._check_every:
            return None
        self._since_check = 0

        if elapsed_sec < self._min_grace_sec:
            return None
        if self._total < self._min_lines:
            return None
        n = len(self._window)
        if n < self._min_lines:
            return None

        unique = len(set(self._window))
        unique_ratio = unique / n
        if unique_ratio <= self._unique_ratio:
            return (f"low-entropy: {unique}/{n} unique lines "
                    f"({unique_ratio:.1%} ≤ {self._unique_ratio:.0%})")

        # Prefix dominance — one repeated header / status line drowns out
        # everything else even if exact-line dedup doesn't catch it.
        prefixes = Counter(s[: self._prefix_len] for s in self._window)
        top_prefix, top_count = prefixes.most_common(1)[0]
        share = top_count / n
        if share >= self._prefix_dom:
            return (f"prefix-dominated: '{top_prefix}…' = {share:.0%} "
                    f"of last {n} lines")

        return None

    # ── Diagnostics ───────────────────────────────────────────────────────
    def stats(self) -> dict:
        n = len(self._window)
        unique = len(set(self._window)) if n else 0
        return {
            "total_seen":   self._total,
            "window_size":  n,
            "unique_ratio": (unique / n) if n else 0.0,
        }
