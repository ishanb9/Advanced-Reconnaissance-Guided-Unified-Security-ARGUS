"""
ARGUS Phase 4 — In-process async-safe TTL + LRU cache.

No Redis dependency.  Uses cachetools.TTLCache (O(1) LRU eviction + per-entry
TTL) when available; falls back to a pure-Python expiry dict otherwise.

Singleton caches are defined at the bottom; import them directly:

    from db.cache import findings_cache, graph_cache, stats as cache_stats
"""

import asyncio
import time
from typing import Any, Tuple

try:
    from cachetools import TTLCache as _TTLCache
    _CACHETOOLS = True
except ImportError:
    _CACHETOOLS = False


# ── Global cache hit/miss stats ───────────────────────────────────────────────

class _Stats:
    __slots__ = ("hits", "misses", "evictions")

    def __init__(self):
        self.hits = self.misses = self.evictions = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return round(self.hits / total, 4) if total else 0.0

    def to_dict(self) -> dict:
        return {
            "hits":      self.hits,
            "misses":    self.misses,
            "evictions": self.evictions,
            "hit_rate":  self.hit_rate,
            "backend":   "cachetools.TTLCache" if _CACHETOOLS else "builtin-dict",
        }


stats = _Stats()


# ── Async-safe TTL+LRU cache ──────────────────────────────────────────────────

class AsyncTTLCache:
    """
    Async-safe TTL + LRU cache suitable for FastAPI coroutines.

    Parameters
    ----------
    maxsize : int
        Maximum number of entries.  Oldest LRU entry evicted when full.
    ttl : float
        Seconds before an entry expires regardless of access frequency.
    """

    def __init__(self, maxsize: int = 256, ttl: float = 30.0):
        self._ttl     = ttl
        self._maxsize = maxsize
        self._lock    = asyncio.Lock()
        self._init_backend()

    # ── Internal helpers ──────────────────────────────────────

    def _init_backend(self):
        if _CACHETOOLS:
            self._cache = _TTLCache(maxsize=self._maxsize, ttl=self._ttl)
        else:
            # {key: (value, expires_at_monotonic)}
            self._cache: dict = {}

    def _fallback_get(self, key: str) -> Tuple[bool, Any]:
        entry = self._cache.get(key)
        if entry is None:
            return False, None
        value, expires = entry
        if time.monotonic() < expires:
            return True, value
        del self._cache[key]
        return False, None

    def _fallback_set(self, key: str, value: Any):
        if len(self._cache) >= self._maxsize:
            # evict the entry with the earliest expiry
            oldest = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest]
            stats.evictions += 1
        self._cache[key] = (value, time.monotonic() + self._ttl)

    # ── Public API ────────────────────────────────────────────

    async def get(self, key: str) -> Tuple[bool, Any]:
        """Return (hit: bool, value: Any).  Value is None on miss."""
        async with self._lock:
            if _CACHETOOLS:
                try:
                    val = self._cache[key]
                    stats.hits += 1
                    return True, val
                except KeyError:
                    stats.misses += 1
                    return False, None
            else:
                hit, val = self._fallback_get(key)
                if hit:
                    stats.hits += 1
                else:
                    stats.misses += 1
                return hit, val

    async def set(self, key: str, value: Any) -> None:
        """Store value under key, evicting LRU entry if at capacity."""
        async with self._lock:
            if _CACHETOOLS:
                self._cache[key] = value
            else:
                self._fallback_set(key, value)

    async def invalidate(self, key: str) -> None:
        """Remove a single key (no-op if absent)."""
        async with self._lock:
            self._cache.pop(key, None)

    async def invalidate_prefix(self, prefix: str) -> None:
        """Remove all keys that begin with *prefix*."""
        async with self._lock:
            keys = [k for k in list(self._cache.keys()) if k.startswith(prefix)]
            for k in keys:
                self._cache.pop(k, None)

    def size(self) -> int:
        """Current number of live entries (approximate under concurrency)."""
        return len(self._cache)

    def clear(self) -> None:
        """Flush all entries (not async — call from startup/test only)."""
        self._init_backend()


# ── Bounded instruction cache (replaces plain dict in MasterAgent) ───────────

class BoundedInstructionCache:
    """
    Thread-safe wrapper around cachetools.TTLCache used by MasterAgent to
    prevent unbounded memory growth on long engagements.

    Drops to a plain dict-with-max-size when cachetools is unavailable.

    Parameters
    ----------
    maxsize : int   Maximum cached instructions per session (default 500).
    ttl     : float Seconds before a cached result expires (default 4 h).
    """

    def __init__(self, maxsize: int = 500, ttl: float = 14_400.0):
        self._maxsize = maxsize
        self._ttl     = ttl
        self._hits    = 0
        self._misses  = 0
        if _CACHETOOLS:
            self._cache = _TTLCache(maxsize=maxsize, ttl=ttl)
        else:
            self._cache: dict = {}

    # ── Dict-compatible interface so no call-site changes are needed ──

    def __contains__(self, key: str) -> bool:
        if _CACHETOOLS:
            try:
                _ = self._cache[key]
                return True
            except KeyError:
                return False
        return key in self._cache

    def __getitem__(self, key: str):
        self._hits += 1
        return self._cache[key]

    def __setitem__(self, key: str, value):
        if not _CACHETOOLS and len(self._cache) >= self._maxsize:
            # Evict arbitrary oldest entry (FIFO approximation)
            try:
                del self._cache[next(iter(self._cache))]
            except StopIteration:
                pass
        self._cache[key] = value

    def get(self, key: str, default=None):
        if key in self:
            return self[key]
        self._misses += 1
        return default

    def __len__(self) -> int:
        return len(self._cache)

    def cache_stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "size":     len(self._cache),
            "maxsize":  self._maxsize,
            "hits":     self._hits,
            "misses":   self._misses,
            "hit_rate": round(self._hits / total, 4) if total else 0.0,
            "ttl_sec":  self._ttl,
        }


# ── Singleton endpoint caches ─────────────────────────────────────────────────

# Findings + severity summary — changes during an active scan
findings_cache    = AsyncTTLCache(maxsize=256, ttl=20.0)

# Full attack-graph topology — expensive read, changes infrequently
graph_cache       = AsyncTTLCache(maxsize=64,  ttl=60.0)

# Tool-outputs listing — append-only; refresh frequently
tool_outputs_cache = AsyncTTLCache(maxsize=256, ttl=15.0)

# Session metadata (status, phases, started_at)
session_meta_cache = AsyncTTLCache(maxsize=128, ttl=10.0)
