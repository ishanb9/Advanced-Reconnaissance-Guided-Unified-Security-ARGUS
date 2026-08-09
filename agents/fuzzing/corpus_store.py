"""agents/fuzzing/corpus_store.py — persistent fuzz corpus for deep-continuous mode.

A small, dependency-free on-disk store of "interesting" fuzz inputs so a LAB-ONLY
deep-continuous campaign (Slice 3) can resume from prior runs instead of starting cold
each time.  Each input is content-addressed by its SHA-1 hash and written to
``<hash>.bin`` exactly once (dedup); ``load()`` reads them back as ``bytes``.

Strictly additive and defensive: this module NEVER raises out of its public methods.
On any IO error it degrades to an in-memory / no-op behaviour and logs at debug level.
Filenames are purely hash-derived (no clock, no randomness) so a corpus is reproducible
and a given input always maps to the same file.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from typing import List, Optional

logger = logging.getLogger("argus.fuzz.corpus_store")

# Defensive caps so a runaway corpus can never exhaust memory / disk on load.
_MAX_FILES = 5000           # cap number of corpus entries read per load()
_MAX_FILE_BYTES = 1 << 20   # 1 MiB per-file read cap (skip larger files)
_DEFAULT_BASE = os.path.join("logs", "fuzz_corpus")


def _sanitise_key(key: str) -> str:
    """Reduce an arbitrary campaign key to a safe single path segment."""
    raw = str(key or "default")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
    return (safe or "default")[:120]


def _as_bytes(value: object) -> Optional[bytes]:
    """Coerce a corpus input (bytes/str) to bytes, or None if uncoercible."""
    try:
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8", "surrogatepass")
    except Exception:
        return None
    return None


class CorpusStore:
    """A persistent, hash-deduplicated corpus of fuzz inputs on disk.

    All methods are best-effort and never raise; failures degrade to no-ops.
    """

    def __init__(self, key: str, base: Optional[str] = None) -> None:
        self.key = _sanitise_key(key)
        base_dir = base or _DEFAULT_BASE
        try:
            self.dir = os.path.join(str(base_dir), self.key)
        except Exception:
            self.dir = os.path.join(_DEFAULT_BASE, self.key)
        # In-memory fallback set of seen hashes when the dir is unwritable, so
        # add() still dedups within a process even with no disk.
        self._mem_seen: set = set()
        self._writable = self._ensure_dir()

    def _ensure_dir(self) -> bool:
        """Best-effort mkdir.  Returns True if the dir exists and is usable."""
        try:
            os.makedirs(self.dir, exist_ok=True)
            return os.path.isdir(self.dir)
        except Exception as exc:  # pragma: no cover - environment dependent
            logger.debug("corpus dir unavailable (%s): %s", self.dir, exc)
            return False

    def load(self) -> List[bytes]:
        """Read all corpus entries as bytes (capped); skip unreadable files.

        Returns an empty list on any error.  Never raises.
        """
        out: List[bytes] = []
        try:
            if not os.path.isdir(self.dir):
                return out
            names = sorted(os.listdir(self.dir))
        except Exception as exc:
            logger.debug("corpus load listing failed (%s): %s", self.dir, exc)
            return out
        for name in names:
            if len(out) >= _MAX_FILES:
                break
            if not name.endswith(".bin"):
                continue
            path = os.path.join(self.dir, name)
            try:
                if not os.path.isfile(path):
                    continue
                if os.path.getsize(path) > _MAX_FILE_BYTES:
                    continue
                with open(path, "rb") as fh:
                    out.append(fh.read(_MAX_FILE_BYTES))
            except Exception as exc:
                logger.debug("corpus skip unreadable %s: %s", path, exc)
                continue
        return out

    def add(self, inputs: List) -> int:
        """Persist interesting inputs, deduplicated by SHA-1 hash.

        Each input (bytes or str) is hashed and written to ``<hash>.bin`` only if
        that file is not already present.  Returns the number of NEWLY added
        entries.  Never raises (degrades to in-memory dedup / no-op on IO error).
        """
        if not inputs:
            return 0
        added = 0
        for item in inputs:
            data = _as_bytes(item)
            if data is None:
                continue
            try:
                digest = hashlib.sha1(data).hexdigest()
            except Exception:
                continue
            if digest in self._mem_seen:
                continue
            # No writable dir → in-memory dedup only (count as added once).
            if not self._writable:
                self._mem_seen.add(digest)
                added += 1
                continue
            path = os.path.join(self.dir, digest + ".bin")
            try:
                if os.path.exists(path):
                    self._mem_seen.add(digest)
                    continue
                with open(path, "wb") as fh:
                    fh.write(data)
                self._mem_seen.add(digest)
                added += 1
            except Exception as exc:
                logger.debug("corpus add failed for %s: %s", path, exc)
                # Track in-memory so we don't retry the same input repeatedly.
                self._mem_seen.add(digest)
                continue
        return added
