"""knowledge/crash_ledger.py — on-disk crash dedup store (JSON, leaf, stdlib-only).

The fuzz proof spine surfaces many crashes per campaign, but a single underlying
bug typically reproduces under dozens of distinct inputs that all collapse onto the
same sanitizer stack hash.  The :class:`CrashLedger` is the durable memory that lets
TRIAGE-PLUS answer "have we already clustered this exact crash?" across campaigns and
process restarts — so a finding is reported once, not once per input.

On-disk shape (``logs/crash_ledger.json`` by default)::

    {
      "<target>": {
        "<stack_hash>": {
          "cluster_id": "<short(target)>-<stack_hash[:8]>",
          "count": <int>,
          "first_seen": <caller-supplied ts or None>,
          "meta": { ... last recorded meta ... }
        }
      }
    }

Design constraints (per Slice-1 spec):
  * Pure standard library + :mod:`json`.  No network, no clock at import time.
  * Never raises on I/O errors — degrades to an in-memory store so a flaky disk can
    never crash a campaign.
  * Deterministic for tests: the timestamp is read *only* inside :meth:`record`, and
    only from a caller-supplied ``meta['ts']`` (or ``meta['first_seen']``).  No
    implicit ``time.time()`` call, so tests stay reproducible.
  * Atomic persistence: write a sibling tmp file then :func:`os.replace` it over the
    target, so a concurrent reader never sees a half-written file.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional
try:
    from knowledge.identifier_scrub import contains_identifier as _has_ident
except ImportError:                                          # flat/script mode
    from identifier_scrub import contains_identifier as _has_ident

log = logging.getLogger(__name__)

_REPO = Path(__file__).resolve().parent.parent
_DEFAULT_PATH = _REPO / "logs" / "crash_ledger.json"

# Targets are arbitrary strings (paths, urls, binary names).  Keep the cluster-id
# prefix short, filesystem-safe and stable so the same target always clusters the same.
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _short(target: str, n: int = 24) -> str:
    """A short, stable, filesystem-safe slug for a target name (basename-ish)."""
    try:
        base = os.path.basename(str(target).rstrip("/\\")) or str(target)
        slug = _SAFE.sub("_", base).strip("_")
        # The ledger is a repo-level JSON shared by every engagement, so the slug
        # must not name a client asset.  A URL/host/binary path here would persist
        # one client's identity into the next client's crash clustering.  Hash it
        # instead: still stable (same target always clusters together), no longer
        # a name.  A plainly non-identifying slug is kept for readability.
        if _has_ident(slug) or _has_ident(str(target)):
            import hashlib as _h
            return "t_" + _h.sha256(str(target).encode("utf-8", "ignore")).hexdigest()[:12]
        return (slug or "target")[:n]
    except Exception:
        return "target"


class CrashLedger:
    """JSON-backed dedup store keyed by ``(target, stack_hash)``.

    The whole store is held in memory and re-persisted on every :meth:`record`; the
    expected volume (a handful of unique clusters per campaign) makes that trivially
    cheap and keeps the on-disk file consistent at all times.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self._path: Path = Path(path) if path else _DEFAULT_PATH
        # shape: {target: {stack_hash: {cluster_id, count, first_seen, meta}}}
        self._data: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._load()

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        """Load the JSON store, tolerating a missing/corrupt/unreadable file."""
        try:
            if not self._path.exists():
                self._data = {}
                return
            raw = self._path.read_text(encoding="utf-8")
            parsed = json.loads(raw) if raw.strip() else {}
            if isinstance(parsed, dict):
                # keep only well-shaped nested dicts; ignore garbage defensively
                self._data = {
                    str(t): {str(h): dict(rec) for h, rec in (tbl or {}).items()
                             if isinstance(rec, dict)}
                    for t, tbl in parsed.items() if isinstance(tbl, dict)
                }
            else:
                self._data = {}
        except Exception as exc:  # corrupt JSON, perms, encoding — degrade in-memory
            log.warning("CrashLedger: could not load %s (%s); starting empty",
                        self._path, exc)
            self._data = {}

    def _persist(self) -> None:
        """Atomically write the store via a tmp file + :func:`os.replace`.

        Best-effort: an I/O failure here leaves the in-memory store authoritative for
        the rest of the process and is logged, never raised.
        """
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix=self._path.name + ".", suffix=".tmp", dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self._data, fh, ensure_ascii=False, indent=2,
                              sort_keys=True, default=str)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self._path)
            finally:
                # if os.replace already consumed tmp this is a harmless no-op
                try:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                except Exception:
                    pass
        except Exception as exc:
            log.warning("CrashLedger: could not persist %s (%s); kept in memory",
                        self._path, exc)

    # -- public API --------------------------------------------------------

    def seen(self, target: str, stack_hash: str) -> bool:
        """True if ``(target, stack_hash)`` has already been recorded."""
        try:
            return str(stack_hash) in self._data.get(str(target), {})
        except Exception:
            return False

    def record(self, target: str, stack_hash: str,
               meta: Optional[Dict[str, Any]] = None) -> str:
        """Record one crash and return its stable ``cluster_id``.

        First sighting of ``(target, stack_hash)`` creates the cluster (``count=1``);
        subsequent sightings increment ``count`` and refresh ``meta`` while keeping the
        original ``cluster_id`` and ``first_seen``.

        ``cluster_id`` is ``f"{short(target)}-{stack_hash[:8]}"``.  Any timestamp is
        taken only from ``meta['ts']`` / ``meta['first_seen']`` (caller-supplied) so the
        ledger never reads a clock implicitly — tests stay deterministic.  Never raises.
        """
        try:
            tkey = str(target)
            hkey = str(stack_hash)
            meta = dict(meta) if isinstance(meta, dict) else {}
            cluster_id = "%s-%s" % (_short(tkey), hkey[:8])

            table = self._data.setdefault(tkey, {})
            rec = table.get(hkey)
            if rec is None:
                ts = meta.get("ts", meta.get("first_seen"))
                rec = {
                    "cluster_id": cluster_id,
                    "count": 1,
                    "first_seen": ts,
                    "meta": meta,
                }
                table[hkey] = rec
            else:
                try:
                    rec["count"] = int(rec.get("count", 0)) + 1
                except Exception:
                    rec["count"] = 1
                rec["meta"] = meta
                # preserve original cluster_id/first_seen across re-sightings
                cluster_id = str(rec.get("cluster_id") or cluster_id)
                rec["cluster_id"] = cluster_id

            self._persist()
            return cluster_id
        except Exception as exc:
            log.warning("CrashLedger.record failed (%s); returning best-effort id", exc)
            try:
                return "%s-%s" % (_short(str(target)), str(stack_hash)[:8])
            except Exception:
                return "target-unknown"
