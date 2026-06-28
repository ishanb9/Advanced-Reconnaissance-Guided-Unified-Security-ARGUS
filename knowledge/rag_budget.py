"""rag_budget.py — RAG resource metering + a fail-safe growth guardrail.

As ARGUS learns, the vector store grows. This reports how much STORAGE (on-disk
DB), RAM (process RSS + estimated vector memory), and how many chunks the RAG
uses — and ENFORCES a budget so it can never overwhelm the host: new ingests are
blocked when the chunk/DB cap is hit, or when free disk / free RAM run low.
The engagement keeps running; only RAG *growth* stops, and the human is warned to
prune (scripts/rag_maintenance.py --prune).

Budgets (env; generous defaults — lower them on small VMs):
  ARGUS_RAG_MAX_CHUNKS       max chunks                     (default 1_000_000)
  ARGUS_RAG_MAX_DB_MB        max on-disk DB size, MB        (default 8192)
  ARGUS_RAG_MIN_FREE_DISK_MB block ingest if free disk below (default 1024)
  ARGUS_RAG_MIN_FREE_RAM_MB  block ingest if free RAM below  (default 512)
  ARGUS_RAG_BUDGET=0         disable the guardrail entirely
Best-effort + offline: a missing metric (e.g. no psutil) never blocks ingestion.
"""
from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("argus.rag.budget")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except Exception:
        return default


def _db_path() -> Path:
    try:
        from knowledge import knowledge_base as kb
        p = getattr(kb, "CHROMA_PATH", None)
        if p:
            return Path(p)
    except Exception:
        pass
    return Path(__file__).resolve().parent / "db"


def dir_size_mb(path: Path) -> float:
    try:
        total = 0
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except Exception:
                    pass
        return round(total / 1e6, 1)
    except Exception:
        return 0.0


def free_disk_mb(path: Path) -> Optional[float]:
    try:
        target = path if path.exists() else path.parent
        return round(shutil.disk_usage(str(target)).free / 1e6, 1)
    except Exception:
        return None


def free_ram_mb() -> Optional[float]:
    try:
        import psutil
        return round(psutil.virtual_memory().available / 1e6, 1)
    except Exception:
        pass
    try:                                # Linux /proc fallback (no psutil)
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return round(int(line.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    return None


def process_rss_mb() -> Optional[float]:
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / 1e6, 1)
    except Exception:
        pass
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    return None


def chunk_count() -> int:
    try:
        from knowledge import knowledge_base as kb
        return int(kb._get_collection().count())
    except Exception:
        return 0


def budgets() -> Dict[str, int]:
    return {
        "max_chunks":        _int_env("ARGUS_RAG_MAX_CHUNKS", 1_000_000),
        "max_db_mb":         _int_env("ARGUS_RAG_MAX_DB_MB", 8192),
        "min_free_disk_mb":  _int_env("ARGUS_RAG_MIN_FREE_DISK_MB", 1024),
        "min_free_ram_mb":   _int_env("ARGUS_RAG_MIN_FREE_RAM_MB", 512),
    }


def evaluate(chunks: int, db_mb: Optional[float], free_disk: Optional[float],
             free_ram: Optional[float], b: Optional[Dict[str, int]] = None) -> Tuple[bool, str]:
    """Pure budget decision (testable).  A None metric is treated as 'unknown' and
    never blocks on its own."""
    b = b or budgets()
    if chunks >= b["max_chunks"]:
        return False, f"chunk cap reached ({chunks} >= {b['max_chunks']})"
    if db_mb is not None and db_mb >= b["max_db_mb"]:
        return False, f"db size cap reached ({db_mb}MB >= {b['max_db_mb']}MB)"
    if free_disk is not None and free_disk < b["min_free_disk_mb"]:
        return False, f"low free disk ({free_disk}MB < {b['min_free_disk_mb']}MB)"
    if free_ram is not None and free_ram < b["min_free_ram_mb"]:
        return False, f"low free RAM ({free_ram}MB < {b['min_free_ram_mb']}MB)"
    return True, "ok"


def usage() -> Dict[str, Any]:
    """Full resource report (does a dir scan for db size — use for reporting, not
    the per-ingest hot path)."""
    dbp = _db_path()
    chunks = chunk_count()
    dim = _int_env("ARGUS_RAG_EMBED_DIM", 384)   # bge-small-en-v1.5 = 384
    # float32 vectors + HNSW graph overhead (~1.7x) — an estimate of the index RAM.
    est_vec_ram = round(chunks * dim * 4 / 1e6 * 1.7, 1)
    db_mb = dir_size_mb(dbp)
    fdisk = free_disk_mb(dbp)
    fram = free_ram_mb()
    b = budgets()
    ok, reason = evaluate(chunks, db_mb, fdisk, fram, b)
    return {
        "chunks": chunks,
        "chunks_pct_of_cap": round(100 * chunks / b["max_chunks"], 2) if b["max_chunks"] else 0.0,
        "db_size_mb": db_mb,
        "est_vector_ram_mb": est_vec_ram,
        "process_rss_mb": process_rss_mb(),
        "free_disk_mb": fdisk,
        "free_ram_mb": fram,
        "embed_dim": dim,
        "budgets": b,
        "within_budget": ok,
        "reason": reason,
        "db_path": str(dbp),
    }


# ── Throttled per-ingest gate (fast checks only — no dir scan) ────────────────
_cache: Dict[str, Any] = {"t": -1e9, "ok": True, "reason": "ok", "n": 0, "logged": False}


def ingest_allowed() -> Tuple[bool, str]:
    """Fast, throttled guardrail used by knowledge_base.ingest().  Re-evaluates at
    most every ~5s (or every 200 calls); caches between.  Uses only the cheap
    metrics (chunk count + free disk/RAM); the dir-scan db-size cap lives in the
    reporting path.  Never raises."""
    if os.environ.get("ARGUS_RAG_BUDGET", "1") == "0":
        return True, "disabled"
    try:
        _cache["n"] += 1
        now = time.monotonic()
        if (now - _cache["t"] < 5.0) and (_cache["n"] % 200 != 0):
            return _cache["ok"], _cache["reason"]
        b = budgets()
        ok, reason = evaluate(chunk_count(), None, free_disk_mb(_db_path()),
                              free_ram_mb(), b)
        _cache.update(t=now, ok=ok, reason=reason)
        if not ok and not _cache["logged"]:
            logger.warning("[rag-budget] BLOCKING new RAG ingests: %s — prune with "
                           "scripts/rag_maintenance.py --prune", reason)
            _cache["logged"] = True
            try:
                from knowledge import rag_logger as _rl
                _rl.log_event("ingest_blocked", reason=reason)
            except Exception:
                pass
        if ok:
            _cache["logged"] = False
        return ok, reason
    except Exception:
        return True, "check-error"


__all__ = ["usage", "ingest_allowed", "evaluate", "budgets", "chunk_count",
           "dir_size_mb", "free_disk_mb", "free_ram_mb", "process_rss_mb"]
