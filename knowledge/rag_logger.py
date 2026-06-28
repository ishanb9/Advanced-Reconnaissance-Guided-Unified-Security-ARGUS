"""rag_logger.py — dedicated, separate trace of all RAG communication.

The knowledge base is otherwise a black box: you can't tell whether the chunks it
returns are actually relevant or dead weight.  This logs EVERY ingest and EVERY
query — with similarity scores, the retrieving caller, and result snippets — to a
channel kept SEPARATE from the main app log:

  logs/rag.log         human-readable, rotating
  logs/rag_trace.jsonl one JSON object per event (for scripts/rag_report.py)

Analyse it with ``python -X utf8 scripts/rag_report.py`` to get a verdict on
whether the chunks earn their place or need enhancement.

Toggles (default ON so you can troubleshoot immediately):
  ARGUS_RAG_DEBUG=0   disable all RAG logging
  ARGUS_RAG_TRACE=0   keep the human log, skip the JSONL trace
Best-effort: logging never raises into ingest/search.
"""
from __future__ import annotations

import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List

_REPO = Path(__file__).resolve().parent.parent
_LOG_DIR = _REPO / "logs"


def _active_dir() -> Path:
    """Write RAG traces INTO the active scan's log folder (logs/<ts>_<sid>/) so they
    live alongside scan.log, instead of polluting the repo-level logs/ root.  Falls
    back to the shared logs/ root when no scan is active (or off-scan tooling)."""
    try:
        from utils.scan_logger import current_log_dir
        d = current_log_dir()
        if d:
            return Path(d)
    except Exception:
        pass
    return _LOG_DIR


def _trace_file() -> Path:
    env = os.environ.get("ARGUS_RAG_TRACE_PATH")
    if env:
        return Path(env)
    return _active_dir() / "rag_trace.jsonl"
# A result is "relevant" when its score is above this. The default search path
# reranks with a cross-encoder whose scores are unbounded logits (positive =
# relevant, negative = not), so 0.0 is the natural relevant/irrelevant boundary.
# Override for a pure-cosine (no-rerank) setup via ARGUS_RAG_RELEVANT_THRESHOLD.
_RELEVANT_AT = float(os.environ.get("ARGUS_RAG_RELEVANT_THRESHOLD", "0.0"))
_logger = None
_logger_dir = None      # the dir the current rag.log handler points at


def _enabled() -> bool:
    return os.environ.get("ARGUS_RAG_DEBUG", "1") != "0"


def _trace_enabled() -> bool:
    return os.environ.get("ARGUS_RAG_TRACE", "1") != "0"


def _get_logger():
    """Return the RAG file logger, pointing rag.log at the ACTIVE scan folder.  When
    a new scan starts (the active dir changes), the handler is re-pointed so each
    scan's RAG log lives inside its own folder."""
    global _logger, _logger_dir
    target_dir = _active_dir()
    if _logger is not None and _logger_dir == target_dir:
        return _logger
    lg = logging.getLogger("argus.rag")
    lg.setLevel(logging.INFO)
    lg.propagate = False           # keep it OUT of the main app log
    # Drop any handler from a previous scan dir before attaching the new one.
    for h in list(lg.handlers):
        try:
            lg.removeHandler(h)
            h.close()
        except Exception:
            pass
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        h = RotatingFileHandler(target_dir / "rag.log", maxBytes=5_000_000,
                                backupCount=3, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
        lg.addHandler(h)
    except Exception:
        pass
    _logger = lg
    _logger_dir = target_dir
    return lg


def _ts() -> str:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return ""


def _trace(obj: Dict[str, Any]) -> None:
    if not _trace_enabled():
        return
    try:
        p = _trace_file()
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        pass


def caller_hint() -> str:
    """The first caller frame outside the knowledge-base/log plumbing — i.e. the
    agent/module that actually asked RAG for something."""
    try:
        import inspect
        for fr in inspect.stack()[2:9]:
            fn = Path(fr.filename).name
            if fn not in ("knowledge_base.py", "rag_logger.py"):
                return f"{fn}:{fr.lineno}"
    except Exception:
        pass
    return "?"


def log_ingest(source: str, chunk_type: str, doc_id: str, added: bool,
               n_chars: int, reason: str = "") -> None:
    if not _enabled():
        return
    try:
        mark = "+" if added else "x"
        _get_logger().info(
            f"INGEST {mark} type={chunk_type} chars={n_chars} src={source} id={doc_id}"
            + (f" ({reason})" if reason else ""))
        _trace({"ts": _ts(), "kind": "ingest", "added": bool(added),
                "chunk_type": chunk_type, "chars": int(n_chars or 0),
                "source": str(source), "doc_id": str(doc_id), "reason": reason})
    except Exception:
        pass


def log_search(query: str, results: List[Dict[str, Any]], elapsed_ms: float,
               caller: str = "", kb_size: int = 0, reason: str = "") -> None:
    """Log one retrieval with the per-chunk relevance scores + snippets."""
    if not _enabled():
        return
    try:
        results = results or []
        rels = [round(float(r.get("relevance", 0)), 4) for r in results]
        top = rels[0] if rels else 0.0
        avg = round(sum(rels) / len(rels), 4) if rels else 0.0
        # "relevant" = score above the boundary (cross-encoder >0). The trailing
        # results that pad top_k with low/negative scores are NOT counted.
        n_rel = sum(1 for r in rels if r > _RELEVANT_AT)
        verdict = "EMPTY" if not results else ("WEAK" if n_rel == 0 else "OK")
        brief = [{
            "source": r.get("source_file") or r.get("source", ""),
            "type": r.get("chunk_type", ""),
            "rel": round(float(r.get("relevance", 0)), 4),
            "snip": (r.get("text", "") or "")[:140].replace("\n", " "),
        } for r in results[:8]]
        _get_logger().info(
            f"QUERY [{verdict}] n={len(results)} relevant={n_rel} top={top} avg={avg} "
            f"ms={round(elapsed_ms,1)} caller={caller} kb={kb_size} q={query[:160]!r}"
            + (f" ({reason})" if reason else ""))
        for b in brief:
            _get_logger().info(f"    -> rel={b['rel']} type={b['type']} src={b['source']} :: {b['snip']}")
        _trace({"ts": _ts(), "kind": "search", "query": query[:300], "caller": caller,
                "kb_size": int(kb_size or 0), "n": len(results), "relevant": n_rel,
                "top": top, "avg": avg, "elapsed_ms": round(elapsed_ms, 1),
                "verdict": verdict, "reason": reason, "results": brief})
    except Exception:
        pass


def log_event(kind: str, **fields: Any) -> None:
    if not _enabled():
        return
    try:
        _get_logger().info(f"{str(kind).upper()} "
                           + " ".join(f"{k}={v}" for k, v in fields.items()))
        _trace({"ts": _ts(), "kind": str(kind), **fields})
    except Exception:
        pass


def trace_path() -> str:
    return str(_trace_file())


__all__ = ["log_ingest", "log_search", "log_event", "caller_hint", "trace_path"]
