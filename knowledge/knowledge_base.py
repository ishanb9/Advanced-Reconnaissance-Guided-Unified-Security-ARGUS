"""
knowledge_base.py — Enhanced RAG knowledge base for the Kali Pentest Platform v2

Improvements over v1:
  - Optional cross-encoder reranking (cross-encoder/ms-marco-MiniLM-L-6-v2)
  - Multi-query expansion for better recall on specific CVEs/tools/techniques
  - chunk_type-aware search output (script/command/procedure/technique/tip/finding)
  - Additional API: search_raw(), search_commands(), search_procedures(), ingest_tip()
  - Configurable embedding model: MiniLM (fast) or MPNet (higher quality)
  - Better relevance scoring with distance-to-similarity conversion
  - Richer output formatting showing chunk type and MITRE TTPs

Install dependencies (run once):
  pip install chromadb sentence-transformers

Optional for higher quality reranking:
  pip install sentence-transformers  # already included — CrossEncoder is part of it
"""

import os
import json
import hashlib
import logging
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger("knowledge_base")

# ── Config ──────────────────────────────────────────────────────────────────────
# Vector store directory.  Default location is ``knowledge/db/`` (clean
# separation from the source corpus in ``knowledge/data/``).  Falls back
# to the legacy ``knowledge/chroma_db/`` for in-place upgrades.
def _resolve_chroma_path() -> str:
    base = os.path.dirname(__file__)
    new = os.path.join(base, "db")
    legacy = os.path.join(base, "chroma_db")
    if os.path.isdir(new):
        return new
    if os.path.isdir(legacy):
        return legacy
    return new   # default for fresh installs

CHROMA_PATH   = os.environ.get("KB_DB_PATH") or _resolve_chroma_path()
COLLECTION    = "pentest_knowledge"

# Primary embedding model — RAM-budget guidance:
#
#   "BAAI/bge-small-en-v1.5"  → ~130 MB on disk, ~300 MB RAM loaded,  384-dim,  ← DEFAULT
#                              512 token ctx, fast on CPU, BGE-family quality.
#                              Best fit for 4-8 GB hosts.
#   "BAAI/bge-base-en-v1.5"   → ~440 MB on disk, ~1.0 GB RAM,         768-dim,
#                              512 token ctx.  Middle ground for 8-12 GB hosts.
#   "BAAI/bge-m3"             → ~570 MB on disk, ~1.5 GB RAM,        1024-dim,
#                              8192 token ctx, best multilingual recall.  Use
#                              only on hosts with >= 12 GB RAM + browser space.
#   "all-MiniLM-L6-v2"        → ~90 MB on disk,  ~150 MB RAM,         384-dim,
#                              256 token ctx, fastest CPU encode.  Quality is
#                              ~80% of BGE.  Last resort for < 4 GB hosts.
#   "all-mpnet-base-v2"       → ~420 MB on disk, ~900 MB RAM,         768-dim.
#   "BAAI/bge-large-en-v1.5"  → ~1.3 GB on disk, ~2.8 GB RAM,        1024-dim.
#
# NOTE: changing model requires --reset (dimensions must match entire collection).
# Run:   python knowledge/build_kb.py --reset --path knowledge/data
EMBED_MODEL   = os.environ.get("KB_EMBED_MODEL", "BAAI/bge-small-en-v1.5")

# Cross-encoder reranking model (set KB_RERANK_MODEL="" to disable).
# Disabling saves ~250 MB RAM + ~40% on query latency at the cost of
# 10-15% precision-at-1.  Recommended on hosts with < 8 GB total RAM.
#
#   ""                                       → DISABLED  (saves ~250 MB)
#   "cross-encoder/ms-marco-TinyBERT-L-2-v2" → ~17 MB / ~50 MB RAM  — minimal
#   "cross-encoder/ms-marco-MiniLM-L-4-v2"   → ~50 MB / ~180 MB RAM — balanced
#   "cross-encoder/ms-marco-MiniLM-L-6-v2"   → ~70 MB / ~250 MB RAM — default quality
#   "cross-encoder/ms-marco-MiniLM-L-12-v2"  → ~120 MB/ ~400 MB RAM — higher quality
RERANK_MODEL  = os.environ.get("KB_RERANK_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")

MAX_RESULTS   = 6           # results returned to agent per query
MIN_RELEVANCE = 0.28        # cosine similarity threshold
RERANK_FETCH  = 25          # candidates fetched from ChromaDB before reranking to top MAX_RESULTS

# bge-m3 supports up to 8192 tokens; bge-small / BERT family / MiniLM are 512;
# all-MiniLM-L6-v2 is actually 256 but the tokenizer pads to 512 silently.
def _resolve_max_length(model: str) -> int:
    if "bge-m3" in model:
        return 8192
    if "MiniLM-L6" in model or "all-MiniLM" in model:
        return 256
    return 512
EMBED_MAX_LENGTH = _resolve_max_length(EMBED_MODEL)


# ── Memory-budget startup warning ──────────────────────────────────────────
# Emit a clear nudge if the active embedder is too heavy for this host.
# Avoids the classic "scan dies silently mid-recon" footgun we hit in v3.
def _emit_memory_warning() -> None:
    try:
        import psutil  # type: ignore
        total_gb = psutil.virtual_memory().total / (1024 ** 3)
    except Exception:
        return
    heavy = {
        "BAAI/bge-m3":            (3.5, "bge-m3 needs ~1.5 GB RAM (model) + ~3 GB ChromaDB hot index"),
        "BAAI/bge-large-en-v1.5": (3.0, "bge-large needs ~2.8 GB RAM loaded"),
        "all-mpnet-base-v2":      (1.5, "mpnet needs ~0.9 GB RAM loaded"),
    }
    for key, (min_gb_above_kali_baseline, note) in heavy.items():
        if key in EMBED_MODEL and total_gb < (2.0 + min_gb_above_kali_baseline + 1.5):
            logger.warning(
                "[kb] Host has only %.1f GB total RAM but KB_EMBED_MODEL=%s. %s. "
                "Recommended: KB_EMBED_MODEL=BAAI/bge-small-en-v1.5 and "
                "KB_RERANK_MODEL='' to fit safely. Re-ingest required after change "
                "(python knowledge/build_kb.py --reset).",
                total_gb, EMBED_MODEL, note,
            )
            break

_emit_memory_warning()

# Chunk type icons for formatted output
CHUNK_TYPE_ICONS = {
    "command":    "⚡",
    "script":     "📜",
    "procedure":  "📋",
    "technique":  "🎯",
    "playbook":   "🗺️",
    "tip":        "💡",
    "finding":    "🔍",
    "tool_usage": "🔧",
    "output":     "📊",
    "report":     "📄",
    "unknown":    "📝",
}

# ── Lazy singletons ─────────────────────────────────────────────────────────────
#
# Singletons are stored on the *Python interpreter* (sys.modules['builtins'])
# so they survive even if this module is imported under two different names
# (e.g. ``knowledge_base`` AND ``knowledge.knowledge_base``).  Without this
# guard, a stray ``from knowledge import knowledge_base`` somewhere in the
# codebase causes Python to instantiate a SECOND module object with its own
# _embedder global — bge-m3 (1.5 GB) and the cross-encoder (250 MB) end up
# loaded twice, OOM-killing the agent on 7-8 GB hosts.  The shared-on-builtins
# pattern is robust to that: whichever module-instance hits _get_embedder()
# first stores the model on builtins; the second one finds it and reuses it.
import builtins as _builtins
import threading as _threading

_SINGLETON_KEY_EMBEDDER  = "_argus_kb_embedder"
_SINGLETON_KEY_COLLECTION = "_argus_kb_collection"
_SINGLETON_KEY_CLIENT     = "_argus_kb_client"
_SINGLETON_KEY_RERANKER   = "_argus_kb_reranker"
_SINGLETON_KEY_RERANK_OK  = "_argus_kb_reranker_available"

# Serialises the FIRST load of each heavyweight model so concurrent callers can
# never each load their own copy.  Without this lock a multi-host scan (one
# MasterAgent per host, KB queries dispatched to a thread pool) had every host's
# first query miss the singleton cache simultaneously and load its OWN
# CrossEncoder/SentenceTransformer — 7+ concurrent multi-GB CPU loads thrashed
# RAM and effectively FROZE the whole run.  Double-checked locking (cache →
# lock → re-check → load → cache) guarantees exactly ONE process-wide load that
# every other caller then reuses.  Stored on builtins so it is shared even if
# the module is imported under different names.
_MODEL_LOAD_LOCK = getattr(_builtins, "_argus_kb_model_load_lock", None)
if _MODEL_LOAD_LOCK is None:
    _MODEL_LOAD_LOCK = _threading.Lock()
    setattr(_builtins, "_argus_kb_model_load_lock", _MODEL_LOAD_LOCK)

# Module-level mirrors (kept for backward compat with any external code
# that pokes at them by name).  Reads go through getattr / builtins.
_client     = getattr(_builtins, _SINGLETON_KEY_CLIENT,     None)
_collection = getattr(_builtins, _SINGLETON_KEY_COLLECTION, None)
_embedder   = getattr(_builtins, _SINGLETON_KEY_EMBEDDER,   None)
_reranker   = getattr(_builtins, _SINGLETON_KEY_RERANKER,   None)
_reranker_available = getattr(_builtins, _SINGLETON_KEY_RERANK_OK, None)


def _get_embedder():
    global _embedder
    cached = getattr(_builtins, _SINGLETON_KEY_EMBEDDER, None)
    if cached is not None:
        _embedder = cached
        return cached
    if _embedder is not None:
        setattr(_builtins, _SINGLETON_KEY_EMBEDDER, _embedder)
        return _embedder
    # Serialise the load so N concurrent first-callers (parallel hosts) don't each
    # load their own copy.  Re-check the cache inside the lock.
    with _MODEL_LOAD_LOCK:
        cached = getattr(_builtins, _SINGLETON_KEY_EMBEDDER, None)
        if cached is not None:
            _embedder = cached
            return cached
        from sentence_transformers import SentenceTransformer
        logger.info("Loading embedding model: %s (max_length=%s)", EMBED_MODEL, EMBED_MAX_LENGTH)
        _embedder = SentenceTransformer(EMBED_MODEL)
        # Override tokenizer max_length to use the model's full context window.
        # bge-m3 supports 8192 tokens; BERT-based models are capped at 512.
        _embedder.max_seq_length = EMBED_MAX_LENGTH
        try:                       # name renamed in newer sentence-transformers
            _dim = _embedder.get_embedding_dimension()
        except AttributeError:
            _dim = _embedder.get_sentence_embedding_dimension()
        logger.info("Embedding model ready — dim=%s", _dim)
        setattr(_builtins, _SINGLETON_KEY_EMBEDDER, _embedder)
        return _embedder


def _get_collection():
    global _client, _collection
    cached_coll   = getattr(_builtins, _SINGLETON_KEY_COLLECTION, None)
    cached_client = getattr(_builtins, _SINGLETON_KEY_CLIENT,     None)
    if cached_coll is not None:
        _collection = cached_coll
        _client     = cached_client
        return cached_coll
    if _collection is not None:
        setattr(_builtins, _SINGLETON_KEY_COLLECTION, _collection)
        setattr(_builtins, _SINGLETON_KEY_CLIENT,     _client)
        return _collection
    # One Chroma client per process — concurrent PersistentClient opens on the
    # same path can conflict; serialise + re-check inside the lock.
    with _MODEL_LOAD_LOCK:
        cached_coll = getattr(_builtins, _SINGLETON_KEY_COLLECTION, None)
        if cached_coll is not None:
            _collection = cached_coll
            _client     = getattr(_builtins, _SINGLETON_KEY_CLIENT, None)
            return cached_coll
        import chromadb
        from chromadb.config import Settings
        os.makedirs(CHROMA_PATH, exist_ok=True)
        _client = chromadb.PersistentClient(
            path=CHROMA_PATH,
            settings=Settings(anonymized_telemetry=False)
        )
        _collection = _client.get_or_create_collection(
            name=COLLECTION,
            metadata={"hnsw:space": "cosine"}
        )
        logger.info("ChromaDB collection ready: %s chunks indexed", _collection.count())
        setattr(_builtins, _SINGLETON_KEY_COLLECTION, _collection)
        setattr(_builtins, _SINGLETON_KEY_CLIENT,     _client)
        return _collection


def _get_reranker():
    """Lazy-load cross-encoder reranker. Returns None if unavailable."""
    global _reranker, _reranker_available
    cached = getattr(_builtins, _SINGLETON_KEY_RERANKER, None)
    if cached is not None:
        _reranker = cached
        _reranker_available = True
        return cached
    cached_flag = getattr(_builtins, _SINGLETON_KEY_RERANK_OK, None)
    if cached_flag is False:
        _reranker_available = False
        return None
    if _reranker is not None:
        setattr(_builtins, _SINGLETON_KEY_RERANKER, _reranker)
        return _reranker
    if _reranker_available is False:
        return None
    if not RERANK_MODEL:
        _reranker_available = False
        setattr(_builtins, _SINGLETON_KEY_RERANK_OK, False)
        return None
    # Serialise: the reranker is ~1.1 GB on CPU.  Without this lock every host's
    # first KB query loaded its OWN copy concurrently — the freeze.  Re-check the
    # cache inside the lock so only the first caller loads; the rest reuse it.
    with _MODEL_LOAD_LOCK:
        cached = getattr(_builtins, _SINGLETON_KEY_RERANKER, None)
        if cached is not None:
            _reranker = cached
            _reranker_available = True
            return cached
        if getattr(_builtins, _SINGLETON_KEY_RERANK_OK, None) is False:
            _reranker_available = False
            return None
        try:
            from sentence_transformers import CrossEncoder
            logger.info("Loading reranker: %s", RERANK_MODEL)
            _reranker = CrossEncoder(RERANK_MODEL, max_length=512)   # BERT hard limit is 512 tokens
            _reranker_available = True
            logger.info("Reranker ready")
            setattr(_builtins, _SINGLETON_KEY_RERANKER, _reranker)
            setattr(_builtins, _SINGLETON_KEY_RERANK_OK, True)
            return _reranker
        except Exception as e:
            logger.warning("Reranker unavailable (%s) — using cosine similarity only", e)
            _reranker_available = False
            setattr(_builtins, _SINGLETON_KEY_RERANK_OK, False)
            return None


# ── Metadata merge for content-hash dedup ──────────────────────────────────────
# Used by ingest() when an incoming chunk hashes to an ID already present in
# the collection (i.e. identical content from a different source file).  We
# don't want to lose the new source's tags — instead, union the list-valued
# fields and keep the more-specific scalar values.
_MERGE_UNION_FIELDS = {
    "cves", "mitre_ttps", "tools", "attack_types", "services", "ports",
    "alt_sources", "alt_source_files",
}
_MERGE_KEEP_BETTER  = {
    # If existing value is empty / "unknown" / None, prefer the new value.
    "outcome", "phase", "os", "box_name", "difficulty",
}


def _merge_dup_metadata(col, doc_id: str, existing: Dict[str, Any],
                        incoming: Dict[str, Any], source_file: str) -> None:
    """Merge `incoming` into `existing` and write back via col.update().

    No-op if the merge wouldn't change anything (saves a write).
    """
    merged = dict(existing)
    changed = False

    # Track alternative source files that contributed identical chunks so the
    # operator can see provenance breadth in the metadata.
    alt = merged.get("alt_source_files")
    try:
        alt_list = json.loads(alt) if isinstance(alt, str) else (alt or [])
    except (ValueError, TypeError):
        alt_list = []
    src_name = os.path.basename(source_file)
    if src_name and src_name != merged.get("source_file") and src_name not in alt_list:
        alt_list.append(src_name)
        merged["alt_source_files"] = json.dumps(alt_list)
        changed = True

    # Union list-valued tag fields
    for field in _MERGE_UNION_FIELDS:
        new_val = incoming.get(field)
        if not new_val:
            continue
        try:
            new_list = json.loads(new_val) if isinstance(new_val, str) else list(new_val)
        except (ValueError, TypeError):
            new_list = [new_val]
        cur = merged.get(field)
        try:
            cur_list = json.loads(cur) if isinstance(cur, str) else list(cur or [])
        except (ValueError, TypeError):
            cur_list = []
        union = list(dict.fromkeys(cur_list + new_list))   # order-preserving
        if union != cur_list:
            merged[field] = json.dumps(union)
            changed = True

    # Promote scalar fields if the existing value is empty/unknown
    for field in _MERGE_KEEP_BETTER:
        new_val = incoming.get(field)
        cur_val = merged.get(field)
        if new_val and (not cur_val or str(cur_val).lower() in ("unknown", "none", "")):
            merged[field] = str(new_val)
            changed = True

    if changed:
        try:
            col.update(ids=[doc_id], metadatas=[merged])
        except Exception as exc:
            logger.debug("col.update failed for %s: %s", doc_id, exc)


# ── Query expansion ─────────────────────────────────────────────────────────────

def _expand_query(query: str) -> List[str]:
    """
    Generate query variations to improve recall.
    Returns 1–3 query strings covering different angles.
    """
    queries = [query]
    q = query.lower()

    if any(w in q for w in ["exploit", "rce", "shell", "payload", "reverse"]):
        queries.append(f"{query} reverse shell payload command execution foothold")
    elif any(w in q for w in ["recon", "scan", "enum", "discover", "port"]):
        queries.append(f"{query} nmap service version enumeration open ports")
    elif any(w in q for w in ["privesc", "escalat", "root", "sudo", "suid"]):
        queries.append(f"{query} privilege escalation sudo SUID cron GTFOBins linpeas")
    elif any(w in q for w in ["web", "http", "sqli", "xss", "lfi", "upload", "burp"]):
        queries.append(f"{query} web application vulnerability bypass injection")
    elif any(w in q for w in ["password", "hash", "crack", "brute", "credential"]):
        queries.append(f"{query} hashcat john password hash cracking wordlist rockyou")
    elif any(w in q for w in ["lateral", "pivot", "smb", "winrm", "psexec"]):
        queries.append(f"{query} lateral movement pivot proxychains network traversal")
    elif any(w in q for w in ["ad", "active directory", "kerberos", "ldap", "domain"]):
        queries.append(f"{query} Active Directory BloodHound kerberoasting pass-the-hash")

    return queries[:3]


# ── Public API ──────────────────────────────────────────────────────────────────

def ingest(
    text: str,
    source_file: str,
    chunk_index: int,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Add one text chunk to the knowledge base.
    Returns True if added, False if duplicate (same hash already exists).

    metadata keys (all optional):
      chunk_type    : str         "command" | "script" | "procedure" | "technique" |
                                  "tip" | "finding" | "tool_usage" | "output" | "report"
      services      : list[str]   e.g. ["apache 2.4", "openssh 7.2"]
      ports         : list[int]   e.g. [80, 443]
      cves          : list[str]   e.g. ["CVE-2021-41773"]
      mitre_ttps    : list[str]   e.g. ["T1059", "T1548.003"]
      tools         : list[str]   e.g. ["gobuster", "sqlmap"]
      outcome       : str         "shell obtained" | "root" | "user flag" | "failed"
      attack_types  : list[str]   e.g. ["sqli", "lfi_rce"]
      os            : str         "linux ubuntu 18.04" | "windows server 2019"
      phase         : str         "recon" | "exploit" | "privesc" | "web" | "post" | "lateral"
      difficulty    : str         "easy" | "medium" | "hard" | "insane"
      box_name      : str         "lame" | "jerry" | "buff" (HTB/THM names)
      section_title : str         Heading of the section this chunk belongs to
    """
    if not text or len(text.strip()) < 40:
        try:
            from knowledge import rag_logger as _rl
            _rl.log_ingest(source_file, (metadata or {}).get("chunk_type", "technique"),
                           "", False, len(text or ""), reason="too_short")
        except Exception:
            pass
        return False

    # ── CONTENT-BASED CHUNK ID (dedup-by-design) ─────────────────────────────
    # Previous formula hashed (source_file:chunk_index:text[:80]).  That made
    # the ID *file-scoped* — two files with identical text (e.g. MITRE ATT&CK
    # v15 vs v19) produced different IDs, so both got embedded.  Result: a
    # 96% duplicate corpus on real-world data.
    #
    # New formula hashes a normalised view of the chunk text alone.  Same
    # text from any file → same ID → ChromaDB upsert is idempotent, and we
    # merge metadata from the duplicate occurrence so its tags aren't lost.
    normalized = " ".join(text.strip().lower().split())
    doc_id = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:24]

    col = _get_collection()

    # Already present → MERGE metadata instead of dropping the duplicate's tags
    existing = col.get(ids=[doc_id], include=["metadatas"])
    if existing["ids"]:
        if metadata:
            try:
                _merge_dup_metadata(col, doc_id,
                                    (existing.get("metadatas") or [{}])[0] or {},
                                    metadata, source_file)
            except Exception as _merge_exc:
                logger.debug("metadata merge failed for %s: %s", doc_id, _merge_exc)
        try:
            from knowledge import rag_logger as _rl
            _rl.log_ingest(source_file, (metadata or {}).get("chunk_type", "technique"),
                           doc_id, False, len(text), reason="duplicate")
        except Exception:
            pass
        return False

    # ── RAG growth guardrail: never let the store overwhelm the host ──────────
    # Blocked when over the chunk/DB cap or when free disk/RAM run low.  Checked
    # BEFORE the (expensive) embedding so a blocked ingest wastes no compute.
    try:
        from knowledge import rag_budget as _rb
        _ok, _why = _rb.ingest_allowed()
        if not _ok:
            try:
                from knowledge import rag_logger as _rl
                _rl.log_ingest(source_file, (metadata or {}).get("chunk_type", "technique"),
                               "", False, len(text), reason=f"budget:{_why}")
            except Exception:
                pass
            return False
    except Exception:
        pass

    embedder  = _get_embedder()

    # Prepend chunk_type context to improve embedding quality
    chunk_type = (metadata or {}).get("chunk_type", "technique")
    prefix_map = {
        "command":    "Security tool command: ",
        "script":     "Security script or payload: ",
        "procedure":  "Penetration testing procedure: ",
        "technique":  "Security technique: ",
        "playbook":   "Red team attack playbook: ",
        "tip":        "Security tip or trick: ",
        "finding":    "Vulnerability finding: ",
        "tool_usage": "Security tool usage: ",
        "output":     "Tool output or scan result: ",
        "report":     "Penetration test report: ",
    }
    embed_text = prefix_map.get(chunk_type, "") + text
    embedding  = embedder.encode(embed_text, normalize_embeddings=True).tolist()

    meta = {
        "source_file":   os.path.basename(source_file),
        "chunk_index":   chunk_index,
        "text_preview":  text[:200],
        "chunk_type":    chunk_type,
    }
    if metadata:
        for k, v in metadata.items():
            if k == "chunk_type":
                continue  # already set
            if isinstance(v, list):
                meta[k] = json.dumps(v)
            elif v is not None:
                meta[k] = str(v)

    col.add(ids=[doc_id], embeddings=[embedding], documents=[text], metadatas=[meta])
    try:
        from knowledge import rag_logger as _rl
        _rl.log_ingest(source_file, chunk_type, doc_id, True, len(text))
    except Exception:
        pass
    return True


def ingest_tip(
    text: str,
    category: str = "general",
    source: str = "manual",
    extra_metadata: Optional[Dict] = None,
) -> bool:
    """
    Convenience function: ingest a single tip/trick/technique into the KB.

    Args:
        text      : The tip text (can be multi-line)
        category  : e.g. "privesc", "web", "recon", "exploit", "post"
        source    : identifier string (default: "manual")
        extra_metadata : additional metadata dict

    Returns True if added.
    """
    meta: Dict[str, Any] = {
        "chunk_type": "tip",
        "phase":      category,
        "outcome":    "unknown",
        "source_type": "manual_tip",
    }
    if extra_metadata:
        meta.update(extra_metadata)

    # Use a counter-based index for manual tips
    tip_hash = hashlib.sha256(text.encode()).hexdigest()[:8]
    chunk_idx = int(tip_hash, 16) % 999999

    return ingest(text=text, source_file=source, chunk_index=chunk_idx, metadata=meta)


def _trim_reranked(results, floor: float = 0.0):
    """Drop reranker-rejected padding (relevance <= floor) so the operator's
    context isn't filled with chunks the cross-encoder judged irrelevant — but
    always keep at least the best hit(s) so a query never returns empty just
    because its top score is marginally below the boundary."""
    keep = [c for c in (results or []) if float(c.get("relevance", 0)) > floor]
    return keep if keep else (results or [])[:min(2, len(results or []))]


def search_raw(
    query: str,
    top_k: int = MAX_RESULTS,
    phase_filter: Optional[str] = None,
    outcome_filter: Optional[str] = None,
    chunk_type_filter: Optional[str] = None,
    use_reranker: bool = True,
    expand_query: bool = True,
) -> List[Dict[str, Any]]:
    """
    Semantic search returning structured result dicts.

    Each result dict contains:
      text, source_file, chunk_index, chunk_type, phase, outcome,
      tools, cves, mitre_ttps, attack_types, box_name, os,
      relevance (float, higher = better), section_title

    Results are sorted by relevance descending.
    Returns empty list if nothing found above MIN_RELEVANCE.
    """
    if not query or not query.strip():
        return []

    import time as _t
    _t0 = _t.monotonic()
    _caller = ""
    try:
        from knowledge import rag_logger as _rl
        _caller = _rl.caller_hint()
    except Exception:
        _rl = None

    col = _get_collection()
    total = col.count()
    if total == 0:
        if _rl is not None:
            try:
                _rl.log_search(query, [], (_t.monotonic() - _t0) * 1000, _caller, 0, reason="kb_empty")
            except Exception:
                pass
        return []

    embedder = _get_embedder()

    # Multi-query expansion for better recall
    queries = _expand_query(query) if expand_query else [query]
    fetch_n  = min(RERANK_FETCH if use_reranker else top_k * 2, total)

    # Build ChromaDB where clause
    where: Dict = {}
    conditions = []
    if phase_filter:
        conditions.append({"phase": {"$eq": phase_filter}})
    if outcome_filter:
        conditions.append({"outcome": {"$eq": outcome_filter}})
    if chunk_type_filter:
        conditions.append({"chunk_type": {"$eq": chunk_type_filter}})

    if len(conditions) == 1:
        where = conditions[0]
    elif len(conditions) > 1:
        where = {"$and": conditions}

    # Collect candidate results from all queries (deduplicate by doc id)
    seen_ids: Dict[str, Dict] = {}

    for q in queries:
        emb = embedder.encode(q, normalize_embeddings=True).tolist()
        kwargs: Dict[str, Any] = dict(
            query_embeddings=[emb],
            n_results=fetch_n,
            include=["documents", "metadatas", "distances"],
        )
        if where:
            kwargs["where"] = where

        try:
            results = col.query(**kwargs)
        except Exception as e:
            logger.warning("ChromaDB query error: %s", e)
            continue

        docs      = results["documents"][0]
        metas     = results["metadatas"][0]
        distances = results["distances"][0]

        for doc, meta, dist in zip(docs, metas, distances):
            relevance = 1.0 - dist
            if relevance < MIN_RELEVANCE:
                continue
            # Stable key: source_file + chunk_index
            key = f"{meta.get('source_file','')}:{meta.get('chunk_index','')}"
            if key not in seen_ids or seen_ids[key]["relevance"] < relevance:
                seen_ids[key] = {
                    "text":          doc,
                    "source_file":   meta.get("source_file", "unknown"),
                    "chunk_index":   meta.get("chunk_index", 0),
                    "chunk_type":    meta.get("chunk_type", "technique"),
                    "phase":         meta.get("phase", ""),
                    "outcome":       meta.get("outcome", ""),
                    "tools":         _parse_list(meta.get("tools", "")),
                    "cves":          _parse_list(meta.get("cves", "")),
                    "mitre_ttps":    _parse_list(meta.get("mitre_ttps", "")),
                    "attack_types":  _parse_list(meta.get("attack_types", "")),
                    "services":      _parse_list(meta.get("services", "")),
                    "box_name":      meta.get("box_name", ""),
                    "os":            meta.get("os", ""),
                    "difficulty":    meta.get("difficulty", ""),
                    "section_title": meta.get("section_title", ""),
                    "relevance":     relevance,
                }

    candidates = list(seen_ids.values())
    if not candidates:
        if _rl is not None:
            try:
                _rl.log_search(query, [], (_t.monotonic() - _t0) * 1000, _caller, total,
                               reason="below_min_relevance")
            except Exception:
                pass
        return []

    # Optional cross-encoder reranking
    reranker = _get_reranker() if use_reranker else None
    _reranked = False
    if reranker and len(candidates) > 1:
        try:
            pairs  = [(query, c["text"]) for c in candidates]
            scores = reranker.predict(pairs)
            for c, s in zip(candidates, scores):
                c["relevance"] = float(s)
            _reranked = True
        except Exception as e:
            logger.warning("Reranker failed: %s — using cosine scores", e)

    # Sort by relevance, take top_k
    candidates.sort(key=lambda x: x["relevance"], reverse=True)
    _out = candidates[:top_k]

    # Post-rerank relevance-floor trim: the cross-encoder gives padding chunks a
    # NEGATIVE score (it judged them irrelevant), but they still fill top_k and
    # become noise in the operator's context.  When the reranker ran, drop results
    # at/below the floor — but always keep at least the best hit so a query never
    # returns empty just because its top score is marginally negative.  Only the
    # reranked path is trimmed (cosine scores are already MIN_RELEVANCE-filtered).
    # Disable with ARGUS_RAG_TRIM=0; tune the boundary with ARGUS_RAG_RERANK_FLOOR.
    if _reranked and os.environ.get("ARGUS_RAG_TRIM", "1") != "0":
        try:
            _floor = float(os.environ.get("ARGUS_RAG_RERANK_FLOOR", "0.0"))
        except ValueError:
            _floor = 0.0
        _out = _trim_reranked(_out, _floor)

    if _rl is not None:
        try:
            _rl.log_search(query, _out, (_t.monotonic() - _t0) * 1000, _caller, total)
        except Exception:
            pass
    return _out


def search(
    query: str,
    top_k: int = MAX_RESULTS,
    phase_filter: Optional[str] = None,
    outcome_filter: Optional[str] = None,
    chunk_type_filter: Optional[str] = None,
) -> str:
    """
    Semantic search returning a formatted string ready for LLM injection.

    Returns empty string if nothing relevant found.
    """
    results = search_raw(
        query=query,
        top_k=top_k,
        phase_filter=phase_filter,
        outcome_filter=outcome_filter,
        chunk_type_filter=chunk_type_filter,
    )

    if not results:
        return ""

    chunks = []
    for r in results:
        icon   = CHUNK_TYPE_ICONS.get(r["chunk_type"], "📝")
        source = r["source_file"]
        box    = r["box_name"]
        phase  = r["phase"]
        outcome = r["outcome"]
        rel    = r["relevance"]
        ctype  = r["chunk_type"]
        section = r.get("section_title", "")

        # Header line
        header_parts = [f"{icon} [{source}"]
        if box:
            header_parts.append(f" · {box}")
        if section:
            header_parts.append(f" § {section}")
        if phase:
            header_parts.append(f" · {phase}")
        if outcome and outcome not in ("unknown", ""):
            header_parts.append(f" → {outcome}")
        header_parts.append(f" · {rel:.2f}]")
        header = "".join(header_parts)

        # Tag line
        tags = []
        if r["tools"]:
            tags.append(f"tools: {', '.join(r['tools'][:6])}")
        if r["cves"]:
            tags.append(f"cves: {', '.join(r['cves'][:3])}")
        if r["mitre_ttps"]:
            tags.append(f"mitre: {', '.join(r['mitre_ttps'][:4])}")
        if r["attack_types"]:
            tags.append(f"techniques: {', '.join(r['attack_types'][:4])}")

        # Body — show more text for command/script/procedure, less for others
        max_body = 800 if ctype in ("command", "script", "procedure") else 600
        body = r["text"].strip()[:max_body]
        if len(r["text"].strip()) > max_body:
            body += "…"

        chunk_lines = [header]
        if tags:
            chunk_lines.append("  " + " | ".join(tags))
        chunk_lines.append(f"  {body}")
        chunks.append("\n".join(chunk_lines))

    return (
        "=== KNOWLEDGE BASE: RELEVANT PAST EXPERIENCE ===\n"
        + "\n\n".join(chunks)
        + "\n=== END KNOWLEDGE BASE ===\n"
        "Apply the above examples to inform your decisions. "
        "Prefer techniques and commands that previously succeeded. "
        "These examples are from DIFFERENT past targets — host identifiers are "
        "redacted to <host>/<mac>/<redacted>. Reuse the METHOD (product/version, "
        "CVE, port, payload, technique), but ALWAYS substitute the CURRENT "
        "target's address/hostname/credentials — never reuse an old IP or host."
    )


def search_commands(query: str, top_k: int = 5) -> List[str]:
    """
    Return raw command-type chunks relevant to the query.
    Useful for agents that need specific tool invocation examples.
    """
    results = search_raw(
        query=query,
        top_k=top_k,
        chunk_type_filter="command",
        expand_query=True,
    )
    if not results:
        # Fall back to any chunk type if no command chunks found
        results = search_raw(query=query, top_k=top_k, expand_query=True)

    return [r["text"] for r in results]


def search_procedures(query: str, top_k: int = 3) -> List[str]:
    """
    Return raw procedure-type chunks (step-by-step processes).
    """
    results = search_raw(
        query=query,
        top_k=top_k,
        chunk_type_filter="procedure",
        expand_query=True,
    )
    return [r["text"] for r in results]


def search_scripts(query: str, top_k: int = 3) -> List[str]:
    """
    Return raw script/payload-type chunks.
    """
    results = search_raw(
        query=query,
        top_k=top_k,
        chunk_type_filter="script",
        expand_query=True,
    )
    return [r["text"] for r in results]


def stats() -> Dict[str, Any]:
    """Return counts and metadata summary for the UI."""
    try:
        col   = _get_collection()
        total = col.count()
        # Sample up to 2000 to aggregate metadata
        sample = col.get(limit=min(2000, total), include=["metadatas"])
        sources:     set  = set()
        phases:      dict = {}
        outcomes:    dict = {}
        chunk_types: dict = {}

        for meta in sample["metadatas"]:
            sources.add(meta.get("source_file", "?"))
            p = meta.get("phase", "unknown")
            phases[p] = phases.get(p, 0) + 1
            o = meta.get("outcome", "unknown")
            outcomes[o] = outcomes.get(o, 0) + 1
            ct = meta.get("chunk_type", "unknown")
            chunk_types[ct] = chunk_types.get(ct, 0) + 1

        # Resource metering (storage / RAM / chunk-budget) — best-effort.
        resources: Dict[str, Any] = {}
        try:
            from knowledge import rag_budget as _rb
            resources = _rb.usage()
        except Exception:
            pass
        return {
            "total_chunks": total,
            "source_files": len(sources),
            "by_phase":      phases,
            "by_outcome":    outcomes,
            "by_chunk_type": chunk_types,
            "note":          "by_phase/outcome/chunk_type are from a 2000-chunk sample, not the full corpus",
            "embed_model":   EMBED_MODEL,
            "rerank_model":  RERANK_MODEL or "disabled",
            "db_path":       CHROMA_PATH,
            "resources":     resources,
        }
    except Exception as e:
        return {"error": str(e), "total_chunks": 0}


# ── Helpers ──────────────────────────────────────────────────────────────────────

def _parse_list(value: Any) -> List[str]:
    """Parse a JSON-serialized list string or return empty list."""
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return [str(value)] if value else []
