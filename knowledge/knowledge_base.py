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
CHROMA_PATH   = os.path.join(os.path.dirname(__file__), "chroma_db")
COLLECTION    = "pentest_knowledge"

# Primary embedding model — choose one:
#   "BAAI/bge-m3"             → ~570 MB, 1024-dim, 8192 token ctx, best quality  ← ACTIVE
#   "all-MiniLM-L6-v2"        → ~80 MB,  384-dim, fast CPU, good quality
#   "all-mpnet-base-v2"       → ~420 MB, 768-dim, slower, better quality
#   "BAAI/bge-small-en-v1.5"  → ~130 MB, 384-dim, good quality, instruction-tuned
#   "BAAI/bge-large-en-v1.5"  → ~1.3 GB, 1024-dim, best English-only quality
# NOTE: changing model requires --reset (dimensions must match entire collection)
EMBED_MODEL   = os.environ.get("KB_EMBED_MODEL", "BAAI/bge-m3")

# Optional cross-encoder reranking model (set KB_RERANK_MODEL="" to disable)
#   "cross-encoder/ms-marco-MiniLM-L-6-v2" → ~70 MB, BERT-based, 512-token limit
#   "cross-encoder/ms-marco-MiniLM-L-12-v2" → ~120 MB, higher quality, same 512-token limit
RERANK_MODEL  = os.environ.get("KB_RERANK_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")

MAX_RESULTS   = 6           # results returned to agent per query
MIN_RELEVANCE = 0.28        # cosine similarity threshold
RERANK_FETCH  = 25          # candidates fetched from ChromaDB before reranking to top MAX_RESULTS

# bge-m3 supports up to 8192 tokens; set here so _get_embedder() can use it
EMBED_MAX_LENGTH = 8192 if "bge-m3" in EMBED_MODEL else 512

# Chunk type icons for formatted output
CHUNK_TYPE_ICONS = {
    "command":    "⚡",
    "script":     "📜",
    "procedure":  "📋",
    "technique":  "🎯",
    "tip":        "💡",
    "finding":    "🔍",
    "tool_usage": "🔧",
    "output":     "📊",
    "report":     "📄",
    "unknown":    "📝",
}

# ── Lazy singletons ─────────────────────────────────────────────────────────────
_client     = None
_collection = None
_embedder   = None
_reranker   = None
_reranker_available = None   # None = untested, True/False = tested


def _get_embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        logger.info(f"Loading embedding model: {EMBED_MODEL} (max_length={EMBED_MAX_LENGTH})")
        _embedder = SentenceTransformer(EMBED_MODEL)
        # Override tokenizer max_length to use the model's full context window.
        # bge-m3 supports 8192 tokens; BERT-based models are capped at 512.
        _embedder.max_seq_length = EMBED_MAX_LENGTH
        logger.info(f"Embedding model ready — dim={_embedder.get_sentence_embedding_dimension()}")
    return _embedder


def _get_collection():
    global _client, _collection
    if _collection is None:
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
        logger.info(f"ChromaDB collection ready: {_collection.count()} chunks indexed")
    return _collection


def _get_reranker():
    """Lazy-load cross-encoder reranker. Returns None if unavailable."""
    global _reranker, _reranker_available
    if _reranker_available is False:
        return None
    if _reranker is not None:
        return _reranker
    if not RERANK_MODEL:
        _reranker_available = False
        return None
    try:
        from sentence_transformers import CrossEncoder
        logger.info(f"Loading reranker: {RERANK_MODEL}")
        _reranker = CrossEncoder(RERANK_MODEL, max_length=512)   # BERT hard limit is 512 tokens
        _reranker_available = True
        logger.info("Reranker ready")
        return _reranker
    except Exception as e:
        logger.warning(f"Reranker unavailable ({e}) — using cosine similarity only")
        _reranker_available = False
        return None


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
        return False

    # Stable ID: hash of source + index + first 80 chars
    doc_id = hashlib.sha256(
        f"{source_file}:{chunk_index}:{text[:80]}".encode()
    ).hexdigest()[:24]

    col = _get_collection()

    # Skip duplicates
    existing = col.get(ids=[doc_id])
    if existing["ids"]:
        return False

    embedder  = _get_embedder()

    # Prepend chunk_type context to improve embedding quality
    chunk_type = (metadata or {}).get("chunk_type", "technique")
    prefix_map = {
        "command":    "Security tool command: ",
        "script":     "Security script or payload: ",
        "procedure":  "Penetration testing procedure: ",
        "technique":  "Security technique: ",
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

    col = _get_collection()
    total = col.count()
    if total == 0:
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
            logger.warning(f"ChromaDB query error: {e}")
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
        return []

    # Optional cross-encoder reranking
    reranker = _get_reranker() if use_reranker else None
    if reranker and len(candidates) > 1:
        try:
            pairs  = [(query, c["text"]) for c in candidates]
            scores = reranker.predict(pairs)
            for c, s in zip(candidates, scores):
                c["relevance"] = float(s)
        except Exception as e:
            logger.warning(f"Reranker failed: {e} — using cosine scores")

    # Sort by relevance, take top_k
    candidates.sort(key=lambda x: x["relevance"], reverse=True)
    return candidates[:top_k]


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
        "Adapt commands to the current target."
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

        return {
            "total_chunks": total,
            "source_files": len(sources),
            "by_phase":      phases,
            "by_outcome":    outcomes,
            "by_chunk_type": chunk_types,
            "embed_model":   EMBED_MODEL,
            "rerank_model":  RERANK_MODEL or "disabled",
            "db_path":       CHROMA_PATH,
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
