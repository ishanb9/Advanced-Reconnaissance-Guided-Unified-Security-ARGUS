"""
dedupe_kb.py — find and (optionally) remove duplicate chunks from the
ARGUS ChromaDB knowledge base.

Three dedup strategies:

  exact     hash(full chunk text)               — catches true duplicates
  near      hash(first 200 chars)               — catches overlapping-window dupes
  semantic  cosine sim > threshold (default .97) — catches near-duplicate paraphrases

Default mode is REPORT ONLY (no deletions).  Pass --apply to actually
delete extras.  When deleting a duplicate group, we keep the row with
the lowest chunk_index (most likely the original ingest) and remove
the rest.

USAGE
─────

  # Show how many duplicates exist (no changes)
  python knowledge/dedupe_kb.py --mode exact

  # Same, but with the overlap-window-aware near-dup detector
  python knowledge/dedupe_kb.py --mode near

  # Actually delete exact duplicates
  python knowledge/dedupe_kb.py --mode exact --apply

  # Show top-20 source files contributing the most duplicates
  python knowledge/dedupe_kb.py --mode exact --top-sources 20

  # Semantic dedup (expensive — uses HNSW search, requires the embedder
  # model to be loaded; ~5-30 min for a 700k corpus)
  python knowledge/dedupe_kb.py --mode semantic --threshold 0.97

ENV VARS HONOURED
─────────────────
  KB_DB_PATH       — chroma persistent directory (default: knowledge/db)
  KB_EMBED_MODEL   — only used in --mode semantic

BATCHING
────────
The script streams the collection in batches of 5,000 rows so it won't
hold the entire corpus in RAM.  Safe to run on Kali alongside other
processes (uses < 500 MB even at the 700k scale).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Resolve DB path the same way knowledge_base.py does
_BASE = Path(__file__).resolve().parent
_DEFAULT_DB = _BASE / "db"
_LEGACY_DB  = _BASE / "chroma_db"


def resolve_db_path() -> Path:
    env = os.environ.get("KB_DB_PATH")
    if env:
        return Path(env)
    if _DEFAULT_DB.is_dir():
        return _DEFAULT_DB
    if _LEGACY_DB.is_dir():
        return _LEGACY_DB
    return _DEFAULT_DB


COLLECTION_NAME = "pentest_knowledge"
BATCH = 5_000


def get_collection():
    import chromadb
    from chromadb.config import Settings
    db = resolve_db_path()
    if not db.exists():
        sys.exit(f"ERR: KB db not found at {db}")
    print(f"[INFO] Connecting to ChromaDB at {db}", flush=True)
    client = chromadb.PersistentClient(
        path=str(db),
        settings=Settings(anonymized_telemetry=False),
    )
    return client.get_or_create_collection(
        name=COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
    )


def iter_collection(col, want_embeddings: bool = False):
    """Yield (ids, docs, metas, embs?) batches of size BATCH."""
    total = col.count()
    print(f"[INFO] Collection has {total:,} chunks", flush=True)
    offset = 0
    t0 = time.time()
    while offset < total:
        include = ["documents", "metadatas"]
        if want_embeddings:
            include.append("embeddings")
        batch = col.get(limit=BATCH, offset=offset, include=include)
        ids   = batch.get("ids") or []
        docs  = batch.get("documents") or []
        metas = batch.get("metadatas") or []
        embs  = batch.get("embeddings") if want_embeddings else None
        if not ids:
            break
        yield ids, docs, metas, embs
        offset += len(ids)
        if offset % (BATCH * 4) == 0:
            elapsed = time.time() - t0
            rate = offset / max(elapsed, 1e-6)
            eta = (total - offset) / max(rate, 1e-6)
            print(f"  scanned {offset:,}/{total:,}  ({rate:,.0f}/s, ETA {eta/60:.1f}m)",
                  flush=True)


def hash_full(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def hash_prefix(text: str, n: int = 200) -> str:
    """Normalize whitespace + lowercase first N chars."""
    norm = " ".join(text.strip().lower().split())[:n]
    return hashlib.sha256(norm.encode("utf-8", errors="replace")).hexdigest()


def index_of_meta(meta: Optional[dict]) -> int:
    """Lowest chunk_index wins (preserves the original ingest)."""
    if not meta:
        return 10**9
    v = meta.get("chunk_index", meta.get("chunk_idx"))
    try:
        return int(v)
    except (TypeError, ValueError):
        return 10**9


def source_of_meta(meta: Optional[dict]) -> str:
    if not meta:
        return "<unknown>"
    for k in ("source_file", "source", "path", "file"):
        v = meta.get(k)
        if v:
            return str(v)
    return "<unknown>"


# ────────────────────────────────────────────────────────────────────────────
# exact / near modes — single-pass hash-based dedup
# ────────────────────────────────────────────────────────────────────────────

def find_hash_duplicates(col, mode: str) -> Tuple[Dict[str, List[str]], Dict[str, dict]]:
    """Return (hash → list-of-ids, id → meta) for chunks sharing a hash."""
    hashes: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
    meta_of: Dict[str, dict] = {}
    src_of:  Dict[str, str]  = {}

    hash_fn = hash_full if mode == "exact" else hash_prefix
    total_scanned = 0

    for ids, docs, metas, _ in iter_collection(col):
        for cid, text, meta in zip(ids, docs, metas):
            if not text:
                continue
            h = hash_fn(text)
            hashes[h].append((cid, index_of_meta(meta)))
            meta_of[cid] = meta or {}
            src_of[cid]  = source_of_meta(meta)
            total_scanned += 1

    print(f"[INFO] Scanned {total_scanned:,} chunks", flush=True)

    # Filter to only hashes with > 1 occurrence
    dupes: Dict[str, List[str]] = {}
    for h, pairs in hashes.items():
        if len(pairs) < 2:
            continue
        # Sort by chunk_index ASC so the keeper is first
        pairs.sort(key=lambda x: (x[1], x[0]))
        dupes[h] = [cid for cid, _ in pairs]

    return dupes, meta_of


# ────────────────────────────────────────────────────────────────────────────
# semantic mode — cosine-similarity HNSW dedup
# ────────────────────────────────────────────────────────────────────────────

def find_semantic_duplicates(col, threshold: float) -> Tuple[Dict[str, List[str]], Dict[str, dict]]:
    """For each chunk, query the index for its 5 nearest neighbours; any
    neighbour with cosine distance < (1 - threshold) is a semantic duplicate.

    Returns the same (hash → ids, id → meta) shape so the deletion code is
    shared.  "Hash" here is a synthetic group key.
    """
    print(f"[INFO] Semantic mode — neighbour search at sim >= {threshold}", flush=True)
    cosine_distance_cutoff = 1.0 - threshold

    # Build seed list of (id, embedding) — stream to keep RAM bounded
    visited: set = set()
    group_of: Dict[str, str] = {}   # cid → group leader id
    dupes:    Dict[str, List[str]] = defaultdict(list)
    meta_of:  Dict[str, dict] = {}

    for ids, _docs, metas, embs in iter_collection(col, want_embeddings=True):
        for cid, emb, meta in zip(ids, embs, metas):
            if cid in visited:
                continue
            meta_of[cid] = meta or {}
            try:
                res = col.query(
                    query_embeddings = [emb],
                    n_results        = 5,
                    include          = ["distances", "metadatas"],
                )
            except Exception as exc:
                print(f"  [WARN] query failed for {cid[:12]}: {exc}", flush=True)
                continue
            neigh_ids   = (res.get("ids")       or [[]])[0]
            neigh_dists = (res.get("distances") or [[]])[0]
            neigh_metas = (res.get("metadatas") or [[]])[0]

            # Always seed the leader with the current chunk
            group = [cid]
            for nid, nd, nmeta in zip(neigh_ids, neigh_dists, neigh_metas):
                if nid == cid:
                    continue
                if nd is None or nd > cosine_distance_cutoff:
                    continue
                # Skip already-grouped
                if nid in visited:
                    continue
                group.append(nid)
                meta_of[nid] = nmeta or {}

            if len(group) > 1:
                # Pick the lowest chunk_index as leader/keeper
                group.sort(key=lambda c: (index_of_meta(meta_of.get(c, {})), c))
                dupes[group[0]] = group
                for g in group:
                    visited.add(g)
            else:
                visited.add(cid)

    return dupes, meta_of


# ────────────────────────────────────────────────────────────────────────────
# Report + delete
# ────────────────────────────────────────────────────────────────────────────

def report(dupes: Dict[str, List[str]], meta_of: Dict[str, dict],
           top_sources: int = 0) -> int:
    """Print a duplicate report.  Returns the number of chunks that would
    be deleted (every dup group except the leader)."""
    if not dupes:
        print("[OK] No duplicates found.")
        return 0
    total_groups = len(dupes)
    total_dups   = sum(len(g) - 1 for g in dupes.values())   # deletions
    total_chunks = sum(len(g)     for g in dupes.values())
    print(f"\n=== DUPLICATE REPORT ===")
    print(f"  Duplicate groups : {total_groups:,}")
    print(f"  Chunks involved  : {total_chunks:,}")
    print(f"  Deletions        : {total_dups:,}  (keeping 1 per group)")
    if top_sources > 0:
        contrib: Dict[str, int] = defaultdict(int)
        for ids in dupes.values():
            # All but the first (keeper) are deletions; tally by source
            for cid in ids[1:]:
                contrib[source_of_meta(meta_of.get(cid, {}))] += 1
        top = sorted(contrib.items(), key=lambda kv: kv[1], reverse=True)[:top_sources]
        print(f"\n  Top {len(top)} source files contributing duplicates:")
        for src, n in top:
            print(f"    {n:>8,}  {src}")
    return total_dups


def delete_duplicates(col, dupes: Dict[str, List[str]]) -> int:
    """Delete every chunk in each group except the first (keeper).
    Returns the number actually deleted."""
    to_delete: List[str] = []
    for ids in dupes.values():
        # First id is the keeper (lowest chunk_index, see sort above)
        to_delete.extend(ids[1:])
    if not to_delete:
        return 0
    print(f"\n[ACTION] Deleting {len(to_delete):,} duplicate chunks…", flush=True)
    n = 0
    # Delete in batches to stay friendly with ChromaDB
    CHUNK = 500
    for i in range(0, len(to_delete), CHUNK):
        slice_ = to_delete[i:i + CHUNK]
        try:
            col.delete(ids=slice_)
            n += len(slice_)
        except Exception as exc:
            print(f"  [WARN] delete batch {i}-{i+CHUNK} failed: {exc}", flush=True)
        if (i // CHUNK) % 20 == 0:
            print(f"  deleted {n:,}/{len(to_delete):,}", flush=True)
    print(f"[DONE] Deleted {n:,} duplicate chunks.")
    return n


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(
        description="Find and remove duplicates from the ARGUS ChromaDB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--mode", choices=("exact", "near", "semantic"),
                   default="exact",
                   help="Dedup strategy (default: exact)")
    p.add_argument("--threshold", type=float, default=0.97,
                   help="Cosine similarity threshold for --mode semantic (default 0.97)")
    p.add_argument("--apply", action="store_true",
                   help="Actually delete duplicates (default: report only)")
    p.add_argument("--top-sources", type=int, default=10,
                   help="Show top-N source files contributing duplicates (default 10)")
    args = p.parse_args()

    col = get_collection()

    t0 = time.time()
    if args.mode in ("exact", "near"):
        dupes, meta_of = find_hash_duplicates(col, args.mode)
    else:
        dupes, meta_of = find_semantic_duplicates(col, args.threshold)
    elapsed = time.time() - t0
    print(f"[INFO] Scan completed in {elapsed/60:.1f} min")

    would_delete = report(dupes, meta_of, top_sources=args.top_sources)

    if args.apply:
        if not dupes:
            return 0
        # Tiny safety pause so a fat-finger Ctrl+C is possible
        print("\n[CONFIRM] --apply set; deleting in 5s.  Ctrl+C to abort.")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n[ABORT] Cancelled by user.")
            return 1
        delete_duplicates(col, dupes)
        # ChromaDB has lazy compaction; print final count for confirmation
        try:
            final = col.count()
            print(f"[INFO] Final chunk count: {final:,}")
        except Exception:
            pass
    else:
        if would_delete:
            print(f"\n[DRY-RUN] Re-run with --apply to delete {would_delete:,} chunks.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
