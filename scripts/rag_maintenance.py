#!/usr/bin/env python3
"""scripts/rag_maintenance.py — RAG resource report + safe pruning.

The RAG grows as ARGUS learns. This shows its footprint (storage / RAM / chunks
vs. the budget) and lets you reclaim space WITHOUT touching the curated knowledge:
it prunes only the low-value bulk chunk types (raw tool `output` by default),
never `skill` / `finding` / `tip` / engagement-`lesson` / `playbook`.

Usage:
  python -X utf8 scripts/rag_maintenance.py --usage              # resource report
  python -X utf8 scripts/rag_maintenance.py --usage --json
  python -X utf8 scripts/rag_maintenance.py --prune --dry-run    # show what would go
  python -X utf8 scripts/rag_maintenance.py --prune              # prune to the chunk cap
  python -X utf8 scripts/rag_maintenance.py --prune --max 400000 --types output,technique
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

# Curated chunk types that pruning must NEVER delete.
_PROTECTED = {"skill", "finding", "tip", "playbook", "engagement_lesson", "procedure"}


def prune(max_chunks: Optional[int] = None, drop_types=("output",),
          dry_run: bool = False) -> Dict[str, Any]:
    """Delete low-value bulk chunks (by chunk_type) until under max_chunks.
    Protected/curated types are never touched. Returns a summary."""
    from knowledge import knowledge_base as kb
    from knowledge import rag_budget as rb
    col = kb._get_collection()
    total = col.count()
    target = int(max_chunks if max_chunks is not None else rb.budgets()["max_chunks"])
    if total <= target:
        return {"pruned": 0, "total": total, "target": target, "reason": "already under target"}
    need = total - target
    removed = 0
    by_type: Dict[str, int] = {}
    for ct in drop_types:
        if ct in _PROTECTED:
            continue
        if removed >= need:
            break
        try:
            got = col.get(where={"chunk_type": {"$eq": ct}}, limit=int(need - removed))
            ids: List[str] = got.get("ids") or []
        except Exception:
            ids = []
        if ids and not dry_run:
            try:
                col.delete(ids=ids)
            except Exception:
                ids = []
        removed += len(ids)
        by_type[ct] = len(ids)
    after = total if dry_run else col.count()
    return {"pruned": removed, "by_type": by_type, "total_before": total,
            "total_after": after, "target": target, "dry_run": dry_run,
            "shortfall": max(0, after - target)}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="ARGUS RAG resource report + pruning")
    ap.add_argument("--usage", action="store_true", help="show the resource footprint")
    ap.add_argument("--prune", action="store_true", help="prune low-value chunks to the cap")
    ap.add_argument("--max", type=int, default=None, help="target max chunks (default: budget cap)")
    ap.add_argument("--types", default="output", help="comma list of chunk_types to prune (default: output)")
    ap.add_argument("--dry-run", action="store_true", help="show what would be pruned, delete nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    from knowledge import rag_budget as rb
    if not args.prune or args.usage:
        u = rb.usage()
        if args.json:
            print(json.dumps(u, indent=2, ensure_ascii=False))
        else:
            print("=== RAG RESOURCE FOOTPRINT ===")
            print(f"  chunks:        {u['chunks']}  ({u['chunks_pct_of_cap']}% of cap {u['budgets']['max_chunks']})")
            print(f"  on-disk DB:    {u['db_size_mb']} MB  (cap {u['budgets']['max_db_mb']} MB)  @ {u['db_path']}")
            print(f"  est. index RAM:{u['est_vector_ram_mb']} MB  (vectors {u['chunks']}×{u['embed_dim']} f32 ×1.7)")
            print(f"  process RSS:   {u['process_rss_mb']} MB")
            print(f"  free disk:     {u['free_disk_mb']} MB  (floor {u['budgets']['min_free_disk_mb']} MB)")
            print(f"  free RAM:      {u['free_ram_mb']} MB  (floor {u['budgets']['min_free_ram_mb']} MB)")
            print(f"  within budget: {u['within_budget']}  ({u['reason']})")
            if not u["within_budget"]:
                print("  ⚠ over budget — new RAG ingests are being BLOCKED. Prune with --prune.")

    if args.prune:
        types = tuple(t.strip() for t in args.types.split(",") if t.strip())
        res = prune(max_chunks=args.max, drop_types=types, dry_run=args.dry_run)
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            verb = "would prune" if args.dry_run else "pruned"
            print(f"{verb} {res['pruned']} chunks {res.get('by_type', {})}: "
                  f"{res['total_before']} -> {res['total_after']} (target {res['target']})")
            if res.get("shortfall"):
                print(f"  ⚠ still {res['shortfall']} over target — add more types via --types "
                      "(e.g. output,technique) — note: that removes reference knowledge.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
