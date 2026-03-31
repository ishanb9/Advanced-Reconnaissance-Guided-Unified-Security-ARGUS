#!/usr/bin/env python3
"""
ingest_data.py — Standalone knowledge base ingestion runner
for the Kali Pentest Platform

Automatically discovers and ingests all supported files from the data/ folder
into the RAG knowledge base. Supports incremental updates — only new or
modified files are processed.

Usage:
  python3 ingest_data.py                    # incremental ingest (default)
  python3 ingest_data.py --force            # re-process all files
  python3 ingest_data.py --reset            # wipe KB and start fresh
  python3 ingest_data.py --stats            # show current KB stats
  python3 ingest_data.py --search QUERY     # test a search query
  python3 ingest_data.py --add FILE         # add a specific file
  python3 ingest_data.py --add-tip TEXT     # add a manual tip/trick
  python3 ingest_data.py --dir /custom/path # ingest custom directory

Examples:
  # First-time ingest of all 261 writeups:
  python3 ingest_data.py --reset

  # Add new writeups that appeared in data/:
  python3 ingest_data.py

  # Add a specific PDF:
  python3 ingest_data.py --add /path/to/new_writeup.pdf

  # Manually add a penetration testing tip:
  python3 ingest_data.py --add-tip "When testing Apache Struts, try CVE-2017-5638 with Content-Type injection. Use: curl -v -H 'Content-Type: %{(#_='multipart/form-data')...}' http://TARGET/"

  # Test if a topic returns good results:
  python3 ingest_data.py --search "apache RCE shell"
  python3 ingest_data.py --search "privilege escalation sudo misconfiguration"
  python3 ingest_data.py --search "Active Directory kerberoasting"

Supported file types:
  .pdf, .md, .markdown, .html, .htm, .mhtml, .mht, .txt, .json, .yaml, .yml
"""

import os
import sys
import json
import time
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ingest_data")

# ── Path resolution ──────────────────────────────────────────────────────────────

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR     = os.path.join(SCRIPT_DIR, "data")

# Also check for a root-level data/ folder (one level up from knowledge/)
ROOT_DATA_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "data")


def find_data_dirs() -> list:
    """Return all existing data directories to ingest from."""
    dirs = []
    if os.path.isdir(DATA_DIR):
        dirs.append(DATA_DIR)
    if os.path.isdir(ROOT_DATA_DIR) and ROOT_DATA_DIR != DATA_DIR:
        dirs.append(ROOT_DATA_DIR)
    return dirs


def _load_kb_modules():
    """Import knowledge_base and ingest modules from the knowledge/ directory."""
    sys.path.insert(0, SCRIPT_DIR)
    import knowledge_base as kb_module
    import ingest as ingest_module
    return kb_module, ingest_module


# ── Stats display ────────────────────────────────────────────────────────────────

def print_stats(kb_module):
    """Pretty-print knowledge base statistics."""
    s = kb_module.stats()
    if "error" in s:
        print(f"  ⚠ KB error: {s['error']}")
        return

    print(f"\n{'─'*50}")
    print(f"  📚 Knowledge Base Statistics")
    print(f"{'─'*50}")
    print(f"  Total chunks   : {s.get('total_chunks', 0):,}")
    print(f"  Source files   : {s.get('source_files', 0)}")
    print(f"  Embed model    : {s.get('embed_model', 'unknown')}")
    print(f"  Rerank model   : {s.get('rerank_model', 'disabled')}")
    print(f"  DB path        : {s.get('db_path', 'unknown')}")

    by_phase = s.get("by_phase", {})
    if by_phase:
        print(f"\n  By phase:")
        for phase, count in sorted(by_phase.items(), key=lambda x: -x[1]):
            bar = "█" * min(30, count // max(1, max(by_phase.values()) // 30))
            print(f"    {phase:<12} {count:5,}  {bar}")

    by_type = s.get("by_chunk_type", {})
    if by_type:
        print(f"\n  By chunk type:")
        icons = {
            "command": "⚡", "script": "📜", "procedure": "📋",
            "technique": "🎯", "tip": "💡", "finding": "🔍",
            "tool_usage": "🔧", "output": "📊", "report": "📄",
        }
        for ctype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            icon = icons.get(ctype, "📝")
            print(f"    {icon} {ctype:<12} {count:5,}")

    by_outcome = s.get("by_outcome", {})
    if by_outcome:
        print(f"\n  By outcome:")
        for outcome, count in sorted(by_outcome.items(), key=lambda x: -x[1]):
            print(f"    {outcome:<20} {count:5,}")
    print(f"{'─'*50}\n")


# ── Main ─────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Kali Pentest Platform — RAG Knowledge Base Ingestion Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("--stats",   action="store_true", help="Show KB statistics and exit")
    parser.add_argument("--reset",   action="store_true", help="Wipe KB and re-ingest everything from scratch")
    parser.add_argument("--force",   action="store_true", help="Re-ingest all files (ignore manifest)")
    parser.add_argument("--search",  metavar="QUERY",     help="Test a search query")
    parser.add_argument("--top-k",   type=int, default=5,  help="Results for --search (default: 5)")
    parser.add_argument("--add",     metavar="FILE",       help="Add a specific file to the KB")
    parser.add_argument("--add-tip", metavar="TEXT",       help="Add a manual tip/trick to the KB")
    parser.add_argument("--category", default="general",  help="Category for --add-tip (default: general)")
    parser.add_argument("--dir",     metavar="PATH",       help="Ingest from a custom directory instead of data/")
    parser.add_argument("--list-sources", action="store_true", help="List all data source directories")

    args = parser.parse_args()

    kb_module, ingest_module = _load_kb_modules()

    # ── Stats ──
    if args.stats:
        print_stats(kb_module)
        return

    # ── List sources ──
    if args.list_sources:
        print("\nData source directories:")
        for d in find_data_dirs():
            count = sum(1 for _, _, files in os.walk(d) for f in files)
            print(f"  {d}  ({count} files)")
        return

    # ── Search test ──
    if args.search:
        print(f"\n🔍 Searching: '{args.search}'  (top_k={args.top_k})\n")
        print_stats(kb_module)
        result = kb_module.search(args.search, top_k=args.top_k)
        if result:
            print(result)
        else:
            print("(no results above relevance threshold)")
            print("\nTry:")
            print("  python3 ingest_data.py  # to populate the knowledge base first")
        return

    # ── Add single tip ──
    if args.add_tip:
        tip_text = args.add_tip.strip()
        if len(tip_text) < 20:
            print("⚠ Tip is too short (minimum 20 characters)")
            sys.exit(1)
        ok = kb_module.ingest_tip(
            text     = tip_text,
            category = args.category,
            source   = "manual_tip",
        )
        if ok:
            print(f"✅ Tip added to KB (category: {args.category})")
        else:
            print("⚠ Tip already exists in KB (duplicate)")
        return

    # ── Add single file ──
    if args.add:
        path = os.path.expanduser(args.add)
        if not os.path.isfile(path):
            logger.error(f"File not found: {path}")
            sys.exit(1)

        print(f"\n📄 Ingesting: {path}")
        t0     = time.time()
        result = ingest_module.ingest_file(path, kb_module)

        # Update manifest
        manifest = ingest_module.load_manifest()
        manifest[path] = {
            "hash":      ingest_module.file_hash(path),
            "timestamp": time.time(),
            "chunks":    result.get("added", 0),
        }
        ingest_module.save_manifest(manifest)

        print(f"✅ Done in {time.time()-t0:.1f}s")
        print(f"   Chunks added  : {result.get('added', 0)}")
        print(f"   Chunks skipped: {result.get('skipped', 0)}")
        return

    # ── Reset ──
    if args.reset:
        import shutil
        chroma_path = kb_module.CHROMA_PATH
        if os.path.exists(chroma_path):
            shutil.rmtree(chroma_path)
            logger.info("🗑  Knowledge base wiped")
        manifest_path = ingest_module.MANIFEST_FILE
        if os.path.exists(manifest_path):
            os.remove(manifest_path)
            logger.info("🗑  Ingestion manifest cleared")
        args.force = True

    # ── Determine target directories ──
    target_dirs = []
    if args.dir:
        custom = os.path.expanduser(args.dir)
        if not os.path.isdir(custom):
            logger.error(f"Directory not found: {custom}")
            sys.exit(1)
        target_dirs = [custom]
    else:
        target_dirs = find_data_dirs()

    if not target_dirs:
        logger.error(
            f"No data directories found. Expected:\n"
            f"  {DATA_DIR}\n"
            f"  {ROOT_DATA_DIR}\n"
            f"Create one of these directories and place your files in it,\n"
            f"or use --dir to specify a custom path."
        )
        sys.exit(1)

    # ── Print pre-ingest stats ──
    print_stats(kb_module)

    # ── Run ingestion ──
    print(f"📦 Ingesting from: {', '.join(target_dirs)}")
    print(f"   Mode: {'full re-ingest (--force)' if args.force else 'incremental (new/modified files only)'}\n")

    manifest    = ingest_module.load_manifest() if not args.force else {}
    grand_total = {"added": 0, "skipped": 0, "errors": 0, "files": 0, "files_skipped": 0}
    t0          = time.time()

    for data_dir in target_dirs:
        logger.info(f"Processing directory: {data_dir}")
        result, manifest = ingest_module.ingest_directory(
            data_dir, kb_module, manifest=manifest, force=args.force
        )
        for k in grand_total:
            grand_total[k] += result.get(k, 0)

    ingest_module.save_manifest(manifest)
    elapsed = time.time() - t0

    # ── Print results ──
    print(f"\n{'═'*50}")
    print(f"  ✅ INGESTION COMPLETE  ({elapsed:.1f}s)")
    print(f"{'═'*50}")
    print(f"  Files processed    : {grand_total['files']}")
    print(f"  Files unchanged    : {grand_total['files_skipped']}")
    print(f"  Chunks added       : {grand_total['added']:,}")
    print(f"  Chunks skipped     : {grand_total['skipped']:,} (duplicates)")
    print(f"  Errors             : {grand_total['errors']}")

    # Post-ingest stats
    print_stats(kb_module)

    # Quick search test if anything was added
    if grand_total["added"] > 0:
        print("🔍 Quick search test — 'nmap recon service enumeration':")
        sample = kb_module.search("nmap recon service enumeration", top_k=2)
        if sample:
            # Show just first result
            lines = sample.split('\n')
            print('\n'.join(lines[:8]))
            if len(lines) > 8:
                print("  (... truncated, use --search to see full results)")
        else:
            print("  (no results yet — may need more indexed content)")


if __name__ == "__main__":
    main()
