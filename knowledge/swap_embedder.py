"""
swap_embedder.py — atomically switch the ARGUS embedding/reranker models.

Changing the embedding model changes the vector DIMENSION (bge-m3 = 1024,
bge-small = 384, etc.), so ChromaDB must be wiped and the corpus
re-embedded.  This script does that in one shot:

  1. Backs up the current ChromaDB to a timestamped tarball.
  2. Wipes knowledge/db/ and the manifest.
  3. Sets KB_EMBED_MODEL / KB_RERANK_MODEL env vars (in-process only).
  4. Re-runs build_kb.py against knowledge/data/.

Usage
─────
  # Recommended for 4-8 GB hosts:
  python knowledge/swap_embedder.py --embed BAAI/bge-small-en-v1.5 --no-reranker

  # Minimal RAM (< 4 GB):
  python knowledge/swap_embedder.py --embed sentence-transformers/all-MiniLM-L6-v2 --no-reranker

  # Best quality (12+ GB hosts):
  python knowledge/swap_embedder.py --embed BAAI/bge-m3 \\
      --reranker cross-encoder/ms-marco-MiniLM-L-6-v2

  # Skip backup (faster but no rollback):
  python knowledge/swap_embedder.py --embed BAAI/bge-small-en-v1.5 --no-backup

Re-ingest only — keep current models (handy if KB got corrupted):
  python knowledge/swap_embedder.py --rebuild-only
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent          # knowledge/
DB_DIR = HERE / "db"
DATA_DIR = HERE / "data"
MANIFEST = DB_DIR / "ingest_manifest.json"


def backup_db(path: Path) -> Path:
    """tar.gz the ChromaDB dir.  Returns the backup path."""
    if not path.exists():
        print(f"[INFO] No existing DB at {path}; skipping backup.")
        return Path("/dev/null")
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = path.parent / f"db-backup-{ts}.tar.gz"
    print(f"[INFO] Backing up {path} → {backup}")
    with tarfile.open(backup, "w:gz") as tf:
        tf.add(path, arcname=path.name)
    size_mb = backup.stat().st_size / (1024 * 1024)
    print(f"[INFO] Backup complete ({size_mb:.1f} MB).")
    return backup


def wipe_db(path: Path) -> None:
    if path.exists():
        print(f"[INFO] Wiping {path}")
        shutil.rmtree(path)
    if MANIFEST.exists():
        print(f"[INFO] Removing manifest {MANIFEST}")
        MANIFEST.unlink()


def run_build(embed: str, reranker: str, data: Path) -> int:
    env = os.environ.copy()
    env["KB_EMBED_MODEL"]  = embed
    env["KB_RERANK_MODEL"] = reranker     # empty string disables
    print("=" * 70)
    print(f"[INFO] Rebuilding KB with:")
    print(f"         KB_EMBED_MODEL  = {embed}")
    print(f"         KB_RERANK_MODEL = {reranker or '(disabled)'}")
    print(f"         data dir        = {data}")
    print("=" * 70)
    cmd = [sys.executable, str(HERE / "build_kb.py"), "--reset", str(data)]
    return subprocess.call(cmd, env=env)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Swap the ARGUS embedder/reranker and rebuild the KB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--embed",
                   help="New KB_EMBED_MODEL (e.g. BAAI/bge-small-en-v1.5).")
    p.add_argument("--reranker", default=None,
                   help="New KB_RERANK_MODEL (omit to keep current default).")
    p.add_argument("--no-reranker", action="store_true",
                   help="Disable reranker entirely (saves ~250 MB RAM).")
    p.add_argument("--no-backup", action="store_true",
                   help="Skip the tar.gz backup before wipe.")
    p.add_argument("--rebuild-only", action="store_true",
                   help="Don't change models; just wipe and re-ingest.")
    p.add_argument("--data", default=str(DATA_DIR),
                   help=f"Source corpus directory (default: {DATA_DIR})")
    args = p.parse_args()

    if args.rebuild_only:
        embed    = os.environ.get("KB_EMBED_MODEL",  "BAAI/bge-small-en-v1.5")
        reranker = os.environ.get("KB_RERANK_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")
    else:
        if not args.embed:
            p.error("--embed is required unless --rebuild-only is used.")
        embed = args.embed
        if args.no_reranker:
            reranker = ""
        elif args.reranker is not None:
            reranker = args.reranker
        else:
            reranker = "cross-encoder/ms-marco-MiniLM-L-6-v2"

    data = Path(args.data).expanduser().resolve()
    if not data.exists():
        print(f"[ERR ] Data directory not found: {data}")
        print("       Drop your source files into knowledge/data/ first.")
        return 2

    if not args.no_backup:
        backup_db(DB_DIR)
    wipe_db(DB_DIR)
    rc = run_build(embed, reranker, data)
    if rc != 0:
        print(f"[ERR ] build_kb exited with {rc}.  Restore from backup if needed.")
        return rc

    print("=" * 70)
    print("[DONE] KB rebuilt with new models.")
    print()
    print("To make this permanent, add to your .env (next to agent_server.py):")
    print(f"  KB_EMBED_MODEL={embed}")
    print(f"  KB_RERANK_MODEL={reranker}")
    print()
    print("Then restart agent_server.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
