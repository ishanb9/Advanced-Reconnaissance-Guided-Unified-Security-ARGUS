"""
fetch_offensive_corpus.py - pull HackTricks + PayloadsAllTheThings into
ARGUS's knowledge corpus so the RAG retriever can ground LLM decisions
in real exploitation chains, not just MITRE ATT&CK technique descriptions.

Why these two corpora
---------------------
- HackTricks (book.hacktricks.wiki / github.com/HackTricks-wiki/hacktricks):
  ~3,000 pages of practical exploitation chains.  The operator wiki for
  offensive work.  Every common service has a "what to check / how to
  exploit" page with command examples.
- PayloadsAllTheThings (github.com/swisskyrepo/PayloadsAllTheThings):
  Categorised payload library covering every common vulnerability class
  (SQLi, XSS, SSTI, LFI, command injection, deserialisation, etc.)
  with multiple bypass variants.

Together they cover the gap between MITRE ("what is XSS") and execution
("here is exactly how to bypass WAF X on version Y") that the existing
corpus has.

Usage
-----
    python knowledge/fetch_offensive_corpus.py

    # Or specific subsets:
    python knowledge/fetch_offensive_corpus.py --skip-patt
    python knowledge/fetch_offensive_corpus.py --skip-hacktricks
    python knowledge/fetch_offensive_corpus.py --update    # refresh existing

After fetching, run:
    python knowledge/build_kb.py --path knowledge/data

The script honours the existing manifest, so a subsequent rebuild only
ingests the new files.

What this script does NOT do
----------------------------
- Does not embed - that's build_kb.py's job.
- Does not modify the source markdown / yaml files - kept verbatim so
  if a writeup changes upstream you can git pull and re-ingest.
- Does not download git LFS / large binaries - markdown only.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


HERE      = Path(__file__).resolve().parent              # knowledge/
DATA_DIR  = HERE / "data"
HT_DEST   = DATA_DIR / "hacktricks"
PATT_DEST = DATA_DIR / "PayloadsAllTheThings"

HACKTRICKS_REPO = os.environ.get(
    "HACKTRICKS_REPO",
    "https://github.com/HackTricks-wiki/hacktricks.git",
)
PATT_REPO = os.environ.get(
    "PATT_REPO",
    "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
)


def _ensure_git() -> str:
    git = shutil.which("git")
    if not git:
        sys.exit("ERR: git binary not found on PATH. Install git first.")
    return git


def _run(argv: List[str], cwd: str = None) -> Tuple[int, str, str]:
    """Run a subprocess with positional argv (no shell, no injection)."""
    logger.info("$ %s", " ".join(argv))
    proc = subprocess.run(
        argv, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def clone_or_update(repo_url: str, dest: Path, update: bool) -> bool:
    """Shallow-clone a repo (or `git pull` if already present + update)."""
    git = _ensure_git()
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists() and (dest / ".git").exists():
        if not update:
            logger.info("[corpus] %s already present (use --update to refresh)", dest)
            return True
        logger.info("[corpus] updating %s ...", dest)
        rc, out, err = _run([git, "pull", "--ff-only", "--depth", "1"], cwd=str(dest))
        if rc != 0:
            logger.warning("[corpus] git pull failed (%s): %s", rc, err[:200])
            return False
        return True

    if dest.exists():
        logger.warning("[corpus] %s exists but is not a git repo; leaving it alone", dest)
        return False

    logger.info("[corpus] cloning %s -> %s", repo_url, dest)
    rc, out, err = _run([
        git, "clone", "--depth", "1", "--filter=blob:none",
        repo_url, str(dest),
    ])
    if rc != 0:
        logger.error("[corpus] clone failed: %s", err[:500])
        return False
    return True


def prune_binaries(root: Path) -> int:
    """Delete file extensions we don't want in the corpus (images, archives)."""
    drop_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
        ".zip", ".tar", ".tar.gz", ".gz", ".7z", ".rar",
        ".mp4", ".mov", ".webm", ".wav", ".mp3",
        ".exe", ".dll", ".bin", ".so", ".dylib",
    }
    removed = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in drop_exts:
            try:
                p.unlink()
                removed += 1
            except OSError:
                pass
    if removed:
        logger.info("[corpus] pruned %d non-text files under %s", removed, root.name)
    return removed


def show_size(root: Path) -> None:
    if not root.exists():
        return
    md_count = sum(1 for _ in root.rglob("*.md"))
    yaml_count = sum(1 for _ in root.rglob("*.y*ml"))
    total = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    logger.info("[corpus] %s: %d markdown, %d yaml, %.1f MB",
                root.name, md_count, yaml_count, total / (1024 * 1024))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--skip-hacktricks", action="store_true",
                   help="Don't fetch HackTricks.")
    p.add_argument("--skip-patt",       action="store_true",
                   help="Don't fetch PayloadsAllTheThings.")
    p.add_argument("--update",          action="store_true",
                   help="If repo already present, git-pull instead of skipping.")
    p.add_argument("--no-prune",        action="store_true",
                   help="Don't delete images/archives after fetch.")
    args = p.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    ok_count = 0
    fail_count = 0
    if not args.skip_hacktricks:
        if clone_or_update(HACKTRICKS_REPO, HT_DEST, update=args.update):
            ok_count += 1
            if not args.no_prune:
                prune_binaries(HT_DEST)
            show_size(HT_DEST)
        else:
            fail_count += 1

    if not args.skip_patt:
        if clone_or_update(PATT_REPO, PATT_DEST, update=args.update):
            ok_count += 1
            if not args.no_prune:
                prune_binaries(PATT_DEST)
            show_size(PATT_DEST)
        else:
            fail_count += 1

    print("=" * 60)
    print(f"[corpus] {ok_count} repo(s) ready, {fail_count} failed.")
    print()
    print("Next: re-ingest the knowledge base to embed the new content")
    print("      python knowledge/build_kb.py --path knowledge/data")
    print()
    print("If you switched models recently, do a full rebuild instead:")
    print("      python knowledge/build_kb.py --reset --path knowledge/data")
    print("=" * 60)
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
