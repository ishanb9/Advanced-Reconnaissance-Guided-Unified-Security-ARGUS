#!/usr/bin/env python3
"""scripts/purge_client_identifiers.py — retract client identity already stored.

WHY YOU NEED THIS
=================
The code now refuses to WRITE client identifiers into anything that outlives one
engagement, and scrubs again on READ.  Neither retracts what is already on disk
and in MongoDB from before the fix: episodes keyed on a client's IP, RAG corpus
documents with `target:` frontmatter and whole command lines, lessons tagged with
a session id, a crash ledger clustered by hostname.

This script finds and removes it.  Run it once after deploying the fix.

    # see what would change, touch nothing (DEFAULT)
    python -X utf8 scripts/purge_client_identifiers.py

    # actually rewrite
    python -X utf8 scripts/purge_client_identifiers.py --apply

    # also drop the RAG corpus documents that came from scans, so `build_kb`
    # re-ingests them clean (see --rebuild-hint)
    python -X utf8 scripts/purge_client_identifiers.py --apply --drop-scan-corpus

DRY RUN IS THE DEFAULT.  Nothing is modified unless you pass --apply.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from knowledge.identifier_scrub import (contains_identifier, scrub_payload,  # noqa: E402
                                        scrub_text)

REPO = Path(__file__).resolve().parent.parent
# Must match auto_ingest_scans.HISTORY_OUT exactly, including the env override.
SCAN_HISTORY = Path(os.environ.get("ARGUS_HISTORY_DIR",
                    str(REPO / "knowledge" / "data" / "scan_history")))


# ── Mongo: engagement_episodes + long_term_memory ────────────────────────────
async def purge_mongo(apply: bool) -> dict:
    """Scrub identifiers from the two cross-engagement collections IN PLACE.

    SURGICAL, not replace_one.  Identifying fields are $unset and identifier-
    bearing strings are $set to their scrubbed form; the record's OWN keys
    (_id, session_id) are never touched.  This is why it cannot trip the unique
    session_id index — an earlier replace_one rewrote session_id to a hex-shaped
    value that scrubbed to a constant "[redacted]", and the second write then
    collided.  It is also idempotent: re-running finds nothing left to change.

    It additionally REPAIRS records a previous (broken) run corrupted, whose
    session_id is now the literal "[redacted]": that value is dropped, which the
    sparse-unique index tolerates, so those episodes stop blocking every write.
    """
    from knowledge.identifier_scrub import (IDENTIFYING_FIELDS, PRESERVE_FIELDS,
                                            REDACTED, contains_identifier,
                                            scrub_payload, scrub_text)
    import db.mongo_client as db
    stats = {"episodes_scanned": 0, "episodes_rewritten": 0, "episodes_repaired": 0,
             "memories_scanned": 0, "memories_rewritten": 0, "memories_repaired": 0}
    try:
        await db.ensure_setup()
    except Exception as exc:                                     # noqa: BLE001
        print(f"  ! MongoDB unreachable ({exc}) — skipping the DB half")
        return stats
    d = db.get_db()

    for coll, s_key, r_key, fix_key in (
            ("engagement_episodes", "episodes_scanned", "episodes_rewritten",
             "episodes_repaired"),
            ("long_term_memory", "memories_scanned", "memories_rewritten",
             "memories_repaired")):
        # Snapshot first — never iterate a live cursor while writing to it.
        docs = await d[coll].find({}).to_list(length=None)
        for doc in docs:
            stats[s_key] += 1
            _id = doc.get("_id")
            unset: dict = {}
            setf: dict = {}
            for k, v in doc.items():
                if k == "_id" or k in PRESERVE_FIELDS:
                    continue                       # ARGUS's own keys stay verbatim
                if k in IDENTIFYING_FIELDS:
                    unset[k] = ""
                elif isinstance(v, str) and contains_identifier(v):
                    setf[k] = scrub_text(v)
                elif isinstance(v, list):
                    nv = [scrub_text(x) if isinstance(x, str) else x for x in v]
                    if nv != v:
                        setf[k] = nv
                elif isinstance(v, dict):
                    nv = scrub_payload(v)
                    if nv != v:
                        setf[k] = nv

            # Repair a session_id a previous broken run collapsed to "[redacted]".
            repaired = False
            if str(doc.get("session_id")) == REDACTED:
                unset["session_id"] = ""
                repaired = True

            if not unset and not setf:
                continue
            update: dict = {}
            if unset:
                update["$unset"] = unset
            if setf:
                update["$set"] = setf

            stats[r_key] += 1
            if repaired:
                stats[fix_key] += 1
            _changed = sorted(set(unset) | set(setf))
            print(f"  [{coll}] {_id}: {'REPAIR+' if repaired else ''}fix {_changed}")
            if apply:
                await d[coll].update_one({"_id": _id}, update)
    return stats


# ── RAG corpus on disk ───────────────────────────────────────────────────────
#: build_kb ingests the WHOLE of knowledge/data, not just scan_history, so the
#: sweep has to cover all of it.  But that tree also holds CURATED knowledge —
#: playbooks, HackTricks, PayloadsAllTheThings — whose example addresses
#: (10.10.10.10, victim.local) are teaching content, not client data.  Scrubbing
#: those would quietly degrade the corpus.  So: scan everything, but only MODIFY
#: files that are demonstrably scan-derived; merely REPORT the rest.
RAG_DATA = Path(os.environ.get("KB_DATA_DIR", str(REPO / "knowledge" / "data")))

#: Markers auto_ingest_scans writes into every document it produces.
_SCAN_DOC_MARKERS = ("doc_type: live_findings", "target_type:", "# Engagement summary",
                     "# Scan summary", "## Successful tool runs")


def _is_scan_derived(path: Path, text: str) -> bool:
    if SCAN_HISTORY in path.parents or path.parent.name == "scan_history":
        return True
    head = text[:400]
    return any(m in head for m in _SCAN_DOC_MARKERS)


def purge_corpus(apply: bool, drop_scan_docs: bool) -> dict:
    stats = {"files_scanned": 0, "files_rewritten": 0, "files_deleted": 0,
             "curated_flagged": 0}
    if not RAG_DATA.exists():
        print(f"  ! no RAG corpus at {RAG_DATA} — nothing on disk to clean.")
        print("    (If your corpus lives elsewhere, set KB_DATA_DIR and re-run.)")
        return stats
    print(f"  scanning {RAG_DATA}")
    flagged: list = []
    for f in sorted(RAG_DATA.rglob("*")):
        if not f.is_file() or f.suffix.lower() not in (".md", ".markdown", ".txt"):
            continue
        stats["files_scanned"] += 1
        text = f.read_text(encoding="utf-8", errors="replace")
        if not contains_identifier(text):
            continue
        rel = f.relative_to(RAG_DATA)
        if not _is_scan_derived(f, text):
            # Curated content — an example IP in a playbook is not a client leak.
            stats["curated_flagged"] += 1
            flagged.append(str(rel))
            continue
        if drop_scan_docs:
            stats["files_deleted"] += 1
            print(f"  [corpus] DELETE {rel}")
            if apply:
                f.unlink()
            continue
        stats["files_rewritten"] += 1
        print(f"  [corpus] scrub  {rel}")
        if apply:
            f.write_text(scrub_text(text), encoding="utf-8")

    if flagged:
        print(f"\n  {len(flagged)} CURATED file(s) contain address-like text and were "
              f"NOT modified —\n  these are normally playbook examples, not client "
              f"data. Review if unsure:")
        for r in flagged[:15]:
            print(f"    - {r}")
        if len(flagged) > 15:
            print(f"    … and {len(flagged) - 15} more")
    return stats


# ── repo-level JSON/JSONL artifacts ──────────────────────────────────────────
def purge_artifacts(apply: bool) -> dict:
    stats = {"artifacts_rewritten": 0}
    for rel in ("logs/crash_ledger.json", "agents/training/dataset.jsonl"):
        p = REPO / rel
        if not p.exists():
            continue
        raw = p.read_text(encoding="utf-8", errors="replace")
        if not contains_identifier(raw):
            continue
        stats["artifacts_rewritten"] += 1
        print(f"  [artifact] scrub {rel}")
        if not apply:
            continue
        if p.suffix == ".jsonl":
            out = []
            for line in raw.splitlines():
                if not line.strip():
                    continue
                try:
                    out.append(json.dumps(scrub_payload(json.loads(line)),
                                          ensure_ascii=False))
                except Exception:                                # noqa: BLE001
                    out.append(scrub_text(line))
            p.write_text("\n".join(out) + "\n", encoding="utf-8")
        else:
            try:
                p.write_text(json.dumps(scrub_payload(json.loads(raw)), indent=2),
                             encoding="utf-8")
            except Exception:                                    # noqa: BLE001
                p.write_text(scrub_text(raw), encoding="utf-8")
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="actually modify data (default is a dry run)")
    ap.add_argument("--drop-scan-corpus", action="store_true",
                    help="delete scan-derived corpus docs instead of scrubbing "
                         "them, so a rebuild re-ingests them cleanly")
    args = ap.parse_args()

    mode = "APPLY" if args.apply else "DRY RUN (nothing will change)"
    print(f"=== purge client identifiers — {mode} ===\n")

    print("MongoDB:")
    m = asyncio.run(purge_mongo(args.apply))
    print("\nRAG corpus:")
    c = purge_corpus(args.apply, args.drop_scan_corpus)
    print("\nRepo artifacts:")
    a = purge_artifacts(args.apply)

    print("\n=== summary ===")
    for k, v in {**m, **c, **a}.items():
        print(f"  {k:22} {v}")
    if not args.apply:
        print("\nRe-run with --apply to make these changes.")
    elif c["files_deleted"]:
        print("\nCorpus documents were deleted — rebuild the index:")
        print("    python -X utf8 knowledge/build_kb.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
