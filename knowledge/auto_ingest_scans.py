"""
auto_ingest_scans.py - feed completed scan transcripts back into the RAG corpus.

Why this exists
---------------
Episodic memory in ARGUS recalls similar past engagements as priors,
but it's untrained: the operator's first 5 scans don't have anything
to recall.  After 50+ engagements, the platform SHOULD know:
  "every time we found Apache 2.4.49, traversal worked 89% of the time"
  "OpenSSH 8.9 publickey-only -> brute-force is hopeless, pivot to web"
  "MinIO :9000 + nginx :80 -> facts.htb redirect was the path"

This module converts a completed scan's logs into RAG-ingestible
markdown so subsequent scans can pattern-match the same shape of
target.

What it produces
----------------
For each completed scan it writes ONE markdown file:

    knowledge/data/scan_history/<session_id>.md

  ---
  scan_id: 6a04bd677c38a424561cc75f
  target: 10.129.54.94
  target_type: linux
  duration_sec: 5234
  shell_obtained: true
  root_obtained: false
  findings_count: 24
  cves: ["CVE-2024-1313"]
  ---

  # Scan summary - 10.129.54.94 (linux)

  Engagement type: pentest
  Duration: 1h 27m

  ## Discovered services
  - 22/tcp ssh OpenSSH 8.9 (publickey)
  - 80/tcp http nginx/1.26.3 -> facts.htb
  - 54321/tcp http MinIO

  ## Critical findings
  - HIGH MinIO anonymous bucket listing
  - HIGH Spring Actuator /heapdump downloadable
  ...

  ## Attack chain that succeeded
  1. vhost pivot to facts.htb (auto-/etc/hosts)
  2. Spring Actuator /heapdump -> JWT secret extracted
  3. JWT forged -> admin login on facts.htb/admin
  4. Admin XSS -> session hijack
  5. (no shell obtained)

The format is markdown-with-frontmatter so the existing chunker picks
it up automatically and tags the chunks with structured metadata.

Trigger
-------
This module is called by agent_server.py at session_end (or by a
standalone cron via the CLI).  Each scan is ingested exactly once
(idempotent via content hash + manifest).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
# Dual-mode: base_agent.py inserts knowledge/ on sys.path and does
# `from auto_ingest_scans import capture_finding`, i.e. a FLAT import.
try:
    from knowledge.identifier_scrub import scrub_text as _scrub
except ImportError:                                          # flat/script mode
    from identifier_scrub import scrub_text as _scrub

logger = logging.getLogger(__name__)


REPO_ROOT     = Path(__file__).resolve().parent.parent
SCAN_LOG_DIR  = Path(os.environ.get("ARGUS_LOG_DIR",  str(REPO_ROOT / "logs")))
HISTORY_OUT   = Path(os.environ.get("ARGUS_HISTORY_DIR",
                                    str(REPO_ROOT / "knowledge" / "data" / "scan_history")))


def _fmt_duration(secs: float) -> str:
    if secs < 60:
        return f"{int(secs)}s"
    if secs < 3600:
        return f"{int(secs // 60)}m {int(secs % 60)}s"
    return f"{int(secs // 3600)}h {int((secs % 3600) // 60)}m"


def _safe_load_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except (OSError, IOError):
        pass
    return out


def _safe_read(path: Path) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (OSError, IOError):
        return ""


# ── Builders ────────────────────────────────────────────────────────────

def build_markdown_summary(session_dir: Path) -> Optional[str]:
    """Read a session's logs and produce a markdown blob.

    Returns None if the session looks too incomplete to be useful
    (no findings, no tool calls).
    """
    # Try summary.json first (it has everything pre-aggregated)
    summary_path = session_dir / "summary.json"
    summary: Dict[str, Any] = {}
    if summary_path.exists():
        try:
            summary = json.loads(_safe_read(summary_path))
        except Exception:
            summary = {}

    # Pull individual streams
    findings   = _safe_load_jsonl(session_dir / "findings.jsonl")
    tool_calls = _safe_load_jsonl(session_dir / "tool_calls.jsonl")
    subagents  = _safe_load_jsonl(session_dir / "subagents.jsonl")
    events     = _safe_load_jsonl(session_dir / "events.jsonl")

    if not findings and not tool_calls and not events:
        return None

    # Pull header info from events.jsonl first record if present
    sess_start_evt = next((e for e in events if e.get("event") == "session_start"), {})
    target = sess_start_evt.get("target") or summary.get("target") or "?"
    target_type = sess_start_evt.get("engagement_type") or summary.get("target_type") or "?"
    session_id  = sess_start_evt.get("session_id") or summary.get("session_id") or session_dir.name
    started     = sess_start_evt.get("ts") or summary.get("started_at") or ""

    # Duration from last event timestamp
    last_evt = events[-1] if events else {}
    last_ts  = last_evt.get("ts") or ""
    duration = 0.0
    try:
        if started and last_ts:
            t0 = datetime.fromisoformat(started.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            duration = (t1 - t0).total_seconds()
    except Exception:
        pass

    # Service inventory from findings + tool outputs
    services: Dict[int, Dict[str, str]] = {}
    for f in findings:
        p = f.get("port")
        if isinstance(p, int) and p not in services:
            services[p] = {
                "service": str(f.get("service") or ""),
                "banner":  str(f.get("description") or "")[:200],
            }

    # CVE list
    cve_set: set = set()
    for f in findings:
        c = f.get("cve") or f.get("cves")
        if isinstance(c, str) and c.startswith("CVE-"):
            cve_set.add(c)
        elif isinstance(c, list):
            for x in c:
                if isinstance(x, str) and x.startswith("CVE-"):
                    cve_set.add(x)

    # Outcome detection (rough)
    shell_obtained = any(
        e.get("type") in ("shell_obtained", "shell_open") or
        ("shell" in str(e.get("event") or "").lower())
        for e in events
    )
    root_obtained = any(
        f.get("severity") == "CRITICAL" and
        ("root" in str(f.get("title") or "").lower() or
         "uid=0" in str(f.get("evidence") or ""))
        for f in findings
    )

    # Group findings by severity, pick top-N
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    top_findings: List[Dict[str, Any]] = []
    for sev in sev_order:
        for f in findings:
            if str(f.get("severity") or "").upper() == sev:
                top_findings.append(f)
        if len(top_findings) >= 15:
            break
    top_findings = top_findings[:15]

    # Successful tool calls (the chain that actually worked)
    successful_tools = [
        t for t in tool_calls
        if t.get("exit_code") == 0 and len(t.get("stdout_tail") or "") > 50
    ][:20]

    # Build frontmatter + markdown body
    fm_lines = [
        "---",
        # NO scan_id and NO target.  Both identify a client engagement and the
        # corpus is shared with every FUTURE engagement.  target_type is a
        # technology class ("web", "linux", "ad") and is what makes the document
        # retrievable, so it stays.
        f"target_type: {target_type}",
        f"duration_sec: {int(duration)}",
        f"findings_count: {len(findings)}",
        f"shell_obtained: {str(shell_obtained).lower()}",
        f"root_obtained: {str(root_obtained).lower()}",
        f"cves: {json.dumps(sorted(cve_set))}",
        f"ingested_at: {datetime.now(timezone.utc).isoformat()}",
        "---",
        "",
    ]

    body_lines: List[str] = [
        f"# Engagement summary — {target_type}",
        "",
        f"- Started: {started}",
        f"- Duration: {_fmt_duration(duration)}",
        f"- Findings: {len(findings)} ({sum(1 for f in findings if str(f.get('severity') or '').upper() in ('CRITICAL','HIGH'))} high+)",
        f"- Shell obtained: {'YES' if shell_obtained else 'no'}",
        f"- Root: {'YES' if root_obtained else 'no'}",
    ]
    if cve_set:
        body_lines.append(f"- CVEs surfaced: {', '.join(sorted(cve_set))}")
    body_lines.append("")

    if services:
        body_lines.append("## Discovered services")
        for port in sorted(services):
            info = services[port]
            # Banners routinely embed the host's own FQDN or certificate CN.
            body_lines.append(
                f"- `{port}/tcp` {info['service']} - "
                f"{_scrub(info['banner'][:100])}")
        body_lines.append("")

    if top_findings:
        body_lines.append("## Top findings")
        for f in top_findings:
            body_lines.append(
                f"- **{str(f.get('severity') or 'INFO').upper()}** "
                f"`{f.get('port') or '?'}` "
                f"{_scrub(str(f.get('title') or 'untitled')[:160])}"
            )
        body_lines.append("")

    if successful_tools:
        body_lines.append("## Successful tool runs (what worked)")
        for t in successful_tools[:10]:
            body_lines.append(
                # The ARGUMENTS are the technique; the address inside them is not.
                f"- `{t.get('tool')}` `{_scrub((t.get('args') or '')[:80])}` "
                f"({t.get('duration_sec', 0):.1f}s)"
            )
        body_lines.append("")

    body_lines.append("## Operator-facing prior")
    body_lines.append(
        f"When ARGUS encounters a {target_type} target with a similar service "
        f"profile ({', '.join(sorted(s.get('service') for s in services.values() if s.get('service')))}), "
        f"this engagement is relevant: the productive moves were "
        f"{'shell-obtained' if shell_obtained else 'recon/enum-heavy'} "
        f"and {len(top_findings)} findings of HIGH+ severity were produced "
        f"in {_fmt_duration(duration)}."
    )

    return "\n".join(fm_lines + body_lines)


def ingest_session(session_dir: Path, force: bool = False) -> Optional[Path]:
    """Convert one session's logs into a markdown file.

    Returns the written path, or None if skipped (no useful content).
    Idempotent: re-ingesting the same session overwrites the existing
    file (atomic write).
    """
    if not session_dir.is_dir():
        return None
    out_file = HISTORY_OUT / f"{session_dir.name}.md"
    if out_file.exists() and not force:
        return out_file

    md = build_markdown_summary(session_dir)
    if md is None:
        logger.debug("[scan-ingest] %s skipped (insufficient data)", session_dir.name)
        return None

    HISTORY_OUT.mkdir(parents=True, exist_ok=True)
    tmp = out_file.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(md)
            f.flush()
            try:
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        os.replace(tmp, out_file)
        logger.info("[scan-ingest] wrote %s (%d bytes)", out_file, len(md))
    except Exception as exc:
        logger.warning("[scan-ingest] write failed for %s: %s", session_dir.name, exc)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return None
    index_document(out_file)
    # The live-findings document is APPENDED to throughout the engagement, so it
    # is only complete now.  Indexing it per-finding would re-embed a growing
    # file over and over; indexing once here captures the finished set.
    live = HISTORY_OUT / f"{session_dir.name}{LIVE_FINDINGS_SUFFIX}"
    if live.exists():
        index_document(live)
    return out_file


def index_document(path: Path) -> int:
    """Embed a written corpus document into Chroma NOW.  Returns chunks added.

    Writing the markdown only put it on disk; nothing searched it until someone
    remembered to run build_kb.py, so a finished engagement contributed nothing to
    the next one until a manual rebuild.  This closes that gap: the document is
    chunked, typed and embedded immediately, exactly as build_kb would do it.

    Deliberately REUSES build_kb.ingest_file rather than re-implementing chunking
    and metadata — one code path means the live index and a later full rebuild
    cannot drift apart in what they extract.  The manifest is updated too, so a
    subsequent `build_kb.py` sees the file as already ingested and skips it
    instead of duplicating (ingest() also dedups by content hash, so a double
    entry would be rejected anyway — this just avoids the wasted embedding).

    Best-effort by design: a missing chromadb, a cold embedder or a locked index
    must never break the scan that produced the document.
    """
    if os.environ.get("ARGUS_RAG_AUTOINDEX", "1") == "0":
        logger.info("[scan-ingest] auto-index disabled (ARGUS_RAG_AUTOINDEX=0)")
        return 0
    try:
        import knowledge.build_kb as _bkb
        import knowledge.knowledge_base as _kb
    except Exception as exc:                                     # noqa: BLE001
        logger.warning("[scan-ingest] auto-index unavailable (%s) — run "
                       "`python knowledge/build_kb.py` to embed %s", exc, path.name)
        return 0
    try:
        res = _bkb.ingest_file(str(path), _kb)
        added = int(res.get("added", 0) or 0)
        try:
            man = _bkb.load_manifest()
            man[str(path)] = {"hash": _bkb.file_hash(str(path)),
                              "timestamp": time.time(), "chunks": added}
            _bkb.save_manifest(man)
        except Exception as _mexc:                               # noqa: BLE001
            # A stale manifest only costs a redundant re-ingest later, which the
            # content-hash dedup absorbs.  Not worth failing the index for.
            logger.debug("[scan-ingest] manifest update skipped: %s", _mexc)
        logger.info("[scan-ingest] indexed %s (+%d chunk(s)) — searchable now",
                    path.name, added)
        return added
    except Exception as exc:                                     # noqa: BLE001
        logger.warning("[scan-ingest] auto-index failed for %s: %s — the file is "
                       "on disk and `build_kb.py` will pick it up", path.name, exc)
        return 0


def ingest_all_sessions(force: bool = False) -> List[Path]:
    """Walk SCAN_LOG_DIR and ingest every session subdirectory.

    Returns the list of newly-written paths.
    """
    out: List[Path] = []
    if not SCAN_LOG_DIR.exists():
        logger.info("[scan-ingest] %s does not exist; nothing to ingest", SCAN_LOG_DIR)
        return out
    for entry in sorted(SCAN_LOG_DIR.iterdir()):
        if not entry.is_dir():
            continue
        path = ingest_session(entry, force=force)
        if path is not None:
            out.append(path)
    return out


# ── Per-finding live capture (real-time episodic priming) ────────────────
# store_finding() calls capture_finding() for every high/critical finding.
# We append it to a per-session markdown-with-frontmatter file that lives
# INSIDE the RAG corpus (knowledge/data/scan_history/), which the chunker
# walks recursively — so the finding is ingestible immediately and is also
# rolled into the session summary ingest_session() writes at scan end.
# This is the module the finding hook was always meant to reach; the hook
# imported a nonexistent ``auto_ingest`` module, so it had been dead.

LIVE_FINDINGS_SUFFIX = ".live.md"
_CAPTURED_FINGERPRINTS: Dict[str, set] = {}


def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    title = str(finding.get("title") or finding.get("name") or "").strip().lower()
    host  = str(finding.get("host") or finding.get("target") or "").strip().lower()
    port  = str(finding.get("port") or "").strip()
    return f"{host}|{port}|{title}"


def _capture_finding_sync(finding: Dict[str, Any], session_id: str,
                          phase: str = "") -> Optional[Path]:
    """Append one high-value finding to the session's live RAG corpus file.

    Returns the written path, or None if skipped (low severity / duplicate /
    no session id). Never raises.
    """
    try:
        sev = str(finding.get("severity") or "").upper()
        if sev not in ("HIGH", "CRITICAL"):
            return None
        sid = str(session_id or "").strip()
        if not sid:
            return None
        fp = _finding_fingerprint(finding)
        seen = _CAPTURED_FINGERPRINTS.setdefault(sid, set())
        if fp in seen:
            return None

        title = str(finding.get("title") or finding.get("name") or "finding").strip()
        host  = str(finding.get("host") or finding.get("target") or "").strip()
        port  = str(finding.get("port") or "").strip()
        desc  = str(finding.get("description") or finding.get("evidence") or "").strip()
        cves  = finding.get("cves") or finding.get("cve") or []
        if isinstance(cves, str):
            cves = [cves]

        HISTORY_OUT.mkdir(parents=True, exist_ok=True)
        out_file = HISTORY_OUT / f"{sid}{LIVE_FINDINGS_SUFFIX}"
        new_file = not out_file.exists()
        with open(out_file, "a", encoding="utf-8") as f:
            if new_file:
                f.write(
                    "---\n"
                    "doc_type: live_findings\n"
                    "---\n\n"
                    "# Live findings\n\n"
                    "High/critical findings captured during the engagement, "
                    "primed into the RAG corpus for episodic recall.\n\n"
                )
            # The PORT is a technique detail worth keeping; the host is not.
            f.write(f"## {sev} — {_scrub(str(title))}\n")
            if port:
                f.write(f"- Port: {port}\n")
            if cves:
                f.write(f"- CVEs: {', '.join(str(c) for c in cves[:8])}\n")
            if phase:
                f.write(f"- Phase: {phase}\n")
            if desc:
                f.write(f"- Detail: {desc[:400]}\n")
            f.write("\n")
        seen.add(fp)
        return out_file
    except Exception:
        logger.debug("[live-capture] failed for session %s", session_id, exc_info=True)
        return None


async def capture_finding(finding: Dict[str, Any], session_id: str,
                          phase: str = "") -> Optional[Path]:
    """Async entry point used by BaseAgent.store_finding.

    Off-loads the file write to a thread so it never blocks the event loop,
    and never raises into the caller.
    """
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, _capture_finding_sync,
            dict(finding or {}), str(session_id or ""), str(phase or ""))
    except Exception:
        logger.debug("[live-capture] async wrapper failed", exc_info=True)
        return None


# ── CLI ─────────────────────────────────────────────────────────────────

def _cli() -> int:
    import argparse
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--session", default=None,
                   help="Ingest one session dir instead of all")
    p.add_argument("--force", action="store_true",
                   help="Re-ingest already-written sessions")
    args = p.parse_args()

    if args.session:
        path = ingest_session(Path(args.session), force=args.force)
        print(f"wrote: {path}" if path else "skipped (no useful content)")
        return 0 if path else 1
    written = ingest_all_sessions(force=args.force)
    print(f"{len(written)} session(s) ingested -> {HISTORY_OUT}")
    print()
    print("Next: rebuild/refresh the KB so the new files get embedded:")
    print(f"  python knowledge/build_kb.py --path knowledge/data")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())


__all__ = [
    "build_markdown_summary", "ingest_session", "ingest_all_sessions",
]
