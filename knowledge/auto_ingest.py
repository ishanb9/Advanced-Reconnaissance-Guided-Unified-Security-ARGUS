"""
knowledge/auto_ingest.py — Automatic RAG KB capture for ARGUS

After high/critical findings are stored, call `capture_finding()` to ingest
the structured finding + its raw tool output into ChromaDB so future scan
sessions can benefit from accumulated experience.

Also exposes `capture_tool_output()` for ingesting tool output that produced
actionable information but may not have risen to a formal finding.

Both functions are safe to call from async context via asyncio.create_task();
they run sync ChromaDB calls in the default executor.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("auto_ingest")

# ── threshold — only auto-capture these severities ──────────────────────────
AUTO_CAPTURE_SEVERITIES = {"critical", "high"}


# ── helpers ─────────────────────────────────────────────────────────────────

def _severity_str(sev: Any) -> str:
    return str(sev).lower().replace("findingseverity.", "")


def _build_finding_text(finding: Dict) -> str:
    """Build a rich text blob for embedding from a finding dict."""
    parts = []
    title = finding.get("title") or finding.get("name") or "Unknown Finding"
    parts.append(f"# {title}")

    desc = finding.get("description") or ""
    if desc:
        parts.append(desc)

    host    = finding.get("host") or ""
    port    = finding.get("port") or ""
    service = finding.get("service") or ""
    if host:
        loc = host
        if port:
            loc += f":{port}"
        if service:
            loc += f" ({service})"
        parts.append(f"Target: {loc}")

    cves = finding.get("cves") or []
    if cves:
        parts.append(f"CVEs: {', '.join(cves)}")

    tool = finding.get("tool_used") or finding.get("tool") or ""
    if tool:
        parts.append(f"Discovered by: {tool}")

    extra = finding.get("extra") or {}
    remediation = extra.get("remediation") or finding.get("remediation") or ""
    if remediation:
        parts.append(f"Remediation: {remediation}")

    raw = finding.get("raw_output") or ""
    if raw:
        # Only first 1500 chars of raw output to stay within token budget
        parts.append(f"Tool output:\n{raw[:1500]}")

    return "\n\n".join(parts)


def _stable_id(text: str) -> str:
    return "autoingest_" + hashlib.sha256(text.encode()).hexdigest()[:16]


def _ingest_sync(text: str, source: str, metadata: Dict):
    """Blocking ChromaDB ingest — run in executor."""
    try:
        import sys, os
        # Ensure knowledge directory is on path
        kb_dir = os.path.join(os.path.dirname(__file__))
        if kb_dir not in sys.path:
            sys.path.insert(0, kb_dir)
        import knowledge_base as kb
        import hashlib
        chunk_index = int(hashlib.sha256(text.encode()).hexdigest(), 16) % 9_999_999
        kb.ingest(
            text        = text,
            source_file = source,
            chunk_index = chunk_index,
            metadata    = metadata,
        )
        return True
    except Exception as exc:
        logger.debug(f"auto_ingest ChromaDB error: {exc}")
        return False


# ── public API ───────────────────────────────────────────────────────────────

async def capture_finding(
    finding:    Dict,
    session_id: str,
    phase:      Optional[str] = None,
) -> bool:
    """
    Ingest a finding into the RAG knowledge base.
    Only processes high/critical severities by default.
    Safe to call with asyncio.create_task().
    """
    sev = _severity_str(finding.get("severity", ""))
    if sev not in AUTO_CAPTURE_SEVERITIES:
        return False

    text = _build_finding_text(finding)
    if len(text.strip()) < 30:
        return False

    title    = finding.get("title") or "finding"
    cves     = finding.get("cves") or []
    tool     = finding.get("tool_used") or finding.get("tool") or "unknown"
    host     = finding.get("host") or ""
    mitre    = []  # populated if finding carries MITRE data

    # MITRE ttps may live inside extra
    extra = finding.get("extra") or {}
    mitre = extra.get("mitre_ttps") or finding.get("mitre_ttps") or []

    metadata = {
        "chunk_type":  "finding",
        "outcome":     sev,
        "phase":       phase or "unknown",
        "tool":        tool,
        "host":        host,
        "cves":        json.dumps(cves),
        "mitre_ttps":  json.dumps(mitre),
        "session_id":  session_id,
        "auto_ingested": "true",
    }
    source = f"auto_ingest/{session_id}/{title[:40]}"

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _ingest_sync, text, source, metadata)
    if result:
        logger.info(f"[{session_id}] Auto-ingested {sev} finding: {title[:60]}")
    return result


async def capture_tool_output(
    tool_name:  str,
    target:     str,
    raw_output: str,
    session_id: str,
    phase:      Optional[str] = None,
    tags:       Optional[List[str]] = None,
) -> bool:
    """
    Ingest significant tool output directly into the RAG knowledge base.
    Useful for novel technique outputs or large successful tool runs.
    """
    if not raw_output or len(raw_output.strip()) < 50:
        return False

    text = (
        f"Tool: {tool_name}\nTarget: {target}\n\n"
        f"Output:\n{raw_output[:4000]}"
    )
    metadata = {
        "chunk_type":  "output",
        "tool":        tool_name,
        "host":        target,
        "phase":       phase or "unknown",
        "session_id":  session_id,
        "tags":        json.dumps(tags or []),
        "auto_ingested": "true",
    }
    source = f"auto_ingest/{session_id}/{tool_name}_{target}"

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _ingest_sync, text, source, metadata)
    if result:
        logger.info(f"[{session_id}] Auto-ingested tool output: {tool_name} → {target}")
    return result
