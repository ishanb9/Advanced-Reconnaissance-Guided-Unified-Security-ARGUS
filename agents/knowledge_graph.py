"""
agents/knowledge_graph.py — Semantic relationship inference for ARGUS

After each tool execution, call `infer_and_write()` as a fire-and-forget
background task.  It asks the LLM to extract (subject, predicate, object)
semantic triples from the raw tool output, maps the predicates to typed
Neo4j relationship labels, then persists the graph to Neo4j.

Predicate → Neo4j relationship mapping
───────────────────────────────────────
  exposes / opens / has_port          → EXPOSES
  runs / serves / listens             → RUNS
  vulnerable_to / has_vuln / affected → VULNERABLE_TO
  leads_to / enables / allows         → LEADS_TO
  references / is / mapped_to / cve   → REFERENCES
  exploitable_with / exploited_by     → EXPLOITABLE_WITH
  has_credential / uses_credential    → HAS_CREDENTIAL
  compromised_via / pwned_by          → COMPROMISED_VIA
  escalates_to / privesc_to           → ESCALATES_TO
  pivots_to / lateral_to              → PIVOTS_TO
  affects / impacts                   → AFFECTS

Usage
─────
  import asyncio
  from agents.knowledge_graph import infer_and_write
  asyncio.create_task(infer_and_write(
      session_id = session_id,
      tool_name  = "nikto",
      target     = "192.168.1.1",
      raw_output = nikto_stdout,
      llm_url    = "http://localhost:11434",
      llm_model  = "llama3",
  ))
"""

from __future__ import annotations

import json
import logging
import re
from typing import Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("knowledge_graph")

# ── predicate → relationship type map ───────────────────────────────────────
_PRED_MAP: List[Tuple[List[str], str]] = [
    (["exposes", "opens", "has_port", "open_port"],          "EXPOSES"),
    (["runs", "serves", "listens", "hosts"],                  "RUNS"),
    (["vulnerable_to", "has_vuln", "affected_by", "has_vulnerability"], "VULNERABLE_TO"),
    (["leads_to", "enables", "allows", "grants"],             "LEADS_TO"),
    (["references", "is_cve", "mapped_to", "associated_with"], "REFERENCES"),
    (["exploitable_with", "exploited_by", "exploited_via"],   "EXPLOITABLE_WITH"),
    (["has_credential", "uses_credential", "leaked"],         "HAS_CREDENTIAL"),
    (["compromised_via", "pwned_by", "breached_via"],         "COMPROMISED_VIA"),
    (["escalates_to", "privesc_to", "privesc"],               "ESCALATES_TO"),
    (["pivots_to", "lateral_to", "moves_to"],                 "PIVOTS_TO"),
    (["affects", "impacts"],                                   "AFFECTS"),
]


def _map_predicate(raw: str) -> str:
    norm = raw.lower().strip().replace(" ", "_").replace("-", "_")
    for keywords, rel_type in _PRED_MAP:
        if any(norm == kw or norm.startswith(kw) for kw in keywords):
            return rel_type
    return "RELATED_TO"


# ── node type inference ─────────────────────────────────────────────────────

def _infer_node_type(node_label: str) -> str:
    """Guess the Neo4j label from a node's text representation."""
    low = node_label.lower()
    if re.match(r"\d{1,3}(\.\d{1,3}){3}", low):
        return "Host"
    if re.match(r"cve-\d{4}-\d+", low):
        return "CVE"
    if any(k in low for k in ("port", "/tcp", "/udp")):
        return "Port"
    if any(k in low for k in ("http", "ssh", "ftp", "smtp", "smb", "rdp", "service")):
        return "Service"
    if any(k in low for k in ("vuln", "vulnerability", "cve", "exploit")):
        return "Vulnerability"
    if any(k in low for k in ("cred", "password", "hash", "token")):
        return "Credential"
    if any(k in low for k in ("user", "account", "admin")):
        return "User"
    if any(k in low for k in ("share", "smb", "nfs")):
        return "Share"
    if any(k in low for k in ("access", "shell", "flag", "root")):
        return "Access"
    return "Finding"


# ── LLM extraction ─────────────────────────────────────────────────────────

_TRIPLE_PROMPT = """\
You are a cybersecurity knowledge graph extractor.

Given the output of a security tool called "{tool_name}" run against "{target}", extract semantic triples.

Return ONLY a JSON array of objects, no explanation, no markdown fences.
Each object: {{"subject": "...", "predicate": "...", "object": "..."}}

Rules:
- subject and object must be specific entities (IPs, hostnames, ports, CVEs, services, vulnerabilities, credentials, users)
- predicate must be ONE of: exposes, runs, vulnerable_to, leads_to, references, exploitable_with, has_credential, compromised_via, escalates_to, pivots_to, affects
- Do NOT invent entities; only use what is explicitly in the output
- Limit to the 15 most important triples
- If nothing meaningful can be extracted, return []

Tool output (first 3000 chars):
{output}
"""

async def _extract_triples(
    tool_name:  str,
    target:     str,
    raw_output: str,
    llm_url:    str,
    llm_model:  str,
) -> List[Dict]:
    """Call LLM to extract semantic triples. Returns [] on any error."""
    prompt = _TRIPLE_PROMPT.format(
        tool_name=tool_name,
        target=target,
        output=raw_output[:3000],
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{llm_url}/api/generate",
                json={
                    "model":  llm_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 800},
                },
            )
        if resp.status_code != 200:
            return []
        raw_text = resp.json().get("response", "")
        # Strip any markdown fences the model might add
        raw_text = re.sub(r"```[a-z]*", "", raw_text).strip()
        triples = json.loads(raw_text)
        if isinstance(triples, list):
            return [t for t in triples if isinstance(t, dict)
                    and all(k in t for k in ("subject", "predicate", "object"))]
        return []
    except Exception as exc:
        logger.debug(f"Triple extraction failed ({tool_name}): {exc}")
        return []


# ── public entry point ──────────────────────────────────────────────────────

async def infer_and_write(
    session_id: str,
    tool_name:  str,
    target:     str,
    raw_output: str,
    llm_url:    str  = "",   # resolved at call time from OLLAMA_URL env var
    llm_model:  str  = "",  # resolved at call time from OLLAMA_MODEL env var
) -> int:
    """
    Fire-and-forget coroutine.
    Extracts semantic triples from tool output via LLM and writes them to Neo4j.
    Returns the number of triples written (0 if Neo4j unavailable or no triples).
    """
    import os as _os
    if not llm_url:
        llm_url = _os.environ.get("OLLAMA_URL", "http://192.168.0.101:11434")
    if not llm_model:
        llm_model = _os.environ.get("OLLAMA_MODEL", "deepseek-v3.1:671b-cloud")

    if not raw_output or len(raw_output.strip()) < 20:
        return 0

    # Import here to avoid circular imports at module load time
    try:
        from db import neo4j_client as neo4j
    except ImportError:
        return 0

    if not await neo4j.ping():
        return 0

    triples = await _extract_triples(tool_name, target, raw_output, llm_url, llm_model)
    if not triples:
        return 0

    written = 0
    for triple in triples:
        subj = str(triple["subject"]).strip()
        pred = str(triple["predicate"]).strip()
        obj  = str(triple["object"]).strip()
        if not subj or not obj:
            continue

        subj_id   = _node_id(subj)
        obj_id    = _node_id(obj)
        subj_type = _infer_node_type(subj)
        obj_type  = _infer_node_type(obj)
        rel_type  = _map_predicate(pred)

        try:
            await neo4j.upsert_node(
                session_id=session_id, node_id=subj_id,
                node_type=subj_type, label=subj,
                properties={"source_tool": tool_name, "target": target},
            )
            await neo4j.upsert_node(
                session_id=session_id, node_id=obj_id,
                node_type=obj_type, label=obj,
                properties={"source_tool": tool_name, "target": target},
            )
            await neo4j.upsert_edge(
                session_id=session_id,
                source_id=subj_id, target_id=obj_id,
                rel_type=rel_type,
                properties={"tool": tool_name, "predicate_raw": pred},
            )
            written += 1
        except Exception as exc:
            logger.debug(f"Neo4j write error: {exc}")

    if written:
        logger.info(f"[{session_id}] {tool_name}: wrote {written} semantic triples to Neo4j")
    return written


def _node_id(label: str) -> str:
    """Stable node ID from its label string."""
    return re.sub(r"[^a-z0-9_]", "_", label.lower().strip())[:80]
