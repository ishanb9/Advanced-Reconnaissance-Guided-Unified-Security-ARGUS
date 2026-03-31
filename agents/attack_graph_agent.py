"""
attack_graph_agent.py — Live Attack Chain Analyzer

Watches findings as they arrive during a pentest, uses RAG + LLM to:
  1. Identify realistic attack chains from the discovered findings
  2. Generate step-by-step exploitation guides with exact commands
  3. Show what's needed to complete each chain
  4. Annotate the attack graph with chain edges and enriched nodes
  5. Surface "next best action" recommendations in real-time

Architecture
-----------
- Runs as a background asyncio task alongside master_agent
- Polls DB every POLL_INTERVAL seconds for new findings
- Batches findings → RAG queries → single LLM analysis call per batch
- Stores ChainAnalysis documents in MongoDB
- Emits chain_analysis WS events that the frontend subscribes to
- Re-runs whenever ≥ NEW_FINDINGS_THRESHOLD new findings have appeared

Design decisions
----------------
- Does NOT call master agent — operates independently so it never blocks exploiting
- Uses a single focused LLM system prompt instead of inheriting master's planner persona
- Deduplicates: tracks which finding IDs have already been analyzed
- Never emits duplicate chain IDs; merges with previous analysis
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

import db.mongo_client as _db

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
OLLAMA_URL   = "http://192.168.0.100:11434"
MODEL_NAME   = "glm-5:cloud"
LLM_TIMEOUT  = 180     # seconds
POLL_INTERVAL = 35     # seconds between polls
NEW_FINDINGS_THRESHOLD = 3  # min new findings before re-analysis
MAX_FINDINGS_PER_PROMPT = 40  # cap to keep prompt manageable

# ── RAG ───────────────────────────────────────────────────────────────────────
try:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "knowledge"))
    import knowledge_base as _kb
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False


def _rag(query: str, top_k: int = 4) -> str:
    if not _KB_AVAILABLE:
        return ""
    try:
        items = _kb.search(query, top_k=top_k)
        if not items:
            return ""
        return "\n\n".join(f"[KB {i+1}] {c.strip()}" for i, c in enumerate(items))
    except Exception:
        return ""


def _rag_commands(query: str, top_k: int = 4) -> str:
    if not _KB_AVAILABLE:
        return ""
    try:
        cmds = _kb.search_commands(query, top_k=top_k)
        if not cmds:
            return ""
        return "\n".join(f"[CMD {i+1}] {c.strip()}" for i, c in enumerate(cmds))
    except Exception:
        return ""


# ── LLM system prompt for chain analysis ────────────────────────────────────
_SYSTEM_PROMPT = """You are an expert penetration tester specializing in attack chain analysis.
Given a set of security findings from an active pentest, you:
1. Identify all viable multi-step attack chains (how to actually compromise the target)
2. Provide specific, runnable tool commands for each step
3. Map each step to a MITRE ATT&CK technique
4. Rate each chain by probability and impact
5. Identify what additional information or access is needed to complete each chain
6. Recommend the single most promising next action

Your analysis must be PRACTICAL: real commands a pentester can copy and run.
Do not describe what to do in vague terms — give exact syntax adapted to the target IP/service.
If a finding suggests SQL injection, provide the exact sqlmap command. If it shows SSH, provide hydra/nmap commands.
Always think in terms of: initial access → privilege escalation → objectives."""


# ── Prompt builder ────────────────────────────────────────────────────────────

def _fmt_finding(f: dict, idx: int) -> str:
    lines = [
        f"[F{idx}] {f.get('title','?')} | Severity: {f.get('severity','?')} | Phase: {f.get('phase','?')}",
        f"    Description: {(f.get('description') or '')[:200]}",
    ]
    if f.get("tool"):
        lines.append(f"    Tool: {f.get('tool')}  Port: {f.get('port','')}  Host: {f.get('host','')}")
    if f.get("cves"):
        lines.append(f"    CVEs: {f.get('cves')}")
    return "\n".join(lines)


def _build_prompt(target: str, findings: List[dict], services: dict, rag_ctx: str) -> str:
    finding_block = "\n".join(_fmt_finding(f, i) for i, f in enumerate(findings[:MAX_FINDINGS_PER_PROMPT]))
    svc_block = ", ".join(
        f"{p}/{(v.get('service') or v) if isinstance(v, dict) else v}"
        for p, v in list(services.items())[:12]
    ) if services else "unknown"

    return f"""TARGET: {target}
OPEN SERVICES: {svc_block}
FINDING COUNT: {len(findings)}

SECURITY FINDINGS:
{finding_block}

RELEVANT EXPLOITATION TECHNIQUES (from knowledge base):
{rag_ctx or '(no KB context available)'}

---
Analyze the above findings and produce a structured attack chain analysis.

You MUST return ONLY valid JSON matching this exact schema:

{{
  "chains": [
    {{
      "id": "chain_001",
      "title": "Short title (e.g. SQLi → OS Shell → Root)",
      "description": "Step-by-step description of what this chain achieves",
      "probability": 0.75,
      "impact": "critical",
      "entry_point": "port 80 HTTP",
      "objective": "root shell / data exfil / credential dump",
      "missing_requirements": ["need valid credentials", "need HTTP access"],
      "finding_refs": ["F0", "F2"],
      "steps": [
        {{
          "id": "s1",
          "order": 1,
          "technique": "SQL Injection",
          "description": "Exploit SQLi on login form to gain DB access",
          "tool": "sqlmap",
          "command": "sqlmap -u 'http://{target}/login.php' --data='user=admin&pass=test' --level=5 --risk=3 --dbs",
          "expected_outcome": "Database names enumerated, potential OS shell",
          "mitre_id": "T1190",
          "mitre_tactic": "initial_access",
          "requires": [],
          "produces": "db_access",
          "finding_ref": "F0"
        }},
        {{
          "id": "s2",
          "order": 2,
          "technique": "OS Command Execution via SQLi",
          "description": "Use --os-shell in sqlmap to get a command shell",
          "tool": "sqlmap",
          "command": "sqlmap -u 'http://{target}/login.php' --data='user=admin&pass=test' --os-shell",
          "expected_outcome": "Interactive OS shell as mysql user",
          "mitre_id": "T1059",
          "mitre_tactic": "execution",
          "requires": ["db_access"],
          "produces": "shell_limited",
          "finding_ref": "F0"
        }}
      ]
    }}
  ],
  "immediate_actions": [
    "Run sqlmap against discovered login endpoints to verify SQLi",
    "Attempt default credentials on SSH port 22"
  ],
  "recommended_chain_id": "chain_001",
  "target_assessment": "2-3 sentence summary of the target's security posture and most critical weaknesses",
  "graph_nodes": [
    {{"id": "sqli_login", "type": "vulnerability", "label": "SQL Injection /login", "severity": "critical", "metadata": {{"port": "80", "technique": "T1190"}}}}
  ],
  "graph_edges": [
    {{"source": "sqli_login", "target": "os_shell", "label": "exploitable_via_os_shell"}}
  ]
}}

Replace {target} in all commands with the actual target IP/hostname.
Probability: 0.0–1.0 (how likely this chain succeeds given the findings).
Impact: critical / high / medium / low.
Provide at minimum 1 chain, ideally 2-4 covering different entry points.
Only include chains that are realistically achievable from the discovered findings."""


# ── Chain Analysis Agent ───────────────────────────────────────────────────────

class AttackGraphAgent:
    """
    Background agent that continuously analyzes pentest findings to
    build actionable attack chains and enrich the attack graph.
    """

    def __init__(
        self,
        session_id:  str,
        target:      str,
        broadcast:   Callable[[dict], Coroutine[Any, Any, None]],
        db:          AsyncIOMotorDatabase,
        services:    Optional[dict] = None,
    ) -> None:
        self.session_id  = session_id
        self.target      = target
        self.broadcast   = broadcast
        self.db          = db
        self.services    = services or {}
        self._stop       = False
        self._seen_fids: set[str] = set()   # finding IDs already analyzed
        self._analysis_count = 0

    def request_stop(self) -> None:
        self._stop = True

    def update_services(self, services: dict) -> None:
        """Called by master agent when new service data arrives."""
        self.services = services

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def run_analysis_loop(self) -> None:
        """
        Continuous background loop. Runs until stop is requested.
        Polls for new findings and triggers chain analysis when enough accumulate.
        """
        logger.info("[AttackGraphAgent] Starting analysis loop for session %s", self.session_id)
        await self._emit("chain_analysis_status", {"status": "started", "message": "Attack Graph Agent monitoring findings..."})

        consecutive_errors = 0

        while not self._stop:
            try:
                await asyncio.sleep(POLL_INTERVAL)
                if self._stop:
                    break

                # Fetch all findings for this session
                findings = await _db.get_findings(self.session_id)
                if not findings:
                    continue

                # Check if enough new findings have accumulated
                new_fids = {f.get("id") or f.get("_id") or f.get("finding_id", "") for f in findings}
                new_fids = {fid for fid in new_fids if fid}
                truly_new = new_fids - self._seen_fids

                if len(truly_new) < NEW_FINDINGS_THRESHOLD and self._analysis_count > 0:
                    continue  # not enough new data, wait

                logger.info("[AttackGraphAgent] %d new findings → running chain analysis", len(truly_new))
                await self._run_analysis(findings)
                self._seen_fids = new_fids
                consecutive_errors = 0

            except asyncio.CancelledError:
                break
            except Exception as exc:
                consecutive_errors += 1
                logger.warning("[AttackGraphAgent] Analysis error (%d): %s", consecutive_errors, exc)
                if consecutive_errors >= 5:
                    logger.error("[AttackGraphAgent] Too many errors, stopping loop")
                    break
                await asyncio.sleep(30)

        logger.info("[AttackGraphAgent] Analysis loop stopped for session %s", self.session_id)

    # ── Core analysis ─────────────────────────────────────────────────────────

    async def _run_analysis(self, findings: List[dict]) -> None:
        """Query RAG + LLM, produce chain analysis, persist, emit."""
        await self._emit("chain_analysis_status", {
            "status":  "analyzing",
            "message": f"Analyzing {len(findings)} findings for attack chains...",
        })

        # Build RAG query from top findings
        top_titles = " ".join(
            f.get("title", "") for f in findings[:8]
            if f.get("severity") in ("CRITICAL", "HIGH")
        ) or " ".join(f.get("title", "") for f in findings[:5])

        rag_ctx = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _rag(top_titles + " exploitation attack chain", top_k=5)
        )
        rag_cmds = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _rag_commands(top_titles, top_k=4)
        )
        combined_rag = "\n\n".join(filter(None, [rag_ctx, rag_cmds]))

        prompt = _build_prompt(self.target, findings, self.services, combined_rag)

        try:
            raw = await self._llm_call(prompt)
            analysis = self._parse_json(raw)
        except Exception as exc:
            logger.warning("[AttackGraphAgent] LLM call failed: %s", exc)
            await self._emit("chain_analysis_status", {
                "status":  "error",
                "message": f"LLM analysis failed: {exc}",
            })
            return

        if not analysis or analysis.get("parse_error"):
            logger.warning("[AttackGraphAgent] Failed to parse LLM JSON")
            return

        self._analysis_count += 1

        # Persist to DB
        doc_id = await self._persist(analysis, findings)

        # Update attack graph with chain nodes/edges
        await self._update_graph(analysis)

        # Emit full analysis to frontend
        await self._emit("chain_analysis", {
            "analysis_id":        doc_id,
            "chains":             analysis.get("chains", []),
            "immediate_actions":  analysis.get("immediate_actions", []),
            "recommended_chain":  analysis.get("recommended_chain_id", ""),
            "target_assessment":  analysis.get("target_assessment", ""),
            "finding_count":      len(findings),
            "ts":                 datetime.now(timezone.utc).isoformat(),
        })

        await self._emit("chain_analysis_status", {
            "status":  "complete",
            "message": f"Analysis #{self._analysis_count}: {len(analysis.get('chains', []))} chains identified",
        })

        logger.info("[AttackGraphAgent] Analysis #%d complete: %d chains",
                    self._analysis_count, len(analysis.get("chains", [])))

    # ── Graph updates ─────────────────────────────────────────────────────────

    async def _update_graph(self, analysis: dict) -> None:
        """Push chain nodes and edges into the attack graph DB."""
        try:
            # Add chain nodes
            for node in analysis.get("graph_nodes", []):
                nid = node.get("id") or str(uuid.uuid4())[:8]
                await _db.add_attack_node(
                    session_id = self.session_id,
                    node_id    = f"chain_{nid}",
                    node_type  = node.get("type", "vulnerability"),
                    label      = node.get("label", nid),
                    host       = self.target,
                    port       = int(node.get("metadata", {}).get("port", 0) or 0) or None,
                    severity   = node.get("severity", "medium"),
                    phase      = "chain_analysis",
                    metadata   = {**(node.get("metadata") or {}), "from_chain_agent": True},
                )

            # Add chain edges
            for edge in analysis.get("graph_edges", []):
                src = f"chain_{edge.get('source', '')}"
                tgt = f"chain_{edge.get('target', '')}"
                if src and tgt:
                    edge_id = f"{src}->{tgt}"
                    await _db.add_attack_edge(
                        session_id = self.session_id,
                        edge_id    = edge_id,
                        source     = src,
                        target     = tgt,
                        label      = edge.get("label", "leads_to"),
                        tool       = "chain_analysis",
                    )

            # Add a chain cluster node for each chain
            for chain in analysis.get("chains", []):
                chain_node_id = f"chain_cluster_{chain.get('id', uuid.uuid4().hex[:8])}"
                await _db.add_attack_node(
                    session_id = self.session_id,
                    node_id    = chain_node_id,
                    node_type  = "exploit",
                    label      = f"⛓ {chain.get('title', 'Attack Chain')}",
                    host       = self.target,
                    severity   = chain.get("impact", "high"),
                    phase      = "chain_analysis",
                    metadata   = {
                        "chain_id":    chain.get("id"),
                        "probability": chain.get("probability", 0),
                        "objective":   chain.get("objective", ""),
                        "steps":       len(chain.get("steps", [])),
                        "from_chain_agent": True,
                    },
                )

            # Emit graph events so frontend refreshes
            await self._emit("graph_refresh", {"reason": "chain_analysis", "session_id": self.session_id})

        except Exception as exc:
            logger.warning("[AttackGraphAgent] Graph update failed: %s", exc)

    # ── Persistence ───────────────────────────────────────────────────────────

    async def _persist(self, analysis: dict, findings: List[dict]) -> str:
        """Store chain analysis to MongoDB. Returns document ID."""
        doc_id = str(uuid.uuid4())
        doc = {
            "_id":              doc_id,
            "session_id":       self.session_id,
            "target":           self.target,
            "analysis_number":  self._analysis_count,
            "chains":           analysis.get("chains", []),
            "immediate_actions": analysis.get("immediate_actions", []),
            "recommended_chain": analysis.get("recommended_chain_id", ""),
            "target_assessment": analysis.get("target_assessment", ""),
            "finding_count":    len(findings),
            "created_at":       datetime.now(timezone.utc).isoformat(),
        }
        try:
            await self.db["chain_analyses"].insert_one(doc)
        except Exception as exc:
            logger.warning("[AttackGraphAgent] DB persist failed: %s", exc)
        return doc_id

    # ── LLM ───────────────────────────────────────────────────────────────────

    async def _llm_call(self, prompt: str) -> str:
        """Call Ollama API with the chain analysis prompt."""
        messages = [
            {"role": "system",  "content": _SYSTEM_PROMPT},
            {"role": "user",    "content": prompt},
        ]
        async with httpx.AsyncClient(timeout=httpx.Timeout(LLM_TIMEOUT)) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={"model": MODEL_NAME, "messages": messages, "stream": False},
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"]

    @staticmethod
    def _parse_json(raw: str) -> dict:
        """Extract and parse JSON from LLM response."""
        # Direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
        # Code block
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        # Greedy brace match
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        return {"raw_response": raw[:500], "parse_error": True}

    # ── Emit ──────────────────────────────────────────────────────────────────

    async def _emit(self, event_type: str, data: dict) -> None:
        """Broadcast a WS event. Compatible with both broadcast(dict) and broadcast(WebSocketMessage)."""
        from db.schemas import WebSocketMessage
        msg = WebSocketMessage(
            type       = event_type,
            session_id = self.session_id,
            agent      = "attack_graph",
            data       = data,
        )
        try:
            await self.broadcast(msg)
        except Exception as exc:
            logger.debug("[AttackGraphAgent] broadcast failed: %s", exc)
