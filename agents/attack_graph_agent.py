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
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

import db.mongo_client as _db

logger = logging.getLogger(__name__)


def _safe_port(value: Any) -> Optional[int]:
    """Coerce an LLM-supplied port to a valid int, or None.

    The model sometimes labels a node's port with a SERVICE NAME ("DNS",
    "http", "smb") instead of a number.  ``int("DNS")`` raised
    ``ValueError`` and aborted the WHOLE graph update — every chain node and
    edge from that analysis was silently dropped ("Graph update failed:
    invalid literal for int()").  This guard returns a port only when it is
    a real number in range, else None (which the DB layer accepts), so one
    bad field can never sink the rest of the graph."""
    if value is None:
        return None
    if isinstance(value, bool):          # bool is an int subclass — reject
        return None
    if isinstance(value, int):
        return value if 0 < value <= 65535 else None
    s = str(value).strip()
    if not s.isdigit():
        return None
    try:
        p = int(s)
    except (TypeError, ValueError):
        return None
    return p if 0 < p <= 65535 else None

# ── Config ────────────────────────────────────────────────────────────────────
# Note: the LLM backend (Anthropic / Claude Code / Ollama / OpenAI / etc.)
# is selected by ``utils.llm_providers.get_provider()`` from the operator's
# environment at startup.  This agent does NOT hold its own provider URL
# any more — it routes through the unified provider exactly like every
# other ARGUS agent so a single configuration drives the whole platform.
# Per-call upper bound.  Locally-hosted LLMs (Ollama / LM Studio / llama.cpp) are
# much slower than a cloud API, so the default is generous (600s = 10 min) and
# overridable for very slow hosts.  Was 180s, which timed out local models.
LLM_TIMEOUT  = int(os.environ.get("ARGUS_ATTACKGRAPH_TIMEOUT",
                                  os.environ.get("LOCAL_LLM_TIMEOUT", "600")))
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
_SYSTEM_PROMPT = """You are a defensive security analyst supporting an AUTHORIZED, scoped penetration-testing engagement. Working only from confirmed findings produced by the engagement's own tooling, your job is analytical: you help the defending organization understand how discrete weaknesses could be chained together into attack PATHS, map those paths to MITRE ATT&CK, and decide which ones to fix first.

You are an attack-path RISK PRIORITIZATION engine. Given a set of security findings from the authorized assessment, you:
1. Correlate related findings into plausible multi-step attack PATHS (chains) — how individual weaknesses could realistically combine into a route toward a meaningful objective (initial access -> privilege escalation -> lateral movement -> impact), so defenders see end-to-end risk rather than isolated issues.
2. For each step, describe the METHOD at a planning level: the technique, the NAME of the tool or capability class typically associated with validating it, and which finding or exposed service it applies to. Do NOT write runnable, target-specific exploit commands, flags, or payloads; describe the approach, not copy-and-paste syntax.
3. Map each step to a MITRE ATT&CK technique (technique ID and tactic).
4. Rate each path by probability of success and by business impact, so the team can rank them.
5. Identify the prerequisites and the missing information or access each path still needs before it could be validated — these are the gaps defenders can widen to break the chain.
6. Recommend the single highest-priority path to focus validation and remediation on, with a short rationale.

Your analysis is PRACTICAL but stays at the level of risk assessment and methodology: think in terms of attacker objectives, prerequisites, and MITRE-mapped tactic progression — not weaponized commands. Keep the framing defensive throughout: the purpose is to prioritize validation and remediation on an authorized engagement so defenders can see where to break the chain."""


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

RELEVANT DEFENSIVE / TECHNIQUE REFERENCES (from knowledge base):
{rag_ctx or '(no KB context available)'}

---
Analyze the above findings and produce a structured attack-path risk analysis for this authorized assessment.

For each path, correlate the findings into a plausible multi-step route, map each step to MITRE ATT&CK, rate probability and impact, and list what is still missing. Describe each step by METHOD (technique + tool NAME + which finding it applies to), not by a runnable exploit string.

You MUST return ONLY valid JSON matching this exact schema:

{{
  "chains": [
    {{
      "id": "chain_001",
      "title": "Short attack-path title (e.g. Web input weakness -> data-store access -> host foothold)",
      "description": "Plain-language summary of how these findings could chain and what the path would achieve",
      "probability": 0.6,
      "impact": "critical",
      "entry_point": "port 80 HTTP",
      "objective": "host foothold / data access / credential exposure",
      "missing_requirements": ["valid application credentials", "confirmed HTTP reachability"],
      "finding_refs": ["F0", "F2"],
      "steps": [
        {{
          "id": "s1",
          "order": 1,
          "technique": "SQL injection validation",
          "description": "Assess whether the login input on the F0 web finding is injectable and could expose the backing database",
          "tool": "sqlmap",
          "command": "SQL injection validation against the F0 login endpoint (tool: sqlmap)",
          "expected_outcome": "Determination of whether the input is injectable and what data it would expose",
          "mitre_id": "T1190",
          "mitre_tactic": "initial_access",
          "requires": [],
          "produces": "database_access",
          "finding_ref": "F0"
        }},
        {{
          "id": "s2",
          "order": 2,
          "technique": "Credential access from exposed data store",
          "description": "If the database is reachable, assess whether stored credentials could be recovered to reach a host account",
          "tool": "hashcat",
          "command": "Offline credential-recovery method applied to data exposed in step s1 (tool: hashcat)",
          "expected_outcome": "Assessment of whether recovered credentials enable a host foothold",
          "mitre_id": "T1003",
          "mitre_tactic": "credential_access",
          "requires": ["database_access"],
          "produces": "host_credentials",
          "finding_ref": "F0"
        }}
      ]
    }}
  ],
  "immediate_actions": [
    "Prioritize validating the F0 web input weakness — it is the entry point of the highest-rated path",
    "Confirm reachability and scope of the SSH service on port 22 before considering it as an alternate entry point"
  ],
  "recommended_chain_id": "chain_001",
  "target_assessment": "2-3 sentence summary of the target's security posture and the most critical weaknesses driving risk",
  "graph_nodes": [
    {{"id": "sqli_login", "type": "vulnerability", "label": "SQL injection candidate /login", "severity": "critical", "metadata": {{"port": "80", "technique": "T1190"}}}}
  ],
  "graph_edges": [
    {{"source": "sqli_login", "target": "data_access", "label": "could_enable"}}
  ]
}}

Field guidance:
- "command" is a HIGH-LEVEL METHOD label for display only — describe the technique and which finding/endpoint it targets, and reference the tool by NAME (e.g. "Credential-spray assessment against the F1 SSH service (tool: hydra)"). Do NOT put runnable exploit syntax, flags, payloads, or target substitutions in this field.
- "tool" is the NAME of the tool or capability class typically associated with validating that step (e.g. sqlmap, hydra, nmap) — a name, not an invocation.
- "immediate_actions": prioritized analytical next-steps for the team (what to validate or investigate first, and why), not exploit instructions.
- "probability": 0.0-1.0, how likely this path succeeds given the findings.
- "impact": critical / high / medium / low.
- Reference findings by their [F#] ids in "finding_refs" and each step's "finding_ref".
- Map every step to a real MITRE ATT&CK "mitre_id" and "mitre_tactic".
- Provide at minimum 1 path, ideally 2-4 covering different entry points.
- Only include paths that are realistically achievable from the discovered findings. Keep the example values above generic — do not emit real exploit payloads anywhere in the output."""


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
        master:      Optional[Any] = None,
    ) -> None:
        self.session_id  = session_id
        self.target      = target
        self.broadcast   = broadcast
        self.db          = db
        self.services    = services or {}
        # Optional back-reference to the master so chain analysis (which already
        # runs in PARALLEL and uses the LLM/KB) can feed advisories to the
        # operator via master.notify_advisor — supporting the operator without
        # blocking it.  None when run standalone; advisory push is then skipped.
        self._master     = master
        self._stop       = False
        self._seen_fids: set[str] = set()   # finding IDs already analyzed
        self._analysis_count = 0
        # LLM provider state — primary + .env-configured backup (no hardcode).
        self._active_provider   = None      # lazily built primary (get_provider)
        self._fallback_provider = None      # lazily built backup (LLM_FALLBACK_*)
        self._fallback_loaded   = False
        self._on_fallback       = False

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
                # ── Backup-LLM fallback (configured ENTIRELY via .env) ──────
                # Fall back to the LLM_FALLBACK_* backup after
                # ATTACKGRAPH_FALLBACK_AFTER (default 5) consecutive PRIMARY
                # failures, or immediately on a usage-policy / content refusal
                # (a refusing model never recovers on retry).  Nothing is
                # hardcoded — primary and backup both come from .env.
                _es = str(exc).lower()
                _is_refusal = any(s in _es for s in ("usage policy", "aup",
                                  "unable to respond", "violate", "refus"))
                import os as _os
                _threshold = int(_os.environ.get("ATTACKGRAPH_FALLBACK_AFTER", "5") or 5)
                if not self._on_fallback and (consecutive_errors >= _threshold or _is_refusal):
                    if self._switch_to_fallback():
                        _fb = self._active_provider
                        logger.warning("[AttackGraphAgent] primary LLM failed %d× — "
                                       "switching to .env backup %s/%s",
                                       consecutive_errors,
                                       getattr(_fb, "name", "?"), getattr(_fb, "model", "?"))
                        try:
                            await self._emit("chain_analysis_status", {
                                "status":  "degraded",
                                "message": (f"Primary LLM failed {consecutive_errors}× — "
                                            f"switched to backup "
                                            f"{getattr(_fb,'name','?')}/{getattr(_fb,'model','?')} "
                                            f"(from .env LLM_FALLBACK_*)."),
                            })
                        except Exception:
                            pass
                        consecutive_errors = 0
                        await asyncio.sleep(2)
                        continue
                    if _is_refusal:
                        # No backup configured AND a refusal → cannot recover.
                        logger.error("[AttackGraphAgent] primary refused + no .env backup "
                                     "configured — disabling chain analysis")
                        try:
                            await self._emit("chain_analysis_status", {
                                "status":  "stopped",
                                "message": ("Primary LLM refused offensive analysis and no "
                                            "LLM_FALLBACK_PROVIDER is set in .env — disabled. "
                                            "Configure LLM_FALLBACK_PROVIDER/_MODEL to enable a backup."),
                            })
                        except Exception:
                            pass
                        break
                # Emit a single warning when we've burned half the budget
                # so the operator knows we're about to give up.
                if consecutive_errors == 3:
                    try:
                        await self._emit("chain_analysis_status", {
                            "status":  "degraded",
                            "message": (
                                f"Attack-chain analysis has failed {consecutive_errors} "
                                "times in a row.  Will auto-stop after 5 failures.  "
                                "Check that the configured LLM provider is reachable."
                            ),
                        })
                    except Exception:
                        pass
                if consecutive_errors >= 5:
                    logger.error("[AttackGraphAgent] Too many errors, stopping loop")
                    try:
                        await self._emit("chain_analysis_status", {
                            "status":  "stopped",
                            "message": (
                                "Attack-chain analysis stopped after 5 consecutive "
                                "LLM failures.  Restart the scan once the LLM "
                                "provider is reachable to resume."
                            ),
                        })
                    except Exception:
                        pass
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
                "message": f"LLM analysis failed: {str(exc).strip() or type(exc).__name__}",
            })
            # Re-raise so the outer loop's consecutive_errors counter
            # increments and the loop self-terminates after 5 failures
            # instead of spamming the event feed indefinitely.  Without
            # this, an LLM that is genuinely down causes a poll-and-fail
            # cycle every 35 seconds for the entire engagement.
            raise

        if not analysis or analysis.get("parse_error"):
            logger.warning("[AttackGraphAgent] Failed to parse LLM JSON")
            # A parse failure is a softer issue than a transport failure
            # — don't count it toward the auto-stop counter, but still
            # surface it to the UI so the operator can see it happened.
            await self._emit("chain_analysis_status", {
                "status":  "parse_error",
                "message": "LLM returned content but JSON parse failed — analysis skipped this cycle",
            })
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

        # PARALLEL SUPPORT — feed the operator the single most valuable next step
        # this analysis surfaced (advisory only; never blocks the operator loop).
        try:
            if self._master is not None and hasattr(self._master, "notify_advisor"):
                _acts = analysis.get("immediate_actions") or []
                _chains = analysis.get("chains") or []
                _hint = ""
                if _acts:
                    _first = _acts[0]
                    _hint = (_first.get("description") or _first.get("action") or str(_first)
                             if isinstance(_first, dict) else str(_first))
                elif _chains:
                    _c0 = _chains[0]
                    _hint = (_c0.get("name") or _c0.get("description") or str(_c0)
                             if isinstance(_c0, dict) else str(_c0))
                if _hint:
                    self._master.notify_advisor(
                        "attack-graph",
                        f"Highest-value next step from chain analysis "
                        f"({len(_chains)} chain(s) mapped): {str(_hint)[:300]}")
        except Exception:
            pass

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
                    port       = _safe_port((node.get("metadata") or {}).get("port")),
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

    def _provider(self):
        """Return the ACTIVE LLM provider.

        Primary is whatever ``.env`` configures (``LLM_PROVIDER`` /
        ``OLLAMA_MODEL`` / ``ANTHROPIC_MODEL`` / … via ``get_provider()``) —
        nothing is hardcoded here.  Once the loop has fallen back, this returns
        the ``.env``-configured backup instead.
        """
        if self._active_provider is None:
            from utils.llm_providers import get_provider
            self._active_provider = get_provider()
        return self._active_provider

    def _load_fallback(self):
        """Lazily build the backup provider from ``.env`` (LLM_FALLBACK_*).
        Returns the provider, or None if no backup is configured."""
        if not self._fallback_loaded:
            self._fallback_loaded = True
            try:
                from utils.llm_providers import get_fallback_provider
                self._fallback_provider = get_fallback_provider()
            except Exception:
                self._fallback_provider = None
        return self._fallback_provider

    def _switch_to_fallback(self) -> bool:
        """Switch the active provider to the ``.env`` backup.  Returns True if
        a backup was configured and we switched (False = no backup → caller
        decides whether to stop)."""
        fb = self._load_fallback()
        if fb is not None and not self._on_fallback:
            self._active_provider = fb
            self._on_fallback = True
            return True
        return False

    async def _llm_call(self, prompt: str) -> str:
        """Route through the ACTIVE LLM provider (primary, or the .env backup
        after the loop falls back).  The provider is resolved entirely from
        ``.env`` — nothing is hardcoded.
        """
        messages = [
            {"role": "system",  "content": _SYSTEM_PROMPT},
            {"role": "user",    "content": prompt},
        ]
        provider = self._provider()
        tokens: list[str] = []
        try:
            async for tok in provider.stream(messages, timeout=LLM_TIMEOUT):
                if tok:
                    tokens.append(tok)
        except Exception as exc:                                # noqa: BLE001
            # Bubble up with the provider name so the event-feed message
            # tells the operator WHICH backend is failing, not just
            # "All connection attempts failed".
            _emsg = str(exc).strip() or (
                f"{type(exc).__name__} (no detail — usually a read timeout or "
                "connection reset; the local LLM may be slow/down, raise the "
                "timeout via ARGUS_ATTACKGRAPH_TIMEOUT or check it is running)")
            raise RuntimeError(
                f"{provider.name} ({provider.model or '?'}) failed: {_emsg}"
            ) from exc

        if not tokens:
            raise RuntimeError(
                f"{provider.name} returned no content "
                "(empty stream — check the provider is reachable and the model exists)"
            )
        return "".join(tokens)

    @staticmethod
    def _parse_json(raw: str) -> dict:
        """Extract and parse JSON from LLM response.

        Falls back to the tolerant parser in utils.json_tolerant for
        common LLM-emitted JSON dialects (// comments, .join() chains,
        trailing commas, markdown fences, smart quotes, etc.).
        """
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
        # Tolerant repair pass
        try:
            from utils.json_tolerant import parse_lossy
            parsed, _ = parse_lossy(raw)
            if parsed is not None and isinstance(parsed, dict):
                return parsed
        except Exception:
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
