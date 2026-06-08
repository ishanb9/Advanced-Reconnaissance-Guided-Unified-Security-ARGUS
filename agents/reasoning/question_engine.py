"""
agents/reasoning/question_engine.py

Orchestrates the 3-layer answer extraction pipeline for ARGUS.

Layer 1 — DeterministicExtractor  (regex/heuristics, no LLM, always runs first)
Layer 2 — Improved LLM extraction  (few-shot, answer-type hints, JSON validation)
Layer 3 — Targeted tool dispatch   (picks minimal tool, re-runs L1+L2 on output)

Dual-mode operation:
  Objective Mode  — CTF / forensics / compliance: predefined questions, tracked state
  Discovery Mode  — pentest / red_team / bug_bounty: surface findings automatically
                    from tool outputs; ad-hoc questions via guidance or Ask bar

Activated only when use_reasoning_loop=True.  All imports guarded.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from agents.master_agent import MasterAgent

from agents.reasoning.deterministic_extractor import (
    DeterministicExtractor,
    ExtractorResult,
    DiscoveryFinding,
)


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

class QuestionState(str, Enum):
    PENDING      = "pending"
    SEARCHING    = "searching"
    ANSWERED     = "answered"
    UNANSWERABLE = "unanswerable"


@dataclass
class Question:
    id:            str
    text:          str
    state:         QuestionState    = QuestionState.PENDING
    answer:        Optional[str]    = None
    evidence:      str              = ""
    layer_used:    int              = 0          # 1, 2, or 3
    finding_id:    Optional[str]    = None
    objective_idx: Optional[int]    = None       # set for CTF objectives


# ─────────────────────────────────────────────────────────────────────────────
# Tool selection table for Layer 3
# Each entry: ([question_keywords], tool_name, args_template)
# {target} is replaced with the actual session target.
# ─────────────────────────────────────────────────────────────────────────────

_LAYER3_TOOL_MAP: List[Tuple[List[str], str, str]] = [
    (["how many port", "open port", "number of port", "ports open"],
     "nmap", "-sV --open {target}"),
    (["web server", "http server", "what server", "web service", "whatweb"],
     "whatweb", "{target}"),
    (["operating system", "what os", "which os", "os version", "os detection"],
     "nmap", "-O {target}"),
    (["directory", "web path", "gobuster", "endpoint", "hidden"],
     "gobuster", "dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q"),
    (["ssh version", "openssh", "ssh banner"],
     "nmap", "-p 22 -sV {target}"),
    (["ftp", "vsftpd", "ftp version"],
     "nmap", "-p 21 -sV {target}"),
    (["smb", "samba", "windows share", "netbios"],
     "nmap", "-p 445 --script=smb-os-discovery {target}"),
    (["ssl", "tls", "certificate", "https cert"],
     "nmap", "-p 443 --script=ssl-cert {target}"),
    (["mysql", "database", "sql server", "postgres"],
     "nmap", "-p 3306,5432,1433,27017 -sV {target}"),
    (["crack", "hash", "password hash"],
     "hashcat", "--example-hashes"),
    (["user flag", "user.txt"],
     "cat", "/home/*/user.txt 2>/dev/null || find / -name user.txt -readable 2>/dev/null | head -5"),
    (["root flag", "root.txt"],
     "cat", "/root/root.txt 2>/dev/null || find / -name root.txt -readable 2>/dev/null | head -5"),
]

# Engagement types that use Discovery Mode
_DISCOVERY_MODES = {"pentest", "red_team", "bug_bounty", ""}


# ─────────────────────────────────────────────────────────────────────────────
# QuestionEngine
# ─────────────────────────────────────────────────────────────────────────────

class QuestionEngine:
    """
    Orchestrates the 3-layer pipeline and dual-mode operation.

    Usage in ReasoningLoop:
        # Initialise once
        self._qe = QuestionEngine(master, session_id, target, emit_fn)

        # Load CTF objectives at start
        for i, obj in enumerate(objectives):
            self._qe.add_question(obj.get("task") or str(obj), objective_idx=i)

        # After every tool execution:
        await self._qe.answer_all(intel, tool_stdout)
        await self._qe.run_discovery_pass(tool_stdout, phase, tool, intel)

        # Ad-hoc question from guidance / Ask bar:
        q = await self._qe.answer_single("what web server is running?", intel)
    """

    # Question-intent detection keywords (starts-with)
    _QUESTION_PREFIXES = (
        "what", "how", "which", "find", "where", "who", "is there",
        "does", "can you", "tell me", "show me", "list", "identify",
        "detect", "enumerate", "scan", "check", "get the", "what is",
    )

    def __init__(
        self,
        master_agent: "MasterAgent",
        session_id:   str,
        target:       str,
        emit_fn:      Callable[..., Any],
    ) -> None:
        self._master     = master_agent
        self._session_id = session_id
        self._target     = target
        self._emit       = emit_fn
        self._extractor  = DeterministicExtractor()
        self._questions: Dict[str, Question] = {}

    # ─────────────────────────────────────────────────────────────────────────
    # Public interface
    # ─────────────────────────────────────────────────────────────────────────

    def is_question(self, text: str) -> bool:
        """Return True if the text looks like a question, not a directive."""
        t = text.strip().lower()
        if t.endswith("?"):
            return True
        return any(t.startswith(p) for p in self._QUESTION_PREFIXES)

    def add_question(self, text: str, objective_idx: int = None) -> Question:
        """Register a question. Idempotent — same text returns the existing Question."""
        t_norm = text.strip().lower()
        for q in self._questions.values():
            if q.text.strip().lower() == t_norm:
                return q
        qid = str(uuid.uuid4())[:8]
        q   = Question(id=qid, text=text, objective_idx=objective_idx)
        self._questions[qid] = q
        return q

    def load_from_intel(self, intel: dict) -> None:
        """Restore question states from intel snapshot (pause/resume)."""
        for qid, data in intel.get("question_states", {}).items():
            if qid not in self._questions:
                self._questions[qid] = Question(
                    id            = qid,
                    text          = data.get("text", ""),
                    state         = QuestionState(data.get("state", "pending")),
                    answer        = data.get("answer"),
                    evidence      = data.get("evidence", ""),
                    layer_used    = data.get("layer_used", 0),
                    objective_idx = data.get("objective_idx"),
                )

    def save_to_intel(self, intel: dict) -> None:
        """Persist question states into intel for checkpointing."""
        intel["question_states"] = {
            qid: {
                "text":          q.text,
                "state":         q.state.value,
                "answer":        q.answer,
                "evidence":      q.evidence,
                "layer_used":    q.layer_used,
                "objective_idx": q.objective_idx,
            }
            for qid, q in self._questions.items()
        }

    async def answer_all(self, intel: dict, raw_output: str = "") -> None:
        """
        Process all PENDING questions against current intel + raw_output.
        Called after every tool execution in the reasoning loop.
        """
        pending = [q for q in self._questions.values()
                   if q.state == QuestionState.PENDING]
        for q in pending:
            await self._answer_question(q, intel, raw_output)
        self.save_to_intel(intel)

    # ─────────────────────────────────────────────────────────────────────────
    # Holistic objective grading (complete / partial / not_complete)
    # ─────────────────────────────────────────────────────────────────────────

    def _build_evidence_summary(self, intel: dict) -> str:
        """Condense the engagement state into an evidence block the LLM can
        grade objectives against."""
        lines: List[str] = []
        lines.append(f"Open ports: {intel.get('open_ports') or []}")
        svcs = intel.get("services") or {}
        if svcs:
            lines.append("Services: " + "; ".join(
                f"{p}={(v.get('service') if isinstance(v, dict) else v)} "
                f"{(v.get('version', '') if isinstance(v, dict) else '')}".strip()
                for p, v in list(svcs.items())[:12]))
        lines.append(f"Shell access: {bool(intel.get('shell_access'))} "
                     f"(current_user={intel.get('current_user') or '?'})")
        shells = intel.get("shells") or []
        if shells:
            lines.append(f"Shells ({len(shells)}): " + "; ".join(
                f"{(s.get('user') if isinstance(s, dict) else '?')}"
                f"{'(root/elevated)' if isinstance(s, dict) and s.get('elevated') else ''}"
                for s in shells[:5]))
        creds = intel.get("credentials") or []
        if creds:
            lines.append(f"Credentials harvested: {len(creds)}")
        for k in ("user_flag", "root_flag"):
            if intel.get(k):
                lines.append(f"{k}: {str(intel.get(k))[:80]}")
        ca = intel.get("ctf_answers") or {}
        if ca:
            lines.append("Captured answers: " + "; ".join(
                f"#{k}={str(v.get('answer'))[:60]}" for k, v in list(ca.items())[:8]))
        loot = intel.get("loot_entries") or []
        if loot:
            lines.append(f"Loot entries: {len(loot)}")
        vulns = intel.get("vulnerabilities") or []
        if vulns:
            lines.append("Vulnerabilities: " + "; ".join(
                (v.get("title", "") if isinstance(v, dict) else str(v))[:60] for v in vulns[:6]))
        return "\n".join(lines) or "(no evidence gathered yet)"

    async def evaluate_objectives(self, intel: dict) -> dict:
        """Holistically grade EVERY objective against the FULL engagement
        evidence — complete / partial / not_complete + confidence + evidence +
        blocker.

        This is the authoritative completion signal.  ``answer_all`` only
        resolves *literal-answer* objectives (a flag string in tool output);
        STATE objectives — "obtain a shell", "escalate to root", "find the 3
        keys" — can never be marked done by string extraction, and a question
        that went UNANSWERABLE was never revisited.  This grader looks at the
        whole evidence picture every time it runs, so previously-unmet
        objectives flip to complete the moment the supporting evidence appears.

        Updates ``intel['objective_status']``, emits per-objective +
        ``objectives_summary`` events, and returns the summary counts.  Never
        raises (best-effort).
        """
        objectives = (
            (intel.get("engagement_context") or {}).get("objectives")
            or intel.get("ctf_objectives") or []
        )
        if not objectives:
            return {}
        obj_texts: List[str] = []
        for i, o in enumerate(objectives):
            t = (o.get("task") or o.get("question") or str(o)) if isinstance(o, dict) else str(o)
            obj_texts.append(t)

        evidence = self._build_evidence_summary(intel)
        system = (
            "You are grading an AUTHORIZED penetration test against its declared "
            "objectives. For EACH objective decide its status from the EVIDENCE "
            "ONLY: 'complete' (evidence proves it is done — e.g. a flag captured, "
            "a shell as the required user, a key found), 'partial' (real progress "
            "but not done), or 'not_complete' (no real progress). NEVER mark "
            "complete without concrete supporting evidence in the data."
        )
        numbered = "\n".join(f"{i}: {t}" for i, t in enumerate(obj_texts))
        prompt = (
            f"OBJECTIVES:\n{numbered}\n\n"
            f"EVIDENCE GATHERED SO FAR:\n{evidence}\n\n"
            'Return JSON: {"objectives":[{"index":0,"status":"complete|partial|not_complete",'
            '"confidence":0.0,"evidence":"why (cite the evidence)","blocker":"what is '
            'still needed / the next step"}]}'
        )
        try:
            spec = await self._master.think_json(prompt, system)
        except Exception:
            spec = {}
        results = spec.get("objectives") if isinstance(spec, dict) else None
        if not isinstance(results, list):
            return {}

        status_map: dict = intel.setdefault("objective_status", {})
        for r in results:
            if not isinstance(r, dict):
                continue
            try:
                idx = int(r.get("index"))
            except Exception:
                continue
            if idx < 0 or idx >= len(objectives):
                continue
            st = str(r.get("status", "not_complete")).lower().strip()
            if st not in ("complete", "partial", "not_complete"):
                st = "not_complete"
            # Never DOWNGRADE an objective already proven complete.
            prev = status_map.get(str(idx))
            if prev and prev.get("status") == "complete" and st != "complete":
                continue
            entry = {
                "objective":  obj_texts[idx],
                "status":     st,
                "confidence": float(r.get("confidence") or 0.0),
                "evidence":   str(r.get("evidence") or "")[:300],
                "blocker":    str(r.get("blocker") or "")[:200],
            }
            status_map[str(idx)] = entry
            try:
                await self._emit({
                    "type":       "objective_status",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       {"index": idx, "total": len(objectives), **entry},
                })
            except Exception:
                pass

        summary = {
            "complete":     sum(1 for v in status_map.values() if v.get("status") == "complete"),
            "partial":      sum(1 for v in status_map.values() if v.get("status") == "partial"),
            "not_complete": sum(1 for v in status_map.values() if v.get("status") == "not_complete"),
            "total":        len(objectives),
        }
        intel["objectives_summary"] = summary
        try:
            await self._emit({
                "type":       "objectives_summary",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       summary,
            })
        except Exception:
            pass
        return summary

    async def answer_single(
        self,
        question_text: str,
        intel:         dict,
        raw_output:    str = "",
    ) -> Question:
        """
        Answer a single ad-hoc question immediately.
        Returns the Question object (check .state, .answer).
        """
        q = self.add_question(question_text)
        if q.state == QuestionState.ANSWERED:
            return q
        # Reset to PENDING so we re-try with latest intel
        q.state = QuestionState.PENDING
        await self._answer_question(q, intel, raw_output)
        self.save_to_intel(intel)
        return q

    async def run_discovery_pass(
        self,
        raw_output: str,
        phase:      str,
        tool:       str,
        intel:      dict,
    ) -> None:
        """
        Mode 2 — Discovery Pass.
        Scan raw tool output for noteworthy facts and surface them as findings.
        Only runs when engagement_type is pentest / red_team / bug_bounty.
        Skipped entirely in CTF / forensics / compliance / network_analysis mode.
        """
        eng_type = (intel.get("engagement_context") or {}).get("engagement_type", "")
        if eng_type not in _DISCOVERY_MODES:
            return

        findings = self._extractor.discover(raw_output, phase, tool)
        if not findings:
            return

        # Deduplicate across the whole session using intel set
        seen: set = intel.setdefault("_discovery_titles_seen", set())
        if isinstance(seen, list):          # upgrade from list (old checkpoints)
            seen = set(seen)
            intel["_discovery_titles_seen"] = seen

        for f in findings:
            if f.title in seen:
                continue
            seen.add(f.title)
            await self._emit_finding(
                title       = f"[Discovery] {f.title}",
                severity    = f.severity,
                description = f"{f.description}\n\nEvidence: {f.evidence}\nTool: {tool}",
                phase       = phase or "recon",
                tool        = tool,
                tag         = "auto_discovery",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # Core 3-layer pipeline
    # ─────────────────────────────────────────────────────────────────────────

    async def _answer_question(
        self,
        q:          Question,
        intel:      dict,
        raw_output: str,
    ) -> None:
        """Run Layers 1 → 2 → 3 until the question is answered or exhausted."""
        q.state = QuestionState.SEARCHING

        # ── Layer 1: Deterministic ────────────────────────────────────────────
        result = self._extractor.extract(q.text, intel, raw_output)
        if result.answer:
            await self._accept(q, result.answer, result.evidence, layer=1, intel=intel)
            return

        # ── Layer 2: Improved LLM extraction ─────────────────────────────────
        if raw_output.strip():
            answer, evidence = await self._llm_extract(q.text, raw_output, intel)
            if answer:
                await self._accept(q, answer, evidence, layer=2, intel=intel)
                return

        # ── Layer 3: Targeted tool dispatch ───────────────────────────────────
        tool_name, tool_args = self._pick_tool(q.text)
        if tool_name:
            fresh = await self._dispatch_tool(tool_name, tool_args)
            if fresh:
                # Re-run Layer 1 on fresh output
                r2 = self._extractor.extract(q.text, intel, fresh)
                if r2.answer:
                    await self._accept(q, r2.answer, r2.evidence, layer=3, intel=intel)
                    return
                # Re-run Layer 2 on fresh output
                a2, e2 = await self._llm_extract(q.text, fresh, intel)
                if a2:
                    await self._accept(q, a2, e2, layer=3, intel=intel)
                    return

        # ── All layers exhausted ──────────────────────────────────────────────
        q.state = QuestionState.UNANSWERABLE
        await self._emit_finding(
            title       = f"[Inconclusive] {q.text[:120]}",
            severity    = "info",
            description = (
                "All extraction layers were exhausted without finding an answer.\n"
                "More targeted reconnaissance may be required.\n"
                f"Question: {q.text}"
            ),
            phase = "exploit",
            tool  = "question_engine",
            tag   = "unanswerable",
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 2: Improved LLM extraction
    # ─────────────────────────────────────────────────────────────────────────

    async def _llm_extract(
        self,
        question:   str,
        raw_output: str,
        intel:      dict,
    ) -> Tuple[Optional[str], str]:
        """
        LLM extraction with:
        - Answer-type hint derived from question keywords
        - 1 few-shot example of the expected format
        - Strict JSON schema validation
        - Confidence gating (< 0.5 → rejected)
        - One retry with a simpler prompt if the first response is malformed
        """
        answer_type, few_shot = self._classify_question(question)
        trimmed               = self._prioritise_output(question, raw_output, max_chars=4000)

        system = (
            "You are a security expert extracting a specific answer from tool output.\n"
            f"Expected answer type: {answer_type}\n"
            f"Example of a correct response:\n{few_shot}\n\n"
            "Rules:\n"
            "- Only answer what the data directly supports. Never fabricate.\n"
            "- For counting questions, count the relevant items in the output.\n"
            "- For version questions, extract the exact version string.\n"
            "- For flag questions, copy the flag verbatim.\n"
            "- Set confidence 0.0–1.0 (1.0 = certain, 0.5 = likely, <0.5 = unsure).\n"
            "Respond with JSON ONLY (no markdown fences):\n"
            '{"answer": "the exact answer", '
            '"evidence": "the exact line(s) from the output", '
            '"confidence": 0.95}'
        )
        prompt = (
            f"Question: {question}\n\n"
            f"Tool output:\n{trimmed}\n\n"
            "Extract the answer. "
            'If the answer is not in the output return: {"answer": null, "evidence": "", "confidence": 0.0}'
        )

        for attempt in range(2):
            try:
                raw = await self._master.think_json(prompt, system)
            except Exception:
                return None, ""

            if not isinstance(raw, dict):
                # Retry with a simpler prompt on first attempt
                if attempt == 0:
                    prompt = (
                        f"Answer this question using the text below.\n"
                        f"Question: {question}\n"
                        f"Text: {trimmed[:2000]}\n"
                        'Return JSON: {"answer": "value or null", "evidence": "line", "confidence": 0.0}'
                    )
                    continue
                return None, ""

            answer     = (raw.get("answer") or "")
            evidence   = (raw.get("evidence") or "").strip()
            confidence = float(raw.get("confidence") or 0.0)

            # Reject null / empty / low-confidence answers
            if not answer or str(answer).lower() in ("null", "none", "n/a", "unknown"):
                return None, ""
            if confidence < 0.5:
                return None, ""

            return str(answer).strip(), evidence

        return None, ""

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 2 helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _classify_question(question: str) -> Tuple[str, str]:
        """Return (answer_type_description, one_shot_example_json)."""
        q = question.lower()
        if any(k in q for k in ["how many", "count", "number of"]):
            return (
                "an integer (e.g. '3')",
                '{"answer": "3", "evidence": "22/tcp open  ssh\\n80/tcp open  http\\n443/tcp open  https", "confidence": 1.0}',
            )
        if any(k in q for k in ["flag{", "flag", "ctf", "user.txt", "root.txt"]):
            return (
                "a CTF flag string (e.g. 'flag{abc123}')",
                '{"answer": "flag{s0m3_v4lu3}", "evidence": "$ cat user.txt\\nflag{s0m3_v4lu3}", "confidence": 1.0}',
            )
        if any(k in q for k in ["version", "running", "server", "service"]):
            return (
                "a software name + version string (e.g. 'Apache 2.4.49')",
                '{"answer": "Apache 2.4.49", "evidence": "Server: Apache/2.4.49 (Ubuntu)", "confidence": 0.95}',
            )
        if any(k in q for k in ["ip", "address", "hostname"]):
            return (
                "an IP address or hostname",
                '{"answer": "10.10.10.5", "evidence": "Nmap scan report for 10.10.10.5", "confidence": 1.0}',
            )
        if any(k in q for k in ["password", "credential", "username", "user"]):
            return (
                "a credential (username, password, or user:pass pair)",
                '{"answer": "admin:letmein", "evidence": "[+] Valid credentials: admin:letmein", "confidence": 0.95}',
            )
        if any(k in q for k in ["operating system", "os ", " os"]):
            return (
                "an OS name and version (e.g. 'Ubuntu 20.04')",
                '{"answer": "Ubuntu 20.04.3 LTS", "evidence": "OS details: Ubuntu 20.04", "confidence": 0.9}',
            )
        return (
            "the most specific exact value that answers the question",
            '{"answer": "the exact value", "evidence": "the relevant line(s)", "confidence": 0.8}',
        )

    @staticmethod
    def _prioritise_output(question: str, output: str, max_chars: int = 4000) -> str:
        """
        Trim output to max_chars, putting the most question-relevant lines first.
        """
        if len(output) <= max_chars:
            return output

        stop = {"the", "a", "an", "is", "are", "what", "which", "how",
                "many", "of", "on", "in", "for", "to", "be", "do"}
        keywords = [w for w in question.lower().split() if len(w) > 3 and w not in stop]

        lines        = output.splitlines()
        scored_lines = []
        for line in lines:
            ll = line.lower()
            score = sum(1 for kw in keywords if kw in ll)
            scored_lines.append((score, line))

        scored_lines.sort(key=lambda x: x[0], reverse=True)
        result = "\n".join(ln for _, ln in scored_lines)
        return result[:max_chars]

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 3 helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _pick_tool(self, question: str) -> Tuple[Optional[str], str]:
        """Return (tool_name, args) for the question, or (None, '') if no match."""
        q = question.lower()
        for keywords, tool, args_tpl in _LAYER3_TOOL_MAP:
            if any(kw in q for kw in keywords):
                args = args_tpl.replace("{target}", self._target)
                return tool, args
        return None, ""

    async def _dispatch_tool(self, tool: str, args: str) -> str:
        """Dispatch a tool via MasterAgent and return stdout (empty on error)."""
        try:
            result = await self._master._dispatch_to_agent(
                tool    = tool,
                args    = args,
                purpose = "Layer 3: targeted question-answer dispatch",
                phase   = "question_engine",
            )
            return (result or {}).get("stdout", "")
        except Exception:
            return ""

    # ─────────────────────────────────────────────────────────────────────────
    # Accept answer & emit
    # ─────────────────────────────────────────────────────────────────────────

    async def _accept(
        self,
        q:        Question,
        answer:   str,
        evidence: str,
        layer:    int,
        intel:    dict,
    ) -> None:
        """Mark question answered, emit finding + WebSocket events."""
        q.state      = QuestionState.ANSWERED
        q.answer     = answer
        q.evidence   = evidence
        q.layer_used = layer

        layer_label = {1: "Deterministic", 2: "LLM", 3: "Tool Dispatch"}.get(layer, str(layer))

        # Title varies by mode
        if q.objective_idx is not None:
            title = f"[Q{q.objective_idx + 1}] {q.text[:100]}"
        else:
            title = f"[Answer] {q.text[:100]}"

        finding_id   = str(uuid.uuid4())
        q.finding_id = finding_id

        await self._emit_finding(
            title       = title,
            severity    = "high",
            description = (
                f"**Answer:** {answer}\n\n"
                f"**Evidence:** {evidence}\n\n"
                f"**Extracted by:** Layer {layer} ({layer_label})"
            ),
            phase      = "exploit",
            tool       = "question_engine",
            tag        = "question_answered",
            finding_id = finding_id,
        )

        # ── question_answered WS event (drives Ask bar + any UI panel) ────────
        try:
            await self._emit({
                "type":       "question_answered",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "question_id":   q.id,
                    "question":      q.text,
                    "answer":        answer,
                    "evidence":      evidence,
                    "layer":         layer,
                    "layer_label":   layer_label,
                    "finding_id":    finding_id,
                    "objective_idx": q.objective_idx,
                },
            })
        except Exception:
            pass

        # ── ctf_answer WS event for objective-mode questions ──────────────────
        if q.objective_idx is not None:
            await self._emit_ctf_answer(q, answer, evidence, layer, intel)

    async def _emit_ctf_answer(
        self,
        q:        Question,
        answer:   str,
        evidence: str,
        layer:    int,
        intel:    dict,
    ) -> None:
        """Emit ctf_answer event and update intel["ctf_answers"]."""
        objectives = (
            (intel.get("engagement_context") or {}).get("objectives")
            or intel.get("ctf_objectives")
            or []
        )
        obj      = objectives[q.objective_idx] if q.objective_idx < len(objectives) else {}
        q_text   = (obj.get("task") or obj.get("question") or q.text) if isinstance(obj, dict) else q.text
        section  = obj.get("section", "") if isinstance(obj, dict) else ""

        ctf_answers = intel.setdefault("ctf_answers", {})
        ctf_answers[str(q.objective_idx)] = {
            "answer":   answer,
            "evidence": evidence,
            "tool":     "question_engine",
            "layer":    layer,
        }

        try:
            await self._emit({
                "type":       "ctf_answer",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "objective_index": q.objective_idx,
                    "objective":       q_text,
                    "section":         section,
                    "answer":          answer,
                    "evidence":        evidence,
                    "tool":            "question_engine",
                    "layer":           layer,
                    "total":           len(objectives),
                    "answered_count":  len(ctf_answers),
                },
            })
        except Exception:
            pass

        # Plan step
        try:
            await self._emit({
                "type":       "plan_step_update",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "step_id":     f"ctf_{q.objective_idx}",
                    "label":       f"🏁 [Q{q.objective_idx + 1}] {q_text[:60]}",
                    "status":      "done",
                    "result":      answer,
                    "phase":       "exploit",
                    "probability": 1.0,
                    "found":       True,
                    "ts":          datetime.utcnow().isoformat(),
                },
            })
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Emit helpers
    # ─────────────────────────────────────────────────────────────────────────

    async def _emit_finding(
        self,
        title:       str,
        severity:    str,
        description: str,
        phase:       str = "exploit",
        tool:        str = "question_engine",
        tag:         str = "",
        finding_id:  str = None,
    ) -> None:
        fid = finding_id or str(uuid.uuid4())
        try:
            await self._emit({
                "type":       "finding",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "finding": {
                        "id":          fid,
                        "title":       title[:200],
                        "severity":    severity,
                        "description": description[:1000],
                        "phase":       phase,
                        "tool":        tool,
                        "host":        self._target,
                        "port":        None,
                        "service":     "question_engine",
                        "cves":        [],
                        "mitre":       "",
                        "tag":         tag,
                        "timestamp":   datetime.utcnow().isoformat(),
                    }
                },
            })
            # Persist to DB
            try:
                import db.mongo_client as _dbm
                await _dbm.store_finding(
                    session_id  = self._session_id,
                    host        = self._target,
                    title       = title[:200],
                    severity    = severity,
                    description = description[:1000],
                    tool        = tool,
                    phase       = phase,
                )
            except Exception:
                pass
        except Exception:
            pass
