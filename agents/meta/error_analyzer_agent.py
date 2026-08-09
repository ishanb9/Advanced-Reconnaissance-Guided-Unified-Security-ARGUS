"""
error_analyzer_agent.py — LLM-driven error triage and course-correction.

PROBLEM IT SOLVES
=================
In every failed engagement we observed, 60-80% of tool calls produced
errors yet the platform kept blindly re-trying.  Examples from real logs:

  • 1,292 curl calls against port 80 — but the actual web app is on 8080
    (exit 28 timeouts every time, no course correction)
  • `enum4linux-ng` + `kerbrute` against a *Linux* target (Overpass 3)
    — runs anyway because the agent doesn't know the target is not AD
  • `dalfox` repeatedly fails with "Tool not found: 'dalfox'.  Install:
    apt install dalfox -y" — 56 retries in a single scan
  • `nikto -maxtime 300` hits its internal timeout 30+ times — same
    response, no adaptation

A real pentester sees an error like "ERROR Opening: http://10.x.x.x - no
address for X.htb" and immediately understands: "/etc/hosts entry missing
— add it OR drop the vhost".  The LLM is perfectly capable of this kind
of reasoning, but only if it is asked.  That's what this agent does.

ARCHITECTURE
============
Long-running background task subscribed to ``tool_error`` /
``subagent_tool_exit`` events.  For each error:

  1. Build an error signature: (tool, stderr_first_line, return_code)
  2. Drop duplicates seen recently (don't spam the LLM)
  3. Ask the LLM to classify + recommend course correction
  4. Pin the recommendation as a critical insight on the
     EngagementContext so the master + every other LLM call sees it
  5. If the recommendation includes blocking a specific tool/target,
     trip the EngagementContext circuit breaker

Classifications produced:

  • transient      — retry once
  • wrong_target   — tool was aimed at wrong host/port
                     (e.g. curl to port 80 when service is on 8080)
  • tool_missing   — binary not installed; remove from arsenal
  • bad_args       — args malformed; re-craft
  • unsupported    — protocol/feature not applicable to this target
                     (e.g. enum4linux on Linux, AD scripts on web app)
  • dead_endpoint  — endpoint doesn't exist; mark dead
  • other          — generic; surface as advisory only

SCOPE IS NOT THIS AGENT'S JOB.  It could previously answer `scope_drift`, which is
a category error: this agent sees one tool's stderr, never the engagement's
authorization.  In the field it read ANOTHER CLIENT's addresses out of recalled
memory, concluded the actual client was out of scope, and advised stopping the
scan and going after the other client's subnet instead.  A tool failure cannot
establish what is in scope.  Scope is fixed before launch at the target-selection
gate and enforced by the safety governor + per-target authorization; this agent
classifies TECHNICAL failure only.

Course corrections produced:

  • Specific replacement command
  • Skip this entire tool for the remainder of the engagement
  • Update intel field (e.g. correct port, vhost)
  • Block circuit breaker permanently for (tool, target)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from agents.meta.base_meta_agent import BaseMetaAgent
from agents.meta.correction import Correction
from db.schemas import AgentName

logger = logging.getLogger(__name__)


# How many seconds before the same error signature is re-classified.
# Within this window we mark it as duplicate and skip the LLM call.
DEDUP_WINDOW_SEC: float = float(
    os.environ.get("ARGUS_ERROR_DEDUP_WINDOW", "180")
)

# Maximum LLM calls per engagement (so a flood of errors doesn't burn
# the token budget on the same advice).
MAX_CLASSIFICATIONS_PER_ENGAGEMENT: int = int(
    os.environ.get("ARGUS_ERROR_MAX_CLASSIFICATIONS", "40")
)

# F7 — coarse throttle: once the SAME (tool, classification) advice has been
# emitted, suppress it for this long.  Stops the "retry with a longer timeout"
# storm (the old 180 s same-signature window let identical advice re-fire ~12×).
ADVICE_DEDUP_SEC: float = float(
    os.environ.get("ARGUS_ERROR_ADVICE_DEDUP_SEC", "600")
)

# Core executors / shells must NEVER be classified "tool_missing" + hard-blocked
# — a single `bash` exit 1 (e.g. an awk subcommand emitting "No such file or
# directory") previously force-blocked bash for the whole engagement.
_CORE_EXECUTORS: frozenset = frozenset({
    "bash", "sh", "zsh", "dash", "cat", "echo", "env", "timeout", "sudo", "true",
})


# Error signatures we always treat as transient with no LLM call.
# (saves token budget on noise that doesn't need reasoning)
_TRANSIENT_ERROR_PATTERNS: Tuple[str, ...] = (
    "temporary failure in name resolution",
    "could not resolve host",
    "connection reset by peer",
    "ssl_error_syscall",
    "interrupted system call",
)

# Error signatures that immediately tell us the tool is unusable
# regardless of target/args.  No need to consult the LLM.
_TOOL_MISSING_PATTERNS: Tuple[str, ...] = (
    "tool not found",
    "command not found",
    "no such file or directory",
    "cannot execute binary file",
    "is not installed",
    "apt install",
    "permission denied: not allowed",
)


@dataclass
class ErrorEvent:
    """Normalised view of an error from any source."""
    tool:      str
    args:      str
    target:    str
    exit_code: int
    stderr:    str
    phase:     str
    ts:        float = field(default_factory=time.time)

    def signature(self) -> str:
        """Stable hash for dedup."""
        first = (self.stderr or "").splitlines()[:1]
        key   = f"{self.tool}|{self.exit_code}|{(first or [''])[0][:200]}"
        return hashlib.sha256(key.encode("utf-8", errors="ignore")
                              ).hexdigest()[:24]


class ErrorAnalyzerAgent(BaseMetaAgent):
    """
    Subscribes to tool-error events.  Classifies each unique error via
    the LLM and pins course-correct guidance on the EngagementContext.

    Lives as a background asyncio task spawned at engagement start.
    """

    def __init__(self, broadcast=None, session_id: Optional[str] = None,
                 db_conn=None, enabled: bool = True):
        super().__init__(
            name       = AgentName.MASTER,   # uses Master's LLM thread
            broadcast  = broadcast,
            session_id = session_id,
            db_conn    = db_conn,
            enabled    = enabled,
        )
        # Dedup memory: signature → (last_seen_ts, classification)
        self._seen: Dict[str, Tuple[float, str]] = {}
        # F7 — coarse (tool|classification) → last-emitted-ts throttle
        self._advice_seen: Dict[str, float] = {}
        self._classifications_done: int = 0
        # Async queue of incoming ErrorEvents
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._stop_requested: bool = False
        # Running tally for the GUI summary panel
        self._stats = {"total": 0, "blocking": 0, "advisory": 0,
                        "tool_missing": 0, "wrong_target": 0,
                        "transient": 0, "other": 0}

    @property
    def _agent_name_str(self) -> str:
        """Override so all meta_agent_status / meta_agent_thinking /
        meta_correction events are tagged 'error_analyzer' — this is
        what the GUI store routes on.  Without this override the agent
        would emit as 'master' (the value of AgentName.MASTER) and its
        events would pollute the Issue-Validator panel."""
        return "error_analyzer"

    # ── BaseMetaAgent contract ──────────────────────────────────

    def _build_system_prompt(self) -> str:
        return (
            "You are the ARGUS Error Triage Specialist — an offensive-"
            "security expert focused on rapid error diagnosis.  A "
            "penetration testing platform has just observed a tool "
            "failure during an active engagement.  Your job is to "
            "classify the error and recommend a SPECIFIC, ACTIONABLE "
            "course correction so the engagement can move forward "
            "instead of looping on the same dead end.\n\n"
            "SCOPE IS OUT OF YOUR REMIT.  You are looking at ONE tool failure. "
            "You cannot see the engagement's authorization and must not infer it. "
            "Never decide, state or imply that the target is out of scope, "
            "unauthorized, or the wrong client; never recommend stopping the "
            "engagement; and never name a different host, IP or network to scan "
            "instead of the current target.  Addresses appearing in memory or "
            "prior-engagement context belong to OTHER engagements and are never "
            "alternatives you may propose.  If a failure looks like a scope or "
            "authorization problem, classify it \"other\" and describe the "
            "technical symptom only — the human operator owns scope.\n\n"
            "CRITICAL VHOST RULE: a redirect or Host-header reference to an "
            "internal-looking hostname (*.htb, *.local, *.lan, *.corp, "
            "*.internal, *.thm) is NOT scope_drift — that hostname is a "
            "VIRTUAL HOST of the CURRENT target and IS in scope.  The fix is "
            "to (re)map it to the current target IP in /etc/hosts and re-run "
            "the tool with that vhost (curl --resolve / -H 'Host: <vhost>' or "
            "an /etc/hosts entry), NOT to delete it.  NEVER recommend "
            "`sed -i .../etc/hosts` deletions, `> /etc/hosts`, or purging a "
            "vhost entry — doing so destroys the only path to the web app. "
            "If the vhost currently resolves to a stale/old IP, recommend "
            "REPLACING that mapping with the current target IP.\n\n"
            "Respond ONLY with strict JSON, no markdown fences, no "
            "commentary outside the JSON object.  Required shape:\n"
            "{\n"
            "  \"classification\": one of "
            "\"transient\" | \"wrong_target\" | \"tool_missing\" | "
            "\"bad_args\" | \"unsupported\" | "
            "\"dead_endpoint\" | \"other\",\n"
            "  \"confidence\": 0.0-1.0,\n"
            "  \"reasoning\": one short sentence,\n"
            "  \"course_correction\": one short sentence describing the "
            "FIX — be specific, actionable, name the next concrete tool "
            "or command,\n"
            "  \"block_tool\": true|false (true means stop using this "
            "tool entirely for this engagement),\n"
            "  \"block_target\": true|false (true means stop hitting "
            "this specific target/URL with any tool),\n"
            "  \"replacement_command\": optional string — a concrete "
            "shell command that should be tried instead (or empty)\n"
            "}"
        )

    async def evaluate(self, **kwargs) -> List[Correction]:    # noqa: ARG002
        """BaseMetaAgent contract — not used; we react to queue events."""
        return []

    # ── Public ingest API ────────────────────────────────────────

    def ingest_error(self, *, tool: str, args: str, target: str,
                       exit_code: int, stderr: str, phase: str) -> None:
        """Non-blocking — drop into queue.  Safe to call from any code path."""
        if not self._enabled:
            return
        # F3 — operator cancellations are NOT errors.  Exit -2 / "stopped by
        # operator" means the human killed the tool on purpose; analysing it
        # (and telling MASTER to "retry") actively fights the cancel button and
        # was a prime driver of the cancel-then-refire loop.  Drop it.
        _slc = (stderr or "").lower()
        if exit_code == -2 or "stopped by operator" in _slc or "[cancelled]" in _slc:
            return
        try:
            evt = ErrorEvent(
                tool      = (tool or "").strip(),
                args      = (args or "")[:600],
                target    = (target or "")[:200],
                exit_code = int(exit_code) if exit_code is not None else -1,
                stderr    = (stderr or "")[:2000],
                phase     = (phase or "")[:60],
            )
            self._queue.put_nowait(evt)
        except asyncio.QueueFull:
            # Best-effort: drop oldest, keep newest
            try:
                _ = self._queue.get_nowait()
                self._queue.task_done()
                self._queue.put_nowait(evt)
            except Exception:
                pass
        except Exception as exc:
            logger.debug("[error_analyzer] ingest failed: %s", exc)

    def request_stop(self) -> None:
        self._stop_requested = True

    # ── Background loop ──────────────────────────────────────────

    async def run(self) -> None:
        """Main loop.  Spawned as asyncio.create_task at engagement start."""
        if not self._enabled:
            return
        logger.info("[error_analyzer] started for session %s",
                     self._session_id)
        while not self._stop_requested:
            try:
                evt = await asyncio.wait_for(self._queue.get(), timeout=10.0)
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.debug("[error_analyzer] dequeue error: %s", exc)
                continue
            try:
                await self._handle(evt)
            except Exception as exc:                              # noqa: BLE001
                logger.warning("[error_analyzer] handler error: %s", exc)
            finally:
                self._queue.task_done()
        logger.info("[error_analyzer] stopped for session %s",
                     self._session_id)

    async def _handle(self, evt: ErrorEvent) -> None:
        sig = evt.signature()
        now = evt.ts
        # Dedup inside window
        prior = self._seen.get(sig)
        if prior and (now - prior[0]) < DEDUP_WINDOW_SEC:
            return
        stderr_lc = evt.stderr.lower()

        # F7 — once the host is flagged unreachable, the liveness breaker owns
        # the situation.  Stop emitting per-tool "retry with a longer timeout"
        # advice: it can't help a dead host and floods the prompt window (this
        # was the ~12× repeated-advice storm against the black-holed target).
        try:
            from agents.reasoning.tool_blacklist import get_blacklist as _gb
            if _gb().host_unreachable(evt.target) and (
                evt.exit_code in (28, 124, -1)
                or any(k in stderr_lc for k in (
                    "timeout", "timed out", "readtimeout",
                    "appears to be down", "max retries", "execution expired"))
            ):
                return
        except Exception:
            pass

        _tool0 = (evt.tool or "").strip().lower().split()[0] if evt.tool else ""

        # Fast-path: a tool is genuinely MISSING only on a REAL not-found signal
        # (exit 127 / "command not found" / MCP "Tool not found: 'x'" / explicit
        # install hint), AND it is not a core executor.  F6: a bare "no such file
        # or directory" from a bash subcommand is NOT a missing tool — that false
        # positive previously force-blocked `bash` (the universal executor) for
        # the whole engagement at confidence 0.99.
        _real_missing = (
            evt.exit_code == 127
            or "command not found" in stderr_lc
            or "tool not found" in stderr_lc
            or "cannot execute binary file" in stderr_lc
            or "is not installed" in stderr_lc
            or (bool(_tool0) and f"apt install {_tool0}" in stderr_lc)
        )
        if _real_missing and _tool0 not in _CORE_EXECUTORS:
            await self._apply_classification(
                evt, sig,
                classification    = "tool_missing",
                confidence        = 0.99,
                reasoning         = "Tool binary missing / not installed.",
                course_correction = (
                    f"Stop using '{evt.tool}' for this engagement; "
                    "operator should install it or the LLM should pick a "
                    "different tool."
                ),
                block_tool        = True,
                block_target      = False,
                replacement_cmd   = "",
            )
            return
        if any(p in stderr_lc for p in _TRANSIENT_ERROR_PATTERNS):
            await self._apply_classification(
                evt, sig,
                classification    = "transient",
                confidence        = 0.7,
                reasoning         = "Transient network/system error.",
                course_correction = "Retry once; do NOT loop.",
                block_tool        = False,
                block_target      = False,
                replacement_cmd   = "",
            )
            return

        # LLM path — but budget-bounded
        if self._classifications_done >= MAX_CLASSIFICATIONS_PER_ENGAGEMENT:
            return

        prompt = self._build_classification_prompt(evt)
        try:
            response = await self.think_with_history(prompt)
        except Exception as exc:                                # noqa: BLE001
            logger.warning("[error_analyzer] LLM call failed: %s", exc)
            return
        self._classifications_done += 1

        parsed = self._parse_json(response)
        if not parsed:
            return
        # Defence in depth: the prompt forbids scope verdicts, but the answer is
        # model output and must not be trusted to obey.  Anything scope-shaped is
        # demoted to a plain technical advisory, and foreign addresses are stripped
        # from the advice before it can be pinned into every later prompt.
        _cls = self._sanitize_classification(parsed.get("classification", "other"))
        _cc  = self._strip_foreign_targets(evt, parsed.get("course_correction", "")[:400])
        await self._apply_classification(
            evt, sig,
            classification    = _cls,
            confidence        = float(parsed.get("confidence", 0.5) or 0.5),
            reasoning         = parsed.get("reasoning", "")[:300],
            course_correction = _cc,
            block_tool        = bool(parsed.get("block_tool", False)),
            block_target      = bool(parsed.get("block_target", False)),
            replacement_cmd   = (parsed.get("replacement_command") or "")[:400],
        )

    # ── Guards: this agent never decides scope, and never names another
    #    engagement's addresses ─────────────────────────────────────────────

    #: Everything this agent is allowed to conclude.  Purely technical.
    ALLOWED_CLASSIFICATIONS = ("transient", "wrong_target", "tool_missing",
                               "bad_args", "unsupported", "dead_endpoint", "other")

    @classmethod
    def _sanitize_classification(cls, raw: str) -> str:
        """Coerce anything outside the technical taxonomy to 'other'.

        `scope_drift` used to be a valid answer.  A tool's stderr cannot establish
        authorization, and when recalled memory put another client's subnet in the
        context the model duly concluded the REAL client was out of scope.  Scope
        belongs to the pre-launch gate and the governor; a stray verdict here is
        demoted rather than obeyed.
        """
        v = str(raw or "").strip().lower()
        return v if v in cls.ALLOWED_CLASSIFICATIONS else "other"

    @staticmethod
    def _strip_foreign_targets(evt: "ErrorEvent", text: str) -> str:
        """Remove IPs/CIDRs that are not part of THIS engagement.

        The course correction is pinned into every subsequent LLM prompt, so an
        address that leaks in here becomes a standing instruction.  In the field
        that produced "stop scanning <client A> ... resume against 192.168.50.0/24"
        — another client's lab range, recalled from memory.  Only addresses tied to
        the failing event survive; anything else is replaced with a neutral marker
        so the technical advice still reads sensibly.
        """
        import re as _re
        if not text:
            return text
        _own = {str(getattr(evt, "target", "") or "").strip()}
        _own.discard("")
        _ipish = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

        def _keep(m):
            tok = m.group(0)
            bare = tok.split("/")[0]
            if any(bare == o or o.startswith(bare) or bare in o for o in _own):
                return tok
            return "[out-of-engagement address removed]"

        return _ipish.sub(_keep, text)

    # ── Apply the classification to the EngagementContext ──────

    async def _apply_classification(self, evt: ErrorEvent, sig: str,
                                       *, classification: str,
                                       confidence: float,
                                       reasoning: str,
                                       course_correction: str,
                                       block_tool: bool,
                                       block_target: bool,
                                       replacement_cmd: str) -> None:
        """Pin the result onto the EngagementContext + emit event."""
        self._seen[sig] = (evt.ts, classification)

        # F7 — coarse (tool|classification) throttle: if we already emitted this
        # exact advice for this tool recently, skip it.  Stops the same guidance
        # (e.g. "retry with a longer timeout") from re-pinning every few minutes
        # and evicting useful insights from the prompt window.
        _akey = f"{(evt.tool or '').lower()}|{classification}"
        if (evt.ts - self._advice_seen.get(_akey, 0.0)) < ADVICE_DEDUP_SEC:
            return
        self._advice_seen[_akey] = evt.ts

        try:
            from agents.engagement_context import get_context
            ctx = (get_context(self._session_id)
                     if self._session_id else None)
        except Exception:
            ctx = None

        # ── C8 arbitration: don't fight forward progress ──────────────────
        # Once recon has mapped the attack surface, a "wrong_target / dead
        # endpoint → run a full TCP nmap scan" correction directly contradicts
        # the Expert's push to exploit and historically looped the planner on
        # redundant re-scans.  When ports are already known, downgrade such
        # advice and strip any "full scan" replacement so it can't re-queue one.
        try:
            _ports_known = bool(ctx and ctx.intel.get("open_ports"))
        except Exception:
            _ports_known = False
        if _ports_known and classification in ("wrong_target", "dead_endpoint"):
            _cc = (course_correction or "").lower()
            if any(k in _cc for k in (
                "full tcp", "full nmap", "full port", "port scan", "nmap scan",
                "re-scan", "rescan", "discover the actual", "actual web port",
                "actual listening",
            )):
                classification    = "other"   # no longer a critical re-scan signal
                course_correction = (
                    "Attack surface is already mapped (ports known) — do NOT "
                    "re-scan.  Pivot to the discovered service / vhost and "
                    "exploit it."
                )
                replacement_cmd = ""           # don't re-queue a scan
                block_tool      = False
                block_target    = False

        # Pin the course correction so every subsequent LLM prompt sees it
        if ctx is not None:
            try:
                severity = ("critical" if classification in (
                    "tool_missing", "unsupported", "wrong_target"
                ) else "important")
                ctx.pin_insight(
                    text=(
                        f"ERROR-ANALYZER: {evt.tool!r} produced an error "
                        f"({classification}, conf={confidence:.2f}).  "
                        f"Reason: {reasoning[:160]}.  "
                        f"COURSE CORRECTION: {course_correction[:240]}"
                        + (f" — REPLACEMENT: {replacement_cmd[:160]}"
                           if replacement_cmd else "")
                    ),
                    phase=evt.phase or "all",
                    severity=severity,
                    source="error_analyzer",
                )
                # Hard-block the tool / target in the engagement context
                if block_tool:
                    ctx.force_block(evt.tool, evt.target or evt.args,
                                       duration_sec=86400.0)   # rest of engagement
                if block_target and (evt.target or evt.args):
                    ctx.force_block(evt.tool, evt.target or evt.args,
                                       duration_sec=86400.0)
                # Replacement command — queue it on next_commands so the
                # first-strike loop / entry-attempt dispatcher picks it up.
                if replacement_cmd and replacement_cmd.strip():
                    cmds = list(ctx.intel.get("next_commands") or [])
                    if replacement_cmd not in cmds:
                        cmds.insert(0, replacement_cmd)
                        ctx.intel["next_commands"] = cmds
                        ctx.detect_entry_points()
            except Exception as exc:                            # noqa: BLE001
                logger.debug("[error_analyzer] context update failed: %s", exc)

        # ── Update GUI stats ────────────────────────────────────────
        is_blocking = bool(block_tool or block_target) or confidence >= 0.8
        self._stats["total"]   += 1
        self._stats["blocking"] += 1 if is_blocking else 0
        self._stats["advisory"] += 0 if is_blocking else 1
        if classification in self._stats:
            self._stats[classification] += 1

        # ── Emit a meta_correction so the Error-Analyzer GUI panel's
        # Corrections tab populates (reuses the existing meta-agent
        # store infrastructure).  source="error_analyzer" routes it to
        # the dedicated panel.
        try:
            from agents.meta.correction import Correction
            corr = Correction(
                source             = "error_analyzer",
                scan_id            = self._session_id or "",
                phase              = evt.phase or "",
                confidence         = float(confidence),
                issue_type         = "tool_failure_unhandled",
                description        = (
                    f"{evt.tool} ({classification}): {reasoning[:200]}"
                ),
                recommended_action = (
                    course_correction[:300]
                    + (f"  REPLACEMENT: {replacement_cmd[:160]}"
                       if replacement_cmd else "")
                ),
                affected_finding_ids = [],
            )
            await self.emit_correction(corr)
        except Exception as exc:                                # noqa: BLE001
            logger.debug("[error_analyzer] emit_correction failed: %s", exc)

        # WS event so the dedicated feed + live error stream also show it
        try:
            await self._emit("error_analysis", {
                "agent":             "error_analyzer",
                "tool":              evt.tool,
                "exit_code":         evt.exit_code,
                "classification":    classification,
                "confidence":        confidence,
                "reasoning":         reasoning,
                "course_correction": course_correction,
                "replacement_cmd":   replacement_cmd,
                "block_tool":        block_tool,
                "block_target":      block_target,
                "phase":             evt.phase,
                "signature":         sig,
                "stats":             dict(self._stats),
            })
        except Exception:
            pass

        logger.info(
            "[error_analyzer] %s/%s → %s (conf %.2f): %s",
            evt.tool, evt.exit_code, classification, confidence,
            course_correction[:120],
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _build_classification_prompt(self, evt: ErrorEvent) -> str:
        return (
            "A tool failed during an active penetration test.  Classify "
            "the error and recommend a SPECIFIC course correction.\n\n"
            f"Tool:          {evt.tool}\n"
            f"Arguments:     {evt.args[:300]}\n"
            f"Target:        {evt.target}\n"
            f"Phase:         {evt.phase}\n"
            f"Exit code:     {evt.exit_code}\n"
            f"Stderr (head): {evt.stderr[:600]}\n"
            "\nRespond with the strict JSON shape described in your "
            "system prompt.  Be specific about the next action — name "
            "the concrete tool, command, or intel update required."
        )

    @staticmethod
    def _parse_json(raw: str) -> Optional[Dict[str, Any]]:
        if not raw:
            return None
        # Direct
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
        # Inside code fence
        m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', raw)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        # Greedy brace match
        m = re.search(r'(\{[\s\S]*\})', raw)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        return None


# ── Per-session registry ─────────────────────────────────────────
# BaseSubagent.collect_tool needs to surface errors to the analyzer
# without changing constructor signatures.  This module-level dict
# lets the master register its analyzer at engagement start; the
# subagents look it up by session_id.

_GLOBAL_REGISTRY: Dict[str, "ErrorAnalyzerAgent"] = {}


def register_analyzer(analyzer: "ErrorAnalyzerAgent") -> None:
    if analyzer is None or not getattr(analyzer, "_session_id", None):
        return
    _GLOBAL_REGISTRY[analyzer._session_id] = analyzer


def get_analyzer(session_id: str) -> Optional["ErrorAnalyzerAgent"]:
    return _GLOBAL_REGISTRY.get(session_id)


def unregister_analyzer(session_id: str) -> None:
    _GLOBAL_REGISTRY.pop(session_id, None)


__all__ = [
    "ErrorAnalyzerAgent", "ErrorEvent",
    "register_analyzer", "get_analyzer", "unregister_analyzer",
    "_GLOBAL_REGISTRY",
]
