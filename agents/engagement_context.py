"""
agents/engagement_context.py — the unified working memory for ARGUS.

Why this exists
===============
The old architecture had ``self._intel`` (a dict on MasterAgent) as the
only carrier of cross-phase state.  In practice it was:

  * Phase-shaped (services, open_ports, cves) but lacking reasoning
    structure (what did the LLM just conclude?  what's the objective?
    what have we tried that failed?).
  * Not propagated into every LLM prompt — each phase planner built its
    own ad-hoc prompt and re-derived context, producing the "intel
    snapshot is empty" syndrome at 1h35m even after OSINT had already
    identified the kill chain.
  * Not tied to tool-execution outcomes — so the same curl could be
    re-fired 486 times against the same dead URL without any record
    saying "we tried this, it didn't pan out."

EngagementContext fixes those three problems by being:

  1. **The objective** (what is the goal of this engagement — carried in
     EVERY LLM prompt as the north star).
  2. **A real reasoning transcript** (action → observation → reasoning
     triples, compressed and budget-bounded for prompt inclusion).
  3. **Pinned insights** (the LLM's high-value conclusions that survive
     across phases — like "MinIO CVE-2023-28432 is the kill chain").
  4. **Failed-action memory** (don't repeat — both at the LLM-planning
     level and the tool-dispatch level).
  5. **Tool usage stats** (every tool call counted; per-tool circuit
     breakers tripped when unproductive cycles emerge).
  6. **Output-signature dedup** (5 identical 404 pages from curl =
     stop hitting that endpoint family).
  7. **Findings store** (confirmed findings with evidence).

It is backed by ``self._intel`` for backward compatibility, so existing
code paths that read ``self._intel["services"]`` still work — but new
code paths read structured fields from EngagementContext directly and
get richer information.

Design principle
================
The LLM is the most expensive component of an engagement.  Every prompt
should give it MAXIMUM signal: the objective, what we know, what we've
tried, what failed, and the recent observations.  EngagementContext's
``render_for_prompt()`` method is the canonical prompt-prelude builder.
"""
from __future__ import annotations

import hashlib
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────
#  Action / observation / insight record types
# ─────────────────────────────────────────────────────────────────────


@dataclass
class ReactStep:
    """One iteration of the reason-act loop.

    The reasoning + observation pair is what makes the next LLM call
    actually intelligent — it sees what just happened, not just a
    summary derived from intel.
    """
    ts:          float
    phase:       str
    tool:        str
    args:        str
    reasoning:   str
    observation: str         # truncated tool output / outcome summary
    productive:  bool        # did this produce findings or useful intel?
    finding_ids: List[str] = field(default_factory=list)

    def render(self, max_chars: int = 220) -> str:
        """One-line representation for prompt inclusion."""
        out_excerpt = self.observation.replace("\n", " ")[:max_chars]
        flag = "✓" if self.productive else "∅"
        return (f"  [{flag} {self.phase}] {self.tool} {self.args[:60]}"
                f"  →  {out_excerpt}")


@dataclass
class PinnedInsight:
    """A high-value LLM observation that must survive across phases.

    Examples:
      * "MinIO on 54321 is the critical attack surface (CVE-2023-28432)"
      * "Target uses WordPress 6.2 with plugin XYZ — known RCE"
      * "DC name resolved to FOO.local; AD attack path available via..."
    """
    ts:        float
    phase:     str
    severity:  str           # info | important | critical
    text:      str
    source:    str = ""      # which LLM call / subagent produced it
    consumed_by: List[str] = field(default_factory=list)   # which phases
                                                            # have used it


@dataclass
class ToolStats:
    """Per-(tool, target_sig) circuit-breaker accounting."""
    invocations:        int   = 0
    productive:         int   = 0
    consecutive_empty:  int   = 0
    consecutive_dup:    int   = 0
    last_invoked_at:    float = 0.0
    last_productive_at: float = 0.0
    blocked_until:      float = 0.0
    output_signatures:  Set[str] = field(default_factory=set)


# ─────────────────────────────────────────────────────────────────────
#  Tunables
# ─────────────────────────────────────────────────────────────────────


# Per-tool "unproductive call" thresholds.  When (tool, target) hits the
# threshold, further calls are short-circuited until the next productive
# result or operator override.
CIRCUIT_BREAKER_THRESHOLDS: Dict[str, int] = {
    "curl":          6,    # the 486-call offender on the failed run
    "gobuster":      3,
    "ffuf":          3,
    "wfuzz":         3,
    "dirb":          3,
    "feroxbuster":   3,
    "wafw00f":       2,
    "whatweb":       3,
    "dalfox":        2,
    "commix":        2,
    "davtest":       2,
    "sqlmap":        3,
    "nuclei":        4,
    "nikto":         3,
    "hydra":         2,    # very loud — limit retries
    "patator":       2,
    "crackmapexec":  4,
    # default = 5 (see _threshold_for)
}

# Absolute engagement-wide ceilings per tool.  A tool can run AT MOST
# this many times during a single engagement, regardless of how
# productive each individual call was.  Prevents a "kept finding new
# URLs to fuzz" pattern from spiraling.
PER_TOOL_INVOCATION_CAPS: Dict[str, int] = {
    "curl":          120,
    "gobuster":      20,
    "ffuf":          20,
    "wfuzz":         15,
    "feroxbuster":   20,
    "dirb":          15,
    "nuclei":        25,
    "nikto":         15,
    "sqlmap":        20,
    "hydra":         15,
    "patator":       15,
    "crackmapexec":  40,
    "msfconsole":    25,
    "searchsploit":  40,
    # default = 200 (very high; only the loud/loop-prone tools above
    # carry stricter ceilings)
}
DEFAULT_PER_TOOL_CAP = 200

# Global engagement-wide invocation budget.  Total tool calls across
# ALL tools combined.  Default 500 is high enough that a real
# investigation never hits it, but a runaway loop does.
DEFAULT_ENGAGEMENT_INVOCATION_BUDGET = 500

# Same-action burst window: if the EXACT same (tool, args) was
# called within this many seconds AND the prior call was
# unproductive, block immediately on the repeat — don't wait for the
# consecutive-N counter to climb.
SAME_ACTION_BURST_WINDOW_SEC = 30.0

# Win-condition fields on intel that, when all true, mean the
# engagement objective is "structurally" satisfied.  When this state
# is reached, only evidence/report/cleanup tools are allowed.
WIN_CONDITION_INTEL_FIELDS = ("shell_access", "user_flag", "root_flag")

# How long a circuit-break stays in force.  10 minutes is enough for the
# LLM to pivot but not so long that a legitimate later attempt is blocked.
CIRCUIT_BREAK_DURATION_SEC = 600.0

# How many recent ReactSteps to render in the prompt.
RECENT_STEPS_FOR_PROMPT = 8

# How many pinned insights to render (newest-first; older ones still
# in memory but skipped from prompt to save tokens).
PINNED_INSIGHTS_FOR_PROMPT = 6

# Output-signature uniqueness threshold — if the same (tool, target,
# output_hash) triplet appears more than this many times, mark as dup.
DUP_OUTPUT_THRESHOLD = 3


# ─────────────────────────────────────────────────────────────────────
#  The context itself
# ─────────────────────────────────────────────────────────────────────


class EngagementContext:
    """Single source of truth for an engagement's state and reasoning.

    Instantiate one per session; pass to MasterAgent + every subagent
    that needs context.  Reads/writes are O(1).  Prompt rendering is
    O(n) in transcript length but capped by ``RECENT_STEPS_FOR_PROMPT``.
    """

    def __init__(
        self,
        *,
        session_id: str,
        target:     str,
        objective:  str = "",
        intel_ref:  Optional[Dict[str, Any]] = None,
    ) -> None:
        self.session_id = session_id
        self.target     = target
        # Objective is THE most important field.  Every LLM prompt must
        # include it.  Without it the LLM has no notion of "what would
        # success look like" — which is why ARGUS executes tools for
        # tool-execution's sake instead of working toward the goal.
        self.objective  = objective or self._default_objective(target)

        # The legacy intel dict — shared by reference so existing code
        # paths keep working unchanged.  New code reads via the typed
        # properties on this object.
        self.intel: Dict[str, Any] = intel_ref if intel_ref is not None else {}

        # ReAct transcript — bounded deque, oldest evicted when full.
        self.transcript: deque[ReactStep] = deque(maxlen=200)

        # Pinned insights — high-value LLM conclusions that survive
        # across phases.  Unbounded but `render_for_prompt` only shows
        # the most recent N.
        self.pinned: List[PinnedInsight] = []

        # Failed (tool, args_signature) pairs.  Distinct from circuit
        # breaker — these are pairs the LLM tried that didn't help.
        # Used to discourage repetition in subsequent prompts.
        self.failed_actions: Set[Tuple[str, str]] = set()

        # Tool statistics — keyed by (tool, target_signature).  Drives
        # the universal circuit breaker.
        self.tool_stats: Dict[Tuple[str, str], ToolStats] = {}

        # Confirmed findings — separate from intel because findings
        # have stronger semantics (evidence, severity, MITRE ID).
        self.findings: List[Dict[str, Any]] = []

        # Counters for engagement-wide observability.
        self.started_at = time.monotonic()
        self.phase_started_at: Dict[str, float] = {}
        self.phase_completed: Dict[str, bool] = {}

        # ── Engagement-wide budgets (the next tier of loop defense) ──
        # Global invocation count across all tools — capped to prevent
        # runaway sessions even when each individual call was nominally
        # productive (the LLM keeps finding new URLs to fuzz, etc.).
        self.total_invocations: int = 0
        self.invocation_budget: int = DEFAULT_ENGAGEMENT_INVOCATION_BUDGET
        # Per-tool absolute invocation counts (in addition to the
        # consecutive-empty breaker, this caps total calls per tool).
        self.invocations_per_tool: Dict[str, int] = {}
        # Tools/categories the operator marked as exempt from the
        # win-condition short-circuit (e.g. evidence collection,
        # report generation, post-engagement cleanup).
        self.post_completion_allowed_tools: Set[str] = {
            "tar", "zip", "scp", "rsync", "shred",
            # report-generation tools
            "pandoc", "wkhtmltopdf",
            # exfiltration helpers explicitly allowed once shell is owned
            "cat", "find", "grep",
        }
        # Operator can mark the engagement complete manually to halt
        # further dispatch.  Distinct from the auto-derived win
        # condition so an operator can pause before flag capture
        # (e.g. for evidence collection) or extend past it.
        self.operator_marked_complete: bool = False
        # Track which sub-goal each action serves, for traceability.
        # Keyed by ReactStep index in transcript.
        self.action_goal_tags: Dict[int, str] = {}

        # ── Engagement-mode state machine (reactive dispatch) ────
        # The big architectural shift: instead of a fixed phase
        # pipeline (recon → osint → vuln → exploit → post-exploit),
        # we model the engagement as a reactive state machine.  All
        # pipelines (scanners, exploit, loot, privesc) poll this
        # state and react cooperatively.
        #
        # States:
        #   "scanning"           — broad exploration, all scanners run
        #   "attempting_entry"   — viable entry point identified;
        #                          exploit attempt is in flight IN
        #                          PARALLEL with continued scanning.
        #                          Scanning does NOT stop here — the
        #                          user explicitly wanted "even if
        #                          other scanning wants to run in
        #                          parallel".
        #   "post_exploit"       — entry succeeded (shell / creds /
        #                          flag / loot).  ALL active scanning
        #                          STOPS.  Only loot, privesc, and
        #                          lateral pipelines run.
        #   "complete"           — objective satisfied or operator halt
        #
        # The transition functions are idempotent — calling them
        # multiple times is safe.  Each transition publishes an event
        # so pipelines polling between phases can react.
        self.engagement_mode: str = "scanning"
        # Each accumulated entry point becomes a dispatchable target
        # for the entry-attempt dispatcher.  Newest at the front so
        # the dispatcher picks fresh leads first.
        self.entry_points: List[Dict[str, Any]] = []
        # Set of entry-point signature hashes already seen, so the
        # detector doesn't re-fire on the same finding repeatedly.
        self._entry_point_sigs: Set[str] = set()
        # Success signals accumulated (kept for audit trail even after
        # mode transitions to complete).
        self.success_signals: List[Dict[str, Any]] = []
        # Async event the entry-attempt dispatcher awaits.  Set every
        # time a new entry point appears; the dispatcher consumes
        # one at a time.
        self._new_entry_point_event: Any = None      # lazy asyncio.Event
        # Mode-change subscribers (callable(old_mode, new_mode, reason))
        self._mode_subscribers: List[Any] = []

        # ── Cross-pipeline focused-attack interrupt ────────────────
        # When one pipeline (typically OSINT synthesis) identifies a
        # SPECIFIC attack chain — a concrete URL/endpoint to exploit
        # right now — it sets these fields.  ANY other long-running
        # pipeline (WebOrchestrator's 14-phase WSTG playbook,
        # vuln-id batch, the WSTG-style mechanical fuzzers) is
        # expected to call ``should_yield_to_focused_attack()``
        # cooperatively between phases AND between tools, and abort
        # when it returns True.
        #
        # This is the fix the previous "phase short-circuit" approach
        # could not solve: parallel pipelines that don't see each
        # other.  An interrupt-flag they all poll DOES coordinate
        # them without requiring a full rewrite.
        self.focused_attack_endpoints: List[str] = []   # URL/cmd queue
        self.focused_attack_reason:    str       = ""
        self.focused_attack_source:    str       = ""
        self.focused_attack_set_at:    float     = 0.0
        self.focused_attack_vhost:     str       = ""   # Host header value
        # Set of pipeline names that have ACKED the interrupt by
        # yielding.  Useful for telemetry + tests.
        self.pipelines_yielded:        Set[str]  = set()

    # ── Convenience properties wrapping the underlying intel dict ────

    @property
    def services(self) -> Dict[Any, Any]:
        return self.intel.get("services", {}) or {}

    @property
    def open_ports(self) -> List[Any]:
        return self.intel.get("open_ports", []) or []

    @property
    def critical_cves(self) -> List[str]:
        return list(self.intel.get("critical_cves") or [])

    @property
    def exploit_chain(self) -> Dict[str, Any]:
        return self.intel.get("exploit_chain", {}) or {}

    @property
    def next_commands(self) -> List[str]:
        return list(self.intel.get("next_commands") or [])

    # ── Action / observation recording ───────────────────────────────

    def record_action(
        self,
        *,
        tool:        str,
        args:        str,
        phase:       str,
        reasoning:   str,
        observation: str,
        productive:  Optional[bool] = None,
        finding_ids: Optional[List[str]] = None,
        goal_tag:    str = "",
    ) -> ReactStep:
        """Append a ReactStep to the transcript and update tool stats.

        ``productive`` defaults to a heuristic: a result is productive
        if it contains non-trivial output (>40 useful chars) AND
        doesn't match a known dead-pattern (404, connection refused,
        empty body).
        """
        obs_excerpt = (observation or "").strip()
        if productive is None:
            productive = self._is_productive(obs_excerpt, tool)

        step = ReactStep(
            ts          = time.monotonic(),
            phase       = phase or "unknown",
            tool        = tool,
            args        = args[:200],
            reasoning   = reasoning[:400],
            observation = obs_excerpt[:600],
            productive  = productive,
            finding_ids = list(finding_ids or []),
        )
        self.transcript.append(step)
        # Track engagement-wide invocation totals (the global budget)
        self.total_invocations += 1
        self.invocations_per_tool[tool] = (
            self.invocations_per_tool.get(tool, 0) + 1
        )
        # Goal tagging — link the action to the sub-objective it serves
        if goal_tag:
            self.action_goal_tags[len(self.transcript) - 1] = goal_tag[:80]

        # Update tool stats (drives circuit breaker)
        cb_key = (tool, self._target_sig(args))
        st = self.tool_stats.get(cb_key) or ToolStats()
        st.invocations    += 1
        st.last_invoked_at = step.ts

        # ── Signature first, so the productive branch can distinguish
        # "productive AND novel" (real reset) from "productive AND dup"
        # (still going in circles).
        sig = self._signature(obs_excerpt) if obs_excerpt else ""
        is_dup = bool(sig) and (sig in st.output_signatures)

        if productive and not is_dup:
            # Genuinely useful new output → reset both counters
            st.productive          += 1
            st.consecutive_empty    = 0
            st.consecutive_dup      = 0
            st.last_productive_at   = step.ts
            st.blocked_until        = 0.0
        elif productive and is_dup:
            # Productive but identical to a prior response — still a loop
            st.productive       += 1
            st.consecutive_dup  += 1
        else:
            # Unproductive
            st.consecutive_empty += 1
            self.failed_actions.add((tool, args[:80]))
            if is_dup:
                st.consecutive_dup += 1
        # Always record the new signature (set is idempotent)
        if sig:
            st.output_signatures.add(sig)
        self.tool_stats[cb_key] = st
        return step

    # ── Insights ─────────────────────────────────────────────────────

    def pin_insight(
        self,
        text:     str,
        *,
        phase:    str = "",
        severity: str = "important",
        source:   str = "",
    ) -> PinnedInsight:
        """Pin a high-value reasoning conclusion that must propagate.

        Use this whenever the LLM produces an "aha" moment that should
        survive across phases — e.g. "the attack chain is X" or
        "service Y is the entry point."
        """
        ins = PinnedInsight(
            ts=time.monotonic(), phase=phase, severity=severity,
            text=text[:600], source=source,
        )
        self.pinned.append(ins)
        return ins

    def pin_insights_from_intel(self) -> None:
        """Pull high-value entries already in intel into the pinned list.

        Called once after the OSINT synthesis writes ``exploit_chain``
        + ``critical_cves`` + ``next_commands`` — so the LLM sees them
        in every subsequent prompt rather than having to re-derive.
        """
        chain = self.exploit_chain
        cves  = self.critical_cves
        cmds  = self.next_commands
        sev   = (chain.get("severity") or
                  self.intel.get("risk_verdict") or "").lower()
        if not (chain or cves or cmds):
            return
        # Avoid duplicate pinning across multiple OSINT cycles
        for p in self.pinned:
            if p.source == "osint_synthesis":
                return
        bits = []
        if sev:
            bits.append(f"Severity: {sev.upper()}")
        if cves:
            bits.append(f"Critical CVEs: {', '.join(cves[:5])}")
        if cmds:
            bits.append(f"Pre-staged kill-chain commands ({len(cmds)}): {cmds[0][:100]}...")
        self.pin_insight(
            text=" | ".join(bits),
            phase="osint",
            severity="critical",
            source="osint_synthesis",
        )

    # ── Findings ────────────────────────────────────────────────────

    def record_finding(self, finding: Dict[str, Any]) -> None:
        """Store a finding.  Idempotent on (title, host, severity).

        After storing, runs both detectors:
          * detect_entry_points() — might transition mode to attempting_entry
          * detect_success_signals() — might transition to post_exploit

        Synchronous so the caller sees the updated mode immediately.
        """
        sig = (finding.get("title", ""), finding.get("host", ""),
               finding.get("severity", ""))
        for f in self.findings:
            if (f.get("title"), f.get("host"), f.get("severity")) == sig:
                return
        self.findings.append(finding)
        # ── Reactive dispatch hook ──────────────────────────────
        # Findings are the primary signal source: a finding titled
        # "Anonymous Bind Allowed" is a viable entry point and the
        # exploit attempt should fire RIGHT NOW.  Same for shell-
        # access findings, default creds, etc.
        try:
            self.detect_entry_points()
            self.detect_success_signals()
        except Exception:
            pass

    # ── Circuit-breaker queries ─────────────────────────────────────

    def is_tool_blocked(self, tool: str, args: str) -> Tuple[bool, str]:
        """Return (blocked, reason_message).

        Blocked when ANY of the following hold:
          (0) **No necessary basis** — the tool's precondition is not
              met against current state (wpscan with no WordPress
              detected, hydra with no creds, evil-winrm with no
              shell, etc.).  This is the *prescriptive* gate that
              ensures every invocation has a reason, not just that
              it stays under a cap.
          (a) **Operator complete-flag** — operator manually halted
              dispatch (only post-completion-allowed tools may run).
          (b) **Win condition reached** — shell + flags captured;
              only evidence/report/cleanup tools may run.
          (c) **Engagement-wide invocation budget exhausted** —
              total tool calls hit the global cap.
          (d) **Per-tool absolute cap** — this tool has been called
              its full quota for the engagement.
          (e) **Same-action burst** — exact same (tool, args) called
              within SAME_ACTION_BURST_WINDOW_SEC AND prior call was
              unproductive (no need to wait for consecutive-N).
          (f) **Consecutive-empty threshold** — (tool, target_sig)
              has produced N unproductive results in a row.
          (g) **Dup-output threshold** — same response signature
              repeated DUP_OUTPUT_THRESHOLD+ times.
          (h) **Explicit timed block** still in force.
        """
        tool_lc = (tool or "").lower()

        # (0) — Necessary-basis check (prescriptive gate).  Run FIRST so
        # the system never even counts an unwarranted call against the
        # budget — it's refused at the door.
        warranted, why = check_tool_warranted(tool, args, self)
        if not warranted:
            return True, f"NO BASIS — {why}"

        # (a) — operator halted further dispatch
        if self.operator_marked_complete and tool_lc not in self.post_completion_allowed_tools:
            return True, (
                f"Engagement marked complete by operator — "
                f"{tool} is not in the post-completion allow-list "
                f"({sorted(self.post_completion_allowed_tools)})"
            )

        # (b) — win condition reached
        if self.is_engagement_complete() and tool_lc not in self.post_completion_allowed_tools:
            return True, (
                f"Engagement objective satisfied (shell + flags captured). "
                f"{tool} is not an allowed post-completion tool. "
                f"Pivot to evidence collection / report generation."
            )

        # (c) — global invocation budget
        if self.total_invocations >= self.invocation_budget:
            return True, (
                f"Engagement-wide invocation budget exhausted "
                f"({self.total_invocations}/{self.invocation_budget} calls). "
                f"Operator must raise the budget or end the engagement."
            )

        # (d) — per-tool absolute cap
        per_cap = PER_TOOL_INVOCATION_CAPS.get(tool_lc, DEFAULT_PER_TOOL_CAP)
        count = self.invocations_per_tool.get(tool, 0)
        if count >= per_cap:
            return True, (
                f"{tool} has been invoked {count} times "
                f"(cap {per_cap}/engagement) — pivot to a different tool"
            )

        cb_key = (tool, self._target_sig(args))
        st = self.tool_stats.get(cb_key)
        now = time.monotonic()

        # (e) — same-action burst (kicks in EVEN before any stats exist
        # for newly-tracked target_sig because we check the last
        # ReactStep on the transcript).
        if self.transcript:
            last = self.transcript[-1]
            if (last.tool == tool
                    and last.args[:80] == args[:80]
                    and not last.productive
                    and (now - last.ts) < SAME_ACTION_BURST_WINDOW_SEC):
                return True, (
                    f"Same {tool} call against {args[:60]!r} just produced "
                    f"unproductive output {int(now - last.ts)}s ago — "
                    f"do not immediately retry; change tool or target"
                )

        # Remaining gates need tool_stats — early return if none yet.
        if st is None:
            return False, ""

        # (h) — explicit timed block
        if st.blocked_until and now < st.blocked_until:
            remain = int(st.blocked_until - now)
            return True, (f"{tool} against {cb_key[1]} is in circuit-break "
                          f"for {remain}s more (after "
                          f"{st.consecutive_empty} unproductive calls)")

        # (f) — consecutive-empty threshold
        threshold = self._threshold_for(tool)
        if st.consecutive_empty >= threshold:
            st.blocked_until = now + CIRCUIT_BREAK_DURATION_SEC
            self.tool_stats[cb_key] = st
            return True, (f"{tool} against {cb_key[1]} blocked after "
                          f"{st.consecutive_empty} consecutive empty/error "
                          f"results — LLM must pivot to a different action")

        # (g) — dup-output threshold
        if st.consecutive_dup >= DUP_OUTPUT_THRESHOLD:
            return True, (f"{tool} against {cb_key[1]} blocked — "
                          f"output signature repeated "
                          f"{st.consecutive_dup} times (same dead-end response). "
                          f"Pivot to different tool or target")
        return False, ""

    # ── Engagement-completion check ────────────────────────────────

    def is_engagement_complete(self) -> bool:
        """Auto-derive whether the structural objective is satisfied.

        Defaults to: shell_access AND (user_flag OR root_flag) — the
        "we own the box AND have at least one flag" line.  Operator
        can override by setting ``operator_marked_complete`` or by
        passing a custom win-condition function later.
        """
        if self.operator_marked_complete:
            return True
        shell = bool(self.intel.get("shell_access"))
        user_flag = bool(self.intel.get("user_flag"))
        root_flag = bool(self.intel.get("root_flag"))
        # Conservative: require shell + ≥1 flag.  An "evidence-only"
        # engagement can be marked complete by operator without flags.
        if shell and (user_flag or root_flag):
            return True
        return False

    # ── Stall watchdog ────────────────────────────────────────────
    # Hard-stop heuristic that fires when an engagement burns
    # significant wall-clock with zero findings AND no focused-attack
    # signal in flight.  Prevents the "2 hours, 0 findings, 256 curls"
    # pattern observed in the logs.  Phases that call this and get
    # True back should mark the engagement complete (or transition to
    # report generation) instead of cycling the playbook again.
    def is_engagement_stalled(
        self,
        *,
        max_idle_minutes: int = 25,
        min_recent_actions: int = 30,
    ) -> bool:
        """Return True when the engagement is clearly not making progress.

        Conditions (ALL must hold):
          1. Wall-clock elapsed is more than ``max_idle_minutes``.
          2. At least ``min_recent_actions`` actions have been
             recorded (we have actually been trying things, not just
             starting up).
          3. Zero findings recorded.
          4. No focused-attack signal currently in flight.
          5. No shell access obtained.

        When all hold, mechanical playbooks should yield + the
        engagement should transition to reporting.
        """
        elapsed_min = (time.monotonic() - self.started_at) / 60.0
        if elapsed_min < max_idle_minutes:
            return False
        if self.total_invocations < min_recent_actions:
            return False
        if self.findings:
            return False
        if self.focused_attack_endpoints:
            return False
        if self.intel.get("shell_access"):
            return False
        return True

    def mark_complete(self, *, reason: str = "operator halt") -> None:
        """Manually halt all further tool dispatch.

        Use when the operator wants to stop active testing and move to
        evidence collection / reporting.  Post-completion-allowed tools
        (tar, scp, pandoc, etc.) continue to function.
        """
        self.operator_marked_complete = True
        self.pin_insight(
            f"ENGAGEMENT MARKED COMPLETE: {reason}",
            phase="all", severity="critical", source="operator",
        )

    def set_invocation_budget(self, budget: int) -> None:
        """Adjust the global tool-call ceiling for this engagement."""
        if budget > 0:
            self.invocation_budget = int(budget)

    def allow_tool_post_completion(self, tool: str) -> None:
        """Add a tool to the post-completion allow-list."""
        self.post_completion_allowed_tools.add(tool.lower())

    # ── Target classification (genuinely different fix) ─────────────
    #
    # The previous "phase machine + circuit breakers" model assumes
    # every target needs the same phase pipeline (recon → vuln → web
    # → exploit).  That assumption is wrong: an AD Domain Controller
    # has no web app, a SOAP-only API has no AD, and an IoT device
    # has neither.  Running the WSTG 14-phase OWASP playbook against
    # a DC's closed port 80 burned 90 minutes in the last engagement.
    #
    # The correct primitive is to CLASSIFY the target after recon and
    # dispatch only the phases that apply.  Profile names are
    # intentionally stable strings (lowercased) so trigger logic can
    # branch on them.

    AD_PORTS_REQUIRED   = (88, 389)        # kerberos + LDAP = AD
    AD_PORTS_SUPPORTING = (445, 139, 636, 3268, 3269, 5985, 5986, 9389)
    WEB_PORTS_COMMON    = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8181)
    DB_PORTS            = (1433, 3306, 5432, 27017, 6379, 9200)

    def classify_target_profile(self) -> str:
        """Categorise the target so phase routing can skip irrelevant
        playbooks.  Called by the master agent after RECON completes.

        Returns one of: ``ad_dc``, ``web_app``, ``mixed``, ``db_server``,
        ``smb_only``, ``ssh_only``, ``unknown``.
        """
        ports = set()
        for p in (self.open_ports or []):
            try:
                ports.add(int(str(p).split("/")[0]))
            except Exception:
                continue
        # Some pipelines populate services without open_ports (e.g.
        # banner_subagent stores its findings as services dict only).
        for p in self.services.keys():
            try:
                ports.add(int(str(p).split("/")[0]))
            except Exception:
                continue

        has_ad = all(p in ports for p in self.AD_PORTS_REQUIRED)
        # 5985 is WinRM HTTPAPI — looks like HTTP but is admin-only,
        # NOT a web app surface.  Exclude when classifying as web.
        web_ports_found = [
            p for p in ports if p in self.WEB_PORTS_COMMON and p != 5985
        ]
        has_web = len(web_ports_found) > 0

        # Detect actual web SERVICE (not just an open port) from
        # service banners to reduce false positives.
        has_real_web_service = False
        for svc in self.services.values():
            if isinstance(svc, dict):
                banner = " ".join(str(svc.get(k, "")) for k in
                                    ("service", "product", "version", "banner")).lower()
                # WinRM HTTPAPI looks like http but is NOT a web app
                if "httpapi" in banner or "winrm" in banner:
                    continue
                if any(h in banner for h in ("http", "nginx", "apache",
                                                "iis", "tomcat", "jetty",
                                                "lighttpd", "caddy", "express",
                                                "node", "django", "flask",
                                                "wordpress", "drupal", "joomla")):
                    has_real_web_service = True
                    break

        # DB-only target?
        db_ports = [p for p in ports if p in self.DB_PORTS]

        # Decision tree (most specific first)
        if has_ad and has_real_web_service:
            return "mixed"
        if has_ad:
            return "ad_dc"
        if has_real_web_service:
            return "web_app"
        if db_ports:
            return "db_server"
        # SMB without AD = file-server style
        if 445 in ports or 139 in ports:
            return "smb_only"
        # SSH only is common for Linux boxes
        if 22 in ports and len(ports) <= 3:
            return "ssh_only"
        return "unknown"

    def commit_target_profile(self) -> str:
        """Run classify_target_profile and persist the result.

        Stores the profile on ``intel["target_profile"]`` for backward
        compat with legacy consumers AND on the context itself for
        typed access.  Pins it as an insight so it surfaces in every
        subsequent LLM prompt.
        """
        profile = self.classify_target_profile()
        self.intel["target_profile"] = profile
        # Pin so the LLM sees the verdict in every subsequent prompt
        if not any(p.source == "target_profile" for p in self.pinned):
            self.pin_insight(
                text=(
                    f"TARGET PROFILE = {profile!r}.  "
                    f"Open ports: {sorted(set(int(str(p).split('/')[0]) for p in (self.open_ports or []) if str(p).split('/')[0].isdigit()))[:10]}.  "
                    f"Phase router will dispatch the playbook(s) "
                    f"appropriate for this profile and SKIP irrelevant ones "
                    f"(e.g. WSTG is skipped for ad_dc profile because the "
                    f"target has no web application surface)."
                ),
                phase="recon",
                severity="critical",
                source="target_profile",
            )
        return profile

    def get_target_profile(self) -> str:
        """Cheap accessor — falls back to recomputation if not yet committed."""
        return (self.intel.get("target_profile")
                  or self.classify_target_profile())

    def should_skip_web_testing(self) -> bool:
        """Return True when WSTG / WebOrchestrator should NOT run.

        Skips when:
          * profile is ad_dc / db_server / ssh_only / smb_only
            (no web app surface at all), OR
          * profile is unknown AND no web ports are actually open
        """
        profile = self.get_target_profile()
        if profile in ("ad_dc", "db_server", "ssh_only", "smb_only"):
            return True
        if profile == "unknown":
            ports = set()
            for p in self.open_ports or []:
                try:
                    ports.add(int(str(p).split("/")[0]))
                except Exception:
                    continue
            web_ports = ports & set(self.WEB_PORTS_COMMON)
            if not web_ports:
                return True
        return False

    # ═════════════════════════════════════════════════════════════
    #  Port targeting helpers (universal across target types)
    # ═════════════════════════════════════════════════════════════

    def primary_web_port(self) -> Optional[int]:
        """Return the BEST web port to target on this host.

        Priority (in order):
          1. A non-default port (8080, 8443, 3000, 5000, etc.) where
             the service banner positively identifies a web app —
             this catches the Overpass-3 / TwoMillion pattern where
             the actual app is on 8080 and port 80 is closed/filtered.
          2. Standard ports (80, 443) where a web service banner is
             present.
          3. None when no web service is identified anywhere.

        The point: WSTG / WebOrchestrator / curl-spray pipelines must
        target the REAL web port, not blindly hit 80.  The failed
        Overpass-3 run wasted 27 minutes hitting port 80 (closed)
        while the actual Werkzeug app was on 8080.
        """
        services = self.services or {}
        open_ports = set()
        for p in self.open_ports or []:
            try:
                open_ports.add(int(str(p).split("/")[0]))
            except Exception:
                continue

        # First pass: prefer NON-DEFAULT web ports with positive banners
        # (these are usually the "real" application servers)
        non_default = (8080, 8443, 8000, 8888, 3000, 5000, 9000, 8181,
                          4443, 7443, 5985)   # 5985 excluded later
        for port, svc in services.items():
            try:
                port_int = int(str(port).split("/")[0])
            except Exception:
                continue
            if port_int == 5985:
                continue  # WinRM, not a real web app
            if port_int not in non_default:
                continue
            if port_int not in open_ports and open_ports:
                continue  # port not actually open
            if isinstance(svc, dict):
                banner = " ".join(str(svc.get(k, "")) for k in
                                    ("service", "product", "version",
                                      "banner", "extrainfo", "info")).lower()
                if any(h in banner for h in (
                    "http", "nginx", "apache", "tomcat", "jetty",
                    "werkzeug", "express", "node", "django", "flask",
                    "wordpress", "drupal", "joomla", "iis", "lighttpd",
                    "caddy",
                )):
                    return port_int

        # Second pass: standard 80/443 with a service banner
        for port_candidate in (443, 80):
            svc = services.get(port_candidate) or services.get(str(port_candidate))
            if not svc:
                continue
            if open_ports and port_candidate not in open_ports:
                continue
            if isinstance(svc, dict):
                banner = " ".join(str(svc.get(k, "")) for k in
                                    ("service", "product", "version",
                                      "banner")).lower()
                if any(h in banner for h in (
                    "http", "nginx", "apache", "tomcat", "iis"
                )):
                    return port_candidate

        # Last resort: ANY non-default port that's open and might be web
        for port_int in sorted(open_ports):
            if port_int in non_default and port_int != 5985:
                return port_int
        # Fallback to 80 only if it's actually open
        if 80 in open_ports:
            return 80
        if 443 in open_ports:
            return 443
        return None

    def primary_web_url(self, *, scheme_hint: str = "") -> Optional[str]:
        """Return a canonical http(s)://host:port URL for web pipelines."""
        port = self.primary_web_port()
        if port is None:
            return None
        host = (self.intel.get("target_host") or self.target or "").strip()
        if not host:
            return None
        # Pick scheme heuristically
        scheme = scheme_hint.lower() if scheme_hint else ""
        if not scheme:
            scheme = "https" if port in (443, 8443, 4443, 7443) else "http"
        # Don't append default ports to the URL
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    # ═════════════════════════════════════════════════════════════
    #  Phase wall-clock budgets (hard time caps)
    # ═════════════════════════════════════════════════════════════

    # Default budgets in seconds.  Tunable via set_phase_budget().
    # Designed against the failed-engagement post-mortem: vuln_id ran
    # for 40 minutes producing zero findings; wstg config phase ran
    # for 27 minutes.  These caps force-advance regardless of
    # internal completion state.
    PHASE_BUDGET_DEFAULTS: Dict[str, float] = {
        "recon":       600.0,     # 10 min
        "osint":       600.0,     # 10 min
        "vuln_id":     720.0,     # 12 min
        "web_testing": 900.0,     # 15 min
        "exploit":    1500.0,     # 25 min
        "post_exploit":1200.0,    # 20 min
        "lateral":     900.0,     # 15 min
        "privesc":     900.0,
    }

    def set_phase_budget(self, phase: str, seconds: float) -> None:
        """Override default phase budget."""
        if not phase:
            return
        if not hasattr(self, "_phase_budgets"):
            self._phase_budgets: Dict[str, float] = {}
        self._phase_budgets[phase.lower()] = max(60.0, float(seconds))

    def get_phase_budget(self, phase: str) -> float:
        """Return wall-clock seconds remaining or 0 if not started yet."""
        if not phase:
            return 0.0
        key = phase.lower().replace("attackphase.", "")
        custom = getattr(self, "_phase_budgets", {}).get(key)
        return custom if custom is not None else self.PHASE_BUDGET_DEFAULTS.get(
            key, 900.0
        )

    def is_phase_budget_exceeded(self, phase: str) -> bool:
        """True if the named phase has been running longer than its budget."""
        key = phase.lower().replace("attackphase.", "")
        started = self.phase_started_at.get(key)
        if started is None:
            return False
        budget = self.get_phase_budget(key)
        return (time.monotonic() - started) > budget

    def mark_phase_started(self, phase: str) -> None:
        key = phase.lower().replace("attackphase.", "")
        if key not in self.phase_started_at:
            self.phase_started_at[key] = time.monotonic()

    # ═════════════════════════════════════════════════════════════
    #  Engagement-mode state machine + reactive dispatch
    # ═════════════════════════════════════════════════════════════

    def transition_mode(self, new_mode: str, *,
                          reason: str = "", payload: Optional[Dict] = None) -> bool:
        """Move the engagement to a new mode.

        Returns True if a transition occurred, False if no-op (same
        mode).  Publishes a pinned insight + invokes all subscribers.
        Idempotent.
        """
        valid = ("scanning", "attempting_entry", "post_exploit", "complete")
        if new_mode not in valid:
            return False
        old = self.engagement_mode
        if old == new_mode:
            return False
        # Forbid going backward from post_exploit / complete except to
        # complete (so a successful entry can't be "undone" by later
        # noisy scanner traffic).
        if old in ("post_exploit", "complete") and new_mode in ("scanning", "attempting_entry"):
            return False
        self.engagement_mode = new_mode
        severity = ("critical" if new_mode in ("post_exploit", "complete")
                     else "important")
        self.pin_insight(
            text=(
                f"ENGAGEMENT MODE: {old!r} → {new_mode!r}.  "
                f"Reason: {reason[:280]}.  "
                + (
                    "Scanning continues IN PARALLEL with exploit dispatch."
                    if new_mode == "attempting_entry"
                    else
                    "ALL ACTIVE SCANNING MUST STOP.  Focus shifts to loot "
                    "harvesting + privilege escalation + lateral movement."
                    if new_mode == "post_exploit"
                    else
                    "Engagement objective satisfied.  No further dispatch."
                    if new_mode == "complete"
                    else
                    "Resumed broad exploration."
                )
            ),
            phase=self.engagement_mode,
            severity=severity,
            source="engagement_mode",
        )
        # Notify subscribers (synchronous — they should be cheap)
        for cb in list(self._mode_subscribers):
            try:
                cb(old, new_mode, reason)
            except Exception:
                pass
        return True

    def subscribe_mode_changes(self, callback) -> None:
        """Register callable(old_mode, new_mode, reason)."""
        if callable(callback) and callback not in self._mode_subscribers:
            self._mode_subscribers.append(callback)

    def is_post_exploit_mode(self) -> bool:
        """Cheap helper for scanners to poll between phases."""
        return self.engagement_mode in ("post_exploit", "complete")

    def is_attempting_entry(self) -> bool:
        return self.engagement_mode == "attempting_entry"

    def should_scanners_yield(self) -> bool:
        """Universal: any scanner-style pipeline (WSTG, vuln-batch, recon)
        should yield when this returns True.

        Returns True only when:
          * engagement is in post_exploit or complete mode, OR
          * operator manually halted, OR
          * win-condition met
        Note: attempting_entry does NOT trigger yield — the user
        explicitly wanted scanning to continue in parallel.
        """
        return (self.is_post_exploit_mode()
                  or self.operator_marked_complete
                  or self.is_engagement_complete())

    # ── Entry-point detector (universal: AD / Linux / IoT / web) ──

    # Title fragments that universally indicate a viable entry point.
    # Designed to match findings from recon/vuln subagents regardless
    # of target type.  Lowercased substring match.
    _ENTRY_FINDING_PATTERNS = (
        "anonymous bind allowed",
        "null session",
        "default credentials",
        "default password",
        "default creds",
        "guest access",
        "guest login",
        "no authentication",
        "unauthenticated access",
        "weak credentials",
        "weak password",
        "credential exposure",
        "exposed credentials",
        "leaked credentials",
        "valid credentials",
        "shell access",
        "rce confirmed",
        "remote code execution",
        "command injection",
        "sql injection",
        "lfi confirmed",
        "ssrf confirmed",
        "directory traversal",
        "unauthenticated rce",
        "telnet allowed",
        "ftp anonymous",
        "ftp anon",
        "snmp public",
        "snmp default community",
        "redis unauth",
        "mongodb unauth",
        "elasticsearch unauth",
        "docker api exposed",
        "kubelet anonymous",
        "wp-admin accessible",
        "tomcat manager",
        "phpmyadmin accessible",
        "jenkins anonymous",
        "git repository exposed",
        ".env exposed",
        "backup file accessible",
    )

    def detect_entry_points(self) -> List[Dict[str, Any]]:
        """Scan intel for VIABLE ENTRY POINTS, regardless of target type.

        Returns a list of new (not previously detected) entry-point
        descriptors.  Side effect: appends them to
        ``self.entry_points`` and (if the engagement is still in
        ``scanning`` mode) transitions to ``attempting_entry``.

        This is UNIVERSAL by design — it checks intel fields that are
        populated regardless of whether the target is AD / Linux /
        Windows / IoT / web app / database.  Specific protocols don't
        need bespoke detection logic here; the per-protocol triggers
        in finding_triggers.py populate intel["next_commands"] which
        is one of the signals this detector watches for.
        """
        new_entries: List[Dict[str, Any]] = []

        def _sig(d: Dict[str, Any]) -> str:
            """Stable hash so the same entry doesn't fire twice."""
            return hashlib.sha256(
                (str(d.get("type", "")) + "|" + str(d.get("key", ""))[:200]
                  ).encode("utf-8", errors="ignore")
            ).hexdigest()[:24]

        # 1. Findings with entry-point titles (universal across targets)
        for f in self.findings:
            title = (f.get("title") if isinstance(f, dict) else "").lower()
            if not title:
                continue
            for pattern in self._ENTRY_FINDING_PATTERNS:
                if pattern in title:
                    entry = {
                        "type":     "finding_match",
                        "subtype":  pattern,
                        "key":      f.get("finding_id") or f.get("title"),
                        "finding":  {k: v for k, v in f.items() if k != "_id"},
                        "severity": f.get("severity", "HIGH"),
                        "priority": 9,
                    }
                    s = _sig(entry)
                    if s not in self._entry_point_sigs:
                        self._entry_point_sigs.add(s)
                        new_entries.append(entry)
                    break

        # 2. Concrete commands already pre-staged by finding_triggers
        #    (these encode entry attempts for AD, Linux SSH, IoT, DB, etc.)
        cmds = self.intel.get("next_commands") or []
        if cmds:
            entry = {
                "type":     "pre_staged_commands",
                "key":      f"next_commands::{len(cmds)}::{cmds[0][:80]}",
                "commands": list(cmds),
                "priority": 10,
            }
            s = _sig(entry)
            if s not in self._entry_point_sigs:
                self._entry_point_sigs.add(s)
                new_entries.append(entry)

        # 3. URL endpoints identified by OSINT URL-extractor
        if self.focused_attack_endpoints:
            entry = {
                "type":      "focused_endpoints",
                "key":       f"focused::{len(self.focused_attack_endpoints)}",
                "endpoints": list(self.focused_attack_endpoints),
                "priority":  10,
            }
            s = _sig(entry)
            if s not in self._entry_point_sigs:
                self._entry_point_sigs.add(s)
                new_entries.append(entry)

        # 4. Credentials already in intel (any harvest path)
        creds = self.intel.get("credentials") or []
        if creds:
            entry = {
                "type":  "credentials_available",
                "key":   f"creds::{len(creds)}",
                "creds": creds,
                "priority": 10,
            }
            s = _sig(entry)
            if s not in self._entry_point_sigs:
                self._entry_point_sigs.add(s)
                new_entries.append(entry)

        # 5. Known-exploitable CVE present.  Source CVEs from the OSINT
        #    exploit_chain when available, but ALSO from raw intel['cves']
        #    and vulnerability findings.  A CVE identified by recon or the
        #    vuln scan (e.g. a versioned service banner → CVE-2018-15473) is
        #    exploit-worthy even if OSINT never synthesised a formal chain —
        #    this guarantees "vulnerability found → exploitation attempt"
        #    rather than waiting on OSINT synthesis that may never run.
        chain = self.exploit_chain
        cve_candidates: List[str] = []
        if chain and chain.get("critical_cves"):
            for c in (chain.get("critical_cves") or []):
                cu = str(c).strip().upper()
                if cu and cu not in cve_candidates:
                    cve_candidates.append(cu)
        for c in (self.intel.get("cves") or []):
            cu = str(c).strip().upper()
            if cu and cu not in cve_candidates:
                cve_candidates.append(cu)
        for v in (self.intel.get("vulnerabilities") or []):
            if not isinstance(v, dict):
                continue
            v_cves = v.get("cves") or ([v.get("cve")] if v.get("cve") else [])
            for c in v_cves:
                cu = str(c).strip().upper()
                if cu and cu not in cve_candidates:
                    cve_candidates.append(cu)
        if cve_candidates:
            sev = (chain.get("severity", "high") if chain else "high") or "high"
            entry = {
                "type":     "exploitable_cve",
                "key":      f"cves::{','.join(cve_candidates[:3])}",
                "cves":     cve_candidates,
                "severity": str(sev).lower(),
                "priority": 9,
            }
            s = _sig(entry)
            if s not in self._entry_point_sigs:
                self._entry_point_sigs.add(s)
                new_entries.append(entry)

        # ── Update state machine + queue ────────────────────────────
        if new_entries:
            for e in new_entries:
                # Newest highest-priority at the front
                self.entry_points.insert(0, e)
            # Trip the asyncio event so the dispatcher wakes up
            try:
                import asyncio as _aio
                if self._new_entry_point_event is None:
                    self._new_entry_point_event = _aio.Event()
                self._new_entry_point_event.set()
            except Exception:
                pass
            # If we're still in pure scanning mode, escalate.  Do NOT
            # downgrade from post_exploit/complete back to attempting.
            if self.engagement_mode == "scanning":
                reasons = ", ".join(f"{e['type']}({e.get('subtype','')})"
                                       for e in new_entries[:3])
                self.transition_mode(
                    "attempting_entry",
                    reason=f"Detected {len(new_entries)} new entry point(s): {reasons}",
                )

        return new_entries

    def pop_entry_point(self) -> Optional[Dict[str, Any]]:
        """Take one entry point off the queue for an exploit attempt."""
        if not self.entry_points:
            return None
        return self.entry_points.pop(0)

    async def wait_for_entry_point(self, timeout: float = 30.0) -> bool:
        """Async helper for the dispatcher to await the next entry point.

        Returns True if an event fired before timeout, False otherwise.
        """
        try:
            import asyncio as _aio
            if self._new_entry_point_event is None:
                self._new_entry_point_event = _aio.Event()
            try:
                await _aio.wait_for(self._new_entry_point_event.wait(),
                                      timeout=timeout)
                self._new_entry_point_event.clear()
                return True
            except _aio.TimeoutError:
                return False
        except Exception:
            return False

    # ── Success detector (universal: shell, creds, flag, loot) ────

    def detect_success_signals(self) -> List[Dict[str, Any]]:
        """Check intel for indications of successful initial access.

        Returns NEW signals (not previously detected).  Side effect:
        if any signal is found, transitions mode to ``post_exploit``.

        Universal: works for Windows shell, Linux shell, web app
        admin login, IoT credential bypass, database access, etc.
        """
        signals: List[Dict[str, Any]] = []
        # Reuse the entry-point sig set so a signal isn't fired twice
        # — but tag the keys so they're distinct from entry-point keys.
        def _sig(d: Dict[str, Any]) -> str:
            return ("SUCCESS::" + hashlib.sha256(
                (str(d.get("type", "")) + "|" + str(d.get("key", ""))[:200]
                  ).encode("utf-8", errors="ignore")
            ).hexdigest()[:24])

        # Shell access of any kind
        if self.intel.get("shell_access"):
            sig = {"type": "shell", "key": "shell_access",
                    "details": self.intel.get("shell_id") or "active"}
            s = _sig(sig)
            if s not in self._entry_point_sigs:
                self._entry_point_sigs.add(s)
                signals.append(sig)

        # Credentials harvested (any source)
        if self.intel.get("credentials"):
            sig = {"type": "credentials", "key": f"creds::{len(self.intel['credentials'])}",
                    "details": self.intel.get("credentials")}
            s = _sig(sig)
            if s not in self._entry_point_sigs:
                self._entry_point_sigs.add(s)
                signals.append(sig)

        # Flags captured
        for fkey in ("user_flag", "root_flag"):
            if self.intel.get(fkey):
                sig = {"type": "flag", "key": fkey}
                s = _sig(sig)
                if s not in self._entry_point_sigs:
                    self._entry_point_sigs.add(s)
                    signals.append(sig)

        # Loot harvested
        loot = self.intel.get("loot") or {}
        for loot_kind in ("ssh_keys", "nt_hashes", "kerberos_tgts",
                            "kerberos_tgss", "secrets"):
            if loot.get(loot_kind):
                sig = {"type": "loot",
                        "key": f"loot::{loot_kind}::{len(loot[loot_kind])}",
                        "kind": loot_kind, "count": len(loot[loot_kind])}
                s = _sig(sig)
                if s not in self._entry_point_sigs:
                    self._entry_point_sigs.add(s)
                    signals.append(sig)

        if signals:
            for sg in signals:
                self.success_signals.append(sg)
            # Win condition met? Mark complete.  Else pivot to post_exploit.
            if self.is_engagement_complete():
                self.transition_mode(
                    "complete",
                    reason="Win condition satisfied (shell + flag captured)",
                )
            else:
                kinds = ", ".join(sg["type"] for sg in signals)
                self.transition_mode(
                    "post_exploit",
                    reason=(
                        f"Entry succeeded — signals detected: {kinds}.  "
                        "All scanning stops; loot + privesc + lateral take over."
                    ),
                )
        return signals

    def extract_ad_domain(self) -> str:
        """Pull the AD domain (e.g. ``support.htb``) out of intel.

        Looks at LDAP service banners (which encode the domain via
        ``Microsoft Windows Active Directory LDAP (Domain: …)``) and
        falls back to the target if nothing matches.
        """
        import re as _re
        for svc in self.services.values():
            if not isinstance(svc, dict):
                continue
            blob = " ".join(str(svc.get(k, "")) for k in
                              ("service", "product", "version", "banner",
                                "extrainfo", "info"))
            m = _re.search(r"Domain:\s*([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)", blob, _re.IGNORECASE)
            if m:
                # Strip trailing dot/0 the LDAP banner sometimes appends
                return m.group(1).rstrip("0.").lower()
        # Fall back to DN-style extraction from a previously pinned
        # finding text (the service_banner subagent emits
        # "Base DN: DC=support,DC=htb").
        for p in self.pinned + self.findings:
            text = p.text if hasattr(p, "text") else (p.get("description", "") if isinstance(p, dict) else "")
            m = _re.search(r"DC=([A-Za-z0-9_-]+(?:,DC=[A-Za-z0-9_-]+)+)", text or "", _re.IGNORECASE)
            if m:
                # "DC=support,DC=htb" → "support.htb"
                parts = [seg.split("=", 1)[1] for seg in m.group(0).split(",")]
                return ".".join(parts).lower()
        return ""

    # ── Focused-attack interrupt API ────────────────────────────────

    def set_focused_attack(
        self,
        endpoints: List[str],
        *,
        reason:    str = "",
        source:    str = "",
        vhost:     str = "",
    ) -> None:
        """Signal every long-running pipeline that a specific attack
        chain has been identified and they MUST yield.

        Called by OSINT synthesis (and any other pipeline) the moment
        a concrete exploit chain becomes known.  Mechanical playbook
        runners (WebOrchestrator, vuln batch, ...) must call
        ``should_yield_to_focused_attack()`` between phases AND
        between tools, and abort when it returns True.

        Idempotent — additional endpoints are appended to the queue,
        but the reason/source only update on the first call.
        """
        accepted: List[str] = []
        for ep in endpoints or []:
            ep_s = (ep or "").strip()
            if ep_s and ep_s not in self.focused_attack_endpoints:
                accepted.append(ep_s)
        if not accepted and self.focused_attack_endpoints:
            return     # already set, nothing new to add
        if accepted:
            self.focused_attack_endpoints.extend(accepted)
        if not self.focused_attack_reason and reason:
            self.focused_attack_reason = reason[:400]
        if not self.focused_attack_source and source:
            self.focused_attack_source = source[:80]
        if vhost and not self.focused_attack_vhost:
            self.focused_attack_vhost = vhost.strip()[:120]
        if self.focused_attack_set_at == 0.0:
            self.focused_attack_set_at = time.monotonic()
        # Mirror into legacy intel for backward-compat consumers
        self.intel["focused_attack_mode"]      = True
        self.intel["focused_attack_endpoints"] = list(self.focused_attack_endpoints)
        if vhost:
            self.intel.setdefault("vhosts", [])
            if vhost not in self.intel["vhosts"]:
                self.intel["vhosts"].append(vhost)
        # Pin the decision so every subsequent LLM prompt sees it
        self.pin_insight(
            text=(
                f"FOCUSED ATTACK MODE engaged: {len(self.focused_attack_endpoints)} "
                f"specific endpoint(s) queued. Reason: {reason[:180]!r}"
            ),
            phase="all", severity="critical", source=source or "focused_attack",
        )
        # Reactive dispatch — focused endpoints ARE entry points
        try:
            self.detect_entry_points()
        except Exception:
            pass

    def should_yield_to_focused_attack(
        self, *, pipeline_name: str = "",
    ) -> bool:
        """Returns True if a mechanical playbook should ABORT now.

        Pipelines (WebOrchestrator, vuln batch, anything with a long
        sequential playbook) must call this between phases AND
        between tools, and exit cleanly when it returns True.

        ``pipeline_name`` is recorded for telemetry so we can verify
        in tests that the right pipelines yielded.
        """
        if not self.focused_attack_endpoints:
            return False
        # Caller may pass own name; default = "anonymous"
        self.pipelines_yielded.add(pipeline_name or "anonymous")
        return True

    def pop_focused_attack_endpoint(self) -> Optional[str]:
        """Take one endpoint off the queue for execution.

        Once all endpoints are consumed, ``should_yield_to_focused_attack``
        keeps returning True until ``clear_focused_attack`` is called
        — because the chain may have spawned new follow-on actions.
        """
        if not self.focused_attack_endpoints:
            return None
        return self.focused_attack_endpoints.pop(0)

    def clear_focused_attack(self) -> None:
        """Remove the focused-attack signal (e.g., after exploitation
        succeeded or the chain was exhausted)."""
        self.focused_attack_endpoints = []
        self.focused_attack_reason = ""
        self.focused_attack_source = ""
        self.focused_attack_set_at = 0.0
        self.focused_attack_vhost = ""
        self.intel.pop("focused_attack_mode", None)
        self.intel.pop("focused_attack_endpoints", None)

    def force_block(self, tool: str, args: str, duration_sec: float = 600.0) -> None:
        """Operator / supervisor manually trips the breaker."""
        cb_key = (tool, self._target_sig(args))
        st = self.tool_stats.get(cb_key) or ToolStats()
        st.blocked_until = time.monotonic() + duration_sec
        self.tool_stats[cb_key] = st

    def lift_block(self, tool: str, args: str = "") -> None:
        """Operator overrides — clear the block."""
        cb_key = (tool, self._target_sig(args))
        st = self.tool_stats.get(cb_key)
        if st:
            st.blocked_until = 0.0
            st.consecutive_empty = 0
            st.consecutive_dup = 0

    # ── Prompt rendering ────────────────────────────────────────────

    def render_for_prompt(self, *, max_chars: int = 4500) -> str:
        """Build the canonical prompt prelude.

        Includes (in order):
          1. The objective (always)
          2. Active engagement stats (target, elapsed, findings count)
          3. Pinned insights (most recent N) — the LLM's prior big-picture conclusions
          4. Recent actions (last N ReactSteps) — what just happened
          5. Failed actions (don't repeat these)
          6. Blocked tools (don't propose these)

        Budget-bounded: truncates sections from the bottom when limit hit.
        """
        out: List[str] = []

        # 1. Objective — always present, never truncated
        out.append("=== ENGAGEMENT OBJECTIVE ===")
        out.append(self.objective)
        out.append("")

        # 2. Stats + engagement budget status
        elapsed = int(time.monotonic() - self.started_at)
        elapsed_str = f"{elapsed // 60}m {elapsed % 60}s"
        budget_used_pct = (
            int(100 * self.total_invocations / self.invocation_budget)
            if self.invocation_budget > 0 else 0
        )
        win_marker = " | OBJECTIVE SATISFIED" if self.is_engagement_complete() else ""
        out.append(f"Target: {self.target}  |  Elapsed: {elapsed_str}  "
                    f"|  Findings: {len(self.findings)}  "
                    f"|  Pinned insights: {len(self.pinned)}  "
                    f"|  Tool calls: {self.total_invocations}/{self.invocation_budget} "
                    f"({budget_used_pct}%){win_marker}")
        # Warn the LLM when budget is running out so it prioritises
        # high-value actions over enumeration.
        if budget_used_pct >= 80:
            out.append(
                f"!! TOOL BUDGET WARNING: {budget_used_pct}% used — "
                f"only the highest-value actions should be issued from "
                f"here.  Generic enumeration must stop."
            )
        if self.is_engagement_complete():
            out.append(
                "*** OBJECTIVE STRUCTURALLY SATISFIED: shell + flag(s) "
                "captured.  Stop active testing; pivot to evidence "
                "collection and report generation."
            )
        # Focused-attack signal — every prompt should see this prominently
        # so the LLM does not propose generic enumeration when a specific
        # chain is already queued.
        if self.focused_attack_endpoints:
            out.append(
                f">>> FOCUSED ATTACK MODE — "
                f"{len(self.focused_attack_endpoints)} specific endpoint(s) "
                f"queued for direct exploitation.  Reason: "
                f"{self.focused_attack_reason[:200]}.  "
                f"DO NOT propose generic enumeration; consume the queued "
                f"endpoints and observe results."
            )
            for ep in self.focused_attack_endpoints[:6]:
                out.append(f"    → {ep[:200]}")
        out.append("")

        # 3. Pinned insights (newest first)
        if self.pinned:
            out.append("=== KEY INSIGHTS (carry these forward) ===")
            for ins in self.pinned[-PINNED_INSIGHTS_FOR_PROMPT:][::-1]:
                marker = ("!!!" if ins.severity == "critical"
                           else "!!" if ins.severity == "important"
                           else " *")
                out.append(f"{marker} [{ins.phase}] {ins.text}")
            out.append("")

        # 4. Recent ReAct steps
        if self.transcript:
            out.append("=== RECENT ACTIONS (observation = first 220 chars) ===")
            for st in list(self.transcript)[-RECENT_STEPS_FOR_PROMPT:]:
                out.append(st.render())
            out.append("")

        # 5. Failed actions — succinct list
        if self.failed_actions:
            out.append("=== ACTIONS ALREADY TRIED (do not repeat) ===")
            for tool, args in list(self.failed_actions)[-12:]:
                out.append(f"  ✗ {tool} {args[:80]}")
            out.append("")

        # 6. Blocked tools
        blocked = self._render_blocked_tools()
        if blocked:
            out.append("=== CIRCUIT-BREAKER: BLOCKED TOOLS (must pivot) ===")
            out.extend(blocked)
            out.append("")

        result = "\n".join(out)
        if len(result) > max_chars:
            # Hard-truncate from the bottom of sections 4-6 (preserve 1-3).
            cut = result.rfind("\n=== ", 0, max_chars)
            if cut > 0:
                result = result[:cut] + "\n[context truncated to fit prompt budget]"
            else:
                result = result[:max_chars] + "\n[truncated]"
        return result

    # ── Internals ───────────────────────────────────────────────────

    def _render_blocked_tools(self) -> List[str]:
        now = time.monotonic()
        out: List[str] = []
        for (tool, target_sig), st in self.tool_stats.items():
            if st.blocked_until and now < st.blocked_until:
                remain = int(st.blocked_until - now)
                out.append(f"  ⛔ {tool} {target_sig} (blocked for {remain}s)")
            elif st.consecutive_dup >= DUP_OUTPUT_THRESHOLD:
                out.append(f"  ⛔ {tool} {target_sig} "
                            f"(same dead-end output {st.consecutive_dup}x)")
        return out

    @staticmethod
    def _threshold_for(tool: str) -> int:
        return CIRCUIT_BREAKER_THRESHOLDS.get(tool.lower(), 5)

    @staticmethod
    def _target_sig(args: str) -> str:
        """Reduce args to a stable signature for tool-stats keying.

        Strategy: keep the first whitespace-separated token, drop only
        query string + fragment.  Different paths on the SAME host get
        their own counters (legitimate enumeration like /admin /login
        /backup is allowed); the dedup-by-output-signature path catches
        the broader "curl-floods many URLs all returning the same 404"
        pattern, so we don't need the per-host collapse.
        """
        if not args:
            return ""
        first = args.split()[0]
        # Drop query and fragment if present
        for sep in ("?", "#"):
            if sep in first:
                first = first.split(sep, 1)[0]
        return first[:120]

    @staticmethod
    def _signature(text: str) -> str:
        """SHA-256 of the first 512 chars (cheap dedup key for outputs)."""
        return hashlib.sha256((text or "")[:512].encode("utf-8", errors="ignore")
                              ).hexdigest()[:16]

    @staticmethod
    def _is_productive(observation: str, tool: str) -> bool:
        """Heuristic for whether an observation is meaningful enough to
        reset the empty-counter.

        Conservative: short outputs, generic 404s, "connection refused",
        and empty results count as unproductive.
        """
        if not observation:
            return False
        body = observation.strip()
        if len(body) < 40:
            return False
        bodylc = body.lower()
        dead_markers = (
            "404 not found", "could not resolve host", "connection refused",
            "no exploits found", "no matching template",
            "0 paths found", "no vulnerable plugins",
            "moved permanently",  # often redirects to /login.html etc — useful sometimes
        )
        # 404 NOT FOUND specifically is dead unless tool is web-fuzzer
        # (gobuster/ffuf — they REPORT 404s as their primary output,
        # interesting findings show up as 200/301/302/401/403).
        web_fuzzers = ("gobuster", "ffuf", "wfuzz", "feroxbuster", "dirb")
        if tool.lower() in web_fuzzers:
            # Productive only if there's a non-404 line in the output
            non_404_codes = ("status: 200", "status: 301", "status: 302",
                              "status: 401", "status: 403", "[200 ", "[301 ",
                              "[302 ", "[401 ", "[403 ")
            return any(code in bodylc for code in non_404_codes)
        # Generic dead markers — if the output is JUST one of these
        if any(m in bodylc for m in dead_markers) and len(body) < 200:
            return False
        return True

    @staticmethod
    def _default_objective(target: str) -> str:
        return (
            f"OBJECTIVE: Compromise host {target} — gain initial access, "
            "escalate privilege, capture any flags/credentials/sensitive data, "
            "and document the kill chain.  PRIORITIES: (1) move toward "
            "concrete access not generic enumeration; (2) confirm exploitable "
            "leads with one targeted command before broad fuzzing; "
            "(3) PIVOT immediately when intel says a high-confidence chain "
            "exists; (4) do NOT cycle the same tool against the same target "
            "if prior calls produced no useful output."
        )

    # ── Persistence (snapshot for /sessions/{id}/checkpoint) ────────

    def snapshot(self) -> Dict[str, Any]:
        return {
            "session_id":     self.session_id,
            "target":         self.target,
            "objective":      self.objective,
            "intel_keys":     sorted(self.intel.keys()),
            "transcript":     [t.__dict__ for t in self.transcript],
            "pinned":         [p.__dict__ for p in self.pinned],
            "failed_actions": list(self.failed_actions),
            "findings_count": len(self.findings),
            "tool_stats":     {
                f"{k[0]}|{k[1]}": {
                    "invocations":      v.invocations,
                    "productive":       v.productive,
                    "consecutive_empty": v.consecutive_empty,
                    "blocked":          v.blocked_until > time.monotonic(),
                }
                for k, v in self.tool_stats.items()
            },
        }


# ─────────────────────────────────────────────────────────────────────
#  Session registry — lets subagents discover the active context.
# ─────────────────────────────────────────────────────────────────────
#
# Subagents are spawned by MasterAgent and only receive (session_id,
# target, broadcast, db) in their constructor.  We register the
# EngagementContext under session_id so any subagent can look it up
# without changing the constructor signature.
#
# Thread-safety: ARGUS is asyncio single-threaded so a plain dict is
# fine.  Each session registers exactly once at engagement start and
# unregisters at completion.

_ACTIVE_CONTEXTS: Dict[str, "EngagementContext"] = {}


def register_context(ctx: "EngagementContext") -> None:
    """Register the active context for this session.

    Idempotent — replacing an existing entry is allowed (the MasterAgent
    may re-instantiate during a hot resume).
    """
    _ACTIVE_CONTEXTS[ctx.session_id] = ctx


def get_context(session_id: str) -> Optional["EngagementContext"]:
    """Return the EngagementContext for ``session_id`` if any.

    Subagents call this from ``collect_tool`` to consult the circuit
    breaker.  Returns ``None`` if no context is registered — callers
    must tolerate that for backward compatibility with code paths that
    haven't migrated yet.
    """
    return _ACTIVE_CONTEXTS.get(session_id)


def unregister_context(session_id: str) -> Optional["EngagementContext"]:
    """Remove and return the context for ``session_id`` (or ``None``)."""
    return _ACTIVE_CONTEXTS.pop(session_id, None)


# ═════════════════════════════════════════════════════════════════════
#  Tool-Justification Layer — "necessary basis" gate
# ═════════════════════════════════════════════════════════════════════
#
# The circuit-breaker prevents runaway loops AFTER a tool has been
# called too many times.  The justification layer prevents the call
# in the first place when there is no STATE-BASED REASON to make it.
#
# A "necessary basis" for invoking a tool means at least one of:
#   * a discovered service / open port that this tool targets
#     (e.g. wpscan only after WordPress is detected, enum4linux only
#     when 445 is open)
#   * a discovered CVE / exploit module that this tool exploits
#     (e.g. msfconsole only when a specific exploit module is known)
#   * an operator-supplied directive
#   * a trigger-fired action (which already carries its own rationale)
#
# Tools without a registered precondition default to "permitted with
# warning" (information gathering tools like nmap, dig, curl-info).
# Aggressive / specific tools without preconditions are REFUSED.

@dataclass
class ToolPrecondition:
    """Declarative gate on whether a tool may run given current state."""
    tool: str
    # Port-based: at least one of these ports must be open
    requires_open_port: List[int] = field(default_factory=list)
    # Service-banner regex (case-insensitive) — must match in any service
    requires_service_re: str = ""
    # Intel keys that must be truthy (e.g. "shell_access" for post-exploit tools)
    requires_intel_key: str = ""
    # Args must contain at least one of these substrings (lower-cased match)
    requires_args_contains: List[str] = field(default_factory=list)
    # Custom callable: takes (ctx, args) → bool
    custom_check: Optional[Any] = None
    # Tier: "discovery" (permissive default-allow) | "targeted" (must match) |
    #       "aggressive" (refuse without strong basis)
    tier: str = "targeted"
    # Human-readable refusal message
    rationale: str = ""


# Default precondition registry.  Keys are tool basenames (lowercased,
# no path/options).  Tools NOT in this registry get the implicit
# permissive default ("discovery" tier — allowed if invocations are
# within cap).
DEFAULT_TOOL_PRECONDITIONS: Dict[str, ToolPrecondition] = {
    # ── Web-app testing — must have HTTP/HTTPS service ─────────────
    "wpscan": ToolPrecondition(
        tool="wpscan",
        requires_service_re=r"wordpress|wp-content|wp-login|wp-json",
        tier="targeted",
        rationale="wpscan only runs after WordPress is detected in service fingerprinting",
    ),
    "nikto": ToolPrecondition(
        tool="nikto",
        requires_open_port=[80, 443, 8080, 8443, 8000, 8888],
        requires_service_re=r"http|https|nginx|apache|tomcat|iis|lighttpd",
        tier="targeted",
        rationale="nikto requires a known HTTP/HTTPS service",
    ),
    "gobuster": ToolPrecondition(
        tool="gobuster",
        requires_open_port=[80, 443, 8080, 8443, 8000, 8888],
        requires_service_re=r"http|nginx|apache|tomcat|iis|lighttpd|jetty|node|express",
        requires_args_contains=["http://", "https://", "-u "],
        tier="targeted",
        rationale="gobuster requires a target URL and a confirmed web server",
    ),
    "ffuf": ToolPrecondition(
        tool="ffuf",
        requires_args_contains=["http://", "https://", "-u "],
        tier="targeted",
        rationale="ffuf requires a target URL",
    ),
    "wfuzz": ToolPrecondition(
        tool="wfuzz",
        requires_args_contains=["http://", "https://"],
        tier="targeted",
        rationale="wfuzz requires a target URL",
    ),
    "feroxbuster": ToolPrecondition(
        tool="feroxbuster",
        requires_args_contains=["http://", "https://", "-u "],
        tier="targeted",
        rationale="feroxbuster requires a target URL",
    ),
    "dirb": ToolPrecondition(
        tool="dirb",
        requires_args_contains=["http://", "https://"],
        tier="targeted",
        rationale="dirb requires a target URL",
    ),
    "dalfox": ToolPrecondition(
        tool="dalfox",
        requires_args_contains=["http://", "https://"],
        tier="targeted",
        rationale="dalfox (XSS) needs a target URL with parameters",
    ),
    "sqlmap": ToolPrecondition(
        tool="sqlmap",
        requires_args_contains=["-u ", "--url", "-r ", "--data"],
        tier="aggressive",
        rationale="sqlmap requires a specific URL/request with parameters; do not run blind",
    ),

    # ── SMB / Windows file-share tools — port 445 must be open ─────
    "enum4linux": ToolPrecondition(
        tool="enum4linux",
        requires_open_port=[139, 445],
        tier="targeted",
        rationale="enum4linux requires SMB port 139 or 445 open",
    ),
    "enum4linux-ng": ToolPrecondition(
        tool="enum4linux-ng",
        requires_open_port=[139, 445],
        tier="targeted",
        rationale="enum4linux-ng requires SMB port 139 or 445 open",
    ),
    "smbclient": ToolPrecondition(
        tool="smbclient",
        requires_open_port=[139, 445],
        tier="targeted",
        rationale="smbclient requires SMB port 139 or 445 open",
    ),
    "smbmap": ToolPrecondition(
        tool="smbmap",
        requires_open_port=[139, 445],
        tier="targeted",
        rationale="smbmap requires SMB port 139 or 445 open",
    ),
    "rpcclient": ToolPrecondition(
        tool="rpcclient",
        requires_open_port=[135, 139, 445],
        tier="targeted",
        rationale="rpcclient requires MS-RPC or SMB ports open",
    ),

    # ── AD / LDAP / Kerberos ───────────────────────────────────────
    "ldapsearch": ToolPrecondition(
        tool="ldapsearch",
        requires_open_port=[389, 636, 3268, 3269],
        tier="targeted",
        rationale="ldapsearch requires LDAP/LDAPS port open",
    ),
    "kerbrute": ToolPrecondition(
        tool="kerbrute",
        requires_open_port=[88],
        tier="aggressive",
        rationale="kerbrute requires Kerberos port 88 open AND a userlist",
    ),
    "impacket-getnpusers": ToolPrecondition(
        tool="impacket-getnpusers",
        requires_open_port=[88, 389],
        tier="targeted",
        rationale="GetNPUsers (AS-REP roast) requires Kerberos + AD",
    ),
    "impacket-getuserspns": ToolPrecondition(
        tool="impacket-getuserspns",
        requires_open_port=[88, 389],
        tier="targeted",
        rationale="GetUserSPNs (Kerberoast) requires Kerberos + AD",
    ),
    "evil-winrm": ToolPrecondition(
        tool="evil-winrm",
        requires_open_port=[5985, 5986],
        requires_args_contains=["-u ", "-p ", "-i "],
        tier="aggressive",
        rationale="evil-winrm requires WinRM ports open AND credentials",
    ),

    # ── Database probes — port + (sometimes) credentials ───────────
    "mysql": ToolPrecondition(
        tool="mysql",
        requires_open_port=[3306],
        tier="targeted",
        rationale="mysql client requires port 3306",
    ),
    "psql": ToolPrecondition(
        tool="psql",
        requires_open_port=[5432],
        tier="targeted",
        rationale="psql requires PostgreSQL port 5432",
    ),
    "mongo": ToolPrecondition(
        tool="mongo",
        requires_open_port=[27017, 27018],
        tier="targeted",
        rationale="mongo client requires MongoDB port open",
    ),
    "redis-cli": ToolPrecondition(
        tool="redis-cli",
        requires_open_port=[6379],
        tier="targeted",
        rationale="redis-cli requires port 6379 open",
    ),
    "impacket-mssqlclient": ToolPrecondition(
        tool="impacket-mssqlclient",
        requires_open_port=[1433],
        tier="targeted",
        rationale="mssqlclient requires MSSQL port 1433 open",
    ),

    # ── Other targeted protocols ───────────────────────────────────
    "showmount": ToolPrecondition(
        tool="showmount",
        requires_open_port=[2049],
        tier="targeted",
        rationale="showmount requires NFS port 2049 open",
    ),
    "snmpwalk": ToolPrecondition(
        tool="snmpwalk",
        requires_open_port=[161],
        tier="targeted",
        rationale="snmpwalk requires SNMP port 161 open",
    ),
    "snmpget": ToolPrecondition(
        tool="snmpget",
        requires_open_port=[161],
        tier="targeted",
        rationale="snmpget requires SNMP port 161 open",
    ),

    # ── Aggressive / brute-force — require strong basis ────────────
    "hydra": ToolPrecondition(
        tool="hydra",
        requires_args_contains=["-l ", "-L ", "-p ", "-P "],
        tier="aggressive",
        rationale="hydra requires explicit user/password (list) arguments AND a known service target",
    ),
    "patator": ToolPrecondition(
        tool="patator",
        requires_args_contains=["user=", "password=", "host="],
        tier="aggressive",
        rationale="patator requires explicit user/password/host arguments",
    ),
    "medusa": ToolPrecondition(
        tool="medusa",
        requires_args_contains=["-u ", "-U ", "-p ", "-P "],
        tier="aggressive",
        rationale="medusa requires user/password arguments",
    ),
    "msfconsole": ToolPrecondition(
        tool="msfconsole",
        requires_args_contains=["use ", "exploit/", "auxiliary/", "post/"],
        tier="aggressive",
        rationale="msfconsole must specify a concrete module (exploit/auxiliary/post)",
    ),

    # ── Post-exploit tools — require shell ─────────────────────────
    "linpeas": ToolPrecondition(
        tool="linpeas",
        requires_intel_key="shell_access",
        tier="aggressive",
        rationale="linpeas needs a Linux shell foothold first",
    ),
    "winpeas": ToolPrecondition(
        tool="winpeas",
        requires_intel_key="shell_access",
        tier="aggressive",
        rationale="winpeas needs a Windows shell foothold first",
    ),
    "mimikatz": ToolPrecondition(
        tool="mimikatz",
        requires_intel_key="shell_access",
        tier="aggressive",
        rationale="mimikatz needs a Windows shell with high privileges",
    ),
    "bloodhound": ToolPrecondition(
        tool="bloodhound",
        requires_open_port=[88, 389],
        tier="targeted",
        rationale="BloodHound requires AD environment + ideally creds for SharpHound",
    ),

    # ── Search/info tools — broad but need a search term ───────────
    "searchsploit": ToolPrecondition(
        tool="searchsploit",
        requires_args_contains=[" "],   # any non-empty search term
        tier="discovery",
        rationale="searchsploit requires a search term",
    ),

    # ── Discovery — broadly allowed ────────────────────────────────
    "nmap":     ToolPrecondition(tool="nmap",     tier="discovery"),
    "rustscan": ToolPrecondition(tool="rustscan", tier="discovery"),
    "masscan":  ToolPrecondition(tool="masscan",  tier="discovery"),
    "dig":      ToolPrecondition(tool="dig",      tier="discovery"),
    "host":     ToolPrecondition(tool="host",     tier="discovery"),
    "nslookup": ToolPrecondition(tool="nslookup", tier="discovery"),
    "whois":    ToolPrecondition(tool="whois",    tier="discovery"),
    "ping":     ToolPrecondition(tool="ping",     tier="discovery"),
    "traceroute": ToolPrecondition(tool="traceroute", tier="discovery"),
    "curl":     ToolPrecondition(tool="curl",     tier="discovery"),
    "wget":     ToolPrecondition(tool="wget",     tier="discovery"),
    "whatweb":  ToolPrecondition(tool="whatweb",  tier="discovery"),
    "wafw00f":  ToolPrecondition(tool="wafw00f",  tier="discovery"),
    "nuclei":   ToolPrecondition(tool="nuclei",   tier="targeted",
                                  requires_args_contains=["-u ", "-l ", "-target"],
                                  rationale="nuclei requires a target URL/host argument"),
}


def register_precondition(precond: ToolPrecondition) -> None:
    """Plug-in hook for per-engagement tool gating overrides."""
    DEFAULT_TOOL_PRECONDITIONS[precond.tool.lower()] = precond


def get_precondition(tool: str) -> Optional[ToolPrecondition]:
    return DEFAULT_TOOL_PRECONDITIONS.get((tool or "").lower())


def check_command_warranted(cmd_line: str, ctx: "EngagementContext"
                              ) -> Tuple[bool, str]:
    """Validate a full shell command line (e.g. from intel['next_commands']).

    Splits off the first whitespace-token as the tool and feeds the
    rest to ``check_tool_warranted``.  Lets the master agent filter
    LLM-supplied or trigger-supplied commands BEFORE queueing them
    for dispatch.
    """
    cmd_line = (cmd_line or "").strip()
    if not cmd_line:
        return False, "empty command"
    parts = cmd_line.split(None, 1)
    tool = parts[0]
    args = parts[1] if len(parts) > 1 else ""
    return check_tool_warranted(tool, args, ctx)


def check_tool_warranted(tool: str, args: str, ctx: "EngagementContext"
                          ) -> Tuple[bool, str]:
    """Return (warranted, reason).

    A tool is "warranted" iff its precondition is satisfied OR no
    precondition is registered AND it's not an aggressive verb.
    """
    if not tool:
        return False, "no tool name"
    tool_lc = tool.lower()
    # Strip path / leading subprocess.run(...) wrapping
    base = tool_lc.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    pre = get_precondition(base) or get_precondition(tool_lc)
    if pre is None:
        # Unknown tool — discovery-tier default, allowed
        return True, ""

    # ── Tier gate ──
    # "discovery" tools allowed if args provided
    if pre.tier == "discovery":
        if pre.requires_args_contains and not _args_contain_any(args, pre.requires_args_contains):
            return False, (
                f"{tool} ({pre.tier} tier) needs args containing one of "
                f"{pre.requires_args_contains}; got: {args[:80]!r}. "
                + (pre.rationale or "")
            )
        return True, ""

    # ── Targeted / aggressive: every declared requirement must hold ──
    if pre.requires_open_port:
        if not any(_port_open_ctx(ctx, p) for p in pre.requires_open_port):
            return False, (
                f"{tool} requires one of ports {pre.requires_open_port} open, "
                f"but ports {list(ctx.open_ports)} are open. "
                + (pre.rationale or "")
            )
    if pre.requires_service_re:
        import re as _re
        services = ctx.services or {}
        hit = False
        for _p, svc in services.items():
            if isinstance(svc, dict):
                hay = " ".join(str(svc.get(k, "")) for k in
                                ("service", "product", "version", "banner",
                                  "extrainfo", "info")).lower()
                if _re.search(pre.requires_service_re, hay, _re.IGNORECASE):
                    hit = True
                    break
        if not hit:
            return False, (
                f"{tool} requires a service matching r{pre.requires_service_re!r} "
                f"in fingerprinted services, but none matched. "
                + (pre.rationale or "")
            )
    if pre.requires_intel_key:
        if not ctx.intel.get(pre.requires_intel_key):
            return False, (
                f"{tool} requires intel.{pre.requires_intel_key} to be truthy "
                f"(currently {ctx.intel.get(pre.requires_intel_key)!r}). "
                + (pre.rationale or "")
            )
    if pre.requires_args_contains:
        if not _args_contain_any(args, pre.requires_args_contains):
            return False, (
                f"{tool} requires args to contain one of "
                f"{pre.requires_args_contains}; got: {args[:80]!r}. "
                + (pre.rationale or "")
            )
    if pre.custom_check is not None:
        try:
            ok = bool(pre.custom_check(ctx, args))
        except Exception:
            ok = False
        if not ok:
            return False, (
                f"{tool} failed its custom precondition check. "
                + (pre.rationale or "")
            )
    return True, ""


def _args_contain_any(args: str, needles: Iterable[str]) -> bool:
    a = (args or "").lower()
    return any((n or "").lower() in a for n in needles)


def _port_open_ctx(ctx: "EngagementContext", port: int) -> bool:
    """Reuse port-check from EngagementContext without circular import."""
    ports = ctx.open_ports or []
    for p in ports:
        try:
            if int(p) == int(port):
                return True
        except Exception:
            continue
    # Also check services dict (some pipelines populate services without open_ports)
    services = ctx.services or {}
    for p in services.keys():
        try:
            if int(p) == int(port):
                return True
        except Exception:
            continue
    return False


__all__ = [
    "EngagementContext", "ReactStep", "PinnedInsight", "ToolStats",
    "CIRCUIT_BREAKER_THRESHOLDS", "PER_TOOL_INVOCATION_CAPS",
    "DEFAULT_ENGAGEMENT_INVOCATION_BUDGET",
    "register_context", "get_context", "unregister_context",
    # Justification layer
    "ToolPrecondition", "DEFAULT_TOOL_PRECONDITIONS",
    "register_precondition", "get_precondition",
    "check_tool_warranted", "check_command_warranted",
]
