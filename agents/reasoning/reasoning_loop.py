"""
agents/reasoning/reasoning_loop.py

The core reasoning engine that replaces the linear phase executor.

Loop: Observe → Interpret → Hypothesize → Prioritize → Execute → Validate → Update → Repeat

Key design decisions
--------------------
- Backward compatible: the loop delegates ALL tool execution to the existing
  83 subagents via master_agent._dispatch_to_agent(). No subagent code changes.
- Pause/resume: check_pause_fn is called at every iteration boundary; state
  is fully serialisable to the existing SessionCheckpoint schema.
- Safety cap: MAX_ITERATIONS prevents runaway loops.
- Specialist activation: specialist agents (AD, Cloud, Container) are only
  dispatched when evidence warrants them — not unconditionally.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, TYPE_CHECKING


# ── Meta-agent review timeouts ──────────────────────────────────────────────
# The Expert (RedTeamExpertAgent) and MasterChecker pre/post-phase reviews
# each fire one LLM call.  On slow local models (xploiter/the-xploiter,
# deepseek-v3.1:671b-cloud on CPU) these can take 5-8 minutes each and would
# BLOCK every phase transition.  These ceilings let the actual scan continue
# if a meta-review stalls — the review is advisory, the scan is essential.
#
# Override with env vars when running on a fast model (e.g. GPU).  Setting
# them to a very large number (e.g. 99999) effectively disables the cap.
_META_PRE_TIMEOUT  = int(os.environ.get("EXPERT_PREREVIEW_TIMEOUT_SEC",  "120"))
_META_POST_TIMEOUT = int(os.environ.get("EXPERT_POSTREVIEW_TIMEOUT_SEC", "120"))
# F8 — hard backstop on the number of distinct phase meta-review passes per
# engagement (each pass = up to 4 meta-LLM calls).  Generous so a normal run
# (recon/osint/vuln/web/exploit/privesc/lateral/post ≈ 8) is never starved,
# but a pathological loop can't spin out ~65 corrections.
_MAX_META_REVIEW_PASSES = int(os.environ.get("ARGUS_MAX_META_REVIEW_PASSES", "12"))

# ── Hard wall-clock backstop for the reasoning loop ─────────────────────────
# The stall-convergence logic ends a *stuck* engagement within ~10 cheap
# iterations, but this is the ultimate ceiling for pathological cases where
# evidence keeps shifting slightly without ever advancing toward a foothold
# (so the stall counter never trips) — e.g. the 2h42m / 266-LLM-call / 0-shell
# spin observed against the Go/IPFS/InfluxDB target.  Generous by default;
# override with the env var.  Set very large (e.g. 999999) to disable.
_MAX_LOOP_SECONDS = int(os.environ.get("ARGUS_MAX_LOOP_SECONDS", "3600"))


async def _meta_review_with_timeout(coro, *, label: str, timeout: int,
                                    emit_reasoning):
    """Run a meta-agent review with a hard ceiling.

    On TimeoutError, cancel the coroutine, emit a clear reasoning line,
    and return None so the caller proceeds with the actual scan instead
    of blocking on a slow model.  All other exceptions are re-raised so
    the existing try/except handlers around each call site keep working.
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        await emit_reasoning(
            f"[meta] {label} timed out after {timeout}s — proceeding without it. "
            f"Set {('EXPERT_PREREVIEW_TIMEOUT_SEC' if 'pre' in label else 'EXPERT_POSTREVIEW_TIMEOUT_SEC')}=N "
            f"to allow a slower model."
        )
        return None

if TYPE_CHECKING:
    from agents.master_agent import MasterAgent

from agents.reasoning.hypothesis_engine  import HypothesisEngine, Hypothesis
from agents.reasoning.attack_planner     import AttackPlanner, RankedAttackPath
from agents.reasoning.decision_engine    import DecisionEngine, JustifiedAction
from agents.reasoning.negative_memory    import NegativeMemory
from agents.reasoning.question_engine    import QuestionEngine


class ReasoningLoop:
    """
    Hypothesis-driven reasoning loop.

    Parameters
    ----------
    master_agent:
        Reference to the MasterAgent instance (forward reference used here).
        Access to: _intel, think_json, _dispatch_to_agent, broadcast, etc.
    session_id, target:
        Active session context.
    hypothesis_engine, decision_engine, attack_planner, negative_memory:
        Pre-constructed reasoning components.
    emit_fn:
        Async broadcast callable for WebSocket events.
    check_pause_fn:
        Async callable → bool. Returns True if operator has requested pause.
    save_checkpoint_fn:
        Async callable(iteration) → None. Saves state to MongoDB.
    """

    MAX_ITERATIONS:         int   = 50     # Safety cap — stops infinite loops
    CONVERGENCE_THRESHOLD:  float = 0.95   # Stop early if top path confidence ≥ this
    CHECKPOINT_EVERY:       int   = 5      # Save checkpoint every N iterations
    # ── Stall / convergence control ──────────────────────────────────────
    # The two planning LLM calls (hypothesize → "TARGET STATE", prioritize →
    # "CURRENT EVIDENCE") cost ~40–55s EACH and ran every iteration regardless
    # of whether anything changed — turning a stuck engagement into a 2h+
    # spin of identical web enumeration.  These thresholds make the loop:
    #   * skip those calls (reuse cache) while evidence is unchanged,
    #   * force ONE genuine exploitation push when stuck,
    #   * then converge so the testing cycle actually completes.
    STALL_ESCALATE_AT:      int   = 5      # No compromise-progress iters → force exploit escalation
    STALL_BREAK_AT:         int   = 10     # No compromise-progress iters (post-escalation) → converge + finish
    MAX_LOOP_SECONDS:       int   = _MAX_LOOP_SECONDS  # Hard wall-clock ceiling (env: ARGUS_MAX_LOOP_SECONDS)

    def __init__(
        self,
        master_agent:        "MasterAgent",
        session_id:          str,
        target:              str,
        intel:               dict,
        hypothesis_engine:   HypothesisEngine,
        decision_engine:     DecisionEngine,
        attack_planner:      AttackPlanner,
        negative_memory:     NegativeMemory,
        emit_fn:             Callable[..., Any],
        check_pause_fn:      Callable[[], Coroutine],
        save_checkpoint_fn:  Callable[[int], Coroutine],
    ) -> None:
        self._master          = master_agent
        self._session_id      = session_id
        self._target          = target
        self._intel           = intel
        self._hypothesis_eng  = hypothesis_engine
        self._decision_eng    = decision_engine
        self._attack_planner  = attack_planner
        self._neg_memory      = negative_memory
        self._emit            = emit_fn
        self._check_pause     = check_pause_fn
        self._save_checkpoint = save_checkpoint_fn

        self._iteration:      int                     = 0
        self._hypotheses:     List[Hypothesis]        = []
        self._ranked_paths:   List[RankedAttackPath]  = []
        self._last_action:    Optional[JustifiedAction] = None
        self._journal:        List[str]               = []
        # Tracks last validated hypothesis node for graph edge chaining
        self._last_validated_node_id: Optional[str]  = None

        # Web-intelligence pivot agent — lazy-init on first stuck-state event
        self._web_intel: Optional[Any] = None

        # ── Improvement #17 — reasoning trace ("Why?" panel) ──────────
        try:
            from agents.reasoning.reasoning_trace import ReasoningTrace
            self._reasoning_trace = ReasoningTrace(session_id=session_id)
            # Surface to master so other components and the API layer can
            # query the chain by ref.
            try:
                master_agent.reasoning_trace = self._reasoning_trace  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception:
            self._reasoning_trace = None
        # Per-iteration step ids for parent-pointer chaining.
        self._last_select_step_id:   Optional[str] = None
        self._last_validate_step_id: Optional[str] = None

        # ── Improvement #4 — unified decision loop ────────────────────────
        # Tracks which phase units have already been dispatched so the
        # cross-phase audit (_consider_pivots) is idempotent.  Keys are the
        # phase slug strings ("recon", "vuln_id", "web_testing", "exploit",
        # "privesc", "lateral_movement", etc.).  Values are the iteration
        # number when dispatch happened.
        self._phases_dispatched: Dict[str, int] = {}

        # ── Meta-agent review budget (F8) ──────────────────────────────────
        # Each distinct phase is meta-reviewed ONCE; forced re-runs (e.g. the
        # stall-escalation exploit re-dispatch) skip the 4-call review storm.
        # A hard cap backstops a pathological loop.  Keeps meta-agents informing
        # instead of flooding ~65 corrections / engagement.
        self._meta_reviewed_phases: set = set()
        self._meta_review_passes:   int = 0

        # ── Loop-convergence / stall detection ────────────────────────────
        # ``_full_fp``        — fingerprint of ALL meaningful evidence; when it
        #                       is unchanged the loop is spinning and the two
        #                       expensive planning LLM calls are skipped
        #                       (cached hypotheses / paths reused instead).
        # ``_breakthrough_fp``— fingerprint of COMPROMISE progress only (shell,
        #                       creds, vulns, flags, cves, loot).  Drives
        #                       escalation + convergence: pure web-path growth
        #                       does NOT reset it, so a fuzzer that keeps
        #                       finding 404s can no longer keep the loop alive
        #                       forever without advancing toward a foothold.
        self._full_fp:            Optional[str] = None
        self._breakthrough_fp:    Optional[str] = None
        self._no_breakthrough:    int           = 0
        self._stall_escalated:    bool          = False

        # ── Question Engine (3-layer extraction + discovery pass) ─────────
        self._question_engine = QuestionEngine(
            master_agent = master_agent,
            session_id   = session_id,
            target       = target,
            emit_fn      = emit_fn,
        )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> dict:
        """
        Execute the reasoning loop until objective achieved, max iterations
        reached, pause requested, or stop requested.

        Returns the final intel dict so MasterAgent can use it for reporting.
        """
        await self._emit_status("Reasoning loop starting", "THINKING")
        await self._emit_loop_event("loop_start", {
            "target": self._target,
            "max_iterations": self.MAX_ITERATIONS,
        })
        # Seed the MissionControl plan skeleton with phase markers
        for _sid, _label, _ph in [
            ("bootstrap_recon",  "🔍 Reconnaissance",         "recon"),
            ("hypothesize",      "🧠 Hypothesis Generation",   "exploit"),
            ("prioritize",       "📊 Attack Path Ranking",     "exploit"),
            ("execute_actions",  "⚡ Hypothesis Execution",    "exploit"),
            ("validate",         "✅ Validation & Scoring",    "exploit"),
            ("reporting",        "📄 Report Generation",       "reporting"),
        ]:
            await self._emit_plan_step(_sid, _label, "pending", "", _ph)
        # Emit target graph node so the attack graph has a root
        await self._emit_graph_node(
            node_id   = f"target_{self._target.replace('.', '_')}",
            node_type = "host",
            label     = self._target,
            phase     = "recon",
            severity  = "info",
            metadata  = {"ip": self._target, "role": "target"},
        )

        # ── Broadcast engagement context + objectives to frontend ───────────
        eng_ctx  = self._intel.get("engagement_context") or {}
        eng_type = eng_ctx.get("engagement_type", "pentest")
        objectives = eng_ctx.get("objectives") or self._intel.get("ctf_objectives") or []

        if objectives:
            await self._emit({
                "type":       "ctf_objectives_set",   # reuse same event name for compatibility
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "objectives":      objectives,
                    "total":           len(objectives),
                    "engagement_type": eng_type,
                    "title":           eng_ctx.get("title", ""),
                },
            })
            emoji = {"ctf": "🏁", "forensics": "🔎", "network_analysis": "📡",
                     "malware_analysis": "🦠", "compliance": "📋"}.get(eng_type, "🎯")
            await self._emit_reasoning(
                f"{emoji} {eng_type.upper()}: {len(objectives)} objectives loaded"
            )
            # Seed plan steps per section group
            sections_seen: set = set()
            for i, obj in enumerate(objectives):
                sec = obj.get("section", "") if isinstance(obj, dict) else ""
                if sec and sec not in sections_seen:
                    sections_seen.add(sec)
                    await self._emit_plan_step(
                        f"obj_section_{i}", f"{emoji} {sec[:50]}", "pending", "", "exploit"
                    )

        # ── Load objectives into QuestionEngine ──────────────────────────
        # Restore any previously answered questions from checkpoint first
        self._question_engine.load_from_intel(self._intel)
        # Register all unanswered objectives as questions
        _qe_objectives = (
            (self._intel.get("engagement_context") or {}).get("objectives")
            or self._intel.get("ctf_objectives")
            or []
        )
        for _qi, _obj in enumerate(_qe_objectives):
            _q_text = (
                (_obj.get("task") or _obj.get("question") or str(_obj))
                if isinstance(_obj, dict) else str(_obj)
            )
            self._question_engine.add_question(_q_text, objective_idx=_qi)

        # Restore from checkpoint if reasoning_journal already populated
        self._journal = list(self._intel.get("reasoning_journal", []))
        self._decision_eng.set_score(self._intel.get("action_score", 0))

        # Restore attack planner state if checkpoint has paths
        stored_paths = self._intel.get("ranked_attack_paths", [])
        if stored_paths:
            self._attack_planner.restore_from_dicts(stored_paths)

        # [15] Restore the phase-dispatch ledger so _safe_phase/_consider_pivots do
        # NOT re-run already-completed phases after a pause/resume.
        self._phases_dispatched.update(self._intel.get("phases_dispatched") or {})
        # [86] Restore the hypotheses + iteration cursor so a resumed run continues
        # from where it paused instead of restarting from hypothesis-zero/iter-zero.
        _stored_hyp = self._intel.get("hypotheses") or []
        if _stored_hyp:
            try:
                self._hypotheses = [Hypothesis.from_dict(h) for h in _stored_hyp]
            except Exception:
                pass
        _resume_iter = int(self._intel.get("reasoning_iteration") or 0)

        # --- INITIAL RECON BOOTSTRAP ---
        # If no ports have been discovered yet, run the basic recon phase first
        # so the hypothesis engine has evidence to work with.
        if not self._intel.get("open_ports"):
            await self._bootstrap_recon()

        # --- SELF-HEAL: ensure recon evidence reached the shared intel ---
        # Subagents persist findings straight to the DB; if the master's
        # intel-sync paths are missing or failed, the loop would otherwise
        # iterate forever on "0 ports".  Rebuild the attack surface from the
        # findings store before any hypothesis/answer work begins.
        if not self._intel.get("open_ports"):
            await self._reconcile_intel_from_findings()

        # --- POST-BOOTSTRAP ANSWER EXTRACTION ---
        # Run QuestionEngine against all gathered intel (no raw output yet).
        await self._question_engine.answer_all(self._intel, "")

        # Wall-clock backstop — see MAX_LOOP_SECONDS.  Bounds total reasoning
        # time so a pathological "evidence keeps shifting slightly" engagement
        # can never grind for hours; the stall counter handles the common case
        # much sooner.
        loop_start = time.monotonic()

        # [86] Resume the iteration cursor from the checkpoint (0 on a fresh run) so a
        # resumed reasoning loop continues its budget rather than restarting from 0.
        for iteration in range(_resume_iter, self.MAX_ITERATIONS):
            self._iteration = iteration
            converged = False   # [28] reset the convergence flag each iteration

            # ── WALL-CLOCK BACKSTOP ──────────────────────────────────────
            _elapsed = time.monotonic() - loop_start
            if _elapsed >= self.MAX_LOOP_SECONDS and not self._intel.get("shell_access"):
                await self._emit_status(
                    f"Reasoning loop hit the {self.MAX_LOOP_SECONDS}s wall-clock "
                    f"ceiling (no shell) — converging and completing the testing "
                    f"cycle. Raise ARGUS_MAX_LOOP_SECONDS to allow longer runs.",
                    "DONE",
                )
                break

            # ── PER-TARGET TOKEN BUDGET ──────────────────────────────────
            # [107] The human-set per-target LLM-token budget was enforced ONLY by
            # OperatorCore; on the legacy ReasoningLoop fallback it was ignored, so a
            # runaway reasoning run could blow past the budget unbounded.  Honour it at
            # the iteration boundary here too.
            _tok_budget = int(getattr(self._master, "_token_budget_per_target", 0) or 0)
            _tok_used   = int(getattr(self._master, "_tokens_used", 0) or 0)
            if _tok_budget > 0 and _tok_used >= _tok_budget:
                await self._emit_status(
                    f"Per-target token budget reached ({_tok_used}/{_tok_budget}) — "
                    f"stopping the reasoning loop.", "DONE")
                break

            # ── PLAYBOOK DISPATCH (E1 wiring) ──────────────────────────────
            # Match current intel against the playbook library; dispatch any
            # never-yet-run playbook whose trigger fires.  Each playbook
            # runs at most once per scan via the dispatched-set.
            # Always wrapped in try; engine errors must not break the loop.
            try:
                await self._dispatch_matched_playbooks()
            except Exception:
                pass

            # ── OPERATOR DIRECTIVE DRAIN (E11 wiring) ──────────────────────
            # Consume any operator_directive messages the WS handler queued
            # since the last iteration boundary.  All directives applied
            # via sticky-state mutators on the queue itself; this drain
            # is purely for the consumed-ack stream.  Honour pause + skip
            # via the existing pause/skip mechanisms.
            try:
                from agents.operator_interrupts import get_queue
                _dir_q = get_queue()
                _sid   = getattr(self._master, "_session_id", "") or ""
                # Block while operator has the scan paused (independent of
                # the _check_pause path which checks the master agent flag).
                if _dir_q.is_paused(_sid):
                    await self._emit_status(
                        "Paused by operator directive at iteration boundary",
                        "WAITING",
                    )
                    await _dir_q.wait_while_paused(_sid, poll_sec=1.0)
                # Drain + emit consumed acks (sticky state already applied)
                _pending = await _dir_q.drain(_sid)
                for _d in _pending:
                    detail = ""
                    # Push the focus_phase hint to the planner if set
                    if _d.directive == "inject_hint":
                        try:
                            self._intel.setdefault("operator_hints", []).append(
                                str(_d.payload.get("hint") or ""))
                        except Exception:
                            pass
                    await _dir_q.mark_consumed(_d, "applied", detail)
            except Exception as _dir_exc:
                # Operator-directive plumbing must never break the scan
                pass

            # ── PAUSE CHECK ──────────────────────────────────────────────
            # B-1 — On pause, AWAIT the operator's resume instead of breaking
            # out of the loop.  The previous behaviour exited the loop on
            # first pause, so a pause/resume cycle terminated the scan.
            try:
                should_pause = await self._check_pause()
                if should_pause:
                    await self._emit_status("Paused at iteration boundary", "WAITING")
                    # Wait for the operator to clear the pause signal.
                    # The master's `_pause_event` is set when running and
                    # cleared when paused; `pause_event.wait()` blocks
                    # until the operator clicks Resume.  We poll every
                    # 1 s so an explicit Stop request is still picked up
                    # promptly via the stop-check below.
                    while True:
                        # Stop overrides pause — exit cleanly if the
                        # operator decided to stop instead of resume.
                        if getattr(self._master, "_stop_requested", False):
                            await self._emit_status("Stop requested while paused — exiting", "DONE")
                            # [25] MUST return self._intel (run() is annotated -> dict and the
                            # caller does `final_intel = await loop.run()` then `key in
                            # final_intel`).  A bare `return` here returned None, so a
                            # pause-then-stop (a normal operator UI sequence) raised TypeError
                            # in _reasoning_loop_run and SKIPPED evidence-collection + report
                            # generation — the run produced no pentest report at all.
                            return self._intel
                        try:
                            still_paused = await self._check_pause()
                        except Exception:
                            still_paused = False
                        if not still_paused:
                            await self._emit_status("Resumed", "RUNNING")
                            break
                        await asyncio.sleep(1.0)
            except Exception:
                pass

            # ── STOP CHECK ───────────────────────────────────────────────
            if getattr(self._master, "_stop_requested", False):
                await self._emit_status("Stop requested — exiting loop", "DONE")
                break

            # ── HOST-LIVENESS + OPERATOR-CANCEL CIRCUIT BREAKERS ─────────
            # The two failure modes that turned a 38-min run into 44 timeouts
            # and a "RECON keeps re-triggering after I cancel it" loop:
            #   (F2) the operator kills tools but the web-primer ladder just
            #        fires the next rung — so stop the auto-sweep after a
            #        cancel streak; one tool-kill must not spawn the next.
            #   (F5) the target goes dark (timeouts/unreachable) yet ARGUS
            #        keeps flailing on stale "port open" intel — detect it,
            #        alert the operator, and converge instead of wasting 35 min.
            try:
                from agents.reasoning.tool_blacklist import get_blacklist as _get_bl
                _bl  = _get_bl()
                _tgt = self._target
                if (not self._intel.get("_web_primer_halted")
                        and _bl.cancel_streak_tripped(_tgt)):
                    self._intel["_web_primer_halted"] = True
                    _ncancel = _bl.consecutive_cancels(_tgt)
                    try:
                        await self._emit("web_primer_halted", {
                            "session_id": self._session_id,
                            "target":     _tgt,
                            "cancels":    _ncancel,
                            "reason":     "operator cancelled multiple tools in a row",
                        })
                    except Exception:
                        pass
                    await self._emit_reasoning(
                        f"🛑 Operator cancelled {_ncancel} tools in a row — halting "
                        f"the automated web-primer sweep against {_tgt}. ARGUS will "
                        f"stop re-dispatching web tools you keep killing and await "
                        f"guidance / pursue non-web vectors."
                    )
                if _bl.host_unreachable(_tgt) and not self._intel.get("shell_access"):
                    _nfail = _bl.consecutive_host_failures(_tgt)
                    try:
                        await self._emit("host_unreachable", {
                            "session_id":            self._session_id,
                            "target":                _tgt,
                            "consecutive_failures":  _nfail,
                        })
                    except Exception:
                        pass
                    await self._emit_status(
                        f"Target {_tgt} stopped responding — {_nfail} consecutive "
                        f"timeouts/unreachable with no success in between. The host is "
                        f"down, firewalled, or rate-limiting; halting active testing "
                        f"instead of flailing. Re-run once it is reachable again.",
                        "DONE",
                    )
                    break
            except Exception:
                pass

            await self._emit_loop_event("iteration_start", {"iteration": iteration})

            # ── OBSERVE ──────────────────────────────────────────────────
            evidence = await self._observe()

            # ── INTERPRET ────────────────────────────────────────────────
            assessment = await self._interpret(evidence)
            if assessment:
                self._journal.append(f"[{iteration}] {assessment}")
                self._intel["reasoning_journal"] = self._journal

            # ── OBJECTIVE GRADING (periodic) ─────────────────────────────
            # Holistically re-grade EVERY objective (complete/partial/
            # not_complete) against the full evidence every few iterations, so
            # the status tracks progress as evidence accrues — not just whatever
            # literal answers were extracted from tool output.
            if iteration and iteration % 3 == 0:
                try:
                    await self._question_engine.evaluate_objectives(self._intel)
                except Exception:
                    pass

            # ── OBJECTIVE CHECK ──────────────────────────────────────────
            if self._is_objective_achieved():
                await self._emit_status("Objective achieved — loop complete", "DONE")
                break

            # ── STALL DETECTION / CONVERGENCE GATE ───────────────────────
            # Compute two fingerprints of the current state.  When the FULL
            # fingerprint is unchanged the loop is spinning, so the two
            # expensive planning LLM calls (hypothesize + prioritize) are
            # skipped and cached results reused.  The COMPROMISE fingerprint
            # drives escalation + convergence so the testing cycle finishes
            # instead of grinding to MAX_ITERATIONS doing identical web probes.
            full_fp  = self._evidence_fingerprint(full=True)
            brk_fp   = self._evidence_fingerprint(full=False)
            evidence_changed = (full_fp != self._full_fp) or not self._hypotheses
            if brk_fp != self._breakthrough_fp:
                self._no_breakthrough = 0
            else:
                self._no_breakthrough += 1
            self._full_fp         = full_fp
            self._breakthrough_fp = brk_fp
            await self._emit_loop_event("stall_status", {
                "iteration":        iteration,
                "evidence_changed": evidence_changed,
                "no_breakthrough":  self._no_breakthrough,
                "escalated":        self._stall_escalated,
            })

            # ── Follow-through guard ──────────────────────────────────────────
            # Never abandon a host ONE STEP short of a foothold.  If a
            # challenge/salt handshake was fetched but not consumed (Hikvision
            # activation), a backup/config artifact was enumerated but not
            # downloaded+grepped (Crestron device.bak/web.config), or a credential
            # surface was hit only once, surface the MANDATORY next action and delay
            # convergence ONCE so ARGUS finishes the started exploit.  (scan
            # 20260712-174430: .21 stopped one encode-and-submit short of camera
            # admin.)  Bounded by _followups_forced so it can only delay once.
            if (self._no_breakthrough >= self.STALL_BREAK_AT
                    and not self._intel.get("shell_access")
                    and not getattr(self, "_followups_forced", False)):
                try:
                    from agents.exploit.follow_through import detect_followups
                    _fups = detect_followups(self._intel, "")
                except Exception:
                    _fups = []
                if _fups:
                    self._followups_forced = True
                    self._no_breakthrough = 0            # fresh window for the started exploit
                    self._intel["pending_followups"] = _fups
                    _hints = self._intel.setdefault("operator_hints", [])
                    for _f in _fups:
                        _hints.append(f"[FOLLOW-THROUGH] {_f.get('reason','')} → {_f.get('next_action','')}")
                        try:
                            await self._emit_reasoning(
                                f"🎯 FOLLOW-THROUGH ({_f.get('kind')}): {_f.get('reason','')} "
                                f"NEXT → {_f.get('next_action','')}")
                        except Exception:
                            pass
                    continue                             # carry the exploit to completion, don't converge

            # Converge & finish: clearly stuck AND we already tried to escalate
            # to genuine exploitation — stop instead of spinning to iter 50.
            if (self._no_breakthrough >= self.STALL_BREAK_AT
                    and self._stall_escalated
                    and not self._intel.get("shell_access")):
                await self._emit_status(
                    f"No compromise progress after {self._no_breakthrough} "
                    f"stagnant iterations (exploitation already attempted) — "
                    f"converging and completing the testing cycle",
                    "DONE",
                )
                break

            # First time we cross the escalate threshold: force ONE genuine
            # exploitation push (re-run the exploit phase + orchestrator) even
            # though the decision engine keeps proposing recon/web steps.  This
            # is the "actually try to compromise before giving up" gate.
            if (self._no_breakthrough >= self.STALL_ESCALATE_AT
                    and not self._stall_escalated
                    and not self._intel.get("shell_access")):
                self._stall_escalated = True
                await self._emit_reasoning(
                    f"⛏️  Stalled {self._no_breakthrough} iterations with no "
                    f"compromise progress — forcing exploitation escalation "
                    f"(exploit phase + orchestrator, then Tier-2 synth path)"
                )
                try:
                    await self._escalate_to_exploitation()
                except Exception as exc:
                    await self._emit_reasoning(f"[stall] escalation error: {exc}")
                # Escalation may have produced fresh evidence — re-snapshot so
                # the planning calls below run against the new state.
                full_fp  = self._evidence_fingerprint(full=True)
                evidence_changed = (full_fp != self._full_fp) or not self._hypotheses
                self._full_fp = full_fp

            # ── HYPOTHESIZE ──────────────────────────────────────────────
            if evidence_changed:
                self._hypotheses = await self._hypothesize(evidence)
            else:
                await self._emit_reasoning(
                    "[loop] evidence unchanged — reusing cached hypotheses "
                    "(skipping the TARGET-STATE planning call to converge faster)"
                )
            if not self._hypotheses:
                await self._emit_reasoning("No hypotheses generated — gathering more evidence")
                await self._gather_more_evidence()
                # Re-run QE after fresh evidence
                await self._question_engine.answer_all(self._intel, "")
                continue

            # Emit attack tree skeleton from fresh hypotheses
            await self._emit_attack_tree_from_hypotheses(self._hypotheses)
            await self._emit_plan_step(
                "hypothesize", "🧠 Hypothesis Generation", "done",
                f"{len(self._hypotheses)} hypotheses — top: {(self._hypotheses[0].statement or '')[:60]}",
                "exploit", probability=self._hypotheses[0].confidence, found=True,
            )
            # Feed hypotheses to the ReasoningEnginePage
            await self._emit({
                "type":       "hypotheses_generated",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       {"hypotheses": [h.to_dict() for h in self._hypotheses]},
            })

            # Update intel with current hypotheses
            self._intel["hypotheses"] = [h.to_dict() for h in self._hypotheses]
            self._intel["confidence_scores"] = {
                h.hypothesis_id: h.confidence for h in self._hypotheses
            }

            # Persist top hypotheses to DB
            await self._persist_hypotheses()

            # Improvement #7 — refresh hypothesis-conditioned scan profile
            await self._refresh_scan_profile()

            # Improvement #9 — procedural RAG: attach technique chains to top hyps
            await self._refresh_technique_chains()

            # Improvement #10 — Neo4j-driven attack-path inference
            await self._refresh_inferred_paths()

            # Improvement #12 — defensive posture fingerprinting (passive)
            await self._refresh_defensive_posture()

            # Improvement #18 — live goal-progress timeline
            await self._refresh_goal_timeline()

            # ── PRIORITIZE ───────────────────────────────────────────────
            # Skip the expensive CURRENT-EVIDENCE ranking call when nothing
            # changed since last iteration — reuse the cached ranked paths.
            if evidence_changed or not self._ranked_paths:
                self._ranked_paths = await self._prioritize()
            if self._ranked_paths:
                self._intel["ranked_attack_paths"] = [
                    p.to_dict() for p in self._ranked_paths
                ]
                # Persist to DB
                await self._persist_ranked_paths()
                # Emit updated attack tree with optimal path from ranked paths
                optimal_ids = [
                    p.path_id for p in self._ranked_paths[:3] if p.total_score >= 0.5
                ]
                await self._emit_attack_tree_from_hypotheses(self._hypotheses, optimal_ids=optimal_ids)
                await self._emit_plan_step(
                    "prioritize", "📊 Attack Path Ranking", "done",
                    f"{len(self._ranked_paths)} paths ranked — best score: {self._ranked_paths[0].total_score:.2f}",
                    "exploit", probability=self._ranked_paths[0].total_score, found=True,
                )

            # ── CONVERGENCE CHECK ────────────────────────────────────────
            top_path = self._attack_planner.get_best_path()
            # [28] Set a flag (was a no-op emit) so the loop actually STOPS once the
            # best path clears the threshold.  The flag is read at the loop tail AFTER
            # this iteration executes the converged best path once — matching the
            # "executing best path" wording.
            converged = bool(top_path and top_path.total_score >= self.CONVERGENCE_THRESHOLD)
            if converged:
                await self._emit_reasoning(
                    f"Convergence threshold reached "
                    f"(score={top_path.total_score:.3f}) — executing best path"
                )

            # ── SELECT ACTION ────────────────────────────────────────────
            action = await self._decision_eng.select_action(
                hypotheses      = self._hypotheses,
                intel           = self._intel,
                used_tools      = getattr(self._master, "_used_tools", {}),
                negative_memory = self._neg_memory,
                # [27] Feed the ranked attack paths so the decision engine can bubble
                # candidates that lie on the best path (was computed then discarded).
                ranked_paths    = self._ranked_paths,
            )

            # Improvement #17 — record selection trace step parented on
            # the hypothesis it derives from.
            if action is not None:
                _hyp_step = None
                trace = getattr(self, "_reasoning_trace", None)
                if trace is not None:
                    _hyp_step = trace.latest_step_for("hypothesis_id", action.hypothesis_id or "")
                self._last_select_step_id = await self._record_trace_step(
                    kind      = "select",
                    summary   = (
                        f"selected {action.tool} → {action.target_service or '?'} "
                        f"(conf={action.confidence:.2f})"
                    ),
                    parent_id = (_hyp_step.step_id if _hyp_step else None),
                    refs      = {
                        "action_id":     action.action_id or "",
                        "hypothesis_id": action.hypothesis_id or "",
                        "tool":          action.tool or "",
                    },
                    payload   = {
                        "args":    (action.args or "")[:200],
                        "reason":  (action.reason or "")[:200],
                        "expected_outcome": (action.expected_outcome or "")[:200],
                    },
                )

            if action is None:
                await self._emit_reasoning(
                    "No actionable hypothesis found — exhausting more evidence paths"
                )
                gather_result = await self._gather_more_evidence()
                # Re-run QE after fresh evidence
                await self._question_engine.answer_all(self._intel, "")
                if gather_result:
                    continue

                # ── WEB-INTELLIGENCE PIVOT ────────────────────────────────
                # Last-resort intelligence step before giving up.  When all
                # primer chains have run, all hypotheses are exhausted, and
                # gather_more_evidence returned nothing, search the web for
                # exploitation techniques specific to the discovered
                # service+version / CVE / framework hints.  Successfully
                # extracted hints become new hypotheses and the loop
                # continues; otherwise we exit as before.
                try:
                    web_intel = self._get_or_init_web_intel()
                    if web_intel is not None:
                        injected = await web_intel.run(self._intel, self._hypotheses)
                        if injected > 0:
                            await self._emit_reasoning(
                                f"Web intel pivot injected {injected} new "
                                f"hypothesis branches — resuming loop"
                            )
                            # Re-rank attack paths so the new hypotheses
                            # compete fairly with surviving ones.  Use keyword
                            # args matching _prioritize() — the positional form
                            # here silently raised TypeError (swapped intel/
                            # hypotheses + missing negative_memory) so this
                            # re-rank never actually ran.
                            try:
                                self._ranked_paths = await self._attack_planner.rank_paths(
                                    intel           = self._intel,
                                    hypotheses      = self._hypotheses,
                                    negative_memory = self._neg_memory,
                                    iteration       = self._iteration,
                                )
                            except Exception:
                                pass
                            continue
                except Exception as exc:
                    import logging as _l
                    _l.getLogger(__name__).warning(
                        "[web_intel] pivot failed (non-fatal): %s", exc
                    )

                await self._emit_status("No more actions available — loop complete", "DONE")
                break

            # ── CONFIRMATION GATE ────────────────────────────────────────
            if action.requires_confirmation:
                await self._emit_confirmation_request(action)
                confirmed = await self._wait_for_confirmation(action, timeout=60)
                if not confirmed:
                    await self._emit_reasoning(
                        f"Action not confirmed within timeout — skipping: {action.tool}"
                    )
                    # Record as a low-confidence skip (no penalty)
                    await self._neg_memory.record_failure(
                        tool           = action.tool,
                        args           = action.args,
                        target_service = action.target_service,
                        failure_reason = "Operator did not confirm (confidence too low)",
                        hypothesis_id  = action.hypothesis_id,
                        host           = self._target,
                    )
                    continue

            # ── EMIT PRE-EXECUTION PLAN ───────────────────────────────────
            if action.plan:
                await self._emit_loop_event("pre_execution_plan", action.plan.to_dict())

            # Mark action as active in plan tracker
            active_hyp_stmt = ""
            active_hyp_mitre = ""
            for h in self._hypotheses:
                if h.hypothesis_id == action.hypothesis_id:
                    active_hyp_stmt  = h.statement or ""
                    active_hyp_mitre = h.mitre_technique or ""
                    break
            await self._emit_plan_step(
                action.action_id,
                f"⚡ {action.tool}",
                "active",
                action.reason[:120] if action.reason else "",
                "exploit",
                mitre_id    = active_hyp_mitre,
                probability = action.confidence,
                detail      = f"Target: {action.target_service} | Expected: {(action.expected_outcome or '')[:80]}",
            )
            # Mark parent execute_actions step active
            await self._emit_plan_step(
                "execute_actions", "⚡ Hypothesis Execution", "active",
                f"Executing: {action.tool} — {(action.reason or '')[:80]}",
                "exploit", probability=action.confidence,
            )

            # ── DRY-RUN GATE (Improvement #13) ───────────────────────────
            # Soft gate: when master.dry_run_mode is enabled and the action
            # is classified destructive (or risky on stealth engagements),
            # emit a preview event and skip execution this iteration.  The
            # operator confirms via the existing requires_confirmation
            # path or toggles dry_run_mode off in the UI.
            if getattr(self._master, "dry_run_mode", False) and not action.requires_confirmation:
                try:
                    from agents.reasoning.dry_run import (
                        classify_action, build_preview,
                    )
                    verdict = classify_action(action)
                    nb_for_tier = getattr(self._master, "noise_budget", None)
                    is_stealth = bool(nb_for_tier and getattr(nb_for_tier, "mode", "") == "stealth")
                    gate = (verdict.tier == "destructive") or (is_stealth and verdict.tier == "risky")
                    if gate:
                        preview = build_preview(
                            action,
                            session_id = self._session_id,
                            iteration  = self._iteration,
                        )
                        await self._emit({
                            "type":       "dry_run_preview",
                            "session_id": self._session_id,
                            "agent":      "master",
                            "data":       preview,
                        })
                        await self._neg_memory.record_failure(
                            tool           = action.tool,
                            args           = action.args,
                            target_service = action.target_service,
                            failure_reason = (
                                f"dry_run_gated tier={verdict.tier} "
                                f"reasons={'; '.join(verdict.reasons)[:120]}"
                            ),
                            hypothesis_id  = action.hypothesis_id,
                            host           = self._target,
                        )
                        await self._emit_plan_step(
                            action.action_id,
                            f"🧪 {action.tool} (dry-run preview)",
                            "failed",
                            f"[{verdict.tier}] {(verdict.reasons[0] if verdict.reasons else '')[:120]}",
                            "exploit",
                            mitre_id    = active_hyp_mitre,
                            probability = action.confidence,
                            found       = False,
                        )
                        continue
                except Exception as exc:
                    await self._emit_reasoning(f"[dry_run] gate error: {exc}")

            # ── SELF-CRITIQUE GATE (Improvement #15) ─────────────────────
            # Pre-mortem on risky/destructive actions: structured checks
            # for preconditions, negative-memory repeats, sub-threshold
            # confidence, scope membership, and defender compatibility.
            try:
                from agents.reasoning.dry_run import classify_action as _cls
                from agents.reasoning.self_critique import critique_action
                _verdict = _cls(action)
                if _verdict.tier in ("risky", "destructive") and not action.requires_confirmation:
                    eng_ctx = self._intel.get("engagement_context") or {}
                    scope_hosts = eng_ctx.get("scope_hosts") or eng_ctx.get("targets") or []
                    crit = critique_action(
                        action,
                        hypothesis  = next((h for h in self._hypotheses
                                            if h.hypothesis_id == action.hypothesis_id), None),
                        intel       = self._intel,
                        tier        = _verdict.tier,
                        neg_memory  = self._neg_memory,
                        posture     = self._intel.get("defensive_posture"),
                        scope_hosts = scope_hosts,
                        target      = self._target,
                    )
                    self._intel["last_self_critique"] = crit.to_dict()
                    await self._emit({
                        "type":       "self_critique",
                        "session_id": self._session_id,
                        "agent":      "master",
                        "data": {
                            "tool":          action.tool,
                            "tier":          _verdict.tier,
                            "hypothesis_id": action.hypothesis_id,
                            "critique":      crit.to_dict(),
                        },
                    })
                    if crit.recommendation == "abort":
                        await self._record_trace_step(
                            kind     = "gate",
                            summary  = f"self-critique ABORT: {crit.reason[:120]}",
                            parent_id= self._last_select_step_id,
                            refs     = {"action_id": action.action_id or "",
                                        "gate":      "self_critique"},
                            payload  = crit.to_dict(),
                        )
                        await self._emit_reasoning(
                            f"[self_critique] aborting {action.tool} — {crit.reason}"
                        )
                        await self._neg_memory.record_failure(
                            tool           = action.tool,
                            args           = action.args,
                            target_service = action.target_service,
                            failure_reason = f"self_critique_abort: {crit.reason[:140]}",
                            hypothesis_id  = action.hypothesis_id,
                            host           = self._target,
                        )
                        await self._emit_plan_step(
                            action.action_id,
                            f"🛑 {action.tool} (self-critique abort)",
                            "failed",
                            crit.reason[:120],
                            "exploit",
                            mitre_id    = active_hyp_mitre,
                            probability = action.confidence,
                            found       = False,
                        )
                        continue
                    if crit.recommendation == "hold":
                        # Promote to a confirmation-required action so the
                        # operator can review before it fires next iter.
                        action.requires_confirmation = True
                        await self._emit_reasoning(
                            f"[self_critique] holding {action.tool} for review — {crit.reason}"
                        )
                        await self._emit_confirmation_request(action)
                        confirmed = await self._wait_for_confirmation(action, timeout=60)
                        if not confirmed:
                            await self._neg_memory.record_failure(
                                tool           = action.tool,
                                args           = action.args,
                                target_service = action.target_service,
                                failure_reason = f"self_critique_hold_unconfirmed: {crit.reason[:120]}",
                                hypothesis_id  = action.hypothesis_id,
                                host           = self._target,
                            )
                            continue
            except Exception as exc:
                await self._emit_reasoning(f"[self_critique] gate error: {exc}")

            # ── NOISE BUDGET GATE (Improvement #11) ──────────────────────
            # Soft gate: if the action's estimated noise cost would push the
            # session over budget, skip & record a negative-memory entry so
            # the next decision picks a quieter alternative.  Confirmed
            # high-confidence actions (operator-confirmed) skip this gate.
            nb = getattr(self._master, "noise_budget", None)
            if nb is not None and not action.requires_confirmation:
                try:
                    if nb.would_exceed(action):
                        cost = nb.cost_of(action)
                        await self._emit({
                            "type":       "noise_budget_blocked",
                            "session_id": self._session_id,
                            "agent":      "master",
                            "data": {
                                "tool":      action.tool,
                                "args":      action.args,
                                "cost":      cost,
                                "remaining": nb.remaining,
                                "status":    nb.status(),
                                "reason":    "would exceed noise budget",
                            },
                        })
                        await self._neg_memory.record_failure(
                            tool           = action.tool,
                            args           = action.args,
                            target_service = action.target_service,
                            failure_reason = (
                                f"noise_budget_exceeded "
                                f"(cost={cost} remaining={nb.remaining})"
                            ),
                            hypothesis_id  = action.hypothesis_id,
                            host           = self._target,
                        )
                        await self._emit_plan_step(
                            action.action_id,
                            f"🛑 {action.tool} (noise gated)",
                            "failed",
                            f"Skipped — noise cost {cost} > remaining {nb.remaining}",
                            "exploit",
                            mitre_id    = active_hyp_mitre,
                            probability = action.confidence,
                            found       = False,
                        )
                        continue
                except Exception:
                    pass

            # ── EXECUTE ──────────────────────────────────────────────────
            # Capture pre-execute pivot snapshot so post-execute we can diff
            # and synthesise credential_found / shell_obtained / flag_found
            # events for anything new — these route through master and
            # trigger _consider_pivots opportunistically (Improvement #5).
            pivot_pre = self._intel_snapshot_for_pivots()
            was_shell = pivot_pre["shell_access"]
            result    = await self._execute(action)

            # Improvement #17 — record execute step
            _exec_step_id = await self._record_trace_step(
                kind      = "execute",
                summary   = (
                    f"ran {action.tool} (exit={result.get('exit_code', '?')}, "
                    f"stdout={len((result.get('stdout') or ''))}b)"
                ),
                parent_id = self._last_select_step_id,
                refs      = {
                    "action_id":     action.action_id or "",
                    "hypothesis_id": action.hypothesis_id or "",
                    "tool":          action.tool or "",
                },
                payload   = {
                    "exit_code": result.get("exit_code"),
                    "stdout_preview": (result.get("stdout") or "")[:200],
                },
            )

            # ── NOISE BUDGET CONSUME (Improvement #11) ───────────────────
            if nb is not None:
                try:
                    taken = nb.consume(action, note=action.target_service or "")
                    await self._emit({
                        "type":       "noise_budget_updated",
                        "session_id": self._session_id,
                        "agent":      "master",
                        "data": {
                            **nb.to_dict(),
                            "last_tool": action.tool,
                            "last_cost": taken,
                        },
                    })
                except Exception:
                    pass
            result["_was_shell_before"] = was_shell  # used by score_action_result

            # ── VALIDATE ─────────────────────────────────────────────────
            active_hyp = next(
                (h for h in self._hypotheses
                 if h.hypothesis_id == action.hypothesis_id),
                None
            )
            validated  = await self._validate(action, result, active_hyp)

            # ── B-7 — NOISE BUDGET REFUND for actions that produced no
            # real network traffic.  Refund full cost when the tool died
            # before reaching the target (MCP unknown-tool, immediate
            # connect-refused, OS spawn failure).  Refund half on auth
            # failures (handshake DID happen but no follow-up).
            if nb is not None:
                try:
                    refund_fraction = self._noise_refund_fraction(action, result, validated)
                    if refund_fraction > 0:
                        returned = nb.refund(action, fraction=refund_fraction,
                                             note=f"failed:{action.target_service or ''}")
                        if returned > 0:
                            await self._emit({
                                "type":       "noise_budget_updated",
                                "session_id": self._session_id,
                                "agent":      "master",
                                "data": {
                                    **nb.to_dict(),
                                    "last_tool":   action.tool,
                                    "last_refund": returned,
                                },
                            })
                except Exception:
                    pass

            # Improvement #17 — record validate step
            self._last_validate_step_id = await self._record_trace_step(
                kind      = "validate",
                summary   = (
                    f"{'CONFIRMED' if validated else 'unconfirmed'} "
                    f"{(active_hyp.statement if active_hyp else action.tool)[:120]}"
                ),
                parent_id = _exec_step_id,
                refs      = {
                    "action_id":     action.action_id or "",
                    "hypothesis_id": action.hypothesis_id or "",
                },
                payload   = {"validated": bool(validated)},
            )

            # ── EMIT RESULTS TO ALL DASHBOARDS ───────────────────────────
            stdout_preview = (result.get("stdout") or "")[:200]
            await self._emit_plan_step(
                action.action_id,
                f"{'✅' if validated else '❌'} {action.tool}",
                "done" if validated else "failed",
                stdout_preview or (action.expected_outcome or "")[:150],
                "exploit",
                mitre_id    = active_hyp_mitre,
                probability = action.confidence,
                found       = validated,
            )

            if validated and active_hyp:
                sev = "high" if active_hyp.confidence >= 0.8 else "medium"
                # Emit as a finding so FindingsBoard shows it
                await self._emit_finding(
                    title       = f"[Confirmed] {(active_hyp.statement or '')[:120]}",
                    severity    = sev,
                    description = f"Tool: {action.tool}\nReason: {action.reason}\nOutput: {stdout_preview}",
                    phase       = active_hyp.attack_phase or "exploit",
                    tool        = action.tool,
                    mitre       = active_hyp.mitre_technique or "",
                )
                # Emit hypothesis as a graph node
                await self._emit_graph_node(
                    node_id   = active_hyp.hypothesis_id,
                    node_type = "technique",
                    label     = (active_hyp.statement or "")[:80],
                    phase     = active_hyp.attack_phase or "exploit",
                    severity  = sev,
                    metadata  = {
                        "confidence":  active_hyp.confidence,
                        "mitre":       active_hyp.mitre_technique or "",
                        "tool":        action.tool,
                        "iteration":   self._iteration,
                        "validated":   True,
                    },
                )
                # Chain edge from previous validated node (or from target)
                _prev_node = self._last_validated_node_id or f"target_{self._target.replace('.', '_')}"
                await self._emit_graph_edge(
                    source = _prev_node,
                    target = active_hyp.hypothesis_id,
                    label  = action.tool,
                    tool   = action.tool,
                )
                self._last_validated_node_id = active_hyp.hypothesis_id

                # Update hypothesis status in ReasoningEnginePage
                await self._emit({
                    "type":       "hypothesis_update",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       {**active_hyp.to_dict(), "validated": True, "invalidated": False},
                })

            elif not validated and active_hyp:
                # Update hypothesis as invalidated
                await self._emit({
                    "type":       "hypothesis_update",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       {**active_hyp.to_dict(), "validated": False, "invalidated": True},
                })

            # Emit score update
            await self._emit({
                "type":       "action_score_update",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "delta": 0,  # will be recalculated in _update
                    "total": self._decision_eng.get_score(),
                    "tool":  action.tool,
                },
            })

            # ── UPDATE STATE ──────────────────────────────────────────────
            await self._update(action, result, validated, active_hyp)

            # ── UNIFIED CROSS-PHASE PIVOTS (Improvements #4 + #5) ─────────
            # Step 1 (#5): synthesise discrete events for any high-value
            # delta vs. the pre-execute snapshot.  These flow through
            # master._broadcast_raw → master.notify_pivot_event → ReasoningLoop.
            # on_pivot_event, which immediately calls _consider_pivots under
            # a lock.  So credentials / shells / flags trigger pivots as soon
            # as they appear in intel.
            try:
                await self._emit_pivot_deltas(pivot_pre)
            except Exception as exc:
                await self._emit_reasoning(f"[pivots] delta-emit error: {exc}")

            # Step 2 (#4): even when no discrete pivot event fired, audit
            # cross-phase triggers once per iteration so newly-satisfied
            # state (e.g. new vulns, ports) still dispatches phases.
            try:
                fired = await self._consider_pivots()
                if fired:
                    await self._emit_loop_event("pivots_fired", {
                        "iteration": iteration,
                        "phases":    fired,
                    })
            except Exception as exc:
                await self._emit_reasoning(f"[pivots] error: {exc}")

            # ── QUESTION ENGINE: answer extraction + discovery pass ────────
            # Layer 1 (deterministic) + Layer 2 (LLM) + Layer 3 (tool) against
            # this tool's output. Works for both CTF objectives and ad-hoc questions.
            _tool_stdout = (result.get("stdout") or result.get("output") or "")
            await self._question_engine.answer_all(self._intel, _tool_stdout)
            # Discovery pass: surface interesting facts for real pentests
            await self._question_engine.run_discovery_pass(
                raw_output = _tool_stdout,
                phase      = action.hypothesis_id or "exploit",
                tool       = action.tool,
                intel      = self._intel,
            )

            # ── AUTO POST-EXPLOITATION ────────────────────────────────────
            # Shell-gained event still emits a clear operator message, but the
            # actual post-exploit + privesc + lateral dispatches now flow
            # through the unified _consider_pivots() above (idempotent), so
            # this no longer duplicates work nor enforces a hardcoded order.
            if not result.get("_was_shell_before") and self._intel.get("shell_access"):
                await self._emit_reasoning(
                    "🎯 Shell access gained — pivots will fire post-exploit / privesc / lateral"
                )

            # ── CHECKPOINT ───────────────────────────────────────────────
            if iteration % self.CHECKPOINT_EVERY == 0:
                try:
                    await self._save_checkpoint(iteration)
                except Exception:
                    pass

            await self._emit_loop_event("iteration_complete", {
                "iteration":   iteration,
                "validated":   validated,
                "action_tool": action.tool,
                "score":       self._decision_eng.get_score(),
            })

            # [28] Convergence early-stop — the best path scored >= threshold and was
            # executed this iteration; now stop the loop instead of spinning on.
            if converged:
                await self._emit_reasoning(
                    "Best attack path executed at convergence — ending reasoning loop.")
                break

        # Sync final state back to intel
        self._intel["action_score"]        = self._decision_eng.get_score()
        self._intel["negative_memory"]     = self._neg_memory.to_dict_list()
        self._intel["reasoning_journal"]   = self._journal
        self._intel["ranked_attack_paths"] = self._attack_planner.get_paths_as_dicts()

        # Emit final confirmed attack tree
        validated_hyps = [h for h in self._hypotheses if h.validated]
        all_hyps_sorted = sorted(
            self._hypotheses,
            key=lambda h: (h.validated, h.confidence),
            reverse=True
        )
        await self._emit_attack_tree_from_hypotheses(
            all_hyps_sorted,
            optimal_ids=[h.hypothesis_id for h in validated_hyps[:5]],
        )
        await self._emit_plan_step(
            "execute_actions", "⚡ Hypothesis Execution", "done",
            f"{len(validated_hyps)} confirmed / {len(self._hypotheses)} total hypotheses",
            "exploit", found=bool(validated_hyps),
        )
        await self._emit_plan_step(
            "validate", "✅ Validation & Scoring",
            "done" if validated_hyps else "failed",
            f"Final score: {self._decision_eng.get_score():+d} | {len(validated_hyps)} confirmed hypotheses",
            "exploit", found=bool(validated_hyps),
        )
        # ── Final objective grading ──────────────────────────────────────
        # Authoritative complete/non-complete verdict over ALL evidence, so the
        # operator + report get a clear per-objective status at scan end rather
        # than "we don't know what was achieved".
        try:
            _summ = await self._question_engine.evaluate_objectives(self._intel)
            if _summ:
                await self._emit_reasoning(
                    f"Objective status: {_summ.get('complete', 0)}/{_summ.get('total', 0)} "
                    f"complete, {_summ.get('partial', 0)} partial, "
                    f"{_summ.get('not_complete', 0)} not complete")
        except Exception:
            pass

        # Transition to reporting
        await self._emit_plan_step("reporting", "📄 Report Generation", "active", "Generating report", "reporting")

        await self._emit_loop_event("loop_complete", {
            "iterations": self._iteration,
            "score":      self._decision_eng.get_score(),
            "shell":      bool(self._intel.get("shell_access")),
        })

        return self._intel

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------

    async def _bootstrap_recon(self) -> None:
        """
        Engagement-aware intelligence bootstrap.
        Routes to the correct bootstrap strategy based on engagement type.
        """
        eng_ctx  = self._intel.get("engagement_context") or {}
        eng_type = eng_ctx.get("engagement_type", "pentest")

        if eng_type in ("forensics", "malware_analysis"):
            await self._bootstrap_file_analysis()
        elif eng_type == "network_analysis":
            await self._bootstrap_network_analysis()
        elif eng_type == "compliance":
            await self._bootstrap_compliance()
        else:
            # pentest, ctf, red_team, bug_bounty, custom → network-first
            await self._bootstrap_network()

    async def _bootstrap_network(self) -> None:
        """Standard network-first bootstrap for pentest/CTF/red_team."""
        await self._emit_reasoning("Starting network intelligence bootstrap")
        await self._emit_plan_step(
            "bootstrap_recon", "🔍 Intelligence Bootstrap", "active",
            f"Full recon + service fingerprinting on {self._target}", "recon"
        )

        # Route through _safe_phase so meta-agent pre/post hooks fire.
        await self._safe_phase(self._master._phase_recon,
                               phase_slug="recon",
                               target=self._target, plan={})

        ports_found = self._intel.get("open_ports", [])
        # Use a LIST (not a set) so downstream code that slices/indexes it works.
        # Previously this was a set-comprehension, which caused
        # "'set' object is not subscriptable" when any consumer did `port_nums[:N]`.
        _seen_ports = set()
        port_nums: list = []
        for p in ports_found:
            val = p.get("port") if isinstance(p, dict) else p
            try:
                val_i = int(str(val).split("/")[0])
            except (ValueError, TypeError):
                continue
            if val_i not in _seen_ports:
                _seen_ports.add(val_i)
                port_nums.append(val_i)
        port_nums.sort()

        parallel_tasks: list = []
        parallel_tasks.append(("OSINT", self._safe_phase(self._master._phase_osint,
                                                          phase_slug="osint",
                                                          target=self._target)))
        if port_nums:
            parallel_tasks.append(("Vuln ID", self._safe_phase(self._master._phase_vuln_id,
                                                                phase_slug="vuln_id",
                                                                target=self._target)))
        web_ports = [p for p in port_nums if p in {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443}]
        if web_ports:
            parallel_tasks.append(("Web", self._safe_phase(self._master._phase_web_testing,
                                                            phase_slug="web_testing",
                                                            target=self._target, web_ports=web_ports)))

        if parallel_tasks:
            await self._emit_plan_step("bootstrap_deep", "🔬 Deep Fingerprinting", "active",
                                       f"Parallel: {', '.join(l for l, _ in parallel_tasks)}", "recon")
            await asyncio.gather(*[t for _, t in parallel_tasks], return_exceptions=True)
            await self._emit_plan_step("bootstrap_deep", "🔬 Deep Fingerprinting", "done",
                                       f"{len(self._intel.get('vulnerabilities',[]))} vulns | "
                                       f"{len(self._intel.get('technologies',[]))} techs", "recon", found=True)

        total_ports = len(self._intel.get("open_ports", []))
        await self._emit_plan_step(
            "bootstrap_recon", "🔍 Intelligence Bootstrap",
            "done" if total_ports else "failed",
            f"{total_ports} ports | {len(self._intel.get('vulnerabilities',[]))} vulns",
            "recon", found=total_ports > 0
        )

        # ── Exploit phase ─────────────────────────────────────────────────
        # The reasoning loop previously never invoked the exploit phase, so
        # no exploitation attempts were ever made. Invoke it here if we have
        # any vuln/port evidence. `_phase_exploit` itself respects the
        # `_auto_exploit` gate — when False it will await confirmation.
        if port_nums:
            await self._emit_plan_step(
                "bootstrap_exploit", "💥 Exploitation", "active",
                f"Attempting exploitation on {len(port_nums)} open ports", "exploit"
            )
            # Route through _safe_phase so meta-agent pre/post hooks fire.
            await self._safe_phase(self._master._phase_exploit,
                                   phase_slug="exploit",
                                   target=self._target)
            await self._emit_plan_step(
                "bootstrap_exploit", "💥 Exploitation", "done",
                f"{len(self._intel.get('shells',[]))} shells | "
                f"{len(self._intel.get('credentials',[]))} creds",
                "exploit",
                found=bool(self._intel.get("shells") or self._intel.get("credentials")),
            )

    async def _bootstrap_file_analysis(self) -> None:
        """Bootstrap for forensics / malware_analysis — run file analysis tools."""
        eng_ctx  = self._intel.get("engagement_context") or {}
        eng_type = eng_ctx.get("engagement_type", "forensics")
        emoji    = "🔎" if eng_type == "forensics" else "🦠"

        await self._emit_reasoning(f"Starting {eng_type} file analysis bootstrap")
        await self._emit_plan_step("bootstrap_recon", f"{emoji} File Analysis Bootstrap", "active",
                                   f"Static analysis of {self._target}", "recon")

        tools_preferred = eng_ctx.get("tools_preferred") or ["file", "strings", "binwalk", "foremost", "xxd"]
        tasks = []
        for tool_cmd in tools_preferred[:6]:
            tool = tool_cmd.split()[0]
            args = (tool_cmd + f" {self._target}").replace(tool, "", 1).strip() if "{target}" not in tool_cmd else tool_cmd.format(target=self._target).replace(tool + " ", "")
            tasks.append(self._safe_dispatch(tool, f"{self._target}", f"Static analysis: {tool}"))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        artifacts = sum(1 for r in results if not isinstance(r, Exception) and r)
        await self._emit_plan_step("bootstrap_recon", f"{emoji} File Analysis Bootstrap",
                                   "done" if artifacts else "failed",
                                   f"{artifacts} analysis tools completed", "recon", found=bool(artifacts))

    async def _bootstrap_network_analysis(self) -> None:
        """Bootstrap for network_analysis — run pcap/traffic analysis tools."""
        await self._emit_reasoning("Starting network traffic analysis bootstrap")
        await self._emit_plan_step("bootstrap_recon", "📡 Traffic Analysis Bootstrap", "active",
                                   f"Analysing {self._target}", "recon")

        tasks = [
            self._safe_dispatch("tshark", f"-r {self._target} -q -z io,phs", "Protocol hierarchy statistics"),
            self._safe_dispatch("tshark", f"-r {self._target} -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head -30", "Top conversations"),
            self._safe_dispatch("tshark", f"-r {self._target} -Y 'http or dns or ftp or smtp' -T json | head -200", "Application layer traffic"),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._emit_plan_step("bootstrap_recon", "📡 Traffic Analysis Bootstrap", "done",
                                   "Traffic baseline established", "recon", found=True)

    async def _bootstrap_compliance(self) -> None:
        """Bootstrap for compliance checks — light network scan + config analysis."""
        await self._emit_reasoning("Starting compliance assessment bootstrap")
        await self._emit_plan_step("bootstrap_recon", "📋 Compliance Bootstrap", "active",
                                   f"Service discovery on {self._target}", "recon")
        await self._safe_phase(self._master._phase_recon,
                               phase_slug="recon",
                               target=self._target, plan={})
        await self._emit_plan_step("bootstrap_recon", "📋 Compliance Bootstrap", "done",
                                   "Service baseline collected", "recon", found=True)

    async def _safe_dispatch(self, tool: str, args: str, purpose: str) -> dict:
        """Dispatch a single tool via master agent, returning empty dict on error."""
        try:
            return await self._master._dispatch_to_agent(
                tool=tool, args=args, purpose=purpose, phase="recon"
            ) or {}
        except Exception as e:
            await self._emit_reasoning(f"{tool} dispatch error: {e}")
            return {}

    # ------------------------------------------------------------------
    # Loop steps
    # ------------------------------------------------------------------

    async def _reconcile_intel_from_findings(self, union: bool = False) -> int:
        """Self-healing safety net: rebuild core recon evidence from the
        authoritative findings store when the in-memory intel dict is empty.

        WHY THIS EXISTS
        ---------------
        Subagents (network_scan, service_banner, …) persist every Finding
        directly to the ``findings`` collection via ``store_finding``, but
        that helper does NOT touch the shared ``intel`` dict — population of
        ``intel['open_ports']`` relies entirely on the master's sync paths
        (``_run_network_scan_and_sync``, ``_await_and_sync_subagents``,
        ``_phase_recon`` merge).  If ANY of those paths is missing (a stale
        build) or silently fails, the reasoning loop would observe
        ``Ports open: 0`` forever — re-requesting a port scan every
        iteration — even though recon already discovered the full attack
        surface and wrote it to the database.

        This method closes that gap unconditionally: it reads the findings
        the scan actually produced and backfills ``open_ports`` /
        ``services`` / ``cves`` so the loop's evidence ALWAYS reflects
        reality.  It only fills keys that are currently empty, so it never
        clobbers richer in-memory state.  Fully defensive — never raises.

        Returns the number of open ports recovered (0 when nothing to do).
        """
        # Fast path: intel already has ports → nothing to reconcile, UNLESS we
        # are explicitly union-merging to catch a PARTIAL port list (e.g. intel
        # has [80] but recon actually found [22,80] — the gap that kept the
        # loop reporting "Ports open: 1" and re-requesting a full scan).
        if self._intel.get("open_ports") and not union:
            return 0
        try:
            from db import mongo_client as _db
            findings = await _db.get_findings(self._session_id, limit=2000)
        except Exception:
            return 0
        if not findings:
            return 0

        import re as _re
        ports: list = []
        services: dict = dict(self._intel.get("services") or {})
        cve_seen = {str(c).upper() for c in (self._intel.get("cves") or [])}
        new_cves: list = []
        vulns: list = []

        for f in findings:
            # ── Ports ──────────────────────────────────────────────────
            raw_port = f.get("port")
            port_i = None
            if raw_port is not None:
                try:
                    port_i = int(str(raw_port).split("/")[0])
                except (ValueError, TypeError):
                    port_i = None
            if port_i is not None and port_i not in ports:
                ports.append(port_i)

            # ── Service / version (best-effort parse of finding text) ──
            if port_i is not None and port_i not in services:
                title = str(f.get("title") or "")
                desc  = str(f.get("description") or "")
                svc, ver = "", ""
                # network_scan style: "Open Port 22/tcp: ssh (OpenSSH 7.2p2 …)"
                m = _re.search(r"Open Port\s+\d+/\w+:\s*([A-Za-z][\w\-./]*)\s*(?:\(([^)]*)\))?", title)
                if m:
                    svc = (m.group(1) or "").strip()
                    ver = (m.group(2) or "").strip()
                # service_banner style: "Service: ssh. Version: OpenSSH 7.2p2."
                if not ver:
                    mv = _re.search(r"Version:\s*([^.]+)", desc)
                    if mv:
                        ver = mv.group(1).strip()
                if not svc:
                    ms = _re.search(r"Service:\s*([A-Za-z][\w\-./]*)", desc)
                    if ms:
                        svc = ms.group(1).strip()
                if svc or ver:
                    services[port_i] = {
                        "service":  svc,
                        "version":  ver,
                        "port":     port_i,
                        "protocol": "tcp",
                    }

            # ── CVEs ───────────────────────────────────────────────────
            f_cves = []
            for c in (f.get("cves") or []):
                cu = str(c).strip().upper()
                if cu:
                    f_cves.append(cu)
                    if cu not in cve_seen:
                        cve_seen.add(cu)
                        new_cves.append(cu)

            # ── Vulnerabilities ────────────────────────────────────────
            # A finding that carries a CVE or is rated HIGH/CRITICAL is an
            # actionable vulnerability — surface it so the hypothesis engine
            # and the exploit gate (which look at intel['vulnerabilities'])
            # see exploit evidence, not just raw ports.
            sev = str(f.get("severity") or "").upper()
            if f_cves or sev in ("HIGH", "CRITICAL"):
                vulns.append({
                    "title":    str(f.get("title") or "")[:160],
                    "severity": sev or "MEDIUM",
                    "cve":      f_cves[0] if f_cves else "",
                    "cves":     f_cves,
                    "port":     port_i,
                    "source":   "findings_reconcile",
                })

        if not ports:
            return 0

        # ── UNION mode: merge findings ports into a PARTIAL in-memory list ──
        if union:
            existing = []
            for p in (self._intel.get("open_ports") or []):
                try:
                    existing.append(int(str(p).split("/")[0]))
                except (ValueError, TypeError):
                    continue
            new_ports = [p for p in ports if p not in existing]
            if not new_ports:
                return 0   # nothing new — avoid churn/log spam every iteration
            self._intel["open_ports"] = sorted(set(existing) | set(ports))
            cur_svcs = dict(self._intel.get("services") or {})
            for k, v in services.items():
                cur_svcs.setdefault(k, v)   # never clobber existing service entry
            if cur_svcs:
                self._intel["services"] = cur_svcs
            if new_cves:
                cur_cves = list(self._intel.get("cves") or [])
                # Coerce every entry to a canonical, HASHABLE CVE-id string before dedup.
                # A CVE lookup path can store a dict ({"id":..,"cvss":..} or malformed), and
                # dict.fromkeys() would raise "unhashable type: 'dict'" and abort the phase
                # (the exact crash that killed this engagement).  Dropping id-less dicts also
                # keeps undefendable records out of intel.
                def _cid(_c):
                    if isinstance(_c, dict):
                        _c = (_c.get("id") or _c.get("cve") or _c.get("cve_id")
                              or _c.get("name") or "")
                    return str(_c or "").strip().upper()
                self._intel["cves"] = [x for x in dict.fromkeys(
                    _cid(c) for c in (cur_cves + new_cves)) if x]
            await self._emit_reasoning(
                f"Reconciled {len(new_ports)} additional open port(s) from the "
                f"findings store — in-memory list was partial (now "
                f"{len(self._intel['open_ports'])} total: "
                f"{', '.join(str(p) for p in self._intel['open_ports'][:12])})"
            )
            return len(new_ports)

        # ── Empty-fill mode: backfill ONLY empty keys (never clobber) ──────
        self._intel["open_ports"] = sorted(ports)
        if services and not self._intel.get("services"):
            self._intel["services"] = services
        if new_cves and not self._intel.get("cves"):
            self._intel["cves"] = new_cves
        if vulns and not self._intel.get("vulnerabilities"):
            self._intel["vulnerabilities"] = vulns

        await self._emit_reasoning(
            f"Recovered {len(ports)} open port(s) "
            f"({', '.join(str(p) for p in sorted(ports)[:12])}) and "
            f"{len(services)} service(s) from the findings store — "
            f"in-memory intel was empty despite a completed recon"
        )
        return len(ports)

    async def _observe(self) -> dict:
        """Snapshot the current evidence state."""
        # Self-healing: if recon evidence never reached the shared intel dict
        # (stale build / failed sync path), rebuild it from the findings the
        # scan actually produced so the loop never reasons on empty evidence
        # while the database holds a full attack surface.
        if not self._intel.get("open_ports"):
            await self._reconcile_intel_from_findings()
        elif (self._iteration % 3) == 0:
            # Partial-list guard: even with SOME ports, periodically union-merge
            # from the findings store so a truncated open_ports (e.g. [80] when
            # recon found [22,80]) can't keep the loop stuck on "Ports open: 1".
            await self._reconcile_intel_from_findings(union=True)
        return {
            "target":          self._intel.get("target", self._target),
            "open_ports":      self._intel.get("open_ports", []),
            "services":        self._intel.get("services", {}),
            "technologies":    self._intel.get("technologies", []),
            "web_paths":       self._intel.get("web_paths", []),
            "web_targets":     self._intel.get("web_targets", []),
            "vulnerabilities": self._intel.get("vulnerabilities", []),
            "cves":            self._intel.get("cves", []),
            "credentials":     self._intel.get("credentials", []),
            "shell_access":    self._intel.get("shell_access", False),
            "current_user":    self._intel.get("current_user"),
            "user_flag":       self._intel.get("user_flag"),
            "root_flag":       self._intel.get("root_flag"),
            "web_vulns":       self._intel.get("web_vulns", []),
            "os_guess":        self._intel.get("os_guess", ""),
            "domain_info":     self._intel.get("domain_info", {}),
        }

    async def _interpret(self, evidence: dict) -> str:
        """
        LLM produces a one-sentence situation assessment.
        Appended to reasoning_journal for audit trail.
        """
        # Normalise the port count: dedupe by integer port number so mixed
        # shapes (80 vs "80/tcp") and duplicates can't under/over-count and make
        # the assessment claim "Ports open: 1" when several are actually open.
        _pset = set()
        for _p in (evidence.get("open_ports") or []):
            try:
                _pset.add(int(str(_p).split("/")[0]))
            except (ValueError, TypeError):
                _pset.add(str(_p))
        ports   = len(_pset)
        shell   = evidence.get("shell_access", False)
        vulns   = len(evidence.get("vulnerabilities", []))
        creds   = len(evidence.get("credentials", []))
        score   = self._decision_eng.get_score()

        system = (
            "You are a penetration tester. In ONE sentence, state the most important "
            "fact about the current situation that should drive the next action. "
            "Be specific and actionable. No JSON needed."
        )
        prompt = (
            f"Target: {self._target}\n"
            f"Ports open: {ports} | Vulns: {vulns} | Creds: {creds}\n"
            f"Shell access: {shell}\n"
            f"Score: {score:+d}\n"
            f"Iteration: {self._iteration}\n\n"
            "One-sentence situation assessment:"
        )

        try:
            assessment = await self._master.think(prompt, system)
            return (assessment or "").strip()[:200]
        except Exception:
            return f"Iteration {self._iteration}: {ports} ports, {vulns} vulns, shell={shell}"

    async def _hypothesize(self, evidence: dict) -> List[Hypothesis]:
        """
        Delegate to HypothesisEngine and emit expert-methodology reasoning events.

        The HypothesisEngine stores temporary observation/interpretation/avoid
        in intel under '_tmp_*' keys.  We pop them here, emit them as visible
        reasoning traces for the operator, then delete them so they don't
        pollute checkpoints.
        """
        hypotheses = await self._hypothesis_eng.generate_hypotheses(
            intel           = self._intel,
            negative_memory = self._neg_memory,
            iteration       = self._iteration,
        )

        # ── Emit expert OBSERVE / INTERPRET / AVOID events ───────────────────
        observation    = self._intel.pop("_tmp_observation",    "")
        interpretation = self._intel.pop("_tmp_interpretation", "")
        avoid_list     = self._intel.pop("_tmp_avoid",          [])

        if observation:
            await self._emit_reasoning(f"🔍 OBSERVE [{self._iteration}]: {observation}")
        if interpretation:
            await self._emit_reasoning(f"💡 INTERPRET [{self._iteration}]: {interpretation}")
        if avoid_list:
            avoid_str = " | ".join(str(a)[:80] for a in avoid_list[:4])
            await self._emit_reasoning(f"🚫 AVOID: {avoid_str}")

        # ── Emit DECIDE event showing the 1-2 chosen actions ─────────────────
        if hypotheses:
            action_strs = []
            for h in hypotheses[:2]:
                if h.recommended_next_actions:
                    action_strs.append(h.recommended_next_actions[0][:100])
            if action_strs:
                await self._emit_reasoning(
                    f"⚡ DECIDE [{self._iteration}]: "
                    + " | ".join(f"({i+1}) {a}" for i, a in enumerate(action_strs))
                )

        return hypotheses

    def _evidence_fingerprint(self, *, full: bool) -> str:
        """Stable hash of the current progress state.

        ``full=False`` → COMPROMISE progress only (shell, elevated, flags,
        creds, vulns, web_vulns, cves, loot, graded objectives).  Used to
        decide escalation + convergence: discovering yet another 404 path does
        NOT count as progress, so a fuzzer cannot keep the loop alive forever.

        ``full=True`` → the above PLUS the cheap recon surface (open ports,
        web paths / params / tech tags).  Used to decide whether the two
        expensive planning LLM calls can be skipped (state genuinely static).
        """
        it = self._intel

        def _n(key: str) -> int:
            v = it.get(key)
            if isinstance(v, (list, dict, set, tuple, str)):
                return len(v)
            return 1 if v else 0

        parts = [
            "sh:%d"  % (1 if it.get("shell_access")   else 0),
            "es:%d"  % (1 if it.get("elevated_shell") else 0),
            "uf:%d"  % (1 if it.get("user_flag")      else 0),
            "rf:%d"  % (1 if it.get("root_flag")      else 0),
            "cr:%d"  % _n("credentials"),
            "v:%d"   % _n("vulnerabilities"),
            "wv:%d"  % _n("web_vulns"),
            "cve:%d" % _n("cves"),
            "loot:%d" % _n("loot"),
        ]
        # Graded-objective completion count (holistic grader output).
        try:
            st = it.get("objective_status") or {}
            done = sum(1 for s in st.values()
                       if str(s).lower() in ("complete", "completed", "done", "achieved"))
            parts.append("obj:%d" % done)
        except Exception:
            pass

        if full:
            try:
                ports = sorted(
                    str(p.get("port") if isinstance(p, dict) else p)
                    for p in (it.get("open_ports") or [])
                )
            except Exception:
                ports = []
            parts.extend([
                "p:" + ",".join(ports),
                "wp:%d"  % _n("web_paths"),
                "wpu:%d" % _n("web_param_urls"),
                "tag:%d" % _n("web_tech_tags"),
            ])
        return "|".join(parts)

    async def _escalate_to_exploitation(self) -> None:
        """Forced exploitation push when the loop stalls.

        Fires ONCE, after the loop has demonstrably stopped making compromise
        progress, before the convergence break.  Re-runs the exploit phase
        (which launches the ExploitOrchestrator — searchsploit / metasploit /
        web_exploit / credential_spray — and, on Tier-1 failure, the Tier-2
        LLM synth path that writes a bespoke PoC for service-specific targets
        like an IPFS / InfluxDB API that have no off-the-shelf exploit).

        Heavily guarded — never raises into the loop.  ``_phase_exploit`` was
        already run earlier in the engagement without hanging, so re-running it
        here is safe with respect to the mandatory human-approval gate.
        """
        m = self._master
        try:
            await self._emit_loop_event("exploitation_escalation", {
                "iteration": self._iteration,
                "reason":    "stall",
            })
        except Exception:
            pass
        # Re-dispatch the full exploit phase, overriding the per-phase
        # idempotency guard so the orchestrator + synth fallback run again
        # against the latest intel.
        try:
            phase_fn = getattr(m, "_phase_exploit", None)
            if phase_fn is not None:
                await self._safe_phase(phase_fn, phase_slug="exploit",
                                       force=True, target=self._target)
        except Exception as exc:
            await self._emit_reasoning(f"[stall] exploit re-dispatch error: {exc}")

    async def _prioritize(self) -> List[RankedAttackPath]:
        """Delegate to AttackPlanner."""
        return await self._attack_planner.rank_paths(
            intel           = self._intel,
            hypotheses      = self._hypotheses,
            negative_memory = self._neg_memory,
            iteration       = self._iteration,
        )

    async def _execute(self, action: JustifiedAction) -> dict:
        """
        Dispatch the action to the appropriate slave agent.
        Returns a result dict with stdout, exit_code, and any parsed findings.
        """
        try:
            return await self._master._dispatch_to_agent(
                tool    = action.tool,
                args    = action.args,
                purpose = action.reason,
                phase   = action.hypothesis_id,
            )
        except Exception as e:
            return {"error": str(e), "stdout": "", "exit_code": -1}

    async def _validate(
        self,
        action:     JustifiedAction,
        result:     dict,
        hypothesis: Optional[Hypothesis],
    ) -> bool:
        """
        Ask the LLM: does this result confirm or refute the hypothesis?
        Falls back to heuristic validation on LLM failure.

        Improvement #14 — after the LLM/heuristic returns 'validated',
        the Issue Validator is run as a hard gate.  Even an enthusiastic
        'yes' from the LLM is overruled when the raw stdout contains no
        concrete evidence pattern for the hypothesis class.  Findings
        that fail the gate stay at 'suspected'.
        """
        if not hypothesis:
            return False

        stdout_full = (result.get("stdout") or result.get("output") or "")
        stdout      = stdout_full[:1000]
        exit_code   = result.get("exit_code", -1)

        soft_validated = False  # the pre-gate verdict

        # Quick heuristic: obvious failure signals
        error_signals = [
            "connection refused", "no route to host",
            "command not found", "permission denied",
            "module not found", "exploit failed",
        ]
        stdout_lower = stdout.lower()
        failed_hard = any(sig in stdout_lower for sig in error_signals)

        if failed_hard:
            soft_validated = False
        else:
            # Quick heuristic: obvious success signals
            success_signals = ["shell", "uid=", "whoami", "flag{", "root@", "meterpreter"]
            if any(sig in stdout_lower for sig in success_signals):
                soft_validated = True
            elif len(stdout) < 20:
                soft_validated = (exit_code == 0)
            else:
                system = (
                    "You are a penetration tester reviewing a tool's output. "
                    "Determine if the output confirms the hypothesis. "
                    "Respond with ONLY 'yes' or 'no'."
                )
                prompt = (
                    f"Hypothesis: {hypothesis.statement}\n"
                    f"Tool: {action.tool}\n"
                    f"Exit code: {exit_code}\n"
                    f"Output:\n{stdout[:500]}\n\n"
                    "Does this output confirm the hypothesis? (yes/no)"
                )
                try:
                    response = await self._master.think(prompt, system)
                    response = (response or "").strip().lower()
                    soft_validated = response.startswith("yes")
                except Exception:
                    soft_validated = (exit_code == 0)

        # ── HARD GATE (Improvement #14) ───────────────────────────────
        try:
            from agents.reasoning.issue_validator import validate_grounding
            iv = validate_grounding(
                statement = hypothesis.statement or "",
                mitre     = hypothesis.mitre_technique or "",
                tool      = action.tool or "",
                stdout    = stdout_full,
                exit_code = exit_code,
            )
            grounded = iv.grounded
            await self._emit({
                "type":       "finding_validation",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "statement":     (hypothesis.statement or "")[:160],
                    "tool":          action.tool,
                    "soft_validated": soft_validated,
                    "grounded":       grounded,
                    "validation":     iv.to_dict(),
                },
            })
            if soft_validated and not grounded:
                # Override: refuse to confirm without grounding evidence.
                await self._emit_reasoning(
                    f"[issue_validator] downgraded {hypothesis.hypothesis_id} "
                    f"({iv.issue_class}) — {iv.reason}"
                )
                return False

            # Recommendation A — when grounding identifies a shell-class win,
            # register it through the master so post-ex / privesc / lateral
            # phases can fire regardless of which path produced the shell.
            if grounded and iv.issue_class == "shell_obtained":
                try:
                    register = getattr(self._master, "register_shell", None)
                    if callable(register):
                        # Try to extract a user from the matched evidence.
                        user = "unknown"
                        for q in iv.evidence_quotes:
                            ql = q.lower()
                            if "uid=0" in ql or "(root)" in ql:
                                user = "root"; break
                            if "system" in ql or "nt authority" in ql:
                                user = "SYSTEM"; break
                        await register(
                            source   = f"reasoning_loop:{action.tool}",
                            user     = user,
                            host     = self._target,
                            method   = action.tool,
                            evidence = (iv.evidence_quotes[0] if iv.evidence_quotes else "")[:300],
                        )
                except Exception as _re_exc:
                    await self._emit_reasoning(f"[register_shell] error: {_re_exc}")

            # If soft says no but grounding finds strong evidence, leave
            # the soft verdict in place (the heuristic / LLM saw a real
            # failure signal we trust over our pattern set).
            return soft_validated
        except Exception as exc:
            await self._emit_reasoning(f"[issue_validator] gate error: {exc}")
            return soft_validated

    async def _update(
        self,
        action:     JustifiedAction,
        result:     dict,
        validated:  bool,
        hypothesis: Optional[Hypothesis],
    ) -> None:
        """
        Update all state after an action completes:
          - Mark hypothesis validated/invalidated
          - Update attack path scores
          - Record failure in NegativeMemory if not validated
          - Update action score
          - Persist to DB
        """
        # B-2 — Credential-validation observer.  The credentialed primer
        # gates its expensive steps on intel['ad']['creds_validated'].
        # We detect the outcome from the cheapest probe (crackmapexec smb
        # without flags / sshpass+ssh) and set the flag.  Without this,
        # the gate never opens and the heavy steps never run; OR a typo'd
        # password silently runs the entire chain.
        try:
            self._observe_cred_validation(action, result)
        except Exception:
            pass
        # Update hypothesis status
        if hypothesis:
            if validated:
                hypothesis.validated   = True
            else:
                hypothesis.invalidated = True
            # Update confidence scores
            delta = 0.15 if validated else -0.25
            hypothesis.confidence = max(0.0, min(1.0, hypothesis.confidence + delta))
            self._intel["confidence_scores"][hypothesis.hypothesis_id] = hypothesis.confidence

            # Persist updated status
            try:
                await getattr(self._master, "_db_update_hypothesis", lambda *a, **k: None)(
                    session_id    = self._session_id,
                    hypothesis_id = hypothesis.hypothesis_id,
                    validated     = validated,
                    invalidated   = not validated,
                    confidence    = hypothesis.confidence,
                )
            except Exception:
                pass

        # Update attack planner
        if self._ranked_paths:
            best = self._ranked_paths[0]
            await self._attack_planner.update_path_after_result(
                path          = best,
                action_tool   = action.tool,
                action_result = result,
                validated     = validated,
            )

        # Record failure in NegativeMemory
        if not validated:
            stdout  = (result.get("stdout") or result.get("output") or "")[:500]
            reasons = self._extract_failure_reason(result)
            await self._neg_memory.record_failure(
                tool           = action.tool,
                args           = action.args,
                target_service = action.target_service,
                failure_reason = reasons,
                evidence       = stdout,
                hypothesis_id  = action.hypothesis_id,
                host           = self._target,
            )
            self._intel["negative_memory"] = self._neg_memory.to_dict_list()

            # Update failed_attempts quick-index
            key = f"{action.tool}:{action.target_service}"
            fa  = self._intel.get("failed_attempts", {})
            fa[key] = fa.get(key, 0) + 1
            self._intel["failed_attempts"] = fa

        # B-5 — Record SUCCESSFUL-BUT-UNINFORMATIVE outputs in negative_memory
        # too.  Without this, a curl `-w '%{http_code}' -o /dev/null` against
        # /admin returns "404\n" (short, exit-0) which the heuristic
        # validator marks `validated=True`, so the failure-record branch
        # above never fires.  Result: the LLM re-proposes the same URL
        # every iteration.  Tracking these as low-signal failures keyed on
        # (tool, args_signature) makes the dedup pre-flight check work.
        else:
            # B-9 — record genuine successes in success_index so primer
            # dispatchers know not to re-fire the same step.
            try:
                if isinstance(result.get("exit_code"), int) and result["exit_code"] == 0:
                    self._neg_memory.record_success(
                        tool           = action.tool,
                        target_service = action.target_service,
                        args           = action.args,
                    )
            except Exception:
                pass
            low_signal_reason = self._classify_low_signal_result(action, result)
            if low_signal_reason:
                stdout = (result.get("stdout") or result.get("output") or "")[:500]
                await self._neg_memory.record_failure(
                    tool           = action.tool,
                    args           = action.args,
                    target_service = action.target_service,
                    failure_reason = f"low_signal:{low_signal_reason}",
                    evidence       = stdout,
                    hypothesis_id  = action.hypothesis_id,
                    host           = self._target,
                )
                self._intel["negative_memory"] = self._neg_memory.to_dict_list()

        # Capture score BEFORE update so delta calculation is accurate
        prev_score = self._intel.get("action_score", 0)

        # Update engagement score
        new_score, score_reason = await self._decision_eng.score_action_result(
            action    = action,
            result    = result,
            validated = validated,
            intel     = self._intel,
        )
        self._intel["action_score"] = new_score

        # Persist score event to DB — delta = new − previous (captured before update)
        try:
            import db.mongo_client as dbm
            await dbm.store_action_score_event(
                session_id    = self._session_id,
                host          = self._target,
                action_id     = action.action_id,
                delta         = new_score - prev_score,
                reason        = score_reason,
                running_total = new_score,
                tool          = action.tool,
                hypothesis_id = action.hypothesis_id,
            )
        except Exception:
            pass

        # Track used_tools on master agent
        if hasattr(self._master, "_used_tools"):
            key = f"{action.tool}:{action.target_service}"
            self._master._used_tools[key] = self._master._used_tools.get(key, 0) + 1

        # Emit update event
        await self._emit_loop_event("state_updated", {
            "validated":      validated,
            "action_score":   new_score,
            "score_reason":   score_reason,
            "neg_mem_count":  len(self._neg_memory),
        })

    # ------------------------------------------------------------------
    # Specialist evidence gathering
    # ------------------------------------------------------------------

    def _get_or_init_web_intel(self) -> Optional[Any]:
        """Lazy-init the WebIntelAgent.  Returns ``None`` if the module
        isn't importable (e.g. unit-test harness) so the calling site can
        proceed without it."""
        if self._web_intel is not None:
            return self._web_intel
        try:
            from agents.reasoning.web_intel_agent import WebIntelAgent
        except Exception as exc:
            import logging as _l
            _l.getLogger(__name__).warning(
                "[reasoning_loop] WebIntelAgent unavailable: %s", exc
            )
            return None
        self._web_intel = WebIntelAgent(
            master_agent = self._master,
            session_id   = self._session_id,
            target       = self._target,
            broadcast    = self._emit,
        )
        return self._web_intel

    async def _gather_more_evidence(self) -> bool:
        """
        Run ALL relevant specialist agents simultaneously based on what's known.
        Like a human pentester: don't pick one thread — chase every lead in parallel.
        Returns True if any evidence-gathering tasks were launched.
        """
        intel = self._intel
        tasks: list  = []   # (label, step_id, phase, coroutine)

        # ── Engagement context guards ────────────────────────────────────────
        eng_ctx    = intel.get("engagement_context") or {}
        tools_excl = {t.lower().split()[0] for t in (eng_ctx.get("tools_excluded") or [])}
        is_passive = eng_ctx.get("engagement_type", "pentest") in (
            "forensics", "network_analysis", "malware_analysis", "compliance"
        )

        # ── Active Directory ────────────────────────────────────────────────
        if not is_passive and self._should_run_ad() and "bloodhound-python" not in tools_excl:
            tasks.append(("AD Enumeration", "ad_enum", "lateral",
                          self._run_ad_enum()))

        # ── Web deep scan ───────────────────────────────────────────────────
        if not is_passive and "gobuster" not in tools_excl and (intel.get("web_targets") or intel.get("web_paths")):
            web_ports = [
                p.get("port") if isinstance(p, dict) else p
                for p in intel.get("open_ports", [])
                if (p.get("port") if isinstance(p, dict) else p)
                   in {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}
            ] or [80]
            tasks.append(("Web Deep Scan", "web_deep", "web_testing",
                          self._safe_phase(self._master._phase_web_testing,
                                           target=self._target, web_ports=web_ports)))

        # ── Vulnerability scan ──────────────────────────────────────────────
        # Run if: ports exist AND (no vulns yet OR fewer than expected based on port count)
        vuln_count = len(intel.get("vulnerabilities") or [])
        port_count = len(intel.get("open_ports") or [])
        vuln_scan_needed = intel.get("open_ports") and (
            vuln_count == 0 or                                    # no vulns at all
            (port_count > 3 and vuln_count < 3) or                # many ports but few vulns
            not intel.get("_vuln_agent_ran")                      # vuln agent hasn't run yet
        )
        if not is_passive and "nikto" not in tools_excl and vuln_scan_needed:
            intel["_vuln_agent_ran"] = True  # prevent re-running
            tasks.append(("Vulnerability Scan", "vuln_scan", "vuln_id",
                          self._safe_phase(self._master._phase_vuln_id,
                                           target=self._target)))

        # ── Cloud metadata ──────────────────────────────────────────────────
        if not is_passive and self._should_run_cloud():
            tasks.append(("Cloud Enumeration", "cloud_check", "post_exploit",
                          self._safe_phase(self._master._phase_cloud,
                                           target=self._target)))

        # ── Container escape ────────────────────────────────────────────────
        if intel.get("container_info", {}).get("type"):
            tasks.append(("Container Escape", "container_escape", "privesc",
                          self._safe_phase(self._master._phase_container,
                                           target=self._target)))

        # ── Privilege escalation (if shell) ─────────────────────────────────
        if intel.get("shell_access") and not intel.get("root_flag"):
            tasks.append(("Privilege Escalation", "privesc_enum", "privesc",
                          self._safe_phase(self._master._phase_privesc,
                                           target=self._target)))

        # ── Lateral movement (if creds or AD) ───────────────────────────────
        if not is_passive and self._should_run_lateral():
            tasks.append(("Lateral Movement", "lateral_move", "lateral",
                          self._safe_phase(self._master._phase_lateral_movement,
                                           target=self._target)))

        if not tasks:
            return False

        # Emit active plan steps for every launched task
        labels = [l for l, _, _, _ in tasks]
        await self._emit_reasoning(f"Chasing {len(tasks)} evidence threads: {', '.join(labels)}")
        for label, step_id, phase, _ in tasks:
            await self._emit_plan_step(step_id, f"🔍 {label}", "active",
                                       f"Running {label.lower()}", phase)

        # Run all in parallel
        results = await asyncio.gather(*[coro for _, _, _, coro in tasks],
                                       return_exceptions=True)

        # Mark plan steps done/failed
        for (label, step_id, phase, _), result in zip(tasks, results):
            success = not isinstance(result, Exception)
            if isinstance(result, Exception):
                await self._emit_reasoning(f"{label} error: {result}")
            await self._emit_plan_step(step_id, f"🔍 {label}",
                                       "done" if success else "failed",
                                       "", phase, found=success)

        return True

    # ------------------------------------------------------------------
    # Intel-based answer extraction (post-bootstrap)
    # ------------------------------------------------------------------

    async def _extract_answers_from_intel(self) -> None:
        """
        After bootstrap, build a comprehensive text summary of everything we
        know (open ports, services, vulnerabilities, technologies, etc.) and
        run answer extraction against it.  This catches easy wins like
        'How many ports are open?' or 'What web server is running?'
        """
        intel = self._intel
        lines: list[str] = []

        # Ports + services
        ports = intel.get("open_ports") or []
        if ports:
            lines.append(f"Open ports ({len(ports)} total):")
            for p in ports[:60]:
                if isinstance(p, dict):
                    lines.append(
                        f"  {p.get('port','')} / {p.get('protocol','tcp')} "
                        f"— {p.get('service','')} {p.get('version','')}"
                    )
                else:
                    lines.append(f"  {p}")

        # Services list
        services = intel.get("services") or []
        if services:
            lines.append(f"\nServices ({len(services)}):")
            for s in services[:30]:
                if isinstance(s, dict):
                    lines.append(
                        f"  {s.get('port','')}: {s.get('name','')} "
                        f"{s.get('product','')} {s.get('version','')}"
                    )
                else:
                    lines.append(f"  {s}")

        # OS guess
        if intel.get("os_guess"):
            lines.append(f"\nOS guess: {intel['os_guess']}")

        # Vulnerabilities
        vulns = intel.get("vulnerabilities") or []
        if vulns:
            lines.append(f"\nVulnerabilities ({len(vulns)}):")
            for v in vulns[:30]:
                if isinstance(v, dict):
                    lines.append(
                        f"  [{v.get('severity','?')}] {v.get('title','')} "
                        f"{v.get('cve','')} — {v.get('description','')[:120]}"
                    )
                else:
                    lines.append(f"  {v}")

        # CVEs
        cves = intel.get("cves") or []
        if cves:
            lines.append(f"\nCVEs: {', '.join(str(c) for c in cves[:30])}")

        # Technologies
        techs = intel.get("technologies") or []
        if techs:
            lines.append(f"\nTechnologies: {', '.join(str(t) for t in techs[:30])}")

        # Web targets
        webs = intel.get("web_targets") or []
        if webs:
            lines.append(f"\nWeb targets: {', '.join(str(w) for w in webs[:20])}")

        # Web paths
        paths = intel.get("web_paths") or []
        if paths:
            lines.append(f"\nWeb paths ({len(paths)}):")
            for wp in paths[:40]:
                if isinstance(wp, dict):
                    lines.append(f"  {wp.get('path','')} [{wp.get('status','')}] {wp.get('title','')}")
                else:
                    lines.append(f"  {wp}")

        # Web vulns
        wvulns = intel.get("web_vulns") or []
        if wvulns:
            lines.append(f"\nWeb vulnerabilities ({len(wvulns)}):")
            for wv in wvulns[:20]:
                if isinstance(wv, dict):
                    lines.append(f"  {wv.get('type','')}: {wv.get('url','')} — {wv.get('detail','')[:100]}")
                else:
                    lines.append(f"  {wv}")

        # Credentials
        creds = intel.get("credentials") or []
        if creds:
            lines.append(f"\nCredentials ({len(creds)}):")
            for c in creds[:15]:
                if isinstance(c, dict):
                    lines.append(f"  {c.get('user','')}:{c.get('secret','')} ({c.get('service','')})")
                else:
                    lines.append(f"  {c}")

        # Domain info
        domain = intel.get("domain_info")
        if domain:
            lines.append(f"\nDomain info: {domain}")

        if not lines:
            return

        summary = "\n".join(lines)

        # Create a synthetic action and result for the standard extraction method
        class _SyntheticAction:
            tool = "bootstrap_recon"
            args = ""
            reason = "Intelligence bootstrap"
        await self._extract_ctf_answers(_SyntheticAction(), {"stdout": summary})

    # ------------------------------------------------------------------
    # CTF answer extraction
    # ------------------------------------------------------------------

    async def _extract_ctf_answers(self, action, result: dict) -> None:
        """
        After each tool execution, ask the LLM to extract answers to any
        unanswered objectives from the raw tool output.

        Works for any engagement type — CTF flags, forensic artifacts,
        network IOCs, malware indicators, etc.

        Emits `ctf_answer` WS events and stores answers as high-priority findings.
        """
        eng_ctx    = self._intel.get("engagement_context") or {}
        eng_type   = eng_ctx.get("engagement_type", "pentest")
        objectives = eng_ctx.get("objectives") or self._intel.get("ctf_objectives") or []
        if not objectives:
            return

        ctf_answers  = self._intel.setdefault("ctf_answers", {})
        unanswered   = [
            (i, obj) for i, obj in enumerate(objectives)
            if str(i) not in ctf_answers
        ]
        if not unanswered:
            return

        stdout = (result.get("stdout") or result.get("output") or "")
        if not stdout.strip():
            return

        # Send generous chunk to LLM — tool outputs with port/service data
        # need enough context for the LLM to count/identify items
        stdout_snippet = stdout[:8000]

        # Build compact objective list for the LLM — include ALL unanswered
        # (up to 30) so nothing is missed just because it's low-priority
        q_lines = "\n".join(
            f"{i+1}. {obj.get('task') or obj.get('question') or str(obj)}"
            for i, obj in unanswered[:30]
        )

        # Engagement-type-specific extraction hints
        extraction_hints = {
            "ctf":             "Flags look like: flag{...}, FLAG{...}, or a specific value/number/string.",
            "forensics":       "Look for file paths, timestamps, usernames, deleted content, metadata values.",
            "network_analysis":"Look for suspicious IPs, ports, protocols, credentials, C2 indicators.",
            "malware_analysis":"Look for URLs, IPs, registry keys, file paths, API calls, hashes.",
            "compliance":      "Look for configuration values, version numbers, policy settings, enabled/disabled states.",
        }.get(eng_type, "Look for specific values, strings, numbers, or paths that directly answer each question.")

        prompt = (
            f"Engagement type: {eng_type}\n"
            f"Tool executed: {action.tool}\n"
            f"Tool output / intelligence summary:\n{stdout_snippet}\n\n"
            f"Objectives to answer:\n{q_lines}\n\n"
            f"Extraction guidance: {extraction_hints}\n\n"
            "INSTRUCTIONS:\n"
            "- For each objective, check if the output above contains enough data to answer it.\n"
            "- Answers CAN be derived by counting items, reading version strings, identifying services, etc.\n"
            "- For 'how many' questions, COUNT the relevant items in the output.\n"
            "- For 'what is' questions, extract the exact value from the output.\n"
            "- Be precise — give the specific value, number, name, or string.\n"
            "- Do NOT fabricate data not supported by the output.\n"
            "- Include evidence: the actual line(s) from the output that support your answer.\n\n"
            "Respond with JSON only — no markdown fences, no prose:\n"
            '{{"answers": [{{"index": <objective_number>, "question": "...", "answer": "the answer", "evidence": "supporting line(s) from output"}}]}}\n'
            'If no objectives can be answered from this output, return: {{"answers": []}}'
        )
        system = (
            f"You are a {eng_type} expert extracting precise answers from tool output. "
            "You can count items, read versions, identify services, and derive answers from data. "
            "Be accurate and specific. Only answer what the data supports."
        )

        try:
            raw = await self._master.think_json(prompt, system)
        except Exception:
            return

        if not isinstance(raw, dict):
            return

        answers_found = raw.get("answers", [])
        if not isinstance(answers_found, list):
            return

        for item in answers_found:
            if not isinstance(item, dict):
                continue
            idx     = item.get("index")
            answer  = (item.get("answer") or "").strip()
            evidence= (item.get("evidence") or "").strip()
            question= (item.get("question") or "").strip()

            if not answer:
                continue

            # Map by index (1-based from LLM) or by question text match
            target_idx = None
            if isinstance(idx, int) and 1 <= idx <= len(objectives):
                target_idx = idx - 1  # convert to 0-based
            else:
                for i, obj in unanswered:
                    q = (obj.get("task") or obj.get("question") or str(obj)) if isinstance(obj, dict) else str(obj)
                    if question.lower() in q.lower() or q.lower() in question.lower():
                        target_idx = i
                        break

            if target_idx is None:
                continue
            if str(target_idx) in ctf_answers:
                continue  # already answered

            obj       = objectives[target_idx]
            q_text    = (obj.get("task") or obj.get("question") or str(obj)) if isinstance(obj, dict) else str(obj)
            section   = obj.get("section", "") if isinstance(obj, dict) else ""

            # Store the answer
            ctf_answers[str(target_idx)] = {
                "answer":   answer,
                "evidence": evidence,
                "tool":     action.tool,
                "iteration": self._iteration,
            }
            self._intel["ctf_answers"] = ctf_answers

            await self._emit_reasoning(
                f"🏁 CTF Answer [{target_idx+1}]: {q_text} → {answer}"
            )

            # Broadcast ctf_answer event (drives FindingsBoard checklist)
            await self._emit({
                "type":       "ctf_answer",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "objective_index": target_idx,
                    "objective":       q_text,
                    "section":         section,
                    "answer":          answer,
                    "evidence":        evidence,
                    "tool":            action.tool,
                    "iteration":       self._iteration,
                    "total":           len(objectives),
                    "answered_count":  len(ctf_answers),
                },
            })

            # Also persist as a regular finding so it shows in FindingsBoard table
            await self._emit_finding(
                title       = f"[CTF #{target_idx+1}] {q_text}",
                severity    = "high",
                description = f"Answer: **{answer}**\n\nEvidence:\n{evidence}\n\nTool: {action.tool}",
                phase       = "exploit",
                tool        = action.tool,
                mitre       = "",
            )

            # Emit plan step so MissionControl tracks CTF progress
            await self._emit_plan_step(
                step_id     = f"ctf_{target_idx}",
                label       = f"🏁 [{target_idx+1}] {q_text[:60]}",
                status      = "done",
                result      = answer,
                phase       = "exploit",
                probability = 1.0,
                found       = True,
            )

    # ------------------------------------------------------------------
    # Specialist condition helpers
    # ------------------------------------------------------------------

    async def _safe_phase(self, phase_fn, *, phase_slug: Optional[str] = None,
                          force: bool = False, **kwargs):
        """Call a MasterAgent phase safely, returning {} on error.

        Wraps the call with meta-agent pre/post hooks so MasterChecker and
        IssueValidator are exercised during the reasoning-loop path (which
        bypasses the legacy phase-by-phase flow where those hooks live).

        Improvement #4 — unified decision loop:
          * ``phase_slug`` may be passed explicitly to decouple meta-hooks
            from the ``_phase_*`` naming convention.  When omitted, the slug
            is derived from the function name as before (back-compat).
          * ``force=False`` skips the call when this phase slug was already
            dispatched in a previous iteration, returning ``{}``.  Pass
            ``force=True`` for the bootstrap phase or for explicit
            re-runs that need to override the idempotency guard.
        """
        name = getattr(phase_fn, "__name__", "phase")
        # Derive phase slug from method name: "_phase_recon" → "recon"
        if not phase_slug:
            phase_slug = name.replace("_phase_", "").strip("_") or "reasoning"

        # Idempotency: skip if already dispatched (unless force=True).
        if not force and phase_slug in self._phases_dispatched:
            await self._emit_reasoning(
                f"[loop] {phase_slug} already dispatched at iter "
                f"{self._phases_dispatched[phase_slug]} — skipping"
            )
            return {}
        # Mark as dispatched up-front so concurrent calls do not race.
        self._phases_dispatched[phase_slug] = self._iteration

        # Broadcast that a unit-of-work is starting (operator transparency).
        try:
            await self._emit({
                "type":       "phase_unit_dispatched",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       {
                    "phase":     phase_slug,
                    "iteration": self._iteration,
                    "forced":    bool(force),
                },
            })
        except Exception:
            pass

        # MasterChecker was removed; the IssueValidator now runs as a real
        # finding GATE at the store_finding choke-point (covers this legacy path
        # too), so _safe_phase keeps only the live Expert advisor.
        ex  = getattr(self._master, "_expert",          None)
        _meta_on = getattr(self._master, "_meta_agents_enabled", False)

        # F8 — meta-review budget: review each distinct phase ONCE, and cap the
        # total number of 4-call review passes per engagement.  A forced
        # re-dispatch (e.g. the stall-escalation exploit re-run) no longer
        # re-fires the whole pre/post review storm, and a pathological loop
        # can't spin out ~65 corrections.  Meta-agents inform, not flood.
        _meta_budget_ok = (
            phase_slug not in self._meta_reviewed_phases
            and self._meta_review_passes < _MAX_META_REVIEW_PASSES
        )
        if _meta_on and _meta_budget_ok:
            self._meta_reviewed_phases.add(phase_slug)
            self._meta_review_passes += 1
        elif _meta_on and not _meta_budget_ok:
            await self._emit_reasoning(
                f"[meta] skipping duplicate/over-budget review for '{phase_slug}' "
                f"(passes {self._meta_review_passes}/{_MAX_META_REVIEW_PASSES})"
            )

        ex_enabled = _meta_on and _meta_budget_ok and ex is not None

        # Collect pre-phase peer corrections so the Expert can grade them.
        pre_peer_corrections = []

        # ── EXPERT: pre-phase directive (runs FIRST, sets mission context) ─
        # Wrapped in a hard timeout so a slow LLM (xploiter, deepseek 671b on
        # CPU, etc.) can't block the actual scan.  The directive is advisory.
        if ex_enabled:
            try:
                await _meta_review_with_timeout(
                    ex.pre_phase_directive(
                        phase          = phase_slug,
                        intel_snapshot = dict(self._intel),
                    ),
                    label          = f"expert.pre_phase_directive({phase_slug})",
                    timeout        = _META_PRE_TIMEOUT,
                    emit_reasoning = self._emit_reasoning,
                )
            except Exception as e:
                await self._emit_reasoning(f"[expert] pre_phase_directive({phase_slug}) error: {e}")

        # ── Actual phase ──────────────────────────────────────────
        try:
            result = await phase_fn(**kwargs)
            result = result or {}
        except Exception as e:
            await self._emit_reasoning(f"{name} error: {e}")
            result = {}

        # ── EXPERT: post-phase directive ──────────────────────────
        if ex_enabled:
            try:
                # Pull this phase's findings for the Expert directive.
                phase_findings_ex = []
                try:
                    from db import mongo_client as _db2
                    phase_findings_ex = await _db2.get_findings_by_phase(
                        self._master._session_id, phase_slug
                    ) or []
                except Exception:
                    pass

                # No MasterChecker/IssueValidator peer corrections any more; the
                # Expert reviews only what the pre-phase produced (currently none).
                peer_all = list(pre_peer_corrections)

                expert_corrs = await _meta_review_with_timeout(
                    ex.post_phase_directive(
                        phase            = phase_slug,
                        intel_snapshot   = dict(self._intel),
                        findings         = phase_findings_ex,
                        peer_corrections = peer_all,
                    ),
                    label          = f"expert.post_phase_directive({phase_slug})",
                    timeout        = _META_POST_TIMEOUT,
                    emit_reasoning = self._emit_reasoning,
                )
                # Expert's own peer-review corrections flow through _handle_corrections
                # as advisory guidance too (never blocking by default).
                if expert_corrs and hasattr(self._master, "_handle_corrections"):
                    try:
                        await self._master._handle_corrections(expert_corrs, phase_slug, allow_replan=False)
                    except Exception:
                        pass
            except Exception as e:
                await self._emit_reasoning(f"[expert] post_phase_directive({phase_slug}) error: {e}")

        # ── Win-condition tracker (Improvement #2) ────────────────
        try:
            if hasattr(self._master, "evaluate_win_conditions"):
                snap = await self._master.evaluate_win_conditions(phase=phase_slug)
                if snap and snap.get("newly_achieved"):
                    await self._emit_reasoning(
                        f"[win] {phase_slug}: newly achieved → {', '.join(snap['newly_achieved'])} "
                        f"({snap['achieved_count']}/{snap['total']})"
                    )
        except Exception as e:
            await self._emit_reasoning(f"[win] evaluate_win_conditions({phase_slug}) error: {e}")

        return result

    # ------------------------------------------------------------------
    # Improvement #5 — Opportunistic event-driven pivots
    # ------------------------------------------------------------------

    def _intel_snapshot_for_pivots(self) -> Dict[str, Any]:
        """Capture a small snapshot of intel keys we diff for pivot emission."""
        intel = self._intel
        return {
            "shell_access": bool(intel.get("shell_access")),
            "user_flag":    intel.get("user_flag") or "",
            "root_flag":    intel.get("root_flag") or "",
            "creds_count":  len(intel.get("credentials") or []),
            "shells_count": len(intel.get("shells") or []),
        }

    async def _emit_pivot_deltas(self, prev: Dict[str, Any]) -> List[str]:
        """Emit synthesized pivot-trigger events for any high-value deltas.

        Each emission is routed via ``self._emit`` → ``master._broadcast_raw``
        which in turn calls ``master.notify_pivot_event`` — so the master is
        always the single funnel for pivot decisions.

        Returns the list of event types emitted (informational).
        """
        emitted: List[str] = []
        cur = self._intel_snapshot_for_pivots()

        # ── Shell newly gained ────────────────────────────────────────────
        if cur["shell_access"] and not prev.get("shell_access"):
            shell_data = {}
            shells = self._intel.get("shells") or []
            if shells:
                last = shells[-1] if isinstance(shells[-1], dict) else {}
                shell_data = {
                    "shell_id": last.get("shell_id") or last.get("id") or f"shell_{cur['shells_count']}",
                    "rhost":    last.get("rhost") or last.get("host") or self._target,
                    "rport":    last.get("rport") or last.get("port"),
                    "user":     last.get("user"),
                }
            else:
                shell_data = {"shell_id": "shell_0", "rhost": self._target}
            await self._emit({
                "type":       "shell_obtained",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       shell_data,
            })
            emitted.append("shell_obtained")

        # ── Flags newly captured ──────────────────────────────────────────
        for kind in ("user_flag", "root_flag"):
            if cur[kind] and cur[kind] != prev.get(kind):
                await self._emit({
                    "type":       "flag_found",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data": {
                        "flag_type": "root" if kind == "root_flag" else "user",
                        "value":     str(cur[kind])[:80],
                        "location":  self._target,
                    },
                })
                emitted.append("flag_found")

        # ── New credentials harvested ─────────────────────────────────────
        if cur["creds_count"] > prev.get("creds_count", 0):
            new_creds = (self._intel.get("credentials") or [])[prev.get("creds_count", 0):]
            for cred in new_creds:
                if not isinstance(cred, dict):
                    continue
                # ── Credential vault ingest (E4 wiring) ────────────────
                # Every newly-discovered credential is dropped into the
                # process-wide CredentialVault so it can be sprayed
                # against the rest of the in-scope auth surface.
                try:
                    from agents.credential_pipeline import get_vault, Credential
                    _cred_type = "password"
                    _secret    = None
                    if cred.get("hash"):
                        _cred_type = "ntlm_hash"
                        _secret    = str(cred.get("hash"))
                    elif cred.get("key") or cred.get("private_key"):
                        _cred_type = "ssh_key"
                        _secret    = str(cred.get("key") or cred.get("private_key"))
                    elif cred.get("token") or cred.get("api_token"):
                        _cred_type = "api_token"
                        _secret    = str(cred.get("token") or cred.get("api_token"))
                    elif cred.get("dsn"):
                        _cred_type = "db_dsn"
                        _secret    = str(cred.get("dsn"))
                    # Per-engagement vault (was a process-wide singleton).
                    _vault = get_vault(getattr(self, '_session_id', None))
                    await _vault.ingest(
                        Credential(
                            cred_type   = _cred_type,
                            username    = cred.get("user") or cred.get("username") or None,
                            password    = cred.get("pass") or cred.get("password") or None,
                            secret      = _secret,
                            domain      = cred.get("domain") or None,
                            source_host = cred.get("host") or self._target,
                            source_path = cred.get("source") or cred.get("path") or None,
                            notes       = str(cred.get("notes") or "")[:200],
                        ),
                        on_event=self._emit_credential_pipeline_event,
                    )
                except Exception:
                    # Vault ingest is advisory; never fail the emit on it.
                    pass

                # ── PERSIST to db.credentials so the UI panel + the
                # API endpoint /sessions/{id}/credentials actually has
                # data.  Previously credentials only flowed via WS
                # events into in-memory frontend state and were lost
                # on page reload.
                _persist_user    = cred.get("user") or cred.get("username") or "?"
                _persist_host    = cred.get("host") or self._target
                _persist_service = str(cred.get("service") or cred.get("port") or "?")
                _persist_secret  = (cred.get("pass") or cred.get("password")
                                       or cred.get("hash") or "")
                _persist_type    = ("hash" if cred.get("hash")
                                       else "ssh_key" if cred.get("key")
                                       else "plaintext")
                try:
                    import db.mongo_client as _db
                    await _db.store_credential(
                        session_id = self._session_id,
                        user       = _persist_user,
                        secret     = _persist_secret,
                        cred_type  = _persist_type,
                        service    = _persist_service,
                        host       = _persist_host,
                        port       = cred.get("port"),
                        found_by   = cred.get("found_by") or "credential_vault",
                        phase      = "exploit",
                        extra      = {k: v for k, v in cred.items() if k not in
                                       ("user","username","pass","password",
                                         "hash","host","service","port","found_by")},
                    )
                except Exception:
                    # Persistence is best-effort; never fail the emit.
                    pass

                await self._emit({
                    "type":       "credential_found",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data": {
                        "user":    _persist_user,
                        "host":    _persist_host,
                        "service": _persist_service,
                        "secret":  _persist_secret[:40],
                        "type":    _persist_type,
                    },
                })
                emitted.append("credential_found")

        return emitted

    async def on_pivot_event(self, event_type: str, payload: Any) -> None:
        """Called by ``MasterAgent.notify_pivot_event`` when a high-value
        engagement event fires.  Re-runs the cross-phase audit immediately
        so any newly-applicable phase dispatches now, without waiting for
        the next iteration boundary.

        The master holds a lock around this call so concurrent triggers do
        not race on ``_phases_dispatched``.
        """
        try:
            short = str(payload)[:80] if not isinstance(payload, dict) else (
                f"user={payload.get('user','?')}@{payload.get('host','?')}" if event_type == "credential_found"
                else f"shell={payload.get('rhost','?')}:{payload.get('rport','?')}" if event_type == "shell_obtained"
                else f"flag={payload.get('flag_type','?')}" if event_type == "flag_found"
                else str(payload)[:80]
            )
            await self._emit_reasoning(
                f"[opportunistic] {event_type} → re-evaluating pivots ({short})"
            )
            fired = await self._consider_pivots()
            await self._emit({
                "type":       "opportunistic_pivot",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "trigger":   event_type,
                    "iteration": self._iteration,
                    "phases":    fired,
                    "summary":   short,
                },
            })
        except Exception as exc:
            await self._emit_reasoning(f"[opportunistic] on_pivot_event error: {exc}")

    # ------------------------------------------------------------------
    # Improvement #10 — Neo4j-driven attack-path inference
    # ------------------------------------------------------------------

    async def _refresh_inferred_paths(self) -> None:
        """Query Neo4j for the current session subgraph and compute the
        cheapest weighted paths from foothold(s) to goal(s).  Emit on
        material change; render in ``_intel_summary`` for all planners.
        """
        try:
            from db import neo4j_client
            from agents.reasoning.path_inference import (
                derive_goal_node_ids, derive_foothold_node_ids,
                dijkstra_paths, summarise_paths,
            )
        except Exception as exc:
            await self._emit_reasoning(f"[path_inference] import error: {exc}")
            return

        try:
            sub = await neo4j_client.fetch_subgraph_for_inference(self._session_id)
        except Exception as exc:
            # Neo4j unavailable / empty graph → silent skip
            await self._emit_reasoning(f"[path_inference] neo4j fetch skipped: {exc}")
            return

        nodes = sub.get("nodes") or []
        edges = sub.get("edges") or []
        if not nodes:
            return

        sources = derive_foothold_node_ids(nodes, intel=self._intel)
        sinks   = derive_goal_node_ids(nodes,    intel=self._intel)
        if not sources or not sinks:
            # Nothing to infer yet — graph still being built
            return

        try:
            raw_paths = dijkstra_paths(nodes, edges, sources, sinks, max_paths=5)
            paths = summarise_paths(raw_paths, nodes)
        except Exception as exc:
            await self._emit_reasoning(f"[path_inference] dijkstra error: {exc}")
            return

        prev = self._intel.get("inferred_paths") or []
        self._intel["inferred_paths"] = paths

        # Emit only when the cheapest path or top-3 set changed
        def _signature(ps):
            return tuple((p.get("dst"), tuple(p.get("nodes", [])),
                          round(p.get("cost", 0.0), 2)) for p in ps[:3])
        if not paths or _signature(paths) == _signature(prev):
            return

        try:
            await self._emit({
                "type":       "inferred_paths_updated",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "iteration": self._iteration,
                    "count":     len(paths),
                    "top": [{
                        "src":        p["src"],
                        "dst":        p["dst"],
                        "cost":       p["cost"],
                        "confidence": p["confidence"],
                        "length":     len(p["nodes"]) - 1,
                        "labels":     [n.get("label") or n.get("node_id")
                                       for n in p.get("nodes_decorated", [])],
                    } for p in paths[:3]],
                },
            })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Improvement #9 — Procedural RAG: technique-chain selection
    # ------------------------------------------------------------------

    async def _refresh_technique_chains(self) -> None:
        """For the top-K hypotheses, look up matching technique chains and
        stash them on intel.  The chains are rendered into ``_intel_summary``
        so every existing LLM phase planner picks up the procedural prior.
        """
        try:
            from agents.reasoning.technique_chains import (
                select_chains_for_hypothesis,
            )
        except Exception as exc:
            await self._emit_reasoning(f"[procedural_rag] import error: {exc}")
            return

        if not self._hypotheses:
            return

        top = sorted(
            self._hypotheses,
            key=lambda h: float(getattr(h, "confidence", 0.0) or 0.0),
            reverse=True,
        )[:3]

        attached: List[Dict[str, Any]] = []
        seen_ids: set = set()
        for h in top:
            if getattr(h, "invalidated", False):
                continue
            try:
                chains = select_chains_for_hypothesis(h, self._intel, top_n=2)
            except Exception:
                chains = []
            for ch in chains:
                if ch.chain_id in seen_ids:
                    continue
                seen_ids.add(ch.chain_id)
                attached.append({
                    "hypothesis_id":  getattr(h, "hypothesis_id", ""),
                    "hypothesis":     getattr(h, "statement", "")[:160],
                    "chain":          ch.to_dict(),
                })

        prev_ids = {a["chain"]["chain_id"]
                    for a in (self._intel.get("technique_chains") or [])
                    if isinstance(a, dict) and isinstance(a.get("chain"), dict)}
        new_ids = {a["chain"]["chain_id"] for a in attached}

        self._intel["technique_chains"] = attached

        if attached and new_ids != prev_ids:
            try:
                await self._emit({
                    "type":       "technique_chain_selected",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data": {
                        "iteration": self._iteration,
                        "count":     len(attached),
                        "chains":    [{
                            "chain_id":   a["chain"]["chain_id"],
                            "name":       a["chain"]["name"],
                            "phase":      a["chain"]["phase"],
                            "mitre":      a["chain"]["mitre"],
                            "hypothesis": a["hypothesis"],
                        } for a in attached],
                    },
                })
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Improvement #7 — Hypothesis-conditioned scan profile
    # ------------------------------------------------------------------

    async def _refresh_scan_profile(self) -> None:
        """Build a ScanProfile from current hypotheses, stash on intel, emit.

        The profile is rendered into ``_intel_summary()`` (via
        ``master_agent``) so every existing LLM phase planner that reads
        the summary picks up the bias automatically — no per-planner
        change required.
        """
        try:
            from agents.reasoning.scan_profile import build_scan_profile
            profile = build_scan_profile(
                hypotheses = self._hypotheses,
                intel      = self._intel,
                top_n      = 5,
                iteration  = self._iteration,
            )
        except Exception as exc:
            await self._emit_reasoning(f"[scan_profile] build error: {exc}")
            return

        prev = (self._intel.get("scan_profile") or {})
        new  = profile.to_dict()
        self._intel["scan_profile"] = new

        # Skip the WS event when the bias hasn't materially changed —
        # avoids feed spam on iterations that don't shift hypotheses.
        material_keys = ("priority_ports", "priority_services",
                         "priority_cves", "priority_paths")
        changed = any(prev.get(k) != new.get(k) for k in material_keys)
        if not changed:
            return
        if profile.is_empty():
            return

        try:
            await self._emit({
                "type":       "scan_profile_updated",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       new,
            })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Improvement #12 — Defensive posture fingerprinting
    # ------------------------------------------------------------------

    async def _refresh_defensive_posture(self) -> None:
        """Mine intel passively for EDR/WAF/SIEM/IDS fingerprints.

        On material change emits ``defensive_posture_updated``.  When a
        high-weight EDR or SIEM is freshly identified and the noise budget
        (#11) is still in default mode, the budget is auto-downshifted to
        stealth so subsequent action selection prefers quiet tradecraft.
        """
        try:
            from agents.reasoning.defensive_posture import (
                fingerprint_posture,
            )
        except Exception as exc:
            await self._emit_reasoning(f"[defensive_posture] import error: {exc}")
            return

        prior_mode = "default"
        nb = getattr(self._master, "noise_budget", None)
        if nb is not None:
            prior_mode = getattr(nb, "mode", "default") or "default"

        try:
            posture = fingerprint_posture(
                self._intel,
                iteration  = self._iteration,
                prior_mode = prior_mode,
            )
        except Exception as exc:
            await self._emit_reasoning(f"[defensive_posture] fingerprint error: {exc}")
            return

        prev = self._intel.get("defensive_posture") or {}
        new  = posture.to_dict()
        prev_sig = tuple(sorted(
            (cat, tuple(sorted(set(prods))))
            for cat, prods in (prev.get("products") or {}).items()
        ))
        new_sig = posture.signature()
        self._intel["defensive_posture"] = new

        if prev_sig == new_sig:
            return

        # Auto-downshift noise budget when EDR/SIEM appears.
        if posture.stealth_recommended and nb is not None and prior_mode == "default":
            try:
                from agents.reasoning.noise_budget import (
                    NoiseBudget, STEALTH_BUDGET,
                )
                old_total     = nb.total
                old_remaining = nb.remaining
                # Cap remaining at the new total so we don't grant credits.
                nb.total     = STEALTH_BUDGET
                nb.remaining = min(old_remaining, STEALTH_BUDGET)
                nb.mode      = "stealth"
                await self._emit({
                    "type":       "noise_budget_updated",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data": {
                        **nb.to_dict(),
                        "auto_downshift": True,
                        "previous_total": old_total,
                        "trigger":        "defensive_posture",
                    },
                })
            except Exception as exc:
                await self._emit_reasoning(f"[defensive_posture] noise downshift error: {exc}")

        try:
            await self._emit({
                "type":       "defensive_posture_updated",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       new,
            })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Improvement #18 — Live goal-progress timeline
    # ------------------------------------------------------------------

    async def _refresh_goal_timeline(self) -> None:
        """Reconcile the win-condition snapshot into a live timeline.

        Surfaces structured per-goal state transitions, milestones, and
        a velocity-based ETA on remaining iterations.  Emits
        ``goal_timeline_updated`` when any goal state or progress
        materially changes.  Renders a banner via
        ``MasterAgent._intel_summary`` so phase planners see overall
        progress at the top of every prompt.
        """
        try:
            from agents.reasoning.goal_timeline import (
                GoalTimeline, render_timeline_for_prompt,
            )
        except Exception as exc:
            await self._emit_reasoning(f"[goal_timeline] import error: {exc}")
            return

        # Refresh underlying win-conditions snapshot.
        try:
            evaluator = getattr(self._master, "evaluate_win_conditions", None)
            if callable(evaluator):
                await evaluator()  # updates self._intel["win_conditions"]
        except Exception as exc:
            await self._emit_reasoning(f"[goal_timeline] evaluate failed: {exc}")

        snapshot = self._intel.get("win_conditions") or {}
        if not snapshot.get("conditions"):
            return  # no mission brief / no win conditions configured

        tl = getattr(self._master, "goal_timeline", None)
        if tl is None:
            tl = GoalTimeline()
            try:
                self._master.goal_timeline = tl
            except Exception:
                pass

        prior_sig = tl.signature()
        changed, milestones = tl.update(
            win_snapshot = snapshot,
            intel        = self._intel,
            iteration    = self._iteration,
        )
        new_sig = tl.signature()

        payload = tl.to_dict(iteration=self._iteration)
        self._intel["goal_timeline"] = payload

        if not changed and prior_sig == new_sig:
            return

        try:
            await self._emit({
                "type":       "goal_timeline_updated",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    **payload,
                    "new_milestones": [m.to_dict() for m in milestones],
                },
            })
        except Exception:
            pass

        # Record one trace step per state transition (Improvement #17).
        for m in milestones:
            try:
                if m.kind == "transition" and m.from_state and m.to_state:
                    await self._record_trace_step(
                        kind     = "observation",
                        summary  = (
                            f"goal '{m.note[:60] if m.note else ''}' "
                            f"{m.from_state} → {m.to_state}"
                        ),
                        refs     = {"goal_transition": f"{m.from_state}->{m.to_state}"},
                        payload  = m.to_dict(),
                    )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Improvement #4 — Unified decision loop: cross-phase pivots
    # ------------------------------------------------------------------

    def _phase_enabled(self, slug: str) -> bool:
        """[14] Honour the operator's Target-Config phase selection in the reasoning
        pivot path (it was ignored — every detected pivot fired regardless).
        master._phases_to_run holds canonical AttackPhase tokens; map each pivot slug
        onto one.  An EMPTY selection means 'all phases' (the default) → True, exact
        parity with the linear pipeline's phase_enabled closure."""
        want = getattr(self._master, "_phases_to_run", None)
        if not want:
            return True
        canon = {
            "web_testing":      "exploit",
            "ad_enum":          "vuln_id",
            "lateral_movement": "lateral",
        }.get(slug, slug)
        try:
            want_l = {str(p).lower().split(".")[-1] for p in want}
        except Exception:
            return True
        return canon in want_l or slug in want_l

    async def _consider_pivots(self) -> List[str]:
        """Per-iteration cross-phase audit.

        Runs after every action update.  For each phase whose state-driven
        trigger is currently satisfied, dispatch it via ``_safe_phase`` —
        which is idempotent, so phases already executed are silently
        skipped.  This unifies what used to be the rigid bootstrap →
        exploit → post-exploit chain into a single state-driven decision
        loop where pivots fire as soon as evidence warrants them.

        Returns the list of phase slugs that actually fired this call
        (empty when nothing new is warranted).
        """
        intel       = self._intel
        eng_ctx     = intel.get("engagement_context") or {}
        is_passive  = eng_ctx.get("engagement_type", "pentest") in (
            "forensics", "network_analysis", "malware_analysis", "compliance"
        )
        tools_excl  = {t.lower().split()[0] for t in (eng_ctx.get("tools_excluded") or [])}

        # Each candidate is (phase_slug, condition_bool, dispatch_coro_factory).
        # Conditions read from intel only — never side-effecting.
        candidates: List[tuple] = []

        if not is_passive:
            # Vulnerability scan — once ports are known, before we exploit.
            candidates.append((
                "vuln_id",
                bool(intel.get("open_ports")) and "nikto" not in tools_excl,
                lambda: self._safe_phase(self._master._phase_vuln_id,
                                         phase_slug="vuln_id",
                                         target=self._target),
            ))
            # Web testing — any web port discovered, OR explicit URL/app target.
            web_ports = sorted({
                int(str(p.get("port") if isinstance(p, dict) else p).split("/")[0])
                for p in intel.get("open_ports", [])
                if (isinstance(p, dict) and str(p.get("port", "")).split("/")[0].isdigit())
                   or (not isinstance(p, dict) and str(p).split("/")[0].isdigit())
            } & {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443})
            # Force-include web ports when a URL/app target is set
            if (not web_ports) and intel.get("target_url"):
                try:
                    from urllib.parse import urlparse as _up
                    _u = _up(intel["target_url"])
                    web_ports = [int(_u.port or (443 if _u.scheme == "https" else 80))]
                except Exception:
                    web_ports = [443] if str(intel.get("target_url","")).startswith("https") else [80]
            elif (not web_ports) and intel.get("target_kind") in ("hostname", "url", "app"):
                web_ports = [80, 443]
            candidates.append((
                "web_testing",
                bool(web_ports) and "gobuster" not in tools_excl,
                lambda wp=web_ports: self._safe_phase(
                    self._master._phase_web_testing,
                    phase_slug="web_testing",
                    target=self._target, web_ports=wp,
                ),
            ))
            # AD enumeration.
            candidates.append((
                "ad_enum",
                self._should_run_ad() and "bloodhound-python" not in tools_excl,
                lambda: self._run_ad_enum(),
            ))
            # Cloud metadata.
            candidates.append((
                "cloud",
                self._should_run_cloud(),
                lambda: self._safe_phase(self._master._phase_cloud,
                                         phase_slug="cloud",
                                         target=self._target),
            ))
            # Exploit — open ports + ANY actionable signal.  A fingerprinted
            # service VERSION (e.g. "OpenSSH 7.2p2", "Apache 2.4.18") or a
            # known CVE is just as exploitable as a formal vuln entry — a real
            # tester starts attacking the moment a versioned service is
            # identified.  Previously only vulnerabilities/technologies
            # satisfied this gate, so version-only recon left the loop stuck
            # in endless enumeration instead of attempting exploitation.
            _svc_has_version = any(
                (s.get("version") if isinstance(s, dict) else "")
                for s in (intel.get("services") or {}).values()
            )
            has_exploit_evidence = bool(intel.get("open_ports")) and (
                bool(intel.get("vulnerabilities"))
                or bool(intel.get("technologies"))
                or bool(intel.get("cves"))
                or _svc_has_version
            )
            candidates.append((
                "exploit",
                has_exploit_evidence and not intel.get("shell_access"),
                lambda: self._safe_phase(self._master._phase_exploit,
                                         phase_slug="exploit",
                                         target=self._target),
            ))
            # Lateral movement — credentials harvested or AD detected.
            candidates.append((
                "lateral_movement",
                self._should_run_lateral(),
                lambda: self._safe_phase(self._master._phase_lateral_movement,
                                         phase_slug="lateral_movement",
                                         target=self._target),
            ))

        # Container escape — driven purely by detection, applies to passive too.
        if intel.get("container_info", {}).get("type"):
            candidates.append((
                "container",
                True,
                lambda: self._safe_phase(self._master._phase_container,
                                         phase_slug="container",
                                         target=self._target),
            ))

        # Privilege escalation — fires the moment a shell appears.
        if intel.get("shell_access") and not intel.get("root_flag"):
            candidates.append((
                "privesc",
                True,
                lambda: self._safe_phase(self._master._phase_privesc,
                                         phase_slug="privesc",
                                         target=self._target),
            ))
            # Post-exploit enumeration (creds, tokens, files).
            candidates.append((
                "post_exploit",
                True,
                lambda: self._safe_phase(self._master._phase_post_exploit,
                                         phase_slug="post_exploit",
                                         target=self._target),
            ))

        # Filter to phases not yet dispatched whose triggers are satisfied.
        to_fire = [
            (slug, factory) for slug, ok, factory in candidates
            if ok and slug not in self._phases_dispatched and self._phase_enabled(slug)
        ]
        if not to_fire:
            return []

        slugs = [s for s, _ in to_fire]
        await self._emit_reasoning(
            f"[pivots] iter {self._iteration}: dispatching {len(slugs)} phase(s) "
            f"in parallel → {', '.join(slugs)}"
        )
        # Fire them in parallel — _safe_phase already swallows exceptions.
        await asyncio.gather(*[f() for _, f in to_fire], return_exceptions=True)
        return slugs

    async def _run_ad_enum(self) -> dict:
        """Run Active Directory enumeration via BloodHound."""
        try:
            await self._master._dispatch_to_agent(
                tool    = "bloodhound-python",
                args    = f"-d domain.local -ns {self._target} -c All",
                purpose = "AD attack path enumeration",
                phase   = "lateral",
            )
        except Exception as e:
            await self._emit_reasoning(f"AD enum error: {e}")
        return {}

    async def _auto_post_exploit(self) -> None:
        """
        Automatically chain post-exploitation when shell access is first gained.
        Mirrors a human attacker's immediate next steps after getting a shell:
        enumerate → privesc → lateral movement.
        """
        await self._emit_plan_step("auto_post", "🎯 Post-Exploitation Chain", "active",
                                   "Shell gained — running post-exploit + privesc", "post_exploit")
        # Post-exploit: enumerate users, creds, tokens, interesting files
        await self._safe_phase(self._master._phase_post_exploit, target=self._target)

        # Privesc check — immediately look for escalation paths
        await self._emit_plan_step("auto_privesc", "⬆️ Auto Privilege Escalation", "active",
                                   "Checking privesc vectors", "privesc")
        await self._safe_phase(self._master._phase_privesc, target=self._target)

        elevated = self._intel.get("elevated_shell") or self._intel.get("root_flag")
        await self._emit_plan_step("auto_privesc", "⬆️ Auto Privilege Escalation",
                                   "done" if elevated else "active",
                                   f"User: {self._intel.get('current_user', 'unknown')}",
                                   "privesc", found=elevated)

        # Lateral movement — if credentials harvested or AD detected
        if self._should_run_lateral():
            await self._emit_plan_step("auto_lateral", "↔️ Lateral Movement", "active",
                                       "Credentials found — checking lateral paths", "lateral")
            await self._safe_phase(self._master._phase_lateral_movement, target=self._target)
            await self._emit_plan_step("auto_lateral", "↔️ Lateral Movement", "done",
                                       "Lateral movement assessment complete", "lateral", found=True)

        await self._emit_plan_step("auto_post", "🎯 Post-Exploitation Chain", "done",
                                   f"Creds: {len(self._intel.get('credentials', []))} | "
                                   f"Elevated: {bool(elevated)}",
                                   "post_exploit", found=True)

    def _should_run_ad(self) -> bool:
        """True if AD-related ports or domain artifacts found."""
        ports = {p.get("port") if isinstance(p, dict) else p
                 for p in self._intel.get("open_ports", [])}
        ad_ports = {88, 389, 636, 445, 5985, 5986, 3268, 3269}
        if ports & ad_ports:
            return True
        domain_info = self._intel.get("domain_info", {})
        if isinstance(domain_info, dict):
            return bool(domain_info.get("domain") or domain_info.get("dc_ip"))
        return False

    def _should_run_cloud(self) -> bool:
        """True if cloud-provider indicators found in technologies or services."""
        techs = [str(t).lower() for t in self._intel.get("technologies", [])]
        cloud_markers = ["aws", "azure", "gcp", "ec2", "s3", "lambda", "cloud"]
        return any(m in t for t in techs for m in cloud_markers)

    def _should_run_lateral(self) -> bool:
        """True if lateral movement is warranted: credentials found, AD detected, or multiple hosts."""
        intel = self._intel
        if self._should_run_ad():
            return True
        if intel.get("credentials") and len(intel.get("credentials", [])) > 0:
            return True
        if len(intel.get("discovered_hosts", [])) > 1:
            return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_objective_achieved(self) -> bool:
        """True if root/SYSTEM shell, both flags captured, OR the objective
        grader has marked every declared objective complete."""
        intel = self._intel
        if intel.get("root_flag") and intel.get("user_flag"):
            return True
        shells = intel.get("shells", [])
        for sh in shells:
            if isinstance(sh, dict) and sh.get("elevated"):
                return True
        # All declared objectives graded complete by the holistic evaluator.
        objs = ((intel.get("engagement_context") or {}).get("objectives")
                or intel.get("ctf_objectives") or [])
        st = intel.get("objective_status") or {}
        # objective_status values are MIXED: the holistic evaluator writes dicts
        # ({"status": "complete", …}) while the operator's _mark_objective writes
        # plain strings ("complete").  Read both shapes so a string value never
        # raises 'str object has no attribute get' (which crashed the legacy
        # fallback right after the operator handed off).
        def _st(v):
            return v.get("status") if isinstance(v, dict) else v
        if objs and len(st) >= len(objs) and st and \
                all(_st(v) == "complete" for v in st.values()):
            return True
        return False

    @staticmethod
    def _noise_refund_fraction(action: Any, result: dict, validated: bool) -> float:
        """B-7 — return the fraction (0..1) of noise budget to refund for
        ``action`` based on how much actual traffic it generated.

        Heuristic:
          1.0  — tool failed before any wire interaction
                 (MCP unknown-tool, spawn fail, immediate timeout < 1s)
          0.7  — connect refused / no route / DNS failure
          0.4  — auth failure (handshake happened, no payload)
          0.2  — successful but uninformative (curl 404, gobuster zero results)
          0.0  — action ran to completion (full noise stays charged)
        """
        exit_code = result.get("exit_code")
        stdout    = (result.get("stdout") or "")
        stderr    = (result.get("stderr") or "")
        blob      = (stdout + " " + stderr).lower()

        # 1.0 — never reached the wire
        if isinstance(exit_code, int) and exit_code in (-1, -2, -3, -4, 127):
            return 1.0
        if "unknown tool" in blob or "command not found" in blob:
            return 1.0
        if "spawn failed" in blob or "module not found" in blob:
            return 1.0

        # 0.7 — network unreachable
        if any(s in blob for s in (
            "connection refused", "no route to host", "network is unreachable",
            "could not resolve host", "name or service not known",
            "could not connect to server",
        )):
            return 0.7

        # 0.4 — auth failure
        if any(s in blob for s in (
            "authentication failed", "permission denied", "access is denied",
            "access denied for user", "login failed for user",
            "invalid credentials", "status_logon_failure", "401 unauthorized",
        )):
            return 0.4

        # 0.2 — succeeded but produced no actionable signal
        if validated is False and isinstance(exit_code, int) and exit_code == 0:
            return 0.2

        return 0.0

    def _observe_cred_validation(
        self,
        action: JustifiedAction,
        result: dict,
    ) -> None:
        """B-2 — observe whether a credential-using action proved the
        operator-supplied creds work or not, and stamp
        ``intel['ad']['creds_validated']`` / ``creds_invalid`` accordingly.

        Detection patterns:

        SUCCESS markers (any of):
          * crackmapexec / netexec ``[+] domain\\user:pass`` (with or
            without ``Pwn3d!``)
          * crackmapexec banner ``(name:DC01) (domain:...)`` followed by
            no auth-error within the same response
          * sshpass+ssh containing ``uid=`` (id command output)
          * evil-winrm reaching ``*Evil-WinRM* PS C:\\>`` prompt
          * impacket-* tools producing TGS/AS-REP hashes
          * ``register_shell`` already fired during this update (handled
            by the master agent, but mirrored here as fallback)

        FAILURE markers:
          * ``STATUS_LOGON_FAILURE`` (Windows SMB)
          * ``STATUS_ACCESS_DENIED``
          * ``ldap_bind: Invalid credentials (49)``
          * ``Permission denied`` from sshpass+ssh (followed by exit 5/255)
          * ``Authentication failed.``  (msfconsole / hydra / impacket)
          * ``Access is denied.``
          * 401 Unauthorized headers in HTTP basic-auth probe
        """
        import re as _re
        tool = (action.tool or "").lower()
        # Only observe credential-using tools
        if tool not in (
            "crackmapexec", "cme", "nxc", "netexec",
            "sshpass", "ssh",
            "evil-winrm", "evilwinrm",
            "impacket-getuserspns", "impacket-GetUserSPNs",
            "impacket-getnpusers", "impacket-GetNPUsers",
            "impacket-secretsdump",
            "impacket-mssqlclient", "impacket-psexec", "impacket-wmiexec",
            "ldapsearch",
            "curl", "wget",
            "mysql", "psql", "mongosh", "redis-cli",
            "hydra",
        ):
            return

        stdout = (result.get("stdout") or result.get("output") or "")
        stderr = (result.get("stderr") or "")
        blob   = (stdout + "\n" + stderr)
        if not blob.strip():
            return

        ad_state = self._intel.setdefault("ad", {}) if isinstance(self._intel.get("ad"), dict) else {}
        if not isinstance(self._intel.get("ad"), dict):
            self._intel["ad"] = {}
            ad_state = self._intel["ad"]

        # Already locked-in either way?  Don't downgrade success → failure
        # without operator intervention; auth flapping is real but rare.
        if ad_state.get("creds_validated"):
            return

        # ── SUCCESS detection ─────────────────────────────────────────
        success_re = _re.compile(
            r"(?:"
            r"\[\+\][^\n]*?(?:\\\\|\\)"     # CrackMapExec [+] domain\user
            r"|Pwn3d!|"                     # CME admin-creds marker
            r"\buid=\d+\("                  # `id` output
            r"|\*Evil-WinRM\*\s*PS\s+[A-Z]:\\"  # evil-winrm prompt
            r"|\$krb5tgs\$"                 # kerberoast hash captured
            r"|\$krb5asrep\$"               # AS-REP hash captured
            r"|Service Principal Name"      # GetUserSPNs success header
            r"|Trying to connect\.\.\.OK"   # impacket-secretsdump initial connect
            r")",
            _re.I,
        )
        # Validate-only specific: crackmapexec smb without -p Pwn3d! still
        # produces a banner line if creds are valid:
        # `SMB  10.0.0.1  445  DC01  [+] domain\\user:pass`
        cme_validated = _re.search(
            r"SMB\s+\S+\s+\d+\s+\S+\s+\[\+\]\s+\S+:\S+",
            blob, _re.I,
        )

        if success_re.search(blob) or cme_validated:
            ad_state["creds_validated"] = True
            ad_state["creds_invalid"]   = False
            ad_state["validated_via"]   = action.tool
            try:
                import logging as _l
                _l.getLogger(__name__).info(
                    "[B-2 creds_validated=True] via %s — heavy primer steps unlocked",
                    action.tool,
                )
            except Exception:
                pass
            return

        # ── FAILURE detection ─────────────────────────────────────────
        failure_patterns = (
            "STATUS_LOGON_FAILURE",
            "STATUS_ACCESS_DENIED",
            "STATUS_ACCOUNT_DISABLED",
            "STATUS_ACCOUNT_LOCKED_OUT",
            "STATUS_PASSWORD_EXPIRED",
            "Invalid credentials (49)",       # ldapsearch
            "ldap_bind: Invalid credentials",
            "Authentication failed",
            "authentication failure",
            "Access is denied",
            "Access denied for user",         # MySQL
            "password authentication failed", # PostgreSQL
            "Login failed for user",          # MSSQL
            "WinRMAuthorizationError",
            "401 Unauthorized",
        )
        if any(p.lower() in blob.lower() for p in failure_patterns):
            # Increment a fail counter — only flip creds_invalid after
            # 2+ distinct failures.  A single flap (ldap server rejecting
            # auth on first try) shouldn't kill the chain.
            ad_state["cred_fail_count"] = int(ad_state.get("cred_fail_count", 0)) + 1
            if ad_state["cred_fail_count"] >= 2:
                ad_state["creds_invalid"]   = True
                ad_state["creds_validated"] = False
                try:
                    import logging as _l
                    _l.getLogger(__name__).warning(
                        "[B-2 creds_invalid=True] %d auth failures — "
                        "halting credentialed primer chain",
                        ad_state["cred_fail_count"],
                    )
                except Exception:
                    pass

    def _classify_low_signal_result(
        self,
        action: JustifiedAction,
        result: dict,
    ) -> Optional[str]:
        """B5 — return a short label when ``result`` is technically a
        success (exit_code==0) but produced no actionable evidence, so
        re-proposing the same args wastes iterations.

        Returns None when the result IS informative.  Returns a short
        category string (``http_4xx``, ``http_5xx``, ``empty_body``,
        ``zero_results``) when it isn't.
        """
        exit_code = result.get("exit_code")
        if exit_code not in (0, None):
            return None  # already a real failure → handled by main branch

        stdout = (result.get("stdout") or result.get("output") or "")
        stripped = stdout.strip()
        tool = (action.tool or "").lower()
        args = (action.args or "")

        # ── curl with -w '%{http_code}' or -I HEAD probe ─────────────
        # Args using the http_code template print just the status code +
        # newline.  Three-digit-only output like "404" / "403" / "500"
        # is the canonical low-signal pattern.
        if tool in ("curl", "wget", "httpx", "httprobe"):
            # Pure status code response (3 digits possibly preceded by tags)
            import re as _re
            m = _re.search(r"(?<!\d)(\d{3})(?!\d)", stripped[:32])
            if m and len(stripped) < 80:
                code = int(m.group(1))
                if 400 <= code < 500:
                    return f"http_{code}"
                if 500 <= code < 600:
                    return f"http_{code}"
                if code in (200, 204, 301, 302) and len(stripped) <= 6:
                    # Probed and got OK but body discarded — fine, but
                    # not actionable enough to justify a re-probe.
                    return None  # let LLM re-purpose the URL with a body fetch
            # Empty body from -o /dev/null with no -w printed → useless
            if not stripped:
                return "empty_body"

        # ── gobuster / ffuf / feroxbuster — no findings ──────────────
        if tool in ("gobuster", "ffuf", "feroxbuster", "dirb", "wfuzz"):
            # Empty findings line is the no-result banner — these tools
            # exit 0 even when nothing was found.
            if any(sig in stdout.lower() for sig in (
                "0 results", "0 matches", "no targets",
                "no urls found", "0 patterns",
            )):
                return "zero_results"

        # ── nuclei / wpscan / nikto with no findings ────────────────
        if tool in ("nuclei", "wpscan", "nikto", "wapiti"):
            if "0 hosts found" in stdout.lower() or "no vulnerabilities" in stdout.lower():
                return "zero_results"

        # ── Universal: completely empty output is always low-signal ──
        if not stripped:
            return "empty_output"

        # ── Universal: very short non-error output that doesn't carry
        # any of the strong success signals the validator looks for.
        if len(stripped) < 20:
            success_markers = (
                "uid=", "root@", "flag{", "shell", "meterpreter",
                "pwned", "win!", "compromised", "logged in",
            )
            if not any(m in stripped.lower() for m in success_markers):
                return "trivial_output"

        return None

    def _extract_failure_reason(self, result: dict) -> str:
        """Extract a brief failure reason from a tool result dict."""
        stdout = (result.get("stdout") or result.get("output") or "").lower()
        stderr = (result.get("stderr") or "").lower()
        combined = (stdout + " " + stderr)[:300]

        failure_map = {
            "connection refused":  "Connection refused",
            "no route to host":    "Network unreachable",
            "permission denied":   "Permission denied",
            "authentication fail": "Authentication failed",
            "exploit failed":      "Exploit failed",
            "no sessions":         "No sessions created",
            "module not found":    "Module not found",
            "command not found":   "Command not found",
            "timeout":             "Timeout",
        }
        for sig, reason in failure_map.items():
            if sig in combined:
                return reason

        exit_code = result.get("exit_code", -1)
        if exit_code != 0 and exit_code is not None:
            return f"Non-zero exit code: {exit_code}"

        return "Action did not advance hypothesis"

    async def _wait_for_confirmation(
        self,
        action:  JustifiedAction,
        timeout: int = 60,
    ) -> bool:
        """
        Wait for operator confirmation for a low-confidence action.
        Uses master agent's existing confirmation event infrastructure.
        """
        event_key = f"reasoning_{action.action_id}"
        try:
            confirm_events = getattr(self._master, "_confirm_events", {})
            evt = asyncio.Event()
            confirm_events[event_key] = evt
            try:
                await asyncio.wait_for(evt.wait(), timeout=timeout)
                return True
            except asyncio.TimeoutError:
                return False
            finally:
                confirm_events.pop(event_key, None)
        except Exception:
            # If confirmation infrastructure unavailable, auto-approve
            return True

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    async def _persist_hypotheses(self) -> None:
        """Store top hypotheses to MongoDB."""
        # Improvement #17 — record one trace step per top hypothesis so
        # later select/execute/validate steps can be parented back to it.
        trace = getattr(self, "_reasoning_trace", None)
        if trace is not None:
            for h in self._hypotheses[:5]:
                # Only record if we don't already have a step for this hyp_id
                # (avoid spam — hypotheses persist for many iterations).
                if trace.latest_step_for("hypothesis_id", h.hypothesis_id):
                    continue
                try:
                    await self._record_trace_step(
                        kind    = "hypothesis",
                        summary = (
                            f"H[{(h.mitre_technique or '?')}] "
                            f"{(h.statement or '')[:140]} (conf={h.confidence:.2f})"
                        ),
                        refs    = {
                            "hypothesis_id": h.hypothesis_id or "",
                            "mitre":         h.mitre_technique or "",
                        },
                        payload = {
                            "evidence_supporting": list(h.evidence_supporting or [])[:5],
                            "attack_phase":        h.attack_phase or "",
                        },
                    )
                except Exception:
                    pass

        try:
            import db.mongo_client as dbm
            for h in self._hypotheses[:5]:
                await dbm.store_hypothesis(
                    session_id               = self._session_id,
                    host                     = self._target,
                    hypothesis_id            = h.hypothesis_id,
                    statement                = h.statement,
                    confidence               = h.confidence,
                    evidence_supporting      = h.evidence_supporting,
                    required_evidence        = h.required_evidence,
                    recommended_next_actions = h.recommended_next_actions,
                    attack_phase             = h.attack_phase,
                    mitre_technique          = h.mitre_technique,
                    iteration_number         = h.iteration_number,
                )
        except Exception:
            pass

    async def _persist_ranked_paths(self) -> None:
        """Store ranked paths snapshot to MongoDB."""
        try:
            import db.mongo_client as dbm
            top = self._ranked_paths[0] if self._ranked_paths else None
            await dbm.store_ranked_paths(
                session_id     = self._session_id,
                host           = self._target,
                iteration      = self._iteration,
                paths          = [p.to_dict() for p in self._ranked_paths],
                top_path_score = top.total_score if top else 0.0,
                top_path_id    = top.path_id if top else "",
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Emit helpers
    # ------------------------------------------------------------------

    async def _emit_status(self, message: str, status: str = "THINKING") -> None:
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       "agent_status",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data": {
                        "status":  status,
                        "phase":   "reasoning_loop",
                        "message": message,
                    },
                })
        except Exception:
            pass

    async def _record_trace_step(
        self,
        *, kind: str,
        summary: str,
        parent_id: Optional[str] = None,
        refs: Optional[Dict[str, str]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Improvement #17 — append a reasoning trace step and broadcast it."""
        trace = getattr(self, "_reasoning_trace", None)
        if trace is None:
            return None
        try:
            step = trace.record(
                kind      = kind,
                summary   = summary,
                parent_id = parent_id,
                refs      = refs,
                payload   = payload,
                iteration = self._iteration,
            )
        except Exception:
            return None
        try:
            await self._emit({
                "type":       "reasoning_trace_step",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       step.to_dict(),
            })
        except Exception:
            pass
        return step.step_id

    async def _emit_reasoning(self, message: str) -> None:
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       "reasoning_loop",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data": {
                        "iteration": self._iteration,
                        "message":   message,
                    },
                })
        except Exception:
            pass

    async def _emit_loop_event(self, event_type: str, data: dict) -> None:
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       f"reasoning_{event_type}",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       {"iteration": self._iteration, **data},
                })
        except Exception:
            pass

    async def _emit_credential_pipeline_event(self, event_type: str, data: dict) -> None:
        """Bridge from CredentialVault on_event callback to the master WS bus.

        Vault calls this on credential_ingested / credential_spray_hit so
        the UI can show the operator what's flowing through the pipeline.
        """
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       event_type,
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       dict(data),
                })
        except Exception:
            pass

    # ── Playbook dispatch (E1 wiring) ────────────────────────────────────
    # Each iteration, match the current intel against the playbook library
    # and run any matching playbook that hasn't been dispatched yet.
    # _playbooks_dispatched is per-instance to dedup across iterations.

    async def _dispatch_matched_playbooks(self) -> None:
        """Match intel -> playbooks -> dispatch unrun ones once per scan.

        Wrapped in try/except so any error in the engine never breaks the
        reasoning iteration.  Each playbook id is dispatched at most once
        per scan via _playbooks_dispatched.
        """
        try:
            from agents.playbook.engine import get_engine
        except Exception:
            return

        if not hasattr(self, "_playbooks_dispatched"):
            self._playbooks_dispatched: set = set()

        # Build intel in the engine's expected shape from self._intel
        try:
            services_raw = self._intel.get("services") or {}
            if isinstance(services_raw, dict):
                services = [
                    {"port": int(p) if str(p).isdigit() else p,
                     "service": v.get("service") if isinstance(v, dict) else str(v),
                     "banner":  v.get("banner")  if isinstance(v, dict) else "",
                     "version": v.get("version") if isinstance(v, dict) else "",}
                    for p, v in services_raw.items()
                ]
            else:
                services = list(services_raw or [])
        except Exception:
            services = []

        intel = {
            "target":   self._intel.get("target") or self._target,
            "services": services,
            "findings": self._intel.get("findings", []),
            "cves":     self._intel.get("cves", []),
        }
        try:
            matches = get_engine().match(intel)
        except Exception:
            return
        if not matches:
            return

        for pb, ctx in matches:
            if pb.id in self._playbooks_dispatched:
                continue
            # Skip legacy-schema playbooks whose steps lack the new
            # `args` shape (their `cmd` strings can't safely run via
            # tool_runner).  These remain reference material until
            # migrated.
            if not pb.steps or not pb.steps[0].args:
                self._playbooks_dispatched.add(pb.id)
                continue
            self._playbooks_dispatched.add(pb.id)
            await self._emit_reasoning(
                f"[playbook] dispatching {pb.id} on {ctx.get('url')}"
            )
            try:
                async def _tool_runner(tool: str, args: list, timeout: int):
                    result = await self._master.run_tool(
                        tool, " ".join(args), timeout=timeout,
                    )
                    return (result.get("exit_code", -1),
                            result.get("stdout", ""),
                            result.get("stderr", ""))

                pb_findings = await get_engine().run(
                    pb, ctx, _tool_runner,
                    on_event=lambda et, data: self._emit({
                        "type": et, "session_id": self._session_id,
                        "agent": "master", "data": dict(data),
                    }) if callable(self._emit) else None,
                )
                for pf in pb_findings or []:
                    try:
                        await self._master.store_finding(
                            severity    = getattr(__import__("db.schemas",
                                                             fromlist=["FindingSeverity"]).FindingSeverity,
                                                  pf.severity.upper(), None) or
                                          __import__("db.schemas",
                                                     fromlist=["FindingSeverity"]).FindingSeverity.INFO,
                            title       = pf.title,
                            description = pf.description,
                            host        = pf.host or self._target,
                            port        = pf.port,
                            tool_used   = "playbook:" + pb.id,
                            evidence    = pf.evidence,
                            cves        = [pf.cve] if pf.cve else [],
                            extra       = {"playbook_id": pb.id, "step": pf.step_name},
                        )
                    except Exception:
                        # store_finding failure is per-finding; keep going
                        continue
            except Exception as exc:
                await self._emit_reasoning(f"[playbook] {pb.id} error: {exc}")

    async def _emit_confirmation_request(self, action: JustifiedAction) -> None:
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       "reasoning_confirmation_required",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data": {
                        "action_id":        action.action_id,
                        "tool":             action.tool,
                        "args":             action.args,
                        "reason":           action.reason,
                        "confidence":       action.confidence,
                        "expected_outcome": action.expected_outcome,
                        "success_criteria": action.success_criteria,
                        "plan":             action.plan.to_dict() if action.plan else None,
                    },
                })
        except Exception:
            pass

    async def _emit_plan_step(
        self,
        step_id:     str,
        label:       str,
        status:      str,
        result:      str    = "",
        phase:       str    = "exploit",
        mitre_id:    str    = "",
        probability: float  = 0.0,
        detail:      str    = "",
        found:       bool   = None,
    ) -> None:
        """Emit a plan_step_update event — drives MissionControl plan tracker."""
        try:
            await self._emit({
                "type":       "plan_step_update",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "step_id":     step_id,
                    "label":       label,
                    "status":      status,
                    "result":      result[:200] if result else "",
                    "detail":      detail[:300] if detail else "",
                    "phase":       phase,
                    "mitre_id":    mitre_id or "",
                    "probability": probability,
                    "found":       found,
                    "ts":          datetime.utcnow().isoformat(),
                },
            })
        except Exception:
            pass

    async def _emit_finding(
        self,
        title:       str,
        severity:    str,
        description: str,
        phase:       str = "reasoning",
        tool:        str = "reasoning_engine",
        mitre:       str = "",
    ) -> None:
        """Emit a finding event — populates FindingsBoard."""
        finding_id = str(uuid.uuid4())
        # Improvement #17 — finding step parented on the most recent
        # validate step (if any) so the chain is complete from
        # observation → finding.
        try:
            await self._record_trace_step(
                kind      = "finding",
                summary   = f"FINDING [{severity}] {title[:140]}",
                parent_id = self._last_validate_step_id,
                refs      = {
                    "finding_id": finding_id,
                    "mitre":      mitre or "",
                    "tool":       tool or "",
                },
                payload   = {"phase": phase, "severity": severity},
            )
        except Exception:
            pass
        try:
            await self._emit({
                "type":       "finding",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "finding": {
                        "id":          finding_id,
                        "title":       title[:200],
                        "severity":    severity,
                        "description": description[:500],
                        "phase":       phase,
                        "tool":        tool,
                        "host":        self._target,
                        "port":        None,
                        "service":     "reasoning_engine",
                        "cves":        [],
                        "mitre":       mitre or "",
                        "timestamp":   datetime.utcnow().isoformat(),
                    }
                },
            })
            # Also persist to DB so FindingsBoard REST load picks it up
            try:
                import db.mongo_client as _dbm
                await _dbm.store_finding(
                    session_id  = self._session_id,
                    host        = self._target,
                    title       = title[:200],
                    severity    = severity,
                    description = description[:500],
                    tool        = tool,
                    phase       = phase,
                )
            except Exception:
                pass
        except Exception:
            pass

    async def _emit_graph_node(
        self,
        node_id:   str,
        node_type: str,
        label:     str,
        phase:     str   = "exploit",
        severity:  str   = "medium",
        metadata:  dict  = None,
    ) -> None:
        """Emit a graph_node event — populates AttackGraph."""
        try:
            await self._emit({
                "type":       "graph_node",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "node_id":   node_id,
                    "type":      node_type,
                    "label":     label[:100],
                    "host":      self._target,
                    "port":      None,
                    "phase":     phase,
                    "severity":  severity,
                    "metadata":  metadata or {},
                },
            })
        except Exception:
            pass

    async def _emit_graph_edge(
        self,
        source: str,
        target: str,
        label:  str = "",
        tool:   str = "reasoning_engine",
    ) -> None:
        """Emit a graph_edge event — populates AttackGraph."""
        try:
            await self._emit({
                "type":       "graph_edge",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "edge_id": f"edge_{source[:20]}_{target[:20]}",
                    "source":  source,
                    "target":  target,
                    "label":   label[:80],
                    "tool":    tool,
                },
            })
        except Exception:
            pass

    async def _emit_attack_tree_from_hypotheses(
        self,
        hypotheses: list,
        optimal_ids: list = None,
    ) -> None:
        """
        Emit attack_tree_ready built from current hypotheses.
        Drives MissionControl plan skeleton.
        """
        try:
            nodes = []
            optimal = optimal_ids or []
            for h in hypotheses[:12]:
                actions = h.recommended_next_actions or []
                first_action = actions[0] if actions else "unknown"
                tool_name = first_action.split()[0] if first_action else "unknown"
                nodes.append({
                    "id":          h.hypothesis_id,
                    "technique":   (h.statement or "")[:80],
                    "step":        (h.statement or "")[:80],
                    "tool":        tool_name,
                    "mitre_id":    h.mitre_technique or "",
                    "mitre_name":  h.mitre_technique or "",
                    "probability": h.confidence,
                    "produces":    h.attack_phase or "unknown",
                    "requires":    [],
                    "is_optimal":  h.hypothesis_id in optimal,
                })
                if not optimal_ids and h.confidence >= 0.65 and not h.invalidated:
                    optimal.append(h.hypothesis_id)

            tree = {
                "hypothesis":   f"Hypothesis-driven pentest of {self._target}",
                "assessment":   "hypothesis_driven",
                "attack_nodes": nodes,
                "optimal_path": optimal[:5],
            }
            await self._emit({
                "type":       "attack_tree_ready",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       {"tree": tree},
            })
            # Also update the ranked_paths for the ReasoningEnginePage
            await self._emit({
                "type":       "ranked_paths_update",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       {"paths": [p.to_dict() for p in self._ranked_paths]},
            })
        except Exception:
            pass

    def serialize_state(self) -> dict:
        """
        Produce a dict for inclusion in checkpoint intel_snapshot.
        Called by MasterAgent._save_checkpoint().
        """
        return {
            "reasoning_iteration":  self._iteration,
            "hypotheses":           [h.to_dict() for h in self._hypotheses],
            "negative_memory":      self._neg_memory.to_dict_list(),
            "action_score":         self._decision_eng.get_score(),
            "ranked_attack_paths":  self._attack_planner.get_paths_as_dicts(),
            "reasoning_journal":    self._journal,
            # [15] Persist the phase-dispatch idempotency ledger so a resumed run does
            # not re-fire phases it already completed before the pause.
            "phases_dispatched":    dict(self._phases_dispatched),
        }
