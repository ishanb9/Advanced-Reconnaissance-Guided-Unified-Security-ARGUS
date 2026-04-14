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
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from agents.master_agent import MasterAgent

from agents.reasoning.hypothesis_engine import HypothesisEngine, Hypothesis
from agents.reasoning.attack_planner    import AttackPlanner, RankedAttackPath
from agents.reasoning.decision_engine   import DecisionEngine, JustifiedAction
from agents.reasoning.negative_memory   import NegativeMemory


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

        # Restore from checkpoint if reasoning_journal already populated
        self._journal = list(self._intel.get("reasoning_journal", []))
        self._decision_eng.set_score(self._intel.get("action_score", 0))

        # Restore attack planner state if checkpoint has paths
        stored_paths = self._intel.get("ranked_attack_paths", [])
        if stored_paths:
            self._attack_planner.restore_from_dicts(stored_paths)

        # --- INITIAL RECON BOOTSTRAP ---
        # If no ports have been discovered yet, run the basic recon phase first
        # so the hypothesis engine has evidence to work with.
        if not self._intel.get("open_ports"):
            await self._bootstrap_recon()

        for iteration in range(self.MAX_ITERATIONS):
            self._iteration = iteration

            # ── PAUSE CHECK ──────────────────────────────────────────────
            try:
                should_pause = await self._check_pause()
                if should_pause:
                    await self._emit_status("Paused at iteration boundary", "WAITING")
                    break
            except Exception:
                pass

            # ── STOP CHECK ───────────────────────────────────────────────
            if getattr(self._master, "_stop_requested", False):
                await self._emit_status("Stop requested — exiting loop", "DONE")
                break

            await self._emit_loop_event("iteration_start", {"iteration": iteration})

            # ── OBSERVE ──────────────────────────────────────────────────
            evidence = await self._observe()

            # ── INTERPRET ────────────────────────────────────────────────
            assessment = await self._interpret(evidence)
            if assessment:
                self._journal.append(f"[{iteration}] {assessment}")
                self._intel["reasoning_journal"] = self._journal

            # ── OBJECTIVE CHECK ──────────────────────────────────────────
            if self._is_objective_achieved():
                await self._emit_status("Objective achieved — loop complete", "DONE")
                break

            # ── HYPOTHESIZE ──────────────────────────────────────────────
            self._hypotheses = await self._hypothesize(evidence)
            if not self._hypotheses:
                await self._emit_reasoning("No hypotheses generated — gathering more evidence")
                await self._gather_more_evidence()
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

            # ── PRIORITIZE ───────────────────────────────────────────────
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
            if top_path and top_path.total_score >= self.CONVERGENCE_THRESHOLD:
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
            )

            if action is None:
                await self._emit_reasoning(
                    "No actionable hypothesis found — exhausting more evidence paths"
                )
                result = await self._gather_more_evidence()
                if not result:
                    await self._emit_status("No more actions available — loop complete", "DONE")
                    break
                continue

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

            # ── EXECUTE ──────────────────────────────────────────────────
            was_shell = bool(self._intel.get("shell_access"))
            result    = await self._execute(action)
            result["_was_shell_before"] = was_shell  # used by score_action_result

            # ── VALIDATE ─────────────────────────────────────────────────
            active_hyp = next(
                (h for h in self._hypotheses
                 if h.hypothesis_id == action.hypothesis_id),
                None
            )
            validated  = await self._validate(action, result, active_hyp)

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

            # ── CTF ANSWER EXTRACTION ─────────────────────────────────────
            # After every tool execution, check if the output answers any
            # CTF objectives that the operator provided in notes.
            if self._intel.get("ctf_objectives"):
                await self._extract_ctf_answers(action, result)

            # ── AUTO POST-EXPLOITATION ────────────────────────────────────
            # If shell access was just gained this iteration, immediately
            # chain post-exploit + privesc (mirrors how a real attacker works)
            if not result.get("_was_shell_before") and self._intel.get("shell_access"):
                await self._emit_reasoning(
                    "🎯 Shell access gained — automatically chaining post-exploitation"
                )
                await self._auto_post_exploit()

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

        try:
            await self._master._phase_recon(target=self._target, plan={})
        except Exception as e:
            await self._emit_reasoning(f"Recon error: {e}")

        ports_found = self._intel.get("open_ports", [])
        port_nums   = {p.get("port") if isinstance(p, dict) else p for p in ports_found}

        parallel_tasks: list = []
        parallel_tasks.append(("OSINT", self._safe_phase(self._master._phase_osint, target=self._target)))
        if port_nums:
            parallel_tasks.append(("Vuln ID", self._safe_phase(self._master._phase_vuln_id, target=self._target)))
        web_ports = [p for p in port_nums if p in {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443}]
        if web_ports:
            parallel_tasks.append(("Web", self._safe_phase(self._master._phase_web_testing, target=self._target, web_ports=web_ports)))

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
        try:
            await self._master._phase_recon(target=self._target, plan={})
        except Exception as e:
            await self._emit_reasoning(f"Compliance recon error: {e}")
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

    async def _observe(self) -> dict:
        """Snapshot the current evidence state."""
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
        ports   = len(evidence.get("open_ports", []))
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
        """Delegate to HypothesisEngine."""
        return await self._hypothesis_eng.generate_hypotheses(
            intel           = self._intel,
            negative_memory = self._neg_memory,
            iteration       = self._iteration,
        )

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
        """
        if not hypothesis:
            return False

        stdout    = (result.get("stdout") or result.get("output") or "")[:1000]
        exit_code = result.get("exit_code", -1)

        # Quick heuristic: obvious failure signals
        error_signals = [
            "connection refused", "no route to host",
            "command not found", "permission denied",
            "module not found", "exploit failed",
        ]
        stdout_lower = stdout.lower()
        for sig in error_signals:
            if sig in stdout_lower:
                return False

        # Quick heuristic: obvious success signals
        success_signals = ["shell", "uid=", "whoami", "flag{", "root@", "meterpreter"]
        for sig in success_signals:
            if sig in stdout_lower:
                return True

        # LLM validation for ambiguous cases
        if len(stdout) < 20:
            return exit_code == 0

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
            return response.startswith("yes")
        except Exception:
            return exit_code == 0

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
        if not is_passive and "nikto" not in tools_excl and intel.get("open_ports") and not intel.get("vulnerabilities"):
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

        # Only send first 3000 chars to LLM to stay within context
        stdout_snippet = stdout[:3000]

        # Build compact objective list for the LLM
        q_lines = "\n".join(
            f"{i+1}. {obj.get('task') or obj.get('question') or str(obj)}"
            for i, obj in unanswered[:10]
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
            f"Tool output:\n{stdout_snippet}\n\n"
            f"Objectives to answer (find exact answers in the output above):\n{q_lines}\n\n"
            f"Extraction guidance: {extraction_hints}\n\n"
            "For each objective whose answer is DIRECTLY visible in the output, return it.\n"
            "Only report answers explicitly present — never guess or infer.\n"
            "Respond with JSON only — no prose:\n"
            '{{"answers": [{{"index": 1, "question": "...", "answer": "exact value from output", "evidence": "verbatim line"}}]}}\n'
            'If nothing matches, return: {{"answers": []}}'
        )
        system = (
            f"You extract precise answers to {eng_type} objectives from tool output. "
            "Only report what is explicitly present in the output. Never guess. If unsure, omit."
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

    async def _safe_phase(self, phase_fn, **kwargs):
        """Call a MasterAgent phase safely, returning {} on error."""
        try:
            result = await phase_fn(**kwargs)
            return result or {}
        except Exception as e:
            name = getattr(phase_fn, "__name__", "phase")
            await self._emit_reasoning(f"{name} error: {e}")
            return {}

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
        """True if root/SYSTEM shell or both flags captured."""
        intel = self._intel
        if intel.get("root_flag") and intel.get("user_flag"):
            return True
        shells = intel.get("shells", [])
        for sh in shells:
            if isinstance(sh, dict) and sh.get("elevated"):
                return True
        return False

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
        try:
            await self._emit({
                "type":       "finding",
                "session_id": self._session_id,
                "agent":      "master",
                "data": {
                    "finding": {
                        "id":          str(uuid.uuid4()),
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
        }
