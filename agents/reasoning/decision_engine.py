"""
agents/reasoning/decision_engine.py

Converts ranked hypotheses into justified, executable actions.

Before executing ANY tool the DecisionEngine:
  1. Checks the hypothesis meets the confidence threshold
  2. Verifies the tool+service has not already failed (NegativeMemory)
  3. Forces the LLM to produce a PreExecutionPlan (objective + actions + fallbacks)
  4. Returns a JustifiedAction with reason/expected_outcome/success_criteria

This is the component that replaces "run every tool" with
"run the minimum action necessary to test the best hypothesis".

Scoring
-------
  +10  validated foothold (shell or flag obtained)
  +5   high-confidence finding confirmed
  +2   hypothesis partially validated
  -3   redundant scan (tool already run on same target)
  -5   irrelevant exploit attempt (confidence < 0.4 but ran anyway)
  -10  repeated failed action (same tool+service tried again)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from agents.reasoning.hypothesis_engine import Hypothesis
from agents.reasoning.attack_planner    import RankedAttackPath
from agents.reasoning.negative_memory   import NegativeMemory


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PreExecutionPlan:
    """
    Mandatory plan produced before any tool runs.
    Forces the LLM to reason about *why* an action is being taken.
    """
    objective:         str
    current_best_path: str
    required_actions:  List[str] = field(default_factory=list)
    fallback_paths:    List[str] = field(default_factory=list)
    risk_assessment:   str       = "medium"  # low|medium|high|critical

    def to_dict(self) -> dict:
        return {
            "objective":         self.objective,
            "current_best_path": self.current_best_path,
            "required_actions":  list(self.required_actions),
            "fallback_paths":    list(self.fallback_paths),
            "risk_assessment":   self.risk_assessment,
        }


@dataclass
class JustifiedAction:
    """
    A single executable action that has been approved by the DecisionEngine.
    Carries the full reasoning chain so the operator can audit every decision.
    """
    action_id:            str
    tool:                 str
    args:                 str
    target_service:       str
    reason:               str
    expected_outcome:     str
    success_criteria:     str
    hypothesis_id:        str
    confidence:           float
    requires_confirmation: bool = False
    plan:                 Optional[PreExecutionPlan] = None
    created_at:           str  = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "action_id":            self.action_id,
            "tool":                 self.tool,
            "args":                 self.args,
            "target_service":       self.target_service,
            "reason":               self.reason,
            "expected_outcome":     self.expected_outcome,
            "success_criteria":     self.success_criteria,
            "hypothesis_id":        self.hypothesis_id,
            "confidence":           self.confidence,
            "requires_confirmation": self.requires_confirmation,
            "plan":                 self.plan.to_dict() if self.plan else None,
            "created_at":           self.created_at,
        }


# Scoring deltas
_SCORE_FOOTHOLD:          int = +10
_SCORE_HIGH_CONF_FINDING: int = +5
_SCORE_PARTIAL_VALID:     int = +2
_SCORE_REDUNDANT_SCAN:    int = -3
_SCORE_IRRELEVANT_EXPLOIT: int = -5
_SCORE_REPEATED_FAILURE:  int = -10


# ---------------------------------------------------------------------------
# DecisionEngine
# ---------------------------------------------------------------------------

class DecisionEngine:
    """
    Selects the next action to execute based on ranked hypotheses.

    Parameters
    ----------
    think_json_fn:
        Async callable matching BaseAgent.think_json(prompt, system) → dict.
    emit_fn:
        Async broadcast callable — used to emit reasoning events to frontend.
    session_id:
        Active session identifier.
    auto_execute_threshold:
        Confidence floor for automatic execution (default 0.70).
        Actions below this threshold set requires_confirmation=True.
    """

    AUTO_EXECUTE_THRESHOLD: float = 0.70

    def __init__(
        self,
        think_json_fn:          Callable[..., Coroutine],
        emit_fn:                Callable[..., Any],
        session_id:             str,
        auto_execute_threshold: float = 0.70,
        voi_rank_fn:            Optional[Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]] = None,
    ) -> None:
        self._think_json  = think_json_fn
        self._emit        = emit_fn
        self._session_id  = session_id
        self._threshold   = auto_execute_threshold
        self._action_score: int = 0
        # Optional Value-of-Information ranker injected by MasterAgent.
        # Signature: rank_actions(list[dict]) -> list[dict] sorted by VoI desc,
        # each dict augmented with voi_score / voi_factors / voi_reasons / voi_dropped.
        self._voi_rank_fn = voi_rank_fn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def select_action(
        self,
        hypotheses:      List[Hypothesis],
        intel:           dict,
        used_tools:      Dict[str, int],
        negative_memory: NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """
        Select the best actionable hypothesis and return a JustifiedAction.

        Returns None when:
          - No actionable hypotheses exist (all invalidated or empty)
          - The best hypothesis has no recommended_next_actions

        Sets requires_confirmation=True when confidence < threshold.

        Parameters
        ----------
        hypotheses:
            Sorted by confidence descending (from HypothesisEngine).
        intel:
            Current master agent _intel dict.
        used_tools:
            {tool_name: run_count} tracking for redundancy detection.
        negative_memory:
            Failed attempts registry for quick pre-flight checks.
        """
        target = intel.get("target", "")

        # ── Phase 0 (Recommendation E): Foothold primers force-promoted ────
        # If an open service has a registered cheap-unauth primer chain
        # (FTP anon, telnet default-creds, SNMP public, SMB null-session,
        # DB default-creds, redis unauth) that has NOT yet been tried this
        # session, fire its first read-only step ahead of any LLM-proposed
        # action.  This is what turns "did we even try the door?" from a
        # planner-luck question into a deterministic guarantee.
        primer = self._next_unused_foothold_primer(
            intel           = intel,
            target          = target,
            used_tools      = used_tools,
            negative_memory = negative_memory,
        )
        if primer is not None:
            await self._emit_reasoning(
                f"[primer] auto-firing cheap-foothold probe: "
                f"{primer.tool} → {primer.target_service} (chain={primer.plan.path[0] if primer.plan and primer.plan.path else '?'})"
            )
            return primer

        # ── Phase 1: gather every viable (hypothesis, action) candidate ─────
        # Recommendation G — index validated hypotheses by id so dependent
        # steps in the current iteration can check whether their parent
        # has already landed.
        validated_ids: set = {
            h.hypothesis_id for h in hypotheses
            if getattr(h, "validated", False)
        }

        candidates: List[Dict[str, Any]] = []
        for hypothesis in hypotheses:
            if hypothesis.invalidated:
                continue
            if not hypothesis.recommended_next_actions:
                continue

            # Defer dependent steps until their parent is validated.  Steps
            # without a parent (the common case, idx=1) fall through.
            parent_id = getattr(hypothesis, "parent_hypothesis_id", None)
            if parent_id and parent_id not in validated_ids:
                await self._emit_reasoning(
                    f"Deferring step {getattr(hypothesis, 'step_index', '?')} "
                    f"({hypothesis.statement[:60]}…) — parent not yet validated"
                )
                continue

            for action_str in hypothesis.recommended_next_actions:
                if not action_str or not action_str.strip():
                    continue

                tool, args, target_service = self._parse_action_str(
                    action_str, target
                )
                if tool == "unknown":
                    continue

                # Hard skip: this exact (tool, service, args_signature) failed
                # before — Recommendation D's fine-grained ban.  A previous
                # sqlmap on /login.php?user= failing no longer blocks sqlmap
                # on /admin/api/users.php?id=.
                if negative_memory.has_failed_before(tool, target_service, args=args):
                    count = negative_memory.attempt_count(tool, target_service, args=args)
                    await self._emit_reasoning(
                        f"Skipping {tool} on {target_service} (this variant) — "
                        f"failed {count}x previously"
                    )
                    continue

                # Hard skip: scan already exhausted
                tool_key = f"{tool}:{target_service}"
                if used_tools.get(tool_key, 0) >= 3:
                    await self._emit_reasoning(
                        f"Skipping redundant scan: {tool} on {target_service} "
                        f"already run {used_tools[tool_key]}x"
                    )
                    continue

                candidates.append({
                    "tool":           tool,
                    "args":           args,
                    "target_service": target_service,
                    "action_str":     action_str,
                    "phase":          intel.get("current_phase", ""),
                    "confidence":     hypothesis.confidence,
                    "_hypothesis":    hypothesis,
                })

        if not candidates:
            return None

        # ── Phase 2: Value-of-Information re-ranking ────────────────────────
        ranked = candidates
        if self._voi_rank_fn is not None:
            try:
                # Strip the hypothesis ref before scoring (not JSON-friendly),
                # then re-attach by index after.
                scoring_input = [
                    {k: v for k, v in c.items() if k != "_hypothesis"}
                    for c in candidates
                ]
                scored = self._voi_rank_fn(scoring_input)
                # Re-attach hypothesis by matching action_str + tool + target_service
                lookup = {
                    (c["tool"], c["target_service"], c["action_str"]): c["_hypothesis"]
                    for c in candidates
                }
                ranked = []
                for s in scored:
                    key = (s.get("tool"), s.get("target_service"), s.get("action_str"))
                    s["_hypothesis"] = lookup.get(key)
                    ranked.append(s)
                # Drop hard-rejected actions
                ranked = [r for r in ranked if not r.get("voi_dropped")]
                # Emit a transparency event with the top of the ranking
                await self._emit_voi_ranking(ranked[:5])
            except Exception as exc:
                await self._emit_reasoning(f"VoI ranking failed: {exc}")
                ranked = candidates

        if not ranked:
            return None

        chosen = ranked[0]
        hypothesis = chosen.get("_hypothesis")
        if hypothesis is None:
            return None

        # Build pre-execution plan for the winner
        plan = await self.build_pre_execution_plan(hypothesis, intel)

        voi_score   = chosen.get("voi_score")
        voi_reasons = chosen.get("voi_reasons") or []

        reason = self._build_reason(hypothesis)
        if voi_score is not None:
            reason = f"[VoI={voi_score}] " + reason
            if voi_reasons:
                reason += "  ::  " + "; ".join(voi_reasons[:3])

        action = JustifiedAction(
            action_id            = str(uuid.uuid4()),
            tool                 = chosen["tool"],
            args                 = chosen["args"],
            target_service       = chosen["target_service"],
            reason               = reason,
            expected_outcome     = chosen.get("action_str", ""),
            success_criteria     = self._build_success_criteria(hypothesis),
            hypothesis_id        = hypothesis.hypothesis_id,
            confidence           = hypothesis.confidence,
            requires_confirmation = hypothesis.confidence < self._threshold,
            plan                 = plan,
        )

        await self._emit_action(action)
        return action

    async def build_pre_execution_plan(
        self,
        hypothesis: Hypothesis,
        intel:      dict,
    ) -> PreExecutionPlan:
        """
        Force the LLM to produce an explicit plan before any tool runs.

        Returns a safe fallback plan on LLM failure.
        """
        system = (
            "You are a penetration tester about to execute an attack step. "
            "Before running any tool you must articulate your objective, the "
            "specific path you are following, the ordered actions required, and "
            "fallback options if the primary path fails. "
            "Respond ONLY with valid JSON. No markdown."
        )

        target = intel.get("target", "unknown")
        shell  = "YES" if intel.get("shell_access") else "NO"

        prompt = (
            f"Target: {target}\n"
            f"Shell access: {shell}\n"
            f"Hypothesis: {hypothesis.statement}\n"
            f"Confidence: {hypothesis.confidence:.2f}\n"
            f"Supporting evidence: {', '.join(hypothesis.evidence_supporting[:3])}\n"
            f"Next actions proposed: {', '.join(hypothesis.recommended_next_actions[:3])}\n\n"
            "Produce a pre-execution plan in EXACTLY this JSON format:\n"
            "{\n"
            '  "objective": "specific goal of this action",\n'
            '  "current_best_path": "brief description of the attack path",\n'
            '  "required_actions": ["ordered list of exact tool commands"],\n'
            '  "fallback_paths": ["alternative approaches if primary fails"],\n'
            '  "risk_assessment": "low|medium|high|critical"\n'
            "}"
        )

        try:
            raw = await self._think_json(prompt, system)
            if raw and isinstance(raw, dict):
                return PreExecutionPlan(
                    objective         = str(raw.get("objective", hypothesis.statement)),
                    current_best_path = str(raw.get("current_best_path", "")),
                    required_actions  = [
                        str(a) for a in (raw.get("required_actions") or [])
                    ],
                    fallback_paths    = [
                        str(f) for f in (raw.get("fallback_paths") or [])
                    ],
                    risk_assessment   = str(raw.get("risk_assessment", "medium")),
                )
        except Exception:
            pass

        # Safe fallback
        return PreExecutionPlan(
            objective         = hypothesis.statement,
            current_best_path = hypothesis.statement,
            required_actions  = list(hypothesis.recommended_next_actions[:3]),
            fallback_paths    = [],
            risk_assessment   = "medium",
        )

    async def score_action_result(
        self,
        action:       JustifiedAction,
        result:       dict,
        validated:    bool,
        intel:        dict,
    ) -> Tuple[int, str]:
        """
        Apply scoring rules and return (new_total_score, reason_string).

        Called by ReasoningLoop._update() after every tool execution.
        """
        delta  = 0
        reason = ""

        # Foothold obtained
        if intel.get("shell_access") and not result.get("_was_shell_before", False):
            delta  += _SCORE_FOOTHOLD
            reason  = "Foothold obtained — shell access confirmed"

        # Flag captured
        elif intel.get("user_flag") or intel.get("root_flag"):
            delta  += _SCORE_FOOTHOLD
            reason  = "Flag captured"

        # High-confidence finding validated
        elif validated and action.confidence >= 0.7:
            delta  += _SCORE_HIGH_CONF_FINDING
            reason  = f"High-confidence finding validated (conf={action.confidence:.2f})"

        # Partial validation
        elif validated:
            delta  += _SCORE_PARTIAL_VALID
            reason  = "Hypothesis partially validated"

        # Repeated failure (negative memory already had this)
        elif not validated and action.confidence < 0.4:
            delta  += _SCORE_IRRELEVANT_EXPLOIT
            reason  = f"Low-confidence exploit attempt failed (conf={action.confidence:.2f})"

        # Not validated — neutral, no penalty for honest attempts
        else:
            reason = "Action executed — hypothesis not yet validated"

        self._action_score += delta
        return self._action_score, reason

    def get_score(self) -> int:
        """Return the current cumulative engagement score."""
        return self._action_score

    def set_score(self, score: int) -> None:
        """Restore score from checkpoint."""
        self._action_score = score

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_action_str(
        self,
        action_str: str,
        target:     str,
    ) -> Tuple[str, str, str]:
        """
        Parse an action string like "sqlmap -u http://TARGET/login" into
        (tool, args, target_service).

        Falls back gracefully when the string is not a recognisable command.
        """
        action_str = action_str.strip()
        parts      = action_str.split(None, 1)  # split on first whitespace
        tool       = parts[0].lower() if parts else "unknown"
        args       = parts[1] if len(parts) > 1 else ""

        # Derive a target_service identifier from the args or tool name
        target_service = self._infer_target_service(tool, args, target)

        return tool, args, target_service

    def _infer_target_service(self, tool: str, args: str, target: str) -> str:
        """
        Attempt to derive a "service:port" identifier from tool and args.
        Used for NegativeMemory dedup and redundancy detection.
        """
        combined = (args or "").lower()

        # Port patterns
        import re
        port_match = re.search(r':(\d{2,5})', combined)
        if port_match:
            port = port_match.group(1)
            # Guess service from port
            service_map = {
                "21": "ftp", "22": "ssh", "23": "telnet",
                "25": "smtp", "53": "dns", "80": "http",
                "110": "pop3", "143": "imap", "389": "ldap",
                "443": "https", "445": "smb", "1433": "mssql",
                "1521": "oracle", "3306": "mysql", "3389": "rdp",
                "5432": "postgresql", "5900": "vnc", "6379": "redis",
                "8080": "http", "8443": "https", "8888": "http",
            }
            svc = service_map.get(port, "tcp")
            return f"{svc}:{port}"

        # Tool → service inference
        tool_service = {
            "sqlmap":     f"http:80",
            "hydra":      f"ssh:22",
            "crackmapexec": f"smb:445",
            "nmap":       f"scan:{target}",
            "gobuster":   f"http:80",
            "ffuf":       f"http:80",
            "nikto":      f"http:80",
            "dirb":       f"http:80",
            "wpscan":     f"http:80",
            "msfconsole": f"exploit:{target}",
            "searchsploit": f"exploit:{target}",
            "impacket-secretsdump": f"smb:445",
            "evil-winrm": f"winrm:5985",
            "bloodhound-python": f"ldap:389",
        }
        return tool_service.get(tool, f"{tool}:{target}")

    # ── Recommendation E: foothold-primer auto-promotion ──────────────────

    # Map of (port → (chain_id, tool, args_template)) — the read-only first
    # step of each cheap-foothold primer chain.  These run before any
    # LLM-proposed action whenever their port is open and they haven't
    # yet fired this session.  Args use a bare {target} placeholder.
    _FOOTHOLD_PRIMERS: List[Dict[str, Any]] = [
        # FTP anonymous probe
        {"chain": "ftp_anonymous_login", "ports": ["21"],
         "tool": "nmap", "args": "--script ftp-anon -p21 {target}",
         "service_label": "ftp:21",
         "rationale": "vsftpd/proftpd routinely ship with anon-read enabled"},
        # Telnet — passive nmap probe (no brute on first iteration)
        {"chain": "telnet_default_creds", "ports": ["23"],
         "tool": "nmap", "args": "-sV -p23 --script banner {target}",
         "service_label": "telnet:23",
         "rationale": "telnet banner often leaks default-creds product family"},
        # SNMP public walk
        {"chain": "snmp_public_v2c_walk", "ports": ["161"],
         "tool": "snmpwalk", "args": "-v 2c -c public {target}",
         "service_label": "snmp:161",
         "rationale": "default community 'public' leaks users + processes"},
        # SMB null-session enum
        {"chain": "smb_anonymous_enum", "ports": ["139", "445"],
         "tool": "smbclient", "args": "-L //{target}/ -N",
         "service_label": "smb:445",
         "rationale": "null-session shares + user enum still works on many boxes"},
        # MySQL empty-password root
        {"chain": "db_default_creds_quick", "ports": ["3306"],
         "tool": "mysql", "args": "-h {target} -u root -e 'SHOW DATABASES;'",
         "service_label": "mysql:3306",
         "rationale": "lab boxes often leave root/'' enabled"},
        # Postgres default
        {"chain": "db_default_creds_quick", "ports": ["5432"],
         "tool": "psql", "args": "-h {target} -U postgres -c '\\l' -W postgres",
         "service_label": "postgresql:5432",
         "rationale": "default postgres/postgres credentials"},
        # MongoDB unauth
        {"chain": "db_default_creds_quick", "ports": ["27017"],
         "tool": "mongosh", "args": "--host {target} --eval 'db.adminCommand({listDatabases:1})'",
         "service_label": "mongodb:27017",
         "rationale": "unauthenticated Mongo on default port"},
        # Redis unauth
        {"chain": "redis_unauth_to_shell", "ports": ["6379"],
         "tool": "redis-cli", "args": "-h {target} ping",
         "service_label": "redis:6379",
         "rationale": "unauthenticated Redis ping → write-key foothold"},
    ]

    def _next_unused_foothold_primer(
        self,
        *, intel:           dict,
        target:             str,
        used_tools:         Dict[str, int],
        negative_memory:    NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """Return a primer action if any open service has a primer that
        has not yet fired and was not already banned.  None otherwise.

        The intent is "always knock on the obvious doors before invoking
        the heavyweight planner".  Once every applicable primer has run
        once, this returns None forever (per session) and the normal
        LLM-driven planner takes over.
        """
        # Open ports — accept ints or strings or {port:..} dicts.
        open_ports: set = set()
        for p in (intel.get("open_ports") or []):
            if isinstance(p, dict):
                pp = p.get("port")
                if pp is not None:
                    open_ports.add(str(pp))
            else:
                open_ports.add(str(p).split("/")[0])

        if not open_ports:
            return None

        # Track which primers have already fired this session via a
        # state key on intel (reset on session-start).
        fired = intel.setdefault("_foothold_primers_fired", set())
        if isinstance(fired, list):
            fired = set(fired)
            intel["_foothold_primers_fired"] = fired

        for primer in self._FOOTHOLD_PRIMERS:
            if not (set(primer["ports"]) & open_ports):
                continue
            primer_key = primer["chain"] + ":" + primer["service_label"]
            if primer_key in fired:
                continue
            tool = primer["tool"]
            svc  = primer["service_label"]
            # Respect negative memory — if this exact probe failed already,
            # skip it (saves a round-trip on a confirmed-dead service).
            try:
                args_filled = primer["args"].format(target=target)
            except Exception:
                args_filled = primer["args"]
            if negative_memory.has_failed_before(tool, svc, args=args_filled):
                # Mark fired so we don't re-evaluate it next iteration.
                fired.add(primer_key)
                continue

            # Mark fired pre-emptively so a slow listener / repeated
            # select_action call doesn't re-issue the same primer.
            fired.add(primer_key)

            return JustifiedAction(
                action_id            = f"primer-{primer['chain']}-{primer['service_label']}",
                tool                 = tool,
                args                 = args_filled,
                target_service       = svc,
                reason               = (
                    f"[Primer/{primer['chain']}] cheap-unauth probe before LLM "
                    f"planner — {primer['rationale']}"
                ),
                expected_outcome     = "Primer banner / version / share list / unauth confirmation",
                success_criteria     = "Tool exits 0 with non-error output indicating service responds",
                hypothesis_id        = "primer",
                confidence           = 0.85,
                requires_confirmation= False,
            )
        return None

    def _build_reason(self, hypothesis: Hypothesis) -> str:
        """Format a justification string from a hypothesis."""
        evidence = " | ".join(hypothesis.evidence_supporting[:2])
        return (
            f"Hypothesis: {hypothesis.statement[:80]}. "
            f"Confidence: {hypothesis.confidence:.2f}. "
            f"Evidence: {evidence}"
        )

    def _build_success_criteria(self, hypothesis: Hypothesis) -> str:
        """Derive success criteria from the hypothesis required_evidence."""
        if hypothesis.required_evidence:
            return "Confirm: " + " AND ".join(hypothesis.required_evidence[:2])
        return "Hypothesis validated — action produced expected output"

    async def _emit_reasoning(self, message: str) -> None:
        """Emit a reasoning trace event to the frontend."""
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       "reasoning_decision",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       {"message": message, "component": "decision_engine"},
                })
        except Exception:
            pass

    async def _emit_voi_ranking(self, ranked: List[Dict[str, Any]]) -> None:
        """Emit the top-N VoI-ranked candidates so the operator can see *why*
        a particular action was chosen and what runners-up were considered."""
        try:
            if not callable(self._emit):
                return
            payload = []
            for r in ranked:
                payload.append({
                    "tool":           r.get("tool"),
                    "args":           r.get("args"),
                    "target_service": r.get("target_service"),
                    "action_str":     r.get("action_str"),
                    "voi_score":      r.get("voi_score"),
                    "voi_factors":    r.get("voi_factors") or {},
                    "voi_reasons":    r.get("voi_reasons") or [],
                    "voi_dropped":    bool(r.get("voi_dropped", False)),
                    "confidence":     r.get("confidence"),
                })
            await self._emit({
                "type":       "voi_ranking",
                "session_id": self._session_id,
                "agent":      "master",
                "data":       {"top": payload, "count": len(payload)},
            })
        except Exception:
            pass

    async def _emit_action(self, action: JustifiedAction) -> None:
        """Emit a justified_action event to the frontend."""
        try:
            if callable(self._emit):
                await self._emit({
                    "type":       "justified_action",
                    "session_id": self._session_id,
                    "agent":      "master",
                    "data":       action.to_dict(),
                })
        except Exception:
            pass
