"""
voi_scorer.py — Improvement #3: Value-of-Information action scorer.

Pure scoring module that ranks candidate actions by their expected progress
toward the mission's *unachieved* win conditions, blended with practical
penalties for novelty, negative memory, scope/budget violations, and
phase-fit.

The scorer never executes anything and never reaches the network; it only
returns numeric scores plus a human-readable breakdown so the operator can
see *why* a given action ranks where it does.

Scoring components (each contributes a signed integer delta):

  +30   strong win-relevance   — action directly advances an unachieved
                                  win condition (e.g. credential dump when
                                  ``creds_captured`` is pending).
  +15   weak win-relevance     — action plausibly contributes (e.g. a port
                                  scan when *initial_access* is pending).
   +5   high-confidence hyp    — backing hypothesis confidence ≥ 0.7
   +2   medium-confidence hyp  — confidence in [0.4, 0.7)
   -5   low-confidence hyp     — confidence < 0.4
   -8   redundant              — same tool already executed N≥2 times on
                                  same target_service
  -15   negative-memory hit    — known prior failure of this exact pair
  -20   scope-out violation    — target falls outside ``mission_brief.scope_in``
                                  or hits ``scope_out``
  -10   noise overspend        — action's noise > brief.noise_budget
  -∞    blast-radius violation — destructive action when blast_radius=passive
                                  / active actions when blast_radius=passive
                                  → returned as score = -10**6 so the action
                                  is effectively dropped

The numeric weights are intentionally simple so the operator can reason about
why one action beat another without reading code.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Tool → win-condition relevance map
#
# These mappings encode "which kind of action plausibly moves which goal
# forward?".  Keys are LOWER-CASE tool-name substrings; values are sets of
# win-condition tokens this tool helps achieve.  A tool can target many goals.
# ─────────────────────────────────────────────────────────────────────────────

_STRONG_TOOL_GOALS: Dict[str, set] = {
    # Credential capture
    "hydra":         {"creds_captured", "credentials_captured"},
    "medusa":        {"creds_captured", "credentials_captured"},
    "crackmapexec":  {"creds_captured", "credentials_captured", "lateral_movement"},
    "cme":           {"creds_captured", "credentials_captured", "lateral_movement"},
    "secretsdump":   {"creds_captured", "credentials_captured"},
    "mimikatz":      {"creds_captured", "credentials_captured", "domain_admin"},
    "lazagne":       {"creds_captured", "credentials_captured"},
    "responder":     {"creds_captured", "credentials_captured"},
    "kerbrute":      {"creds_captured", "credentials_captured"},
    "impacket-getnp": {"creds_captured", "credentials_captured"},
    "impacket-gettgt": {"creds_captured", "credentials_captured", "domain_admin"},
    # Shells / RCE
    "metasploit":    {"shell_obtained", "rce_confirmed", "initial_access"},
    "msfconsole":    {"shell_obtained", "rce_confirmed", "initial_access"},
    "msfvenom":      {"shell_obtained", "initial_access"},
    "exploit":       {"shell_obtained", "rce_confirmed", "initial_access"},
    "sqlmap":        {"rce_confirmed", "creds_captured"},
    "nuclei":        {"rce_confirmed"},
    "wpscan":        {"rce_confirmed", "creds_captured"},
    # Privilege escalation
    "linpeas":       {"privilege_escalated", "privesc"},
    "winpeas":       {"privilege_escalated", "privesc"},
    "linenum":       {"privilege_escalated", "privesc"},
    "pspy":          {"privilege_escalated", "privesc"},
    "gtfobins":      {"privilege_escalated", "privesc"},
    # Lateral movement
    "psexec":        {"lateral_movement", "shell_obtained"},
    "wmiexec":       {"lateral_movement", "shell_obtained"},
    "smbexec":       {"lateral_movement", "shell_obtained"},
    "evil-winrm":    {"lateral_movement", "shell_obtained"},
    "bloodhound":    {"lateral_movement", "domain_admin"},
    # Persistence
    "schtasks":      {"persistence", "persistence_established"},
    "crontab":       {"persistence", "persistence_established"},
    # Flag capture
    "find":          {"user_flag_captured", "root_flag_captured", "any_flag_captured"},
    "cat":           {"user_flag_captured", "root_flag_captured", "any_flag_captured"},
    "type":          {"user_flag_captured", "root_flag_captured", "any_flag_captured"},
    # Exfil
    "scp":           {"data_exfiltrated", "exfil"},
    "rsync":         {"data_exfiltrated", "exfil"},
    "curl":          {"data_exfiltrated", "exfil"},
}

# Weaker (recon-style) tools that *enable* later goals but don't directly
# satisfy them.
_WEAK_TOOL_GOALS: Dict[str, set] = {
    "nmap":          {"initial_access", "shell_obtained"},
    "rustscan":      {"initial_access", "shell_obtained"},
    "masscan":       {"initial_access", "shell_obtained"},
    "enum4linux":    {"creds_captured", "lateral_movement"},
    "smbclient":     {"creds_captured", "lateral_movement"},
    "smbmap":        {"creds_captured", "lateral_movement"},
    "ldapsearch":    {"creds_captured", "lateral_movement", "domain_admin"},
    "rpcclient":     {"creds_captured", "lateral_movement"},
    "gobuster":      {"initial_access", "rce_confirmed"},
    "ffuf":          {"initial_access", "rce_confirmed"},
    "feroxbuster":   {"initial_access", "rce_confirmed"},
    "dirb":          {"initial_access"},
    "nikto":         {"initial_access", "rce_confirmed"},
    "whatweb":       {"initial_access"},
    "wafw00f":       {"initial_access"},
    "dnsrecon":      {"initial_access"},
    "ssh":           {"shell_obtained", "lateral_movement"},
}

# Approximate noise score per tool category (0..100 scale; higher = louder).
_TOOL_NOISE: Dict[str, int] = {
    "nmap":         40,
    "rustscan":     60,
    "masscan":      90,
    "nuclei":       55,
    "nikto":        70,
    "sqlmap":       80,
    "hydra":        85,
    "medusa":       85,
    "metasploit":   75,
    "msfconsole":   75,
    "responder":    50,
    "crackmapexec": 65,
    "bloodhound":   55,
    "ffuf":         70,
    "gobuster":     65,
    "feroxbuster":  70,
    "whatweb":      25,
    "wafw00f":      15,
    "dnsrecon":     20,
    "enum4linux":   45,
}

# Categorisation for blast radius
#
# DESTRUCTIVE = data-altering / DoS / instability risk.  Kept intentionally
#   narrow so normal active-mode workflows (sqlmap, hydra, MSF) are not
#   dropped under blast_radius="active".  Operators who need those forbidden
#   should set blast_radius="passive".
# ACTIVE      = sends packets to the target (scans, brute force, exploits).
# PASSIVE     = OSINT / no traffic to target.
_DESTRUCTIVE_TOKENS = (
    "slowloris", "hping3", "t50", "thc-ssl-dos", "wfuzz-dos",
    "sqlmap --drop", "ransom",
)
_ACTIVE_TOKENS = (
    "nmap", "rustscan", "masscan", "nuclei", "nikto", "ffuf", "gobuster",
    "feroxbuster", "dirb", "whatweb", "smbclient", "smbmap", "ldapsearch",
    "rpcclient", "enum4linux", "responder", "crackmapexec", "cme",
    "bloodhound", "hydra", "medusa", "sqlmap", "metasploit", "msfconsole",
    "msfvenom", "exploit", "psexec", "wmiexec", "smbexec", "evil-winrm",
    "ssh", "kerbrute", "secretsdump", "mimikatz", "linpeas", "winpeas",
    "wpscan",
)
# Anything not in either list is considered "passive" by default.

VOI_DROP = -10**6   # "do not pick" sentinel


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _tool_key(tool: str) -> str:
    return (tool or "").strip().lower()


def _action_blast_class(tool: str) -> str:
    t = _tool_key(tool)
    if any(d in t for d in _DESTRUCTIVE_TOKENS):
        return "destructive"
    if any(a in t for a in _ACTIVE_TOKENS):
        return "active"
    return "passive"


def _tool_noise(tool: str, args: str = "") -> int:
    t = _tool_key(tool)
    base = _TOOL_NOISE.get(t)
    if base is None:
        # Conservative default: small footprint
        base = 25
    # Common amplifiers
    if "-T5" in (args or "") or "--rate" in (args or ""):
        base = min(100, base + 20)
    return base


def _strong_goals_for(tool: str) -> set:
    t = _tool_key(tool)
    out: set = set()
    for k, v in _STRONG_TOOL_GOALS.items():
        if k in t:
            out |= v
    return out


def _weak_goals_for(tool: str) -> set:
    t = _tool_key(tool)
    out: set = set()
    for k, v in _WEAK_TOOL_GOALS.items():
        if k in t:
            out |= v
    return out


def _pending_conditions(win_snapshot: Dict[str, Any]) -> set:
    """Return the set of condition tokens that are NOT yet achieved."""
    pending: set = set()
    for c in (win_snapshot or {}).get("conditions", []):
        if isinstance(c, dict) and not c.get("achieved"):
            name = (c.get("name") or "").lower()
            # If it's a boolean expression, fall back to its sub-state tokens
            sub  = c.get("sub_state") or {}
            if sub:
                for tok, val in sub.items():
                    if not val:
                        pending.add(tok.lower())
            else:
                pending.add(name)
    return pending


def _scope_violation(target_service: str, brief: Dict[str, Any]) -> bool:
    if not brief:
        return False
    target_lc = (target_service or "").lower()
    if not target_lc:
        return False
    scope_out = [(s or "").lower() for s in brief.get("scope_out", []) or []]
    for bad in scope_out:
        if bad and bad in target_lc:
            return True
    scope_in = [(s or "").lower() for s in brief.get("scope_in", []) or []]
    if scope_in:
        # If scope_in is set, the target must match at least one entry
        if not any(s in target_lc for s in scope_in if s):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VoIBreakdown:
    score:    int
    factors:  Dict[str, int] = field(default_factory=dict)
    reasons:  List[str]      = field(default_factory=list)
    dropped:  bool           = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def score_action(
    action:        Dict[str, Any],
    intel:         Dict[str, Any],
    win_snapshot:  Dict[str, Any],
    used_tools:    Optional[Dict[str, int]]    = None,
    failed_pairs:  Optional[Dict[str, int]]    = None,
    mission_brief: Optional[Dict[str, Any]]    = None,
) -> VoIBreakdown:
    """Score a single candidate action.

    *action* is a dict with at least:  ``tool`` (str).
    Optional keys:  ``args``, ``target_service``, ``phase``, ``confidence``.

    All context arguments are tolerant — pass ``None`` or empty dicts and the
    scorer falls back to neutral defaults.
    """
    used_tools    = used_tools    or {}
    failed_pairs  = failed_pairs  or {}
    mission_brief = mission_brief or {}
    win_snapshot  = win_snapshot  or {}
    intel         = intel         or {}

    tool        = action.get("tool", "") or ""
    args        = action.get("args", "") or ""
    tgt_service = (action.get("target_service") or "").strip()
    confidence  = float(action.get("confidence", 0.5) or 0.5)

    factors: Dict[str, int] = {}
    reasons: List[str]      = []

    # ── 0. Blast-radius gate (hard) ─────────────────────────────────────
    blast_brief  = (mission_brief.get("blast_radius") or "active").lower()
    blast_action = _action_blast_class(tool)
    if blast_brief == "passive" and blast_action != "passive":
        return VoIBreakdown(
            score=VOI_DROP, factors={"blast_radius_violation": VOI_DROP},
            reasons=[f"brief is passive but {tool} is {blast_action}"],
            dropped=True,
        )
    if blast_brief == "active" and blast_action == "destructive":
        return VoIBreakdown(
            score=VOI_DROP, factors={"blast_radius_violation": VOI_DROP},
            reasons=[f"brief forbids destructive ops ({tool})"],
            dropped=True,
        )

    # ── 1. Win-relevance ────────────────────────────────────────────────
    pending = _pending_conditions(win_snapshot)
    strong_match = _strong_goals_for(tool) & pending
    weak_match   = _weak_goals_for(tool)   & pending

    if strong_match:
        factors["win_relevance_strong"] = +30
        reasons.append(f"directly advances {sorted(strong_match)}")
    elif weak_match:
        factors["win_relevance_weak"] = +15
        reasons.append(f"plausibly enables {sorted(weak_match)}")
    else:
        # Action does not map to any pending goal — slight penalty
        if pending:
            factors["no_win_match"] = -3
            reasons.append("no mapping to pending win conditions")

    # ── 2. Hypothesis confidence weighting ─────────────────────────────
    if confidence >= 0.7:
        factors["hyp_high_conf"] = +5
    elif confidence >= 0.4:
        factors["hyp_med_conf"] = +2
    else:
        factors["hyp_low_conf"] = -5

    # ── 3. Redundancy ──────────────────────────────────────────────────
    pair_key = f"{_tool_key(tool)}:{tgt_service}".rstrip(":")
    used_n   = int(used_tools.get(pair_key, 0) or used_tools.get(_tool_key(tool), 0))
    if used_n >= 2:
        factors["redundant"] = -8 * (used_n - 1)
        reasons.append(f"{tool} already run {used_n}x on {tgt_service or 'target'}")

    # ── 4. Negative memory ────────────────────────────────────────────
    if failed_pairs.get(pair_key, 0) > 0:
        factors["negative_memory"] = -15
        reasons.append(f"prior failure of {tool} on {tgt_service}")

    # ── 5. Scope guardrails ───────────────────────────────────────────
    if _scope_violation(tgt_service, mission_brief):
        factors["scope_violation"] = -20
        reasons.append(f"{tgt_service} violates mission scope")

    # ── 6. Noise budget ───────────────────────────────────────────────
    noise_budget = int(mission_brief.get("noise_budget", 70) or 70)
    action_noise = _tool_noise(tool, args)
    if action_noise > noise_budget:
        delta = -10 - max(0, action_noise - noise_budget) // 5
        factors["noise_overspend"] = delta
        reasons.append(f"noise={action_noise} > budget={noise_budget}")

    # ── 7. Mission-complete shortcut ──────────────────────────────────
    if win_snapshot.get("all_achieved"):
        # Strongly prefer wrap-up actions (exfil/persist/report) once mission
        # is achieved.  Down-weight everything else.
        wrap_goals = {"exfil", "data_exfiltrated", "persistence", "persistence_established"}
        if not (_strong_goals_for(tool) & wrap_goals):
            factors["mission_already_complete"] = -10
            reasons.append("mission complete — non-wrap-up action")

    score = sum(factors.values())
    return VoIBreakdown(
        score=int(score), factors=factors, reasons=reasons, dropped=False
    )


def rank_actions(
    actions:       List[Dict[str, Any]],
    intel:         Dict[str, Any],
    win_snapshot:  Dict[str, Any],
    used_tools:    Optional[Dict[str, int]]    = None,
    failed_pairs:  Optional[Dict[str, int]]    = None,
    mission_brief: Optional[Dict[str, Any]]    = None,
) -> List[Dict[str, Any]]:
    """Score every action and return them sorted by score descending.

    Each result dict carries the original action plus ``voi_score``,
    ``voi_factors``, ``voi_reasons``, and ``voi_dropped``.
    """
    out: List[Dict[str, Any]] = []
    for a in actions or []:
        b = score_action(
            action       = a,
            intel        = intel,
            win_snapshot = win_snapshot,
            used_tools   = used_tools,
            failed_pairs = failed_pairs,
            mission_brief= mission_brief,
        )
        out.append({
            **a,
            "voi_score":   b.score,
            "voi_factors": b.factors,
            "voi_reasons": b.reasons,
            "voi_dropped": b.dropped,
        })
    # Sort: dropped to the back, then score desc, then confidence desc
    out.sort(key=lambda x: (
        x.get("voi_dropped", False),
        -int(x.get("voi_score", 0)),
        -float(x.get("confidence", 0.0) or 0.0),
    ))
    return out
