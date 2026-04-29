"""Dry-run mode for destructive operations (Improvement #13).

The reasoning loop happily executes whatever the decision engine selects.
That is fine for nmap and whatweb.  It is *not* fine when an action would
reach into the target and irreversibly alter state — drop a database,
delete a file, install persistence, push a payload, or run an exploit
that crashes the service.

This module provides a soft gate that:

1. Classifies an action as destructive / risky / safe via tool+args
   heuristics (regex over the args, plus a tool-tier table).
2. For destructive actions, builds a *preview* dict — what would happen,
   why we think it's destructive, suggested safer probe.
3. The reasoning loop, when ``master.dry_run_mode`` is on, emits a
   ``dry_run_preview`` event, records a "skipped pending review"
   negative-memory entry, and continues without firing the action.
4. Operators can either confirm via the existing
   ``requires_confirmation`` path (already plumbed in #11) or flip
   ``dry_run_mode`` off entirely in the UI.

The classifier is deliberately conservative — false positives just
delay loud actions; false negatives let irreversible commands fly.  We
err toward gating.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


__all__ = [
    "DryRunVerdict", "classify_action", "build_preview", "is_destructive",
    "default_mode_for_engagement", "DESTRUCTIVE_TOOLS", "RISKY_TOOLS",
]


# ── Risk tiers ──────────────────────────────────────────────────────────
# DESTRUCTIVE  — an irreversible side-effect on the target box.
# RISKY        — exploit / payload delivery / DoS-adjacent — should
#                preview before firing on production engagements.
# SAFE         — read-only / passive / reconnaissance.

DESTRUCTIVE_TOOLS = {
    # File / disk
    "rm", "rmdir", "unlink", "shred", "dd", "mkfs", "format", "fdisk",
    "diskpart", "wipe", "srm",
    # Privileged Windows
    "cipher", "vssadmin", "wevtutil", "wmic", "schtasks", "reg",
    # Persistence / cleanup
    "crontab", "systemctl", "service", "launchctl",
}

RISKY_TOOLS = {
    # Exploit frameworks (payload delivery)
    "msfconsole", "msfvenom", "metasploit",
    # Active web exploitation
    "sqlmap", "commix", "xsstrike", "dalfox",
    # Brute force (lockout risk)
    "hydra", "medusa", "patator", "kerbrute",
    # Lateral / cred dumping
    "impacket-secretsdump", "impacket-psexec", "impacket-smbexec",
    "crackmapexec", "evil-winrm", "responder", "mitm6",
    # Aggressive scanners that can crash fragile services
    "masscan", "rustscan",
}


# Argument patterns that turn an otherwise-benign tool destructive.
# Each entry: (regex, reason, tier)
_ARG_RULES: List[Tuple[re.Pattern, str, str]] = [
    # Shell deletion
    (re.compile(r"\brm\s+(?:-[rRfF]+\s+)*\S*/", re.I),
     "rm -rf style file deletion", "destructive"),
    (re.compile(r"\bshred\b|\bsrm\b|\bwipe\b", re.I),
     "secure-delete utility", "destructive"),
    (re.compile(r"\bdd\s+if=.*\bof=/dev/", re.I),
     "dd writing directly to a block device", "destructive"),
    (re.compile(r"\bmkfs\.|\bformat\b", re.I),
     "filesystem format / reformat", "destructive"),
    (re.compile(r"\b(?:reg|wmic)\s+(?:delete|remove)\b", re.I),
     "Windows registry/WMI deletion", "destructive"),
    (re.compile(r"\bvssadmin\s+delete\s+shadows\b", re.I),
     "shadow-copy deletion (ransomware-class)", "destructive"),
    (re.compile(r"\bwevtutil\s+(?:cl|clear-log)\b", re.I),
     "Windows event-log clearing (anti-forensics)", "destructive"),
    (re.compile(r"\bcipher\s+/w:", re.I),
     "cipher /w: free-space wipe", "destructive"),
    (re.compile(r"\bschtasks\s+/(?:delete|change)\b", re.I),
     "scheduled-task delete/modify", "destructive"),
    (re.compile(r"\bcrontab\s+-r\b", re.I),
     "crontab -r removes user crontab", "destructive"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.I),
     "fork bomb", "destructive"),

    # SQL destructive verbs
    (re.compile(r"\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM)\b", re.I),
     "destructive SQL statement", "destructive"),
    (re.compile(r"--os-shell|--os-pwn|--file-write|--sql-shell", re.I),
     "sqlmap shell / file-write payload", "risky"),
    (re.compile(r"--dump-all|--all\b", re.I),
     "sqlmap full dump (high data exfil)", "risky"),

    # Metasploit / msfvenom payloads
    (re.compile(r"\bexploit/(?:windows|linux|unix|multi)/", re.I),
     "msf exploit module — delivers payload", "risky"),
    (re.compile(r"\b(?:meterpreter|reverse_tcp|bind_tcp|reverse_https)\b", re.I),
     "shellcode payload", "risky"),

    # nmap NSE that crash services
    (re.compile(r"--script\s+(?:.*[,/])?(?:dos|brute|exploit)\b", re.I),
     "nmap dos/brute/exploit NSE family", "risky"),

    # Hydra / Medusa lockout-class
    (re.compile(r"\bhydra\s+", re.I),
     "credential brute-force (account lockout risk)", "risky"),

    # Responder poisoning
    (re.compile(r"\bresponder\b|\bmitm6\b", re.I),
     "LLMNR/NBT-NS or DHCPv6 poisoning", "risky"),

    # Live exploit code
    (re.compile(r"\bsearchsploit\s+-x\b|\bexploit-db\b", re.I),
     "fetching ready-to-run exploit code", "risky"),
]


# Tools that already have a built-in dry-run flag — preserve the user's
# args but suggest the safer variant.
_DRY_RUN_FLAGS: Dict[str, str] = {
    "rsync":      "--dry-run",
    "make":       "-n",
    "ansible":    "--check",
    "terraform":  "plan",
    "kubectl":    "--dry-run=client",
    "helm":       "--dry-run",
    "git":        "--dry-run",
    "apt":        "--simulate",
    "apt-get":    "--simulate",
    "yum":        "--assumeno",
    "dnf":        "--assumeno",
}


# Suggest a safer probe for the most common destructive families.
_SAFER_PROBE: Dict[str, str] = {
    "rm":           "ls -la <path>   # confirm contents before deletion",
    "shred":        "stat <file>     # verify path before secure-erase",
    "dd":           "lsblk           # confirm device map before dd",
    "mkfs":         "blkid           # confirm partition before format",
    "vssadmin":     "vssadmin list shadows   # enumerate before deletion",
    "wevtutil":     "wevtutil el     # list logs before clearing",
    "crontab":      "crontab -l      # list cron entries before -r",
    "schtasks":     "schtasks /query # enumerate before /delete",
    "msfconsole":   "info <module>; check; show options   # validate target before exploit",
    "msfvenom":     "msfvenom -l payloads | grep <plat>   # list payloads only",
    "sqlmap":       "sqlmap -u <url> --batch --current-db   # enumerate, no dump",
    "hydra":        "hydra -L users.txt -p <single-pass>  # 1 attempt per user, watch for lockout",
    "responder":    "responder -A    # analyze mode (no poisoning)",
}


# ── Verdict object ──────────────────────────────────────────────────────

@dataclass
class DryRunVerdict:
    tier:        str = "safe"          # "safe" | "risky" | "destructive"
    reasons:     List[str] = field(default_factory=list)
    suggestion:  str = ""
    safer_probe: str = ""
    preview_cmd: str = ""               # the *would-be* full command line

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier":        self.tier,
            "reasons":     list(self.reasons),
            "suggestion":  self.suggestion,
            "safer_probe": self.safer_probe,
            "preview_cmd": self.preview_cmd,
        }


# ── Public helpers ──────────────────────────────────────────────────────

def _action_fields(action: Any) -> Tuple[str, str]:
    if action is None:
        return "", ""
    if isinstance(action, dict):
        return (str(action.get("tool") or "").strip().lower(),
                str(action.get("args") or ""))
    return (str(getattr(action, "tool", "") or "").strip().lower(),
            str(getattr(action, "args", "") or ""))


def classify_action(action: Any) -> DryRunVerdict:
    """Return a :class:`DryRunVerdict` describing the risk tier."""
    tool, args = _action_fields(action)
    verdict = DryRunVerdict(preview_cmd=f"{tool} {args}".strip())

    if not tool:
        return verdict

    # 1. Tool-tier table.
    if tool in DESTRUCTIVE_TOOLS:
        verdict.tier = "destructive"
        verdict.reasons.append(f"tool '{tool}' is in DESTRUCTIVE_TOOLS")
    elif tool in RISKY_TOOLS:
        verdict.tier = "risky"
        verdict.reasons.append(f"tool '{tool}' is in RISKY_TOOLS")

    # 2. Argument-pattern escalation.
    blob = f"{tool} {args}"
    for pat, reason, tier in _ARG_RULES:
        if pat.search(blob):
            verdict.reasons.append(reason)
            # Escalate: destructive > risky > safe
            if tier == "destructive":
                verdict.tier = "destructive"
            elif tier == "risky" and verdict.tier == "safe":
                verdict.tier = "risky"

    # 3. Suggestions.
    if verdict.tier in ("destructive", "risky"):
        verdict.safer_probe = _SAFER_PROBE.get(tool, "")
        if tool in _DRY_RUN_FLAGS:
            verdict.suggestion = (
                f"re-run with built-in dry-run: {tool} {_DRY_RUN_FLAGS[tool]} {args}".strip()
            )
        elif verdict.tier == "destructive":
            verdict.suggestion = (
                "Operator review required before this action lands on the target."
            )
        else:
            verdict.suggestion = (
                "Risky action — confirm scope and lockout/availability impact "
                "before executing."
            )

    return verdict


def is_destructive(action: Any) -> bool:
    """True iff the action would cause an irreversible side effect."""
    return classify_action(action).tier == "destructive"


def build_preview(action: Any, *, session_id: str = "",
                  iteration: int = 0) -> Dict[str, Any]:
    """Produce a serialisable preview payload suitable for the WS feed."""
    tool, args = _action_fields(action)
    verdict = classify_action(action)
    return {
        "session_id":  session_id,
        "iteration":   iteration,
        "tool":        tool,
        "args":        args,
        "verdict":     verdict.to_dict(),
    }


def default_mode_for_engagement(engagement_type: str,
                                target_type: str = "",
                                notes: str = "",
                                scope: str = "") -> bool:
    """Pick a sensible default for ``MasterAgent.dry_run_mode``.

    * Production / red-team engagements → ON
    * CTF / lab / homelab               → OFF
    * Anything else                     → ON (fail safe)
    """
    blob = " ".join(filter(None, [engagement_type, target_type, notes, scope])).lower()
    if any(k in blob for k in ("ctf", "lab", "homelab", "hackthebox", "tryhackme",
                                "vulnhub", "training")):
        return False
    if any(k in blob for k in ("prod", "production", "live", "client",
                                "enterprise", "stealth", "red team", "red-team")):
        return True
    return True   # fail-safe default
