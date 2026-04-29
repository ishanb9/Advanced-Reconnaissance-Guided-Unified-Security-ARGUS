"""Self-critique gates before exploitation (Improvement #15).

A weakness of LLM-driven decision loops is plan over-confidence: the
model proposes an exploit, the decision engine ranks it highly, and the
loop fires it without ever asking "what if I'm wrong?"  When the cost
is a noisy nmap, that is fine.  When the cost is firing EternalBlue at
a Windows 11 target, or running ``hydra`` against a service that locks
out after three attempts, it is not.

The Self-Critique gate runs immediately before a *high-stakes* action
executes (risky / destructive tier per :mod:`dry_run`).  It performs a
structured **pre-mortem**:

* **Preconditions** — does the intel actually contain what the exploit
  assumes?  E.g. an SMB exploit on 445 requires ``services[445]`` to
  exist and look like SMB; a Linux SUID escalation requires
  ``os_guess`` to be Linux-ish.
* **Negative-memory** — has this same (tool, args, target_service) been
  tried before and failed?  If so, the action is a near-certain repeat
  failure.
* **Confidence threshold** — risky tier needs hypothesis confidence
  ≥ 0.5; destructive tier needs ≥ 0.7.  Below threshold the loop is
  asking us to bet the engagement on a weak guess.
* **Scope check** — engagement context's ``scope_hosts`` (when set)
  must include the target.
* **Defensive-posture compatibility** — if an EDR is fingerprinted
  (#12) and the chosen tool is in the *loud* set (msfconsole exploit/,
  hydra, masscan), surface the conflict and request review.

The gate emits one of three recommendations:

* ``"proceed"``  — no concerns; the loop fires the action.
* ``"hold"``    — soft concerns; the action is gated and routed
                  through the existing requires_confirmation path.
* ``"abort"``   — at least one hard blocker; the action is dropped
                  and recorded in negative memory.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


__all__ = ["Critique", "critique_action", "render_critique_for_prompt"]


# ── Confidence thresholds ──────────────────────────────────────────────
# tier → minimum hypothesis confidence the action is allowed to carry.
_TIER_MIN_CONFIDENCE = {
    "destructive": 0.70,
    "risky":       0.50,
    "safe":        0.0,
}

_LOUD_TOOL_RE = re.compile(
    r"^(?:masscan|rustscan|hydra|medusa|patator|nikto|sqlmap|"
    r"msfconsole|metasploit|responder|mitm6|gobuster|ffuf|feroxbuster)\b",
    re.I,
)


# ── Verdict object ─────────────────────────────────────────────────────

@dataclass
class Critique:
    recommendation: str = "proceed"     # "proceed" | "hold" | "abort"
    blockers:      List[str] = field(default_factory=list)
    concerns:      List[str] = field(default_factory=list)
    assumptions:   List[str] = field(default_factory=list)
    confidence_after: float = 1.0       # plan confidence after critique
    reason:        str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation":   self.recommendation,
            "blockers":         list(self.blockers[:5]),
            "concerns":         list(self.concerns[:5]),
            "assumptions":      list(self.assumptions[:5]),
            "confidence_after": round(self.confidence_after, 3),
            "reason":           self.reason,
        }


# ── Helpers ─────────────────────────────────────────────────────────────

def _action_fields(action: Any) -> Tuple[str, str, str, float, str]:
    if action is None:
        return "", "", "", 0.0, ""
    if isinstance(action, dict):
        return (str(action.get("tool") or "").strip().lower(),
                str(action.get("args") or ""),
                str(action.get("target_service") or ""),
                float(action.get("confidence") or 0.0),
                str(action.get("hypothesis_id") or ""))
    return (str(getattr(action, "tool", "") or "").strip().lower(),
            str(getattr(action, "args", "") or ""),
            str(getattr(action, "target_service", "") or ""),
            float(getattr(action, "confidence", 0.0) or 0.0),
            str(getattr(action, "hypothesis_id", "") or ""))


def _hypothesis_fields(hypothesis: Any) -> Tuple[str, str, float, str]:
    if hypothesis is None:
        return "", "", 0.0, ""
    if isinstance(hypothesis, dict):
        return (str(hypothesis.get("statement") or ""),
                str(hypothesis.get("mitre_technique") or ""),
                float(hypothesis.get("confidence") or 0.0),
                str(hypothesis.get("attack_phase") or ""))
    return (str(getattr(hypothesis, "statement", "") or ""),
            str(getattr(hypothesis, "mitre_technique", "") or ""),
            float(getattr(hypothesis, "confidence", 0.0) or 0.0),
            str(getattr(hypothesis, "attack_phase", "") or ""))


# Map MITRE families / statement keywords to required intel preconditions.
# (callable that takes intel and returns (ok, reason)).
def _check_smb_preconds(intel: Dict[str, Any]) -> Tuple[bool, str]:
    ports = intel.get("open_ports") or []
    has_445 = any(str(p).split("/")[0] == "445" for p in ports if p)
    if not has_445:
        return False, "no port 445 in open_ports"
    services = intel.get("services") or {}
    smb_seen = any("smb" in str(v).lower() or "microsoft-ds" in str(v).lower()
                   for v in services.values())
    if not smb_seen:
        return False, "port 445 open but no SMB banner"
    return True, ""


def _check_linux_local_preconds(intel: Dict[str, Any]) -> Tuple[bool, str]:
    os_guess = str(intel.get("os_guess") or "").lower()
    if os_guess and not any(k in os_guess for k in ("linux", "unix", "ubuntu",
                                                      "debian", "centos",
                                                      "alpine", "redhat",
                                                      "fedora")):
        return False, f"os_guess='{os_guess}' is not Linux-ish"
    if not intel.get("shell_access"):
        return False, "no shell_access — can't run local privesc"
    return True, ""


def _check_windows_preconds(intel: Dict[str, Any]) -> Tuple[bool, str]:
    os_guess = str(intel.get("os_guess") or "").lower()
    if os_guess and not any(k in os_guess for k in ("windows", "microsoft",
                                                      "win32", "win64")):
        return False, f"os_guess='{os_guess}' is not Windows"
    return True, ""


def _check_web_preconds(intel: Dict[str, Any]) -> Tuple[bool, str]:
    web_ports = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9090, 9443}
    ports = intel.get("open_ports") or []
    found = any(int(str(p).split("/")[0]) in web_ports
                for p in ports if str(p).split("/")[0].isdigit())
    if not found:
        return False, "no web port (80/443/8080/…) in open_ports"
    return True, ""


# Match against (mitre prefix, tool prefix) → preconditions list.
_PRECONDITION_RULES: List[Tuple[Tuple[str, str], List]] = [
    # SMB / EternalBlue family
    (("T1210", ""),                    [("SMB v1 service on 445", _check_smb_preconds)]),
    (("",      "smbclient"),           [("SMB v1 service on 445", _check_smb_preconds)]),
    (("",      "smbmap"),              [("SMB v1 service on 445", _check_smb_preconds)]),
    (("",      "crackmapexec"),        [("SMB v1 service on 445", _check_smb_preconds)]),
    (("",      "evil-winrm"),          [("Windows target",         _check_windows_preconds)]),
    # Linux post-exploit
    (("T1548", ""),                    [("Linux shell available",  _check_linux_local_preconds)]),
    (("T1068", ""),                    [("Linux shell available",  _check_linux_local_preconds)]),
    (("",      "linpeas"),             [("Linux shell available",  _check_linux_local_preconds)]),
    # Web / app
    (("T1190", ""),                    [("web port reachable",     _check_web_preconds)]),
    (("",      "sqlmap"),              [("web port reachable",     _check_web_preconds)]),
    (("",      "nikto"),               [("web port reachable",     _check_web_preconds)]),
    (("",      "wpscan"),              [("web port reachable",     _check_web_preconds)]),
    (("",      "gobuster"),            [("web port reachable",     _check_web_preconds)]),
    (("",      "ffuf"),                [("web port reachable",     _check_web_preconds)]),
    (("",      "feroxbuster"),         [("web port reachable",     _check_web_preconds)]),
]


def _gather_preconditions(tool: str, mitre: str,
                          intel: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Return (failed_preconditions, satisfied_preconditions)."""
    failed:    List[str] = []
    satisfied: List[str] = []
    seen_labels: set = set()
    mitre_up = (mitre or "").upper().split(".")[0]
    tool_low = (tool or "").lower()
    for (mt_prefix, tool_prefix), checks in _PRECONDITION_RULES:
        if mt_prefix and not mitre_up.startswith(mt_prefix):
            continue
        if tool_prefix and not tool_low.startswith(tool_prefix):
            continue
        if not (mt_prefix or tool_prefix):
            continue
        for label, fn in checks:
            if label in seen_labels:
                continue
            seen_labels.add(label)
            try:
                ok, reason = fn(intel)
            except Exception:
                ok, reason = True, ""
            if ok:
                satisfied.append(label)
            else:
                failed.append(f"{label}: {reason}")
    return failed, satisfied


def _check_negative_memory(neg_memory: Any, tool: str, args: str,
                           target_service: str) -> Optional[Dict[str, Any]]:
    """Look for prior failed attempts matching tool+args+service."""
    if neg_memory is None:
        return None

    # Try the to_dict_list interface first (matches the existing
    # NegativeMemory class).
    records: List[Dict[str, Any]] = []
    try:
        if hasattr(neg_memory, "to_dict_list"):
            records = neg_memory.to_dict_list() or []
        elif isinstance(neg_memory, list):
            records = neg_memory
    except Exception:
        return None

    if not records:
        return None

    target_norm = (target_service or "").strip().lower()
    args_norm   = (args or "").strip().lower()
    for r in records:
        if not isinstance(r, dict):
            continue
        if str(r.get("tool", "")).strip().lower() != tool.strip().lower():
            continue
        prior_service = str(r.get("target_service", "")).strip().lower()
        if target_norm and prior_service and prior_service != target_norm:
            continue
        prior_args = str(r.get("args", "")).strip().lower()
        if args_norm and prior_args and prior_args != args_norm:
            # Allow loose match: same tool, same target, even if args differ
            # is still a soft warning, just not a hard block.
            continue
        return r
    return None


# ── Public API ─────────────────────────────────────────────────────────

def critique_action(
    action: Any,
    *, hypothesis: Any = None,
    intel:        Optional[Dict[str, Any]] = None,
    tier:         str = "risky",
    neg_memory:   Any = None,
    posture:      Optional[Dict[str, Any]] = None,
    scope_hosts:  Optional[List[str]] = None,
    target:       str = "",
) -> Critique:
    """Run the structured pre-mortem and return a :class:`Critique`."""
    intel = intel or {}
    tool, args, target_service, action_conf, _hyp_id = _action_fields(action)
    statement, mitre, hyp_conf, phase = _hypothesis_fields(hypothesis)

    crit = Critique()
    base_conf = max(action_conf, hyp_conf)
    crit.confidence_after = base_conf

    # ── 1. Preconditions ──────────────────────────────────────────────
    failed_pre, satisfied_pre = _gather_preconditions(tool, mitre, intel)
    crit.assumptions.extend(satisfied_pre)
    if failed_pre:
        # Failed preconditions are blockers for risky/destructive tiers
        for f in failed_pre:
            crit.blockers.append(f"precondition failed — {f}")

    # ── 2. Negative memory ────────────────────────────────────────────
    prior = _check_negative_memory(neg_memory, tool, args, target_service)
    if prior is not None:
        reason_prev = str(prior.get("failure_reason") or "(no reason)")[:140]
        crit.blockers.append(
            f"prior failure on identical (tool,args,service): {reason_prev}"
        )

    # ── 3. Confidence threshold ───────────────────────────────────────
    min_conf = _TIER_MIN_CONFIDENCE.get(tier, 0.0)
    if base_conf < min_conf:
        crit.concerns.append(
            f"confidence {base_conf:.2f} below {tier}-tier threshold {min_conf:.2f}"
        )
        # Hard block for destructive tier; soft hold for risky.
        if tier == "destructive":
            crit.blockers.append("destructive action with sub-threshold confidence")

    # ── 4. Scope check ────────────────────────────────────────────────
    if scope_hosts:
        scope_norm = {str(h).strip().lower() for h in scope_hosts if h}
        target_norm = (target or "").strip().lower()
        if target_norm and scope_norm and target_norm not in scope_norm:
            crit.blockers.append(
                f"target '{target}' not in scope_hosts {sorted(scope_norm)[:3]}"
            )

    # ── 5. Defensive-posture compatibility ────────────────────────────
    if posture and posture.get("products"):
        prods = posture.get("products") or {}
        edr_seen  = bool(prods.get("edr"))
        siem_seen = bool(prods.get("siem"))
        loud      = bool(_LOUD_TOOL_RE.match(tool))
        if (edr_seen or siem_seen) and loud:
            crit.concerns.append(
                f"loud tool '{tool}' against {'EDR' if edr_seen else 'SIEM'}-monitored host "
                f"({', '.join((prods.get('edr') or prods.get('siem') or [])[:2])})"
            )

    # ── 6. Compose recommendation ─────────────────────────────────────
    if crit.blockers:
        crit.recommendation = "abort"
        crit.confidence_after = 0.0
        crit.reason = (
            f"{len(crit.blockers)} blocker(s): "
            + "; ".join(crit.blockers[:2])
        )
    elif crit.concerns:
        crit.recommendation = "hold"
        crit.confidence_after = max(0.0, base_conf - 0.15 * len(crit.concerns))
        crit.reason = (
            f"{len(crit.concerns)} concern(s) — operator review recommended: "
            + "; ".join(crit.concerns[:2])
        )
    else:
        crit.recommendation = "proceed"
        crit.reason = "no concerns surfaced by pre-mortem checks"

    return crit


def render_critique_for_prompt(crit: Optional[Dict[str, Any]]) -> str:
    """Compact LLM-prompt rendering of the most-recent critique."""
    if not crit or not isinstance(crit, dict):
        return ""
    rec = crit.get("recommendation", "?")
    icon = {"abort": "🛑", "hold": "⚠", "proceed": "✓"}.get(rec, "?")
    lines = [f"--- Last self-critique ({icon} {rec}) ---"]
    if crit.get("blockers"):
        lines.append(f"  blockers : {' | '.join(crit['blockers'][:3])}")
    if crit.get("concerns"):
        lines.append(f"  concerns : {' | '.join(crit['concerns'][:3])}")
    if crit.get("assumptions"):
        lines.append(f"  satisfied: {', '.join(crit['assumptions'][:3])}")
    if crit.get("reason"):
        lines.append(f"  reason   : {str(crit['reason'])[:200]}")
    lines.append("---")
    return "\n".join(lines)
