"""Per-session noise budget (Improvement #11).

Real engagements often have stealth constraints — every aggressive scan,
brute-force, or loud exploit raises the chance of detection.  Without a
budget, the agent will keep firing nmap-vuln-scripts and hydra brute
forces until the deadline, even when 80% of the engagement could be
solved with surgical, low-noise actions.

This module models that constraint as a simple session-scoped credit
system:

* Each action has a *noise cost* (look-up table by tool + heuristics over
  args).  Costs are normalised to roughly "events likely to fire on a
  defender's SIEM."
* :class:`NoiseBudget` tracks remaining credits, refuses actions that
  would overspend (so the planner picks something quieter), and emits
  status updates each time credits are consumed.
* Operators tune the budget per session (default 1000 = "moderate-noise
  authorised pentest").  Stealth red-team engagements should set ~250.

The check is intentionally **soft** — actions over budget are not killed,
they're *skipped* by the decision engine via a candidate-filter callback.
The agent then falls through to the next-best option.  Critical / high
confidence actions can still be confirmed by the operator if needed.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


__all__ = [
    "NoiseBudget", "score_action_noise", "DEFAULT_BUDGET",
    "STEALTH_BUDGET", "AGGRESSIVE_BUDGET",
]


DEFAULT_BUDGET    = 1000     # moderate authorised pentest
STEALTH_BUDGET    = 250      # red-team / live engagement
AGGRESSIVE_BUDGET = 5000     # CTF / lab — basically no limit


# ── Tool noise cost table ─────────────────────────────────────────────────
# Numbers are deliberately coarse — we only need enough fidelity to
# distinguish "passive" from "loud".  When in doubt, default to 5.
_TOOL_COST: Dict[str, int] = {
    # Passive / OSINT (≤2)
    "whois":        1,
    "dnsrecon":     2,
    "dig":          1,
    "host":         1,
    "amass":        2,
    "sublist3r":    2,
    "theharvester": 2,
    "shodan":       1,
    "wafw00f":      2,
    "whatweb":      3,
    "curl":         2,
    "wget":         2,
    "httpx":        3,
    # Light-touch service probes (3–8)
    "nmap":         8,    # bumped per-args below
    "smbmap":       5,
    "snmpwalk":     5,
    "onesixtyone":  4,
    "fping":        2,
    "ssh":          3,
    "openssl":      2,
    # Aggressive scanners (15–40)
    "masscan":      40,
    "rustscan":     25,
    "nikto":        20,
    "gobuster":     15,
    "ffuf":         15,
    "feroxbuster":  18,
    "dirb":         20,
    "wfuzz":        18,
    "wpscan":       15,
    "joomscan":     15,
    "droopescan":   15,
    "nuclei":       12,
    # Brute force / cred attacks (40–80)
    "hydra":        80,
    "medusa":       80,
    "patator":      75,
    "crackmapexec": 30,    # auth attempts are noisy but signal-rich
    "evil-winrm":   15,
    # Exploit frameworks (10–30)
    "msfconsole":   25,
    "msfvenom":     5,     # builds payload — local
    "metasploit":   25,
    "searchsploit": 1,
    # Web exploitation (40–60)
    "sqlmap":       60,
    "xsstrike":     25,
    "dalfox":       30,
    "commix":       40,
    # Local / postex (low-touch on attacker box)
    "linpeas":      4,     # only shells output back
    "winpeas":      4,
    "bloodhound-python": 25,
    "kerbrute":     30,
    "impacket-getuserspns": 8,
    "impacket-getnpusers":  8,
    "impacket-secretsdump": 6,
    "impacket-psexec":      12,
    "impacket-mssqlclient": 4,
    "responder":    40,
    "mitm6":        50,
    # Local helpers
    "bash":         1, "sh": 1, "cmd": 1, "powershell": 2,
    "python":       1, "python3": 1,
    "echo":         0, "cat": 0, "ls": 0,
}

# Argument flags that turbo-charge noise on top of the base cost
_NOISE_FLAGS: List[Tuple[re.Pattern, int]] = [
    (re.compile(r"-(?:T5|--min-rate\s*\d{4,})", re.IGNORECASE), 15),
    (re.compile(r"--script\s+vuln", re.IGNORECASE),              10),
    (re.compile(r"-A\b"),                                        8),
    (re.compile(r"-O\b"),                                        4),
    (re.compile(r"-p-"),                                         5),
    (re.compile(r"-sU\b"),                                       6),
    (re.compile(r"-(?:level|risk)\s*[3-9]", re.IGNORECASE),      10),
    (re.compile(r"--threads?\s*\d{3,}", re.IGNORECASE),          8),
    (re.compile(r"-r\s*\d{4,}", re.IGNORECASE),                  10),  # masscan rate
    (re.compile(r"--all|--full|--complete", re.IGNORECASE),      5),
]


def score_action_noise(action: Any) -> int:
    """Estimate the noise cost of a single action.

    Accepts either a ``JustifiedAction`` (with ``tool`` and ``args``
    attributes) or a plain dict ``{"tool": ..., "args": ...}``.
    """
    if action is None:
        return 1
    if isinstance(action, dict):
        tool = (action.get("tool") or "").strip().lower()
        args = str(action.get("args") or "")
    else:
        tool = (getattr(action, "tool", "") or "").strip().lower()
        args = str(getattr(action, "args", "") or "")

    base = _TOOL_COST.get(tool, 5)
    bonus = 0
    for pat, extra in _NOISE_FLAGS:
        if pat.search(args):
            bonus += extra
    return max(0, base + bonus)


# ── Budget object ─────────────────────────────────────────────────────────

@dataclass
class _ConsumeEntry:
    ts:    str
    tool:  str
    cost:  int
    after: int   # remaining after this consumption
    note:  str = ""


class NoiseBudget:
    """Session-scoped noise credit tracker."""

    WARN_PCT     = 0.25     # warn when ≤25% remaining
    EXCEEDED_PCT = 0.0

    def __init__(self, total: int = DEFAULT_BUDGET, *,
                 session_id: Optional[str] = None,
                 mode: str = "default") -> None:
        self.total       = max(1, int(total))
        self.remaining   = self.total
        self.session_id  = session_id
        self.mode        = mode
        self._history: List[_ConsumeEntry] = []
        self._lock        = Lock()
        self.created_at   = datetime.now(timezone.utc).isoformat()

    # ── Predicates ────────────────────────────────────────────────────
    def status(self) -> str:
        pct = self.remaining / self.total
        if pct <= self.EXCEEDED_PCT:
            return "exceeded"
        if pct <= self.WARN_PCT:
            return "warning"
        return "ok"

    def would_exceed(self, action: Any) -> bool:
        cost = score_action_noise(action)
        return cost > self.remaining

    def cost_of(self, action: Any) -> int:
        return score_action_noise(action)

    # ── Mutation ──────────────────────────────────────────────────────
    def consume(self, action: Any, *, note: str = "") -> int:
        """Deduct the cost; clamps at 0.  Returns the cost actually deducted."""
        cost = score_action_noise(action)
        with self._lock:
            taken = min(cost, self.remaining)
            self.remaining -= taken
            tool = (action.get("tool") if isinstance(action, dict)
                    else getattr(action, "tool", "")) or "?"
            self._history.append(_ConsumeEntry(
                ts    = datetime.now(timezone.utc).isoformat(),
                tool  = str(tool),
                cost  = cost,
                after = self.remaining,
                note  = note,
            ))
        return taken

    def refund(self, action: Any, *, fraction: float = 1.0, note: str = "") -> int:
        """B-7 — Return budget for an action that failed before producing
        meaningful traffic.

        Without this method, ``consume()`` charges the full cost on
        dispatch even when the tool errors out before sending any packets
        (MCP "unknown tool", auth-fail before second handshake, instant
        timeout).  Over a long session those phantom charges exhaust the
        budget and block productive actions.

        ``fraction`` lets callers tune partial refunds — e.g. an auth
        failure that DID send the auth packet but no follow-up should
        refund maybe 0.5 of the cost.  Default 1.0 = full refund for
        actions that produced no observable traffic.

        Returns the credits actually restored (capped so total never
        exceeds the budget).
        """
        cost = int(round(score_action_noise(action) * max(0.0, min(1.0, fraction))))
        if cost <= 0:
            return 0
        with self._lock:
            new_remaining = min(self.total, self.remaining + cost)
            actually_returned = new_remaining - self.remaining
            self.remaining = new_remaining
            tool = (action.get("tool") if isinstance(action, dict)
                    else getattr(action, "tool", "")) or "?"
            self._history.append(_ConsumeEntry(
                ts    = datetime.now(timezone.utc).isoformat(),
                tool  = str(tool),
                cost  = -actually_returned,   # negative = refund
                after = self.remaining,
                note  = (note or "refund") + (f" frac={fraction}" if fraction != 1.0 else ""),
            ))
        return actually_returned

    def reset(self, total: Optional[int] = None) -> None:
        with self._lock:
            if total is not None:
                self.total = max(1, int(total))
            self.remaining = self.total
            self._history.clear()

    def adjust(self, delta: int) -> None:
        """Operator-driven adjustment (positive = grant more credits)."""
        with self._lock:
            self.total = max(1, self.total + int(delta))
            self.remaining = max(0, self.remaining + int(delta))

    # ── Reporting ─────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        used = self.total - self.remaining
        recent = [
            {"ts": e.ts, "tool": e.tool, "cost": e.cost,
             "after": e.after, "note": e.note}
            for e in self._history[-10:]
        ]
        return {
            "session_id":  self.session_id,
            "mode":        self.mode,
            "total":       self.total,
            "used":        used,
            "remaining":   self.remaining,
            "pct_used":    round(used / self.total, 4),
            "status":      self.status(),
            "recent":      recent,
            "created_at":  self.created_at,
        }

    def render_for_prompt(self) -> str:
        used = self.total - self.remaining
        bar_len = 20
        filled = int(round(bar_len * used / self.total))
        bar = "█" * filled + "·" * (bar_len - filled)
        warn = "  ⚠ near limit — prefer quieter tools" if self.status() == "warning" else (
               "  🛑 budget exhausted — only operator-confirmed actions" if self.status() == "exceeded" else "")
        return (f"=== NOISE BUDGET ({self.mode}) ===\n"
                f"  used {used}/{self.total}  remaining={self.remaining}  "
                f"[{bar}]  status={self.status()}{warn}\n"
                f"  Avoid loud tools (masscan, hydra, sqlmap, --script vuln, -T5) "
                f"unless the remaining budget covers their cost.")


def budget_from_mode(mode: str, *, session_id: Optional[str] = None) -> NoiseBudget:
    """Build a NoiseBudget from a named mode string."""
    m = (mode or "").strip().lower()
    if m in ("stealth", "redteam", "red-team", "quiet"):
        return NoiseBudget(STEALTH_BUDGET, session_id=session_id, mode="stealth")
    if m in ("aggressive", "ctf", "lab", "loud"):
        return NoiseBudget(AGGRESSIVE_BUDGET, session_id=session_id, mode="aggressive")
    return NoiseBudget(DEFAULT_BUDGET, session_id=session_id, mode="default")


def parse_mode_from_text(text: str) -> str:
    """Extract a noise mode hint from operator notes / scope text."""
    if not text:
        return "default"
    low = text.lower()
    if any(k in low for k in ("stealth", "red team", "red-team", "low noise", "quiet")):
        return "stealth"
    if any(k in low for k in ("aggressive", "loud", "ctf", "lab")):
        return "aggressive"
    return "default"
