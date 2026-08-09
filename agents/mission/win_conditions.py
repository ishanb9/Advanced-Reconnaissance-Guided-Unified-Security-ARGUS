"""
win_conditions.py — Improvement #2: Win-condition tracker.

Each win condition is a short string token (e.g. ``"shell_obtained"``).  At any
time the tracker can evaluate every condition against the current intel snapshot
and report which are achieved, which are pending, and emit an aggregate
``progress_pct``.

Built-in conditions are pure ``intel -> bool`` predicates; operators may also
write boolean expressions over those tokens such as
``"user_flag_captured AND root_flag_captured"`` or
``"creds_captured AND (shell_obtained OR rce_confirmed)"``.

Boolean expressions are parsed with a tiny hand-rolled recursive-descent
parser so we never call ``eval()``.

The tracker has no I/O of its own — it returns plain dicts so the caller can
broadcast / persist as it sees fit.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Built-in condition predicates
# ─────────────────────────────────────────────────────────────────────────────

def _truthy_list(intel: Dict[str, Any], key: str) -> bool:
    v = intel.get(key) or []
    return bool(v) and len(v) > 0


def _shell_obtained(intel: Dict[str, Any]) -> bool:
    return bool(intel.get("shell_access")) or bool(intel.get("shell_id"))


def _user_flag_captured(intel: Dict[str, Any]) -> bool:
    return bool(intel.get("user_flag"))


def _root_flag_captured(intel: Dict[str, Any]) -> bool:
    return bool(intel.get("root_flag"))


def _any_flag_captured(intel: Dict[str, Any]) -> bool:
    return bool(intel.get("user_flag")) or bool(intel.get("root_flag"))


def _creds_captured(intel: Dict[str, Any]) -> bool:
    return _truthy_list(intel, "credentials")


def _rce_confirmed(intel: Dict[str, Any]) -> bool:
    """Heuristic — vulnerability or web-vuln tagged as RCE / code-exec."""
    for v in (intel.get("vulnerabilities") or []) + (intel.get("web_vulns") or []):
        if not isinstance(v, dict):
            continue
        title = (v.get("title") or v.get("name") or "").lower()
        if any(t in title for t in ("rce", "remote code", "code execution", "command injection")):
            return True
    return False


def _privilege_escalated(intel: Dict[str, Any]) -> bool:
    user = (intel.get("current_user") or "").lower()
    return user in {"root", "system", "administrator", "nt authority\\system"}


def _domain_admin(intel: Dict[str, Any]) -> bool:
    user = (intel.get("current_user") or "").lower()
    if "domain admin" in user or "domain_admin" in user:
        return True
    for c in (intel.get("credentials") or []):
        if not isinstance(c, dict):
            continue
        if "domain admin" in (c.get("privilege_level") or "").lower():
            return True
        if "domain admin" in (c.get("domain") or "").lower() and c.get("verified"):
            return True
    return False


def _lateral_movement(intel: Dict[str, Any]) -> bool:
    return _truthy_list(intel, "lateral_targets") or _truthy_list(intel, "pivot_paths")


def _persistence_established(intel: Dict[str, Any]) -> bool:
    for ev in (intel.get("evidence") or []):
        if isinstance(ev, dict) and "persist" in (ev.get("type") or "").lower():
            return True
    return False


def _data_exfiltrated(intel: Dict[str, Any]) -> bool:
    for ev in (intel.get("evidence") or []):
        if isinstance(ev, dict) and any(t in (ev.get("type") or "").lower()
                                        for t in ("exfil", "exfiltration", "loot")):
            return True
    return False


def _initial_access(intel: Dict[str, Any]) -> bool:
    return (
        _shell_obtained(intel)
        or _rce_confirmed(intel)
        or bool(intel.get("foothold"))
    )


def _validated_findings(intel: Dict[str, Any]) -> list:
    """Findings that passed the evidence gate.  A finding only counts when it is
    NOT explicitly rejected/unvalidated — the severity policy and issue validator own
    that verdict; we never re-grade here."""
    out = []
    for f in (intel.get("findings") or []):
        if not isinstance(f, dict):
            continue
        if f.get("rejected") or f.get("validated") is False:
            continue
        out.append(f)
    return out


_SEV_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3,
             "critical": 4}


def _vulnerabilities_confirmed(intel: Dict[str, Any]) -> bool:
    """At least one MEDIUM-or-above validated finding exists.

    This is the win condition a VULNERABILITY ASSESSMENT actually has.  Many
    engagements have no user/root flag at all — the deliverable is proven, evidence-
    backed vulnerabilities — and without this token that goal was inexpressible, so
    such an engagement could only ever be graded 'recon_only'."""
    for f in _validated_findings(intel):
        if _SEV_RANK.get(str(f.get("severity") or "").lower(), 0) >= 2:
            return True
    return bool(intel.get("vulnerabilities"))


def _exploit_verified(intel: Dict[str, Any]) -> bool:
    """A vulnerability was PROVEN exploitable with a captured artifact — short of (or
    without) taking a shell.  Covers assessments authorized to demonstrate impact."""
    if intel.get("rce_confirmed") or intel.get("exploited"):
        return True
    for f in _validated_findings(intel):
        blob = f"{f.get('title', '')} {f.get('description', '')}".lower()
        if f.get("exploit_verified") or f.get("reproduced"):
            return True
        if any(k in blob for k in ("verified exploit", "exploitation confirmed",
                                  "proof of concept confirmed")):
            return True
    return False


def _loot_collected(intel: Dict[str, Any]) -> bool:
    """Sensitive data was retrieved.  Reads intel['loot'] directly — the existing
    ``data_exfiltrated`` token only inspected intel['evidence'], so loot recorded in
    intel['loot'] (which is where the loot hunter writes it) satisfied nothing."""
    if intel.get("loot"):
        return True
    return _data_exfiltrated(intel)


def _access_demonstrated(intel: Dict[str, Any]) -> bool:
    """Any concrete access proof: a shell, RCE, harvested credentials, or loot.  The
    'we got in' condition for engagements that do not use flags."""
    return bool(_shell_obtained(intel) or _rce_confirmed(intel)
                or _creds_captured(intel) or _loot_collected(intel))


BUILTIN_EVALUATORS: Dict[str, Callable[[Dict[str, Any]], bool]] = {
    "shell_obtained":          _shell_obtained,
    "initial_access":          _initial_access,
    # ── Non-flag outcomes: not every engagement has a user/root flag ──────────
    "vulnerabilities_confirmed": _vulnerabilities_confirmed,
    "vulns_confirmed":         _vulnerabilities_confirmed,
    "exploit_verified":        _exploit_verified,
    "loot_collected":          _loot_collected,
    "access_demonstrated":     _access_demonstrated,
    "user_flag_captured":      _user_flag_captured,
    "root_flag_captured":      _root_flag_captured,
    "any_flag_captured":       _any_flag_captured,
    "creds_captured":          _creds_captured,
    "credentials_captured":    _creds_captured,
    "rce_confirmed":           _rce_confirmed,
    "privilege_escalated":     _privilege_escalated,
    "privesc":                 _privilege_escalated,
    "domain_admin":            _domain_admin,
    "lateral_movement":        _lateral_movement,
    "persistence_established": _persistence_established,
    "persistence":             _persistence_established,
    "data_exfiltrated":        _data_exfiltrated,
    "exfil":                   _data_exfiltrated,
}


# ─────────────────────────────────────────────────────────────────────────────
# Hand-rolled boolean expression parser
#
#   expr   := term   (OR term)*
#   term   := factor (AND factor)*
#   factor := NOT factor | '(' expr ')' | TOKEN
#
# Tokens are looked up in BUILTIN_EVALUATORS (case-insensitive).
# Unknown tokens evaluate to False and are reported in `unresolved`.
# No eval() — only structural parse + boolean ops.
# ─────────────────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z_][A-Za-z0-9_]*")
_OPS = {"AND", "OR", "NOT"}


# ─────────────────────────────────────────────────────────────────────────────
# Per-engagement-type win conditions
#
# The old single default ("shell_obtained", "user_flag_captured",
# "root_flag_captured") assumed every engagement is a flag hunt.  On an external
# vulnerability assessment root_flag_captured can never become true, so the mission
# was permanently incomplete and the compromise gate kept forcing exploitation the
# engagement may not even authorize.  Flags are now opt-in per engagement type.
# ─────────────────────────────────────────────────────────────────────────────
ENGAGEMENT_WIN_CONDITIONS: Dict[str, List[str]] = {
    # Flag-bearing: a lab/CTF box genuinely has user.txt / root.txt.
    "ctf":               ["user_flag_captured", "root_flag_captured", "shell_obtained"],
    "lab":               ["user_flag_captured", "root_flag_captured", "shell_obtained"],
    # Full-depth offensive engagements: access + impact, flags only if present.
    "red_team":          ["access_demonstrated", "privilege_escalated",
                          "lateral_movement", "loot_collected"],
    "pentest":           ["vulnerabilities_confirmed", "exploit_verified",
                          "access_demonstrated"],
    "bug_bounty":        ["vulnerabilities_confirmed", "exploit_verified"],
    # Assessment-only: NO exploitation authorized, so success is proven findings.
    "vuln_assessment":   ["vulnerabilities_confirmed"],
    "assessment":        ["vulnerabilities_confirmed"],
    "external":          ["vulnerabilities_confirmed", "exploit_verified"],
    # Data-focused engagements.
    "loot":              ["loot_collected", "access_demonstrated"],
    "exfil":             ["loot_collected", "data_exfiltrated"],
    # Non-offensive engagement types have no compromise goal at all.
    "forensics":         ["vulnerabilities_confirmed"],
    "network_analysis":  ["vulnerabilities_confirmed"],
    "compliance":        ["vulnerabilities_confirmed"],
}

DEFAULT_WIN_CONDITIONS: List[str] = ["vulnerabilities_confirmed", "exploit_verified",
                                     "access_demonstrated"]


def win_conditions_for(engagement_type: str = "",
                       objectives: Optional[List[str]] = None) -> List[str]:
    """The win conditions an engagement of this TYPE can actually satisfy.

    Explicit operator ``objectives`` always win.  Otherwise the engagement type
    selects a set; an unknown type falls back to the flag-free default rather than
    demanding a root flag that will never exist."""
    if objectives:
        clean = [str(o).strip() for o in objectives if str(o).strip()]
        if clean:
            return clean
    return list(ENGAGEMENT_WIN_CONDITIONS.get(
        (engagement_type or "").strip().lower(), DEFAULT_WIN_CONDITIONS))


def expects_flags(engagement_type: str = "",
                  win_conditions: Optional[List[str]] = None) -> bool:
    """True only when this engagement genuinely has flags to capture.  Callers use it
    to avoid reporting 'no flag captured' as a shortfall on an engagement that never
    had one."""
    conds = [str(c).lower() for c in (win_conditions
             or ENGAGEMENT_WIN_CONDITIONS.get((engagement_type or "").lower(), []))]
    return any("flag" in c for c in conds)


def _tokenise(expr: str) -> List[str]:
    out: List[str] = []
    for raw in _TOKEN_RE.findall(expr):
        upper = raw.upper()
        if upper in _OPS:
            out.append(upper)
        else:
            out.append(raw)
    return out


class _Parser:
    """Tiny recursive-descent parser for the boolean grammar above."""

    def __init__(self, tokens: List[str]):
        self.toks = tokens
        self.pos  = 0
        self.evaluated: Dict[str, bool] = {}
        self.unresolved: List[str] = []

    def _peek(self) -> Optional[str]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _eat(self) -> Optional[str]:
        tok = self._peek()
        self.pos += 1
        return tok

    def parse(self, intel: Dict[str, Any], evaluators: Dict[str, Callable]) -> bool:
        if not self.toks:
            return False
        result = self._expr(intel, evaluators)
        # Ignore trailing junk silently — best-effort
        return result

    # expr := term (OR term)*
    def _expr(self, intel: Dict[str, Any], evaluators: Dict[str, Callable]) -> bool:
        left = self._term(intel, evaluators)
        while self._peek() == "OR":
            self._eat()
            right = self._term(intel, evaluators)
            left  = left or right
        return left

    # term := factor (AND factor)*
    def _term(self, intel: Dict[str, Any], evaluators: Dict[str, Callable]) -> bool:
        left = self._factor(intel, evaluators)
        while self._peek() == "AND":
            self._eat()
            right = self._factor(intel, evaluators)
            left  = left and right
        return left

    # factor := NOT factor | '(' expr ')' | TOKEN
    def _factor(self, intel: Dict[str, Any], evaluators: Dict[str, Callable]) -> bool:
        tok = self._peek()
        if tok is None:
            return False
        if tok == "NOT":
            self._eat()
            return not self._factor(intel, evaluators)
        if tok == "(":
            self._eat()
            v = self._expr(intel, evaluators)
            if self._peek() == ")":
                self._eat()
            return v
        # Bare token
        self._eat()
        if tok in _OPS or tok in ("(", ")"):
            return False
        key = tok.lower()
        fn  = evaluators.get(key)
        if fn is None:
            self.unresolved.append(tok)
            self.evaluated[tok] = False
            return False
        try:
            val = bool(fn(intel))
        except Exception as exc:
            logger.warning("[win_conditions] evaluator %s failed: %s", key, exc)
            val = False
        self.evaluated[tok] = val
        return val


def evaluate_expression(
    expr:  str,
    intel: Dict[str, Any],
    extra_evaluators: Optional[Dict[str, Callable[[Dict[str, Any]], bool]]] = None,
) -> Dict[str, Any]:
    """Evaluate a boolean win-condition expression.

    Returns ``{result: bool, evaluated: {token: bool}, unresolved: [token, ...]}``.
    """
    if not expr or not expr.strip():
        return {"result": False, "evaluated": {}, "unresolved": []}

    evaluators = dict(BUILTIN_EVALUATORS)
    if extra_evaluators:
        evaluators.update({k.lower(): v for k, v in extra_evaluators.items()})

    parser = _Parser(_tokenise(expr))
    try:
        result = parser.parse(intel, evaluators)
    except Exception as exc:
        logger.warning("[win_conditions] parse failed: %s — expr=%r", exc, expr)
        result = False

    return {
        "result":     bool(result),
        "evaluated":  parser.evaluated,
        "unresolved": parser.unresolved,
    }


# ─────────────────────────────────────────────────────────────────────────────
# WinConditionTracker — stateful per-scan tracker
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _ConditionState:
    name:        str
    achieved:    bool          = False
    achieved_at: Optional[float] = None
    evidence:    str           = ""
    is_expression: bool        = False
    sub_state:   Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WinConditionTracker:
    """Evaluates a list of win-condition tokens or expressions against intel."""

    def __init__(self, win_conditions: List[str]):
        self._conditions: List[_ConditionState] = []
        for raw in win_conditions or []:
            cond = (raw or "").strip()
            if not cond:
                continue
            self._conditions.append(_ConditionState(
                name          = cond,
                is_expression = bool(re.search(r"\b(AND|OR|NOT)\b", cond, re.I)),
            ))

    def evaluate(self, intel: Dict[str, Any]) -> Dict[str, Any]:
        """Re-evaluate every condition against ``intel``. Mutates internal state."""
        newly_achieved: List[str] = []
        for c in self._conditions:
            if c.is_expression:
                ev = evaluate_expression(c.name, intel)
                achieved = ev["result"]
                c.sub_state = ev["evaluated"]
            else:
                fn = BUILTIN_EVALUATORS.get(c.name.lower())
                if fn is None:
                    achieved = False
                    c.evidence = "(unknown condition token)"
                else:
                    try:
                        achieved = bool(fn(intel))
                    except Exception as exc:
                        logger.warning("[win_conditions] %s evaluator failed: %s", c.name, exc)
                        achieved = False

            if achieved and not c.achieved:
                c.achieved    = True
                c.achieved_at = time.time()
                c.evidence    = self._evidence_for(c.name, intel)
                newly_achieved.append(c.name)
            # Once True stays True (avoid flapping when shell drops momentarily).

        achieved_count = sum(1 for c in self._conditions if c.achieved)
        total          = len(self._conditions)
        progress_pct   = int(round(100.0 * achieved_count / total)) if total else 0

        return {
            "conditions":    [c.to_dict() for c in self._conditions],
            "achieved_count": achieved_count,
            "total":         total,
            "progress_pct":  progress_pct,
            "all_achieved":  achieved_count == total and total > 0,
            "newly_achieved": newly_achieved,
            "ts":            time.time(),
        }

    def _evidence_for(self, cond: str, intel: Dict[str, Any]) -> str:
        c = cond.lower()
        if "shell" in c:
            return f"shell_id={intel.get('shell_id')}, user={intel.get('current_user')}"
        if "user_flag" in c:
            return f"user_flag={str(intel.get('user_flag') or '')[:40]}"
        if "root_flag" in c:
            return f"root_flag={str(intel.get('root_flag') or '')[:40]}"
        if "cred" in c:
            n = len(intel.get("credentials") or [])
            return f"{n} credential(s) captured"
        if "domain_admin" in c:
            return f"current_user={intel.get('current_user')}"
        if "lateral" in c:
            n = len(intel.get("lateral_targets") or []) + len(intel.get("pivot_paths") or [])
            return f"{n} lateral pivot(s)"
        if "persist" in c:
            return "persistence evidence found"
        if "exfil" in c:
            return "exfiltration evidence found"
        return "achieved"

    def to_prompt_block(self, snapshot: Optional[Dict[str, Any]] = None) -> str:
        """Compact text rendering for prompt injection."""
        snap = snapshot or self.snapshot()
        lines = [
            "=== WIN-CONDITION STATE ===",
            f"Progress: {snap['achieved_count']}/{snap['total']} ({snap['progress_pct']}%)",
        ]
        for c in snap["conditions"]:
            mark = "[X]" if c["achieved"] else "[ ]"
            line = f"  {mark} {c['name']}"
            if c["achieved"] and c["evidence"]:
                line += f"  — {c['evidence']}"
            lines.append(line)
        if snap["all_achieved"]:
            lines.append(">>> ALL WIN CONDITIONS ACHIEVED — mission can wrap up <<<")
        return "\n".join(lines)

    def snapshot(self) -> Dict[str, Any]:
        achieved_count = sum(1 for c in self._conditions if c.achieved)
        total          = len(self._conditions)
        return {
            "conditions":    [c.to_dict() for c in self._conditions],
            "achieved_count": achieved_count,
            "total":         total,
            "progress_pct":  int(round(100.0 * achieved_count / total)) if total else 0,
            "all_achieved":  achieved_count == total and total > 0,
            "newly_achieved": [],
            "ts":            time.time(),
        }
