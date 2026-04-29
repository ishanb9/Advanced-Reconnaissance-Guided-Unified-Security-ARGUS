"""Scope-guard LLM prompt prefix (Improvement #16).

Every LLM planning call this engine makes — phase planners, hypothesis
generators, validation judges — gets a system prompt.  Without an
engagement scope baked into that prompt, the model is free to suggest
"while we're in there, also try the adjacent /24" or "test
internal-tools.example.com" the moment such an asset appears in the
intel summary.  That is how scope leaks happen.

This module produces a **hard scope-guard prefix** assembled from the
current engagement context, operator notes, and an explicit refusal
directive.  The prefix:

* lists allowed hosts / IPs / CIDRs / domains,
* lists explicit out-of-scope assets,
* enumerates rules of engagement (no DoS, exfil window, change
  windows, …),
* repeats operator-imposed constraints,
* ends with a non-negotiable directive: refuse any plan whose target
  is not on the allowed list, and decline destructive operations
  outside the agreed window.

The prefix is prepended to every ``system`` message sent through
``BaseAgent.think`` (when ``self._scope_guard`` is set), and is also
rendered as a block at the top of ``MasterAgent._intel_summary`` so
phase planners that already use the intel summary as their context
window pick it up automatically.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


logger = logging.getLogger(__name__)


__all__ = [
    "ScopeGuard", "build_scope_guard", "build_scope_prefix",
    "is_in_scope", "extract_scope_entries",
]


# ── Regexes ─────────────────────────────────────────────────────────────
_RE_IPV4_CIDR = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})\b")
_RE_IPV4      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN    = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24}\b",
    re.IGNORECASE,
)
_RE_OUT_OF_SCOPE_HEADER = re.compile(
    r"(?:out[-\s]?of[-\s]?scope|excluded|do not test|do not touch|forbidden|deny[-\s]?list)\s*:?",
    re.I,
)
_RE_NO_DOS = re.compile(r"\bno\s+(?:dos|denial[-\s]?of[-\s]?service|dl|flood)\b", re.I)
_RE_NO_DESTRUCT = re.compile(
    r"\b(?:no\s+destructive|read[-\s]?only|non[-\s]?destructive|enumerate\s+only)\b",
    re.I,
)
_RE_BUSINESS_HOURS = re.compile(
    r"\b(?:business\s+hours|after\s+hours|change\s+window|maintenance\s+window|quiet\s+hours)\b",
    re.I,
)


# ── Data class ─────────────────────────────────────────────────────────

@dataclass
class ScopeGuard:
    target:           str = ""
    allowed_hosts:    List[str] = field(default_factory=list)
    allowed_cidrs:    List[str] = field(default_factory=list)
    allowed_domains:  List[str] = field(default_factory=list)
    out_of_scope:     List[str] = field(default_factory=list)
    rules_of_engagement: List[str] = field(default_factory=list)
    operator_notes:   str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target":              self.target,
            "allowed_hosts":       list(self.allowed_hosts),
            "allowed_cidrs":       list(self.allowed_cidrs),
            "allowed_domains":     list(self.allowed_domains),
            "out_of_scope":        list(self.out_of_scope),
            "rules_of_engagement": list(self.rules_of_engagement),
            "operator_notes":      self.operator_notes[:400],
        }

    def is_empty(self) -> bool:
        return not (self.allowed_hosts or self.allowed_cidrs
                    or self.allowed_domains)


# ── Extraction ─────────────────────────────────────────────────────────

def extract_scope_entries(text: str) -> Tuple[List[str], List[str], List[str], List[str]]:
    """Return (hosts, cidrs, domains, out_of_scope) parsed from free text."""
    if not text:
        return [], [], [], []

    # Split into in-scope vs. out-of-scope sections — anything after a
    # "Out of scope:" / "Excluded:" header goes to OOS.
    parts = _RE_OUT_OF_SCOPE_HEADER.split(text, maxsplit=1)
    in_scope_blob  = parts[0]
    oos_blob       = parts[1] if len(parts) > 1 else ""

    def _grab(blob: str) -> Tuple[List[str], List[str], List[str]]:
        cidrs   = []
        for m in _RE_IPV4_CIDR.finditer(blob):
            try:
                ipaddress.ip_network(m.group(0), strict=False)
                cidrs.append(m.group(0))
            except Exception:
                pass
        # Strip CIDRs out so plain IPs left over don't double-match.
        without_cidrs = _RE_IPV4_CIDR.sub(" ", blob)
        hosts = []
        for m in _RE_IPV4.finditer(without_cidrs):
            try:
                ipaddress.ip_address(m.group(0))
                hosts.append(m.group(0))
            except Exception:
                pass
        domains = []
        for m in _RE_DOMAIN.finditer(blob):
            d = m.group(0).lower()
            if d.replace(".", "").isdigit():
                continue
            # Skip obvious non-domains (file extensions, version numbers)
            if d.endswith((".log", ".exe", ".dll", ".so", ".py", ".json")):
                continue
            domains.append(d)
        return hosts, cidrs, domains

    in_hosts, in_cidrs, in_domains = _grab(in_scope_blob)
    oos_hosts, oos_cidrs, oos_domains = _grab(oos_blob)

    # Dedup, preserve order
    def _uniq(seq: Iterable[str]) -> List[str]:
        seen = set(); out = []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    return (_uniq(in_hosts), _uniq(in_cidrs), _uniq(in_domains),
            _uniq(oos_hosts + oos_cidrs + oos_domains))


def _extract_rules(text: str) -> List[str]:
    rules: List[str] = []
    if not text:
        return rules
    if _RE_NO_DOS.search(text):
        rules.append("No denial-of-service or volumetric attacks.")
    if _RE_NO_DESTRUCT.search(text):
        rules.append("Read-only / non-destructive enumeration only.")
    if _RE_BUSINESS_HOURS.search(text):
        rules.append("Respect agreed change/quiet windows for any active testing.")
    # Generic compliance hints
    low = text.lower()
    if "pci" in low:
        rules.append("PCI-DSS engagement — no cardholder data exfil; mask PANs.")
    if "hipaa" in low:
        rules.append("HIPAA engagement — no PHI access or exfil.")
    if "gdpr" in low:
        rules.append("GDPR engagement — minimise PII exposure.")
    return rules


# ── Builders ────────────────────────────────────────────────────────────

def build_scope_guard(
    *, target: str = "",
    engagement_context: Optional[Dict[str, Any]] = None,
    notes: str = "",
    scope: str = "",
) -> ScopeGuard:
    """Assemble a :class:`ScopeGuard` from all known engagement inputs."""
    guard = ScopeGuard(target=target or "")

    eng = engagement_context or {}

    # Pull explicit lists from engagement_context first.
    eng_hosts   = list(eng.get("scope_hosts") or eng.get("targets") or [])
    eng_cidrs   = list(eng.get("scope_cidrs") or eng.get("cidrs") or [])
    eng_domains = list(eng.get("scope_domains") or eng.get("domains") or [])
    eng_oos     = list(eng.get("out_of_scope") or eng.get("excluded") or [])
    eng_rules   = list(eng.get("rules_of_engagement") or eng.get("rules") or [])

    guard.allowed_hosts.extend(str(h) for h in eng_hosts if h)
    guard.allowed_cidrs.extend(str(c) for c in eng_cidrs if c)
    guard.allowed_domains.extend(str(d).lower() for d in eng_domains if d)
    guard.out_of_scope.extend(str(o) for o in eng_oos if o)
    guard.rules_of_engagement.extend(str(r) for r in eng_rules if r)

    # Parse free-text notes/scope as a fallback.
    blob = " ".join(filter(None, [scope or "", notes or ""]))
    h, c, d, oos = extract_scope_entries(blob)
    guard.allowed_hosts.extend(h)
    guard.allowed_cidrs.extend(c)
    guard.allowed_domains.extend(d)
    guard.out_of_scope.extend(oos)
    guard.rules_of_engagement.extend(_extract_rules(blob))

    # Always include the primary target.
    if target and target not in guard.allowed_hosts and target not in guard.allowed_domains:
        # Decide which bucket based on whether it parses as IP.
        try:
            ipaddress.ip_address(target)
            guard.allowed_hosts.insert(0, target)
        except Exception:
            guard.allowed_domains.insert(0, target.lower())

    # Dedup preserving order
    def _uniq(seq: List[str]) -> List[str]:
        seen = set(); out = []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    guard.allowed_hosts        = _uniq(guard.allowed_hosts)
    guard.allowed_cidrs        = _uniq(guard.allowed_cidrs)
    guard.allowed_domains      = _uniq(guard.allowed_domains)
    guard.out_of_scope         = _uniq(guard.out_of_scope)
    guard.rules_of_engagement  = _uniq(guard.rules_of_engagement)
    guard.operator_notes       = (notes or "").strip()[:400]
    return guard


def build_scope_prefix(guard: ScopeGuard) -> str:
    """Render the guard as a hard system-prompt preamble.

    The exact wording is intentionally directive — the LLM should treat
    these as non-negotiable constraints, not suggestions.
    """
    if guard is None or guard.is_empty():
        # Even with no explicit scope we still want a refusal directive.
        return (
            "=== SCOPE GUARD ===\n"
            "No explicit engagement scope provided.  Treat ONLY the primary "
            "target as in-scope.  Refuse to plan, enumerate, or exploit any "
            "asset whose hostname, IP, or domain you cannot trace back to the "
            "primary target.  Never propose actions against adjacent or "
            "third-party systems.\n"
            "=== END SCOPE GUARD ===\n"
        )

    lines: List[str] = ["=== SCOPE GUARD (NON-NEGOTIABLE) ==="]
    lines.append(f"Primary target : {guard.target or '(unset)'}")
    if guard.allowed_hosts:
        lines.append(f"Allowed hosts  : {', '.join(guard.allowed_hosts[:12])}")
    if guard.allowed_cidrs:
        lines.append(f"Allowed CIDRs  : {', '.join(guard.allowed_cidrs[:8])}")
    if guard.allowed_domains:
        lines.append(f"Allowed domains: {', '.join(guard.allowed_domains[:8])}")
    if guard.out_of_scope:
        lines.append(f"Out-of-scope   : {', '.join(guard.out_of_scope[:10])}")
    if guard.rules_of_engagement:
        lines.append("Rules of engagement:")
        for r in guard.rules_of_engagement[:6]:
            lines.append(f"  - {r}")
    if guard.operator_notes:
        lines.append(f"Operator notes : {guard.operator_notes[:240]}")

    lines.append("")
    lines.append("DIRECTIVE:")
    lines.append(
        "  1. Refuse any plan, command, or hypothesis whose target is "
        "outside the allowed lists above."
    )
    lines.append(
        "  2. If the intel summary contains adjacent IPs or domains not in "
        "scope, ignore them — do not propose actions against them."
    )
    lines.append(
        "  3. Honour all rules of engagement (no DoS, no destructive ops "
        "outside agreed windows, etc.)."
    )
    lines.append(
        "  4. If asked to act outside scope, respond with a refusal and an "
        "explanation citing this guard."
    )
    lines.append("=== END SCOPE GUARD ===")
    return "\n".join(lines) + "\n"


def is_in_scope(asset: str, guard: ScopeGuard) -> bool:
    """Return True iff ``asset`` (IP / hostname / domain) falls in scope."""
    if not asset or guard is None:
        return False
    a = asset.strip().lower()
    if not a:
        return False

    # Out-of-scope wins
    for o in guard.out_of_scope:
        if a == str(o).strip().lower():
            return False

    # Direct host match
    if a in {h.lower() for h in guard.allowed_hosts}:
        return True

    # Domain match (suffix)
    for d in guard.allowed_domains:
        d_low = d.lower()
        if a == d_low or a.endswith("." + d_low):
            return True

    # CIDR match
    try:
        ip = ipaddress.ip_address(a)
        for cidr in guard.allowed_cidrs:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except Exception:
                continue
    except Exception:
        pass

    return False
