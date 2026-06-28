"""knowledge/severity_policy.py — the single source of truth for finding severity.

ARGUS grades a finding by what it OPERATIONALLY demonstrated or assessed (the
red-team convention), not by a raw CVSS number.  This module is a pure,
dependency-free policy so severity is consistent run-to-run and testable in
isolation.  CVSS is computed elsewhere and kept only as a reference score; it
never drives the headline severity.

The rubric (top-down, first match wins — a finding lands at the HIGHEST tier its
evidence justifies):

  CRITICAL  ARGUS demonstrated COMPROMISE — root/admin or domain-admin — OR an
            equivalent catastrophic demonstrated impact: full unauthenticated
            data exfiltration (total_data) or control of an OT/safety system
            (ot_control).
  HIGH      A public exploit is available for a CONFIRMED product+version (run or
            not), OR a demonstrated partial / non-root foothold, OR a confirmed
            DIRECTLY-exploitable weakness (no public exploit needed) that is not
            catastrophic.  Definite risk, high chaining probability.
  MEDIUM    A confirmed weakness with NO applicable public exploit and not
            directly exploitable alone, but CHAINABLE with other vulns/misconfigs.
            (Also: a public exploit exists but the vulnerable version is
            unconfirmed — we do not inflate on guesswork.)
  LOW       A confirmed minor issue / information leak — not directly exploitable,
            weak/remote chaining value, useful mainly for recon.
  INFO      Bare detection / harmless information — attack surface, not
            exploitable.  (inherent_risk metadata still drives prioritisation.)

`grade(signals)` returns {severity, rationale, evidence_tag, factors}.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Ordered severity ladder (low → high) for comparisons / monotonic re-grade.
SEVERITY_ORDER: List[str] = ["info", "low", "medium", "high", "critical"]

# Compromise ladder (none → strongest).  The last four are CRITICAL-class
# outcomes (demonstrated full compromise or catastrophic impact); foothold /
# user_rce are partial (HIGH-class).
COMPROMISE_ORDER: List[str] = [
    "none", "foothold", "user_rce",
    "root_admin", "domain_admin", "total_data", "ot_control",
]
_CRITICAL_COMPROMISE = {"root_admin", "domain_admin", "total_data", "ot_control"}
_PARTIAL_COMPROMISE  = {"foothold", "user_rce"}

# Evidence tags — replace the misleading blanket "VERIFIED" badge with an honest
# statement of WHAT was established.
TAG_DEMONSTRATED = "DEMONSTRATED"   # compromise / impact actually achieved
TAG_PUBLIC_EXPLOIT = "PUBLIC-EXPLOIT"  # applicable public exploit exists
TAG_CONFIRMED = "CONFIRMED"         # weakness proven by a probe
TAG_OBSERVED  = "OBSERVED"          # detection / information only


def _sev_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(str(sev).lower())
    except ValueError:
        return 0


def _compromise_rank(level: str) -> int:
    try:
        return COMPROMISE_ORDER.index(str(level or "none").lower())
    except ValueError:
        return 0


def _b(signals: Dict[str, Any], key: str, default: bool = False) -> bool:
    v = signals.get(key, default)
    return bool(v)


def grade(signals: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the operational severity for a finding from its evidence signals.

    See the module docstring for the rubric.  Pure + deterministic: the same
    signals always yield the same verdict.
    """
    s = signals or {}
    compromise = str(s.get("compromise", "none") or "none").lower()
    factors: List[str] = []

    def verdict(sev: str, rationale: str, tag: str) -> Dict[str, Any]:
        return {"severity": sev, "rationale": rationale,
                "evidence_tag": tag, "factors": list(factors)}

    # ── CRITICAL — demonstrated compromise or equivalent catastrophic impact ──
    if compromise in _CRITICAL_COMPROMISE:
        factors.append(f"compromise={compromise}")
        _why = {
            "root_admin":   "root/administrator access obtained on the host",
            "domain_admin": "domain-administrator access obtained",
            "total_data":   "full unauthenticated data exfiltration demonstrated",
            "ot_control":   "control of an OT/safety system demonstrated",
        }[compromise]
        return verdict("critical", f"ARGUS compromised the target — {_why}.",
                       TAG_DEMONSTRATED)

    # ── HIGH — partial foothold, applicable public exploit, or directly-exploitable ──
    if compromise in _PARTIAL_COMPROMISE:
        factors.append(f"compromise={compromise}")
        _why = ("an interactive non-root foothold (low-privilege shell)"
                if compromise == "foothold" else "user-level code execution")
        return verdict("high", f"ARGUS demonstrated {_why} — partial compromise, "
                               "privilege escalation likely chains to full control.",
                       TAG_DEMONSTRATED)

    confirmed   = _b(s, "confirmed")
    exploit_avl = _b(s, "exploit_available")
    version_ok  = _b(s, "version_confirmed", True)
    direct      = _b(s, "directly_exploitable")
    chainable   = _b(s, "chainable")

    if exploit_avl and confirmed and version_ok:
        factors.append("exploit_available+version_confirmed")
        return verdict("high", "A public exploit is available for the confirmed "
                               "product/version — definite risk whether or not it was run.",
                       TAG_PUBLIC_EXPLOIT)

    if confirmed and direct:
        factors.append("directly_exploitable")
        return verdict("high", "Confirmed directly-exploitable weakness (no public "
                               "exploit required) — a definite standalone risk.",
                       TAG_CONFIRMED)

    # ── MEDIUM — confirmed + chainable (no applicable public exploit) ──
    if exploit_avl and not version_ok:
        factors.append("exploit_available+version_unconfirmed")
        return verdict("medium", "A public exploit exists for the product, but the "
                                 "vulnerable version could not be confirmed — chainable risk.",
                       TAG_PUBLIC_EXPLOIT)

    if confirmed and chainable:
        factors.append("confirmed+chainable")
        return verdict("medium", "Confirmed weakness with no applicable public exploit, "
                                 "but a high chance of chaining with other issues.",
                       TAG_CONFIRMED)

    # ── LOW — confirmed minor / info-leak, weak chaining, recon value ──
    if _b(s, "info_leak_only") or (confirmed and not _b(s, "detection_only")):
        factors.append("info_leak_or_minor_confirmed")
        return verdict("low", "Not directly exploitable; leaks information useful for "
                              "recon or has only a remote chaining possibility.",
                       TAG_CONFIRMED)

    # ── INFO — bare detection / harmless information ──
    factors.append("detection_only" if _b(s, "detection_only") else "informational")
    return verdict("info", "Attack-surface observation — present but not exploitable "
                          "on its own.", TAG_OBSERVED)


def merge_signals(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Additively merge evidence for a re-grade.  Booleans OR together; the
    compromise level takes the STRONGER of the two; other scalars prefer the new
    value when provided.  Used so a finding escalates as evidence accrues."""
    out = dict(old or {})
    for k, v in (new or {}).items():
        if k == "compromise":
            if _compromise_rank(v) > _compromise_rank(out.get("compromise", "none")):
                out["compromise"] = v
        elif isinstance(v, bool):
            out[k] = bool(out.get(k, False)) or v
        elif v is not None:
            out[k] = v
    return out


def is_escalation(old_sev: str, new_sev: str) -> bool:
    """True if new_sev is strictly higher than old_sev on the severity ladder."""
    return _sev_rank(new_sev) > _sev_rank(old_sev)


# ════════════════════════════════════════════════════════════════════════════
# Report-time normalization — the SINGLE source of truth applied to every finding
# before it is rendered, so a report never inflates severity or shows tool noise.
# Render-only: the DB is never mutated; the autonomous flow is untouched.
# ════════════════════════════════════════════════════════════════════════════
import re as _re   # noqa: E402

# A "finding" that is actually raw tool output, an internal ARGUS diagnostic, or a
# malformed record — these must NEVER reach a client report.  Kept tight (high
# precision) so a real finding is never dropped.
_NOISE_RE = _re.compile(
    r"\[stderr\]|^\s*\[?stderr\b|searchsploit\s*:\s*no exploits found|no exploits found for|"
    r"starting searchsploit|searchsploit\s+-j|--exclude=|^\s*e\.g\.\b|"
    r"exploit attempted\s*[—-]\s*$|operator core unavailable|legacy fallback engaged|"
    r"scan terminated:|host\(s\) tested|multiple index files found|"
    r"\{\s*['\"]cve['\"]\s*:|public exploit:\s*\[stderr\]|public exploit:\s*starting", _re.I)

# Bare attack-surface DETECTION (no exploitation) → INFO.
_DETECTION_RE = _re.compile(
    r"\bdetected\b|server disclosure|version disclosure|service / framework version|"
    r"os fingerprint|open port\b|\bbanner\b|appears to be outdated|wildcard dns|"
    r"\bvhost(s)?\b|virtual host|subdomain|web director(y|ies)|hidden vhost|"
    r"access-controlled surface|index files", _re.I)

# Hygiene / information-leak → LOW (still confirmed, just not directly exploitable).
_INFO_LEAK_RE = _re.compile(
    r"missing (security )?header|missing hsts|information disclosure|phpinfo|"
    r"verbose error|directory listing|x-powered-by|strict-transport", _re.I)

# An injection / RCE CLAIM whose proof must be checked before it can be CRITICAL.
_UNPROVEN_RCE_RE = _re.compile(
    r"\brce\b|remote code execution|command injection|\bcmdi\b|sql injection|\bsqli\b|"
    r"\bssrf\b|\bidor\b|\bbola\b|\bxxe\b|deserciali[sz]ation|deserciali|template injection|\bssti\b", _re.I)

_REPRO_PROVEN = {"reproduced", "confirmed", "demonstrated", "verified"}
_REPRO_UNPROVEN = {"", "na", "n/a", "none", "unreproduced", "unverified", "pending", "attempted"}


def _norm_sev(sev: Any) -> str:
    s = str(sev or "").lower().replace("findingseverity.", "").strip()
    return s if s in SEVERITY_ORDER else ("info" if not s else s)


def is_noise(finding: Dict[str, Any]) -> "tuple[bool, str]":
    """True (+reason) when a stored 'finding' is raw tool output / an internal ARGUS
    diagnostic / a malformed record that must not appear as a client-facing finding."""
    f = finding or {}
    title = str(f.get("title") or "")
    low = title.lower()
    if _NOISE_RE.search(title):
        return True, "raw tool output / internal diagnostic — not a security finding"
    if "operator core unavailable" in low or "legacy fallback" in low:
        return True, "internal ARGUS status message — not a target finding"
    if low.startswith(("public exploit: [stderr]", "public exploit: starting",
                       "searchsploit:", "metasploit: exploit attempted")):
        return True, "tool invocation log line — not a security finding"
    return False, ""


def _has_validated_cve(finding: Dict[str, Any]) -> bool:
    """A real CVE id is attached (so a critical CVE keeps its weight — founder policy)."""
    cves = finding.get("cves") or []
    for c in cves:
        cid = c.get("cve") if isinstance(c, dict) else c
        if cid and _re.match(r"cve-\d{4}-\d+", str(cid), _re.I):
            return True
    return False


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """The single source of truth for a finding's REPORT severity.  Returns
    ``{drop, severity, evidence_tag, rationale}``.  Conservative — it only reclassifies
    well-understood classes (tool-noise, detection-only, unproven-injection, demonstrated
    compromise, validated-CVE); anything else keeps its (clamped) producer severity.

    Founder decisions encoded here:
      • a VALIDATED critical CVE stays CRITICAL even if ARGUS did not execute it;
      • an UNPROVEN injection/RCE claim (no CVE, not reproduced) is capped at MEDIUM
        until command execution is demonstrated;
      • bare detection / service-discovery is INFO (LOW for an info-leak);
      • tool-output / internal-diagnostic records are DROPPED from the report.
    """
    f = finding or {}
    raw = _norm_sev(f.get("severity"))

    noise, why = is_noise(f)
    if noise:
        return {"drop": True, "severity": "info", "evidence_tag": TAG_OBSERVED, "rationale": why}

    # Real evidence signals present → the operational policy governs verbatim.
    signals = f.get("signals") if isinstance(f.get("signals"), dict) else None
    if signals:
        v = grade(signals)
        return {"drop": False, "severity": v["severity"],
                "evidence_tag": v["evidence_tag"], "rationale": v["rationale"]}

    blob = (str(f.get("title") or "") + " " + str(f.get("description") or "")).lower()
    repro = str(f.get("reproduce_status") or "").lower()
    src = str(f.get("source") or "").lower()

    # Demonstrated compromise (committed-exploit win, reproduced PoC, captured proof).
    if (str(f.get("evidence_tag") or "") == TAG_DEMONSTRATED or repro in _REPRO_PROVEN
            or src == "committed_exploit"):
        keep = raw if raw in ("critical", "high") else "high"
        return {"drop": False, "severity": keep, "evidence_tag": TAG_DEMONSTRATED,
                "rationale": "ARGUS demonstrated this issue (reproduced / captured proof)."}

    # Validated critical/high CVE with a real CVE id → keep its weight (founder policy).
    if _has_validated_cve(f) and raw in ("critical", "high") and repro not in ("false", "rejected"):
        return {"drop": False, "severity": raw, "evidence_tag": TAG_PUBLIC_EXPLOIT,
                "rationale": "Validated CVE for the confirmed product — public exploit risk."}

    # Unproven injection / RCE claim (no CVE, not reproduced) → cap at MEDIUM pending proof.
    if _UNPROVEN_RCE_RE.search(blob) and not _has_validated_cve(f) and repro in _REPRO_UNPROVEN:
        capped = "medium" if _sev_rank(raw) > _sev_rank("medium") else raw
        return {"drop": False, "severity": capped, "evidence_tag": TAG_OBSERVED,
                "rationale": "Injection signature observed but command execution was NOT "
                             "demonstrated — capped pending proof of exploitation."}

    # Metasploit / generic 'exploit attempted' with no session → INFO.
    if "exploit attempted" in blob and "shell obtained" not in blob and "session opened" not in blob:
        return {"drop": False, "severity": "info", "evidence_tag": TAG_OBSERVED,
                "rationale": "Exploit attempted; no session/shell obtained."}

    # Information / hygiene exposure (missing headers, disclosure, phpinfo) → LOW.
    if _INFO_LEAK_RE.search(blob) and repro in _REPRO_UNPROVEN:
        return {"drop": False, "severity": "low", "evidence_tag": TAG_OBSERVED,
                "rationale": "Information/hygiene exposure — not directly exploitable."}

    # Bare detection / attack-surface observation → INFO.
    if _DETECTION_RE.search(blob) and repro in _REPRO_UNPROVEN:
        return {"drop": False, "severity": "info", "evidence_tag": TAG_OBSERVED,
                "rationale": "Attack-surface detection — present, not exploitable on its own."}

    # Otherwise: keep the producer severity (clamped to a valid label).
    return {"drop": False, "severity": raw, "evidence_tag": str(f.get("evidence_tag") or ""),
            "rationale": ""}


def compute_final_rating(sev_counts: Dict[str, int], *, root: bool = False,
                         shell: bool = False, has_issues: bool = False) -> "tuple[str, str]":
    """The ONE canonical engagement verdict, derived from the normalized severity counts
    and the compromise state — identical across every report theme.  Returns
    ``(final_rating, final_rating_label)``.  Proven-compromise-first, then critical issues,
    so the headline can never disagree between report types."""
    c = {k: int((sev_counts or {}).get(k, 0) or 0) for k in SEVERITY_ORDER}
    total = sum(c.values())
    if root:
        return "critical", "FULL COMPROMISE — ROOT"
    if shell:
        return "critical", "COMPROMISED — FOOTHOLD"
    if c["critical"] > 0:
        return "critical", "CRITICAL — UNEXPLOITED CRITICAL ISSUES"
    if c["high"] > 0:
        return "high", "HIGH — SIGNIFICANT ISSUES IDENTIFIED"
    if total > 0 or has_issues:
        # highest present severity drives the colour; wording stays the familiar one.
        rating = "medium" if c["medium"] > 0 else ("low" if c["low"] > 0 else "info")
        return rating, "PARTIAL — ISSUES IDENTIFIED"
    return "none", "RECON ONLY"
