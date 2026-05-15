"""
cvss_scorer.py - automatic CVSS estimation + chain-level risk scoring.

Why this exists
---------------
ARGUS findings currently carry only severity (CRITICAL/HIGH/MEDIUM/LOW/
INFO).  That's adequate for triage but not for prioritization across a
real engagement.  Operators want to know:
  - Which finding is the SINGLE-most-impactful one to exploit next?
  - Which chain of findings, taken together, leads to the highest
    business impact?

CVSS v3.1 gives us a numeric score (0-10) with a structured vector
(AV/AC/PR/UI/S/C/I/A).  This module:
  1. Estimates the CVSS vector from a finding's title + description +
     CVE id (if any) using a rules-based heuristic.
  2. Computes the v3.1 base score.
  3. Ranks chains of findings by combined-impact score (max of CVSS +
     bonuses for exploitability proof).

No external network calls - we don't query NVD.  The heuristic is
deliberately conservative; the operator can override any score
through the Finding metadata `cvss_vector` or `cvss_base` fields.
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── CVSS v3.1 metric values ─────────────────────────────────────────────
_AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_VALUES = {"L": 0.77, "H": 0.44}
_PR_VALUES = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},     # scope unchanged
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},     # scope changed
}
_UI_VALUES = {"N": 0.85, "R": 0.62}
_CIA_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    """CVSS v3.1 round-up to one decimal (ceil to 0.1)."""
    return math.ceil(x * 10.0) / 10.0


def calculate_base(vector: Dict[str, str]) -> float:
    """Compute CVSS v3.1 base score from an AV/AC/PR/UI/S/C/I/A vector dict."""
    try:
        av = _AV_VALUES[vector["AV"]]
        ac = _AC_VALUES[vector["AC"]]
        ui = _UI_VALUES[vector["UI"]]
        scope = vector["S"]
        pr = _PR_VALUES[scope][vector["PR"]]
        c  = _CIA_VALUES[vector["C"]]
        i  = _CIA_VALUES[vector["I"]]
        a  = _CIA_VALUES[vector["A"]]
    except KeyError:
        return 0.0

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploit, 10))
    return _roundup(min(1.08 * (impact + exploit), 10))


def vector_to_string(vector: Dict[str, str]) -> str:
    """Render vector dict to canonical CVSS v3.1 string."""
    return "CVSS:3.1/" + "/".join(
        f"{k}:{vector[k]}" for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
        if k in vector
    )


def severity_band(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "INFO"


# ── Heuristic vector inference ──────────────────────────────────────────

# Keyword bundles -> (vector_overrides, severity_floor).  First match wins.
_HEURISTIC_RULES: List[Tuple[List[str], Dict[str, str], str]] = [
    # RCE / unauth-command-execution
    (["rce", "remote code execution", "command injection", "code execution",
      "unauthenticated rce", "deserialization rce"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"H"},
     "CRITICAL"),
    # Auth bypass / default creds
    (["default cred", "default credentials", "default password",
      "no authentication", "unauthenticated", "auth bypass"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"L"},
     "HIGH"),
    # SQL injection
    (["sql injection", "sqli", "blind sqli", "boolean sqli", "time-based sqli"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"L"},
     "HIGH"),
    # Path traversal / arbitrary file read
    (["path traversal", "directory traversal", "lfi", "local file inclusion",
      "arbitrary file read", "file disclosure"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"N","A":"N"},
     "HIGH"),
    # SSRF
    (["ssrf", "server side request forgery"],
     {"AV":"N","AC":"L","PR":"L","UI":"N","S":"C","C":"H","I":"L","A":"N"},
     "HIGH"),
    # Heap dump / env dump / credential disclosure
    (["heapdump", "heap dump", "secret in heap", "actuator/env", "secrets exposed",
      "spring actuator", "/env exposes", "credentials in"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"N","A":"N"},
     "HIGH"),
    # Anonymous bucket listing / data exposure
    (["anonymous bucket", "public bucket", "open s3", "exposed minio",
      "elasticsearch index", "mongodb without"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"L","A":"N"},
     "HIGH"),
    # XSS
    (["stored xss", "reflected xss", "dom xss", "cross-site scripting"],
     {"AV":"N","AC":"L","PR":"N","UI":"R","S":"C","C":"L","I":"L","A":"N"},
     "MEDIUM"),
    # CSRF
    (["csrf", "cross site request forgery"],
     {"AV":"N","AC":"L","PR":"N","UI":"R","S":"U","C":"N","I":"L","A":"N"},
     "MEDIUM"),
    # AD: Kerberoast / AS-REP-roast / DCSync
    (["kerberoast", "as-rep", "asrep", "dcsync", "zerologon", "petitpotam",
      "esc1", "esc8"],
     {"AV":"N","AC":"L","PR":"L","UI":"N","S":"C","C":"H","I":"H","A":"H"},
     "CRITICAL"),
    # Open SMB shares / null sessions
    (["null session", "smb signing disabled", "anonymous share",
      "smb1 enabled"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"L","I":"L","A":"N"},
     "MEDIUM"),
    # Missing headers / info disclosure (low severity)
    (["missing security headers", "server disclosure", "version disclosure",
      "missing strict-transport", "x-frame-options"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"L","I":"N","A":"N"},
     "LOW"),
    # XXE
    (["xxe", "xml external entity"],
     {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"L","A":"L"},
     "HIGH"),
    # Privilege escalation
    (["suid", "sudo misconfig", "weak sudo", "writable /etc",
      "kernel exploit", "polkit", "pwnkit"],
     {"AV":"L","AC":"L","PR":"L","UI":"N","S":"U","C":"H","I":"H","A":"H"},
     "HIGH"),
    # Container escape
    (["container escape", "docker escape", "privileged container"],
     {"AV":"L","AC":"L","PR":"L","UI":"N","S":"C","C":"H","I":"H","A":"H"},
     "CRITICAL"),
]


def infer_vector(finding: Dict[str, Any]) -> Tuple[Dict[str, str], float, str]:
    """Best-effort CVSS vector + score for a finding.

    Returns (vector_dict, base_score, severity_band).
    Falls back to (LOW vector, 3.1, "LOW") if no rules match.
    """
    # Honor operator-supplied overrides
    if finding.get("cvss_vector"):
        # Try to parse a CVSS:3.1 string
        v = _parse_vector_string(str(finding["cvss_vector"]))
        if v:
            s = calculate_base(v)
            return v, s, severity_band(s)
    if isinstance(finding.get("cvss_base"), (int, float)):
        s = float(finding["cvss_base"])
        return {}, s, severity_band(s)

    haystack = " ".join(str(finding.get(k) or "")
                        for k in ("title", "description", "evidence", "exploit_suggestion",
                                  "cve", "tags")).lower()

    for keywords, vec, _floor in _HEURISTIC_RULES:
        for kw in keywords:
            if kw in haystack:
                score = calculate_base(vec)
                return dict(vec), score, severity_band(score)

    # Default: low/info if no rule matched
    sev = str(finding.get("severity") or "INFO").upper()
    default_score = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0,
                     "LOW": 3.1, "INFO": 0.0}.get(sev, 0.0)
    return {}, default_score, sev


def _parse_vector_string(s: str) -> Optional[Dict[str, str]]:
    """Parse 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> dict."""
    if not s:
        return None
    parts = s.split("/")
    out: Dict[str, str] = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            if k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
                out[k] = v
    return out if len(out) >= 8 else None


# ── Chain scoring ────────────────────────────────────────────────────────

@dataclass
class FindingScore:
    finding_id:  str
    title:       str
    severity:    str
    cvss_base:   float
    cvss_vector: str
    rationale:   str = ""


def score_findings(findings: List[Dict[str, Any]]) -> List[FindingScore]:
    """Score each finding individually.  Returns list sorted highest-first."""
    out: List[FindingScore] = []
    for f in findings:
        vec, score, band = infer_vector(f)
        out.append(FindingScore(
            finding_id  = str(f.get("finding_id") or f.get("id") or ""),
            title       = str(f.get("title") or ""),
            severity    = band,
            cvss_base   = score,
            cvss_vector = vector_to_string(vec) if vec else "(heuristic)",
            rationale   = f"keyword match -> {band}" if vec else "severity-only fallback",
        ))
    out.sort(key=lambda x: x.cvss_base, reverse=True)
    return out


@dataclass
class ChainScore:
    chain_id:   str
    member_ids: List[str]
    base_score: float        # max(member) + bonuses
    bonus:      float        # for proof-of-exploit, chain length, etc.
    severity:   str
    rationale:  str = ""


def score_chain(chain: Dict[str, Any], findings_by_id: Dict[str, Dict[str, Any]]) -> ChainScore:
    """Score an attack chain (combined-impact view).

    `chain` is the attack_chains entry from the attack-graph agent
    (has .chain_id, .nodes / .steps, .combined_probability).

    Combined-impact heuristic:
      base = max(CVSS over members)
      + 0.5 if any member proves RCE / shell obtained
      + 0.3 if chain length >= 3 (multi-step deserves more weight)
      + 1.0 if combined_probability >= 0.7 (attacker-confidence signal)
    Capped at 10.0.
    """
    cid = str(chain.get("chain_id") or chain.get("id") or "chain")
    member_ids = []
    member_findings: List[Dict[str, Any]] = []
    for n in (chain.get("nodes") or chain.get("steps") or chain.get("members") or []):
        if isinstance(n, dict):
            mid = str(n.get("finding_id") or n.get("id") or "")
            if mid:
                member_ids.append(mid)
                if mid in findings_by_id:
                    member_findings.append(findings_by_id[mid])
        elif isinstance(n, str):
            member_ids.append(n)
            if n in findings_by_id:
                member_findings.append(findings_by_id[n])

    if not member_findings:
        return ChainScore(
            chain_id   = cid,
            member_ids = member_ids,
            base_score = 0.0,
            bonus      = 0.0,
            severity   = "INFO",
            rationale  = "no resolvable members",
        )

    scores = [infer_vector(f)[1] for f in member_findings]
    base = max(scores)

    bonus = 0.0
    rationale_parts = [f"max member={base:.1f}"]
    titles = " ".join(str(f.get("title") or "").lower() for f in member_findings)
    if any(k in titles for k in ("rce", "shell", "code execution", "command injection")):
        bonus += 0.5
        rationale_parts.append("+0.5 RCE proof")
    if len(member_findings) >= 3:
        bonus += 0.3
        rationale_parts.append(f"+0.3 length={len(member_findings)}")
    try:
        prob = float(chain.get("combined_probability") or 0)
    except (TypeError, ValueError):
        prob = 0.0
    if prob >= 0.7:
        bonus += 1.0
        rationale_parts.append(f"+1.0 prob={prob:.2f}")

    total = min(base + bonus, 10.0)
    return ChainScore(
        chain_id   = cid,
        member_ids = member_ids,
        base_score = total,
        bonus      = bonus,
        severity   = severity_band(total),
        rationale  = "; ".join(rationale_parts),
    )


def rank_chains(chains: List[Dict[str, Any]],
                findings: List[Dict[str, Any]]) -> List[ChainScore]:
    """Score every chain; return sorted highest-first."""
    findings_by_id = {
        str(f.get("finding_id") or f.get("id")): f
        for f in findings
        if (f.get("finding_id") or f.get("id"))
    }
    scored = [score_chain(c, findings_by_id) for c in chains]
    scored.sort(key=lambda x: x.base_score, reverse=True)
    return scored


__all__ = [
    "calculate_base", "vector_to_string", "severity_band",
    "infer_vector", "score_findings", "score_chain", "rank_chains",
    "FindingScore", "ChainScore",
]
