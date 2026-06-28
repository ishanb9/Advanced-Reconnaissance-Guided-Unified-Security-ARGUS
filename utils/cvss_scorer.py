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


# ── AIVSS: AI-aware risk scoring (Slice 3) ──────────────────────────────
#
# AI/LLM findings don't fit CVSS cleanly: the "exploit" is probabilistic (a
# measured Attack Success Rate, not a binary), and agentic capabilities
# (tool use, autonomy, persistence) amplify impact beyond a single host.  This
# is an AIVSS-aligned heuristic (OWASP AI Vulnerability Scoring System spirit):
#
#     AIVSS = clamp( CVSS_base × reliability(ASR) × (1 + agentic_amplification) )
#
# where reliability scales by the measured ASR (a probe that never succeeded is
# half-weighted) and agentic_amplification reflects how much the attack class
# lets the model *act* (excessive agency > memory persistence > injection).
# Transparent + conservative; content-agnostic (reads finding metadata only).

# attack-class → agentic amplification factor (0.0–0.6).  Keyed on the OWASP-LLM
# category / attack_vector carried in finding.extra.
_AGENTIC_AMP: Dict[str, float] = {
    "excessive_agency":     0.60,   # tool misuse / confused deputy — model takes actions
    "memory_poisoning":     0.45,   # persistence across sessions
    "indirect_injection":   0.40,   # crosses a trust boundary (RAG/tool/web content)
    "jailbreak":            0.30,   # guardrail bypass
    "insecure_output":      0.30,   # downstream XSS/SQLi from model output
    "prompt_injection":     0.25,
    "system_prompt_leak":   0.15,
    "unbounded_consumption":0.20,   # denial-of-wallet
}


@dataclass
class AIVSSScore:
    finding_id:  str
    title:       str
    cvss_base:   float
    asr:         float
    agentic:     float
    aivss_score: float
    severity:    str
    vector:      str
    rationale:   str = ""


def _ai_category(finding: Dict[str, Any]) -> str:
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    cat = str(extra.get("attack_vector") or extra.get("category") or "").lower()
    if cat:
        return cat
    # fall back to OWASP-LLM id → coarse class
    owasp = str(extra.get("owasp_llm") or "").upper()
    if "LLM06" in owasp:
        return "excessive_agency"
    if "LLM04" in owasp:
        return "memory_poisoning"
    if "LLM05" in owasp:
        return "insecure_output"
    if "LLM07" in owasp:
        return "system_prompt_leak"
    if "LLM10" in owasp:
        return "unbounded_consumption"
    return "prompt_injection"


def score_ai_finding(finding: Dict[str, Any]) -> AIVSSScore:
    """AIVSS-aligned score for one AI/LLM finding (uses finding.extra: asr,
    owasp_llm, attack_vector).  Returns an AIVSSScore (CVSS parity + AI factors)."""
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    cvss_base = infer_vector(finding)[1]
    if cvss_base <= 0.0:
        # No CVSS keyword rule matched (typical for AI findings) — derive the
        # base from the finding's severity so AIVSS never collapses to zero when
        # there is a real measured ASR.
        cvss_base = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0,
                     "LOW": 3.1, "INFO": 2.0}.get(
            str(finding.get("severity") or "").upper(), 4.0)
    try:
        asr = float(extra.get("asr"))
    except (TypeError, ValueError):
        asr = 0.0
    asr = max(0.0, min(1.0, asr))
    cat = _ai_category(finding)
    agentic = _AGENTIC_AMP.get(cat, 0.20)
    reliability = 0.5 + 0.5 * asr          # asr=1 → full base, asr=0 → half
    aivss = min(10.0, round(cvss_base * reliability * (1.0 + agentic), 1))
    owasp = str(extra.get("owasp_llm") or "").split()[0] if extra.get("owasp_llm") else ""
    vector = (f"AIVSS/ASR:{asr:.2f}/AG:{agentic:.2f}"
              + (f"/OWASP:{owasp}" if owasp else ""))
    return AIVSSScore(
        finding_id  = str(finding.get("finding_id") or finding.get("id") or ""),
        title       = str(finding.get("title") or ""),
        cvss_base   = cvss_base,
        asr         = asr,
        agentic     = agentic,
        aivss_score = aivss,
        severity    = severity_band(aivss),
        vector      = vector,
        rationale   = (f"CVSS {cvss_base:.1f} × reliability {reliability:.2f}(ASR={asr:.0%}) "
                       f"× agentic {1.0 + agentic:.2f}({cat}) = {aivss:.1f}"),
    )


def score_ai_findings(findings: List[Dict[str, Any]]) -> List[AIVSSScore]:
    """Score every AI finding (those with extra.ai_finding) highest-first."""
    out: List[AIVSSScore] = []
    for f in findings:
        extra = f.get("extra") if isinstance(f.get("extra"), dict) else {}
        if extra.get("ai_finding") or extra.get("asr") is not None or f.get("tool_used") == "ai_red_team":
            out.append(score_ai_finding(f))
    out.sort(key=lambda x: x.aivss_score, reverse=True)
    return out


__all__ = [
    "calculate_base", "vector_to_string", "severity_band",
    "infer_vector", "score_findings", "score_chain", "rank_chains",
    "FindingScore", "ChainScore",
    "score_ai_finding", "score_ai_findings", "AIVSSScore",
]
