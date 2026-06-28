"""evals/scorer.py — pure, deterministic scoring of one benchmark run (Gap #6).

Given a benchmark case and the output ARGUS produced for it, decide whether ARGUS
EXPLOITED the target (the injected flag token surfaced — un-fakeable) and/or
DETECTED it (a finding matched the expected CVE / title / severity signature).

Everything here is pure and side-effect free, so the whole scoring policy is
unit-testable without standing up a single target.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(s: Any) -> int:
    return _SEV_ORDER.get(str(s or "").lower().replace("findingseverity.", ""), 0)


def _haystack(run_output: Dict[str, Any]) -> str:
    """Every place an exfiltrated flag could legitimately appear in ARGUS output:
    the session flags_found list, captured loot, the flags collection (Flag.value),
    and each finding's evidence/title."""
    parts: List[str] = []
    parts += [str(x) for x in (run_output.get("flags_found") or [])]
    parts += [str(x) for x in (run_output.get("loot") or [])]
    for fl in (run_output.get("flags") or []):
        parts.append(str(fl.get("value") if isinstance(fl, dict) else fl))
    for f in (run_output.get("findings") or []):
        parts.append(str(f.get("evidence") or ""))
        parts.append(str(f.get("title") or ""))
    return "\n".join(parts)


def _finding_cves(f: Dict[str, Any]) -> List[str]:
    cves = list(f.get("cves") or [])
    if f.get("cve"):
        cves.append(f.get("cve"))
    return [str(c).upper() for c in cves]


def _finding_matches(expected: Dict[str, Any], findings: List[Dict[str, Any]]) -> bool:
    """A finding matches if it meets the minimum severity AND (any expected CVE is
    present) AND (every expected title keyword is present).  Empty constraints are
    treated as satisfied — but a case with NO expectations never matches."""
    exp = expected or {}
    kws = [k.lower() for k in (exp.get("title_keywords") or [])]
    cves = [c.upper() for c in (exp.get("cves") or [])]
    if not kws and not cves:
        return False                       # nothing to match against — never a pass
    min_rank = _sev_rank(exp.get("min_severity"))
    for f in (findings or []):
        if _sev_rank(f.get("severity")) < min_rank:
            continue
        title = str(f.get("title") or "").lower()
        cve_ok = (not cves) or any(c in _finding_cves(f) for c in cves)
        kw_ok = (not kws) or all(k in title for k in kws)
        if cve_ok and kw_ok:
            return True
    return False


@dataclass
class CaseResult:
    case_id: str
    pass_mode: str
    exploited: bool
    detected: bool
    passed: bool
    score: float
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def score_case(case: Any, run_output: Dict[str, Any], run_flag: Any = None) -> CaseResult:
    """Score one case.  ``case`` is a BenchmarkCase or an equivalent dict;
    ``run_output`` is what ARGUS produced ({findings, flags_found, loot, flags});
    ``run_flag`` overrides the catalog flag for a per-run nonce.  Pure."""
    c = case.to_dict() if hasattr(case, "to_dict") else dict(case)
    pass_mode = c.get("pass_mode", "detect")
    flag = run_flag or c.get("flag") or ""
    run_output = run_output or {}
    findings = run_output.get("findings") or []
    reasons: List[str] = []

    exploited = bool(flag) and flag in _haystack(run_output)
    if flag:
        reasons.append("injected flag recovered → compromise proven (un-fakeable)"
                       if exploited else "injected flag token NOT found in ARGUS output")

    detected = _finding_matches(c.get("expected") or {}, findings)
    reasons.append("finding signature matched"
                   if detected else "no finding matched the expected signature")

    if pass_mode == "exploit":
        passed = exploited
        score = 1.0 if exploited else (0.5 if detected else 0.0)
    else:  # "detect"
        passed = detected
        score = 1.0 if detected else 0.0

    return CaseResult(case_id=c.get("id", "?"), pass_mode=pass_mode,
                      exploited=exploited, detected=detected, passed=passed,
                      score=score, reasons=reasons)
