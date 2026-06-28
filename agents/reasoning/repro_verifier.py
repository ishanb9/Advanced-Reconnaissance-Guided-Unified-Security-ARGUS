"""agents/reasoning/repro_verifier.py — independent reproduction + status gate (Gap #1).

Closes the "verified findings" gap: a high/critical finding should be backed by
PROOF, and what ARGUS cannot reproduce should not masquerade as confirmed.  This
module assigns an HONEST reproduction status and gates un-reproduced high/critical
findings into the same "Unverified" lane Gap #2 introduced (never silently
dropped), and offers an independent RE-RUN for tool-based findings.

Honest taxonomy (we never overclaim):
  reproduced        — independently DEMONSTRATED on a separate path: a browser
                      confirmation (Gap #2), a proven compromise/foothold, or a
                      successful independent tool re-run.
  evidence_confirmed— grounded by tool evidence / an applicable public exploit, but
                      on a SINGLE path (not an independent re-run).
  unreproduced      — a high/critical CLAIM with no verification, OR a browser/tool
                      re-run that tried and could not reproduce it.
  na                — info/low; independent reproduction is not required.

Pure decision functions are unit-testable without any tool/browser; ``reproduce``
performs the optional independent re-run and is best-effort (never raises).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("argus.repro")

_SEV_HIGH = {"high", "critical"}
_CRITICAL_COMPROMISE = {"root_admin", "domain_admin", "total_data", "ot_control",
                        "foothold", "user_rce"}


def _g(finding: Dict[str, Any], key: str):
    """Read a key from the finding top-level OR its ``extra`` (the two paths store
    provenance in different places)."""
    if key in finding and finding.get(key) is not None:
        return finding.get(key)
    return (finding.get("extra") or {}).get(key)


def _sev(finding: Dict[str, Any]) -> str:
    return str(finding.get("severity") or "").lower().replace("findingseverity.", "")


def repro_status(finding: Dict[str, Any]) -> str:
    """Derive the reproduction status from the verification signals ARGUS already
    produced (Gap #2 browser result, operational evidence tag, compromise state).
    Pure."""
    bv  = _g(finding, "browser_verified")
    tag = str(_g(finding, "evidence_tag") or "").upper()
    sig = (_g(finding, "severity_signals") or finding.get("signals") or {})
    comp = str((sig or {}).get("compromise") or "").lower()

    if bv is True or tag == "DEMONSTRATED" or comp in _CRITICAL_COMPROMISE:
        return "reproduced"
    if bv is False:
        return "unreproduced"            # a browser tried and could not prove it
    if tag in ("CONFIRMED", "PUBLIC-EXPLOIT"):
        return "evidence_confirmed"
    if _sev(finding) in _SEV_HIGH:
        return "unreproduced"            # high/critical claim with no verification
    return "na"


def needs_independent_rerun(finding: Dict[str, Any]) -> bool:
    """True for a high/critical finding that has tool evidence but no independent
    confirmation yet — a candidate for an autonomous tool re-run."""
    if _sev(finding) not in _SEV_HIGH:
        return False
    st = repro_status(finding)
    return st in ("evidence_confirmed", "unreproduced")


def apply_repro_status(finding: Dict[str, Any], status: Optional[str] = None) -> Dict[str, Any]:
    """Stamp ``reproduce_status`` and gate an unreproduced high/critical finding
    into the 'unverified' report lane (never dropped).  Pure — mutates + returns."""
    if not isinstance(finding.get("extra"), dict):
        finding["extra"] = {}
    extra = finding["extra"]
    st = status or repro_status(finding)
    extra["reproduce_status"] = st
    if st in ("unreproduced", "failed") and _sev(finding) in _SEV_HIGH:
        extra.setdefault("report_section", "unverified")
        extra.setdefault("unverified_reason",
                         "high/critical finding not independently reproduced")
    return finding


# ── Independent re-run (best-effort) ──────────────────────────────────────────
def _rerunnable_command(finding: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Reconstruct a safe, READ-ONLY re-run command for a tool finding when we can.
    Only idempotent probes are re-run (never a destructive/exploit action)."""
    tool = str(finding.get("tool_used") or finding.get("tool") or "").lower()
    host = finding.get("host") or ""
    port = finding.get("port")
    url  = _g(finding, "url") or ""
    m = re.search(r"https?://[^\s'\"]+", str(finding.get("evidence") or finding.get("raw_output") or ""))
    if not url and m:
        url = m.group(0)
    if url and tool in ("", "curl", "nikto", "nuclei", "httpx", "wafw00f", "web", "ffuf"):
        return {"tool": "curl", "args": f"-sk -m 15 -i {url}"}
    if host and port and tool in ("nmap", "rustscan", "masscan", "nmap_vulners"):
        return {"tool": "nmap", "args": f"-sV -Pn -p {port} {host}"}
    return None


async def reproduce(finding: Dict[str, Any], intel: Dict[str, Any],
                    run_tool: Optional[Callable] = None) -> Dict[str, Any]:
    """Independently re-prove a finding on a SEPARATE path.  Best-effort + never
    raises.  Web → Gap #2 browser verification; tool findings → re-run an
    idempotent probe and re-match the evidence pattern.  Returns
    {reproduced: True|False|None, method, artifacts}."""
    try:
        from agents.web import browser_verify_subagent as _bv
        if _bv.verifiable_class(finding) and _bv.is_browser_available():
            v = await _bv.verify(finding, intel, {})
            r = v.get("verified")
            return {"reproduced": (True if r is True else False if r is False else None),
                    "method": "browser:" + str(v.get("method", "")),
                    "artifacts": v.get("artifacts", []), "reason": v.get("reason", "")}
    except Exception as exc:
        logger.debug("repro browser path failed: %s", exc)

    cmd = _rerunnable_command(finding)
    if cmd is None or run_tool is None:
        return {"reproduced": None, "reason": "no independent re-run available for this finding"}
    try:
        out = await run_tool(cmd["tool"], cmd["args"])
        text = out.get("stdout", "") if isinstance(out, dict) else str(out or "")
        if _evidence_reappears(finding, text):
            return {"reproduced": True, "method": f"rerun:{cmd['tool']}",
                    "reason": "evidence re-appeared on an independent run"}
        return {"reproduced": False, "method": f"rerun:{cmd['tool']}",
                "reason": "evidence did NOT re-appear on an independent run"}
    except Exception as exc:
        logger.debug("repro tool re-run failed: %s", exc)
        return {"reproduced": None, "reason": f"re-run error: {type(exc).__name__}"}


def _evidence_reappears(finding: Dict[str, Any], rerun_output: str) -> bool:
    """Re-match the original finding's grounding against a fresh tool run, reusing
    the Issue-Validator evidence patterns where available."""
    if not rerun_output:
        return False
    low = rerun_output.lower()
    try:
        from agents.reasoning.issue_validator import EVIDENCE_PATTERNS  # type: ignore
        title = str(finding.get("title") or "").lower()
        for key, pats in (EVIDENCE_PATTERNS or {}).items():
            if key.replace("_", " ") in title or key in title:
                for rx in (pats if isinstance(pats, (list, tuple)) else [pats]):
                    try:
                        if re.search(rx, rerun_output, re.I):
                            return True
                    except Exception:
                        continue
    except Exception:
        pass
    # Fallback: a strong evidence token from the original finding re-appears.
    cve = str(finding.get("cve") or "")
    if cve and cve.lower() in low:
        return True
    ev = str(finding.get("evidence") or "")[:60].strip().lower()
    return bool(ev) and len(ev) > 12 and ev in low
