"""avot/recon.py — Crestron AV/OT recon fingerprint + finding hook.

This is the *capability-module* side of the integration: all Crestron-specific
knowledge (ports, banners, the SAST/fuzzer hint, the finding wording) lives
HERE, in the avot package — never in the engine.  The engine calls the generic
``detect()`` / ``finding_for()`` helpers so ARGUS becomes Crestron-aware
without baking AV/OT specifics into master_agent / operator_core.

This is the template for the broader OT/IoT/IT capability-module pattern
(sub-project #5): each domain module exposes a ``detect(intel)`` fingerprint and
a ``finding_for(detection)`` record, and the engine iterates registered
detectors after recon.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Crestron control-system wire protocols (default ports).  CIP = Crestron-over-IP
# control bus; CTP = the text console.  Seeing these on the LAN means a Crestron
# control processor (e.g. a CP4/4-Series) is exposed.
CRESTRON_PORTS: Dict[int, str] = {41794: "CIP", 41795: "CTP/console"}

# Banner/service substrings that also identify Crestron gear (case-insensitive).
_CRESTRON_BANNERS = ("crestron", "cip ", "ctp ", "cp4", "dm-nvx", "am-100", "am-101")

# What ARGUS can DO with a detected Crestron target (the avot capability).
_CAPABILITY_HINT = (
    "agents/avot provides: (1) a SIMPL+/SIMPL# static analyzer — "
    "`python3 agents/avot/sast/simpl_scan.py <program-dir> --fail-on HIGH` "
    "(run it on any supplied integrator code), and (2) a field-aware CIP/CTP "
    "protocol fuzzer — `python3 agents/avot/fuzz/crestron_fuzzer.py <ip> "
    "--device cp4 --model cip --dry-run` (dry-run is SAFE and sends nothing; "
    "live sending needs --authorized + an allowlisted scope on owned lab gear)."
)


def _iter_ports(intel: Dict[str, Any]):
    """Yield (port:int, service:str, version:str) from intel in either shape."""
    for p in (intel.get("open_ports") or []):
        if isinstance(p, dict):
            try:
                yield int(p.get("port")), str(p.get("service") or ""), str(p.get("version") or "")
            except Exception:
                continue
        else:
            try:
                yield int(p), "", ""
            except Exception:
                continue
    svcs = intel.get("services") or {}
    if isinstance(svcs, dict):
        for k, v in svcs.items():
            try:
                port = int(v.get("port") if isinstance(v, dict) and v.get("port") else k)
            except Exception:
                continue
            svc = str((v or {}).get("service") or "") if isinstance(v, dict) else ""
            ver = str((v or {}).get("version") or "") if isinstance(v, dict) else ""
            yield port, svc, ver


def detect(intel: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Content-agnostic-to-the-engine Crestron fingerprint.  Returns a detection
    dict when a Crestron control system is present in ``intel`` (open Crestron
    ports OR a Crestron banner), else None."""
    if not isinstance(intel, dict):
        return None
    hit_ports: List[int] = []
    evidence: List[str] = []
    for port, svc, ver in _iter_ports(intel):
        if port in CRESTRON_PORTS:
            hit_ports.append(port)
            evidence.append(f"{port}/tcp ({CRESTRON_PORTS[port]})")
        blob = f"{svc} {ver}".lower()
        if any(b in blob for b in _CRESTRON_BANNERS):
            evidence.append(f"{port}/tcp banner: {svc} {ver}".strip())
    if not hit_ports and not evidence:
        return None
    return {
        "technology": "Crestron control system",
        "category": "OT",
        "ports": sorted(set(hit_ports)),
        "evidence": "; ".join(dict.fromkeys(evidence)) or "Crestron service signature",
        "capability": "agents/avot",
        "hint": _CAPABILITY_HINT,
    }


def finding_for(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Build a store_finding-shaped record for a Crestron detection."""
    ev = detection.get("evidence", "")
    return {
        # Presence of Crestron control gear = attack surface (INFO). HIGH is
        # reserved for a CONFIRMED issue (default creds / unauth control proven).
        "severity": "info",
        "inherent_risk": "high",
        "title": "Crestron control system exposed (AV/OT)",
        "description": (
            "A Crestron control processor was detected on the network "
            f"({ev}). Crestron gear runs proprietary control protocols (CIP "
            "41794 / CTP 41795) and historically ships exploitable surface "
            "(unauth control, default creds, weak transport). " + detection.get("hint", "")),
        "evidence": ev,
        "remediation": (
            "Isolate AV/OT control gear on a dedicated VLAN with no inbound "
            "access from user/IT networks; disable plaintext CIP/CTP and enforce "
            "TLS + authentication; change default credentials; restrict the "
            "console (CTP/SSH) to a management network; subscribe to Crestron "
            "PSIRT advisories and patch firmware."),
        "tool_used": "avot.recon",
        "mitre": "T0846",  # ICS: Remote System Discovery (Crestron control bus reachable)
    }
