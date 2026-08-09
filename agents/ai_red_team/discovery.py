"""discovery.py — shadow-AI / ungoverned-LLM-surface fingerprint (Slice 2).

The *capability-module* side of AI discovery, parallel to ``agents/avot/recon``.
During a NORMAL network engagement (any target_type), ARGUS's capability-scan
hook calls ``detect(intel)`` here; when an exposed AI/LLM/agent surface is found
(Ollama, an OpenAI-compatible API, a vLLM/TGI server, an MCP endpoint, …) it is
recorded as a **shadow-AI governance finding** and the operator is told the
endpoint can be deep-tested by configuring it as an ``target_type="ai"`` target.

Content-agnostic to the engine: every AI-surface signature lives as DATA in
``knowledge/data/ai_security/discovery_signatures.yaml`` — adding a new surface
is a YAML entry, not code.  ``detect`` returns a LIST (a host can expose several
AI surfaces); the engine's registry handles single-dict or list returns.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional


def _token_in_blob(tok, blob: str) -> bool:
    t = str(tok).lower().strip()
    if not t:
        return False
    if any(c in t for c in ":._") and len(t) >= 4:
        return t in blob
    return re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", blob) is not None

_SIG_FILE = (Path(__file__).resolve().parent.parent.parent
             / "knowledge" / "data" / "ai_security" / "discovery_signatures.yaml")

# Code-level false-positive guard (defense-in-depth, independent of the data):
# a port-only match on one of these genuinely-shared web ports does NOT fire a
# detection on its own — it must be corroborated by a banner or HTTP marker.
# Only AI-DEDICATED ports (e.g. 11434 Ollama, 1234 LM Studio, 5001 KoboldCpp,
# 7860 Gradio) fire on a port match alone.
_SHARED_PORTS = {80, 443, 3000, 3001, 4000, 5000, 5005, 8000, 8001, 8002,
                 8080, 8081, 8082, 8265, 8443, 8888, 9000, 9090, 9099}

# intel keys whose string values are worth scanning for HTTP/path/header markers
# (kept narrow so the detector does not false-positive on unrelated text).
_TEXT_KEYS = ("http", "https", "web", "whatweb", "headers", "banners", "http_banners",
              "titles", "server_headers", "web_findings", "http_titles", "tech")


def _load_signatures(root: Optional[str] = None) -> List[Dict[str, Any]]:
    try:
        import yaml  # pyyaml is already a dependency
    except Exception:
        return []
    f = Path(root) if root else _SIG_FILE
    if not f.exists():
        return []
    try:
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or []
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for s in (data if isinstance(data, list) else []):
        if isinstance(s, dict) and s.get("technology") and (
                s.get("ports") or s.get("banners") or s.get("markers")):
            out.append(s)
    return out


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


def _text_blob(intel: Dict[str, Any]) -> str:
    """Aggregate searchable lowercased text from intel for marker matching."""
    parts: List[str] = []
    for _p, svc, ver in _iter_ports(intel):
        parts.append(f"{svc} {ver}")
    for k in _TEXT_KEYS:
        v = intel.get(k)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, tuple)):
            parts.extend(str(x) for x in v)
        elif isinstance(v, dict):
            parts.extend(f"{kk} {vv}" for kk, vv in v.items())
    return " \n ".join(parts).lower()


def detect(intel: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a list of shadow-AI detections for every AI/LLM/agent surface that
    matches a knowledge signature (by port, service banner, or HTTP marker).
    Empty list when nothing matches (never raises)."""
    if not isinstance(intel, dict):
        return []
    sigs = _load_signatures()
    if not sigs:
        return []
    port_index: List = list(_iter_ports(intel))
    open_ports = {p for p, _s, _v in port_index}
    blob = _text_blob(intel)
    out: List[Dict[str, Any]] = []
    for s in sigs:
        evidence: List[str] = []
        hit_ports: List[int] = []
        dedicated_port_hit = False
        for p in (s.get("ports") or []):
            try:
                pi = int(p)
            except Exception:
                continue
            if pi in open_ports:
                hit_ports.append(pi)
                evidence.append(f"{pi}/tcp")
                if pi not in _SHARED_PORTS:
                    dedicated_port_hit = True
        banner_hit = False
        for b in (s.get("banners") or []):
            if b and _token_in_blob(b, blob):
                evidence.append(f"banner:{b}")
                banner_hit = True
        marker_hit = False
        for m in (s.get("markers") or []):
            if m and _token_in_blob(m, blob):
                evidence.append(f"marker:{m}")
                marker_hit = True
        # FIRE only on a dedicated-port hit OR a banner OR an HTTP marker.  A
        # shared-port hit alone (8000/8080/5000/…) is NOT enough — avoids the
        # false positive of flagging any web app on a common port as shadow-AI.
        if not (dedicated_port_hit or banner_hit or marker_hit):
            continue
        out.append({
            "technology": s.get("technology", "AI/LLM surface"),
            "category": s.get("category", "shadow-ai"),
            "ports": sorted(set(hit_ports)),
            "evidence": "; ".join(dict.fromkeys(evidence)),
            "owasp_llm": s.get("owasp_llm", ""),
            "atlas": s.get("atlas", ""),
            "severity": s.get("severity", "medium"),
            "governance": s.get("governance", ""),
            "remediation": s.get("remediation", ""),
            "capability": "agents/ai_red_team",
            "hint": ("Exposed AI/LLM surface — configure it as an AI target "
                     "(target_type='ai') to run the full AI red-team probe catalog "
                     "(prompt injection, jailbreak, system-prompt leak, excessive agency)."),
        })
    return out


def finding_for(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Build a store_finding-shaped record for a shadow-AI detection."""
    tech = detection.get("technology", "AI/LLM surface")
    ev = detection.get("evidence", "")
    owasp = detection.get("owasp_llm", "")
    gov = detection.get("governance") or (
        "An AI/LLM inference or agent surface is reachable on the network. "
        "Ungoverned 'shadow AI' expands the attack surface (prompt injection, "
        "data exfiltration via the model, excessive tool agency) and usually sits "
        "outside the org's AI inventory, monitoring, and access controls.")
    remediation = detection.get("remediation") or (
        "Add the endpoint to the AI inventory; require authentication and "
        "network isolation (no inbound from user/IT networks); enforce egress "
        "allow-listing for any tool/agent capability; rate-limit and log "
        "inference; and red-team it before exposure. Deep-test it in ARGUS by "
        "configuring it as an AI target (target_type='ai').")
    return {
        "severity": detection.get("severity", "medium"),
        "title": f"Shadow AI: {tech} exposed (ungoverned LLM surface)",
        "description": (
            f"{tech} was detected on the network ({ev}). "
            + (f"OWASP-LLM relevance: {owasp}. " if owasp else "")
            + gov + " " + detection.get("hint", "")),
        "evidence": ev,
        "remediation": remediation,
        "tool_used": "ai_red_team.discovery",
        "mitre": detection.get("atlas", "") or "AML.T0040",  # ML Model Inference API Access
    }
