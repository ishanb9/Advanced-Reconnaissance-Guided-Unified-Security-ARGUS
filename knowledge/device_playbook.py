"""Fingerprint → playbook dispatcher.

The generic web-app battery (WordPress/sqlmap/commix/dalfox/wfuzz/dirb) burns the
whole per-host budget returning HTTP-000 / exit 7 when it is pointed at an OT / IoT /
embedded device — a camera, router/firewall, PBX phone, AV controller, PLC, smart TV —
whose real foothold is a device-specific protocol or CVE, not a web injection.

This router classifies a host (reusing ``agents.reasoning.device_classifier``) and, for
embedded / OT / IoT device classes, recommends SUPPRESSING the generic web sweep and
driving the matched device-specific skill playbooks instead
(``knowledge.skill_registry.match_skills`` — MikroTik Winbox, FortiGate CVE checks,
ONVIF/Hikvision, Crestron CTP, r-services, Yealink, Tizen sdb, …).

Additive + revertible: master_agent gates the web phase on
``route_host(intel)['suppress_generic_web']``.  ``ARGUS_DEVICE_ROUTER=0`` disables the
router entirely (behaviour unchanged).  Never raises.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

# Device classes whose real attack surface is NOT a generic web app — for these the
# WordPress/sqlmap/commix battery is suppressed and the device-specific playbook runs.
_SUPPRESS_KINDS = {
    "iot_camera", "iot_printer", "iot_router", "iot_voip", "iot_media",
    "iot_industrial", "iot_smart_home", "network_device", "embedded_generic",
}

# Skill categories that are DEVICE/protocol-specific (not a generic web app).  A strong
# match here (critical/high) suppresses the generic sweep even when the coarse classifier
# calls the host a "web_app" — e.g. a FortiGate SSL-VPN portal looks like a web app but
# its real vector is CVE-2022-40684, not WordPress/sqlmap.
_DEVICE_SKILL_CATS = {
    "network", "security", "ot", "iot", "os", "home", "aviation", "medical", "avot",
}
_STRONG_SEV = {"critical", "high"}

# Minimum classifier confidence before we suppress the (otherwise safe) generic sweep.
_MIN_CONF = float(os.environ.get("ARGUS_DEVICE_ROUTER_MIN_CONF", "0.45") or 0.45)


def _ports_from_intel(intel: Dict[str, Any]) -> List[int]:
    """Ports from intel['open_ports'] (which may hold ints, 'port/proto' strings, or
    whole {'port':..} dicts) plus the keys of intel['services']."""
    out = set()
    for p in (intel.get("open_ports") or []):
        try:
            out.add(int(p.get("port") if isinstance(p, dict) else str(p).split("/")[0]))
        except (TypeError, ValueError, AttributeError):
            continue
    for k in (intel.get("services") or {}):
        try:
            out.add(int(str(k).split("/")[0]))
        except (TypeError, ValueError):
            continue
    return sorted(out)


def route_host(intel: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a host and decide whether to suppress the generic web-app sweep in
    favour of device-specific modules.  Returns a dict with keys: kind, os_family,
    confidence, is_embedded, suppress_generic_web, device_skills[], rationale.
    Never raises — on any failure returns a no-suppress result."""
    result: Dict[str, Any] = {
        "kind": "unknown", "os_family": "unknown", "confidence": 0.0,
        "is_embedded": False, "suppress_generic_web": False,
        "device_skills": [], "rationale": "",
    }
    if os.environ.get("ARGUS_DEVICE_ROUTER", "1") == "0":
        result["rationale"] = "device router disabled (ARGUS_DEVICE_ROUTER=0)"
        return result
    intel = intel or {}

    try:
        from agents.reasoning.device_classifier import classify_device
        cls = classify_device(
            open_ports  = _ports_from_intel(intel),
            services    = intel.get("services") or {},
            os_guess    = intel.get("os_guess") or "",
            web_tech    = list(intel.get("web_tech") or intel.get("technologies") or []),
            banners     = intel.get("banners") or {},
            target_kind = intel.get("target_kind") or "",
            raw_target  = str(intel.get("raw") or intel.get("target_host")
                              or intel.get("target") or ""),
        )
        result["kind"] = cls.kind.value
        result["os_family"] = cls.os_family
        result["confidence"] = round(float(cls.confidence), 3)
    except Exception:
        return result

    # Device-specific skill matches carry the real quick_wins / CVEs to run instead.
    try:
        from knowledge.skill_registry import match_skills, rank_matches
        _m = match_skills(intel) or []
        try:
            _m = rank_matches(_m)
        except Exception:
            pass
        for d in _m[:8]:
            if not isinstance(d, dict):
                continue
            result["device_skills"].append({
                "id":         d.get("id") or d.get("technology") or "",
                "technology": d.get("technology") or "",
                "category":   d.get("category") or "",
                "severity":   str(d.get("severity") or "").lower(),
                "safety":     d.get("safety_class") or "",
                "references": list(d.get("references") or [])[:6],
                "quick_wins": [(q.get("cmd") if isinstance(q, dict) else str(q))
                               for q in (d.get("quick_wins") or [])[:6]],
            })
    except Exception:
        pass

    kind = result["kind"]
    is_embedded = kind in _SUPPRESS_KINDS
    result["is_embedded"] = is_embedded
    # A strong device/protocol-specific skill match (e.g. FortiGate, MikroTik, Crestron)
    # means the real vector is device-specific even if the coarse classifier said web_app.
    _strong_device_skill = any(
        s.get("category") in _DEVICE_SKILL_CATS and s.get("severity") in _STRONG_SEV
        for s in result["device_skills"])
    # Suppress the generic sweep when confidently embedded/OT/IoT, OR when a strong
    # device-specific skill matched.
    result["suppress_generic_web"] = bool(
        (is_embedded and result["confidence"] >= _MIN_CONF) or _strong_device_skill)

    if result["suppress_generic_web"]:
        _sk = ", ".join(s["id"] for s in result["device_skills"][:4]) or "device-specific probes"
        result["rationale"] = (
            f"classified {kind} (conf {result['confidence']:.2f}); the generic web-app "
            f"battery does not apply to this device class — run the device playbook: {_sk}")
    elif is_embedded:
        result["rationale"] = (
            f"classified {kind} but confidence {result['confidence']:.2f} < {_MIN_CONF} — "
            f"generic web sweep retained as a fallback")
    else:
        result["rationale"] = f"classified {kind}; generic web-app playbook applies"
    return result
