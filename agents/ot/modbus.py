"""agents/ot/modbus.py — read-only Modbus/TCP capability module (Tier-2 exemplar).

Demonstrates an ACTIVE protocol-speaking capability module that is safe-by-default:
detection is a passive 502/tcp fingerprint; the only documented active probe is the
read-only Read-Device-Identification (FC 0x2B / MEI 14). All write function codes are
documented-but-gated (never emitted here). Pattern mirrors agents/avot/recon.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

MODBUS_PORT = 502
SAFETY_CLASS = "safe"


def _ports(intel):
    for p in (intel.get("open_ports") or []):
        try:
            yield (int(p.get("port")) if isinstance(p, dict) else int(p))
        except Exception:
            continue
    for k, v in (intel.get("services") or {}).items():
        try:
            yield int(v.get("port") if isinstance(v, dict) and v.get("port") else k)
        except Exception:
            continue


def detect(intel: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(intel, dict) or MODBUS_PORT not in set(_ports(intel)):
        return None
    return {
        "technology": "Modbus / Modbus-TCP", "domain": "OT", "safety_class": SAFETY_CLASS,
        "ports": [MODBUS_PORT], "evidence": "502/tcp (Modbus MBAP)",
        "capability": "agents/ot/modbus",
        "hint": ("Read-only Modbus enumeration: nmap --script modbus-discover, or FC 0x2B/MEI 14 "
                 "(Read Device ID) — vendor/product/firmware. WRITE FCs 0x05/06/0F/10 are GATED "
                 "(disruptive — actuate the process)."),
    }


def finding_for(detection: Dict[str, Any]) -> Dict[str, Any]:
    return {
        # A reachable Modbus/TCP port is attack surface (INFO). HIGH is reserved
        # for a confirmed unauthenticated register read/write proven via probe.
        "severity": "info",
        "inherent_risk": "high",
        "title": "Modbus/TCP control interface exposed (OT)",
        "description": ("A Modbus/TCP endpoint was detected on 502/tcp (" + detection.get("evidence", "")
                        + "). Modbus has no authentication, encryption, or integrity: any reachable "
                        "client can read process data and (via write function codes) command coils/"
                        "registers. Test read-only by default; writes can shut down a live PLC."),
        "evidence": detection.get("evidence", ""),
        "remediation": ("Isolate OT on a segmented VLAN with no inbound access from IT/user networks; "
                        "front Modbus with an authenticating gateway; disable unused write access; "
                        "monitor 502/tcp; map findings to CISA ICS advisories."),
        "tool_used": "agents.ot.modbus", "mitre": "T0846",
    }
