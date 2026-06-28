"""agents/ot/bacnet.py — read-only BACnet/IP capability module (Tier-2 active speaker).

BACnet/IP is the flagship building-automation OT protocol (47808/udp). ``detect``
is a passive fingerprint (registry-driven, safe). ``safe_probe`` is an OPTIONAL,
read-only **Who-Is** broadcast/unicast the operator may invoke under an authorized
engagement — it asks devices to identify themselves (I-Am) and writes nothing.
WriteProperty (actuates HVAC / fire / access) is GATED and never emitted here.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

BACNET_PORT = 47808          # 0xBAC0
SAFETY_CLASS = "safe"
_BANNERS = ("bacnet", "bac0", "bacnet/ip")


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
    if not isinstance(intel, dict):
        return None
    ports = set(_ports(intel))
    blob = " ".join(
        f"{(p.get('service') if isinstance(p, dict) else '')} {(p.get('version') if isinstance(p, dict) else '')}"
        for p in (intel.get("open_ports") or [])).lower()
    if BACNET_PORT not in ports and not any(b in blob for b in _BANNERS):
        return None
    return {
        "technology": "BACnet/IP", "domain": "OT", "safety_class": SAFETY_CLASS,
        "ports": [BACNET_PORT] if BACNET_PORT in ports else [],
        "evidence": (f"{BACNET_PORT}/udp (BACnet/IP)" if BACNET_PORT in ports else "BACnet banner"),
        "capability": "agents/ot/bacnet",
        "hint": ("Read-only BACnet enumeration: Who-Is → I-Am device inventory, then "
                 "ReadProperty(Device) → vendor/model/firmware/location (nmap bacnet-info / BAC0). "
                 "WriteProperty actuates HVAC / fire / access and is GATED (disruptive)."),
    }


def finding_for(detection: Dict[str, Any]) -> Dict[str, Any]:
    return {
        # Reachability of a BACnet/IP endpoint is an OBSERVATION → INFO. HIGH is
        # reserved for a confirmed Who-Is inventory leak / writable object.
        "severity": "info",
        "inherent_risk": "high",
        "title": "BACnet/IP building-automation interface exposed (OT)",
        "description": ("A BACnet/IP endpoint was detected (" + detection.get("evidence", "")
                        + "). BACnet is stateless and unauthenticated: a single Who-Is yields a full "
                        "device inventory, and WriteProperty can override setpoints, unlock doors, or "
                        "disable fire alarms. Enumerate read-only (Who-Is/ReadProperty) only."),
        "evidence": detection.get("evidence", ""),
        "remediation": ("Place BACnet on an isolated building-automation VLAN with no inbound access "
                        "from IT/user networks; deploy a BACnet Secure Connect (BACnet/SC) gateway "
                        "where supported; restrict UDP/47808; flag life-safety objects as no-actuation."),
        "tool_used": "agents.ot.bacnet", "mitre": "T0846",
    }


async def safe_probe(host: str, port: int = BACNET_PORT, timeout: float = 3.0) -> Dict[str, Any]:
    """OPTIONAL read-only BACnet Who-Is (unicast). Returns {"bacnet":True,...} when an
    I-Am-style response is observed, else {}. Writes nothing; never raises; not auto-run."""
    import asyncio

    def _whois() -> Dict[str, Any]:
        import socket
        # BVLC(0x81 Original-Unicast-NPDU, len) + NPDU(version, control) + APDU(Unconfirmed-Req, Who-Is)
        pkt = bytes([0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08])
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (host, port))
            data, _addr = s.recvfrom(1500)
            # An I-Am reply is a BACnet/IP frame (BVLC 0x81) carrying APDU 0x10 0x00 (I-Am).
            if data and data[0] == 0x81:
                return {"bacnet": True, "raw": data[:12].hex()}
            return {}
        except Exception:
            return {}
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass

    try:
        return await asyncio.to_thread(_whois)
    except Exception:
        return {}
