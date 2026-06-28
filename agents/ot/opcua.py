"""agents/ot/opcua.py — read-only OPC-UA capability module (Tier-2 active speaker).

OPC-UA is the modern, IP-native OT protocol most amenable to IT-style testing.
``detect`` is a passive 4840/tcp fingerprint (registry-driven, safe). ``safe_probe``
is an OPTIONAL, read-only opc.tcp HELLO/ACK handshake the operator may invoke under
an authorized engagement — it sends only a connection HELLO (no session, no writes)
and confirms the server speaks opc.tcp.  Never writes; never auto-run by the scan.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

OPCUA_PORT = 4840
SAFETY_CLASS = "safe"
_BANNERS = ("opc.tcp", "opcua", "opc-ua", "opc ua")


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
    if OPCUA_PORT not in ports and not any(b in blob for b in _BANNERS):
        return None
    return {
        "technology": "OPC-UA", "domain": "OT", "safety_class": SAFETY_CLASS,
        "ports": [OPCUA_PORT] if OPCUA_PORT in ports else [],
        "evidence": (f"{OPCUA_PORT}/tcp (opc.tcp)" if OPCUA_PORT in ports else "opc.tcp banner"),
        "capability": "agents/ot/opcua",
        "hint": ("Read-only OPC-UA enumeration: opc.tcp HELLO/ACK → GetEndpoints; check for "
                 "anonymous access + SecurityPolicy None + cert-trust misconfig (OpalOPC / "
                 "Claroty Team82). Session writes / method calls are GATED (intrusive)."),
    }


def finding_for(detection: Dict[str, Any]) -> Dict[str, Any]:
    return {
        # Detecting an OPC-UA server is an OBSERVATION → INFO. HIGH is reserved
        # for confirmed anonymous access / SecurityPolicy None at probe time.
        "severity": "info",
        "inherent_risk": "high",
        "title": "OPC-UA server exposed (OT)",
        "description": ("An OPC-UA server was detected (" + detection.get("evidence", "")
                        + "). OPC-UA is the modern OT control protocol; exposed servers frequently "
                        "permit anonymous sessions with SecurityPolicy None, leaking the address "
                        "space and (with writes) allowing process control. Enumerate read-only first."),
        "evidence": detection.get("evidence", ""),
        "remediation": ("Require an authenticated SecurityPolicy (Basic256Sha256+), disable "
                        "anonymous + None endpoints, enforce certificate trust, and segment OT from "
                        "IT/user networks; track vendor + CISA ICS advisories."),
        "tool_used": "agents.ot.opcua", "mitre": "T0846",
    }


async def safe_probe(host: str, port: int = OPCUA_PORT, timeout: float = 4.0) -> Dict[str, Any]:
    """OPTIONAL read-only opc.tcp HELLO/ACK handshake (no session, no writes).
    Returns {"protocol":"opc.tcp","ack":True} when the server ACKs, else {}.
    Never raises; sends only a connection HELLO.  Not called automatically."""
    import asyncio

    def _hello() -> Dict[str, Any]:
        import socket, struct
        try:
            endpoint = f"opc.tcp://{host}:{port}".encode("utf-8")
            body = (struct.pack("<IIIII", 0, 65536, 65536, 0, 0)
                    + struct.pack("<i", len(endpoint)) + endpoint)
            msg = b"HELF" + struct.pack("<I", 8 + len(body)) + body
            s = socket.create_connection((host, port), timeout=timeout)
            try:
                s.settimeout(timeout)
                s.sendall(msg)
                resp = s.recv(512) or b""
            finally:
                s.close()
            if resp[:3] == b"ACK":
                return {"protocol": "opc.tcp", "ack": True, "raw": resp[:8].hex()}
            if resp[:3] == b"ERR":
                return {"protocol": "opc.tcp", "ack": False, "error": resp[:8].hex()}
            return {}
        except Exception:
            return {}

    try:
        return await asyncio.to_thread(_hello)
    except Exception:
        return {}
