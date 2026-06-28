"""agents/ot/passive_ingest.py — passive OT fingerprinting from a PCAP/SPAN capture.

The GRASSMARLIN doctrine: for fragile OT, prefer to characterise the network from
*observed* traffic with **zero packets sent**.  ``ingest_pcap`` turns a capture file
into an intel-shaped dict (open_ports / services / banners); ``passive_scan`` then runs
the SAME capability fingerprints (the skill registry + the OT code modules) over those
observations — no active probing.  Best-effort: requires scapy for PCAP parsing; returns
an empty result (never raises) if scapy or the file is unavailable.
"""
from __future__ import annotations

from typing import Any, Dict, List

# OT/ICS-relevant ports worth surfacing from passive capture (informational).
_OT_PORTS = {502, 102, 20000, 44818, 47808, 2404, 9600, 4840, 1911, 4911,
             1200, 2455, 11740, 5094, 3671, 1628, 1629, 4059, 13400}


def ingest_pcap(path: str, max_packets: int = 200000) -> Dict[str, Any]:
    """Parse a PCAP into an intel-shaped dict WITHOUT sending any packets.
    Returns {"open_ports":[{port,service,...}], "services":{...}, "passive": True}
    or {} when scapy/the file is unavailable."""
    try:
        from scapy.all import PcapReader, TCP, UDP, IP  # type: ignore
    except Exception:
        return {}
    ports: Dict[int, Dict[str, Any]] = {}
    banners: List[str] = []
    try:
        n = 0
        with PcapReader(path) as pr:
            for pkt in pr:
                n += 1
                if n > max_packets:
                    break
                try:
                    if TCP in pkt:
                        for p in (int(pkt[TCP].sport), int(pkt[TCP].dport)):
                            if p in _OT_PORTS or p < 1024:
                                ports.setdefault(p, {"port": p, "service": "", "protocol": "tcp"})
                        load = bytes(pkt[TCP].payload)[:64]
                        if load:
                            txt = load.decode("latin-1", "ignore").strip()
                            if txt and any(c.isprintable() for c in txt):
                                banners.append(txt)
                    elif UDP in pkt:
                        for p in (int(pkt[UDP].sport), int(pkt[UDP].dport)):
                            if p in _OT_PORTS:
                                ports.setdefault(p, {"port": p, "service": "", "protocol": "udp"})
                except Exception:
                    continue
    except Exception:
        return {}
    if not ports:
        return {}
    return {
        "open_ports": list(ports.values()),
        "services": {str(p): v for p, v in ports.items()},
        "banners": banners[:50],
        "passive": True,
    }


def passive_scan(intel: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run the capability fingerprints over already-observed intel — zero packets.
    Combines the data-driven skill registry with the OT code modules."""
    out: List[Dict[str, Any]] = []
    try:
        from knowledge import skill_registry as _sr
        out.extend(_sr.match_skills(intel))
    except Exception:
        pass
    for _modname in ("agents.ot.modbus", "agents.ot.opcua", "agents.ot.bacnet"):
        try:
            import importlib
            mod = importlib.import_module(_modname)
            det = mod.detect(intel)
            if det:
                out.extend(det if isinstance(det, list) else [det])
        except Exception:
            continue
    return out
