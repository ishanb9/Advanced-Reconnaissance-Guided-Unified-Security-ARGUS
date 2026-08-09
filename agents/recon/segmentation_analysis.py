"""agents/recon/segmentation_analysis.py — E2 cross-host/segmentation/architectural analysis
and E3 out-of-scope surface discovery.  Pure functions over CAPTURED observations, so they are
unit-testable with mocked reachability results and multicast frames — no network required.

E2: emit a SYSTEMIC finding ONLY when a real cross-segment reachability / internal-DNS
    resolution / multicast leak is DEMONSTRATED (the record carries captured evidence) and the
    two endpoints are in DIFFERENT segments, all within the authorized scope.
E3: list an asset that was PASSIVELY observed (multicast / DNS answer / ARP / route hint) but
    is NOT in the authorized scope, as "observed out-of-scope — recommend adding to scope".
    E3 never probes; it only reports what was already seen.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional


def _seg_label(ip: str, segments: Optional[List[str]] = None) -> str:
    """Return the segment label for an IP: the matching CIDR from ``segments`` if given, else
    the /24 the address falls in.  Non-IP inputs return the raw string (best-effort)."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return str(ip)
    for cidr in (segments or []):
        try:
            if addr in ipaddress.ip_network(str(cidr), strict=False):
                return str(cidr)
        except ValueError:
            continue
    try:
        return str(ipaddress.ip_network(f"{addr}/24", strict=False))
    except ValueError:
        return str(ip)


def _sensitive_port(port: Any) -> bool:
    try:
        p = int(str(port).split("/")[0])
    except (ValueError, TypeError):
        return False
    # management / lateral-movement / control ports whose cross-segment reachability matters most
    return p in {22, 23, 135, 139, 445, 389, 636, 3389, 5985, 5986, 623, 502, 47808, 102,
                 1433, 3306, 5432, 6443, 2375, 161, 8291, 4786, 830}


def analyze_segmentation(
    *,
    reachability: Optional[List[Dict[str, Any]]] = None,
    leaks: Optional[List[Dict[str, Any]]] = None,
    segments: Optional[List[str]] = None,
    scope_hosts: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Correlate captured cross-segment observations into first-class SYSTEMIC findings.

    ``reachability`` records: {from_host, to_host, port, service, reachable(bool),
        evidence(str), resolved_name(optional)}.  A record only yields a finding when
        ``reachable`` is True AND ``evidence`` is non-empty AND the endpoints are in different
        segments — i.e. the segmentation weakness is DEMONSTRATED, never inferred.
    ``leaks`` records: {proto: mdns|ssdp|llmnr|nbns, src, observer, name, evidence}.
    ``scope_hosts`` (optional): when given, BOTH reachability endpoints (and a leak's observer)
        must be IN the authorized scope for a systemic finding — an out-of-scope endpoint is
        never named as an in-scope systemic issue (it belongs to E3's out-of-scope report).
    """
    from knowledge.safety_governor import host_in_scope
    _scope = [str(h).strip() for h in (scope_hosts or []) if str(h).strip()]
    def _in_scope(h: str) -> bool:
        return (not _scope) or host_in_scope(str(h), _scope)   # no scope given -> pure-eval mode
    out: List[Dict[str, Any]] = []
    for r in (reachability or []):
        if not (r.get("reachable") and str(r.get("evidence") or "").strip()):
            continue
        fh, th = str(r.get("from_host") or ""), str(r.get("to_host") or "")
        fs, ts = _seg_label(fh, segments), _seg_label(th, segments)
        if not fh or not th or fs == ts:
            continue                    # same segment (or unknown) — not a segmentation issue
        if not (_in_scope(fh) and _in_scope(th)):
            continue                    # an out-of-scope endpoint is not an in-scope systemic finding
        port = r.get("port")
        rname = str(r.get("resolved_name") or "")
        is_dns = (str(r.get("service") or "").lower() == "dns" or str(port) in ("53",)) and rname
        if is_dns:
            out.append({
                "title": f"Internal DNS resolvable from a lower-trust segment ({fs} → {th})",
                "severity": "medium", "category": "segmentation",
                "host": th, "systemic": True,
                "description": (f"A host in {fs} resolved the internal name '{rname}' via {th} "
                                f"in {ts}. Internal name resolution across trust boundaries aids "
                                "reconnaissance and lateral movement."),
                "evidence": str(r.get("evidence"))[:2000],
                "remediation": ("Restrict internal DNS to trusted segments; block cross-segment "
                                "DNS (UDP/TCP 53) at the segment boundary; use split-horizon DNS."),
            })
            continue
        sev = "medium" if _sensitive_port(port) else "low"
        out.append({
            "title": f"Cross-segment reachability demonstrated ({fs} → {th}:{port})",
            "severity": sev, "category": "segmentation",
            "host": th, "systemic": True,
            "description": (f"A host in segment {fs} reached {th}:{port} in segment {ts}. "
                            "Segmentation does not isolate these zones as intended; this enables "
                            "lateral movement across the trust boundary."
                            + (" The reached port is a management/control service."
                               if _sensitive_port(port) else "")),
            "evidence": str(r.get("evidence"))[:2000],
            "remediation": ("Enforce inter-segment ACLs/firewall rules to deny this path; "
                            "permit only explicitly required flows between these zones."),
        })
    for l in (leaks or []):
        src, obs = str(l.get("src") or ""), str(l.get("observer") or "")
        ss, os_ = _seg_label(src, segments), _seg_label(obs, segments)
        if not src or not obs or ss == os_ or not str(l.get("evidence") or "").strip():
            continue                    # only a CROSS-segment leak with captured evidence
        if not _in_scope(obs):
            continue                    # the sensor/observer must be an authorized in-scope host
        proto = str(l.get("proto") or "multicast").lower()
        out.append({
            "title": f"Cross-segment {proto.upper()} leakage exposes a device from {ss}",
            "severity": "low", "category": "segmentation",
            "host": src, "systemic": True,
            "description": (f"An observer in {os_} passively captured a {proto} announcement from "
                            f"'{l.get('name') or src}' ({src}) in {ss}. Multicast/broadcast "
                            "discovery is crossing the segment boundary, disclosing devices and "
                            "aiding cross-zone reconnaissance."),
            "evidence": str(l.get("evidence"))[:2000],
            "remediation": (f"Constrain {proto} to its own segment (disable multicast forwarding / "
                            "IGMP snooping leakage between VLANs; block LLMNR/NBNS via GPO)."),
        })
    return out


def discover_out_of_scope(
    *,
    observed: Optional[List[Dict[str, Any]]] = None,
    scope_hosts: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Report (never test) assets that were PASSIVELY observed but are NOT in the authorized
    scope.  ``observed`` records: {ip, source: mdns|ssdp|arp|dns|route|gateway, name, evidence}.
    Returns report-only findings; performs NO active probing of any asset."""
    from knowledge.safety_governor import host_in_scope
    scope = list(scope_hosts or [])
    seen: Dict[str, Dict[str, Any]] = {}
    for o in (observed or []):
        ip = str(o.get("ip") or "").strip()
        if not ip or host_in_scope(ip, scope):
            continue                    # in-scope assets are handled by the normal pipeline
        rec = seen.setdefault(ip, {"ip": ip, "sources": set(), "names": set(), "evidence": []})
        rec["sources"].add(str(o.get("source") or "passive"))
        if o.get("name"):
            rec["names"].add(str(o.get("name")))
        if o.get("evidence"):
            rec["evidence"].append(str(o.get("evidence"))[:400])
    out: List[Dict[str, Any]] = []
    for ip, rec in sorted(seen.items()):
        names = ", ".join(sorted(rec["names"])) or "(unnamed)"
        srcs = ", ".join(sorted(rec["sources"]))
        out.append({
            "title": f"Observed out-of-scope asset {ip} — recommend adding to scope",
            "severity": "info", "category": "out_of_scope",
            "host": ip, "systemic": True, "in_scope": False, "probed": False,
            "description": (f"Passively observed asset {ip} ('{names}') via {srcs}. It is NOT in "
                            "the authorized scope and was NOT probed. It is reachable/leaking on "
                            "the assessed environment and may warrant inclusion in a future scope."),
            "evidence": " | ".join(rec["evidence"])[:2000],
            "remediation": ("Confirm ownership and, if in-scope for the engagement, add to the "
                            "authorized target list before any active testing; otherwise treat as "
                            "adjacent exposure to segment away."),
        })
    return out
