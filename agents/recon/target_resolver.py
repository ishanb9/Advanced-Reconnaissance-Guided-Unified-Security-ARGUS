"""
target_resolver.py — the single "what do I target?" brain.

ARGUS constantly faces a host that is reachable by IP but whose real web
application is served only on a virtual host (the classic HTB pattern: the
bare IP 302-redirects to http://cctv.htb/).  The correct target DIFFERS by
tool class:

  • NETWORK tools (nmap, ssh, smb, rpc, ldap, …)  → always the IP.
  • WEB tools (curl, whatweb, nikto, nuclei, ffuf, gobuster, sqlmap, the
    web-primer, the WSTG orchestrator)            → the VHOST when one was
    discovered, otherwise the IP.

Historically each web code path built its own URL from the bare IP, so the
moment a target used a vhost the whole web assessment hit a redirect stub and
found nothing.  This module is now the ONE source of truth: every web tool
resolves through ``web_base_url()`` / ``web_host()``; network tools use
``network_ip()``.  The decision is recorded in intel (``record_vhost``) so all
consumers agree, and is summarised by ``decision()`` for operator transparency.

Pure + dependency-free (stdlib only) so it is trivially unit-testable offline.
"""
from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import urlparse

_HTTPS_PORTS = {"443", "8443", "4443", "7443", "9443"}


def network_ip(intel: Dict) -> str:
    """Bare IP/host for NETWORK-level tools (nmap/ssh/smb/rpc).  Never a vhost."""
    return str((intel or {}).get("target") or "").strip()


def web_host(intel: Dict) -> str:
    """Hostname WEB tools should send.

    Priority:
      1. ``intel['web_host']``        — the explicitly-decided vhost
      2. first ``intel['vhosts']``    — any discovered vhost
      3. host of ``intel['target_url']``
      4. the bare IP                  — no vhost known
    """
    intel = intel or {}
    wh = str(intel.get("web_host") or "").strip().strip(".")
    if wh:
        return wh
    vhosts = intel.get("vhosts") or []
    if isinstance(vhosts, (list, tuple)) and vhosts:
        cand = str(vhosts[0] or "").strip().strip(".")
        if cand:
            return cand
    tu = str(intel.get("target_url") or "").strip()
    if tu:
        try:
            h = urlparse(tu).hostname
            if h:
                return h
        except Exception:
            pass
    return network_ip(intel)


def uses_vhost(intel: Dict) -> bool:
    """True when the chosen web host is a vhost distinct from the bare IP."""
    wh = web_host(intel)
    ip = network_ip(intel)
    return bool(wh) and wh != ip


def web_base_url(intel: Dict, port=80, scheme: Optional[str] = None) -> str:
    """Canonical base URL for web tools — vhost-aware.  No trailing slash."""
    host = web_host(intel) or network_ip(intel)
    p = str(port).split("/")[0]
    if scheme is None:
        # The PORT decides the scheme first (443→https, 80/8080/…→http); only
        # fall back to the target_url scheme for non-standard ports.
        if p in _HTTPS_PORTS:
            scheme = "https"
        elif p in ("80", "8080", "8000", "8888", "8081", "5000", "5001", "9000"):
            scheme = "http"
        else:
            tu = str((intel or {}).get("target_url") or "").strip()
            scheme = (urlparse(tu).scheme if tu else "") or "http"
    suffix = "" if p in ("80", "443") else (f":{p}" if p.isdigit() else "")
    return f"{scheme}://{host}{suffix}"


def curl_resolve_args(intel: Dict, port=80) -> List[str]:
    """``--resolve vhost:port:ip`` so HTTP reaches the vhost even without an
    /etc/hosts entry.  Empty when no vhost (plain IP target)."""
    wh = web_host(intel)
    ip = network_ip(intel)
    p = str(port).split("/")[0]
    if wh and ip and wh != ip and p.isdigit():
        return ["--resolve", f"{wh}:{p}:{ip}"]
    return []


def record_vhost(intel: Dict, vhost: str, *, ip: Optional[str] = None,
                 verified: bool = False) -> bool:
    """Record a discovered vhost as THE web target in intel (idempotent).

    Centralizes the ``web_host`` / ``target_url`` / ``vhosts`` writes so every
    code path agrees on the decision.  Returns True if this set/added a vhost.
    Never overwrites a ``target_url`` that already points at a (different) vhost
    — only when it is unset or still pointing at the bare IP.
    """
    if not isinstance(intel, dict):
        return False
    vhost = (vhost or "").strip().lower().strip(".")
    if not vhost:
        return False
    vh = list(intel.get("vhosts") or [])
    changed = vhost not in vh
    if changed:
        vh.append(vhost)
    intel["vhosts"] = vh
    # Only (re)set the primary web_host when this is a verified pick or none is
    # set yet — a secondary unverified vhost must not downgrade the primary.
    if verified or not str(intel.get("web_host") or "").strip():
        intel["web_host"] = vhost
        ip = (ip or network_ip(intel)).strip()
        cur = str(intel.get("target_url") or "").strip()
        if not cur or (ip and ip in cur):
            intel["target_url"] = f"http://{vhost}/"
    if verified:
        intel["web_host_verified"] = True
    return changed


def decision(intel: Dict) -> Dict:
    """Human-readable summary of the current IP-vs-vhost decision."""
    ip = network_ip(intel)
    wh = web_host(intel)
    return {
        "network_ip": ip,
        "web_host":   wh,
        "web_base":   web_base_url(intel, 80),
        "uses_vhost": bool(wh) and wh != ip,
        "verified":   bool((intel or {}).get("web_host_verified")),
    }


__all__ = [
    "network_ip", "web_host", "uses_vhost", "web_base_url",
    "curl_resolve_args", "record_vhost", "decision",
]
