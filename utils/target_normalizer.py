"""utils/target_normalizer.py — One-stop target classification + normalisation.

The platform was originally written assuming `target` is always an IP
address.  Operators in the field need to start engagements from any of
these target shapes:

    1. IPv4 / IPv6:    ``10.10.10.42``,  ``2001:db8::1``
    2. CIDR block:     ``10.10.10.0/24`` (CIDROrchestrator handles the expansion)
    3. Hostname:       ``app.corp.local``,  ``ad.example.com``
    4. URL:            ``https://app.example.com/api/v2/users``
    5. Application:    same as URL but explicitly tagged so the planner
                       knows to skip network-layer probes and focus on
                       app-level testing (auth, RBAC, business logic).

This module produces a normalised ``NormalisedTarget`` carrying:

    .raw              the operator's original input
    .kind             one of: ``ip`` | ``cidr`` | ``hostname`` | ``url`` | ``app``
    .host             clean host string (no scheme, no path) for nmap / SMB / SSH
    .url              full URL when input was a URL, else None
    .port             explicit port from URL when given (else None)
    .scheme           ``http`` / ``https`` / None
    .resolved_ip      best-effort A-record resolution; None when DNS fails
    .scope_hosts      list of host strings that should be considered IN scope
                      (host + resolved_ip + the URL's host).  Used by the
                      scope guard to validate downstream tool dispatches.

The module never raises on unparseable input — it falls back to ``hostname``
classification and lets the existing CIDROrchestrator + nmap handle the
final arbitration.  This keeps the existing IP/CIDR happy path bit-exact
while strictly extending behaviour for new shapes.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse


__all__ = ["NormalisedTarget", "normalise_target"]


# ── Patterns ──────────────────────────────────────────────────────────────
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+"
    r"(?:[A-Za-z]{2,63})$"
)
_URL_RE      = re.compile(r"^https?://", re.IGNORECASE)
_CIDR_RE     = re.compile(r"^[0-9.:a-fA-F]+/\d{1,3}$")
_MULTI_RE    = re.compile(r"\s*,\s*")
_PORT_RE     = re.compile(r":(\d{1,5})$")


@dataclass
class NormalisedTarget:
    raw:         str                   = ""
    kind:        str                   = "hostname"   # ip|cidr|hostname|url|app
    host:        str                   = ""
    url:         Optional[str]         = None
    port:        Optional[int]         = None
    scheme:      Optional[str]         = None
    resolved_ip: Optional[str]         = None
    scope_hosts: List[str]             = field(default_factory=list)

    @property
    def is_url(self) -> bool: return self.kind in ("url", "app")
    @property
    def is_cidr(self) -> bool: return self.kind == "cidr"
    @property
    def is_ip(self) -> bool: return self.kind == "ip"
    @property
    def is_hostname(self) -> bool: return self.kind == "hostname"

    def to_dict(self) -> dict:
        return {
            "raw":         self.raw,
            "kind":        self.kind,
            "host":        self.host,
            "url":         self.url,
            "port":        self.port,
            "scheme":      self.scheme,
            "resolved_ip": self.resolved_ip,
            "scope_hosts": list(self.scope_hosts),
        }

    def primary_for_tools(self) -> str:
        """The string to substitute into ``{target}`` placeholders for tools
        that operate at the network layer (nmap, SMB, SSH).  For URL/app
        targets we strip back to host so port-scans hit the right address.
        For CIDR we return the original spec (CIDROrchestrator handles it).
        """
        if self.is_cidr:
            return self.raw
        return self.host or self.raw

    def primary_url(self) -> Optional[str]:
        """The full URL to feed into web-aware tools (whatweb, sqlmap,
        nuclei, gobuster, ffuf).  Synthesised from host + scheme/port when
        the operator gave only a hostname."""
        if self.url:
            return self.url
        if self.host:
            scheme = self.scheme or "http"
            port_part = ""
            if self.port and self.port not in (80, 443):
                port_part = f":{self.port}"
            return f"{scheme}://{self.host}{port_part}/"
        return None


# ── Resolution helpers ────────────────────────────────────────────────────
def _try_resolve(host: str) -> Optional[str]:
    """Best-effort A-record / AAAA lookup.  Returns the first IP or None."""
    if not host:
        return None
    try:
        info = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC)
        for fam, _, _, _, sockaddr in info:
            ip = sockaddr[0]
            if ip:
                return ip
    except Exception:
        pass
    return None


def _is_ip(s: str) -> bool:
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_cidr(s: str) -> bool:
    if not s or "/" not in s:
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except (ValueError, TypeError):
        return False


# ── Main normaliser ───────────────────────────────────────────────────────
def normalise_target(
    raw: str,
    *,
    target_type_hint: Optional[str] = None,
    resolve_dns:      bool          = True,
) -> NormalisedTarget:
    """Classify and normalise an arbitrary operator-supplied target string.

    ``target_type_hint`` may be ``"app"`` to force application-mode for a
    URL (skips host-port probes when the operator explicitly only wants
    web-app testing).  Any other value falls back to auto-classification.
    """
    raw_str = (raw or "").strip()
    out = NormalisedTarget(raw=raw_str)

    if not raw_str:
        return out  # empty — caller decides what to do

    # 1. Multi-target — caller (CIDROrchestrator) parses; we look at the first
    if "," in raw_str:
        first = raw_str.split(",", 1)[0].strip()
        # Recurse on the first component only — the orchestrator will iterate
        return normalise_target(
            first, target_type_hint=target_type_hint, resolve_dns=resolve_dns,
        )

    # 2. CIDR
    if _is_cidr(raw_str):
        out.kind = "cidr"
        out.host = raw_str
        out.scope_hosts = [raw_str]
        return out

    # 3. URL (must look like http(s)://...)
    if _URL_RE.match(raw_str):
        try:
            parsed = urlparse(raw_str)
            host   = (parsed.hostname or "").strip()
            scheme = (parsed.scheme   or "").lower() or None
            port   = parsed.port
            out.kind   = "app" if (target_type_hint or "").lower() == "app" else "url"
            out.host   = host
            out.url    = raw_str
            out.port   = port
            out.scheme = scheme
        except Exception:
            # Fall through to hostname interpretation
            out.kind = "hostname"
            out.host = raw_str
    # 4. IP (rare bare address but support it)
    elif _is_ip(raw_str):
        out.kind = "ip"
        out.host = raw_str
    # 5. host:port shorthand (e.g. ad.example.com:8443)
    elif _PORT_RE.search(raw_str):
        m = _PORT_RE.search(raw_str)
        host_only = raw_str[:m.start()]
        port_only = int(m.group(1))
        if _is_ip(host_only):
            out.kind = "ip"
        elif _HOSTNAME_RE.match(host_only):
            out.kind = "hostname"
        else:
            out.kind = "hostname"   # permissive — single-label hostnames OK
        out.host = host_only
        out.port = port_only
        out.scheme = "https" if port_only in (443, 8443) else ("http" if port_only in (80, 8080) else None)
    # 6. Hostname (FQDN or single-label)
    else:
        out.kind = "hostname"
        out.host = raw_str

    # Resolve DNS if applicable + scope_hosts assembly
    if resolve_dns and out.kind in ("hostname", "url", "app"):
        out.resolved_ip = _try_resolve(out.host)

    out.scope_hosts = _build_scope(out)

    return out


def _build_scope(t: NormalisedTarget) -> List[str]:
    """Produce the in-scope host list for the scope guard.  We include:
      * the canonical host
      * the resolved IP (if DNS succeeded)
      * the URL's host (already covered, but kept for explicitness)
    """
    scope: List[str] = []
    if t.host:
        scope.append(t.host.lower())
    if t.resolved_ip and t.resolved_ip not in scope:
        scope.append(t.resolved_ip)
    if t.url:
        try:
            u = urlparse(t.url)
            if u.hostname and u.hostname.lower() not in scope:
                scope.append(u.hostname.lower())
        except Exception:
            pass
    return scope
