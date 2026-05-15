"""
tool_blacklist.py - per-target tool-failure feedback loop.

Why this exists
---------------
The LLM keeps re-proposing tools that have already failed against a
given target.  Looking at the operator's session log, smbclient
returned NT_STATUS_CONNECTION_REFUSED at 19:18:46, then ARGUS spent
the next 20 minutes considering more SMB tools because the master
planner has no notion of "we already tried that and it doesn't work."

This module is the missing memory layer.  When a tool fails on a
target (connection refused, host unreachable, auth failed in a way
that means the service is closed), we record:

    (host, port, service_class) -> failure_reason

and the master planner can ask `is_dead(host, port)` before proposing
a tool against that surface.

Definitions of "dead"
---------------------
A target/service combination is considered dead if ANY of:
  - 3+ recent tool runs returned a hard-network failure
    (ConnectionRefused, HostUnreachable, NoRouteToHost, Timeout
     with zero bytes received)
  - The service has been explicitly marked dead by a nmap rescan
    that shows the port closed/filtered

Note: "tool returned no findings" is NOT dead.  A clean exit with
no output just means there was nothing to find, not that the surface
is unreachable.

Reset semantics
---------------
The blacklist is per-target + per-service, and decays after
BLACKLIST_TTL_SEC (default 30 min).  Long scans where a service
flaps in and out (firewalled bursts, rate-limited target) recover
automatically.
"""
from __future__ import annotations

import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


BLACKLIST_TTL_SEC      = int(os.environ.get("TOOL_BLACKLIST_TTL_SEC", "1800"))
BLACKLIST_FAIL_THRESH  = int(os.environ.get("TOOL_BLACKLIST_FAIL_THRESH", "3"))


# Failure patterns - if any match the stderr or stdout, count as
# hard-network failure.  Each entry: (regex, normalised_reason).
_HARD_FAILURE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"connection refused",        re.I), "connection_refused"),
    (re.compile(r"no route to host",          re.I), "no_route"),
    (re.compile(r"host (is )?(un)?reachable", re.I), "unreachable"),
    (re.compile(r"name or service not known", re.I), "dns_failure"),
    (re.compile(r"name resolution failed",    re.I), "dns_failure"),
    (re.compile(r"connection (timed out|timeout)", re.I), "timeout"),
    (re.compile(r"could not resolve",         re.I), "dns_failure"),
    (re.compile(r"NT_STATUS_CONNECTION_REFUSED", re.I), "connection_refused"),
    (re.compile(r"NT_STATUS_HOST_UNREACHABLE",  re.I), "unreachable"),
    (re.compile(r"NT_STATUS_IO_TIMEOUT",        re.I), "timeout"),
    (re.compile(r"connection reset by peer",  re.I), "reset"),
    (re.compile(r"network is unreachable",    re.I), "unreachable"),
    (re.compile(r"failed to connect",         re.I), "connect_failed"),
    (re.compile(r"socket\.error.*errno\s*(111|110|113)", re.I), "connection_refused"),
]


def _classify_service(tool: str, port: Optional[int]) -> str:
    """Map (tool, port) to a coarse service class for blacklist keying.

    Multiple tools probe the same surface (smbmap, smbclient, enum4linux
    all hit SMB).  Keying by service class instead of tool name means
    a refused connection on one teaches every related tool to skip.
    """
    tool = (tool or "").lower()
    if any(t in tool for t in ("smb", "enum4linux", "rpcclient", "lookupsid")):
        return "smb"
    if "snmp" in tool:
        return "snmp"
    if "ldap" in tool:
        return "ldap"
    if "ftp" in tool:
        return "ftp"
    if "ssh" in tool:
        return "ssh"
    if "rdp" in tool or "xfreerdp" in tool or "rdesktop" in tool:
        return "rdp"
    if "winrm" in tool:
        return "winrm"
    if tool in ("redis-cli",) or "redis" in tool:
        return "redis"
    if tool in ("mongosh", "mongo") or "mongo" in tool:
        return "mongodb"
    if "mysql" in tool:
        return "mysql"
    if "mssql" in tool or "sqlcmd" in tool:
        return "mssql"
    if "psql" in tool or "postgres" in tool:
        return "postgresql"
    if tool in ("curl", "wget", "whatweb", "nikto", "gobuster", "feroxbuster",
                "dirsearch", "ffuf", "wfuzz", "wpscan", "nuclei", "katana"):
        # Web tools - key by port if known, otherwise generic http
        if port in (443, 8443):
            return f"https:{port}"
        if port:
            return f"http:{port}"
        return "http"
    return f"{tool}_unknown"


@dataclass
class _FailRec:
    count:        int   = 0
    last_ts:      float = 0.0
    reasons:      Dict[str, int] = field(default_factory=lambda: defaultdict(int))


class ToolBlacklist:
    """Per-(host, service_class) failure tracker."""

    def __init__(self) -> None:
        self._recs: Dict[Tuple[str, str], _FailRec] = {}
        self._sticky: Dict[Tuple[str, str], str] = {}  # explicit "this is closed"

    def record_run(
        self,
        host:      str,
        tool:      str,
        port:      Optional[int],
        exit_code: int,
        stdout:    str,
        stderr:    str,
    ) -> Optional[str]:
        """Examine a finished tool run; if it looks like a hard-network
        failure, increment the counter.  Returns the normalised reason if
        we logged a hit, else None.
        """
        if not host:
            return None
        # Successful runs reset the failure counter for that surface
        haystack = (stderr or "") + "\n" + (stdout or "")
        svc = _classify_service(tool, port)
        key = (host, svc)
        if exit_code == 0 and not any(p.search(haystack) for p, _ in _HARD_FAILURE_PATTERNS):
            # Clean success - clear any prior failure record for this surface
            self._recs.pop(key, None)
            return None

        reason: Optional[str] = None
        for pat, name in _HARD_FAILURE_PATTERNS:
            if pat.search(haystack):
                reason = name
                break
        if reason is None:
            return None
        rec = self._recs.setdefault(key, _FailRec())
        rec.count += 1
        rec.last_ts = time.time()
        rec.reasons[reason] += 1
        logger.debug("[blacklist] %s/%s fail (%s) count=%d", host, svc, reason, rec.count)
        return reason

    def mark_closed(self, host: str, port: int, service: str = "") -> None:
        """Explicit "this port is closed/filtered" from an nmap rescan."""
        svc = _classify_service(service or "", port)
        key = (host, svc)
        self._sticky[key] = "closed"
        logger.info("[blacklist] sticky-closed %s/%s", host, svc)

    def is_dead(self, host: str, tool: str = "", port: Optional[int] = None,
                service: str = "") -> bool:
        """Should we skip dispatching `tool` against (host, port)?"""
        svc = service if service else _classify_service(tool, port)
        key = (host, svc)
        if key in self._sticky:
            return True
        rec = self._recs.get(key)
        if not rec:
            return False
        if time.time() - rec.last_ts > BLACKLIST_TTL_SEC:
            # Decay
            self._recs.pop(key, None)
            return False
        return rec.count >= BLACKLIST_FAIL_THRESH

    def summary(self) -> List[Dict[str, str]]:
        """Snapshot for UI / debug.  One row per blacklisted surface."""
        out = []
        for (host, svc), rec in self._recs.items():
            if rec.count >= BLACKLIST_FAIL_THRESH:
                out.append({
                    "host":    host,
                    "service": svc,
                    "count":   rec.count,
                    "reasons": ",".join(f"{k}={v}" for k, v in rec.reasons.items()),
                    "age_sec": int(time.time() - rec.last_ts),
                })
        for (host, svc), state in self._sticky.items():
            out.append({"host": host, "service": svc, "state": state, "count": -1})
        return out

    def clear(self, host: Optional[str] = None) -> int:
        """Wipe records.  If host given, only that host.  Returns count cleared."""
        if host is None:
            n = len(self._recs) + len(self._sticky)
            self._recs.clear()
            self._sticky.clear()
            return n
        keys = [k for k in self._recs if k[0] == host]
        for k in keys:
            self._recs.pop(k, None)
        sticky_keys = [k for k in self._sticky if k[0] == host]
        for k in sticky_keys:
            self._sticky.pop(k, None)
        return len(keys) + len(sticky_keys)


_BLACKLIST: Optional[ToolBlacklist] = None


def get_blacklist() -> ToolBlacklist:
    global _BLACKLIST
    if _BLACKLIST is None:
        _BLACKLIST = ToolBlacklist()
    return _BLACKLIST


__all__ = ["ToolBlacklist", "get_blacklist"]
