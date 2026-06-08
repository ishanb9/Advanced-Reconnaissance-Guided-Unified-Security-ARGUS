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

# Per-HOST liveness: after this many CONSECUTIVE "host not responding" tool
# runs (timeout / unreachable / connect-failed) with no success in between,
# the host is treated as down (gone, firewalled, or rate-limiting us).  The
# reasoning loop uses this to STOP flailing against a black-holed target.
HOST_UNREACHABLE_THRESH = int(os.environ.get("ARGUS_HOST_UNREACHABLE_THRESH", "5"))

# Operator-cancel circuit breaker: this many tool kills in a row (within the
# TTL, with no successful tool in between) means "stop auto-firing tools the
# operator keeps killing."
CANCEL_STREAK_THRESH = int(os.environ.get("ARGUS_CANCEL_STREAK_THRESH", "2"))
CANCEL_STREAK_TTL    = float(os.environ.get("ARGUS_CANCEL_STREAK_TTL", "300"))

# curl's timeout exit code is 28; GNU `timeout` / the MCP watchdog use 124.
# These have NO matching stderr text (curl -s -m exits silently), so they must
# be recognised by exit code, not regex.
_TIMEOUT_EXIT_CODES = {28, 124}

# Reasons that mean "the host did not answer" (vs. refused/reset, which prove
# the host IS up).  Only these advance the per-host liveness counter.
_LIVENESS_DOWN_REASONS = {"timeout", "unreachable", "no_route", "connect_failed"}


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
    # ── Timeout / unreachable text ARGUS actually emits (was previously
    #    UNMATCHED, so a black-holed host never got marked dead) ──
    (re.compile(r"\bread ?timeout\b",         re.I), "timeout"),
    (re.compile(r"\[timeout\]",               re.I), "timeout"),
    (re.compile(r"\btimed out\b",             re.I), "timeout"),
    (re.compile(r"execution expired",         re.I), "timeout"),
    (re.compile(r"max retries exceeded",      re.I), "timeout"),
    (re.compile(r"connecttimeout",            re.I), "timeout"),
    (re.compile(r"\[agent error\][^\n]*timeout", re.I), "timeout"),
    (re.compile(r"failed to establish a new connection", re.I), "connect_failed"),
    (re.compile(r"appears to be down",        re.I), "unreachable"),
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


@dataclass
class _HostLive:
    """Per-host liveness: consecutive 'host did not answer' runs."""
    consec_fail:  int   = 0
    last_fail_ts: float = 0.0
    last_ok_ts:   float = 0.0


@dataclass
class _CancelRec:
    """Per-host operator-cancel streak."""
    streak:  int   = 0
    last_ts: float = 0.0


class ToolBlacklist:
    """Per-(host, service_class) failure tracker + per-host liveness/cancel."""

    def __init__(self) -> None:
        self._recs: Dict[Tuple[str, str], _FailRec] = {}
        self._sticky: Dict[Tuple[str, str], str] = {}  # explicit "this is closed"
        self._host_live: Dict[str, _HostLive] = {}      # per-host liveness
        self._cancels:   Dict[str, _CancelRec] = {}      # per-host cancel streak

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
        # Operator cancellation (-2) is NEITHER success NOR host failure — it is
        # an operator action.  It must not reset liveness or inflate failures;
        # cancels are tracked separately via record_cancel().
        if exit_code == -2:
            return None
        haystack = (stderr or "") + "\n" + (stdout or "")
        svc = _classify_service(tool, port)
        key = (host, svc)

        # Determine failure reason: timeout exit codes first (curl 28 / timeout
        # 124 emit NO matching text), then the text patterns.
        reason: Optional[str] = None
        if exit_code in _TIMEOUT_EXIT_CODES:
            reason = "timeout"
        else:
            for pat, name in _HARD_FAILURE_PATTERNS:
                if pat.search(haystack):
                    reason = name
                    break

        if exit_code == 0 and reason is None:
            # Clean success — clear failure record for this surface AND reset
            # the per-host liveness + cancel streak (the host is demonstrably up).
            self._recs.pop(key, None)
            live = self._host_live.get(host)
            if live:
                live.consec_fail = 0
                live.last_ok_ts  = time.time()
            self._cancels.pop(host, None)
            return None

        if reason is None:
            return None

        rec = self._recs.setdefault(key, _FailRec())
        rec.count += 1
        rec.last_ts = time.time()
        rec.reasons[reason] += 1

        # Per-host liveness: only "host did not answer" reasons count toward the
        # unreachable verdict (a refused/reset connection proves the host IS up).
        if reason in _LIVENESS_DOWN_REASONS:
            live = self._host_live.setdefault(host, _HostLive())
            live.consec_fail += 1
            live.last_fail_ts = time.time()

        logger.debug("[blacklist] %s/%s fail (%s) count=%d", host, svc, reason, rec.count)
        return reason

    # ── Per-host liveness ────────────────────────────────────────────
    def host_unreachable(self, host: str, thresh: Optional[int] = None) -> bool:
        """True when `host` has gone dark — N consecutive no-answer runs with no
        success in between, within the TTL."""
        live = self._host_live.get(host)
        if not live or live.consec_fail <= 0:
            return False
        if time.time() - live.last_fail_ts > BLACKLIST_TTL_SEC:
            return False
        return live.consec_fail >= (thresh if thresh is not None else HOST_UNREACHABLE_THRESH)

    def consecutive_host_failures(self, host: str) -> int:
        live = self._host_live.get(host)
        if not live:
            return 0
        if time.time() - live.last_fail_ts > BLACKLIST_TTL_SEC:
            return 0
        return live.consec_fail

    # ── Operator-cancel streak ───────────────────────────────────────
    def record_cancel(self, host: str) -> int:
        """Record an operator tool-kill against `host`; returns the streak."""
        if not host:
            return 0
        c = self._cancels.get(host)
        now = time.time()
        if c is None or (now - c.last_ts) > CANCEL_STREAK_TTL:
            c = _CancelRec()
            self._cancels[host] = c
        c.streak += 1
        c.last_ts = now
        return c.streak

    def consecutive_cancels(self, host: str) -> int:
        c = self._cancels.get(host)
        if not c:
            return 0
        if (time.time() - c.last_ts) > CANCEL_STREAK_TTL:
            return 0
        return c.streak

    def cancel_streak_tripped(self, host: str) -> bool:
        return self.consecutive_cancels(host) >= CANCEL_STREAK_THRESH

    def reset_cancels(self, host: str) -> None:
        self._cancels.pop(host, None)

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
            self._host_live.clear()
            self._cancels.clear()
            return n
        keys = [k for k in self._recs if k[0] == host]
        for k in keys:
            self._recs.pop(k, None)
        sticky_keys = [k for k in self._sticky if k[0] == host]
        for k in sticky_keys:
            self._sticky.pop(k, None)
        self._host_live.pop(host, None)
        self._cancels.pop(host, None)
        return len(keys) + len(sticky_keys)


_BLACKLIST: Optional[ToolBlacklist] = None


def get_blacklist() -> ToolBlacklist:
    global _BLACKLIST
    if _BLACKLIST is None:
        _BLACKLIST = ToolBlacklist()
    return _BLACKLIST


__all__ = ["ToolBlacklist", "get_blacklist"]
