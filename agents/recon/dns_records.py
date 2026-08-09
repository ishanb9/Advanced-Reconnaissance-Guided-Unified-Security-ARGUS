"""agents/recon/dns_records.py — DNSDumpster-style full DNS record sweep for an apex domain.

Given a domain, collect the record set a tester actually wants before choosing targets:

    A / AAAA      host addresses for the apex
    NS            authoritative nameservers (+ their addresses)
    MX            mail exchangers with priority (+ their addresses)
    TXT           raw TXT, plus the extracted SPF / DMARC / DKIM-ish policies
    SOA           zone authority + serial
    CNAME         apex alias (rare but tells you it is fronted)
    CAA           which CAs may issue — leaks the certificate vendor
    SRV           common service records (_sip, _ldap, _kerberos, ...)
    PTR           reverse lookups for every address discovered
    AXFR          zone-transfer attempt against EVERY nameserver (the single
                  highest-value misconfiguration a DNS sweep can find)
    wildcard      does *.apex resolve (which makes brute-force results noise)

Design
------
* PURE PARSERS.  Every ``parse_*`` function takes text and returns data, so the whole
  sweep is unit-testable against captured ``dig`` output with no network at all.
* INJECTABLE I/O.  ``sweep()`` takes ``tool_runner`` / ``resolver`` callables with the
  same signatures ``subdomain_hunter`` already uses, so tests share one fake.
* READ-ONLY.  Every query is a lookup.  AXFR is a read of a zone the nameserver
  chooses to hand out; nothing here writes, updates or transfers anything else.
* NO NEW DEPENDENCIES — ``dig`` when present, otherwise the stdlib resolver.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shutil
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# (tool, argv, timeout) -> (exit_code, stdout, stderr)   [same shape as subdomain_hunter]
ToolRunner = Callable[[str, List[str], int], Awaitable[Tuple[int, str, str]]]
Resolver = Callable[[str], Awaitable[List[str]]]

# Service records worth probing on a first pass (cheap, high signal).
DEFAULT_SRV = (
    "_sip._tcp", "_sips._tcp", "_ldap._tcp", "_kerberos._tcp", "_kpasswd._tcp",
    "_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp", "_xmpp-client._tcp",
    "_xmpp-server._tcp", "_mysql._tcp", "_vpn._tcp",
)

SIMPLE_TYPES = ("A", "AAAA", "NS", "TXT", "SOA", "CNAME", "CAA")


# ══════════════════════════════════════════════════════════════════════════════
#  PURE PARSERS
# ══════════════════════════════════════════════════════════════════════════════
def parse_short(text: str) -> List[str]:
    """Parse ``dig +short`` output into a de-duplicated, order-preserving list."""
    out: List[str] = []
    for line in (text or "").splitlines():
        v = line.strip()
        if not v or v.startswith(";"):
            continue
        if v not in out:
            out.append(v)
    return out


def parse_mx(text: str) -> List[Dict[str, Any]]:
    """``dig +short MX`` → [{priority, host}] sorted by priority (lowest first)."""
    recs: List[Dict[str, Any]] = []
    for v in parse_short(text):
        parts = v.split()
        if len(parts) >= 2 and parts[0].isdigit():
            recs.append({"priority": int(parts[0]), "host": parts[1].rstrip(".").lower()})
        elif parts:
            recs.append({"priority": 0, "host": parts[0].rstrip(".").lower()})
    recs.sort(key=lambda r: (r["priority"], r["host"]))
    return recs


def parse_srv(text: str) -> List[Dict[str, Any]]:
    """``dig +short SRV`` → [{priority, weight, port, target}]."""
    recs: List[Dict[str, Any]] = []
    for v in parse_short(text):
        p = v.split()
        if len(p) >= 4 and p[0].isdigit():
            try:
                recs.append({"priority": int(p[0]), "weight": int(p[1]),
                             "port": int(p[2]), "target": p[3].rstrip(".").lower()})
            except ValueError:
                continue
    recs.sort(key=lambda r: (r["priority"], r["port"]))
    return recs


def parse_soa(text: str) -> Dict[str, Any]:
    """``dig +short SOA`` → {mname, rname, serial, refresh, retry, expire, minimum}."""
    for v in parse_short(text):
        p = v.split()
        if len(p) >= 7:
            def _i(x: str) -> int:
                try:
                    return int(x)
                except ValueError:
                    return 0
            return {"mname": p[0].rstrip(".").lower(), "rname": p[1].rstrip(".").lower(),
                    "serial": _i(p[2]), "refresh": _i(p[3]), "retry": _i(p[4]),
                    "expire": _i(p[5]), "minimum": _i(p[6])}
    return {}


def parse_txt(text: str) -> List[str]:
    """``dig +short TXT`` → unquoted strings (dig splits long TXT into chunks)."""
    out: List[str] = []
    for v in parse_short(text):
        joined = "".join(re.findall(r'"([^"]*)"', v)) or v.strip('"')
        joined = joined.strip()
        if joined and joined not in out:
            out.append(joined)
    return out


def classify_txt_policies(txts: List[str]) -> Dict[str, Any]:
    """Pull the security-relevant email policies out of raw TXT records.

    Reported as OBSERVATIONS, not findings — a missing SPF/DMARC only becomes a
    finding once the normal severity policy grades it with captured evidence."""
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    dkim = [t for t in txts if t.lower().startswith("v=dkim1")]
    verifications = [t for t in txts
                     if re.match(r"^[a-z0-9\-]+(-site)?-verification=", t, re.I)
                     or "verification=" in t.lower()]
    out: Dict[str, Any] = {
        "spf": spf, "dmarc": dmarc, "dkim": dkim,
        "site_verifications": verifications,
        "has_spf": bool(spf), "has_dmarc": bool(dmarc),
    }
    if spf:
        first = spf[0].lower()
        # The SPF "all" qualifier: -all (hard fail) / ~all (soft) / ?all (neutral)
        m = re.search(r"([-~?+])all\b", first)
        out["spf_all_qualifier"] = m.group(1) if m else ""
        out["spf_includes"] = re.findall(r"include:([^\s]+)", first)
    if dmarc:
        m = re.search(r"\bp\s*=\s*([a-z]+)", dmarc[0], re.I)
        out["dmarc_policy"] = (m.group(1).lower() if m else "")
    return out


_AXFR_REFUSED = ("transfer failed", "connection refused", "communications error",
                 "xfr size", "; transfer failed.", "refused", "not authoritative",
                 "timed out", "no servers could be reached")


def parse_axfr(text: str, apex: str) -> Dict[str, Any]:
    """Detect a SUCCESSFUL zone transfer and extract the hostnames it leaked.

    Success requires actual zone content — a record line for the zone — not merely
    a zero exit code, because ``dig axfr`` can exit 0 while printing only a refusal.
    """
    blob = text or ""
    low = blob.lower()
    hosts: List[str] = []
    soa_seen = False
    for line in blob.splitlines():
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        parts = s.split()
        if len(parts) < 4:
            continue
        name, rtype = parts[0].rstrip(".").lower(), parts[3].upper()
        if rtype == "SOA":
            soa_seen = True
        if rtype in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SRV", "PTR"):
            if name and (name == apex.lower() or name.endswith("." + apex.lower())):
                if name not in hosts:
                    hosts.append(name)
    # A real transfer prints the zone's SOA plus records; refusals do not.
    succeeded = bool(soa_seen and hosts)
    if not succeeded and any(m in low for m in _AXFR_REFUSED):
        return {"succeeded": False, "hosts": [], "reason": "refused/failed"}
    return {"succeeded": succeeded, "hosts": hosts,
            "reason": "" if succeeded else "no zone content returned"}


# ══════════════════════════════════════════════════════════════════════════════
#  RESULT
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class DomainRecords:
    apex:      str
    a:         List[str] = field(default_factory=list)
    aaaa:      List[str] = field(default_factory=list)
    ns:        List[str] = field(default_factory=list)
    mx:        List[Dict[str, Any]] = field(default_factory=list)
    txt:       List[str] = field(default_factory=list)
    soa:       Dict[str, Any] = field(default_factory=dict)
    cname:     List[str] = field(default_factory=list)
    caa:       List[str] = field(default_factory=list)
    srv:       List[Dict[str, Any]] = field(default_factory=list)
    ptr:       Dict[str, List[str]] = field(default_factory=dict)   # ip -> names
    ns_ips:    Dict[str, List[str]] = field(default_factory=dict)   # ns  -> ips
    mx_ips:    Dict[str, List[str]] = field(default_factory=dict)   # mx  -> ips
    txt_policies: Dict[str, Any] = field(default_factory=dict)
    zone_transfer: Dict[str, Any] = field(default_factory=dict)     # ns -> result
    wildcard:  bool = False
    errors:    List[str] = field(default_factory=list)
    tool:      str = ""                                            # dig | stdlib
    # Record types whose query actually COMPLETED.  Absence of a record and
    # absence of a query look identical in the parsed output, and conflating them
    # is how a run with no `dig` reported "no SPF, no DMARC" as though it had
    # checked.  Only a type listed here supports a claim that something is MISSING.
    queried:   List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apex": self.apex, "a": self.a, "aaaa": self.aaaa, "ns": self.ns,
            "mx": self.mx, "txt": self.txt, "soa": self.soa, "cname": self.cname,
            "caa": self.caa, "srv": self.srv, "ptr": self.ptr,
            "ns_ips": self.ns_ips, "mx_ips": self.mx_ips,
            "txt_policies": self.txt_policies, "zone_transfer": self.zone_transfer,
            "wildcard": self.wildcard, "errors": self.errors, "tool": self.tool,
            "queried": list(self.queried),
            "summary": self.summary(),
        }

    def summary(self) -> Dict[str, Any]:
        axfr_ok = [ns for ns, r in (self.zone_transfer or {}).items()
                   if (r or {}).get("succeeded")]
        return {
            "addresses":      len(set(self.a) | set(self.aaaa)),
            "nameservers":    len(self.ns),
            "mail_exchangers": len(self.mx),
            "txt_records":    len(self.txt),
            "srv_records":    len(self.srv),
            "zone_transfer_open": axfr_ok,
            "has_spf":  bool((self.txt_policies or {}).get("has_spf")),
            "has_dmarc": bool((self.txt_policies or {}).get("has_dmarc")),
            # Did the TXT query actually run?  Without this, "no SPF" is
            # indistinguishable from "never asked".
            "txt_queried": "TXT" in (self.queried or []),
            "queried": list(self.queried or []),
            "wildcard": self.wildcard,
        }

    def all_hosts(self) -> List[str]:
        """Every HOSTNAME this sweep learned about (NS/MX/CNAME/SRV targets + any
        names a zone transfer leaked).  Used to offer extra pick candidates."""
        out: List[str] = []
        def _add(h: str) -> None:
            h = (h or "").strip().rstrip(".").lower()
            if h and h not in out:
                out.append(h)
        for n in self.ns:
            _add(n)
        for m in self.mx:
            _add(m.get("host", ""))
        for c in self.cname:
            _add(c)
        for s in self.srv:
            _add(s.get("target", ""))
        for r in (self.zone_transfer or {}).values():
            for h in (r or {}).get("hosts", []) or []:
                _add(h)
        return out

    def all_ips(self) -> List[str]:
        out: List[str] = []
        for ip in list(self.a) + list(self.aaaa):
            if ip not in out:
                out.append(ip)
        for ips in list(self.ns_ips.values()) + list(self.mx_ips.values()):
            for ip in ips:
                if ip not in out:
                    out.append(ip)
        return out


# ══════════════════════════════════════════════════════════════════════════════
#  DEFAULT I/O (dig when available, stdlib otherwise)
# ══════════════════════════════════════════════════════════════════════════════
async def _local_tool_runner(tool: str, argv: List[str], timeout: int
                             ) -> Tuple[int, str, str]:
    """Run a local binary with positional argv (never a shell) — a hostname can
    therefore never inject a command."""
    if not shutil.which(tool):
        return 127, "", f"{tool} not found"
    try:
        proc = await asyncio.create_subprocess_exec(
            tool, *argv,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except Exception as exc:                                   # noqa: BLE001
        return 127, "", f"{type(exc).__name__}: {exc}"
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return 124, "", f"{tool} timed out after {timeout}s"
    return (proc.returncode or 0), out.decode(errors="replace"), err.decode(errors="replace")


async def _stdlib_resolver(host: str) -> List[str]:
    """Resolve via the stdlib (works with no dig installed)."""
    import socket
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except Exception:
        return []
    out: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


async def _reverse(ip: str) -> List[str]:
    import socket
    loop = asyncio.get_running_loop()
    try:
        name, aliases, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
    except Exception:
        return []
    out = [name] + list(aliases or [])
    return [h.rstrip(".").lower() for h in out if h]


# ══════════════════════════════════════════════════════════════════════════════
#  SWEEP
# ══════════════════════════════════════════════════════════════════════════════
async def sweep(
    apex: str,
    *,
    tool_runner: Optional[ToolRunner] = None,
    resolver: Optional[Resolver] = None,
    reverse_fn: Optional[Callable[[str], Awaitable[List[str]]]] = None,
    srv_names: Tuple[str, ...] = DEFAULT_SRV,
    attempt_axfr: bool = True,
    timeout: int = 15,
    on_progress: Optional[Callable[[str], Awaitable[None]]] = None,
) -> DomainRecords:
    """Collect the full record set for ``apex``.  Never raises — a failed query is
    recorded in ``errors`` and the rest of the sweep continues."""
    apex = (apex or "").strip().lower().strip(".")
    rec = DomainRecords(apex=apex)
    if not apex:
        rec.errors.append("no domain given")
        return rec
    runner = tool_runner or _local_tool_runner
    resolve = resolver or _stdlib_resolver
    rev = reverse_fn or _reverse

    async def _say(msg: str) -> None:
        if on_progress:
            try:
                await on_progress(msg)
            except Exception:
                pass

    async def _dig(rtype: str, name: str, extra: Optional[List[str]] = None
                   ) -> Tuple[int, str, str]:
        argv = ["+short", "+time=5", "+tries=2", rtype, name] + list(extra or [])
        return await runner("dig", argv, timeout)

    # ── simple record types ───────────────────────────────────────────────
    await _say(f"DNS: querying {apex} record types")
    code, out, err = await _dig("A", apex)
    if code == 127:
        # No dig on this host — degrade to the stdlib for addresses only.
        rec.tool = "stdlib"
        rec.errors.append("dig unavailable — address records only (stdlib resolver)")
        ips = await resolve(apex)
        for ip in ips:
            try:
                (rec.aaaa if ipaddress.ip_address(ip).version == 6 else rec.a).append(ip)
            except ValueError:
                continue
    else:
        rec.tool = "dig"
        rec.a = [v for v in parse_short(out) if _is_ip(v, 4)]
        rec.queried.append("A")
        for rtype in SIMPLE_TYPES[1:]:
            c, o, e = await _dig(rtype, apex)
            if c not in (0,):
                rec.errors.append(f"{rtype}: {(e or 'query failed').strip()[:120]}")
                continue
            rec.queried.append(rtype)
            if rtype == "AAAA":
                rec.aaaa = [v for v in parse_short(o) if _is_ip(v, 6)]
            elif rtype == "NS":
                rec.ns = [v.rstrip(".").lower() for v in parse_short(o)]
            elif rtype == "TXT":
                rec.txt = parse_txt(o)
            elif rtype == "SOA":
                rec.soa = parse_soa(o)
            elif rtype == "CNAME":
                rec.cname = [v.rstrip(".").lower() for v in parse_short(o)]
            elif rtype == "CAA":
                rec.caa = parse_short(o)
        c, o, _e = await _dig("MX", apex)
        if c == 0:
            rec.mx = parse_mx(o)
            rec.queried.append("MX")

        # ── SRV service records ──
        await _say("DNS: probing common SRV service records")
        for svc in srv_names:
            c, o, _e = await _dig("SRV", f"{svc}.{apex}")
            if c == 0:
                got = parse_srv(o)
                if got:
                    for g in got:
                        g["service"] = svc
                    rec.srv.extend(got)

    rec.txt_policies = classify_txt_policies(rec.txt)

    # ── resolve NS / MX hosts (their addresses are real infrastructure) ───
    await _say("DNS: resolving nameserver and mail-exchanger addresses")
    for ns in rec.ns:
        ips = await resolve(ns)
        if ips:
            rec.ns_ips[ns] = ips
    for m in rec.mx:
        h = m.get("host", "")
        if h:
            ips = await resolve(h)
            if ips:
                rec.mx_ips[h] = ips

    # ── wildcard detection (makes brute-force output untrustworthy) ───────
    probe = f"argus-wildcard-probe-zz9.{apex}"
    rec.wildcard = bool(await resolve(probe))
    if rec.wildcard:
        await _say("DNS: wildcard detected — brute-force results will be noisy")

    # ── reverse PTR for every address found ──────────────────────────────
    await _say("DNS: reverse-resolving discovered addresses")
    for ip in rec.all_ips():
        names = await rev(ip)
        if names:
            rec.ptr[ip] = names

    # ── AXFR against every nameserver ────────────────────────────────────
    if attempt_axfr and rec.ns and rec.tool == "dig":
        await _say(f"DNS: attempting zone transfer against {len(rec.ns)} nameserver(s)")
        for ns in rec.ns:
            c, o, e = await runner("dig", ["+time=5", "+tries=1", "axfr", apex, f"@{ns}"],
                                   timeout)
            if c == 127:
                break
            verdict = parse_axfr(o, apex)
            if not verdict.get("succeeded") and e.strip():
                verdict["reason"] = (verdict.get("reason") or "") or e.strip()[:120]
            rec.zone_transfer[ns] = verdict
            if verdict.get("succeeded"):
                logger.warning("[dns] ZONE TRANSFER OPEN on %s for %s (%d names)",
                               ns, apex, len(verdict.get("hosts") or []))
                await _say(f"DNS: ZONE TRANSFER OPEN on {ns} — "
                           f"{len(verdict.get('hosts') or [])} names leaked")

    await _say("DNS: record sweep complete")
    return rec


def _is_ip(v: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(v).version == version
    except ValueError:
        return False


__all__ = [
    "DomainRecords", "sweep", "ToolRunner", "Resolver",
    "parse_short", "parse_mx", "parse_srv", "parse_soa", "parse_txt",
    "classify_txt_policies", "parse_axfr", "DEFAULT_SRV", "SIMPLE_TYPES",
]
