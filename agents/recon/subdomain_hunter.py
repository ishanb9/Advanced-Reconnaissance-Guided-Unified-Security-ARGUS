"""
subdomain_hunter.py — hunt every subdomain of a domain across the public net.

Given an apex domain (e.g. ``example.com``) this gathers subdomains from BOTH:
  • Passive sources — certificate-transparency (crt.sh) + ``subfinder`` (which
    itself aggregates dozens of OSINT APIs).  No traffic to the target's own
    DNS infrastructure.
  • Active brute-force — ``gobuster dns`` (wordlist brute) against the apex's
    nameservers for unlisted hosts.

Every discovered host is RESOLVED to its IP(s) and classified for authorization
context:
  • ``in_apex_network`` — shares a /24 with an apex IP → almost certainly the
    same operator's infra.
  • ``third_party``     — resolves elsewhere (CDN / SaaS / shared hosting) →
    flagged so the human doesn't accidentally attack someone else's box.

The hunter NEVER decides scope on its own — it presents everything (flagged) so
the human can pick.  Tool execution + DNS resolution are injected (``tool_runner``
/ ``resolver``) so the parsing + classification logic is unit-testable offline.

Design mirrors vhost_pivot.py: pure parsers + a thin async orchestrator.
All subprocesses use the no-shell list form (execFile-equivalent) — no shell
string is ever built from a hostname.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# (tool, argv_list, timeout) -> (exit_code, stdout, stderr)
ToolRunner = Callable[[str, List[str], int], Awaitable[Tuple[int, str, str]]]
# host -> list[ip]
Resolver = Callable[[str], Awaitable[List[str]]]

DEFAULT_WORDLIST = os.environ.get(
    "SUBDOMAIN_WORDLIST",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
)
MAX_CANDIDATES = int(os.environ.get("SUBDOMAIN_MAX_CANDIDATES", "300"))

# A valid DNS label-set (no scheme, no port, no path).
_HOST_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


# ── Hostname hygiene ─────────────────────────────────────────────────────

def clean_host(raw: str) -> str:
    """Normalise a raw token to a bare hostname, or '' if it isn't one."""
    if not raw:
        return ""
    h = raw.strip().lower().strip(".")
    h = h.split("://", 1)[-1]          # strip scheme
    h = h.split("/", 1)[0]             # strip path
    h = h.split(":", 1)[0]             # strip port
    h = h.lstrip("*.")                 # wildcard cert → bare host
    if h.startswith("."):
        h = h[1:]
    return h if _HOST_RE.match(h) else ""


def in_scope_of_apex(host: str, apex: str) -> bool:
    """True if ``host`` is the apex itself or a subdomain of it."""
    host = host.lower().strip(".")
    apex = apex.lower().strip(".")
    return bool(host) and (host == apex or host.endswith("." + apex))


# ── Source parsers (pure) ────────────────────────────────────────────────

def parse_crtsh_json(text: str, apex: str) -> Set[str]:
    """Parse crt.sh ``output=json`` — each row has a ``name_value`` that may
    contain several newline-separated names (incl. wildcards)."""
    found: Set[str] = set()
    try:
        rows = json.loads(text)
    except Exception:
        # crt.sh sometimes returns concatenated/partial JSON; salvage names.
        rows = [{"name_value": m.group(1)}
                for m in re.finditer(r'"name_value":"([^"]+)"', text or "")]
    for row in rows if isinstance(rows, list) else []:
        nv = (row or {}).get("name_value", "") if isinstance(row, dict) else ""
        for piece in str(nv).replace("\\n", "\n").splitlines():
            h = clean_host(piece)
            if h and in_scope_of_apex(h, apex):
                found.add(h)
    return found


def parse_host_lines(text: str, apex: str) -> Set[str]:
    """Parse plain one-host-per-line tool output (subfinder, assetfinder, dnsx)."""
    found: Set[str] = set()
    for line in (text or "").splitlines():
        h = clean_host(line)
        if h and in_scope_of_apex(h, apex):
            found.add(h)
    return found


def parse_gobuster_dns(text: str, apex: str) -> Set[str]:
    """Parse ``gobuster dns`` output lines: ``Found: sub.example.com``."""
    found: Set[str] = set()
    for line in (text or "").splitlines():
        m = re.search(r"Found:\s*([^\s]+)", line)
        if m:
            h = clean_host(m.group(1))
            if h and in_scope_of_apex(h, apex):
                found.add(h)
    return found


# ── Scope classification ─────────────────────────────────────────────────

def _same_ipv4_24(a: str, b: str) -> bool:
    try:
        ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
        if ia.version != 4 or ib.version != 4:
            return False
        return ipaddress.ip_network(f"{a}/24", strict=False) == \
               ipaddress.ip_network(f"{b}/24", strict=False)
    except ValueError:
        return False


def classify(host: str, ips: List[str], apex_ips: List[str]) -> Tuple[bool, bool, str]:
    """Return (in_apex_network, third_party, note)."""
    if not ips:
        return (False, False, "did not resolve (dangling / internal-only)")
    for ip in ips:
        for aip in apex_ips:
            if ip == aip or _same_ipv4_24(ip, aip):
                return (True, False, "same network as apex")
    return (False, True, "resolves outside apex network — likely third-party/CDN")


@dataclass
class SubdomainCandidate:
    host: str
    ips: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    in_apex_network: bool = False
    third_party: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host, "ips": self.ips, "sources": sorted(set(self.sources)),
            "in_apex_network": self.in_apex_network, "third_party": self.third_party,
            "note": self.note,
        }


# ── Default local runners (overridable / injectable for tests) ───────────

def _run_tool_sync(tool: str, argv: List[str], timeout: int,
                   cwd: Optional[str]) -> Tuple[int, str, str]:
    # No-shell list form (execFile-equivalent): a hostname can never be
    # interpreted as a shell metacharacter.
    try:
        cp = subprocess.run([tool, *argv], capture_output=True,
                            timeout=timeout, cwd=cwd, check=False)
        return (cp.returncode or 0,
                (cp.stdout or b"").decode("utf-8", "replace"),
                (cp.stderr or b"").decode("utf-8", "replace"))
    except FileNotFoundError:
        return (127, "", f"{tool} not installed")
    except subprocess.TimeoutExpired:
        return (124, "", "timeout")
    except Exception as exc:                                  # noqa: BLE001
        return (1, "", str(exc))


async def _local_tool_runner(tool: str, argv: List[str], timeout: int) -> Tuple[int, str, str]:
    """Run a recon tool locally in the scratch dir.  A missing binary just
    yields a non-zero rc + empty stdout (that source is skipped)."""
    try:
        from agents.base_agent import _tool_scratch_dir
        cwd = _tool_scratch_dir()
    except Exception:
        cwd = None
    return await asyncio.to_thread(_run_tool_sync, tool, argv, timeout, cwd)


async def _socket_resolver(host: str) -> List[str]:
    """Resolve a host to its IPv4/IPv6 addresses via the stdlib resolver."""
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except Exception:
        return []
    ips: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip and ip not in ips:
            ips.append(ip)
    return ips


# ── High-level hunt ──────────────────────────────────────────────────────

async def hunt(
    apex: str,
    *,
    tool_runner: Optional[ToolRunner] = None,
    resolver: Optional[Resolver] = None,
    passive: bool = True,
    active: bool = True,
    wordlist: Optional[str] = None,
    max_candidates: int = MAX_CANDIDATES,
    timeout: int = 180,
    on_progress: Optional[Callable[[str], Awaitable[None]]] = None,
) -> List[SubdomainCandidate]:
    """Hunt + resolve + classify subdomains of ``apex``.  Returns candidates
    sorted in-apex-network first (most likely in scope); apex always included.
    """
    apex = clean_host(apex) or apex.strip().lower().strip(".")
    runner = tool_runner or _local_tool_runner
    resolve_fn = resolver or _socket_resolver

    async def _say(msg: str) -> None:
        if on_progress:
            try:
                await on_progress(msg)
            except Exception:
                pass

    hosts: Set[str] = {apex}
    sources: Dict[str, Set[str]] = {apex: {"apex"}}

    def _add(hs: Set[str], src: str) -> None:
        for h in hs:
            hosts.add(h)
            sources.setdefault(h, set()).add(src)

    # ── Passive ──────────────────────────────────────────────────────
    if passive:
        await _say("passive: crt.sh certificate transparency")
        _rc, out, _e = await runner(
            "curl",
            ["-s", "-m", str(min(timeout, 60)),
             f"https://crt.sh/?q=%25.{apex}&output=json"],
            min(timeout, 60),
        )
        if out:
            _add(parse_crtsh_json(out, apex), "crt.sh")

        await _say("passive: subfinder (OSINT aggregation)")
        _rc, out, _e = await runner("subfinder", ["-d", apex, "-silent"], timeout)
        if out:
            _add(parse_host_lines(out, apex), "subfinder")

    # ── Active brute-force ───────────────────────────────────────────
    if active:
        wl = wordlist or DEFAULT_WORDLIST
        if os.path.exists(wl):
            await _say(f"active: gobuster dns brute ({os.path.basename(wl)})")
            _rc, out, _e = await runner(
                "gobuster",
                ["dns", "-d", apex, "-w", wl, "-q", "--no-color", "-t", "50"],
                timeout,
            )
            if out:
                _add(parse_gobuster_dns(out, apex), "brute")
        else:
            await _say(f"active: wordlist not found ({wl}) — skipping brute")

    # Cap BEFORE resolving so we never resolve thousands.
    ordered = [apex] + sorted(h for h in hosts if h != apex)
    if len(ordered) > max_candidates:
        ordered = ordered[:max_candidates]
    await _say(f"resolving {len(ordered)} unique host(s)")

    # ── Resolve apex first (basis for scope classification) ──────────
    apex_ips = await resolve_fn(apex)

    # ── Resolve all candidates (bounded concurrency) ─────────────────
    sem = asyncio.Semaphore(20)

    async def _resolve_one(h: str) -> Tuple[str, List[str]]:
        async with sem:
            return h, await resolve_fn(h)

    resolved = dict(await asyncio.gather(*[_resolve_one(h) for h in ordered]))

    candidates: List[SubdomainCandidate] = []
    for h in ordered:
        ips = resolved.get(h, [])
        in_net, third, note = classify(h, ips, apex_ips)
        if h == apex:
            in_net, third = True, False
            note = note or "apex domain"
        candidates.append(SubdomainCandidate(
            host=h, ips=ips, sources=sorted(sources.get(h, set())),
            in_apex_network=in_net, third_party=third, note=note,
        ))

    # Sort: apex, then in-network, then resolved third-party, then unresolved.
    def _rank(c: SubdomainCandidate) -> tuple:
        if c.host == apex:
            return (0, c.host)
        if c.in_apex_network:
            return (1, c.host)
        if c.ips:
            return (2, c.host)
        return (3, c.host)

    candidates.sort(key=_rank)
    await _say(f"hunt complete — {len(candidates)} candidate(s)")
    return candidates


__all__ = [
    "SubdomainCandidate", "hunt", "clean_host", "in_scope_of_apex",
    "parse_crtsh_json", "parse_host_lines", "parse_gobuster_dns", "classify",
    "DEFAULT_WORDLIST", "MAX_CANDIDATES",
]
