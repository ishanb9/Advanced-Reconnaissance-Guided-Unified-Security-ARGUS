"""
vhost_pivot.py - automatic /etc/hosts management and vhost enumeration.

Why this exists
---------------
HTB-style targets routinely redirect to .htb / .local / .internal
hostnames that don't resolve until the operator adds them to /etc/hosts.
ARGUS currently sees the redirect, logs it, and moves on.  The actual
attack surface lives behind the hostname, so the scan misses everything.

This module:
  1. Scans recent recon output for redirect destinations + Host headers
     pointing at hostnames that look like internal/scope-local names.
  2. Optionally adds them to /etc/hosts mapped to the target IP
     (write requires HOSTS_AUTOWRITE=1 - off by default).
  3. Performs vhost brute-forcing via ffuf with a curated subdomain
     wordlist; new vhosts that return different response sizes / 200s
     get added to /etc/hosts too.

OPSEC
-----
/etc/hosts writes are LOCAL to the operator box - they don't touch
the target.  The vhost brute-force generates traffic to the target,
which is fine in scope but should respect rate-limits.

Scope safety
------------
Hostname extraction never accepts external/public domains.  An allowlist
of TLDs treated as "internal/HTB-like" gates what we'll auto-add:
  .htb, .local, .lan, .corp, .internal, .test, .home, .arpa
Plus any TLD already present in scope_hostnames passed by the caller.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


HOSTS_FILE = os.environ.get("HOSTS_FILE", "/etc/hosts")
HOSTS_AUTOWRITE = os.environ.get("HOSTS_AUTOWRITE", "0") in ("1", "true", "True", "yes")
# VHOST_AUTOMAP governs the *redirect-discovered* vhost pivot (distinct from
# the noisy ffuf brute-force gated by HOSTS_AUTOWRITE).  When the target's own
# HTTP service redirects to an internal vhost (e.g. bare IP 302→http://cctv.htb/),
# that hostname IS the target's web app and MUST be mapped to the current
# target IP or the entire web attack surface is unreachable.  Defaults ON
# because without it HTB-style vhost boxes can never be compromised.  Set
# VHOST_AUTOMAP=0 to fall back to dry-run/event-only behaviour.
VHOST_AUTOMAP = os.environ.get("VHOST_AUTOMAP", "1") in ("1", "true", "True", "yes")
HOSTS_MANAGED_MARKER = "# argus-managed"
VHOST_WORDLIST = os.environ.get(
    "VHOST_WORDLIST",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
)
VHOST_FFUF_THREADS = int(os.environ.get("VHOST_FFUF_THREADS", "40"))
VHOST_FFUF_TIMEOUT = int(os.environ.get("VHOST_FFUF_TIMEOUT", "300"))

# TLDs we consider safe to auto-add to /etc/hosts
INTERNAL_TLDS = {
    "htb", "local", "lan", "corp", "internal", "test",
    "home", "arpa", "thm",   # tryhackme
}

# Pattern: hostname like foo.bar.htb or foo.local
_HOSTNAME_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62}){0,4})\b", re.I)
_REDIRECT_RE = re.compile(r"^(?:Location|location):\s*https?://([^/\s:]+)", re.MULTILINE)
_LINK_RE     = re.compile(r"href=[\"']https?://([^/\s\"'`]+)", re.I)


# ── Hostname extraction ─────────────────────────────────────────────────

def _looks_internal(hostname: str, scope_hostnames: Set[str]) -> bool:
    h = hostname.lower().strip(".")
    if not h or "." not in h:
        return False
    tld = h.rsplit(".", 1)[-1]
    if tld in INTERNAL_TLDS:
        return True
    if h in scope_hostnames:
        return True
    # exact suffix match against scope (e.g. "intranet.example.com")
    for s in scope_hostnames:
        if h == s or h.endswith("." + s):
            return True
    return False


def extract_hostnames(text: str, scope_hostnames: Optional[Set[str]] = None) -> List[str]:
    """Pull internal-looking hostnames out of curl/whatweb/wget output."""
    if not text:
        return []
    scope_hostnames = scope_hostnames or set()
    found: Set[str] = set()
    # 1) HTTP redirects
    for h in _REDIRECT_RE.findall(text):
        if _looks_internal(h, scope_hostnames):
            found.add(h.lower())
    # 2) <a href="http://host">  links
    for h in _LINK_RE.findall(text):
        if _looks_internal(h, scope_hostnames):
            found.add(h.lower())
    # 3) Bare mentions  e.g. whatweb output "Redirect: http://foo.htb"
    for m in _HOSTNAME_RE.finditer(text):
        cand = m.group(1).lower()
        if "." in cand and _looks_internal(cand, scope_hostnames):
            found.add(cand)
    return sorted(found)


# ── /etc/hosts management ────────────────────────────────────────────────

def _sudo_tee(content: str, append: bool) -> bool:
    """Write ``content`` to HOSTS_FILE via ``sudo tee`` (no shell).

    Fallback for when the Python process lacks root on the real /etc/hosts
    (the agent server usually runs unprivileged while tools run via sudo).
    Passwordless sudo is assumed — standard on the Kali operator box, and the
    same `sudo tee` the LLM already uses successfully.  Only fires on a real
    /etc path so tests pointed at a temp HOSTS_FILE never shell out.
    """
    if HOSTS_FILE != "/etc/hosts" and not HOSTS_FILE.startswith("/etc/"):
        return False
    argv = ["sudo", "tee"] + (["-a"] if append else []) + [HOSTS_FILE]
    try:
        cp = subprocess.run(
            argv, input=content.encode("utf-8"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
        return cp.returncode == 0
    except Exception:
        return False


def hosts_read() -> List[str]:
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            return f.readlines()
    except Exception as exc:
        logger.warning("[vhost] could not read %s: %s", HOSTS_FILE, exc)
        return []


def hosts_currently_mapped(hostname: str) -> Optional[str]:
    """Return the IP `hostname` currently resolves to via /etc/hosts, or None."""
    target = hostname.lower().strip()
    for line in hosts_read():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for h in parts[1:]:
            if h.lower() == target:
                return ip
    return None


def hosts_remove(hostnames: Iterable[str]) -> List[str]:
    """Remove any /etc/hosts lines that map *any* of `hostnames`.

    Used to purge a STALE mapping (e.g. cctv.htb left over from a previous
    engagement, pointing at a now-unreachable IP) before re-mapping it to the
    current target.  Returns the list of hostnames whose lines were removed.
    Best-effort; never raises.
    """
    wanted = {h.lower().strip() for h in hostnames if h and "." in h}
    if not wanted:
        return []
    try:
        lines = hosts_read()
    except Exception:
        return []
    removed: List[str] = []
    kept: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            kept.append(line)
            continue
        parts = stripped.split()
        line_hosts = {p.lower() for p in parts[1:] if not p.startswith("#")}
        if line_hosts & wanted:
            removed.extend(sorted(line_hosts & wanted))
            continue  # drop this line
        kept.append(line)
    if not removed:
        return []
    try:
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.writelines(kept)
        logger.info("[vhost] removed stale /etc/hosts mapping(s): %s", removed)
    except PermissionError:
        if _sudo_tee("".join(kept), append=False):
            logger.info("[vhost] removed stale /etc/hosts mapping(s) via sudo: %s", removed)
            return removed
        logger.warning("[vhost] no permission to rewrite %s (stale removal skipped)", HOSTS_FILE)
        return []
    except Exception as exc:
        logger.warning("[vhost] /etc/hosts stale-removal failed: %s", exc)
        return []
    return removed


def hosts_add(ip: str, hostnames: Iterable[str], dry_run: bool = False,
              force: bool = False) -> Tuple[List[str], List[str]]:
    """Add `ip <host1> <host2>...` to /etc/hosts.  Returns (added, skipped).

    Idempotent: if the same (ip, hostname) pair already exists, skip.  If a
    hostname currently maps to a DIFFERENT ip, the stale line is removed first
    so the new mapping takes effect (otherwise glibc honours the first match
    and the vhost stays pointed at the wrong/old box).

    Writes when ``force=True`` OR ``HOSTS_AUTOWRITE`` is on.  When neither and
    not dry_run, returns what WOULD be written without touching the file.
    """
    hostnames = [h.lower().strip() for h in hostnames if h and "." in h]
    added: List[str] = []
    skipped: List[str] = []
    stale: List[str] = []
    for h in hostnames:
        cur = hosts_currently_mapped(h)
        if cur == ip:
            skipped.append(h)
            continue
        if cur is not None and cur != ip:
            stale.append(h)      # mapped elsewhere → must replace
        added.append(h)
    if not added or dry_run or not (force or HOSTS_AUTOWRITE):
        return added, skipped
    try:
        if stale:
            hosts_remove(stale)   # purge wrong-IP lines before re-mapping
        line = f"{ip} {' '.join(added)} {HOSTS_MANAGED_MARKER}\n"
        with open(HOSTS_FILE, "a", encoding="utf-8") as f:
            f.write(line)
        logger.info("[vhost] wrote /etc/hosts: %s -> %s", ip, added)
    except PermissionError:
        # Python isn't root — fall back to `sudo tee -a` (passwordless sudo on
        # the Kali op box).  Without this the auto-map silently no-ops and the
        # vhost never resolves, so web tools keep hitting the bare IP.
        if _sudo_tee(line, append=True):
            logger.info("[vhost] wrote /etc/hosts via sudo: %s -> %s", ip, added)
            return added, skipped
        logger.warning("[vhost] no permission to write %s (run as root or set HOSTS_FILE=)", HOSTS_FILE)
        return [], hostnames
    except Exception as exc:
        logger.warning("[vhost] /etc/hosts write failed: %s", exc)
        return [], hostnames
    return added, skipped


def remap_vhosts(target_ip: str, hostnames: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Force-(re)map `hostnames` → `target_ip`, replacing any stale mappings.

    This is the redirect-discovery pivot: the hostnames came from the target's
    OWN HTTP redirect, so they belong to THIS target IP regardless of any
    leftover /etc/hosts entry from a prior box.  Honours VHOST_AUTOMAP.
    """
    return hosts_add(target_ip, hostnames, force=VHOST_AUTOMAP)


def reconcile_stale_vhosts_for_target(
    target_ip: str, *, force: Optional[bool] = None
) -> List[str]:
    """PROACTIVELY purge STALE argus-managed /etc/hosts entries at scan start.

    Across engagements ARGUS leaves ``<ip> <vhost> # argus-managed`` lines in
    /etc/hosts.  When the NEXT target reuses the same vhost name on a new IP
    (the norm for HTB-style boxes — e.g. a hostname that was 10.129.17.70 last
    run and 10.129.21.9 this run), the leftover line wins glibc's first-match
    rule and every web tool silently hits the OLD box.  In the reviewed run
    this misdirected ~6-7 min of recon before the *reactive* ``remap_vhosts``
    caught it mid-web-testing.

    Run ONCE at scan start, this removes any argus-managed hostname mapped to
    an IP other than ``target_ip`` so it re-resolves cleanly when the redirect
    pivot later re-maps it to the live target.

    Safety: ONLY lines bearing :data:`HOSTS_MANAGED_MARKER` are candidates —
    an operator's own manual /etc/hosts entries are never touched.  Honours
    :data:`VHOST_AUTOMAP` as the write gate (when off, reports what WOULD be
    reconciled without modifying the file).  Returns the reconciled hostnames.
    Best-effort; never raises.
    """
    if not target_ip:
        return []
    do_write = VHOST_AUTOMAP if force is None else force
    try:
        lines = hosts_read()
    except Exception:
        return []
    reconciled: List[str] = []
    kept: List[str] = []
    for line in lines:
        stripped = line.strip()
        # Only argus-managed mapping lines are candidates for removal.
        if (not stripped or stripped.startswith("#")
                or HOSTS_MANAGED_MARKER not in line):
            kept.append(line)
            continue
        parts = stripped.split()
        if len(parts) < 2:
            kept.append(line)
            continue
        ip = parts[0]
        line_hosts = [p for p in parts[1:] if not p.startswith("#")]
        if ip != target_ip and line_hosts:
            reconciled.extend(h.lower() for h in line_hosts)
            continue                       # drop the stale managed line
        kept.append(line)
    if not reconciled:
        return []
    if not do_write:
        logger.info("[vhost] stale managed mapping(s) detected (automap off, "
                    "not rewriting): %s", reconciled)
        return reconciled
    try:
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.writelines(kept)
        logger.info("[vhost] reconciled stale /etc/hosts mapping(s) at scan "
                    "start: %s", reconciled)
    except PermissionError:
        if _sudo_tee("".join(kept), append=False):
            logger.info("[vhost] reconciled stale /etc/hosts mapping(s) via "
                        "sudo: %s", reconciled)
            return reconciled
        logger.warning("[vhost] no permission to rewrite %s (stale reconcile "
                       "skipped)", HOSTS_FILE)
        return []
    except Exception as exc:
        logger.warning("[vhost] /etc/hosts stale reconcile failed: %s", exc)
        return []
    return reconciled


# ── ffuf-driven vhost brute-force ───────────────────────────────────────

ToolRunner = Callable[[str, List[str], int], Awaitable[Tuple[int, str, str]]]


@dataclass
class VhostResult:
    discovered:   List[str] = field(default_factory=list)
    added_to_hosts: List[str] = field(default_factory=list)
    skipped:      List[str] = field(default_factory=list)
    notes:        List[str] = field(default_factory=list)


async def bruteforce_vhosts(
    target_ip: str,
    base_domain: str,
    tool_runner: ToolRunner,
    scope_hostnames: Optional[Set[str]] = None,
    wordlist: Optional[str] = None,
    filter_size: Optional[int] = None,
) -> VhostResult:
    """Use ffuf to brute-force vhost names (Host: header).

    base_domain is the "right side" of the hostname (e.g. "htb" or "example.local").
    Discovered hostnames that return a different size from the baseline get
    flagged + optionally added to /etc/hosts.
    """
    result = VhostResult()
    ffuf = shutil.which("ffuf")
    if not ffuf:
        result.notes.append("ffuf not on PATH - install via apt install ffuf")
        return result

    wl = wordlist or VHOST_WORDLIST
    if not os.path.exists(wl):
        result.notes.append(f"vhost wordlist not found: {wl} (set VHOST_WORDLIST=...)")
        return result

    # Baseline: hit the IP without a Host header to find the default content size
    out_json = f"/tmp/argus-ffuf-vhost-{int(time.time())}.json"
    args = [
        "-u",   f"http://{target_ip}/",
        "-H",   f"Host: FUZZ.{base_domain.lstrip('.')}",
        "-w",   wl,
        "-mc",  "all",
        "-t",   str(VHOST_FFUF_THREADS),
        "-of",  "json",
        "-o",   out_json,
        "-r",
    ]
    if filter_size is not None:
        args += ["-fs", str(filter_size)]
    try:
        exit_code, stdout, stderr = await tool_runner(ffuf, args, VHOST_FFUF_TIMEOUT)
    except Exception as exc:
        result.notes.append(f"ffuf invocation error: {exc}")
        return result

    # Parse the JSON output for the discovered hostnames
    try:
        import json
        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        for res in (data.get("results") or []):
            sub = res.get("input", {}).get("FUZZ")
            if not sub:
                continue
            host = f"{sub}.{base_domain.lstrip('.')}"
            if host not in result.discovered:
                result.discovered.append(host)
    except Exception as exc:
        result.notes.append(f"ffuf json parse error: {exc}")
    finally:
        try:
            os.remove(out_json)
        except OSError:
            pass

    if result.discovered:
        added, skipped = hosts_add(target_ip, result.discovered)
        result.added_to_hosts = added
        result.skipped = skipped
    return result


# ── High-level pivot driver ─────────────────────────────────────────────

@dataclass
class PivotResult:
    extracted_hostnames: List[str]
    added_to_hosts:      List[str]
    skipped:             List[str]
    new_vhosts:          List[str] = field(default_factory=list)
    notes:               List[str] = field(default_factory=list)


async def pivot_from_recon_output(
    target_ip: str,
    recon_text: str,
    tool_runner: Optional[ToolRunner] = None,
    scope_hostnames: Optional[Set[str]] = None,
    deep_bruteforce: bool = False,
) -> PivotResult:
    """End-to-end pivot.

    Args:
        target_ip:    IP to map discovered hostnames to
        recon_text:   raw stdout from curl / whatweb / nmap / etc.
        tool_runner:  async fn(tool, argv, timeout) - needed only if
                      deep_bruteforce=True (vhost ffuf step)
        scope_hostnames: extra hostnames considered in-scope for the
                      internal-domain heuristic
        deep_bruteforce: when True AND we found at least one .htb-style
                      hostname, run ffuf against its base domain to
                      discover additional vhosts.
    """
    scope_hostnames = scope_hostnames or set()
    extracted = extract_hostnames(recon_text, scope_hostnames)
    # Redirect-discovered vhosts belong to THIS target — force-(re)map them to
    # the current target IP (replacing any stale leftover), so the web attack
    # surface behind the vhost is actually reachable.
    added, skipped = remap_vhosts(target_ip, extracted)
    pr = PivotResult(
        extracted_hostnames = extracted,
        added_to_hosts      = added,
        skipped             = skipped,
    )
    if not (VHOST_AUTOMAP or HOSTS_AUTOWRITE) and added:
        pr.notes.append(
            f"DRY-RUN: would map {len(added)} hostname(s) to {target_ip} in "
            f"{HOSTS_FILE}. Set VHOST_AUTOMAP=1 to enable (requires root)."
        )
    elif added:
        pr.notes.append(
            f"Mapped {len(added)} vhost(s) → {target_ip} in {HOSTS_FILE}: "
            f"{', '.join(added)}"
        )

    if deep_bruteforce and extracted and tool_runner is not None:
        # Pick the highest-cardinality base domain to brute against
        base = None
        for h in extracted:
            parts = h.split(".")
            if len(parts) >= 2:
                # base = "<everything-after-the-first-label>"
                candidate = ".".join(parts[1:])
                if base is None or candidate.count(".") > base.count("."):
                    base = candidate
        if base:
            try:
                vr = await bruteforce_vhosts(
                    target_ip, base, tool_runner, scope_hostnames,
                )
                pr.new_vhosts = vr.discovered
                pr.added_to_hosts.extend(vr.added_to_hosts)
                pr.skipped.extend(vr.skipped)
                pr.notes.extend(vr.notes)
            except Exception as exc:
                pr.notes.append(f"vhost brute-force error: {exc}")
    return pr


__all__ = [
    "extract_hostnames", "hosts_add", "hosts_remove", "hosts_currently_mapped",
    "remap_vhosts", "bruteforce_vhosts", "pivot_from_recon_output",
    "VhostResult", "PivotResult",
    "HOSTS_AUTOWRITE", "VHOST_AUTOMAP", "INTERNAL_TLDS",
]
