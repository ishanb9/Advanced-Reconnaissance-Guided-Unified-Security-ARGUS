"""
intel_cascade.py — Real-world-tester intelligence cascade.

THE PROBLEM
===========
A real pentester, the moment they see a banner like
`Werkzeug 0.14.1 Python 3.6.9`, immediately:

  1. Googles "Werkzeug 0.14.1 exploit"
  2. Searches GitHub for "Werkzeug debug PIN" repos
  3. Checks NVD for Werkzeug CVEs
  4. Looks up the CVE on CISA KEV
  5. Searches Vulners for vendor advisories
  6. Greps HackerOne for disclosed Werkzeug bugs
  7. Checks ExploitDB
  8. Searches HackTricks for the technique

That's 8 parallel queries triggered by one banner.  ARGUS's old
OSINT pipeline ran a fixed sweep ONCE per phase and never reacted
to new signals appearing later.

THE FIX
=======
This orchestrator subscribes to NEW intel signals.  When any of
these events fire it fans out queries across every relevant
source:

  • new banner       → NVD (CPE), ExploitDB, GitHub PoC, Vulners,
                       HackerOne, Wayback, HackTricks dorks,
                       Shodan host search (if keyed)
  • new CVE          → CISA KEV (CRITICAL), GitHub PoC, Vulners,
                       HackerOne, Metasploit module search
  • new domain       → crt.sh, theHarvester, Wayback, BGPView,
                       SecurityTrails, Censys, Google Dorks
  • new finding      → Google Dorks (targeted pattern), Vulners,
                       HackerOne (bug class search)

Each source is rate-respecting, idempotent (same signal won't
re-fire), and async-parallel.  Aggregated results are stored as
OSINT results and surfaced into the discovery context so the
master agent's prompts see them on the next iteration.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from agents.osint.osint_config import SOURCES_ENABLED

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
#  Signal types
# ─────────────────────────────────────────────────────────────────────


@dataclass
class IntelSignal:
    """One unit of new information that should trigger a cascade.

    `kind` drives which sources fire.  `value` is the canonical
    identifier (e.g. "OpenSSH 7.6p1", "CVE-2023-28432", "example.com").
    """
    kind:    str   # "banner" | "cve" | "domain" | "ip" | "finding" | "tech"
    value:   str
    meta:    Dict[str, Any] = field(default_factory=dict)

    def signature(self) -> str:
        return hashlib.sha256(
            f"{self.kind}|{self.value.lower().strip()}".encode("utf-8")
        ).hexdigest()[:24]


# ─────────────────────────────────────────────────────────────────────
#  Mapping: signal kind → list of sources that should fire on it
# ─────────────────────────────────────────────────────────────────────

# Each source is identified by a string token; the orchestrator looks
# up the actual subagent factory via SOURCE_FACTORIES.  This indirection
# lets us extend the cascade without rewriting the orchestrator.
SIGNAL_ROUTES: Dict[str, List[str]] = {
    "banner": [
        "nvd_cpe",          # CPE-based NVD lookup (version-applicable CVEs)
        "exploit_db",
        "github_poc",
        "vulners",
        "hackerone",
        "wayback",          # archive paths for the product
        "shodan",           # similar exposed hosts
        "google_dorks",
    ],
    "tech": [
        "nvd_cpe",
        "exploit_db",
        "github_poc",
        "vulners",
        "hackerone",
        "google_dorks",
        "builtwith",
    ],
    "cve": [
        "cisa_kev",         # actively-exploited check
        "github_poc",       # runnable PoC
        "vulners",          # aggregator
        "hackerone",        # disclosed reports citing this CVE
        "exploit_db",
    ],
    "domain": [
        "crtsh",            # subdomain enum via cert transparency
        "theharvester",
        "wayback",
        "bgpview",
        "security_trails",
        "censys",
        "google_dorks",
        "ahmia",            # dark web mentions
        "hibp",             # breach data for the domain
    ],
    "ip": [
        "bgpview",
        "shodan",
        "censys",
        "ahmia",
    ],
    "finding": [
        # A new finding (e.g. "/admin accessible") triggers targeted
        # dorks + Vulners search for the finding type.
        "google_dorks",
        "vulners",
        "hackerone",
    ],
}


# ─────────────────────────────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────────────────────────────


class IntelCascade:
    """Real-world-tester intelligence cascade.

    Instantiate one per engagement.  Master agent + every OSINT
    subagent can call ``submit_signal()`` to inject new intel; the
    orchestrator dedupes and dispatches sources in parallel.
    """

    def __init__(self, session_id: str, target: str,
                 broadcast: Optional[Callable] = None,
                 discovery: Optional[Dict[str, Any]] = None) -> None:
        self.session_id = session_id
        self.target     = target
        self.broadcast  = broadcast
        self.discovery  = discovery or {}
        self._seen_sigs: Set[str] = set()
        self._inflight:  List[asyncio.Task] = []
        # Per-source rate-limit lock so we don't fire 10 parallel
        # crt.sh / Vulners queries.
        self._source_locks: Dict[str, asyncio.Semaphore] = {}
        self._stop = False
        # Map source token → subagent factory.  Filled by register().
        self._factories: Dict[str, Callable[[IntelSignal], Optional[Any]]] = {}
        self._register_default_factories()

    # ── Stop hook ──────────────────────────────────────────────

    def request_stop(self) -> None:
        self._stop = True

    # ── Signal submission ──────────────────────────────────────

    def submit_signal(self, signal: IntelSignal) -> bool:
        """Queue a signal for fan-out.

        Returns True iff the signal is novel (not seen before).  The
        dedup tracking happens regardless of whether an event loop
        is available to dispatch — callers can submit synchronously
        and the cascade will fire the queued signals as soon as a
        loop is available via `join()` or the next async hook.
        """
        if self._stop:
            return False
        sig = signal.signature()
        if sig in self._seen_sigs:
            return False
        self._seen_sigs.add(sig)
        # Fire-and-forget — try to dispatch on the running event loop.
        # If no loop is running (sync caller / unit test) we still
        # report the signal as accepted (dedup remembers it).
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._dispatch(signal))
            self._inflight.append(task)
        except RuntimeError:
            pass
        return True

    def submit_many(self, signals: List[IntelSignal]) -> int:
        return sum(int(self.submit_signal(s)) for s in signals)

    async def join(self, timeout: float = 60.0) -> None:
        """Wait up to `timeout` for all dispatched fan-outs to finish."""
        if not self._inflight:
            return
        try:
            await asyncio.wait(self._inflight, timeout=timeout)
        except Exception:
            pass

    # ── Convenience: derive signals from intel snapshot ────────

    def harvest_signals_from_intel(self, intel: Dict[str, Any]) -> int:
        """Walk an intel dict and submit every signal we haven't seen."""
        submitted = 0
        # Banners + product+version
        services = intel.get("services") or {}
        for port, svc in (services.items() if isinstance(services, dict) else []):
            if isinstance(svc, dict):
                product = (svc.get("product") or svc.get("service") or "").strip()
                version = (svc.get("version") or "").strip()
                banner  = (svc.get("banner")  or "").strip()
                if product and version:
                    submitted += int(self.submit_signal(IntelSignal(
                        kind="banner",
                        value=f"{product} {version}",
                        meta={"port": port, "service": product, "version": version},
                    )))
                elif banner:
                    submitted += int(self.submit_signal(IntelSignal(
                        kind="banner", value=banner[:160],
                        meta={"port": port},
                    )))
        # CVEs
        for entry in (intel.get("cves_with_score") or []):
            cid = None
            if isinstance(entry, (list, tuple)) and entry:
                cid = str(entry[0])
            elif isinstance(entry, dict):
                cid = entry.get("cve_id")
            if cid and re.match(r"^CVE-\d{4}-\d{4,7}$", cid, re.IGNORECASE):
                submitted += int(self.submit_signal(IntelSignal(
                    kind="cve", value=cid.upper(),
                    meta={"source": "intel_snapshot"},
                )))
        for c in (intel.get("critical_cves") or []):
            if isinstance(c, str) and re.match(r"^CVE-\d{4}-\d{4,7}$", c, re.IGNORECASE):
                submitted += int(self.submit_signal(IntelSignal(
                    kind="cve", value=c.upper(),
                )))
        # Domains
        for d in (intel.get("hostnames") or []) + (intel.get("subdomains") or []):
            if isinstance(d, str) and "." in d and not _is_ip_like(d):
                submitted += int(self.submit_signal(IntelSignal(
                    kind="domain", value=d.lower().strip(),
                )))
        # IPs (the primary target)
        if _is_ip_like(self.target):
            submitted += int(self.submit_signal(IntelSignal(
                kind="ip", value=self.target,
            )))
        return submitted

    # ── Dispatch ──────────────────────────────────────────────

    async def _dispatch(self, signal: IntelSignal) -> None:
        """Run every registered source for this signal kind in parallel."""
        sources = SIGNAL_ROUTES.get(signal.kind, [])
        if not sources:
            return
        await self._emit_status(
            f"Intel cascade: {signal.kind} '{signal.value[:80]}' → "
            f"fan-out across {len(sources)} source(s)"
        )
        coros = []
        for src in sources:
            if not self._source_enabled(src):
                continue
            sem = self._source_locks.setdefault(src, asyncio.Semaphore(2))
            coros.append(self._fire_source_with_lock(sem, src, signal))
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

    async def _fire_source_with_lock(self, sem: asyncio.Semaphore,
                                          src: str, signal: IntelSignal) -> None:
        async with sem:
            try:
                factory = self._factories.get(src)
                if factory is None:
                    return
                sub = factory(signal)
                if sub is None:
                    return
                # Inject our discovery + the freshest signal context
                if hasattr(sub, "_discovery"):
                    sub._discovery = dict(self.discovery)
                    sub._discovery["cascade_signal"] = {
                        "kind":  signal.kind,
                        "value": signal.value,
                        "meta":  signal.meta,
                    }
                await sub.run()
                # If the subagent populated _results, merge them into
                # our discovery so downstream signals see them
                for r in getattr(sub, "_results", []) or []:
                    raw = (r or {}).get("raw") or {}
                    if raw.get("data_type") == "kev":
                        existing = list(self.discovery.get("kev_cves") or [])
                        cid = raw.get("cve_id")
                        if cid and cid not in existing:
                            existing.append(cid)
                            self.discovery["kev_cves"] = existing
                    if raw.get("data_type") == "crtsh_subdomains":
                        existing = set(self.discovery.get("subdomains") or [])
                        existing.update(raw.get("subdomains") or [])
                        self.discovery["subdomains"] = sorted(existing)
            except Exception as exc:
                logger.debug("[intel_cascade] %s failed: %s", src, exc)

    # ── Factory registration ──────────────────────────────────

    def register_source(self, token: str,
                            factory: Callable[[IntelSignal], Any]) -> None:
        self._factories[token] = factory

    def _register_default_factories(self) -> None:
        """Wire each known source token to its subagent class."""
        # Lazy imports so this module loads cheaply
        def _make(cls):
            return lambda sig: cls(
                session_id  = self.session_id,
                target      = self.target,
                broadcast_fn= self.broadcast,
                discovery   = self.discovery,
            )

        try:
            from agents.osint.github_poc_subagent import GitHubPoCSubagent
            self.register_source("github_poc", _make(GitHubPoCSubagent))
        except Exception:
            pass
        try:
            from agents.osint.cisa_kev_subagent import CisaKevSubagent
            self.register_source("cisa_kev", _make(CisaKevSubagent))
        except Exception:
            pass
        try:
            from agents.osint.crtsh_subagent import CrtshSubagent
            self.register_source("crtsh", _make(CrtshSubagent))
        except Exception:
            pass
        try:
            from agents.osint.vulners_subagent import VulnersSubagent
            self.register_source("vulners", _make(VulnersSubagent))
        except Exception:
            pass
        try:
            from agents.osint.hackerone_subagent import HackerOneSubagent
            self.register_source("hackerone", _make(HackerOneSubagent))
        except Exception:
            pass
        try:
            from agents.osint.shodan_subagent import ShodanSubagent
            self.register_source("shodan", _make(ShodanSubagent))
        except Exception:
            pass
        try:
            from agents.osint.security_trails_subagent import SecurityTrailsSubagent
            self.register_source("security_trails", _make(SecurityTrailsSubagent))
        except Exception:
            pass
        try:
            from agents.osint.builtwith_subagent import BuiltWithSubagent
            self.register_source("builtwith", _make(BuiltWithSubagent))
        except Exception:
            pass
        try:
            from agents.osint.bgpview_subagent import BGPViewSubagent
            self.register_source("bgpview", _make(BGPViewSubagent))
        except Exception:
            pass
        try:
            from agents.osint.theharvester_subagent import TheHarvesterSubagent
            self.register_source("theharvester", _make(TheHarvesterSubagent))
        except Exception:
            pass
        try:
            from agents.osint.wayback_subagent import WaybackSubagent
            self.register_source("wayback", _make(WaybackSubagent))
        except Exception:
            pass
        try:
            from agents.osint.ahmia_subagent import AhmiaSubagent
            self.register_source("ahmia", _make(AhmiaSubagent))
        except Exception:
            pass
        try:
            from agents.osint.google_dorks_subagent import GoogleDorksSubagent
            self.register_source("google_dorks", _make(GoogleDorksSubagent))
        except Exception:
            pass
        try:
            from agents.osint.censys_subagent import CensysSubagent
            self.register_source("censys", _make(CensysSubagent))
        except Exception:
            pass
        try:
            from agents.osint.hibp_subagent import HIBPSubagent
            self.register_source("hibp", _make(HIBPSubagent))
        except Exception:
            pass
        # "nvd_cpe" route — handled by the master OSINT agent's NVD
        # CPE search, not a standalone subagent.  We surface the
        # signal via discovery so the master picks it up.  No factory
        # needed; the signal still flows through SIGNAL_ROUTES so
        # observers can see it.

    # ── Source-enabled check ──────────────────────────────────

    @staticmethod
    def _source_enabled(token: str) -> bool:
        """Respect the user's SOURCES_ENABLED configuration."""
        # The cascade treats "_cpe" suffix as part of the nvd source
        canonical = token.replace("_cpe", "").rstrip("_")
        # Sources we make defaults-on independent of API keys
        always_on = {"nvd", "exploit_db", "wayback", "ahmia", "bgpview",
                       "theharvester", "github_poc", "cisa_kev", "crtsh",
                       "vulners", "hackerone", "google_dorks"}
        if canonical in always_on:
            return SOURCES_ENABLED.get(canonical, True)
        return SOURCES_ENABLED.get(canonical, False)

    # ── Status broadcast ──────────────────────────────────────

    async def _emit_status(self, message: str) -> None:
        if not self.broadcast:
            return
        try:
            await self.broadcast({
                "type":  "intel_cascade",
                "agent": "osint",
                "data":  {"message": message, "session_id": self.session_id},
            })
        except Exception:
            pass


def _is_ip_like(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", s or ""))


# ─────────────────────────────────────────────────────────────────────
#  Per-session cascade registry
# ─────────────────────────────────────────────────────────────────────

_CASCADES: Dict[str, IntelCascade] = {}


def register_cascade(cascade: IntelCascade) -> None:
    _CASCADES[cascade.session_id] = cascade


def get_cascade(session_id: str) -> Optional[IntelCascade]:
    return _CASCADES.get(session_id)


def unregister_cascade(session_id: str) -> None:
    cascade = _CASCADES.pop(session_id, None)
    if cascade is not None:
        cascade.request_stop()


__all__ = [
    "IntelSignal", "IntelCascade", "SIGNAL_ROUTES",
    "register_cascade", "get_cascade", "unregister_cascade",
]
