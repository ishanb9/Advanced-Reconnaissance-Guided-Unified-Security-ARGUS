"""
ARGUS — OSINT Agent (Enhanced)
================================
Orchestrates a full fleet of OSINT subagents covering 13 intelligence sources.

Sources (always-on, no key required):
  nvd             — NIST National Vulnerability Database CVE search
  exploit_db      — ExploitDB + local searchsploit
  theharvester    — Email, subdomain, hostname, IP harvesting
  recon_ng        — Recon-ng framework (DNS, WHOIS, contacts, GHDB)
  wayback         — Archive.org / Wayback Machine historical URLs
  ahmia           — Ahmia.fi dark web / Tor network mentions
  bgpview         — BGP routing, ASN, IP prefix data

Sources (API key required — configure in agents/osint/osint_config.py):
  shodan          — Network scanner: ports, CVEs, banners, SSL certs
  security_trails — DNS history, subdomains, associated domains
  hibp            — Have I Been Pwned breach database
  google_dorks    — Google Custom Search with 25+ dork templates
  builtwith       — Website technology profiler
  tineye          — Reverse image search
  spiderfoot      — Local SpiderFoot instance (200+ modules)
  censys          — Internet-wide scan: hosts, ports, certs, SANs

Adding new sources
------------------
1. Create agents/osint/my_source_subagent.py extending OsintSubagentBase
2. Add an entry to SOURCES_ENABLED in agents/osint/osint_config.py
3. Import and instantiate in _run_all_subagents() below
"""

import asyncio
import os
import re
import signal as _signal
from typing import Optional, Dict, List, Any

import httpx

from agents.base_agent import BaseAgent, BroadcastFn
from db.schemas import AgentName, AgentStatus, AttackPhase, FindingSeverity
import db.mongo_client as db

# ── Config & subagent imports ─────────────────────────────────────────────────
from agents.osint.osint_config import (
    NVD_API_KEY, SOURCES_ENABLED, TIMEOUTS
)
from agents.osint.theharvester_subagent    import TheHarvesterSubagent
from agents.osint.recon_ng_subagent        import ReconNgSubagent
from agents.osint.wayback_subagent         import WaybackSubagent
from agents.osint.ahmia_subagent           import AhmiaSubagent
from agents.osint.shodan_subagent          import ShodanSubagent
from agents.osint.security_trails_subagent import SecurityTrailsSubagent
from agents.osint.bgpview_subagent         import BGPViewSubagent
from agents.osint.hibp_subagent            import HIBPSubagent
from agents.osint.google_dorks_subagent    import GoogleDorksSubagent
from agents.osint.builtwith_subagent       import BuiltWithSubagent
from agents.osint.tineye_subagent          import TinEyeSubagent
from agents.osint.spiderfoot_subagent      import SpiderFootSubagent
from agents.osint.censys_subagent          import CensysSubagent
from agents.osint.github_poc_subagent       import GitHubPoCSubagent
from agents.osint.cisa_kev_subagent         import CisaKevSubagent
from agents.osint.crtsh_subagent            import CrtshSubagent
from agents.osint.vulners_subagent          import VulnersSubagent
from agents.osint.hackerone_subagent        import HackerOneSubagent
from agents.osint.intel_cascade             import (
    IntelCascade, IntelSignal,
    register_cascade, get_cascade, unregister_cascade,
)


class OsintAgent(BaseAgent):
    """
    Master OSINT orchestrator.
    Runs all configured intelligence sources in parallel waves,
    feeds results to the OSINT Intel dashboard in real time.
    """

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.OSINT, broadcast)
        self.phase = AttackPhase.OSINT

    # ─────────────────────────────────────────────────────────────
    #  Main entry point
    # ─────────────────────────────────────────────────────────────

    async def run(
        self,
        session_id:   str,
        target:       str,
        search_terms: List[str] = None,
        services:     Dict      = None,
        discovery:    Dict      = None,
        **kwargs
    ) -> Dict:
        self._session_id = session_id
        search_terms     = search_terms or []
        services         = services or {}
        # Discovery context — EVERYTHING recon/vuln/web have already found.
        # Subagents use these artefacts to drive targeted queries instead of
        # just searching the bare IP/domain.
        self._discovery  = discovery or {}

        result: Dict = {
            "exploit_modules": [],
            "cve_details":     [],
            "shodan_data":     None,
            "intelligence":    [],
            "emails":          [],
            "subdomains":      [],
            "technologies":    [],
        }

        await self.set_status(AgentStatus.RUNNING, f"Starting comprehensive OSINT for {target}")
        await self._emit("osint_start", {
            "target":  target,
            "sources": [k for k, v in SOURCES_ENABLED.items() if v],
        })

        # ── Register the intel cascade for this engagement ─────────
        # The cascade is the "real-world tester" pivot — when any new
        # banner / CVE / domain / finding appears (now or later during
        # vuln_id / exploit phases), it fans out queries across every
        # relevant source automatically.
        cascade = IntelCascade(
            session_id = session_id,
            target     = target,
            broadcast  = self.broadcast,
            discovery  = self._discovery,
        )
        register_cascade(cascade)

        # ── Wave 1: NVD CVE search (fast, always-on) ──────────────
        cves = await self._run_nvd(target, search_terms, session_id)
        result["cve_details"].extend(cves)

        # ── Wave 2: ExploitDB ─────────────────────────────────────
        exploits = await self._run_exploitdb(search_terms, session_id)
        result["exploit_modules"].extend(exploits)

        # ── Surface CVEs + product+version into discovery context so
        # the GitHub PoC subagent can use them as search queries ────
        cve_ids = [r["cve_id"] for r in cves if r.get("cve_id")]
        cves_with_score = [
            (r["cve_id"], r.get("cvss_score", 0)) for r in cves
            if r.get("cve_id")
        ]
        self._discovery.setdefault("critical_cves", []).extend(cve_ids)
        self._discovery.setdefault("cves_with_score", []).extend(cves_with_score)
        # Deduplicate to keep the lists tight
        self._discovery["critical_cves"] = list(dict.fromkeys(
            self._discovery["critical_cves"]
        ))
        seen_sc = set()
        deduped: List[tuple] = []
        for c, s in self._discovery["cves_with_score"]:
            if c not in seen_sc:
                seen_sc.add(c)
                deduped.append((c, s))
        self._discovery["cves_with_score"] = deduped

        # ── Wave 3: All subagents run concurrently ─────────────────
        subagent_results = await self._run_all_subagents(target, session_id)

        # Harvest structured data from subagent output
        for r in subagent_results:
            raw = r.get("raw") or {}
            dt  = raw.get("data_type", "")
            if dt == "email" and raw.get("email"):
                result["emails"].append(raw["email"])
            # Every source that yields hostnames must land here, or its subdomains
            # never reach master intel.  crt.sh (certificate transparency) is the
            # single richest free source and its data_type is "crtsh_subdomains" —
            # it was absent from this list, so every CT-discovered name was parsed,
            # stored for the UI, and then silently dropped before the intel merge.
            if dt in ("harvester_results", "recon_ng_results", "crtsh_subdomains",
                      "securitytrails_subdomains", "censys_subdomains",
                      "shodan_dns", "subdomains"):
                result["subdomains"].extend(raw.get("subdomains", []))
                # Some sources name the field differently.
                for _alt in ("hostnames", "hosts", "domains"):
                    _vals = raw.get(_alt)
                    if isinstance(_vals, list):
                        result["subdomains"].extend(str(v) for v in _vals if v)
            if dt == "tech_profile":
                result["technologies"].extend(raw.get("technologies", []))
            if dt == "shodan_host":
                result["shodan_data"] = raw

        result["emails"]       = list(dict.fromkeys(result["emails"]))
        result["subdomains"]   = list(dict.fromkeys(result["subdomains"]))
        result["technologies"] = list(dict.fromkeys(result["technologies"]))

        # ── Wave 3.5: CISA KEV check (runs after NVD writes CVEs) ──
        # Must run AFTER _run_nvd has surfaced cves_with_score into
        # self._discovery.  KEV is the strongest signal we have:
        # CVEs in KEV are by definition being exploited in the wild.
        if SOURCES_ENABLED.get("cisa_kev", True):
            try:
                kev = CisaKevSubagent(
                    session_id   = session_id,
                    target       = target,
                    broadcast_fn = self.broadcast,
                    discovery    = self._discovery,
                )
                kev_results = await kev.run()
                for r in kev_results:
                    # Promote KEV-listed CVEs into the discovery
                    # context as `kev_cves` (consumed by master agent
                    # + cascade for prioritisation)
                    raw = (r or {}).get("raw") or {}
                    if raw.get("data_type") == "kev":
                        cid = raw.get("cve_id")
                        if cid:
                            existing = list(self._discovery.get("kev_cves") or [])
                            if cid not in existing:
                                existing.append(cid)
                                self._discovery["kev_cves"] = existing
            except Exception as exc:
                await self._emit("osint_warning", {
                    "message": f"CISA KEV check failed: {exc}"
                })

        # ── Wave 3.6: Intel Cascade fan-out for everything we know ──
        # Harvest signals from current intel (services + CVEs +
        # domains) and let the cascade scatter queries across every
        # registered source in parallel.  Each signal fires its
        # sources exactly once per engagement.
        try:
            count = cascade.harvest_signals_from_intel({
                "services":        services,
                "cves_with_score": self._discovery.get("cves_with_score"),
                "critical_cves":   self._discovery.get("critical_cves"),
                "hostnames":       self._discovery.get("hostnames"),
                "subdomains":      self._discovery.get("subdomains"),
            })
            if count:
                await self._emit("osint_status", {
                    "message": f"Intel cascade: harvested {count} new signals",
                })
            # Wait briefly for fan-out to complete before synthesis,
            # but cap at 60s so a slow source doesn't stall OSINT.
            await cascade.join(timeout=60.0)
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"Intel cascade fan-out failed: {exc}"
            })

        # ── Wave 4: HIBP with harvested emails ────────────────────
        # Combine harvested emails with any emails already known in discovery.
        all_emails = list(dict.fromkeys(
            (result.get("emails") or []) + (self._discovery.get("emails") or [])
        ))
        if all_emails and SOURCES_ENABLED.get("hibp"):
            hibp = HIBPSubagent(session_id, target, self.broadcast,
                                discovery=self._discovery)
            try:
                await hibp.run(emails=all_emails[:20])
            except Exception as exc:
                await self._emit("osint_warning", {
                    "message": f"HIBP email check error: {exc}"
                })

        # ── Wave 5: LLM synthesis ─────────────────────────────────
        if result["cve_details"] or result["exploit_modules"] or result["shodan_data"]:
            result["synthesis"] = await self._synthesize_intel(target, result, services)

        total = await self._count_osint_results(session_id)
        await self.set_status(
            AgentStatus.DONE,
            f"OSINT complete — {total} intel entries | "
            f"{len(result['cve_details'])} CVEs | "
            f"{len(result['exploit_modules'])} exploits | "
            f"{len(result['emails'])} emails | "
            f"{len(result['subdomains'])} subdomains"
        )
        await self._emit("osint_complete", {
            "agent":         self.name,
            "total_results": total,
            "cves":          len(result["cve_details"]),
            "exploits":      len(result["exploit_modules"]),
            "emails":        len(result["emails"]),
            "subdomains":    len(result["subdomains"]),
            "technologies":  len(result["technologies"]),
            "kev_cves":      len(self._discovery.get("kev_cves") or []),
        })

        # Surface KEV CVEs into the result so master_agent.execute_tasks
        # can fold them into the global intel for downstream prompts.
        result["kev_cves"] = list(self._discovery.get("kev_cves") or [])
        # Keep the cascade alive across the engagement — vuln_id /
        # exploit phases can submit new signals.  The MasterAgent's
        # shutdown path calls unregister_cascade(session_id).
        return result

    # ─────────────────────────────────────────────────────────────
    #  Subagent orchestration
    # ─────────────────────────────────────────────────────────────

    async def _run_all_subagents(
        self, target: str, session_id: str
    ) -> List[Dict]:
        """Run all enabled OSINT subagents concurrently."""

        named_coros: List[tuple] = []
        disco = getattr(self, "_discovery", {}) or {}

        def _mk(cls):
            return cls(session_id, target, self.broadcast, discovery=disco)

        if SOURCES_ENABLED.get("theharvester"):
            named_coros.append(("theHarvester", _mk(TheHarvesterSubagent).run()))
        if SOURCES_ENABLED.get("recon_ng"):
            named_coros.append(("recon-ng",     _mk(ReconNgSubagent).run()))
        if SOURCES_ENABLED.get("wayback"):
            named_coros.append(("wayback",      _mk(WaybackSubagent).run()))
        if SOURCES_ENABLED.get("ahmia"):
            named_coros.append(("ahmia",        _mk(AhmiaSubagent).run()))
        if SOURCES_ENABLED.get("bgpview"):
            named_coros.append(("bgpview",      _mk(BGPViewSubagent).run()))
        if SOURCES_ENABLED.get("shodan"):
            named_coros.append(("shodan",       _mk(ShodanSubagent).run()))
        if SOURCES_ENABLED.get("security_trails"):
            named_coros.append(("securitytrails", _mk(SecurityTrailsSubagent).run()))
        if SOURCES_ENABLED.get("google_dorks"):
            named_coros.append(("googledorks",  _mk(GoogleDorksSubagent).run()))
        if SOURCES_ENABLED.get("builtwith"):
            named_coros.append(("builtwith",    _mk(BuiltWithSubagent).run()))
        if SOURCES_ENABLED.get("tineye"):
            named_coros.append(("tineye",       _mk(TinEyeSubagent).run()))
        if SOURCES_ENABLED.get("spiderfoot"):
            named_coros.append(("spiderfoot",   _mk(SpiderFootSubagent).run()))
        if SOURCES_ENABLED.get("censys"):
            named_coros.append(("censys",       _mk(CensysSubagent).run()))
        if SOURCES_ENABLED.get("github_poc", True):
            named_coros.append(("github_poc",   _mk(GitHubPoCSubagent).run()))
        if SOURCES_ENABLED.get("crtsh", True):
            named_coros.append(("crtsh",        _mk(CrtshSubagent).run()))
        if SOURCES_ENABLED.get("hackerone", True):
            named_coros.append(("hackerone",    _mk(HackerOneSubagent).run()))
        if SOURCES_ENABLED.get("vulners", True):
            named_coros.append(("vulners",      _mk(VulnersSubagent).run()))
        # CISA KEV runs LAST (after NVD writes CVEs into discovery)
        # but is critical — actively-exploited check.  Handled below
        # outside the parallel batch.

        if not named_coros:
            return []

        await self.set_status(
            AgentStatus.RUNNING,
            f"Running {len(named_coros)} OSINT source(s) in parallel"
        )

        gathered = await asyncio.gather(
            *[coro for _, coro in named_coros],
            return_exceptions=True,
        )

        all_results: List[Dict] = []
        for (name, _), outcome in zip(named_coros, gathered):
            if isinstance(outcome, Exception):
                await self._emit("osint_warning", {
                    "message": f"[{name}] error: {outcome}"
                })
            elif isinstance(outcome, list):
                all_results.extend(outcome)

        return all_results

    # ─────────────────────────────────────────────────────────────
    #  NVD CVE search
    # ─────────────────────────────────────────────────────────────

    async def _run_nvd(
        self, target: str, search_terms: List[str], session_id: str
    ) -> List[Dict]:
        """Run NVD lookups — CPE-first, keyword fallback.

        CHANGE (Overpass-3 post-mortem): the old code did
        `keywordSearch=OpenSSH` which returned CVE-1999-0661 (Solaris
        telnet from 1999) and other ancient junk against modern
        targets.  Now we try to build a CPE 2.3 identifier
        (`cpe:2.3:a:openbsd:openssh:7.6p1`) and use NVD's
        `virtualMatchString` / `cpeName` parameter for product+version
        matching first.  When CPE construction fails, we fall back to
        `keywordSearch` BUT additionally filter results by published
        date so only CVEs from the last 8 years pass through (older
        CVEs against modern banners are noise).
        """
        if not SOURCES_ENABLED.get("nvd"):
            return []

        from agents.osint.cpe_builder import map_search_term_to_cpe

        cpe_queries:     List[Tuple[str, Optional[str]]] = []
        keyword_queries: List[str] = []
        for term in search_terms[:12]:
            if not term or len(term) < 3:
                continue
            cm = map_search_term_to_cpe(term)
            if cm is not None and cm.confidence >= 0.60:
                cpe_queries.append((cm.cpe_uri, cm.version))
            elif len(term) > 3 and len(term) < 80:
                keyword_queries.append(term)

        if not cpe_queries and not keyword_queries:
            if not self._is_ip(target):
                keyword_queries = [target.split(".")[0]]
            else:
                return []

        results: List[Dict] = []
        # ── CPE pass — version-specific, low-noise ──
        for cpe_uri, version in cpe_queries[:8]:
            if self._stop_requested:
                break
            await self.set_status(AgentStatus.RUNNING,
                                     f"NVD CPE search: {cpe_uri}")
            sub = await self._search_nvd_cpe(cpe_uri, version, session_id)
            results.extend(sub)
            await asyncio.sleep(0.4)

        # ── Keyword fallback — used only when no CPE matched ──
        # Cap aggressively because keyword results are low-signal.
        if not results:
            for q in keyword_queries[:4]:
                if self._stop_requested:
                    break
                await self.set_status(AgentStatus.RUNNING,
                                         f"NVD keyword fallback: {q}")
                results.extend(
                    await self._search_nvd(q, session_id, modern_only=True)
                )
                await asyncio.sleep(0.5)

        return results

    async def _search_nvd_cpe(self, cpe_uri: str,
                                 product_version: Optional[str],
                                 session_id: str) -> List[Dict]:
        """Query NVD for CVEs that apply to a specific CPE 2.3 identifier.

        Uses `virtualMatchString` which honours the version range
        constraints inside a CPE — so a query for
        `cpe:2.3:a:openbsd:openssh:7.6p1` returns ONLY CVEs whose
        affected-CPE range includes 7.6p1, instead of every OpenSSH
        CVE ever recorded.
        """
        url     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {
            "User-Agent": "ARGUS-pentest/1.0",
            "Accept":     "application/json",
        }
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        params: Dict[str, Any] = {
            "virtualMatchString": cpe_uri,
            "resultsPerPage":     20,
            "startIndex":         0,
        }
        try:
            async with httpx.AsyncClient(
                timeout=TIMEOUTS.get("default", 20)
            ) as client:
                resp = await client.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                # CPE-format error → silently fall back; rate limit → skip
                return []
            data = resp.json()
        except Exception:
            return []
        return await self._ingest_nvd_response(
            data, keyword=cpe_uri, session_id=session_id,
            product_version=product_version, source_label="nvd_cpe",
        )

    async def _search_nvd(self, keyword: str, session_id: str,
                              modern_only: bool = False) -> List[Dict]:
        """Keyword search fallback — used only when CPE construction fails.

        With `modern_only=True` (the new default for the fallback path)
        we only ask NVD for CVEs published in the last 8 years.  This
        cuts the CVE-1999/2008 noise that polluted previous runs.
        """
        kw = (keyword or "").strip()
        if not kw or len(kw) < 3 or len(kw) > 80:
            return []
        if any(c in kw for c in ("/", ":", "\n")):
            return []
        if kw.startswith(("-", "--", ".")) or kw[0].isdigit():
            return []

        url     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {
            "User-Agent": "ARGUS-pentest/1.0",      # NVD 404s on missing UA
            "Accept":     "application/json",
        }
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        params: Dict[str, Any]  = {
            "keywordSearch":  kw,
            "resultsPerPage": 10,
            "startIndex":     0,
        }
        if modern_only:
            # NVD expects ISO 8601 timestamps for the date filter
            from datetime import datetime, timedelta, timezone as _tz
            now   = datetime.now(_tz.utc)
            start = now - timedelta(days=365 * 8)
            params["pubStartDate"] = start.strftime(
                "%Y-%m-%dT%H:%M:%S.000+00:00"
            )
            params["pubEndDate"]   = now.strftime(
                "%Y-%m-%dT%H:%M:%S.000+00:00"
            )

        try:
            async with httpx.AsyncClient(
                timeout=TIMEOUTS.get("default", 20)
            ) as client:
                resp = await client.get(url, params=params, headers=headers)
            # 404/403 on the unauthenticated path == rate-limited / bad key —
            # not a server-side outage.  Skip silently so the feed isn't
            # spammed with osint_warning lines that the planner then treats
            # as evidence.
            if resp.status_code in (403, 404):
                return []
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"NVD error for '{kw[:40]}': {exc}"
            })
            return []

        return await self._ingest_nvd_response(
            data, keyword=keyword, session_id=session_id,
            product_version=None, source_label="nvd",
        )

    async def _ingest_nvd_response(
        self, data: Dict, *, keyword: str, session_id: str,
        product_version: Optional[str], source_label: str,
    ) -> List[Dict]:
        """Parse + filter + store NVD vulnerability entries.

        Filtering rules applied (Overpass-3 post-mortem):
          * Drop CVEs older than 2017 unless their CVSS >= 9.0
          * If we have a discovered version, drop CVEs whose
            affected-version range demonstrably excludes it
            (uses agents.osint.cpe_builder.in_version_range)
          * Score each entry's relevance (0.0–1.0) so the synthesis
            prompt can rank — instead of receiving a flat dump of
            generic CVEs.
        """
        from agents.osint.cpe_builder import in_version_range
        from datetime import datetime as _dt

        results: List[Dict] = []
        for vuln in data.get("vulnerabilities", [])[:15]:
            cve    = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            published = cve.get("published") or ""
            year = None
            try:
                if published:
                    year = int(published[:4])
            except Exception:
                year = None

            score    = 0.0
            severity = FindingSeverity.INFO
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(key, [])
                if metrics:
                    cvss     = metrics[0].get("cvssData", {})
                    score    = cvss.get("baseScore", 0.0) or 0.0
                    severity = {
                        "CRITICAL": FindingSeverity.CRITICAL,
                        "HIGH":     FindingSeverity.HIGH,
                        "MEDIUM":   FindingSeverity.MEDIUM,
                        "LOW":      FindingSeverity.LOW,
                    }.get(cvss.get("baseSeverity", "").upper(), FindingSeverity.INFO)
                    break

            # ── Relevance filter A: age + severity gate ──
            # Drop ancient CVEs that aren't CRITICAL (>= 9.0)
            if year is not None and year < 2017 and score < 9.0:
                continue

            # ── Relevance filter B: version applicability ──
            if product_version:
                applies = in_version_range(product_version, desc + " " + cve_id)
                if applies is False:
                    continue   # explicit non-match
                applicability = applies   # True / None
            else:
                applicability = None

            # Relevance score: blend CVSS with version-applicability and recency
            relevance = min(score / 10.0, 1.0)
            if applicability is True:
                relevance = min(1.0, relevance + 0.2)
            if year is not None and year >= 2020:
                relevance = min(1.0, relevance + 0.1)
            elif year is not None and year < 2014:
                relevance *= 0.5

            entry = {
                "cve_id":         cve_id,
                "description":    desc[:500],
                "cvss_score":     score,
                "severity":       severity,
                "url":            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "keyword":        keyword,
                "published_year": year,
                "applies":        applicability,
                "relevance":      round(relevance, 3),
                "product_version": product_version,
            }
            results.append(entry)

            await db.store_osint_result(
                session_id = session_id,
                host       = self._session_id or "",
                query      = keyword,
                source     = source_label,
                title      = f"{cve_id}: {desc[:80]}",
                summary    = desc[:400],
                url        = entry["url"],
                cves       = [cve_id],
                severity   = severity,
                relevance  = relevance,
                raw        = {
                    "score":           score,
                    "keyword":         keyword,
                    "data_type":       "cve",
                    "published_year":  year,
                    "applies":         applicability,
                    "product_version": product_version,
                },
            )

            if score >= 7.0 and applicability is not False:
                await self.store_finding(
                    severity    = severity,
                    title       = f"CVE: {cve_id} (CVSS {score})",
                    description = desc[:400],
                    host        = "internet_intel",
                    cves        = [cve_id],
                    tool_used   = source_label,
                    extra       = {"cvss_score": score, "keyword": keyword,
                                    "applies": applicability,
                                    "product_version": product_version},
                )

        # Sort by relevance desc — caller benefits from top-N triage
        results.sort(key=lambda r: r["relevance"], reverse=True)
        return results[:10]

    # ─────────────────────────────────────────────────────────────
    #  ExploitDB search
    # ─────────────────────────────────────────────────────────────

    async def _run_exploitdb(
        self, search_terms: List[str], session_id: str
    ) -> List[Dict]:
        if not SOURCES_ENABLED.get("exploit_db"):
            return []

        results: List[Dict] = []
        for q in search_terms[:4]:
            if self._stop_requested:
                break
            await self.set_status(AgentStatus.RUNNING, f"ExploitDB search: {q}")
            results.extend(await self._search_exploitdb(q, session_id))

        return results

    async def _search_exploitdb(self, query: str, session_id: str) -> List[Dict]:
        """ExploitDB lookup with version-aware filtering.

        Overpass-3 post-mortem: an OpenSSH 7.6 target was matched
        against "OpenSSH 1.2 - '.scp' File Create/Overwrite" (1999)
        and "FreeBSD OpenSSH 3.5p1 - Remote Command Execution".
        Neither applies to 7.6.  We now extract the version mentioned
        in the title and discard any title that demonstrably does NOT
        apply to the discovered version.
        """
        from agents.osint.cpe_builder import (
            map_search_term_to_cpe, in_version_range,
        )

        # Pull discovered version (if any) from the query — we get
        # strings like "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3" or
        # "Apache 2.4.66" from the master's search_terms list.
        cm = map_search_term_to_cpe(query)
        product_version = cm.version if cm is not None else None

        results: List[Dict] = []
        try:
            async with httpx.AsyncClient(
                timeout=TIMEOUTS.get("default", 20), follow_redirects=True
            ) as client:
                resp = await client.get(
                    "https://www.exploit-db.com/search",
                    params={"q": query, "type": "exploits"},
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
                        "Accept":     "application/json",
                    },
                )
            if resp.status_code == 200:
                kept = 0
                # Pull more candidates so the filter has room to work
                for item in resp.json().get("data", [])[:25]:
                    edb_id = item.get("id", "")
                    title  = item.get("description", "")
                    # Strip ANSI colour codes that exploit-db search returns
                    clean_title = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", title)
                    # ── Filter ── exclude exploits whose title's version
                    # range provably excludes the discovered version
                    if product_version:
                        applies = in_version_range(product_version, clean_title)
                        if applies is False:
                            continue
                    # Drop ancient-date prefixes: anything starting with
                    # "OpenSSH 1.x"/"OpenSSH 2.x" / "Apache 1." etc when
                    # the discovered version is in the modern major range.
                    if product_version and self._ancient_for_modern(
                        clean_title, product_version
                    ):
                        continue
                    # Compute relevance: title-mention boost + applicability
                    rel = 0.60
                    if product_version and product_version in clean_title:
                        rel = 0.95
                    elif product_version:
                        rel = 0.45 if "applies" not in locals() else (
                            0.95 if applies is True
                            else 0.55 if applies is None
                            else 0.10
                        )
                    results.append({
                        "edb_id":         str(edb_id),
                        "title":          clean_title,
                        "url":            f"https://www.exploit-db.com/exploits/{edb_id}",
                        "type":           item.get("type", {}).get("name", ""),
                        "platform":       item.get("platform", {}).get("name", ""),
                        "keyword":        query,
                        "product_version": product_version,
                        "relevance":      round(rel, 3),
                    })
                    await db.store_osint_result(
                        session_id = session_id,
                        query      = query,
                        source     = "exploit_db",
                        title      = clean_title[:100],
                        summary    = f"ExploitDB #{edb_id}: {clean_title}",
                        url        = f"https://www.exploit-db.com/exploits/{edb_id}",
                        exploits   = [str(edb_id)],
                        severity   = FindingSeverity.HIGH,
                        relevance  = rel,
                        raw        = {**item, "data_type": "exploit",
                                       "product_version": product_version},
                    )
                    kept += 1
                    if kept >= 5:
                        break
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"ExploitDB error for '{query}': {exc}"
            })

        # Local searchsploit (list form — no shell injection risk)
        try:
            proc = await asyncio.create_subprocess_exec(
                "searchsploit", query,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,  # new process group → killpg kills all children
            )
            raw_stdout = b""
            try:
                raw_stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            except asyncio.TimeoutError:
                try:
                    os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                try:
                    proc.kill()
                except Exception:
                    pass
            for line in raw_stdout.decode("utf-8", errors="replace").splitlines():
                if "|" in line and not line.startswith("-") and "Exploit Title" not in line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        results.append({
                            "title":   parts[0].strip(),
                            "path":    parts[-1].strip(),
                            "source":  "searchsploit_local",
                            "keyword": query,
                        })
        except Exception:
            pass

        return results[:10]

    # ─────────────────────────────────────────────────────────────
    #  LLM synthesis
    # ─────────────────────────────────────────────────────────────

    async def _synthesize_intel(
        self, target: str, result: Dict, services: Dict
    ) -> str:
        """Synthesise the OSINT findings into an actionable kill-chain.

        IMPORTANT CHANGE (Overpass-3 post-mortem):
        Previously this prompt dumped a flat (cve_id, cvss) list and
        asked the LLM to "synthesise".  The LLM correctly noted "these
        CVEs are ancient and don't apply" but the operator wasted 30
        minutes waiting for that conclusion.

        We now PRE-FILTER and ANNOTATE before the LLM ever sees the
        data:
          • Only CVEs with relevance >= 0.4 are passed
          • Each CVE shows: cvss + published year + applicability +
            relevance score
          • GitHub PoC hits surface alongside ExploitDB
          • The prompt explicitly tells the LLM which version was
            discovered so it can reason about applicability
          • The LLM is asked to produce a STRUCTURED block of
            concrete next commands the master can execute
        """
        # ── Filter + rank CVEs ──
        cve_details = [
            r for r in result.get("cve_details", [])
            if (r.get("relevance") or 0) >= 0.40
        ]
        cve_details.sort(key=lambda r: r.get("relevance", 0), reverse=True)
        cve_rows = [
            (
                r.get("cve_id", "?"),
                f"CVSS {r.get('cvss_score', 0):.1f}",
                f"yr={r.get('published_year', '?')}",
                f"rel={r.get('relevance', 0):.2f}",
                "APPLIES" if r.get("applies") is True
                  else "MAYBE"  if r.get("applies") is None
                  else "DOES_NOT_APPLY",
                r.get("description", "")[:120],
            )
            for r in cve_details[:8]
        ]

        # ── Filter exploits by relevance ──
        exploits = [
            (e.get("title", ""), e.get("relevance", 0.5),
              e.get("product_version", ""), e.get("url", ""))
            for e in result.get("exploit_modules", [])
            if (e.get("relevance") or 0) >= 0.50
        ]
        exploits.sort(key=lambda t: t[1], reverse=True)
        exploits = exploits[:8]

        # ── Pull GitHub PoC + Shodan hits from intelligence list ──
        github_pocs: List[str] = []
        for item in result.get("intelligence", [])[:30]:
            if not isinstance(item, dict):
                continue
            raw = item.get("raw") or {}
            if raw.get("data_type") == "github_poc":
                for repo in (raw.get("repos") or [])[:3]:
                    github_pocs.append(
                        f"{repo.get('name', '?')} ({repo.get('stars', 0)}★, "
                        f"{repo.get('lang', '?')}, {repo.get('updated', '?')}) "
                        f"— {repo.get('url', '')}"
                    )

        tech_stack   = (result.get("technologies") or [])[:10]
        emails_found = (result.get("emails") or [])[:5]

        # Service summary — show only the high-signal fields per port
        service_lines = []
        for port, svc in list(services.items())[:8]:
            if isinstance(svc, dict):
                product = svc.get("product") or svc.get("service") or "?"
                version = svc.get("version") or "?"
                service_lines.append(f"  {port}/tcp  {product}  {version}")
            else:
                service_lines.append(f"  {port}/tcp  {svc}")
        services_block = "\n".join(service_lines) or "  (none discovered)"

        cve_block = "\n".join(
            f"  • {row[0]}  {row[1]}  {row[2]}  {row[3]}  [{row[4]}]\n      {row[5]}"
            for row in cve_rows
        ) or "  (no version-applicable CVEs after filtering)"
        exploit_block = "\n".join(
            f"  • [{rel:.2f}] {title}  (v={pv or '?'}, {url})"
            for title, rel, pv, url in exploits
        ) or "  (no exploits passed version-applicability filter)"
        github_block = "\n".join(f"  • {x}" for x in github_pocs[:10]) or \
                          "  (no GitHub PoCs found yet)"

        prompt = f"""
You are a senior penetration tester producing an OSINT synthesis.

NOTE: All CVEs/exploits listed below have ALREADY been version-filtered
against the discovered service versions.  Items marked [APPLIES] match
the discovered version; [MAYBE] need manual confirmation; the
[DOES_NOT_APPLY] items have already been removed.  DO NOT advise
re-validating the filter — just use the data.

Target  : {target}
Services:
{services_block}

CVEs (relevance-ranked, version-filtered):
{cve_block}

Exploits (relevance-ranked, version-filtered):
{exploit_block}

GitHub PoCs (runnable code, star-ranked):
{github_block}

Technologies fingerprinted: {tech_stack}
Emails harvested          : {emails_found}

Produce:
1. **Most critical attack vectors** — name the top 1-3 concrete paths
   given the version-applicable findings (NOT generic categories).
2. **Reliable public exploits** — which CVEs have PoCs that work
   against the discovered versions.  If GitHub repo URLs were found,
   reference them.
3. **Concrete next commands** — a fenced ```bash block with the EXACT
   shell commands the operator should run next.  Each command must
   reference the discovered service+version, target a real port from
   the Services list above, and be runnable as-is.  No placeholder
   `<targets>` syntax.
4. **Overall risk** — Critical / High / Medium / Low with a one-line
   rationale.

Be terse.  Focus on initial-access paths, not generic categories.
""".strip()
        return await self.think(prompt, timeout=60)

    # ─────────────────────────────────────────────────────────────
    #  Helpers
    # ─────────────────────────────────────────────────────────────

    async def _count_osint_results(self, session_id: str) -> int:
        try:
            return len(await db.get_osint_results(session_id))
        except Exception:
            return 0

    @staticmethod
    def _is_ip(s: str) -> bool:
        return bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s or ""))

    @staticmethod
    def _ancient_for_modern(title: str, discovered_version: str) -> bool:
        """Return True if `title` mentions an ancient version that
        couldn't possibly apply to the modern `discovered_version`.

        Catches the Overpass-3 pattern: target had OpenSSH 7.6p1 but
        results included "OpenSSH 1.2 - '.scp' File Create/Overwrite"
        and "FreeBSD OpenSSH 3.5p1".  Compares major versions —
        anything 2+ majors lower is dropped.
        """
        if not discovered_version or not title:
            return False
        try:
            from agents.osint.cpe_builder import extract_versions
            discovered_major = int(discovered_version.split(".")[0])
        except Exception:
            return False
        versions_in_title = extract_versions(title)
        if not versions_in_title:
            return False
        try:
            title_major = int(versions_in_title[0].split(".")[0])
        except Exception:
            return False
        return (discovered_major - title_major) >= 2

    # ── Legacy compatibility: execute_tasks (called by master_agent) ──────────

    async def execute_tasks(
        self,
        target:      str,
        tasks:       List[Dict],
        phase_label: str,
        intel:       Dict,
    ) -> Dict:
        """
        Called by master_agent._phase_osint().

        Builds two things from the accumulated scan intel:
          1. `discovery_context` — rich dict of artefacts (subdomains, SSL CNs,
             emails, web tech, service versions, banners) passed down to every
             subagent so they can pivot on real findings instead of just the
             bare target string.
          2. `search_terms` — product+version strings for NVD/ExploitDB queries
             derived from actual recon output, plus LLM-suggested args.
        """
        intel = intel or {}

        # ── Pull LLM-suggested args from planned tasks ───────────────
        search_terms: List[str] = []
        for t in tasks:
            args = t.get("args", "")
            if isinstance(args, str) and args.strip():
                search_terms.append(args.strip())

        # ── Convert services dict into usable search strings ─────────
        # `services` is {port: {service, version, product, banner, ...}}, not a
        # flat map of strings. Earlier code checked isinstance(str) which was
        # always False → NVD got NO service-derived queries. Fixed here.
        services = intel.get("services", {}) or {}
        product_versions: List[str] = []          # "apache 2.4.49"
        products_only:    List[str] = []          # "OpenSSH"
        banners:          List[str] = []

        for port, svc in (services.items() if isinstance(services, dict) else []):
            if isinstance(svc, dict):
                product = (svc.get("product") or svc.get("service") or "").strip()
                version = (svc.get("version") or "").strip()
                banner  = (svc.get("banner")  or svc.get("extrainfo") or "").strip()
                if product and version:
                    product_versions.append(f"{product} {version}")
                if product:
                    products_only.append(product)
                if banner:
                    banners.append(banner[:120])
            elif isinstance(svc, str) and svc.strip():
                product_versions.append(svc.strip())

        # Also consider the flat service_versions map if present.
        sv_map = intel.get("service_versions", {}) or {}
        if isinstance(sv_map, dict):
            for ver in sv_map.values():
                if isinstance(ver, str) and ver.strip():
                    product_versions.append(ver.strip())

        # Web-tech discovered during web_testing (WhatWeb, Wappalyzer, …)
        web_tech = intel.get("web_tech") or intel.get("technologies") or []
        if isinstance(web_tech, dict):
            web_tech = list(web_tech.values())
        web_tech = [str(t).strip() for t in (web_tech or []) if str(t).strip()]

        # Compose search_terms: LLM args + product+version + web tech + OS.
        search_terms.extend(dict.fromkeys(product_versions))
        search_terms.extend(dict.fromkeys(web_tech))
        os_guess = (intel.get("os_guess") or "").strip()
        if os_guess and os_guess.lower() not in ("unknown", ""):
            search_terms.append(os_guess)
        # Dedup preserving order; cap to avoid NVD rate limits.
        search_terms = list(dict.fromkeys(search_terms))[:20]

        # ── Collect domain/host artefacts ────────────────────────────
        hostnames = list(dict.fromkeys(
            (intel.get("hostnames") or []) +
            (intel.get("subdomains") or []) +
            (intel.get("virtual_hosts") or [])
        ))
        ssl_cns = list(dict.fromkeys(
            (intel.get("ssl_cns") or []) +
            (intel.get("ssl_sans") or [])
        ))
        emails = list(dict.fromkeys(
            (intel.get("emails") or []) +
            (intel.get("harvested_emails") or [])
        ))
        users = list(dict.fromkeys(intel.get("users") or []))
        # Collect any IPs discovered beyond the primary target.
        ips = list(dict.fromkeys(
            (intel.get("resolved_ips") or []) +
            (intel.get("a_records")    or []) +
            (intel.get("ips")          or [])
        ))

        discovery_context: Dict = {
            # Network-level
            "open_ports":        intel.get("open_ports", []),
            "services":          services,
            "service_versions":  sv_map,
            "product_versions":  product_versions[:20],
            "products":          list(dict.fromkeys(products_only))[:20],
            "banners":           banners[:15],
            "os_guess":          os_guess,
            # Host/DNS-level
            "hostnames":         hostnames[:60],
            "subdomains":        list(dict.fromkeys(intel.get("subdomains") or []))[:60],
            "virtual_hosts":     list(dict.fromkeys(intel.get("virtual_hosts") or []))[:30],
            "ssl_cns":           list(dict.fromkeys(intel.get("ssl_cns") or []))[:30],
            "ssl_sans":          list(dict.fromkeys(intel.get("ssl_sans") or []))[:60],
            "ips":               ips[:20],
            # Web-level
            "web_tech":          web_tech[:30],
            "http_titles":       list(dict.fromkeys(intel.get("http_titles") or []))[:20],
            "login_pages":       list(dict.fromkeys(intel.get("login_pages") or []))[:20],
            "admin_panels":      list(dict.fromkeys(intel.get("admin_panels") or []))[:20],
            "interesting_files": list(dict.fromkeys(intel.get("interesting_files") or []))[:20],
            # People-level
            "emails":            emails[:30],
            "users":             users[:30],
            # Org-level
            "org":               intel.get("org") or intel.get("organization") or "",
            "asn":               intel.get("asn") or "",
            # Keep a reference so subagents can dig further if needed.
            "_target":           target,
            "_target_type":      intel.get("target_type", ""),
        }

        result = await self.run(
            session_id   = self._session_id or "",
            target       = target,
            search_terms = search_terms,
            services     = services,
            discovery    = discovery_context,
        )

        # Fold any newly-harvested artefacts back into master's intel so
        # downstream phases (vuln/exploit) see them.
        for key in ("emails", "subdomains", "technologies", "kev_cves"):
            vals = result.get(key) or []
            if vals:
                intel.setdefault(key, [])
                existing = intel[key] if isinstance(intel[key], list) else []
                merged = list(dict.fromkeys(list(existing) + list(vals)))
                intel[key] = merged

        # If any CVEs were found to be KEV-listed (actively exploited),
        # add them as critical pinned insights on the engagement context
        # so the master agent + LLM see them in every subsequent prompt.
        if result.get("kev_cves"):
            try:
                from agents.engagement_context import get_context
                ctx_kev = get_context(self._session_id)
                if ctx_kev is not None:
                    ctx_kev.pin_insight(
                        text=(
                            f"🔥 ACTIVELY EXPLOITED CVE(s) on this target: "
                            f"{', '.join(result['kev_cves'][:5])}.  "
                            f"CISA KEV-listed = confirmed in-the-wild "
                            f"exploitation.  These are the highest-priority "
                            f"vectors to attempt."
                        ),
                        phase="osint",
                        severity="critical",
                        source="cisa_kev",
                    )
            except Exception:
                pass

        # ────────────────────────────────────────────────────────────
        # CRITICAL FIX (was: synthesis text dropped on the floor).
        #
        # The LLM synthesis above frequently identifies the kill chain
        # ("CVE-2023-28432 on MinIO — curl POST /minio/bootstrap/v1/verify")
        # but its structured payload was only "cves" + "exploit_modules"
        # — the actionable text was buried in raw_outputs["osint"] and
        # never read by downstream phases.
        #
        # Parse the synthesis for:
        #   * concrete CVE IDs prioritised by the LLM
        #   * severity verdict (Critical/High/Medium/Low)
        #   * shell commands inside ```bash or ``` code fences
        # and stash them as STRUCTURED intel so the vuln/exploit phases
        # can pivot immediately instead of mechanical fuzzing.
        # ────────────────────────────────────────────────────────────
        synthesis_text = str(result.get("synthesis", "") or "")
        chain = self._extract_exploit_chain(synthesis_text)
        if chain.get("critical_cves") or chain.get("next_commands"):
            existing_chain = intel.get("exploit_chain") or {}
            intel["exploit_chain"] = {
                **existing_chain,
                **chain,
                "source":     "osint_synthesis",
                "discovered_at_phase": "osint",
            }
            # ── Validate LLM-supplied commands BEFORE queueing ────────
            # The exploit-phase first-strike loop consumes
            # intel["next_commands"] directly.  Any unwarranted command
            # (hydra without creds, evil-winrm without shell, sqlmap
            # without a URL) would otherwise be dispatched unchecked.
            # We filter them HERE so the queue only contains commands
            # with a necessary basis under current state.
            if chain.get("next_commands"):
                try:
                    from agents.engagement_context import (
                        get_context, check_command_warranted,
                    )
                    ctx_now = get_context(self._session_id)
                except Exception:
                    ctx_now = None
                    check_command_warranted = None
                accepted: List[str] = []
                rejected: List[Dict[str, str]] = []
                for raw_cmd in chain["next_commands"]:
                    cmd = (raw_cmd or "").strip()
                    if not cmd:
                        continue
                    if ctx_now is not None and check_command_warranted is not None:
                        ok, reason = check_command_warranted(cmd, ctx_now)
                        if not ok:
                            rejected.append({"cmd": cmd[:200], "reason": reason[:200]})
                            continue
                    accepted.append(cmd)
                if rejected:
                    intel.setdefault("rejected_commands", []).extend(rejected)
                merged_cmds = list(dict.fromkeys(
                    (intel.get("next_commands") or []) + accepted
                ))
                intel["next_commands"] = merged_cmds
                # ── CRITICAL: auto-fire focused_attack from synthesis ──
                # The user's directive: "web testing continues
                # unnecessarily even if initial foothold method is
                # possibly identified".  The moment OSINT writes
                # concrete commands, raise the focused-attack signal so
                # WSTG / WebOrchestrator / mechanical fuzz batches all
                # YIELD immediately (via should_scanners_yield contract).
                # The entry-attempt dispatcher then runs the commands
                # in parallel — no further phase wait.
                if ctx_now is not None and accepted:
                    try:
                        ctx_now.set_focused_attack(
                            endpoints=accepted[:10],
                            reason=(
                                "OSINT synthesis identified concrete kill-"
                                "chain commands.  All scanners must yield "
                                "so these can execute first."
                            ),
                            source="osint_synthesis_autofire",
                        )
                    except Exception:
                        pass
            if chain.get("critical_cves"):
                merged_cves = list(dict.fromkeys(
                    (intel.get("critical_cves") or []) + chain["critical_cves"]
                ))
                intel["critical_cves"] = merged_cves
            if chain.get("severity"):
                intel["risk_verdict"] = chain["severity"]

        # ── Cross-pipeline focused-attack signal ──────────────────
        # When the OSINT synthesis mentions specific URL paths in
        # narrative text (e.g. "the documented chain is: invite-code
        # generation via /js/inviteapi.min.js → /api/v1/invite/generate
        # → register → authenticated /api/v1/admin/*") we treat those
        # as a HIGH-CONFIDENCE LEAD and raise the focused-attack
        # signal so every long-running pipeline (WebOrchestrator's
        # 14-phase WSTG playbook, mechanical fuzz batches) yields.
        url_paths = self._extract_url_paths(synthesis_text)
        vhosts    = self._extract_vhosts(synthesis_text)
        host_for_curl = ""
        if vhosts:
            # Prefer the vhost that doesn't equal the raw target hostname
            host_for_curl = vhosts[0]
            existing_vhosts = list(intel.get("vhosts") or [])
            for v in vhosts:
                if v not in existing_vhosts:
                    existing_vhosts.append(v)
            intel["vhosts"] = existing_vhosts

        # ── Findings-driven trigger dispatch ────────────────────────
        # Evaluate the declarative when→actions trigger library against
        # the engagement context (which shares ``intel`` by reference).
        # Triggers fire ONCE per (session, trigger_name) so re-running
        # the OSINT phase doesn't duplicate kill-chain commands.
        try:
            from agents.engagement_context import get_context
            ctx = get_context(self._session_id)
        except Exception:
            ctx = None

        if ctx is not None and url_paths:
            # Build curl commands for each identified endpoint, using
            # the vhost Host header when known (fixes the "could not
            # resolve 2million.htb" exit-6 storm).
            host_arg = f"-H 'Host: {host_for_curl}' " if host_for_curl else ""
            target_host = (
                intel.get("target_host")
                or intel.get("target")
                or self._target if hasattr(self, "_target") else "TARGET"
            )
            focused_cmds = [
                f"curl -sk -m 15 {host_arg}http://{target_host}{p}"
                for p in url_paths[:8]
            ]
            ctx.set_focused_attack(
                endpoints=focused_cmds,
                reason=(
                    f"OSINT synthesis identified {len(url_paths)} specific "
                    f"URL path(s) in narrative — directing all execution "
                    f"toward these endpoints instead of generic enumeration"
                ),
                source="osint_synthesis_url_extract",
                vhost=host_for_curl,
            )
            # Also mirror into next_commands so the existing exploit-
            # phase first-strike loop picks them up.
            merged = list(dict.fromkeys(
                (intel.get("next_commands") or []) + focused_cmds
            ))
            intel["next_commands"] = merged
            # Force pivot regardless of severity classification.
            intel["pivot_to_exploit"] = True
            intel["pivot_reason"] = (
                f"OSINT synthesis identified {len(url_paths)} specific URL "
                f"endpoint(s) — pivoting to focused exploitation regardless "
                f"of CVE severity score (severity score reflects noisy CVE "
                f"queries, not the concrete chain). "
                f"First endpoint: {url_paths[0]}"
            )
        if ctx is not None:
            # First: pin the chain from OSINT synthesis as a top-line
            # insight the LLM sees in every subsequent prompt.
            try:
                ctx.pin_insights_from_intel()
            except Exception:
                pass
            try:
                from agents import finding_triggers as _ft
                actions = _ft.evaluate_triggers(ctx)
            except Exception as _exc:
                actions = []
                import logging as _llog
                _llog.getLogger(__name__).debug(
                    "finding_triggers eval failed: %s", _exc
                )
            # Merge command actions into intel["next_commands"];
            # pin insight actions; subagent dispatch is recorded so the
            # MasterAgent's pivot logic can read it.
            trig_cmds: List[str] = []
            for a in actions:
                if a.kind == "command" and a.payload:
                    trig_cmds.append(a.payload)
                elif a.kind == "insight" and a.payload:
                    try:
                        ctx.pin_insight(
                            a.payload, phase="osint",
                            severity=("critical" if a.priority >= 9
                                       else "important" if a.priority >= 6
                                       else "info"),
                            source="finding_trigger",
                        )
                    except Exception:
                        pass
                elif a.kind == "subagent" and a.payload:
                    # Pin as an insight + record in intel for the master.
                    sub_targets = list(intel.get("triggered_subagents") or [])
                    if a.payload not in sub_targets:
                        sub_targets.append(a.payload)
                    intel["triggered_subagents"] = sub_targets
            if trig_cmds:
                merged_cmds = list(dict.fromkeys(
                    (intel.get("next_commands") or []) + trig_cmds
                ))
                intel["next_commands"] = merged_cmds
                # Record on the transcript so the next LLM prompt sees
                # "10 trigger commands queued from <MinIO/SMB/etc.>"
                try:
                    ctx.pin_insight(
                        f"{len(trig_cmds)} kill-chain command(s) queued by findings-trigger system",
                        phase="osint",
                        severity="important",
                        source="finding_trigger_summary",
                    )
                except Exception:
                    pass

        return {
            "cves":            [r["cve_id"] for r in result.get("cve_details", [])],
            "exploit_modules": [
                e.get("title") or e.get("path", "")
                for e in result.get("exploit_modules", [])
            ],
            "exploit_chain":   intel.get("exploit_chain", {}),
            "next_commands":   intel.get("next_commands", []),
            "critical_cves":   intel.get("critical_cves", []),
            "raw_outputs":     {"osint": synthesis_text[:2000]},
        }

    # ─────────────────────────────────────────────────────────────
    #  OSINT-synthesis parser — extracts STRUCTURED actions from
    #  the LLM's free-form "senior pentester" verdict.  Drives the
    #  pivot trigger + exploit-phase first-strike.
    # ─────────────────────────────────────────────────────────────
    _CVE_RE      = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    # Severity verdict — LLM commonly emits "## Overall Risk Assessment\n\n**CRITICAL**"
    # so allow newlines + markdown emphasis between the heading and the verdict.
    _SEVERITY_RE = re.compile(
        r"(?:overall\s+(?:risk|severity|assessment|verdict)|risk\s+assessment)"
        r"[\s\S]{0,80}?\*?\*?\b(critical|high|medium|low)\b\*?\*?",
        re.IGNORECASE,
    )
    # Shell commands the LLM frequently emits inside ```bash blocks OR
    # bullet-pointed individual `curl … / searchsploit … / nuclei …` lines.
    _CMD_PREFIXES = ("curl", "searchsploit", "nuclei", "nmap", "gobuster",
                      "ffuf", "feroxbuster", "wfuzz", "sqlmap", "hydra",
                      "crackmapexec", "smbclient", "rpcclient", "ldapsearch",
                      "enum4linux", "smbmap", "wpscan", "evil-winrm",
                      "msfconsole", "impacket-", "python3 ")
    _CMD_LINE_RE = re.compile(
        r"^\s*(?:[-*$#]|\d+\.\s+)?\s*(" +
        "|".join(re.escape(p) for p in _CMD_PREFIXES) +
        r")\b.*$", re.IGNORECASE | re.MULTILINE,
    )
    # URL-path extractor — finds REST-style endpoints mentioned in
    # narrative LLM text (e.g., "/api/v1/invite/generate",
    # "/js/inviteapi.min.js", "/admin/login.php").  These are the
    # SPECIFIC TARGETS a red-teamer would attack — but the previous
    # bash-block-only parser ignored them because they're in prose,
    # not in fenced code.
    _URL_PATH_RE = re.compile(
        r"(?<![A-Za-z0-9_/-])"           # left boundary
        r"(/[A-Za-z0-9_-][A-Za-z0-9_./-]{2,80}"
        r"(?:/[A-Za-z0-9_.-]{0,60})*)"   # any number of path segments
        r"(?![A-Za-z0-9_/])"             # right boundary
    )
    # vhost names mentioned in synthesis text (e.g. "twomillion.htb",
    # "wingdata.htb").  Used to (a) seed the focused-attack curl Host
    # header, (b) propagate into intel["vhosts"] so downstream curls
    # auto-add the Host header.
    _VHOST_RE = re.compile(
        r"\b([a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.htb)\b",
        re.IGNORECASE,
    )

    @classmethod
    def _extract_url_paths(cls, text: str) -> List[str]:
        """Find specific URL paths mentioned in narrative LLM output.

        Filters out:
          * obvious filesystem paths (/tmp/, /usr/, /home/, /etc/, /var/)
          * generic single-segment paths (/login, /admin) UNLESS combined
            with other segments — those are too noisy on their own.
          * already-deduplicated paths

        Returns the de-duplicated list in order of first appearance.
        """
        if not text:
            return []
        # Filesystem-path noise that the regex catches but isn't a URL
        _FS_PREFIXES = ("/tmp/", "/usr/", "/var/", "/etc/", "/home/",
                          "/root/", "/bin/", "/sbin/", "/opt/", "/dev/",
                          "/proc/", "/sys/", "/mnt/", "/media/")
        seen: List[str] = []
        for m in cls._URL_PATH_RE.finditer(text):
            p = m.group(1).rstrip(".,);:")
            if not p or len(p) < 4:
                continue
            if any(p.startswith(fs) for fs in _FS_PREFIXES):
                continue
            # Drop trailing punctuation
            while p and p[-1] in ".,);:":
                p = p[:-1]
            # Require at least one slash separating a non-trivial first
            # segment from a second segment OR a clear API-style path
            segs = [s for s in p.split("/") if s]
            if len(segs) < 2 and not any(
                k in p.lower() for k in ("api", "wp-", "graphql",
                                          "swagger", "/.git", "/.env")
            ):
                continue
            if p not in seen:
                seen.append(p)
        return seen[:12]

    @classmethod
    def _extract_vhosts(cls, text: str) -> List[str]:
        """Find HTB-style virtual hostnames (`*.htb`) in narrative text."""
        if not text:
            return []
        seen: List[str] = []
        for m in cls._VHOST_RE.finditer(text):
            v = m.group(1).lower()
            if v not in seen:
                seen.append(v)
        return seen[:6]

    @classmethod
    def _extract_exploit_chain(cls, text: str) -> Dict[str, Any]:
        """Parse a senior-pentester LLM verdict and return an actionable
        chain {critical_cves, severity, next_commands}.

        Tolerant to:
          * commands inside ```bash / ``` fences
          * commands as bullet points (-, *, $, #, "1.")
          * inline mention of CVE IDs anywhere in the text
        """
        if not text:
            return {}

        # 1. CVE IDs (deduped, preserves order of appearance)
        cves = list(dict.fromkeys(m.group(0).upper()
                                    for m in cls._CVE_RE.finditer(text)))

        # 2. Severity / risk verdict
        sev_match = cls._SEVERITY_RE.search(text)
        severity = sev_match.group(1).lower() if sev_match else ""

        # 3. Shell commands — extract code-fence blocks first, then the
        #    full text for stray bullet/inline commands.
        commands: List[str] = []
        # ```bash … ``` and ``` … ``` fenced blocks
        for fence in re.finditer(r"```(?:[a-zA-Z]+\s*\n)?(.*?)```",
                                   text, flags=re.DOTALL):
            for line in fence.group(1).splitlines():
                stripped = line.strip().lstrip("$").lstrip("#").strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                    continue
                for p in cls._CMD_PREFIXES:
                    if stripped.lower().startswith(p.lower()):
                        commands.append(stripped)
                        break
        # Stray inline / bulleted commands outside code fences
        for m in cls._CMD_LINE_RE.finditer(text):
            cmd = m.group(0).lstrip(" -*$#0123456789.").strip()
            # Drop quoted/wrapped examples like "(if you …)" comments
            cmd = cmd.split("#", 1)[0].strip()
            if cmd and cmd not in commands:
                commands.append(cmd)

        # Cap at a reasonable number — we want the LLM's top picks, not a
        # firehose.  More than 25 means the parser caught noise.
        commands = commands[:25]

        return {
            "critical_cves": cves,
            "severity":      severity,
            "next_commands": commands,
        }
