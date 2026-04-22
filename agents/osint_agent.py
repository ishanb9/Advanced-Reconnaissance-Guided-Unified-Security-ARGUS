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
from typing import Optional, Dict, List

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

        # ── Wave 1: NVD CVE search (fast, always-on) ──────────────
        cves = await self._run_nvd(target, search_terms, session_id)
        result["cve_details"].extend(cves)

        # ── Wave 2: ExploitDB ─────────────────────────────────────
        exploits = await self._run_exploitdb(search_terms, session_id)
        result["exploit_modules"].extend(exploits)

        # ── Wave 3: All subagents run concurrently ─────────────────
        subagent_results = await self._run_all_subagents(target, session_id)

        # Harvest structured data from subagent output
        for r in subagent_results:
            raw = r.get("raw") or {}
            dt  = raw.get("data_type", "")
            if dt == "email" and raw.get("email"):
                result["emails"].append(raw["email"])
            if dt in ("harvester_results", "recon_ng_results"):
                result["subdomains"].extend(raw.get("subdomains", []))
            if dt == "tech_profile":
                result["technologies"].extend(raw.get("technologies", []))
            if dt == "shodan_host":
                result["shodan_data"] = raw

        result["emails"]       = list(dict.fromkeys(result["emails"]))
        result["subdomains"]   = list(dict.fromkeys(result["subdomains"]))
        result["technologies"] = list(dict.fromkeys(result["technologies"]))

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
        })

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
        if not SOURCES_ENABLED.get("nvd"):
            return []

        queries = [t for t in search_terms if len(t) > 3][:8]
        if not queries and not self._is_ip(target):
            queries = [target.split(".")[0]]

        results: List[Dict] = []
        for q in queries:
            if self._stop_requested:
                break
            await self.set_status(AgentStatus.RUNNING, f"NVD CVE search: {q}")
            results.extend(await self._search_nvd(q, session_id))
            await asyncio.sleep(0.5)

        return results

    async def _search_nvd(self, keyword: str, session_id: str) -> List[Dict]:
        url     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        params  = {"keywordSearch": keyword, "resultsPerPage": 5, "startIndex": 0}

        try:
            async with httpx.AsyncClient(
                timeout=TIMEOUTS.get("default", 20)
            ) as client:
                resp = await client.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"NVD error for '{keyword}': {exc}"
            })
            return []

        results: List[Dict] = []
        for vuln in data.get("vulnerabilities", [])[:5]:
            cve    = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc   = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            score    = 0.0
            severity = FindingSeverity.INFO
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(key, [])
                if metrics:
                    cvss     = metrics[0].get("cvssData", {})
                    score    = cvss.get("baseScore", 0.0)
                    severity = {
                        "CRITICAL": FindingSeverity.CRITICAL,
                        "HIGH":     FindingSeverity.HIGH,
                        "MEDIUM":   FindingSeverity.MEDIUM,
                        "LOW":      FindingSeverity.LOW,
                    }.get(cvss.get("baseSeverity", "").upper(), FindingSeverity.INFO)
                    break

            entry = {
                "cve_id":      cve_id,
                "description": desc[:500],
                "cvss_score":  score,
                "severity":    severity,
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "keyword":     keyword,
            }
            results.append(entry)

            await db.store_osint_result(
                session_id = session_id,
                host       = self._session_id or "",
                query      = keyword,
                source     = "nvd",
                title      = f"{cve_id}: {desc[:80]}",
                summary    = desc[:400],
                url        = entry["url"],
                cves       = [cve_id],
                severity   = severity,
                relevance  = min(score / 10.0, 1.0),
                raw        = {"score": score, "keyword": keyword, "data_type": "cve"},
            )

            if score >= 7.0:
                await self.store_finding(
                    severity    = severity,
                    title       = f"CVE: {cve_id} (CVSS {score})",
                    description = desc[:400],
                    host        = "internet_intel",
                    cves        = [cve_id],
                    tool_used   = "nvd_api",
                    extra       = {"cvss_score": score, "keyword": keyword},
                )

        return results

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
                for item in resp.json().get("data", [])[:5]:
                    edb_id = item.get("id", "")
                    title  = item.get("description", "")
                    results.append({
                        "edb_id":   str(edb_id),
                        "title":    title,
                        "url":      f"https://www.exploit-db.com/exploits/{edb_id}",
                        "type":     item.get("type", {}).get("name", ""),
                        "platform": item.get("platform", {}).get("name", ""),
                        "keyword":  query,
                    })
                    await db.store_osint_result(
                        session_id = session_id,
                        query      = query,
                        source     = "exploit_db",
                        title      = title[:100],
                        summary    = f"ExploitDB #{edb_id}: {title}",
                        url        = f"https://www.exploit-db.com/exploits/{edb_id}",
                        exploits   = [str(edb_id)],
                        severity   = FindingSeverity.HIGH,
                        relevance  = 0.80,
                        raw        = {**item, "data_type": "exploit"},
                    )
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
        cve_summary    = [
            (r["cve_id"], r.get("cvss_score", 0))
            for r in result.get("cve_details", [])[:10]
        ]
        exploit_titles = [e.get("title", "") for e in result.get("exploit_modules", [])[:10]]
        tech_stack     = result.get("technologies", [])[:10]
        emails_found   = result.get("emails", [])[:5]

        prompt = f"""
You are a senior penetration tester. Synthesize the following OSINT intelligence.

Target       : {target}
Services     : {list(services.values())[:5]}
CVEs found   : {cve_summary}
Exploits     : {exploit_titles}
Technologies : {tech_stack}
Emails found : {emails_found}

Provide:
1. Most critical attack vectors to prioritise
2. Which CVEs have reliable public exploits
3. Recommended Metasploit modules
4. Social engineering opportunities (if emails found)
5. Overall risk assessment (Critical / High / Medium / Low)

Be specific and actionable. Focus on realistic initial access paths.
"""
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
        for key in ("emails", "subdomains", "technologies"):
            vals = result.get(key) or []
            if vals:
                intel.setdefault(key, [])
                existing = intel[key] if isinstance(intel[key], list) else []
                merged = list(dict.fromkeys(list(existing) + list(vals)))
                intel[key] = merged

        return {
            "cves":            [r["cve_id"] for r in result.get("cve_details", [])],
            "exploit_modules": [
                e.get("title") or e.get("path", "")
                for e in result.get("exploit_modules", [])
            ],
            "raw_outputs": {"osint": str(result.get("synthesis", ""))[:2000]},
        }
