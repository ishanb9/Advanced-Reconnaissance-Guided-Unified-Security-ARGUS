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
        # Bug-fix (post-mortem of v2 crash 2026-04-19): the OSINT planner
        # was forwarding command-fragment "queries" like
        # "-d 10.129.33.11 -b all" or "net:10.129.33.11/24" to NVD, which
        # always 404s.  Reject obvious junk before firing — anything that
        # isn't a plausible service+version keyword is dropped silently.
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
        params  = {"keywordSearch": kw, "resultsPerPage": 5, "startIndex": 0}

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
