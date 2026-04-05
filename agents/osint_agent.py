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
import re
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
        **kwargs
    ) -> Dict:
        self._session_id = session_id
        search_terms     = search_terms or []
        services         = services or {}

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
        if result["emails"] and SOURCES_ENABLED.get("hibp"):
            hibp = HIBPSubagent(session_id, target, self.broadcast)
            try:
                await hibp.run(emails=result["emails"][:15])
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

        if SOURCES_ENABLED.get("theharvester"):
            named_coros.append(("theHarvester",
                TheHarvesterSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("recon_ng"):
            named_coros.append(("recon-ng",
                ReconNgSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("wayback"):
            named_coros.append(("wayback",
                WaybackSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("ahmia"):
            named_coros.append(("ahmia",
                AhmiaSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("bgpview"):
            named_coros.append(("bgpview",
                BGPViewSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("shodan"):
            named_coros.append(("shodan",
                ShodanSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("security_trails"):
            named_coros.append(("securitytrails",
                SecurityTrailsSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("google_dorks"):
            named_coros.append(("googledorks",
                GoogleDorksSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("builtwith"):
            named_coros.append(("builtwith",
                BuiltWithSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("tineye"):
            named_coros.append(("tineye",
                TinEyeSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("spiderfoot"):
            named_coros.append(("spiderfoot",
                SpiderFootSubagent(session_id, target, self.broadcast).run()))
        if SOURCES_ENABLED.get("censys"):
            named_coros.append(("censys",
                CensysSubagent(session_id, target, self.broadcast).run()))

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
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            for line in stdout.decode("utf-8", errors="replace").splitlines():
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
        Extracts service/version search terms from task list then runs full OSINT suite.
        """
        search_terms: List[str] = []
        for t in tasks:
            args = t.get("args", "")
            if isinstance(args, str) and args:
                search_terms.append(args)

        services = intel.get("services", {})
        for svc in services.values():
            if isinstance(svc, str) and svc:
                search_terms.append(svc)

        result = await self.run(
            session_id   = self._session_id or "",
            target       = target,
            search_terms = search_terms,
            services     = services,
        )

        return {
            "cves":            [r["cve_id"] for r in result.get("cve_details", [])],
            "exploit_modules": [
                e.get("title") or e.get("path", "")
                for e in result.get("exploit_modules", [])
            ],
            "raw_outputs": {"osint": str(result.get("synthesis", ""))[:2000]},
        }
