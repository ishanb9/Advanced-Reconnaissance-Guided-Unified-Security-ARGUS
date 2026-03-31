"""
KALI PENTEST PLATFORM v2 — OSINT Agent
Internet intelligence gathering agent.

Sources:
  - NVD (NIST National Vulnerability Database) API
  - ExploitDB search (via searchsploit + web)
  - Shodan API (optional, requires API key)
  - CVEdetails scraping
  - LLM-guided web research
  - theHarvester for email/subdomain OSINT

No API keys required for NVD (rate limited but free).
Shodan requires free API key: https://account.shodan.io
"""

import asyncio
import json
import re
import httpx
from typing import Optional, Dict, List

from agents.base_agent import BaseAgent, BroadcastFn
from db.schemas import (
    AgentName, AgentStatus, AttackPhase, FindingSeverity
)
import db.mongo_client as db


# ─── Optional API keys (set via environment or config) ─────
import os
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")   # Optional, increases rate limit


class OsintAgent(BaseAgent):
    """
    Internet OSINT and intelligence agent.
    Searches NVD, ExploitDB, and Shodan for target intelligence.
    """

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.OSINT, broadcast)
        self.phase = AttackPhase.OSINT

    async def run(
        self,
        session_id:   str,
        target:       str,
        search_terms: List[str] = None,
        services:     Dict      = None,
        **kwargs
    ) -> Dict:
        self._session_id = session_id
        search_terms = search_terms or []
        services     = services or {}

        result = {
            "exploit_modules": [],
            "cve_details":     [],
            "shodan_data":     None,
            "intelligence":    []
        }

        await self.set_status(AgentStatus.RUNNING, "Starting internet OSINT")

        # ── Step 1: NVD CVE search for each service ────────────
        unique_queries = [t for t in search_terms if len(t) > 3][:8]  # limit to 8
        for query in unique_queries:
            if self._stop_requested:
                break
            await self.set_status(AgentStatus.RUNNING, f"NVD search: {query}")
            cve_results = await self._search_nvd(query, session_id)
            result["cve_details"].extend(cve_results)
            await asyncio.sleep(0.5)  # NVD rate limiting

        # ── Step 2: Shodan lookup (if key available) ───────────
        if SHODAN_API_KEY and self._is_ip(target):
            await self.set_status(AgentStatus.RUNNING, f"Shodan lookup: {target}")
            shodan_data = await self._shodan_lookup(target, session_id)
            if shodan_data:
                result["shodan_data"] = shodan_data

        # ── Step 3: ExploitDB web search via LLM ──────────────
        for query in unique_queries[:4]:
            if self._stop_requested:
                break
            await self.set_status(AgentStatus.RUNNING, f"Exploit search: {query}")
            exploits = await self._search_exploitdb(query, session_id)
            result["exploit_modules"].extend(exploits)

        # ── Step 4: theHarvester for email/subdomain intel ─────
        if not self._is_ip(target):
            await self.set_status(AgentStatus.RUNNING, "theHarvester email/subdomain OSINT")
            th = await self.run_tool(
                "theHarvester",
                f"-d {target} -l 100 -b bing,google",
                target  = target,
                timeout = 120
            )
            if th["stdout"]:
                emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', th["stdout"])
                hosts  = re.findall(r'\b[\w\-\.]+\.' + re.escape(target) + r'\b', th["stdout"])
                if emails or hosts:
                    await self.store_finding(
                        severity    = FindingSeverity.INFO,
                        title       = f"OSINT: Emails/Hosts for {target}",
                        description = f"Found {len(emails)} emails and {len(hosts)} hostnames",
                        host        = target,
                        tool_used   = "theHarvester",
                        raw_output  = th["stdout"][:3000],
                        extra       = {"emails": emails[:20], "hosts": hosts[:20]}
                    )

        # ── Step 5: LLM synthesis of OSINT results ────────────
        if result["cve_details"] or result["exploit_modules"]:
            synthesis = await self._synthesize_intel(target, result, services)
            result["synthesis"] = synthesis
            await self._emit("osint_complete", {
                "agent":    self.name,
                "findings": len(result["cve_details"]),
                "exploits": len(result["exploit_modules"]),
                "synthesis": synthesis
            })

        await self.set_status(AgentStatus.DONE,
            f"OSINT complete — {len(result['cve_details'])} CVEs, {len(result['exploit_modules'])} exploits")

        return result

    # ─── NVD Search ───────────────────────────────────────

    async def _search_nvd(self, keyword: str, session_id: str) -> List[Dict]:
        """Search NIST NVD for CVEs matching keyword."""
        results = []
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5,
            "startIndex": 0
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code != 200:
                    return results
                data = resp.json()

            for vuln in data.get("vulnerabilities", [])[:5]:
                cve    = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                desc   = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                # CVSS score
                score    = 0.0
                severity = FindingSeverity.INFO
                metrics  = cve.get("metrics", {})
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metric_key in metrics and metrics[metric_key]:
                        cvss = metrics[metric_key][0].get("cvssData", {})
                        score = cvss.get("baseScore", 0.0)
                        sev_str = cvss.get("baseSeverity", "").upper()
                        severity = {
                            "CRITICAL": FindingSeverity.CRITICAL,
                            "HIGH":     FindingSeverity.HIGH,
                            "MEDIUM":   FindingSeverity.MEDIUM,
                            "LOW":      FindingSeverity.LOW
                        }.get(sev_str, FindingSeverity.INFO)
                        break

                entry = {
                    "cve_id":      cve_id,
                    "description": desc[:500],
                    "cvss_score":  score,
                    "severity":    severity,
                    "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "keyword":     keyword
                }
                results.append(entry)

                # Store in DB
                await db.store_osint_result(
                    session_id = session_id,
                    query      = keyword,
                    source     = "nvd",
                    title      = f"{cve_id}: {desc[:80]}",
                    summary    = desc[:400],
                    url        = entry["url"],
                    cves       = [cve_id],
                    severity   = severity,
                    relevance  = min(score / 10.0, 1.0),
                    raw        = {"score": score, "keyword": keyword}
                )

                # Store as finding if high severity
                if score >= 7.0:
                    await self.store_finding(
                        severity    = severity,
                        title       = f"CVE Found: {cve_id} (CVSS {score})",
                        description = desc[:400],
                        host        = "internet_intel",
                        cves        = [cve_id],
                        tool_used   = "nvd_api",
                        extra       = {"cvss_score": score, "keyword": keyword}
                    )

        except httpx.TimeoutException:
            await self._emit("osint_warning", {"message": f"NVD API timeout for: {keyword}"})
        except Exception as e:
            print(f"[OSINT] NVD error for '{keyword}': {e}")

        return results

    # ─── ExploitDB Search ─────────────────────────────────

    async def _search_exploitdb(self, query: str, session_id: str) -> List[Dict]:
        """Search ExploitDB website for public exploits."""
        results = []
        url = f"https://www.exploit-db.com/search?q={query.replace(' ', '+')}"
        headers = {
            "User-Agent":    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept":        "text/html,application/xhtml+xml",
            "X-Requested-With": "XMLHttpRequest"
        }
        # Use JSON API
        api_url = f"https://www.exploit-db.com/search?q={query.replace(' ', '+')}&type=exploits"
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                # ExploitDB has a JSON endpoint
                resp = await client.get(
                    "https://www.exploit-db.com/search",
                    params={"q": query, "type": "exploits"},
                    headers={**headers, "Accept": "application/json"}
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        for item in data.get("data", [])[:5]:
                            edb_id = item.get("id", "")
                            title  = item.get("description", "")
                            results.append({
                                "edb_id":   str(edb_id),
                                "title":    title,
                                "url":      f"https://www.exploit-db.com/exploits/{edb_id}",
                                "type":     item.get("type", {}).get("name", ""),
                                "platform": item.get("platform", {}).get("name", ""),
                                "keyword":  query
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
                                relevance  = 0.8,
                                raw        = item
                            )
                    except Exception:
                        pass
        except Exception as e:
            print(f"[OSINT] ExploitDB error for '{query}': {e}")

        # Also run local searchsploit (offline, fast)
        local = await self.run_tool(
            "searchsploit",
            query,
            target  = query,
            timeout = 20
        )
        if local["stdout"]:
            for line in local["stdout"].splitlines():
                if "|" in line and not line.startswith("-") and not line.lower().startswith("exploit"):
                    parts = line.split("|")
                    if len(parts) >= 2:
                        results.append({
                            "title":    parts[0].strip(),
                            "path":     parts[-1].strip(),
                            "source":   "searchsploit_local",
                            "keyword":  query
                        })

        return results[:10]

    # ─── Shodan ───────────────────────────────────────────

    async def _shodan_lookup(self, ip: str, session_id: str) -> Optional[Dict]:
        """Shodan host lookup — requires API key."""
        if not SHODAN_API_KEY:
            return None
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": SHODAN_API_KEY}
                )
                if resp.status_code != 200:
                    return None
                data = resp.json()

            summary = {
                "ip":           data.get("ip_str"),
                "org":          data.get("org"),
                "country":      data.get("country_name"),
                "os":           data.get("os"),
                "ports":        data.get("ports", []),
                "hostnames":    data.get("hostnames", []),
                "vulns":        list(data.get("vulns", {}).keys()),
                "last_update":  data.get("last_update")
            }

            await db.store_osint_result(
                session_id = session_id,
                query      = ip,
                source     = "shodan",
                title      = f"Shodan Host: {ip}",
                summary    = f"Org: {summary['org']}, Ports: {summary['ports'][:10]}, Vulns: {summary['vulns'][:5]}",
                cves       = summary["vulns"][:20],
                severity   = FindingSeverity.HIGH if summary["vulns"] else FindingSeverity.INFO,
                relevance  = 0.95,
                raw        = summary
            )

            if summary["vulns"]:
                await self.store_finding(
                    severity    = FindingSeverity.CRITICAL,
                    title       = f"Shodan: {len(summary['vulns'])} CVEs for {ip}",
                    description = f"Shodan reports {ip} has known CVEs: {', '.join(summary['vulns'][:10])}",
                    host        = ip,
                    cves        = summary["vulns"][:20],
                    tool_used   = "shodan"
                )
            return summary

        except Exception as e:
            print(f"[OSINT] Shodan error: {e}")
            return None

    # ─── LLM Synthesis ────────────────────────────────────

    async def _synthesize_intel(self, target: str, result: Dict, services: Dict) -> str:
        """LLM synthesizes all OSINT data into actionable guidance."""
        cve_summary    = [(r["cve_id"], r.get("cvss_score", 0)) for r in result["cve_details"][:10]]
        exploit_titles = [e.get("title", "") for e in result["exploit_modules"][:10]]

        prompt = f"""
You are a senior penetration tester. Synthesize this OSINT intelligence.

Target: {target}
Services: {list(services.values())[:5]}
CVEs found (cve_id, cvss_score): {cve_summary}
Public exploits available: {exploit_titles}

Provide:
1. Most critical attack vectors to try first
2. Which CVEs have reliable public exploits
3. Recommended Metasploit modules if any
4. Overall risk assessment

Be specific and actionable. Focus on what can realistically give initial access.
"""
        return await self.think(prompt, timeout=60)

    def _is_ip(self, s: str) -> bool:
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))
