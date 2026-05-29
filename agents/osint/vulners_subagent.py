"""
vulners_subagent.py — Vulners.com vulnerability aggregator.

WHY IT MATTERS
==============
Vulners aggregates 200+ vulnerability databases:
  • NVD + MITRE
  • ExploitDB + Packet Storm
  • Metasploit module registry
  • Vendor advisories (Cisco, Microsoft, Red Hat, Oracle, etc.)
  • Nuclei templates
  • GitHub security advisories
  • Twitter/X security mentions
  • Trend Micro / Checkpoint / Talos advisories

When NVD returns a CVE without much context, Vulners often has the
vendor advisory + Metasploit module + Nuclei template + multiple
PoC repos for the same CVE — giving the OSINT synthesis a much
richer picture of "is this actually exploitable?"

Free-tier usage
---------------
Vulners offers a free anonymous tier at vulners.com/api (limited
requests/minute).  Setting VULNERS_API_KEY env var lifts the cap.
We use the public search/burp endpoint which doesn't require auth
for low-volume usage.

This subagent is fan-driven by the cascade — for every discovered
CVE it issues one query that returns aggregated metadata.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

import httpx

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

VULNERS_API_KEY = os.environ.get("VULNERS_API_KEY", "")
VULNERS_SEARCH_URL = "https://vulners.com/api/v3/search/lucene/"


class VulnersSubagent(OsintSubagentBase):
    """Vulners cross-reference for discovered CVEs."""

    SOURCE_NAME  = "vulners"
    DISPLAY_NAME = "Vulners"

    MAX_CVES_PER_RUN = int(os.environ.get("VULNERS_MAX_CVES", "10"))

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("vulners", True):
            return []
        cves: List[str] = []
        for entry in (self._disco("cves_with_score") or []):
            if isinstance(entry, (list, tuple)) and len(entry) >= 1:
                cves.append(str(entry[0]).upper())
        for c in (self._disco("critical_cves") or []):
            if isinstance(c, str) and c.upper() not in cves:
                cves.append(c.upper())
        # Dedup
        cves = list(dict.fromkeys(c for c in cves if c))
        if not cves:
            return []

        await self._emit("osint_status", {
            "message": f"Vulners: enriching {min(len(cves), self.MAX_CVES_PER_RUN)} CVEs",
        })
        for cve_id in cves[: self.MAX_CVES_PER_RUN]:
            if self._stopped:
                break
            if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
                continue
            await self._search_cve(cve_id)
        return self._results

    async def _search_cve(self, cve_id: str) -> None:
        # Vulners search endpoint — query the CVE ID directly.
        headers = {
            "User-Agent": "ARGUS-pentest/1.0",
            "Accept":     "application/json",
            "Content-Type": "application/json",
        }
        if VULNERS_API_KEY:
            headers["X-Api-Key"] = VULNERS_API_KEY
        try:
            async with httpx.AsyncClient(
                timeout=TIMEOUTS.get("vulners", 20)
            ) as client:
                resp = await client.post(
                    VULNERS_SEARCH_URL,
                    json={
                        "query": cve_id,
                        "skip":  0,
                        "size":  10,
                    },
                    headers=headers,
                )
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"Vulners: {cve_id} query error: {exc}"
            })
            return
        if resp.status_code == 401:
            await self._emit("osint_warning", {
                "message": "Vulners: unauthenticated quota exhausted "
                             "— set VULNERS_API_KEY env var to extend"
            })
            return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return
        results = ((data or {}).get("data") or {}).get("search") or []
        if not results:
            return

        # Categorise the search hits by type
        types: Dict[str, List[Dict[str, Any]]] = {}
        for hit in results[:25]:
            src = hit.get("_source") or {}
            t   = src.get("bulletinFamily") or src.get("type") or "other"
            types.setdefault(t, []).append({
                "id":          src.get("id", ""),
                "title":       (src.get("title") or src.get("id", ""))[:200],
                "type":        t,
                "href":        src.get("href", ""),
                "published":   (src.get("published") or "")[:10],
                "score":       (src.get("cvss") or {}).get("score", 0),
            })
        # Build a concise summary
        lines: List[str] = []
        has_msf       = bool(types.get("metasploit"))
        has_nuclei    = bool(types.get("nuclei"))
        has_exploitdb = bool(types.get("exploitdb") or types.get("exploit"))
        has_github    = bool(types.get("githubexploit") or types.get("github"))
        for category, hits in types.items():
            if not hits:
                continue
            lines.append(f"[{category}]")
            for h in hits[:3]:
                lines.append(f"  • {h['title'][:120]}  {h['href']}")

        # Relevance: presence of working exploit code is the strongest signal
        relevance = 0.5
        signals = []
        if has_msf:
            relevance += 0.20
            signals.append("Metasploit module exists")
        if has_nuclei:
            relevance += 0.15
            signals.append("Nuclei template available")
        if has_exploitdb:
            relevance += 0.10
            signals.append("ExploitDB entry")
        if has_github:
            relevance += 0.10
            signals.append("GitHub PoC")
        relevance = min(relevance, 0.99)

        severity = (FindingSeverity.HIGH if relevance >= 0.75
                      else FindingSeverity.MEDIUM)
        if has_msf and has_exploitdb:
            severity = FindingSeverity.CRITICAL

        signal_str = " | ".join(signals) if signals else "advisory only"
        await self._store(
            query     = cve_id,
            title     = f"Vulners: {cve_id} — {signal_str}",
            summary   = (
                f"Vulners aggregation for {cve_id}.\n"
                f"Exploit signals: {signal_str}.\n\n"
                + "\n".join(lines[:60])
            ),
            url       = f"https://vulners.com/cve/{cve_id}",
            cves      = [cve_id],
            severity  = severity,
            relevance = relevance,
            raw       = {
                "data_type":       "vulners",
                "cve_id":          cve_id,
                "by_type":         types,
                "has_msf":         has_msf,
                "has_nuclei":      has_nuclei,
                "has_exploitdb":   has_exploitdb,
                "has_github_poc":  has_github,
            },
        )


__all__ = ["VulnersSubagent"]
