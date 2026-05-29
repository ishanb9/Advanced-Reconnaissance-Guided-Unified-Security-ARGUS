"""
hackerone_subagent.py — Public HackerOne disclosed reports search.

WHY IT MATTERS
==============
HackerOne hosts the world's largest collection of disclosed real-
world vulnerability reports.  When the target uses a product like
"GitLab", "Apache Tomcat", "WordPress", or has a domain that maps to
a HackerOne program, searching disclosed reports often surfaces:

  • The exact attack pattern that worked against that product
  • Reproduction steps written by skilled hunters
  • Payloads that bypassed WAFs / filters
  • Reports for the SAME bug class on the SAME version

Even when the target isn't a HackerOne customer, the catalogue is a
goldmine for "how do people actually exploit X" guides — written by
attackers, validated by security teams, ranked by bounty payout.

No API key required for public report search.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

HACKERONE_HACKTIVITY_URL = "https://hackerone.com/hacktivity/search.json"


class HackerOneSubagent(OsintSubagentBase):
    """Search public HackerOne disclosed reports for the discovered stack."""

    SOURCE_NAME  = "hackerone"
    DISPLAY_NAME = "HackerOne Hacktivity"

    MAX_QUERIES = 8

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("hackerone", True):
            return []
        queries = self._build_queries()
        if not queries:
            return []
        await self._emit("osint_status", {
            "message": f"HackerOne: scanning disclosed reports — "
                         f"{min(len(queries), self.MAX_QUERIES)} queries"
        })
        for q, label in queries[: self.MAX_QUERIES]:
            if self._stopped:
                break
            await self._search_one(q, label)
        return self._results

    def _build_queries(self) -> List[tuple]:
        """Build searches from product+version, then bare products, then CVEs."""
        out: List[tuple] = []
        # Product+version pairs (high precision)
        for pv in (self._disco("product_versions") or [])[:6]:
            if pv and len(pv) >= 4:
                out.append((pv, f"Reports mentioning {pv}"))
        # Bare products (broader)
        seen_products: set = set()
        for p in (self._disco("products") or [])[:6]:
            p = (p or "").strip().lower()
            if p and p not in seen_products and len(p) >= 3:
                seen_products.add(p)
                out.append((p, f"Reports for product '{p}'"))
        # CVE IDs (in case any reports cite the CVE directly)
        for entry in (self._disco("cves_with_score") or [])[:4]:
            if isinstance(entry, (list, tuple)) and len(entry) >= 1:
                cid = str(entry[0])
                if re.match(r"^CVE-\d{4}-\d{4,7}$", cid, re.IGNORECASE):
                    out.append((cid, f"Reports citing {cid}"))
        return out

    async def _search_one(self, query: str, label: str) -> None:
        # HackerOne's hacktivity search supports a `query` field and
        # honours `disclosed=true` filter via URL params.  Public
        # access works for anonymous clients.
        resp = await self._get(
            HACKERONE_HACKTIVITY_URL,
            params={
                "query": query,
                "sort_type": "popular",
            },
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
                "Accept":     "application/json",
            },
            timeout=TIMEOUTS.get("hackerone", 20),
        )
        if resp is None:
            return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return
        # Hacktivity returns {"results": [...], ...}
        items = data.get("results") or []
        if not items:
            # Fall back to scraping the HTML version: build a reference URL
            # the operator can manually visit
            await self._store(
                query     = query,
                title     = f"HackerOne: no public reports for '{query}'",
                summary   = (
                    f"No disclosed reports surfaced for '{query}'.  "
                    "May exist behind a private program; check manually."
                ),
                url       = f"https://hackerone.com/hacktivity?query={query.replace(' ', '%20')}",
                severity  = FindingSeverity.INFO,
                relevance = 0.25,
                raw       = {"data_type": "hackerone_empty", "query": query},
            )
            return

        # Categorise top reports
        rows: List[Dict[str, Any]] = []
        for it in items[:5]:
            rep = it.get("hacktivity_report") or it
            rows.append({
                "title":    (rep.get("title") or "")[:200],
                "url":      rep.get("url") or rep.get("permalink") or "",
                "team":     (rep.get("team") or {}).get("handle", ""),
                "bounty":   rep.get("total_awarded_amount") or 0,
                "severity": (rep.get("severity_rating") or "").lower(),
                "disclosed_at": (rep.get("disclosed_at") or "")[:10],
            })

        # Highest payout proxies for "this is a real attack path"
        max_bounty = max((r["bounty"] or 0) for r in rows) if rows else 0
        relevance = (0.95 if max_bounty >= 10000
                       else 0.85 if max_bounty >= 1000
                       else 0.70)
        # Promote severity if any row is critical/high
        severity = FindingSeverity.MEDIUM
        if any(r["severity"] == "critical" for r in rows):
            severity = FindingSeverity.CRITICAL
        elif any(r["severity"] == "high" for r in rows):
            severity = FindingSeverity.HIGH

        summary_lines = [
            f"• {r['title']}  "
            f"({r['severity'] or 'severity?'}, ${r['bounty'] or 0}, {r['team']})  "
            f"{r['url']}"
            for r in rows
        ]
        await self._store(
            query     = query,
            title     = f"HackerOne: {label} — {len(items)} report(s) "
                          f"(max bounty ${max_bounty})",
            summary   = (
                f"HackerOne disclosed-report search for '{query}' returned "
                f"{len(items)} public report(s).  Top 5:\n\n"
                + "\n".join(summary_lines)
            ),
            url       = f"https://hackerone.com/hacktivity?query={query.replace(' ', '%20')}",
            severity  = severity,
            relevance = relevance,
            raw       = {
                "data_type":  "hackerone",
                "query":      query,
                "reports":    rows,
                "max_bounty": max_bounty,
            },
        )


__all__ = ["HackerOneSubagent"]
