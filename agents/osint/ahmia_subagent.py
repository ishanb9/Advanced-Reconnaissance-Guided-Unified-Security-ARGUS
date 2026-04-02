"""
ahmia_subagent.py — Ahmia.fi dark web / Tor network OSINT.

Ahmia.fi is a clearnet-accessible search engine for the Tor (.onion) network.
Searches for mentions of the target in dark web sites.

Use cases:
  - Check if target credentials/data are being traded
  - Discover if the organisation appears in leak sites
  - Find .onion mirrors or related infrastructure

No API key required. Rate limit: be gentle (~1 req per search term).
"""

from __future__ import annotations

import re
from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

AHMIA_SEARCH_URL = "https://ahmia.fi/search/"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml",
}


class AhmiaSubagent(OsintSubagentBase):
    SOURCE_NAME  = "ahmia"
    DISPLAY_NAME = "Ahmia (Dark Web)"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("ahmia"):
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"Ahmia: dark web / Tor search for {target}"
        })

        queries = self._build_queries(target)

        for q in queries:
            if self._stopped:
                break
            await self._search_ahmia(q)

        return self._results

    # ── Query builder ─────────────────────────────────────────────

    def _build_queries(self, target: str) -> List[str]:
        queries = [target]
        if not self._is_ip(target):
            parts = target.split(".")
            # Add the organisation name (second-level domain)
            if len(parts) >= 2:
                queries.append(parts[-2])
        return queries

    # ── Search ────────────────────────────────────────────────────

    async def _search_ahmia(self, query: str):
        resp = await self._get(
            AHMIA_SEARCH_URL,
            params={"q": query},
            headers=_HEADERS,
            timeout=TIMEOUTS.get("ahmia", 30),
        )

        if not resp or resp.status_code != 200:
            return

        html = resp.text

        # .onion URLs found in page
        onion_links = list(set(re.findall(
            r'https?://[a-z2-7]{16,56}\.onion[^\s"\'<>]*', html
        )))

        # Result count reported by Ahmia
        count_match = re.search(r'About\s+([\d,]+)\s+result', html)
        count_str   = count_match.group(1) if count_match else "0"
        count_int   = int(count_str.replace(",", "")) if count_match else 0

        # Page titles from result snippets
        titles = re.findall(r'<h4[^>]*>\s*([^<]{4,120})\s*</h4>', html)

        if count_int == 0 and not onion_links:
            return

        await self._store(
            query     = query,
            title     = f"Ahmia: {count_str} dark web results for '{query}'",
            summary   = (
                f"'{query}' appears in {count_str} indexed Tor (.onion) results.\n"
                + (
                    "\nSample .onion sites:\n  " + "\n  ".join(onion_links[:6])
                    if onion_links else ""
                )
                + (
                    "\nResult titles:\n  " + "\n  ".join(titles[:6])
                    if titles else ""
                )
            ),
            url       = f"https://ahmia.fi/search/?q={query}",
            severity  = FindingSeverity.HIGH if onion_links else FindingSeverity.MEDIUM,
            relevance = 0.65,
            raw       = {
                "query":        query,
                "result_count": count_str,
                "onion_links":  onion_links[:30],
                "titles":       titles[:20],
                "data_type":    "dark_web_mentions",
            },
        )
