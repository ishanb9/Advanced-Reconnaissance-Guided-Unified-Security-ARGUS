"""
wayback_subagent.py — Archive.org / Wayback Machine intelligence.

Uses the free CDX Server API to discover:
  - All archived URLs for the target domain
  - Historical paths that may expose sensitive files
  - Old admin panels, login pages, config files, backups
  - Deleted content that may still be accessible via archive

No API key required.
CDX API docs: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
"""

from __future__ import annotations

import re
from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

CDX_URL = "http://web.archive.org/cdx/search/cdx"

# Path fragments that indicate sensitive or interesting pages
INTERESTING_PATTERNS = [
    "admin", "login", "config", "backup", "wp-admin", "phpinfo",
    ".env", "passwd", "credential", "api/", "swagger", ".git",
    "debug", "test", "dev.", "staging", "upload", "dashboard",
    "panel", "secret", "token", "key", "database", "db.", ".bak",
    ".sql", ".log", ".xml", ".json", "setup", "install", "readme",
]


class WaybackSubagent(OsintSubagentBase):
    SOURCE_NAME  = "wayback"
    DISPLAY_NAME = "Wayback Machine"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("wayback"):
            return []

        # Query once per discovered domain — apex target PLUS every subdomain
        # and SSL CN/SAN recon turned up. Each gets its own archive sweep so
        # we find historical admin panels / backups per-host, not just root.
        domains = self._target_domains()
        if not domains:
            return []

        for dom in domains[:8]:
            if self._stopped:
                break
            await self._query_domain(dom)
        return self._results

    async def _query_domain(self, target: str):
        await self._emit("osint_status", {
            "message": f"Wayback Machine: querying Archive.org for {target}"
        })

        resp = await self._get(
            CDX_URL,
            params={
                "url":      f"*.{target}/*",
                "output":   "json",
                "fl":       "original,statuscode,timestamp",
                "collapse": "urlkey",
                "limit":    500,
                "filter":   "statuscode:200",
            },
            timeout=TIMEOUTS.get("wayback", 30),
        )

        if not resp or resp.status_code != 200:
            return
        try:
            rows = resp.json()
        except Exception:
            return
        if len(rows) <= 1:          # Only the header row returned
            return

        urls       = [r[0] for r in rows[1:] if r and len(r) >= 1]
        timestamps = [r[2] for r in rows[1:] if r and len(r) >= 3 and r[2]]

        interesting = [
            u for u in urls
            if any(p in u.lower() for p in INTERESTING_PATTERNS)
        ]

        latest_ts   = max(timestamps) if timestamps else ""
        earliest_ts = min(timestamps) if timestamps else ""

        if urls:
            await self._store(
                query     = target,
                title     = f"Wayback Machine: {len(urls)} archived URLs for {target}",
                summary   = (
                    f"Total archived pages : {len(urls)}\n"
                    f"Date range           : "
                    f"{earliest_ts[:8] if earliest_ts else '?'} – "
                    f"{latest_ts[:8] if latest_ts else '?'}\n"
                    f"Interesting paths    : {len(interesting)}"
                    + (
                        "\n\nNotable URLs:\n  " + "\n  ".join(interesting[:12])
                        if interesting else ""
                    )
                ),
                url       = f"https://web.archive.org/web/*/{target}",
                severity  = FindingSeverity.MEDIUM if interesting else FindingSeverity.INFO,
                relevance = 0.60,
                raw       = {
                    "total_urls":    len(urls),
                    "interesting":   interesting[:60],
                    "sample_urls":   urls[:50],
                    "latest_ts":     latest_ts,
                    "earliest_ts":   earliest_ts,
                    "data_type":     "archived_urls",
                },
            )

        # Store individually notable paths (first 10)
        for url in interesting[:10]:
            await self._store(
                query     = target,
                title     = f"Archived sensitive path: {url[-80:]}",
                summary   = (
                    "Historical URL found in Archive.org / Wayback Machine.\n"
                    "May expose sensitive data or older vulnerable versions."
                ),
                url       = f"https://web.archive.org/web/*/{url}",
                severity  = FindingSeverity.MEDIUM,
                relevance = 0.70,
                raw       = {"url": url, "data_type": "interesting_archived_url"},
            )
