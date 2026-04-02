"""
google_dorks_subagent.py — Automated Google Dorking via Custom Search API.

Google Dorks use specialised search operators to find sensitive information
indexed by Google that is publicly accessible but not intended to be.
Operators used: site:, filetype:, inurl:, intitle:, intext:

Requires:
  GOOGLE_API_KEY — https://console.developers.google.com (free: 100 queries/day)
  GOOGLE_CX      — https://cse.google.com → create engine set to "Search the entire web"

Set env vars: GOOGLE_API_KEY, GOOGLE_CX

Add / remove dorks by editing DOMAIN_DORKS or GENERAL_DORKS below.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Tuple

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import GOOGLE_API_KEY, GOOGLE_CX, SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

GOOGLE_SEARCH_URL = "https://www.googleapis.com/customsearch/v1"

# (dork_template, human_description, severity)
# {target} is replaced with the actual domain/IP
DOMAIN_DORKS: List[Tuple[str, str, FindingSeverity]] = [
    ('site:{target} filetype:pdf',                     'PDF documents exposed',                   FindingSeverity.INFO),
    ('site:{target} filetype:xls OR filetype:xlsx',    'Spreadsheets publicly accessible',        FindingSeverity.MEDIUM),
    ('site:{target} filetype:sql',                     'SQL dump files indexed',                  FindingSeverity.HIGH),
    ('site:{target} filetype:log',                     'Log files publicly accessible',           FindingSeverity.HIGH),
    ('site:{target} filetype:conf OR filetype:cfg',    'Config files indexed',                    FindingSeverity.HIGH),
    ('site:{target} filetype:bak OR filetype:old',     'Backup files indexed',                    FindingSeverity.HIGH),
    ('site:{target} inurl:admin',                      'Admin panels indexed',                    FindingSeverity.HIGH),
    ('site:{target} inurl:login',                      'Login pages indexed',                     FindingSeverity.MEDIUM),
    ('site:{target} inurl:config',                     'Config paths indexed',                    FindingSeverity.HIGH),
    ('site:{target} inurl:backup',                     'Backup paths indexed',                    FindingSeverity.HIGH),
    ('site:{target} inurl:.git',                       'Git repositories exposed',                FindingSeverity.CRITICAL),
    ('site:{target} inurl:phpinfo',                    'PHP info pages exposed',                  FindingSeverity.HIGH),
    ('site:{target} intitle:"index of"',               'Directory listings open',                 FindingSeverity.HIGH),
    ('site:{target} intext:"password"',                'Pages mentioning passwords',              FindingSeverity.HIGH),
    ('site:{target} intext:"api_key" OR intext:"apikey"', 'API keys in page content',            FindingSeverity.CRITICAL),
    ('site:{target} intext:"error" OR intext:"exception" OR intext:"stack trace"',
                                                        'Error/exception pages indexed',          FindingSeverity.MEDIUM),
    ('site:{target} inurl:wp-admin OR inurl:wp-login', 'WordPress admin interfaces',              FindingSeverity.HIGH),
    ('site:{target} inurl:phpmyadmin',                 'phpMyAdmin exposed',                      FindingSeverity.CRITICAL),
    ('site:{target} inurl:jenkins',                    'Jenkins CI/CD exposed',                   FindingSeverity.HIGH),
    ('site:{target} inurl:kibana',                     'Kibana dashboard exposed',                FindingSeverity.HIGH),
    ('site:{target} inurl:grafana',                    'Grafana dashboard exposed',               FindingSeverity.MEDIUM),
    ('site:{target} inurl:swagger OR inurl:api-docs',  'API documentation exposed',              FindingSeverity.MEDIUM),
    ('site:{target} ext:env OR ext:yml inurl:secret',  'Environment/secret files indexed',       FindingSeverity.CRITICAL),
]

GENERAL_DORKS: List[Tuple[str, str, FindingSeverity]] = [
    ('"{target}" site:pastebin.com',                   'Pastes mentioning target',                FindingSeverity.HIGH),
    ('"{target}" site:github.com',                     'GitHub repos / issues mentioning target', FindingSeverity.MEDIUM),
    ('"{target}" site:gitlab.com',                     'GitLab mentions of target',               FindingSeverity.MEDIUM),
    ('"{target}" site:linkedin.com',                   'LinkedIn profiles / company page',        FindingSeverity.INFO),
    ('"{target}" filetype:pdf site:gov.uk OR site:gov OR site:edu', 'Government/academic docs',  FindingSeverity.INFO),
    ('email "{target}"',                               'Email addresses for target domain',       FindingSeverity.INFO),
]


class GoogleDorksSubagent(OsintSubagentBase):
    SOURCE_NAME  = "google_dorks"
    DISPLAY_NAME = "Google Dorks"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("google_dorks"):
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"Google Dorks: running {len(DOMAIN_DORKS) + len(GENERAL_DORKS)} queries for {target}"
        })

        dorks: List[Tuple[str, str, FindingSeverity]] = []

        if not self._is_ip(target):
            dorks += [(d.format(target=target), desc, sev) for d, desc, sev in DOMAIN_DORKS]
            dorks += [(d.format(target=target), desc, sev) for d, desc, sev in GENERAL_DORKS]
        else:
            dorks = [
                (f'"{target}" inurl:admin',   f'Admin interfaces mentioning {target}', FindingSeverity.HIGH),
                (f'"{target}" intext:"password"', f'Pages with passwords for {target}', FindingSeverity.HIGH),
                (f'"{target}" site:pastebin.com', f'Pastes with IP {target}',           FindingSeverity.MEDIUM),
            ]

        for dork, desc, severity in dorks:
            if self._stopped:
                break
            await self._run_dork(dork, desc, severity)
            await asyncio.sleep(0.4)    # Stay within free-tier 100/day budget

        return self._results

    # ── Single dork query ─────────────────────────────────────────

    async def _run_dork(
        self,
        dork:     str,
        description: str,
        severity: FindingSeverity,
    ):
        resp = await self._get(
            GOOGLE_SEARCH_URL,
            params={
                "key": GOOGLE_API_KEY,
                "cx":  GOOGLE_CX,
                "q":   dork,
                "num": 5,
            },
            timeout=TIMEOUTS.get("google_dorks", 15),
        )

        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        items = data.get("items", [])
        if not items:
            return

        results_text = "\n".join(
            f"• {item.get('title', '(no title)')}\n  {item.get('link', '')}"
            for item in items[:5]
        )
        total = data.get("searchInformation", {}).get("totalResults", "0")

        # Severity bump for critical dorks with actual results
        effective_sev = severity
        if severity == FindingSeverity.CRITICAL and items:
            effective_sev = FindingSeverity.CRITICAL
        elif severity == FindingSeverity.HIGH and items:
            effective_sev = FindingSeverity.HIGH

        await self._store(
            query     = dork,
            title     = f"Google Dork: {description} — {total} result(s)",
            summary   = f"Query: {dork}\n\nResults ({total} total):\n{results_text}",
            url       = f"https://www.google.com/search?q={dork.replace(' ', '+')}",
            severity  = effective_sev,
            relevance = 0.80 if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) else 0.55,
            raw       = {
                "dork":        dork,
                "description": description,
                "total":       total,
                "items": [
                    {
                        "title":   i.get("title", ""),
                        "url":     i.get("link", ""),
                        "snippet": i.get("snippet", ""),
                    }
                    for i in items
                ],
                "data_type":   "google_dork",
            },
        )
