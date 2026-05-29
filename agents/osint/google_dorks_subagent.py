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
import os
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


# Global Google CSE health cache shared across all dorks subagent
# instances and all sessions.  When the bundled / operator-supplied
# key returns accessNotConfigured / forbidden once, the rest of the
# engagement skips Google CSE entirely — no per-query 403 noise.
_CSE_DEAD_KEYS: Dict[str, float] = {}


def _cse_key_dead(key: str) -> bool:
    import time as _t
    until = _CSE_DEAD_KEYS.get((key or "")[:16])
    return until is not None and _t.time() < until


def _cse_mark_dead(key: str, *, permanent: bool) -> None:
    import time as _t
    ttl = 86400.0 if permanent else 1800.0
    _CSE_DEAD_KEYS[(key or "")[:16]] = _t.time() + ttl


class GoogleDorksSubagent(OsintSubagentBase):
    SOURCE_NAME  = "google_dorks"
    DISPLAY_NAME = "Google Dorks"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("google_dorks"):
            return []
        # ── Pre-flight: if the API key was marked dead in a previous
        # call, skip the entire dork batch.  This stops the 56-query
        # 403 flood we saw against accessNotConfigured projects.
        if _cse_key_dead(GOOGLE_API_KEY):
            await self._emit("osint_status", {
                "message": (
                    "Google Dorks SKIPPED — API key previously failed "
                    "(accessNotConfigured / quota exhausted / invalid).  "
                    "Configure GOOGLE_API_KEY + enable Custom Search JSON "
                    "API at console.cloud.google.com/apis/library/"
                    "customsearch.googleapis.com to re-enable."
                )
            })
            return []

        target = self._target

        dorks: List[Tuple[str, str, FindingSeverity]] = []

        # ── Base dorks per discovered domain ──────────────────────
        all_domains = self._target_domains() or ([target] if not self._is_ip(target) else [])
        # Primary domain gets the full catalogue; subdomains get a subset.
        primary = all_domains[0] if all_domains else ""
        if primary:
            dorks += [(d.format(target=primary), desc, sev) for d, desc, sev in DOMAIN_DORKS]
            dorks += [(d.format(target=primary), desc, sev) for d, desc, sev in GENERAL_DORKS]
        # Subdomain-specific: focus on high-value patterns per subdomain.
        _SUB_PATTERNS = [
            ('site:{target} inurl:admin',      'Admin panels on subdomain',      FindingSeverity.HIGH),
            ('site:{target} inurl:login',      'Login pages on subdomain',       FindingSeverity.MEDIUM),
            ('site:{target} intitle:"index of"','Directory listings on subdomain',FindingSeverity.HIGH),
            ('site:{target} filetype:log OR filetype:bak', 'Log/backup on subdomain', FindingSeverity.HIGH),
        ]
        for sub in all_domains[1:6]:
            for d, desc, sev in _SUB_PATTERNS:
                dorks.append((d.format(target=sub), f"{desc} ({sub})", sev))

        # ── Tech-stack-specific dorks ─────────────────────────────
        # Pull WordPress/Drupal/Joomla/phpMyAdmin/Jenkins hints from the
        # discovered web_tech list and inject targeted dorks. This is the
        # core "discovery-driven" pivot — we only ask questions that fit the
        # stack recon actually found.
        web_tech = [str(t).lower() for t in (self._disco("web_tech") or [])]
        products = [str(p).lower() for p in (self._disco("products") or [])]
        tech_blob = " ".join(web_tech + products)

        def _has(*keys): return any(k in tech_blob for k in keys)

        tech_dorks: List[Tuple[str, str, FindingSeverity]] = []
        for dom in (all_domains[:3] or [target]):
            if _has("wordpress", "wp-", "wp "):
                tech_dorks += [
                    (f'site:{dom} inurl:wp-content/uploads filetype:sql',    'WordPress SQL dumps',      FindingSeverity.CRITICAL),
                    (f'site:{dom} inurl:wp-config',                          'WordPress config exposed', FindingSeverity.CRITICAL),
                    (f'site:{dom} inurl:wp-json/wp/v2/users',                'WordPress user enum API',  FindingSeverity.HIGH),
                ]
            if _has("drupal"):
                tech_dorks += [
                    (f'site:{dom} inurl:user/register',                      'Drupal registration page', FindingSeverity.MEDIUM),
                    (f'site:{dom} inurl:?q=admin',                           'Drupal admin path',        FindingSeverity.HIGH),
                ]
            if _has("joomla"):
                tech_dorks += [
                    (f'site:{dom} inurl:administrator/index.php',            'Joomla admin login',       FindingSeverity.HIGH),
                ]
            if _has("jenkins"):
                tech_dorks += [
                    (f'site:{dom} intitle:"Dashboard [Jenkins]"',            'Jenkins dashboard exposed', FindingSeverity.HIGH),
                ]
            if _has("jira", "confluence", "atlassian"):
                tech_dorks += [
                    (f'site:{dom} inurl:plugins/servlet',                    'Atlassian servlet exposed', FindingSeverity.HIGH),
                ]
            if _has("tomcat"):
                tech_dorks += [
                    (f'site:{dom} inurl:manager/html',                       'Tomcat manager',            FindingSeverity.CRITICAL),
                ]
        dorks += tech_dorks

        # ── Emails/usernames already harvested → credential-leak dorks ──
        for email in (self._disco("emails") or [])[:5]:
            dorks += [
                (f'"{email}" site:pastebin.com',  f'Leaked credentials for {email} on pastebin', FindingSeverity.HIGH),
                (f'"{email}" site:github.com',    f'Credentials/code referencing {email}',        FindingSeverity.MEDIUM),
            ]
        for user in (self._disco("users") or [])[:3]:
            dorks += [
                (f'"{user}" site:pastebin.com',   f'Paste mentioning user {user}',                FindingSeverity.MEDIUM),
                (f'"{user}" password site:github.com', f'Possible leaked password for {user}',    FindingSeverity.HIGH),
            ]

        # ── IP-only fallback ──────────────────────────────────────
        if self._is_ip(target) and not all_domains:
            dorks += [
                (f'"{target}" inurl:admin',        f'Admin interfaces mentioning {target}', FindingSeverity.HIGH),
                (f'"{target}" intext:"password"',  f'Pages with passwords for {target}',    FindingSeverity.HIGH),
                (f'"{target}" site:pastebin.com',  f'Pastes with IP {target}',              FindingSeverity.MEDIUM),
            ]

        # Dedup in case multiple doms produced the same dork.
        seen = set()
        unique: List[Tuple[str, str, FindingSeverity]] = []
        for d, desc, sev in dorks:
            if d not in seen:
                seen.add(d)
                unique.append((d, desc, sev))

        # Google CSE free tier = 100 queries/day. Prioritise CRITICAL/HIGH
        # severity dorks and cap total. Override with GOOGLE_DORKS_MAX env var.
        sev_rank = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH:     1,
            FindingSeverity.MEDIUM:   2,
            FindingSeverity.INFO:     3,
        }
        unique.sort(key=lambda x: sev_rank.get(x[2], 9))
        max_dorks = int(os.environ.get("GOOGLE_DORKS_MAX", "60"))
        dorks = unique[:max_dorks]

        await self._emit("osint_status", {
            "message": (
                f"Google Dorks: running {len(dorks)} discovery-driven queries "
                f"for {target} (cap={max_dorks}, sev-prioritised)"
            )
        })

        for dork, desc, severity in dorks:
            if getattr(self, "_quota_exhausted", False):
                break
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

        if not resp:
            return
        # 429 = rate limit, 403 = daily quota exhausted, accessNotConfigured,
        # or API key permission denied.  Mark the key dead in either case
        # so subsequent calls (this scan + same key on next scan) skip
        # the API and go straight to DDG.
        if resp.status_code in (403, 429):
            permanent = False
            reason = ""
            try:
                err = resp.json().get("error", {})
                if (err.get("errors") or []) and isinstance(err["errors"][0], dict):
                    reason = err["errors"][0].get("reason", "")
                if reason in ("accessNotConfigured", "PERMISSION_DENIED",
                                "forbidden", "keyInvalid"):
                    permanent = True
            except Exception:
                pass
            _cse_mark_dead(GOOGLE_API_KEY, permanent=permanent)
            self._quota_exhausted = True
            await self._emit("osint_warning", {
                "message": (
                    f"Google Dorks: HTTP {resp.status_code} ({reason or 'unknown'}) — "
                    + (
                        "Custom Search JSON API not enabled on the project for "
                        "this key — marking dead for the engagement."
                        if permanent else
                        "rate/quota — stopping further dorks for 30 minutes."
                    )
                )
            })
            return
        if resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        # Even on HTTP 200 the API sometimes returns {"error": {...}}.
        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            reason = ""
            try:
                reason = (err.get("errors") or [{}])[0].get("reason", "")
            except Exception:
                pass
            permanent = reason in ("accessNotConfigured", "PERMISSION_DENIED",
                                       "forbidden", "keyInvalid")
            if reason in ("quotaExceeded", "dailyLimitExceeded",
                           "rateLimitExceeded") or permanent:
                _cse_mark_dead(GOOGLE_API_KEY, permanent=permanent)
                self._quota_exhausted = True
                await self._emit("osint_warning", {
                    "message": f"Google Dorks: {reason} — stopping further dorks."
                })
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
