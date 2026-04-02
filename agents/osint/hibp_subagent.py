"""
hibp_subagent.py — Have I Been Pwned breach intelligence.

Checks whether email accounts associated with the target domain have been
compromised in known data breaches.

Two query modes:
  1. Domain breach check — lists all email accounts from that domain in any breach
  2. Individual email check — checks specific addresses (from theHarvester etc.)

Requires paid API key (~$3.50/month):
  https://haveibeenpwned.com/API/Key

Set env: HIBP_API_KEY
Rate limit: 1 request per 1.5 seconds (enforced automatically)
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import HIBP_API_KEY, SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

BASE_URL = "https://haveibeenpwned.com/api/v3"
_RATE_DELAY = 1.6   # seconds between requests (HIBP enforces 1 req/1.5s)

_COMMON_PREFIXES = [
    "admin", "info", "support", "security", "contact",
    "noreply", "helpdesk", "it", "webmaster", "hello",
]


class HIBPSubagent(OsintSubagentBase):
    SOURCE_NAME  = "hibp"
    DISPLAY_NAME = "Have I Been Pwned"

    @property
    def _headers(self) -> Dict:
        return {
            "hibp-api-key": HIBP_API_KEY,
            "User-Agent":   "ARGUS-OSINT/1.0",
        }

    async def run(self, emails: Optional[List[str]] = None) -> List[Dict]:
        if not SOURCES_ENABLED.get("hibp"):
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"HIBP: checking breach database for {target}"
        })

        # --- Mode 1: domain-level breach search ---
        if not self._is_ip(target):
            await self._check_domain(target)
            await asyncio.sleep(_RATE_DELAY)

        # --- Mode 2: individual email checks ---
        if not emails and not self._is_ip(target):
            emails = [f"{p}@{target}" for p in _COMMON_PREFIXES]

        for email in (emails or [])[:12]:
            if self._stopped:
                break
            await self._check_email(email)
            await asyncio.sleep(_RATE_DELAY)

        return self._results

    # ── Domain breach ─────────────────────────────────────────────

    async def _check_domain(self, domain: str):
        resp = await self._get(
            f"{BASE_URL}/breacheddomain/{domain}",
            headers=self._headers,
            timeout=TIMEOUTS.get("hibp", 15),
        )
        if not resp:
            return
        if resp.status_code == 404:
            return   # Not in any breach — good
        if resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        # Response: { "alias@domain.com": ["BreachName1", "BreachName2"], ... }
        accounts      = list(data.keys())
        total_entries = sum(len(v) for v in data.values() if isinstance(v, list))

        if not accounts:
            return

        await self._store(
            query     = domain,
            title     = f"HIBP: {len(accounts)} corporate email(s) from {domain} found in breaches",
            summary   = (
                f"{len(accounts)} accounts from {domain} are in known data breaches.\n"
                f"Total breach entries: {total_entries}\n"
                f"Sample accounts: {', '.join(accounts[:12])}"
            ),
            url       = "https://haveibeenpwned.com/DomainSearch",
            severity  = FindingSeverity.HIGH,
            relevance = 0.85,
            raw       = {
                "domain":            domain,
                "breached_accounts": accounts[:60],
                "total_entries":     total_entries,
                "data_type":         "corporate_breach",
            },
        )

    # ── Single email ──────────────────────────────────────────────

    async def _check_email(self, email: str):
        resp = await self._get(
            f"{BASE_URL}/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers=self._headers,
            timeout=TIMEOUTS.get("hibp", 15),
        )
        if not resp:
            return
        if resp.status_code == 404:
            return   # Not breached
        if resp.status_code != 200:
            return

        try:
            breaches = resp.json()
        except Exception:
            return

        if not breaches:
            return

        breach_names = [b.get("Name", "") for b in breaches]
        data_classes = list(dict.fromkeys(
            dc for b in breaches for dc in b.get("DataClasses", [])
        ))

        await self._store(
            query     = email,
            title     = f"HIBP: {email} in {len(breaches)} breach(es)",
            summary   = (
                f"Compromised in: {', '.join(breach_names[:10])}\n"
                f"Exposed data : {', '.join(data_classes[:10])}"
            ),
            url       = f"https://haveibeenpwned.com/account/{email}",
            severity  = FindingSeverity.HIGH if len(breaches) >= 3 else FindingSeverity.MEDIUM,
            relevance = 0.82,
            raw       = {
                "email":       email,
                "breaches": [
                    {
                        "name":  b.get("Name"),
                        "date":  b.get("BreachDate"),
                        "data":  b.get("DataClasses", []),
                    }
                    for b in breaches
                ],
                "data_classes": data_classes,
                "data_type":    "email_breach",
            },
        )
