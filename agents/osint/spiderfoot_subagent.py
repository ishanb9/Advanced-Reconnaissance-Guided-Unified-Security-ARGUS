"""
spiderfoot_subagent.py — SpiderFoot automated OSINT integration.

SpiderFoot is a powerful open-source OSINT automation framework with 200+
modules covering: DNS, email, social media, dark web, threat intel, PGP
key servers, Shodan, HIBP, and many more.

Setup (required — local install):
  1. git clone https://github.com/smicallef/spiderfoot
  2. cd spiderfoot && pip3 install -r requirements.txt
  3. python3 sf.py -l 127.0.0.1:5009
  4. Set SOURCES_ENABLED["spiderfoot"] = True in osint_config.py

Config:
  SPIDERFOOT_URL     — default http://127.0.0.1:5009
  SPIDERFOOT_API_KEY — only if you enabled API auth in SpiderFoot settings
  SPIDERFOOT_SCAN_MODE:
    "PASSIVE" — safe, no direct traffic sent to target (recommended)
    "ACTIVE"  — sends probes directly to target

Results are grouped by SpiderFoot event type and stored as OSINT results.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import (
    SPIDERFOOT_URL, SPIDERFOOT_API_KEY, SPIDERFOOT_SCAN_MODE, SOURCES_ENABLED, TIMEOUTS
)
from db.schemas import FindingSeverity

# SpiderFoot event types that warrant HIGH severity
_HIGH_SEVER_TYPES = {
    "VULNERABILITY_CVE_CRITICAL", "VULNERABILITY_CVE_HIGH",
    "VULNERABILITY_GENERAL", "PASSWORD_COMPROMISED",
    "HACKED_EMAIL_ADDRESS", "LEAKSITE_URL", "DARKNET_MENTION_CONTENT",
    "CREDENTIAL_COMPROMISED",
}
_MEDIUM_SEVER_TYPES = {
    "EMAILADDR_COMPROMISED", "SOCIAL_MEDIA", "DOMAIN_WHOIS",
    "PHONE_NUMBER", "HUMAN_NAME", "USERNAME",
    "ACCOUNT_EXTERNAL_OWNED", "DARKNET_MENTION_URL",
}


class SpiderFootSubagent(OsintSubagentBase):
    SOURCE_NAME  = "spiderfoot"
    DISPLAY_NAME = "SpiderFoot"

    @property
    def _headers(self) -> Dict:
        h = {"Accept": "application/json"}
        if SPIDERFOOT_API_KEY:
            h["X-SpiderFoot-API-Key"] = SPIDERFOOT_API_KEY
        return h

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("spiderfoot"):
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"SpiderFoot: starting {SPIDERFOOT_SCAN_MODE} scan for {target}"
        })

        scan_id = await self._start_scan(target)
        if not scan_id:
            await self._emit("osint_warning", {
                "message": "SpiderFoot: could not start scan — is SpiderFoot running at "
                           + SPIDERFOOT_URL + "?"
            })
            return []

        await self._emit("osint_status", {
            "message": f"SpiderFoot: scan {scan_id} running (may take several minutes)..."
        })

        completed = await self._wait_for_scan(scan_id)
        if not completed:
            await self._emit("osint_warning", {
                "message": f"SpiderFoot: scan {scan_id} did not complete within timeout"
            })
            return []

        await self._fetch_results(scan_id, target)
        return self._results

    # ── Start scan ────────────────────────────────────────────────

    async def _start_scan(self, target: str) -> Optional[str]:
        if self._is_ip(target):
            sf_type = "IP_ADDRESS"
        elif self._is_email(target):
            sf_type = "EMAILADDR"
        else:
            sf_type = "INTERNET_NAME"

        resp = await self._post(
            f"{SPIDERFOOT_URL}/startscan",
            form_data={
                "scanname":   f"ARGUS_{target.replace('.', '_')}",
                "scantarget": target,
                "typetarget": sf_type,
                "usecase":    SPIDERFOOT_SCAN_MODE,
                "modulelist": "",
            },
            headers=self._headers,
            timeout=15,
        )
        if not resp or resp.status_code != 200:
            return None
        try:
            return resp.json().get("id", "") or None
        except Exception:
            return None

    # ── Poll for completion ───────────────────────────────────────

    async def _wait_for_scan(self, scan_id: str) -> bool:
        max_wait = TIMEOUTS.get("spiderfoot_scan", 600)
        waited   = 0
        while waited < max_wait:
            await asyncio.sleep(15)
            waited += 15

            resp = await self._get(
                f"{SPIDERFOOT_URL}/scanstatus/{scan_id}",
                headers=self._headers,
                timeout=10,
            )
            if not resp or resp.status_code != 200:
                continue
            try:
                status = resp.json().get("status", "")
            except Exception:
                continue

            if status in ("FINISHED", "FAILED", "ABORTED"):
                return status == "FINISHED"

        return False

    # ── Fetch and store results ───────────────────────────────────

    async def _fetch_results(self, scan_id: str, target: str):
        resp = await self._get(
            f"{SPIDERFOOT_URL}/scaneventresultsunique/{scan_id}",
            params={"eventType": ""},
            headers=self._headers,
            timeout=30,
        )
        if not resp or resp.status_code != 200:
            return
        try:
            rows = resp.json()
        except Exception:
            return

        # Group by event type
        by_type: Dict[str, List[str]] = {}
        for row in (rows or []):
            et  = row[4] if len(row) > 4 else "UNKNOWN"
            val = str(row[1]) if len(row) > 1 else ""
            by_type.setdefault(et, []).append(val)

        for event_type, values in by_type.items():
            if not values:
                continue

            if event_type in _HIGH_SEVER_TYPES:
                severity  = FindingSeverity.HIGH
                relevance = 0.85
            elif event_type in _MEDIUM_SEVER_TYPES:
                severity  = FindingSeverity.MEDIUM
                relevance = 0.70
            else:
                severity  = FindingSeverity.INFO
                relevance = 0.55

            await self._store(
                query     = target,
                title     = f"SpiderFoot [{event_type}]: {len(values)} result(s)",
                summary   = "\n".join(v[:200] for v in values[:25]),
                severity  = severity,
                relevance = relevance,
                raw       = {
                    "event_type": event_type,
                    "values":     [v[:500] for v in values[:60]],
                    "scan_id":    scan_id,
                    "data_type":  "spiderfoot",
                },
            )
