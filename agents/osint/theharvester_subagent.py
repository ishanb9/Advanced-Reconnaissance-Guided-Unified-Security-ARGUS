"""
theharvester_subagent.py — theHarvester email / subdomain / employee OSINT.

theHarvester is an open-source OSINT tool that scrapes public sources for:
  - Email addresses
  - Subdomains / hosts
  - IP addresses
  - Employee names (from LinkedIn etc.)
  - Open ports (via Shodan source)

Install: pip install theHarvester  or  apt install theharvester
GitHub:  https://github.com/laramies/theHarvester
"""

from __future__ import annotations

import re
from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS, THEHARVESTER_SOURCES
from db.schemas import FindingSeverity


class TheHarvesterSubagent(OsintSubagentBase):
    SOURCE_NAME  = "theharvester"
    DISPLAY_NAME = "theHarvester"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("theharvester"):
            return []
        if self._is_ip(self._target):
            return []   # theHarvester is domain-focused

        target = self._target
        await self._emit("osint_status", {
            "message": f"theHarvester: gathering emails, subdomains, IPs for {target}"
        })

        output = await self._run_cli(
            [
                "theHarvester",
                "-d", target,
                "-l", "200",
                "-b", THEHARVESTER_SOURCES,
            ],
            timeout=TIMEOUTS.get("theharvester", 180),
        )

        if not output:
            return []

        await self._parse_and_store(target, output)
        return self._results

    # ── Output parser ─────────────────────────────────────────────

    async def _parse_and_store(self, target: str, output: str):
        emails     = list(set(re.findall(r'[\w\.\-\+]+@[\w\.\-]+\.\w{2,}', output)))
        hosts      = list(set(re.findall(
            r'\b[\w\-\.]+\.' + re.escape(target) + r'\b', output
        )))
        ips        = list(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', output)))

        # Filter bogus IPs
        ips = [ip for ip in ips if not ip.startswith(("0.", "127.", "255.", "0/"))]

        if not (emails or hosts or ips):
            return

        parts = []
        if emails: parts.append(f"{len(emails)} emails")
        if hosts:  parts.append(f"{len(hosts)} subdomains")
        if ips:    parts.append(f"{len(ips)} IPs")

        await self._store(
            query     = target,
            title     = f"theHarvester: {', '.join(parts)} for {target}",
            summary   = (
                (f"Emails ({len(emails)}):\n  " + "\n  ".join(emails[:15]) + "\n\n"
                 if emails else "")
                + (f"Subdomains ({len(hosts)}):\n  " + "\n  ".join(hosts[:15]) + "\n\n"
                   if hosts else "")
                + (f"IPs ({len(ips)}):\n  " + "\n  ".join(ips[:10])
                   if ips else "")
            ).strip(),
            severity  = FindingSeverity.MEDIUM if (emails or hosts) else FindingSeverity.INFO,
            relevance = 0.80,
            raw       = {
                "emails":      emails[:60],
                "subdomains":  hosts[:60],
                "ips":         ips[:30],
                "sources":     THEHARVESTER_SOURCES,
                "raw_output":  output[:5000],
                "data_type":   "harvester_results",
            },
        )

        # Individual email entries — makes HIBP lookups possible downstream
        for email in emails[:25]:
            await self._store(
                query     = email,
                title     = f"Email found: {email}",
                summary   = (
                    f"Email address associated with {target} "
                    f"discovered via theHarvester."
                ),
                severity  = FindingSeverity.INFO,
                relevance = 0.65,
                raw       = {
                    "email":         email,
                    "source_domain": target,
                    "data_type":     "email",
                },
                value     = email,
            )

    # ── Exported email list (for HIBP chaining) ───────────────────

    def get_emails(self) -> List[str]:
        """Return extracted emails from run() for use by HIBPSubagent."""
        return [
            r.get("raw", {}).get("email", "")
            for r in self._results
            if r.get("raw", {}).get("data_type") == "email"
        ]
