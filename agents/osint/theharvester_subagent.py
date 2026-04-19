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

        # Build domain list from discovery: apex target + harvested subdomains +
        # SSL CN/SANs. If the primary target is an IP, pivot to any domains that
        # recon/SSL handshakes turned up — we never want to query theHarvester
        # with a bare IP (it's domain-focused).
        domains = self._target_domains()
        if not domains:
            return []

        # Deduplicate apex domains so we don't probe "api.example.com" after
        # "example.com" has already returned its subdomains.
        apex = []
        seen = set()
        for d in domains:
            parts = d.split(".")
            a = ".".join(parts[-2:]) if len(parts) >= 2 else d
            if a not in seen:
                seen.add(a)
                apex.append(a)
            # Always probe the exact host too when different from apex (some
            # vhosts have their own MX/emails).
            if d != a and d not in seen:
                seen.add(d)
                apex.append(d)

        # Cap to avoid runaway; 180-sec timeout each adds up fast.
        apex = apex[:4]

        for dom in apex:
            if self._stopped:
                break
            await self._emit("osint_status", {
                "message": f"theHarvester: gathering emails/subdomains/IPs for {dom}"
            })
            output = await self._run_cli(
                [
                    "theHarvester",
                    "-d", dom,
                    "-l", "200",
                    "-b", THEHARVESTER_SOURCES,
                ],
                timeout=TIMEOUTS.get("theharvester", 180),
            )
            if output:
                await self._parse_and_store(dom, output)

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
