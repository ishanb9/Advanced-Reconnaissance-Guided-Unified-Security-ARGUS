"""
security_trails_subagent.py — SecurityTrails DNS and domain intelligence.

SecurityTrails provides:
  - Current DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - DNS history — previous values + when they changed
  - Subdomain enumeration
  - Associated domains (same IP or nameserver)
  - IP neighbours and historical IP lookup

Free tier: 50 API calls/month
Sign up:   https://securitytrails.com/app/account/credentials
Set env:   SECURITY_TRAILS_API_KEY
"""

from __future__ import annotations

import asyncio
from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SECURITY_TRAILS_API_KEY, SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

BASE_URL = "https://api.securitytrails.com/v1"


class SecurityTrailsSubagent(OsintSubagentBase):
    SOURCE_NAME  = "security_trails"
    DISPLAY_NAME = "SecurityTrails"

    @property
    def _headers(self) -> Dict:
        return {"APIKEY": SECURITY_TRAILS_API_KEY, "Accept": "application/json"}

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("security_trails"):
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"SecurityTrails: querying DNS/subdomain data for {target}"
        })

        if self._is_ip(target):
            await self._query_ip_neighbours(target)
        else:
            # Run all domain queries with small gaps to respect free-tier rate limit
            await self._query_domain(target)
            await asyncio.sleep(0.5)
            await self._query_subdomains(target)
            await asyncio.sleep(0.5)
            await self._query_dns_history(target)
            await asyncio.sleep(0.5)
            await self._query_associated_domains(target)

        return self._results

    # ── Domain current DNS ────────────────────────────────────────

    async def _query_domain(self, domain: str):
        resp = await self._get(
            f"{BASE_URL}/domain/{domain}",
            headers=self._headers,
            timeout=TIMEOUTS.get("security_trails", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return

        dns = data.get("current_dns", {})
        a_records  = [v.get("ip", "")    for v in dns.get("a",  {}).get("values", [])]
        mx_records = [v.get("value", "") for v in dns.get("mx", {}).get("values", [])]
        ns_records = [v.get("value", "") for v in dns.get("ns", {}).get("values", [])]
        txt_records= [v.get("value", "") for v in dns.get("txt", {}).get("values", [])]

        a_records  = [x for x in a_records  if x]
        mx_records = [x for x in mx_records if x]
        ns_records = [x for x in ns_records if x]
        txt_records= [x for x in txt_records if x]

        await self._store(
            query     = domain,
            title     = f"SecurityTrails: Current DNS for {domain}",
            summary   = (
                f"A  : {', '.join(a_records[:5])  or 'none'}\n"
                f"MX : {', '.join(mx_records[:5]) or 'none'}\n"
                f"NS : {', '.join(ns_records[:5]) or 'none'}\n"
                f"TXT: {', '.join(txt_records[:3]) or 'none'}\n"
                f"Alexa rank: {data.get('alexa_rank', 'N/A')}"
            ),
            url       = f"https://securitytrails.com/domain/{domain}/dns",
            severity  = FindingSeverity.INFO,
            relevance = 0.70,
            raw       = {
                "a_records":   a_records,
                "mx_records":  mx_records,
                "ns_records":  ns_records,
                "txt_records": txt_records,
                "alexa_rank":  data.get("alexa_rank"),
                "data_type":   "dns_records",
            },
        )

    # ── Subdomains ────────────────────────────────────────────────

    async def _query_subdomains(self, domain: str):
        resp = await self._get(
            f"{BASE_URL}/domain/{domain}/subdomains",
            params={"children_only": "false", "include_inactive": "false"},
            headers=self._headers,
            timeout=TIMEOUTS.get("security_trails", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return

        subs   = data.get("subdomains", [])
        count  = data.get("subdomain_count", len(subs))
        if not subs:
            return

        full = [f"{s}.{domain}" for s in subs[:40]]

        await self._store(
            query     = domain,
            title     = f"SecurityTrails: {count} subdomains for {domain}",
            summary   = "Discovered subdomains:\n  " + "\n  ".join(full[:30]),
            url       = f"https://securitytrails.com/domain/{domain}/subdomains",
            severity  = FindingSeverity.MEDIUM,
            relevance = 0.75,
            raw       = {
                "subdomains": full,
                "total":      count,
                "data_type":  "subdomains",
            },
        )

    # ── DNS history ───────────────────────────────────────────────

    async def _query_dns_history(self, domain: str):
        for rtype in ("a", "mx", "ns"):
            resp = await self._get(
                f"{BASE_URL}/history/{domain}/dns/{rtype}",
                headers=self._headers,
                timeout=TIMEOUTS.get("security_trails", 15),
            )
            if not resp or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except Exception:
                continue

            records = data.get("records", [])
            if not records:
                continue

            history_lines = []
            for rec in records[:15]:
                for val in rec.get("values", []):
                    v = val.get("ip") or val.get("value", "")
                    if v:
                        history_lines.append(
                            f"{v}  (first: {rec.get('first_seen','?')}, last: {rec.get('last_seen','?')})"
                        )

            if history_lines:
                await self._store(
                    query     = domain,
                    title     = f"SecurityTrails: Historical {rtype.upper()} records for {domain}",
                    summary   = f"Past {rtype.upper()} records:\n  " + "\n  ".join(history_lines[:20]),
                    url       = f"https://securitytrails.com/domain/{domain}/history/dns",
                    severity  = FindingSeverity.INFO,
                    relevance = 0.60,
                    raw       = {
                        "record_type": rtype,
                        "history":     records[:20],
                        "data_type":   "dns_history",
                    },
                )
            await asyncio.sleep(0.3)

    # ── Associated domains ────────────────────────────────────────

    async def _query_associated_domains(self, domain: str):
        resp = await self._get(
            f"{BASE_URL}/domain/{domain}/associated",
            headers=self._headers,
            timeout=TIMEOUTS.get("security_trails", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return

        associated = [
            r.get("hostname", "") for r in data.get("records", []) if r.get("hostname")
        ]
        if not associated:
            return

        await self._store(
            query     = domain,
            title     = f"SecurityTrails: {len(associated)} associated domains for {domain}",
            summary   = (
                "Domains sharing same IP or nameservers:\n  "
                + "\n  ".join(associated[:25])
            ),
            url       = f"https://securitytrails.com/domain/{domain}/associated",
            severity  = FindingSeverity.INFO,
            relevance = 0.65,
            raw       = {"associated": associated[:60], "data_type": "associated_domains"},
        )

    # ── IP neighbours ─────────────────────────────────────────────

    async def _query_ip_neighbours(self, ip: str):
        resp = await self._get(
            f"{BASE_URL}/ips/nearby/{ip}",
            headers=self._headers,
            timeout=TIMEOUTS.get("security_trails", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return

        blocks = data.get("blocks", [])
        if blocks:
            await self._store(
                query     = ip,
                title     = f"SecurityTrails: IP neighbourhood for {ip}",
                summary   = f"Nearby IP block data:\n{str(blocks[:5])}",
                severity  = FindingSeverity.INFO,
                relevance = 0.55,
                raw       = {"blocks": blocks[:10], "data_type": "ip_neighbors"},
            )
