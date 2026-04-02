"""
bgpview_subagent.py — BGPView BGP routing and ASN intelligence.

BGPView is a free API (no key required) for:
  - ASN details and announced prefixes
  - IP geolocation, ISP and ASN assignment
  - BGP peer information
  - Domain-to-ASN mapping via search

Useful for:
  - Mapping the target's network footprint
  - Identifying hosting providers and CDN usage
  - Finding all IP ranges owned by the target organisation
  - Pivot from one IP to related infrastructure

API docs: https://bgpview.docs.apiary.io/
"""

from __future__ import annotations

from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

BASE_URL = "https://api.bgpview.io"


class BGPViewSubagent(OsintSubagentBase):
    SOURCE_NAME  = "bgpview"
    DISPLAY_NAME = "BGPView"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("bgpview"):
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"BGPView: querying BGP/ASN routing data for {target}"
        })

        if self._is_ip(target):
            await self._query_ip(target)
        else:
            await self._search_target(target)

        return self._results

    # ── IP lookup ─────────────────────────────────────────────────

    async def _query_ip(self, ip: str):
        resp = await self._get(
            f"{BASE_URL}/ip/{ip}",
            timeout=TIMEOUTS.get("bgpview", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json().get("data", {})
        except Exception:
            return

        prefixes = data.get("prefixes", [])
        rir      = data.get("rir_allocation", {})
        ptr      = data.get("ptr_record", "")
        country  = data.get("country_code", "")

        prefix_lines = []
        for p in prefixes[:8]:
            asn  = p.get("asn", {})
            line = (
                f"ASN{asn.get('asn','')} ({asn.get('name','')}) — "
                f"{p.get('prefix','')} — {asn.get('country_code','')}"
            )
            prefix_lines.append(line)

        await self._store(
            query     = ip,
            title     = f"BGPView: ASN/routing data for {ip} ({country})",
            summary   = (
                f"PTR    : {ptr or 'none'}\n"
                f"Country: {country}\n"
                f"RIR    : {rir.get('rir_name','N/A')} — allocated {rir.get('date_allocated','?')}\n"
                f"Prefixes:\n  " + "\n  ".join(prefix_lines)
            ),
            url       = f"https://bgpview.io/ip/{ip}",
            severity  = FindingSeverity.INFO,
            relevance = 0.55,
            raw       = {
                "ip":        ip,
                "prefixes":  prefixes[:10],
                "rir":       rir,
                "ptr":       ptr,
                "country":   country,
                "data_type": "bgp_routing",
            },
        )

        # Also query the ASN for each prefix to find full IP range
        asn_seen = set()
        for p in prefixes[:3]:
            asn_num = p.get("asn", {}).get("asn")
            if asn_num and asn_num not in asn_seen:
                asn_seen.add(asn_num)
                await self._query_asn(asn_num)

    # ── Domain search ─────────────────────────────────────────────

    async def _search_target(self, domain: str):
        resp = await self._get(
            f"{BASE_URL}/search",
            params={"query_term": domain},
            timeout=TIMEOUTS.get("bgpview", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json().get("data", {})
        except Exception:
            return

        asns          = data.get("asns", [])
        ipv4_prefixes = data.get("ipv4_prefixes", [])
        ipv6_prefixes = data.get("ipv6_prefixes", [])

        if not asns and not ipv4_prefixes:
            return

        asn_lines = [
            f"ASN{a.get('asn')} — {a.get('name','')} ({a.get('country_code','')})"
            for a in asns[:8]
        ]
        pfx_lines = [
            f"{p.get('prefix','')} — {p.get('name','')} ({p.get('country_code','')})"
            for p in ipv4_prefixes[:8]
        ]

        await self._store(
            query     = domain,
            title     = f"BGPView: {len(asns)} ASN(s), {len(ipv4_prefixes)} IPv4 prefix(es) for {domain}",
            summary   = (
                ("ASNs:\n  " + "\n  ".join(asn_lines) if asn_lines else "")
                + ("\n\nIPv4 Prefixes:\n  " + "\n  ".join(pfx_lines) if pfx_lines else "")
            ).strip(),
            url       = f"https://bgpview.io/search/{domain}",
            severity  = FindingSeverity.INFO,
            relevance = 0.55,
            raw       = {
                "asns":           asns[:10],
                "ipv4_prefixes":  ipv4_prefixes[:10],
                "ipv6_prefixes":  ipv6_prefixes[:5],
                "data_type":      "asn_lookup",
            },
        )

    # ── ASN detail (called from IP path) ─────────────────────────

    async def _query_asn(self, asn_num: int):
        resp = await self._get(
            f"{BASE_URL}/asn/{asn_num}/prefixes",
            timeout=TIMEOUTS.get("bgpview", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json().get("data", {})
        except Exception:
            return

        ipv4 = data.get("ipv4_prefixes", [])
        if not ipv4:
            return

        await self._store(
            query     = str(asn_num),
            title     = f"BGPView: ASN{asn_num} — {len(ipv4)} IPv4 prefix(es)",
            summary   = "IPv4 prefixes:\n  " + "\n  ".join(
                p.get("prefix", "") for p in ipv4[:20]
            ),
            url       = f"https://bgpview.io/asn/{asn_num}",
            severity  = FindingSeverity.INFO,
            relevance = 0.50,
            raw       = {
                "asn":            asn_num,
                "ipv4_prefixes":  [p.get("prefix") for p in ipv4[:30]],
                "data_type":      "asn_prefixes",
            },
        )
