"""
shodan_subagent.py — Enhanced Shodan network intelligence.

Shodan is a search engine for internet-connected devices. It indexes:
  - Open ports and running services
  - Banner information and service versions
  - SSL/TLS certificate details
  - Known CVEs affecting the host
  - Geolocation, ISP, and ASN data
  - IoT device information

This subagent supports both IP and domain targets:
  - IP:     Direct host lookup
  - Domain: DNS resolution via Shodan, then host lookups for discovered IPs

Sign up (free tier): https://account.shodan.io
Free tier: 1 query credit/day + limited API access
Set env: SHODAN_API_KEY
"""

from __future__ import annotations

from typing import Dict, List, Optional

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SHODAN_API_KEY, SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

BASE_URL = "https://api.shodan.io"


class ShodanSubagent(OsintSubagentBase):
    SOURCE_NAME  = "shodan"
    DISPLAY_NAME = "Shodan"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("shodan") or not SHODAN_API_KEY:
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"Shodan: querying host/service data for {target}"
        })

        if self._is_ip(target):
            await self._query_host(target)
        else:
            await self._query_domain(target)

        return self._results

    # ── Host lookup ───────────────────────────────────────────────

    async def _query_host(self, ip: str):
        resp = await self._get(
            f"{BASE_URL}/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY, "history": "false", "minify": "false"},
            timeout=TIMEOUTS.get("shodan", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return

        ports     = data.get("ports", [])
        vulns     = list(data.get("vulns", {}).keys())
        org       = data.get("org", "")
        country   = data.get("country_name", "")
        os_info   = data.get("os", "")
        hostnames = data.get("hostnames", [])
        tags      = data.get("tags", [])

        # Build per-service summary + extract SSL cert CNs
        service_lines: List[str] = []
        for item in data.get("data", [])[:12]:
            port     = item.get("port", "")
            product  = item.get("product", "")
            version  = item.get("version", "")
            service_lines.append(f":{port}  {product} {version}".strip())

            ssl = item.get("ssl", {})
            if ssl:
                cert    = ssl.get("cert", {})
                subject = cert.get("subject", {})
                cn      = subject.get("CN", "")
                issuer  = cert.get("issuer", {})
                if cn:
                    await self._store(
                        query     = ip,
                        title     = f"Shodan SSL cert on :{port} — CN={cn}",
                        summary   = (
                            f"Port     : {port}\n"
                            f"CN       : {cn}\n"
                            f"Issuer   : {issuer.get('O','') or issuer.get('CN','')}\n"
                            f"Expires  : {cert.get('expires','?')}"
                        ),
                        severity  = FindingSeverity.INFO,
                        relevance = 0.55,
                        raw       = {"ssl": ssl, "port": port, "data_type": "ssl_cert"},
                    )

        # Main host summary
        await self._store(
            query     = ip,
            title     = (
                f"Shodan: {ip} — {len(ports)} port(s), "
                f"{len(vulns)} CVE(s) ({org or 'unknown org'})"
            ),
            summary   = (
                f"IP       : {ip}\n"
                f"Org      : {org}\n"
                f"Country  : {country}\n"
                f"OS       : {os_info or 'Unknown'}\n"
                f"Tags     : {', '.join(tags) if tags else 'none'}\n"
                f"Ports    : {ports[:20]}\n"
                f"Hostnames: {', '.join(hostnames[:6])}\n"
                f"CVEs     : {', '.join(vulns[:10]) or 'none reported'}\n\n"
                f"Services :\n  " + "\n  ".join(service_lines[:10])
            ),
            url       = f"https://www.shodan.io/host/{ip}",
            cves      = vulns[:20],
            severity  = (
                FindingSeverity.CRITICAL if len(vulns) >= 5
                else FindingSeverity.HIGH if vulns
                else FindingSeverity.MEDIUM if len(ports) > 15
                else FindingSeverity.INFO
            ),
            relevance = 0.95,
            raw       = {
                "ip":        ip,
                "org":       org,
                "country":   country,
                "os":        os_info,
                "ports":     ports[:30],
                "vulns":     vulns[:20],
                "hostnames": hostnames[:20],
                "tags":      tags,
                "services":  service_lines[:20],
                "data_type": "shodan_host",
            },
        )

        # Individual CVE entries
        for cve in vulns[:10]:
            await self._store(
                query     = ip,
                title     = f"Shodan CVE: {cve} on {ip}",
                summary   = f"Shodan reports {ip} is affected by {cve}.",
                url       = f"https://nvd.nist.gov/vuln/detail/{cve}",
                cves      = [cve],
                severity  = FindingSeverity.HIGH,
                relevance = 0.88,
                raw       = {"cve": cve, "ip": ip, "data_type": "shodan_cve"},
            )

    # ── Domain DNS lookup via Shodan ──────────────────────────────

    async def _query_domain(self, domain: str):
        resp = await self._get(
            f"{BASE_URL}/dns/domain/{domain}",
            params={"key": SHODAN_API_KEY},
            timeout=TIMEOUTS.get("shodan", 15),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return

        ips = list(dict.fromkeys(
            entry.get("value", "")
            for entry in data.get("data", [])
            if entry.get("type") == "A" and entry.get("value")
        ))
        subdomains = data.get("subdomains", [])

        if ips:
            await self._store(
                query     = domain,
                title     = f"Shodan DNS: {len(ips)} IP(s) for {domain}",
                summary   = (
                    f"IPs        : {', '.join(ips[:10])}\n"
                    f"Subdomains : {', '.join(subdomains[:20])}"
                ),
                severity  = FindingSeverity.INFO,
                relevance = 0.80,
                raw       = {
                    "ips":        ips[:20],
                    "subdomains": subdomains[:50],
                    "domain":     domain,
                    "data_type":  "shodan_dns",
                },
            )

            # Deep-dive first 3 discovered IPs
            for ip in ips[:3]:
                await self._query_host(ip)
