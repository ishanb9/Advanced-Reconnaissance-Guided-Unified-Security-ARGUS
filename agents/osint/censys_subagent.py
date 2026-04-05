"""
censys_subagent.py — Censys internet-wide scan intelligence.

Censys continuously scans the entire IPv4 internet and indexes every
open port, certificate, and service banner. Useful for:
  - Host/IP intelligence: open ports, services, ASN, location
  - Certificate transparency and TLS configuration details
  - Discovering infrastructure and exposed services for a domain
  - Finding subdomains via certificate Subject Alternative Names (SANs)

API docs : https://search.censys.io/api
Free tier : 250 queries/month
Get key   : https://search.censys.io/account/api
Auth      : HTTP Basic (API_ID : API_SECRET)
"""

from __future__ import annotations

from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import CENSYS_API_ID, CENSYS_API_SECRET, SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

BASE_URL = "https://search.censys.io/api/v2"


class CensysSubagent(OsintSubagentBase):
    SOURCE_NAME  = "censys"
    DISPLAY_NAME = "Censys"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("censys"):
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"Censys: querying internet scan data for {target}"
        })

        if self._is_ip(target):
            await self._query_host(target)
        elif self._is_domain(target):
            await self._search_certificates(target)
            await self._search_hosts(target)

        return self._results

    # ── Host lookup (IP) ──────────────────────────────────────────

    async def _query_host(self, ip: str):
        resp = await self._get(
            f"{BASE_URL}/hosts/{ip}",
            headers=self._auth_headers(),
            timeout=TIMEOUTS.get("censys", 20),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            result = resp.json().get("result", {})
        except Exception:
            return

        services   = result.get("services", [])
        location   = result.get("location", {})
        asn_info   = result.get("autonomous_system", {})
        labels     = result.get("labels", [])

        port_lines = []
        cves       = []
        for svc in services[:20]:
            port      = svc.get("port", "?")
            transport = svc.get("transport_protocol", "")
            name      = svc.get("service_name", "")
            banner    = svc.get("banner", "")[:80]
            port_lines.append(f"{port}/{transport} — {name}  {banner}".strip())
            # Extract CVEs if present in extended_service_name or labels
            for label in svc.get("labels", []):
                if label.upper().startswith("CVE-"):
                    cves.append(label.upper())

        severity = FindingSeverity.MEDIUM if len(services) > 10 else FindingSeverity.INFO

        await self._store(
            query    = ip,
            title    = (
                f"Censys: {ip} — {len(services)} service(s) "
                f"[{asn_info.get('name', '')} / {location.get('country', '')}]"
            ),
            summary  = (
                f"ASN    : AS{asn_info.get('asn', '?')} {asn_info.get('name', '')}\n"
                f"Country: {location.get('country', 'Unknown')} ({location.get('country_code', '')})\n"
                f"Labels : {', '.join(labels) if labels else 'none'}\n\n"
                f"Open services:\n  " + "\n  ".join(port_lines)
            ),
            url      = f"https://search.censys.io/hosts/{ip}",
            severity = severity,
            relevance= 0.75,
            cves     = cves or None,
            raw      = {
                "ip":          ip,
                "services":    services[:20],
                "asn":         asn_info,
                "location":    location,
                "labels":      labels,
                "data_type":   "censys_host",
            },
        )

    # ── Certificate search (domain → subdomains via SANs) ─────────

    async def _search_certificates(self, domain: str):
        resp = await self._post(
            f"{BASE_URL}/certificates/search",
            json_data={
                "q":        f"parsed.names: {domain}",
                "per_page": 50,
                "fields":   ["parsed.names", "parsed.subject_dn", "parsed.issuer.organization"],
            },
            headers=self._auth_headers(),
            timeout=TIMEOUTS.get("censys", 20),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            hits = resp.json().get("result", {}).get("hits", [])
        except Exception:
            return

        if not hits:
            return

        subdomains = set()
        for hit in hits:
            for name in hit.get("parsed.names", []):
                name = name.lstrip("*.")
                if domain in name:
                    subdomains.add(name)

        if not subdomains:
            return

        await self._store(
            query    = domain,
            title    = f"Censys: {len(subdomains)} subdomain(s) found via certificate SANs",
            summary  = "Subdomains from certificate transparency:\n  " + "\n  ".join(sorted(subdomains)[:50]),
            url      = f"https://search.censys.io/certificates?q=parsed.names%3A{domain}",
            severity = FindingSeverity.INFO,
            relevance= 0.70,
            raw      = {
                "domain":     domain,
                "subdomains": sorted(subdomains)[:50],
                "data_type":  "subdomains",
            },
        )

    # ── Host search (domain → associated IPs) ────────────────────

    async def _search_hosts(self, domain: str):
        resp = await self._post(
            f"{BASE_URL}/hosts/search",
            json_data={
                "q":        f"dns.reverse_dns.reverse_dns: {domain}",
                "per_page": 25,
                "fields":   ["ip", "services", "autonomous_system", "location"],
            },
            headers=self._auth_headers(),
            timeout=TIMEOUTS.get("censys", 20),
        )
        if not resp or resp.status_code != 200:
            return
        try:
            hits = resp.json().get("result", {}).get("hits", [])
        except Exception:
            return

        if not hits:
            return

        ip_lines = []
        for hit in hits[:15]:
            ip     = hit.get("ip", "?")
            svcs   = hit.get("services", [])
            ports  = [str(s.get("port", "")) for s in svcs[:5]]
            asn    = hit.get("autonomous_system", {}).get("name", "")
            ip_lines.append(f"{ip} — ports {','.join(ports)} — {asn}")

        await self._store(
            query    = domain,
            title    = f"Censys: {len(hits)} host(s) associated with {domain}",
            summary  = "Associated hosts:\n  " + "\n  ".join(ip_lines),
            url      = f"https://search.censys.io/search?resource=hosts&q=dns.reverse_dns.reverse_dns%3A{domain}",
            severity = FindingSeverity.INFO,
            relevance= 0.65,
            raw      = {
                "domain":    domain,
                "hosts":     [h.get("ip") for h in hits],
                "data_type": "censys_hosts",
            },
        )

    # ── Auth helper ───────────────────────────────────────────────

    def _auth_headers(self) -> Dict:
        import base64
        creds = base64.b64encode(
            f"{CENSYS_API_ID}:{CENSYS_API_SECRET}".encode()
        ).decode()
        return {"Authorization": f"Basic {creds}"}
