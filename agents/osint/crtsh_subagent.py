"""
crtsh_subagent.py — Certificate Transparency subdomain enumeration via crt.sh.

WHY IT MATTERS
==============
Certificate Transparency logs are a free, no-auth, comprehensive source
of subdomains for any domain — every TLS certificate issued by a public
CA is logged.  Pentesters use crt.sh as the first stop for subdomain
discovery because it requires no rate-limited DNS bruteforce and
catches subdomains that don't appear in passive DNS lists.

For ARGUS this is critical: when the target is a domain (HTB lab name,
real company), crt.sh often surfaces 10-100 subdomains the operator
didn't supply, including:
  * `dev.example.com`, `staging.example.com` — often less hardened
  * `vpn.example.com`, `mail.example.com` — high-value targets
  * Internal-sounding hostnames that hint at app architecture

How it works
------------
crt.sh's `?q=%.<domain>&output=json` endpoint returns a JSON array of
all certificates whose CN or SAN contains the domain.  We extract
unique hostnames + dedup wildcards + filter to in-scope subdomains
+ store each as an OSINT result.

No API key required.  crt.sh is rate-limited (1 req/sec) but very
generous — single query per engagement is fine.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Set

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

CRTSH_URL = "https://crt.sh/"

# Subdomain hostname pattern — accepts unicode, hyphens, dots
_HOST_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9\-]{2,})+$"
)


class CrtshSubagent(OsintSubagentBase):
    """Subdomain enumeration via Certificate Transparency (crt.sh)."""

    SOURCE_NAME  = "crtsh"
    DISPLAY_NAME = "crt.sh (Cert Transparency)"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("crtsh", True):
            return []

        # crt.sh is domain-only — pivot to discovered domains
        domains = self._target_domains()
        if not domains:
            return []

        # Limit to apex domains (dedupe subdomains of same TLD+1)
        apex_set: Set[str] = set()
        for d in domains[:8]:
            parts = d.split(".")
            if len(parts) >= 2:
                apex_set.add(".".join(parts[-2:]))
        apex = sorted(apex_set)[:4]

        for dom in apex:
            if self._stopped:
                break
            await self._query_domain(dom)
        return self._results

    async def _query_domain(self, domain: str) -> None:
        await self._emit("osint_status", {
            "message": f"crt.sh: Certificate Transparency enum for {domain}"
        })
        resp = await self._get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=TIMEOUTS.get("crtsh", 30),
            headers={"User-Agent": "ARGUS-pentest/1.0", "Accept": "application/json"},
        )
        if resp is None or resp.status_code != 200:
            await self._emit("osint_warning", {
                "message": (
                    f"crt.sh: query failed for {domain} "
                    f"(status={getattr(resp, 'status_code', 'n/a')})"
                )
            })
            return
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            return
        if not isinstance(data, list):
            return

        # Extract unique hostnames
        hostnames: Set[str] = set()
        wildcards: Set[str] = set()
        for cert in data[:5000]:    # crt.sh sometimes returns a lot
            if not isinstance(cert, dict):
                continue
            # The `name_value` field is a newline-separated list of CN+SANs
            name_value = cert.get("name_value", "") or ""
            for line in name_value.split("\n"):
                host = line.strip().lower()
                if not host:
                    continue
                if host.startswith("*."):
                    wildcards.add(host[2:])
                    continue
                # Only keep hostnames that end in our target domain
                if not host.endswith("." + domain) and host != domain:
                    continue
                if _HOST_RE.match(host):
                    hostnames.add(host)

        if not hostnames:
            await self._emit("osint_status", {
                "message": f"crt.sh: no subdomains found for {domain}"
            })
            return

        # Surface into discovery + store
        existing = set(self._discovery.get("subdomains") or [])
        new_subs = sorted(hostnames - existing)
        self._discovery["subdomains"] = sorted(existing | hostnames)

        # Detect high-value subdomain patterns for severity bump
        HIGH_VALUE = (
            "admin", "dev", "staging", "test", "vpn", "mail", "api",
            "internal", "intranet", "git", "jenkins", "jira", "wiki",
            "monitoring", "grafana", "kibana", "ops", "backup",
            "ftp", "remote", "rdp", "ssh", "console", "portal",
        )
        high_value_subs = [
            s for s in hostnames
            if any(hv in s.split(".")[0].lower() for hv in HIGH_VALUE)
        ]

        severity = (FindingSeverity.HIGH if high_value_subs
                      else FindingSeverity.INFO)
        # Storing as one aggregate result with all subdomains in raw
        await self._store(
            query     = f"%.{domain}",
            title     = (
                f"crt.sh: {len(hostnames)} subdomain(s) of {domain} found "
                + (f"({len(high_value_subs)} high-value)"
                   if high_value_subs else "")
            ),
            summary   = (
                f"Certificate Transparency search for {domain} returned "
                f"{len(hostnames)} unique subdomains.  Top 30:\n  • "
                + "\n  • ".join(sorted(hostnames)[:30])
                + (f"\n\nHigh-value subdomains (admin/dev/staging/etc.):\n  • "
                   + "\n  • ".join(high_value_subs[:15])
                   if high_value_subs else "")
                + (f"\n\nWildcards observed: {len(wildcards)}"
                   if wildcards else "")
            ),
            url       = f"https://crt.sh/?q=%25.{domain}",
            severity  = severity,
            relevance = 0.90 if high_value_subs else 0.65,
            raw       = {
                "data_type":         "crtsh_subdomains",
                "apex_domain":       domain,
                "subdomain_count":   len(hostnames),
                "subdomains":        sorted(hostnames),
                "high_value_subs":   high_value_subs,
                "wildcards":         sorted(wildcards),
                "newly_discovered":  new_subs,
            },
            tags      = ["subdomain_enum", "cert_transparency"],
        )


__all__ = ["CrtshSubagent"]
