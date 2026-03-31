"""
dns_recon_subagent.py — DNS reconnaissance and subdomain enumeration.

Methodology:
  1. dnsrecon -t std   — standard A, MX, NS, TXT, CNAME, SOA records
  2. subfinder          — passive subdomain enumeration via OSINT sources
  3. dnsrecon -t axfr  — zone transfer attempt against all NS servers
  4. dnsx               — resolve discovered subdomains → live IPs
  5. Wildcard detection — identify wildcard DNS entries
  6. Internal IP leak   — RFC 1918 addresses in public DNS
  7. Severity grading:
       CRITICAL — zone transfer succeeded (full DNS zone exposed)
       HIGH     — wildcard DNS, internal IPs in public DNS
       MEDIUM   — subdomains found (attack surface expansion)
       INFO     — individual DNS record types
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC 1918 / internal IP patterns
# ---------------------------------------------------------------------------
_RFC1918_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# dnsrecon record line
_DNSRECON_RECORD_RE = re.compile(
    r"\[\*\]\s+(A|AAAA|MX|NS|TXT|CNAME|SOA|PTR|SRV)\s+(\S+)\s+(.+)",
    re.IGNORECASE,
)

# Subdomain line from subfinder (one per line, plain hostname)
_SUBDOMAIN_RE = re.compile(r"^([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})$")

# dnsx output: "hostname A ip"
_DNSX_RE = re.compile(r"^(\S+)\s+\[([A-Z]+)\]\s+\[(.+)\]", re.IGNORECASE)

# Zone transfer success indicator
_AXFR_SUCCESS_RE = re.compile(
    r"zone transfer was successful|trying ns.*\[\*\]\s+A\s+", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class DnsReconSubagent(BaseSubagent):
    """
    Full DNS reconnaissance: standard records, passive subdomain enumeration,
    zone transfer, resolution, and internal IP leak detection.
    """

    AGENT_NAME    = "recon"
    SUBAGENT_NAME = "dns_recon"

    async def run(  # noqa: C901
        self,
        target: str,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Execute DNS recon against *target* domain.

        Parameters
        ----------
        target:
            Domain name to enumerate (e.g. "example.com").

        Returns
        -------
        SubagentResult
            parsed_data["records"]    — list of DNS record dicts
            parsed_data["subdomains"] — list of discovered subdomain strings
            parsed_data["live_hosts"] — list of {"host": str, "ips": list[str]}
            parsed_data["zone_transfer_success"] — bool
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {
            "records":               [],
            "subdomains":            [],
            "live_hosts":            [],
            "zone_transfer_success": False,
        }
        wall_start = time.monotonic()

        # ── Step 1: Standard DNS records ──────────────────────────────────
        logger.info("[dns_recon] Step 1 — standard records: %s", target)
        records: list[dict] = []
        try:
            std_out = await self.collect_tool(
                "dnsrecon",
                target,
                {"options": f"-d {target} -t std"},
            )
            self._tool_outputs["dnsrecon_std"] = std_out
            records = _parse_dnsrecon_records(std_out)
            logger.info("[dns_recon] parsed %d records", len(records))

            # Emit INFO finding per record type seen
            record_types_seen: set[str] = set()
            for rec in records:
                rtype = rec.get("type", "?")
                if rtype not in record_types_seen:
                    record_types_seen.add(rtype)
                    await self.store_finding(Finding(
                        title=f"DNS {rtype} Record Found: {target}",
                        description=(
                            f"DNS {rtype} records discovered for {target}. "
                            f"Example: {rec.get('name', '')} → {rec.get('value', '')}"
                        ),
                        severity="INFO",
                        evidence=std_out[:400],
                        tool="dnsrecon",
                        host=target,
                    ))

        except Exception as exc:
            logger.error("[dns_recon] dnsrecon std error: %s", exc)

        # Check for internal IPs in public DNS
        for rec in records:
            value = rec.get("value", "")
            if _RFC1918_RE.search(value):
                await self.store_finding(Finding(
                    title=f"Internal IP in Public DNS: {rec.get('name', target)}",
                    description=(
                        f"DNS record {rec.get('type')} for {rec.get('name')} resolves to "
                        f"private/RFC1918 address {value}. This leaks internal network topology."
                    ),
                    severity="HIGH",
                    evidence=f"{rec.get('type')} {rec.get('name')} {value}",
                    tool="dnsrecon",
                    host=target,
                    mitre_technique="T1590",
                    exploit_suggestion=(
                        "Internal IP ranges revealed. Use these as pivot targets if "
                        "internal network access is obtained."
                    ),
                ))

        # ── Step 2: Subdomain enumeration ─────────────────────────────────
        logger.info("[dns_recon] Step 2 — passive subdomain enum: %s", target)
        subdomains: list[str] = []
        try:
            sf_out = await self.collect_tool(
                "subfinder",
                target,
                {"options": f"-d {target} -silent -all"},
            )
            self._tool_outputs["subfinder"] = sf_out
            subdomains = _parse_subdomains(sf_out)
            logger.info("[dns_recon] subfinder found %d subdomains", len(subdomains))

            if subdomains:
                await self.store_finding(Finding(
                    title=f"Subdomains Discovered: {len(subdomains)} for {target}",
                    description=(
                        f"Passive subdomain enumeration found {len(subdomains)} subdomains "
                        f"for {target}. These expand the attack surface."
                    ),
                    severity="MEDIUM",
                    evidence="\n".join(subdomains[:30]),
                    tool="subfinder",
                    host=target,
                    mitre_technique="T1590",
                    exploit_suggestion=(
                        "Probe each subdomain for exposed services, login panels, "
                        "dev/staging environments, and unpatched software."
                    ),
                ))

        except Exception as exc:
            logger.error("[dns_recon] subfinder error: %s", exc)

        # Also run fierce for additional subdomain brute-force
        try:
            fierce_out = await self.collect_tool(
                "fierce",
                target,
                {"options": f"--domain {target}"},
            )
            self._tool_outputs["fierce"] = fierce_out
            fierce_subs = _parse_subdomains(fierce_out)
            for s in fierce_subs:
                if s not in subdomains:
                    subdomains.append(s)
            logger.info("[dns_recon] fierce found %d additional subdomains", len(fierce_subs))
        except Exception as exc:
            logger.warning("[dns_recon] fierce error (non-critical): %s", exc)

        # ── Step 3: Zone transfer ──────────────────────────────────────────
        logger.info("[dns_recon] Step 3 — zone transfer attempt: %s", target)
        zone_transfer_success = False
        try:
            axfr_out = await self.collect_tool(
                "dnsrecon",
                target,
                {"options": f"-d {target} -t axfr"},
            )
            self._tool_outputs["dnsrecon_axfr"] = axfr_out

            if _AXFR_SUCCESS_RE.search(axfr_out) or (
                axfr_out.count("[*]") > 5  # many records returned == likely success
            ):
                zone_transfer_success = True
                await self.store_finding(Finding(
                    title=f"DNS Zone Transfer Succeeded: {target}",
                    description=(
                        f"A full DNS zone transfer (AXFR) succeeded for {target}. "
                        f"The complete DNS zone is exposed, revealing all internal hostnames, "
                        f"IP mappings, mail servers, and infrastructure details."
                    ),
                    severity="CRITICAL",
                    evidence=axfr_out[:800],
                    tool="dnsrecon",
                    host=target,
                    mitre_technique="T1590",
                    exploit_suggestion=(
                        "Parse all records from zone transfer to map full internal topology. "
                        "Look for internal hostnames, development servers, and administrative hosts."
                    ),
                ))

                # Parse additional records from zone transfer
                zone_records = _parse_dnsrecon_records(axfr_out)
                for zr in zone_records:
                    if zr not in records:
                        records.append(zr)
                    # Add any new subdomains
                    name = zr.get("name", "")
                    if target in name and name != target:
                        sub = name.rstrip(".")
                        if sub not in subdomains:
                            subdomains.append(sub)

        except Exception as exc:
            logger.warning("[dns_recon] zone transfer error (non-critical): %s", exc)

        # ── Step 4: Wildcard DNS detection ────────────────────────────────
        try:
            wildcard_probe = f"nonexistent-{int(time.monotonic()*1000)}.{target}"
            ns_out = await self.collect_tool(
                "nslookup",
                target,
                {"options": f"{wildcard_probe}"},
            )
            self._tool_outputs["nslookup_wildcard"] = ns_out
            if re.search(r"Address:\s*\d+\.\d+\.\d+\.\d+", ns_out):
                await self.store_finding(Finding(
                    title=f"Wildcard DNS Detected: *.{target}",
                    description=(
                        f"Wildcard DNS is configured for *.{target}. "
                        f"All subdomains resolve, making subdomain enumeration unreliable "
                        f"and potentially enabling subdomain takeover risks."
                    ),
                    severity="HIGH",
                    evidence=ns_out[:400],
                    tool="nslookup",
                    host=target,
                    mitre_technique="T1584",
                    exploit_suggestion=(
                        "Wildcard DNS may enable subdomain takeover. "
                        "Check CNAME records pointing to unclaimed cloud services."
                    ),
                ))
        except Exception as exc:
            logger.debug("[dns_recon] wildcard probe error: %s", exc)

        # ── Step 5: Resolve subdomains with dnsx ──────────────────────────
        logger.info("[dns_recon] Step 5 — resolving %d subdomains with dnsx", len(subdomains))
        live_hosts: list[dict] = []
        if subdomains:
            try:
                subs_str = "\n".join(subdomains[:200])  # cap at 200
                dnsx_out = await self.collect_tool(
                    "dnsx",
                    target,
                    {
                        "options": "-resp -a -cname -silent",
                        "stdin":   subs_str,
                    },
                )
                self._tool_outputs["dnsx"] = dnsx_out
                live_hosts = _parse_dnsx_output(dnsx_out)
                logger.info("[dns_recon] dnsx resolved %d live hosts", len(live_hosts))
            except Exception as exc:
                logger.warning("[dns_recon] dnsx error: %s", exc)

        # ── Step 6: Assemble result ────────────────────────────────────────
        result.parsed_data["records"]               = records
        result.parsed_data["subdomains"]            = list(dict.fromkeys(subdomains))
        result.parsed_data["live_hosts"]            = live_hosts
        result.parsed_data["zone_transfer_success"] = zone_transfer_success
        result.findings                             = self._findings
        result.tool_outputs                         = self._tool_outputs
        result.duration_seconds                     = time.monotonic() - wall_start

        await self._emit(
            "dns_recon_complete",
            {
                "target":                 target,
                "record_count":           len(records),
                "subdomain_count":        len(subdomains),
                "live_host_count":        len(live_hosts),
                "zone_transfer_success":  zone_transfer_success,
                "finding_count":          len(self._findings),
                "duration_seconds":       round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[dns_recon] complete — %d records, %d subdomains, zt=%s, %d findings, %.1fs",
            len(records), len(subdomains), zone_transfer_success,
            len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_dnsrecon_records(output: str) -> list[dict]:
    """Extract DNS records from dnsrecon text output."""
    records: list[dict] = []
    for line in output.splitlines():
        m = _DNSRECON_RECORD_RE.search(line)
        if m:
            records.append({
                "type":  m.group(1).upper(),
                "name":  m.group(2).strip(),
                "value": m.group(3).strip(),
            })
    return records


def _parse_subdomains(output: str) -> list[str]:
    """Extract subdomain hostnames from tool output (one per line)."""
    subs: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        # Remove common prefixes from fierce / subfinder output
        line = re.sub(r"^\[\+\]\s*|^\*\s*|^Found:\s*", "", line)
        if _SUBDOMAIN_RE.match(line):
            subs.append(line.lower())
    return list(dict.fromkeys(subs))


def _parse_dnsx_output(output: str) -> list[dict]:
    """Parse dnsx -resp output into live host dicts."""
    hosts: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _DNSX_RE.match(line)
        if m:
            hosts.append({
                "host":   m.group(1),
                "type":   m.group(2),
                "values": [v.strip() for v in m.group(3).split(",")],
            })
        elif re.match(r"[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}", line):
            # plain hostname with IP on same line
            parts = line.split()
            if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[-1]):
                hosts.append({"host": parts[0], "type": "A", "values": [parts[-1]]})
    return hosts
