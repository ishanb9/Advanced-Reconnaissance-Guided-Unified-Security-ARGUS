"""
recon_ng_subagent.py — Recon-ng OSINT framework wrapper.

Recon-ng is driven via a resource file (non-interactive CLI mode).
Modules auto-selected based on target type:
  Domain targets:
    recon/domains-hosts/hackertarget       — subdomain enumeration
    recon/domains-hosts/threatcrowd        — subdomain/IP mapping
    recon/domains-contacts/whois_pocs      — WHOIS contact info
    recon/domains-vulnerabilities/ghdb     — Google Hacking DB matches
  IP targets:
    recon/hosts-hosts/reverse_resolve      — reverse DNS

Install recon-ng: pip install recon-ng  or  apt install recon-ng
Install modules:  recon-ng -m marketplace install all
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity


class ReconNgSubagent(OsintSubagentBase):
    SOURCE_NAME  = "recon_ng"
    DISPLAY_NAME = "Recon-ng"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("recon_ng"):
            return []

        target = self._target
        await self._emit("osint_status", {"message": f"recon-ng: scanning {target}"})

        if self._is_domain(target):
            commands = self._domain_commands(target)
        elif self._is_ip(target):
            commands = self._ip_commands(target)
        else:
            return []

        output = await self._run_resource_file(commands)
        if not output:
            return []

        await self._parse_and_store(target, output)
        return self._results

    # ── Command builders ──────────────────────────────────────────

    def _domain_commands(self, domain: str) -> List[str]:
        safe = domain.replace(".", "_")
        return [
            f"workspaces create argus_{safe}",
            f"db insert domains name={domain}",
            "modules load recon/domains-hosts/hackertarget",
            "run",
            "modules load recon/domains-hosts/threatcrowd",
            "run",
            "modules load recon/domains-contacts/whois_pocs",
            "run",
            "show hosts",
            "show contacts",
            "exit",
        ]

    def _ip_commands(self, ip: str) -> List[str]:
        safe = ip.replace(".", "_")
        return [
            f"workspaces create argus_{safe}",
            f"db insert hosts ip_address={ip}",
            "modules load recon/hosts-hosts/reverse_resolve",
            "run",
            "show hosts",
            "exit",
        ]

    # ── Resource file runner ──────────────────────────────────────

    async def _run_resource_file(self, commands: List[str]) -> str:
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".rc", delete=False, encoding="utf-8"
            ) as f:
                f.write("\n".join(commands) + "\n")
                tmp_path = f.name

            return await self._run_cli(
                ["recon-ng", "--no-check", "-r", tmp_path],
                timeout=TIMEOUTS.get("recon_ng", 300),
            )
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    # ── Output parser ─────────────────────────────────────────────

    async def _parse_and_store(self, target: str, output: str):
        # Subdomains — table row pattern: | subdomain.target.com | ...
        hosts = list(set(re.findall(
            r'\|\s+([\w\.\-]+\.' + re.escape(target) + r')\s+\|',
            output
        )))
        # Contacts / emails
        contacts = list(set(re.findall(r'[\w\.\-\+]+@[\w\.\-]+\.\w{2,}', output)))
        # IPs
        ips = list(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', output)))
        ips = [ip for ip in ips if not ip.startswith(("0.", "127.", "255."))]

        if not (hosts or contacts or ips):
            return

        parts = []
        if hosts:    parts.append(f"{len(hosts)} subdomains")
        if contacts: parts.append(f"{len(contacts)} contacts")
        if ips:      parts.append(f"{len(ips)} IPs")

        summary_lines = []
        if hosts:    summary_lines.append("Subdomains:\n  " + "\n  ".join(hosts[:15]))
        if contacts: summary_lines.append("Contacts:\n  " + "\n  ".join(contacts[:15]))
        if ips:      summary_lines.append("IPs:\n  " + "\n  ".join(ips[:10]))

        await self._store(
            query     = target,
            title     = f"Recon-ng: {', '.join(parts)} for {target}",
            summary   = "\n\n".join(summary_lines),
            severity  = FindingSeverity.MEDIUM if (hosts or contacts) else FindingSeverity.INFO,
            relevance = 0.75,
            raw       = {
                "subdomains":  hosts[:50],
                "contacts":    contacts[:30],
                "ips":         ips[:30],
                "raw_output":  output[:4000],
                "data_type":   "recon_ng_results",
            },
        )
