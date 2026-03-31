"""
iot_firmware_subagent.py — IoT Firmware Version Analysis & CVE Lookup

Extracts firmware/hardware version information from:
  - HTTP server headers and admin panel pages
  - SNMP sysDescr MIB
  - Telnet/SSH banners
  - RTSP DESCRIBE responses
  - UPnP device descriptions

Then cross-references with NVD/ExploitDB for known CVEs specific to
that firmware version (using searchsploit and nmap vuln scripts).
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from agents.base_subagent import BaseSubagent, Finding, SubagentResult


class IoTFirmwareSubagent(BaseSubagent):
    AGENT_NAME    = "IoTAgent"
    SUBAGENT_NAME = "iot_firmware"

    async def run(self, target: str, **kwargs) -> SubagentResult:
        start = datetime.now(timezone.utc)
        self._findings.clear()
        await self._emit_start()

        open_ports: list[str] = kwargs.get("open_ports", [])
        port_set = set(str(p) for p in open_ports)

        firmware_strings: list[str] = []

        # Gather firmware strings from all available sources in parallel
        gather_tasks = [
            self._extract_http_firmware(target, port_set, firmware_strings),
            self._extract_snmp_firmware(target, firmware_strings),
            self._extract_banner_firmware(target, port_set, firmware_strings),
        ]
        await asyncio.gather(*gather_tasks, return_exceptions=True)

        # Deduplicate
        unique_fw = list(dict.fromkeys(s for s in firmware_strings if s.strip()))

        if unique_fw:
            await self._searchsploit_lookup(target, unique_fw)
            await self._nmap_vuln_scan(target, open_ports)
        else:
            # No firmware version extracted — still run nmap vuln scripts
            await self._nmap_vuln_scan(target, open_ports)

        duration = (datetime.now(timezone.utc) - start).total_seconds()
        result = SubagentResult(
            findings=self._findings,
            duration_seconds=duration,
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        await self._emit_complete(result)
        return result

    # ── HTTP firmware extraction ───────────────────────────────────────────────

    async def _extract_http_firmware(self, target: str, port_set: set, out: list) -> None:
        for port in (p for p in ("80", "8080", "443", "8443") if p in port_set or not port_set):
            scheme = "https" if port in ("443", "8443") else "http"
            cmd = (
                f"curl -sk --max-time 8 -i {scheme}://{target}:{port}/ 2>/dev/null | head -50"
            )
            output_lines: list[str] = []
            async for line in self.run_tool("run_command", target, {"command": cmd}):
                if self._stop_requested:
                    return
                output_lines.append(line)
            raw = "\n".join(output_lines)

            # Server header
            srv_m = re.search(r'(?i)server:\s*(.+)', raw)
            if srv_m:
                out.append(srv_m.group(1).strip())

            # Version patterns in page body
            for pat in (
                r'[Ff]irmware[:\s]+([0-9A-Za-z._\-]+)',
                r'[Vv]ersion[:\s]+([0-9]+\.[0-9]+[0-9A-Za-z._\-]*)',
                r'[Hh][Ww][:\s]+([0-9A-Za-z._\-]+)',
                r'[Mm]odel[:\s]+([A-Za-z0-9\-_]+)',
            ):
                m = re.search(pat, raw)
                if m:
                    out.append(m.group(1).strip())

            if raw.strip() and len(out) > 0:
                self._findings.append(Finding(
                    title=f"Firmware/Version Info Exposed via HTTP on port {port}",
                    description=(
                        f"HTTP response reveals version information: {', '.join(out[:4])}. "
                        "This allows targeted CVE searches for this specific firmware."
                    ),
                    severity="INFO",
                    evidence=raw[:400],
                    tool="curl",
                    host=target,
                    port=int(port),
                ))
            break  # use first responding web port

    # ── SNMP firmware extraction ───────────────────────────────────────────────

    async def _extract_snmp_firmware(self, target: str, out: list) -> None:
        for community in ("public", "private"):
            cmd = f"snmpget -v2c -c {community} {target} 1.3.6.1.2.1.1.1.0 2>/dev/null"
            output_lines: list[str] = []
            async for line in self.run_tool("run_command", target, {"command": cmd}):
                if self._stop_requested:
                    return
                output_lines.append(line)
            raw = "\n".join(output_lines)
            if raw.strip() and "Timeout" not in raw and "No Such" not in raw:
                # sysDescr often contains: "Linux routerX 4.1.27 ... firmware 2.1.3"
                out.append(raw.strip()[:200])
                # Extract version tokens
                for m in re.finditer(r'([0-9]+\.[0-9]+[0-9A-Za-z._\-]*)', raw):
                    out.append(m.group(1))
                break

    # ── Banner firmware extraction ─────────────────────────────────────────────

    async def _extract_banner_firmware(self, target: str, port_set: set, out: list) -> None:
        for port in (p for p in ("22", "23", "21") if p in port_set):
            cmd = f"timeout 5 nc -w 3 {target} {port} </dev/null 2>&1 | head -5"
            output_lines: list[str] = []
            async for line in self.run_tool("run_command", target, {"command": cmd}):
                if self._stop_requested:
                    return
                output_lines.append(line)
            raw = "\n".join(output_lines)
            if raw.strip():
                out.append(raw.strip()[:150])
                for m in re.finditer(r'([0-9]+\.[0-9]+[0-9A-Za-z._\-]*)', raw):
                    out.append(m.group(1))

    # ── Searchsploit lookup ────────────────────────────────────────────────────

    async def _searchsploit_lookup(self, target: str, firmware_strings: list[str]) -> None:
        # Use the most informative strings (server header + first version)
        queries = list(dict.fromkeys(firmware_strings))[:4]
        for query in queries:
            if self._stop_requested:
                return
            # Clean query — remove path info, keep product+version
            q = re.sub(r'[/\\].*', '', query).strip()
            if not q or len(q) < 4:
                continue
            cmd = f"searchsploit --json '{q}' 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); [print(e['Title'],'|',e['EDB-ID'],'|',e['Path']) for e in d.get('RESULTS_EXPLOIT',[])[:5]]\" 2>/dev/null"
            output_lines: list[str] = []
            async for line in self.run_tool("run_command", target, {"command": cmd}):
                output_lines.append(line)
            raw = "\n".join(output_lines)

            if raw.strip():
                exploits = [l.strip() for l in output_lines if "|" in l]
                for exploit_line in exploits[:5]:
                    parts = exploit_line.split("|")
                    if len(parts) >= 2:
                        title = parts[0].strip()
                        edb   = parts[1].strip()
                        path  = parts[2].strip() if len(parts) > 2 else ""
                        self._findings.append(Finding(
                            title=f"Known Exploit for Firmware: {title}",
                            description=(
                                f"SearchSploit found a public exploit matching firmware version '{q}': "
                                f"{title} (EDB-ID: {edb}). "
                                f"Exploit path: {path}"
                            ),
                            severity="CRITICAL",
                            evidence=exploit_line,
                            tool="searchsploit",
                            host=target,
                            exploit_suggestion=(
                                f"searchsploit -x {edb}\n"
                                f"# or copy: searchsploit -m {edb}"
                            ),
                        ))

    # ── Nmap vuln scripts ──────────────────────────────────────────────────────

    async def _nmap_vuln_scan(self, target: str, open_ports: list[str]) -> None:
        ports_str = ",".join(str(p) for p in open_ports[:20]) if open_ports else "22,23,80,443,502,1883,8080"
        cmd = (
            f"nmap -sV -p {ports_str} "
            f"--script=vuln,http-shellshock,http-slowloris-check,"
            f"ssl-heartbleed,ssl-poodle,ftp-anon,telnet-brute "
            f"--script-timeout 30s -T4 {target} 2>&1 | tail -60"
        )
        output_lines: list[str] = []
        async for line in self.run_tool("nmap", target, {"args": cmd}):
            if self._stop_requested:
                break
            output_lines.append(line)
        raw = "\n".join(output_lines)

        # Parse CVEs from nmap vuln output
        cve_re = re.compile(r'(CVE-\d{4}-\d+)', re.IGNORECASE)
        cves = list(set(cve_re.findall(raw)))

        if cves:
            self._findings.append(Finding(
                title=f"Nmap Vuln Scripts Identified {len(cves)} CVEs",
                description=(
                    f"Nmap vulnerability scripts found: {', '.join(cves[:10])}. "
                    "Review the full scan output for detailed exploit paths."
                ),
                severity="HIGH",
                evidence=raw[-1000:],
                tool="nmap",
                host=target,
                cve=", ".join(cves[:5]),
                exploit_suggestion=f"searchsploit {cves[0]}" if cves else "",
            ))

        # Look for VULNERABLE: markers
        vuln_blocks = re.findall(r'VULNERABLE:.*?(?=\n\n|\Z)', raw, re.DOTALL)
        for block in vuln_blocks[:5]:
            title_m = re.search(r'VULNERABLE:\s*(.+)', block)
            title = title_m.group(1).strip() if title_m else "Vulnerability Detected"
            self._findings.append(Finding(
                title=f"Nmap Confirmed: {title}",
                description=block.strip()[:400],
                severity="CRITICAL",
                evidence=block[:600],
                tool="nmap",
                host=target,
            ))
