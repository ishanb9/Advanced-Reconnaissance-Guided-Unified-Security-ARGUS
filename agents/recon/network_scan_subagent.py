"""
network_scan_subagent.py — Full TCP/UDP port scan and service fingerprinting.

Methodology (OSCP-style):
  1. Host discovery  — fping to verify liveness
  2. Fast port scan  — masscan -p1-65535 (root) or nmap -p- -T4 --open
  3. Service detect  — nmap -sV -sC --script=banner,version on ALL open ports
  4. OS detection    — nmap -O (root only)
  5. Parse output    — structured port/service/version/banner/os dicts
  6. Store findings  — severity-graded per service risk model
  7. Emit events     — "network_scan_complete" with full port list
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Any, Optional

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity classification tables
# ---------------------------------------------------------------------------

# port → severity override (must match before generic service-name check)
_PORT_SEVERITY: dict[int, str] = {
    23: "CRITICAL",    # Telnet — cleartext
    512: "CRITICAL",   # rexec
    513: "CRITICAL",   # rlogin / rsh
    514: "CRITICAL",   # rsh
    2049: "HIGH",      # NFS
    6000: "HIGH",      # X11
    111: "HIGH",       # RPC portmapper
    2375: "CRITICAL",  # Docker daemon (unauthenticated)
    2376: "HIGH",      # Docker TLS
    4444: "HIGH",      # Metasploit default listener
    5900: "HIGH",      # VNC
    5901: "HIGH",      # VNC-1
    6379: "HIGH",      # Redis
    27017: "HIGH",     # MongoDB
    9200: "HIGH",      # Elasticsearch
    11211: "HIGH",     # Memcached
}

_SERVICE_SEVERITY: dict[str, str] = {
    # CRITICAL tier
    "telnet": "CRITICAL",
    "rsh": "CRITICAL",
    "rexec": "CRITICAL",
    "rlogin": "CRITICAL",
    # HIGH tier
    "ftp": "HIGH",
    "http-proxy": "HIGH",
    "ms-wbt-server": "HIGH",   # RDP
    "netbios-ssn": "HIGH",
    "microsoft-ds": "HIGH",    # SMB 445
    "smb": "HIGH",
    "vnc": "HIGH",
    "x11": "HIGH",
    "nfs": "HIGH",
    "rpcbind": "HIGH",
    "docker": "HIGH",
    "redis": "HIGH",
    "mongodb": "HIGH",
    "elasticsearch": "HIGH",
    "memcache": "HIGH",
    # MEDIUM tier
    "ssh": "MEDIUM",
    "http": "MEDIUM",
    "https": "MEDIUM",
    "ssl/http": "MEDIUM",
    "smtp": "MEDIUM",
    "pop3": "MEDIUM",
    "imap": "MEDIUM",
    "mysql": "MEDIUM",
    "postgresql": "MEDIUM",
    "mssql": "MEDIUM",
    "oracle": "MEDIUM",
    "rdp": "MEDIUM",
    "snmp": "MEDIUM",
    "ldap": "MEDIUM",
    "dns": "MEDIUM",
}

# Banner patterns that escalate severity
_CRITICAL_BANNER_PATTERNS: list[re.Pattern] = [
    re.compile(r"ms-wbt-server.*Welcome to Windows", re.IGNORECASE),
    re.compile(r"220.*FileZilla", re.IGNORECASE),
    re.compile(r"\(Debian\s+\d\.", re.IGNORECASE),  # old Debian SSH
]
_HIGH_BANNER_PATTERNS: list[re.Pattern] = [
    re.compile(r"OpenSSH[_\s](\d+)\.(\d+)", re.IGNORECASE),  # old SSH
    re.compile(r"vsftpd\s+2\.[012]", re.IGNORECASE),          # old vsftpd
    re.compile(r"Anonymous FTP", re.IGNORECASE),
    re.compile(r"ProFTPD\s+1\.[23]", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_root() -> bool:
    """Return True when the process is running as root (UID 0)."""
    return os.getuid() == 0


def _classify_port(port: int, service: str, version: str, banner: str) -> str:
    """Return a severity string for a discovered port/service combination."""
    combined_text = f"{service} {version} {banner}".lower()

    # Check explicit critical banner patterns first
    for pat in _CRITICAL_BANNER_PATTERNS:
        if pat.search(combined_text):
            return "CRITICAL"

    # Port-level override
    if port in _PORT_SEVERITY:
        base = _PORT_SEVERITY[port]
        # Telnet/RSH ports are always CRITICAL regardless of banner
        if base == "CRITICAL":
            return "CRITICAL"
        # Escalate HIGH if banner matches high patterns
        if base == "HIGH":
            for pat in _HIGH_BANNER_PATTERNS:
                if pat.search(combined_text):
                    return "CRITICAL"
            return "HIGH"

    # Service-name match
    for svc_key, sev in _SERVICE_SEVERITY.items():
        if svc_key in service.lower():
            if sev in ("CRITICAL", "HIGH"):
                for pat in _HIGH_BANNER_PATTERNS:
                    if pat.search(combined_text):
                        return "CRITICAL" if sev == "HIGH" else "CRITICAL"
                return sev
            return sev

    return "INFO"


def _parse_nmap_ports(output: str) -> list[dict]:
    """
    Parse nmap text output into a list of port dicts.

    Handles lines of the form:
        80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
        22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
        3306/tcp open  mysql   MySQL 5.7.34-log
    Also captures NSE script output immediately following a port line for
    banner extraction (e.g. ssh-hostkey, http-server-header).
    """
    ports: list[dict] = []
    # Accept leading whitespace and states: open, open|filtered.
    port_re = re.compile(
        r"^\s*(\d{1,5})/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)\s*(.*)",
        re.IGNORECASE,
    )
    banner_script_re = re.compile(
        r"^\|[_\s]+(\S.*?):\s*(.*)",
        re.IGNORECASE,
    )
    # Grepable/-oG fallback:  Host: 1.2.3.4 ()  Ports: 22/open/tcp//ssh//OpenSSH 7.4//, 80/open/tcp//http//Apache 2.4.49//
    grepable_ports_re = re.compile(r"Ports:\s*(.+)", re.IGNORECASE)
    # XML fallback: <port protocol="tcp" portid="22"><state state="open" .../><service name="ssh" product="OpenSSH" version="7.4" .../></port>
    xml_port_re = re.compile(
        r'<port[^>]*protocol="(tcp|udp)"[^>]*portid="(\d+)"[^>]*>'
        r'.*?<state[^>]*state="(open(?:\|filtered)?)"[^>]*/?>'
        r'(?:.*?<service(?P<svc>[^/]*)/?>)?',
        re.IGNORECASE | re.DOTALL,
    )
    svc_attr_re = re.compile(r'(\w+)="([^"]*)"')

    # Try XML parse first if output looks like XML.
    if "<nmaprun" in output or "<port " in output:
        for xm in xml_port_re.finditer(output):
            proto   = xm.group(1).lower()
            port_num = int(xm.group(2))
            attrs = dict(svc_attr_re.findall(xm.group("svc") or ""))
            service = (attrs.get("name") or "unknown").lower()
            version = " ".join(
                v for v in (attrs.get("product"), attrs.get("version"), attrs.get("extrainfo"))
                if v
            ).strip()
            ports.append({
                "port": port_num,
                "protocol": proto,
                "service": service,
                "version": version,
                "banner": attrs.get("banner", ""),
                "os_guess": "",
            })
        if ports:
            return ports

    # Try grepable parse
    for gm in grepable_ports_re.finditer(output):
        for entry in gm.group(1).split(","):
            parts = [p.strip() for p in entry.strip().split("/")]
            # portid / state / proto / owner / service / rpc_info / version
            if len(parts) < 3:
                continue
            try:
                port_num = int(parts[0])
            except ValueError:
                continue
            state = parts[1].lower()
            if "open" not in state:
                continue
            proto   = parts[2].lower() if parts[2] else "tcp"
            service = parts[4].lower() if len(parts) > 4 and parts[4] else "unknown"
            version = parts[6] if len(parts) > 6 else ""
            ports.append({
                "port": port_num,
                "protocol": proto,
                "service": service,
                "version": version,
                "banner": "",
                "os_guess": "",
            })
    if ports:
        return ports

    current_port: Optional[dict] = None
    for line in output.splitlines():
        line = line.rstrip()
        m = port_re.match(line)
        if m:
            if current_port:
                ports.append(current_port)
            port_num  = int(m.group(1))
            proto     = m.group(2).lower()
            # group 3 is state ("open" or "open|filtered"); service/version shift.
            service   = m.group(4).lower().strip()
            version   = m.group(5).strip()
            current_port = {
                "port":     port_num,
                "protocol": proto,
                "service":  service,
                "version":  version,
                "banner":   "",
                "os_guess": "",
            }
        elif current_port:
            bm = banner_script_re.match(line)
            if bm:
                key = bm.group(1).strip()
                val = bm.group(2).strip()
                # Append banner snippets from scripts
                if current_port["banner"]:
                    current_port["banner"] += f" | {key}: {val}"
                else:
                    current_port["banner"] = f"{key}: {val}"

    if current_port:
        ports.append(current_port)

    return ports


def _parse_os_guess(output: str) -> str:
    """Extract the best OS guess from nmap -O output."""
    # Try "OS details: ..." first (most accurate)
    m = re.search(r"OS details:\s*(.+)", output)
    if m:
        return m.group(1).strip()
    # Aggressive guess fallback
    m = re.search(r"Aggressive OS guesses:\s*(.+?)(?:\n|,)", output)
    if m:
        return m.group(1).strip()
    # Generic keyword fallback
    if re.search(r"linux", output, re.IGNORECASE):
        return "Linux"
    if re.search(r"windows", output, re.IGNORECASE):
        return "Windows"
    return "unknown"


def _extract_masscan_ports(output: str) -> list[int]:
    """Parse masscan output: 'Discovered open port 80/tcp on 10.0.0.1'"""
    return sorted(set(
        int(m.group(1))
        for m in re.finditer(r"Discovered open port (\d+)/tcp", output, re.IGNORECASE)
    ))


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class NetworkScanSubagent(BaseSubagent):
    """
    Full network port scan and service fingerprint subagent.

    Executes a layered scan methodology:
      fping → masscan/nmap (full range) → nmap -sV -sC → nmap -O
    All findings are severity-graded and stored via store_finding().
    """

    AGENT_NAME    = "recon"
    SUBAGENT_NAME = "network_scan"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:  # noqa: C901
        """
        Execute the full network scan chain against *target*.

        Parameters
        ----------
        target:
            IP address, hostname, or CIDR range to scan.
        **kwargs:
            Unused; accepted for interface compatibility.

        Returns
        -------
        SubagentResult
            parsed_data["ports"]      — list of port dicts (port, protocol,
                                        service, version, banner, severity)
            parsed_data["os_guess"]   — best OS string
            parsed_data["open_ports"] — sorted list of open port integers
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {
            "ports": [],
            "open_ports": [],
            "os_guess": "unknown",
        }

        wall_start = time.monotonic()
        root = _is_root()

        # ── Step 1: Host discovery ─────────────────────────────────────────
        logger.info("[network_scan] Step 1 — host discovery: %s", target)
        host_alive = False
        try:
            fping_out = await self.collect_tool(
                "fping",
                target,
                {"options": f"-a -q {target}"},
            )
            if re.search(r"\d+\.\d+\.\d+\.\d+", fping_out) or "alive" in fping_out.lower():
                host_alive = True
            else:
                # Try nmap ping sweep as fallback
                nmap_ping = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"-sn -PE --send-ip {target}"},
                )
                host_alive = "Host is up" in nmap_ping
        except Exception as exc:
            logger.warning("[network_scan] host discovery error (continuing): %s", exc)
            host_alive = True  # assume alive, ICMP may be filtered

        if not host_alive:
            logger.info(
                "[network_scan] %s did not respond to ping — proceeding anyway "
                "(ICMP may be blocked).",
                target,
            )

        await self._emit(
            "network_scan_host_alive",
            {"target": target, "alive": host_alive},
        )

        # ── Step 2: Fast full-range port scan ─────────────────────────────
        logger.info("[network_scan] Step 2 — fast full-range scan: %s", target)
        open_ports: list[int] = []
        try:
            if root:
                # masscan is much faster but requires root
                masscan_out = await self.collect_tool(
                    "masscan",
                    target,
                    {"options": f"-p1-65535 --rate=1000 {target}"},
                )
                self._tool_outputs["masscan"] = masscan_out
                open_ports = _extract_masscan_ports(masscan_out)
                logger.info("[network_scan] masscan found %d ports", len(open_ports))
            else:
                # nmap fallback (slower but no root needed)
                nmap_fast_out = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"-p- -T4 --open --min-rate 3000 {target}"},
                )
                self._tool_outputs["nmap_fast"] = nmap_fast_out
                open_ports = sorted(set(
                    int(m.group(1))
                    for m in re.finditer(r"(\d+)/tcp\s+open", nmap_fast_out)
                ))
                logger.info("[network_scan] nmap fast scan found %d ports", len(open_ports))
        except Exception as exc:
            logger.error("[network_scan] fast scan error: %s", exc)

        # ── Step 3: Service/version/script detection on ALL open ports ────
        logger.info(
            "[network_scan] Step 3 — service detection on %d ports", len(open_ports)
        )
        port_dicts: list[dict] = []
        if open_ports:
            ports_csv = ",".join(str(p) for p in open_ports)
            try:
                nmap_svc_out = await self.collect_tool(
                    "nmap",
                    target,
                    {
                        "options": (
                            f"-sV -sC --script=banner,version,http-server-header,"
                            f"ssh-hostkey,ftp-anon,smtp-commands "
                            f"-p {ports_csv} {target}"
                        )
                    },
                )
                self._tool_outputs["nmap_services"] = nmap_svc_out
                port_dicts = _parse_nmap_ports(nmap_svc_out)
                logger.info("[network_scan] parsed %d service entries", len(port_dicts))
            except Exception as exc:
                logger.error("[network_scan] service detection error: %s", exc)
                # Build minimal port dicts from what we know
                port_dicts = [
                    {"port": p, "protocol": "tcp", "service": "unknown",
                     "version": "", "banner": "", "os_guess": ""}
                    for p in open_ports
                ]

        # ── Step 4: OS detection ──────────────────────────────────────────
        # nmap -O needs raw sockets (root).  When ARGUS is not root it never
        # runs and os_guess stays "unknown" — which mis-routed every
        # downstream tech-specific stage (a Windows AD DC was handed a Linux
        # payload and the WinRM shell path was skipped).  So: try -O when
        # root, then ALWAYS fall back to deriving the OS from the unprivileged
        # -sV service banners + the open-port fingerprint.
        os_guess = "unknown"
        if root and open_ports:
            logger.info("[network_scan] Step 4 — OS detection (nmap -O): %s", target)
            try:
                ports_csv = ",".join(str(p) for p in open_ports[:10])
                nmap_os_out = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"-O -p {ports_csv} {target}"},
                )
                self._tool_outputs["nmap_os"] = nmap_os_out
                os_guess = _parse_os_guess(nmap_os_out)
            except Exception as exc:
                logger.warning("[network_scan] OS detection error: %s", exc)

        # Banner/port fallback — runs whenever -O produced nothing usable.
        if (os_guess or "unknown").strip().lower() in ("", "unknown"):
            try:
                from agents.exploit.exploitability import infer_os
                blob_parts = [str(v) for v in self._tool_outputs.values()]
                for _pd in port_dicts:
                    blob_parts.append(
                        f"{_pd.get('service','')} {_pd.get('version','')} "
                        f"{_pd.get('banner','')}"
                    )
                inferred = infer_os(text=" ".join(blob_parts), open_ports=open_ports)
                if inferred:
                    os_guess = inferred.capitalize()
                    logger.info(
                        "[network_scan] OS inferred from -sV banners/ports: %s",
                        os_guess,
                    )
            except Exception as exc:
                logger.warning("[network_scan] OS banner-inference error: %s", exc)

        # Attach os_guess to all port dicts
        for pd in port_dicts:
            pd["os_guess"] = os_guess

        # ── Step 5: Classify severity and store findings ───────────────────
        logger.info("[network_scan] Step 5 — storing %d findings", len(port_dicts))
        for pd in port_dicts:
            port    = pd["port"]
            service = pd.get("service", "unknown")
            version = pd.get("version", "")
            banner  = pd.get("banner", "")

            severity = _classify_port(port, service, version, banner)
            pd["severity"] = severity

            # Build evidence string
            evidence_parts = [f"{port}/{pd['protocol']} open  {service}"]
            if version:
                evidence_parts.append(version)
            if banner:
                evidence_parts.append(f"[banner] {banner[:200]}")
            evidence = "  ".join(evidence_parts)

            # Exploit suggestion per severity
            if severity == "CRITICAL":
                exploit_hint = (
                    "Service presents critical risk. Check for known CVEs, "
                    "default credentials, and unauthenticated access vectors."
                )
            elif severity == "HIGH":
                exploit_hint = (
                    "Service presents high risk. Enumerate further, test for "
                    "weak credentials and known exploits."
                )
            else:
                exploit_hint = "Enumerate service version and test for known vulnerabilities."

            finding = Finding(
                title=(
                    f"Open Port {port}/{pd['protocol']}: "
                    f"{service}" + (f" ({version[:40]})" if version else "")
                ),
                description=(
                    f"Port {port}/{pd['protocol']} is open on {target}. "
                    f"Service: {service}. "
                    + (f"Version: {version}. " if version else "")
                    + (f"OS: {os_guess}. " if os_guess != 'unknown' else "")
                ),
                severity=severity,
                evidence=evidence,
                tool="nmap",
                host=target,
                port=port,
                exploit_suggestion=exploit_hint,
            )
            await self.store_finding(finding)

        # OS finding (separate, INFO level unless something interesting)
        if os_guess and os_guess != "unknown":
            await self.store_finding(Finding(
                title=f"OS Fingerprint: {os_guess}",
                description=(
                    f"nmap OS detection identified target {target} as: {os_guess}"
                ),
                severity="INFO",
                evidence=os_guess,
                tool="nmap",
                host=target,
            ))

        # ── Step 6: Build parsed_data and result ──────────────────────────
        all_open = sorted(set(pd["port"] for pd in port_dicts))
        result.parsed_data["ports"]      = port_dicts
        result.parsed_data["open_ports"] = all_open
        result.parsed_data["os_guess"]   = os_guess
        result.findings                  = self._findings
        result.tool_outputs              = self._tool_outputs
        result.duration_seconds          = time.monotonic() - wall_start

        # ── Step 7: Emit completion event ─────────────────────────────────
        await self._emit(
            "network_scan_complete",
            {
                "target":     target,
                "open_ports": all_open,
                "os_guess":   os_guess,
                "port_count": len(all_open),
                "finding_count": len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[network_scan] complete — %d ports, %d findings, %.1fs",
            len(all_open), len(self._findings), result.duration_seconds,
        )
        return result
