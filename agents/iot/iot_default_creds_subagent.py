"""
iot_default_creds_subagent.py — IoT Default Credential Testing

Tests discovered services for default/common IoT credentials across:
  - HTTP admin panels (form-based and Basic auth)
  - SSH / Telnet
  - MQTT (username/password)
  - FTP (often left open on NAS/printers)
  - RTSP (IP camera streams)

Uses curated IoT-specific credential lists sourced from known defaults for:
  - Consumer routers (Netgear, TP-Link, D-Link, ASUS, Linksys)
  - IP cameras (Hikvision, Dahua, Axis, Reolink, Amcrest)
  - Smart home hubs (SmartThings, Hubitat, Home Assistant default)
  - Industrial HMIs (Siemens, Rockwell, Schneider)
  - NAS devices (Synology, QNAP)
  - Embedded Linux devices (OpenWRT, DD-WRT)
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

# Curated IoT default credential pairs [username, password]
IOT_DEFAULT_CREDS = [
    ("admin",       "admin"),
    ("admin",       "password"),
    ("admin",       "1234"),
    ("admin",       "12345"),
    ("admin",       "123456"),
    ("admin",       ""),
    ("root",        "root"),
    ("root",        ""),
    ("root",        "admin"),
    ("root",        "toor"),
    ("root",        "1234"),
    ("admin",       "Admin"),
    ("administrator", "administrator"),
    ("user",        "user"),
    ("guest",       "guest"),
    ("ubnt",        "ubnt"),         # Ubiquiti
    ("pi",          "raspberry"),    # Raspberry Pi
    ("admin",       "admin123"),
    ("admin",       "default"),
    ("support",     "support"),
    ("service",     "service"),
    ("admin",       "smcadmin"),     # SMC routers
    ("cusadmin",    "highspeed"),    # Virgin Media routers
    ("admin",       "motorola"),     # Motorola
    ("admin",       "password1"),
    ("Admin",       "admin"),
    ("admin",       "Admin1234"),    # Hikvision default
    ("888888",      "888888"),       # Dahua default
    ("666666",      "666666"),       # Dahua default
]

# Hydra service name mappings
HYDRA_SERVICE_MAP = {
    "22":   "ssh",
    "23":   "telnet",
    "21":   "ftp",
    "80":   "http-get-form",
    "8080": "http-get-form",
    "443":  "https-get-form",
    "8443": "https-get-form",
    "1883": "mqtt",
}


class IoTDefaultCredsSubagent(BaseSubagent):
    AGENT_NAME    = "IoTAgent"
    SUBAGENT_NAME = "iot_default_creds"

    async def run(self, target: str, **kwargs) -> SubagentResult:
        start = datetime.now(timezone.utc)
        self._findings.clear()
        await self._emit_start()

        open_ports: list[str] = kwargs.get("open_ports", ["22", "23", "80", "8080"])
        services:   dict      = kwargs.get("services", {})

        for port in open_ports:
            if self._stop_requested:
                break
            svc = services.get(str(port), {})
            svc_name = svc.get("service", "") if isinstance(svc, dict) else str(svc)
            await self._test_port(target, str(port), svc_name.lower())

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

    # ── Per-port testing ───────────────────────────────────────────────────────

    async def _test_port(self, target: str, port: str, svc_name: str) -> None:
        if "ssh" in svc_name or port == "22":
            await self._test_ssh(target, port)
        elif "telnet" in svc_name or port == "23":
            await self._test_telnet(target, port)
        elif "ftp" in svc_name or port == "21":
            await self._test_ftp(target, port)
        elif "mqtt" in svc_name or port in ("1883", "8883"):
            await self._test_mqtt(target, port)
        elif "http" in svc_name or port in ("80", "8080", "443", "8443", "8081"):
            await self._test_http(target, port)

    async def _test_ssh(self, target: str, port: str) -> None:
        # Build hydra cred file
        cred_pairs = "\n".join(f"{u}:{p}" for u, p in IOT_DEFAULT_CREDS[:20])
        cmd = (
            f"echo '{cred_pairs}' > /tmp/iot_creds.txt && "
            f"hydra -C /tmp/iot_creds.txt -s {port} ssh://{target} "
            f"-t 4 -w 3 -f 2>&1 | tail -20"
        )
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            if self._stop_requested:
                return
            output_lines.append(line)
        self._parse_hydra_output(target, int(port), "ssh", "\n".join(output_lines))

    async def _test_telnet(self, target: str, port: str) -> None:
        cred_pairs = "\n".join(f"{u}:{p}" for u, p in IOT_DEFAULT_CREDS[:20])
        cmd = (
            f"echo '{cred_pairs}' > /tmp/iot_creds.txt && "
            f"hydra -C /tmp/iot_creds.txt -s {port} telnet://{target} "
            f"-t 4 -w 3 -f 2>&1 | tail -20"
        )
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            if self._stop_requested:
                return
            output_lines.append(line)
        self._parse_hydra_output(target, int(port), "telnet", "\n".join(output_lines))

    async def _test_ftp(self, target: str, port: str) -> None:
        # Try anonymous first
        cmd = f"curl -s --max-time 5 ftp://{target}:{port}/ --user 'anonymous:anonymous' 2>&1 | head -5"
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            if self._stop_requested:
                return
            output_lines.append(line)
        raw = "\n".join(output_lines)
        if raw.strip() and "Login incorrect" not in raw and "530" not in raw:
            self._findings.append(Finding(
                title="FTP Anonymous Login Allowed",
                description="FTP server accepts anonymous login — common on IoT NAS and printers.",
                severity="HIGH",
                evidence=raw[:300],
                tool="curl",
                host=target,
                port=int(port),
                exploit_suggestion=f"ftp {target}  # user: anonymous  pass: anonymous",
            ))

    async def _test_mqtt(self, target: str, port: str) -> None:
        # Try unauthenticated first
        cmd = f"timeout 5 mosquitto_sub -h {target} -p {port} -t 'test' --quiet 2>&1"
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            if self._stop_requested:
                return
            output_lines.append(line)
        raw = "\n".join(output_lines)
        if "Connection refused" not in raw and "error" not in raw.lower():
            self._findings.append(Finding(
                title=f"MQTT Broker Accepts Unauthenticated Connection (port {port})",
                description="MQTT broker allows connection without credentials.",
                severity="HIGH",
                evidence=raw[:300],
                tool="mosquitto_sub",
                host=target,
                port=int(port),
                exploit_suggestion=f"mosquitto_sub -h {target} -p {port} -t '#' -v",
            ))

    async def _test_http(self, target: str, port: str) -> None:
        scheme = "https" if port in ("443", "8443") else "http"
        # Try HTTP Basic auth with each credential pair
        for user, passwd in IOT_DEFAULT_CREDS[:15]:
            if self._stop_requested:
                return
            cmd = (
                f"curl -sk --max-time 5 -u '{user}:{passwd}' "
                f"-o /dev/null -w '%{{http_code}}' "
                f"{scheme}://{target}:{port}/ 2>/dev/null"
            )
            output_lines: list[str] = []
            async for line in self.run_tool("run_command", target, {"command": cmd}):
                output_lines.append(line)
            code = "".join(output_lines).strip()
            if code in ("200", "301", "302") and code != "":
                self._findings.append(Finding(
                    title=f"Default HTTP Credentials Valid: {user}/{passwd} on port {port}",
                    description=(
                        f"HTTP Basic authentication accepted default credentials "
                        f"'{user}:{passwd}' with HTTP {code}. "
                        "Full admin access may be possible."
                    ),
                    severity="CRITICAL",
                    evidence=f"curl -sk -u '{user}:{passwd}' {scheme}://{target}:{port}/ → HTTP {code}",
                    tool="curl",
                    host=target,
                    port=int(port),
                    exploit_suggestion=(
                        f"curl -sk -u '{user}:{passwd}' {scheme}://{target}:{port}/\n"
                        f"# Try admin panel, firmware update, remote code exec"
                    ),
                ))
                break  # Stop on first hit

    # ── Hydra output parser ────────────────────────────────────────────────────

    def _parse_hydra_output(self, target: str, port: int, svc: str, raw: str) -> None:
        # Hydra success: [port][service] host: x.x.x.x  login: xxx  password: yyy
        m = re.search(r'login:\s*(\S+)\s+password:\s*(\S*)', raw)
        if m:
            user, passwd = m.group(1), m.group(2)
            self._findings.append(Finding(
                title=f"Default {svc.upper()} Credentials Found: {user}/{passwd}",
                description=(
                    f"Hydra confirmed default credentials for {svc.upper()} on port {port}: "
                    f"username='{user}' password='{passwd}'. "
                    "This provides direct shell or admin access to the IoT device."
                ),
                severity="CRITICAL",
                evidence=raw[:400],
                tool="hydra",
                host=target,
                port=port,
                exploit_suggestion=(
                    f"ssh {user}@{target} # password: {passwd}" if svc == "ssh"
                    else f"telnet {target} # login: {user}  password: {passwd}"
                ),
            ))
