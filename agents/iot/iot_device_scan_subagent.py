"""
iot_device_scan_subagent.py — IoT Device Fingerprinting & Enumeration

Detects and fingerprints IoT devices by probing IoT-specific ports and protocols:
  - MQTT (1883 / 8883 TLS)
  - CoAP (5683 UDP)
  - Modbus (502)
  - BACnet (47808 UDP)
  - AMQP (5672)
  - Zigbee/Z-Wave gateway APIs (common ports)
  - SNMP (161 UDP) for device MIB info
  - Telnet (23) — still common on embedded devices
  - UPnP (1900 UDP / 49152+)
  - mDNS/DNS-SD device advertisements
  - Device web admin panels (80/443/8080/8443)
  - RTSP streams (554) — IP cameras
  - Modbus, DNP3 for ICS/SCADA

Also runs nmap IoT/ICS NSE scripts and banner-grabs to extract firmware version,
manufacturer, and model from HTTP headers and SNMP MIBs.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Optional

from agents.base_subagent import BaseSubagent, Finding, SubagentResult


class IoTDeviceScanSubagent(BaseSubagent):
    AGENT_NAME    = "IoTAgent"
    SUBAGENT_NAME = "iot_device_scan"

    # IoT-specific port groups
    IOT_PORTS = "22,23,80,161,443,502,554,1883,4840,5000,5683,5672,7547,8080,8081,8443,8883,47808,49152"

    async def run(self, target: str, **kwargs) -> SubagentResult:
        start = datetime.now(timezone.utc)
        self._findings.clear()
        await self._emit_start()

        # 1. IoT-focused nmap port + service scan with NSE scripts
        await self._nmap_iot_scan(target)

        # 2. SNMP enumeration for device info
        await self._snmp_enum(target)

        # 3. UPnP discovery
        await self._upnp_probe(target)

        # 4. MQTT broker probe
        await self._mqtt_probe(target)

        # 5. Web admin panel fingerprint
        await self._web_admin_fingerprint(target)

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

    # ── nmap IoT scan ──────────────────────────────────────────────────────────

    async def _nmap_iot_scan(self, target: str) -> None:
        kb = await self._kb_search(f"IoT device nmap scan {target}", top_k=2)
        cmd = (
            f"nmap -sV -sC -p {self.IOT_PORTS} --open "
            f"--script=banner,snmp-info,mqtt-subscribe,modbus-discover,"
            f"bacnet-info,upnp-info,rtsp-url-brute "
            f"-T4 {target}"
        )
        output_lines: list[str] = []
        async for line in self.run_tool("nmap", target, {"args": cmd}):
            if self._stop_requested:
                break
            output_lines.append(line)

        raw = "\n".join(output_lines)
        self._parse_nmap_iot(target, raw)

    def _parse_nmap_iot(self, target: str, raw: str) -> None:
        # Extract open ports and services
        port_re = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?")
        for m in port_re.finditer(raw):
            port, proto, svc, version = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()
            svc_lower = svc.lower()

            # IoT-specific severity mapping
            severity = "INFO"
            title = f"Open {proto.upper()} port {port} — {svc}"
            description = f"Service: {svc} {version}".strip()
            extra = {"port": int(port), "protocol": proto, "service": svc, "version": version}

            if port in ("23",):  # Telnet
                severity = "HIGH"
                title = f"Telnet Open on port {port} (IoT risk)"
                description = (
                    "Telnet is cleartext and commonly left enabled on IoT/embedded devices. "
                    "Default credentials or authentication bypass frequently applies. "
                    f"Version: {version}"
                )
            elif port in ("161",):  # SNMP
                severity = "MEDIUM"
                title = f"SNMP Exposed on port {port}"
                description = (
                    "SNMP exposes device MIB — manufacturer, firmware version, interfaces. "
                    "Commonly uses default community strings 'public'/'private'. "
                    f"Version: {version}"
                )
            elif port in ("1883",):  # MQTT unencrypted
                severity = "HIGH"
                title = "MQTT Broker Open (Unencrypted port 1883)"
                description = (
                    "Unencrypted MQTT broker detected. May allow unauthenticated subscription "
                    "to all topics (#), device command injection, and sensor data interception."
                )
            elif port in ("8883",):  # MQTT TLS
                severity = "MEDIUM"
                title = "MQTT Broker Open (TLS port 8883)"
                description = "Encrypted MQTT broker. Check for weak TLS, client certificate bypass, or no auth."
            elif port in ("502",):  # Modbus
                severity = "CRITICAL"
                title = "Modbus/TCP ICS Protocol Exposed (port 502)"
                description = (
                    "Modbus has NO authentication. Any client can read/write coils and registers. "
                    "This can allow direct control of industrial equipment or sensors."
                )
                extra["mitre"] = "T0843"
            elif port in ("47808",):  # BACnet
                severity = "HIGH"
                title = "BACnet Building Automation Protocol Exposed (port 47808)"
                description = (
                    "BACnet/IP has no authentication. Allows enumeration and control of "
                    "HVAC, lighting, and building management systems."
                )
            elif port in ("554",):  # RTSP
                severity = "MEDIUM"
                title = f"RTSP Stream Open on port {port} (IP Camera)"
                description = (
                    "RTSP endpoint detected — likely an IP camera. "
                    "Check for unauthenticated stream access or default credentials."
                )
            elif port in ("4840",):  # OPC-UA
                severity = "HIGH"
                title = "OPC-UA Industrial Protocol Exposed (port 4840)"
                description = "OPC-UA server detected. May expose industrial process data without authentication."

            if severity != "INFO" or port in ("80","443","8080","8443","5000","7547"):
                f = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    evidence=raw[max(0, raw.find(m.group(0))-50):raw.find(m.group(0))+200],
                    tool="nmap",
                    host=target,
                    port=int(port),
                    mitre_technique=extra.get("mitre"),
                    exploit_suggestion=self._exploit_hint(port, svc_lower),
                )
                self._add_finding(f)

        # Extract NSE script results
        if "modbus-discover" in raw:
            self._add_finding(Finding(
                title="Modbus Device Identified via NSE",
                description="Nmap modbus-discover script confirmed a Modbus slave device.",
                severity="CRITICAL",
                evidence=raw[:500],
                tool="nmap",
                host=target,
                port=502,
                mitre_technique="T0843",
                exploit_suggestion="Use mbtget or modbus-cli to read/write registers: mbtget -r 1 -c 10 " + target,
            ))

        if "mqtt-subscribe" in raw and "topics" in raw.lower():
            self._add_finding(Finding(
                title="MQTT Topics Accessible Without Authentication",
                description="Nmap mqtt-subscribe script was able to subscribe to MQTT topics, indicating no authentication is required.",
                severity="HIGH",
                evidence=raw[:500],
                tool="nmap",
                host=target,
                port=1883,
                exploit_suggestion=f"mosquitto_sub -h {target} -t '#' -v",
            ))

        if "bacnet-info" in raw:
            self._add_finding(Finding(
                title="BACnet Device Information Exposed",
                description="BACnet device info retrieved — building automation system detected with no auth.",
                severity="HIGH",
                evidence=raw[:500],
                tool="nmap",
                host=target,
                port=47808,
            ))

    def _exploit_hint(self, port: str, svc: str) -> str:
        hints = {
            "23":  "Use hydra for default cred spray: hydra -L /usr/share/wordlists/metasploit/mirai_user.txt -P /usr/share/wordlists/metasploit/mirai_pass.txt telnet://{target}",
            "161": "Enumerate SNMP: snmpwalk -v2c -c public {target} . | head -50",
            "1883": "Subscribe all topics: mosquitto_sub -h {target} -t '#' -v",
            "502": "Read Modbus: mbtget -r 1 -c 10 {target}",
            "554": "Try RTSP URL: cvlc rtsp://{target}:554/live or rtsp-url-brute via nmap",
        }
        return hints.get(port, "")

    # ── SNMP enum ──────────────────────────────────────────────────────────────

    async def _snmp_enum(self, target: str) -> None:
        # Try common community strings
        for community in ("public", "private", "admin", "cisco", "monitor"):
            output_lines: list[str] = []
            async for line in self.run_tool(
                "run_command", target,
                {"command": f"snmpwalk -v2c -c {community} {target} 1.3.6.1.2.1.1 2>/dev/null | head -20"}
            ):
                if self._stop_requested:
                    return
                output_lines.append(line)

            raw = "\n".join(output_lines)
            if raw.strip() and "Timeout" not in raw and "No Such" not in raw:
                # Extract sysDescr (OID .1.3.6.1.2.1.1.1.0)
                desc_m = re.search(r'sysDescr.*?:\s*(.+)', raw)
                desc = desc_m.group(1).strip() if desc_m else raw[:300]

                self._add_finding(Finding(
                    title=f"SNMP Community String '{community}' Accepted",
                    description=(
                        f"SNMP community string '{community}' is valid. "
                        f"Device info: {desc}. "
                        "This can reveal firmware version, interfaces, and routing tables."
                    ),
                    severity="HIGH" if community in ("public", "private") else "MEDIUM",
                    evidence=raw[:500],
                    tool="snmpwalk",
                    host=target,
                    port=161,
                    exploit_suggestion=(
                        f"snmpwalk -v2c -c {community} {target} . > snmp_full.txt && "
                        f"snmp-check {target} -c {community}"
                    ),
                ))
                break  # found a valid string, stop

    # ── UPnP probe ─────────────────────────────────────────────────────────────

    async def _upnp_probe(self, target: str) -> None:
        output_lines: list[str] = []
        async for line in self.run_tool(
            "run_command", target,
            {"command": f"curl -s --max-time 5 http://{target}:49152/rootDesc.xml 2>/dev/null || "
                        f"curl -s --max-time 5 http://{target}:5000/rootDesc.xml 2>/dev/null | head -40"}
        ):
            if self._stop_requested:
                return
            output_lines.append(line)

        raw = "\n".join(output_lines)
        if "<device>" in raw.lower() or "friendlyname" in raw.lower():
            model_m = re.search(r'<modelName>(.*?)</modelName>', raw, re.IGNORECASE)
            mfr_m   = re.search(r'<manufacturer>(.*?)</manufacturer>', raw, re.IGNORECASE)
            model = model_m.group(1) if model_m else "unknown"
            mfr   = mfr_m.group(1)   if mfr_m   else "unknown"
            self._add_finding(Finding(
                title=f"UPnP Device Exposed: {mfr} {model}",
                description=(
                    f"UPnP rootDesc.xml accessible. Manufacturer: {mfr}, Model: {model}. "
                    "UPnP can expose port mappings, device capabilities, and NAT traversal APIs. "
                    "Check for UPnP SOAP injection attacks."
                ),
                severity="MEDIUM",
                evidence=raw[:500],
                tool="curl",
                host=target,
                exploit_suggestion=f"miranda (UPnP tool): msearch; then info, portmap for SOAP injection",
            ))

    # ── MQTT probe ─────────────────────────────────────────────────────────────

    async def _mqtt_probe(self, target: str) -> None:
        output_lines: list[str] = []
        async for line in self.run_tool(
            "run_command", target,
            {"command": f"timeout 8 mosquitto_sub -h {target} -p 1883 -t '#' -v --quiet 2>&1 | head -20"}
        ):
            if self._stop_requested:
                return
            output_lines.append(line)

        raw = "\n".join(output_lines)
        if raw.strip() and "Connection refused" not in raw and "error" not in raw.lower():
            self._add_finding(Finding(
                title="MQTT Broker Allows Unauthenticated Wildcard Subscription",
                description=(
                    "Successfully subscribed to all MQTT topics (#) without credentials. "
                    "All device telemetry, commands, and sensor data is exposed. "
                    "Attackers can also publish commands to actuator topics."
                ),
                severity="CRITICAL",
                evidence=raw[:600],
                tool="mosquitto_sub",
                host=target,
                port=1883,
                mitre_technique="T0886",
                exploit_suggestion=(
                    f"mosquitto_sub -h {target} -t '#' -v &\n"
                    f"mosquitto_pub -h {target} -t 'device/cmd' -m '{{\"action\":\"reboot\"}}'"
                ),
            ))

    # ── Web admin fingerprint ──────────────────────────────────────────────────

    async def _web_admin_fingerprint(self, target: str) -> None:
        for port in ("80", "8080", "443", "8443", "8081"):
            scheme = "https" if port in ("443", "8443") else "http"
            output_lines: list[str] = []
            async for line in self.run_tool(
                "run_command", target,
                {"command": f"curl -sk --max-time 6 -I {scheme}://{target}:{port}/ 2>/dev/null | head -20"}
            ):
                if self._stop_requested:
                    return
                output_lines.append(line)

            raw = "\n".join(output_lines)
            if not raw.strip() or "Connection refused" in raw:
                continue

            # Look for known IoT firmware fingerprints in headers
            server_m = re.search(r'(?i)server:\s*(.+)', raw)
            server   = server_m.group(1).strip() if server_m else ""

            # Data-driven IDENTIFICATION labels only (server-string -> human label).  These
            # NAME the surface; they do NOT rate severity.  Merely fingerprinting a vendor
            # web UI is an INFO attack-surface observation — severity elevates ONLY on a
            # CONFIRMED default-credential login or a matched CVE (produced elsewhere with
            # real evidence), never from the presence of a vendor string.  (Was: HIGH/MEDIUM
            # invented from the name alone — a fabrication that fails for every unlisted
            # vendor and over-rates every listed one.)
            iot_signatures = {
                "uhttpd":       "OpenWRT Router Admin Panel",
                "lighttpd":     "Embedded lighttpd Web Server (Router/Camera)",
                "GoAhead":      "GoAhead Embedded Web Server (IP Camera/Router)",
                "mini_httpd":   "mini_httpd Embedded Server (IoT Device)",
                "Hikvision":    "Hikvision IP Camera Web Interface",
                "Dahua":        "Dahua IP Camera Web Interface",
                "Netgear":      "Netgear Router Admin Panel",
                "D-Link":       "D-Link Router Admin Panel",
                "TP-Link":      "TP-Link Router Admin Panel",
                "RouterOS":     "MikroTik RouterOS Web Interface",
            }

            severity = "INFO"   # identification is attack-surface, never a graded finding
            title    = f"Web Interface on {scheme}://{target}:{port}"
            desc     = f"HTTP server: {server}. Check for default credentials and known CVEs."

            for sig, sig_title in iot_signatures.items():
                if sig.lower() in server.lower() or sig.lower() in raw.lower():
                    title = sig_title + f" on port {port}"
                    desc  = (
                        f"Identified an embedded/IoT vendor web interface ({sig}) — attack "
                        "surface only.  This is INFO: severity elevates ONLY on a confirmed "
                        f"default-credential login or a matched CVE.  Server: {server}"
                    )
                    break

            self._add_finding(Finding(
                title=title,
                description=desc,
                severity=severity,
                evidence=raw[:400],
                tool="curl",
                host=target,
                port=int(port),
                exploit_suggestion=(
                    f"Try default creds: admin/admin, admin/password, root/root\n"
                    f"Check firmware CVEs: searchsploit '{server.split('/')[0]}'"
                ),
            ))

    # ── Helper ─────────────────────────────────────────────────────────────────

    def _add_finding(self, f: Finding) -> None:
        self._findings.append(f)
