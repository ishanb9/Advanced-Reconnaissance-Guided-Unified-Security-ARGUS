"""
pcap_capture_subagent.py — Packet capture and traffic analysis.

AGENT_NAME  : "traffic"
SUBAGENT_NAME: "pcap_capture"

Methodology:
  1. Identify network interfaces (primary/bridge/VPN)
  2. Capture traffic for a defined window (default 30s) with tcpdump
  3. Analyze with tshark: protocol breakdown, unique IPs, suspicious flows
  4. Extract HTTP/FTP/SMTP clear-text artifacts
  5. Identify credentials in captures (via tshark dissectors)
  6. Save pcap to evidence directory with SHA256 hash
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_IFACE_RE   = re.compile(r'^(\d+\.\s+)?(\w[\w:]+)\s', re.M)
_CRED_RE    = re.compile(r'(Authorization:\s*Basic|password=|passwd=|login=|user=)', re.I)
_HTTP_RE    = re.compile(r'(GET|POST|PUT|DELETE)\s+\S+\s+HTTP', re.I)
_PROTO_RE   = re.compile(r'(\d+)\s+([\w.]+)\s+\d+\.\d+%')


class PcapCaptureSubagent(BaseSubagent):
    """Capture and analyze network traffic for sensitive data."""

    AGENT_NAME    = "traffic"
    SUBAGENT_NAME = "pcap_capture"

    async def run(self, target: str, interface: str = "",
                  duration: int = 30,
                  capture_filter: str = "",
                  evidence_dir: str = "/tmp/pentest_evidence",
                  **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        # ── Ensure evidence dir exists ─────────────────────────────────
        await self.collect_tool("bash", target,
            {"options": f"-c \"mkdir -p {evidence_dir}/pcaps\""})

        # ── Detect interfaces ──────────────────────────────────────────
        if not interface:
            iface_out = await self.collect_tool("bash", target,
                {"options": "-c \"ip link show 2>/dev/null || ifconfig -a 2>/dev/null\""})
            # Pick first non-loopback
            for line in iface_out.splitlines():
                m = re.match(r'^\d+:\s+(\w+):', line)
                if m and m.group(1) not in ('lo', 'localhost'):
                    interface = m.group(1)
                    break
            if not interface:
                interface = "eth0"

        await self.store_finding(Finding(
            title=f"Traffic: Capturing on Interface {interface} for {duration}s",
            description=f"Starting packet capture. Interface: {interface}, Duration: {duration}s, Filter: '{capture_filter or 'none'}'",
            severity="INFO",
            evidence=f"Interface: {interface}", tool="bash", host=target,
            mitre_technique="T1040",
        ))

        # ── tcpdump capture ────────────────────────────────────────────
        pcap_file = f"{evidence_dir}/pcaps/capture_{target.replace('.', '_')}.pcap"
        filter_arg = f"'{capture_filter}'" if capture_filter else "''"
        tcpdump_out = await self.collect_tool("bash", target,
            {"options": f"-c \"timeout {duration} tcpdump -i {interface} {'-f ' + filter_arg if capture_filter else ''} -w {pcap_file} -q 2>&1; echo EXIT_CODE:$?\""})

        captured = "EXIT_CODE:0" in tcpdump_out or "EXIT_CODE:124" in tcpdump_out  # 124 = timeout (normal)
        await self.store_finding(Finding(
            title=f"Traffic: Packet Capture {'Complete' if captured else 'Failed'} — {pcap_file}",
            description=f"tcpdump capture result. File: {pcap_file}. Success: {captured}.",
            severity="INFO" if captured else "MEDIUM",
            evidence=tcpdump_out[:400], tool="bash", host=target,
            mitre_technique="T1040",
        ))

        if captured:
            # ── tshark protocol summary ────────────────────────────────
            proto_out = await self.collect_tool("bash", target,
                {"options": f"-c \"tshark -r {pcap_file} -qz io,phs 2>/dev/null | head -40\""})
            await self.store_finding(Finding(
                title="Traffic: Protocol Distribution Summary",
                description="Protocol hierarchy from captured traffic.",
                severity="INFO",
                evidence=proto_out[:600], tool="bash", host=target,
                mitre_technique="T1040",
            ))

            # ── Extract HTTP artifacts ─────────────────────────────────
            http_out = await self.collect_tool("bash", target,
                {"options": f"-c \"tshark -r {pcap_file} -Y http -T fields -e http.request.method -e http.request.uri -e http.host -e http.authorization -e http.file_data 2>/dev/null | head -50\""})
            cred_lines = [l for l in http_out.splitlines() if _CRED_RE.search(l)]
            if cred_lines:
                await self.store_finding(Finding(
                    title=f"Traffic: {len(cred_lines)} HTTP Credential(s) Captured in Plaintext",
                    description=f"Clear-text HTTP credentials or auth tokens found in traffic: {cred_lines[:3]}",
                    severity="CRITICAL",
                    evidence="\n".join(cred_lines[:20]), tool="bash", host=target,
                    mitre_technique="T1040",
                    exploit_suggestion="Decode Basic auth: echo '<base64>' | base64 -d",
                ))
            elif http_out.strip():
                await self.store_finding(Finding(
                    title=f"Traffic: HTTP Requests Captured — No Auth Headers",
                    description="HTTP traffic captured without credential headers.",
                    severity="INFO",
                    evidence=http_out[:400], tool="bash", host=target,
                    mitre_technique="T1040",
                ))

            # ── Extract FTP/Telnet credentials ────────────────────────
            ftp_out = await self.collect_tool("bash", target,
                {"options": f"-c \"tshark -r {pcap_file} -Y 'ftp or telnet' -T fields -e ftp.request.command -e ftp.request.arg -e telnet.data 2>/dev/null | grep -iE 'USER|PASS|password' | head -20\""})
            if ftp_out.strip():
                await self.store_finding(Finding(
                    title="Traffic: FTP/Telnet Credentials in Capture",
                    description=f"Clear-text FTP or Telnet credentials captured:\n{ftp_out.strip()[:300]}",
                    severity="CRITICAL",
                    evidence=ftp_out[:400], tool="bash", host=target,
                    mitre_technique="T1040",
                ))

            # ── Unique IP summary ──────────────────────────────────────
            ip_out = await self.collect_tool("bash", target,
                {"options": f"-c \"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst 2>/dev/null | tr '\\t' '\\n' | sort -u | head -30\""})
            await self.store_finding(Finding(
                title="Traffic: Unique IP Addresses Observed",
                description=f"All unique IPs in capture:\n{ip_out.strip()[:400]}",
                severity="INFO",
                evidence=ip_out[:400], tool="bash", host=target,
                mitre_technique="T1040",
            ))

            # ── Hash the pcap ─────────────────────────────────────────
            hash_out = await self.collect_tool("bash", target,
                {"options": f"-c \"sha256sum {pcap_file} 2>/dev/null\""})
            await self.store_finding(Finding(
                title="Traffic: PCAP Hash (Chain of Custody)",
                description=f"SHA256: {hash_out.strip()}",
                severity="INFO",
                evidence=hash_out.strip(), tool="bash", host=target,
                mitre_technique="T1040",
            ))

            # [77] Populate the live Traffic Captures panel, which consumes a
            # traffic_capture_added WS event that nothing ever emitted.
            try:
                await self._emit("traffic_capture_added", {
                    "id":          f"cap_{target.replace('.', '_')}",
                    "interface":   interface,
                    "file":        pcap_file,
                    "pcap_file":   pcap_file,
                    "credentials": cred_lines[:20] if cred_lines else [],
                    "duration":    duration,
                    "summary":     f"Captured on {interface} for {duration}s",
                })
            except Exception:
                pass

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
