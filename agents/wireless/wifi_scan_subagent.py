"""
wifi_scan_subagent.py — WiFi network discovery and assessment.

AGENT_NAME  : "wireless"
SUBAGENT_NAME: "wifi_scan"

Methodology:
  1. Put wireless interface into monitor mode (airmon-ng)
  2. Scan for access points (airodump-ng)
  3. Identify open networks, WEP, WPA/WPA2, WPA3
  4. Identify hidden SSIDs, detect rogue APs
  5. Enumerate associated clients per AP
  6. Check for PMKID capture opportunities
  7. Restore managed mode after scan
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_AP_RE      = re.compile(r'([0-9A-F:]{17})\s+[-\d]+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\w+)\s+\S+\s+\S+\s+(.+)', re.I)
_OPEN_RE    = re.compile(r'\bOPN\b|\bOPEN\b', re.I)
_WEP_RE     = re.compile(r'\bWEP\b', re.I)
_WPA_RE     = re.compile(r'WPA[23]?\b', re.I)
_CLIENT_RE  = re.compile(r'([0-9A-F:]{17})\s+[-\d]+\s+[-\d]+\s+\d+\s+\d+\s+\d+\s+([0-9A-F:]{17})', re.I)
_HIDDEN_RE  = re.compile(r'<length:\s*\d+>|<\s*>', re.I)


class WifiScanSubagent(BaseSubagent):
    """Scan and enumerate WiFi networks in range."""

    AGENT_NAME    = "wireless"
    SUBAGENT_NAME = "wifi_scan"

    async def run(self, target: str, interface: str = "wlan0",
                  scan_duration: int = 30,
                  band: str = "bg",
                  evidence_dir: str = "/tmp/pentest_evidence",
                  **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        await self.collect_tool("bash", target,
            {"options": f"-c \"mkdir -p {evidence_dir}/wireless\""})

        # ── Check for aircrack-ng suite ───────────────────────────────
        tools_out = await self.collect_tool("bash", target,
            {"options": "-c \"which airmon-ng airodump-ng iw iwconfig 2>/dev/null\""})
        has_airmon = "airmon-ng" in tools_out
        has_airodump = "airodump-ng" in tools_out
        has_iw = "iw" in tools_out

        if not (has_airmon or has_iw):
            await self.store_finding(Finding(
                title="WiFi Scan: Wireless Tools Not Available",
                description="aircrack-ng suite not found. Install: apt install -y aircrack-ng wireless-tools",
                severity="INFO",
                evidence=tools_out[:200], tool="bash", host=target,
                mitre_technique="T1595",
                exploit_suggestion="Install: apt install -y aircrack-ng",
            ))
            result.findings = list(self._findings)
            result.tool_outputs = dict(self._tool_outputs)
            return result

        # ── Kill interfering processes ────────────────────────────────
        kill_out = await self.collect_tool("bash", target,
            {"options": f"-c \"airmon-ng check kill 2>&1; echo DONE\""})

        # ── Enable monitor mode ───────────────────────────────────────
        mon_out = await self.collect_tool("bash", target,
            {"options": f"-c \"airmon-ng start {interface} 2>&1 | tail -5\""})
        mon_iface = interface + "mon" if "mon" not in interface else interface
        # Try to extract actual monitor interface name
        mon_match = re.search(r'monitor mode (?:enabled on|vif enabled for)|monitor mode already enabled on\s+(\w+)', mon_out, re.I)
        if mon_match and mon_match.lastindex and mon_match.group(1):
            mon_iface = mon_match.group(1)

        await self.store_finding(Finding(
            title=f"WiFi Scan: Monitor Mode Enabled — {mon_iface}",
            description=f"Wireless interface {interface} set to monitor mode as {mon_iface}.",
            severity="INFO",
            evidence=mon_out[:300], tool="bash", host=target,
            mitre_technique="T1595",
        ))

        # ── airodump-ng scan ──────────────────────────────────────────
        csv_prefix = f"{evidence_dir}/wireless/scan"
        scan_out = await self.collect_tool("bash", target,
            {"options": f"-c \"timeout {scan_duration} airodump-ng --band {band} -w {csv_prefix} --output-format csv {mon_iface} 2>&1; echo SCAN_DONE\""})

        # Parse CSV output
        csv_out = await self.collect_tool("bash", target,
            {"options": f"-c \"cat {csv_prefix}-01.csv 2>/dev/null | head -100\""})

        # Parse APs
        aps = []
        open_nets = []
        wep_nets = []
        hidden_nets = []

        for line in csv_out.splitlines():
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 14 and re.match(r'[0-9A-F:]{17}', parts[0], re.I):
                bssid   = parts[0]
                channel = parts[3].strip()
                privacy = parts[5].strip()
                essid   = parts[13].strip() if len(parts) > 13 else "(unknown)"

                aps.append({'bssid': bssid, 'channel': channel, 'privacy': privacy, 'essid': essid})

                if _OPEN_RE.search(privacy):
                    open_nets.append((essid, bssid, channel))
                if _WEP_RE.search(privacy):
                    wep_nets.append((essid, bssid, channel))
                if _HIDDEN_RE.search(essid) or not essid:
                    hidden_nets.append((bssid, channel))

        await self.store_finding(Finding(
            title=f"WiFi Scan: {len(aps)} Access Point(s) — {len(open_nets)} Open, {len(wep_nets)} WEP, {len(hidden_nets)} Hidden",
            description=(
                f"WiFi survey results:\n"
                f"  Total APs: {len(aps)}\n"
                f"  Open (no encryption): {len(open_nets)}\n"
                f"  WEP (crackable): {len(wep_nets)}\n"
                f"  Hidden SSID: {len(hidden_nets)}\n"
                f"  Sample APs: {[ap['essid'] for ap in aps[:5]]}"
            ),
            severity="HIGH" if (open_nets or wep_nets) else "MEDIUM",
            evidence=csv_out[:800], tool="bash", host=target,
            mitre_technique="T1595",
        ))

        if open_nets:
            await self.store_finding(Finding(
                title=f"WiFi: {len(open_nets)} Open Network(s) — No Encryption",
                description=f"Open WiFi networks (no password required):\n" + "\n".join([f"{e[0]} ({e[1]}) ch{e[2]}" for e in open_nets[:10]]),
                severity="HIGH",
                evidence=str(open_nets[:10]), tool="bash", host=target,
                mitre_technique="T1595",
                exploit_suggestion=f"Connect: iwconfig {interface} essid '{open_nets[0][0]}'; dhclient {interface}",
            ))

        if wep_nets:
            await self.store_finding(Finding(
                title=f"WiFi: {len(wep_nets)} WEP Network(s) — Crackable",
                description=f"WEP-encrypted networks (trivially crackable):\n" + "\n".join([f"{e[0]} ({e[1]})" for e in wep_nets[:5]]),
                severity="CRITICAL",
                evidence=str(wep_nets[:5]), tool="bash", host=target,
                mitre_technique="T1595",
                exploit_suggestion=f"Crack: airodump-ng -c <ch> --bssid {wep_nets[0][1]} -w /tmp/wep {mon_iface}; aircrack-ng /tmp/wep*.cap",
            ))

        # ── PMKID capture opportunity check ──────────────────────────
        pmkid_out = await self.collect_tool("bash", target,
            {"options": "-c \"which hcxdumptool hcxtools 2>/dev/null\""})
        has_hcx = bool(pmkid_out.strip())

        if has_hcx and aps:
            target_bssid = aps[0]['bssid'] if aps else ""
            await self.store_finding(Finding(
                title=f"WiFi: PMKID Capture Available (hcxdumptool) — {len(aps)} Target(s)",
                description="hcxdumptool found. Can capture PMKID without de-authentication. No clients needed.",
                severity="HIGH",
                evidence=pmkid_out[:100], tool="bash", host=target,
                mitre_technique="T1056",
                exploit_suggestion=f"Capture: hcxdumptool -i {mon_iface} --filterlist_ap={target_bssid} -o /tmp/pmkid.pcapng; hcxpcapngtool -o /tmp/hash.hc22000 /tmp/pmkid.pcapng; hashcat -m 22000 /tmp/hash.hc22000 /usr/share/wordlists/rockyou.txt",
            ))

        # ── Restore managed mode ───────────────────────────────────────
        restore_out = await self.collect_tool("bash", target,
            {"options": f"-c \"airmon-ng stop {mon_iface} 2>&1; systemctl restart NetworkManager 2>/dev/null; echo RESTORED\""})
        await self.store_finding(Finding(
            title=f"WiFi Scan: Interface Restored to Managed Mode",
            description=f"Wireless interface {mon_iface} restored. NetworkManager restarted.",
            severity="INFO",
            evidence=restore_out[:200], tool="bash", host=target,
            mitre_technique="T1595",
        ))

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
