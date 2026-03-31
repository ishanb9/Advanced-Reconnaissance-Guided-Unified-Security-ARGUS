"""
defense_enum_subagent.py — Enumerate defensive controls and identify gaps.

AGENT_NAME  : "evasion"
SUBAGENT_NAME: "defense_enum"

Methodology:
  Linux:
    SELinux/AppArmor status, auditd rules, iptables/nftables, AIDE/Tripwire
  Windows:
    Defender exclusions, AppLocker/SRP policy, WDAC, ETW providers, CLM
  Both:
    Network-level controls (proxy, IDS indicators, blocked ports)
    Identify monitoring blind spots for the audit report
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_SELINUX_RE   = re.compile(r'(enforcing|permissive|disabled)', re.I)
_APPARMOR_RE  = re.compile(r'(enforce|complain|disabled|profiles.*loaded)', re.I)
_IPTABLES_RE  = re.compile(r'(-A INPUT|-A FORWARD|-j DROP|-j REJECT)', re.I)
_APPLOCKER_RE = re.compile(r'(AppLocker|SRP|Whitelisting|WDAC)', re.I)
_EXCLUSION_RE = re.compile(r'(ExclusionPath|ExclusionExtension|ExclusionProcess)', re.I)
_ETW_RE       = re.compile(r'(Microsoft-Windows-PowerShell|Microsoft-Antimalware)', re.I)


class DefenseEnumSubagent(BaseSubagent):
    """Map defensive controls to identify blind spots for evasion strategy."""

    AGENT_NAME    = "evasion"
    SUBAGENT_NAME = "defense_enum"

    async def run(self, target: str, os_type: str = "linux", **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        if os_type.lower() == "windows":
            await self._enum_windows(target)
        else:
            await self._enum_linux(target)

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    async def _enum_linux(self, target: str):
        # SELinux
        sel_out = await self.collect_tool("bash", target,
            {"options": "-c \"sestatus 2>/dev/null || getenforce 2>/dev/null || echo 'SELinux: not installed'\""})
        m = _SELINUX_RE.search(sel_out)
        sel_mode = m.group(1).lower() if m else "unknown"
        await self.store_finding(Finding(
            title=f"Linux Defense: SELinux = {sel_mode.upper()}",
            description=f"SELinux mode: {sel_mode}. {'Enforcing blocks policy violations — bypass or find permissive domains.' if sel_mode=='enforcing' else 'Not enforcing — SELinux is not a barrier.'}",
            severity="MEDIUM" if sel_mode == "enforcing" else "INFO",
            evidence=sel_out[:300], tool="bash", host=target, mitre_technique="T1518.001",
            exploit_suggestion="Check SELinux contexts: ps -eZ | grep unconfined; ls -Z /tmp" if sel_mode == "enforcing" else None,
        ))

        # AppArmor
        aa_out = await self.collect_tool("bash", target,
            {"options": "-c \"aa-status 2>/dev/null || apparmor_status 2>/dev/null || echo 'AppArmor: not found'\""})
        aa_active = _APPARMOR_RE.search(aa_out) and "not found" not in aa_out
        await self.store_finding(Finding(
            title=f"Linux Defense: AppArmor {'Active' if aa_active else 'Not Active'}",
            description=aa_out[:300],
            severity="MEDIUM" if aa_active else "INFO",
            evidence=aa_out[:400], tool="bash", host=target, mitre_technique="T1518.001",
        ))

        # Firewall
        fw_out = await self.collect_tool("bash", target,
            {"options": "-c \"iptables -L -n 2>/dev/null | head -30; nft list ruleset 2>/dev/null | head -20; ufw status 2>/dev/null\""})
        has_rules = bool(_IPTABLES_RE.search(fw_out))
        await self.store_finding(Finding(
            title=f"Linux Defense: Firewall {'Rules Present' if has_rules else 'No Active Rules Detected'}",
            description=f"Firewall configuration summary. Active rules: {has_rules}.",
            severity="INFO", evidence=fw_out[:600], tool="bash", host=target, mitre_technique="T1518.001",
        ))

        # AIDE/Tripwire
        aide_out = await self.collect_tool("bash", target,
            {"options": "-c \"which aide tripwire 2>/dev/null; crontab -l 2>/dev/null | grep -iE 'aide|tripwire'; systemctl is-active aide.timer 2>/dev/null\""})
        has_fim = bool(re.search(r'(aide|tripwire)', aide_out, re.I))
        await self.store_finding(Finding(
            title=f"Linux Defense: File Integrity Monitoring — {'PRESENT' if has_fim else 'NOT DEPLOYED'}",
            description=f"AIDE/Tripwire FIM: {'active' if has_fim else 'not found'}. {'' if has_fim else 'No FIM deployed — file modifications will not be detected.'}",
            severity="MEDIUM" if not has_fim else "INFO",
            evidence=aide_out[:300], tool="bash", host=target, mitre_technique="T1518.001",
        ))

    async def _enum_windows(self, target: str):
        # Defender exclusions
        excl_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess | Format-List\" 2>&1"})
        has_excl = bool(_EXCLUSION_RE.search(excl_out))
        excl_vals = re.findall(r'Exclusion(?:Path|Extension|Process)\s*:\s*(.+)', excl_out)
        if has_excl and excl_vals:
            await self.store_finding(Finding(
                title=f"Windows Defender: {len(excl_vals)} Exclusion(s) Configured — Blind Spot",
                description=f"Defender exclusions present: {excl_vals[:5]}. Placing payloads in excluded paths/using excluded extensions bypasses real-time scanning.",
                severity="HIGH", evidence=excl_out[:400], tool="powershell", host=target,
                mitre_technique="T1562.001",
                exploit_suggestion=f"Drop payload in excluded path: {excl_vals[0] if excl_vals else 'C:\\ProgramData\\excluded'}",
            ))

        # AppLocker / WDAC
        appl_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Select-Object RuleCollections | Format-List\" 2>&1"})
        wdac_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-CIPolicy -ErrorAction SilentlyContinue 2>&1\""})
        has_appl = bool(re.search(r'RuleCollection', appl_out))
        has_wdac = bool(re.search(r'CIPolicy|WDACPolicy', wdac_out))

        await self.store_finding(Finding(
            title=f"Windows Defense: AppLocker={'ACTIVE' if has_appl else 'NONE'} | WDAC={'ACTIVE' if has_wdac else 'NONE'}",
            description=f"Application whitelisting status. AppLocker: {has_appl}, WDAC: {has_wdac}.",
            severity="HIGH" if has_appl or has_wdac else "MEDIUM",
            evidence=(appl_out + wdac_out)[:400], tool="powershell", host=target,
            mitre_technique="T1562.001",
            exploit_suggestion="AppLocker bypass: LOLBins (mshta, regsvr32, rundll32, msbuild). WDAC: check whitelisted paths.",
        ))

        # ETW logging
        etw_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-EtwTraceProvider -ErrorAction SilentlyContinue | Where-Object {$_.Name -match 'PowerShell|Antimalware'} | Select Name,Enabled\" 2>&1"})
        etw_ps = bool(_ETW_RE.search(etw_out))
        await self.store_finding(Finding(
            title=f"Windows Defense: ETW PowerShell Logging — {'ENABLED' if etw_ps else 'NOT DETECTED'}",
            description=f"ETW (Event Tracing for Windows) providers status. PowerShell ETW: {etw_ps}.",
            severity="INFO", evidence=etw_out[:300], tool="powershell", host=target,
            mitre_technique="T1562.006",
            exploit_suggestion="ETW bypass: patch EtwEventWrite in ntdll.dll (requires local code execution). Or use CLM-bypassed PS session.",
        ))
