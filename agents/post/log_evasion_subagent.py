"""
log_evasion_subagent.py — Log and monitoring landscape audit.

AGENT_NAME  : "post"
SUBAGENT_NAME: "log_evasion"

Purpose:
  This subagent DOCUMENTS the logging and monitoring landscape of the compromised
  host for the audit report. It enumerates what evidence has been generated and
  what monitoring systems are present — useful for blue team gap analysis.

Methodology:
  Linux:
    1. Identify running SIEM/EDR/AV agents (Splunk, Elastic, CrowdStrike, etc.)
    2. Check syslog / journald configuration
    3. Identify audit daemon (auditd) rules
    4. Enumerate log retention policies
    5. Check for SIEM log shipping destinations
  Windows:
    1. Check Windows Event Forwarding (WEF) configuration
    2. Identify EDR/AV products (Defender, CrowdStrike, SentinelOne, etc.)
    3. Check Windows Event Log audit policies
    4. Identify Sysmon deployment and configuration
    5. Check PowerShell logging and script block logging
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

_EDR_RE = re.compile(
    r"(crowdstrike|falcon|sentinelone|carbonblack|cbdefense|cylance|"
    r"defender|mde|eset|kaspersky|symantec|mcafee|sophos|darktrace|"
    r"vectra|cybereason|elastic.*security|wazuh|ossec)",
    re.IGNORECASE,
)
_SIEM_RE = re.compile(
    r"(splunkd|splunk-forwarder|elasticsearch|logstash|kibana|"
    r"filebeat|metricbeat|auditbeat|graylog|sumo.*logic|qradar|"
    r"arcsight|exabeam|chronicle|datadog-agent)",
    re.IGNORECASE,
)
_SYSMON_RE = re.compile(r"(sysmon|winlogbeat)", re.IGNORECASE)
_AUDIT_RE = re.compile(r"(auditd|audit\.rules|/etc/audit)", re.IGNORECASE)
_LOG_SHIP_RE = re.compile(r"(fluentd|fluent-bit|nxlog|rsyslog.*@@|syslog-ng.*tcp)", re.IGNORECASE)
_PS_LOGGING_RE = re.compile(r"(ScriptBlockLogging|ModuleLogging|Transcription)", re.IGNORECASE)


class LogEvasionSubagent(BaseSubagent):
    """Enumerate logging and monitoring infrastructure for audit report."""

    AGENT_NAME: str = "post"
    SUBAGENT_NAME: str = "log_evasion"

    async def run(self, target: str, os_type: str = "linux", **kwargs: Any) -> SubagentResult:
        """
        Enumerate logging and monitoring landscape.

        Parameters
        ----------
        target:
            Compromised host IP or hostname.
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

        if os_type.lower() == "windows":
            await self._audit_windows(target)
        else:
            await self._audit_linux(target)

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ------------------------------------------------------------------
    # Linux monitoring audit
    # ------------------------------------------------------------------

    async def _audit_linux(self, target: str) -> None:
        """Audit Linux logging and monitoring configuration."""

        # ── 1. Running security processes ────────────────────────────────
        ps_output = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"ps aux 2>/dev/null | grep -v grep\""},
        )

        edr_processes = [l for l in ps_output.splitlines() if _EDR_RE.search(l)]
        siem_processes = [l for l in ps_output.splitlines() if _SIEM_RE.search(l)]
        log_ship_processes = [l for l in ps_output.splitlines() if _LOG_SHIP_RE.search(l)]

        if edr_processes:
            edr_names = list(set(re.search(r"(crowdstrike|falcon|sentinelone|cbdefense|cylance|defender|eset|kaspersky|symantec|mcafee|sophos|wazuh|ossec|elastic)", p, re.IGNORECASE).group(0) for p in edr_processes if re.search(_EDR_RE, p)))
            await self.store_finding(Finding(
                title=f"Monitoring Landscape: EDR/AV Detected — {', '.join(edr_names[:3])}",
                description=(
                    f"Endpoint Detection and Response (EDR) or Antivirus processes found: "
                    f"{', '.join(set(l.split()[10] for l in edr_processes[:3] if len(l.split()) > 10))}. "
                    "These tools may detect and alert on post-exploitation activities. "
                    "Document for blue team gap analysis in the audit report."
                ),
                severity="INFO",
                evidence="\n".join(edr_processes[:5]),
                tool="bash",
                host=target,
                mitre_technique="T1518.001",
                exploit_suggestion=(
                    "Note EDR version for bypass research. "
                    "Consider living-off-the-land techniques to reduce detection surface."
                ),
            ))
        else:
            await self.store_finding(Finding(
                title="Monitoring Landscape: No EDR/AV Processes Detected",
                description=(
                    "No known EDR or AV processes were identified on the system. "
                    "This represents a significant detection gap — the host may have "
                    "no endpoint visibility for post-exploitation activities."
                ),
                severity="MEDIUM",
                evidence=ps_output[:500],
                tool="bash",
                host=target,
                mitre_technique="T1518.001",
                exploit_suggestion=(
                    "Document the detection gap in the audit report. "
                    "Recommend deploying EDR agent to this host."
                ),
            ))

        if siem_processes:
            await self.store_finding(Finding(
                title=f"Monitoring Landscape: SIEM/Log Forwarding Agent Active — {len(siem_processes)} Process(es)",
                description=(
                    f"{len(siem_processes)} SIEM or log forwarding process(es) detected. "
                    "Activities on this host are likely being shipped to a central SIEM. "
                    "Post-exploitation activities may generate alerts."
                ),
                severity="INFO",
                evidence="\n".join(siem_processes[:5]),
                tool="bash",
                host=target,
                mitre_technique="T1070",
                exploit_suggestion=(
                    "Check SIEM destinations to understand what is being logged. "
                    "Document for the report — blue team should review SIEM alerts for this host."
                ),
            ))
        else:
            await self.store_finding(Finding(
                title="Monitoring Landscape: No SIEM Agent — Logs Not Centralised",
                description=(
                    "No SIEM log forwarding agent detected. System logs remain local only. "
                    "A compromise of this host would not generate real-time SIEM alerts. "
                    "This is a significant detection capability gap."
                ),
                severity="MEDIUM",
                evidence="No Splunk/Elastic/filebeat/rsyslog agents found in process list.",
                tool="bash",
                host=target,
                mitre_technique="T1070",
                exploit_suggestion=(
                    "Recommend deploying a log forwarding agent and shipping to central SIEM. "
                    "At minimum, configure remote syslog to prevent local log tampering."
                ),
            ))

        # ── 2. auditd configuration ───────────────────────────────────────
        auditd_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"systemctl is-active auditd 2>/dev/null; "
                "cat /etc/audit/auditd.conf 2>/dev/null | head -30; "
                "auditctl -l 2>/dev/null | head -20\""
            )},
        )

        auditd_active = "active" in auditd_output.lower() and not "inactive" in auditd_output.lower()
        rule_count = len([l for l in auditd_output.splitlines() if l.strip().startswith("-")])

        await self.store_finding(Finding(
            title=f"Linux Audit: auditd {'Active' if auditd_active else 'Inactive/Not Deployed'} — {rule_count} Rule(s)",
            description=(
                f"auditd status: {'ACTIVE' if auditd_active else 'INACTIVE'}. "
                f"Audit rules configured: {rule_count}. "
                f"{'Kernel-level syscall audit logging is enabled.' if auditd_active else 'No kernel-level audit logging — command execution is unmonitored.'}"
            ),
            severity="INFO" if auditd_active else "MEDIUM",
            evidence=auditd_output[:1000],
            tool="bash",
            host=target,
            mitre_technique="T1562.001",
            exploit_suggestion=(
                "Review auditd rules for completeness. "
                "Recommended rules: execve, open, connect, setuid/setgid syscalls."
            ) if auditd_active else (
                "Recommend deploying auditd with CIS or STIG baseline rules. "
                "Without auditd, forensic timeline reconstruction is severely limited."
            ),
        ))

        # ── 3. Syslog configuration ───────────────────────────────────────
        syslog_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | "
                "grep -E '(@|@@|tcp|udp)' | head -15; "
                "cat /etc/syslog-ng/syslog-ng.conf 2>/dev/null | grep -i 'destination\\|tcp\\|udp' | head -10\""
            )},
        )

        remote_syslog = bool(re.search(r"(@@|@\d+\.\d+|tcp\(|udp\()", syslog_output))
        await self.store_finding(Finding(
            title=f"Linux Logging: Syslog {'Forwarded to Remote Server' if remote_syslog else 'Local Only (No Remote Forwarding)'}",
            description=(
                f"Syslog configuration: {'remote forwarding configured' if remote_syslog else 'local-only logging'}. "
                f"{'Log entries are shipped to a central syslog server.' if remote_syslog else 'System logs are local and could be cleared by an attacker to cover tracks.'}"
            ),
            severity="INFO" if remote_syslog else "MEDIUM",
            evidence=syslog_output[:500],
            tool="bash",
            host=target,
            mitre_technique="T1070.002",
        ))

        # ── 4. Log retention check ────────────────────────────────────────
        log_sizes = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"du -sh /var/log/* 2>/dev/null | sort -rh | head -10\""},
        )

        journal_config = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"journalctl --disk-usage 2>/dev/null; cat /etc/systemd/journald.conf 2>/dev/null | grep -i 'retention\\|maxsize\\|maxfile'\""},
        )

        await self.store_finding(Finding(
            title="Linux Logging: Log Retention and Disk Usage Summary",
            description=(
                "Current log footprint and retention configuration. "
                "Review ensures adequate log retention for forensic investigation. "
                "Minimum recommended: 90 days for compliance frameworks (PCI-DSS, ISO 27001)."
            ),
            severity="INFO",
            evidence=f"Disk usage:\n{log_sizes[:300]}\n\nJournal config:\n{journal_config[:300]}",
            tool="bash",
            host=target,
            mitre_technique="T1070.002",
        ))

    # ------------------------------------------------------------------
    # Windows monitoring audit
    # ------------------------------------------------------------------

    async def _audit_windows(self, target: str) -> None:
        """Audit Windows logging and monitoring configuration."""

        # ── 1. Security processes (EDR/AV) ────────────────────────────────
        tasklist_output = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c tasklist /v 2>&1"},
        )

        edr_tasks = [l for l in tasklist_output.splitlines() if _EDR_RE.search(l)]
        sysmon_active = bool(_SYSMON_RE.search(tasklist_output))

        if edr_tasks:
            await self.store_finding(Finding(
                title=f"Monitoring Landscape: EDR/AV Running — {len(edr_tasks)} Security Process(es)",
                description=(
                    f"{len(edr_tasks)} security agent(s) detected via tasklist. "
                    "These tools provide endpoint visibility and may alert on "
                    "credential dumping, lateral movement, and C2 activity."
                ),
                severity="INFO",
                evidence="\n".join(edr_tasks[:10]),
                tool="cmd",
                host=target,
                mitre_technique="T1518.001",
            ))
        else:
            await self.store_finding(Finding(
                title="Monitoring Landscape: No EDR/AV Detected on Windows Host",
                description=(
                    "No known EDR or AV processes were found. "
                    "The host has no endpoint security coverage — a critical gap "
                    "that allows unrestricted post-exploitation activity."
                ),
                severity="HIGH",
                evidence=tasklist_output[:300],
                tool="cmd",
                host=target,
                mitre_technique="T1518.001",
            ))

        # ── 2. Sysmon deployment check ────────────────────────────────────
        await self.store_finding(Finding(
            title=f"Windows Logging: Sysmon {'Deployed' if sysmon_active else 'NOT Deployed — Critical Visibility Gap'}",
            description=(
                f"Sysmon (System Monitor) {'is active' if sysmon_active else 'was not found'}. "
                f"{'Sysmon provides detailed process, network, and file system event logging.' if sysmon_active else 'Without Sysmon, Windows event logs lack process creation details, network connections, and file hash logging — significantly limiting forensic capability.'}"
            ),
            severity="INFO" if sysmon_active else "HIGH",
            evidence=f"Sysmon in tasklist: {sysmon_active}",
            tool="cmd",
            host=target,
            mitre_technique="T1562.001",
            exploit_suggestion=(
                "Deploy Sysmon with SwiftOnSecurity config: "
                "sysmon -accepteula -i sysmonconfig.xml"
            ) if not sysmon_active else None,
        ))

        # ── 3. PowerShell script block logging ────────────────────────────
        ps_logging_output = await self.collect_tool(
            "cmd",
            target,
            {"options": (
                "/c reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /s 2>&1"
            )},
        )

        ps_scriptblock = bool(re.search(r"EnableScriptBlockLogging\s+REG_DWORD\s+0x1", ps_logging_output))
        ps_module_log = bool(re.search(r"EnableModuleLogging\s+REG_DWORD\s+0x1", ps_logging_output))
        ps_transcription = bool(re.search(r"EnableTranscripting\s+REG_DWORD\s+0x1", ps_logging_output))

        await self.store_finding(Finding(
            title=(
                f"Windows Logging: PowerShell Logging — "
                f"ScriptBlock={'ON' if ps_scriptblock else 'OFF'}, "
                f"Module={'ON' if ps_module_log else 'OFF'}, "
                f"Transcription={'ON' if ps_transcription else 'OFF'}"
            ),
            description=(
                f"PowerShell logging configuration audit. "
                f"Script block logging: {'enabled (Event ID 4104 captures all PS commands)' if ps_scriptblock else 'DISABLED'}. "
                f"Module logging: {'enabled' if ps_module_log else 'DISABLED'}. "
                f"Transcription: {'enabled' if ps_transcription else 'DISABLED'}. "
                f"{'All three logging types should be enabled for full PS visibility.' if not all([ps_scriptblock, ps_module_log, ps_transcription]) else 'Good PS logging coverage.'}"
            ),
            severity="INFO" if all([ps_scriptblock, ps_module_log]) else "MEDIUM",
            evidence=ps_logging_output[:500],
            tool="cmd",
            host=target,
            mitre_technique="T1562.001",
        ))

        # ── 4. Windows Event Log audit policy ─────────────────────────────
        auditpol_output = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c auditpol /get /category:* 2>&1"},
        )

        no_auditing = len(re.findall(r"No Auditing", auditpol_output))
        total_policies = len(re.findall(r"(Success|Failure|No Auditing)", auditpol_output))

        await self.store_finding(Finding(
            title=f"Windows Logging: Audit Policy — {no_auditing}/{total_policies} Policies Not Configured",
            description=(
                f"Windows audit policy review: {no_auditing} sub-categories set to 'No Auditing' "
                f"out of {total_policies} total. "
                "Critical categories to enable: Logon/Logoff, Object Access, "
                "Process Creation, Account Logon, Privilege Use."
            ),
            severity="INFO" if no_auditing < 5 else "MEDIUM",
            evidence=auditpol_output[:1500],
            tool="cmd",
            host=target,
            mitre_technique="T1562.002",
        ))

        # ── 5. Windows Event Forwarding ───────────────────────────────────
        wef_output = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c wevtutil gl Security /f:xml 2>&1 | findstr /i \"autoBackup maxSize\""},
        )

        wecutil_output = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c wecutil es 2>&1"},
        )

        wef_active = bool(wecutil_output.strip()) and not "No subscriptions" in wecutil_output
        await self.store_finding(Finding(
            title=f"Windows Logging: Event Forwarding {'Configured' if wef_active else 'NOT Configured'}",
            description=(
                f"Windows Event Forwarding (WEF): {'active subscriptions found' if wef_active else 'not configured'}. "
                f"{'Events are being forwarded to a Windows Event Collector.' if wef_active else 'Windows event logs remain local only. A compromise could result in log clearing without central detection.'}"
            ),
            severity="INFO" if wef_active else "MEDIUM",
            evidence=f"WEF subscriptions:\n{wecutil_output[:300]}\n\nLog config:\n{wef_output[:200]}",
            tool="cmd",
            host=target,
            mitre_technique="T1070.001",
        ))
