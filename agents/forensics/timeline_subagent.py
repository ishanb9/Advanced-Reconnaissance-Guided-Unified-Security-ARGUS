"""
timeline_subagent.py — Reconstruct attack timeline from log and filesystem artifacts.

AGENT_NAME  : "forensics"
SUBAGENT_NAME: "timeline"

Methodology:
  1. Correlate filesystem timestamps (mtime/atime/ctime) with known attack window
  2. Parse auth/syslog for sequence of events
  3. Extract shell command timestamps from history files
  4. Build ordered event sequence for the report
  5. Identify first foothold time, privilege escalation time, persistence install time
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_TIMESTAMP_RE  = re.compile(r'(\w{3}\s+\d+\s+[\d:]+|\d{4}-\d{2}-\d{2}[T\s][\d:]+)', re.I)
_PRIVESC_RE    = re.compile(r'(sudo|su root|NOPASSWD|passwd|useradd|usermod|visudo)', re.I)
_SHELL_DROP_RE = re.compile(r'(nc\s+-[el]|bash\s+-i|python.*pty|socat|/bin/sh|meterpreter|shell\.php|webshell)', re.I)
_PERSIST_RE    = re.compile(r'(crontab|authorized_keys|\.bashrc|\.profile|init\.d|systemd|rc\.local)', re.I)
_EXFIL_RE      = re.compile(r'(curl|wget|scp|rsync|ftp|nc\s+\d+\.\d+|/dev/tcp)', re.I)


class TimelineSubagent(BaseSubagent):
    """Reconstruct attack timeline from system artifacts and logs."""

    AGENT_NAME    = "forensics"
    SUBAGENT_NAME = "timeline"

    async def run(self, target: str, os_type: str = "linux",
                  attack_start: str = "", **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        if os_type.lower() == "windows":
            await self._timeline_windows(target, attack_start)
        else:
            await self._timeline_linux(target, attack_start)

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ──────────────────────────── Linux ──────────────────────────────────
    async def _timeline_linux(self, target: str, attack_start: str):
        # ── Mactime-style file timeline (last 24h) ─────────────────────
        since_flag = f"-newer /proc/1" if not attack_start else f"-newer /tmp"
        timeline_out = await self.collect_tool("bash", target,
            {"options": f"-c \"find / -xdev {since_flag} -not -path '/proc/*' -not -path '/sys/*' -printf '%TY-%Tm-%Td %TH:%TM  %p\\n' 2>/dev/null | sort | tail -80\""})

        events = timeline_out.strip().splitlines()
        shell_events   = [e for e in events if _SHELL_DROP_RE.search(e)]
        persist_events = [e for e in events if _PERSIST_RE.search(e)]
        exfil_events   = [e for e in events if _EXFIL_RE.search(e)]

        await self.store_finding(Finding(
            title=f"Timeline: {len(events)} FS Events — {len(shell_events)} Shell / {len(persist_events)} Persistence / {len(exfil_events)} Exfil",
            description=(
                f"Filesystem timeline reconstruction:\n"
                f"  Total events: {len(events)}\n"
                f"  Shell drop indicators: {len(shell_events)}\n"
                f"  Persistence modifications: {len(persist_events)}\n"
                f"  Exfiltration indicators: {len(exfil_events)}"
            ),
            severity="HIGH" if (shell_events or persist_events) else "MEDIUM",
            evidence=timeline_out[:1000], tool="bash", host=target,
            mitre_technique="T1070.006",
        ))

        if shell_events:
            await self.store_finding(Finding(
                title=f"Timeline: Shell Deployment Event(s) Detected — {len(shell_events)} File(s)",
                description=f"Files associated with shell deployment:\n" + "\n".join(shell_events[:10]),
                severity="CRITICAL",
                evidence="\n".join(shell_events[:20]), tool="bash", host=target,
                mitre_technique="T1059",
                exploit_suggestion="Capture for evidence: cp <path> /forensics/evidence/; sha256sum <path>",
            ))

        if persist_events:
            await self.store_finding(Finding(
                title=f"Timeline: Persistence Mechanism Installation — {len(persist_events)} Event(s)",
                description=f"Persistence-related file modifications:\n" + "\n".join(persist_events[:10]),
                severity="HIGH",
                evidence="\n".join(persist_events[:20]), tool="bash", host=target,
                mitre_technique="T1053.003",
            ))

        # ── Auth log timeline ──────────────────────────────────────────
        auth_timeline = await self.collect_tool("bash", target,
            {"options": "-c \"grep -iE 'accepted|session opened|sudo|su|root' /var/log/auth.log /var/log/secure 2>/dev/null | tail -80\""})
        privesc_lines = [l for l in auth_timeline.splitlines() if _PRIVESC_RE.search(l)]

        await self.store_finding(Finding(
            title=f"Timeline: Auth Log — {len(privesc_lines)} Privilege Escalation Event(s)",
            description=f"Authentication timeline with privilege escalation moments identified: {len(privesc_lines)} events.",
            severity="CRITICAL" if privesc_lines else "INFO",
            evidence=auth_timeline[:800], tool="bash", host=target,
            mitre_technique="T1078",
            exploit_suggestion=f"First privesc event: {privesc_lines[0][:120]}" if privesc_lines else None,
        ))

        # ── Wtmp / last logins ─────────────────────────────────────────
        wtmp_out = await self.collect_tool("bash", target,
            {"options": "-c \"last -a -F 2>/dev/null | head -40; lastb -a 2>/dev/null | head -20\""})
        await self.store_finding(Finding(
            title="Timeline: Login History (wtmp/btmp)",
            description="Historical login records. Correlate with known attack window to identify initial access.",
            severity="INFO",
            evidence=wtmp_out[:600], tool="bash", host=target,
            mitre_technique="T1078",
        ))

        # ── Syslog attack trace ───────────────────────────────────────
        syslog_out = await self.collect_tool("bash", target,
            {"options": "-c \"grep -iE 'exploit|shellcode|segfault|buffer overflow|heap|stack smash' /var/log/syslog /var/log/messages /var/log/kern.log 2>/dev/null | tail -50\""})
        if syslog_out.strip():
            await self.store_finding(Finding(
                title="Timeline: Kernel/Syslog Exploitation Indicators",
                description="Kernel logs contain exploitation-related keywords. Possible exploit attempt recorded.",
                severity="HIGH",
                evidence=syslog_out[:600], tool="bash", host=target,
                mitre_technique="T1203",
            ))

    # ──────────────────────────── Windows ────────────────────────────────
    async def _timeline_windows(self, target: str, attack_start: str):
        # ── Security event timeline ────────────────────────────────────
        evts_out = await self.collect_tool("powershell", target,
            {"options": (
                "-Command \"Get-WinEvent -FilterHashtable @{LogName='Security';"
                " Id=4624,4625,4648,4672,4688,4720,4732,4776} -MaxEvents 300 -ErrorAction SilentlyContinue"
                " | Sort-Object TimeCreated"
                " | Select-Object TimeCreated,Id,@{N='User';E={$_.Properties[5].Value}},"
                "@{N='Source';E={$_.Properties[18].Value}} | Format-Table -AutoSize\" 2>&1"
            )})
        await self.store_finding(Finding(
            title="Windows Timeline: Security Event Chronology",
            description="Chronological security events covering logon, failed auth, privilege use, process creation, and account changes.",
            severity="HIGH",
            evidence=evts_out[:1000], tool="powershell", host=target,
            mitre_technique="T1078",
        ))

        # ── Process creation timeline (4688) ──────────────────────────
        proc_out = await self.collect_tool("powershell", target,
            {"options": (
                "-Command \"Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688}"
                " -MaxEvents 100 -ErrorAction SilentlyContinue"
                " | Select-Object TimeCreated,"
                "@{N='Process';E={$_.Properties[5].Value}},"
                "@{N='CmdLine';E={$_.Properties[8].Value}}"
                " | Format-Table -AutoSize\" 2>&1"
            )})
        suspicious_procs = [l for l in proc_out.splitlines() if _SHELL_DROP_RE.search(l)]
        await self.store_finding(Finding(
            title=f"Windows Timeline: Process Creation Log — {len(suspicious_procs)} Suspicious",
            description=f"Process creation events (Event ID 4688) with suspicious command lines: {len(suspicious_procs)}.",
            severity="CRITICAL" if suspicious_procs else "INFO",
            evidence=proc_out[:800], tool="powershell", host=target,
            mitre_technique="T1059.001",
            exploit_suggestion=f"Suspicious process: {suspicious_procs[0][:120]}" if suspicious_procs else None,
        ))

        # ── PowerShell scriptblock logging ────────────────────────────
        ps_out = await self.collect_tool("powershell", target,
            {"options": (
                "-Command \"Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';"
                " Id=4104} -MaxEvents 50 -ErrorAction SilentlyContinue"
                " | Select-Object TimeCreated,Message | Format-List\" 2>&1"
            )})
        encoded_cmds = bool(re.search(r'(EncodedCommand|-enc|-e\s+[A-Za-z0-9+/]{40})', ps_out, re.I))
        await self.store_finding(Finding(
            title=f"Windows Timeline: PowerShell Script Block Logs{'  — ENCODED COMMANDS DETECTED' if encoded_cmds else ''}",
            description=f"PowerShell script block logging events. Encoded command usage: {encoded_cmds}.",
            severity="HIGH" if encoded_cmds else "INFO",
            evidence=ps_out[:800], tool="powershell", host=target,
            mitre_technique="T1059.001",
        ))

        # ── File system timeline via MFT timestamps ───────────────────
        mft_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-ChildItem C:\\Users\\,C:\\Windows\\Temp\\,C:\\ProgramData\\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Select-Object FullName,LastWriteTime | Sort-Object LastWriteTime | Select-Object -Last 40 | Format-Table -AutoSize\" 2>&1"})
        await self.store_finding(Finding(
            title="Windows Timeline: Recently Modified Files (Last 24h)",
            description="Files modified in the last 24 hours across user/temp/ProgramData directories.",
            severity="MEDIUM",
            evidence=mft_out[:800], tool="powershell", host=target,
            mitre_technique="T1070.006",
        ))
