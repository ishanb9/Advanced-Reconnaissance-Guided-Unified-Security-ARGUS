"""
artifact_collect_subagent.py — Collect forensic artifacts from a compromised host.

AGENT_NAME  : "forensics"
SUBAGENT_NAME: "artifact_collect"

Methodology:
  Linux:
    /var/log/* (auth, syslog, kern, wtmp, lastlog, btmp, secure, messages)
    /proc/<pid>/exe, /proc/<pid>/maps for suspicious processes
    Crontab entries (system + user), at jobs
    SUID/SGID binaries, world-writable directories, recently modified files
    Bash history, .ssh/ authorized_keys, /etc/passwd / /etc/shadow diff
    Loaded kernel modules, network connections, listening ports
  Windows:
    Event logs (Security 4624/4625/4648/4688/4720, System, Application)
    Scheduled tasks, startup items (Run/RunOnce), services
    Prefetch files, recent docs, MRU keys from registry
    Netstat + ARP table, loaded DLLs in suspicious processes
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_LOG_FAIL_RE   = re.compile(r'(Failed|Failure|Invalid|authentication failure)', re.I)
_SUID_RE       = re.compile(r'(-rwsr|SUID|setuid)', re.I)
_CRON_RE       = re.compile(r'(curl|wget|bash|sh|python|nc|ncat|/tmp|/dev/shm)', re.I)
_SUSPICIOUS_RE = re.compile(r'(/tmp/|/dev/shm/|\.\.\/|base64|eval)', re.I)
_EVT_LOGON_RE  = re.compile(r'(EventID.*4624|EventID.*4648|SpecialLogon)', re.I)
_EVT_FAIL_RE   = re.compile(r'(EventID.*4625|EventID.*4771)', re.I)
_PERSIST_RE    = re.compile(r'(HKLM.*Run|CurrentVersion\\Run|Startup)', re.I)


class ArtifactCollectSubagent(BaseSubagent):
    """Harvest forensic artifacts for post-incident analysis."""

    AGENT_NAME    = "forensics"
    SUBAGENT_NAME = "artifact_collect"

    async def run(self, target: str, os_type: str = "linux", **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        if os_type.lower() == "windows":
            await self._collect_windows(target)
        else:
            await self._collect_linux(target)

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ──────────────────────────── Linux ──────────────────────────────────
    async def _collect_linux(self, target: str):
        # ── Auth log failures ──────────────────────────────────────────
        auth_out = await self.collect_tool("bash", target,
            {"options": "-c \"grep -iE 'failed|invalid|failure' /var/log/auth.log /var/log/secure 2>/dev/null | tail -100\""})
        fail_count = len(_LOG_FAIL_RE.findall(auth_out))
        await self.store_finding(Finding(
            title=f"Linux Forensics: Auth Log — {fail_count} Failure Event(s)",
            description=f"Authentication failures found in system logs: {fail_count} events. May indicate brute-force or lateral movement activity.",
            severity="HIGH" if fail_count > 20 else "MEDIUM" if fail_count > 5 else "INFO",
            evidence=auth_out[:800], tool="bash", host=target,
            mitre_technique="T1110",
        ))

        # ── Recently modified files ────────────────────────────────────
        recent_out = await self.collect_tool("bash", target,
            {"options": "-c \"find / -xdev -newer /tmp -not -path '/proc/*' -not -path '/sys/*' -type f 2>/dev/null | head -50\""})
        suspicious_files = [l for l in recent_out.splitlines() if _SUSPICIOUS_RE.search(l)]
        await self.store_finding(Finding(
            title=f"Linux Forensics: {len(recent_out.splitlines())} Recently Modified Files ({len(suspicious_files)} Suspicious)",
            description=f"Files modified since last boot/tmp creation. Suspicious paths: {suspicious_files[:10]}",
            severity="HIGH" if suspicious_files else "INFO",
            evidence=recent_out[:600], tool="bash", host=target,
            mitre_technique="T1070.006",
            exploit_suggestion="Investigate suspicious files manually: file <path>; strings <path>; sha256sum <path>" if suspicious_files else None,
        ))

        # ── SUID / SGID binaries ───────────────────────────────────────
        suid_out = await self.collect_tool("bash", target,
            {"options": "-c \"find / -xdev -perm /6000 -type f 2>/dev/null | head -40\""})
        suid_list = [l.strip() for l in suid_out.splitlines() if l.strip()]
        known_safe = {'/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/su', '/usr/bin/newgrp',
                      '/usr/bin/gpasswd', '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/pkexec',
                      '/bin/su', '/bin/mount', '/bin/umount', '/bin/ping'}
        unusual_suid = [f for f in suid_list if f not in known_safe]

        if unusual_suid:
            await self.store_finding(Finding(
                title=f"Linux Forensics: {len(unusual_suid)} Unusual SUID Binary(ies) Detected",
                description=f"Non-standard SUID/SGID binaries detected: {unusual_suid[:10]}. May represent persistence or privilege escalation mechanisms.",
                severity="HIGH",
                evidence=suid_out[:600], tool="bash", host=target,
                mitre_technique="T1548.001",
                exploit_suggestion=f"Investigate: ls -la {unusual_suid[0]}; file {unusual_suid[0]}; strings {unusual_suid[0]}",
            ))

        # ── Crontab / scheduled tasks ──────────────────────────────────
        cron_out = await self.collect_tool("bash", target,
            {"options": "-c \"crontab -l 2>/dev/null; cat /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null\""})
        suspicious_cron = [l for l in cron_out.splitlines() if _CRON_RE.search(l) and not l.strip().startswith('#')]
        await self.store_finding(Finding(
            title=f"Linux Forensics: Crontab Entries — {len(suspicious_cron)} Suspicious Line(s)",
            description=f"Scheduled task analysis. Suspicious entries: {suspicious_cron[:5]}",
            severity="HIGH" if suspicious_cron else "INFO",
            evidence=cron_out[:600], tool="bash", host=target,
            mitre_technique="T1053.003",
            exploit_suggestion="Remove malicious cron: crontab -e; rm /etc/cron.d/<malicious>" if suspicious_cron else None,
        ))

        # ── Network connections ────────────────────────────────────────
        net_out = await self.collect_tool("bash", target,
            {"options": "-c \"ss -tulnp 2>/dev/null; netstat -tulnp 2>/dev/null; arp -n 2>/dev/null\""})
        await self.store_finding(Finding(
            title="Linux Forensics: Network Connections Snapshot",
            description="Current active network connections and listening services. Review for unexpected outbound connections.",
            severity="INFO",
            evidence=net_out[:800], tool="bash", host=target,
            mitre_technique="T1049",
        ))

        # ── Loaded kernel modules ──────────────────────────────────────
        kmod_out = await self.collect_tool("bash", target,
            {"options": "-c \"lsmod | sort; dmesg 2>/dev/null | grep -i 'module\\|rootkit\\|hide' | tail -20\""})
        rootkit_hints = bool(re.search(r'(rootkit|hide|unhide|adore|wnps)', kmod_out, re.I))
        await self.store_finding(Finding(
            title=f"Linux Forensics: Kernel Modules{'  — ROOTKIT INDICATOR' if rootkit_hints else ''}",
            description=f"Loaded kernel modules enumerated. Rootkit keywords detected: {rootkit_hints}.",
            severity="CRITICAL" if rootkit_hints else "INFO",
            evidence=kmod_out[:600], tool="bash", host=target,
            mitre_technique="T1014",
            exploit_suggestion="Check with: rkhunter --check; chkrootkit; unhide proc" if rootkit_hints else None,
        ))

        # ── Bash history harvest ───────────────────────────────────────
        hist_out = await self.collect_tool("bash", target,
            {"options": "-c \"cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE 'wget|curl|nc|python|perl|ruby|ssh|sudo|su|passwd|base64|openssl' | tail -60\""})
        if hist_out.strip():
            await self.store_finding(Finding(
                title="Linux Forensics: Bash History — Suspicious Commands Found",
                description="Command history contains potentially malicious commands. Review carefully for attacker TTPs.",
                severity="MEDIUM",
                evidence=hist_out[:800], tool="bash", host=target,
                mitre_technique="T1059.004",
            ))

    # ──────────────────────────── Windows ────────────────────────────────
    async def _collect_windows(self, target: str):
        # ── Security event log — logon events ─────────────────────────
        evt_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4688,4720} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | Format-List\" 2>&1"})

        logon_count = len(_EVT_LOGON_RE.findall(evt_out))
        fail_count  = len(_EVT_FAIL_RE.findall(evt_out))
        await self.store_finding(Finding(
            title=f"Windows Forensics: Event Log — {logon_count} Logons, {fail_count} Failures",
            description=f"Security event log analysis: {logon_count} logon events, {fail_count} failed logons.",
            severity="HIGH" if fail_count > 10 else "MEDIUM",
            evidence=evt_out[:800], tool="powershell", host=target,
            mitre_technique="T1078",
        ))

        # ── Scheduled tasks ────────────────────────────────────────────
        tasks_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName,TaskPath,State | Format-Table -AutoSize\" 2>&1"})
        suspicious_tasks = [l for l in tasks_out.splitlines() if _SUSPICIOUS_RE.search(l)]
        await self.store_finding(Finding(
            title=f"Windows Forensics: Scheduled Tasks — {len(suspicious_tasks)} Suspicious",
            description=f"Scheduled task enumeration. Suspicious entries: {suspicious_tasks[:5]}",
            severity="HIGH" if suspicious_tasks else "INFO",
            evidence=tasks_out[:600], tool="powershell", host=target,
            mitre_technique="T1053.005",
        ))

        # ── Startup / persistence registry keys ───────────────────────
        reg_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue | Format-List *\" 2>&1"})
        persist_entries = _PERSIST_RE.findall(reg_out)
        await self.store_finding(Finding(
            title=f"Windows Forensics: Registry Persistence — {len(persist_entries)} Run Key Entry(ies)",
            description=f"Registry Run key persistence mechanisms found: {len(persist_entries)} entries.",
            severity="HIGH" if persist_entries else "INFO",
            evidence=reg_out[:600], tool="powershell", host=target,
            mitre_technique="T1547.001",
            exploit_suggestion="Remove malicious run key: Remove-ItemProperty -Path 'HKCU:\\...\\Run' -Name '<malicious>'" if persist_entries else None,
        ))

        # ── Network connections ────────────────────────────────────────
        net_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"netstat -ano; arp -a\" 2>&1"})
        await self.store_finding(Finding(
            title="Windows Forensics: Network Connections Snapshot",
            description="Active network connections including PIDs. Investigate unusual outbound connections.",
            severity="INFO",
            evidence=net_out[:800], tool="powershell", host=target,
            mitre_technique="T1049",
        ))

        # ── Prefetch artifacts ────────────────────────────────────────
        pf_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-ChildItem C:\\Windows\\Prefetch\\ -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 30 | Format-Table Name,LastWriteTime\" 2>&1"})
        await self.store_finding(Finding(
            title="Windows Forensics: Prefetch — Recent Program Executions",
            description="Prefetch files indicate recently executed programs. Useful for establishing attacker timeline.",
            severity="INFO",
            evidence=pf_out[:600], tool="powershell", host=target,
            mitre_technique="T1204",
        ))
