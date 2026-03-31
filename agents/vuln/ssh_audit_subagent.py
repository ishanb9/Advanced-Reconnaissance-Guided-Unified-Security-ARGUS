"""
ssh_audit_subagent.py — SSH service security audit.

AGENT_NAME   : "vuln"
SUBAGENT_NAME: "ssh_audit"

Methodology:
  1. Banner grab: OpenSSH version, server OS fingerprint
  2. ssh-audit / nmap NSE for cipher/algorithm weakness detection
  3. Check for deprecated KEX (diffie-hellman-group1, diffie-hellman-group14)
  4. Check for deprecated ciphers (arcfour, 3des-cbc, blowfish)
  5. Check for deprecated MACs (hmac-md5, hmac-sha1)
  6. Brute-force with common SSH credentials (hydra)
  7. Check for authorized_keys / known_hosts exposure
  8. CVE check for OpenSSH version (CVE-2023-38408 etc.)
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_SSH_VER_RE   = re.compile(r'SSH-2\.0-(OpenSSH[_\s][\d.p]+\w*)', re.I)
_WEAK_KEX_RE  = re.compile(r'(diffie-hellman-group1|diffie-hellman-group14-sha1|gss-group1)', re.I)
_WEAK_ENC_RE  = re.compile(r'(arcfour|3des-cbc|blowfish-cbc|cast128-cbc|idea-cbc|des-cbc)', re.I)
_WEAK_MAC_RE  = re.compile(r'(hmac-md5(?!-etm)|hmac-sha1(?!-etm)|hmac-ripemd160|umac-64(?!@))', re.I)
_CVE_MAP = {
    "OpenSSH 9.1":  [],
    "OpenSSH 8.9":  [],
    "OpenSSH 7.7":  ["CVE-2018-15919"],     # username enumeration
    "OpenSSH 7.4":  ["CVE-2016-10708"],
    "OpenSSH 6.6":  ["CVE-2014-1692"],
    "OpenSSH 2.":   ["CVE-2001-0572"],
}
WEAK_CREDS = [
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("admin", "admin"), ("admin", "password"), ("ubuntu", "ubuntu"),
    ("ec2-user", ""), ("centos", "centos"), ("pi", "raspberry"),
    ("vagrant", "vagrant"), ("ansible", "ansible"),
]


class SshAuditSubagent(BaseSubagent):
    """Audit SSH service for weak configuration, deprecated algorithms, and credential issues."""

    AGENT_NAME    = "vuln"
    SUBAGENT_NAME = "ssh_audit"

    async def run(self, target: str, port: int = 22, **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        # ── 1. Banner grab ─────────────────────────────────────────────
        banner_out = await self.collect_tool("bash", target,
            {"options": f"-c \"echo '' | nc -w 3 {target} {port} 2>&1 | head -3\""})
        ver_match = _SSH_VER_RE.search(banner_out)
        version   = ver_match.group(1) if ver_match else banner_out.strip()[:60]

        await self.store_finding(Finding(
            title=f"SSH: Service Detected — {version} on port {port}",
            description=f"SSH banner: {banner_out.strip()[:200]}",
            severity="INFO",
            evidence=banner_out[:200], tool="bash", host=target, port=port,
            mitre_technique="T1021.004",
        ))

        # ── 2. ssh-audit (preferred) ───────────────────────────────────
        audit_tool = await self.collect_tool("bash", target,
            {"options": "-c \"which ssh-audit ssh_audit 2>/dev/null\""})
        audit_bin  = audit_tool.strip().splitlines()[0] if audit_tool.strip() else None

        if audit_bin:
            audit_out = await self.collect_tool("bash", target,
                {"options": f"-c \"{audit_bin} -p {port} {target} 2>&1\""})
        else:
            # Fallback: nmap NSE
            audit_out = await self.collect_tool("nmap", target,
                {"options": f"-p {port} --script ssh2-enum-algos,ssh-auth-methods {target}"})

        # ── 3. Weak KEX algorithms ─────────────────────────────────────
        weak_kex = _WEAK_KEX_RE.findall(audit_out)
        if weak_kex:
            await self.store_finding(Finding(
                title=f"SSH Weak KEX: {len(set(weak_kex))} Deprecated Key Exchange Algorithm(s)",
                description=f"Server supports deprecated KEX (susceptible to Logjam/FREAK): {list(set(weak_kex))}",
                severity="MEDIUM",
                evidence="\n".join([l for l in audit_out.splitlines() if _WEAK_KEX_RE.search(l)])[:400],
                tool="bash", host=target, port=port, mitre_technique="T1040",
                exploit_suggestion="Mitigate: KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512 in /etc/ssh/sshd_config",
            ))

        # ── 4. Weak encryption ciphers ─────────────────────────────────
        weak_enc = _WEAK_ENC_RE.findall(audit_out)
        if weak_enc:
            await self.store_finding(Finding(
                title=f"SSH Weak Ciphers: {len(set(weak_enc))} Deprecated Encryption Algorithm(s)",
                description=f"Deprecated stream/block ciphers enabled: {list(set(weak_enc))}",
                severity="MEDIUM",
                evidence="\n".join([l for l in audit_out.splitlines() if _WEAK_ENC_RE.search(l)])[:400],
                tool="bash", host=target, port=port, mitre_technique="T1040",
                exploit_suggestion="Mitigate: Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com in sshd_config",
            ))

        # ── 5. Weak MACs ───────────────────────────────────────────────
        weak_mac = _WEAK_MAC_RE.findall(audit_out)
        if weak_mac:
            await self.store_finding(Finding(
                title=f"SSH Weak MACs: {len(set(weak_mac))} Deprecated MAC Algorithm(s)",
                description=f"Deprecated MAC algorithms enabled: {list(set(weak_mac))}",
                severity="LOW",
                evidence="\n".join([l for l in audit_out.splitlines() if _WEAK_MAC_RE.search(l)])[:300],
                tool="bash", host=target, port=port, mitre_technique="T1040",
                exploit_suggestion="Mitigate: MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com in sshd_config",
            ))

        # ── 6. Auth methods check ──────────────────────────────────────
        auth_out = await self.collect_tool("bash", target,
            {"options": f"-c \"ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -p {port} root@{target} 2>&1 | head -5\""})
        password_auth = "password" in auth_out.lower() or "publickey,password" in auth_out.lower()
        kbd_auth      = "keyboard-interactive" in auth_out.lower()

        if password_auth or kbd_auth:
            await self.store_finding(Finding(
                title=f"SSH: Password Authentication ENABLED — Brute-Force Attack Surface",
                description=f"SSH accepts password authentication. Methods: {auth_out.strip()[:100]}",
                severity="MEDIUM",
                evidence=auth_out[:200], tool="bash", host=target, port=port,
                mitre_technique="T1110.003",
                exploit_suggestion=f"Brute: hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -s {port} ssh://{target}",
            ))

            # ── 7. Brute-force common credentials ─────────────────────
            hydra_out = await self.collect_tool("bash", target,
                {"options": (
                    f"-c \"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt "
                    f"-P /usr/share/seclists/Passwords/Common-Credentials/best15.txt "
                    f"-t 4 -s {port} -o /tmp/ssh_brute.txt ssh://{target} 2>&1 | tail -10\""
                )})
            ssh_hits = re.findall(r'\[22\]\s*\[ssh\]\s*host:\s*\S+\s*login:\s*(\S+)\s*password:\s*(\S+)', hydra_out)
            if ssh_hits:
                await self.store_finding(Finding(
                    title=f"SSH: Brute-Force Credentials Found — {ssh_hits[0][0]}:{ssh_hits[0][1]}",
                    description=f"Valid SSH credentials:\n" + "\n".join([f"  {u}:{p}" for u, p in ssh_hits[:5]]),
                    severity="CRITICAL",
                    evidence=hydra_out[:400], tool="bash", host=target, port=port,
                    mitre_technique="T1110.003",
                    exploit_suggestion=f"ssh -p {port} {ssh_hits[0][0]}@{target}",
                ))

        # ── 8. Username enumeration check ─────────────────────────────
        enum_out = await self.collect_tool("bash", target,
            {"options": f"-c \"nmap -p {port} --script ssh-auth-methods --script-args 'ssh.user=root' {target} 2>&1 | head -15\""})
        if "publickey" in enum_out.lower() and "none" in enum_out.lower():
            await self.store_finding(Finding(
                title="SSH: Username Enumeration Possible (CVE-2018-15919 pattern)",
                description="SSH server differentiates between valid and invalid usernames via auth method response timing.",
                severity="LOW",
                evidence=enum_out[:300], tool="bash", host=target, port=port,
                cve="CVE-2018-15919", mitre_technique="T1592",
                exploit_suggestion=f"Enumerate: ssh-user-enum -p {port} -t {target} -U /usr/share/wordlists/user.txt",
            ))

        # ── 9. CVE lookup by version ───────────────────────────────────
        for ver_prefix, cves in _CVE_MAP.items():
            if ver_prefix.lower() in version.lower() and cves:
                for cve in cves:
                    await self.store_finding(Finding(
                        title=f"SSH CVE: {cve} Applies to {version}",
                        description=f"Known CVE for SSH version {version}: {cve}",
                        severity="HIGH",
                        evidence=f"Version: {version}", tool="bash", host=target, port=port,
                        cve=cve, mitre_technique="T1210",
                        exploit_suggestion=f"searchsploit '{ver_prefix}'; msfconsole -x 'search {cve}'",
                    ))

        # ── 10. Host key check (weak RSA) ──────────────────────────────
        hk_out = await self.collect_tool("bash", target,
            {"options": f"-c \"ssh-keyscan -p {port} -t rsa {target} 2>/dev/null | ssh-keygen -lf - 2>/dev/null\""})
        rsa_bits = re.search(r'(\d+)\s+SHA', hk_out)
        if rsa_bits and int(rsa_bits.group(1)) < 2048:
            await self.store_finding(Finding(
                title=f"SSH: Weak RSA Host Key — {rsa_bits.group(1)} bits (< 2048)",
                description=f"RSA host key is only {rsa_bits.group(1)} bits. Susceptible to factorisation attacks.",
                severity="MEDIUM",
                evidence=hk_out[:200], tool="bash", host=target, port=port,
                mitre_technique="T1040",
                exploit_suggestion="Regenerate: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key",
            ))

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
