"""
ad_enum_subagent.py — Active Directory enumeration via LDAP and RPC.

AGENT_NAME  : "lateral"
SUBAGENT_NAME: "ad_enum"

Methodology:
  1. rpcclient null/authenticated session — domain info, user list, group list
  2. enum4linux-ng -A — full SMB/LDAP enumeration
  3. ldapdomaindump — dump AD objects over LDAP to JSON
  4. net rpc group / net rpc user — additional group/user detail
  5. crackmapexec smb — domain info, password policy, logged-on users
  6. Parse: domain name, DCs, users, groups, GPOs, password policy, kerberoastable accounts
  7. Severity: HIGH for kerberoastable accounts or AS-REP roastable users;
              MEDIUM for enumerated user lists / password policy;
              INFO for general domain info.
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

_DOMAIN_RE = re.compile(r"(Domain Name|Domain:\s*|NetBIOS Domain Name)\s*[:\-=]\s*(\S+)", re.IGNORECASE)
_DC_RE = re.compile(r"(Domain Controller|PDC|Primary DC|DC)\s*[:\-=]\s*(\S+)", re.IGNORECASE)
_USER_RE = re.compile(r"user:\s*(\S+)", re.IGNORECASE)
_KERBEROASTABLE_RE = re.compile(r"(ServicePrincipalName|SPN|kerberoast|msDS-SupportedEncryptionTypes)", re.IGNORECASE)
_ASREP_RE = re.compile(r"(DONT_REQUIRE_PREAUTH|AS.REP|asreproast)", re.IGNORECASE)
_PASSWD_POLICY_RE = re.compile(r"(password.*policy|min.*pass.*len|pass.*hist|lockout.*thresh)", re.IGNORECASE)
_ADMIN_GROUP_RE = re.compile(r"(Domain Admins|Enterprise Admins|Schema Admins|Administrators)", re.IGNORECASE)
_NULL_SESSION_RE = re.compile(r"(null session|anonymous.*login|session.*established|IPC\$.*OK)", re.IGNORECASE)


class AdEnumSubagent(BaseSubagent):
    """Enumerate Active Directory objects via LDAP, RPC, and SMB."""

    AGENT_NAME: str = "lateral"
    SUBAGENT_NAME: str = "ad_enum"

    async def run(self, target: str, domain: str = "", username: str = "",
                  password: str = "", **kwargs: Any) -> SubagentResult:
        """
        Enumerate AD domain objects.

        Parameters
        ----------
        target:
            Domain controller IP or hostname.
        domain:
            Domain name (optional; discovered automatically if empty).
        username:
            AD account for authenticated enumeration (empty = null session).
        password:
            Account password (empty = null session).

        Returns
        -------
        SubagentResult
            All findings and tool outputs from AD enumeration.
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        auth_flag = ""
        if username and password:
            auth_flag = f"-U '{domain}\\{username}%{password}'" if domain else f"-U '{username}%{password}'"

        # ── 1. enum4linux-ng — comprehensive SMB/LDAP enumeration ────────
        enum4_output = await self.collect_tool(
            "enum4linux-ng",
            target,
            {"options": f"-A {auth_flag} -oJ /tmp/enum4linux_{target.replace('.', '_')}"},
        )

        discovered_domain = ""
        m = _DOMAIN_RE.search(enum4_output)
        if m:
            discovered_domain = m.group(2).strip()

        null_session = bool(_NULL_SESSION_RE.search(enum4_output))
        user_lines = [l for l in enum4_output.splitlines() if _USER_RE.search(l)]

        await self.store_finding(Finding(
            title=f"AD Enumeration: Domain '{discovered_domain or domain or target}' via enum4linux-ng",
            description=(
                f"enum4linux-ng successfully enumerated the domain. "
                f"Null/anonymous session allowed: {null_session}. "
                f"Found {len(user_lines)} user account references. "
                f"Domain identified: {discovered_domain or domain or 'unknown'}."
            ),
            severity="MEDIUM" if null_session else "INFO",
            evidence=enum4_output[:2000],
            tool="enum4linux-ng",
            host=target,
            mitre_technique="T1087.002",
            exploit_suggestion=(
                "Use discovered users for password spraying or Kerberoasting. "
                "Run kerberos_subagent if SPNs are found."
            ),
        ))

        # ── 2. rpcclient — domain info and user enumeration ──────────────
        rpc_creds = f"-U '{username}%{password}'" if username else "-U '' -N"
        rpc_cmds = "enumdomusers;enumdomgroups;querydominfo;getdompwinfo"
        rpc_output = await self.collect_tool(
            "rpcclient",
            target,
            {"options": f"{rpc_creds} -c \"{rpc_cmds}\" 2>&1"},
        )

        admin_groups_found = bool(_ADMIN_GROUP_RE.search(rpc_output))
        if admin_groups_found:
            await self.store_finding(Finding(
                title="AD: Privileged Groups Enumerated via RPC",
                description=(
                    "Privileged Active Directory groups (Domain Admins, Enterprise Admins, etc.) "
                    "were successfully enumerated via rpcclient. Members of these groups are "
                    "high-value targets for credential attacks and lateral movement."
                ),
                severity="HIGH",
                evidence="\n".join([l for l in rpc_output.splitlines() if _ADMIN_GROUP_RE.search(l)])[:1000],
                tool="rpcclient",
                host=target,
                mitre_technique="T1069.002",
                exploit_suggestion=(
                    "Attempt targeted credential attacks against identified admin accounts. "
                    "Check for password reuse across identified admin usernames."
                ),
            ))

        # ── 3. crackmapexec — domain info, SMB signing, password policy ──
        cme_creds = f"-u '{username}' -p '{password}'" if username else "-u '' -p ''"
        cme_output = await self.collect_tool(
            "crackmapexec",
            target,
            {"options": f"smb {target} {cme_creds} --pass-pol --users --groups 2>&1"},
        )

        # Check SMB signing
        signing_disabled = bool(re.search(r"signing:\s*False", cme_output, re.IGNORECASE))
        if signing_disabled:
            await self.store_finding(Finding(
                title="AD: SMB Signing Disabled — NTLM Relay Possible",
                description=(
                    "SMB signing is disabled on the target domain controller. "
                    "This allows NTLM relay attacks where captured authentication "
                    "challenges can be relayed to gain unauthorised access."
                ),
                severity="HIGH",
                evidence=cme_output[:500],
                tool="crackmapexec",
                host=target,
                mitre_technique="T1557.001",
                exploit_suggestion=(
                    "Run ntlm_capture_subagent (Responder + ntlmrelayx) to capture "
                    "and relay NTLM hashes. Target: SMB shares, LDAP, MSSQL."
                ),
            ))

        passwd_policy = bool(_PASSWD_POLICY_RE.search(cme_output))
        if passwd_policy:
            await self.store_finding(Finding(
                title="AD: Password Policy Extracted",
                description=(
                    "Domain password policy successfully extracted. "
                    "Review minimum password length and lockout thresholds "
                    "before conducting password spray attacks to avoid account lockout."
                ),
                severity="INFO",
                evidence="\n".join([l for l in cme_output.splitlines() if _PASSWD_POLICY_RE.search(l)])[:500],
                tool="crackmapexec",
                host=target,
                mitre_technique="T1201",
                exploit_suggestion=(
                    "Use lockout threshold to calibrate password spray rate. "
                    "Common safe threshold: 1 attempt per 30 minutes."
                ),
            ))

        # ── 4. ldapdomaindump — full LDAP object dump ────────────────────
        ldap_creds = f"-u '{domain}\\{username}' -p '{password}'" if username else "--no-pass"
        ldap_output = await self.collect_tool(
            "ldapdomaindump",
            target,
            {"options": f"{ldap_creds} -o /tmp/ldd_{target.replace('.', '_')} {target} 2>&1"},
        )

        kerberoastable = bool(_KERBEROASTABLE_RE.search(enum4_output + rpc_output + ldap_output))
        asrep_roastable = bool(_ASREP_RE.search(enum4_output + rpc_output + ldap_output))

        if kerberoastable:
            await self.store_finding(Finding(
                title="AD: Kerberoastable Accounts Detected (SPNs Found)",
                description=(
                    "Service Principal Names (SPNs) were identified in the domain. "
                    "Accounts with SPNs can be targeted with Kerberoasting — requesting "
                    "service tickets and cracking them offline to recover plaintext passwords."
                ),
                severity="HIGH",
                evidence="\n".join([l for l in (enum4_output + rpc_output).splitlines()
                                    if _KERBEROASTABLE_RE.search(l)])[:1000],
                tool="ldapdomaindump",
                host=target,
                mitre_technique="T1558.003",
                exploit_suggestion=(
                    "Run: impacket-GetUserSPNs -request -dc-ip {target} {domain}/{username}:{password} "
                    "Then crack with hashcat -m 13100 hashes.txt wordlist.txt"
                ),
            ))

        if asrep_roastable:
            await self.store_finding(Finding(
                title="AD: AS-REP Roastable Accounts Detected",
                description=(
                    "Accounts with 'Do not require Kerberos preauthentication' set were found. "
                    "These accounts allow AS-REP roasting — requesting authentication data "
                    "without valid credentials and cracking offline."
                ),
                severity="HIGH",
                evidence="\n".join([l for l in (enum4_output + rpc_output + ldap_output).splitlines()
                                    if _ASREP_RE.search(l)])[:500],
                tool="ldapdomaindump",
                host=target,
                mitre_technique="T1558.004",
                exploit_suggestion=(
                    "Run: impacket-GetNPUsers -dc-ip {target} -no-pass {domain}/ "
                    "Then crack with hashcat -m 18200 asrep_hashes.txt wordlist.txt"
                ),
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
