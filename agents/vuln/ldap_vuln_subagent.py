"""
ldap_vuln_subagent.py — LDAP / Active Directory vulnerability checks.

Methodology:
  1. Try anonymous LDAP bind: ldapsearch -x -H ldap://target -b "" -s base
  2. Run nmap --script=ldap-rootdse,ldap-brute,ldap-search
  3. Enumerate domain: ldapsearch with discovered naming context
  4. Look for: domain name, naming context, LDAP signing enforcement
  5. Findings: CRITICAL for anonymous read of accounts; HIGH for no LDAP signing;
               MEDIUM for LDAP info disclosure
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_NAMING_CTX_RE = re.compile(
    r"namingContexts:\s*(.+)", re.IGNORECASE
)
_DEFAULT_NC_RE = re.compile(
    r"defaultNamingContext:\s*(.+)", re.IGNORECASE
)
_DOMAIN_RE = re.compile(
    r"DC=([^,\s]+)", re.IGNORECASE
)
_USER_ACCOUNT_RE = re.compile(
    r"sAMAccountName:\s*(\S+)", re.IGNORECASE
)
_ANON_SUCCESS_RE = re.compile(
    r"(result: 0 Success|numEntries: \d+|dn:\s+\w)", re.IGNORECASE
)
_LDAP_SIGNING_RE = re.compile(
    r"(supportedCapabilities|LDAPServiceName|LDAP server.*signing|ldapServiceName)",
    re.IGNORECASE,
)
_SIGNING_REQUIRED_RE = re.compile(
    r"(signing required|ldapEnforceChannelBinding|IntegritySigning)", re.IGNORECASE
)
_PASSWORD_IN_ATTR_RE = re.compile(
    r"(userPassword|unicodePwd|description.*pass|comment.*pass):\s*(\S+)",
    re.IGNORECASE,
)
_KERBEROASTABLE_RE = re.compile(
    r"servicePrincipalName:\s*(.+)", re.IGNORECASE
)


def _extract_naming_context(output: str) -> str:
    """Extract the default naming context (base DN) from ldapsearch rootdse."""
    m = _DEFAULT_NC_RE.search(output)
    if m:
        return m.group(1).strip()
    m = _NAMING_CTX_RE.search(output)
    if m:
        return m.group(1).strip()
    return ""


def _build_domain_name(nc: str) -> str:
    """Convert DC=example,DC=com → example.com"""
    parts = [m.group(1) for m in _DOMAIN_RE.finditer(nc)]
    return ".".join(parts) if parts else ""


class LdapVulnSubagent(BaseSubagent):
    """
    LDAP / Active Directory vulnerability assessment.

    Tests for anonymous bind, enumerates naming contexts, discovers
    domain users via anonymous LDAP reads, and checks LDAP signing config.
    """

    AGENT_NAME    = "vuln"
    SUBAGENT_NAME = "ldap_vuln"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:  # noqa: C901
        """
        Perform LDAP vulnerability assessment against target.

        Parameters
        ----------
        target:
            IP or hostname.
        services_list:
            Optional list of service dicts. LDAP checks run regardless.
        ldap_port:
            Override LDAP port (default 389). Pass 636 for LDAPS.

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        wall_start = time.monotonic()

        ldap_port: int = int(kwargs.get("ldap_port", 389))
        ldap_url  = f"ldap://{target}:{ldap_port}"
        all_output: list[str] = []

        # ── Step 1: Anonymous rootdse probe ──────────────────────────────
        logger.info("[ldap_vuln] anonymous rootdse probe on %s", ldap_url)
        rootdse_out = ""
        try:
            rootdse_out = await self.collect_tool(
                "ldapsearch",
                target,
                {
                    "options": (
                        f'-x -H {ldap_url} -b "" -s base "(objectClass=*)"'
                    )
                },
            )
            all_output.append(rootdse_out)
        except Exception as exc:
            logger.warning("[ldap_vuln] rootdse probe error: %s", exc)

        # ── Step 2: nmap ldap scripts ─────────────────────────────────────
        logger.info("[ldap_vuln] nmap ldap scripts on %s:%s", target, ldap_port)
        nmap_ldap_out = ""
        try:
            nmap_ldap_out = await self.collect_tool(
                "nmap",
                target,
                {
                    "options": (
                        f"--script=ldap-rootdse,ldap-search "
                        f"-p {ldap_port} {target}"
                    )
                },
            )
            all_output.append(nmap_ldap_out)
        except Exception as exc:
            logger.warning("[ldap_vuln] nmap ldap error: %s", exc)

        combined_early = "\n".join(all_output)
        nc = _extract_naming_context(combined_early)
        domain = _build_domain_name(nc)

        # ── Step 3: Anonymous domain enumeration ─────────────────────────
        anon_enum_out = ""
        if nc:
            logger.info("[ldap_vuln] anonymous enum on base dn: %s", nc)
            try:
                anon_enum_out = await self.collect_tool(
                    "ldapsearch",
                    target,
                    {
                        "options": (
                            f'-x -H {ldap_url} -b "{nc}" "(objectClass=*)" '
                            f'sAMAccountName userPrincipalName memberOf '
                            f'servicePrincipalName description comment'
                        )
                    },
                )
                all_output.append(anon_enum_out)
            except Exception as exc:
                logger.warning("[ldap_vuln] anon enum error: %s", exc)

        # Emit emit collected domain info
        if nc or domain:
            await self._emit(
                "ldap_domain_discovered",
                {"target": target, "naming_context": nc, "domain": domain},
            )

        combined = "\n".join(all_output)

        # ── Step 4: Light ldap brute ──────────────────────────────────────
        logger.info("[ldap_vuln] nmap ldap-brute on %s:%s", target, ldap_port)
        ldap_brute_out = ""
        try:
            ldap_brute_out = await self.collect_tool(
                "nmap",
                target,
                {
                    "options": (
                        f"--script=ldap-brute "
                        f"--script-args ldap.base='{nc}' "
                        f"-p {ldap_port} {target}"
                    )
                },
            )
            all_output.append(ldap_brute_out)
            combined = "\n".join(all_output)
        except Exception as exc:
            logger.info("[ldap_vuln] ldap-brute not available or error: %s", exc)

        # ── Parse findings ────────────────────────────────────────────────

        # Anonymous bind succeeds
        if _ANON_SUCCESS_RE.search(rootdse_out):
            # Check if we enumerated real user accounts
            users = _USER_ACCOUNT_RE.findall(anon_enum_out)
            unique_users = [u for u in set(users) if "$" not in u]  # exclude computers

            if unique_users:
                await self.store_finding(Finding(
                    title=f"Anonymous LDAP Read Exposes {len(unique_users)} User Accounts on {target}",
                    description=(
                        f"Anonymous LDAP bind on {target}:{ldap_port} succeeded and "
                        f"returned {len(unique_users)} user accounts. "
                        f"Domain: {domain}. "
                        f"Sample users: {', '.join(unique_users[:10])}."
                    ),
                    severity="CRITICAL",
                    evidence=anon_enum_out[:3000],
                    tool="ldapsearch",
                    host=target,
                    port=ldap_port,
                    mitre_technique="T1087.002",
                    exploit_suggestion=(
                        f"ldapsearch -x -H ldap://{target} -b '{nc}' "
                        f"'(objectClass=user)' sAMAccountName"
                    ),
                ))
            else:
                await self.store_finding(Finding(
                    title=f"Anonymous LDAP Bind Allowed on {target}:{ldap_port}",
                    description=(
                        f"Anonymous LDAP bind succeeded on {target}:{ldap_port}. "
                        f"Base DN: {nc or 'N/A'}. Domain: {domain or 'N/A'}. "
                        f"Directory information is readable without authentication."
                    ),
                    severity="HIGH",
                    evidence=rootdse_out[:2000],
                    tool="ldapsearch",
                    host=target,
                    port=ldap_port,
                    mitre_technique="T1087.002",
                    exploit_suggestion=(
                        f"ldapsearch -x -H ldap://{target} -b '{nc}' '(objectClass=*)'"
                    ),
                ))

        # [55] "LDAP Signing Not Required" was fired HIGH whenever the rootDSE was merely
        # READABLE — _LDAP_SIGNING_RE matches supportedCapabilities/ldapServiceName (present
        # in EVERY AD rootDSE) and _SIGNING_REQUIRED_RE looks for a "signing required" keyword
        # that ldapsearch/nmap ldap-rootdse NEVER emit — so it fabricated a HIGH on essentially
        # every reachable DC with no test of signing at all.  Only flag it on a REAL positive
        # signal: an unauthenticated/anonymous bind that actually SUCCEEDED over CLEARTEXT ldap
        # (389), which demonstrates the server accepts unsigned binds (the NTLM-relay
        # precondition).  LDAPS/636 is signed by the transport, so it never qualifies.
        _unsigned_bind_proven = (str(ldap_port) == "389"
                                 and bool(_ANON_SUCCESS_RE.search(combined)))
        if _unsigned_bind_proven:
            await self.store_finding(Finding(
                title=f"LDAP Signing Not Enforced on {target}:{ldap_port}",
                description=(
                    f"An unauthenticated LDAP bind on cleartext {target}:{ldap_port} "
                    f"returned directory data, so the server accepts unsigned binds. An "
                    f"attacker performing an NTLM relay can authenticate to it without "
                    f"valid credentials."
                ),
                severity="MEDIUM",
                evidence=combined[:2000],
                tool="nmap_ldap",
                host=target,
                port=ldap_port,
                mitre_technique="T1557.001",
                exploit_suggestion=(
                    "Enforce LDAP signing via GPO: "
                    "'Domain controller: LDAP server signing requirements = Require signing'"
                ),
            ))

        # Passwords in LDAP attributes (description / comment)
        pw_matches = _PASSWORD_IN_ATTR_RE.findall(anon_enum_out)
        if pw_matches:
            pw_evidence = "; ".join(
                f"{attr}={val}" for attr, val in pw_matches[:5]
            )
            await self.store_finding(Finding(
                title=f"Credentials in LDAP Attributes on {target}",
                description=(
                    f"LDAP attributes on {target} contain potential credentials or "
                    f"password hints: {pw_evidence}."
                ),
                severity="CRITICAL",
                evidence=anon_enum_out[:2000],
                tool="ldapsearch",
                host=target,
                port=ldap_port,
                mitre_technique="T1552.001",
                exploit_suggestion="Extract and test credentials across all discovered services.",
            ))

        # Kerberoastable SPNs discovered
        spn_matches = _KERBEROASTABLE_RE.findall(anon_enum_out)
        if spn_matches:
            await self.store_finding(Finding(
                title=f"Kerberoastable Service Accounts Found on {target}: {len(spn_matches)} SPNs",
                description=(
                    f"Anonymous LDAP enumeration found {len(spn_matches)} service "
                    f"principal names (SPNs): {', '.join(spn_matches[:5])}. "
                    f"These accounts are susceptible to Kerberoasting."
                ),
                severity="HIGH",
                evidence=anon_enum_out[:2000],
                tool="ldapsearch",
                host=target,
                port=ldap_port,
                mitre_technique="T1558.003",
                exploit_suggestion=(
                    "impacket-GetUserSPNs -dc-ip target domain/user  "
                    "or crackmapexec ldap target --kerberoasting"
                ),
            ))

        # Generic info disclosure if rootdse responded
        if rootdse_out and not _ANON_SUCCESS_RE.search(rootdse_out) and nc:
            await self.store_finding(Finding(
                title=f"LDAP RootDSE Information Disclosure on {target}:{ldap_port}",
                description=(
                    f"The LDAP server on {target}:{ldap_port} exposed its rootDSE "
                    f"(naming context: {nc}, domain: {domain}). "
                    f"This assists attackers in crafting targeted queries."
                ),
                severity="MEDIUM",
                evidence=rootdse_out[:1000],
                tool="ldapsearch",
                host=target,
                port=ldap_port,
                mitre_technique="T1087.002",
                exploit_suggestion=f"Enumerate further: ldapsearch -x -H ldap://{target} -b '{nc}'",
            ))

        # ── Finalise ───────────────────────────────────────────────────────
        result.findings         = self._findings
        result.tool_outputs     = self._tool_outputs
        result.duration_seconds = time.monotonic() - wall_start

        await self._emit(
            "ldap_vuln_complete",
            {
                "target": target,
                "domain": domain,
                "naming_context": nc,
                "findings": len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )
        logger.info(
            "[ldap_vuln] complete — domain=%s, %d findings, %.1fs",
            domain, len(self._findings), result.duration_seconds,
        )
        return result
