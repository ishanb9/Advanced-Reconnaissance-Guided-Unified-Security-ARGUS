"""
smb_vuln_subagent.py — SMB vulnerability assessment.

Methodology:
  1. Run nmap --script=smb-vuln-* on port 445
  2. Run enum4linux-ng -A target for full SMB enumeration
  3. Run crackmapexec smb target --shares to list shares
  4. Try anonymous/null session: smbclient -L //target -N
  5. Check for MS17-010 (EternalBlue), MS08-067, MS10-054, PrintNightmare
  6. Findings: CRITICAL for MS17-010/MS08-067/anonymous write; HIGH for null session/C$;
               MEDIUM for SMBv1 enabled
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_MS17010_RE = re.compile(
    r"(ms17.010|EternalBlue|VULNERABLE.*445|smb-vuln-ms17-010.*VULNERABLE)",
    re.IGNORECASE,
)
_MS08067_RE = re.compile(
    r"(ms08.067|smb-vuln-ms08-067.*VULNERABLE|CVE-2008-4250)",
    re.IGNORECASE,
)
_MS10054_RE = re.compile(
    r"(ms10.054|smb-vuln-ms10-054.*VULNERABLE|CVE-2010-2550)",
    re.IGNORECASE,
)
_PRINTNIGHTMARE_RE = re.compile(
    r"(PrintNightmare|CVE-2021-1675|CVE-2021-34527|print.*spooler.*VULNERABLE)",
    re.IGNORECASE,
)
_NULL_SESSION_RE = re.compile(
    r"(null session|anonymous.*session|IPC\$.*OK|\$.*Disk|session.*established)",
    re.IGNORECASE,
)
_SMBV1_RE = re.compile(r"(SMBv1|SMB1|dialect.*NT LM 0\.12)", re.IGNORECASE)
_SHARE_RE = re.compile(
    r"(Disk|IPC)\s+([A-Za-z0-9_$\-]+)\s*(READ|WRITE)?", re.IGNORECASE
)
_ADMIN_SHARE_RE = re.compile(r"\b(C\$|ADMIN\$|IPC\$)\b")
_WRITE_ACCESS_RE = re.compile(r"WRITE|writable", re.IGNORECASE)
_CRACKMAPEXEC_SHARE_RE = re.compile(
    r"(\S+)\s+(READ|WRITE|READ,WRITE)", re.IGNORECASE
)


def _parse_shares(output: str) -> list[dict]:
    """Parse smbclient / crackmapexec share listing into structured dicts."""
    shares: list[dict] = []
    for m in re.finditer(
        r"(?:Sharename|SHARE)\s*[:\-]?\s*([A-Za-z0-9_$]+).*?(READ|WRITE|NO ACCESS)?",
        output, re.IGNORECASE
    ):
        shares.append({"name": m.group(1), "access": m.group(2) or "unknown"})

    # Fallback: parse crackmapexec style
    if not shares:
        for m in _CRACKMAPEXEC_SHARE_RE.finditer(output):
            shares.append({"name": m.group(1), "access": m.group(2)})
    return shares


class SmbVulnSubagent(BaseSubagent):
    """
    SMB vulnerability assessment.

    Combines nmap smb-vuln scripts, enum4linux-ng, crackmapexec, and
    smbclient to identify critical SMB flaws including EternalBlue,
    null sessions, and anonymous share access.
    """

    AGENT_NAME    = "vuln"
    SUBAGENT_NAME = "smb_vuln"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:  # noqa: C901
        """
        Perform SMB vulnerability assessment against target.

        Parameters
        ----------
        target:
            IP or hostname.
        services_list:
            Optional list of service dicts. SMB is checked regardless.

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

        # Determine SMB port (usually 445, legacy 139)
        services_list: list[dict] = kwargs.get("services_list", [])
        smb_port = 445
        for svc in services_list:
            if str(svc.get("service", "")).lower() in ("microsoft-ds", "smb", "netbios-ssn"):
                smb_port = int(svc.get("port", 445))
                break

        all_output: list[str] = []

        # ── Step 1: nmap smb-vuln-* ────────────────────────────────────────
        logger.info("[smb_vuln] nmap smb-vuln scripts on %s:%s", target, smb_port)
        nmap_vuln_out = ""
        try:
            nmap_vuln_out = await self.collect_tool(
                "nmap",
                target,
                {
                    "options": (
                        f"--script=smb-vuln-ms17-010,smb-vuln-ms08-067,"
                        f"smb-vuln-ms10-054,smb-vuln-ms10-061,smb-security-mode,"
                        f"smb2-security-mode,smb-protocols "
                        f"-p {smb_port},139 {target}"
                    )
                },
            )
            all_output.append(nmap_vuln_out)
        except Exception as exc:
            logger.warning("[smb_vuln] nmap smb-vuln error: %s", exc)

        # ── Step 2: enum4linux-ng ─────────────────────────────────────────
        logger.info("[smb_vuln] enum4linux-ng -A %s", target)
        enum4linux_out = ""
        try:
            enum4linux_out = await self.collect_tool(
                "enum4linux-ng",
                target,
                {"options": f"-A {target}"},
            )
            all_output.append(enum4linux_out)
        except Exception as exc:
            logger.warning("[smb_vuln] enum4linux-ng error: %s", exc)

        # ── Step 3: crackmapexec smb --shares ────────────────────────────
        logger.info("[smb_vuln] crackmapexec smb --shares on %s", target)
        cme_out = ""
        try:
            cme_out = await self.collect_tool(
                "crackmapexec",
                target,
                {"options": f"smb {target} --shares"},
            )
            all_output.append(cme_out)
        except Exception as exc:
            logger.warning("[smb_vuln] crackmapexec error: %s", exc)

        # ── Step 4: smbclient null session ───────────────────────────────
        logger.info("[smb_vuln] smbclient null session on %s", target)
        smbclient_out = ""
        try:
            smbclient_out = await self.collect_tool(
                "smbclient",
                target,
                {"options": f"-L //{target} -N -p {smb_port}"},
            )
            all_output.append(smbclient_out)
        except Exception as exc:
            logger.warning("[smb_vuln] smbclient error: %s", exc)

        combined = "\n".join(all_output)

        # ── Parse findings ────────────────────────────────────────────────

        # MS17-010 / EternalBlue
        if _MS17010_RE.search(combined):
            await self.store_finding(Finding(
                title=f"MS17-010 EternalBlue on {target}:{smb_port}",
                description=(
                    f"The SMB service on {target}:{smb_port} is vulnerable to "
                    f"MS17-010 (EternalBlue / CVE-2017-0144). This pre-auth RCE "
                    f"vulnerability was used by WannaCry and NotPetya ransomware "
                    f"and grants SYSTEM-level remote code execution."
                ),
                severity="CRITICAL",
                evidence=nmap_vuln_out[:3000],
                tool="nmap_smb-vuln",
                host=target,
                port=smb_port,
                cve="CVE-2017-0144",
                mitre_technique="T1210",
                exploit_suggestion=(
                    "MSF: exploit/windows/smb/ms17_010_eternalblue  "
                    "or impacket: python3 eternalblue.py"
                ),
            ))

        # MS08-067
        if _MS08067_RE.search(combined):
            await self.store_finding(Finding(
                title=f"MS08-067 NetAPI on {target}:{smb_port}",
                description=(
                    f"The SMB service on {target}:{smb_port} is vulnerable to "
                    f"MS08-067 (CVE-2008-4250), allowing unauthenticated remote "
                    f"code execution as SYSTEM on older Windows systems."
                ),
                severity="CRITICAL",
                evidence=nmap_vuln_out[:3000],
                tool="nmap_smb-vuln",
                host=target,
                port=smb_port,
                cve="CVE-2008-4250",
                mitre_technique="T1210",
                exploit_suggestion="MSF: exploit/windows/smb/ms08_067_netapi",
            ))

        # MS10-054
        if _MS10054_RE.search(combined):
            await self.store_finding(Finding(
                title=f"MS10-054 SMB DoS on {target}:{smb_port}",
                description=(
                    f"The SMB service on {target}:{smb_port} may be vulnerable to "
                    f"MS10-054 (CVE-2010-2550), allowing remote denial of service."
                ),
                severity="HIGH",
                evidence=nmap_vuln_out[:2000],
                tool="nmap_smb-vuln",
                host=target,
                port=smb_port,
                cve="CVE-2010-2550",
                mitre_technique="T1499",
                exploit_suggestion="Apply MS10-054 patch.",
            ))

        # PrintNightmare
        if _PRINTNIGHTMARE_RE.search(combined):
            await self.store_finding(Finding(
                title=f"PrintNightmare on {target}",
                description=(
                    f"Evidence of PrintNightmare (CVE-2021-1675 / CVE-2021-34527) "
                    f"on {target}. The Windows Print Spooler allows authenticated "
                    f"(low-priv) users to achieve SYSTEM-level RCE."
                ),
                severity="CRITICAL",
                evidence=combined[:2000],
                tool="nmap_smb-vuln",
                host=target,
                port=smb_port,
                cve="CVE-2021-1675",
                mitre_technique="T1547.012",
                exploit_suggestion=(
                    "MSF: exploit/windows/local/cve_2021_1675_printnightmare  "
                    "or impacket: python3 CVE-2021-1675.py"
                ),
            ))

        # Null / Anonymous session
        if _NULL_SESSION_RE.search(combined):
            await self.store_finding(Finding(
                title=f"SMB Null/Anonymous Session on {target}:{smb_port}",
                description=(
                    f"The SMB service on {target}:{smb_port} permits null/anonymous "
                    f"authentication. An unauthenticated attacker can enumerate users, "
                    f"groups, shares, and domain information."
                ),
                severity="HIGH",
                evidence=(enum4linux_out or smbclient_out)[:2000],
                tool="smbclient+enum4linux",
                host=target,
                port=smb_port,
                mitre_technique="T1135",
                exploit_suggestion=(
                    f"smbclient -L //{target} -N  "
                    f"enum4linux-ng -A {target}"
                ),
            ))

        # Parse share list for misconfigurations
        shares = _parse_shares(cme_out + smbclient_out)
        for share in shares:
            name   = share.get("name", "")
            access = str(share.get("access", "")).upper()

            if _ADMIN_SHARE_RE.match(name) and "WRITE" in access:
                await self.store_finding(Finding(
                    title=f"Writable Admin Share {name} on {target}",
                    description=(
                        f"The administrative share {name} on {target} is writable. "
                        f"This gives effective admin-level filesystem access."
                    ),
                    severity="CRITICAL",
                    evidence=cme_out[:2000],
                    tool="crackmapexec",
                    host=target,
                    port=smb_port,
                    mitre_technique="T1021.002",
                    exploit_suggestion=(
                        f"smbclient //{target}/{name} -N  (then drop payload)"
                    ),
                ))
            elif _ADMIN_SHARE_RE.match(name) and "READ" in access:
                await self.store_finding(Finding(
                    title=f"Readable Admin Share {name} on {target}",
                    description=(
                        f"The administrative share {name} on {target} is readable. "
                        f"Sensitive files, credentials, and configurations may be exposed."
                    ),
                    severity="HIGH",
                    evidence=cme_out[:2000],
                    tool="crackmapexec",
                    host=target,
                    port=smb_port,
                    mitre_technique="T1039",
                    exploit_suggestion=f"smbclient //{target}/{name} -N",
                ))

        # SMBv1 enabled
        if _SMBV1_RE.search(combined):
            await self.store_finding(Finding(
                title=f"SMBv1 Enabled on {target}:{smb_port}",
                description=(
                    f"SMBv1 is enabled on {target}:{smb_port}. SMBv1 is the protocol "
                    f"exploited by EternalBlue/WannaCry and is insecure by design. "
                    f"Microsoft has deprecated SMBv1."
                ),
                severity="MEDIUM",
                evidence=nmap_vuln_out[:2000],
                tool="nmap_smb-protocols",
                host=target,
                port=smb_port,
                mitre_technique="T1210",
                exploit_suggestion="Disable SMBv1 via 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'.",
            ))

        # ── Finalise ───────────────────────────────────────────────────────
        result.findings         = self._findings
        result.tool_outputs     = self._tool_outputs
        result.duration_seconds = time.monotonic() - wall_start

        await self._emit(
            "smb_vuln_complete",
            {
                "target": target,
                "findings": len(self._findings),
                "shares_found": len(shares),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )
        logger.info(
            "[smb_vuln] complete — %d findings, %d shares, %.1fs",
            len(self._findings), len(shares), result.duration_seconds,
        )
        return result
