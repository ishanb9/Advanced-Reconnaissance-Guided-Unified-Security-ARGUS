"""
service_vuln_subagent.py — Protocol-specific vulnerability checks.

Methodology:
  1. For SSH:  nmap --script=ssh-auth-methods,ssh-brute (light)
  2. For RDP:  nmap --script=rdp-vuln-ms12-020,rdp-enum-encryption
  3. For VNC:  nmap --script=vnc-info,vnc-brute (light)
  4. For SNMP: nmap --script=snmp-info,snmp-brute
  5. For NFS:  nmap --script=nfs-ls,nfs-showmount
  6. For RPC:  nmap --script=rpcinfo
  7. Parse output for version-specific vulns and misconfigurations
  8. Findings: CRITICAL for BlueKeep/DejaBlue; HIGH for VNC no-auth, SNMP default;
               MEDIUM for weak SSH config
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

_BLUEKEEP_RE   = re.compile(r"(bluekeep|CVE-2019-0708|ms12-020.*VULNERABLE)", re.IGNORECASE)
_DEJABLUE_RE   = re.compile(r"(dejablue|CVE-2019-1181|CVE-2019-1182)", re.IGNORECASE)
_VNC_NOAUTH_RE = re.compile(r"(no.?auth|security type.*None|vnc.*no password)", re.IGNORECASE)
_SNMP_DEFAULT_RE = re.compile(r"(community.*public|community.*private|default community)", re.IGNORECASE)
_SSH_PUBKEY_RE = re.compile(r"publickey", re.IGNORECASE)
_SSH_PASSWORD_RE = re.compile(r"password", re.IGNORECASE)
_SSH_KEYBOARD_RE = re.compile(r"keyboard-interactive", re.IGNORECASE)
_NFS_EXPORT_RE = re.compile(r"(/[^\s]+)\s", re.IGNORECASE)
_RDP_ENC_RE    = re.compile(r"(ENCRYPTION_LEVEL|security.*layer|Classic RDP Security)", re.IGNORECASE)
_SNMP_BRUTE_RE = re.compile(r"Valid credentials.*:\s*(public|private|community)", re.IGNORECASE)


_SSH_PORTS  = {22, 2222}
_RDP_PORTS  = {3389, 3388}
_VNC_PORTS  = {5900, 5901, 5902, 5903}
_SNMP_PORTS = {161, 162}
_NFS_PORTS  = {2049}
_RPC_PORTS  = {111, 135}


def _svc_ports(services_list: list[dict], known_ports: set[int], keyword: str) -> list[int]:
    """Return port numbers matching either known_ports set or service name keyword."""
    matched = set()
    for svc in services_list:
        port = int(svc.get("port", 0))
        svc_name = str(svc.get("service", "")).lower()
        if port in known_ports or keyword in svc_name:
            matched.add(port)
    return sorted(matched)


class ServiceVulnSubagent(BaseSubagent):
    """
    Protocol-specific vulnerability scanner.

    Dispatches nmap NSE scripts tuned per protocol (SSH, RDP, VNC, SNMP,
    NFS, RPC) and elevates findings for critical misconfigurations like
    BlueKeep, VNC no-auth, and SNMP default community strings.
    """

    AGENT_NAME    = "vuln"
    SUBAGENT_NAME = "service_vuln"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:  # noqa: C901
        """
        Run protocol-specific NSE checks against discovered services.

        Parameters
        ----------
        target:
            IP or hostname.
        services_list:
            List of dicts with keys: port (int), service (str), version (str).

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
        services_list: list[dict] = kwargs.get("services_list", [])

        # ── SSH ────────────────────────────────────────────────────────────
        ssh_ports = _svc_ports(services_list, _SSH_PORTS, "ssh")
        for port in ssh_ports:
            logger.info("[service_vuln] SSH checks on port %s", port)
            try:
                ssh_out = await self.collect_tool(
                    "nmap",
                    target,
                    {
                        "options": (
                            f"--script=ssh-auth-methods,ssh2-enum-algos,ssh-hostkey "
                            f"-p {port} {target}"
                        )
                    },
                )
                # Detect password authentication (weak config)
                auth_methods = []
                if _SSH_PASSWORD_RE.search(ssh_out):
                    auth_methods.append("password")
                if _SSH_PUBKEY_RE.search(ssh_out):
                    auth_methods.append("publickey")
                if _SSH_KEYBOARD_RE.search(ssh_out):
                    auth_methods.append("keyboard-interactive")

                if "password" in auth_methods:
                    await self.store_finding(Finding(
                        title=f"SSH Password Authentication Enabled on port {port}",
                        description=(
                            f"SSH on {target}:{port} accepts password authentication, "
                            f"making it susceptible to brute-force attacks. "
                            f"Auth methods: {', '.join(auth_methods)}."
                        ),
                        severity="MEDIUM",
                        evidence=ssh_out[:2000],
                        tool="nmap_ssh",
                        host=target,
                        port=port,
                        mitre_technique="T1110",
                        exploit_suggestion=(
                            "Run: hydra -L users.txt -P rockyou.txt ssh://target"
                        ),
                    ))

                # Light brute — only try default/common creds, not full wordlist
                logger.info("[service_vuln] SSH light brute on port %s", port)
                ssh_brute_out = await self.collect_tool(
                    "nmap",
                    target,
                    {
                        "options": (
                            f"--script=ssh-brute "
                            f"--script-args brute.firstonly=true,brute.mode=user "
                            f"-p {port} {target}"
                        )
                    },
                )
                if "Valid credentials" in ssh_brute_out or "Login Successful" in ssh_brute_out:
                    cred_m = re.search(
                        r"Valid credentials.*?[:\s]+(\S+)\s*/\s*(\S+)", ssh_brute_out
                    )
                    user = cred_m.group(1) if cred_m else "unknown"
                    pw   = cred_m.group(2) if cred_m else "unknown"
                    await self.store_finding(Finding(
                        title=f"SSH Default/Weak Credentials on {target}:{port}",
                        description=(
                            f"nmap ssh-brute found valid SSH credentials on {target}:{port}: "
                            f"user={user}, pass={pw}."
                        ),
                        severity="CRITICAL",
                        evidence=ssh_brute_out[:2000],
                        tool="nmap_ssh-brute",
                        host=target,
                        port=port,
                        mitre_technique="T1110.001",
                        exploit_suggestion=f"ssh {user}@{target} -p {port}",
                    ))
            except Exception as exc:
                logger.warning("[service_vuln] SSH check error on port %s: %s", port, exc)

        # ── RDP ────────────────────────────────────────────────────────────
        rdp_ports = _svc_ports(services_list, _RDP_PORTS, "ms-wbt")
        for port in rdp_ports:
            logger.info("[service_vuln] RDP checks on port %s", port)
            try:
                rdp_out = await self.collect_tool(
                    "nmap",
                    target,
                    {
                        "options": (
                            f"--script=rdp-vuln-ms12-020,rdp-enum-encryption "
                            f"-p {port} {target}"
                        )
                    },
                )
                # BlueKeep
                if _BLUEKEEP_RE.search(rdp_out):
                    await self.store_finding(Finding(
                        title=f"BlueKeep (CVE-2019-0708) on {target}:{port}",
                        description=(
                            f"The RDP service on {target}:{port} appears vulnerable to "
                            f"BlueKeep (CVE-2019-0708), a pre-auth RCE vulnerability "
                            f"in Windows Remote Desktop Services."
                        ),
                        severity="CRITICAL",
                        evidence=rdp_out[:3000],
                        tool="nmap_rdp",
                        host=target,
                        port=port,
                        cve="CVE-2019-0708",
                        mitre_technique="T1210",
                        exploit_suggestion="MSF: exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                    ))

                # DejaBlue
                if _DEJABLUE_RE.search(rdp_out):
                    await self.store_finding(Finding(
                        title=f"DejaBlue (CVE-2019-1181/1182) on {target}:{port}",
                        description=(
                            f"The RDP service on {target}:{port} may be vulnerable to "
                            f"DejaBlue (CVE-2019-1181/1182), similar in nature to BlueKeep."
                        ),
                        severity="CRITICAL",
                        evidence=rdp_out[:2000],
                        tool="nmap_rdp",
                        host=target,
                        port=port,
                        cve="CVE-2019-1181",
                        mitre_technique="T1210",
                        exploit_suggestion="Apply MS patch KB4512501 / KB4512508.",
                    ))

                # MS12-020 DoS
                if re.search(r"ms12.020.*VULNERABLE", rdp_out, re.IGNORECASE):
                    await self.store_finding(Finding(
                        title=f"MS12-020 RDP DoS on {target}:{port}",
                        description=(
                            f"The RDP service on {target}:{port} is vulnerable to "
                            f"MS12-020, allowing remote denial of service."
                        ),
                        severity="HIGH",
                        evidence=rdp_out[:2000],
                        tool="nmap_rdp",
                        host=target,
                        port=port,
                        cve="CVE-2012-0002",
                        mitre_technique="T1499",
                        exploit_suggestion="Apply Microsoft patch MS12-020.",
                    ))

                # Classic (unencrypted) RDP
                if _RDP_ENC_RE.search(rdp_out) and re.search(
                    r"Classic RDP Security|ENCRYPTION_LEVEL.*NONE", rdp_out, re.IGNORECASE
                ):
                    await self.store_finding(Finding(
                        title=f"RDP Classic (Unencrypted) Security on {target}:{port}",
                        description=(
                            f"RDP on {target}:{port} is using Classic RDP Security without "
                            f"TLS, allowing credential interception via MITM."
                        ),
                        severity="HIGH",
                        evidence=rdp_out[:2000],
                        tool="nmap_rdp-enum-encryption",
                        host=target,
                        port=port,
                        mitre_technique="T1040",
                        exploit_suggestion="Enable Network Level Authentication (NLA) and TLS.",
                    ))
            except Exception as exc:
                logger.warning("[service_vuln] RDP check error on port %s: %s", port, exc)

        # ── VNC ────────────────────────────────────────────────────────────
        vnc_ports = _svc_ports(services_list, _VNC_PORTS, "vnc")
        for port in vnc_ports:
            logger.info("[service_vuln] VNC checks on port %s", port)
            try:
                vnc_out = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"--script=vnc-info,vnc-brute -p {port} {target}"},
                )
                if _VNC_NOAUTH_RE.search(vnc_out):
                    await self.store_finding(Finding(
                        title=f"VNC No Authentication on {target}:{port}",
                        description=(
                            f"VNC on {target}:{port} allows connections without any "
                            f"authentication. An attacker gains full desktop control."
                        ),
                        severity="CRITICAL",
                        evidence=vnc_out[:2000],
                        tool="nmap_vnc-info",
                        host=target,
                        port=port,
                        mitre_technique="T1021.005",
                        exploit_suggestion=f"vncviewer {target}:{port}  (no password needed)",
                    ))
                elif "Valid credentials" in vnc_out:
                    await self.store_finding(Finding(
                        title=f"VNC Weak Password on {target}:{port}",
                        description=(
                            f"VNC brute on {target}:{port} found a valid password."
                        ),
                        severity="HIGH",
                        evidence=vnc_out[:2000],
                        tool="nmap_vnc-brute",
                        host=target,
                        port=port,
                        mitre_technique="T1110.001",
                        exploit_suggestion=f"vncviewer {target}:{port}",
                    ))
                else:
                    # VNC present is notable regardless
                    await self.store_finding(Finding(
                        title=f"VNC Service Detected on {target}:{port}",
                        description=(
                            f"VNC remote desktop service is running on {target}:{port}."
                        ),
                        severity="MEDIUM",
                        evidence=vnc_out[:1000],
                        tool="nmap_vnc-info",
                        host=target,
                        port=port,
                        mitre_technique="T1021.005",
                        exploit_suggestion="Attempt brute force: hydra -P rockyou.txt vnc://target",
                    ))
            except Exception as exc:
                logger.warning("[service_vuln] VNC check error on port %s: %s", port, exc)

        # ── SNMP ───────────────────────────────────────────────────────────
        snmp_ports = _svc_ports(services_list, _SNMP_PORTS, "snmp")
        if not snmp_ports:
            snmp_ports = []  # SNMP UDP; only add if explicitly found

        for port in snmp_ports:
            logger.info("[service_vuln] SNMP checks on port %s/udp", port)
            try:
                snmp_out = await self.collect_tool(
                    "nmap",
                    target,
                    {
                        "options": (
                            f"--script=snmp-info,snmp-brute,snmp-sysdescr "
                            f"-sU -p {port} {target}"
                        )
                    },
                )
                if _SNMP_DEFAULT_RE.search(snmp_out) or _SNMP_BRUTE_RE.search(snmp_out):
                    comm_m = re.search(
                        r"community[:\s]+([^\s,\n]+)", snmp_out, re.IGNORECASE
                    )
                    community = comm_m.group(1) if comm_m else "public"
                    await self.store_finding(Finding(
                        title=f"SNMP Default Community String '{community}' on {target}:{port}",
                        description=(
                            f"SNMP on {target}:{port} responds to the default community "
                            f"string '{community}'. This exposes device configuration, "
                            f"network topology, and may allow SNMP writes."
                        ),
                        severity="HIGH",
                        evidence=snmp_out[:2000],
                        tool="nmap_snmp",
                        host=target,
                        port=port,
                        mitre_technique="T1602.001",
                        exploit_suggestion=(
                            f"snmpwalk -v2c -c {community} {target} | grep -i 'pass\\|cred\\|user'"
                        ),
                    ))
                elif snmp_out and "open" in snmp_out.lower():
                    await self.store_finding(Finding(
                        title=f"SNMP Service Open on {target}:{port}",
                        description=(
                            f"SNMP is running on {target}:{port}. Further community "
                            f"string enumeration recommended."
                        ),
                        severity="MEDIUM",
                        evidence=snmp_out[:1000],
                        tool="nmap_snmp-info",
                        host=target,
                        port=port,
                        mitre_technique="T1602.001",
                        exploit_suggestion="onesixtyone -c community_strings.txt target",
                    ))
            except Exception as exc:
                logger.warning("[service_vuln] SNMP check error on port %s: %s", port, exc)

        # ── NFS ────────────────────────────────────────────────────────────
        nfs_ports = _svc_ports(services_list, _NFS_PORTS, "nfs")
        for port in nfs_ports:
            logger.info("[service_vuln] NFS checks on port %s", port)
            try:
                nfs_out = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"--script=nfs-ls,nfs-showmount,nfs-statfs -p {port} {target}"},
                )
                exports = _NFS_EXPORT_RE.findall(nfs_out)
                if exports:
                    # Check for world-readable exports
                    world_exports = [
                        e for e in exports
                        if re.search(r"0\.0\.0\.0|everyone|\*", nfs_out, re.IGNORECASE)
                    ]
                    severity = "CRITICAL" if world_exports else "HIGH"
                    await self.store_finding(Finding(
                        title=f"NFS Exports Found on {target}:{port}: {', '.join(exports[:5])}",
                        description=(
                            f"NFS exports found on {target}:{port}: {', '.join(exports)}."
                            + (f" World-accessible exports: {', '.join(world_exports)}"
                               if world_exports else "")
                        ),
                        severity=severity,
                        evidence=nfs_out[:2000],
                        tool="nmap_nfs",
                        host=target,
                        port=port,
                        mitre_technique="T1039",
                        exploit_suggestion=(
                            f"showmount -e {target} && "
                            f"mount -t nfs {target}:{exports[0] if exports else '/'} /mnt"
                        ),
                    ))
            except Exception as exc:
                logger.warning("[service_vuln] NFS check error on port %s: %s", port, exc)

        # ── RPC ────────────────────────────────────────────────────────────
        rpc_ports = _svc_ports(services_list, _RPC_PORTS, "rpc")
        for port in rpc_ports:
            logger.info("[service_vuln] RPC check on port %s", port)
            try:
                rpc_out = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"--script=rpcinfo -p {port} {target}"},
                )
                if rpc_out and "open" in rpc_out.lower():
                    await self.store_finding(Finding(
                        title=f"RPC Portmapper Exposed on {target}:{port}",
                        description=(
                            f"RPC portmapper is accessible on {target}:{port}. "
                            f"This service can reveal internal RPC services and may "
                            f"be used to reach NFS, NIS, and other internal services."
                        ),
                        severity="HIGH",
                        evidence=rpc_out[:2000],
                        tool="nmap_rpcinfo",
                        host=target,
                        port=port,
                        mitre_technique="T1046",
                        exploit_suggestion="rpcinfo -p target; enumerate exposed RPC services.",
                    ))
            except Exception as exc:
                logger.warning("[service_vuln] RPC check error on port %s: %s", port, exc)

        # ── Finalise ───────────────────────────────────────────────────────
        result.findings         = self._findings
        result.tool_outputs     = self._tool_outputs
        result.duration_seconds = time.monotonic() - wall_start

        await self._emit(
            "service_vuln_complete",
            {
                "target": target,
                "findings": len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )
        logger.info(
            "[service_vuln] complete — %d findings, %.1fs",
            len(self._findings), result.duration_seconds,
        )
        return result
