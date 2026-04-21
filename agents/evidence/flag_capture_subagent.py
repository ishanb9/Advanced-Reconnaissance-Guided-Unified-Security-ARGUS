"""
flag_capture_subagent.py — CTF flag capture and proof-of-exploitation documentation.

AGENT_NAME  : "evidence"
SUBAGENT_NAME: "flag_capture"

Methodology:
  1. Search common flag locations: /root/root.txt, /home/*/user.txt, Desktop/
  2. Try to read /etc/shadow as proof of root access
  3. Search for flag patterns: HTB{...}, THM{...}, FLAG{...}, picoCTF{...}
  4. Windows: %USERPROFILE%\\Desktop\\user.txt, C:\\Users\\Administrator\\Desktop\\root.txt
  5. Document proof: whoami, hostname, ip addr, date, id as ownership proof
  6. Hash and archive all findings for submission
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# Common CTF flag patterns
_FLAG_PATTERN = re.compile(
    r'(HTB\{[^}]+\}|THM\{[^}]+\}|FLAG\{[^}]+\}|flag\{[^}]+\}|'
    r'picoCTF\{[^}]+\}|DUCTF\{[^}]+\}|CTF\{[^}]+\}|'
    r'[A-Z0-9]{32}|[a-f0-9]{32,64})',
    re.I
)
_SHADOW_RE = re.compile(r'^root:[^:]+:', re.M)


class FlagCaptureSubagent(BaseSubagent):
    """Locate and document CTF flags and proof-of-exploitation artifacts."""

    AGENT_NAME    = "evidence"
    SUBAGENT_NAME = "flag_capture"

    async def run(self, target: str, os_type: str = "linux",
                  evidence_dir: str = "/tmp/pentest_evidence",
                  extra_paths: list | None = None,
                  **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)
        extra_paths = extra_paths or []

        if os_type.lower() == "windows":
            await self._capture_windows(target, evidence_dir, extra_paths)
        else:
            await self._capture_linux(target, evidence_dir, extra_paths)

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ──────────────────────────── Linux ──────────────────────────────────
    async def _capture_linux(self, target: str, evidence_dir: str, extra_paths: list):
        await self.collect_tool("bash", target,
            {"options": f"-c \"mkdir -p {evidence_dir}/flags\""})

        # ── Proof of access (whoami/id/hostname) ───────────────────────
        proof_out = await self.collect_tool("bash", target,
            {"options": "-c \"echo '=== PROOF OF ACCESS ==='; whoami; id; hostname; ip addr show | grep 'inet ' | head -5; date; uname -a\""})
        is_root = "uid=0" in proof_out or "root" in proof_out.lower()

        await self.store_finding(Finding(
            title=f"Evidence: Proof of Access — {'ROOT' if is_root else 'USER'} on {target}",
            description=f"Confirmed access level on target. Root: {is_root}.\n{proof_out[:400]}",
            severity="CRITICAL" if is_root else "HIGH",
            evidence=proof_out[:600], tool="bash", host=target,
            mitre_technique="T1033",
            exploit_suggestion=f"Document timestamp: {proof_out.splitlines()[-1][:80] if proof_out.strip() else ''}",
        ))

        # ── Standard flag locations ───────────────────────────────────
        flag_paths = [
            "/root/root.txt", "/root/flag.txt", "/root/proof.txt",
            "/home/*/user.txt", "/home/*/flag.txt", "/home/*/local.txt",
            "/var/www/html/flag.txt", "/opt/flag.txt", "/tmp/flag.txt",
        ] + extra_paths

        all_flags = []
        for path in flag_paths:
            flag_out = await self.collect_tool("bash", target,
                {"options": f"-c \"cat {path} 2>/dev/null && echo '---PATH:{path}---'\""})
            if flag_out.strip() and "---PATH:" in flag_out:
                flags = _FLAG_PATTERN.findall(flag_out)
                all_flags.extend(flags)
                await self.store_finding(Finding(
                    title=f"FLAG FOUND: {path} — {flags[0][:60] if flags else flag_out.strip()[:60]}",
                    description=f"Flag file content at {path}:\n{flag_out.strip()[:300]}",
                    severity="CRITICAL",
                    evidence=flag_out[:400], tool="bash", host=target,
                    mitre_technique="T1005",
                    exploit_suggestion=f"Flag value: {flags[0] if flags else flag_out.strip()[:80]}",
                ))

        # ── Broad flag search ──────────────────────────────────────────
        broad_out = await self.collect_tool("bash", target,
            {"options": "-c \"grep -rE 'HTB\\{|THM\\{|FLAG\\{|picoCTF\\{|flag\\{' / --include='*.txt' -l 2>/dev/null | head -20\""})
        if broad_out.strip():
            for fpath in broad_out.strip().splitlines()[:5]:
                content = await self.collect_tool("bash", target,
                    {"options": f"-c \"cat {fpath.strip()} 2>/dev/null\""})
                flags = _FLAG_PATTERN.findall(content)
                if flags:
                    all_flags.extend(flags)
                    await self.store_finding(Finding(
                        title=f"FLAG FOUND (search): {fpath.strip()[:60]}",
                        description=f"Flag detected via pattern search: {flags[0][:60]}",
                        severity="CRITICAL",
                        evidence=content[:300], tool="bash", host=target,
                        mitre_technique="T1005",
                    ))

        # ── /etc/shadow as root proof ──────────────────────────────────
        shadow_out = await self.collect_tool("bash", target,
            {"options": "-c \"cat /etc/shadow 2>/dev/null | head -5\""})
        has_shadow = bool(_SHADOW_RE.search(shadow_out))
        if has_shadow:
            await self.store_finding(Finding(
                title="Evidence: /etc/shadow Readable — Root Proof",
                description="Successfully read /etc/shadow. Confirms root-level access. Root hash captured.",
                severity="CRITICAL",
                evidence=shadow_out[:300], tool="bash", host=target,
                mitre_technique="T1003.008",
                exploit_suggestion="Extract hashes: cat /etc/shadow; crack with hashcat -m 1800",
            ))

        # ── Summary ───────────────────────────────────────────────────
        if all_flags:
            await self.store_finding(Finding(
                title=f"Evidence Summary: {len(set(all_flags))} Unique Flag(s) Captured",
                description=f"All captured flags:\n" + "\n".join(sorted(set(all_flags))[:20]),
                severity="CRITICAL",
                evidence="\n".join(sorted(set(all_flags))[:20]), tool="bash", host=target,
                mitre_technique="T1005",
            ))
        else:
            await self.store_finding(Finding(
                title="Evidence: No Standard Flags Found — Manual Search Recommended",
                description="No flags matching common CTF patterns found in standard locations. Try: find / -name '*.txt' -readable 2>/dev/null | xargs grep -lE 'HTB|THM|FLAG|flag' 2>/dev/null",
                severity="INFO",
                evidence="", tool="bash", host=target,
                mitre_technique="T1005",
            ))

    # ──────────────────────────── Windows ────────────────────────────────
    async def _capture_windows(self, target: str, evidence_dir: str, extra_paths: list):
        # ── Proof of access ────────────────────────────────────────────
        proof_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Write-Output '=== PROOF OF ACCESS ==='; whoami /all; hostname; ipconfig | Select-String 'IPv4'; Get-Date\" 2>&1"})
        is_admin = bool(re.search(r'(S-1-5-32-544|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM)', proof_out, re.I))

        await self.store_finding(Finding(
            title=f"Evidence: Proof of Access (Windows) — {'ADMIN/SYSTEM' if is_admin else 'USER'} on {target}",
            description=f"Windows access proof. Administrator: {is_admin}.\n{proof_out[:400]}",
            severity="CRITICAL" if is_admin else "HIGH",
            evidence=proof_out[:600], tool="powershell", host=target,
            mitre_technique="T1033",
        ))

        # ── Flag file locations ────────────────────────────────────────
        flag_paths = [
            r"C:\Users\Administrator\Desktop\root.txt",
            r"C:\Users\Administrator\Desktop\flag.txt",
            r"C:\Users\*\Desktop\user.txt",
            r"C:\Users\*\Desktop\flag.txt",
            r"C:\Windows\System32\flag.txt",
        ] + extra_paths

        all_flags = []
        for path in flag_paths:
            flag_out = await self.collect_tool("powershell", target,
                {"options": f"-Command \"Get-Content '{path}' -ErrorAction SilentlyContinue | Write-Output\" 2>&1"})
            if flag_out.strip() and "cannot find" not in flag_out.lower() and len(flag_out.strip()) > 2:
                flags = _FLAG_PATTERN.findall(flag_out)
                all_flags.extend(flags)
                await self.store_finding(Finding(
                    title=f"FLAG FOUND (Windows): {path[:60]}",
                    description=f"Flag file content:\n{flag_out.strip()[:300]}",
                    severity="CRITICAL",
                    evidence=flag_out[:400], tool="powershell", host=target,
                    mitre_technique="T1005",
                    exploit_suggestion=f"Flag value: {flags[0] if flags else flag_out.strip()[:80]}",
                ))

        # ── SAM/SYSTEM hashes as admin proof ──────────────────────────
        sam_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-ItemProperty 'HKLM:\\SAM' -ErrorAction SilentlyContinue; Test-Path C:\\Windows\\System32\\config\\SAM\" 2>&1"})
        if "True" in sam_out:
            await self.store_finding(Finding(
                title="Evidence: SAM Database Accessible — Admin Proof",
                description="SAM database accessible. Use secretsdump.py or mimikatz to extract credentials as admin proof.",
                severity="CRITICAL",
                evidence=sam_out[:200], tool="powershell", host=target,
                mitre_technique="T1003.002",
                exploit_suggestion="Dump: secretsdump.py -sam SAM -system SYSTEM LOCAL",
            ))

        if all_flags:
            await self.store_finding(Finding(
                title=f"Evidence Summary: {len(set(all_flags))} Unique Flag(s) Captured (Windows)",
                description="\n".join(sorted(set(all_flags))[:20]),
                severity="CRITICAL",
                evidence="\n".join(sorted(set(all_flags))[:20]), tool="powershell", host=target,
                mitre_technique="T1005",
            ))
