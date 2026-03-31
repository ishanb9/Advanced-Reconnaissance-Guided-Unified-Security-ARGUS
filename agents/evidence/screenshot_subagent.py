"""
screenshot_subagent.py — Capture screenshots as proof-of-exploitation evidence.

AGENT_NAME  : "evidence"
SUBAGENT_NAME: "screenshot"

Methodology:
  1. Detect available screenshot tools (scrot, gnome-screenshot, xwd, import, etc.)
  2. Capture desktop/VNC/X11 display if DISPLAY is available
  3. For web targets: use cutycapt, wkhtmltoimage, or gowitness
  4. For Windows: PowerShell screenshot via .NET
  5. Save to local evidence directory and record metadata
  6. Hash all artifacts for chain of custody
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_URL_RE    = re.compile(r'^https?://', re.I)
_IMG_RE    = re.compile(r'\.(png|jpg|jpeg|bmp)\b', re.I)
_HASH_RE   = re.compile(r'[0-9a-f]{64}', re.I)


class ScreenshotSubagent(BaseSubagent):
    """Capture visual evidence screenshots for proof-of-exploitation."""

    AGENT_NAME    = "evidence"
    SUBAGENT_NAME = "screenshot"

    async def run(self, target: str, os_type: str = "linux",
                  web_urls: list | None = None,
                  evidence_dir: str = "/tmp/pentest_evidence",
                  **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)
        web_urls = web_urls or []

        # ── Create evidence directory ──────────────────────────────────
        mkdir_out = await self.collect_tool("bash", target,
            {"options": f"-c \"mkdir -p {evidence_dir}/screenshots && echo OK\""})
        if "OK" not in mkdir_out:
            await self.store_finding(Finding(
                title="Evidence: Screenshot Directory Creation Failed",
                description=f"Could not create evidence directory: {evidence_dir}",
                severity="MEDIUM", evidence=mkdir_out[:200], tool="bash", host=target,
                mitre_technique="T1119",
            ))

        if os_type.lower() == "windows":
            await self._screenshot_windows(target, evidence_dir)
        else:
            await self._screenshot_linux(target, evidence_dir, web_urls)

        # ── Hash all collected screenshots ────────────────────────────
        hash_out = await self.collect_tool("bash", target,
            {"options": f"-c \"sha256sum {evidence_dir}/screenshots/* 2>/dev/null\""})
        if hash_out.strip():
            await self.store_finding(Finding(
                title="Evidence: Screenshot Hashes (Chain of Custody)",
                description=f"SHA256 hashes for all captured screenshots:\n{hash_out.strip()}",
                severity="INFO", evidence=hash_out[:800], tool="bash", host=target,
                mitre_technique="T1119",
            ))

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ──────────────────────────── Linux ──────────────────────────────────
    async def _screenshot_linux(self, target: str, evidence_dir: str, web_urls: list):
        # ── Check available tools ──────────────────────────────────────
        tools_out = await self.collect_tool("bash", target,
            {"options": "-c \"which scrot gnome-screenshot xwd import cutycapt wkhtmltoimage gowitness 2>/dev/null\""})
        available = tools_out.strip().splitlines()

        # ── Desktop screenshot (if DISPLAY) ───────────────────────────
        display_out = await self.collect_tool("bash", target,
            {"options": "-c \"echo $DISPLAY\""})
        has_display = bool(display_out.strip())

        if has_display:
            ts_cmd = "$(date +%Y%m%d_%H%M%S)"
            if any('scrot' in t for t in available):
                ss_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"DISPLAY={display_out.strip()} scrot {evidence_dir}/screenshots/desktop_{ts_cmd}.png 2>&1 && echo CAPTURED\""})
            elif any('import' in t for t in available):
                ss_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"DISPLAY={display_out.strip()} import -window root {evidence_dir}/screenshots/desktop_{ts_cmd}.png 2>&1 && echo CAPTURED\""})
            elif any('gnome-screenshot' in t for t in available):
                ss_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"DISPLAY={display_out.strip()} gnome-screenshot -f {evidence_dir}/screenshots/desktop_{ts_cmd}.png 2>&1 && echo CAPTURED\""})
            else:
                ss_out = "No desktop screenshot tool available"

            captured = "CAPTURED" in ss_out
            await self.store_finding(Finding(
                title=f"Evidence: Desktop Screenshot {'Captured' if captured else 'Failed'}",
                description=f"Desktop screenshot for DISPLAY={display_out.strip()}. "
                            f"{'Saved to: ' + evidence_dir + '/screenshots/' if captured else 'Tool output: ' + ss_out[:200]}",
                severity="INFO",
                evidence=ss_out[:300], tool="bash", host=target,
                mitre_technique="T1113",
            ))

        # ── Web screenshots ───────────────────────────────────────────
        for url in web_urls[:5]:
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url)[:40]
            if any('gowitness' in t for t in available):
                gw_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"gowitness single -u {url} --screenshot-path {evidence_dir}/screenshots/ 2>&1 && echo CAPTURED\""})
                captured = "CAPTURED" in gw_out or "screenshot" in gw_out.lower()
            elif any('cutycapt' in t for t in available):
                gw_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"cutycapt --url={url} --out={evidence_dir}/screenshots/web_{safe_name}.png 2>&1 && echo CAPTURED\""})
                captured = "CAPTURED" in gw_out
            elif any('wkhtmltoimage' in t for t in available):
                gw_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"wkhtmltoimage {url} {evidence_dir}/screenshots/web_{safe_name}.png 2>&1 && echo CAPTURED\""})
                captured = "CAPTURED" in gw_out
            else:
                gw_out = "No web screenshot tool available (gowitness/cutycapt/wkhtmltoimage)"
                captured = False

            await self.store_finding(Finding(
                title=f"Evidence: Web Screenshot — {url[:60]} {'[OK]' if captured else '[FAILED]'}",
                description=f"Web page screenshot for: {url}. Captured: {captured}.",
                severity="INFO",
                evidence=gw_out[:300], tool="bash", host=target,
                mitre_technique="T1113",
            ))

        # ── VNC/X11 session list for documentation ────────────────────
        vnc_out = await self.collect_tool("bash", target,
            {"options": "-c \"ls /tmp/.X*-lock 2>/dev/null; who 2>/dev/null; w 2>/dev/null | head -10\""})
        if vnc_out.strip():
            await self.store_finding(Finding(
                title="Evidence: Active Display Sessions Identified",
                description=f"X11/VNC sessions active. Sessions: {vnc_out.strip()[:200]}",
                severity="INFO",
                evidence=vnc_out[:400], tool="bash", host=target,
                mitre_technique="T1113",
            ))

    # ──────────────────────────── Windows ────────────────────────────────
    async def _screenshot_windows(self, target: str, evidence_dir: str):
        win_dir = evidence_dir.replace("/", "\\")
        ps_script = (
            "Add-Type -AssemblyName System.Windows.Forms;"
            "$screen = [System.Windows.Forms.Screen]::PrimaryScreen;"
            "$bmp = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height);"
            "$g = [System.Drawing.Graphics]::FromImage($bmp);"
            "$g.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size);"
            f"$bmp.Save('{win_dir}\\screenshot_{{}}.png' -f (Get-Date -Format 'yyyyMMdd_HHmmss'));"
            "Write-Output 'CAPTURED'"
        )
        ss_out = await self.collect_tool("powershell", target,
            {"options": f"-Command \"{ps_script}\" 2>&1"})
        captured = "CAPTURED" in ss_out

        await self.store_finding(Finding(
            title=f"Evidence: Windows Desktop Screenshot {'Captured' if captured else 'Failed'}",
            description=f"PowerShell .NET screenshot capture. Saved to {win_dir}. Success: {captured}.",
            severity="INFO",
            evidence=ss_out[:400], tool="powershell", host=target,
            mitre_technique="T1113",
        ))

        # Hash with PowerShell
        hash_out = await self.collect_tool("powershell", target,
            {"options": f"-Command \"Get-ChildItem '{win_dir}' -Filter '*.png' | Get-FileHash -Algorithm SHA256 | Format-Table -AutoSize\" 2>&1"})
        if hash_out.strip():
            await self.store_finding(Finding(
                title="Evidence: Windows Screenshot Hashes (Chain of Custody)",
                description="SHA256 hashes of all captured screenshots.",
                severity="INFO",
                evidence=hash_out[:600], tool="powershell", host=target,
                mitre_technique="T1119",
            ))
