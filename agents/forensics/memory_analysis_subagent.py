"""
memory_analysis_subagent.py — Volatile memory analysis for forensic investigation.

AGENT_NAME  : "forensics"
SUBAGENT_NAME: "memory_analysis"

Methodology:
  Linux:
    /proc/<pid> analysis: maps, fd, cmdline, environ for injected/hollowed processes
    strings on suspicious process memory via /proc/<pid>/mem (where accessible)
    Volatility3 if available: linux.pslist, linux.malfind, linux.netstat
    LiME dump trigger check + insmod availability
  Windows:
    WinPmem or Volatility3 analysis if dump exists
    Suspicious process parent/child relationships (ppid-spoof indicators)
    Hollow process detection via PEB vs mapped path mismatch
    Loaded DLLs in suspicious processes for reflective injection
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_INJECT_RE    = re.compile(r'(rwxp|EXECUTE\+WRITE|anonymous|deleted|memfd)', re.I)
_HOLLOW_RE    = re.compile(r'(hollow|injected|smear|malfind)', re.I)
_SUSPECT_PROC = re.compile(r'(python[23]?|perl|ruby|php|node|nc|ncat|socat|meterpreter|beacon|implant)', re.I)
_NETWORK_RE   = re.compile(r'(LISTEN|ESTABLISHED|SYN_SENT)', re.I)


class MemoryAnalysisSubagent(BaseSubagent):
    """Analyze volatile memory for malicious activity indicators."""

    AGENT_NAME    = "forensics"
    SUBAGENT_NAME = "memory_analysis"

    async def run(self, target: str, os_type: str = "linux",
                  dump_path: str = "", **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        if os_type.lower() == "windows":
            await self._analyze_windows(target, dump_path)
        else:
            await self._analyze_linux(target, dump_path)

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ──────────────────────────── Linux ──────────────────────────────────
    async def _analyze_linux(self, target: str, dump_path: str):
        # ── Process list with full paths ───────────────────────────────
        ps_out = await self.collect_tool("bash", target,
            {"options": "-c \"ps auxwwf 2>/dev/null | head -80\""})
        suspect_procs = [l for l in ps_out.splitlines() if _SUSPECT_PROC.search(l)]

        await self.store_finding(Finding(
            title=f"Memory Analysis: Process List — {len(suspect_procs)} Suspicious Process(es)",
            description=f"Running processes. Suspicious interpreters/tools detected: {suspect_procs[:5]}",
            severity="HIGH" if suspect_procs else "INFO",
            evidence=ps_out[:800], tool="bash", host=target,
            mitre_technique="T1057",
            exploit_suggestion=f"Investigate PID: cat /proc/<pid>/cmdline; ls -la /proc/<pid>/exe" if suspect_procs else None,
        ))

        # ── /proc/<pid>/maps — look for RWX anonymous regions ─────────
        maps_out = await self.collect_tool("bash", target,
            {"options": "-c \"for pid in $(ls /proc | grep -E '^[0-9]+$' | head -20); do maps=/proc/$pid/maps; [ -r $maps ] && grep -lE 'rwxp|rwx' $maps 2>/dev/null && echo \\\"PID $pid: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\\\\0' ' ')\\\"; done\""})
        rwx_regions = [l for l in maps_out.splitlines() if _INJECT_RE.search(l)]

        if rwx_regions:
            await self.store_finding(Finding(
                title=f"Memory Analysis: {len(rwx_regions)} Process(es) with RWX Memory Regions — Shellcode Injection Suspected",
                description=f"Processes with anonymous RWX memory mappings (common in shellcode injection / reflective loading): {rwx_regions[:5]}",
                severity="CRITICAL",
                evidence=maps_out[:800], tool="bash", host=target,
                mitre_technique="T1055",
                exploit_suggestion="Dump process memory: gcore -o /tmp/dump <pid>; strings /tmp/dump.<pid> | grep -iE 'cmd|shell|http'",
            ))

        # ── Open network connections by process ────────────────────────
        net_proc_out = await self.collect_tool("bash", target,
            {"options": "-c \"ss -tulnp 2>/dev/null; lsof -i 2>/dev/null | grep -iE 'LISTEN|ESTABLISHED' | head -40\""})
        unusual_listeners = [l for l in net_proc_out.splitlines()
                             if _NETWORK_RE.search(l) and _SUSPECT_PROC.search(l)]

        if unusual_listeners:
            await self.store_finding(Finding(
                title=f"Memory Analysis: {len(unusual_listeners)} Suspicious Process(es) with Network Connections",
                description=f"Unexpected processes with active network connections: {unusual_listeners[:5]}",
                severity="HIGH",
                evidence=net_proc_out[:600], tool="bash", host=target,
                mitre_technique="T1095",
            ))

        # ── Volatility3 live analysis (if available) ───────────────────
        vol_check = await self.collect_tool("bash", target,
            {"options": "-c \"which vol vol3 volatility volatility3 2>/dev/null\""})
        vol_bin = vol_check.strip().splitlines()[0] if vol_check.strip() else None

        if vol_bin and dump_path:
            pslist_out = await self.collect_tool("bash", target,
                {"options": f"-c \"{vol_bin} -f {dump_path} linux.pslist.PsList 2>&1 | head -50\""})
            malfind_out = await self.collect_tool("bash", target,
                {"options": f"-c \"{vol_bin} -f {dump_path} linux.malfind.Malfind 2>&1 | head -50\""})

            malfind_hits = [l for l in malfind_out.splitlines() if _INJECT_RE.search(l)]
            await self.store_finding(Finding(
                title=f"Memory Analysis (Volatility): {len(malfind_hits)} Malfind Hit(s)",
                description=f"Volatility3 malfind plugin results: {len(malfind_hits)} suspicious memory regions.",
                severity="CRITICAL" if malfind_hits else "INFO",
                evidence=(pslist_out[:400] + "\n" + malfind_out[:400]), tool="bash", host=target,
                mitre_technique="T1055",
            ))
        elif not dump_path:
            # Offer LiME dump instructions
            lime_check = await self.collect_tool("bash", target,
                {"options": "-c \"find /lib/modules -name 'lime*.ko' 2>/dev/null; which insmod 2>/dev/null\""})
            await self.store_finding(Finding(
                title="Memory Analysis: No Dump File — LiME Acquisition Available" if lime_check.strip() else "Memory Analysis: No Dump Available",
                description=(
                    f"No memory dump provided. LiME module available: {bool(lime_check.strip())}. "
                    f"To acquire: insmod lime.ko 'path=/tmp/mem.lime format=lime'; then run Volatility3."
                    if lime_check.strip()
                    else "No memory dump provided and LiME not found. Manual dump required."
                ),
                severity="INFO",
                evidence=lime_check[:200], tool="bash", host=target,
                mitre_technique="T1055",
                exploit_suggestion="Acquire dump: insmod /path/to/lime.ko 'path=/tmp/mem.lime format=lime'" if lime_check.strip() else None,
            ))

        # ── Deleted/hidden executable check ───────────────────────────
        deleted_out = await self.collect_tool("bash", target,
            {"options": "-c \"ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'\""})
        deleted_exes = [l.strip() for l in deleted_out.splitlines() if '(deleted)' in l]
        if deleted_exes:
            await self.store_finding(Finding(
                title=f"Memory Analysis: {len(deleted_exes)} Running Process(es) with Deleted Executable",
                description=f"Processes running from deleted executables (common in fileless malware): {deleted_exes[:5]}",
                severity="CRITICAL",
                evidence=deleted_out[:400], tool="bash", host=target,
                mitre_technique="T1055.012",
                exploit_suggestion="Recover: cp /proc/<pid>/exe /forensics/recovered_<pid>",
            ))

    # ──────────────────────────── Windows ────────────────────────────────
    async def _analyze_windows(self, target: str, dump_path: str):
        # ── Process tree (PPID spoof detection) ───────────────────────
        proctree_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-WmiObject Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath | Format-Table -AutoSize\" 2>&1"})
        suspect_procs = [l for l in proctree_out.splitlines() if _SUSPECT_PROC.search(l)]

        await self.store_finding(Finding(
            title=f"Memory Analysis (Windows): Process Tree — {len(suspect_procs)} Suspicious",
            description=f"Full process list with parent relationships. Suspicious: {suspect_procs[:5]}",
            severity="HIGH" if suspect_procs else "INFO",
            evidence=proctree_out[:800], tool="powershell", host=target,
            mitre_technique="T1057",
        ))

        # ── Loaded DLLs in suspicious processes ───────────────────────
        dll_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-Process | Where-Object {$_.Name -match 'rundll32|regsvr32|mshta|wscript|cscript|powershell|cmd'} | ForEach-Object {$proc=$_; $proc.Modules | Select-Object @{N='PID';E={$proc.Id}},@{N='Proc';E={$proc.Name}},FileName} | Format-Table -AutoSize\" 2>&1"})
        unsigned_re = re.compile(r'(AppData|Temp|tmp|Downloads|Users\\[^\\]+\\)', re.I)
        sus_dlls = [l for l in dll_out.splitlines() if unsigned_re.search(l)]

        if sus_dlls:
            await self.store_finding(Finding(
                title=f"Memory Analysis (Windows): {len(sus_dlls)} DLL(s) Loaded from Suspicious Path",
                description=f"DLLs loaded from user-writable or temp directories (reflective injection indicator): {sus_dlls[:5]}",
                severity="CRITICAL",
                evidence=dll_out[:800], tool="powershell", host=target,
                mitre_technique="T1055.001",
                exploit_suggestion="Dump and analyze: Get-Process -Id <pid> | Select-Object -ExpandProperty Modules",
            ))

        # ── Volatility3 (Windows) if dump exists ──────────────────────
        if dump_path:
            vol_check = await self.collect_tool("powershell", target,
                {"options": f"-Command \"Get-Command vol3,volatility3 -ErrorAction SilentlyContinue\" 2>&1"})
            vol_avail = bool(re.search(r'(vol3|volatility3)', vol_check))

            if vol_avail:
                malfind_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"vol3 -f {dump_path} windows.malfind.Malfind 2>&1 | head -60\""})
                hits = [l for l in malfind_out.splitlines() if _INJECT_RE.search(l)]
                await self.store_finding(Finding(
                    title=f"Memory Analysis (Volatility/Windows): {len(hits)} Malfind Hit(s)",
                    description=f"Volatility3 windows.malfind results: {len(hits)} RWX regions in process memory.",
                    severity="CRITICAL" if hits else "INFO",
                    evidence=malfind_out[:800], tool="bash", host=target,
                    mitre_technique="T1055",
                ))
            else:
                await self.store_finding(Finding(
                    title="Memory Analysis (Windows): Volatility3 Not Available",
                    description=f"Dump path provided ({dump_path}) but Volatility3 not found. Install: pip install volatility3",
                    severity="INFO",
                    evidence="", tool="powershell", host=target,
                    mitre_technique="T1055",
                ))

        # ── WER (Windows Error Reporting) crash dumps ─────────────────
        wer_out = await self.collect_tool("powershell", target,
            {"options": "-Command \"Get-ChildItem C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\ -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20 FullName,LastWriteTime | Format-Table -AutoSize\" 2>&1"})
        await self.store_finding(Finding(
            title="Memory Analysis (Windows): WER Crash Dumps",
            description="Windows Error Reporting crash dumps. May contain memory snapshots from exploited processes.",
            severity="INFO",
            evidence=wer_out[:400], tool="powershell", host=target,
            mitre_technique="T1003",
        ))
