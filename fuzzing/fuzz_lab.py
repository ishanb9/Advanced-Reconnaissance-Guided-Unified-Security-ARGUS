"""agents/fuzzing/fuzz_lab.py — human-controlled, parallel fuzzing engine.

Client feedback #6: a separate "Fuzzing Lab" the human drives.  It can fuzz any
technology type (web / app / api / network / iot / ot) against a target ARGUS has
ALREADY identified as in-scope, while the autonomous pentest keeps running.  The
human sets the config and presses Start; findings the fuzzer surfaces are fed
back to the agents (a real finding via ``store_finding`` + an intel-cascade
signal so the operator acts on it).

Design notes
------------
* **Scope-enforced.**  ``scope_for_agent`` derives the set of fuzzable hosts from
  the live session's intel (single-host MasterAgent OR multi-host orchestrator).
  ``FuzzLab`` refuses any target not in that set — fuzzing only ever touches what
  ARGUS is already attacking, so it stays in engagement scope.
* **Data-driven catalog.**  ``CATALOG`` maps a tech type to a list of fuzzer
  specs (binary + argument template + hit patterns).  Adding a fuzzer is data,
  not code.  Missing binaries are reported, never crash the lab.
* **No shell.**  Every fuzzer runs via ``create_subprocess_exec`` with an explicit
  argv (execFile-style) — never a shell string — so a scope-validated target can
  never become a command-injection vector.
* **Parallel + non-blocking.**  Each lab is its own ``asyncio`` task; several can
  run at once and none of them block the engagement loop.
* **Safe-by-default for OT/IoT.**  Specs carry a ``safety`` class; dangerous OT
  fuzzers are flagged so the UI can warn, and the human's explicit Start press is
  the authorization (matching the rest of ARGUS's intrusiveness model).

The engine shells out exactly like the rest of ARGUS, so on Kali it runs the
real tools; in a bare dev box a missing binary is surfaced cleanly.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import shutil
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("argus.fuzz_lab")

# Per-line output cap so a chatty fuzzer cannot flood the WebSocket / memory.
_MAX_RESULT_LINES = int(os.environ.get("ARGUS_FUZZ_MAX_LINES", "4000"))
# Hard wall-clock ceiling per lab run (s); the human can stop earlier.
_DEFAULT_MAX_SEC  = int(os.environ.get("ARGUS_FUZZ_MAX_SEC", "1800"))


# ──────────────────────────────────────────────────────────────────────────────
# Fuzzer catalog — data, not code.  {tech_type: [spec, ...]}
#
# spec fields:
#   id            stable identifier
#   label         human label
#   tool          binary that must be on PATH
#   safety        safe | intrusive | dangerous   (UI surfaces a warning ≥ intrusive)
#   needs         which scope inputs the template requires: url | host | hostport
#   args          argv template list — placeholders {url}{host}{port}{wordlist}
#                 {threads}{rate}{extra} are filled at run time (NO shell)
#   hit           list of regexes; a matching output line is an interesting hit
#   severity      finding severity to record for a hit (info|low|medium|high)
#   desc          one-liner shown in the picker
# ──────────────────────────────────────────────────────────────────────────────
CATALOG: Dict[str, List[Dict[str, Any]]] = {
    "web": [
        {
            "id": "ffuf_content", "label": "ffuf — content/dir discovery",
            "tool": "ffuf", "safety": "intrusive", "needs": "url",
            "args": ["ffuf", "-u", "{url}/FUZZ", "-w", "{wordlist}",
                     "-mc", "200,204,301,302,307,401,403,405", "-t", "{threads}",
                     "-rate", "{rate}", "-noninteractive", "{extra}"],
            "hit": [r"\[Status:\s*(200|301|302|307|401|403)\b"],
            "severity": "info",
            "desc": "Brute hidden paths/files on an HTTP service.",
        },
        {
            "id": "ffuf_vhost", "label": "ffuf — vhost fuzzing",
            "tool": "ffuf", "safety": "intrusive", "needs": "url",
            "args": ["ffuf", "-u", "{url}", "-H", "Host: FUZZ.{host}",
                     "-w", "{wordlist}", "-t", "{threads}", "-rate", "{rate}",
                     "-noninteractive", "{extra}"],
            "hit": [r"\[Status:\s*(200|301|302|401|403)\b"],
            "severity": "info",
            "desc": "Discover virtual hosts on the same IP.",
        },
        {
            "id": "wfuzz_param", "label": "wfuzz — parameter/value fuzzing",
            "tool": "wfuzz", "safety": "intrusive", "needs": "url",
            "args": ["wfuzz", "-c", "-z", "file,{wordlist}", "-t", "{threads}",
                     "--hc", "404", "{extra}", "{url}?FUZZ=1"],
            "hit": [r"\b(200|500|301|302|403)\b\s+\d+\s+L"],
            "severity": "low",
            "desc": "Fuzz query parameters / values for anomalies.",
        },
        {
            "id": "nuclei_fuzz", "label": "nuclei — templated DAST/fuzzing",
            "tool": "nuclei", "safety": "intrusive", "needs": "url",
            "args": ["nuclei", "-u", "{url}", "-dast", "-rl", "{rate}", "{extra}"],
            "hit": [r"\[(critical|high|medium|low)\]"],
            "severity": "medium",
            "desc": "Run nuclei DAST/fuzzing templates against the URL.",
        },
    ],
    "api": [
        {
            "id": "ffuf_api", "label": "ffuf — API endpoint discovery",
            "tool": "ffuf", "safety": "intrusive", "needs": "url",
            "args": ["ffuf", "-u", "{url}/FUZZ", "-w", "{wordlist}",
                     "-mc", "200,201,204,400,401,403,405,500", "-t", "{threads}",
                     "-rate", "{rate}", "-noninteractive", "{extra}"],
            "hit": [r"\[Status:\s*(200|201|204|401|403|405|500)\b"],
            "severity": "info",
            "desc": "Discover REST/GraphQL endpoints + verbs.",
        },
        {
            "id": "ffuf_api_method", "label": "ffuf — HTTP method fuzzing",
            "tool": "ffuf", "safety": "intrusive", "needs": "url",
            "args": ["ffuf", "-u", "{url}", "-X", "FUZZ",
                     "-w", "{wordlist}", "-t", "{threads}", "-rate", "{rate}",
                     "-noninteractive", "{extra}"],
            "hit": [r"\[Status:\s*(200|201|204|405)\b"],
            "severity": "low",
            "desc": "Probe which HTTP methods an endpoint accepts.",
        },
        {
            "id": "schemathesis_api", "label": "schemathesis — OpenAPI property fuzzing",
            "tool": "schemathesis", "safety": "intrusive", "needs": "url",
            "args": ["schemathesis", "run", "{url}", "--checks", "all",
                     "--hypothesis-max-examples", "50", "{extra}"],
            "hit": [r"\bFAILED\b", r"\b5\d\d\b", r"server error", r"Undocumented"],
            "severity": "medium",
            "desc": "Property-based fuzzing of an OpenAPI/Swagger schema (OWASP API fuzzing).",
        },
    ],
    "network": [
        {
            "id": "nmap_fuzz_scripts", "label": "nmap — service fuzz/abuse NSE",
            "tool": "nmap", "safety": "intrusive", "needs": "hostport",
            "args": ["nmap", "-sV", "-p", "{port}", "--script",
                     "fuzzer,*-brute and not dos", "{host}", "{extra}"],
            "hit": [r"\bVULNERABLE\b", r"\bLikely\b", r"valid\s+credentials"],
            "severity": "medium",
            "desc": "Run non-DoS NSE fuzz/abuse scripts on a port.",
        },
        {
            "id": "tlsfuzz", "label": "testssl — TLS edge-case probing",
            "tool": "testssl.sh", "safety": "safe", "needs": "hostport",
            "args": ["testssl.sh", "--fast", "--warnings", "off",
                     "{host}:{port}", "{extra}"],
            "hit": [r"\b(VULNERABLE|NOT ok|insecure)\b"],
            "severity": "medium",
            "desc": "Probe the TLS stack for weak/edge-case handling.",
        },
    ],
    "iot": [
        {
            "id": "mqtt_fuzz", "label": "mosquitto — MQTT topic probing",
            "tool": "mosquitto_sub", "safety": "intrusive", "needs": "hostport",
            "args": ["mosquitto_sub", "-h", "{host}", "-p", "{port}",
                     "-t", "#", "-v", "-W", "15", "{extra}"],
            "hit": [r"\S+\s+\S+"],
            "severity": "medium",
            "desc": "Subscribe to all MQTT topics to surface exposed data.",
        },
        {
            "id": "coap_fuzz", "label": "nmap — CoAP/IoT resource probe",
            "tool": "nmap", "safety": "intrusive", "needs": "hostport",
            "args": ["nmap", "-sU", "-p", "{port}", "--script",
                     "coap-resources", "{host}", "{extra}"],
            "hit": [r"resource", r"\bopen\b"],
            "severity": "low",
            "desc": "Enumerate CoAP resources on a UDP IoT endpoint.",
        },
    ],
    "ot": [
        {
            # READ-ONLY by default — OT is fragile.  Marked dangerous so the UI
            # warns; the human's Start press is the explicit authorization.
            "id": "modbus_enum", "label": "modbus — register enumeration (read-only)",
            "tool": "nmap", "safety": "dangerous", "needs": "hostport",
            "args": ["nmap", "-p", "{port}", "--script",
                     "modbus-discover", "{host}", "{extra}"],
            "hit": [r"modbus", r"\bSlave ID\b", r"\bdevice\b"],
            "severity": "high",
            "desc": "Read-only Modbus unit-id / device enumeration. Fragile OT — handle with care.",
        },
        {
            "id": "s7_enum", "label": "nmap — S7 PLC identification (read-only)",
            "tool": "nmap", "safety": "dangerous", "needs": "hostport",
            "args": ["nmap", "-p", "{port}", "--script", "s7-info",
                     "{host}", "{extra}"],
            "hit": [r"\bModule\b", r"\bS7\b", r"\bPLC\b", r"Serial"],
            "severity": "high",
            "desc": "Identify a Siemens S7 PLC (read-only). Fragile OT.",
        },
    ],
}

# Sensible per-type default config the UI pre-fills (human can override).
_DEFAULT_CONFIG: Dict[str, Dict[str, Any]] = {
    "web":     {"threads": 40, "rate": 200, "iters": 200,
                "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"},
    "api":     {"threads": 40, "rate": 200, "iters": 200,
                "wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"},
    "network": {"threads": 10, "rate": 100, "iters": 100, "wordlist": ""},
    "iot":     {"threads": 10, "rate": 50,  "iters": 100, "wordlist": ""},
    "ot":      {"threads": 1,  "rate": 10,  "iters": 20,  "wordlist": ""},
}

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def tech_types() -> List[str]:
    """Ordered tech types the lab supports."""
    return list(CATALOG.keys())


def fuzzers_for(tech_type: str) -> List[Dict[str, Any]]:
    """Picker-shaped fuzzer list for a tech type (catalog minus internals),
    annotated with whether the tool is installed on this box."""
    out: List[Dict[str, Any]] = []
    for spec in CATALOG.get(tech_type, []):
        out.append({
            "id":        spec["id"],
            "label":     spec["label"],
            "tool":      spec["tool"],
            "safety":    spec["safety"],
            "needs":     spec["needs"],
            "severity":  spec["severity"],
            "desc":      spec["desc"],
            "installed": bool(shutil.which(spec["tool"].split("/")[-1])
                              or shutil.which(spec["tool"])),
            "default_config": _DEFAULT_CONFIG.get(tech_type, {}),
        })
    return out


def _spec_for(tech_type: str, fuzzer_id: str) -> Optional[Dict[str, Any]]:
    for spec in CATALOG.get(tech_type, []):
        if spec["id"] == fuzzer_id:
            return spec
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Scope derivation — the lab may only touch hosts ARGUS already identified.
# ──────────────────────────────────────────────────────────────────────────────
def _is_ipish(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s or ""))


def scope_for_agent(agent: Any) -> Dict[str, Any]:
    """Derive the in-scope fuzz targets from a live session's agent.

    Works for both the single-host ``MasterAgent`` (``_intel``) and the
    multi-host ``CIDROrchestrator`` (per-host masters / host list).  Returns
    ``{"hosts": [{host, url, ports:[{port,service}], label}], "count": n}``.
    Best-effort and defensive — an unknown agent shape yields an empty scope
    rather than raising.
    """
    hosts: Dict[str, Dict[str, Any]] = {}

    def _ingest_intel(intel: Dict[str, Any]) -> None:
        if not isinstance(intel, dict):
            return
        cands: List[str] = []
        for k in ("target_host", "target", "target_resolved_ip"):
            v = intel.get(k)
            if isinstance(v, str) and v.strip():
                cands.append(v.strip())
        for v in (intel.get("target_scope") or []):
            if isinstance(v, str) and v.strip():
                cands.append(v.strip())
        for v in (intel.get("hostnames") or []):
            if isinstance(v, str) and v.strip():
                cands.append(v.strip())
        url = intel.get("target_url")
        for h in cands:
            row = hosts.setdefault(h, {"host": h, "url": "", "ports": [], "label": h})
            if url and not row["url"]:
                row["url"] = url
        primary = (intel.get("target_host") or intel.get("target") or "").strip()
        services = intel.get("services") or {}
        if isinstance(services, dict) and primary:
            row = hosts.setdefault(primary, {"host": primary, "url": url or "",
                                             "ports": [], "label": primary})
            seen = {p.get("port") for p in row["ports"]}
            for port, svc in services.items():
                try:
                    pn = int(port)
                except Exception:
                    continue
                if pn in seen:
                    continue
                seen.add(pn)
                sname = (svc or {}).get("service") if isinstance(svc, dict) else ""
                row["ports"].append({"port": pn, "service": sname or ""})

    intel = getattr(agent, "_intel", None)
    if isinstance(intel, dict):
        _ingest_intel(intel)

    for attr in ("_host_masters", "host_masters", "_masters", "_hosts", "hosts",
                 "_host_data", "host_data", "_live_hosts", "live_hosts"):
        coll = getattr(agent, attr, None)
        if isinstance(coll, dict):
            for key, val in coll.items():
                sub_intel = getattr(val, "_intel", None)
                if isinstance(sub_intel, dict):
                    _ingest_intel(sub_intel)
                elif isinstance(val, dict) and "intel" in val:
                    _ingest_intel(val["intel"])
                elif isinstance(key, str) and (_is_ipish(key) or "." in key):
                    hosts.setdefault(key, {"host": key, "url": "", "ports": [], "label": key})
        elif isinstance(coll, (list, tuple)):
            for val in coll:
                if isinstance(val, str) and val.strip():
                    hosts.setdefault(val, {"host": val, "url": "", "ports": [], "label": val})
                else:
                    sub_intel = getattr(val, "_intel", None)
                    if isinstance(sub_intel, dict):
                        _ingest_intel(sub_intel)

    out = sorted(hosts.values(), key=lambda r: r["host"])
    return {"hosts": out, "count": len(out)}


def _host_in_scope(scope: Dict[str, Any], host: str) -> bool:
    if not host:
        return False
    h = host.strip().lower()
    m = re.search(r"://([^/:]+)", host)
    h_url = m.group(1).lower() if m else None
    for row in scope.get("hosts", []):
        rh = (row.get("host") or "").lower()
        if not rh:
            continue
        if h == rh or h == rh.split("://")[-1]:
            return True
        if h_url and h_url == rh:
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# The lab
# ──────────────────────────────────────────────────────────────────────────────
class FuzzLab:
    """One human-launched fuzzing run.  Streams ``fuzz_status`` / ``fuzz_result``
    via ``emit`` and pushes interesting hits to ``on_finding``.  Non-blocking:
    drive it with ``await run()`` inside its own task."""

    def __init__(self, *, job_id: str, session_id: str, target: str,
                 tech_type: str, fuzzer_id: str, config: Dict[str, Any],
                 emit: Callable[[str, Dict[str, Any]], Any],
                 on_finding: Optional[Callable[[Dict[str, Any]], Any]] = None,
                 feedback: bool = True):
        self.job_id      = job_id
        self.session_id  = session_id
        self.target      = (target or "").strip()
        self.tech_type   = tech_type
        self.fuzzer_id   = fuzzer_id
        self.config      = dict(config or {})
        self._emit_cb    = emit
        self._on_finding = on_finding
        self.feedback    = bool(feedback)
        self.status      = "queued"
        self.started     = 0.0
        self.hits        = 0
        self.lines       = 0
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._stop       = False
        self._spec       = _spec_for(tech_type, fuzzer_id)

    async def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        try:
            res = self._emit_cb(event, {"job_id": self.job_id,
                                        "session_id": self.session_id, **payload})
            if asyncio.iscoroutine(res):
                await res
        except Exception:
            pass

    def _host_part(self) -> str:
        m = re.search(r"://([^/:]+)", self.target)
        if m:
            return m.group(1)
        return re.sub(r":\d+$", "", self.target.split("/")[0])

    def _url_part(self) -> str:
        if self.target.startswith(("http://", "https://")):
            return self.target.rstrip("/")
        port = str(self.config.get("port") or "")
        scheme = "https" if port in ("443", "8443") else "http"
        host = self._host_part()
        return f"{scheme}://{host}" + (f":{port}" if port and port not in ("80", "443") else "")

    def _build_argv(self) -> List[str]:
        spec = self._spec
        cfg  = self.config
        repl = {
            "url":      self._url_part(),
            "host":     self._host_part(),
            "port":     str(cfg.get("port") or ""),
            "wordlist": str(cfg.get("wordlist") or _DEFAULT_CONFIG.get(self.tech_type, {}).get("wordlist", "")),
            "threads":  str(cfg.get("threads") or _DEFAULT_CONFIG.get(self.tech_type, {}).get("threads", 10)),
            "rate":     str(cfg.get("rate") or _DEFAULT_CONFIG.get(self.tech_type, {}).get("rate", 50)),
            "iters":    str(cfg.get("iters") or _DEFAULT_CONFIG.get(self.tech_type, {}).get("iters", 50)),
        }
        extra_raw = str(cfg.get("extra") or "").strip()
        extra_tokens = shlex.split(extra_raw) if extra_raw else []
        argv: List[str] = []
        for tok in spec["args"]:
            if tok == "{extra}":
                argv.extend(extra_tokens)
                continue
            filled = tok
            for k, v in repl.items():
                filled = filled.replace("{" + k + "}", v)
            if filled == "" and tok != "":
                continue
            argv.append(filled)
        return argv

    def _validate(self, scope: Dict[str, Any]) -> Optional[str]:
        if self._spec is None:
            return f"unknown fuzzer '{self.fuzzer_id}' for tech '{self.tech_type}'"
        if not self.target:
            return "no target specified"
        if not _host_in_scope(scope, self.target):
            return (f"target '{self.target}' is not in the engagement scope — "
                    "the fuzzer may only touch hosts ARGUS has identified")
        needs = self._spec.get("needs")
        if needs == "hostport" and not str(self.config.get("port") or "").strip():
            return "this fuzzer needs a port; none was provided"
        tool = self._spec["tool"]
        if not (shutil.which(tool.split("/")[-1]) or shutil.which(tool)):
            return f"tool '{tool}' is not installed on this host"
        return None

    async def _handle_line(self, line: str) -> None:
        self.lines += 1
        if self.lines > _MAX_RESULT_LINES:
            return
        spec = self._spec
        is_hit = any(re.search(p, line, re.IGNORECASE) for p in (spec.get("hit") or []))
        await self._emit("fuzz_result", {"line": line[:600], "hit": is_hit, "n": self.lines})
        if is_hit:
            self.hits += 1
            await self._record_hit(line)

    async def _record_hit(self, line: str) -> None:
        spec = self._spec
        sev  = spec.get("severity", "info")
        finding = {
            "title":       f"Fuzzing hit ({self.tech_type}/{self.fuzzer_id})",
            "description": (f"Human-driven fuzzing with {spec['label']} surfaced an "
                            f"interesting response on {self.target}: {line.strip()[:300]}"),
            "severity":    sev,
            "host":        self._host_part(),
            "port":        (int(self.config["port"]) if str(self.config.get("port") or "").isdigit() else None),
            "service":     self.tech_type,
            "tool_used":   spec["tool"],
            "raw_output":  line.strip()[:600],
            "evidence":    line.strip()[:300],
            "source":      "fuzzing_lab",
            "tech_type":   self.tech_type,
            "fuzzer_id":   self.fuzzer_id,
            "job_id":      self.job_id,
        }
        await self._emit("fuzz_finding", finding)
        if self.feedback and self._on_finding:
            try:
                res = self._on_finding(finding)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as exc:        # pragma: no cover
                logger.debug("fuzz feedback failed: %s", exc)

    async def run(self, scope: Dict[str, Any]) -> None:
        self.started = time.time()
        err = self._validate(scope)
        if err:
            self.status = "error"
            await self._emit("fuzz_status", {"status": "error", "message": err,
                                             "tech_type": self.tech_type,
                                             "fuzzer_id": self.fuzzer_id,
                                             "target": self.target})
            return

        argv = self._build_argv()
        self.status = "running"
        await self._emit("fuzz_status", {
            "status": "running", "target": self.target, "tech_type": self.tech_type,
            "fuzzer_id": self.fuzzer_id, "safety": self._spec.get("safety"),
            "command": " ".join(argv), "feedback": self.feedback,
            "message": f"Fuzzing {self.target} with {self._spec['label']}",
        })
        max_sec = int(self.config.get("max_sec") or _DEFAULT_MAX_SEC)
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
        except FileNotFoundError:
            self.status = "error"
            await self._emit("fuzz_status", {"status": "error",
                                             "message": f"binary not found: {argv[0]}"})
            return
        except Exception as exc:
            self.status = "error"
            await self._emit("fuzz_status", {"status": "error", "message": str(exc)})
            return

        async def _pump() -> None:
            assert self._proc and self._proc.stdout
            while True:
                raw = await self._proc.stdout.readline()
                if not raw or self._stop:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if line.strip():
                    await self._handle_line(line)

        try:
            await asyncio.wait_for(_pump(), timeout=max_sec)
        except asyncio.TimeoutError:
            await self._emit("fuzz_status", {"status": "running",
                                             "message": f"time cap {max_sec}s reached — stopping"})
            self._stop = True
        finally:
            await self._terminate()

        if self.status != "error":
            self.status = "stopped" if self._stop else "completed"
        await self._emit("fuzz_status", {
            "status": self.status, "target": self.target,
            "hits": self.hits, "lines": self.lines,
            "elapsed": round(time.time() - self.started, 1),
            "message": (f"Fuzzing finished — {self.hits} interesting hit(s) "
                        f"in {self.lines} responses"),
        })

    async def _terminate(self) -> None:
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass

    def stop(self) -> None:
        self._stop = True
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def snapshot(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id, "session_id": self.session_id,
            "target": self.target, "tech_type": self.tech_type,
            "fuzzer_id": self.fuzzer_id, "status": self.status,
            "hits": self.hits, "lines": self.lines, "feedback": self.feedback,
            "elapsed": round(time.time() - self.started, 1) if self.started else 0,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Registry — one lab per job_id, many per session, all parallel.
# ──────────────────────────────────────────────────────────────────────────────
_LABS: Dict[str, FuzzLab] = {}


def start_lab(lab: FuzzLab, scope: Dict[str, Any]) -> asyncio.Task:
    """Register + launch a lab as its own task (parallel to the engagement)."""
    _LABS[lab.job_id] = lab
    return asyncio.create_task(lab.run(scope))


def get_lab(job_id: str) -> Optional[FuzzLab]:
    return _LABS.get(job_id)


def stop_lab(job_id: str) -> bool:
    lab = _LABS.get(job_id)
    if lab is None:
        return False
    lab.stop()
    return True


def list_labs(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return [l.snapshot() for l in _LABS.values()
            if session_id is None or l.session_id == session_id]
