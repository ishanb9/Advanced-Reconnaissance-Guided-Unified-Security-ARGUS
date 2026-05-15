"""
agents/playbook/engine.py - deterministic playbook runner.

Why this exists
---------------
Without playbooks, ARGUS asks the LLM to plan every recon -> exploit
chain from scratch.  That costs 30-500 seconds of model latency per
phase boundary, and the LLM has to re-derive a chain it has seen 1,000
times.  When MinIO appears on port 54321, there is exactly one correct
opening move (anonymous bucket listing + default-cred login + recent
CVE check); paying an LLM to "discover" it each time is waste.

Playbooks encode those known-good chains as YAML so a single trigger
match can fire the right sequence in <1 second.  The LLM stays
available for the genuinely novel parts of an engagement.

Schema (knowledge/data/playbooks/*.yml)
---------------------------------------
    id: minio_anonymous
    name: "MinIO anonymous access enumeration"
    description: |
      MinIO instances exposed without auth allow anonymous bucket
      listing and frequently ship with default credentials.
    severity_floor: MEDIUM         # min severity for any finding here
    tags: [storage, default-cred, exposed-service]
    mitre: [T1078, T1592]

    trigger:                       # ANY of these matches triggers
      services:
        - port: 9000               # default MinIO port
        - banner_contains: ["MinIO"]
        - service_name_contains: ["minio"]
      findings:
        - title_contains: ["MinIO"]
      cves: []                     # optional CVE list

    steps:
      - name: anonymous_bucket_listing
        tool: curl
        args:
          - "-s"
          - "{url}/?list-type=2"
        success:                   # any/all of these = success
          stdout_contains: ["ListBucketResult"]
        on_success:
          finding:
            title: "MinIO anonymous bucket listing"
            severity: HIGH
            description: "Bucket can be listed without authentication."

      - name: try_default_creds
        tool: curl
        args:
          - "-s"
          - "-X" "POST"
          - "{url}/minio/admin/v3/info"
          - "-H" "Authorization: AWS4-..."  # operator-tweakable
        success:
          stdout_contains: ["servers"]
        on_success:
          finding:
            title: "MinIO default credentials (minioadmin/minioadmin)"
            severity: CRITICAL

Execution model
---------------
1. PlaybookEngine.match(intel) -> list[(Playbook, score)]
2. For each match, PlaybookEngine.run(pb, target, run_tool=...) yields
   findings.  `run_tool` is a coroutine the caller injects so the
   engine stays transport-agnostic (same engine works for MCP, local
   subprocess, or unit-test mock).
3. Step variables (`{url}`, `{host}`, `{port}`, `{path}`) are
   string-substituted from the trigger context.  No code execution,
   no shell expansion - just template fills.

Safety
------
- Steps are READ-MOSTLY by design: enumeration, auth checks, info
  disclosure.  Exploit primitives belong in a separate "offensive"
  playbook set that requires operator confirmation.
- Each step has a hard timeout (default 60s).
- The engine NEVER concatenates user data into a shell command;
  args are always passed as a list to the caller's run_tool().
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── Data model ──────────────────────────────────────────────────────────

@dataclass
class PlaybookStep:
    name:        str
    tool:        str
    args:        List[str] = field(default_factory=list)
    timeout:     int       = 60
    success:     Dict[str, Any] = field(default_factory=dict)
    on_success:  Dict[str, Any] = field(default_factory=dict)
    on_failure:  Dict[str, Any] = field(default_factory=dict)
    optional:    bool      = False                       # don't abort chain


@dataclass
class PlaybookTrigger:
    services:     List[Any]            = field(default_factory=list)
    findings:     List[Dict[str, Any]] = field(default_factory=list)
    cves:         List[str]            = field(default_factory=list)
    # Legacy schema (carried for backward compat with pre-engine playbooks):
    legacy_ports:        List[int] = field(default_factory=list)
    legacy_technologies: List[str] = field(default_factory=list)


@dataclass
class Playbook:
    id:              str
    name:            str
    description:     str
    severity_floor:  str
    tags:            List[str]
    mitre:           List[str]
    trigger:         PlaybookTrigger
    steps:           List[PlaybookStep]
    file_path:       str = ""


@dataclass
class PlaybookFinding:
    title:        str
    description:  str
    severity:     str
    evidence:     str = ""
    cve:          Optional[str] = None
    mitre:        Optional[str] = None
    host:         str = ""
    port:         Optional[int] = None
    playbook_id:  str = ""
    step_name:    str = ""


# ─── YAML loader ─────────────────────────────────────────────────────────

def _load_yaml_file(path: Path) -> Optional[Playbook]:
    """Parse one YAML file into a Playbook.  Returns None on schema mismatch."""
    try:
        import yaml
    except ImportError:
        logger.error("[playbook] PyYAML not installed - cannot load %s", path)
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception as exc:
        logger.warning("[playbook] failed to load %s: %s", path, exc)
        return None

    if not isinstance(doc, dict):
        return None
    # Required keys
    if not all(k in doc for k in ("id", "trigger", "steps")):
        return None

    trig_raw = doc.get("trigger") or {}
    # Legacy ports may be top-level under trigger (older schema):
    _legacy_ports: List[int] = []
    for p in (trig_raw.get("ports") or []):
        try:
            _legacy_ports.append(int(p))
        except (TypeError, ValueError):
            pass
    trigger = PlaybookTrigger(
        services            = list(trig_raw.get("services") or []),
        findings            = list(trig_raw.get("findings") or []),
        cves                = [str(c) for c in (trig_raw.get("cves") or [])],
        legacy_ports        = _legacy_ports,
        legacy_technologies = [str(t).lower() for t in (trig_raw.get("technologies") or [])],
    )

    steps: List[PlaybookStep] = []
    for s_raw in (doc.get("steps") or []):
        if not isinstance(s_raw, dict):
            continue
        steps.append(PlaybookStep(
            name       = str(s_raw.get("name") or "anonymous"),
            tool       = str(s_raw.get("tool") or ""),
            args       = [str(a) for a in (s_raw.get("args") or [])],
            timeout    = int(s_raw.get("timeout") or 60),
            success    = s_raw.get("success") or {},
            on_success = s_raw.get("on_success") or {},
            on_failure = s_raw.get("on_failure") or {},
            optional   = bool(s_raw.get("optional", False)),
        ))

    return Playbook(
        id              = str(doc["id"]),
        name            = str(doc.get("name") or doc["id"]),
        description     = str(doc.get("description") or "").strip(),
        severity_floor  = str(doc.get("severity_floor") or "INFO").upper(),
        tags            = [str(t) for t in (doc.get("tags") or [])],
        mitre           = [str(m) for m in (doc.get("mitre") or [])],
        trigger         = trigger,
        steps           = steps,
        file_path       = str(path),
    )


# ─── Matcher ─────────────────────────────────────────────────────────────

def _match_service(svc: Dict[str, Any], rule: Any) -> bool:
    """Return True if a single service dict matches a single rule.

    Rule can be either:
      - a dict with `port`/`ports`/`banner_contains`/`service_name_contains`
      - a bare string treated as a service-name substring match
        (legacy playbook schema: `services: ["http","https"]`)

    Returns False for any non-dict, non-string rule (avoids the
    "every empty-rule passes" bug where missing-key checks all
    return False and the function falsely returns True).
    """
    # Legacy: bare string == service-name substring match
    if isinstance(rule, str):
        name = str(svc.get("service") or svc.get("name") or "").lower()
        return rule.lower() in name

    if not isinstance(rule, dict):
        return False

    # An empty dict rule should NOT match everything; require at least one check
    has_check = False

    if "port" in rule:
        has_check = True
        try:
            if int(svc.get("port") or -1) != int(rule["port"]):
                return False
        except (TypeError, ValueError):
            return False

    if "ports" in rule:
        has_check = True
        try:
            allowed = {int(p) for p in rule["ports"]}
            if int(svc.get("port") or -1) not in allowed:
                return False
        except (TypeError, ValueError):
            return False

    if "banner_contains" in rule:
        has_check = True
        banner = str(svc.get("banner") or svc.get("version") or "").lower()
        if not any(str(t).lower() in banner for t in rule["banner_contains"]):
            return False

    if "service_name_contains" in rule:
        has_check = True
        name = str(svc.get("service") or svc.get("name") or "").lower()
        if not any(str(t).lower() in name for t in rule["service_name_contains"]):
            return False

    return has_check


def _match_finding(found: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    if "title_contains" in rule:
        title = str(found.get("title") or "").lower()
        if not any(t.lower() in title for t in rule["title_contains"]):
            return False
    if "cve" in rule:
        if str(found.get("cve") or "").upper() != str(rule["cve"]).upper():
            return False
    return True


def match_playbook(pb: Playbook, intel: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the matched context dict (with port, url, etc.) or None.

    intel must look like:
        {
            "target": "10.0.0.1",
            "services": [{"port": 80, "service": "http", "banner": "..."}],
            "findings": [{"title": "...", "cve": "..."}],
            "cves": ["CVE-..."],
        }

    The first matching service rule's data is captured into the
    returned context so step templates can substitute {port}, {url}, etc.
    """
    target = str(intel.get("target") or "")
    services = list(intel.get("services") or [])
    findings = list(intel.get("findings") or [])
    cves     = [str(c).upper() for c in (intel.get("cves") or [])]

    # Detect legacy schema: if the playbook has top-level ports/technologies
    # under trigger AND the services list is bare strings, the AND-semantics
    # legacy path takes precedence.  Otherwise fall through to the new
    # dict-rule semantics below.
    is_legacy_schema = (
        bool(pb.trigger.legacy_ports or pb.trigger.legacy_technologies)
        and (not pb.trigger.services or
             all(isinstance(r, str) for r in pb.trigger.services))
    )
    if is_legacy_schema:
        # Require: at least one service on one of the listed ports AND
        # at least one technology keyword appears in the haystack.
        port_match_svc = None
        if pb.trigger.legacy_ports:
            for svc in services:
                try:
                    if int(svc.get("port") or -1) in pb.trigger.legacy_ports:
                        port_match_svc = svc
                        break
                except (TypeError, ValueError):
                    continue
        else:
            # No port constraint; use first http-ish service if any
            for svc in services:
                p = svc.get("port")
                if p in (80, 443, 8080, 8443, 8000) or "http" in str(svc.get("service") or "").lower():
                    port_match_svc = svc
                    break
        if port_match_svc is None:
            return None
        # Technology match — must be non-empty and present in haystack
        if pb.trigger.legacy_technologies:
            haystack_parts = []
            for svc in services:
                haystack_parts.append(str(svc.get("banner") or ""))
                haystack_parts.append(str(svc.get("service") or ""))
                haystack_parts.append(str(svc.get("version") or ""))
            for f in findings:
                haystack_parts.append(str(f.get("title") or ""))
                haystack_parts.append(str(f.get("description") or ""))
            haystack = " ".join(haystack_parts).lower()
            tech_hit = any(n in haystack for n in pb.trigger.legacy_technologies)
            if not tech_hit:
                # Also check CVE overlap as a soft tech signal
                if pb.trigger.cves:
                    cve_set = set(c.upper() for c in pb.trigger.cves)
                    if not (cve_set & set(cves)):
                        return None
                else:
                    return None
        port = port_match_svc.get("port")
        is_https = port in (443, 8443) or "https" in str(port_match_svc.get("service") or "").lower()
        scheme = "https" if is_https else "http"
        return {
            "host":   target, "target": target,
            "port":   str(port) if port is not None else "",
            "scheme": scheme,
            "url":    f"{scheme}://{target}" + (f":{port}" if port else ""),
            "base_url": f"{scheme}://{target}" + (f":{port}" if port else ""),
            "path":   "/",
            "matched_service": port_match_svc,
        }

    # 1) Service rules — first matching service wins, captures context
    for rule in pb.trigger.services:
        for svc in services:
            if _match_service(svc, rule):
                port = svc.get("port")
                is_https = (
                    "https" in str(svc.get("service") or "").lower()
                    or "ssl"  in str(svc.get("service") or "").lower()
                    or port in (443, 8443)
                )
                scheme = "https" if is_https else "http"
                ctx = {
                    "host":   target,
                    "port":   str(port) if port is not None else "",
                    "scheme": scheme,
                    "url":    f"{scheme}://{target}" + (f":{port}" if port else ""),
                    "path":   "/",
                    "matched_service": svc,
                }
                return ctx

    # 2) Finding rules
    for rule in pb.trigger.findings:
        for f in findings:
            if _match_finding(f, rule):
                port = f.get("port")
                ctx = {
                    "host":   target,
                    "port":   str(port) if port is not None else "",
                    "scheme": "http",
                    "url":    f"http://{target}" + (f":{port}" if port else ""),
                    "path":   "/",
                    "matched_finding": f,
                }
                return ctx

    # 3) CVE rules — bare list of CVE IDs that must be present in intel
    if pb.trigger.cves:
        cve_set = set(c.upper() for c in pb.trigger.cves)
        if cve_set & set(cves):
            return {
                "host":   target,
                "port":   "",
                "scheme": "http",
                "url":    f"http://{target}",
                "path":   "/",
                "matched_cves": list(cve_set & set(cves)),
            }
    return None


# ─── Template substitution ───────────────────────────────────────────────

_TEMPLATE_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _fill(template: str, ctx: Dict[str, Any]) -> str:
    """Replace {var} placeholders.  Missing keys become empty string."""
    def repl(m: "re.Match[str]") -> str:
        key = m.group(1)
        v = ctx.get(key)
        return "" if v is None else str(v)
    return _TEMPLATE_RE.sub(repl, template)


def _fill_args(args: List[str], ctx: Dict[str, Any]) -> List[str]:
    return [_fill(a, ctx) for a in args]


# ─── Success evaluation ──────────────────────────────────────────────────

def _eval_success(success_spec: Dict[str, Any], stdout: str, stderr: str,
                  exit_code: int) -> bool:
    """Return True iff ALL conditions in success_spec are met.

    Supported keys:
      stdout_contains: List[str]   - all substrings must be present
      stderr_contains: List[str]
      stdout_regex:    str         - matches anywhere
      exit_code:       int
      exit_in:         List[int]
    """
    if "stdout_contains" in success_spec:
        for s in success_spec["stdout_contains"]:
            if str(s).lower() not in stdout.lower():
                return False
    if "stderr_contains" in success_spec:
        for s in success_spec["stderr_contains"]:
            if str(s).lower() not in stderr.lower():
                return False
    if "stdout_regex" in success_spec:
        try:
            if not re.search(success_spec["stdout_regex"], stdout):
                return False
        except re.error:
            return False
    if "exit_code" in success_spec:
        try:
            if int(exit_code) != int(success_spec["exit_code"]):
                return False
        except (TypeError, ValueError):
            return False
    if "exit_in" in success_spec:
        try:
            allowed = {int(c) for c in success_spec["exit_in"]}
            if int(exit_code) not in allowed:
                return False
        except (TypeError, ValueError):
            return False
    # Default: exit 0 = success when no explicit spec
    if not success_spec:
        return exit_code == 0
    return True


def _build_finding(spec: Dict[str, Any], ctx: Dict[str, Any], pb: Playbook,
                   step_name: str, evidence: str) -> Optional[PlaybookFinding]:
    if not spec or not isinstance(spec, dict):
        return None
    title = _fill(str(spec.get("title") or pb.name), ctx)
    severity = str(spec.get("severity") or pb.severity_floor).upper()
    desc  = _fill(str(spec.get("description") or pb.description or ""), ctx)
    cve   = spec.get("cve") or None
    port = None
    try:
        port = int(ctx.get("port")) if ctx.get("port") else None
    except (TypeError, ValueError):
        port = None
    return PlaybookFinding(
        title       = title,
        description = desc,
        severity    = severity,
        evidence    = evidence[:800],
        cve         = str(cve) if cve else None,
        mitre       = (pb.mitre[0] if pb.mitre else None),
        host        = str(ctx.get("host") or ""),
        port        = port,
        playbook_id = pb.id,
        step_name   = step_name,
    )


# ─── Engine ──────────────────────────────────────────────────────────────

# Signature the caller's tool runner must satisfy.
# Returns: (exit_code, stdout, stderr)
ToolRunner = Callable[[str, List[str], int], Awaitable[Tuple[int, str, str]]]


class PlaybookEngine:
    """Loads .yml playbooks once, matches against intel, runs sequences.

    Playbooks are loaded from TWO locations (operator-data takes
    precedence when the same `id` appears in both):

      1. agents/playbook/templates/    — shipped with ARGUS, version-controlled
      2. knowledge/data/playbooks/     — operator-curated, .gitignore'd

    This split lets the platform ship a baseline set of high-quality
    playbooks without conflicting with whatever the operator has tuned
    locally.  An operator override has the same `id:` as the shipped
    playbook and replaces it entirely (no merging).
    """

    def __init__(self, playbook_dirs: Optional[List[Path]] = None):
        repo_root = Path(__file__).resolve().parent.parent.parent
        if playbook_dirs is None:
            playbook_dirs = [
                Path(__file__).resolve().parent / "templates",          # shipped
                repo_root / "knowledge" / "data" / "playbooks",         # operator
            ]
        self.dirs: List[Path] = playbook_dirs
        self.playbooks: List[Playbook] = []
        self._loaded: bool = False

    def load(self) -> int:
        """Load *.yml/*.yaml from every dir in self.dirs.

        Operator-data dir (last in self.dirs) takes precedence when a
        playbook id collides.  Returns count loaded.
        """
        self.playbooks = []
        by_id: Dict[str, Playbook] = {}
        for d in self.dirs:
            if not d.exists():
                logger.debug("[playbook] dir %s missing; skipping", d)
                continue
            for path in sorted(d.rglob("*.y*ml")):
                pb = _load_yaml_file(path)
                if pb is None:
                    continue
                # Later dirs override earlier ones on id collision
                by_id[pb.id] = pb
        self.playbooks = list(by_id.values())
        self._loaded = True
        logger.info("[playbook] loaded %d playbooks from %d dir(s)",
                    len(self.playbooks), len(self.dirs))
        return len(self.playbooks)

    def match(self, intel: Dict[str, Any]) -> List[Tuple[Playbook, Dict[str, Any]]]:
        """Return list of (playbook, context) pairs that match."""
        if not self._loaded:
            self.load()
        matched: List[Tuple[Playbook, Dict[str, Any]]] = []
        for pb in self.playbooks:
            ctx = match_playbook(pb, intel)
            if ctx is not None:
                matched.append((pb, ctx))
        return matched

    async def run(self, pb: Playbook, ctx: Dict[str, Any],
                  tool_runner: ToolRunner,
                  on_event: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
                  ) -> List[PlaybookFinding]:
        """Execute a playbook against a target.

        tool_runner: async fn(tool_name, args, timeout) -> (exit, stdout, stderr).
                     Caller picks the transport (MCP, local subprocess, mock).
        on_event:    optional async fn(event_type, data) for UI streaming.
                     Event types: playbook_start, playbook_step, playbook_finding,
                                  playbook_complete.

        Returns the list of findings produced by this run.
        """
        findings: List[PlaybookFinding] = []
        start = time.monotonic()

        async def emit(et: str, data: Dict[str, Any]) -> None:
            if on_event is None:
                return
            try:
                await on_event(et, data)
            except Exception:
                pass

        await emit("playbook_start", {
            "id": pb.id, "name": pb.name, "host": ctx.get("host"),
            "port": ctx.get("port"), "step_count": len(pb.steps),
        })

        for step in pb.steps:
            step_args = _fill_args(step.args, ctx)
            await emit("playbook_step", {
                "playbook": pb.id, "step": step.name, "tool": step.tool,
                "args_preview": " ".join(step_args)[:200],
            })
            try:
                exit_code, stdout, stderr = await tool_runner(
                    step.tool, step_args, step.timeout,
                )
            except asyncio.TimeoutError:
                logger.info("[playbook] %s/%s timed out", pb.id, step.name)
                exit_code, stdout, stderr = -1, "", "TIMEOUT"
            except Exception as exc:
                logger.warning("[playbook] %s/%s tool error: %s",
                               pb.id, step.name, exc)
                exit_code, stdout, stderr = -1, "", str(exc)

            ok = _eval_success(step.success, stdout, stderr, exit_code)
            spec = step.on_success if ok else step.on_failure
            evidence = (stdout[:400] + ("..." if len(stdout) > 400 else ""))
            finding = _build_finding(spec, ctx, pb, step.name, evidence)
            if finding is not None:
                findings.append(finding)
                await emit("playbook_finding", finding.__dict__)

            # If step failed and is non-optional + has no on_failure spec,
            # stop the chain — subsequent steps probably depend on this one.
            if not ok and not step.optional and not step.on_failure:
                logger.info("[playbook] %s aborting at %s (no on_failure spec)",
                            pb.id, step.name)
                break

        await emit("playbook_complete", {
            "id": pb.id, "duration": round(time.monotonic() - start, 2),
            "findings": len(findings),
        })
        return findings


# ─── Singleton helper ────────────────────────────────────────────────────

_ENGINE: Optional[PlaybookEngine] = None


def get_engine() -> PlaybookEngine:
    """Lazy-singleton accessor.  Loads playbooks on first call."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = PlaybookEngine()
        try:
            _ENGINE.load()
        except Exception as exc:
            logger.warning("[playbook] engine load failed: %s", exc)
    return _ENGINE
