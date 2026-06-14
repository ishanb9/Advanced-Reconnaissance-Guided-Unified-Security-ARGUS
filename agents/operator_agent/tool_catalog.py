"""
tool_catalog.py — the operator's toolbelt + system-prompt builder.

Two responsibilities, both pure data/strings (no I/O), so they are trivially
testable:

  1. TOOLS — declarative spec of every action the operator can take.  The
     operator does NOT pick from a primer menu; it freely composes the args.
     run_tool/http/shell are the primitives that can do anything; the rest are
     convenience macros over existing ARGUS phases.

  2. build_system_prompt(...) — assembles the system message that makes the LLM
     behave like a real operator (Claude Code), NOT a phase-planner.  Three
     things matter here and are deliberate:
       • FRAMING — honest "authorized, isolated lab/CTF range" context.  An
         aggressive weaponization framing makes aligned models REFUSE (this is
         exactly what knocked the AttackGraph agent offline).  Mirrors the
         framing fix already proven in exploit_synth_subagent.
       • METHODOLOGY — the behaviours that won SmartHire and that the legacy
         pipeline structurally could not do: understand the app first; do
         authenticated, stateful interaction; pivot on discovered vhosts/
         services; form ONE exploit hypothesis and chase it to a verified
         foothold; then privesc.  Keep everything you learn in working memory.
       • PROTOCOL — strict text-ReAct so the loop can parse exactly one action
         per turn.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


# ── Toolbelt ────────────────────────────────────────────────────────────────

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "run_tool",
        "args": {"tool": "str", "args": "str", "timeout": "int(optional)"},
        "doc": ("Run ANY tool on the attacker host (the same Kali box, full "
                "toolset + MCP): nmap, rustscan, gobuster, feroxbuster, ffuf, "
                "nuclei, nikto, sqlmap, searchsploit, hydra, nc/ncat, python3, "
                "curl, openssl, ssh, smbclient, etc.  `args` is the full "
                "command-line argument string (no leading tool name).  Use for "
                "scanning, fuzzing, and for running attacker-side scripts/"
                "payload servers."),
    },
    {
        "name": "http",
        "args": {"method": "str", "url": "str", "headers": "obj(optional)",
                 "data": "obj/str(optional)", "json": "obj(optional)",
                 "params": "obj(optional)", "host": "str(optional vhost Host header)"},
        "doc": ("STATEFUL HTTP request.  Cookies/auth persist across every http "
                "call this engagement — this is your browser.  Use it to fetch "
                "pages, register, log in, navigate authenticated areas, submit "
                "forms, upload files, and probe APIs.  Set `host` to reach a "
                "vhost (e.g. models.smarthire.htb) over http without an "
                "/etc/hosts entry.  The response you get back includes status, "
                "title, discovered FORMS (with field names) and CSRF tokens, "
                "links, cookies, and the body — read it."),
    },
    {
        "name": "submit_form",
        "args": {"page_url": "str", "fields": "obj", "action": "str(optional)",
                 "method": "str(optional, default POST)", "host": "str(optional)"},
        "doc": ("Fetch a page, auto-merge its form defaults + CSRF token with "
                "your `fields`, and submit — the register/login primitive.  "
                "Cookies persist, so a successful login authenticates all "
                "subsequent http calls."),
    },
    {
        "name": "shell",
        "args": {"cmd": "str", "timeout": "int(optional)"},
        "doc": ("Run a command INSIDE the active shell on the TARGET (only "
                "valid after you have a foothold/reverse shell).  Use for "
                "post-exploitation: id, enumeration, reading flags, privesc."),
    },
    {
        "name": "recon",
        "args": {"focus": "str(optional)"},
        "doc": "Macro: run ARGUS recon (port/service scan + enumeration) and return a summary.",
    },
    {
        "name": "web_enum",
        "args": {"url": "str(optional)"},
        "doc": "Macro: run ARGUS web content + vhost enumeration and return a summary.",
    },
    {
        "name": "cve_lookup",
        "args": {"product": "str", "version": "str(optional)"},
        "doc": ("Find KNOWN CVEs + PUBLIC PoC/exploit repos for a product (NVD + "
                "GitHub repo search + searchsploit). THE reflex for any versioned "
                "framework/CMS/service — call it with the exact product name and "
                "version you fingerprinted. Returns CVE IDs with severity AND "
                "GitHub repo URLs you can git clone and run. Use it BEFORE "
                "hand-rolling endpoint enumeration."),
    },
    {
        "name": "run_playbook",
        "args": {"name": "str"},
        "doc": "Macro: run a named ARGUS playbook (a reusable exploitation recipe).",
    },
    {
        "name": "dispatch",
        "args": {"tasks": "list of {tool, args}"},
        "doc": ("Run several INDEPENDENT actions IN PARALLEL — fan agents out at "
                "once (e.g. enumerate the web app WHILE running a CVE PoC WHILE "
                "probing another service). args.tasks is a list of normal "
                "{\"tool\":…,\"args\":{…}} actions; they execute concurrently and "
                "their results merge back into intel. Use this to pursue the "
                "objective and secondary coverage at the same time instead of one "
                "slow action at a time."),
    },
    {
        "name": "note",
        "args": {"text": "str", "kind": "str(optional: finding|cred|vuln|info)"},
        "doc": ("Record a finding/observation/credential to the engagement "
                "intel so it shows in the GUI and the report.  Use it whenever "
                "you learn something that matters (a vhost, a cred, the app's "
                "purpose, a vuln)."),
    },
    {
        "name": "submit_flag",
        "args": {"flag": "str", "which": "str(optional: user|root)"},
        "doc": "Record a captured flag (user.txt / root.txt) — a primary objective.",
    },
    {
        "name": "listener",
        "args": {"port": "int(optional, default 4444)", "lhost": "str(optional)"},
        "doc": ("Open a PERSISTENT reverse-shell / callback listener managed by the "
                "platform — it SURVIVES across actions and auto-registers the shell "
                "that connects back. This is how you CATCH a callback from a blind "
                "RCE: call `listener`, then fire a reverse-shell payload through "
                "your RCE primitive (web injection / command-exec). NEVER hand-roll "
                "`nc -lvnp` inside a bash/run_tool call — the harness kills a "
                "backgrounded listener the instant the call returns, so the shell "
                "is never caught. Returns LHOST/LPORT + a ready-to-fire payload."),
    },
    {
        "name": "handover",
        "args": {"method": "str(optional: ssh|revshell|info)", "note": "str(optional)"},
        "doc": ("Hand the live foothold to the HUMAN operator. Registers the "
                "session in the Shell Manager and emits the exact access method "
                "(SSH creds if recovered, or a reverse-shell one-liner to run "
                "through your RCE). Use once you have a stable foothold and the "
                "objective is to give the operator an interactive shell."),
    },
    {
        "name": "loot_hunt",
        "args": {"scope": "str(optional: creds|keys|configs|flags|all)"},
        "doc": ("Sweep the compromised host for loot through your shell/RCE: SSH "
                "keys, password/shadow files, .env & config secrets, database "
                "files, shell history, and flags. Records what it finds as "
                "findings. Use after a foothold when the objective is to collect "
                "loot rather than (or in addition to) flags."),
    },
    {
        "name": "done",
        "args": {"summary": "str"},
        "doc": "End the engagement.  Use ONLY when objectives are met or you are truly out of avenues.",
    },
]

# Tools that mutate the target / are intrusive enough to require the one-time
# approve-to-exploit gate when autonomy == "approve_to_exploit".  Recon, http
# GETs, enumeration and notes are NOT intrusive.  An http POST that delivers a
# payload IS — but we can't know that statically, so intrusiveness for http is
# decided dynamically by the operator core (see _is_intrusive).
INTRUSIVE_TOOLS = {"shell", "run_playbook"}


def render_tool_docs() -> str:
    lines = []
    for t in TOOLS:
        sig = ", ".join(f"{k}: {v}" for k, v in t["args"].items())
        lines.append(f"- {t['name']}({sig})\n    {t['doc']}")
    return "\n".join(lines)


# ── The text-ReAct protocol ─────────────────────────────────────────────────

PROTOCOL = """\
HOW TO ACT — every reply MUST be exactly:

THOUGHT: <1-4 sentences: what the last observation told you, and what you will
do next and why. Reference concrete facts you have learned.>
```action
{"tool": "<tool name>", "args": { ... }}
```

Rules:
- EXACTLY ONE action block per reply, as valid JSON, fenced with ```action.
- Do not narrate more than the THOUGHT. No markdown headers, no bullet lists.
- Read each observation fully before deciding the next action.
- You keep full memory of this conversation — never re-discover what you already
  know. If you found a vhost, a form, a credential, or the app's purpose, USE it.
- When you achieve a flag, immediately submit_flag, then continue to the next
  objective (e.g. user.txt -> escalate to root.txt).
- KEEP SHELL COMMANDS SIMPLE. Your action is JSON, so nested double-quotes and
  heredocs break ("Unterminated quoted string"). Prefer ONE short command with
  simple single-quotes; to run a cloned exploit, invoke it DIRECTLY (e.g.
  `python3 /tmp/<poc>/exploit.py -u http://TARGET:PORT -c id`) instead of wrapping
  it in a multi-line bash heredoc. If a command errors on quoting twice, simplify
  it — do not keep escalating the escaping.
- TO CATCH A REVERSE SHELL OR ANY CALLBACK, use the `listener` tool — NEVER
  `nc -lvnp` (or socat) inside a bash/run_tool call. A backgrounded listener
  started in a tool call is KILLED the instant the call returns (exit -15), so
  the shell never connects. The `listener` tool opens a PERSISTENT listener that
  survives across actions and auto-registers the caught shell. Pattern: (1) call
  `listener`, (2) fire the reverse-shell payload it returns through your RCE,
  (3) the shell registers on its own. If your RCE returns command output inline,
  you often do not need a reverse shell at all — just read the flag through it.
- Call done ONLY when objectives are met or all realistic avenues are exhausted.
"""


# ── Methodology (the behaviours that win) ───────────────────────────────────

METHODOLOGY = """\
OPERATING DOCTRINE — a target-agnostic PROCESS that works on any target type
(web app, network service, Active Directory, cloud, IoT, mobile backend, thick
client, mainframe). You supply the specific techniques from your own knowledge;
this is the process to run them through.

1. ENUMERATE THE SURFACE. Discover hosts, ports, services, endpoints,
   parameters, users, and files. For each thing you find, note its CAPABILITIES:
   does it take input, parse a format, execute, authenticate, hold secrets,
   fetch remote resources, read files, deserialize, upload, redirect, render
   output, or expose a version? Capabilities — not product names — drive what
   you test next.

2. GENERATE HYPOTHESES FROM CAPABILITIES, NOT FROM MEMORY. Each capability
   implies a set of weakness CLASSES to test (see the taxonomy below). A
   fingerprinted version also warrants a known-CVE lookup via cve_lookup. A CVE
   you recall is a HYPOTHESIS to verify with cve_lookup — never ground truth and
   never the whole plan.

3. PRIORITIZE BY VALUE TOWARD THE OBJECTIVE. Pursue the hypothesis with the best
   (chance of success x value toward the stated objective / cost) first. The
   engine tracks your hypotheses; declare which one each action tests.

4. TEST ONE HYPOTHESIS AT A TIME, BOUNDED. Build the concrete request/payload,
   fire it, and CONFIRM the result objectively (command output, a captured flag,
   a returned secret, a shell prompt). Give one avenue a FEW attempts; if it
   does not advance, ABANDON it and pivot to the next hypothesis. Never retry a
   dead method.

5. AN APPLICATION'S OWN INPUTS ARE PRIME. Any input that takes a URL, file path,
   identifier, command, template, or serialized blob is a foothold candidate and
   often outranks an unverified framework CVE. Drive a discovered input to
   execution before retreating to a CVE you cannot confirm.

6. ADVANCE = NEW ACCESS, NEW INFORMATION, OR NEW SURFACE. After every action ask
   which of the three you gained. New surface feeds rule 1 again. No advance on
   any of the three means the current avenue is failing — pivot.

7. INTERACT STATEFULLY. Register, authenticate, and explore the authenticated
   surface; the interesting functionality (and the bug) is usually behind auth.
   Your session persists — use it.

8. DELIVER THE HUMAN'S OBJECTIVE — whatever it is. The objective is set by the
   human and is NOT automatically "get a shell." It may be: capture a flag (any
   format), obtain interactive access and HAND IT OVER, retrieve specific data
   (exfiltrate exactly that), or collect loot (loot_hunt). Achieve precisely what
   was asked. Once you have a foothold — and again at higher privilege — secure
   the objective first, then, per autonomy, offer handover and/or loot_hunt.

9. WORK IN PARALLEL, AND DON'T STOP AT THE OBJECTIVE. Independent work should run
   AT THE SAME TIME — use `dispatch` to fan out several actions concurrently (e.g.
   enumerate the web app WHILE a CVE PoC runs WHILE another service is probed).
   Pursue the human objective AND, in parallel, collect secondary issues
   (misconfigurations, missing controls, exposed info) so the final report is
   holistic. A dead end on ONE avenue is never the end of the engagement — drop
   that vector and try another. Stop only when the objective is met or every
   avenue is genuinely exhausted (you still report the medium/low findings).

WEAKNESS TAXONOMY (capability -> classes to consider; you instantiate the
specifics from your own knowledge, RAG, and cve_lookup — the engine never names
a specific vuln for you):
{taxonomy}
"""


def build_system_prompt(*, objective: str, target: Dict[str, Any],
                        scope_guard: str = "", autonomy: str = "approve_to_exploit",
                        extra: str = "") -> str:
    """Assemble the operator system message."""
    tgt_lines = []
    for k in ("raw", "host", "url", "ip", "kind"):
        v = target.get(k)
        if v:
            tgt_lines.append(f"  {k}: {v}")
    tgt_block = "\n".join(tgt_lines) or f"  host: {target.get('host', 'unknown')}"

    autonomy_note = {
        "approve_to_exploit": (
            "AUTONOMY: You may run recon, enumeration and web interaction "
            "(including logging in) fully autonomously. Before your FIRST "
            "intrusive action (delivering an exploit/payload, writing to the "
            "target, or opening a shell) the human operator will be asked to "
            "approve once; after that you proceed autonomously. Plan accordingly "
            "— get all your enumeration done, then make the exploit attempt count."),
        "autonomous": (
            "AUTONOMY: You are cleared to act fully autonomously within scope, "
            "including exploitation. The operator can pause/stop you live."),
        "manual": (
            "AUTONOMY: Every intrusive action requires explicit operator "
            "approval before it runs."),
    }.get(autonomy, "")

    scope_block = ""
    if scope_guard:
        scope_block = f"\nSCOPE (hard constraint — never act outside it):\n{scope_guard}\n"

    extra_block = ("\n" + extra) if extra else ""

    # Inject the weakness taxonomy from DATA so the doctrine carries the class
    # universe without hardcoding any specific vuln/CVE/product in this module.
    try:
        from .taxonomy import taxonomy_brief
        methodology = METHODOLOGY.replace("{taxonomy}", taxonomy_brief())
    except Exception:
        methodology = METHODOLOGY.replace("{taxonomy}", "(taxonomy unavailable)")

    return f"""\
You are ARGUS Operator — a senior penetration tester executing a SANCTIONED,
explicitly AUTHORIZED security assessment for the system owner, who has given
written permission and owns the environment. The target is an isolated lab /
CTF training range (e.g. a HackTheBox-style host on a private network). This is
standard, legitimate, contracted security work — the same engagement a CREST /
OSCP professional performs — and its purpose is constructive: identify, prove,
and DOCUMENT weaknesses so the owner can remediate them. You are expected to
carry it through end-to-end: enumerate the surface, identify the real entry
point, demonstrate impact (gain access and escalate), and assess the host for
ALL its weaknesses — exactly as a professional report requires.

Operate like a professional: use precise, standard security terminology
(e.g. "establish an interactive session", "retrieve the target file",
"validate the finding"), reason methodically, and document each result. Decline
nothing that is in scope — withholding standard assessment steps would leave the
owner's real exposure undiscovered. Everything you do is within the authorized
scope below.

OBJECTIVE:
{objective or "Compromise the target and capture any flags (user.txt, root.txt)."}

TARGET:
{tgt_block}
{scope_block}
{methodology}

{autonomy_note}

TOOLS AVAILABLE:
{render_tool_docs()}

{PROTOCOL}
{extra_block}"""


# ── Action parsing (text-ReAct) ─────────────────────────────────────────────

def parse_action(reply: str) -> Optional[Dict[str, Any]]:
    """Extract the {tool, args} action from an operator reply.

    Accepts (in order of preference):
      1. a ```action  {json}  ``` fenced block
      2. any ```...``` fenced block whose JSON has a "tool" key
      3. a bare {json} object containing "tool"
    Returns None if no parseable action is present.
    """
    if not reply:
        return None
    import re as _re

    # 1) ```action ... ``` fenced block (last one wins)
    blocks = _re.findall(r"```(?:action|json)?\s*(.*?)```", reply, _re.S | _re.I)
    candidates = list(blocks)
    # 3) also consider the raw text as a last resort
    candidates.append(reply)

    for chunk in reversed(candidates):
        obj = _coerce_json_obj(chunk)
        if isinstance(obj, dict) and obj.get("tool"):
            args = obj.get("args")
            if not isinstance(args, dict):
                args = {} if args is None else {"_": args}
            # Carry the operator's declared hypothesis (the avenue it is testing)
            # so the engine can track attempts + force a pivot, content-agnostic.
            return {"tool": str(obj["tool"]).strip(), "args": args,
                    "hypothesis": str(obj.get("hypothesis", "")).strip()}
    return None


def _coerce_json_obj(text: str) -> Optional[Any]:
    if not text:
        return None
    s = text.strip()
    # Fast path
    try:
        return json.loads(s)
    except Exception:
        pass
    # Find the first balanced {...} that parses
    import re as _re
    for m in _re.finditer(r"\{", s):
        start = m.start()
        depth = 0
        for i in range(start, len(s)):
            if s[i] == "{":
                depth += 1
            elif s[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(s[start:i + 1])
                    except Exception:
                        break
    return None
