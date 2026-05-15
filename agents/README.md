# ARGUS Agent Fleet

> 23 specialist agent folders + 18 top-level orchestration agents.
> The MasterAgent is the single LLM-using brain; everything else is a
> deterministic worker reachable via the AgentBus.

The fleet is the offensive heart of ARGUS. The MasterAgent plans each
phase by consulting the local LLM, then issues typed `Instruction`
objects to specialist agents over a pub/sub bus. Workers run the tools,
parse the output, store findings, and report back. The MasterAgent
re-consults the LLM to decide the next move. The whole loop is
streamed to the operator UI in real time.

---

## Contents

1. [Quick mental model](#quick-mental-model)
2. [Top-level orchestrators](#top-level-orchestrators)
3. [The 23 specialist folders](#the-23-specialist-folders)
4. [Base classes](#base-classes)
5. [AgentBus + Instruction protocol](#agentbus--instruction-protocol)
6. [Dispatch pattern](#dispatch-pattern)
7. [Adding a new specialist agent](#adding-a-new-specialist-agent)
8. [Conventions](#conventions)
9. [Safety + opsec](#safety--opsec)

---

## Quick mental model

```
                           +----------------+
                           |   LLM (Ollama) |
                           |  utils/llm_*   |
                           +--------+-------+
                                    ^  plan / decide
                          +---------+---------+
                          |  MasterAgent      |  <- the ONE LLM caller
                          |  master_agent.py  |
                          +---------+---------+
                                    |  Instruction(payload, target, ttl)
                                    v
                          +-------- AgentBus --------+
                          |  pub/sub typed channels  |
                          +----+--------+--------+---+
                               |        |        |
                  +------------v+  +----v----+  +v------------+
                  | recon       |  | vuln    |  | exploit     |
                  | subagent    |  | subagent|  | subagent    |
                  +-----+-------+  +----+----+  +-----+-------+
                        |               |             |
                        v               v             v
                   nmap, masscan, nuclei, sqlmap, hydra, metasploit, ...
                        |               |             |
                        +---------------+-----+-------+
                                              v
                                        Findings (CVSS,
                                        MITRE T-IDs,
                                        evidence chain)
                                              |
                                              v
                                     MongoDB . Neo4j . UI WebSocket
```

Two **architectural rules** that make this tractable:

1. **MasterAgent is the sole LLM interface.** Every other agent is
   deterministic. Specialists do not call the LLM. This keeps token
   costs predictable and reasoning auditable.

2. **Specialists never talk to each other directly.** All
   inter-agent communication goes through the AgentBus. This keeps
   the fleet horizontally extensible.

---

## Top-level orchestrators

These live directly in `agents/` (not in a subfolder):

| File | Role |
|------|------|
| `master_agent.py` | The LLM-driven planner. Owns the engagement state machine. Issues `Instruction`s. |
| `base_agent.py` | Abstract base for top-level agents. Lifecycle (init/run/teardown), AgentBus binding, audit emit. |
| `base_subagent.py` | Abstract base for sub-agents (lives inside a phase folder). Lighter contract: only `run()`. |
| `cidr_orchestrator.py` | Splits large scope (e.g. `/16`) into manageable sub-targets; load-balances workers. |
| `recon_agent.py` | Top-level reconnaissance phase coordinator. |
| `osint_agent.py` | OSINT phase coordinator. |
| `vuln_agent.py` | Vulnerability-assessment phase coordinator. |
| `web_agent.py` | Web-application testing phase coordinator (WSTG matrix). |
| `exploit_agent.py` | Exploitation phase coordinator. |
| `privesc_agent.py` | Privilege-escalation coordinator. |
| `shell_agent.py` | Live shell management; spawns + multiplexes PTY sessions to the UI. |
| `payload_agent.py` | Payload generation + encoder ladder; emits to evasion subagent. |
| `attack_graph_agent.py` | Builds + updates the Neo4j semantic attack graph. |
| `knowledge_graph.py` | RAG-knowledge-base orchestration (links to `knowledge/`). |
| `credential_pipeline.py` | Cred-harvest -> crack -> spray -> AD-attack pipeline. |
| `operator_interrupts.py` | Pause/resume/manual-override handling. |
| `pentest_context.py` | Engagement-state struct shared across agents (target, scope, mode). |

---

## The 23 specialist folders

Each folder is a phase or a domain of expertise. Counts below are
`.py` files in that folder (subagents + helpers).

| Folder | Files | Domain |
|--------|-------|--------|
| `recon/` | 6 | Active + passive recon - port + service + version |
| `osint/` | 16 | Open-source intel - whois, dns, breach data, social, github leaks |
| `vuln/` | 9 | Vulnerability assessment - nuclei, version-CVE, custom checks |
| `web/` | 15 | OWASP WSTG matrix - injection, auth, sessions, ssrf, xxe, ssti, ... |
| `exploit/` | 9 | Exploitation - payload chaining, attack-graph traversal |
| `privesc/` | 7 | Privilege escalation - Linux + Windows + container escapes |
| `lateral/` | 6 | Lateral movement - pivoting, AD enum, kerberoasting, ntlm-relay |
| `post/` | 6 | Post-exploitation - credential harvest, persistence, data extraction |
| `evasion/` | 5 | AV / EDR evasion - encoder ladders, AMSI bypass, ETW patching |
| `c2/` | 2 | Command-and-control - Sliver implants, beacon management |
| `cloud/` | 5 | Cloud - AWS / Azure / GCP enum + misconfig + creds-in-env |
| `container/` | 4 | Container / Kubernetes - kubelet, dashboard, RBAC, escape |
| `iot/` | 6 | IoT - firmware extraction, UART, MQTT, CoAP, ZigBee |
| `wireless/` | 5 | Wireless - Wi-Fi handshakes, evil twin, bluetooth, BLE |
| `traffic/` | 5 | Network traffic - passive capture, MITM, ARP spoof, DNS poison |
| `forensics/` | 5 | Digital forensics - memory dump analysis, timeline, artefact |
| `evidence/` | 4 | Evidence chain - hash provenance, signed export, retention |
| `reasoning/` | 27 | Hypothesis-driven reasoning loop - the second-largest folder |
| `campaign/` | 2 | Multi-engagement campaign management |
| `mission/` | 3 | Mission-control coordination, briefings |
| `meta/` | 6 | Meta-agents that watch + correct the other agents |
| `playbook/` | 2 | Deterministic playbook execution (links to `knowledge/playbooks/`) |
| `training/` | 2 | Training / lab-mode subagents |

Total: ~158 specialist files + 18 top-level = **~175 Python files** in
the fleet.

---

## Base classes

### `BaseAgent` (top-level)

```python
class BaseAgent:
    AGENT_NAME = "..."                # registered name on the bus

    def __init__(self, session_id, bus, db, llm=None):
        self.session_id = session_id
        self.bus        = bus
        self.db         = db
        self.llm        = llm         # ONLY MasterAgent receives this

    async def run(self) -> None: ...
    async def handle_instruction(self, instr: Instruction) -> None: ...
    async def teardown(self) -> None: ...

    # Helpers
    async def store_finding(self, finding: Finding) -> str: ...
    async def emit_event(self, event_type: str, payload: dict) -> None: ...
    async def collect_tool(self, tool: str, target: str, opts: dict) -> str: ...
```

### `BaseSubagent` (phase-folder workers)

```python
class BaseSubagent:
    AGENT_NAME    = "exploit"         # parent phase
    SUBAGENT_NAME = "av_evasion"      # sub-name

    async def run(self, target: str, **kwargs) -> SubagentResult: ...

    # Helpers (same as BaseAgent)
    async def store_finding(self, finding: Finding) -> str: ...
    async def collect_tool(self, tool: str, target: str, opts: dict) -> str: ...
```

`SubagentResult` is a dataclass:

```python
@dataclass
class SubagentResult:
    session_id:    str
    subagent_name: str
    target:        str
    findings:      list[Finding] = field(default_factory=list)
    notes:         str = ""
    duration_sec:  float = 0.0
```

---

## AgentBus + Instruction protocol

`Instruction` is the typed message a parent agent sends to a subagent:

```python
@dataclass
class Instruction:
    instr_id:     str          # uuid4
    agent_name:   str          # target phase (e.g. "exploit")
    subagent:     str | None   # specific subagent (e.g. "av_evasion")
    target:       str          # host / URL / cidr
    payload:      dict         # subagent-specific args
    ttl_sec:      int = 600
    priority:     int = 5      # 0 (lowest) ... 10 (highest)
    correlation:  str | None = None  # to link cause-effect
    requested_by: str = "master"
```

The bus is publish/subscribe with topics named after `agent_name`.
Multiple workers can subscribe to one topic for parallel dispatch
(CIDROrchestrator uses this to fan out across a /24).

---

## Dispatch pattern

The canonical pattern for `MasterAgent` to call a specialist:

```python
# 1. Build the typed instruction
instr = Instruction(
    instr_id   = uuid4().hex,
    agent_name = "vuln",
    subagent   = "nuclei",
    target     = host_ip,
    payload    = {"templates": "http,cves/2024,exposures"},
    priority   = 6,
)

# 2. Publish to the bus
await self.bus.publish(instr)

# 3. Await the result (correlation-id matching)
result = await self.bus.collect_response(
    instr.instr_id, timeout=instr.ttl_sec,
)

# 4. Store + decide
for finding in result.findings:
    await self.store_finding(finding)
next_step = await self.think_with_history(...)
```

The MasterAgent does not block on a single worker - it queues several
instructions then awaits their responses in parallel.

---

## Adding a new specialist agent

This walkthrough adds a hypothetical `dns_zone_walk` subagent under
the existing `recon/` phase.

### 1. Create the file

`agents/recon/dns_zone_walk_subagent.py`:

```python
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

class DnsZoneWalkSubagent(BaseSubagent):
    AGENT_NAME    = "recon"
    SUBAGENT_NAME = "dns_zone_walk"

    async def run(self, target: str, **kwargs) -> SubagentResult:
        result = SubagentResult(
            session_id    = self.session_id,
            subagent_name = self.SUBAGENT_NAME,
            target        = target,
        )

        # 1. Collect data via MCP-bridged tool
        out = await self.collect_tool("dig", target, {
            "type": "AXFR", "server": kwargs.get("server", ""),
        })

        # 2. Parse + store findings
        for record in self._parse_axfr(out):
            await self.store_finding(Finding(
                title       = f"Zone record {record.name}",
                description = f"{record.type} {record.value}",
                severity    = "INFO",
                evidence    = record.raw,
                tool        = "dig",
                host        = target,
                mitre_technique = "T1590.002",     # DNS
            ))
        result.notes = f"records={len(records)}"
        return result

    def _parse_axfr(self, output): ...     # tool-specific parsing
```

### 2. Register the subagent

`agents/recon/__init__.py` (or wherever your phase exports its subagents):

```python
from agents.recon.dns_zone_walk_subagent import DnsZoneWalkSubagent

SUBAGENTS = {
    "subdomain_enum":  SubdomainEnumSubagent,
    "port_sweep":      PortSweepSubagent,
    "dns_zone_walk":   DnsZoneWalkSubagent,    # <- new
}
```

### 3. Teach the MasterAgent (optional)

If you want this subagent dispatched automatically during the recon
phase, add an entry to the phase-plan generator in
`agents/master_agent.py` (typically a `RECON_TASKS` list). For
manual dispatch (operator triggers it from the cockpit), no further
backend change is needed.

### 4. Surface in the UI (optional)

Add a button to `static/js/pages/TargetConfig.jsx` that calls:

```js
fetch(`/api/agents/dispatch`, {
  method: 'POST',
  body: JSON.stringify({
    agent: 'recon', subagent: 'dns_zone_walk',
    target: '...', payload: { server: 'ns1.target.com' },
  }),
});
```

Cache-bust the JSX in `templates/index.html`.

### 5. Test

```bash
# unit-test the subagent in isolation
python -m pytest agents/recon/tests/test_dns_zone_walk.py

# integration test via the live cockpit
uvicorn agent_server:app --reload
# open http://localhost:8000, sign in, configure target, click your new button
```

---

## Conventions

- **File names** - snake_case, suffixed with `_subagent.py` for
  subagents (`av_evasion_subagent.py`), `_agent.py` for top-level
  (`vuln_agent.py`).
- **Class names** - PascalCase, end with `Subagent` or `Agent`.
- **`AGENT_NAME` constant** - lowercase, no spaces.
- **Subprocess safety** - always use
  `asyncio.create_subprocess_exec(*argv, ...)` with positional argv
  (the safe execFile-equivalent form). Never pass user-controlled
  strings to a shell. The audit-log helper `collect_tool()` enforces
  this for every MCP-bridged tool.
- **Findings** - populate `mitre_technique` whenever possible. The
  attack-graph builder uses it.
- **CVSS** - call `utils.cvss_scorer.score(finding)` rather than
  hand-rolling a score.
- **Logging** - `logger = logging.getLogger("argus.agents.<phase>.<name>")`.
- **Audit emits** - significant state changes call
  `self.emit_event("subagent.completed", {...})` so the UI gets a
  live update.

---

## Safety + opsec

Many specialist agents have an "opsec profile" knob (set by
`utils/opsec_profiles.py`). The three profiles:

| Profile | What it does |
|---------|--------------|
| `loud` | Default. No throttle, no jitter, no UA spoofing. Fastest. |
| `stealth` | Adds jitter, slows scan rate, rotates UA, respects rate-limit headers. |
| `silent` | Stealth + skips any tool that emits identifiable telemetry (e.g. nuclei "INFO" fingerprints). |

Operators set the profile at engagement creation. Subagents that don't
honor it (because they fundamentally can't, e.g. brute-force tools)
are auto-disabled in `silent` mode.

---

## Further reading

- [`../README.md`](../README.md) - project front page
- [`../auth/README.md`](../auth/README.md) - how RBAC scopes agent dispatch per role
- [`../knowledge/README.md`](../knowledge/README.md) - RAG retrieval used by the MasterAgent
- [`../knowledge/PLAYBOOK_GUIDE.md`](../knowledge/PLAYBOOK_GUIDE.md) - authoring deterministic playbooks that bypass the LLM
- [`../docs/README.md`](../docs/README.md) - design specs for the reasoning loop, meta-agents, attack-graph

---

*"The MasterAgent thinks. The specialists do. The bus carries the
verb between them."*
