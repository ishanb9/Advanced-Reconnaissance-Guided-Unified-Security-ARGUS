# ARGUS Operator-Brain Target Architecture

**Date:** 2026-06-05
**Status:** Approved (sequencing: all changes, grounded in this target architecture)
**Scope:** Generalises across target types (web, network service, AD, cloud, IoT,
mobile backend, thick client) and across single-target AND multi-target
engagements. The HTB Reactor box is the proving ground, never the shape.

---

## 1. The one principle

**The LLM operator is the only decision-maker. Every other agent is a stateless
execution service the operator dispatches — in parallel — and folds the results
back. The engagement ends only when the objective is met or every avenue is
genuinely exhausted. Never on a clock. Never on a meta-agent's verdict.**

Everything below is a consequence of that principle.

## 2. The Reactor failure this fixes

The operator (opus) won the foothold (React2Shell RCE, cracked `engineer:reactor1`)
— but three legacy mechanisms running *underneath* it ruined the ending:

1. The **time budget** (4800 s) hard-killed the loop mid-`cat user.txt` — one
   command from the flag (`done_reason=time_budget`, iter 33).
2. The **RedTeamExpert** screamed "27 null phases → tooling failure, abort" at a
   run that had RCE + a cracked credential.
3. The operator's wins (shell/creds) were never written to the fields the
   UI/report/objectives read (`credentials:[]`, `shell_obtained:false`).

Root cause: **two brains.** `master_agent` still runs its own phase pipeline +
phase-stall meta review *concurrently* with the operator. The target architecture
removes the second brain.

## 3. Layered architecture

```
Engagement Orchestrator (1..N targets, concurrent, shared cross-target intel)
   └── Operator (the BRAIN, per target) — persistent ReAct loop, total control
         ├── dispatch(...)  → Execution layer (the HANDS, stateless, PARALLEL)
         │      recon · web-WSTG · exploit/PoC · post-ex/privesc/lateral · payload
         ├── advisors       → Advisory layer (COUNSEL, never control)
         │      RedTeamExpert · error_analyzer · attack_graph
         └── State (single source of truth)
                surface · hypothesis backlog · creds · loot · shells · flags ·
                win_conditions · findings
   └── Reporter → one holistic professional report across all targets
   └── Human (Foothold dashboard) → live: shells (interactive I/O), creds,
                lateral, post-ex, payload builder
```

### 3.1 Engagement Orchestrator (multi-target)
An engagement is a *set* of in-scope targets (1..N). Each target gets its own
Operator instance; targets run concurrently under a bounded pool. Intel is
shared cross-target (a credential found on host A is automatically a hypothesis
on host B — lateral movement falls out of this). Builds on the existing
`cidr_orchestrator`. Output: one aggregated report.

### 3.2 Operator (the brain)
The persistent `converse`-driven ReAct loop (already the default driver). It owns
total control: what to enumerate, which agent to dispatch, when to pivot avenues,
when the engagement is done. It is NEVER terminated by budget or any agent. It
ends only by: objective met, or it declares `done` after judging avenues
exhausted (still emitting any medium/low findings).

### 3.3 Execution layer (the hands)
Stateless services the operator dispatches and that NEVER drive or terminate:
recon/enum, the web WSTG battery (OWASP suite), exploit/PoC runners (cve_lookup,
public PoCs), post-ex/privesc/lateral/loot, payload builder. Exposed to the
operator through a single `dispatch` tool that runs requested agents
**concurrently** (`asyncio.gather`) and merges their findings / intel / creds /
loot / surface back into state. No agent runs its own autonomous phase loop.

### 3.4 Advisory layer (counsel, never control)
RedTeamExpert, error_analyzer, attack_graph produce SUGGESTIONS injected into the
operator's context. They cannot terminate, cannot abort, cannot set
`_stop_requested`. Any "give up / tooling-failure / abort / reclassify" directive
is filtered out before it reaches the operator. The phase-stall reviewer
(master_checker / issue_validator) does not run under the operator.

### 3.5 State & bookkeeping (single source of truth)
Content-agnostic (the holistic-engine taxonomy + surface model + hypothesis
backlog already built). The operator's success detector keeps `shell_access`,
`credentials`, `loot`, `user_flag`/`root_flag`, `win_conditions`, and `findings`
in sync the instant they are achieved, so the UI / report / objective tracker
always reflect reality.

## 4. Budget model (the hard new requirement)

- The time budget is **ADVISORY** the moment ARGUS has *any* valid signal of
  progress: a confirmed finding/vuln, a point of exploit, a foothold/shell, a
  recovered credential, or a captured flag.
- Once that signal exists, the time-budget break is **disabled**. Termination is
  then by **exhaustion** (no untried high-value avenue AND no live shell AND no
  post-ex left) or **objective met** or **human stop** — never by the clock.
- A single huge runaway ceiling (`ARGUS_OPERATOR_HARD_CEILING_SEC`, default very
  large) remains purely as a safety valve against a hung process; when it is hit
  with progress present, it emits a warning and lets the operator finish its
  current action rather than killing it.
- A target with literally zero progress still ends on the ordinary budget (so a
  dead/unreachable target doesn't run forever).

## 5. Foothold dashboard (human interaction, fully plugged)

- **Active Shells:** interactive I/O for every registered shell — PTY shells and
  the RCE console alike — via `shell_input` WS → `handle_input` → PTY stdin /
  RCE-console runner. The human can jump into any shell and type at any time,
  during or after the automated run. (Backend path exists; the gap is
  frontend/runtime — xterm load + RCE-console `run_fn` lifetime — and is fixed.)
- **Credentials:** rendered from `intel.credentials` (now populated by the
  success detector).
- **Lateral / Post-ex / Payload builder:** each bound to the corresponding intel
  + agent so they show live data and can launch the relevant execution agent.

## 6. Reporting

One holistic professional report per engagement (all targets): objective
outcome, the full kill chain, EVERY finding (primary exploitation + secondary
issues such as missing headers / IDOR / misconfig), recovered credentials, and
MITRE ATT&CK mapping.

## 7. Why this generalises

- The operator reasons over an abstract **surface × weakness-taxonomy** backlog —
  domain-independent, so the same brain handles web, AD, cloud, IoT.
- Execution agents are just target-type-specific tools the operator selects; new
  target types add agents/playbooks (data), never engine logic.
- The orchestrator treats 1 and N targets uniformly; cross-target intel sharing
  makes lateral movement and fleet engagements first-class.
- Termination is objective/exhaustion-driven, so depth scales to the target, not
  to a fixed clock.

## 8. Mapping to the 8 reported issues

| # | Issue | Architecture element |
|---|-------|----------------------|
| 1 | Expert aborted the run | §3.4 advisors never control; poison filter; phase-stall reviewer off |
| 2 | Only operator/master/recon useful | §3.2/§3.3 operator drives, agents are execution |
| 3 | LLM total control, agents execution | §1, §3.2, §3.3 |
| 4 | ARGUS unaware of its success | §3.5 success detector keeps state in sync |
| 5 | Objectives not on Findings page | §3.5 live `win_conditions` + objective findings |
| 6 | Foothold dashboard not plugged | §5 |
| 7 | Holistic report + PARALLEL agents | §3.3 parallel dispatch + §6 report |
| 8 | Fail-loop terminates testing | §1, §4 exhaustion-not-clock; abandon a vector, not the engagement |
| NEW | Budget must not fail testing | §4 |

## 9. Implementation workstreams (all to be built)

- **W1 — Termination authority + budget model (§4):** budget never kills a
  progressing run; only the operator/human/exhaustion terminate; meta-agents
  cannot stop. *(highest priority — this is what lost Reactor)*
- **W2 — Operator sole driver + parallel `dispatch` (§3.2/§3.3):** remove the
  second brain; agents become concurrent execution services.
- **W3 — Self-comprehension + objective/state sync (§3.5):** success detector +
  live objectives on Findings.
- **W4 — Foothold dashboard fully plugged (§5):** shell I/O, creds, lateral,
  post-ex, payload.
- **W5 — Multi-target orchestrator + holistic report (§3.1/§6).**

Constraint across all: **do not break the path that reached RCE-on-Reactor**;
keep `agents/test_architecture_integration.py` green; engine stays content-free
(the guard test from the holistic-engine work still applies).
