# Gap #5 — Execution-Boundary Safety Governor Design

**Date:** 2026-06-22
**Status:** Implemented
**Gap:** #5 of the competitive-audit correctness program — "scope/RBAC/intrusiveness/
arg-validation has no teeth at the execution boundary; protection is a scattered
name-blocklist, not a governed chokepoint (NodeZero ships a pre-approved action
catalog enforced at execution time)."

## Problem

ARGUS's protections against running the wrong thing were **reactive and scattered**
inside `base_agent.run_tool`: a `/etc/hosts` self-sabotage rewrite here, a
shell-metacharacter reroute there, ad-hoc scope-drift handling elsewhere. There was
no single, testable policy answering "may ARGUS run *this* invocation, as-is?" — and
nothing stopped a host-destroying command (disk wipe, fork-bomb, shutdown) or an
out-of-scope target at the one point where every tool actually executes.

## Approach

A new **pure** policy module, `knowledge/safety_governor.py`, plus a single
best-effort wiring at `base_agent.run_tool` — the **one chokepoint** every tool
passes through (master, subagents, and the operator all reach the MCP server via
`run_tool`). The governor classifies and decides; `run_tool` enforces.

**Safe-to-enforce by default, never breaks a legit run.** The wiring hard-enforces
only the checks that cannot harm a legitimate pentest:
- **destructive** → host-damaging shell ops are *rewritten to a no-op* (`true`) so the
  agent loop keeps moving without trashing the box.
- **ot_life_safety** → an *intrusive* action against an OT / life-safety target is
  denied unless explicitly authorized (safe-by-default; never fires for normal IT).

**scope** deny is available and enforced **only when an authorised-scope list is
set** (`self._governor_scope_hosts`) — so discovered/pivoted in-scope hosts are never
wrongly blocked. **intrusiveness** ceiling is advisory at `run_tool` (the dispatch
layer already governs auto-run), and callers can opt into hard enforcement.

Any governor exception falls through to `allow` — it can never crash `run_tool`.

## Components

| Unit | Responsibility |
|------|----------------|
| `classify_intrusiveness(tool, args)` | → `safe` \| `light` \| `intrusive` |
| `destructive_match(tool, args)` | matched host-damaging token, **shell tools only**; precise patterns (`rm -rf /`/system roots, `mkfs`, `wipefs`, `dd of=/dev/sd…`, shutdown/reboot/halt, `init 0/6`, fork-bomb, recursive chmod/chown on system) — does **not** flag local-workdir deletes |
| `host_in_scope(host, scope)` | exact / IP / proper sub-domain; empty scope ⇒ in-scope (no false deny) |
| `evaluate(invocation, enforce)` | ordered checks → `{decision, reason, rewritten_args, checks}`; `decision ∈ {allow, rewrite, deny, require_approval}` |

Reuses `knowledge.skill_registry.allowed(...)` for the intrusiveness-ceiling gate
rather than re-deriving the OT clamp.

## Data flow

`run_tool(tool, args, target, …)` → build invocation (defensive getattr/intel
sourcing) → `evaluate(...)` → `deny`: emit `governor_block`, return a blocked result
(`exit_code:-1`); `rewrite`: emit `governor_rewrite`, swap in the no-op args; then the
existing `/etc/hosts` guard + metachar reroute run on the (possibly rewritten) args as
defense-in-depth → execute via MCP.

## Why not patch `mcp-server.js`

The Node MCP server is reached *only* through `run_tool` (the single `MCP_URL`
caller). Enforcing in Python at `run_tool` covers master/subagents/operator without
duplicating the policy in JS (which would drift). `run_tool` **is** the gateway.

## Testing

`test_safety_governor` (always-run harness) asserts: intrusiveness classification;
destructive detection on the dangerous forms **and** non-detection of legit local
deletes / argv tools; scope matching incl. the no-substring rule; `evaluate`
decisions (out-of-scope→deny, destructive→rewrite, OT-unauthorized→deny,
OT-authorized→not-denied, in-scope-light→allow, scope-not-enforced-unless-asked); and
best-effort robustness to empty/None input.

## Out of scope (YAGNI)

A full per-tool RBAC matrix and a UI for editing the action catalog. The governor
exposes `enforce` so policy can tighten later without touching `run_tool`.
