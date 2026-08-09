# ARGUS Holistic Engagement Engine — Design Spec

**Date:** 2026-06-04
**Status:** Draft for review
**Author:** ARGUS engineering (operator-core track)

---

## 1. Problem statement

ARGUS is an autonomous, LLM-driven penetration-test operator. It must perform
well across the *entire* universe of targets (web apps, Active Directory, cloud
APIs, IoT/embedded, mobile backends, thick clients, ICS, mainframes) and the
*entire* universe of weaknesses (thousands of specific vulnerabilities).

The current failure mode is **over-fitting the engine to individual practice
boxes**. After each HTB-style box, box-specific content has been bolted into
*engine code*:

- A hardcoded technique keyword table in `operator_core._method_signature`
  (e.g. `x-middleware-subrequest -> nextjs-mw-bypass`, `sqlmap`, `file://`).
- Named CVEs, products, and endpoints written into the doctrine prompt in
  `tool_catalog.METHODOLOGY` (e.g. `CVE-2025-29927`, "Next.js", "/render").

This does not scale (it can never enumerate thousands of techniques), it
*biases* the operator toward the named techniques on unrelated targets, and it
is brittle (a signature table misses every variant). The HTB Reactor box was
practice; the engine must not be shaped by it.

## 2. The core principle: PROCESS vs CONTENT

There is a bright line that must never be crossed again:

- **PROCESS** — *how* you test anything. Finite, stable, target-independent.
  Belongs in engine code.
- **CONTENT** — *what* a specific weakness / CVE / payload / endpoint is.
  Infinite, target-specific. Belongs in the model's parametric knowledge, the
  RAG knowledge base, runtime lookups, and data-driven playbooks. **Never in
  engine code.**

**The test for every line of engine code:** "Would this still be correct on a
Windows AD box, a cloud API, an IoT device, and a mainframe?" If a line names a
product, CVE, port, endpoint, or payload string, it fails and the content must
move to data/knowledge.

The tractability insight that makes generality achievable: **specific
vulnerabilities are infinite, but weakness *classes* are finite** (~the
CWE / OWASP / MITRE ATT&CK universe — a few dozen). The engine enumerates
`surface x classes` (tractable, general); the LLM + RAG + runtime tools
instantiate the specifics (open-ended).

## 3. Goals / non-goals

**Goals**
- A single, target-agnostic engagement process that works for any target type.
- All vulnerability-specific knowledge lives outside engine code.
- The engine converges on the objective or on honest exhaustion of the
  high-value hypothesis space — not on a wall-clock timeout mid-flail.
- A mechanical guard that makes reintroducing box-specific content impossible.

**Non-goals**
- Encoding specific exploits in code (they live in knowledge/playbooks/runtime).
- Replacing the operator's LLM reasoning — the engine *scaffolds* it, it does
  not script it.
- A rewrite. This extends the existing operator core, intel/attack-graph, and
  playbook concepts.

## 4. Architecture — five components

### 4.1 Surface Model (extend existing intel + attack_graph)
A typed graph of everything discovered.

- **Nodes:** hosts, ports, services, apps, endpoints, parameters, users, files,
  trust boundaries. Each node has a `kind` and, crucially, a set of
  **capabilities** drawn from a small general vocabulary:
  `takes_input`, `parses_format`, `executes`, `authenticates`,
  `stores_secrets`, `fetches_remote`, `file_access`, `deserializes`,
  `version_known`, `renders_output`.
- **Edges:** `reachable_from`, `authenticates_to`, `fetches`, `executes`,
  `trusts`.

Capabilities — not product names — are the generic trigger for hypothesis
generation. "This node accepts a remote resource reference" (`fetches_remote`)
is what suggests the server-side-request-forgery class, regardless of whether
the node is a Next.js route, a PDF generator, or a webhook validator.

### 4.2 Weakness Taxonomy (NEW — data, not code)
File: `knowledge/weakness_taxonomy.yaml`. ~30-50 stable weakness *classes*,
each mapped to:

```yaml
- id: ssrf
  name: Server-Side Request Forgery
  triggering_capabilities: [fetches_remote, takes_input]
  generic_test_strategy: >
    Point the resource reference at internal/loopback/metadata addresses and at
    alternate URI schemes; observe for differential responses or out-of-band
    callbacks indicating the server made the request.
  confirm_signal: >
    Response content or timing proves the server reached an address the client
    cannot, or an out-of-band interaction was received.
```

Every entry is described **generically** — it names a *class* and a *strategy*,
never a product, CVE, or endpoint. The taxonomy is loaded as data and injected
into the operator's doctrine at runtime. Adding/refining a class is a data edit,
never a code change. (Source basis: CWE Top-25, OWASP Top-10 + API Top-10,
MITRE ATT&CK techniques.)

### 4.3 Hypothesis Backlog (NEW — the spine)
The living, content-agnostic checklist the engagement is organized around.

- **Generated by** `surface x taxonomy` + LLM reasoning + RAG retrieval +
  `cve_lookup` (the version->known-CVE path becomes one hypothesis *source*
  among several).
- **Each hypothesis:**
  ```
  { id, node_ref, weakness_class, rationale, expected_value,
    status, attempts[], evidence, source }
  ```
- **Status lifecycle:** `untried -> active -> (confirmed | refuted | blocked)`.
- **expected_value** = P(success) x value(outcome) / cost. A confirmed public
  PoC matching the exact fingerprint is high-P/high-value; a blind guess is
  low-P; a capability-based hypothesis on a custom app is often high-value where
  no CVE exists.

The *structure* is content-agnostic; the *rationale* and the eventual payload
are authored by the operator/LLM. ARGUS owns the backlog bookkeeping; the
operator owns the thinking.

### 4.4 Operator Loop (exists — re-keyed to hypotheses)
Works the backlog top-down by expected value.

- **Every operator action declares the `hypothesis_id` it serves** (a field in
  the action schema). This *replaces* the hardcoded `_method_signature` keyword
  table entirely — ARGUS caps/pivots/measures coverage on the operator's own
  declared hypothesis plus any CVE id (a universal, content-agnostic token).
- **Bounded attempts per hypothesis** (the existing cap, re-keyed): a hypothesis
  gets N attempts (3-5, env-tunable); on exhaustion it is marked `refuted`/
  `blocked` and the operator pivots to the next. A productive attempt (advance,
  see 4.5) clears strikes — a working hypothesis is never penalized.
- **Reactive cve_lookup** keeps firing on new fingerprints; its results enter
  the backlog as `known-CVE`-class hypotheses and populate `exploit_modules`.

### 4.5 Coverage & Convergence (NEW)
- **Progress / "advance" — defined generally:** an action advances the
  engagement if it produces new **access** (auth/shell), new **information**
  (creds/files/versions), or new **surface** (nodes/edges/parameters). This
  generalizes the existing progress signature.
- **Coverage map:** which `(node x applicable-class)` cells have been
  hypothesis-tested.
- **Convergence / end-state:** the engagement ends when the **objective is met**
  OR the backlog of `expected_value >= threshold` hypotheses is **exhausted**.
  On exhaustion without success, a **completeness critic** asks "what surface or
  weakness class did I never consider?" and either generates new hypotheses or
  declares an honest, evidence-based completion. The wall-clock budget remains
  only as a hard safety ceiling, not the primary terminator.

## 5. Control flow (the engagement tick)

1. **Frame objective** (existing flexible-objectives work): flag / access+
   handover / specific data / loot.
2. **Enumerate** (operator action) -> Surface Model updated with nodes +
   inferred capabilities.
3. **On new surface -> Hypothesis Generation:** ARGUS asks the operator
   (structured call) "given these new nodes+capabilities and the taxonomy, what
   hypotheses apply?" + auto-adds `known-CVE` hypotheses from `cve_lookup` +
   RAG-retrieved hypotheses from prior successful chains. Dedup into backlog.
4. **Prioritize** backlog by expected_value.
5. **Test top hypothesis, bounded:** operator instantiates the concrete
   payload/request (tagged with `hypothesis_id`), fires, observes.
6. **Judge advance:** update hypothesis status; on `confirmed`, exploit deeper
   and feed newly reachable nodes back to step 2; on `refuted`, pivot.
7. **Converge:** loop until objective met or high-value backlog exhausted.

## 6. Where knowledge lives (so the engine stays general)

- **Parametric (LLM):** broad technique knowledge — fine as a *first* probe.
- **RAG / KB:** retrievable techniques, CVEs, and *past successful chains*
  (the system already prefers techniques that previously succeeded).
- **Runtime lookups:** `cve_lookup` (NVD / GitHub / searchsploit), live tool
  output.
- **Playbooks-as-data:** concrete multi-step chains as data, keyed by
  `weakness_class` + `capability` (NOT by box). Extends the existing
  capability-as-data playbook concept. The taxonomy's `generic_test_strategy`
  may reference a playbook id.

## 7. Component boundaries (new/changed units)

- `knowledge/weakness_taxonomy.yaml` — NEW data. The class table.
- `knowledge/playbooks/*.yaml` — extend existing. Class/capability-keyed chains.
- `agents/operator_agent/surface_model.py` — NEW. Node/edge/capability model +
  capability inference from intel; serializable into checkpoints.
- `agents/operator_agent/hypothesis_backlog.py` — NEW. Backlog + prioritization
  + coverage + convergence bookkeeping. Pure, content-agnostic, unit-testable.
- `agents/operator_agent/operator_core.py` — CHANGED. Drive the backlog;
  `hypothesis_id` on actions; re-key cap to hypotheses; delete
  `_method_signature` keyword table.
- `agents/operator_agent/tool_catalog.py` — CHANGED. Doctrine = principles +
  taxonomy injected from data; remove all CVE/product/endpoint literals.

## 8. The guardrail test (most important)

A mechanical test (`test_no_hardcoded_attack_content`) scans every *engine*
module (`operator_core`, `tool_catalog`, `surface_model`,
`hypothesis_backlog`, master/loop code) and FAILS if it finds:

- a CVE identifier pattern (`CVE-\d{4}-\d+`),
- a known product+version literal or named endpoint payload,
- a payload/technique string literal (a curated deny-list of markers).

Allowed locations: `knowledge/*` data files, tests, comments explaining the
rule. This makes the over-fitting regression mechanically impossible to
reintroduce — on this box or the next thousand. It lands in Tier A and gates
every subsequent change.

## 9. Testing strategy (general, never box-specific)

- **Unit:** taxonomy loads + validates; capability inference from sample intel;
  hypothesis generation yields `(node x class)` entries; backlog prioritization
  ordering; cap keyed to `hypothesis_id`; coverage + convergence logic;
  completeness critic produces new hypotheses when backlog empties.
- **Behavioral (abstract, no real CVE):** a synthetic surface with abstract
  nodes/capabilities -> backlog generated -> operator works it -> a refuted
  hypothesis forces a pivot -> a confirmed hypothesis adds surface and advances
  -> engagement converges. Uses fake nodes only; asserts the *process*, not any
  specific vuln.
- **Guard:** the `test_no_hardcoded_attack_content` deny-list test above.

## 10. Migration / sequencing (tiers)

- **Tier A — De-box-ify + foundations.** Taxonomy-as-data; doctrine rewritten to
  principles+taxonomy; `hypothesis_id` on actions; delete `_method_signature`
  keyword table (cap re-keyed to declared hypothesis + CVE id); land the guard
  test. *Outcome:* the smell is gone and cannot return; behavior preserved.
- **Tier B — The spine.** Surface capability model; hypothesis backlog +
  generation + prioritization; operator drives the backlog.
- **Tier C — Holistic ending.** Coverage map; convergence on objective/
  exhaustion; completeness critic; clock demoted to safety ceiling.
- **Tier D — Content layer.** Playbooks-as-data keyed by class/capability;
  RAG/KB wired into hypothesis generation; prior-success retrieval.

Each tier ends working, tested, and green. The guard test from Tier A runs in
every subsequent tier.

## 11. Risks & mitigations

- **Operator under-declares hypotheses.** Mitigation: the action schema requires
  a `hypothesis_id`/label; ARGUS auto-creates one from a CVE id or a coarse
  `node+tool` key if omitted, so tracking degrades gracefully.
- **Hypothesis generation explosion.** Mitigation: cap backlog by expected_value
  threshold + per-node class limits; the completeness critic only deepens when
  the high-value set is exhausted.
- **Taxonomy drift / staleness.** Mitigation: it is data, reviewed/extended
  independently of code; keyed to stable CWE/OWASP/ATT&CK anchors.
- **Local-model context limits** (a real constraint already seen): backlog and
  taxonomy injected compactly (ids + one-line strategies), full detail fetched
  on demand — consistent with the existing compaction/seed-cap work.
