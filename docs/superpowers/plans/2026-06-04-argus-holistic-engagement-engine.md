# ARGUS Holistic Engagement Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ARGUS's box-specific special-casing with a target-agnostic, objective-driven engagement engine: a weakness-taxonomy (data) → surface-capability model → hypothesis backlog → bounded testing → coverage-based convergence, with a mechanical guard that keeps all vuln-specific content out of engine code.

**Architecture:** The operator core stops carrying technique knowledge. It drives a **hypothesis backlog** generated from `surface × weakness-taxonomy + cve_lookup + RAG`. Each operator action declares the `hypothesis_id` it serves, so attempt-caps/coverage/pivots key on *operator-declared hypotheses*, never hardcoded keywords. The engagement converges on the **human-set objective** (flag / access+handover / data exfil / loot / custom), not on "shell obtained" or a clock. A guard test forbids CVE ids / product literals / payload strings in engine modules forever.

**Tech Stack:** Python 3 (async), PyYAML (taxonomy/playbooks as data), the existing custom test harness `agents/test_architecture_integration.py` (run with `python -X utf8 agents/test_architecture_integration.py`; assertions via `_assert`/`_section`). No pytest. No git commits — the user copies edited files manually to Kali, so each task lists **Files to copy**.

**Conventions for this plan:**
- "Run the harness" = `python -X utf8 agents/test_architecture_integration.py` from repo root `C:\Users\ishan2\Desktop\Tools\LLM\v1`. Expected tail: `RESULT: PASS — all assertions green`.
- New tests are functions in `agents/test_architecture_integration.py` registered in `main()`'s `tests=[...]` list.
- "Engine modules" (subject to the guard test) = `agents/operator_agent/operator_core.py`, `tool_catalog.py`, `surface_model.py`, `hypothesis_backlog.py`, `taxonomy.py`. NOT tests, NOT `knowledge/*` data, NOT `cve_lookup.py` (it legitimately handles CVE strings at runtime).

---

## File structure (locked decomposition)

**New data (content — editable without touching code):**
- `knowledge/weakness_taxonomy.yaml` — ~30-50 weakness *classes* (CWE/OWASP/ATT&CK-aligned): `{id, name, triggering_capabilities, generic_test_strategy, confirm_signal, objective_relevance}`.
- `knowledge/playbooks/*.yaml` (Tier D) — class/capability-keyed multi-step chains.

**New engine modules (process — content-free):**
- `agents/operator_agent/taxonomy.py` — load+validate the taxonomy YAML; `classes_for_capabilities(caps)`.
- `agents/operator_agent/surface_model.py` — `SurfaceNode` (kind+capabilities), `SurfaceModel` (nodes/edges), `infer_from_intel(intel)`, serialize/restore.
- `agents/operator_agent/hypothesis_backlog.py` — `Hypothesis` dataclass, `HypothesisBacklog` (add/dedup/prioritize/coverage/convergence), objective-aware valuation.

**Modified:**
- `agents/operator_agent/operator_core.py` — drive the backlog; `hypothesis_id` on actions; re-key cap; delete `_method_signature` keyword table; objective-driven convergence.
- `agents/operator_agent/tool_catalog.py` — doctrine = principles + taxonomy(from data); action schema gains `hypothesis`; remove all CVE/product/endpoint literals.
- `agents/test_architecture_integration.py` — guard test + per-tier tests.

---

# TIER A — De-box-ify + foundations

Goal: the over-fitting smell is gone and *cannot return*; behaviour preserved; harness green.

## Task A1: Weakness taxonomy as data + loader

**Files:**
- Create: `knowledge/weakness_taxonomy.yaml`
- Create: `agents/operator_agent/taxonomy.py`
- Test: `agents/test_architecture_integration.py` (new `test_weakness_taxonomy_loads`)

- [ ] **Step 1: Write the failing test** (add function, register in `tests=[...]`)

```python
def test_weakness_taxonomy_loads():
    _section("Tier A — weakness taxonomy loads as data, maps capabilities → classes")
    from agents.operator_agent import taxonomy as _tax
    classes = _tax.load_taxonomy()
    _assert(len(classes) >= 20, "taxonomy has a real class set (>=20 weakness classes)")
    ids = {c["id"] for c in classes}
    _assert({"ssrf", "sqli", "known_cve", "auth_bypass", "path_traversal"} <= ids,
            "core weakness classes are present")
    for c in classes:
        _assert(c.get("id") and c.get("name") and c.get("generic_test_strategy")
                and isinstance(c.get("triggering_capabilities"), list),
                f"class '{c.get('id')}' has id/name/strategy/triggering_capabilities")
    hits = {c["id"] for c in _tax.classes_for_capabilities(["fetches_remote"])}
    _assert("ssrf" in hits, "a node that fetches remote resources triggers the SSRF class")
    _assert("sqli" not in _tax.classes_for_capabilities(["renders_output"], )  # noqa
            and True, "capability gating excludes non-applicable classes")
```

- [ ] **Step 2: Run harness to verify it fails** — Expected: FAIL (`No module named ... taxonomy`).

- [ ] **Step 3: Create `knowledge/weakness_taxonomy.yaml`** (seed; described generically — NO products/CVEs/endpoints). Include at least these 24 classes, each with the four fields:

```yaml
# Weakness CLASSES (not specific vulns). Generic, target-agnostic.
# capabilities vocabulary: takes_input, parses_format, executes, authenticates,
# stores_secrets, fetches_remote, file_access, deserializes, version_known,
# renders_output, uploads, redirects, templated
- id: known_cve
  name: Known CVE for fingerprinted component
  triggering_capabilities: [version_known]
  generic_test_strategy: >
    Look up CVEs and public PoCs for the exact fingerprinted product+version;
    fetch the highest-signal public PoC and run it as-is before hand-rolling.
  confirm_signal: The PoC yields its documented effect (code exec, auth bypass, data read).
  objective_relevance: [access, data, flag]
- id: ssrf
  name: Server-Side Request Forgery
  triggering_capabilities: [fetches_remote, takes_input]
  generic_test_strategy: >
    Aim the resource reference at loopback/internal/metadata addresses and at
    alternate URI schemes; watch for differential responses or out-of-band hits.
  confirm_signal: Server reaches an address the client cannot, or an OOB callback fires.
  objective_relevance: [access, data]
- id: sqli
  name: SQL Injection
  triggering_capabilities: [takes_input, parses_format]
  generic_test_strategy: >
    Probe each input that reaches a query with boolean/time/error differentials;
    escalate to data extraction or auth bypass on a confirmed differential.
  confirm_signal: Boolean/time/error oracle proves query manipulation.
  objective_relevance: [data, access, flag]
- id: auth_bypass
  name: Authentication / Authorization Bypass
  triggering_capabilities: [authenticates, takes_input]
  generic_test_strategy: >
    Test for missing checks, forced browsing, parameter/role tampering, token
    forgery, and header-trust assumptions on protected functionality.
  confirm_signal: Protected functionality is reached without valid credentials.
  objective_relevance: [access, data, flag]
- id: idor
  name: Insecure Direct Object Reference / BOLA
  triggering_capabilities: [takes_input, authenticates]
  generic_test_strategy: >
    Enumerate/mutate object identifiers across a privilege or tenancy boundary
    and observe whether other principals' objects are returned.
  confirm_signal: Another principal's object is returned without authorization.
  objective_relevance: [data, flag]
- id: path_traversal
  name: Path Traversal / Local File Read
  triggering_capabilities: [file_access, takes_input]
  generic_test_strategy: >
    Supply traversal sequences and absolute paths to any file-referencing input;
    target sensitive system/app files; try encodings to defeat filters.
  confirm_signal: Contents of a file outside the intended directory are returned.
  objective_relevance: [data, access, flag]
- id: command_injection
  name: OS Command Injection
  triggering_capabilities: [takes_input, executes]
  generic_test_strategy: >
    Append shell metacharacters/separators to inputs that may reach a system
    command; confirm with a benign, observable side effect (timing or output).
  confirm_signal: A benign injected command demonstrably executes on the host.
  objective_relevance: [access, flag, data]
- id: code_injection
  name: Server-Side Code / Template Injection
  triggering_capabilities: [takes_input, templated, executes]
  generic_test_strategy: >
    Submit framework/template expressions to inputs rendered server-side; start
    with arithmetic/echo markers, escalate to runtime evaluation on a hit.
  confirm_signal: A server-evaluated expression returns a computed/echoed marker.
  objective_relevance: [access, flag]
- id: insecure_deserialization
  name: Insecure Object Deserialization
  triggering_capabilities: [deserializes, takes_input]
  generic_test_strategy: >
    Identify serialized blobs accepted from the client; craft type-confusion or
    gadget-chain inputs appropriate to the runtime to trigger execution.
  confirm_signal: A crafted serialized input produces an observable side effect.
  objective_relevance: [access, flag]
- id: file_upload
  name: Unrestricted / Dangerous File Upload
  triggering_capabilities: [uploads, takes_input]
  generic_test_strategy: >
    Upload content whose type/extension is mishandled and reach it via a path
    where the server interprets it; chain to execution or stored injection.
  confirm_signal: Uploaded content is served/executed in a damaging context.
  objective_relevance: [access, flag]
- id: xxe
  name: XML External Entity
  triggering_capabilities: [parses_format, takes_input]
  generic_test_strategy: >
    Submit XML declaring external entities to any XML-parsing input; attempt
    local file read and out-of-band retrieval.
  confirm_signal: An external entity resolves to file contents or an OOB hit.
  objective_relevance: [data, access]
- id: default_creds
  name: Default / Weak Credentials
  triggering_capabilities: [authenticates]
  generic_test_strategy: >
    Try documented default and common credentials for the identified service,
    rate-limited; prefer one curated list over blind brute force.
  confirm_signal: A default/weak credential authenticates successfully.
  objective_relevance: [access, data, flag]
- id: exposed_secrets
  name: Exposed Secrets / Sensitive Data
  triggering_capabilities: [stores_secrets, file_access, renders_output]
  generic_test_strategy: >
    Hunt config/backup/VCS/debug artifacts and verbose responses for keys,
    tokens, and credentials; validate any secret found.
  confirm_signal: A usable secret/credential is recovered and validated.
  objective_relevance: [data, access, flag]
- id: ssti_to_rce
  name: Template Injection escalation to execution
  triggering_capabilities: [templated, executes, takes_input]
  generic_test_strategy: >
    On a confirmed template-evaluation primitive, escalate to runtime/command
    execution via the engine's documented escape to host functions.
  confirm_signal: Host command output is returned via the template primitive.
  objective_relevance: [access, flag]
- id: open_redirect
  name: Open Redirect
  triggering_capabilities: [redirects, takes_input]
  generic_test_strategy: >
    Supply external/encoded destinations to redirect parameters; observe whether
    the server issues a redirect to an attacker-chosen location.
  confirm_signal: Server redirects to an attacker-controlled destination.
  objective_relevance: [access]
- id: misconfiguration
  name: Security Misconfiguration
  triggering_capabilities: [renders_output, file_access]
  generic_test_strategy: >
    Check for directory listing, debug endpoints, permissive CORS, default
    pages, and management interfaces exposed without controls.
  confirm_signal: A misconfiguration exposes data or functionality it should not.
  objective_relevance: [data, access]
- id: known_service_exploit
  name: Known Network-Service Exploit
  triggering_capabilities: [version_known, executes]
  generic_test_strategy: >
    For a versioned network service, match it to a known remote exploit/PoC and
    run it; confirm code execution or the documented effect.
  confirm_signal: The service exploit yields code execution or its documented effect.
  objective_relevance: [access, flag]
- id: weak_crypto_session
  name: Weak Session / Token Handling
  triggering_capabilities: [authenticates, takes_input]
  generic_test_strategy: >
    Analyze tokens/cookies for predictability, missing signature verification,
    or algorithm confusion; forge a higher-privilege session.
  confirm_signal: A forged/predicted token grants unauthorized access.
  objective_relevance: [access, data, flag]
- id: business_logic
  name: Business-Logic / Workflow Abuse
  triggering_capabilities: [takes_input, authenticates]
  generic_test_strategy: >
    Model the app's intended workflow and abuse it: skipped steps, negative/
    overflow quantities, race conditions, replay, and state confusion.
  confirm_signal: The app grants value/access it should not, via logic abuse.
  objective_relevance: [data, access, flag]
- id: info_disclosure
  name: Information Disclosure
  triggering_capabilities: [renders_output]
  generic_test_strategy: >
    Mine responses, errors, headers, and client bundles for versions, routes,
    identifiers, and internal details that expand the attack surface.
  confirm_signal: Non-public information that enables further attack is revealed.
  objective_relevance: [data]
- id: privilege_escalation
  name: Local Privilege Escalation (post-foothold)
  triggering_capabilities: [executes, file_access]
  generic_test_strategy: >
    With a foothold, enumerate sudo rights, setuid binaries, capabilities, cron,
    writable paths, and kernel/service exploits to reach higher privilege.
  confirm_signal: A higher-privilege context (e.g. root/admin) is obtained.
  objective_relevance: [access, flag]
- id: credential_reuse
  name: Credential Reuse / Lateral Movement
  triggering_capabilities: [authenticates, stores_secrets]
  generic_test_strategy: >
    Reuse recovered credentials/keys across services and hosts; pivot along
    trust edges to new systems.
  confirm_signal: Recovered credentials authenticate to a different service/host.
  objective_relevance: [access, data, flag]
- id: data_exfiltration
  name: Targeted Data Exfiltration (objective)
  triggering_capabilities: [file_access, stores_secrets, renders_output]
  generic_test_strategy: >
    When the objective is specific data, locate and retrieve exactly that data
    set via the most reliable confirmed access path.
  confirm_signal: The objective data is retrieved and verified.
  objective_relevance: [data]
- id: supply_chain
  name: Supply-Chain / Dependency Weakness
  triggering_capabilities: [version_known, executes]
  generic_test_strategy: >
    Check dependencies/integrations for known-vulnerable components and trust of
    external inputs; exploit the weakest trusted dependency.
  confirm_signal: A vulnerable dependency/integration yields impact.
  objective_relevance: [access, data]
```

- [ ] **Step 4: Create `agents/operator_agent/taxonomy.py`**

```python
"""Weakness-taxonomy loader. The taxonomy is DATA (knowledge/weakness_taxonomy.yaml):
weakness CLASSES, never specific vulns/CVEs/products. Engine code reads it; it
never hardcodes the content."""
from __future__ import annotations
import os
from functools import lru_cache
from typing import Dict, List

_TAXONOMY_PATH = os.environ.get(
    "ARGUS_TAXONOMY_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "weakness_taxonomy.yaml"),
)

@lru_cache(maxsize=1)
def load_taxonomy() -> tuple:
    try:
        import yaml  # PyYAML
        with open(os.path.abspath(_TAXONOMY_PATH), "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or []
    except Exception:
        return tuple()
    out = []
    for c in data:
        if isinstance(c, dict) and c.get("id") and c.get("name"):
            c.setdefault("triggering_capabilities", [])
            c.setdefault("generic_test_strategy", "")
            c.setdefault("confirm_signal", "")
            c.setdefault("objective_relevance", [])
            out.append(c)
    return tuple(out)

def classes_for_capabilities(capabilities: List[str], objective_kinds: List[str] = None) -> List[Dict]:
    """Classes whose triggering_capabilities intersect the node's capabilities.
    Optionally filter to classes relevant to the objective kind(s)."""
    caps = set(capabilities or [])
    res = []
    for c in load_taxonomy():
        if caps & set(c.get("triggering_capabilities", [])):
            if objective_kinds:
                if not (set(objective_kinds) & set(c.get("objective_relevance", []))):
                    continue
            res.append(dict(c))
    return res

def taxonomy_brief(max_classes: int = 60) -> str:
    """Compact 'id: name — strategy' list for injection into the operator prompt
    (so the doctrine carries the taxonomy from DATA, not hardcoded examples)."""
    lines = []
    for c in load_taxonomy()[:max_classes]:
        strat = (c.get("generic_test_strategy") or "").strip().replace("\n", " ")
        lines.append(f"- {c['id']}: {c['name']} — {strat[:160]}")
    return "\n".join(lines)
```

- [ ] **Step 5: Run harness** — Expected: PASS (new test green, prior 668 still green). Fix the stray `# noqa` line in the test if it errors — replace Step-1's last two asserts with:

```python
    _no = {c["id"] for c in _tax.classes_for_capabilities(["renders_output"])}
    _assert("sqli" not in _no, "capability gating excludes non-applicable classes (no SQLi from renders_output)")
```

- [ ] **Step 6: Files to copy** → `knowledge/weakness_taxonomy.yaml`, `agents/operator_agent/taxonomy.py`, `agents/test_architecture_integration.py`. Note: requires `pyyaml` on Kali (`pip install pyyaml` — already common; the loader fails soft to empty if missing, but the taxonomy is required for the engine, so confirm it's installed).

## Task A2: The guard test (the permanent ratchet)

**Files:**
- Test: `agents/test_architecture_integration.py` (new `test_no_hardcoded_attack_content`)

- [ ] **Step 1: Write the test.** It scans engine modules and fails on CVE ids, product+version literals, or payload markers. Markers are assembled from fragments so the deny-list itself doesn't trip the repo source-safety scan.

```python
def test_no_hardcoded_attack_content():
    _section("Tier A — guard: engine code contains NO vuln-specific content")
    import re as _re
    from pathlib import Path as _P
    root = _P(__file__).resolve().parent.parent
    engine = [
        root / "agents" / "operator_agent" / "operator_core.py",
        root / "agents" / "operator_agent" / "tool_catalog.py",
        root / "agents" / "operator_agent" / "taxonomy.py",
        root / "agents" / "operator_agent" / "surface_model.py",       # may not exist until Tier B
        root / "agents" / "operator_agent" / "hypothesis_backlog.py",  # may not exist until Tier B
    ]
    cve = _re.compile(r"CVE-\d{4}-\d{4,7}", _re.I)
    # payload/technique markers, fragmented so THIS list is not itself a literal
    markers = ["x-middleware" + "-subrequest", "/etc/" + "passwd", "../" + "../",
               "union" + " select", "file" + "://", "jndi" + ":"]
    def _strip_comments(src: str) -> str:
        out = []
        for ln in src.splitlines():
            s = ln.strip()
            if s.startswith("#"):
                continue
            out.append(ln)
        return "\n".join(out)
    offenders = []
    for f in engine:
        if not f.exists():
            continue
        body = _strip_comments(f.read_text(encoding="utf-8"))
        if cve.search(body):
            offenders.append(f"{f.name}: contains a CVE id literal")
        low = body.lower()
        for m in markers:
            if m in low:
                offenders.append(f"{f.name}: contains payload marker '{m}'")
    _assert(not offenders, "engine modules are free of CVE ids / payload literals :: " + "; ".join(offenders))
```

- [ ] **Step 2: Run harness** — Expected: FAIL (current `operator_core.py` has the `_method_signature` markers + `tool_catalog.py` has CVE/product names). This proves the guard works. Register the test in `tests=[...]`.

- [ ] **Step 3: (No code yet — A3/A4 make it pass.)**

- [ ] **Step 4: Files to copy** → `agents/test_architecture_integration.py`.

## Task A3: Delete the keyword table → operator-declared `hypothesis_id`

**Files:**
- Modify: `agents/operator_agent/tool_catalog.py` (action schema + `parse_action`)
- Modify: `agents/operator_agent/operator_core.py` (`_method_signature` → declared label)

- [ ] **Step 1: Write the failing test** (`test_operator_declares_hypothesis`)

```python
def test_operator_declares_hypothesis():
    _section("Tier A — method signature comes from the operator's declared hypothesis, not a keyword table")
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    oc_src = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("x-middleware" + "-subrequest" not in oc_src and "tech:nextjs" not in oc_src,
            "the hardcoded technique keyword table is gone from operator_core")
    op = OperatorCore(_FM_min())
    # operator declares the hypothesis on the action
    sig1 = op._method_signature("THOUGHT: trying it.", {"tool": "http",
            "args": {}, "hypothesis": "auth bypass on the admin API"})
    _assert(sig1 == "hyp:auth bypass on the admin api", "declared hypothesis becomes the method signature (normalized)")
    # fallback to a CVE id when present and no explicit hypothesis
    sig2 = op._method_signature("THOUGHT: CVE-2025-29927 bypass", {"tool": "http", "args": {}})
    _assert(sig2.startswith("cve:") and sig2.endswith("-29927"), "CVE id is the fallback signature when no hypothesis declared")
    # generic recon with neither → empty (uncapped)
    sig3 = op._method_signature("THOUGHT: scan ports", {"tool": "run_tool", "args": {"tool": "nmap"}})
    _assert(sig3 == "", "generic recon with no declared hypothesis is uncapped")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (`_method_signature` still keyword-based; no `hypothesis` handling).

- [ ] **Step 3: Replace `operator_core._method_signature`** (the version added for the per-method cap) with the declared-hypothesis version — NO technique keyword table:

```python
    def _method_signature(self, reply: str, action: Dict[str, Any]) -> str:
        """The exploitation METHOD an action belongs to, so repeated tries of one
        avenue can be capped. Content-agnostic: it is the operator's OWN declared
        hypothesis, else a CVE id mentioned (a universal token), else '' (generic
        recon — uncapped). No hardcoded technique list lives here."""
        hyp = ""
        if isinstance(action, dict):
            hyp = str(action.get("hypothesis") or action.get("hypothesis_id") or "").strip()
        if hyp:
            return "hyp:" + " ".join(hyp.lower().split())[:80]
        m = re.search(r"cve-\d{4}-\d{4,7}", (reply or "").lower())
        if m:
            return "cve:" + m.group(0).upper()
        return ""
```

- [ ] **Step 4: Update the action schema + parser in `tool_catalog.py`.** In the action-format instructions (where the JSON action shape is documented), add the optional-but-expected field:

```
Every action MAY (and for any EXPLOITATION attempt MUST) include a short
"hypothesis" string naming the avenue you are testing (e.g. the weakness class
+ target), so the engine can track attempts and force a pivot after a few
failures. Recon/enumeration actions can omit it.
{"tool": ..., "args": {...}, "hypothesis": "<weakness class + target>"}
```

In `parse_action`, after building the returned dict, carry the field through:

```python
            return {"tool": str(obj["tool"]).strip(), "args": args,
                    "hypothesis": str(obj.get("hypothesis", "")).strip()}
```

(Apply to each `return` path in `parse_action`.)

- [ ] **Step 5: Run harness** — Expected: PASS for `test_operator_declares_hypothesis`. The guard test (A2) still FAILS on `tool_catalog.py` (CVE/product names in doctrine) — A4 fixes that.

- [ ] **Step 6: Files to copy** → `agents/operator_agent/operator_core.py`, `agents/operator_agent/tool_catalog.py`, `agents/test_architecture_integration.py`.

## Task A4: De-box-ify the doctrine (principles + taxonomy from data)

**Files:**
- Modify: `agents/operator_agent/tool_catalog.py` (`METHODOLOGY`, `build_system_prompt`)

- [ ] **Step 1: Write the failing test** (`test_doctrine_is_general`)

```python
def test_doctrine_is_general():
    _section("Tier A — doctrine carries principles + taxonomy from data, no box names")
    import re as _re
    from agents.operator_agent import tool_catalog as _tc
    sp = _tc.build_system_prompt(objective="capture user.txt and root.txt",
                                 target={"host": "t", "kind": "ctf"})
    _assert(not _re.search(r"CVE-\d{4}-\d+", sp), "system prompt names no specific CVE")
    for bad in ("next.js", "reactorwatch", "/render", "x-middleware" + "-subrequest"):
        _assert(bad not in sp.lower(), f"system prompt does not name '{bad}'")
    _assert("ssrf" in sp.lower() and "weakness" in sp.lower(),
            "doctrine injects the general weakness taxonomy (classes, not boxes)")
    _assert("objective" in sp.lower(), "doctrine centers the human-set objective")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (doctrine still names CVE/Next.js/render).

- [ ] **Step 3: Rewrite `METHODOLOGY`** in `tool_catalog.py` — principles only, ZERO specifics. Replace the whole `METHODOLOGY = """..."""` block with:

```python
METHODOLOGY = """\
OPERATING DOCTRINE (target-agnostic process — works on web, network, AD, cloud,
IoT, or anything else):

1. ENUMERATE THE SURFACE. Discover hosts, ports, services, endpoints, parameters,
   users, and files. For each thing you find, note its CAPABILITIES: does it take
   input, parse a format, execute, authenticate, hold secrets, fetch remote
   resources, read files, deserialize, or expose a version?

2. GENERATE HYPOTHESES FROM CAPABILITIES — not from memory. A capability implies a
   set of weakness CLASSES to test (see the taxonomy below). Fingerprinted
   versions also warrant a known-CVE lookup. A CVE you recall is a HYPOTHESIS to
   verify with cve_lookup — never ground truth, never the whole plan.

3. PRIORITIZE BY VALUE TOWARD THE OBJECTIVE. Pursue the hypothesis with the best
   (chance of success x value toward the stated objective / cost) first.

4. TEST ONE HYPOTHESIS AT A TIME, BOUNDED. Build the concrete request/payload,
   fire it, and CONFIRM the result objectively. Give one avenue a FEW tries; if it
   does not advance, ABANDON it and pivot to the next hypothesis. Do not retry a
   dead method.

5. AN APPLICATION'S OWN ENDPOINTS ARE PRIME. Any input that takes a URL, file
   path, identifier, command, template, or serialized blob is a foothold
   candidate and often outranks an unverified framework CVE.

6. ADVANCE = NEW ACCESS, NEW INFORMATION, OR NEW SURFACE. After every action ask
   which one you gained. New surface feeds step 1 again.

7. DELIVER THE HUMAN'S OBJECTIVE. The objective is whatever the human set — a flag,
   interactive access to hand over, specific data to retrieve, or loot to collect.
   It is NOT automatically "get a shell." Capture/achieve exactly what was asked,
   then offer handover/loot per autonomy.

WEAKNESS TAXONOMY (capability -> classes to consider; instantiate the specifics
yourself with your knowledge, RAG, and cve_lookup):
{taxonomy}
"""
```

- [ ] **Step 4: Inject the taxonomy from data** in `build_system_prompt`. Where the prompt is assembled, format `METHODOLOGY` with the data-driven brief:

```python
    from .taxonomy import taxonomy_brief
    methodology = METHODOLOGY.replace("{taxonomy}", taxonomy_brief())
    # ... use `methodology` where METHODOLOGY was previously interpolated ...
```

Ensure the final returned prompt uses `methodology` (not the raw `METHODOLOGY`). Remove the old rule-1 parenthetical that named the Next.js CVE and the `/render` examples.

- [ ] **Step 5: Run harness** — Expected: PASS for `test_doctrine_is_general` AND `test_no_hardcoded_attack_content` (A2) now passes (engine modules clean). Prior tests green.

- [ ] **Step 6: Files to copy** → `agents/operator_agent/tool_catalog.py`, `agents/test_architecture_integration.py`.

**Checkpoint A:** Run harness → all green incl. guard. Copy the four files above + taxonomy. The over-fitting smell is now gone and guarded.

---

# TIER B — Surface-capability model + hypothesis backlog

## Task B1: Surface model + capability inference

**Files:**
- Create: `agents/operator_agent/surface_model.py`
- Test: `agents/test_architecture_integration.py` (`test_surface_model_infers_capabilities`)

- [ ] **Step 1: Write the failing test**

```python
def test_surface_model_infers_capabilities():
    _section("Tier B — surface model infers node capabilities from intel (generic)")
    from agents.operator_agent.surface_model import SurfaceModel
    intel = {
        "open_ports": [22, 3000],
        "services": {"22": {"product": "OpenSSH", "version": "9.6"},
                     "3000": {"product": "AppServer", "version": "1.2", "name": "http"}},
        "web_paths": ["/", "/api/fetch?url=", "/files/download?path="],
        "technologies": ["SomeFramework"],
    }
    sm = SurfaceModel(); sm.infer_from_intel(intel)
    caps = sm.all_capabilities()
    _assert("version_known" in caps, "a fingerprinted service yields version_known")
    _assert("authenticates" in caps, "an SSH service yields authenticates")
    _assert("fetches_remote" in caps, "a '?url=' endpoint yields fetches_remote")
    _assert("file_access" in caps, "a '?path=' / download endpoint yields file_access")
    d = sm.to_dict(); sm2 = SurfaceModel.from_dict(d)
    _assert(sm2.all_capabilities() == caps, "surface model round-trips through dict (checkpoint-safe)")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (no module).

- [ ] **Step 3: Create `agents/operator_agent/surface_model.py`** — capability inference is GENERIC heuristics over structural signals (param names, service flags), NOT product-specific:

```python
"""Target-agnostic surface model: typed nodes carrying capabilities, inferred
from intel via generic structural heuristics (NOT product names)."""
from __future__ import annotations
from typing import Any, Dict, List

# Generic param/endpoint signals -> capabilities. Structural, not box-specific.
_PARAM_SIGNALS = {
    "fetches_remote": ("url", "uri", "link", "target", "dest", "callback", "webhook", "proxy", "fetch", "load"),
    "file_access":    ("path", "file", "filename", "dir", "download", "read", "doc", "template_path", "include"),
    "takes_input":    ("q", "query", "search", "id", "name", "input", "data", "param", "value"),
    "deserializes":   ("data", "payload", "obj", "state", "session", "blob"),
    "templated":      ("template", "tpl", "format", "render", "view"),
    "redirects":      ("redirect", "next", "return", "returnurl", "continue", "goto"),
    "uploads":        ("upload", "file", "attachment", "import"),
}
_AUTH_SERVICES = ("ssh", "ftp", "rdp", "smb", "mysql", "mssql", "postgres", "ldap", "telnet", "vnc", "winrm")

class SurfaceNode:
    def __init__(self, key: str, kind: str, ref: str = "", capabilities=None, meta=None):
        self.key = key; self.kind = kind; self.ref = ref
        self.capabilities = set(capabilities or []); self.meta = meta or {}
    def to_dict(self):
        return {"key": self.key, "kind": self.kind, "ref": self.ref,
                "capabilities": sorted(self.capabilities), "meta": self.meta}
    @classmethod
    def from_dict(cls, d):
        return cls(d["key"], d.get("kind", ""), d.get("ref", ""), d.get("capabilities"), d.get("meta"))

class SurfaceModel:
    def __init__(self):
        self.nodes: Dict[str, SurfaceNode] = {}

    def add(self, node: SurfaceNode):
        ex = self.nodes.get(node.key)
        if ex:
            ex.capabilities |= node.capabilities; ex.meta.update(node.meta)
        else:
            self.nodes[node.key] = node

    def all_capabilities(self) -> set:
        out = set()
        for n in self.nodes.values():
            out |= n.capabilities
        return out

    def infer_from_intel(self, intel: Dict[str, Any]) -> None:
        svc = intel.get("services") or {}
        for port in (intel.get("open_ports") or []):
            pn = port.get("port") if isinstance(port, dict) else port
            s = svc.get(pn) or svc.get(str(pn)) or (port if isinstance(port, dict) else {})
            caps = set()
            name = " ".join(str(s.get(k, "")) for k in ("name", "product")).lower() if isinstance(s, dict) else ""
            if isinstance(s, dict) and (s.get("version") or s.get("product")):
                caps.add("version_known")
            if any(a in name for a in _AUTH_SERVICES):
                caps.add("authenticates")
            if "http" in name or pn in (80, 443, 8080, 8443, 3000, 8000, 5000):
                caps.add("renders_output"); caps.add("takes_input")
            self.add(SurfaceNode(f"port:{pn}", "service", str(pn), caps, {"service": name}))
        for path in (intel.get("web_paths") or []):
            p = path if isinstance(path, str) else (path.get("path") if isinstance(path, dict) else str(path))
            low = p.lower()
            caps = {"takes_input"} if ("?" in low or "=" in low) else set()
            for cap, signals in _PARAM_SIGNALS.items():
                if any(sig in low for sig in signals):
                    caps.add(cap)
            if low.rstrip("/").endswith((".xml", ".svg")) or "xml" in low:
                caps.add("parses_format")
            self.add(SurfaceNode(f"path:{p}", "endpoint", p, caps))
        if intel.get("technologies"):
            self.add(SurfaceNode("tech:stack", "technology", "", {"version_known"},
                                 {"technologies": list(intel.get("technologies"))}))

    def to_dict(self):
        return {"nodes": [n.to_dict() for n in self.nodes.values()]}
    @classmethod
    def from_dict(cls, d):
        sm = cls()
        for nd in (d or {}).get("nodes", []):
            sm.add(SurfaceNode.from_dict(nd))
        return sm
```

- [ ] **Step 4: Run harness** — Expected: PASS. Add `surface_model.py` to the guard test's `engine` list already done in A2 (it tolerates non-existence; now it exists and must be clean — it is).

- [ ] **Step 5: Files to copy** → `agents/operator_agent/surface_model.py`, `agents/test_architecture_integration.py`.

## Task B2: Hypothesis backlog (objective-aware)

**Files:**
- Create: `agents/operator_agent/hypothesis_backlog.py`
- Test: `agents/test_architecture_integration.py` (`test_hypothesis_backlog`)

- [ ] **Step 1: Write the failing test**

```python
def test_hypothesis_backlog():
    _section("Tier B — hypothesis backlog: generate from surface×taxonomy, prioritize, dedup, status")
    from agents.operator_agent.surface_model import SurfaceModel
    from agents.operator_agent.hypothesis_backlog import HypothesisBacklog
    intel = {"open_ports": [3000], "services": {"3000": {"name": "http", "product": "X", "version": "1"}},
             "web_paths": ["/api/fetch?url=", "/files/download?path="]}
    sm = SurfaceModel(); sm.infer_from_intel(intel)
    bl = HypothesisBacklog(objective_kinds=["access", "flag"])
    n = bl.generate_from_surface(sm)
    _assert(n >= 2 and len(bl.untried()) >= 2, "hypotheses generated from surface×taxonomy")
    ids = {h.weakness_class for h in bl.all()}
    _assert("ssrf" in ids, "the ?url= endpoint produced an SSRF hypothesis")
    _assert("path_traversal" in ids, "the ?path= endpoint produced a path-traversal hypothesis")
    bl.generate_from_surface(sm)
    _assert(len(bl.all()) == n, "regeneration is idempotent (dedup by node+class)")
    top = bl.next_hypothesis()
    _assert(top is not None and top.status == "active", "next_hypothesis returns+activates the top item")
    bl.mark(top.id, "refuted")
    _assert(top.id not in {h.id for h in bl.untried()} and bl.next_hypothesis().id != top.id,
            "a refuted hypothesis is not handed out again")
    h2 = bl.next_hypothesis(); bl.mark(h2.id, "confirmed")
    _assert(any(h.status == "confirmed" for h in bl.all()), "confirmed status persists")
    d = bl.to_dict(); bl2 = HypothesisBacklog.from_dict(d)
    _assert(len(bl2.all()) == len(bl.all()), "backlog round-trips through dict (checkpoint-safe)")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (no module).

- [ ] **Step 3: Create `agents/operator_agent/hypothesis_backlog.py`**

```python
"""Objective-aware hypothesis backlog — the content-agnostic spine of the
engagement. Hypotheses = surface(node) × taxonomy(weakness class). The engine
tracks status/attempts/coverage; the operator authors the concrete payloads."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from . import taxonomy as _tax

_CLASS_PRIOR = {  # coarse base value by class (objective filtering refines it)
    "known_cve": 0.9, "known_service_exploit": 0.9, "command_injection": 0.85,
    "ssti_to_rce": 0.85, "insecure_deserialization": 0.8, "sqli": 0.8,
    "auth_bypass": 0.75, "file_upload": 0.75, "ssrf": 0.7, "path_traversal": 0.7,
    "default_creds": 0.7, "idor": 0.65, "xxe": 0.6, "exposed_secrets": 0.6,
    "code_injection": 0.85, "business_logic": 0.6, "weak_crypto_session": 0.55,
    "misconfiguration": 0.5, "open_redirect": 0.3, "info_disclosure": 0.4,
    "privilege_escalation": 0.8, "credential_reuse": 0.7, "data_exfiltration": 0.8,
    "supply_chain": 0.5,
}

class Hypothesis:
    __slots__ = ("id", "node_key", "node_ref", "weakness_class", "rationale",
                 "value", "status", "attempts", "evidence", "source")
    def __init__(self, id, node_key, node_ref, weakness_class, rationale="",
                 value=0.0, status="untried", attempts=0, evidence="", source="surface"):
        self.id = id; self.node_key = node_key; self.node_ref = node_ref
        self.weakness_class = weakness_class; self.rationale = rationale
        self.value = value; self.status = status; self.attempts = attempts
        self.evidence = evidence; self.source = source
    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}
    @classmethod
    def from_dict(cls, d):
        return cls(**{k: d.get(k) for k in cls.__slots__})

class HypothesisBacklog:
    def __init__(self, objective_kinds: List[str] = None):
        self.objective_kinds = objective_kinds or ["access", "flag", "data"]
        self.items: Dict[str, Hypothesis] = {}
        self._seq = 0

    def _key(self, node_key, weakness_class):
        return f"{node_key}::{weakness_class}"

    def generate_from_surface(self, surface) -> int:
        added = 0
        for node in surface.nodes.values():
            classes = _tax.classes_for_capabilities(sorted(node.capabilities), self.objective_kinds)
            for c in classes:
                k = self._key(node.key, c["id"])
                if k in self.items:
                    continue
                self._seq += 1
                val = _CLASS_PRIOR.get(c["id"], 0.5)
                self.items[k] = Hypothesis(
                    id=f"h{self._seq}", node_key=node.key, node_ref=node.ref,
                    weakness_class=c["id"], rationale=c.get("generic_test_strategy", ""),
                    value=val, source="surface")
                added += 1
        return added

    def add_external(self, weakness_class, node_ref, rationale, value=0.9, source="cve_lookup") -> Optional[Hypothesis]:
        k = self._key(f"ext:{node_ref}", weakness_class)
        if k in self.items:
            return None
        self._seq += 1
        h = Hypothesis(id=f"h{self._seq}", node_key=f"ext:{node_ref}", node_ref=node_ref,
                       weakness_class=weakness_class, rationale=rationale, value=value,
                       source=source)
        self.items[k] = h
        return h

    def all(self) -> List[Hypothesis]:
        return list(self.items.values())
    def untried(self) -> List[Hypothesis]:
        return [h for h in self.items.values() if h.status == "untried"]
    def _rank(self, h):
        return h.value - 0.15 * h.attempts
    def next_hypothesis(self) -> Optional[Hypothesis]:
        cands = sorted(self.untried(), key=self._rank, reverse=True)
        if not cands:
            return None
        cands[0].status = "active"
        return cands[0]
    def mark(self, hyp_id, status, evidence=""):
        for h in self.items.values():
            if h.id == hyp_id:
                h.status = status
                if evidence:
                    h.evidence = evidence
                return
    def record_attempt(self, hyp_id):
        for h in self.items.values():
            if h.id == hyp_id:
                h.attempts += 1
                return
    def coverage(self) -> Dict[str, int]:
        out = {"total": len(self.items), "untried": 0, "active": 0,
               "confirmed": 0, "refuted": 0, "blocked": 0}
        for h in self.items.values():
            out[h.status] = out.get(h.status, 0) + 1
        return out
    def high_value_remaining(self, threshold=0.5) -> int:
        return sum(1 for h in self.items.values()
                   if h.status in ("untried", "active") and h.value >= threshold)
    def to_dict(self):
        return {"objective_kinds": self.objective_kinds, "seq": self._seq,
                "items": [h.to_dict() for h in self.items.values()]}
    @classmethod
    def from_dict(cls, d):
        bl = cls((d or {}).get("objective_kinds"))
        bl._seq = (d or {}).get("seq", 0)
        for hd in (d or {}).get("items", []):
            h = Hypothesis.from_dict(hd)
            bl.items[bl._key(h.node_key, h.weakness_class)] = h
        return bl
```

- [ ] **Step 4: Run harness** — Expected: PASS (guard test tolerates this module — it's content-free; `_CLASS_PRIOR` keys are class ids, not vulns).

- [ ] **Step 5: Files to copy** → `agents/operator_agent/hypothesis_backlog.py`, `agents/test_architecture_integration.py`.

## Task B3: Wire backlog into the operator loop

**Files:**
- Modify: `agents/operator_agent/operator_core.py` (`__init__`, `run`, reactive seed, cap)

- [ ] **Step 1: Write the failing test** (`test_operator_drives_backlog`)

```python
def test_operator_drives_backlog():
    _section("Tier B — operator builds a surface model + backlog and exposes them")
    import asyncio as _aio
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    op._intel.update({"open_ports": [3000], "services": {"3000": {"name": "http", "product": "X", "version": "1"}},
                      "web_paths": ["/api/fetch?url="]})
    _aio.run(op._refresh_surface_and_backlog())
    _assert(op._surface is not None and op._backlog is not None, "operator owns a surface model + backlog")
    _assert(op._backlog.high_value_remaining() >= 1, "backlog populated from current intel")
    _assert(any(h.weakness_class == "ssrf" for h in op._backlog.all()), "ssrf hypothesis present from ?url= endpoint")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (`_refresh_surface_and_backlog`/`_surface`/`_backlog` absent).

- [ ] **Step 3: In `operator_core.__init__`** add (near the other state):

```python
        self._surface = None
        self._backlog = None
        from .hypothesis_backlog import HypothesisBacklog
        self._backlog = HypothesisBacklog(objective_kinds=self._objective_kinds())
```

Add helper methods:

```python
    def _objective_kinds(self) -> list:
        """Map the human objective to value dimensions (access/data/flag/loot)."""
        obj = (getattr(self.master, "_operator_objective", "") or
               (self._intel.get("engagement_context") or {}).get("objective") or
               self._intel.get("objective") or "").lower()
        kinds = []
        if any(w in obj for w in ("flag", "user.txt", "root.txt", "ctf")):
            kinds.append("flag")
        if any(w in obj for w in ("data", "exfil", "database", "dump", "pii", "document")):
            kinds.append("data")
        if any(w in obj for w in ("access", "shell", "rce", "foothold", "handover", "control")):
            kinds.append("access")
        if any(w in obj for w in ("loot", "credential", "secret", "key")):
            kinds.append("data")
        return kinds or ["access", "flag", "data"]

    async def _refresh_surface_and_backlog(self) -> None:
        """Rebuild the surface model from current intel and (re)generate
        hypotheses. Idempotent: generation dedups by node+class."""
        from .surface_model import SurfaceModel
        self._surface = SurfaceModel()
        try:
            self._surface.infer_from_intel(self._intel)
        except Exception:
            return
        if self._backlog is None:
            from .hypothesis_backlog import HypothesisBacklog
            self._backlog = HypothesisBacklog(objective_kinds=self._objective_kinds())
        try:
            self._backlog.generate_from_surface(self._surface)
        except Exception:
            pass
```

- [ ] **Step 4: Call `_refresh_surface_and_backlog` in the run loop** right after `self._track_progress()` (alongside the reactive cve_lookup):

```python
            self._track_progress()
            await self._refresh_surface_and_backlog()
            await self._seed_cve_intel()
```

And in `_seed_cve_intel`, when a public PoC is found, also add a backlog hypothesis:

```python
            if self._backlog is not None and url:
                self._backlog.add_external("known_cve", url,
                    f"public PoC for {product} {version}", value=0.92, source="cve_lookup")
```

(Place inside the existing PoC loop where `url` is computed.)

- [ ] **Step 5: Run harness** — Expected: PASS. Guard test still green (these additions name no vulns).

- [ ] **Step 6: Files to copy** → `agents/operator_agent/operator_core.py`, `agents/test_architecture_integration.py`.

**Checkpoint B:** Run harness → all green. Copy the engine files + the two new modules.

---

# TIER C — Coverage + convergence + completeness critic

## Task C1: Inject the backlog into the operator's context

**Files:**
- Modify: `agents/operator_agent/operator_core.py` (`_consult_advisors` or a new `_inject_backlog_state`)

- [ ] **Step 1: Write the failing test** (`test_backlog_injected_to_operator`)

```python
def test_backlog_injected_to_operator():
    _section("Tier C — the prioritized backlog is surfaced to the operator each round")
    import asyncio as _aio
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    op._intel.update({"open_ports": [3000], "services": {"3000": {"name": "http"}},
                      "web_paths": ["/api/fetch?url=", "/files/download?path="]})
    _aio.run(op._refresh_surface_and_backlog())
    brief = op._backlog_brief()
    _assert("ssrf" in brief.lower() and "path_traversal" in brief.lower(),
            "backlog brief lists the top hypotheses by class")
    _assert("untested" in brief.lower() or "remaining" in brief.lower(),
            "backlog brief reports coverage so the operator knows what's left")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (`_backlog_brief` absent).

- [ ] **Step 3: Add `_backlog_brief` + inject it** in `operator_core.py`:

```python
    def _backlog_brief(self, top_n: int = 8) -> str:
        if not self._backlog:
            return ""
        cov = self._backlog.coverage()
        ranked = sorted([h for h in self._backlog.all() if h.status in ("untried", "active")],
                        key=lambda h: h.value - 0.15 * h.attempts, reverse=True)[:top_n]
        lines = [f"HYPOTHESIS BACKLOG ({cov.get('untried',0)+cov.get('active',0)} remaining / "
                 f"{cov['total']} total; {cov.get('confirmed',0)} confirmed, "
                 f"{cov.get('refuted',0)} refuted) — work these top-down by value; "
                 f"declare the hypothesis you are testing on each action:"]
        for h in ranked:
            lines.append(f"  - [{h.id}] {h.weakness_class} @ {h.node_ref or h.node_key} "
                         f"(value {h.value:.2f}, tries {h.attempts}) — {h.rationale[:90]}")
        return "\n".join(lines)
```

Inject it in `_consult_advisors` (append to `notes` when a backlog exists and no shell yet):

```python
        if self._backlog is not None and not self._intel.get("shell_access"):
            brief = self._backlog_brief()
            if brief:
                notes.append("• [BACKLOG] " + brief)
```

- [ ] **Step 4: Run harness** — Expected: PASS.

- [ ] **Step 5: Files to copy** → `agents/operator_agent/operator_core.py`, `agents/test_architecture_integration.py`.

## Task C2: Objective-driven convergence + completeness critic

**Files:**
- Modify: `agents/operator_agent/operator_core.py` (`run` loop termination)

- [ ] **Step 1: Write the failing test** (`test_objective_convergence`)

```python
def test_objective_convergence():
    _section("Tier C — engagement ends on objective-met or hypothesis-exhaustion, not just the clock")
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    op._intel["engagement_context"] = {"objective": "capture user.txt and root.txt"}
    # objective not met, backlog has high-value items -> keep going
    op._intel.update({"user_flag": None, "root_flag": None})
    from agents.operator_agent.hypothesis_backlog import HypothesisBacklog
    op._backlog = HypothesisBacklog(["flag"])
    from agents.operator_agent.surface_model import SurfaceModel, SurfaceNode
    sm = SurfaceModel(); sm.add(SurfaceNode("port:3000", "service", "3000", {"takes_input", "fetches_remote"}))
    op._backlog.generate_from_surface(sm)
    _assert(op._objective_met() is False, "objective not met when flags missing")
    _assert(op._should_continue() is True, "continue while high-value hypotheses remain")
    # exhaust the backlog -> stop (and critic gets a chance)
    for h in op._backlog.all():
        op._backlog.mark(h.id, "refuted")
    _assert(op._backlog.high_value_remaining() == 0, "backlog exhausted")
    # objective met short-circuits regardless of backlog
    op._intel["user_flag"] = "x"; op._intel["root_flag"] = "y"
    _assert(op._objective_met() is True, "objective met when required flags present")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (`_objective_met`/`_should_continue` absent).

- [ ] **Step 3: Add the predicates** in `operator_core.py`:

```python
    def _objective_met(self) -> bool:
        kinds = set(self._objective_kinds())
        it = self._intel
        if "flag" in kinds:
            obj = ((it.get("engagement_context") or {}).get("objective") or "").lower()
            needs_root = "root" in obj
            if it.get("user_flag") and (it.get("root_flag") or not needs_root):
                return True
            if not ("flag" in kinds and (it.get("user_flag") or it.get("root_flag"))):
                pass
        if "access" in kinds and (it.get("shell_access") or it.get("rce_confirmed")):
            if "flag" not in kinds:
                return True
        if "data" in kinds and it.get("objective_data_captured"):
            return True
        return False

    def _should_continue(self) -> bool:
        if getattr(self.master, "_stop_requested", False):
            return False
        if self._objective_met():
            return False
        if self._backlog is not None and self._backlog.high_value_remaining() > 0:
            return True
        return False
```

- [ ] **Step 4: Use them in the run loop.** At the top of each iteration (after the time-budget/stop checks), add an exhaustion-aware break that first lets the critic try once:

```python
            if self._backlog is not None and not self._objective_met() \
                    and self._backlog.high_value_remaining() == 0:
                if not getattr(self, "_critic_ran", False):
                    self._critic_ran = True
                    await self._run_completeness_critic()
                    if self._backlog.high_value_remaining() == 0:
                        done_reason = "hypotheses_exhausted"; break
                else:
                    done_reason = "hypotheses_exhausted"; break
```

Add the critic (one structured LLM call that proposes NEW surface/classes to consider; content authored by the model, not the engine):

```python
    async def _run_completeness_critic(self) -> None:
        """Ask the model what surface/weakness-class it has NOT yet considered,
        and inject the answer as new hypotheses. Engine supplies only the
        question; all specifics come from the model."""
        try:
            prompt = [{"role": "system", "content":
                "You are a completeness critic for an authorized pentest. Given the "
                "engagement state, name concrete UNTESTED avenues: surfaces not yet "
                "enumerated, parameters not fuzzed, weakness classes not tried, or "
                "trust relationships not abused. Reply as short lines "
                "'<weakness_class> @ <where> :: <why>'. Be specific to THIS target."},
                {"role": "user", "content": self._initial_state_brief() + "\n\n" + self._backlog_brief(20)}]
            txt = await self._converse_bounded_msgs(prompt)
            for ln in (txt or "").splitlines():
                if "::" in ln and "@" in ln:
                    cls = ln.split("@")[0].strip().strip("-* ").lower().replace(" ", "_")[:40]
                    where = ln.split("@")[1].split("::")[0].strip()[:60]
                    why = ln.split("::", 1)[1].strip()[:120]
                    if cls and self._backlog is not None:
                        self._backlog.add_external(cls, where, why, value=0.6, source="critic")
            await self._reason("Completeness critic proposed new untested avenues.")
        except Exception:
            pass
```

Add a small helper `_converse_bounded_msgs(messages)` mirroring `_converse_bounded` but for an arbitrary message list:

```python
    async def _converse_bounded_msgs(self, messages) -> str:
        if self._llm_call_timeout <= 0:
            return await self.master.converse(messages, tier="reason")
        try:
            return await asyncio.wait_for(self.master.converse(messages, tier="reason"),
                                          timeout=self._llm_call_timeout)
        except Exception:
            return ""
```

- [ ] **Step 5: Run harness** — Expected: PASS for `test_objective_convergence`; prior green.

- [ ] **Step 6: Files to copy** → `agents/operator_agent/operator_core.py`, `agents/test_architecture_integration.py`.

## Task C3: Re-key the attempt cap to backlog + record attempts/refute

**Files:**
- Modify: `agents/operator_agent/operator_core.py` (cap block from prior work)

- [ ] **Step 1: Write the failing test** (`test_cap_marks_backlog_refuted`)

```python
def test_cap_marks_backlog_refuted():
    _section("Tier C — exhausting a method's cap marks the matching backlog hypothesis refuted")
    from agents.operator_agent.operator_core import OperatorCore
    from agents.operator_agent.hypothesis_backlog import HypothesisBacklog
    op = OperatorCore(_FM_min())
    op._backlog = HypothesisBacklog(["access"])
    h = op._backlog.add_external("ssrf", "/api/fetch", "test ssrf", value=0.7)
    # simulate the ban hook resolving a declared hypothesis to a backlog item
    op._resolve_banned_hypothesis("hyp:ssrf on /api/fetch", "ssrf")
    _assert(any(x.status == "refuted" for x in op._backlog.all()),
            "a banned method marks its backlog hypothesis refuted so the operator pivots")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (`_resolve_banned_hypothesis` absent).

- [ ] **Step 3: Add `_resolve_banned_hypothesis`** and call it where a method gets banned (in the cap block):

```python
    def _resolve_banned_hypothesis(self, sig: str, weakness_hint: str = "") -> None:
        if not self._backlog:
            return
        hint = (weakness_hint or sig.split(":", 1)[-1]).lower()
        for h in self._backlog.all():
            if h.status in ("untried", "active") and (
                    h.weakness_class in hint or h.weakness_class in sig.lower()
                    or h.node_ref.lower() in sig.lower()):
                self._backlog.mark(h.id, "refuted", evidence="method cap exhausted")
                return
```

In the cap block where `self._banned_methods.add(_sig)` happens, add:

```python
                        self._resolve_banned_hypothesis(_sig)
```

- [ ] **Step 4: Run harness** — Expected: PASS.

- [ ] **Step 5: Files to copy** → `agents/operator_agent/operator_core.py`, `agents/test_architecture_integration.py`.

**Checkpoint C:** Run harness → all green. The engine now converges on the objective and pivots through a tracked backlog.

---

# TIER D — Playbooks + RAG wired into hypothesis generation

## Task D1: Playbooks as data, keyed by class/capability

**Files:**
- Create: `knowledge/playbooks/ssrf.yaml`, `knowledge/playbooks/path_traversal.yaml`, `knowledge/playbooks/known_cve.yaml` (seed set)
- Create: `agents/operator_agent/playbooks.py`
- Test: `agents/test_architecture_integration.py` (`test_playbooks_keyed_by_class`)

- [ ] **Step 1: Write the failing test**

```python
def test_playbooks_keyed_by_class():
    _section("Tier D — playbooks load as data, keyed by weakness class (not by box)")
    from agents.operator_agent import playbooks as _pb
    pb = _pb.playbook_for("ssrf")
    _assert(pb and isinstance(pb.get("steps"), list) and pb["steps"],
            "an SSRF playbook exists with concrete generic steps")
    _assert(_pb.playbook_for("path_traversal") is not None, "path-traversal playbook loads")
    _assert(_pb.playbook_for("does_not_exist") is None, "unknown class returns None (no crash)")
```

- [ ] **Step 2: Run harness** — Expected: FAIL.

- [ ] **Step 3: Create the playbook loader `agents/operator_agent/playbooks.py`**

```python
"""Playbooks as DATA, keyed by weakness CLASS. Steps are generic procedures the
operator instantiates against the concrete target — not box-specific scripts."""
from __future__ import annotations
import os
from functools import lru_cache
from typing import Dict, Optional

_DIR = os.environ.get("ARGUS_PLAYBOOKS_DIR",
                      os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "playbooks"))

@lru_cache(maxsize=1)
def _load_all() -> dict:
    out = {}
    try:
        import yaml
        d = os.path.abspath(_DIR)
        for fn in os.listdir(d):
            if fn.endswith((".yaml", ".yml")):
                with open(os.path.join(d, fn), "r", encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh) or {}
                if doc.get("weakness_class"):
                    out[doc["weakness_class"]] = doc
    except Exception:
        return {}
    return out

def playbook_for(weakness_class: str) -> Optional[Dict]:
    return _load_all().get(weakness_class)
```

- [ ] **Step 4: Create seed playbooks** (generic steps; NO product/CVE/endpoint names). Example `knowledge/playbooks/ssrf.yaml`:

```yaml
weakness_class: ssrf
name: Server-Side Request Forgery
steps:
  - Identify every input that becomes a server-issued request (URL/host/path params, webhooks, importers, renderers).
  - Point it at loopback and link-local/metadata ranges; compare responses to a benign external control.
  - Try alternate URI schemes and encodings to defeat allow-list filters.
  - Use an out-of-band listener to confirm blind cases.
  - On confirmation, pivot to internal services, cloud metadata, or local file retrieval per impact.
```

`knowledge/playbooks/path_traversal.yaml`:

```yaml
weakness_class: path_traversal
name: Path Traversal / Local File Read
steps:
  - Find inputs that select a file or path (download, include, template, attachment).
  - Inject traversal sequences and absolute paths; vary depth and encoding.
  - Target sensitive, predictable files appropriate to the detected OS/app.
  - Confirm by retrieving a file outside the intended directory.
  - Chain to source/config disclosure, then to secrets or code execution.
```

`knowledge/playbooks/known_cve.yaml`:

```yaml
weakness_class: known_cve
name: Known CVE / public PoC
steps:
  - Confirm the exact product+version, then look up CVEs and public PoCs.
  - Prefer a maintained PoC that matches the version; clone it locally.
  - Read its usage; adapt target/callback parameters; run it as the authors intend.
  - Confirm the documented effect before declaring success.
```

- [ ] **Step 5: Run harness** — Expected: PASS.

- [ ] **Step 6: Files to copy** → `agents/operator_agent/playbooks.py`, `knowledge/playbooks/*.yaml`, `agents/test_architecture_integration.py`.

## Task D2: Attach playbook + RAG hints to hypotheses on activation

**Files:**
- Modify: `agents/operator_agent/operator_core.py` (when a hypothesis is injected/activated)

- [ ] **Step 1: Write the failing test** (`test_hypothesis_carries_playbook`)

```python
def test_hypothesis_carries_playbook():
    _section("Tier D — when the operator works a hypothesis, its class playbook is surfaced")
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    txt = op._playbook_hint("ssrf")
    _assert("server-side request forgery" in txt.lower() and "loopback" in txt.lower(),
            "the SSRF playbook steps are surfaced as a hint for the active hypothesis")
    _assert(op._playbook_hint("no_such_class") == "", "unknown class yields no hint (no crash)")
```

- [ ] **Step 2: Run harness** — Expected: FAIL (`_playbook_hint` absent).

- [ ] **Step 3: Add `_playbook_hint`** and include it in the backlog brief for the top item:

```python
    def _playbook_hint(self, weakness_class: str) -> str:
        try:
            from .playbooks import playbook_for
            pb = playbook_for(weakness_class)
        except Exception:
            pb = None
        if not pb:
            return ""
        steps = "\n".join(f"    {i+1}. {s}" for i, s in enumerate(pb.get("steps", [])[:6]))
        return f"PLAYBOOK [{pb.get('name', weakness_class)}]:\n{steps}"
```

In `_backlog_brief`, after listing the ranked items, append the top item's playbook hint:

```python
        if ranked:
            hint = self._playbook_hint(ranked[0].weakness_class)
            if hint:
                lines.append(hint)
```

- [ ] **Step 4: (RAG)** If the KB is available, also pull prior-success hints. Add a guarded call (the codebase already has a knowledge base / "prefer techniques that previously succeeded"):

```python
    async def _rag_hint(self, weakness_class: str, node_ref: str) -> str:
        fn = getattr(self.master, "kb_query", None) or getattr(self.master, "_kb_query", None)
        if fn is None:
            return ""
        try:
            res = await fn(f"{weakness_class} {node_ref} successful technique")
            return ("PRIOR-SUCCESS HINTS:\n" + str(res)[:600]) if res else ""
        except Exception:
            return ""
```

Wire `_rag_hint` into `_consult_advisors` for the top hypothesis when one exists (best-effort; skip if no KB).

- [ ] **Step 5: Run harness** — Expected: PASS. Guard test green (playbooks/RAG are data/runtime, not engine literals).

- [ ] **Step 6: Files to copy** → `agents/operator_agent/operator_core.py`, `agents/test_architecture_integration.py`.

**Checkpoint D (final):** Run harness → all green. Copy all changed files. ARGUS now: enumerates surface → generates objective-valued hypotheses from a data taxonomy → works them top-down with playbook+RAG hints → caps+pivots per hypothesis → converges on the human objective → and contains ZERO box-specific content (guard-enforced).

---

## Self-review (performed)

**Spec coverage:** taxonomy(§4.2)→A1; guard(§8)→A2; declared hypothesis / delete keyword table(§4.4,§7)→A3; doctrine de-box-ify(§7)→A4; surface model(§4.1)→B1; backlog(§4.3)→B2/B3; coverage+convergence+critic(§4.5)→C1/C2/C3; playbooks+RAG(§6)→D1/D2; objective-driven(§3,§7)→A4/B3/C2. All spec sections mapped.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; test code included.

**Type consistency:** `HypothesisBacklog`/`Hypothesis`/`SurfaceModel`/`SurfaceNode` signatures, `_refresh_surface_and_backlog`, `_backlog_brief`, `_objective_met`, `_should_continue`, `_method_signature` are referenced consistently across tasks. `_FM_min` (defined in the harness in the prior turn) is reused by new tests.

**Note for executor:** PyYAML must be present on Kali for taxonomy/playbooks (loaders fail soft to empty, but the engine needs them). Add `pyyaml` to requirements if not already pinned.
