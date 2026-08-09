# Universal Technology Coverage — Skill Registry + Safety Gate (Sub-project #5, Slice 1)

> **Design spec** · 2026-06-20 · Basis for the #5 implementation plan
> Research basis: `docs/superpowers/research/2026-06-20-ot-iot-it-coverage.md`
> Builds on: the capability-module registry shipped in #4 Slice 2 (`MasterAgent._CAPABILITY_MODULES`).

## 1. Goal

Let ARGUS thoroughly test **any** technology type (OT / IoT / IT) without bloating the
engine, and let a human **author coverage as data** — drop in a "skill file" per
technology that ARGUS matches deterministically *and* recalls semantically (RAG).
A human-set **scan-intrusiveness ceiling** (safe | intrusive | disruptive) governs how
far ARGUS may go, safe-by-default for fragile OT.

## 2. Decisions (locked)

- **Hybrid skill files**: Markdown + YAML front-matter; deterministic match **and** auto-RAG.
- **Scope**: framework + skill-file mechanism + seed P0 coverage as skill files + one deep
  code-module exemplar (read-only Modbus). P1/P2 are later slices.
- **Safety**: safe-by-default for OT; a human-selected intrusiveness ceiling (all three of
  safe | intrusive | disruptive) is choosable in the GUI and enforced by the gate.

## 3. Architecture

Two tiers feed ONE registry — the generalized capability scan already iterating
`_CAPABILITY_MODULES` (avot + ai_red_team.discovery):

### 3.1 Tier 1 — Skill files (data, user-authorable) — `knowledge/skills/<domain>/<tech>.md`

Markdown body (guidance → RAG) with YAML front-matter (machine-readable match + actions):

```markdown
---
id: modbus
technology: "Modbus / Modbus-TCP"
domain: OT                    # OT | IoT | IT
safety_class: safe            # safe | intrusive | disruptive  (the BASE class for plain detection)
severity: high                # finding severity if exposed; omit ⇒ guidance-only (no finding)
life_safety: false            # true ⇒ never actuate (elevators/fire/egress/locks)
match:
  ports:   [502]              # AI-DEDICATED ports only (shared ports gated by code FP guard)
  banners: ["modbus"]         # service/version substrings (lowercase)
  markers: ["mbap"]           # HTTP/path/banner markers, specific
quick_wins:
  - cmd: "nmap --script modbus-discover -p502 {host}"
    safety: safe
    note: "Read device ID (FC 43 / MEI 14) — vendor/product/firmware"
  - cmd: "<write coil example>"
    safety: disruptive        # GATED — actuates the process
    note: "Requires explicit authorization; shown, never auto-run"
references: ["ICSA-…", "CVE-…"]
cpe: "cpe:2.3:…"
mitre: "T0846"
---
# Modbus guidance (Markdown → RAG)
Reachability = control. Read-only FC 0x01/0x03/0x2B by default; hard-gate writes
0x05/06/0F/10. ~tens-of-thousands exposed on Shodan…
```

Authoring a new technology = adding one `.md` file. No code change.

### 3.2 Tier 2 — Code capability modules — `agents/<domain>/<tech>.py`

For technologies needing **active protocol speaking / fuzzing**, a code module exposing
`detect(intel) -> dict|list[dict]|None` + `finding_for(det) -> record` (the avot /
`ai_red_team.discovery` pattern), registered in the same registry. Slice 1 ships **one**:
`agents/ot/modbus.py` (read-only).

### 3.3 The loader + matcher — `knowledge/skill_registry.py`

- `load_skills(root=None) -> list[Skill]` — parse every `knowledge/skills/**/*.md`
  front-matter + body; validate (`id`, `technology`, `match` required); never raise.
- `match_skills(intel) -> list[detection]` — match each skill's `match` block against intel
  (ports / banner blob / markers), reusing the shadow-AI matcher semantics **and the
  `_SHARED_PORTS` false-positive guard** (a shared-port-only hit never fires). Returns
  detections carrying `technology`, `domain`, `safety_class`, `severity`, `quick_wins`,
  `evidence`, `guidance`, `references`, `mitre`.
- `finding_for(detection) -> dict` — store_finding-shaped record (only when `severity` set).
- `ingest_to_rag(skill) -> bool` — push the Markdown body to the knowledge base via
  `knowledge.knowledge_base.ingest(text, source_file, chunk_index, metadata={chunk_type:
  "skill", services, ports, cves, mitre_ttps, tools, section_title})`. Best-effort; skipped
  if embeddings unavailable.

### 3.4 Engine wiring (additive)

- Extend `MasterAgent._avot_capability_scan` (already a registry loop) to ALSO run
  `skill_registry.match_skills(self._intel)` and record each via the existing
  `_record_capability_detection` path (dedup + operator advisory + finding).
- On engagement start (best-effort, behind `ARGUS_SKILL_REGISTRY`, default-on): ingest all
  skill bodies to RAG once, so the operator can retrieve them semantically too.
- Matched skills inject **guidance + safety-filtered quick-wins** into
  `_meta_advisory_context` so the operator brain knows the tech is present and how to get a
  safe quick win.

## 4. Safety-class gate + human intrusiveness ceiling

- **Ordering**: `safe (0) < intrusive (1) < disruptive (2)`.
- **Human ceiling** (`scan_intrusiveness`, default `safe`): selectable in the GUI; the
  engagement-wide maximum. An action/quick-win with class `X` may auto-surface to the
  operator only when `level(X) <= level(ceiling)`.
- **OT default**: when a target is OT-classified (matched skill/module `domain == "OT"`, or
  `target_type` OT), the *effective* ceiling is clamped to `safe` UNLESS the human raised it
  AND the engagement is authorized (reuse #1's authorization model). Passive/read-only first.
- **Life-safety**: `life_safety: true` actions are NEVER auto-run, even at a disruptive
  ceiling — they require an explicit per-action human approval.
- Quick-wins above the ceiling are surfaced as *"available — requires authorization"*,
  never executed automatically. The gate is a pure function
  `allowed(action_safety, ceiling, domain, life_safety) -> bool` (unit-tested).

## 5. GUI — scan intrusiveness control

`static/js/pages/TargetConfig.jsx`: a **Scan intrusiveness** selector with three options —
`safe` (read-only / passive), `intrusive` (active enumeration), `disruptive` (writes /
state-changing, OT-gated). Default `safe`. Posts `scan_intrusiveness` →
`StartPentestRequest` → `master_kwargs` → `master.run` → `self._intel["scan_intrusiveness"]`
→ the gate. Cache-bust bumped.

## 6. Seed P0 coverage (workflow-generated, FP-audited)

`knowledge/skills/{ot,iot,it}/*.md` for the P0 families (research §6): OPC-UA, BACnet/IP,
Modbus, S7comm, EtherNet/IP, IEC-104, DNP3, Niagara Fox (OT); MQTT, CoAP, UPnP/SSDP, mDNS,
ONVIF/RTSP, IPP/PJL printers (IoT); AD/SMB, Kerberos, LDAP, VPN-edge appliances, Cloud
IMDS/S3, Kubernetes/Docker, GraphQL/gRPC, databases, message queues (IT). Each: front-matter
(match + safety_class + severity + quick_wins + references + mitre) + a guidance body. Same
generate→FP-audit workflow used for the shadow-AI signatures.

## 7. Findings → report

Unchanged: detections flow through `store_finding` → the #1 Issue-Validator gate → the #2
themes. OT findings carry a CISA-advisory / safety-impact note in the description.

## 8. Manual extension UX

Drop a new `knowledge/skills/<domain>/<tech>.md`; ARGUS auto-loads it on the next run and
ingests it to RAG. No code change, no restart of the design. Documented in
`knowledge/skills/README.md` with the front-matter schema + an annotated example.

## 9. Testing (`python -X utf8 agents/test_architecture_integration.py`)

- `load_skills` parses front-matter + body; rejects malformed; loads the seed P0 breadth (≥15).
- `match_skills` matches a Modbus skill on 502; **no false-positive** on a plain host or a
  shared port; marker match works.
- safety gate: `allowed("safe","safe",…) True`; `allowed("disruptive","intrusive",…) False`;
  OT clamps to safe at a higher ceiling without authorization; `life_safety` never auto-runs.
- `finding_for` shapes a record; `ingest_to_rag` calls the KB ingest (mockable).
- master registry runs `skill_registry.match_skills` + handles list returns (already true).
- `agents/ot/modbus.py` `detect()` fires on 502, negative on 80; `finding_for` shaped.
- GUI: TargetConfig exposes a `scan_intrusiveness` selector; threaded through schema → server.
- Non-regression: `test_no_hardcoded_attack_content` stays green (attack content lives in
  `knowledge/skills` + `agents/<domain>`, never the operator spine); full harness `RESULT: PASS`.

## 10. Slicing

- **Slice 1 (this spec):** registry loader + matcher + safety gate + auto-RAG + master wiring
  + GUI intrusiveness control + seed P0 skill files + Modbus code exemplar + tests.
- **Slice 2:** P1 families as skill files + active code modules (OPC-UA / BACnet speakers) +
  passive PCAP/SPAN ingest path for OT.
- **Slice 3:** transport adapters (Layer-2 / CAN-serial / RF-SDR hardware bridges) for P2.

## 11. Constraints

Additive (non-#5 engagements unchanged); knowledge-driven (coverage = data); safe-by-default;
behind `ARGUS_SKILL_REGISTRY` (default-on); Windows→Kali manual copy; frontend
`React.createElement` + `node --check` + cache-bust; harness green.
