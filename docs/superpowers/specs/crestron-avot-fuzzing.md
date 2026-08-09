# Crestron / AV-IoT Protocol Fuzzing & Security-Partner Capability — Design Spec

| | |
|---|---|
| **Status** | Draft v0.1 (for internal review) |
| **Owner** | ARGUS platform team |
| **Type** | New capability (recon + fuzzing agent) + go-to-partner motion |
| **Scope tag** | `agents/avot` · `knowledge/` (protocol intel) · `report/` |
| **Authorization** | Lab-only on owned hardware; coordinated disclosure via vendor PSIRT |

---

## 1. Why this exists (strategic rationale)

ARGUS wants a formal security relationship with Crestron (a Fishtech-class
ecosystem partner). You do not earn that with a deck — you earn it the way
Claroty, Armis, NCC and Bishop Fox did with their vendors: **find real bugs in
the vendor's gear, disclose them responsibly through the vendor's PSIRT, collect
advisories/CVEs with credit, and convert that credibility into a partnership.**

Crestron already runs a coordinated-disclosure channel ("Report a Product
Vulnerability") and publishes advisories, so the front door exists. The surface
is under-tested: Crestron's control plane runs **proprietary protocols almost no
fuzzer speaks**, on devices that sit on the corporate LAN. Public CVEs prove the
yield:

| CVE class | Device | Impact |
|---|---|---|
| Unauth password change via WebSocket | DM-NVX-DIR / DIR80 / ENT | **CVSS 10.0** |
| Default credentials (`admin/admin`) | AM-100 / AM-101 | Unauth privileged web access |
| SNMP OID command injection → root | AM-100 / AM-101 | Unauth RCE |
| Shell-metachar RCE in ping fn → root | DMC-STRO | Unauth RCE |

**Thesis:** a Crestron-aware protocol fuzzer is the single highest-leverage
thing to build. It produces the CVEs that *make* us a credible partner, and it
seeds an AV/OT/IoT capability that general pentest tooling does not have.

---

## 2. Objectives & non-goals

**Objectives**
1. Fingerprint and inventory Crestron/AV/OT devices from the network (a new ARGUS recon capability).
2. Build protocol-aware fuzzers for the Crestron control + management protocols.
3. Discover, triage, and **coordinate-disclose** vulnerabilities through Crestron PSIRT.
4. Package the result as an ARGUS "Smart-Workplace / AV-IoT Security" module + assessment report.
5. Use the disclosure track record to open a product-security / Integrated-Partner relationship.

**Non-goals**
- No exploitation of production / third-party-owned Crestron deployments without written authorization.
- No public 0-day drops — coordinated disclosure only (this protects the partnership).
- Not a replacement for ARGUS's existing IP/web agents; this is an OT/AV extension.

---

## 3. Target attack surface

| Protocol / surface | Transport | Fuzzing value |
|---|---|---|
| **CIP** (Crestron-over-IP control) | TCP/UDP 41794 | Core proprietary control protocol; near-zero public fuzzing |
| **CTP** (Crestron Terminal Protocol) | TCP 41795 | Console / management; auth + command parsing |
| **Toolbox auto-discovery** | UDP 41794 (broadcast) | Fingerprinting, model/firmware disclosure |
| **Device web / WebSocket** | 80/443/ws | Where the CVSS-10 NVX bug lived; reachable unauth paths |
| **DM-NVX / NAX AV-over-IP** | RTP/RTSP + web/CIP | Stream eavesdropping, control hijack, parser bugs |
| **SNMP** | UDP 161 | Command injection (proven on AM-100), enumeration |
| **SSH / Telnet / console** | 22 / 23 | Auth, default creds, command surface |
| **XiO Cloud client** | AMQP/TLS 5671 | Cloud-management edge (TLS1.2 + X.509 — test cert handling, downgrade) |
| **Flex UC** | SIP / Teams / Zoom | Conferencing edge (privacy, signalling parsers) |
| **Firmware control daemons** | (emulated) | Deep play: coverage-guided fuzzing of extracted binaries |

Highest-yield first: **CIP, CTP, device web/WebSocket, SNMP.**

---

## 4. Architecture (how it fits ARGUS)

```
                ┌─────────────────────────────────────────────┐
   ARGUS  ───▶  │  agents/avot/  (new specialist agent)        │
   MasterAgent  │   ├── recon/      CIP/CTP/SNMP fingerprinting │
                │   ├── protocols/  CIP, CTP, Cresnet, web grammars
                │   ├── fuzz/       network + firmware fuzzers   │
                │   ├── triage/     crash dedup + exploitability │
                │   └── disclose/   PSIRT advisory workflow      │
                └───────┬──────────────────┬────────────────────┘
                        │ findings          │ device/firmware DB
                        ▼                    ▼
              report/ (assessment)   knowledge/ (Crestron protocol intel,
              + evidence chain        device catalog, CVE corpus, playbooks)
```

- **Recon fingerprints** feed ARGUS's existing recon/knowledge_graph so any host
  answering on 41794/41795 is tagged `vendor=Crestron, model=X, fw=Y`.
- **MCP tooling** (`mcp-server.js`) gains wrappers for the fuzzers and helpers
  (`scapy`, `boofuzz`, `binwalk`, `nmap` NSE for Crestron).
- **Report engine** (`report/`) renders findings using the same Gartner-clean
  template we already ship — now with an AV/IoT finding type.

---

## 5. Components

### 5.1 Recon & fingerprinting
- Active + passive identification of Crestron control ports (41794/41795), the
  Toolbox discovery broadcast, device web banners, SNMP sysObjectID.
- Build a **device & firmware catalog** in `knowledge/` (model → ports →
  firmware → known CVEs) so recon auto-correlates to known issues.

### 5.2 Protocol intelligence
- Reverse the **CIP** and **CTP** wire formats from packet captures (lab gear +
  Crestron Toolbox traffic) into structured grammars (length-prefixed framing,
  message types, auth handshake).
- Encode grammars in a fuzzer-consumable form (boofuzz blocks / a small DSL).

### 5.3 Fuzzers
- **Network protocol fuzzing** (boofuzz / custom): grammar-aware mutation +
  generation against CIP, CTP, the web/WebSocket stack, and SNMP, with liveness
  checks and auto-restart between cases.
- **Coverage-guided firmware fuzzing** (deep track): extract firmware
  (`binwalk`), emulate (`FirmAE` / `Qiling` / `unicorn`), and fuzz the control
  daemons with `AFL++` where the binary can be harnessed.
- **Stateful harnesses** for protocols that require an auth/session handshake
  before the interesting parser is reachable.

### 5.4 Crash triage & exploitability
- Auto-dedup by crash signature; classify (DoS / memory-corruption / auth-bypass
  / command-injection); capture minimal PoC + the offending input.
- Record everything in ARGUS's evidence chain (input, trace, device state, hash).

### 5.5 Coordinated-disclosure workflow
1. Reproduce in lab → minimal PoC → CVSS + impact writeup (no operational weaponization in client copies).
2. Submit via **Crestron "Report a Product Vulnerability"** (PSIRT).
3. Track timeline; agree disclosure date; request CVE + advisory credit.
4. Publish a (sanitized) advisory + ARGUS research note once patched.

### 5.6 Reporting
- Reuse `report/` to emit a **lab research report** (per-bug) and a
  **deployment assessment report** (estate-level), both Gartner-clean.

---

## 6. Lab kit (Phase 0)

| Item | Purpose |
|---|---|
| 1× DM-NVX encoder/decoder | AV-over-IP + WebSocket surface |
| 1× 4-Series control processor (e.g. CP4) | CIP/CTP core control plane |
| 1× touch panel (TSW-x70) | Web/UI + control surface |
| 1× legacy AirMedia (AM-x01) if available | Reproduce known-CVE classes, validate tooling |
| Managed switch + span port | Capture CIP/CTP/AVoIP for grammar reversing |
| Crestron Toolbox (vendor tool) | Ground-truth protocol traffic + device mgmt |

Firmware images for the emulation track come from the devices we own + Crestron's published firmware.

---

## 7. Phased plan

| Phase | Outcome | Key deliverables |
|---|---|---|
| **0 — Lab + intel** | Owned kit, protocol captures, recon fingerprints | Device/firmware catalog; CIP/CTP grammars (v0); ARGUS recon plugin |
| **1 — Fuzz + disclose** | First reproducible bugs, first PSIRT submissions | boofuzz harnesses; crash triage; ≥1 coordinated disclosure |
| **2 — Productize** | ARGUS AV-IoT module + report type | `agents/avot` shipped; deployment assessment report template |
| **3 — Partner** | Crestron relationship + case study | Product-security testing engagement and/or Integrated-Partner listing; Fishtech-style case study |
| **4 — Continuous monitoring** | On-prem appliance (offline LLM) for continuous OT/AV monitoring; fleet/SOC service | Edge sensor + offline-LLM triage; store-and-forward console; offline model-update workflow |

---

## 8. Phase 4 — Continuous-monitoring appliance (offline LLM, on-prem)

The work above is point-in-time and services-shaped. The durable, recurring-revenue
evolution is a **hardware appliance running an offline LLM on-premises for continuous
OT/AV monitoring** — the model proven in maritime by CyberOwl/Medulla (now DNV) and on
land by Dragos, Nozomi, Claroty, Armis and Darktrace. ARGUS already runs a local LLM
(Ollama), so the box is ARGUS's reasoning layer pushed to the edge.

### 8.1 Why offline / on-prem
- **Zero data egress / sovereignty** — telemetry never leaves the site (OT, maritime, defense, healthcare, air-gapped, meeting-room AV privacy).
- **Works disconnected** — keeps reasoning with no/intermittent connectivity (the maritime constraint).
- **Compliance** (EU AI Act / GDPR) and **predictable cost** at fleet scale.

### 8.2 Architecture
```
Edge appliance
 |- Passive OT/AV-aware sensor (NDR: CIP/CTP/BACnet/AV-over-IP, asset discovery)
 |- Classic detection engine (signatures + anomaly/ML)   <- heavy lifting
 |- Offline LLM  -> triage, correlation, NL explanation, report gen, analyst Q&A
 |- Local store + evidence chain
 \- Store-and-forward -> fleet/SOC console (syncs when connectivity allows)
```
**Design rule:** the LLM does not inspect raw packets. Proven detection (parsers,
anomaly models, asset inventory) does detection; the LLM is the on-box analyst
(correlation, prioritization, plain-language explanation, report generation),
grounded (RAG) on local structured telemetry, with human-in-the-loop before any
action. This avoids hallucinated detections.

### 8.3 ARGUS's edge
Offensive heritage becomes detection content: **monitor for the exact attack chains
the red team proved.** Crestron protocol intel + red-team findings feed the sensor — a
closed purple-team loop on a box. Pure-defense vendors lack the offense; pure-offense
tools lack the appliance.

### 8.4 Hardware & model
- Ruggedized 1U/edge server with GPU or NPU; secure boot + TPM + hardened OS (it is a security appliance). Jetson-Orin-class variant for constrained/low-power sites.
- Quantized 7–14B model (Qwen/Llama/Mistral-class), ideally distilled/fine-tuned for security triage. Honest trade-off: a local 7–14B is weaker than frontier cloud, so scope it to triage/summarization, not autonomous decisions.
- **Offline updates:** detection content + threat intel + model refresh via scheduled sync, or sneakernet for true air-gap (mirrors CyberOwl shore sync).

### 8.5 Realities to plan for
- Hardware is a real lift: supply chain, support, certification, and a **secure fleet-management plane** for the appliances themselves.
- **OT safety:** passive-first; never disruptive on live OT (same guardrail as the fuzzers).
- **Edge model ops:** validating/updating offline models across disconnected sites is its own discipline.

### 8.6 Roadmap fit
Assessment (today) -> monitoring appliance (this phase) -> fleet / managed SOC
(CyberOwl-from-shore: many boxes, one console, recurring revenue). The appliance is how
we continuously secure a Crestron/AV/OT estate after the assessment opens the door.

---

## 9. Comparison vs Defensics & requirement enhancements

Defensics (Synopsys, now Black Duck) is the benchmark commercial generational
protocol fuzzer: 250+ pre-built suites, deep protocol models, SafeGuard health
instrumentation, certification-grade robustness reporting.

| Dimension | Defensics | ARGUS (this capability) |
|---|---|---|
| Approach | Generational / model-based, black-box network | Generational (boofuzz) + coverage-guided gray-box on emulated firmware |
| Crestron CIP/CTP/Cresnet | Not out of the box (build via SDK) | **Native proprietary protocol intel** |
| Standard protocols (TLS/HTTP/SNMP/SIP/RTSP/BACnet) | 250+ mature suites | Thin — reuse, do not rebuild |
| Failure detection | SafeGuard health checks (catch non-crash failures) | Basic liveness only (enhance) |
| Traceability / reproducibility | Per-test-case IDs, replay, remediation packages | Evidence chain + seeds (formalize) |
| Coverage feedback | Black-box (none) | **Coverage-guided on firmware** |
| Maturity / support | Battle-tested, certification-grade | New, open-tool-based |
| Outcome | Robustness defects | **Validated attack path + CVE + partnership** |
| Cost | Heavy commercial license | Open tooling (boofuzz/AFL++) |

**Where Defensics leads, and what we add to the requirements:**

| # | Enhancement | Pri |
|---|---|---|
| 1 | Target health instrumentation (SafeGuard-equivalent): valid-case probe between anomalies; response/latency/resource monitoring; hardware-in-the-loop serial capture + automated power-cycle for brick detect/recover | P0 |
| 2 | Generational model depth + anomaly taxonomy + per-test-case IDs + deterministic replay | P0 |
| 3 | Reuse mature suites for standard protocols (TLS/HTTP/SNMP/SIP/RTSP/BACnet); custom-build only CIP/CTP/Cresnet | P1 |
| 4 | Certification-style robustness reporting (pass/fail per anomaly class + coverage %) | P1 |
| 5 | CI regression + defect-reproduction packages + remediation guidance | P1 |
| 6 | Campaign orchestration at scale: sequencing, auto-restart/recovery, throughput targets | P1 |
| 7 | OT safe-mode: rate-limited, non-destructive profile near live gear | P1 (safety) |

**Net:** Defensics wins on standard-protocol breadth, failure instrumentation,
and maturity; ARGUS wins on proprietary CIP/CTP depth, coverage-guided firmware
fuzzing, and converting a bug into a validated attack path + CVE + partnership.
We adopt Defensics' instrumentation and traceability discipline; we keep our
proprietary-protocol and offensive-integration edge.

---

## 10. Success criteria & measurement

The first rows measure fuzzer quality; the last two measure partnership
progress. A great fuzzer that yields no accepted disclosures does not earn the
Crestron relationship.

| Criterion | Target | How measured |
|---|---|---|
| Protocol-model coverage | ≥90% of CIP/CTP message types modeled (each with anomaly classes) | Model-coverage matrix |
| Firmware code coverage (gray-box) | ≥60% edge coverage of target daemon | AFL++ / coverage instrumentation |
| Health-check sensitivity | Detect non-crash failures (hang / degrade / leak), not just crashes | Instrumentation logs vs crash-only baseline |
| Defect yield | Unique, triaged, reproducible defects per device; severity split | Dedup'd crash DB |
| Reproducibility | 100% replay from saved case + seed | CI replay job |
| False-positive rate | < 5% | Triage review |
| Throughput / stability | ≥ target cases/sec; campaign uptime ≥ 95%; MTBF-to-restart tracked | Orchestrator metrics |
| Triage latency | Median < a few hours per crash | Workflow timestamps |
| Regression | 0 reintroduced defects across firmware releases | CI gate |
| Product capability | End-to-end discover + assess + report on a Crestron estate | Pilot / demo acceptance |
| Disclosure outcome | ≥1 accepted PSIRT submission in Q1; ≥3 over two quarters; CVEs/advisories with credit | PSIRT tracker |
| Partnership | Named relationship (testing and/or Integrated Partner) + referenceable case study | Signed agreement / published case study |

---

## 11. Risks & guardrails
- **Bricking / OT fragility:** AV/control gear is fragile. Lab-first; production
  work is passive discovery + scoped, careful testing only. Never blind-fuzz live OT.
- **Authorization:** only own/lab gear, or customer estates with written scope.
- **Disclosure ethics:** coordinated disclosure only; no public 0-day drops —
  premature disclosure destroys the partnership we're trying to build.
- **Client copies:** assessment reports redact operational PoCs (consistent with
  the AI report's safe-harbor posture).
- **Legal:** respect EULA/anti-circumvention; security-research framing + vendor PSIRT participation keeps us clean.
- **Target scoping:** the fuzzer enforces an allow/deny list (allowlist required to send); production ranges go on the denylist so the tool cannot be reused outside its lab boundary.
- **Logging & retention:** every run writes a JSONL log (actions, findings, circuit-breaker events) retained per engagement policy alongside the `.bin`/`.json` repro artifacts.
- **Incident-safe rollback:** the consecutive-failure circuit breaker halts and prompts device isolation/power-cycle; operators keep serial console + power control on hand (see the hardware safety checklist in `agents/avot/README.md`).

---

## 12. Partnership / GTM path
1. **Product-security testing partner** — we test their gear (pre-release protocol/firmware fuzzing, regression, PSIRT support).
2. **Integrated / Technology Partner** — the "secure your Crestron estate" ARGUS module, listed in Crestron's Integrated Partners, joint GTM.
3. **Case study** — a Fishtech-style published story once we have disclosures + a deployment win.

Lead with the disclosures, not a cold pitch.

---

## 13. Tooling
`scapy`, `boofuzz`, `binwalk`, `FirmAE`/`Qiling`/`unicorn`, `AFL++`, `Ghidra`,
`nmap` (+ custom NSE), `snmpwalk`, `wireshark`/`tshark`, plus ARGUS's existing
recon/report/evidence stack and the MCP tool gateway.

---

## 14. Open questions / next steps
- Confirm Crestron PSIRT intake format + expected disclosure timeline.
- Decide lead device for Phase 0 (recommend DM-NVX — proven surface).
- Confirm whether firmware-emulation (coverage-guided) track is in Phase 1 or deferred to Phase 2.
- Draft the one-page Crestron partnership brief (separate deliverable) for the security team.

## 15. References
- Crestron — Report a Product Vulnerability (PSIRT)
- Crestron Security Advisories (e.g. AM-100/101)
- Crestron DM NVX/NAX and XiO Cloud security reference guides
- Public Crestron CVEs (DM-NVX unauth password change CVSS 10.0; AM-100/101 default creds + SNMP RCE; DMC-STRO RCE)
