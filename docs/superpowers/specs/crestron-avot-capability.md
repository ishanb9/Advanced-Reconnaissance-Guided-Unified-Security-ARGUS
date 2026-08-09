# Crestron AV/OT Security Capability - Capability Dossier (consolidated)

| | |
|---|---|
| **Status** | Draft v0.3 (consolidated) |
| **Owner** | ARGUS platform team |
| **Detailed design** | [`crestron-avot-fuzzing.md`](crestron-avot-fuzzing.md) |
| **Code** | [`agents/avot/`](../../../agents/avot/) (fuzzer + SAST) |
| **Authorization** | Lab-only on owned hardware; coordinated disclosure via vendor PSIRT |

---

## 1. Executive summary

ARGUS is building an **AV/OT/IoT security capability** to become a Crestron
security partner (a Fishtech-class ecosystem relationship). The wedge is a
Crestron-aware **protocol fuzzer** plus a **SIMPL+/SIMPL# static analyzer**:
find real bugs in Crestron gear and the integrator code that runs on it,
disclose responsibly through Crestron's PSIRT, earn advisories/CVEs, and convert
that credibility into a partnership - then a continuous-monitoring appliance for
recurring revenue. First target device: **CP4 (4-Series control processor)**.

## 2. Why now (the opportunity)

Crestron runs proprietary protocols (**CIP** 41794, **CTP/console** 41795) on
devices that sit on the corporate LAN, and the published CVEs prove the surface:
DM-NVX unauth password change (**CVSS 10.0**), AM-100/101 default creds + SNMP
RCE, DMC-STRO RCE. Crestron already runs a coordinated-disclosure channel
("Report a Product Vulnerability") and an Integrated Partners program - the door
is open.

## 3. What's built today

| Component | Path | Status |
|---|---|---|
| **Protocol fuzzer** (CIP/CTP, field-aware, safe-by-default) | `agents/avot/fuzz/crestron_fuzzer.py` | working sample, CP4 profile |
| **SIMPL+/SIMPL# SAST** (application-layer) | `agents/avot/sast/simpl_scan.py` | working, 7 rules |
| Vulnerable test fixture | `agents/avot/sast/samples/vulnerable_module.usp` | flags 7 findings |
| Design spec (phases, Defensics comparison, success criteria, appliance) | `crestron-avot-fuzzing.md` | detailed |

Both tools are **dependency-free (Python stdlib)** and verified:

- Fuzzer: deterministic per-case IDs (seed `42` reproduces byte-identical cases), field-aware mutation (length/opcode/state/session-token/payload), multi-probe liveness, OT safe-mode + circuit breaker, target scoping (allowlist required to send), PSIRT advisory generator.
- SAST on the sample: **6 HIGH + 1 MEDIUM** (command injection, fixed-buffer overflow, hardcoded creds, missing-auth handler).

## 4. Architecture (fits ARGUS)

```
ARGUS MasterAgent
   └─ agents/avot/
        ├─ fuzz/   protocol fuzzer  (wire layer: CIP/CTP, web later)
        ├─ sast/   SIMPL+/SIMPL# analyzer (application layer: program on the box)
        └─ (recon fingerprints, device/firmware catalog)  -> knowledge/ + report/
```

Wire layer (fuzzer) + application layer (SAST) = full-stack coverage of a
Crestron deployment. Findings feed ARGUS's evidence chain, the report engine,
and (Phase 4) the monitoring appliance.

## 5. Phased roadmap

| Phase | Outcome |
|---|---|
| 0 - Lab + intel | Owned CP4 kit, captured CIP/CTP, recon fingerprints |
| 1 - Fuzz + disclose | Field-aware fuzzing + SAST -> coordinated disclosures to PSIRT |
| 2 - Productize | `agents/avot` module + deployment assessment report |
| 3 - Partner | Product-security testing / Integrated Partner + Fishtech-style case study |
| 4 - Continuous monitoring | On-prem **offline-LLM appliance** (CyberOwl-style) -> fleet/managed SOC |

## 6. Differentiators

- **vs Defensics:** they win on standard-protocol breadth + maturity; we win on proprietary CIP/CTP depth, coverage-guided firmware fuzzing, and turning a bug into a *validated attack path + CVE + partnership*. We adopt their instrumentation/traceability discipline.
- **Offensive heritage:** "monitor for the exact chains we proved" - red-team findings become detection content.
- **Offline-LLM appliance:** data sovereignty, works disconnected/air-gapped; ARGUS already runs a local LLM (Ollama).

## 7. Extensions (started / planned)

- **SIMPL+ / SIMPL# application layer** (started): static analysis of integrator code (buffer overflow, hardcoded creds, command injection, missing auth, weak crypto/TLS) + program-input fuzzing + a vulnerable test fixture.
- **Threat-Intelligence Platform (TIP) link** (planned): `--export stix|misp` to push findings as machine intel (hash, protocol/port, device/fw, CVSS, CWE/CAPEC) into a TIP / the appliance / PSIRT; reverse import to prioritize fuzzing from known CVEs/IOCs. Closes the offense↔intel↔defense loop.

## 8. Runbook

### 8.1 Fuzzer (`crestron_fuzzer.py`)

Prereqs: Python 3.11+ (no install). For live runs: a **CP4 you own**, on an
**isolated VLAN**, with **serial console + smart PDU** attached.

```bash
# 0) Dry-run - generate field-aware cases, send NOTHING (no device needed):
python3 agents/avot/fuzz/crestron_fuzzer.py 10.10.0.5 --device cp4 --model cip --dry-run

# 1) (Phase 0) capture real CIP/CTP frames (Toolbox + span port) into ./cp4-captures,
#    then fill the CIPLikeModel/ConsoleModel templates + implement session_setup().

# 2) Authorized lab run (scoping + safe-mode required):
python3 agents/avot/fuzz/crestron_fuzzer.py 10.10.0.5 --device cp4 --model cip \
    --authorized --scope-allow 10.10.0.0/24 --scope-deny 10.10.0.1/32 \
    --seed-corpus ./cp4-captures --rate 5 --probes 3 --max-consec-fail 3 --outdir out

# 3) Triage: artifacts in out/crashes/*.{json,bin}; run log out/run.jsonl
# 4) Reproduce one finding:
python3 agents/avot/fuzz/crestron_fuzzer.py 10.10.0.5 --device cp4 \
    --replay out/crashes/CR-cip-....bin --authorized --scope-allow 10.10.0.0/24
# 5) Draft a PSIRT advisory from a finding:
python3 agents/avot/fuzz/crestron_fuzzer.py x 0 --advisory out/crashes/CR-cip-....json
```

Safety: defaults to dry-run; sending needs `--authorized` **and** an allowlisted
target; the circuit breaker halts on repeated crash signals - then isolate /
power-cycle before resuming (see the hardware safety checklist in
`agents/avot/README.md`).

### 8.2 SAST (`simpl_scan.py`)

```bash
# scan the bundled vulnerable fixture:
python3 agents/avot/sast/simpl_scan.py agents/avot/sast/samples/vulnerable_module.usp
# scan a real program tree (CI gate: nonzero exit on HIGH):
python3 agents/avot/sast/simpl_scan.py /path/to/program/ --fail-on HIGH --json
```

## 9. Safety, authorization & disclosure

- **Lab-only** on owned/scoped hardware; OT gear bricks easily (passive-first, never blind-fuzz live OT).
- **Target scoping** (allow/deny) so the tool cannot be reused outside its lab boundary.
- **Coordinated disclosure** to Crestron PSIRT only - no public 0-day drops (that torches the partnership).
- **Logging/retention** (JSONL run log + `.bin`/`.json` repro) and an **incident-safe rollback** (circuit breaker + isolation/power-cycle).

## 10. Next steps

1. Phase 0 on the CP4: isolate, capture CIP/CTP, fill templates, implement `session_setup()` + `--tls`.
2. Run the SAST over the integrator's SIMPL+/SIMPL# program; triage HIGH findings.
3. Build the **TIP export** (`--export stix|misp`) and wire findings into the knowledge base / appliance.
4. First coordinated disclosure -> Crestron PSIRT.

## 11. References

- Crestron - Report a Product Vulnerability (PSIRT); Security Advisories (AM-100/101)
- Crestron DM NVX/NAX and XiO Cloud security reference guides
- Public Crestron CVEs (DM-NVX CVSS 10.0; AM-100/101; DMC-STRO)
- Detailed design + Defensics comparison + success criteria: `crestron-avot-fuzzing.md`
