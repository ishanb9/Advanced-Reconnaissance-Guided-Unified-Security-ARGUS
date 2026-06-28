# agents/avot - AV / OT / IoT security capability

Crestron-focused recon + protocol fuzzing (and, later, the continuous-monitoring
appliance). Design doc: [`docs/superpowers/specs/crestron-avot-fuzzing.md`](../../docs/superpowers/specs/crestron-avot-fuzzing.md).

> **Lab use only.** Test hardware you own or are contractually scoped to test.
> AV/OT gear bricks easily. Findings go to the vendor PSIRT via coordinated
> disclosure - never public 0-day drops.

## `fuzz/crestron_fuzzer.py` - sample fuzzer (Phase 0/1, hardened per capability review)

Dependency-free (stdlib only), safe-by-default network protocol fuzzer. It is the
**engine + safety + reproducibility scaffolding**; the proprietary CIP/CTP wire
grammars are reversed in the lab and plugged into a `ProtocolModel`.

| Capability | Notes | Spec ref |
|---|---|---|
| **Field-aware mutation** | `OpcodeField`, `LengthField` (desync), `StateField`, `TokenField` (session/auth), `PayloadField`; fuzzes one field at a time so findings isolate cleanly | enh #2 |
| Structured `cip` model + `console` model | CIP-like 4B length + 2B opcode + 4B token + state + payload (template); CTP-like line protocol | section 5.2 |
| **Multi-probe liveness + response signatures** | majority-of-N probes must return a *signature-valid* response, not just any bytes - catches soft-hung devices | enh #1 |
| **Target scoping** | `--scope-allow` (required to send) / `--scope-deny` (CIDR); do-not-fuzz guard for production | review |
| Deterministic case IDs + per-case seed | 100% replay; `.json` + `.bin` artifacts; JSONL run log | section 10 / 5.4 |
| **OT safe-mode** | rate limit + consecutive-failure **circuit breaker** that halts and prompts isolation | enh #7 |
| Seed-corpus loader + `session_setup()` hook | `--seed-corpus DIR` feeds lab-captured frames; hook does the real auth handshake | enh #1/#2 |
| **PSIRT advisory generator** | `--advisory finding.json` emits a vendor-ready minimal-repro + impact stub | review |

### Quick start

```bash
# Safe default: generate and print field-aware cases, send NOTHING:
python3 agents/avot/fuzz/crestron_fuzzer.py 192.0.2.10 41794 --model cip --cases 20 --dry-run

# Run against a LAB device you own (explicit opt-in + scoping required):
python3 agents/avot/fuzz/crestron_fuzzer.py 10.10.0.5 41794 --model cip --cases 5000 \
    --authorized --scope-allow 10.10.0.0/24 --scope-deny 10.10.0.1/32 \
    --seed-corpus ./captures --rate 8 --probes 3 --max-consec-fail 3

# Reproduce one saved finding:
python3 agents/avot/fuzz/crestron_fuzzer.py 10.10.0.5 41794 \
    --replay out/crashes/CR-cip-....bin --authorized --scope-allow 10.10.0.0/24

# Turn a finding into a draft PSIRT advisory:
python3 agents/avot/fuzz/crestron_fuzzer.py x 0 --advisory out/crashes/CR-cip-....json
```

## Hardware safety checklist (run before any `--authorized` session)

- [ ] **Isolated network** - target on a dedicated switch/VLAN, no path to production or the internet.
- [ ] **Target scoping set** - `--scope-allow` limited to the exact lab range; production ranges in `--scope-deny`.
- [ ] **Out-of-band console** - serial/console access to observe the device and catch soft-hangs.
- [ ] **Known power-cycle method** - smart PDU or manual power so a hung/bricked device can be recovered.
- [ ] **Circuit breaker tuned** - `--max-consec-fail` low (e.g. 3); on trip, STOP and isolate/power-cycle before resuming.
- [ ] **Dry-run first** - review generated cases with `--dry-run`, then start at a low `--rate`.
- [ ] **Backups** - device config/firmware backed up; recovery/reflash procedure known.

## Operational controls (formal capability review)

- **Authorization:** sending requires `--authorized` *and* an allowlisted target; default is dry-run.
- **Scoping:** allow/deny CIDR enforcement; allowlist is mandatory to send (prevents reuse outside the lab boundary).
- **Logging & retention:** every run appends a JSONL log (`<outdir>/run.jsonl`: start, findings, circuit-breaker, end). Retain per engagement policy alongside the `.bin`/`.json` artifacts.
- **Incident-safe rollback:** circuit breaker halts on repeated crash signals and prompts device isolation/power-cycle; keep console + power control on hand.

## Extending toward production (per spec)
1. Reverse CIP/CTP from lab captures -> real opcode set, token semantics, payload seeds, and `response_signature`.
2. Implement `session_setup()` for the real auth handshake; add hardware-in-the-loop health (serial capture, automated power-cycle).
3. Graduate the engine to `boofuzz` (network) and `AFL++` + `FirmAE`/`Qiling` (coverage-guided firmware).
4. Wire findings into ARGUS's evidence chain + report engine, and the PSIRT disclosure workflow.
