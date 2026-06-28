# agents/avot/sast - SIMPL+ / SIMPL# static analyzer

Heuristic SAST for the **application logic** that runs on a Crestron processor
(e.g. the CP4). Complements the protocol fuzzer: the fuzzer tests the wire, this
tests the program loaded on the box.

> Starter / heuristic (regex + light taint), not a full parser. Findings are
> leads to verify. For SIMPL# (C#) pair with Roslyn analyzers.

## Rules

| Rule | Sev | CWE | What |
|---|---|---|---|
| `SIMPL_BUFFER_OVERFLOW` | HIGH | CWE-120 | Untrusted/larger source copied into a fixed STRING buffer |
| `SIMPL_HARDCODED_CRED` | HIGH | CWE-798 | Credential-named var assigned a string literal |
| `SIMPL_CMD_INJECTION` | HIGH | CWE-77 | Tainted (network/serial) input flows into a command/output sink |
| `SIMPL_MISSING_AUTH` | MEDIUM | CWE-306 | Input handler triggers actions with no auth check |
| `SIMPL_INSECURE_TRANSPORT` | LOW | CWE-319 | Telnet/plaintext reference |
| `CS_DISABLED_TLS_VALIDATION` | HIGH | CWE-295 | Cert validation disabled (SIMPL# / C#) |
| `CS_HARDCODED_CRED` / `CS_SHELL_EXEC` / `CS_WEAK_CRYPTO` | HIGH/HIGH/MED | 798/78/327 | C# rules |

## Run

```bash
# scan the bundled vulnerable sample:
python3 agents/avot/sast/simpl_scan.py agents/avot/sast/samples/vulnerable_module.usp

# scan a real program tree (CI gate: nonzero exit on HIGH):
python3 agents/avot/sast/simpl_scan.py /path/to/program/ --fail-on HIGH

# machine output:
python3 agents/avot/sast/simpl_scan.py src/ --json
```

`samples/vulnerable_module.usp` is an **intentionally vulnerable** fixture for
testing the analyzer - do not compile or deploy it.
