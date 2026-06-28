#!/usr/bin/env python3
"""
simpl_scan.py - heuristic SAST for Crestron control programs (SIMPL+ `.usp` and
SIMPL# / C# `.cs`). Part of the agents/avot AV/OT security capability.

It flags well-known insecure patterns in the *application logic* that runs on a
Crestron processor (e.g. the CP4): fixed-buffer overflow/truncation, hardcoded
credentials, command/output injection from untrusted input, network handlers
with no auth, and weak transport/crypto. This complements the protocol fuzzer:
the fuzzer hits the wire, this hits the program.

This is a heuristic regex + light-taint scanner (a starter), NOT a full
compiler/parser - treat findings as leads to verify. For SIMPL# (C#), pair it
with Roslyn analyzers for depth.

Usage:
  python3 simpl_scan.py path/to/program.usp [more ...] [--json] [--fail-on HIGH]
  python3 simpl_scan.py src/        # walks .usp/.simpl/.cs recursively
"""
from __future__ import annotations
import argparse, json, os, re, sys
from dataclasses import dataclass, asdict

SEV = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

@dataclass
class Finding:
    rule: str; severity: str; cwe: str; file: str; line: int; snippet: str; message: str

IDENT = r"[A-Za-z_]\w*"
RE_BUF       = re.compile(rf"\bSTRING\s+({IDENT})\s*\[\s*(\d+)\s*\]", re.I)
RE_INPUT     = re.compile(rf"\b(?:STRING_INPUT|BUFFER_INPUT)\s+({IDENT})\s*\[\s*(\d+)\s*\]", re.I)
RE_ASSIGN    = re.compile(rf"^\s*({IDENT})\s*=\s*(.+?);")
RE_FUNC      = re.compile(rf"\b(?:STRING_|INTEGER_)?FUNCTION\s+({IDENT})\s*\(([^)]*)\)", re.I)
RE_CALL      = re.compile(rf"\b({IDENT})\s*\(([^)]*)\)")
RE_MAKESTR   = re.compile(rf"\bMakeString\s*\(\s*({IDENT})\s*,(.*)\)", re.I)
RE_STRLIT    = re.compile(r'"[^"]*"')
CREDNAME     = re.compile(r"(pass|pwd|secret|api_?key|token|cred)", re.I)
SINKS        = re.compile(r"\b(SocketSend|SerialSend|Print|MakeString)\b", re.I)
AUTHWORD     = re.compile(r"(auth|login|password|verify|token|pin|cred)", re.I)
ACTION       = re.compile(r"\b(SendCommand|SocketSend|SerialSend)\b", re.I)

def _idents(s): return set(re.findall(IDENT, s))

def _block_after(text, pos):
    i = text.find("{", pos)
    if i < 0: return ""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{": depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0: return text[i:j + 1]
    return text[i:]

def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)

def scan_simpl(path, text):
    orig = text.splitlines()
    code = _strip_comments(text)
    F, lines = [], code.splitlines()
    snip = lambda i: orig[i - 1].strip() if 0 < i <= len(orig) else ""
    bufs   = {m.group(1): int(m.group(2)) for m in RE_BUF.finditer(code)}
    inputs = {m.group(1): int(m.group(2)) for m in RE_INPUT.finditer(code)}
    funcs  = {m.group(1): [p.strip().split()[-1] for p in m.group(2).split(",") if p.strip()]
              for m in RE_FUNC.finditer(code)}

    # light taint propagation (multi-pass to converge across calls)
    taint = set(inputs)
    for _ in range(6):
        for ln in lines:
            ms = RE_MAKESTR.match(ln.strip())
            if ms and _idents(ms.group(2)) & taint: taint.add(ms.group(1))
            a = RE_ASSIGN.match(ln)
            if a and _idents(a.group(2)) & taint: taint.add(a.group(1))
            for c in RE_CALL.finditer(ln):
                if c.group(1) in funcs and _idents(c.group(2)) & taint:
                    taint |= set(funcs[c.group(1)])

    for i, ln in enumerate(lines, 1):
        a = RE_ASSIGN.match(ln)
        if a:
            lhs, rhs = a.group(1), a.group(2)
            if CREDNAME.search(lhs) and RE_STRLIT.search(rhs) and '""' not in rhs:
                F.append(Finding("SIMPL_HARDCODED_CRED", "HIGH", "CWE-798", path, i, snip(i),
                                 f"Credential '{lhs}' assigned a hardcoded literal"))
            if lhs in bufs:
                rid = rhs.strip().rstrip(";")
                src = inputs.get(rid) or bufs.get(rid)
                if rid in inputs or (src and src > bufs[lhs]):
                    F.append(Finding("SIMPL_BUFFER_OVERFLOW", "HIGH", "CWE-120", path, i, snip(i),
                        f"'{rid}' (size {src}) copied into '{lhs}' (size {bufs[lhs]}) with no bounds check"))
        if SINKS.search(ln):
            args = "".join(re.findall(r"\((.*)\)", ln))
            if _idents(args) & taint:
                F.append(Finding("SIMPL_CMD_INJECTION", "HIGH", "CWE-77", path, i, snip(i),
                                 "Untrusted (tainted) data flows into an output/command sink"))

    for m in re.finditer(rf"\bCHANGE\s+({IDENT})", code):
        var = m.group(1)
        if var not in inputs: continue
        blk = _block_after(code, m.end())
        if blk and ACTION.search(blk) and not AUTHWORD.search(blk):
            line = code[:m.start()].count("\n") + 1
            F.append(Finding("SIMPL_MISSING_AUTH", "MEDIUM", "CWE-306", path, line, snip(line),
                             f"Input handler '{var}' triggers actions with no authentication check"))

    for i, ln in enumerate(lines, 1):
        if re.search(r"\btelnet\b|\bport\s*23\b", ln, re.I):
            F.append(Finding("SIMPL_INSECURE_TRANSPORT", "LOW", "CWE-319", path, i, snip(i),
                             "Plaintext/Telnet transport reference"))
    return F

CS_RULES = [
    ("CS_DISABLED_TLS_VALIDATION", "HIGH", "CWE-295",
     re.compile(r"ServerCertificateValidationCallback\s*=.*?=>\s*true|CertificatePolicy.*true", re.I),
     "TLS certificate validation disabled"),
    ("CS_HARDCODED_CRED", "HIGH", "CWE-798",
     re.compile(r'\b(password|pwd|api_?key|secret|token)\b\s*=\s*"[^"]+"', re.I), "Hardcoded credential"),
    ("CS_SHELL_EXEC", "HIGH", "CWE-78", re.compile(r"\bProcess\.Start\s*\(", re.I),
     "External process execution"),
    ("CS_WEAK_CRYPTO", "MEDIUM", "CWE-327", re.compile(r"\b(MD5|DES|TripleDES|RC2)\b"),
     "Weak cryptographic primitive"),
]
def scan_csharp(path, text):
    F = []
    for i, ln in enumerate(_strip_comments(text).splitlines(), 1):
        for rid, sev, cwe, rx, msg in CS_RULES:
            if rx.search(ln): F.append(Finding(rid, sev, cwe, path, i, ln.strip(), msg))
    return F

def scan_file(path):
    try: text = open(path, errors="replace").read()
    except Exception: return []
    ext = os.path.splitext(path)[1].lower()
    if ext in (".usp", ".simpl"): return scan_simpl(path, text)
    if ext == ".cs": return scan_csharp(path, text)
    return []

def gather(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                out += [os.path.join(root, f) for f in files
                        if os.path.splitext(f)[1].lower() in (".usp", ".simpl", ".cs")]
        else: out.append(p)
    return out

def main():
    ap = argparse.ArgumentParser(description="Heuristic SAST for Crestron SIMPL+/SIMPL# programs.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=list(SEV), default="HIGH",
                    help="exit nonzero if a finding at/above this severity exists (CI gate)")
    args = ap.parse_args()
    findings = []
    for f in gather(args.paths): findings += scan_file(f)
    findings.sort(key=lambda x: (-SEV[x.severity], x.file, x.line))
    if args.json:
        print(json.dumps([asdict(x) for x in findings], indent=2))
    else:
        for x in findings:
            print(f"[{x.severity:8s}] {x.rule:26s} {x.file}:{x.line}  {x.cwe}  {x.message}")
            print(f"             > {x.snippet}")
        c = {}
        for x in findings: c[x.severity] = c.get(x.severity, 0) + 1
        print(f"\n{len(findings)} finding(s): {c or '{}'}")
    worst = max((SEV[x.severity] for x in findings), default=-1)
    return 1 if worst >= SEV[args.fail_on] else 0

if __name__ == "__main__":
    sys.exit(main())
