#!/usr/bin/env python3
"""
crestron_fuzzer.py - sample protocol fuzzer for Crestron / AV-IoT devices.

Phase-0/1 starting point for the capability in
docs/superpowers/specs/crestron-avot-fuzzing.md.

============================  SAFETY / AUTHORIZATION  ========================
  LAB USE ONLY, on hardware you OWN or have WRITTEN authorization to test.
  Defaults to --dry-run (generates/prints cases, sends NOTHING). Network
  sending requires BOTH --authorized AND an explicit --scope-allow that
  contains the target (target scoping). OT safe-mode is always on: rate limit,
  multi-probe liveness, and a consecutive-failure circuit breaker that stops
  before bricking gear. See the hardware safety checklist in agents/avot/README.md.
  Findings -> coordinated disclosure via vendor PSIRT (spec section 5.5).
=============================================================================

Hardened per capability review:
  * field-aware mutation: length / opcode / state / session-token / payload
  * multi-probe liveness with response signatures (not "any bytes == alive")
  * target scoping: --scope-allow / --scope-deny (CIDR), allowlist required to send
  * seed-corpus loader (--seed-corpus) + session_setup() hook for real frames
  * PSIRT advisory-stub generator (--advisory) for vendor-ready minimal repro
  * per-case IDs + deterministic seed -> 100% replay; .json+.bin artifacts; run log

The Crestron CIP/CTP wire formats are proprietary and reversed in the lab
(spec 5.2). The structured `cip` model and `console` model below are TEMPLATES
with TODO(lab) markers - the engine + safety + reproducibility is real; the
exact opcodes/tokens/prompts get filled from captured traffic.
"""
from __future__ import annotations
import argparse, ipaddress, json, os, random, socket, ssl, struct, sys, time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# ----------------------------------------------------------------------------
# Anomaly primitives (bytes) + integer boundaries (for length/size fields).
# Probes for overflow, off-by-one, format strings, injection, traversal.
# ----------------------------------------------------------------------------
def _anomalies() -> list[bytes]:
    a: list[bytes] = []
    a += [b"A" * n for n in (16, 255, 256, 1024, 4096, 65535, 65536, 1_000_000)]
    a += [b"%n" * 8, b"%s" * 16, b"%x" * 32]
    a += [b";id", b"`id`", b"$(id)", b"|id", b"&&id", b"\nid\n"]
    a += [b"../" * 12 + b"etc/passwd", b"..\\" * 12 + b"win.ini"]
    a += [b"", b"\x00", b"\x00" * 32, b"\xff" * 32, b"\xff\xfe", b"\xc0\x80"]
    a += [b"{" * 64, b"'" * 64, b'"' * 64]
    return a

ANOMALIES = _anomalies()
INT_BOUNDARIES = [0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
                  0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


# ----------------------------------------------------------------------------
# Field-aware mutation. Each field knows how to emit a valid value and how to
# fuzz itself; the structured model mutates ONE field at a time so a finding
# isolates to a specific field (good for triage + PSIRT repro).
# ----------------------------------------------------------------------------
class Field:
    name = "field"
    def valid(self, rng: random.Random) -> bytes: raise NotImplementedError
    def fuzz(self, rng: random.Random) -> tuple[bytes, str]: raise NotImplementedError

class OpcodeField(Field):
    name = "opcode"
    def __init__(self, width=2, valid=(0x0001, 0x0002, 0x0012)):
        self.width, self.valid_ops = width, valid
    def valid(self, rng): return rng.choice(self.valid_ops).to_bytes(self.width, "big")
    def fuzz(self, rng):
        kind = rng.choice(("invalid", "reserved", "boundary"))
        mask = (1 << (8 * self.width)) - 1
        if kind == "boundary": v = rng.choice([0, mask])
        elif kind == "reserved": v = rng.choice([0x7F, 0xFE, 0xFF]) & mask
        else: v = rng.randrange(mask + 1)
        return v.to_bytes(self.width, "big"), f"op={v:#x}({kind})"

class StateField(Field):
    name = "state"
    def __init__(self, valid=(0, 1, 2), width=1):
        self.valid_states, self.width = valid, width
    def valid(self, rng): return rng.choice(self.valid_states).to_bytes(self.width, "big")
    def fuzz(self, rng):
        mask = (1 << (8 * self.width)) - 1
        v = rng.choice([0xFF, 0x80, 0xAA, rng.randrange(mask + 1)]) & mask
        return v.to_bytes(self.width, "big"), f"state={v:#x}(invalid-transition)"

class TokenField(Field):
    """Session / auth token. Set by session_setup(); fuzzed for auth bypass."""
    name = "token"
    def __init__(self, width=4):
        self.width = width
        self.session = b"\x00" * width
    def valid(self, rng): return self.session
    def fuzz(self, rng):
        kind = rng.choice(("empty", "truncated", "bitflip", "oversized", "random", "stale"))
        if kind == "empty": return b"", "tok=empty"
        if kind == "truncated": return self.session[:max(0, self.width - 1)], "tok=truncated"
        if kind == "bitflip":
            b = bytearray(self.session or b"\x00" * self.width)
            if b: b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
            return bytes(b), "tok=bitflip"
        if kind == "oversized": return b"\x41" * (self.width + rng.choice([1, 16, 256])), "tok=oversized"
        if kind == "stale": return bytes(self.width), "tok=stale/zero"
        return bytes(rng.randrange(256) for _ in range(self.width)), "tok=random"

class PayloadField(Field):
    name = "payload"
    def __init__(self, seeds=(b"",)): self.seeds = list(seeds)
    def valid(self, rng): return rng.choice(self.seeds)
    def fuzz(self, rng):
        base = rng.choice(self.seeds); anom = rng.choice(ANOMALIES)
        pos = rng.randint(0, len(base)) if base else 0
        return base[:pos] + anom + base[pos:], f"payload-anomaly@{pos} len={len(anom)}"


# ----------------------------------------------------------------------------
# Protocol models.
# ----------------------------------------------------------------------------
class ProtocolModel:
    name = "base"
    response_signature = None            # bytes or list[bytes]: marks a live target

    def mutate(self, rng): raise NotImplementedError
    def health_probe(self) -> bytes: raise NotImplementedError
    def is_healthy_response(self, resp: bytes, exc: Exception | None) -> bool:
        if exc is not None: return False
        sig = self.response_signature
        if not sig: return True
        sigs = sig if isinstance(sig, (list, tuple)) else [sig]
        return any(s in resp for s in sigs)
    def session_setup(self, target: "Target") -> bytes | None:
        """Override to perform the real auth/hello handshake; return a token."""
        return None
    def load_corpus(self, frames: list[bytes]) -> None:
        """Feed lab-captured frames in as seeds."""
        pass


class StructuredModel(ProtocolModel):
    def __init__(self, header=b"", length_width=4, fields=()):
        self.header, self.length_width, self.fields = header, length_width, list(fields)

    def _frame(self, body: bytes, length_override: int | None = None) -> bytes:
        out = self.header
        if self.length_width:
            n = len(body) if length_override is None else length_override
            n &= (1 << (8 * self.length_width)) - 1
            out += n.to_bytes(self.length_width, "big")
        return out + body

    def _render_body(self, rng, fuzz_idx):
        parts, desc = [], "valid"
        for i, f in enumerate(self.fields):
            if i == fuzz_idx:
                b, d = f.fuzz(rng); desc = f"{f.name}:{d}"
            else:
                b = f.valid(rng)
            parts.append(b)
        return b"".join(parts), desc

    def mutate(self, rng):
        roll = rng.random()
        if self.fields and roll < 0.55:                       # field-aware: fuzz one field
            idx = rng.randrange(len(self.fields))
            body, desc = self._render_body(rng, idx)
            return self._frame(body), desc
        if self.length_width and roll < 0.80:                 # length-vs-body desync
            body, _ = self._render_body(rng, None)
            bad = rng.choice(INT_BOUNDARIES + [len(body) + 1, max(0, len(body) - 1)])
            return self._frame(body, length_override=bad), f"length-desync={bad}(body={len(body)}B)"
        if roll < 0.92:                                       # raw unframed garbage
            return rng.choice(ANOMALIES), "raw-unframed"
        body, _ = self._render_body(rng, None)                # truncated valid message
        m = self._frame(body); cut = rng.randint(0, max(0, len(m) - 1))
        return m[:cut], f"truncated@{cut}"

    def health_probe(self):
        body, _ = self._render_body(random.Random(0), None)
        return self._frame(body)

    def load_corpus(self, frames):
        for f in self.fields:
            if isinstance(f, PayloadField): f.seeds += frames


class CIPLikeModel(StructuredModel):
    """TEMPLATE for Crestron CIP framing: 4B length + 2B opcode + 4B session token
    + payload. TODO(lab): replace opcode set / token semantics / payload seeds and
    set response_signature from captured CIP traffic (spec 5.2)."""
    name = "cip"
    def __init__(self):
        self.token = TokenField(4)
        super().__init__(header=b"", length_width=4, fields=[
            OpcodeField(2, valid=(0x0001, 0x0002, 0x0012)),
            self.token,
            StateField(valid=(0, 1, 2), width=1),
            PayloadField(seeds=[b"", b"\x01", b"PING", b"\x00\x00"]),
        ])
        self.response_signature = None                        # set once a reply marker is known
    def session_setup(self, target):
        # TODO(lab): perform the real CIP hello/auth handshake and return the token.
        return None


class ConsoleModel(ProtocolModel):
    """Line-based console (CTP-like, TCP 41795). TODO(lab): refine PROMPTS and
    command vocabulary from the device's Text Console."""
    name = "console"
    PROMPTS = [b">", b"CP>", b"TSW>", b"Console", b"Crestron"]   # template prompt signatures
    def __init__(self):
        self.cmds = [b"", b"help", b"ver", b"hostname", b"ipconfig", b"auth"]
        self.response_signature = self.PROMPTS
    def mutate(self, rng):
        base = rng.choice(self.cmds); anom = rng.choice(ANOMALIES)
        if rng.random() < 0.5:
            return base + b" " + anom + b"\r\n", f"arg-anomaly len={len(anom)}"
        return anom + b" " + base + b"\r\n", f"verb-anomaly len={len(anom)}"
    def health_probe(self): return b"\r\n"
    def load_corpus(self, frames):
        self.cmds += [f.rstrip(b"\r\n") for f in frames]


MODELS = {m.name: m for m in (CIPLikeModel(), ConsoleModel())}


@dataclass
class DeviceProfile:
    name: str
    ports: dict          # model name -> default TCP port
    prompts: list        # console response signatures
    tls_cip: bool        # 4-Series defaults to TLS-encrypted CIP
    auth_required: bool
    notes: str

DEVICES = {
    "cp4": DeviceProfile(
        name="Crestron CP4 (4-Series control processor)",
        ports={"cip": 41794, "console": 41795},
        prompts=[b">", b"CP4>", b"4-Series"],            # TODO(lab): confirm exact console prompt
        tls_cip=True,
        auth_required=True,
        notes=("4-Series runs a Linux platform, so the firmware track (extract + emulate "
               "+ AFL++) is viable. Default posture is auth + TLS: plaintext CIP (41794) / "
               "console (41795) may be closed, so use --tls and implement session_setup() "
               "for the CIP auth handshake; on hardened units the console is over SSH/22 "
               "(out of scope for this plain-socket sample)."),
    ),
}


# ----------------------------------------------------------------------------
# Target + multi-probe liveness instrumentation.
# ----------------------------------------------------------------------------
class Target:
    def __init__(self, host, port, timeout=3.0, tls=False):
        self.host, self.port, self.timeout, self.tls = host, port, timeout, tls
    def _wrap(self, raw):
        if not self.tls: return raw
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE    # lab: self-signed certs
        return ctx.wrap_socket(raw, server_hostname=self.host)
    def send_case(self, data: bytes):
        t0 = time.monotonic(); resp, exc = b"", None
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as raw:
                s = self._wrap(raw); s.settimeout(self.timeout)
                s.sendall(data)
                try: resp = s.recv(4096)
                except socket.timeout: pass
        except Exception as e:                                # noqa: BLE001
            exc = e
        return resp, exc, time.monotonic() - t0

def liveness(target: Target, model: ProtocolModel, probes=2):
    """Multi-probe health check: require a majority of probes to return a
    signature-valid response. Catches 'soft-hung' devices that stop responding
    correctly without a clean crash."""
    oks, lats, detail = 0, [], "ok"
    for _ in range(max(1, probes)):
        resp, exc, lat = target.send_case(model.health_probe())
        lats.append(lat)
        if model.is_healthy_response(resp, exc): oks += 1
        else: detail = f"exc={type(exc).__name__ if exc else 'no-signature'}"
    healthy = oks >= (max(1, probes) + 1) // 2
    return healthy, sum(lats) / len(lats), detail


# ----------------------------------------------------------------------------
# Deterministic case generation + artifacts.
# ----------------------------------------------------------------------------
def case_id(model, seed, index): return f"CR-{model}-{seed & 0xFFFFFFFF:08x}-{index:06d}"
def gen_case(model, seed, index):
    rng = random.Random(f"{seed}:{index}")
    data, desc = model.mutate(rng)
    return case_id(model.name, seed, index), data, desc
def hexdump(b, limit=48):
    s = b[:limit]
    return s.hex(" ") + (f" ...(+{len(b)-limit}B)" if len(b) > limit else "")

@dataclass
class Finding:
    case_id: str; classification: str; mutation: str; latency: float
    sent_hex: str; sent_len: int; response_hex: str; exception: str; health_detail: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ----------------------------------------------------------------------------
# Target scoping (do-not-fuzz guard). Allowlist required to send.
# ----------------------------------------------------------------------------
def parse_nets(s):
    nets = []
    for part in (s or "").split(","):
        part = part.strip()
        if part: nets.append(ipaddress.ip_network(part, strict=False))
    return nets

def check_scope(host, allow, deny):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except Exception:
        return False, f"cannot resolve {host!r}"
    for n in deny:
        if ip in n: return False, f"{ip} is in denylist ({n})"
    if not allow:
        return False, "no --scope-allow provided (allowlist is required to send)"
    if not any(ip in n for n in allow):
        return False, f"{ip} not in allowlist"
    return True, f"{ip} in scope"


def log_event(path, obj):
    if not path: return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **obj}) + "\n")


# ----------------------------------------------------------------------------
# Campaign.
# ----------------------------------------------------------------------------
def run_campaign(target, model, seed, num, rate, probes, health_every,
                 max_consec_fail, outdir, logpath):
    crash_dir = os.path.join(outdir, "crashes"); os.makedirs(crash_dir, exist_ok=True)
    delay = 1.0 / rate if rate > 0 else 0.0

    tok = model.session_setup(target)
    if tok is not None:
        print(f"[*] session established (token {len(tok)}B)")
    ok0, base_lat, det = liveness(target, model, probes)
    if not ok0:
        print(f"[!] target not alive before fuzzing ({det}); aborting."); return {"aborted": "unreachable"}
    print(f"[*] baseline ok, latency={base_lat*1000:.0f}ms; running {num} cases")
    log_event(logpath, {"event": "start", "target": f"{target.host}:{target.port}",
                        "model": model.name, "seed": seed, "baseline_ms": round(base_lat*1000)})

    stats = {"sent": 0, "findings": 0, "by_class": {}}; consec = 0
    for i in range(num):
        cid, data, desc = gen_case(model, seed, i)
        resp, exc, lat = target.send_case(data); stats["sent"] += 1
        if exc is not None or i % health_every == 0:
            alive, hlat, hdet = liveness(target, model, probes)
        else:
            alive, hlat, hdet = True, lat, "skipped"

        if not alive: cls = "CRASH_SUSPECTED"
        elif exc is not None and not isinstance(exc, socket.timeout): cls = "CONN_ERROR"
        elif hlat > max(0.5, base_lat * 5): cls = "DEGRADED"
        else: cls = "OK"

        if cls != "OK":
            stats["findings"] += 1; stats["by_class"][cls] = stats["by_class"].get(cls, 0) + 1
            f = Finding(cid, cls, desc, lat, hexdump(data, 512), len(data),
                        hexdump(resp, 256), type(exc).__name__ if exc else "", hdet)
            json.dump(asdict(f), open(os.path.join(crash_dir, cid + ".json"), "w"), indent=2)
            open(os.path.join(crash_dir, cid + ".bin"), "wb").write(data)
            log_event(logpath, {"event": "finding", "case": cid, "class": cls, "mutation": desc})
            print(f"[!] {cls:16s} {cid}  {desc}")
            consec = consec + 1 if cls == "CRASH_SUSPECTED" else 0
            if consec >= max_consec_fail:
                print(f"[!] {consec} consecutive crash signals -> STOP. Isolate/power-cycle the device "
                      f"before continuing (see safety checklist).")
                stats["aborted"] = "circuit-breaker"
                log_event(logpath, {"event": "circuit_breaker", "consecutive": consec}); break
        if delay: time.sleep(delay)

    print(f"\n[*] done. sent={stats['sent']} findings={stats['findings']} {stats['by_class']}")
    json.dump({"target": f"{target.host}:{target.port}", "model": model.name, "seed": seed, **stats},
              open(os.path.join(outdir, "summary.json"), "w"), indent=2)
    log_event(logpath, {"event": "end", **stats})
    print(f"[*] artifacts: {crash_dir}/   summary: {outdir}/summary.json   log: {logpath}")
    return stats


def dry_run(model, seed, num):
    print(f"[dry-run] model={model.name} seed={seed} - generating {num} cases, sending NOTHING.\n")
    for i in range(num):
        cid, data, desc = gen_case(model, seed, i)
        print(f"  {cid}  {len(data):>8}B  {desc:<34}  {hexdump(data)}")
    print("\n[dry-run] pass --authorized AND --scope-allow <CIDR> (lab/owned only) to send.")


def replay(target, path):
    data = open(path, "rb").read()
    print(f"[replay] sending {len(data)}B from {path}")
    resp, exc, lat = target.send_case(data)
    print(f"[replay] latency={lat*1000:.0f}ms exc={type(exc).__name__ if exc else 'none'} "
          f"resp={hexdump(resp,256)!r}")


def make_advisory(artifact_json, outdir):
    d = json.load(open(artifact_json))
    md = f"""# DRAFT PSIRT advisory - {d['case_id']}

- **Status:** DRAFT - lab finding, pending validation
- **Classification:** {d['classification']}
- **Protocol / port:** <fill, e.g. CIP / TCP 41794>
- **Device / firmware:** <fill: model, firmware version>
- **Mutation:** `{d['mutation']}`
- **Observed:** latency {d['latency']*1000:.0f} ms; health `{d['health_detail']}`; exception `{d['exception'] or 'none'}`

## Reproduction
1. Confirm target alive (liveness probe passes).
2. Send the saved case:
   `python3 crestron_fuzzer.py <host> <port> --replay {d['case_id']}.bin --authorized --scope-allow <cidr>`
3. Observe: **{d['classification']}**.

First bytes sent: `{d['sent_hex'][:160]}`

## Impact (assess before submission)
<fill: DoS / memory corruption / auth bypass / RCE; pre-auth? privileged?; CVSS v3.1 vector>

## Disclosure
Submit via Crestron "Report a Product Vulnerability" (PSIRT) with the `.bin` and this note.
"""
    os.makedirs(os.path.join(outdir, "advisories"), exist_ok=True)
    out = os.path.join(outdir, "advisories", d["case_id"] + ".md")
    open(out, "w").write(md)
    print(md); print(f"[*] written: {out}")


def main():
    p = argparse.ArgumentParser(description="Sample Crestron/AV-IoT protocol fuzzer (lab use only).")
    p.add_argument("host"); p.add_argument("port", type=int, nargs="?", default=None)
    p.add_argument("--model", choices=list(MODELS), default="cip")
    p.add_argument("--device", choices=list(DEVICES), help="apply a device profile (ports, prompts, TLS)")
    p.add_argument("--tls", dest="tls", action="store_true", default=None, help="wrap connection in TLS")
    p.add_argument("--no-tls", dest="tls", action="store_false", help="force plaintext")
    p.add_argument("--cases", type=int, default=1000)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--rate", type=float, default=10.0, help="max cases/sec (safe-mode)")
    p.add_argument("--probes", type=int, default=2, help="liveness probes per health check")
    p.add_argument("--health-every", type=int, default=10)
    p.add_argument("--max-consec-fail", type=int, default=3, help="circuit breaker")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--outdir", default="out")
    p.add_argument("--log", default=None, help="JSONL run log (default: <outdir>/run.jsonl)")
    p.add_argument("--seed-corpus", help="dir of lab-captured frames (*.bin) to seed the model")
    p.add_argument("--scope-allow", help="comma CIDR/IP allowlist (REQUIRED to send)")
    p.add_argument("--scope-deny", help="comma CIDR/IP denylist (always enforced)")
    p.add_argument("--authorized", action="store_true", help="REQUIRED to send; confirms lab/owned target")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--replay", metavar="ARTIFACT.bin")
    p.add_argument("--advisory", metavar="ARTIFACT.json", help="emit a PSIRT advisory stub and exit")
    args = p.parse_args()

    if args.advisory:
        make_advisory(args.advisory, args.outdir); return 0

    seed = args.seed if args.seed is not None else random.randrange(2**32)
    model = MODELS[args.model]
    prof = DEVICES.get(args.device); port = args.port; tls = args.tls
    if prof:
        if port is None: port = prof.ports.get(args.model)
        if tls is None: tls = prof.tls_cip and args.model == "cip"
        if isinstance(model, ConsoleModel):
            model.PROMPTS = prof.prompts; model.response_signature = prof.prompts
        print(f"[*] device profile: {prof.name}\n    {prof.notes}")
    if port is None:
        print("[!] no port given; pass a port or --device to derive it."); return 2
    tls = bool(tls)
    if args.seed_corpus and os.path.isdir(args.seed_corpus):
        frames = [open(os.path.join(args.seed_corpus, f), "rb").read()
                  for f in sorted(os.listdir(args.seed_corpus))
                  if os.path.isfile(os.path.join(args.seed_corpus, f))]
        model.load_corpus(frames); print(f"[*] loaded {len(frames)} corpus frames")
    target = Target(args.host, port, args.timeout, tls=tls)
    logpath = args.log or os.path.join(args.outdir, "run.jsonl")

    sending = bool(args.authorized) and not args.dry_run
    if not sending and not args.replay:
        dry_run(model, seed, min(args.cases, 50)); return 0

    # Sending or replay -> enforce authorization + scoping.
    if not args.authorized:
        print("[!] sending requires --authorized (lab/owned device only)."); return 2
    ok, why = check_scope(args.host, parse_nets(args.scope_allow), parse_nets(args.scope_deny))
    if not ok:
        print(f"[!] target out of scope: {why}. Refusing to send."); return 3
    print(f"[*] scope check: {why}")

    if args.replay:
        replay(target, args.replay); return 0
    print("=" * 72)
    print(" AUTHORIZED SEND MODE - confirm this is a device you own / are scoped to test.")
    print(f" target={args.host}:{port} tls={tls} model={model.name} seed={seed} rate={args.rate}/s probes={args.probes}")
    print("=" * 72)
    run_campaign(target, model, seed, args.cases, args.rate, args.probes,
                 args.health_every, args.max_consec_fail, args.outdir, logpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
