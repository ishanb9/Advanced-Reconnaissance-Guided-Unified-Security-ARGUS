"""knowledge/grammar_infer.py — LLM-inferred input grammars + deterministic mutation.

Slice-3 depth multiplier #1 (grammar-aware fuzzing).  Blind byte/string mutation
rarely reaches deep parser/protocol states because it shreds the structural framing a
target validates first (magic bytes, length prefixes, enum/type tags).  Here an LLM
infers a lightweight *field model* (``GrammarModel``) from a handful of observed samples;
``mutate`` then walks that model emitting **valid-but-novel** inputs — it keeps the
structural fields intact (magic verbatim, length re-computed, enum chosen from options)
while aggressively fuzzing the *free* fields, so the input survives early validation and
exercises code blind fuzzing never touches.

Everything here is air-gap safe and pure-additive:

* The only outside call is ``await llm_generate(prompt, system)`` (the tiered-fallback
  callable threaded in from the campaign — never a provider import).  No network, no
  filesystem, no subprocess.
* ``infer_grammar`` never raises — it returns ``None`` when there is no LLM or the model
  cannot be parsed.
* ``mutate`` is **deterministic** for a fixed ``rng_seed`` (seeded ``random.Random`` —
  never the global ``random``, ``time``, or any clock) so a finding reproduces, and never
  raises (returns ``[]`` on a bad model).

The emitted payloads are plain ``bytes`` — the exact shape the transport engines
(``live_http``, ``live_proto``, binary) already consume.
"""
from __future__ import annotations

import json
import logging
import random
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("argus.knowledge.grammar_infer")

# Field ``type`` values understood by the mutator.
_FIELD_TYPES = ("magic", "length", "enum", "int", "str", "bytes")
# Grammar ``kind`` values (informational; steers nothing destructive).
_KINDS = ("http", "proto", "file", "generic")

# Known-bad tokens the free-field fuzzer sprinkles in — classic parser/boundary breakers.
_BAD_TOKENS = (
    b"%n", b"%s%s%s", b"\x00", b"\xff\xfe", b"../", b"' OR '1'='1",
    b"\r\n", b"{{7*7}}", b"A" * 64, b"-1", b"2147483648", b"<x>",
    b"\x80\x81\x82", b"%00", b"NaN", b"\xde\xad\xbe\xef",
)
# Printable-ish byte alphabet for random str/bytes generation.
_CHARSET = bytes(range(0x20, 0x7f)) + b"\x00\x01\x07\x08\x09\x0a\x0d\x1b\x7f\xff\xfe\x80"

# Hard caps so a hostile/huge model or sample set can never blow up memory.
_MAX_SAMPLES = 10
_MIN_SAMPLES = 1
_MAX_SAMPLE_BYTES = 2048
_MAX_FIELDS = 64
_MAX_FREE_FIELD_LEN = 4096
_MAX_N = 4096


@dataclass
class GrammarModel:
    """An ordered field model of an input format inferred from observed samples.

    ``fields`` is an ordered list of dicts, each ``{name, type, ...}`` where ``type`` is
    one of ``magic|length|enum|int|str|bytes``:

      * ``magic``  — emit ``value`` verbatim (a constant framing byte run).
      * ``length`` — a byte-length prefix; ``len_of`` names the field it measures and is
        recomputed after assembly so the input stays structurally valid.
      * ``enum``   — pick one of ``options`` per case.
      * ``int``    — a packed integer (fuzzed across boundaries).
      * ``str``    — a text field (fuzzed: random length / charset / known-bad tokens).
      * ``bytes``  — a binary field (fuzzed like ``str`` but full byte range).
    """
    fields: List[Dict[str, Any]] = field(default_factory=list)
    kind: str = "generic"          # http | proto | file | generic
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"fields": list(self.fields), "kind": self.kind, "notes": self.notes}


_INFER_SYS = (
    "You reverse-engineer the structure of an input format for an AUTHORIZED fuzzing "
    "test. You are given a few observed samples. Infer an ordered FIELD MODEL and return "
    "ONLY a single strict JSON object, no prose, of the form:\n"
    '{"kind":"http|proto|file|generic","notes":"...","fields":['
    '{"name":"magic","type":"magic","value":"<hex or text constant>"},'
    '{"name":"len","type":"length","len_of":"<name of the field it measures>"},'
    '{"name":"op","type":"enum","options":["A","B"]},'
    '{"name":"count","type":"int"},'
    '{"name":"name","type":"str"},'
    '{"name":"blob","type":"bytes"}]}\n'
    "Rules: fields are IN ORDER. type is one of magic|length|enum|int|str|bytes. "
    "Use 'magic' for constant framing bytes, 'length' (with len_of) for size prefixes, "
    "'enum' (with options) for a small fixed set, 'int' for numeric fields, 'str'/'bytes' "
    "for free/variable content. Keep it to the structurally important fields only."
)


def _hexdump_sample(s: Any) -> str:
    """Render one sample as a short, LLM-friendly string (text if printable, else hex)."""
    try:
        if isinstance(s, str):
            raw = s.encode("utf-8", "replace")
        elif isinstance(s, (bytes, bytearray)):
            raw = bytes(s)
        else:
            raw = str(s).encode("utf-8", "replace")
    except Exception:
        return ""
    raw = raw[:_MAX_SAMPLE_BYTES]
    # Mostly-printable → show as text; otherwise a compact hex string.
    printable = sum(1 for b in raw if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d))
    if raw and printable / len(raw) > 0.85:
        try:
            return "text: " + raw.decode("utf-8", "replace")
        except Exception:
            pass
    return "hex: " + raw.hex()


def _coerce_value_to_bytes(v: Any) -> bytes:
    """Turn a model's ``value``/``options`` entry into bytes (accept hex or text/int)."""
    try:
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
        if isinstance(v, bool):
            return b"\x01" if v else b"\x00"
        if isinstance(v, int):
            # Smallest big-endian byte run that holds it (at least 1 byte).
            n = max(1, (v.bit_length() + 7) // 8)
            return int(v).to_bytes(n, "big", signed=v < 0)
        s = str(v)
        # A clean even-length hex string → decode as bytes; else raw UTF-8.
        h = s[2:] if s[:2].lower() == "0x" else s
        if h and len(h) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in h):
            try:
                return bytes.fromhex(h)
            except Exception:
                pass
        return s.encode("utf-8", "replace")
    except Exception:
        return b""


def _parse_model(raw: str) -> Optional[Dict[str, Any]]:
    """Tolerant parse of the LLM reply into a dict.  Prefer utils.json_tolerant."""
    if not raw:
        return None
    # Preferred: the project's forgiving parser.
    try:
        from utils.json_tolerant import parse_lossy
        obj, _repairs = parse_lossy(raw)
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, list):
            return {"fields": obj}
    except Exception:
        pass
    # Fallback: strip ```json fences then json.loads the first {...} object.
    try:
        s = raw.strip()
        if "```" in s:
            seg = s.split("```", 2)
            if len(seg) >= 2:
                body = seg[1]
                if body[:4].lower() == "json":
                    body = body[4:]
                s = body.strip()
        i, j = s.find("{"), s.rfind("}")
        if i < 0 or j <= i:
            return None
        obj = json.loads(s[i:j + 1])
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _normalise_fields(raw_fields: Any) -> List[Dict[str, Any]]:
    """Validate + clean the model's field list down to the supported shape."""
    out: List[Dict[str, Any]] = []
    if not isinstance(raw_fields, list):
        return out
    for idx, f in enumerate(raw_fields[:_MAX_FIELDS]):
        if not isinstance(f, dict):
            continue
        ftype = str(f.get("type") or "").strip().lower()
        if ftype not in _FIELD_TYPES:
            continue
        name = str(f.get("name") or f"f{idx}")
        nf: Dict[str, Any] = {"name": name, "type": ftype}
        if ftype == "magic":
            if "value" not in f:
                continue
            nf["value"] = f.get("value")
        elif ftype == "length":
            nf["len_of"] = str(f.get("len_of") or "")
        elif ftype == "enum":
            opts = f.get("options")
            if not isinstance(opts, list) or not opts:
                continue
            nf["options"] = list(opts)
        # int / str / bytes carry no required attributes.
        out.append(nf)
    return out


async def infer_grammar(samples: List[Any], *, llm_generate,
                        hint: str = "") -> "Optional[GrammarModel]":
    """Infer a :class:`GrammarModel` from 3-10 observed samples via the tiered LLM.

    ``samples`` are bytes or str; they are capped + hexdumped and sent to
    ``await llm_generate(prompt, system)`` asking for a strict JSON field model.  Returns
    a :class:`GrammarModel`, or ``None`` when ``llm_generate`` is ``None`` or the reply
    cannot be parsed into a usable model.  Never raises.
    """
    try:
        if llm_generate is None:
            return None
        sample_list = [s for s in (samples or []) if s not in (None, "", b"")]
        if len(sample_list) < _MIN_SAMPLES:
            return None
        rendered = []
        for k, s in enumerate(sample_list[:_MAX_SAMPLES]):
            dumped = _hexdump_sample(s)
            if dumped:
                rendered.append(f"sample[{k}] {dumped}")
        if not rendered:
            return None
        prompt = (
            (f"Hint: {hint}\n" if hint else "")
            + f"{len(rendered)} observed input sample(s):\n"
            + "\n".join(rendered)
            + "\nInfer the ordered field model and return ONLY the strict JSON object."
        )
        try:
            raw = await llm_generate(prompt, _INFER_SYS)
        except Exception as exc:  # noqa: BLE001
            logger.debug("grammar inference llm_generate failed: %s", exc)
            return None
        obj = _parse_model(raw or "")
        if not isinstance(obj, dict):
            return None
        fields = _normalise_fields(obj.get("fields"))
        if not fields:
            return None
        kind = str(obj.get("kind") or "generic").strip().lower()
        if kind not in _KINDS:
            kind = "generic"
        notes = str(obj.get("notes") or "")[:500]
        return GrammarModel(fields=fields, kind=kind, notes=notes)
    except Exception as exc:  # noqa: BLE001
        logger.debug("infer_grammar failed: %s", exc)
        return None


def _fuzz_free_bytes(r: random.Random, *, text: bool) -> bytes:
    """Generate one fuzzed free-field value deterministically from ``r``."""
    strategy = r.randint(0, 4)
    if strategy == 0:
        # A known-bad token (optionally repeated) — classic parser breaker.
        tok = r.choice(_BAD_TOKENS)
        return tok * r.randint(1, 4)
    if strategy == 1:
        # Empty / single byte — boundary.
        return b"" if r.random() < 0.5 else bytes([r.randint(0, 255)])
    if strategy == 2:
        # Long buffer — overflow / DoS pressure.
        n = r.choice((16, 64, 256, 1024))
        n = min(n, _MAX_FREE_FIELD_LEN)
        return bytes(r.choice(_CHARSET) for _ in range(n)) if text else bytes(
            r.randint(0, 255) for _ in range(n))
    # Default: random-length random content.
    n = r.randint(0, 48)
    if text:
        return bytes(r.choice(_CHARSET) for _ in range(n))
    return bytes(r.randint(0, 255) for _ in range(n))


def _fuzz_int_bytes(r: random.Random) -> bytes:
    """A packed integer, biased toward overflow/boundary values, deterministic."""
    boundaries = (0, 1, -1, 127, 128, 255, 256, 32767, 32768, 65535,
                  2147483647, 2147483648, 4294967295)
    if r.random() < 0.6:
        val = r.choice(boundaries)
    else:
        val = r.randint(0, 0xFFFFFFFF)
    width = r.choice((1, 2, 4, 8))
    signed = val < 0
    try:
        return int(val).to_bytes(width, r.choice(("big", "little")), signed=signed)
    except (OverflowError, ValueError):
        # Value doesn't fit the chosen width — fall back to a safe 8-byte pack.
        try:
            return struct.pack(">q" if signed else ">Q", val & 0xFFFFFFFFFFFFFFFF
                               if not signed else val)
        except Exception:
            return b"\x00\x00\x00\x00"


def mutate(model: "GrammarModel", *, n: int = 32, rng_seed: int = 0) -> List[bytes]:
    """Generate ``n`` valid-but-novel inputs from ``model`` as ``list[bytes]``.

    Walks the ordered fields honouring structure — ``magic`` emitted verbatim, ``enum``
    chosen from ``options``, ``int`` packed — while fuzzing ``str``/``bytes`` free fields.
    After each case is assembled, every ``length`` field is rewritten to the byte-length
    of the field named in its ``len_of`` so the input stays structurally valid.

    **Deterministic**: identical ``rng_seed`` (and model) always yields identical output —
    it uses ``random.Random(rng_seed)`` only, never the global RNG/clock.  Never raises;
    returns ``[]`` on a bad/empty model.
    """
    try:
        if model is None:
            return []
        fields = getattr(model, "fields", None)
        if not isinstance(fields, list) or not fields:
            return []
        try:
            count = max(0, min(int(n), _MAX_N))
        except Exception:
            count = 0
        if count == 0:
            return []
        r = random.Random(rng_seed)

        out: List[bytes] = []
        for _case in range(count):
            # Phase 1 — emit each field's bytes, tracking by name for length fix-up.
            parts: List[bytes] = []
            by_name: Dict[str, int] = {}        # field name → index in ``parts``
            length_fields: List[Dict[str, Any]] = []
            for f in fields:
                if not isinstance(f, dict):
                    parts.append(b"")
                    continue
                ftype = str(f.get("type") or "").lower()
                name = str(f.get("name") or "")
                if ftype == "magic":
                    chunk = _coerce_value_to_bytes(f.get("value"))
                elif ftype == "enum":
                    opts = f.get("options") or [b""]
                    chunk = _coerce_value_to_bytes(r.choice(opts))
                elif ftype == "int":
                    chunk = _fuzz_int_bytes(r)
                elif ftype == "length":
                    chunk = b"\x00\x00\x00\x00"   # placeholder; fixed in phase 2
                    length_fields.append(f)
                elif ftype == "str":
                    chunk = _fuzz_free_bytes(r, text=True)
                elif ftype == "bytes":
                    chunk = _fuzz_free_bytes(r, text=False)
                else:
                    chunk = b""
                if name and name not in by_name:
                    by_name[name] = len(parts)
                parts.append(chunk)

            # Phase 2 — rewrite every length field to its target field's byte length.
            for f in length_fields:
                target = str(f.get("len_of") or "")
                tgt_idx = by_name.get(target)
                measured = len(parts[tgt_idx]) if tgt_idx is not None else 0
                idx = by_name.get(str(f.get("name") or ""))
                if idx is None:
                    continue
                width = len(parts[idx]) or 4
                try:
                    parts[idx] = int(measured).to_bytes(width, "big", signed=False)
                except (OverflowError, ValueError):
                    # Measured length exceeds the prefix width — widen to fit.
                    need = max(1, (measured.bit_length() + 7) // 8)
                    parts[idx] = int(measured).to_bytes(need, "big", signed=False)

            out.append(b"".join(parts))
        return out
    except Exception as exc:  # noqa: BLE001
        logger.debug("mutate failed: %s", exc)
        return []


__all__ = ["GrammarModel", "infer_grammar", "mutate"]
