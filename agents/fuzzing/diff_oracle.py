"""agents/fuzzing/diff_oracle.py — differential-testing oracle (Slice 3 depth multiplier).

Send the SAME input to a target AND an operator-supplied reference implementation, then
compare the two responses *after normalisation*.  The bug class this catches is a SILENT
logic / parsing divergence: the two stacks disagree on how to parse or evaluate the same
bytes, but NEITHER crashes and NEITHER reflects an injection marker — so every single-target
oracle in ``oracle.py`` stays quiet.  Differences that survive normalisation (status code,
body, headers, length — with volatile bits like dates / UUIDs / nonces stripped) become a
``type='differential_divergence'`` Anomaly with a family-specific ``exploit_class``:

* status-code divergence on a smuggling-style request → ``request_smuggling``
* a cert / TLS validation divergence                  → ``auth_bypass``
* a SQL / parse semantic divergence                   → ``sqli_exfil``
* anything else materially different                  → ``logic_divergence``

Pure + offline: this module never touches the network itself (the ``differential`` engine
owns transport and feeds it two already-collected Observations).  It NEVER raises — any
internal error returns ``None`` (no false anomaly).
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, Optional

from agents.fuzzing.engines.base import Anomaly

logger = logging.getLogger("argus.fuzz.diff_oracle")

# ── Volatile-bit scrubbers: strip anything that legitimately differs run-to-run so two
#    semantically-identical responses normalise to the same bytes (no spurious divergence). ──
_VOLATILE = [
    # RFC-1123 / common HTTP date headers and ISO-8601 timestamps.
    re.compile(r"\b\w{3},\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT\b", re.I),
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", re.I),
    # UUIDs.
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
    # Nonces / request-ids / csrf tokens / etags (key=longhex|longb64).
    re.compile(r"(?i)(nonce|csrf|request[-_]?id|x-request-id|etag|boundary|session[-_]?id|"
               r"trace[-_]?id|set-cookie)\s*[=:]\s*[\"']?[A-Za-z0-9+/_\-]{8,}[\"']?"),
    # Bare long hex / base64 blobs (signatures, hashes).
    re.compile(r"\b[0-9a-f]{32,}\b", re.I),
]
_VOLATILE_HDRS = {"date", "set-cookie", "etag", "x-request-id", "x-trace-id",
                  "request-id", "age", "expires", "last-modified", "x-amz-request-id",
                  "x-amz-id-2", "cf-ray", "x-served-by", "x-timer", "x-cache",
                  "report-to", "nel"}

# Recognise *why* the two diverged so the develop loop weaponises the right family.
_SQL_SEMANTIC = re.compile(r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3?::|"
                           r"Unclosed quotation|ODBC SQL|syntax error at or near|"
                           r"unterminated quoted|division by zero|invalid input syntax", re.I)
_CERT_TLS = re.compile(r"certificate|tls|ssl|x509|handshake|self[- ]signed|"
                       r"verify failed|hostname mismatch|unknown ca|cert(?:ificate)? expired",
                       re.I)
_SMUGGLE_HDRS = re.compile(r"transfer-encoding|content-length", re.I)


class DifferentialOracle:
    """Classify a (primary, reference) Observation pair into a divergence Anomaly.

    ``reference`` is the operator-supplied reference endpoint / id; it is recorded on the
    Anomaly detail so a finding is reproducible against the same lab pair.
    """

    def __init__(self, reference: str) -> None:
        self.reference = str(reference or "")

    # ── public ──────────────────────────────────────────────────────────────────────
    def classify(self, modality: str, primary_obs: Any,
                 reference_obs: Any) -> Optional[Anomaly]:
        """Return a ``differential_divergence`` Anomaly when the normalised primary vs
        reference outputs differ materially, else ``None``.  Never raises."""
        try:
            if primary_obs is None or reference_obs is None:
                return None
            p = self._normalise(primary_obs)
            r = self._normalise(reference_obs)
            if p is None or r is None:
                return None

            diffs = self._material_diffs(p, r)
            if not diffs:
                return None  # normalised outputs equivalent → not a finding

            exploit_class = self._family(diffs, p, r)
            evidence = self._evidence(diffs, p, r)
            signature = self._signature(diffs, p, r)
            return Anomaly(
                type="differential_divergence",
                exploit_class=exploit_class,
                severity_hint="medium",
                evidence=evidence[:400],
                case_id=str(getattr(primary_obs, "case_id", "") or ""),
                signature=signature,
                detail={
                    "reference": self.reference,
                    "modality": str(modality or ""),
                    "fields": sorted(diffs.keys()),
                },
            )
        except Exception as exc:  # noqa: BLE001 — never raise out of an oracle.
            logger.debug("diff_oracle.classify error: %s", exc)
            return None

    # ── normalisation ───────────────────────────────────────────────────────────────
    def _normalise(self, obs: Any) -> Optional[Dict[str, Any]]:
        """Reduce an Observation (or dict) to a comparable normalised shape.

        Strips volatile substrings from the body, lowercases header *names*, drops
        volatile headers, and derives a length.  Returns ``None`` on a bad input.
        """
        sig = self._get(obs, "signal") or {}
        if not isinstance(sig, dict):
            sig = {}
        raw = self._get(obs, "raw")
        body = raw if isinstance(raw, str) and raw else str(sig.get("body") or "")

        norm_body = self._scrub(body)
        status = sig.get("status")
        headers = self._norm_headers(sig.get("headers"))
        # Prefer a normalised-body length so a date-only delta does not register as a
        # length divergence; fall back to the reported body_len when no body present.
        length = len(norm_body) if norm_body else int(sig.get("body_len") or 0)
        return {
            "status": status,
            "body": norm_body,
            "headers": headers,
            "length": length,
            "raw_body": body,
        }

    @staticmethod
    def _scrub(text: str) -> str:
        if not text:
            return ""
        out = text
        for rx in _VOLATILE:
            try:
                out = rx.sub("<vol>", out)
            except Exception:  # noqa: BLE001
                continue
        return out

    @staticmethod
    def _norm_headers(headers: Any) -> Dict[str, str]:
        """Lowercase header names, drop volatile ones, scrub volatile values."""
        out: Dict[str, str] = {}
        items = []
        if isinstance(headers, dict):
            items = list(headers.items())
        elif isinstance(headers, (list, tuple)):
            for h in headers:
                if isinstance(h, (list, tuple)) and len(h) == 2:
                    items.append((h[0], h[1]))
        for k, v in items:
            try:
                name = str(k).strip().lower()
            except Exception:  # noqa: BLE001
                continue
            if name in _VOLATILE_HDRS:
                continue
            out[name] = DifferentialOracle._scrub(str(v))
        return out

    # ── comparison ──────────────────────────────────────────────────────────────────
    @staticmethod
    def _material_diffs(p: Dict[str, Any], r: Dict[str, Any]) -> Dict[str, Any]:
        """Which normalised fields differ materially.  A pure date/uuid/nonce delta is
        already scrubbed away upstream, so anything left is a real semantic divergence."""
        diffs: Dict[str, Any] = {}
        if p.get("status") != r.get("status"):
            diffs["status"] = (p.get("status"), r.get("status"))
        if p.get("body") != r.get("body"):
            diffs["body"] = (p.get("body", "")[:200], r.get("body", "")[:200])
        if p.get("headers") != r.get("headers"):
            pk, rk = set(p.get("headers") or {}), set(r.get("headers") or {})
            diffs["headers"] = {"only_primary": sorted(pk - rk),
                                "only_reference": sorted(rk - pk)}
        # A length delta that the body diff did not already capture (e.g. equal-after-scrub
        # bodies but differing reported body_len) is still worth recording.
        if "body" not in diffs and p.get("length") != r.get("length"):
            diffs["length"] = (p.get("length"), r.get("length"))
        return diffs

    @staticmethod
    def _family(diffs: Dict[str, Any], p: Dict[str, Any], r: Dict[str, Any]) -> str:
        """Pick a family-specific exploit_class from the divergence pattern."""
        blob = f"{p.get('raw_body', '')}\n{r.get('raw_body', '')}"
        hdr_names = set(p.get("headers") or {}) | set(r.get("headers") or {})

        # SQL / parse semantic divergence: one side leaked a parse/SQL error the other did not.
        if _SQL_SEMANTIC.search(blob):
            return "sqli_exfil"
        # Cert / TLS validation divergence: one side accepted what the other rejected on trust.
        if _CERT_TLS.search(blob):
            return "auth_bypass"
        # Status-code divergence on a smuggling-style request (TE/CL header in play).
        if "status" in diffs and any(_SMUGGLE_HDRS.search(h) for h in hdr_names):
            return "request_smuggling"
        # A bare status-code disagreement is also the classic smuggling/desync tell.
        if "status" in diffs:
            return "request_smuggling"
        return "logic_divergence"

    @staticmethod
    def _evidence(diffs: Dict[str, Any], p: Dict[str, Any], r: Dict[str, Any]) -> str:
        parts = []
        if "status" in diffs:
            a, b = diffs["status"]
            parts.append(f"status {a} vs {b}")
        if "length" in diffs:
            a, b = diffs["length"]
            parts.append(f"len {a} vs {b}")
        if "headers" in diffs:
            h = diffs["headers"]
            if h.get("only_primary"):
                parts.append(f"primary-only headers {h['only_primary']}")
            if h.get("only_reference"):
                parts.append(f"reference-only headers {h['only_reference']}")
        if "body" in diffs:
            a, b = diffs["body"]
            parts.append(f"body differs: primary={a!r} reference={b!r}")
        return "normalised divergence — " + "; ".join(parts) if parts else "normalised divergence"

    @staticmethod
    def _signature(diffs: Dict[str, Any], p: Dict[str, Any], r: Dict[str, Any]) -> str:
        """sha1 over a stable serialisation of the normalised diff (dedup key)."""
        material = "|".join(
            f"{k}={diffs[k]!r}" for k in sorted(diffs.keys())
        )
        digest = hashlib.sha1(material.encode("utf-8", "replace")).hexdigest()[:16]
        return f"diff:{digest}"

    @staticmethod
    def _get(obs: Any, attr: str) -> Any:
        """Read an attribute from an Observation dataclass or a plain dict."""
        if isinstance(obs, dict):
            return obs.get(attr)
        return getattr(obs, attr, None)
