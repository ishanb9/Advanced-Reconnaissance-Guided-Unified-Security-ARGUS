"""Objective-aware hypothesis backlog — the content-agnostic spine of the
engagement.

A hypothesis is `surface(node) x taxonomy(weakness class)`. The engine tracks
status / attempts / coverage and prioritises by value toward the human-set
objective; the operator authors the concrete payloads. No specific vuln, CVE,
product, or payload string lives here — only weakness-class ids (from the data
taxonomy) and structural bookkeeping.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import taxonomy as _tax

# Coarse base value per weakness class (objective filtering refines selection).
# These are class ids from the data taxonomy, not vulns.
_CLASS_PRIOR = {
    "known_cve": 0.9, "known_service_exploit": 0.9, "command_injection": 0.85,
    "ssti_to_rce": 0.85, "code_injection": 0.85, "insecure_deserialization": 0.8,
    "sqli": 0.8, "privilege_escalation": 0.8, "data_exfiltration": 0.8,
    "auth_bypass": 0.75, "file_upload": 0.75, "credential_reuse": 0.7,
    "ssrf": 0.7, "path_traversal": 0.7, "default_creds": 0.7, "idor": 0.65,
    "xxe": 0.6, "exposed_secrets": 0.6, "business_logic": 0.6,
    "weak_crypto_session": 0.55, "misconfiguration": 0.5, "supply_chain": 0.5,
    "info_disclosure": 0.4, "open_redirect": 0.3,
}


class Hypothesis:
    __slots__ = ("id", "node_key", "node_ref", "weakness_class", "rationale",
                 "value", "status", "attempts", "evidence", "source")

    def __init__(self, id, node_key, node_ref, weakness_class, rationale="",
                 value=0.0, status="untried", attempts=0, evidence="", source="surface"):
        self.id = id
        self.node_key = node_key
        self.node_ref = node_ref
        self.weakness_class = weakness_class
        self.rationale = rationale
        self.value = value
        self.status = status
        self.attempts = attempts
        self.evidence = evidence
        self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Hypothesis":
        return cls(**{k: d.get(k) for k in cls.__slots__})


class HypothesisBacklog:
    def __init__(self, objective_kinds: List[str] = None):
        self.objective_kinds = objective_kinds or ["access", "flag", "data"]
        self.items: Dict[str, Hypothesis] = {}
        self._seq = 0

    def _key(self, node_key: str, weakness_class: str) -> str:
        return f"{node_key}::{weakness_class}"

    def generate_from_surface(self, surface) -> int:
        added = 0
        objk = set(self.objective_kinds)
        for node in surface.nodes.values():
            caps = set(node.capabilities)
            # Generate EVERY capability-matched class — an intermediate foothold
            # (e.g. SSRF -> access) is a valid path to a 'flag' objective, so the
            # objective is a value BOOST, not a hard filter.
            classes = _tax.classes_for_capabilities(sorted(caps))
            for c in classes:
                k = self._key(node.key, c["id"])
                if k in self.items:
                    continue
                self._seq += 1
                trig = set(c.get("triggering_capabilities", []))
                # Evidence weighting: a class whose FULL trigger set is present is
                # structurally evidenced and ranks high; one matched on a single
                # generic capability (e.g. command-injection on a non-executing
                # input) is a weak guess and ranks low — but stays tracked.
                strength = (len(caps & trig) / len(trig)) if trig else 0.5
                val = _CLASS_PRIOR.get(c["id"], 0.5) * strength
                if objk & set(c.get("objective_relevance", [])):
                    val = min(1.0, val + 0.1)   # serves the stated objective
                self.items[k] = Hypothesis(
                    id=f"h{self._seq}", node_key=node.key, node_ref=node.ref,
                    weakness_class=c["id"], rationale=c.get("generic_test_strategy", ""),
                    value=round(val, 3), source="surface")
                added += 1
        return added

    def add_external(self, weakness_class: str, node_ref: str, rationale: str,
                     value: float = 0.9, source: str = "cve_lookup") -> Optional[Hypothesis]:
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

    def _rank(self, h: Hypothesis) -> float:
        return h.value - 0.15 * h.attempts

    def next_hypothesis(self) -> Optional[Hypothesis]:
        cands = sorted(self.untried(), key=self._rank, reverse=True)
        if not cands:
            return None
        cands[0].status = "active"
        return cands[0]

    def mark(self, hyp_id: str, status: str, evidence: str = "") -> None:
        for h in self.items.values():
            if h.id == hyp_id:
                h.status = status
                if evidence:
                    h.evidence = evidence
                return

    def record_attempt(self, hyp_id: str) -> None:
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

    def high_value_remaining(self, threshold: float = 0.5) -> int:
        return sum(1 for h in self.items.values()
                   if h.status in ("untried", "active") and h.value >= threshold)

    def to_dict(self) -> Dict[str, Any]:
        return {"objective_kinds": self.objective_kinds, "seq": self._seq,
                "items": [h.to_dict() for h in self.items.values()]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HypothesisBacklog":
        bl = cls((d or {}).get("objective_kinds"))
        bl._seq = (d or {}).get("seq", 0)
        for hd in (d or {}).get("items", []):
            h = Hypothesis.from_dict(hd)
            bl.items[bl._key(h.node_key, h.weakness_class)] = h
        return bl
