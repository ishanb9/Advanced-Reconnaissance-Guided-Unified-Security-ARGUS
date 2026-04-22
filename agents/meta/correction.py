"""
correction.py — Structured correction output from meta-agents.

A Correction represents one identified issue with a confidence score.
Tier (blocking vs advisory) is derived automatically from confidence.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

# Confidence at or above this threshold → blocking correction.
# Overridable at runtime via environment variable.
BLOCKING_THRESHOLD: float = float(
    os.environ.get("ARGUS_META_BLOCKING_THRESHOLD", "0.8")
)

# Maximum advisory entries kept in master's rolling context buffer.
MAX_ADVISORY_CONTEXT: int = int(
    os.environ.get("ARGUS_META_MAX_ADVISORY", "20")
)

# Maximum re-plan retries when a blocking correction is issued pre-phase.
MAX_REPLAN_RETRIES: int = int(
    os.environ.get("ARGUS_META_MAX_RETRIES", "2")
)

# Recognised issue_type values. Open set — extend freely.
ISSUE_TYPES = frozenset({
    "plan_deviation",
    "missed_attack_surface",
    "skipped_tool",
    "false_positive",
    "wrong_severity",
    "missing_cve_ref",
    "missing_mitre_ref",
    "duplicate_finding",
    "objective_not_covered",
    "tool_failure_unhandled",
    "phase_goal_unmet",
})


@dataclass
class Correction:
    """
    A single structured correction produced by a meta-agent.

    Attributes
    ----------
    source               : "master_checker" | "issue_validator"
    scan_id              : Session/scan identifier.
    phase                : Phase this correction relates to.
    confidence           : Float 0.0–1.0. Drives tier derivation.
    issue_type           : One of ISSUE_TYPES (or any string for extensibility).
    description          : Human-readable explanation of the problem.
    recommended_action   : Plain text injected into master's next LLM prompt.
    affected_finding_ids : Finding IDs this correction references (may be empty).
    metadata             : Freeform dict for tool name, raw snippet, etc.
    timestamp            : Unix timestamp of correction creation.
    """

    source:               str
    scan_id:              str
    phase:                str
    confidence:           float
    issue_type:           str
    description:          str
    recommended_action:   str
    affected_finding_ids: List[str]      = field(default_factory=list)
    metadata:             Dict[str, Any] = field(default_factory=dict)
    timestamp:            float          = field(default_factory=time.time)

    @property
    def tier(self) -> str:
        """'blocking' if confidence >= BLOCKING_THRESHOLD, else 'advisory'."""
        return "blocking" if self.confidence >= BLOCKING_THRESHOLD else "advisory"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source":               self.source,
            "scan_id":              self.scan_id,
            "phase":                self.phase,
            "confidence":           self.confidence,
            "tier":                 self.tier,
            "issue_type":           self.issue_type,
            "description":          self.description,
            "recommended_action":   self.recommended_action,
            "affected_finding_ids": self.affected_finding_ids,
            "metadata":             self.metadata,
            "timestamp":            self.timestamp,
        }
