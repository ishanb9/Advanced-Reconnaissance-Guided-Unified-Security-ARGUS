"""
agents/reasoning/attack_planner.py

Scores and ranks attack paths by Likelihood × Impact × Ease so the
DecisionEngine always works on the most-promising path first.

Unlike the legacy _phase_attack_planning() which ran once as a phase,
AttackPlanner is called at every reasoning loop iteration and re-ranks
paths as new evidence comes in. Paths that succeed get promoted; paths
that fail get demoted (or pruned after NegativeMemory threshold).

Scoring formula
---------------
  node_score  = likelihood × impact × ease          (0.0 – 1.0)
  path_score  = mean(node_scores) × path_confidence

Legend
------
  likelihood  — P(this step succeeds given current evidence)
  impact      — how much value this step adds (root=1.0, info=0.1)
  ease        — 1.0 = trivial / off-the-shelf, 0.1 = hard / custom
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, List, Optional

from agents.reasoning.hypothesis_engine import Hypothesis
from agents.reasoning.negative_memory   import NegativeMemory


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AttackPathNode:
    """A single step within a ranked attack path."""
    node_id:          str
    finding:          str          # e.g. "Apache 2.4.49 on port 80"
    confidence:       float        # 0.0–1.0
    likelihood:       float        # P(step succeeds)
    impact:           float        # value of this step (0.0–1.0)
    ease:             float        # 1.0 = trivial, 0.1 = very hard
    preconditions:    List[str]    = field(default_factory=list)
    tools:            List[str]    = field(default_factory=list)
    expected_outcome: str          = ""
    risk:             str          = "medium"  # low|medium|high|critical
    probability:      float        = 0.5       # joint probability along path
    mitre_technique:  Optional[str] = None

    @property
    def score(self) -> float:
        """Likelihood × Impact × Ease."""
        return self.likelihood * self.impact * self.ease

    def to_dict(self) -> dict:
        return {
            "node_id":          self.node_id,
            "finding":          self.finding,
            "confidence":       self.confidence,
            "likelihood":       self.likelihood,
            "impact":           self.impact,
            "ease":             self.ease,
            "score":            self.score,
            "preconditions":    list(self.preconditions),
            "tools":            list(self.tools),
            "expected_outcome": self.expected_outcome,
            "risk":             self.risk,
            "probability":      self.probability,
            "mitre_technique":  self.mitre_technique,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttackPathNode":
        return cls(
            node_id          = d.get("node_id", str(uuid.uuid4())),
            finding          = d.get("finding", ""),
            confidence       = float(d.get("confidence", 0.5)),
            likelihood       = float(d.get("likelihood", 0.5)),
            impact           = float(d.get("impact", 0.5)),
            ease             = float(d.get("ease", 0.5)),
            preconditions    = list(d.get("preconditions", [])),
            tools            = list(d.get("tools", [])),
            expected_outcome = d.get("expected_outcome", ""),
            risk             = d.get("risk", "medium"),
            probability      = float(d.get("probability", 0.5)),
            mitre_technique  = d.get("mitre_technique"),
        )


@dataclass
class RankedAttackPath:
    """A complete attack path from entry-point to objective."""
    path_id:           str
    nodes:             List[AttackPathNode] = field(default_factory=list)
    total_score:       float = 0.0
    description:       str   = ""
    entry_point:       str   = ""
    objective:         str   = "foothold"  # foothold|root|domain_admin|data_exfil
    estimated_effort:  str   = "medium"    # low|medium|high
    path_confidence:   float = 0.5

    def recompute_score(self) -> float:
        """Recompute total_score from node scores and path confidence."""
        if not self.nodes:
            self.total_score = 0.0
            return 0.0
        mean_node = sum(n.score for n in self.nodes) / len(self.nodes)
        self.total_score = mean_node * self.path_confidence
        return self.total_score

    def to_dict(self) -> dict:
        return {
            "path_id":          self.path_id,
            "nodes":            [n.to_dict() for n in self.nodes],
            "total_score":      self.total_score,
            "description":      self.description,
            "entry_point":      self.entry_point,
            "objective":        self.objective,
            "estimated_effort": self.estimated_effort,
            "path_confidence":  self.path_confidence,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RankedAttackPath":
        nodes = [AttackPathNode.from_dict(n) for n in d.get("nodes", [])]
        return cls(
            path_id          = d.get("path_id", str(uuid.uuid4())),
            nodes            = nodes,
            total_score      = float(d.get("total_score", 0.0)),
            description      = d.get("description", ""),
            entry_point      = d.get("entry_point", ""),
            objective        = d.get("objective", "foothold"),
            estimated_effort = d.get("estimated_effort", "medium"),
            path_confidence  = float(d.get("path_confidence", 0.5)),
        )


# ---------------------------------------------------------------------------
# AttackPlanner
# ---------------------------------------------------------------------------

class AttackPlanner:
    """
    Builds and re-ranks attack paths at every reasoning-loop iteration.

    The planner makes a single structured LLM call that returns a list of
    attack paths, each scored by Likelihood × Impact × Ease. Paths are
    updated after each action by update_path_after_result().

    Parameters
    ----------
    think_json_fn:
        Async callable matching BaseAgent.think_json(prompt, system) → dict.
    kb_fn:
        KB context callable matching _kb_context(query, ...) → str.
    session_id:
        Active session identifier.
    """

    _MAX_PATHS:         int   = 5
    _MAX_NODES_PER_PATH: int  = 6

    def __init__(
        self,
        think_json_fn: Callable[..., Coroutine],
        kb_fn:         Callable[..., Any],
        session_id:    str,
    ) -> None:
        self._think_json  = think_json_fn
        self._kb          = kb_fn
        self._session_id  = session_id
        self._paths:      List[RankedAttackPath] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def rank_paths(
        self,
        intel:           dict,
        hypotheses:      List[Hypothesis],
        negative_memory: NegativeMemory,
        iteration:       int = 0,
    ) -> List[RankedAttackPath]:
        """
        Generate and rank attack paths from current evidence and hypotheses.

        Re-uses existing _paths when available (updates scores instead of
        regenerating from scratch) to avoid redundant LLM calls.
        If evidence changed significantly, regenerates fully.

        Returns
        -------
        List[RankedAttackPath]
            Sorted by total_score descending. Empty list on LLM failure.
        """
        prompt  = self._build_prompt(intel, hypotheses, negative_memory)
        system  = self._build_system()

        try:
            raw = await self._think_json(prompt, system)
        except Exception:
            # Return existing paths (possibly from previous iteration)
            return sorted(self._paths, key=lambda p: p.total_score, reverse=True)

        new_paths = self._parse_paths(raw)
        if new_paths:
            self._paths = new_paths

        # Sort and return
        self._paths.sort(key=lambda p: p.total_score, reverse=True)
        return list(self._paths[:self._MAX_PATHS])

    async def update_path_after_result(
        self,
        path:            RankedAttackPath,
        action_tool:     str,
        action_result:   dict,
        validated:       bool,
    ) -> RankedAttackPath:
        """
        Adjust path confidence and node scores after an action executes.

        If the action validated the hypothesis → increase path_confidence.
        If the action refuted the hypothesis  → decrease path_confidence.
        """
        delta = 0.15 if validated else -0.20

        path.path_confidence = max(0.0, min(1.0, path.path_confidence + delta))

        # Update nodes that use the same tool
        for node in path.nodes:
            if action_tool in (node.tools or []):
                if validated:
                    node.likelihood = min(1.0, node.likelihood + 0.1)
                else:
                    node.likelihood = max(0.0, node.likelihood - 0.15)

        path.recompute_score()
        return path

    def get_best_path(self) -> Optional[RankedAttackPath]:
        """Return the highest-scoring path, or None if no paths exist."""
        if not self._paths:
            return None
        return max(self._paths, key=lambda p: p.total_score)

    def get_paths_as_dicts(self) -> List[dict]:
        """Serialise all current paths for checkpoint storage."""
        return [p.to_dict() for p in self._paths]

    def restore_from_dicts(self, path_dicts: List[dict]) -> None:
        """Restore paths from checkpoint data (session resume)."""
        self._paths = [RankedAttackPath.from_dict(d) for d in path_dicts]

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------

    def _build_system(self) -> str:
        return (
            "You are a senior red team operator planning attack paths against a target. "
            "Your goal is to produce a ranked list of attack paths that lead from the "
            "current position to a meaningful objective (foothold, root, domain admin, "
            "or data exfiltration). Each path must be grounded in the observed evidence.\n\n"
            "Score each step by:\n"
            "  likelihood: probability this step succeeds (0.0–1.0)\n"
            "  impact: how much it advances the objective (0.0–1.0; root=1.0)\n"
            "  ease: how easy to execute (1.0=off-the-shelf tool, 0.1=custom exploit)\n\n"
            "Respond ONLY with valid JSON. No markdown. No prose."
        )

    def _build_prompt(
        self,
        intel:           dict,
        hypotheses:      List[Hypothesis],
        negative_memory: NegativeMemory,
    ) -> str:
        lines = ["=== CURRENT EVIDENCE ==="]

        target = intel.get("target", "unknown")
        lines.append(f"Target: {target}")

        # Summarise open ports
        ports = intel.get("open_ports", [])
        if ports:
            port_list = []
            for p in ports[:15]:
                if isinstance(p, dict):
                    port_list.append(
                        f"{p.get('port','?')}/{p.get('service','?')} "
                        f"{p.get('version','')}"
                    )
            lines.append("Ports: " + ", ".join(port_list))

        # Summarise vulns
        vulns = intel.get("vulnerabilities", [])
        if vulns:
            lines.append(f"Vulnerabilities: {len(vulns)}")
            for v in vulns[:4]:
                if isinstance(v, dict):
                    lines.append(f"  [{v.get('severity','?')}] {v.get('title','')[:50]}")

        # Shell status
        if intel.get("shell_access"):
            lines.append(f"Shell: YES (user={intel.get('current_user','?')})")
        else:
            lines.append("Shell: NO")

        # Top hypotheses
        if hypotheses:
            lines.append("")
            lines.append("=== TOP HYPOTHESES ===")
            for h in hypotheses[:3]:
                lines.append(
                    f"  [{h.confidence:.2f}] {h.statement[:70]}"
                )

        # Negative memory
        neg = negative_memory.to_context_block()
        if neg:
            lines += ["", neg]

        lines += [
            "",
            f"Generate up to {self._MAX_PATHS} ranked attack paths.",
            "Each path should have 2-{} steps (nodes).".format(self._MAX_NODES_PER_PATH),
            "",
            "Respond in EXACTLY this JSON format:",
            "{",
            '  "attack_paths": [',
            '    {',
            '      "description": "Path description — entry point to objective",',
            '      "entry_point": "service or technique used to start",',
            '      "objective": "foothold|root|domain_admin|data_exfil",',
            '      "estimated_effort": "low|medium|high",',
            '      "path_confidence": 0.75,',
            '      "nodes": [',
            '        {',
            '          "finding": "Specific observable that enables this step",',
            '          "likelihood": 0.8,',
            '          "impact": 0.7,',
            '          "ease": 0.9,',
            '          "tools": ["tool1", "tool2"],',
            '          "expected_outcome": "What happens if this step succeeds",',
            '          "risk": "low|medium|high|critical",',
            '          "preconditions": ["what must be true before this step"],',
            '          "mitre_technique": "T1190"',
            '        }',
            '      ]',
            '    }',
            '  ]',
            "}",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_paths(self, raw: Any) -> List[RankedAttackPath]:
        """Parse LLM response into RankedAttackPath objects."""
        paths: List[RankedAttackPath] = []

        if not raw or not isinstance(raw, dict):
            return paths

        items = raw.get("attack_paths", raw.get("paths", []))
        if not isinstance(items, list):
            return paths

        for item in items:
            if not isinstance(item, dict):
                continue

            nodes_raw = item.get("nodes", [])
            if not isinstance(nodes_raw, list):
                nodes_raw = []

            nodes = []
            for nr in nodes_raw:
                if not isinstance(nr, dict):
                    continue
                try:
                    likelihood = max(0.0, min(1.0, float(nr.get("likelihood", 0.5))))
                    impact     = max(0.0, min(1.0, float(nr.get("impact", 0.5))))
                    ease       = max(0.0, min(1.0, float(nr.get("ease", 0.5))))
                except (TypeError, ValueError):
                    likelihood, impact, ease = 0.5, 0.5, 0.5

                node = AttackPathNode(
                    node_id          = str(uuid.uuid4()),
                    finding          = str(nr.get("finding", "")),
                    confidence       = likelihood,
                    likelihood       = likelihood,
                    impact           = impact,
                    ease             = ease,
                    preconditions    = [str(p) for p in (nr.get("preconditions") or [])],
                    tools            = [str(t) for t in (nr.get("tools") or [])],
                    expected_outcome = str(nr.get("expected_outcome", "")),
                    risk             = str(nr.get("risk", "medium")),
                    mitre_technique  = nr.get("mitre_technique"),
                )
                nodes.append(node)

            if not nodes:
                continue

            try:
                path_conf = max(0.0, min(1.0, float(item.get("path_confidence", 0.5))))
            except (TypeError, ValueError):
                path_conf = 0.5

            path = RankedAttackPath(
                path_id          = str(uuid.uuid4()),
                nodes            = nodes,
                description      = str(item.get("description", "")),
                entry_point      = str(item.get("entry_point", "")),
                objective        = str(item.get("objective", "foothold")),
                estimated_effort = str(item.get("estimated_effort", "medium")),
                path_confidence  = path_conf,
            )
            path.recompute_score()
            paths.append(path)

        return paths
