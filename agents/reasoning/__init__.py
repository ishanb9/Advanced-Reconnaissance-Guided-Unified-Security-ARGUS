"""
agents/reasoning — Hypothesis-driven reasoning engine for ARGUS.

Components:
  NegativeMemory    — tracks failed attempts, prevents looping
  HypothesisEngine  — converts evidence into ranked hypotheses
  AttackPlanner     — scores attack paths by Likelihood × Impact × Ease
  DecisionEngine    — selects next justified action with confidence gate
  ReasoningLoop     — Observe→Interpret→Hypothesize→Prioritize→Execute→Validate→Update

Activation: enabled via use_reasoning_loop=True in StartPentestRequest.
When disabled (default), MasterAgent runs the legacy linear phase flow unchanged.
"""

from agents.reasoning.negative_memory   import NegativeMemory, FailedAttempt
from agents.reasoning.hypothesis_engine import HypothesisEngine, Hypothesis
from agents.reasoning.attack_planner    import AttackPlanner, RankedAttackPath, AttackPathNode
from agents.reasoning.decision_engine   import DecisionEngine, JustifiedAction, PreExecutionPlan
from agents.reasoning.reasoning_loop    import ReasoningLoop

__all__ = [
    "NegativeMemory", "FailedAttempt",
    "HypothesisEngine", "Hypothesis",
    "AttackPlanner", "RankedAttackPath", "AttackPathNode",
    "DecisionEngine", "JustifiedAction", "PreExecutionPlan",
    "ReasoningLoop",
]
