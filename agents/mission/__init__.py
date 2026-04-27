"""agents.mission — mission-level oversight (formal brief + win-condition tracking)."""
from agents.mission.win_conditions import (
    WinConditionTracker,
    BUILTIN_EVALUATORS,
    evaluate_expression,
)

__all__ = ["WinConditionTracker", "BUILTIN_EVALUATORS", "evaluate_expression"]
