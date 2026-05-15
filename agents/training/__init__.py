"""Self-training utilities for ARGUS — corpus assembly + outcome scoring."""
from agents.training.dataset_builder import (    # noqa: F401
    build_training_set, OutcomeLabel,
)

__all__ = ["build_training_set", "OutcomeLabel"]
