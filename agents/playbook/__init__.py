"""ARGUS playbook subsystem.

Playbooks are deterministic action chains triggered by recon findings.
They replace the LLM-from-scratch planning loop for known service
patterns, collapsing "8 minutes of master thinking" -> "200ms YAML
trigger match + execute" and keeping the LLM free for novel surface.

Public API:
    from agents.playbook.engine import PlaybookEngine, get_engine

    engine = get_engine()           # singleton, loads YAMLs once
    matches = engine.match(intel)   # -> list of (Playbook, trigger_score)
    findings = await engine.run(playbook, target, kb=kb)

See agents/playbook/engine.py for the full schema.
"""
from agents.playbook.engine import PlaybookEngine, Playbook, get_engine  # noqa: F401

__all__ = ["PlaybookEngine", "Playbook", "get_engine"]
