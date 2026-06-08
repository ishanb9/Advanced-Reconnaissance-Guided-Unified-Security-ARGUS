"""
agents.operator — the persistent operator-agent core.

This package inverts ARGUS's control flow: instead of a rigid phase pipeline
that demotes the LLM to a finding-extractor, a single long-lived ReAct agent
(OperatorCore) owns the engagement end-to-end with ONE accumulating transcript
and the full ARGUS toolbelt.  Phases / subagents / playbooks become callable
services the operator invokes when it decides to — not the control flow.

Modules:
  http_session  — stateful HTTP session (cookie jar, CSRF, auth, vhost Host
                  override): the authenticated, multi-request web interaction
                  capability ARGUS lacked.
  tool_catalog  — declarative toolbelt + system-prompt builder (incl. the
                  text-ReAct action protocol and the authorized-lab framing
                  that keeps aligned models from refusing).
  operator_core — the ReAct loop: transcript → converse() → parse action →
                  approve-gate (if intrusive) → dispatch → observe → compact.
"""

from .http_session import HttpSession   # noqa: F401

__all__ = ["HttpSession"]
