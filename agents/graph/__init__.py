"""agents/graph — ADDITIVE, FLAG-GATED graph control plane (strangler fig).

The existing loop engine (agents/reasoning/reasoning_loop.py) remains the DEFAULT and
is untouched.  This package runs only when ARGUS_GRAPH_ENGINE=1, and any engine-level
failure inside it degrades that host back to the loop engine (loudly, once, latched).

Public surface kept intentionally small so importing this package is cheap and safe.
"""
from agents.graph.state import (EngagementState, HostState, ToolCallRecord,
                                EvidenceRecord, FindingRecord, Budgets,
                                STATE_SCHEMA_VERSION, call_key)
from agents.graph.runtime import (GraphSpec, NodeSpec, GraphRunner, TERMINAL,
                                  NodeFailure, EngineFailure, GraphValidationError,
                                  validate_graph, render_edges,
                                  InMemoryCheckpointer, MongoCheckpointer)
from agents.graph.nodes import NodeContext, make_nodes
from agents.graph.engine import (GraphEngine, RollbackPolicy, RollbackOutcome,
                                 build_graph, graph_engine_enabled, kill_switch_engaged,
                                 make_engagement_state, state_to_intel,
                                 apply_handoff_to_master)

__all__ = [
    "EngagementState", "HostState", "ToolCallRecord", "EvidenceRecord", "FindingRecord",
    "Budgets", "STATE_SCHEMA_VERSION", "call_key",
    "GraphSpec", "NodeSpec", "GraphRunner", "TERMINAL", "NodeFailure", "EngineFailure",
    "GraphValidationError", "validate_graph", "render_edges",
    "InMemoryCheckpointer", "MongoCheckpointer",
    "NodeContext", "make_nodes",
    "GraphEngine", "RollbackPolicy", "RollbackOutcome", "build_graph",
    "graph_engine_enabled", "kill_switch_engaged", "make_engagement_state",
    "state_to_intel", "apply_handoff_to_master",
]
