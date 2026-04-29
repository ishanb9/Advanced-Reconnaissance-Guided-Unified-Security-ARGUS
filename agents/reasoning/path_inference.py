"""Neo4j-driven attack-path inference (Improvement #10).

The platform already writes the live attack graph to Neo4j (host nodes,
service nodes, vulnerability nodes, edges like ``RUNS``, ``VULNERABLE_TO``,
``LEADS_TO``, ``COMPROMISED_BY``).  Without inference, that graph is just a
visualisation — the planner re-improvises a route every iteration.

This module *queries* the graph each iteration and computes weighted
shortest paths from the current foothold (target host / compromised host)
to each active goal node (UserFlag, RootShell, DomainAdmin, ScopeTarget,
…).  The paths are stored on ``intel['inferred_paths']`` and rendered into
``_intel_summary`` so every existing LLM phase planner sees a concrete
end-to-end plan, not just a list of facts.

Implementation notes
--------------------
*   We pull the session subgraph once via
    :func:`db.neo4j_client.fetch_subgraph_for_inference` and run Dijkstra
    in Python.  A typical session has dozens of nodes — well within
    pure-Python territory and keeps us free of GDS/APOC dependencies.
*   Edge cost defaults to 1.0; subagents that know their action is risky
    or noisy can set ``cost`` higher when upserting an edge.
*   The reliability of a path is the product of edge confidences (0..1).
    Total path score = (1 - confidence_product) + total_cost — the planner
    then breaks ties on path length.
"""

from __future__ import annotations

import heapq
import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


logger = logging.getLogger(__name__)


__all__ = [
    "derive_goal_node_ids",
    "derive_foothold_node_ids",
    "dijkstra_paths",
    "summarise_paths",
    "render_paths_for_prompt",
    "GOAL_TYPES",
    "FOOTHOLD_TYPES",
]


# Node types we treat as goal sinks (override / extend per session)
GOAL_TYPES: Tuple[str, ...] = (
    "Goal", "Flag", "UserFlag", "RootFlag",
    "DomainAdmin", "RootShell", "Crown",
)

# Node types we treat as foothold sources
FOOTHOLD_TYPES: Tuple[str, ...] = (
    "Host", "Foothold", "Compromised", "Shell",
)


def derive_goal_node_ids(
    nodes:        Sequence[Dict[str, Any]],
    *,
    intel:        Dict[str, Any] = None,
) -> List[str]:
    """Pick goal nodes from the subgraph.

    Strategy: any node whose ``node_type`` is in :data:`GOAL_TYPES`, OR
    whose label/props mark it as an objective.  If none exist, fall back
    to nodes whose label contains a flag-style keyword.
    """
    intel = intel or {}
    goals: List[str] = []
    seen: Set[str] = set()

    keyword_hits = ("flag", "domain admin", "root", "system", "administrator")

    for n in nodes or []:
        nt = (n.get("node_type") or "").strip()
        nid = n.get("node_id")
        if not nid:
            continue
        label = (n.get("label") or "").lower()
        props = n.get("props") or {}
        is_goal = (
            nt in GOAL_TYPES
            or props.get("is_goal") is True
            or props.get("role") == "goal"
            or any(k in label for k in keyword_hits)
        )
        if is_goal and nid not in seen:
            seen.add(nid)
            goals.append(nid)
    return goals


def derive_foothold_node_ids(
    nodes:        Sequence[Dict[str, Any]],
    *,
    intel:        Dict[str, Any] = None,
) -> List[str]:
    """Pick starting foothold nodes from the subgraph.

    Preference order:
      1. Nodes flagged as compromised / shell (any node with role=compromised
         or node_type=Shell/Foothold/Compromised).
      2. Host nodes whose ``label`` matches the current target.
      3. All Host nodes (so we still get a path even pre-foothold).
    """
    intel = intel or {}
    target = (intel.get("target") or "").lower()
    nodes = list(nodes or [])

    compromised: List[str] = []
    target_hosts: List[str] = []
    all_hosts: List[str] = []

    for n in nodes:
        nid = n.get("node_id")
        if not nid:
            continue
        nt = (n.get("node_type") or "").strip()
        props = n.get("props") or {}
        label = (n.get("label") or "").lower()
        if (nt in ("Shell", "Foothold", "Compromised")
                or props.get("compromised") is True
                or props.get("role") == "compromised"):
            compromised.append(nid)
        if nt == "Host":
            all_hosts.append(nid)
            if target and target in label:
                target_hosts.append(nid)

    if compromised:
        return compromised
    if target_hosts:
        return target_hosts
    return all_hosts


def dijkstra_paths(
    nodes:    Sequence[Dict[str, Any]],
    edges:    Sequence[Dict[str, Any]],
    sources:  Iterable[str],
    sinks:    Iterable[str],
    *,
    bidirectional: bool = True,
    max_paths:     int = 5,
) -> List[Dict[str, Any]]:
    """Compute shortest weighted paths from ``sources`` to ``sinks``.

    Returns a list of path dicts sorted by total cost ascending::

        {
          "src": <node_id>,
          "dst": <node_id>,
          "cost": <float>,
          "confidence": <float>,        # product of edge confidences
          "nodes": [<node_id>, ...],
          "rels":  [<rel_type>, ...],
        }
    """
    sources = [s for s in sources if s]
    sinks = set(s for s in sinks if s)
    if not sources or not sinks:
        return []

    # Build adjacency  node_id -> [(neighbour, cost, confidence, rel_type), ...]
    adj: Dict[str, List[Tuple[str, float, float, str]]] = {}
    node_ids = {n.get("node_id") for n in nodes if n.get("node_id")}
    for e in edges:
        s, t = e.get("src"), e.get("tgt")
        if s not in node_ids or t not in node_ids:
            continue
        cost = float(e.get("cost") or 1.0)
        conf = float(e.get("confidence") or 0.5)
        rel  = str(e.get("rel_type") or "")
        adj.setdefault(s, []).append((t, cost, conf, rel))
        if bidirectional:
            adj.setdefault(t, []).append((s, cost, conf, rel))

    paths: List[Dict[str, Any]] = []
    for src in sources:
        if src not in node_ids:
            continue
        # Standard Dijkstra from src
        dist:    Dict[str, float] = {src: 0.0}
        prev:    Dict[str, Tuple[str, str, float]] = {}   # node -> (prev_node, rel_type, conf)
        pq: List[Tuple[float, str]] = [(0.0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, float("inf")):
                continue
            for v, cost, conf, rel in adj.get(u, []):
                nd = d + cost
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = (u, rel, conf)
                    heapq.heappush(pq, (nd, v))

        for sink in sinks:
            if sink not in dist or sink == src:
                continue
            # Reconstruct path
            chain: List[str]   = [sink]
            rels:  List[str]   = []
            confs: List[float] = []
            cur = sink
            while cur in prev:
                pnode, rel, c = prev[cur]
                chain.append(pnode)
                rels.append(rel)
                confs.append(c)
                cur = pnode
            chain.reverse()
            rels.reverse()
            confs.reverse()
            confidence = 1.0
            for c in confs:
                confidence *= max(0.0, min(1.0, c))
            paths.append({
                "src":        src,
                "dst":        sink,
                "cost":       round(dist[sink], 4),
                "confidence": round(confidence, 4),
                "nodes":      chain,
                "rels":       rels,
            })

    paths.sort(key=lambda p: (p["cost"], -p["confidence"], len(p["nodes"])))
    return paths[:max_paths]


def summarise_paths(
    paths:    Sequence[Dict[str, Any]],
    nodes:    Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Decorate raw path dicts with human-readable node labels."""
    by_id = {n.get("node_id"): n for n in nodes if n.get("node_id")}
    out = []
    for p in paths:
        decorated_nodes = []
        for nid in p["nodes"]:
            n = by_id.get(nid) or {}
            decorated_nodes.append({
                "node_id":   nid,
                "node_type": n.get("node_type") or "",
                "label":     n.get("label") or nid,
            })
        out.append({**p, "nodes_decorated": decorated_nodes})
    return out


def render_paths_for_prompt(
    summarised_paths: Sequence[Dict[str, Any]],
    *,
    max_paths: int = 3,
) -> str:
    """Render inferred paths into a compact prompt block."""
    if not summarised_paths:
        return ""
    lines = ["=== NEO4J-INFERRED ATTACK PATHS (cheapest first) ==="]
    for i, p in enumerate(summarised_paths[:max_paths], 1):
        chain = " → ".join(
            f"{n.get('label') or n.get('node_id')}"
            f"({n.get('node_type','?')})"
            for n in p.get("nodes_decorated", [])
        )
        rels = " · ".join(p.get("rels", [])) or "-"
        lines.append(
            f"  [{i}] cost={p['cost']:.2f} conf={p['confidence']:.2f} "
            f"len={len(p['nodes'])-1}"
        )
        lines.append(f"      {chain}")
        lines.append(f"      via: {rels}")
    lines.append(
        "Drive scans/exploits along these paths; only deviate when "
        "evidence contradicts a path's edge."
    )
    return "\n".join(lines)
