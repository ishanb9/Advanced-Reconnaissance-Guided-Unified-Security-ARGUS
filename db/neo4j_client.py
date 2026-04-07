"""
db/neo4j_client.py — Async Neo4j graph database client for ARGUS

Stores the semantic attack graph: typed nodes and typed relationships inferred
from tool output, giving richer path-finding and relationship queries beyond
what MongoDB's flat attack_graph collection can provide.

Node labels:
    Host, Service, Port, Vulnerability, CVE, Credential, User,
    Share, Exploit, Access, Finding

Relationship types:
    EXPOSES, RUNS, VULNERABLE_TO, LEADS_TO, REFERENCES,
    EXPLOITABLE_WITH, HAS_CREDENTIAL, COMPROMISED_VIA,
    ESCALATES_TO, PIVOTS_TO, AFFECTS

Configuration (environment variables — all optional):
    NEO4J_URI      default: bolt://localhost:7687
    NEO4J_USER     default: neo4j
    NEO4J_PASSWORD default: argus123

Neo4j is an OPTIONAL dependency — if it is not running or the driver is not
installed, all calls silently no-op so the rest of ARGUS is unaffected.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("neo4j_client")

NEO4J_URI      = os.environ.get("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.environ.get("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "argus123")

# ── lazy async driver singleton ─────────────────────────────────────────────
_driver = None
_available: Optional[bool] = None   # None = untested


def _get_driver():
    global _driver, _available
    if _available is False:
        return None
    if _driver is not None:
        return _driver
    try:
        from neo4j import AsyncGraphDatabase  # type: ignore
        _driver = AsyncGraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
        )
        _available = True
        logger.info(f"Neo4j driver ready: {NEO4J_URI}")
        return _driver
    except Exception as exc:
        _available = False
        logger.warning(f"Neo4j not available ({exc}) — graph features disabled")
        return None


# ── helpers ─────────────────────────────────────────────────────────────────

async def _run(cypher: str, params: Dict = None):
    """Execute a Cypher statement; returns list of record dicts or []."""
    driver = _get_driver()
    if driver is None:
        return []
    try:
        async with driver.session() as session:
            result = await session.run(cypher, parameters=params or {})
            return [dict(r) async for r in result]
    except Exception as exc:
        logger.debug(f"Neo4j query error: {exc}")
        return []


async def ping() -> bool:
    """Return True if Neo4j is reachable."""
    driver = _get_driver()
    if driver is None:
        return False
    try:
        await driver.verify_connectivity()
        return True
    except Exception:
        return False


# ── schema / constraints ────────────────────────────────────────────────────

async def ensure_schema():
    """Create uniqueness constraints and indexes (idempotent)."""
    stmts = [
        # Node uniqueness
        "CREATE CONSTRAINT neo4j_host_uniq IF NOT EXISTS FOR (n:Host)    REQUIRE (n.session_id, n.ip)      IS UNIQUE",
        "CREATE CONSTRAINT neo4j_svc_uniq  IF NOT EXISTS FOR (n:Service) REQUIRE (n.session_id, n.node_id) IS UNIQUE",
        "CREATE CONSTRAINT neo4j_vuln_uniq IF NOT EXISTS FOR (n:Vulnerability) REQUIRE (n.session_id, n.node_id) IS UNIQUE",
        "CREATE CONSTRAINT neo4j_cve_uniq  IF NOT EXISTS FOR (n:CVE)     REQUIRE (n.cve_id)                IS UNIQUE",
        # Indexes for session-scoped queries
        "CREATE INDEX neo4j_session_idx IF NOT EXISTS FOR (n:Host)    ON (n.session_id)",
        "CREATE INDEX neo4j_svc_sess    IF NOT EXISTS FOR (n:Service) ON (n.session_id)",
    ]
    for s in stmts:
        await _run(s)


# ── node upsert ─────────────────────────────────────────────────────────────

async def upsert_node(
    session_id: str,
    node_id:    str,
    node_type:  str,   # "Host" | "Service" | "Vulnerability" | "CVE" | etc.
    label:      str,
    properties: Dict[str, Any] = None,
) -> bool:
    """
    Merge a node by (session_id, node_id).  Returns True on success.
    node_type becomes the Neo4j label (must be a valid identifier).
    """
    label_clean = _clean_label(node_type)
    props = {**(properties or {}), "node_id": node_id, "session_id": session_id, "label": label}
    cypher = (
        f"MERGE (n:{label_clean} {{session_id: $sid, node_id: $nid}}) "
        "SET n += $props"
    )
    await _run(cypher, {"sid": session_id, "nid": node_id, "props": props})
    return True


async def upsert_edge(
    session_id:    str,
    source_id:     str,
    target_id:     str,
    rel_type:      str,   # "VULNERABLE_TO" | "LEADS_TO" | etc.
    properties:    Dict[str, Any] = None,
) -> bool:
    """
    Merge a typed relationship between two nodes (matched by session_id + node_id).
    Creates stub nodes if they don't exist yet so the edge is never lost.
    """
    rel_clean = _clean_rel(rel_type)
    props = {**(properties or {}), "session_id": session_id}
    cypher = (
        "MATCH (a {session_id: $sid, node_id: $src}) "
        "MATCH (b {session_id: $sid, node_id: $tgt}) "
        f"MERGE (a)-[r:{rel_clean}]->(b) "
        "SET r += $props"
    )
    await _run(cypher, {"sid": session_id, "src": source_id, "tgt": target_id, "props": props})
    return True


# ── query helpers ────────────────────────────────────────────────────────────

async def get_graph(session_id: str) -> Dict[str, List]:
    """
    Return all nodes and relationships for a session as
    {"nodes": [...], "edges": [...]}.
    """
    nodes_raw = await _run(
        "MATCH (n {session_id: $sid}) "
        "RETURN labels(n)[0] AS node_type, properties(n) AS props",
        {"sid": session_id},
    )
    edges_raw = await _run(
        "MATCH (a {session_id: $sid})-[r]->(b {session_id: $sid}) "
        "RETURN a.node_id AS source, b.node_id AS target, "
        "       type(r) AS rel_type, properties(r) AS props",
        {"sid": session_id},
    )
    nodes = [{"node_type": r["node_type"], **r["props"]} for r in nodes_raw]
    edges = [
        {
            "source":   r["source"],
            "target":   r["target"],
            "rel_type": r["rel_type"],
            **r["props"],
        }
        for r in edges_raw
    ]
    return {"nodes": nodes, "edges": edges}


async def get_attack_paths(
    session_id: str,
    from_type:  str = "Host",
    to_type:    str = "Access",
    max_depth:  int = 10,
) -> List[Dict]:
    """
    Find all shortest paths between Host nodes and Access/compromise nodes.
    Returns a list of path dicts: {"length": N, "nodes": [...], "rels": [...]}.
    """
    cypher = (
        f"MATCH p=shortestPath((a:{from_type} {{session_id: $sid}})"
        f"-[*1..{max_depth}]-(b:{to_type} {{session_id: $sid}})) "
        "RETURN [n IN nodes(p) | {node_id: n.node_id, label: n.label, "
        "         node_type: labels(n)[0]}] AS path_nodes, "
        "       [r IN relationships(p) | type(r)] AS path_rels, "
        "       length(p) AS path_length "
        "ORDER BY path_length"
    )
    raw = await _run(cypher, {"sid": session_id})
    return [
        {
            "length": r["path_length"],
            "nodes":  r["path_nodes"],
            "rels":   r["path_rels"],
        }
        for r in raw
    ]


async def delete_session_graph(session_id: str):
    """Remove all nodes and relationships for a session (called on session delete)."""
    await _run(
        "MATCH (n {session_id: $sid}) DETACH DELETE n",
        {"sid": session_id},
    )


# ── internal sanitisers ─────────────────────────────────────────────────────

def _clean_label(raw: str) -> str:
    """Convert a node_type string to a valid Neo4j label (PascalCase, alphanum)."""
    import re
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", str(raw or "Node"))
    # Capitalize first char
    return cleaned[0].upper() + cleaned[1:] if cleaned else "Node"


def _clean_rel(raw: str) -> str:
    """Convert a relationship string to a valid Neo4j relationship type (UPPER_SNAKE)."""
    import re
    return re.sub(r"[^a-zA-Z0-9_]", "_", str(raw or "RELATED").upper())


# ── teardown ────────────────────────────────────────────────────────────────

async def close():
    global _driver
    if _driver:
        await _driver.close()
        _driver = None
