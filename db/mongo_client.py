"""
ARGUS Pentest Platform — MongoDB Client
All database operations. Uses Motor (async MongoDB driver).

Collections (operational):
  sessions, findings, tool_outputs, agent_logs,
  shell_sessions, flags, attack_graph_nodes,
  attack_graph_edges, osint_results, credentials,
  subagent_results, persistence, session_checkpoints,
  session_archives

MongoDB must be running: sudo systemctl start mongod
Default: mongodb://localhost:27017/argus_pentest
"""

import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from bson.errors import InvalidId
import motor.motor_asyncio
from pymongo import ASCENDING, DESCENDING, IndexModel

from db.schemas import (
    AttackPhase, AgentName, AgentStatus, FindingSeverity,
    SessionStatus, SessionCreate
)

# ─── Connection ────────────────────────────────────────────

MONGO_URI = "mongodb://localhost:27017"
DB_NAME   = "argus_pentest"

# Motor async client (initialized in setup())
_client:      Optional[motor.motor_asyncio.AsyncIOMotorClient]  = None
_db:          Optional[motor.motor_asyncio.AsyncIOMotorDatabase] = None
_db_instance: Optional[motor.motor_asyncio.AsyncIOMotorDatabase] = None  # Phase 3 alias


def get_db() -> motor.motor_asyncio.AsyncIOMotorDatabase:
    """Return database handle. Must call setup() first."""
    if _db is None:
        raise RuntimeError("MongoDB not initialized. Call await setup() first.")
    return _db


async def setup(uri: str = MONGO_URI, db_name: str = DB_NAME):
    """Initialize MongoDB connection and create indexes."""
    global _client, _db, _db_instance
    _client      = motor.motor_asyncio.AsyncIOMotorClient(uri)
    _db          = _client[db_name]
    _db_instance = _db  # Phase 3 alias
    await _create_indexes()
    print(f"[DB] Connected to MongoDB: {uri}/{db_name}")


async def teardown():
    """Close MongoDB connection."""
    global _client, _db, _db_instance
    if _client:
        _client.close()
        _db = None
        _db_instance = None
        print("[DB] MongoDB connection closed.")


async def _create_indexes():
    """
    Create all indexes for efficient queries.

    Naming conventions:
      - Every operational collection has (session_id, host) compound index
        for fast per-IP isolation in multi-host scans.
      - TTL indexes auto-expire stale documents; partial filters keep
        only auto-checkpoints under TTL so manual ones survive forever.
      - schema_version indexes let callers target documents with specific
        newer fields without scanning the whole collection.
    """
    db = get_db()

    # ── sessions ────────────────────────────────────────────────────────────
    await db.sessions.create_index([("status", ASCENDING)])
    await db.sessions.create_index([("started_at", DESCENDING)])
    await db.sessions.create_index([("archived", ASCENDING), ("started_at", DESCENDING)])

    # ── findings ────────────────────────────────────────────────────────────
    # Covering index: all three filter fields in one compound index
    await db.findings.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING), ("severity", ASCENDING)]
    )
    await db.findings.create_index([("session_id", ASCENDING), ("phase", ASCENDING)])
    await db.findings.create_index([("session_id", ASCENDING), ("agent", ASCENDING)])
    await db.findings.create_index([("session_id", ASCENDING), ("subagent", ASCENDING)])
    await db.findings.create_index([("cves", ASCENDING)])
    await db.findings.create_index([("finding_id", ASCENDING)], sparse=True)

    # ── tool_outputs ────────────────────────────────────────────────────────
    await db.tool_outputs.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING), ("started_at", DESCENDING)]
    )
    await db.tool_outputs.create_index([("session_id", ASCENDING), ("agent", ASCENDING)])
    # backward-compat index on legacy `target` field
    await db.tool_outputs.create_index([("session_id", ASCENDING), ("target", ASCENDING)])
    # TTL — purge tool output records older than 180 days
    await db.tool_outputs.create_index(
        [("created_at", ASCENDING)],
        expireAfterSeconds=180 * 24 * 3600,
        name="tool_outputs_ttl_180d"
    )

    # ── agent_logs ──────────────────────────────────────────────────────────
    await db.agent_logs.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING), ("timestamp", DESCENDING)]
    )
    await db.agent_logs.create_index([("session_id", ASCENDING), ("agent", ASCENDING)])
    await db.agent_logs.create_index([("session_id", ASCENDING), ("log_level", ASCENDING)])
    # TTL — purge agent logs older than 90 days
    await db.agent_logs.create_index(
        [("created_at", ASCENDING)],
        expireAfterSeconds=90 * 24 * 3600,
        name="agent_logs_ttl_90d"
    )

    # ── shell_sessions ──────────────────────────────────────────────────────
    await db.shell_sessions.create_index([("session_id", ASCENDING), ("active", ASCENDING)])
    await db.shell_sessions.create_index([("session_id", ASCENDING), ("rhost", ASCENDING)])

    # ── flags ───────────────────────────────────────────────────────────────
    await db.flags.create_index([("session_id", ASCENDING), ("host", ASCENDING)])

    # ── attack graph ────────────────────────────────────────────────────────
    await db.attack_graph_nodes.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING)]
    )
    await db.attack_graph_edges.create_index([("session_id", ASCENDING)])

    # ── osint_results ───────────────────────────────────────────────────────
    await db.osint_results.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING), ("relevance_score", DESCENDING)]
    )

    # ── payloads ────────────────────────────────────────────────────────────
    await db.payloads.create_index([("session_id", ASCENDING)])
    await db.payloads.create_index([("generated_at", DESCENDING)])

    # ── attack_tree ─────────────────────────────────────────────────────────
    await db.attack_tree.create_index([("session_id", ASCENDING), ("created_at", DESCENDING)])

    # ── long_term_memory ────────────────────────────────────────────────────
    await db.long_term_memory.create_index([("target_type", ASCENDING)])
    await db.long_term_memory.create_index([("tags", ASCENDING)])
    await db.long_term_memory.create_index([("created_at", DESCENDING)])

    # ── evidence ────────────────────────────────────────────────────────────
    await db.evidence.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING), ("phase", ASCENDING)]
    )
    await db.evidence.create_index([("session_id", ASCENDING), ("evidence_type", ASCENDING)])

    # ── mitre_mappings ──────────────────────────────────────────────────────
    await db.mitre_mappings.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING)]
    )

    # ── credentials ─────────────────────────────────────────────────────────
    await db.credentials.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING), ("service", ASCENDING)]
    )
    await db.credentials.create_index([("session_id", ASCENDING), ("verified", ASCENDING)])

    # ── tunnels ─────────────────────────────────────────────────────────────
    await db.tunnels.create_index([("session_id", ASCENDING), ("active", ASCENDING)])

    # ── persistence ─────────────────────────────────────────────────────────
    await db.persistence.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING)]
    )

    # ── subagent_results ────────────────────────────────────────────────────
    await db.subagent_results.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING), ("agent", ASCENDING)]
    )
    await db.subagent_results.create_index(
        [("session_id", ASCENDING), ("subagent_name", ASCENDING)]
    )

    # ── rag_history ─────────────────────────────────────────────────────────
    await db.rag_history.create_index([("session_id", ASCENDING), ("timestamp", DESCENDING)])
    # TTL — purge RAG history older than 30 days
    await db.rag_history.create_index(
        [("timestamp", ASCENDING)],
        expireAfterSeconds=30 * 24 * 3600,
        name="rag_history_ttl_30d"
    )

    # ── attack_chains ───────────────────────────────────────────────────────
    await db.attack_chains.create_index([("session_id", ASCENDING)])

    # ── session_checkpoints ─────────────────────────────────────────────────
    await db.session_checkpoints.create_index(
        [("session_id", ASCENDING), ("created_at", DESCENDING)]
    )
    await db.session_checkpoints.create_index(
        [("session_id", ASCENDING), ("checkpoint_type", ASCENDING)]
    )
    # TTL — auto-checkpoints expire after 30 days; manual checkpoints kept indefinitely
    await db.session_checkpoints.create_index(
        [("created_at", ASCENDING)],
        expireAfterSeconds=30 * 24 * 3600,
        partialFilterExpression={"checkpoint_type": "auto"},
        name="session_checkpoints_auto_ttl_30d"
    )

    # ── session_archives ────────────────────────────────────────────────────
    await db.session_archives.create_index([("session_id", ASCENDING)], unique=True)
    await db.session_archives.create_index([("archived_at", DESCENDING)])

    # ── hypotheses (reasoning engine) ───────────────────────────────────────
    await db.hypotheses.create_index(
        [("session_id", ASCENDING), ("host", ASCENDING), ("confidence", DESCENDING)]
    )
    await db.hypotheses.create_index(
        [("session_id", ASCENDING), ("hypothesis_id", ASCENDING)], unique=True
    )

    # ── negative_memory (reasoning engine) ──────────────────────────────────
    await db.negative_memory.create_index(
        [("session_id", ASCENDING), ("tool", ASCENDING), ("target_service", ASCENDING)],
        unique=True,
        name="neg_mem_unique_attempt"
    )

    # ── action_scores (reasoning engine) ────────────────────────────────────
    await db.action_scores.create_index(
        [("session_id", ASCENDING), ("created_at", DESCENDING)]
    )

    # ── ranked_paths (reasoning engine) ─────────────────────────────────────
    await db.ranked_paths.create_index(
        [("session_id", ASCENDING), ("iteration", DESCENDING)]
    )

    # ── agent_logs_realtime (capped ring-buffer for sync-gate diagnostics) ──
    # Create only if it doesn't already exist — capped collections cannot be
    # converted after creation, so we guard with a try/except.
    try:
        existing = await db.list_collection_names()
        if "agent_logs_realtime" not in existing:
            await db.create_collection(
                "agent_logs_realtime",
                capped=True,
                size=100 * 1024 * 1024,   # 100 MB ring buffer
                max=500_000
            )
            await db.agent_logs_realtime.create_index(
                [("session_id", ASCENDING), ("timestamp", DESCENDING)]
            )
    except Exception:
        pass  # collection already exists or MongoDB doesn't support capped here

    print("[DB] Indexes created.")


def _oid() -> str:
    """Generate a new MongoDB ObjectId as string."""
    return str(ObjectId())


def _serialize(doc: Dict) -> Dict:
    """Convert MongoDB _id to string id for JSON serialization."""
    if doc is None:
        return None
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    # Convert any nested ObjectId
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            doc[k] = str(v)
        elif isinstance(v, datetime):
            iso = v.isoformat()
            # Naive datetimes (datetime.utcnow()) have no tzinfo — append Z so
            # JavaScript parses them as UTC rather than local time.
            if v.tzinfo is None:
                iso += 'Z'
            doc[k] = iso
    return doc


def _serialize_list(docs) -> List[Dict]:
    return [_serialize(d) for d in docs if d]


# ═══════════════════════════════════════════════════════════
#  SESSIONS
# ═══════════════════════════════════════════════════════════

async def create_session(data: SessionCreate) -> Dict:
    """Create a new pentest session. Returns the created session dict."""
    db = get_db()
    doc = {
        "_id":               ObjectId(),
        "target_ip":         data.target_ip,
        "target_hostname":   data.target_hostname,
        "target_type":       data.target_type,
        "scope":             data.scope,
        "notes":             data.notes,
        "threading_enabled": data.threading_enabled,
        "max_threads":       data.max_threads,
        "status":            SessionStatus.ACTIVE,
        "current_phase":     AttackPhase.RECON,
        "phases_completed":  [],
        "started_at":        datetime.utcnow(),
        "updated_at":        datetime.utcnow(),
        "completed_at":      None,
        "findings_count":    0,
        "tools_run":         0,
        "flags_found":       [],
        # Multi-host fields
        "session_mode":      getattr(data, "session_mode", "single"),
        "max_parallel_hosts": getattr(data, "max_parallel_hosts", 5),
        "discovered_hosts":  [],
        "hosts_completed":   [],
        "host_count":        0,
        # Pause/resume
        "last_checkpoint_id": None,
        "pause_count":        0,
        # Archiving
        "archived":           False,
        "archived_at":        None,
    }
    await db.sessions.insert_one(doc)
    return _serialize(doc)


async def get_session(session_id: str) -> Optional[Dict]:
    """Get a session by ID."""
    db = get_db()
    try:
        doc = await db.sessions.find_one({"_id": ObjectId(session_id)})
        return _serialize(doc) if doc else None
    except InvalidId:
        return None


async def list_sessions(limit: int = 50) -> List[Dict]:
    """List all sessions, newest first."""
    db = get_db()
    cursor = db.sessions.find().sort("started_at", DESCENDING).limit(limit)
    return _serialize_list(await cursor.to_list(length=limit))


async def delete_session(session_id: str) -> bool:
    """
    Permanently delete a session and ALL related data:
    findings, tool outputs, agent logs, flags, attack graph nodes/edges,
    shells, payloads, and OSINT results.
    Returns True if session was found and deleted.
    """
    db = get_db()
    try:
        oid = ObjectId(session_id)
    except InvalidId:
        return False

    # Verify it exists first
    session = await db.sessions.find_one({"_id": oid})
    if not session:
        return False

    # Delete all related collections in parallel
    import asyncio
    await asyncio.gather(
        db.findings.delete_many({"session_id": session_id}),
        db.tool_outputs.delete_many({"session_id": session_id}),
        db.agent_logs.delete_many({"session_id": session_id}),
        db.agent_logs_realtime.delete_many({"session_id": session_id}),
        db.flags.delete_many({"session_id": session_id}),
        db.attack_graph_nodes.delete_many({"session_id": session_id}),
        db.attack_graph_edges.delete_many({"session_id": session_id}),
        db.shell_sessions.delete_many({"session_id": session_id}),
        db.payloads.delete_many({"session_id": session_id}),
        db.osint_results.delete_many({"session_id": session_id}),
        db.credentials.delete_many({"session_id": session_id}),
        db.persistence.delete_many({"session_id": session_id}),
        db.subagent_results.delete_many({"session_id": session_id}),
        db.session_checkpoints.delete_many({"session_id": session_id}),
        db.evidence.delete_many({"session_id": session_id}),
        db.mitre_mappings.delete_many({"session_id": session_id}),
        db.attack_tree.delete_many({"session_id": session_id}),
        db.rag_history.delete_many({"session_id": session_id}),
        db.hypotheses.delete_many({"session_id": session_id}),
        db.negative_memory.delete_many({"session_id": session_id}),
        db.action_scores.delete_many({"session_id": session_id}),
        db.ranked_paths.delete_many({"session_id": session_id}),
        return_exceptions=True  # don't fail if a collection doesn't exist
    )

    # Finally delete the session document itself
    result = await db.sessions.delete_one({"_id": oid})
    return result.deleted_count > 0


async def update_session(session_id: str, updates: Dict) -> bool:
    """Update session fields."""
    db = get_db()
    updates["updated_at"] = datetime.utcnow()
    try:
        result = await db.sessions.update_one(
            {"_id": ObjectId(session_id)},
            {"$set": updates}
        )
        return result.modified_count > 0
    except InvalidId:
        return False


async def update_session_phase(session_id: str, phase: AttackPhase) -> bool:
    """Update current attack phase and mark previous as completed."""
    db = get_db()
    session = await get_session(session_id)
    if not session:
        return False
    completed = session.get("phases_completed", [])
    prev_phase = session.get("current_phase")
    if prev_phase and prev_phase not in completed:
        completed.append(prev_phase)
    try:
        result = await db.sessions.update_one(
            {"_id": ObjectId(session_id)},
            {"$set": {
                "current_phase":    phase,
                "phases_completed": completed,
                "updated_at":       datetime.utcnow()
            }}
        )
        return result.modified_count > 0
    except InvalidId:
        return False


async def increment_session_stats(session_id: str, findings: int = 0, tools: int = 0):
    """Increment findings_count and tools_run counters."""
    db = get_db()
    inc = {}
    if findings: inc["findings_count"] = findings
    if tools:    inc["tools_run"]      = tools
    if inc:
        try:
            await db.sessions.update_one(
                {"_id": ObjectId(session_id)},
                {"$inc": inc, "$set": {"updated_at": datetime.utcnow()}}
            )
        except InvalidId:
            pass


async def add_discovered_host(session_id: str, host: str) -> None:
    """Atomically add a live host to session.discovered_hosts and increment host_count."""
    db = get_db()
    try:
        await db.sessions.update_one(
            {"_id": ObjectId(session_id)},
            {
                "$addToSet": {"discovered_hosts": host},
                "$inc":      {"host_count": 1},
                "$set":      {"updated_at": datetime.utcnow()},
            }
        )
    except InvalidId:
        pass


async def mark_host_complete(session_id: str, host: str) -> None:
    """Mark a specific host as fully tested."""
    db = get_db()
    try:
        await db.sessions.update_one(
            {"_id": ObjectId(session_id)},
            {
                "$addToSet": {"hosts_completed": host},
                "$set":      {"updated_at": datetime.utcnow()},
            }
        )
    except InvalidId:
        pass


async def get_hosts_for_session(session_id: str) -> Dict:
    """Return discovered_hosts, hosts_completed, host_count and session_mode."""
    db = get_db()
    try:
        doc = await db.sessions.find_one(
            {"_id": ObjectId(session_id)},
            {"discovered_hosts": 1, "hosts_completed": 1, "host_count": 1, "session_mode": 1}
        )
    except InvalidId:
        return {}
    if not doc:
        return {}
    return {
        "discovered_hosts": doc.get("discovered_hosts", []),
        "hosts_completed":  doc.get("hosts_completed", []),
        "host_count":       doc.get("host_count", 0),
        "session_mode":     doc.get("session_mode", "single"),
    }


async def add_flag_to_session(session_id: str, flag_value: str):
    """Append flag to session's flags_found list."""
    db = get_db()
    try:
        await db.sessions.update_one(
            {"_id": ObjectId(session_id)},
            {"$addToSet": {"flags_found": flag_value},
             "$set": {"updated_at": datetime.utcnow()}}
        )
    except InvalidId:
        pass


# ═══════════════════════════════════════════════════════════
#  FINDINGS
# ═══════════════════════════════════════════════════════════

async def store_finding(
    session_id:  str,
    agent:       AgentName,
    phase:       AttackPhase,
    severity:    FindingSeverity,
    title:       str,
    description: str,
    host:        str,
    port:        Optional[int]  = None,
    service:     Optional[str]  = None,
    cves:        List[str]      = None,
    exploits:    List[str]      = None,
    tool_used:   Optional[str]  = None,
    raw_output:  Optional[str]  = None,
    extra:       Dict           = None
) -> Dict:
    """Store a new finding. Returns created document."""
    db = get_db()
    doc = {
        "_id":         ObjectId(),
        "session_id":  session_id,
        "agent":       agent,
        "phase":       phase,
        "severity":    severity,
        "title":       title,
        "description": description,
        "host":        host,
        "port":        port,
        "service":     service,
        "protocol":    None,
        "cves":        cves or [],
        "exploits":    exploits or [],
        "tool_used":   tool_used,
        "raw_output":  raw_output,
        "screenshot":  None,
        "remediation": None,
        "found_at":    datetime.utcnow(),
        "verified":    False,
        "extra":       extra or {}
    }
    await db.findings.insert_one(doc)
    # Update session counter
    await increment_session_stats(session_id, findings=1)
    return _serialize(doc)


async def get_findings(
    session_id: str,
    severity:   Optional[str] = None,
    phase:      Optional[str] = None,
    host:       Optional[str] = None,
    limit:      int = 1000,
    skip:       int = 0,
) -> List[Dict]:
    """Get findings for a session with optional pagination (skip/limit)."""
    db = get_db()
    query = {"session_id": session_id}
    if severity: query["severity"] = severity
    if phase:    query["phase"]    = phase
    if host:     query["host"]     = host
    cursor = db.findings.find(query).sort("found_at", DESCENDING).skip(skip).limit(limit)
    return _serialize_list(await cursor.to_list(length=limit))


async def get_findings_count(
    session_id: str,
    severity:   Optional[str] = None,
    phase:      Optional[str] = None,
    host:       Optional[str] = None,
) -> int:
    """Return the total count of findings matching the given filters."""
    db = get_db()
    query = {"session_id": session_id}
    if severity: query["severity"] = severity
    if phase:    query["phase"]    = phase
    if host:     query["host"]     = host
    return await db.findings.count_documents(query)


async def get_findings_summary(session_id: str, host: Optional[str] = None) -> Dict:
    """Return count by severity, optionally scoped to a single host."""
    db = get_db()
    match = {"session_id": session_id}
    if host:
        match["host"] = host
    pipeline = [
        {"$match": match},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]
    results = await db.findings.aggregate(pipeline).to_list(length=10)
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for r in results:
        sev = r["_id"]
        cnt = r["count"]
        summary[sev] = cnt
        summary["total"] += cnt
    return summary


# ═══════════════════════════════════════════════════════════
#  TOOL OUTPUTS
# ═══════════════════════════════════════════════════════════

async def store_tool_output(
    session_id: str,
    agent:      AgentName,
    phase:      AttackPhase,
    tool_name:  str,
    command:    str,
    host:       Optional[str] = None,    # per-host key (None = session-wide)
    target:     Optional[str] = None,    # kept for backward compat
    thread_id:  Optional[str] = None
) -> str:
    """
    Create a tool output record (empty).
    Returns the record ID — use finalize_tool_output() when the tool finishes.
    `host` is the canonical per-IP isolation key; `target` is kept for
    backward-compat with documents written before this field was added.
    """
    db = get_db()
    now = datetime.utcnow()
    doc = {
        "_id":               ObjectId(),
        "session_id":        session_id,
        "host":              host or target,   # canonical field
        "agent":             str(agent),
        "phase":             str(phase),
        "schema_version":    2,
        "tool_name":         tool_name,
        "command":           command,
        "target":            target,           # legacy compat field
        "stdout":            "",
        "stderr":            "",
        "exit_code":         None,
        "content_truncated": False,
        "summary":           None,
        "key_findings":      [],
        "created_at":        now,
        "ended_at":          None,
        "duration_ms":       None,
        "thread_id":         thread_id,
        "extra":             {}
    }
    await db.tool_outputs.insert_one(doc)
    await increment_session_stats(session_id, tools=1)
    return str(doc["_id"])


async def append_tool_stdout(output_id: str, chunk: str):
    """Append streaming stdout chunk to tool output record."""
    db = get_db()
    try:
        await db.tool_outputs.update_one(
            {"_id": ObjectId(output_id)},
            {"$push": {"stdout_chunks": chunk},
             "$set":  {"last_chunk_at": datetime.utcnow()}}
        )
    except InvalidId:
        pass


_STDOUT_CAP = 64 * 1024   # 64 KB — prevents multi-MB nmap outputs dominating storage

async def finalize_tool_output(
    output_id: str,
    stdout:    str,
    stderr:    str,
    exit_code: int,
    summary:   Optional[str]  = None,
    key_findings: List[str]   = None
):
    """
    Mark tool output as complete with final stdout/stderr.
    stdout is capped at 64 KB; if truncated, content_truncated is set True
    so callers know the full output is available only in filesystem logs.
    """
    db = get_db()
    now = datetime.utcnow()
    try:
        doc = await db.tool_outputs.find_one({"_id": ObjectId(output_id)})
        started      = doc.get("created_at", now) if doc else now
        duration_ms  = int((now - started).total_seconds() * 1000)

        truncated = len(stdout.encode("utf-8", errors="replace")) > _STDOUT_CAP
        if truncated:
            stdout = stdout.encode("utf-8", errors="replace")[:_STDOUT_CAP].decode("utf-8", errors="replace")
            stdout += "\n…[truncated — full output in filesystem logs]"

        await db.tool_outputs.update_one(
            {"_id": ObjectId(output_id)},
            {"$set": {
                "stdout":            stdout,
                "stderr":            stderr[:_STDOUT_CAP],
                "exit_code":         exit_code,
                "content_truncated": truncated,
                "summary":           summary,
                "key_findings":      key_findings or [],
                "ended_at":          now,
                "duration_ms":       duration_ms
            }}
        )
    except (InvalidId, TypeError):
        pass


async def get_tool_outputs(
    session_id: str,
    agent:      Optional[str] = None,
    limit:      int = 100,
    skip:       int = 0,
) -> List[Dict]:
    """Get tool outputs for a session with optional pagination (skip/limit)."""
    db = get_db()
    query = {"session_id": session_id}
    if agent: query["agent"] = agent
    cursor = db.tool_outputs.find(query).sort("started_at", DESCENDING).skip(skip).limit(limit)
    return _serialize_list(await cursor.to_list(length=limit))


# ═══════════════════════════════════════════════════════════
#  AGENT LOGS
# ═══════════════════════════════════════════════════════════

async def log_agent_action(
    session_id:    str,
    agent:         AgentName,
    phase:         AttackPhase,
    action:        str,
    reasoning:     str,
    new_status:    AgentStatus,
    host:          Optional[str]         = None,   # per-host key
    prev_status:   Optional[AgentStatus] = None,
    tool:          Optional[str]         = None,
    sent_to:       Optional[AgentName]   = None,
    received_from: Optional[AgentName]   = None,
    message:       Optional[str]         = None,
    log_level:     str                   = "info"  # "debug"|"info"|"warning"|"error"
) -> Dict:
    """
    Log an agent decision or status change.
    debug-level logs are also written to the capped agent_logs_realtime
    ring-buffer for live UI polling without polluting the main log.
    """
    db = get_db()
    now = datetime.utcnow()
    doc = {
        "_id":            ObjectId(),
        "session_id":     session_id,
        "host":           host,
        "agent":          str(agent),
        "phase":          str(phase),
        "schema_version": 2,
        "action":         action,
        "reasoning":      reasoning,
        "tool":           tool,
        "prev_status":    str(prev_status) if prev_status else None,
        "new_status":     str(new_status),
        "timestamp":      now,
        "created_at":     now,
        "sent_to":        str(sent_to)       if sent_to       else None,
        "received_from":  str(received_from) if received_from else None,
        "message":        message,
        "log_level":      log_level,
        "extra":          {}
    }
    await db.agent_logs.insert_one(doc)
    # Mirror debug/info logs to the capped realtime ring-buffer (best-effort)
    try:
        rt_doc = {k: v for k, v in doc.items() if k != "_id"}
        rt_doc["_id"] = ObjectId()
        await db.agent_logs_realtime.insert_one(rt_doc)
    except Exception:
        pass
    return _serialize(doc)


async def get_agent_logs(
    session_id: str,
    agent:      Optional[str] = None,
    limit:      int = 200,
    skip:       int = 0,
) -> List[Dict]:
    """Get agent logs, newest first, with optional pagination (skip/limit)."""
    db = get_db()
    query = {"session_id": session_id}
    if agent: query["agent"] = agent
    cursor = db.agent_logs.find(query).sort("timestamp", DESCENDING).skip(skip).limit(limit)
    return _serialize_list(await cursor.to_list(length=limit))


# ═══════════════════════════════════════════════════════════
#  SHELL SESSIONS
# ═══════════════════════════════════════════════════════════

async def create_shell_session(
    session_id: str,
    shell_type: str,
    rhost:      str,
    lhost:      Optional[str] = None,
    lport:      Optional[int] = None,
    rport:      Optional[int] = None,
    protocol:   str = "tcp"
) -> Dict:
    """Create a new shell session record."""
    db = get_db()
    doc = {
        "_id":            ObjectId(),
        "session_id":     session_id,
        "host":           rhost,          # BaseDocument per-host key mirrors rhost
        "agent":          str(AgentName.SHELL),
        "phase":          "exploit",
        "schema_version": 2,
        "shell_type":     shell_type,
        "lhost":          lhost,
        "lport":          lport,
        "rhost":          rhost,
        "rport":          rport,
        "protocol":       protocol,
        "active":         False,
        "pid":            None,
        "shell_user":     None,
        "shell_cwd":      None,
        "commands":       [],
        "opened_at":      datetime.utcnow(),
        "created_at":     datetime.utcnow(),
        "closed_at":      None,
        "extra":          {}
    }
    await db.shell_sessions.insert_one(doc)
    return _serialize(doc)


async def update_shell_session(shell_id: str, updates: Dict) -> bool:
    """Update shell session fields."""
    db = get_db()
    try:
        result = await db.shell_sessions.update_one(
            {"_id": ObjectId(shell_id)},
            {"$set": updates}
        )
        return result.modified_count > 0
    except InvalidId:
        return False


async def append_shell_command(shell_id: str, cmd: str, output: str):
    """Add a command to shell session history."""
    db = get_db()
    entry = {"cmd": cmd, "output": output, "ts": datetime.utcnow().isoformat()}
    try:
        await db.shell_sessions.update_one(
            {"_id": ObjectId(shell_id)},
            {"$push": {"commands": entry}}
        )
    except InvalidId:
        pass


async def get_shell_sessions(session_id: str, active_only: bool = False) -> List[Dict]:
    """Get all shell sessions for a pentest session."""
    db = get_db()
    query = {"session_id": session_id}
    if active_only: query["active"] = True
    cursor = db.shell_sessions.find(query).sort("opened_at", DESCENDING)
    return _serialize_list(await cursor.to_list(length=50))


# ═══════════════════════════════════════════════════════════
#  FLAGS
# ═══════════════════════════════════════════════════════════

async def store_flag(
    session_id: str,
    flag_type:  str,
    value:      str,
    location:   str,
    found_by:   AgentName,
    host:       Optional[str] = None,   # which host the flag came from
    context:    Optional[str] = None,
    phase:      str           = "post_exploit"
) -> Dict:
    """Store a captured flag."""
    db = get_db()
    now = datetime.utcnow()
    doc = {
        "_id":            ObjectId(),
        "session_id":     session_id,
        "host":           host,
        "agent":          str(found_by),
        "phase":          phase,
        "schema_version": 2,
        "flag_type":      flag_type,
        "value":          value,
        "location":       location,
        "found_by":       str(found_by),
        "context":        context,
        "found_at":       now,
        "created_at":     now,
        "extra":          {}
    }
    await db.flags.insert_one(doc)
    await add_flag_to_session(session_id, value)
    return _serialize(doc)


async def get_flags(session_id: str) -> List[Dict]:
    """Get all flags for a session."""
    db = get_db()
    cursor = db.flags.find({"session_id": session_id}).sort("found_at", ASCENDING)
    return _serialize_list(await cursor.to_list(length=100))


# ═══════════════════════════════════════════════════════════
#  ATTACK GRAPH
# ═══════════════════════════════════════════════════════════

async def add_attack_node(
    session_id: str,
    node_id:    str,
    node_type:  str,
    label:      str,
    phase:      AttackPhase,
    host:       Optional[str] = None,
    port:       Optional[int] = None,
    severity:   Optional[FindingSeverity] = None,
    metadata:   Dict = None
) -> Dict:
    """Add a node to the attack graph."""
    db = get_db()
    # Upsert — update if exists, insert if new
    doc = {
        "node_id":    node_id,
        "session_id": session_id,
        "node_type":  node_type,
        "label":      label,
        "phase":      phase,
        "host":       host,
        "port":       port,
        "severity":   severity,
        "metadata":   metadata or {},
        "created_at": datetime.utcnow()
    }
    await db.attack_graph_nodes.update_one(
        {"node_id": node_id, "session_id": session_id},
        {"$set": doc},
        upsert=True
    )
    return doc


async def add_attack_edge(
    session_id: str,
    edge_id:    str,
    source:     str,
    target:     str,
    label:      str,
    tool:       Optional[str] = None
) -> Dict:
    """Add an edge to the attack graph."""
    db = get_db()
    doc = {
        "edge_id":    edge_id,
        "session_id": session_id,
        "source":     source,
        "target":     target,
        "label":      label,
        "tool":       tool,
        "created_at": datetime.utcnow()
    }
    await db.attack_graph_edges.update_one(
        {"edge_id": edge_id, "session_id": session_id},
        {"$set": doc},
        upsert=True
    )
    return doc


async def get_attack_graph(session_id: str) -> Dict:
    """
    Get the full attack graph, enriched with ALL findings data.
    Like Bloodhound — builds a relationship graph from:
      hosts → services → vulnerabilities → findings → credentials → access
    Merges stored graph nodes/edges with live findings from DB.
    """
    import asyncio as _asyncio

    db = get_db()

    (raw_nodes, raw_edges, findings, flags, session) = await _asyncio.gather(
        db.attack_graph_nodes.find({"session_id": session_id}).to_list(500),
        db.attack_graph_edges.find({"session_id": session_id}).to_list(500),
        db.findings.find({"session_id": session_id}).to_list(500),
        db.flags.find({"session_id": session_id}).to_list(100),
        db.sessions.find_one({"_id": __import__("bson").ObjectId(session_id)}
                              if len(session_id) == 24 else {"session_id": session_id}),
        return_exceptions=True
    )

    def _safe(v, d): return d if isinstance(v, Exception) else (v or d)
    raw_nodes = _safe(raw_nodes, [])
    raw_edges = _safe(raw_edges, [])
    findings  = _safe(findings, [])
    flags     = _safe(flags, [])
    session   = _safe(session, {})

    # Serialize stored nodes/edges
    nodes = []
    edges = []
    node_ids = set()
    edge_ids = set()

    def add_node(node_id, node_type, label, host=None, port=None,
                 severity=None, metadata=None, phase=None):
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append({
            "node_id":   node_id,
            "node_type": node_type,
            "label":     label[:40] if label else label,
            "host":      host,
            "port":      port,
            "severity":  str(severity) if severity else None,
            "phase":     phase,
            "metadata":  metadata or {}
        })

    def add_edge(source, target, label, tool=None):
        edge_id = f"{source}→{target}"
        if edge_id in edge_ids:
            return
        edge_ids.add(edge_id)
        edges.append({
            "edge_id": edge_id,
            "source":  source,
            "target":  target,
            "label":   label,
            "tool":    tool
        })

    # ── 1. Existing graph nodes (hosts + services from scanner) ───────────────
    for n in raw_nodes:
        nid = n.get("node_id", "")
        if not nid:
            continue
        node_ids.add(nid)
        d = {k: v for k, v in n.items() if k not in ("_id","session_id")}
        # Ensure node_type field (older records use "type")
        d["node_type"] = d.get("node_type") or d.get("type") or "host"
        nodes.append(d)

    for e in raw_edges:
        eid = e.get("edge_id", "")
        if not eid:
            continue
        edge_ids.add(eid)
        edges.append({k: v for k, v in e.items() if k not in ("_id","session_id")})

    # ── 2. Target host node (always present) ──────────────────────────────────
    target_ip = (session or {}).get("target_ip", "unknown") if isinstance(session, dict) else "unknown"
    target_nid = f"host_{target_ip.replace('.','_')}"
    add_node(target_nid, "host", target_ip, host=target_ip, phase="recon",
             metadata={"role": "primary_target"})

    # ── 3. Finding nodes — one node per finding, linked to host/service ────────
    sev_colors = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    for f in findings:
        fid    = str(f.get("_id", ""))
        title  = (f.get("title") or "Finding")[:50]
        host   = f.get("host") or target_ip
        port   = f.get("port")
        sev    = str(f.get("severity") or "low").lower()
        tool   = f.get("tool_used") or ""
        cves   = f.get("cves") or []
        phase  = f.get("phase") or "scan"

        # Service node
        svc_nid = f"svc_{host.replace('.','_')}_{port}" if port else f"host_{host.replace('.','_')}"
        if port:
            service = (f.get("service") or "unknown")
            add_node(svc_nid, "service", f"{service}:{port}", host=host, port=port, phase=phase)
            add_edge(target_nid, svc_nid, "has_service", tool="nmap")

        # Finding node
        finding_nid = f"finding_{fid}" if fid else f"finding_{title[:20].replace(' ','_')}"
        add_node(finding_nid, "vulnerability" if sev in ("critical","high") else "finding",
                 title, host=host, port=port, severity=sev, phase=phase,
                 metadata={"cves": cves, "tool": tool, "description": (f.get("description") or "")[:200]})
        add_edge(svc_nid if port else target_nid, finding_nid,
                 f"{sev} finding", tool=tool)

        # CVE nodes — link CVEs to findings
        for cve in cves[:5]:
            cve_nid = f"cve_{cve.replace('-','_')}"
            add_node(cve_nid, "vulnerability", cve, host=host, severity="high",
                     phase=phase, metadata={"cve_id": cve})
            add_edge(finding_nid, cve_nid, "references", tool="searchsploit")

        # Exploit node if tool suggests exploitation
        if any(t in tool.lower() for t in ("sqlmap","metasploit","hydra","exploit")):
            exp_nid = f"exploit_{finding_nid}"
            add_node(exp_nid, "exploit", f"via {tool}", host=host, severity=sev,
                     phase="exploit", metadata={"tool": tool})
            add_edge(finding_nid, exp_nid, "exploitable_with", tool=tool)

    # ── 4. Credential nodes ────────────────────────────────────────────────────
    # Pull credentials from agent_logs / findings metadata
    cred_findings = [f for f in findings if "credential" in (f.get("title") or "").lower()
                     or "password" in (f.get("description") or "").lower()
                     or "valid cred" in (f.get("title") or "").lower()]
    for cf in cred_findings:
        cred_nid = f"cred_{str(cf.get('_id',''))}"
        host     = cf.get("host") or target_ip
        add_node(cred_nid, "access", f"Creds: {(cf.get('title') or '')[:30]}",
                 host=host, severity="high", phase="exploit",
                 metadata={"source": cf.get("tool_used","")})
        src_nid = f"host_{host.replace('.','_')}"
        add_edge(src_nid, cred_nid, "credentials_found", tool=cf.get("tool_used",""))

    # ── 5. Shell/access nodes from flags ───────────────────────────────────────
    for fl in flags:
        ft       = fl.get("flag_type","?")
        location = fl.get("location","")
        fval     = (fl.get("value") or "")[:20]
        flag_nid = f"flag_{ft}_{str(fl.get('_id',''))}"
        add_node(flag_nid, "access",
                 f"{'Root' if ft=='root' else 'User'} flag: {fval}",
                 host=target_ip, severity="critical", phase="privesc" if ft=="root" else "exploit",
                 metadata={"flag_type": ft, "location": location})
        add_edge(target_nid, flag_nid,
                 "compromised → root" if ft=="root" else "compromised → user",
                 tool="shell")

    return {"nodes": nodes, "edges": edges}


# ═══════════════════════════════════════════════════════════
#  OSINT RESULTS
# ═══════════════════════════════════════════════════════════

async def store_osint_result(
    session_id:  str,
    query:       str,
    source:      str,
    title:       str,
    summary:     str,
    host:        Optional[str]  = None,   # target host this OSINT relates to
    url:         Optional[str]  = None,
    cves:        List[str]      = None,
    exploits:    List[str]      = None,
    severity:    Optional[FindingSeverity] = None,
    relevance:   float          = 0.0,
    raw:         Optional[Dict] = None
) -> Dict:
    """Store an OSINT/internet research result."""
    db = get_db()
    now = datetime.utcnow()
    doc = {
        "_id":             ObjectId(),
        "session_id":      session_id,
        "host":            host,
        "agent":           "osint",
        "phase":           "osint",
        "schema_version":  2,
        "query":           query,
        "source":          source,
        "title":           title,
        "url":             url,
        "summary":         summary,
        "cves":            cves or [],
        "exploits":        exploits or [],
        "severity":        str(severity) if severity else None,
        "raw":             raw,
        "relevance_score": relevance,
        "fetched_at":      now,
        "created_at":      now,
        "extra":           {}
    }
    await db.osint_results.insert_one(doc)
    return _serialize(doc)


async def get_osint_results(session_id: str, min_relevance: float = 0.0) -> List[Dict]:
    """Get OSINT results sorted by relevance."""
    db = get_db()
    cursor = db.osint_results.find(
        {"session_id": session_id, "relevance_score": {"$gte": min_relevance}}
    ).sort("relevance_score", DESCENDING)
    return _serialize_list(await cursor.to_list(length=200))


# ═══════════════════════════════════════════════════════════
#  UTILITY
# ═══════════════════════════════════════════════════════════

async def get_session_summary(session_id: str) -> Dict:
    """
    Return a complete session summary for frontend hydration.
    Includes EVERYTHING needed to restore a session's state in the UI:
    session info, findings, flags, graph, tool outputs, logs, intel.
    """
    session  = await get_session(session_id)
    if not session:
        return {"error": "Session not found"}

    import asyncio as _asyncio

    # Fetch all data in parallel for speed
    (
        findings_summary,
        findings_list,
        flags,
        shells,
        recent_logs,
        graph,
        tool_outputs,
    ) = await _asyncio.gather(
        get_findings_summary(session_id),
        get_findings(session_id),
        get_flags(session_id),
        get_shell_sessions(session_id),
        get_agent_logs(session_id, limit=50),
        get_attack_graph(session_id),
        get_tool_outputs(session_id, limit=100),
        return_exceptions=True
    )

    # Safe-default any failed fetches
    def _safe(v, default):
        return default if isinstance(v, Exception) else (v or default)

    return {
        "session":        session,
        "findings":       _safe(findings_summary, {}),
        "findings_list":  _safe(findings_list, []),
        "flags":          _safe(flags, []),
        "shells":         [s for s in _safe(shells, []) if s.get("active")],
        "recent_logs":    _safe(recent_logs, []),
        "graph":          _safe(graph, {"nodes": [], "edges": []}),
        "tool_outputs":   _safe(tool_outputs, []),
        "current_phase":  session.get("current_phase", "idle"),
        "phases_completed": session.get("phases_completed", []),
    }


async def health_check() -> Dict:
    """Check MongoDB connectivity."""
    try:
        db = get_db()
        await db.command("ping")
        return {"status": "ok", "db": DB_NAME}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════
#  PAYLOADS  (Phase 3 — msfvenom generated files)
# ═══════════════════════════════════════════════════════════

async def store_payload(
    session_id:    str,
    platform:      str,
    arch:          str,
    fmt:           str,
    lhost:         str,
    lport:         int,
    payload_name:  str,
    output_path:   str,
    msfvenom_cmd:  str,
    listener_cmd:  str,
    success:       bool,
    encoder:       Optional[str] = None,
    iterations:    int = 1,
    size_bytes:    Optional[int] = None,
    error:         Optional[str] = None,
    raw_output:    Optional[str] = None
) -> Dict:
    """Store a msfvenom payload generation record."""
    db = get_db()
    doc = {
        "_id":          ObjectId(),
        "session_id":   session_id,
        "platform":     platform,
        "arch":         arch,
        "format":       fmt,
        "lhost":        lhost,
        "lport":        lport,
        "encoder":      encoder,
        "iterations":   iterations,
        "payload_name": payload_name,
        "output_path":  output_path,
        "size_bytes":   size_bytes,
        "msfvenom_cmd": msfvenom_cmd,
        "listener_cmd": listener_cmd,
        "success":      success,
        "error":        error,
        "raw_output":   raw_output,
        "generated_at": datetime.utcnow()
    }
    await db.payloads.insert_one(doc)
    return _serialize(doc)


async def get_payloads(session_id: str) -> List[Dict]:
    """Get all payloads for a session, newest first."""
    db = get_db()
    cursor = db.payloads.find({"session_id": session_id}).sort("generated_at", DESCENDING)
    return _serialize_list(await cursor.to_list(length=100))


async def get_payload(payload_id: str) -> Optional[Dict]:
    """Get a single payload by ID."""
    db = get_db()
    try:
        doc = await db.payloads.find_one({"_id": ObjectId(payload_id)})
        return _serialize(doc) if doc else None
    except InvalidId:
        return None


async def delete_payload(payload_id: str) -> bool:
    """Delete a payload record from the database."""
    db = get_db()
    try:
        result = await db.payloads.delete_one({"_id": ObjectId(payload_id)})
        return result.deleted_count > 0
    except InvalidId:
        return False




# ═══════════════════════════════════════════════════════════
#  ATTACK TREE  (Attack Planner output)
# ═══════════════════════════════════════════════════════════

async def store_attack_tree(session_id: str, tree: Dict) -> Dict:
    """
    Store the attack plan/tree generated by the Attack Planner.
    tree = {
      "root": "Initial Access",
      "nodes": [{"id": "n1", "technique": "...", "tool": "...", "probability": 0.8}],
      "edges": [{"from": "n1", "to": "n2", "condition": "success"}],
      "optimal_path": ["n1", "n3", "n5"],
      "mitre_techniques": ["T1190", "T1059"],
      "reasoning": "..."
    }
    """
    db = get_db()
    doc = {
        "_id":        ObjectId(),
        "session_id": session_id,
        "tree":       tree,
        "created_at": datetime.utcnow()
    }
    await db.attack_tree.insert_one(doc)
    return _serialize(doc)


async def get_attack_tree(session_id: str) -> Optional[Dict]:
    """Get the most recent attack tree for a session."""
    db = get_db()
    doc = await db.attack_tree.find_one(
        {"session_id": session_id},
        sort=[("created_at", DESCENDING)]
    )
    return _serialize(doc) if doc else None


# ═══════════════════════════════════════════════════════════
#  CHAIN ANALYSES  (produced by AttackGraphAgent)
# ═══════════════════════════════════════════════════════════

async def get_chain_analyses(session_id: str, limit: int = 10) -> List[Dict]:
    """Return the most recent chain analyses for a session."""
    db = get_db()
    cursor = db.chain_analyses.find(
        {"session_id": session_id}
    ).sort("created_at", DESCENDING).limit(limit)
    return _serialize_list(await cursor.to_list(length=limit))


async def get_latest_chain_analysis(session_id: str) -> Optional[Dict]:
    """Return only the single most recent chain analysis."""
    results = await get_chain_analyses(session_id, limit=1)
    return results[0] if results else None


# ═══════════════════════════════════════════════════════════
#  LONG-TERM MEMORY  (cross-session reusable knowledge)
# ═══════════════════════════════════════════════════════════

async def store_memory(
    memory_type:  str,    # "exploit_pattern" | "tool_reliability" | "credential_pattern"
    target_type:  str,    # "linux" | "windows" | "web" | "ad"
    content:      Dict,   # the knowledge payload
    tags:         List[str] = None,
    success:      bool = True,
    confidence:   float = 0.8
) -> Dict:
    """
    Store a reusable knowledge entry in long-term memory.
    Called after any successful or notable exploitation event.
    """
    db = get_db()
    doc = {
        "_id":         ObjectId(),
        "memory_type": memory_type,
        "target_type": target_type,
        "content":     content,
        "tags":        tags or [],
        "success":     success,
        "confidence":  confidence,
        "use_count":   0,
        "created_at":  datetime.utcnow(),
        "last_used":   None
    }
    await db.long_term_memory.insert_one(doc)
    return _serialize(doc)


async def recall_memory(
    memory_type:  Optional[str] = None,
    target_type:  Optional[str] = None,
    tags:         Optional[List[str]] = None,
    min_confidence: float = 0.5,
    limit:        int = 10
) -> List[Dict]:
    """
    Retrieve relevant memories filtered by type, target, tags.
    Returns most confident entries first.
    """
    db = get_db()
    query: Dict = {"confidence": {"$gte": min_confidence}}
    if memory_type:  query["memory_type"] = memory_type
    if target_type:  query["target_type"] = target_type
    if tags:         query["tags"] = {"$in": tags}

    cursor = db.long_term_memory.find(query)                 .sort([("confidence", DESCENDING), ("use_count", DESCENDING)])                 .limit(limit)
    docs = await cursor.to_list(length=limit)
    # Increment use_count for retrieved memories
    ids = [d["_id"] for d in docs]
    if ids:
        await db.long_term_memory.update_many(
            {"_id": {"$in": ids}},
            {"$inc": {"use_count": 1}, "$set": {"last_used": datetime.utcnow()}}
        )
    return _serialize_list(docs)


async def update_memory_confidence(memory_id: str, delta: float) -> bool:
    """Increase or decrease confidence of a memory entry based on outcome."""
    db = get_db()
    try:
        # Clamp confidence to [0.0, 1.0]
        result = await db.long_term_memory.update_one(
            {"_id": ObjectId(memory_id)},
            [{"$set": {"confidence": {
                "$min": [1.0, {"$max": [0.0, {"$add": ["$confidence", delta]}]}]
            }}}]
        )
        return result.modified_count > 0
    except InvalidId:
        return False


# ═══════════════════════════════════════════════════════════
#  EVIDENCE COLLECTION
# ═══════════════════════════════════════════════════════════

async def store_evidence(
    session_id:    str,
    phase:         str,
    evidence_type: str,   # "shell_output" | "screenshot_desc" | "credential" | "file_content" | "command_transcript"
    title:         str,
    content:       str,
    host:          Optional[str] = None,
    tool_used:     Optional[str] = None,
    severity:      str = "info",
    mitre_technique: Optional[str] = None
) -> Dict:
    """Store structured evidence for reporting and proof-of-exploitation."""
    db = get_db()
    doc = {
        "_id":             ObjectId(),
        "session_id":      session_id,
        "phase":           phase,
        "evidence_type":   evidence_type,
        "title":           title,
        "content":         content[:10000],  # cap at 10KB
        "host":            host,
        "tool_used":       tool_used,
        "severity":        severity,
        "mitre_technique": mitre_technique,
        "captured_at":     datetime.utcnow()
    }
    await db.evidence.insert_one(doc)
    return _serialize(doc)


async def get_evidence(session_id: str, evidence_type: Optional[str] = None) -> List[Dict]:
    """Get all evidence for a session, optionally filtered by type."""
    db = get_db()
    query: Dict = {"session_id": session_id}
    if evidence_type:
        query["evidence_type"] = evidence_type
    cursor = db.evidence.find(query).sort("captured_at", ASCENDING)
    return _serialize_list(await cursor.to_list(length=500))


# ═══════════════════════════════════════════════════════════
#  MITRE ATT&CK MAPPING
# ═══════════════════════════════════════════════════════════

async def store_mitre_mapping(
    session_id:  str,
    technique_id: str,    # e.g. "T1190"
    technique_name: str,  # e.g. "Exploit Public-Facing Application"
    tactic:       str,    # e.g. "Initial Access"
    tool_used:    Optional[str] = None,
    host:         Optional[str] = None,
    success:      bool = False,
    evidence_ref: Optional[str] = None
) -> Dict:
    """Store a MITRE ATT&CK technique mapping for this session."""
    db = get_db()
    # Upsert — avoid duplicate technique entries per session
    doc = {
        "session_id":     session_id,
        "technique_id":   technique_id,
        "technique_name": technique_name,
        "tactic":         tactic,
        "tool_used":      tool_used,
        "host":           host,
        "success":        success,
        "evidence_ref":   evidence_ref,
        "mapped_at":      datetime.utcnow()
    }
    await db.mitre_mappings.update_one(
        {"session_id": session_id, "technique_id": technique_id},
        {"$setOnInsert": {"_id": ObjectId()}, "$set": doc},
        upsert=True
    )
    result = await db.mitre_mappings.find_one(
        {"session_id": session_id, "technique_id": technique_id}
    )
    return _serialize(result) if result else doc


async def get_mitre_mappings(session_id: str) -> List[Dict]:
    """Get all MITRE ATT&CK mappings for a session."""
    db = get_db()
    cursor = db.mitre_mappings.find({"session_id": session_id}).sort("tactic", ASCENDING)
    return _serialize_list(await cursor.to_list(length=200))


# ═══════════════════════════════════════════════════════════
#  SESSION ACTIVATION  (Phase 3 — multi-session switching)
# ═══════════════════════════════════════════════════════════

async def activate_session(session_id: str) -> Optional[Dict]:
    """
    Mark a session as ACTIVE and return its full summary.
    Used when the user switches active sessions in the frontend.
    """
    # Verify session exists
    session = await get_session(session_id)
    if not session:
        return None

    # Ensure it is marked active (resume paused/completed sessions)
    await update_session(session_id, {"status": SessionStatus.ACTIVE})

    # Return a full summary for the frontend to hydrate its store
    return await get_session_summary(session_id)


# ═══════════════════════════════════════════════════════════
#  SESSION CHECKPOINTS  (pause / resume)
#  Full MasterAgent state snapshots — lets operator pause mid-scan
#  and resume from exactly where they left off.
# ═══════════════════════════════════════════════════════════

async def store_checkpoint(
    session_id:           str,
    host:                 str,
    checkpoint_type:      str,   # CheckpointType value string
    state_machine:        str,
    current_phase:        str,
    phases_completed:     List[str]      = None,
    phases_to_run:        List[str]      = None,
    intel_snapshot:       Dict[str, Any] = None,
    used_tools:           Dict[str, int] = None,
    pending_confirmations: List[str]     = None,
    in_flight_subagents:  List[str]      = None,
    master_config:        Dict[str, Any] = None,
) -> str:
    """
    Serialise the full MasterAgent state to session_checkpoints.
    Returns the checkpoint ID (str).  The session document is updated
    with last_checkpoint_id and pause_count is incremented for manual pauses.
    """
    db = get_db()
    doc = {
        "_id":                   ObjectId(),
        "session_id":            session_id,
        "host":                  host,
        "checkpoint_type":       checkpoint_type,
        "schema_version":        1,
        "state_machine":         state_machine,
        "current_phase":         current_phase,
        "phases_completed":      phases_completed or [],
        "phases_to_run":         phases_to_run    or [],
        "intel_snapshot":        intel_snapshot   or {},
        "used_tools":            used_tools       or {},
        "pending_confirmations": pending_confirmations or [],
        "in_flight_subagents":   in_flight_subagents  or [],
        "master_config":         master_config    or {},
        "created_at":            datetime.utcnow(),
    }
    await db.session_checkpoints.insert_one(doc)
    checkpoint_id = str(doc["_id"])

    # Update session to track latest checkpoint
    session_update: Dict = {"last_checkpoint_id": checkpoint_id, "updated_at": datetime.utcnow()}
    if checkpoint_type == "manual_pause":
        session_update["status"] = "paused"
        # Increment pause_count via $inc for atomicity
        try:
            await db.sessions.update_one(
                {"_id": ObjectId(session_id)},
                {"$inc": {"pause_count": 1}, "$set": session_update}
            )
        except Exception:
            pass
    else:
        await update_session(session_id, session_update)

    return checkpoint_id


async def get_latest_checkpoint(
    session_id: str,
    host:       Optional[str] = None
) -> Optional[Dict]:
    """
    Return the most recent checkpoint for a session (optionally scoped to a host).
    Prefers manual_pause checkpoints over auto ones if both share the same timestamp.
    """
    db = get_db()
    query: Dict = {"session_id": session_id}
    if host:
        query["host"] = host
    doc = await db.session_checkpoints.find_one(
        query,
        sort=[("created_at", DESCENDING)]
    )
    return _serialize(doc) if doc else None


async def get_checkpoints(
    session_id: str,
    host:       Optional[str] = None,
    limit:      int           = 20
) -> List[Dict]:
    """List checkpoints for a session, newest first."""
    db = get_db()
    query: Dict = {"session_id": session_id}
    if host:
        query["host"] = host
    cursor = db.session_checkpoints.find(query).sort("created_at", DESCENDING).limit(limit)
    return _serialize_list(await cursor.to_list(length=limit))


async def delete_checkpoint(checkpoint_id: str) -> bool:
    """Delete a specific checkpoint (e.g. after successful resume)."""
    db = get_db()
    try:
        result = await db.session_checkpoints.delete_one({"_id": ObjectId(checkpoint_id)})
        return result.deleted_count > 0
    except InvalidId:
        return False


# ═══════════════════════════════════════════════════════════
#  SESSION ARCHIVING  (>90 day old sessions)
#  archive_session() moves heavy data to archived_* collections
#  and writes a lightweight SessionArchive summary for fast retrieval.
# ═══════════════════════════════════════════════════════════

async def archive_session(session_id: str, report_html: Optional[str] = None) -> Optional[Dict]:
    """
    Archive a completed session:
      1. Write a SessionArchive summary document (with inline report HTML).
      2. Cascade-move findings/tool_outputs/agent_logs to archived_ collections.
      3. Mark session.archived = True and set archived_at timestamp.
    Returns the archive document, or None if session not found.
    """
    db  = get_db()
    session = await get_session(session_id)
    if not session:
        return None

    # ── 1. Build findings severity counts ──────────────────────────────────
    summary = await get_findings_summary(session_id)

    now = datetime.utcnow()
    archive_doc = {
        "_id":            ObjectId(),
        "session_id":     session_id,
        "target_ip":      session.get("target_ip", ""),
        "session_mode":   session.get("session_mode", "single"),
        "started_at":     session.get("started_at") or now,
        "completed_at":   session.get("completed_at"),
        "archived_at":    now,
        "findings_count": summary.get("total", 0),
        "critical_count": summary.get("critical", 0),
        "high_count":     summary.get("high", 0),
        "medium_count":   summary.get("medium", 0),
        "low_count":      summary.get("low", 0),
        "flags_found":    session.get("flags_found", []),
        "hosts_tested":   session.get("hosts_completed") or [session.get("target_ip", "")],
        "report_html":    report_html,
    }

    # ── 2. Upsert archive doc (idempotent) ─────────────────────────────────
    await db.session_archives.update_one(
        {"session_id": session_id},
        {"$setOnInsert": {"_id": ObjectId()}, "$set": archive_doc},
        upsert=True
    )

    # ── 3. Move heavy collections to archived_ siblings (bulk copy + delete) ──
    import asyncio as _asyncio

    async def _move(src_col, dst_col):
        try:
            docs = await db[src_col].find({"session_id": session_id}).to_list(length=50_000)
            if docs:
                await db[dst_col].insert_many(docs, ordered=False)
                await db[src_col].delete_many({"session_id": session_id})
        except Exception:
            pass  # non-fatal — archived_ collections are best-effort

    await _asyncio.gather(
        _move("findings",     "archived_findings"),
        _move("tool_outputs", "archived_tool_outputs"),
        _move("agent_logs",   "archived_agent_logs"),
        _move("osint_results","archived_osint_results"),
    )

    # ── 4. Flag the session as archived ────────────────────────────────────
    await update_session(session_id, {"archived": True, "archived_at": now})

    result = await db.session_archives.find_one({"session_id": session_id})
    return _serialize(result) if result else _serialize(archive_doc)


async def unarchive_session(session_id: str) -> bool:
    """
    Restore an archived session: move data back from archived_ siblings
    and clear the archived flag.  Returns True on success.
    """
    db  = get_db()
    session = await get_session(session_id)
    if not session or not session.get("archived"):
        return False

    import asyncio as _asyncio

    async def _restore(src_col, dst_col):
        try:
            docs = await db[src_col].find({"session_id": session_id}).to_list(length=50_000)
            if docs:
                await db[dst_col].insert_many(docs, ordered=False)
                await db[src_col].delete_many({"session_id": session_id})
        except Exception:
            pass

    await _asyncio.gather(
        _restore("archived_findings",     "findings"),
        _restore("archived_tool_outputs", "tool_outputs"),
        _restore("archived_agent_logs",   "agent_logs"),
        _restore("archived_osint_results","osint_results"),
    )

    await update_session(session_id, {"archived": False, "archived_at": None})
    return True


async def get_session_archive(session_id: str) -> Optional[Dict]:
    """Retrieve the archive summary for a session."""
    db = get_db()
    doc = await db.session_archives.find_one({"session_id": session_id})
    return _serialize(doc) if doc else None


async def list_archived_sessions(limit: int = 50) -> List[Dict]:
    """List all archived session summaries, newest first."""
    db = get_db()
    cursor = db.session_archives.find().sort("archived_at", DESCENDING).limit(limit)
    return _serialize_list(await cursor.to_list(length=limit))


# ═══════════════════════════════════════════════════════════
#  REASONING ENGINE — HYPOTHESES
# ═══════════════════════════════════════════════════════════

async def store_hypothesis(
    session_id: str,
    host: str,
    hypothesis_id: str,
    statement: str,
    confidence: float,
    evidence_supporting: List[str],
    required_evidence: List[str],
    recommended_next_actions: List[str],
    attack_phase: str,
    mitre_technique: Optional[str] = None,
    iteration_number: int = 0,
) -> str:
    """Upsert a hypothesis document. Returns the document id."""
    db_conn = get_db()
    now = datetime.utcnow()
    doc = {
        "session_id":              session_id,
        "host":                    host,
        "hypothesis_id":           hypothesis_id,
        "statement":               statement,
        "confidence":              confidence,
        "evidence_supporting":     evidence_supporting,
        "required_evidence":       required_evidence,
        "recommended_next_actions": recommended_next_actions,
        "attack_phase":            attack_phase,
        "mitre_technique":         mitre_technique,
        "iteration_number":        iteration_number,
        "validated":               False,
        "invalidated":             False,
        "agent":                   "master",
        "phase":                   "hypothesis",
        "schema_version":          1,
        "extra":                   {},
        "created_at":              now,
    }
    result = await db_conn.hypotheses.update_one(
        {"session_id": session_id, "hypothesis_id": hypothesis_id},
        {"$set": doc},
        upsert=True,
    )
    if result.upserted_id:
        return str(result.upserted_id)
    existing = await db_conn.hypotheses.find_one(
        {"session_id": session_id, "hypothesis_id": hypothesis_id},
        {"_id": 1}
    )
    return str(existing["_id"]) if existing else hypothesis_id


async def update_hypothesis_status(
    session_id: str,
    hypothesis_id: str,
    validated: Optional[bool] = None,
    invalidated: Optional[bool] = None,
    confidence: Optional[float] = None,
) -> bool:
    """Patch validation status and/or confidence of an existing hypothesis."""
    db_conn = get_db()
    updates: Dict[str, Any] = {}
    if validated is not None:
        updates["validated"] = validated
    if invalidated is not None:
        updates["invalidated"] = invalidated
    if confidence is not None:
        updates["confidence"] = confidence
    if not updates:
        return False
    result = await db_conn.hypotheses.update_one(
        {"session_id": session_id, "hypothesis_id": hypothesis_id},
        {"$set": updates},
    )
    return result.modified_count > 0


async def get_hypotheses(session_id: str, host: Optional[str] = None) -> List[Dict]:
    """Fetch all hypotheses for a session sorted by confidence descending."""
    db_conn = get_db()
    query: Dict[str, Any] = {"session_id": session_id}
    if host:
        query["host"] = host
    cursor = db_conn.hypotheses.find(query).sort("confidence", DESCENDING)
    return _serialize_list(await cursor.to_list(length=200))


# ═══════════════════════════════════════════════════════════
#  REASONING ENGINE — NEGATIVE MEMORY
# ═══════════════════════════════════════════════════════════

async def store_negative_memory(
    session_id: str,
    host: str,
    attempt_id: str,
    tool: str,
    args: str,
    target_service: str,
    failure_reason: str,
    evidence: str = "",
    hypothesis_id: str = "",
) -> str:
    """
    Upsert a failed attempt. If the same (session_id, tool, target_service)
    combination already exists, increments attempt_count.
    Returns the document id.
    """
    db_conn = get_db()
    now = datetime.utcnow()
    base_doc = {
        "session_id":     session_id,
        "host":           host,
        "attempt_id":     attempt_id,
        "tool":           tool,
        "args":           args,
        "target_service": target_service,
        "failure_reason": failure_reason,
        "evidence":       evidence[:500] if evidence else "",
        "hypothesis_id":  hypothesis_id,
        "agent":          "master",
        "phase":          "decision",
        "schema_version": 1,
        "extra":          {},
        "created_at":     now,
    }
    result = await db_conn.negative_memory.update_one(
        {"session_id": session_id, "tool": tool, "target_service": target_service},
        {
            "$set":  base_doc,
            "$inc":  {"attempt_count": 1},
            "$setOnInsert": {"attempt_count": 1},
        },
        upsert=True,
    )
    if result.upserted_id:
        return str(result.upserted_id)
    existing = await db_conn.negative_memory.find_one(
        {"session_id": session_id, "tool": tool, "target_service": target_service},
        {"_id": 1}
    )
    return str(existing["_id"]) if existing else attempt_id


async def load_negative_memory(session_id: str) -> List[Dict]:
    """Fetch all failed attempts for a session."""
    db_conn = get_db()
    cursor = db_conn.negative_memory.find(
        {"session_id": session_id}
    ).sort("attempt_count", DESCENDING)
    return _serialize_list(await cursor.to_list(length=500))


# ═══════════════════════════════════════════════════════════
#  REASONING ENGINE — ACTION SCORES
# ═══════════════════════════════════════════════════════════

async def store_action_score_event(
    session_id: str,
    host: str,
    action_id: str,
    delta: int,
    reason: str,
    running_total: int,
    tool: str,
    hypothesis_id: str = "",
) -> str:
    """Append a score change event. Returns the new document id."""
    db_conn = get_db()
    doc = {
        "_id":            ObjectId(),
        "session_id":     session_id,
        "host":           host,
        "action_id":      action_id,
        "delta":          delta,
        "reason":         reason,
        "running_total":  running_total,
        "tool":           tool,
        "hypothesis_id":  hypothesis_id,
        "agent":          "master",
        "phase":          "decision",
        "schema_version": 1,
        "extra":          {},
        "created_at":     datetime.utcnow(),
    }
    result = await db_conn.action_scores.insert_one(doc)
    return str(result.inserted_id)


async def get_action_score_total(session_id: str) -> int:
    """Return the latest running_total for a session (0 if no events)."""
    db_conn = get_db()
    doc = await db_conn.action_scores.find_one(
        {"session_id": session_id},
        sort=[("created_at", DESCENDING)],
    )
    return doc.get("running_total", 0) if doc else 0


# ═══════════════════════════════════════════════════════════
#  REASONING ENGINE — RANKED PATHS
# ═══════════════════════════════════════════════════════════

async def store_ranked_paths(
    session_id: str,
    host: str,
    iteration: int,
    paths: List[Dict],
    top_path_score: float = 0.0,
    top_path_id: str = "",
) -> str:
    """Upsert the ranked-path snapshot for a given iteration."""
    db_conn = get_db()
    now = datetime.utcnow()
    doc = {
        "session_id":     session_id,
        "host":           host,
        "iteration":      iteration,
        "paths":          paths,
        "top_path_score": top_path_score,
        "top_path_id":    top_path_id,
        "agent":          "master",
        "phase":          "decision",
        "schema_version": 1,
        "extra":          {},
        "created_at":     now,
    }
    result = await db_conn.ranked_paths.update_one(
        {"session_id": session_id, "iteration": iteration},
        {"$set": doc},
        upsert=True,
    )
    if result.upserted_id:
        return str(result.upserted_id)
    existing = await db_conn.ranked_paths.find_one(
        {"session_id": session_id, "iteration": iteration},
        {"_id": 1}
    )
    return str(existing["_id"]) if existing else ""


async def get_latest_ranked_paths(session_id: str) -> Optional[Dict]:
    """Return the most recent ranked-paths snapshot for a session."""
    db_conn = get_db()
    doc = await db_conn.ranked_paths.find_one(
        {"session_id": session_id},
        sort=[("iteration", DESCENDING)],
    )
    return _serialize(doc) if doc else None


async def get_findings_by_phase(session_id: str, phase: str) -> list:
    """Alias for get_findings(session_id, phase=phase). Used by meta-agents."""
    return await get_findings(session_id, phase=phase, limit=500)
