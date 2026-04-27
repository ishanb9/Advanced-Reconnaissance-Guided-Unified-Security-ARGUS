"""
ARGUS — Advanced Reconnaissance & Guided Unified Security
Agent Server — FastAPI backend with WebSocket + PTY shell routing.

Phase 3 additions vs Phase 1:
  - ShellAgent with real PTY I/O (via WS)
  - PayloadAgent (msfvenom wrapper)
  - ReportGenerator (HTML + PDF)
  - Multi-session support (activate endpoint)
  - WS routes: shell_input, shell_resize

All Phase 1/2 routes preserved unchanged.
Runs on: http://0.0.0.0:5001
"""

import asyncio, json, os, re, subprocess, time, traceback, uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

# Load .env file at startup so NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD
# and any other env vars are available before any module reads os.environ.
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass  # python-dotenv not installed — rely on system env vars

import httpx, netifaces, psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from db.schemas import (
    SessionCreate, AttackPhase, AgentName, AgentStatus,
    FindingSeverity, WebSocketMessage, StartPentestRequest, SessionMode
)
import db.mongo_client as db
from db.cache import (
    findings_cache, graph_cache, tool_outputs_cache, session_meta_cache,
    stats as cache_stats,
)
from agents.master_agent       import MasterAgent
from agents.shell_agent        import ShellAgent
from agents.payload_agent      import PayloadAgent
from agents.cidr_orchestrator  import CIDROrchestrator
from report.generator          import ReportGenerator


# ══════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════

MCP_URL    = "http://localhost:3000"
OLLAMA_URL = os.environ.get("OLLAMA_URL",   "http://192.168.0.101:11434")
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "deepseek-v3.1:671b-cloud")
MONGO_URI  = os.environ.get("MONGO_URI",    "mongodb://localhost:27017")


# ══════════════════════════════════════════════════════════════
#  WEBSOCKET MANAGER
# ══════════════════════════════════════════════════════════════

class WebSocketManager:
    # Buffer last N key events per session so late-connecting WS clients
    # can replay them. plan_skeleton fires before WS connects — without
    # this buffer it is silently dropped and the UI shows nothing.
    BUFFERED_EVENTS = {
        "plan_skeleton", "plan_step_update", "attack_tree_ready",
        "master_plan", "state_change", "agent_status", "phase_change",
        "parallel_intel", "llm_comm", "rag_query", "agent_reasoning",
        "finding", "flag_found", "graph_node", "graph_edge",
        # Subagent events
        "subagent_start", "subagent_complete", "subagent_error", "subagent_finding",
        # Post-exploitation events
        "credential_found", "tunnel_established", "persistence_planted",
        "burp_scan_complete", "chain_exploit_success", "privesc_success",
        "shell_obtained", "network_scan_complete", "phase_start", "phase_complete",
    }
    BUFFER_SIZE = 200  # max buffered events per session

    def __init__(self):
        self._connections: Dict[str, List[WebSocket]]  = {}
        self._event_buffer: Dict[str, List[dict]]       = {}

    async def connect(self, session_id: str, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(session_id, []).append(ws)
        print(f"[WS] Connected to session {session_id} "
              f"(total: {len(self._connections[session_id])})")

    def disconnect(self, session_id: str, ws: WebSocket):
        if session_id in self._connections:
            try:
                self._connections[session_id].remove(ws)
            except ValueError:
                pass

    def get_buffered_events(self, session_id: str) -> List[dict]:
        """Return buffered events for replay on WS connect."""
        return list(self._event_buffer.get(session_id, []))

    async def broadcast(self, message: WebSocketMessage):
        session_id = message.session_id
        payload = message.model_dump()
        if hasattr(payload.get("timestamp"), "isoformat"):
            payload["timestamp"] = payload["timestamp"].isoformat()

        # Buffer key events for late-joining WS clients
        if message.type in self.BUFFERED_EVENTS:
            buf = self._event_buffer.setdefault(session_id, [])
            buf.append(payload)
            if len(buf) > self.BUFFER_SIZE:
                buf.pop(0)

        dead = []
        for ws in self._connections.get(session_id, []):
            try:
                await ws.send_text(json.dumps(payload, default=str))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(session_id, ws)

    async def broadcast_raw(self, session_id: str, event_type: str, data: dict):
        """Broadcast an event, normalising flat subagent dicts into WebSocketMessage.

        BaseSubagent._emit() produces a flat dict:
            { "type": "subagent_start", "session_id": ..., "agent": ..., "subagent": ..., **payload }
        We convert it to WebSocketMessage so the frontend always receives the same
            { type, session_id, agent, data: { subagent, ... } }
        shape, regardless of whether the event came from an Agent or a Subagent.
        """
        if "type" in data and "session_id" in data:
            # Flat subagent dict — re-wrap into WebSocketMessage shape so the
            # frontend routeWsEvent() can always find fields under msg.data
            inner = {k: v for k, v in data.items()
                     if k not in ("type", "session_id", "agent", "phase", "timestamp")}
            msg = WebSocketMessage(
                type=data["type"],
                session_id=data["session_id"],
                agent=data.get("agent"),
                phase=data.get("phase"),
                data=inner,
            )
        else:
            msg = WebSocketMessage(type=event_type, session_id=session_id, data=data)
        await self.broadcast(msg)


ws_manager = WebSocketManager()

# Active state
active_agents:        Dict[str, Any]          = {}   # MasterAgent OR CIDROrchestrator
active_tasks:         Dict[str, asyncio.Task] = {}
active_shell_agents:  Dict[str, ShellAgent]   = {}
report_generator = ReportGenerator()


def _detect_session_mode(target_ip: str) -> SessionMode:
    """Return CIDR, MULTI, or SINGLE based on target_ip string."""
    if "/" in target_ip:
        return SessionMode.CIDR
    if "," in target_ip:
        return SessionMode.MULTI
    return SessionMode.SINGLE


def _resolve_agent_or_subagent(identifier: str):
    """Resolve a `tool_extend` / `tool_stop` target identifier to a live agent.

    The frontend sends back whatever string the backend put in the
    ``subagent`` field of ``tool_timeout_warning``.  That string may be:
      1. A ``SUBAGENT_NAME`` (e.g. ``web_vuln_scan``)            — BaseSubagent registry
      2. A ``BaseAgent`` registry key — usually ``str(AgentName.XXX)``
         which equals ``"AgentName.RECON"`` for a plain ``Enum`` subclass
      3. A free-form ``self.name`` that was reassigned by the subclass
         after ``super().__init__`` (e.g. ``WebAgent.self.name = "web"``)

    Without this helper, case 3 falls through both registries because the
    agent is registered under its original enum string but emits events
    under its renamed string — meaning ``kill_current_tool()`` never
    fires, and the watchdog keeps popping the timeout dialog every 30 s.
    """
    if not identifier:
        return None
    # Import here to avoid circular imports at module load time.
    from agents.base_subagent import get_subagent, _SUBAGENT_REGISTRY
    from agents.base_agent    import get_agent,    _AGENT_REGISTRY

    # 1. Direct lookup in both registries.
    sa = get_subagent(identifier) or get_agent(identifier)
    if sa:
        return sa

    # 2. Case-insensitive fallback across BOTH registries, matching:
    #    - the registry key
    #    - the instance's ``name`` attribute (handles reassignment)
    #    - the instance's ``SUBAGENT_NAME`` / ``AGENT_NAME`` class attributes
    want = identifier.strip().lower()
    candidates = list(_SUBAGENT_REGISTRY.items()) + list(_AGENT_REGISTRY.items())
    for key, inst in candidates:
        if str(key).lower() == want:
            return inst
        inst_name = getattr(inst, "name", None)
        if inst_name is not None:
            nm = getattr(inst_name, "value", None) or str(inst_name)
            if nm.lower() == want:
                return inst
        for attr in ("SUBAGENT_NAME", "AGENT_NAME"):
            v = getattr(inst, attr, None)
            if v and str(v).lower() == want:
                return inst
    return None


# ══════════════════════════════════════════════════════════════
#  LIFESPAN
# ══════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.setup(MONGO_URI)
    print("=" * 65)
    print("  ARGUS — Advanced Reconnaissance & Guided Unified Security")
    print(f"  Ollama : {OLLAMA_URL}")
    print(f"  MCP    : {MCP_URL}")
    print(f"  Mongo  : {MONGO_URI}")
    print("=" * 65)
    yield
    await db.teardown()


app = FastAPI(title="ARGUS Pentest Platform", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ══════════════════════════════════════════════════════════════
#  STATIC FILES & TEMPLATES
# ══════════════════════════════════════════════════════════════

BASE_DIR    = os.path.dirname(__file__)
static_dir  = os.path.join(BASE_DIR, "static")
template_dir = os.path.join(BASE_DIR, "templates")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

templates = Jinja2Templates(directory=template_dir) if os.path.exists(template_dir) else None


@app.get("/")
async def index(request: Request):
    if templates:
        return templates.TemplateResponse("index.html", {"request": request})
    return HTMLResponse("<h2>ARGUS — Backend Running</h2>")


# ══════════════════════════════════════════════════════════════
#  SESSIONS
# ══════════════════════════════════════════════════════════════

@app.post("/sessions")
async def create_session(body: StartPentestRequest):
    session_mode = _detect_session_mode(body.target_ip)

    session_data = SessionCreate(
        target_ip           = body.target_ip,
        target_hostname     = body.target_hostname,
        target_type         = body.target_type,
        scope               = body.scope,
        notes               = body.notes,
        threading_enabled   = body.threading_enabled,
        max_threads         = body.max_threads,
        session_mode        = session_mode,
        max_parallel_hosts  = getattr(body, "max_parallel_hosts", 5),
    )
    session    = await db.create_session(session_data)
    session_id = session["id"]

    async def broadcast(msg: WebSocketMessage):
        await ws_manager.broadcast(msg)

    # Shared kwargs forwarded into every MasterAgent.run()
    master_kwargs = dict(
        target_type        = body.target_type,
        auto_exploit       = body.auto_exploit,
        confirm_web        = getattr(body, "confirm_web",       False),
        web_phase_timeout  = getattr(body, "web_phase_timeout", 600),
        threading_enabled  = body.threading_enabled,
        max_threads        = body.max_threads,
        phases             = body.phases,
        notes              = getattr(body, "notes", "") or "",
        scope              = getattr(body, "scope", "")  or "",
        use_reasoning_loop = True,  # Always enabled — reasoning-driven approach
    )

    if session_mode == SessionMode.SINGLE:
        # ── Original single-host path — zero behaviour change ──────────────
        master = MasterAgent(broadcast=broadcast)
        active_agents[session_id] = master
        task = asyncio.create_task(master.run(
            session_id = session_id,
            target     = body.target_ip,
            **master_kwargs,
        ))
    else:
        # ── Multi-host / CIDR path ─────────────────────────────────────────
        orchestrator = CIDROrchestrator(
            session_id         = session_id,
            target_input       = body.target_ip,
            broadcast          = broadcast,
            session_kwargs     = master_kwargs,
            max_parallel_hosts = getattr(body, "max_parallel_hosts", 5),
        )
        active_agents[session_id] = orchestrator
        task = asyncio.create_task(orchestrator.run())

    active_tasks[session_id] = task

    # Pre-create ShellAgent for this session
    shell_agent = ShellAgent(broadcast=broadcast)
    shell_agent._session_id = session_id
    active_shell_agents[session_id] = shell_agent

    return {"session": session, "message": f"Pentest started on {body.target_ip}",
            "ws_url": f"/ws/{session_id}", "session_mode": session_mode.value}


@app.get("/sessions")
async def list_sessions():
    sessions = await db.list_sessions(limit=100)
    return {"sessions": sessions, "count": len(sessions)}


@app.get("/sessions/{session_id}")
async def get_session(session_id: str):
    s = await db.get_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return s


@app.get("/sessions/{session_id}/summary")
async def get_session_summary(session_id: str):
    return await db.get_session_summary(session_id)


@app.post("/sessions/{session_id}/stop")
async def stop_session(session_id: str):
    """
    Hard-stop a session.  Saves a checkpoint first so the scan can be
    resumed later via POST /sessions/{id}/resume.
    """
    agent = active_agents.get(session_id)
    if agent:
        # Graceful: ask MasterAgent to save a checkpoint before cancelling
        if hasattr(agent, "_save_checkpoint"):
            try:
                await agent._save_checkpoint("manual_pause")
            except Exception:
                pass
        agent.stop_all_agents()   # works for both MasterAgent and CIDROrchestrator
    task = active_tasks.get(session_id)
    if task and not task.done():
        task.cancel()
    await db.update_session(session_id, {"status": "stopped"})
    return {"status": "stopped", "session_id": session_id}


@app.post("/sessions/{session_id}/subagent/{subagent_name}/stop")
async def stop_subagent(session_id: str, subagent_name: str):
    """Cancel a single running subagent/tool without stopping the entire session."""
    from agents.base_subagent import get_subagent
    sa = get_subagent(subagent_name)
    if sa and sa.session_id == session_id:
        sa.request_stop()
        await ws_manager.broadcast_raw(session_id, "subagent_stopped", {
            "subagent": subagent_name,
            "message":  f"Subagent '{subagent_name}' cancelled by operator",
            "ts":       __import__("datetime").datetime.utcnow().isoformat(),
        })
        return {"status": "stopped", "subagent": subagent_name}
    raise HTTPException(status_code=404, detail=f"No running subagent '{subagent_name}' for this session")


@app.post("/sessions/{session_id}/subagent/{subagent_name}/restart")
async def restart_subagent(session_id: str, subagent_name: str, request: Request):
    """Stop a subagent then inject guidance so master re-runs it with an optional note."""
    from agents.base_subagent import get_subagent
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    # Stop if still running
    sa = get_subagent(subagent_name)
    if sa and sa.session_id == session_id:
        sa.request_stop()
    # Inject guidance into master to re-run
    master = active_agents.get(session_id)
    if not master:
        raise HTTPException(status_code=404, detail="No active master agent for this session")
    note  = body.get("note", "")
    tool_hint = subagent_name.replace("_subagent", "").replace("_agent", "")
    guidance = {
        "directive": "note",
        "note": f"[OPERATOR RESTART] Re-run {subagent_name}.{(' Operator note: ' + note) if note else ''}"
                f" — previous run was cancelled.",
        "force_tool": body.get("force_tool", ""),
        "force_args": body.get("force_args", ""),
    }
    master.inject_guidance(guidance)
    await ws_manager.broadcast_raw(session_id, "subagent_restarted", {
        "subagent": subagent_name,
        "note":     note,
        "message":  f"Subagent '{subagent_name}' restart requested",
        "ts":       __import__("datetime").datetime.utcnow().isoformat(),
    })
    return {"status": "restart_queued", "subagent": subagent_name}


@app.post("/api/subagents/run")
async def run_subagent_manual(request: Request):
    """Inject guidance into master to force-run a specific subagent/tool."""
    body = await request.json()
    session_id   = body.get("session_id", "")
    subagent     = body.get("subagent", "")
    note         = body.get("note", "")
    force_tool   = body.get("force_tool", subagent.replace("_subagent", "").replace("_agent", ""))
    force_args   = body.get("force_args", "")
    master = active_agents.get(session_id)
    if not master:
        raise HTTPException(status_code=404, detail="No active session")
    master.inject_guidance({
        "directive":  "force_tool",
        "force_tool": force_tool,
        "force_args": force_args,
        "note": note or f"Operator manually triggered: {subagent}",
    })
    await ws_manager.broadcast_raw(session_id, "guidance_queued", {
        "message": f"Manual run queued: {subagent}"
    })
    return {"status": "queued", "subagent": subagent}


@app.post("/sessions/{session_id}/confirm/{phase}")
async def confirm_action(session_id: str, phase: str):
    master = active_agents.get(session_id)
    if master:
        master.confirm_action(phase)
        return {"status": "confirmed", "phase": phase}
    raise HTTPException(status_code=404, detail="No active session")


@app.post("/sessions/{session_id}/guidance")
async def inject_guidance(session_id: str, request: Request):
    """
    Inject real-time guidance into a running pentest.
    Body: {
      "directive": "skip|note|force_tool",
      "skip_phase": "vuln_id",
      "force_tool": "nikto",
      "force_args": "-h http://target",
      "note": "Focus on the login page at /admin"
    }
    """
    master = active_agents.get(session_id)
    if not master:
        raise HTTPException(status_code=404, detail="No active session")
    body = await request.json()
    master.inject_guidance(body)
    await ws_manager.broadcast_raw(session_id, "guidance_queued", {
        "message": f"Guidance queued: {body.get('note') or body.get('directive', 'unknown')}"
    })
    return {"status": "queued", "guidance": body}


@app.post("/sessions/{session_id}/ask")
async def ask_question(session_id: str, request: Request):
    """
    Ask ARGUS a specific question against the current session intel.
    Runs the 3-layer QuestionEngine pipeline: deterministic → LLM → tool dispatch.
    Works for active sessions (tools can be dispatched) and paused/completed sessions
    (Layer 1 + 2 only — no new tool execution).

    Body: { "question": "what web server is running?", "context": "(optional)" }
    Response: { "answer": "...", "evidence": "...", "layer_used": 1|2|3,
                "finding_id": "...", "state": "answered|unanswerable" }
    """
    body = await request.json()
    question = (body.get("question") or "").strip()
    if not question:
        raise HTTPException(status_code=422, detail="'question' field is required")

    master = active_agents.get(session_id)
    if not master:
        raise HTTPException(status_code=404, detail="No active session found for this id")

    # Get or create QuestionEngine from master agent
    qe = getattr(master, "_question_engine", None)
    if qe is None:
        # Session may use reasoning loop but hasn't started yet, or is legacy mode
        # Fall back to guidance injection so the question is answered when possible
        master.inject_guidance({"directive": "note", "note": question})
        await ws_manager.broadcast_raw(session_id, "guidance_queued", {
            "message": f"Question queued (reasoning loop not active): {question}"
        })
        return {"status": "queued", "message": "Question queued via guidance (reasoning loop not yet active)"}

    # Run extraction immediately against current intel
    intel = getattr(master, "_intel", {})
    q_obj = await qe.answer_single(question, intel, "")

    # Broadcast result over WebSocket so Ask bar can show it
    await ws_manager.broadcast_raw(session_id, "question_answered", {
        "question_id":  q_obj.id,
        "question":     q_obj.text,
        "answer":       q_obj.answer,
        "evidence":     q_obj.evidence,
        "layer":        q_obj.layer_used,
        "state":        q_obj.state.value,
        "finding_id":   q_obj.finding_id,
    })

    return {
        "question":   q_obj.text,
        "answer":     q_obj.answer,
        "evidence":   q_obj.evidence,
        "layer_used": q_obj.layer_used,
        "state":      q_obj.state.value,
        "finding_id": q_obj.finding_id,
    }


@app.post("/sessions/{session_id}/operator-response")
async def operator_response(session_id: str, request: Request):
    """
    Submit operator answers to clarifying questions raised by the engagement context parser.
    Body: { "answers": {"question text": "answer text", ...} }
    """
    master = active_agents.get(session_id)
    if not master:
        raise HTTPException(status_code=404, detail="No active session")
    body  = await request.json()
    answers = body.get("answers") or {}
    if not isinstance(answers, dict):
        raise HTTPException(status_code=422, detail="'answers' must be a dict of {question: answer}")
    master.answer_operator_question(answers)
    await ws_manager.broadcast_raw(session_id, "operator_questions_cleared", {
        "message": f"Received {len(answers)} operator answer(s). Scan context updated."
    })
    return {"status": "ok", "answers_received": len(answers)}


@app.post("/sessions/{session_id}/activate")
async def activate_session(session_id: str):
    """Switch active session — returns full session summary for frontend state."""
    s = await db.get_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    # Ensure shell agent exists for this session
    if session_id not in active_shell_agents:
        async def broadcast(msg): await ws_manager.broadcast(msg)
        agent = ShellAgent(broadcast=broadcast)
        agent._session_id = session_id
        active_shell_agents[session_id] = agent
    return await db.get_session_summary(session_id)


@app.delete("/sessions/{session_id}")
async def delete_session(session_id: str):
    """
    Permanently delete a session and all related data.
    Stops any active pentest for this session first.
    """
    # Stop any running agent for this session
    if session_id in active_agents:
        agent = active_agents[session_id]
        if hasattr(agent, "stop_all_agents"):
            agent.stop_all_agents()

    if session_id in active_tasks:
        task = active_tasks[session_id]
        if not task.done():
            task.cancel()
        del active_tasks[session_id]

    if session_id in active_agents:
        del active_agents[session_id]

    if session_id in active_shell_agents:
        del active_shell_agents[session_id]

    # Disconnect any WebSocket clients for this session
    await ws_manager.broadcast_raw(session_id, "session_deleted", {
        "session_id": session_id,
        "message": "Session deleted"
    })

    # Delete from DB (cascades to all related collections)
    deleted = await db.delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found")

    return {"deleted": True, "session_id": session_id}


# ══════════════════════════════════════════════════════════════
#  FINDINGS / LOGS / FLAGS / GRAPH / OSINT
# ══════════════════════════════════════════════════════════════

@app.get("/sessions/{session_id}/findings")
async def get_findings(
    session_id: str,
    severity:   Optional[str] = None,
    phase:      Optional[str] = None,
    host:       Optional[str] = None,   # filter to a single IP (multi-host sessions)
    limit:      int = 200,              # page size  (max 1000)
    skip:       int = 0,                # offset for pagination
):
    limit = min(limit, 1000)

    # Summary is cheap aggregation — cache with 20 s TTL
    summary_key = f"summary:{session_id}:{host or ''}"
    hit, summary = await findings_cache.get(summary_key)
    if not hit:
        summary = await db.get_findings_summary(session_id, host)
        await findings_cache.set(summary_key, summary)

    # Paginated findings fetch (not cached — always fresh)
    findings = await db.get_findings(session_id, severity, phase, host,
                                     limit=limit, skip=skip)
    total = await db.get_findings_count(session_id, severity, phase, host)
    return {
        "findings": findings,
        "summary":  summary,
        "pagination": {
            "total": total,
            "limit": limit,
            "skip":  skip,
            "has_more": (skip + len(findings)) < total,
        },
    }


@app.get("/sessions/{session_id}/hosts")
async def get_session_hosts(session_id: str):
    """Return discovered hosts, completion status, and per-host finding counts."""
    host_info = await db.get_hosts_for_session(session_id)
    if not host_info:
        raise HTTPException(status_code=404, detail="Session not found")

    # Enrich with per-host finding counts
    enriched = []
    for h in host_info.get("discovered_hosts", []):
        summary = await db.get_findings_summary(session_id, host=h)
        enriched.append({
            "ip":              h,
            "status":          "complete" if h in host_info.get("hosts_completed", []) else "scanning",
            "findings_count":  summary.get("total", 0),
            "severity_counts": {k: summary[k] for k in ("critical","high","medium","low","info")},
        })

    return {
        "hosts":        enriched,
        "host_count":   host_info.get("host_count", 0),
        "session_mode": host_info.get("session_mode", "single"),
    }


@app.get("/sessions/{session_id}/logs")
async def get_logs(
    session_id: str,
    agent:      Optional[str] = None,
    limit:      int = 200,
    skip:       int = 0,
):
    limit = min(limit, 1000)
    logs = await db.get_agent_logs(session_id, agent, limit=limit, skip=skip)
    return {"logs": logs, "count": len(logs), "skip": skip, "limit": limit}


@app.get("/sessions/{session_id}/tool-outputs")
async def get_tool_outputs(
    session_id: str,
    agent:      Optional[str] = None,
    limit:      int = 50,
    skip:       int = 0,
):
    limit = min(limit, 500)
    cache_key = f"tool-outputs:{session_id}:{agent or ''}:{skip}:{limit}"
    hit, cached = await tool_outputs_cache.get(cache_key)
    if hit:
        return cached
    outputs = await db.get_tool_outputs(session_id, agent, limit=limit, skip=skip)
    result = {"outputs": outputs, "count": len(outputs), "skip": skip, "limit": limit}
    await tool_outputs_cache.set(cache_key, result)
    return result


@app.get("/sessions/{session_id}/flags")
async def get_flags(session_id: str):
    return {"flags": await db.get_flags(session_id)}


@app.get("/sessions/{session_id}/graph")
async def get_attack_graph(session_id: str):
    cache_key = f"graph:{session_id}"
    hit, cached = await graph_cache.get(cache_key)
    if hit:
        return cached
    result = await db.get_attack_graph(session_id)
    await graph_cache.set(cache_key, result)
    return result


@app.get("/sessions/{session_id}/graph/neo4j")
async def get_neo4j_graph(session_id: str):
    """Return the Neo4j-backed semantic relationship graph for a session."""
    try:
        import db.neo4j_client as neo4j
        if not await neo4j.ping():
            return JSONResponse(
                {"error": "Neo4j not available", "nodes": [], "edges": []},
                status_code=503,
            )
        graph = await neo4j.get_graph(session_id)
        return graph
    except Exception as exc:
        return JSONResponse({"error": str(exc), "nodes": [], "edges": []}, status_code=500)


@app.get("/sessions/{session_id}/graph/paths")
async def get_attack_paths(
    session_id: str,
    from_type:  str = "Host",
    to_type:    str = "Access",
    max_depth:  int = 10,
):
    """Return shortest attack paths from from_type nodes to to_type nodes."""
    try:
        import db.neo4j_client as neo4j
        if not await neo4j.ping():
            return JSONResponse(
                {"error": "Neo4j not available", "paths": []},
                status_code=503,
            )
        paths = await neo4j.get_attack_paths(
            session_id=session_id,
            from_type=from_type,
            to_type=to_type,
            max_depth=max_depth,
        )
        return {"paths": paths, "count": len(paths)}
    except Exception as exc:
        return JSONResponse({"error": str(exc), "paths": []}, status_code=500)


@app.get("/sessions/{session_id}/chain_analyses")
async def get_chain_analyses(session_id: str, limit: int = 10):
    """Return attack chain analyses produced by the AttackGraphAgent."""
    analyses = await db.get_chain_analyses(session_id, limit=limit)
    return {"analyses": analyses, "count": len(analyses)}


@app.get("/sessions/{session_id}/osint")
async def get_osint(session_id: str):
    results = await db.get_osint_results(session_id)
    return {"results": results, "count": len(results)}


# ══════════════════════════════════════════════════════════════
#  REPORT
# ══════════════════════════════════════════════════════════════

@app.get("/sessions/{session_id}/report")
async def get_report(session_id: str, format: str = "html"):
    """Generate HTML or PDF pentest report."""
    s = await db.get_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")

    if format == "pdf":
        pdf_bytes = await report_generator.generate_pdf(session_id)
        if pdf_bytes:
            return Response(
                content=pdf_bytes, media_type="application/pdf",
                headers={"Content-Disposition":
                         f"attachment; filename=pentest_report_{session_id[:8]}.pdf"}
            )
        # Fallback to HTML if wkhtmltopdf missing
    html = await report_generator.generate_html(session_id)
    return HTMLResponse(content=html)


# ══════════════════════════════════════════════════════════════
#  API — FINDING ANALYSIS
# ══════════════════════════════════════════════════════════════

class FindingAnalysisRequest(BaseModel):
    finding: dict
    session_id: str = ""

@app.post("/api/analyze-finding")
async def analyze_finding(body: FindingAnalysisRequest):
    """LLM-powered exploit chain analysis for a specific finding."""
    f = body.finding
    title = f.get("title", "Unknown Finding")
    description = f.get("description", "")
    severity = f.get("severity", "INFO")
    evidence = (f.get("evidence", "") or "")[:500]
    host = f.get("host", "")
    port = f.get("port", "")
    service = f.get("service", "")
    tool = f.get("tool_used", "")
    remediation = f.get("remediation", "")

    prompt = f"""You are a senior penetration tester and security researcher. Analyze this finding and provide a detailed, actionable exploit chain analysis.

FINDING: {title}
SEVERITY: {severity}
HOST/SERVICE: {host}:{port} ({service})
DESCRIPTION: {description}
EVIDENCE: {evidence}
TOOL: {tool}
REMEDIATION HINT: {remediation}

Provide a structured analysis covering:
1. **What this vulnerability is**: Explain the vulnerability class, why it exists, and its technical root cause
2. **Exploitation steps**: Step-by-step how an attacker would exploit this (be specific with commands/payloads where relevant)
3. **Attack chains**: How this finding chains with other common vulnerabilities (e.g., "This SQLi + file write permission could achieve RCE via INTO OUTFILE")
4. **Real-world impact**: What an attacker gains from successful exploitation
5. **Quick win potential**: Rate how easy/likely this is to exploit (Easy/Medium/Hard) and why
6. **Defensive bypass notes**: Common defenses and how attackers bypass them

Be concise but actionable. Use actual tool names and techniques. Format clearly with numbered points."""

    try:
        import httpx as _httpx
        llm_url = os.environ.get("OLLAMA_URL", "http://192.168.0.101:11434")
        model = os.environ.get("OLLAMA_MODEL", "deepseek-v3.1:671b-cloud")
        resp = await _httpx.AsyncClient(timeout=60.0).post(
            f"{llm_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False}
        )
        if resp.status_code == 200:
            data = resp.json()
            analysis = data.get("response", "").strip()
        else:
            analysis = f"LLM returned status {resp.status_code}"
    except Exception as e:
        analysis = f"Analysis unavailable: {e}"

    return {"analysis": analysis, "finding_id": f.get("id", f.get("_id", ""))}


# ══════════════════════════════════════════════════════════════
#  SHELL SESSIONS
# ══════════════════════════════════════════════════════════════

class ShellCommandRequest(BaseModel):
    command: str


class CreateShellRequest(BaseModel):
    session_id: str
    shell_type: str
    lhost:      Optional[str] = None
    lport:      Optional[int] = None
    rhost:      str
    rport:      Optional[int] = None
    protocol:   str = "tcp"
    # SSH extras
    username:   Optional[str] = None
    password:   Optional[str] = None
    key_file:   Optional[str] = None


@app.get("/sessions/{session_id}/shells")
async def get_shells(session_id: str, active_only: bool = False):
    shells = await db.get_shell_sessions(session_id, active_only)
    return {"shells": shells}


@app.post("/shells/create")
async def create_shell_listener(body: CreateShellRequest):
    """
    Create a shell session with PTY backing via ShellAgent.
    Supports: reverse_shell, netcat, socat, bind_shell, ssh
    """
    async def broadcast(msg: WebSocketMessage):
        await ws_manager.broadcast(msg)

    # Create DB record
    shell = await db.create_shell_session(
        session_id=body.session_id, shell_type=body.shell_type,
        rhost=body.rhost, lhost=body.lhost, lport=body.lport,
        rport=body.rport, protocol=body.protocol
    )
    shell_id = shell["id"]

    # Get/create ShellAgent for session
    session_id = body.session_id
    if session_id not in active_shell_agents:
        agent = ShellAgent(broadcast=broadcast)
        agent._session_id = session_id
        active_shell_agents[session_id] = agent
    else:
        agent = active_shell_agents[session_id]
        agent.broadcast = broadcast

    # SSH special case
    if body.shell_type == "ssh" and body.username:
        result = await agent.connect_ssh(
            session_id=session_id, shell_id=shell_id,
            host=body.rhost, port=body.lport or 22,
            username=body.username, password=body.password, key_file=body.key_file
        )
    else:
        result = await agent.create_listener(
            session_id=session_id, shell_id=shell_id,
            shell_type=body.shell_type, lport=body.lport or 4444,
            lhost=body.lhost, rhost=body.rhost
        )

    result["shell_id"] = shell_id
    return result


@app.post("/shells/{shell_id}/cmd")
async def send_shell_command(shell_id: str, body: ShellCommandRequest,
                              session_id: Optional[str] = None):
    """Send command to shell. Tries PTY agent first, falls back to DB record."""
    if session_id:
        agent = active_shell_agents.get(session_id)
        if agent:
            await agent.handle_input(shell_id, body.command + "\r")
            return {"status": "sent", "command": body.command}
    # Fallback: just store in DB
    await db.append_shell_command(shell_id, body.command, "")
    return {"status": "queued", "command": body.command}


@app.post("/shells/{shell_id}/upgrade")
async def upgrade_shell(shell_id: str, session_id: str):
    """Send TTY stabilisation commands to a dumb shell."""
    agent = active_shell_agents.get(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No shell agent for session")
    msg = await agent.upgrade_shell(shell_id)
    return {"status": msg}


@app.post("/shells/{shell_id}/terminate")
async def terminate_shell(shell_id: str, session_id: str):
    """Kill a shell process."""
    agent = active_shell_agents.get(session_id)
    if agent:
        await agent.terminate_shell(shell_id)
    return {"status": "terminated", "shell_id": shell_id}


@app.get("/shells/payloads")
async def get_shell_payloads(session_id: str = "", lport: int = 4444):
    """Return reverse shell one-liners for current LHOST."""
    agent = active_shell_agents.get(session_id)
    lhost = agent._get_lhost() if agent else "KALI_IP"
    payloads = ShellAgent.generate_payloads(lhost, lport)
    return {"payloads": payloads, "lhost": lhost, "lport": lport}


# ══════════════════════════════════════════════════════════════
#  PAYLOADS
# ══════════════════════════════════════════════════════════════

class GeneratePayloadRequest(BaseModel):
    session_id:    str
    platform:      str = "linux"
    arch:          str = "x64"
    format:        str = "elf"
    lhost:         Optional[str] = None
    lport:         int = 4444
    payload_type:  str = "staged"
    encoder:       Optional[str] = None
    iterations:    int = 1
    custom_payload: Optional[str] = None


@app.post("/payloads/generate")
async def generate_payload(body: GeneratePayloadRequest):
    async def broadcast(msg: WebSocketMessage):
        await ws_manager.broadcast(msg)

    agent = PayloadAgent(broadcast=broadcast)
    agent._session_id = body.session_id
    return await agent.generate(
        session_id=body.session_id, platform=body.platform,
        arch=body.arch, fmt=body.format, lhost=body.lhost,
        lport=body.lport, payload_type=body.payload_type,
        encoder=body.encoder, iterations=body.iterations,
        custom_payload=body.custom_payload
    )


@app.get("/payloads/options")
async def get_payload_options():
    return {
        "format_options":    PayloadAgent.get_format_options(),
        "encoder_options":   PayloadAgent.get_encoder_options(),
        "platform_defaults": PayloadAgent.PLATFORM_DEFAULTS,
    }


@app.get("/sessions/{session_id}/payloads")
async def get_session_payloads(session_id: str):
    agent = PayloadAgent()
    payloads = await agent.list_payloads(session_id)
    return {"payloads": payloads, "count": len(payloads)}


@app.delete("/payloads/{payload_id}")
async def delete_payload(payload_id: str):
    agent = PayloadAgent()
    ok = await agent.delete_payload(payload_id)
    return {"deleted": ok}


# ══════════════════════════════════════════════════════════════
#  TOOLS (preserved from Phase 1)
# ══════════════════════════════════════════════════════════════

@app.get("/tools")
@app.get("/api/tools")
async def get_tools():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(MCP_URL, json={"method": "tools/list", "params": {}})
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        return {"error": str(e), "tools": [], "mcp_offline": True}


class ExecuteToolRequest(BaseModel):
    tool_name:  str
    target:     Optional[str] = ""
    options:    Optional[str] = ""
    session_id: Optional[str] = None


@app.post("/tools/execute")
async def execute_tool_post(body: ExecuteToolRequest):
    return {"stream_url": f"/tools/stream?tool_name={body.tool_name}"
                          f"&target={body.target}&options={body.options}"}


@app.get("/tools/stream")
@app.get("/api/execute-tool")
async def execute_tool_stream(tool_name: str = "", target: str = "",
                               options: str = "", arguments: str = "{}"):
    try:
        args_dict = json.loads(arguments)
        if not target:  target  = args_dict.get("target", "")
        if not options: options = args_dict.get("options", "")
    except Exception:
        pass

    async def generate():
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                payload = {"method": "tools/call",
                           "params": {"name": tool_name,
                                      "arguments": {"target": target, "options": options}}}
                async with client.stream("POST", MCP_URL, json=payload) as resp:
                    async for line in resp.aiter_lines():
                        if line:
                            yield line + "\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/stop")
async def stop_tool():
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            await client.post(MCP_URL, json={"method": "tools/stop", "params": {}})
    except Exception:
        pass
    return {"status": "stopped"}


# ══════════════════════════════════════════════════════════════
#  CHAT (preserved)
# ══════════════════════════════════════════════════════════════

_chat_history: Dict[str, List[Dict]] = {}


class ChatRequest(BaseModel):
    message:    str
    session_id: Optional[str] = None


@app.post("/api/chat")
@app.post("/api/analyze")
@app.post("/chat")
async def chat(body: ChatRequest):
    client_key = body.session_id or "default"
    history    = _chat_history.setdefault(client_key, [])

    import socket
    net_ctx = f"Hostname: {socket.gethostname()}\n"

    system_prompt = (
        f"You are an expert penetration tester. Network: {net_ctx}\n"
        "When asked to run a tool respond with JSON: "
        '{"tool": "name", "target": "...", "options": "...", "reasoning": "..."}'
    )
    history.append({"role": "user", "content": body.message})

    try:
        async with httpx.AsyncClient(timeout=90) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={"model": MODEL_NAME,
                      "messages": [{"role": "system", "content": system_prompt}, *history[-20:]],
                      "stream": False}
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"]

        history.append({"role": "assistant", "content": content})
        if len(history) > 50:
            _chat_history[client_key] = history[-50:]

        import re as _re
        jm = _re.search(r"\{.*\}", content, _re.DOTALL)
        if jm:
            try:
                tc = json.loads(jm.group())
                if tc.get("tool"):
                    return JSONResponse({"tool_call": {"name": tc["tool"],
                                                        "arguments": {"target": tc.get("target",""),
                                                                      "options": tc.get("options","")}},
                                         "reasoning":   tc.get("reasoning",""),
                                         "explanation": tc.get("explanation","")})
            except Exception:
                pass
        return JSONResponse({"response": content})

    except Exception as e:
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/conversation/clear")
@app.post("/api/clear")
async def clear_conv():
    _chat_history.clear()
    return {"status": "cleared"}


# ══════════════════════════════════════════════════════════════
#  KNOWLEDGE BASE API
# ══════════════════════════════════════════════════════════════

# Lazy import — KB is optional; server starts fine without it
_kb_module = None

def _get_kb():
    global _kb_module
    if _kb_module is None:
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "knowledge"))
            import knowledge_base as kb
            _kb_module = kb
        except ImportError:
            pass
    return _kb_module


@app.get("/knowledge/stats")
async def kb_stats():
    kb = _get_kb()
    if not kb:
        return {"available": False, "error": "chromadb/sentence-transformers not installed"}
    try:
        s = kb.stats()
        return {"available": True, **s}
    except Exception as e:
        return {"available": False, "error": str(e)}


class KBSearchRequest(BaseModel):
    query:              str
    top_k:              int = 5
    phase_filter:       Optional[str] = None
    outcome_filter:     Optional[str] = None
    chunk_type_filter:  Optional[str] = None


@app.post("/knowledge/search")
async def kb_search(body: KBSearchRequest):
    kb = _get_kb()
    if not kb:
        return {"available": False, "results": "", "error": "KB not installed"}
    try:
        result = kb.search(
            body.query,
            top_k=body.top_k,
            phase_filter=body.phase_filter,
            outcome_filter=body.outcome_filter,
            chunk_type_filter=body.chunk_type_filter,
        )
        return {"available": True, "results": result, "query": body.query}
    except Exception as e:
        return {"available": False, "results": "", "error": str(e)}


class KBIngestRequest(BaseModel):
    text:        str
    source_file: str = "manual_entry"
    metadata:    Optional[dict] = None


@app.post("/knowledge/ingest")
async def kb_ingest_text(body: KBIngestRequest):
    """Manually ingest a single text snippet into the KB."""
    kb = _get_kb()
    if not kb:
        return {"ok": False, "error": "KB not installed"}
    try:
        ok = kb.ingest(
            text=body.text,
            source_file=body.source_file,
            chunk_index=0,
            metadata=body.metadata,
        )
        return {"ok": ok, "message": "Added" if ok else "Duplicate — skipped"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════
#  NEXT-GEN ARCHITECTURE ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/sessions/{session_id}/attack-tree")
async def get_attack_tree(session_id: str):
    """Get the generated attack tree for a session."""
    tree = await db.get_attack_tree(session_id)
    if not tree:
        # Try to get from active agent's intel
        agent = active_agents.get(session_id)
        if agent and agent._intel.get("attack_tree"):
            return {"attack_tree": agent._intel["attack_tree"], "session_id": session_id}
        return {"attack_tree": None, "session_id": session_id}
    return {"attack_tree": tree.get("tree"), "session_id": session_id, "created_at": tree.get("created_at")}


@app.get("/sessions/{session_id}/evidence")
async def get_evidence(session_id: str, evidence_type: Optional[str] = None):
    """Get structured evidence collected during a session."""
    evidence = await db.get_evidence(session_id, evidence_type)
    return {"evidence": evidence, "count": len(evidence)}


@app.get("/sessions/{session_id}/mitre")
async def get_mitre_mappings(session_id: str):
    """Get MITRE ATT&CK technique mappings for a session."""
    mappings = await db.get_mitre_mappings(session_id)
    # Group by tactic for easier consumption
    by_tactic: dict = {}
    for m in mappings:
        tactic = m.get("tactic", "Unknown")
        by_tactic.setdefault(tactic, []).append(m)
    return {
        "mappings":  mappings,
        "by_tactic": by_tactic,
        "count":     len(mappings),
        "tactics":   list(by_tactic.keys())
    }


@app.get("/sessions/{session_id}/state")
async def get_session_state(session_id: str):
    """Get the current state machine state of an active session."""
    agent = active_agents.get(session_id)
    if agent:
        return {
            "state":           agent._intel.get("state", "UNKNOWN"),
            "current_phase":   str(agent.phase),
            "mitre_count":     len(agent._intel.get("mitre_techniques", [])),
            "evidence_count":  len(agent._intel.get("evidence", [])),
            "lateral_targets": agent._intel.get("lateral_targets", []),
            "attack_tree":     bool(agent._intel.get("attack_tree")),
            "memory_hits":     len(agent._intel.get("long_term_hits", [])),
        }
    # Session not active — check DB
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"state": "COMPLETE", "session_id": session_id}


class MemoryQuery(BaseModel):
    memory_type:    Optional[str] = None
    target_type:    Optional[str] = None
    tags:           Optional[list] = None
    min_confidence: float = 0.5
    limit:          int   = 10


@app.post("/memory/recall")
async def recall_memory(body: MemoryQuery):
    """Query the long-term memory store."""
    memories = await db.recall_memory(
        memory_type   = body.memory_type,
        target_type   = body.target_type,
        tags          = body.tags,
        min_confidence= body.min_confidence,
        limit         = body.limit
    )
    return {"memories": memories, "count": len(memories)}


class MemoryEntry(BaseModel):
    memory_type: str
    target_type: str
    content:     dict
    tags:        list = []
    confidence:  float = 0.8


@app.post("/memory/store")
async def store_memory(body: MemoryEntry):
    """Manually store a memory entry (operator knowledge injection)."""
    memory = await db.store_memory(
        memory_type = body.memory_type,
        target_type = body.target_type,
        content     = body.content,
        tags        = body.tags,
        confidence  = body.confidence
    )
    return {"stored": True, "memory": memory}


@app.get("/memory/stats")
async def memory_stats():
    """Get statistics about the long-term memory store."""
    mdb = db.get_db()
    total       = await mdb.long_term_memory.count_documents({})
    by_type     = {}
    by_target   = {}
    async for doc in mdb.long_term_memory.aggregate([
        {"$group": {"_id": "$memory_type", "count": {"$sum": 1}, "avg_conf": {"$avg": "$confidence"}}}
    ]):
        by_type[doc["_id"]] = {"count": doc["count"], "avg_confidence": round(doc["avg_conf"], 2)}
    async for doc in mdb.long_term_memory.aggregate([
        {"$group": {"_id": "$target_type", "count": {"$sum": 1}}}
    ]):
        by_target[doc["_id"]] = doc["count"]
    return {
        "total_memories": total,
        "by_type":        by_type,
        "by_target_type": by_target
    }


# ══════════════════════════════════════════════════════════════
#  METRICS + STATUS (preserved)
# ══════════════════════════════════════════════════════════════

@app.get("/metrics")
@app.get("/api/metrics")
async def get_metrics():
    try:
        cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
        cpu_overall  = sum(cpu_per_core) / len(cpu_per_core)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net  = psutil.net_io_counters()
        return {
            "cpu":     {"overall": cpu_overall, "per_core": cpu_per_core,
                        "count": psutil.cpu_count(), "freq_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else 0},
            "memory":  {"total_gb": round(mem.total/1e9,2), "used_gb": round(mem.used/1e9,2),
                        "available_gb": round(mem.available/1e9,2), "percent": mem.percent},
            "disk":    {"total_gb": round(disk.total/1e9,2), "used_gb": round(disk.used/1e9,2),
                        "free_gb": round(disk.free/1e9,2), "percent": disk.percent},
            "network": {"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv,
                        "packets_sent": net.packets_sent, "packets_recv": net.packets_recv},
            "processes": len(list(psutil.process_iter())),
            "uptime_sec": time.time() - psutil.boot_time(),
            # Phase 4 — cache summary inline for dashboard widgets
            "cache": cache_stats.to_dict(),
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/metrics/cache")
@app.get("/api/metrics/cache")
async def get_cache_metrics():
    """
    Phase 4 — In-process cache performance metrics.
    Reports hit/miss rates and per-cache entry counts.
    """
    return {
        "global": cache_stats.to_dict(),
        "caches": {
            "findings":    {"size": findings_cache.size(),     "ttl_sec": 20,  "maxsize": 256},
            "graph":       {"size": graph_cache.size(),        "ttl_sec": 60,  "maxsize": 64},
            "tool_outputs":{"size": tool_outputs_cache.size(), "ttl_sec": 15,  "maxsize": 256},
            "session_meta":{"size": session_meta_cache.size(), "ttl_sec": 10,  "maxsize": 128},
        },
        # Per-session instruction cache stats from active agents
        "instruction_caches": {
            sid: agent._instruction_cache.cache_stats()
            for sid, agent in active_agents.items()
            if hasattr(agent, "_instruction_cache")
               and hasattr(agent._instruction_cache, "cache_stats")
        },
    }


@app.post("/metrics/cache/flush")
async def flush_cache(prefix: Optional[str] = None):
    """
    Phase 4 — Flush in-process caches.
    Optional ?prefix= to only evict matching keys (e.g. a session_id).
    """
    if prefix:
        for cache in (findings_cache, graph_cache, tool_outputs_cache, session_meta_cache):
            await cache.invalidate_prefix(prefix)
        return {"flushed": "prefix", "prefix": prefix}
    findings_cache.clear()
    graph_cache.clear()
    tool_outputs_cache.clear()
    session_meta_cache.clear()
    return {"flushed": "all"}


@app.get("/status")
@app.get("/api/status")
async def status():
    mcp_ok = mongo_ok = ollama_ok = False
    try:
        async with httpx.AsyncClient(timeout=2) as c:
            r = await c.post(MCP_URL, json={"method": "tools/list", "params": {}})
            mcp_ok = r.status_code == 200
    except Exception:
        pass
    try:
        mongo_ok = (await db.health_check()).get("status") == "ok"
    except Exception:
        pass
    try:
        async with httpx.AsyncClient(timeout=2) as c:
            r = await c.get(f"{OLLAMA_URL}/api/tags")
            ollama_ok = r.status_code == 200
    except Exception:
        pass

    return {
        "status":          "online",
        "mcp":             "online" if mcp_ok    else "offline",
        "mongo":           "online" if mongo_ok  else "offline",
        "ollama":          "online" if ollama_ok else "offline",
        "model":           MODEL_NAME,
        "active_sessions": [sid for sid, t in active_tasks.items() if not t.done()],
        "agent_count":     len(active_agents),
        "shell_sessions":  sum(len(a._shells) for a in active_shell_agents.values()),
    }


@app.get("/api/llm/check")
async def llm_check():
    """
    Detailed LLM diagnostic endpoint.
    Returns:
      - ollama_reachable: whether the Ollama server responds at all
      - available_models: list of model names pulled on this Ollama server
      - configured_model: MODEL_NAME currently configured
      - model_available:  whether configured_model appears in the pulled list
      - model_test:       result of a quick generation call ("ok" / error string)
      - ollama_url:       the URL being targeted
    """
    diag = {
        "ollama_url":        OLLAMA_URL,
        "configured_model":  MODEL_NAME,
        "ollama_reachable":  False,
        "available_models":  [],
        "model_available":   False,
        "model_test":        "not run",
    }

    # ── 1. Reachability + model list ─────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{OLLAMA_URL}/api/tags")
            if r.status_code == 200:
                diag["ollama_reachable"] = True
                body = r.json()
                models = [m.get("name", "") for m in body.get("models", [])]
                diag["available_models"] = models
                # Match by exact name or by stripping tag suffixes for a fuzzy check
                diag["model_available"] = (
                    MODEL_NAME in models or
                    any(MODEL_NAME.split(":")[0] in m for m in models)
                )
            else:
                diag["ollama_reachable_error"] = f"HTTP {r.status_code}"
    except Exception as e:
        diag["ollama_reachable_error"] = str(e)

    # ── 2. Quick generation smoke test ───────────────────────────────────
    if diag["ollama_reachable"]:
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(
                    f"{OLLAMA_URL}/api/chat",
                    json={
                        "model":    MODEL_NAME,
                        "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
                        "stream":   False,
                    }
                )
                if r.status_code == 200:
                    diag["model_test"] = "ok"
                    diag["model_test_response"] = r.json().get("message", {}).get("content", "")
                elif r.status_code == 404:
                    diag["model_test"] = f"model not found — pull it first: ollama pull {MODEL_NAME}"
                else:
                    diag["model_test"] = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            diag["model_test"] = f"error: {e}"

    return diag


# ══════════════════════════════════════════════════════════════
#  SETTINGS — NEO4J / INTEGRATIONS
# ══════════════════════════════════════════════════════════════

class Neo4jSettingsRequest(BaseModel):
    uri:      str
    user:     str
    password: str

@app.get("/settings/neo4j")
async def get_neo4j_settings():
    """Return current Neo4j connection settings (password masked)."""
    import db.neo4j_client as _neo4j
    connected = await _neo4j.ping()
    return {
        "uri":       os.environ.get("NEO4J_URI",      "bolt://localhost:7687"),
        "user":      os.environ.get("NEO4J_USER",     "neo4j"),
        "password":  "***" if os.environ.get("NEO4J_PASSWORD") else "",
        "connected": connected,
    }

@app.post("/settings/neo4j")
async def save_neo4j_settings(req: Neo4jSettingsRequest):
    """
    Save Neo4j credentials to .env file and hot-reload the driver.
    The server does NOT need a restart — the new settings take effect immediately.
    """
    env_path = os.path.join(os.path.dirname(__file__), ".env")

    # Read existing .env lines, replace or append the three Neo4j vars
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    def _set_var(lines, key, value):
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}=") or line.strip().startswith(f"# {key}="):
                lines[i] = f"{key}={value}\n"
                return lines
        lines.append(f"{key}={value}\n")
        return lines

    lines = _set_var(lines, "NEO4J_URI",      req.uri)
    lines = _set_var(lines, "NEO4J_USER",     req.user)
    lines = _set_var(lines, "NEO4J_PASSWORD", req.password)

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Update live environment and hot-reload the driver
    os.environ["NEO4J_URI"]      = req.uri
    os.environ["NEO4J_USER"]     = req.user
    os.environ["NEO4J_PASSWORD"] = req.password

    import db.neo4j_client as _neo4j
    # Patch the module-level vars and force driver reconnect
    _neo4j.NEO4J_URI      = req.uri
    _neo4j.NEO4J_USER     = req.user
    _neo4j.NEO4J_PASSWORD = req.password
    await _neo4j.close()          # tear down old driver
    _neo4j._available = None      # reset availability flag
    _neo4j._driver    = None

    connected = await _neo4j.ping()
    if connected:
        await _neo4j.ensure_schema()

    return {
        "saved":     True,
        "connected": connected,
        "message":   "Connected to Neo4j successfully." if connected else
                     f"Settings saved but could not connect to {req.uri} — check Neo4j is running and the password is correct.",
    }


# ══════════════════════════════════════════════════════════════
#  SUBAGENT / LATERAL / POST-EXPLOIT ENDPOINTS (Phase 4)
# ══════════════════════════════════════════════════════════════

@app.get("/sessions/{session_id}/credentials")
async def get_credentials(session_id: str, service: Optional[str] = None,
                          cred_type: Optional[str] = None):
    """Get all discovered credentials for a session."""
    mdb = db.get_db()
    query: dict = {"session_id": session_id}
    if service:
        query["service"] = service
    if cred_type:
        query["type"] = cred_type
    docs = await mdb.credentials.find(query, {"_id": 0}).sort("timestamp", -1).to_list(500)
    return {"credentials": docs, "count": len(docs)}


@app.get("/sessions/{session_id}/tunnels")
async def get_tunnels(session_id: str, active_only: bool = False):
    """Get network tunnels established during a session."""
    mdb = db.get_db()
    query: dict = {"session_id": session_id}
    if active_only:
        query["active"] = True
    docs = await mdb.tunnels.find(query, {"_id": 0}).sort("timestamp", -1).to_list(100)
    return {"tunnels": docs, "count": len(docs)}


@app.get("/sessions/{session_id}/persistence")
async def get_persistence(session_id: str):
    """Get all persistence mechanisms established during a session."""
    mdb = db.get_db()
    docs = await mdb.persistence.find({"session_id": session_id}, {"_id": 0}).sort("timestamp", -1).to_list(200)
    return {"persistence": docs, "count": len(docs)}


@app.get("/sessions/{session_id}/lateral")
async def get_lateral_findings(session_id: str):
    """Get lateral movement findings for a session."""
    mdb = db.get_db()
    docs = await mdb.findings.find(
        {"session_id": session_id, "agent": "lateral"},
        {"_id": 0}
    ).sort("timestamp", -1).to_list(500)
    # Also get subagent results for lateral phase
    sub_results = await mdb.subagent_results.find(
        {"session_id": session_id, "agent": "lateral"},
        {"_id": 0}
    ).sort("timestamp", -1).to_list(50)
    return {"findings": docs, "subagent_results": sub_results, "count": len(docs)}


@app.get("/sessions/{session_id}/subagents")
async def get_subagent_results(session_id: str, agent: Optional[str] = None,
                                subagent: Optional[str] = None):
    """Get subagent execution results for a session."""
    mdb = db.get_db()
    query: dict = {"session_id": session_id}
    if agent:
        query["agent"] = agent
    if subagent:
        query["subagent_name"] = subagent
    docs = await mdb.subagent_results.find(query, {"_id": 0}).sort("timestamp", -1).to_list(200)
    # Build summary: group by agent
    by_agent: dict = {}
    for doc in docs:
        a = doc.get("agent", "unknown")
        by_agent.setdefault(a, []).append({
            "subagent": doc.get("subagent_name"),
            "target": doc.get("target"),
            "finding_count": len(doc.get("findings", [])),
            "duration_seconds": doc.get("duration_seconds"),
            "error": doc.get("error"),
            "result_id": doc.get("result_id"),
            "timestamp": doc.get("timestamp"),
        })
    return {"results": docs, "by_agent": by_agent, "count": len(docs)}


class RunSubagentRequest(BaseModel):
    target:  Optional[str] = None
    options: Optional[dict] = None


@app.post("/sessions/{session_id}/subagents/{subagent_name}/run")
async def run_subagent_manually(session_id: str, subagent_name: str, body: RunSubagentRequest):
    """Manually trigger a specific subagent for a session."""
    s = await db.get_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")

    target = body.target or s.get("target_ip") or s.get("target", "")

    # Dynamic subagent lookup
    _SUBAGENT_REGISTRY: dict = {
        # ── Recon ────────────────────────────────────────────────────────
        "network_scan":          "agents.recon.network_scan_subagent.NetworkScanSubagent",
        "web_fingerprint":       "agents.recon.web_fingerprint_subagent.WebFingerprintSubagent",
        "service_banner":        "agents.recon.service_banner_subagent.ServiceBannerSubagent",
        "dns_recon":             "agents.recon.dns_recon_subagent.DnsReconSubagent",
        # ── Web ─────────────────────────────────────────────────────────
        "dir_fuzz":              "agents.web.dir_fuzz_subagent.DirFuzzSubagent",
        "web_vuln_scan":         "agents.web.web_vuln_scan_subagent.WebVulnScanSubagent",
        "sqli":                  "agents.web.sqli_subagent.SqliSubagent",
        "xss":                   "agents.web.xss_subagent.XssSubagent",
        "injection":             "agents.web.injection_subagent.InjectionSubagent",
        "burp":                  "agents.web.burp_subagent.BurpSubagent",
        "cms":                   "agents.web.cms_subagent.CmsSubagent",
        # ── Vulnerability assessment ─────────────────────────────────────
        "cve_lookup":            "agents.vuln.cve_lookup_subagent.CveLookupSubagent",
        "ssl_audit":             "agents.vuln.ssl_audit_subagent.SslAuditSubagent",
        "smb_vuln":              "agents.vuln.smb_vuln_subagent.SmbVulnSubagent",
        "service_vuln":          "agents.vuln.service_vuln_subagent.ServiceVulnSubagent",
        "ldap_vuln":             "agents.vuln.ldap_vuln_subagent.LdapVulnSubagent",
        # ── Privilege escalation ─────────────────────────────────────────
        "linux_enum":            "agents.privesc.linux_enum_subagent.LinuxEnumSubagent",
        "linux_exploit":         "agents.privesc.linux_exploit_subagent.LinuxExploitSubagent",
        "windows_enum":          "agents.privesc.windows_enum_subagent.WindowsEnumSubagent",
        "container_escape":      "agents.privesc.container_escape_subagent.ContainerEscapeSubagent",
        "cloud_meta":            "agents.privesc.cloud_meta_subagent.CloudMetaSubagent",
        # ── Lateral movement ─────────────────────────────────────────────
        "ad_enum":               "agents.lateral.ad_enum_subagent.AdEnumSubagent",
        "kerberos":              "agents.lateral.kerberos_subagent.KerberosSubagent",
        "ntlm_capture":          "agents.lateral.ntlm_capture_subagent.NtlmCaptureSubagent",
        # ── Post-exploitation ─────────────────────────────────────────────
        "persistence":           "agents.post.persistence_subagent.PersistenceSubagent",
        "data_exfil":            "agents.post.data_exfil_subagent.DataExfilSubagent",
        "local_cred_harvest":    "agents.post.local_cred_harvest_subagent.LocalCredHarvestSubagent",
        "log_evasion":           "agents.post.log_evasion_subagent.LogEvasionSubagent",
        "c2_deploy":             "agents.post.c2_deploy_subagent.C2DeploySubagent",
        # ── Exploit ───────────────────────────────────────────────────────
        "metasploit":            "agents.exploit.metasploit_subagent.MetasploitSubagent",
        "credential_spray":      "agents.exploit.credential_spray_subagent.CredentialSpraySubagent",
        "web_exploit":           "agents.exploit.web_exploit_subagent.WebExploitSubagent",
        "searchsploit":          "agents.exploit.searchsploit_subagent.SearchsploitSubagent",
        # ── Cloud ─────────────────────────────────────────────────────────
        "aws_enum":              "agents.cloud.aws_enum_subagent.AwsEnumSubagent",
        "azure_enum":            "agents.cloud.azure_enum_subagent.AzureEnumSubagent",
        "gcp_enum":              "agents.cloud.gcp_enum_subagent.GcpEnumSubagent",
        # ── Container ─────────────────────────────────────────────────────
        "docker_audit":          "agents.container.docker_audit_subagent.DockerAuditSubagent",
        "k8s_audit":             "agents.container.k8s_audit_subagent.K8sAuditSubagent",
        # ── Evasion ───────────────────────────────────────────────────────
        "defense_enum":          "agents.evasion.defense_enum_subagent.DefenseEnumSubagent",
        "av_evasion":            "agents.evasion.av_evasion_subagent.AvEvasionSubagent",
        "amsi_bypass":           "agents.evasion.amsi_bypass_subagent.AmsiBypassSubagent",
        # ── Forensics ─────────────────────────────────────────────────────
        "artifact_collect":      "agents.forensics.artifact_collect_subagent.ArtifactCollectSubagent",
        "timeline":              "agents.forensics.timeline_subagent.TimelineSubagent",
        "memory_analysis":       "agents.forensics.memory_analysis_subagent.MemoryAnalysisSubagent",
        # ── Evidence ──────────────────────────────────────────────────────
        "screenshot":            "agents.evidence.screenshot_subagent.ScreenshotSubagent",
        "flag_capture":          "agents.evidence.flag_capture_subagent.FlagCaptureSubagent",
        # ── Traffic ───────────────────────────────────────────────────────
        "pcap_capture":          "agents.traffic.pcap_capture_subagent.PcapCaptureSubagent",
        "credential_sniff":      "agents.traffic.credential_sniff_subagent.CredentialSniffSubagent",
        "mitm":                  "agents.traffic.mitm_subagent.MitmSubagent",
        # ── Wireless ──────────────────────────────────────────────────────
        "wifi_scan":             "agents.wireless.wifi_scan_subagent.WifiScanSubagent",
        "wpa2_crack":            "agents.wireless.wpa2_crack_subagent.Wpa2CrackSubagent",
        "evil_twin":             "agents.wireless.evil_twin_subagent.EvilTwinSubagent",
        # ── Web (gap-fill) ────────────────────────────────────────────────
        "ssrf":                  "agents.web.ssrf_subagent.SsrfSubagent",
        "auth_bypass":           "agents.web.auth_bypass_subagent.AuthBypassSubagent",
        # ── Vuln (gap-fill) ───────────────────────────────────────────────
        "ftp_vuln":              "agents.vuln.ftp_vuln_subagent.FtpVulnSubagent",
        "ssh_audit":             "agents.vuln.ssh_audit_subagent.SshAuditSubagent",
        # ── Privesc (gap-fill) ────────────────────────────────────────────
        "windows_exploit":       "agents.privesc.windows_exploit_subagent.WindowsExploitSubagent",
        # ── Exploit (gap-fill) ────────────────────────────────────────────
        "exploit_chain":         "agents.exploit.exploit_chain_subagent.ExploitChainSubagent",
        "post_module":           "agents.exploit.post_module_subagent.PostModuleSubagent",
    }

    if subagent_name not in _SUBAGENT_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Unknown subagent: {subagent_name}. Available: {list(_SUBAGENT_REGISTRY)}")

    # Dynamically import and instantiate
    try:
        module_path, cls_name = _SUBAGENT_REGISTRY[subagent_name].rsplit(".", 1)
        import importlib
        mod = importlib.import_module(module_path)
        cls = getattr(mod, cls_name)
    except (ImportError, AttributeError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load subagent {subagent_name}: {exc}")

    async def broadcast(event: dict):
        await ws_manager.broadcast_raw(session_id, event.get("type", "subagent_event"), event)

    mdb = db.get_db()
    subagent_instance = cls(
        session_id=session_id,
        target=target,
        broadcast=broadcast,
        db=mdb,
    )

    # Run in background task
    async def _run():
        try:
            kwargs = body.options or {}
            result = await subagent_instance.execute(**kwargs)
            await ws_manager.broadcast_raw(session_id, "subagent_manual_complete", {
                "subagent": subagent_name,
                "finding_count": len(result.findings),
                "duration_seconds": result.duration_seconds,
                "error": result.error,
            })
        except Exception as exc:
            await ws_manager.broadcast_raw(session_id, "subagent_manual_error", {
                "subagent": subagent_name, "error": str(exc)
            })

    asyncio.create_task(_run())
    return {"status": "started", "subagent": subagent_name, "target": target, "session_id": session_id}


@app.get("/sessions/{session_id}/rag_history")
async def get_rag_history(session_id: str):
    """Get RAG query history for a session."""
    mdb = db.get_db()
    docs = await mdb.rag_history.find({"session_id": session_id}, {"_id": 0}).sort("timestamp", -1).to_list(100)
    return {"rag_history": docs, "count": len(docs)}


@app.get("/sessions/{session_id}/attack_chains")
async def get_attack_chains(session_id: str):
    """Get discovered attack chains for a session."""
    mdb = db.get_db()
    docs = await mdb.attack_chains.find({"session_id": session_id}, {"_id": 0}).sort("timestamp", -1).to_list(50)
    return {"attack_chains": docs, "count": len(docs)}


@app.get("/sessions/{session_id}/context")
async def get_pentest_context(session_id: str):
    """Get the current PentestContext summary for an active session."""
    agent = active_agents.get(session_id)
    if agent and hasattr(agent, "_ctx"):
        ctx = agent._ctx
        if ctx:
            return {
                "session_id": session_id,
                "context": ctx.to_dict(),
                "summary": ctx.to_summary(),
                "active": True,
            }
    # Fall back to DB summary
    summary = await db.get_session_summary(session_id)
    return {"session_id": session_id, "context": summary, "active": False}


# ══════════════════════════════════════════════════════════════
#  WEBSOCKET (Phase 3 — adds shell I/O routing)
# ══════════════════════════════════════════════════════════════

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(ws: WebSocket, session_id: str):
    """
    Real-time event stream + shell I/O bridge.

    Client → server message types:
      ping          : keepalive
      stop          : stop agents
      confirm       : confirm exploitation phase
      shell_input   : { shell_id, data } → PTY stdin
      shell_resize  : { shell_id, cols, rows } → PTY resize
    """
    await ws_manager.connect(session_id, ws)
    try:
        summary = await db.get_session_summary(session_id)

        # Replay buffered key events BEFORE sending 'connected'
        # This ensures plan_skeleton, attack_tree_ready etc. reach
        # clients that connected after those events fired
        buffered = ws_manager.get_buffered_events(session_id)
        for evt in buffered:
            try:
                await ws.send_text(json.dumps(evt, default=str))
            except Exception:
                pass

        await ws.send_text(json.dumps({
            "type": "connected", "session_id": session_id,
            "data": summary, "timestamp": time.time()
        }, default=str))

        while True:
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=30)
                msg = json.loads(raw)
                mtype = msg.get("type", "")

                if mtype == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))

                elif mtype == "stop":
                    master = active_agents.get(session_id)
                    if master:
                        master.stop_all_agents()

                elif mtype == "confirm":
                    master = active_agents.get(session_id)
                    if master:
                        master.confirm_action(msg.get("phase", ""))

                elif mtype == "guidance":
                    # User injects real-time guidance into master agent
                    master = active_agents.get(session_id)
                    if master:
                        guidance = {
                            "directive":       msg.get("directive", "note"),
                            "skip_phase":      msg.get("skip_phase", ""),
                            "force_tool":      msg.get("force_tool", ""),
                            "force_args":      msg.get("force_args", ""),
                            "note":            msg.get("note", ""),
                            "target_override": msg.get("target_override", "")
                        }
                        master.inject_guidance(guidance)
                        await ws.send_text(json.dumps({
                            "type": "guidance_queued",
                            "data": {"message": f"Guidance queued: {guidance.get('note') or guidance.get('directive')}"}
                        }))

                elif mtype == "shell_input":
                    # Route keystroke → PTY stdin
                    shell_id = msg.get("shell_id", "")
                    data     = msg.get("data", "")
                    agent    = active_shell_agents.get(session_id)
                    if agent and shell_id and data:
                        await agent.handle_input(shell_id, data)

                elif mtype == "shell_resize":
                    # Handle terminal resize from xterm.js
                    shell_id = msg.get("shell_id", "")
                    cols     = int(msg.get("cols", 80))
                    rows     = int(msg.get("rows", 24))
                    agent    = active_shell_agents.get(session_id)
                    if agent and shell_id:
                        await agent.resize_shell(shell_id, cols, rows)

                elif mtype == "tool_extend":
                    # Extend a running tool's deadline.
                    # Check both registries: BaseSubagent (v3 subagents) and
                    # BaseAgent (recon/web/vuln/exploit/privesc main agents).
                    from agents.base_subagent import get_subagent
                    from agents.base_agent import get_agent
                    subagent_name = msg.get("subagent", "")
                    extra_sec     = float(msg.get("extra_sec", 600))
                    sa = _resolve_agent_or_subagent(subagent_name)
                    if sa:
                        sa.extend_tool(extra_sec)
                    await ws.send_text(json.dumps({
                        "type": "tool_extended",
                        "data": {"subagent": subagent_name, "extra_sec": extra_sec,
                                 "message": f"Deadline extended by {int(extra_sec//60)} min"}
                    }))

                elif mtype == "tool_stop":
                    # Kill only the current tool — the agent continues with remaining tasks.
                    # Do NOT call request_stop() which permanently halts the entire agent.
                    from agents.base_subagent import get_subagent
                    from agents.base_agent import get_agent
                    subagent_name = msg.get("subagent", "")
                    sa = _resolve_agent_or_subagent(subagent_name)
                    if sa:
                        if hasattr(sa, "kill_current_tool"):
                            sa.kill_current_tool()
                        else:
                            sa.request_stop()   # fallback for older agents
                    else:
                        print(f"[WS] tool_stop: no agent/subagent matched '{subagent_name}'")
                    await ws.send_text(json.dumps({
                        "type": "tool_stopped",
                        "data": {"subagent": subagent_name,
                                 "resolved":  bool(sa),
                                 "message": (f"Tool '{subagent_name}' cancelled — scan continues"
                                             if sa else
                                             f"Stop request for '{subagent_name}' — no matching agent found")}
                    }))

            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"type": "heartbeat", "ts": time.time()}))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[WS] Error: {e}")
    finally:
        ws_manager.disconnect(session_id, ws)
        print(f"[WS] Disconnected from session {session_id}")


# ══════════════════════════════════════════════════════════════
#  PAUSE / RESUME / CHECKPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/sessions/{session_id}/extend/{phase}")
async def extend_phase(session_id: str, phase: str):
    """
    Grant a time extension for a running phase that has hit its timeout.
    Called from the frontend when the user clicks "Extend" in the time-extension dialog.
    Also used to confirm a web-phase confirmation gate.
    """
    agent = active_agents.get(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No active agent for this session")
    if hasattr(agent, "extend_phase"):
        agent.extend_phase(phase)
        await ws_manager.broadcast_raw(session_id, "phase_extended", {
            "phase": phase, "message": f"Time extension granted for {phase}"
        })
        return {"status": "extended", "phase": phase}
    raise HTTPException(status_code=400, detail="Agent does not support phase extension")


@app.post("/sessions/{session_id}/pause")
async def pause_session(session_id: str):
    """
    Request a graceful pause.  The scan stops at the next phase boundary,
    saves a checkpoint, and sets session status to PAUSED.
    Returns immediately; actual pause happens asynchronously at phase boundary.
    """
    agent = active_agents.get(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No active agent for this session")

    # MasterAgent exposes pause(); CIDROrchestrator pause cascades to all hosts
    if hasattr(agent, "pause"):
        await agent.pause()
    else:
        raise HTTPException(status_code=400, detail="Agent does not support pause")

    # Mark as paused in DB immediately so a WS reconnect shows the correct status
    # even if the phase-boundary checkpoint hasn't fired yet.
    await db.update_session(session_id, {"status": "paused"})

    return {"status": "pause_requested", "session_id": session_id,
            "message": "Scan will pause after the current phase completes"}


@app.post("/sessions/{session_id}/resume")
async def resume_session(session_id: str):
    """
    Resume a paused scan.  If the MasterAgent is still in memory (process
    didn't restart), simply unblocks the pause event.  If the process restarted,
    a new MasterAgent is created and restored from the latest checkpoint.
    """
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    agent = active_agents.get(session_id)

    # ── Fast path: agent still in memory ─────────────────────────────────
    if agent and hasattr(agent, "resume"):
        resumed = await agent.resume()
        if resumed:
            await db.update_session(session_id, {"status": "active"})
            return {"status": "resumed", "session_id": session_id, "method": "in_memory"}
        # already running — still return 200
        return {"status": "already_running", "session_id": session_id}

    # ── Cold path: process restarted — restore from checkpoint ───────────
    cp = await db.get_latest_checkpoint(session_id)
    if not cp:
        raise HTTPException(
            status_code=409,
            detail="No checkpoint found — cannot resume. Start a new scan."
        )

    async def broadcast(msg):
        await ws_manager.broadcast(msg)

    master = MasterAgent(broadcast=broadcast)
    active_agents[session_id] = master

    # Re-create ShellAgent for this session
    shell_agent = ShellAgent(broadcast=broadcast)
    shell_agent._session_id = session_id
    active_shell_agents[session_id] = shell_agent

    # Restore run-config from checkpoint
    mc = cp.get("master_config", {})
    task = asyncio.create_task(master.run(
        session_id         = session_id,
        target             = session.get("target_ip", ""),
        target_type        = mc.get("target_type", session.get("target_type", "unknown")),
        auto_exploit       = mc.get("auto_exploit", False),
        threading_enabled  = mc.get("threading_enabled", False),
        max_threads        = mc.get("max_threads", 3),
        phases             = mc.get("phases") or None,
        notes              = mc.get("notes", ""),
        scope              = mc.get("scope", ""),
        checkpoint_id      = cp.get("id"),
        use_reasoning_loop = True,  # Always enabled
    ))
    active_tasks[session_id] = task
    await db.update_session(session_id, {"status": "active"})

    return {
        "status":        "resumed",
        "session_id":    session_id,
        "method":        "checkpoint_restore",
        "checkpoint_id": cp.get("id"),
        "resume_after":  cp.get("current_phase"),
    }


@app.get("/sessions/{session_id}/checkpoints")
async def list_checkpoints(session_id: str, host: Optional[str] = None, limit: int = 20):
    """List all checkpoints for a session, newest first."""
    checkpoints = await db.get_checkpoints(session_id, host=host, limit=limit)
    return {"checkpoints": checkpoints, "count": len(checkpoints)}


@app.get("/sessions/{session_id}/checkpoints/latest")
async def get_latest_checkpoint(session_id: str, host: Optional[str] = None):
    """Get the most recent checkpoint for a session."""
    cp = await db.get_latest_checkpoint(session_id, host=host)
    if not cp:
        raise HTTPException(status_code=404, detail="No checkpoints found for this session")
    return cp


@app.delete("/sessions/{session_id}/checkpoints/{checkpoint_id}")
async def delete_checkpoint(session_id: str, checkpoint_id: str):
    """Delete a specific checkpoint."""
    deleted = await db.delete_checkpoint(checkpoint_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Checkpoint not found")
    return {"status": "deleted", "checkpoint_id": checkpoint_id}


# ══════════════════════════════════════════════════════════════
#  SESSION ARCHIVING
# ══════════════════════════════════════════════════════════════

@app.post("/sessions/{session_id}/archive")
async def archive_session(session_id: str):
    """
    Archive a completed session — moves heavy data to archived_ collections,
    stores a compact summary for fast retrieval, marks session as archived.
    """
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") not in ("completed", "paused", "stopped"):
        raise HTTPException(
            status_code=409,
            detail="Only completed/paused/stopped sessions can be archived"
        )
    archive = await db.archive_session(session_id)
    return {"status": "archived", "session_id": session_id, "archive": archive}


@app.post("/sessions/{session_id}/unarchive")
async def unarchive_session(session_id: str):
    """Restore an archived session — moves data back from archived_ collections."""
    ok = await db.unarchive_session(session_id)
    if not ok:
        raise HTTPException(
            status_code=409,
            detail="Session not found or was not archived"
        )
    return {"status": "unarchived", "session_id": session_id}


@app.get("/sessions/{session_id}/archive")
async def get_session_archive(session_id: str):
    """Get the archive summary for a session."""
    archive = await db.get_session_archive(session_id)
    if not archive:
        raise HTTPException(status_code=404, detail="No archive found for this session")
    return archive


@app.get("/archives")
async def list_archives(limit: int = 50):
    """List all archived session summaries, newest first."""
    archives = await db.list_archived_sessions(limit=limit)
    return {"archives": archives, "count": len(archives)}


# ══════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    print("Starting ARGUS Pentest Platform...")
    uvicorn.run("agent_server:app", host="0.0.0.0", port=5001, reload=False, workers=1)
