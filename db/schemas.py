"""
ARGUS Pentest Platform — Database Schemas
Pydantic models mapping to MongoDB collections.

Design principles:
  - BaseDocument is the contract every operational collection document must satisfy.
  - agent/phase stored as str (not Enum) for forward-compatibility — new agents/phases
    never cause validation failures on old documents.
  - schema_version lets queries target documents that have specific newer fields.
  - extra: Dict[str, Any] absorbs new fields before they are promoted to first-class.
  - All IDs are strings (MongoDB ObjectId serialized as str).
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ═══════════════════════════════════════════════════════════
#  ENUMERATIONS
#  Use str(Enum) so values serialise as plain strings.
#  Add new members freely — they never break existing documents.
# ═══════════════════════════════════════════════════════════

class AttackPhase(str, Enum):
    """Standard penetration testing lifecycle phases."""
    RECON        = "recon"
    SCAN         = "scan"
    VULN_ID      = "vuln_id"
    OSINT        = "osint"
    EXPLOIT      = "exploit"
    POST_EXPLOIT = "post_exploit"
    PRIVESC      = "privesc"
    PERSISTENCE  = "persistence"
    REPORTING    = "reporting"
    # Specialist phases
    LATERAL      = "lateral"
    CLOUD        = "cloud"
    CONTAINER    = "container"
    EVASION      = "evasion"
    TRAFFIC      = "traffic"
    EVIDENCE     = "evidence"
    FORENSICS    = "forensics"
    WIRELESS     = "wireless"
    IOT          = "iot"
    # Reasoning engine phases
    HYPOTHESIS   = "hypothesis"
    DECISION     = "decision"


class AgentName(str, Enum):
    MASTER   = "master"
    RECON    = "recon"
    VULN     = "vuln"
    OSINT    = "osint"
    EXPLOIT  = "exploit"
    PRIVESC  = "privesc"
    SHELL    = "shell"
    PAYLOAD  = "payload"
    IOT      = "iot"


class SessionMode(str, Enum):
    SINGLE = "single"
    CIDR   = "cidr"
    MULTI  = "multi"


class AgentStatus(str, Enum):
    IDLE     = "idle"
    THINKING = "thinking"
    RUNNING  = "running"
    WAITING  = "waiting"
    DONE     = "done"
    ERROR    = "error"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class SessionStatus(str, Enum):
    ACTIVE    = "active"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"
    ARCHIVED  = "archived"


class CheckpointType(str, Enum):
    MANUAL_PAUSE   = "manual_pause"   # operator clicked pause
    AUTO           = "auto"           # auto-saved at key phase boundaries
    PHASE_COMPLETE = "phase_complete" # saved when a major phase finishes


# ═══════════════════════════════════════════════════════════
#  BASE DOCUMENT CONTRACT
#  Every operational collection document must include these.
#  agent/phase are str (not Enum) — accepts any new agent or
#  phase string without migration or validation errors.
# ═══════════════════════════════════════════════════════════

class BaseDocument(BaseModel):
    """Minimum contract for every operational collection document."""
    id:             str
    session_id:     str
    host:           Optional[str]       = None    # per-host isolation key; None = session-wide
    agent:          str                           # str not Enum — new agents work without migration
    phase:          str                           # str not Enum — new phases work without migration
    schema_version: int                 = 1       # bump when fields are added; enables partial queries
    extra:          Dict[str, Any]      = {}      # forward-compatible overflow for new fields
    created_at:     datetime            = Field(default_factory=datetime.utcnow)


# ═══════════════════════════════════════════════════════════
#  COLLECTION: sessions
# ═══════════════════════════════════════════════════════════

class SessionCreate(BaseModel):
    target_ip:          str
    target_hostname:    Optional[str] = None
    target_type:        str = "unknown"
    scope:              Optional[str] = None
    notes:              Optional[str] = None
    threading_enabled:  bool = False
    max_threads:        int  = 3
    session_mode:       SessionMode = SessionMode.SINGLE
    max_parallel_hosts: int  = 5
    phases:             List[str] = []
    auto_exploit:       bool = False


class Session(SessionCreate):
    id:               str
    status:           SessionStatus = SessionStatus.ACTIVE
    current_phase:    str           = "recon"     # str for forward-compat
    phases_completed: List[str]     = []
    started_at:       datetime      = Field(default_factory=datetime.utcnow)
    updated_at:       datetime      = Field(default_factory=datetime.utcnow)
    completed_at:     Optional[datetime] = None
    # Summary stats
    findings_count:   int = 0
    tools_run:        int = 0
    flags_found:      List[str] = []
    # Multi-host tracking
    discovered_hosts: List[str] = []
    hosts_completed:  List[str] = []
    host_count:       int = 0
    # Pause/resume
    last_checkpoint_id: Optional[str] = None
    pause_count:        int = 0
    # Archiving
    archived:           bool = False
    archived_at:        Optional[datetime] = None


# ═══════════════════════════════════════════════════════════
#  COLLECTION: findings
# ═══════════════════════════════════════════════════════════

class Finding(BaseDocument):
    severity:    str                            # FindingSeverity value
    title:       str
    description: str
    # Target info — host is inherited from BaseDocument (required here)
    port:        Optional[int]    = None
    service:     Optional[str]    = None
    protocol:    Optional[str]    = None
    # CVE / exploit info
    cves:        List[str]        = []
    exploits:    List[str]        = []
    # Evidence
    tool_used:   Optional[str]    = None
    raw_output:  Optional[str]    = None
    screenshot:  Optional[str]    = None
    # Remediation
    remediation: Optional[str]    = None
    # Timestamps — created_at inherited; add found_at alias
    found_at:    datetime         = Field(default_factory=datetime.utcnow)
    verified:    bool             = False


# ═══════════════════════════════════════════════════════════
#  COLLECTION: tool_outputs
# ═══════════════════════════════════════════════════════════

class ToolOutput(BaseDocument):
    tool_name:        str
    command:          str
    # host is inherited — replaces the old freeform `target` field
    # target kept for backward compat with existing documents
    target:           Optional[str] = None
    # Output
    stdout:           str   = ""
    stderr:           str   = ""
    exit_code:        Optional[int] = None
    content_truncated: bool = False    # True when stdout was capped at 64KB
    # Parsed summary
    summary:          Optional[str] = None
    key_findings:     List[str]     = []
    # Timing — created_at = started_at
    ended_at:         Optional[datetime] = None
    duration_ms:      Optional[int]      = None
    thread_id:        Optional[str]      = None

    @property
    def started_at(self) -> datetime:
        return self.created_at


# ═══════════════════════════════════════════════════════════
#  COLLECTION: agent_logs
# ═══════════════════════════════════════════════════════════

class AgentLog(BaseDocument):
    action:        str
    reasoning:     str
    tool:          Optional[str]          = None
    prev_status:   Optional[str]          = None   # str for forward-compat
    new_status:    str
    # Timestamps — created_at = timestamp
    timestamp:     datetime               = Field(default_factory=datetime.utcnow)
    # Communication
    sent_to:       Optional[str]          = None
    received_from: Optional[str]          = None
    message:       Optional[str]          = None
    # Diagnostic level — "debug" logs go to capped realtime collection
    log_level:     str                    = "info"  # "debug" | "info" | "warning" | "error"


# ═══════════════════════════════════════════════════════════
#  COLLECTION: shell_sessions
# ═══════════════════════════════════════════════════════════

class ShellSession(BaseDocument):
    shell_type:  str
    lhost:       Optional[str] = None
    lport:       Optional[int] = None
    rhost:       str                    # remote (target) host — connection semantics
    # host (from BaseDocument) mirrors rhost for uniform per-host queries
    rport:       Optional[int] = None
    protocol:    str = "tcp"
    active:      bool     = False
    pid:         Optional[int] = None
    shell_user:  Optional[str] = None
    shell_cwd:   Optional[str] = None
    commands:    List[Dict[str, Any]] = []
    opened_at:   datetime = Field(default_factory=datetime.utcnow)
    closed_at:   Optional[datetime] = None


# ═══════════════════════════════════════════════════════════
#  COLLECTION: flags
# ═══════════════════════════════════════════════════════════

class Flag(BaseDocument):
    flag_type:   str             # "user" | "root" | "admin" | "custom"
    value:       str
    location:    str             # file path, URL, etc.
    found_by:    str             # agent name — str for forward-compat
    context:     Optional[str]  = None
    found_at:    datetime       = Field(default_factory=datetime.utcnow)
    # host is inherited from BaseDocument — which host this flag came from


# ═══════════════════════════════════════════════════════════
#  COLLECTION: credentials
# ═══════════════════════════════════════════════════════════

class Credential(BaseDocument):
    service:         str                    # "ssh" | "smb" | "http" | "ftp" | "mqtt" etc.
    username:        str
    password:        Optional[str]  = None
    hash_value:      Optional[str]  = None  # NTLM/LM/bcrypt hash
    hash_type:       Optional[str]  = None  # "ntlm" | "sha1" | "bcrypt"
    domain:          Optional[str]  = None
    source_tool:     Optional[str]  = None  # "hydra" | "secretsdump" etc.
    verified:        bool           = False
    privilege_level: Optional[str]  = None  # "admin" | "user" | "root"
    port:            Optional[int]  = None


# ═══════════════════════════════════════════════════════════
#  COLLECTION: subagent_results
# ═══════════════════════════════════════════════════════════

class SubagentResult(BaseDocument):
    subagent_name:   str
    parent_agent:    str
    status:          str              # "success" | "error" | "timeout" | "skipped"
    findings_count:  int              = 0
    findings_ids:    List[str]        = []
    raw_summary:     Optional[str]    = None
    duration_ms:     Optional[int]    = None
    error_message:   Optional[str]    = None
    tool_output_ids: List[str]        = []


# ═══════════════════════════════════════════════════════════
#  COLLECTION: persistence_mechanisms
# ═══════════════════════════════════════════════════════════

class PersistenceMechanism(BaseDocument):
    mechanism_type:  str              # "cron" | "registry" | "service" | "startup" | "rootkit"
    description:     str
    command:         Optional[str]    = None
    file_path:       Optional[str]    = None
    privilege_level: Optional[str]    = None
    removed:         bool             = False


# ═══════════════════════════════════════════════════════════
#  COLLECTION: attack_graph
# ═══════════════════════════════════════════════════════════

class AttackNode(BaseDocument):
    node_id:     str
    node_type:   str
    label:       str
    port:        Optional[int] = None
    severity:    Optional[str] = None
    metadata:    Dict[str, Any] = {}


class AttackEdge(BaseDocument):
    edge_id:     str
    source:      str
    target_node: str          # renamed from target to avoid collision with BaseDocument
    label:       str
    tool:        Optional[str] = None


# ═══════════════════════════════════════════════════════════
#  COLLECTION: osint_results
# ═══════════════════════════════════════════════════════════

class OsintResult(BaseDocument):
    query:       str
    source:      str
    title:       str
    url:         Optional[str]              = None
    summary:     str
    cves:        List[str]                  = []
    exploits:    List[str]                  = []
    severity:    Optional[str]              = None
    raw:         Optional[Dict[str, Any]]   = None
    relevance_score: float                  = 0.0
    fetched_at:  datetime                   = Field(default_factory=datetime.utcnow)


# ═══════════════════════════════════════════════════════════
#  COLLECTION: session_checkpoints
#  Pause/resume state snapshots
# ═══════════════════════════════════════════════════════════

class SessionCheckpoint(BaseModel):
    """Full serialized MasterAgent state for pause/resume."""
    id:                     str
    session_id:             str
    host:                   str                   # which host this checkpoint is for
    checkpoint_type:        str = CheckpointType.MANUAL_PAUSE
    schema_version:         int = 1

    # Execution position
    state_machine:          str                   # e.g. "EXPLOITATION"
    current_phase:          str                   # AttackPhase value
    phases_completed:       List[str]     = []
    phases_to_run:          List[str]     = []

    # Full intelligence snapshot — entire _intel dict
    intel_snapshot:         Dict[str, Any] = {}

    # Resume helpers
    used_tools:             Dict[str, int] = {}   # tool → run count
    pending_confirmations:  List[str]      = []   # phases awaiting confirm
    in_flight_subagents:    List[str]      = []   # subagents running at pause time

    # Agent configuration — enough to reconstruct MasterAgent
    master_config:          Dict[str, Any] = {}

    created_at:             datetime = Field(default_factory=datetime.utcnow)


# ═══════════════════════════════════════════════════════════
#  COLLECTION: session_archives
#  Lightweight summary for archived (>90 day old) sessions
# ═══════════════════════════════════════════════════════════

class SessionArchive(BaseModel):
    id:             str
    session_id:     str
    target_ip:      str
    session_mode:   str
    started_at:     datetime
    completed_at:   Optional[datetime]
    archived_at:    datetime = Field(default_factory=datetime.utcnow)
    # Summary counts
    findings_count: int = 0
    critical_count: int = 0
    high_count:     int = 0
    medium_count:   int = 0
    low_count:      int = 0
    flags_found:    List[str] = []
    hosts_tested:   List[str] = []
    # Inline report for fast retrieval without un-archiving
    report_html:    Optional[str] = None


# ═══════════════════════════════════════════════════════════
#  API REQUEST / RESPONSE SHAPES
# ═══════════════════════════════════════════════════════════

class StartPentestRequest(BaseModel):
    target_ip:          str
    target_hostname:    Optional[str] = None
    target_type:        str = "unknown"
    scope:              Optional[str] = None
    notes:              Optional[str] = None
    threading_enabled:  bool = False
    max_threads:        int  = 3
    phases:             List[str] = []
    auto_exploit:       bool = False
    confirm_web:        bool = False  # Show confirmation gate before web testing starts
    web_phase_timeout:  int  = 600    # Seconds before web phase emits time-extension popup (0 = no limit)
    max_parallel_hosts: int  = 5
    use_reasoning_loop: bool = False  # Enable hypothesis-driven reasoning engine


# ═══════════════════════════════════════════════════════════
#  REASONING ENGINE SCHEMAS
#  Collections: hypotheses, negative_memory, action_scores,
#               ranked_paths
# ═══════════════════════════════════════════════════════════

class HypothesisDocument(BaseDocument):
    """
    Collection: hypotheses
    One document per hypothesis generated by the HypothesisEngine.
    Confidence is updated as evidence is gathered.
    """
    hypothesis_id:            str
    statement:                str
    confidence:               float                   = 0.5
    evidence_supporting:      List[str]               = []
    required_evidence:        List[str]               = []
    recommended_next_actions: List[str]               = []
    attack_phase:             str                     = "initial_access"
    mitre_technique:          Optional[str]           = None
    validated:                bool                    = False
    invalidated:              bool                    = False
    iteration_number:         int                     = 0


class NegativeMemoryDocument(BaseDocument):
    """
    Collection: negative_memory
    One document per unique (tool, target_service) failure pair.
    attempt_count tracks how many times the same path was tried.
    """
    attempt_id:       str
    tool:             str
    args:             str                             = ""
    target_service:   str
    failure_reason:   str
    evidence:         str                             = ""
    hypothesis_id:    str                             = ""
    attempt_count:    int                             = 1


class ActionScoreEvent(BaseDocument):
    """
    Collection: action_scores
    Append-only audit log of every scoring event.
    Lets the operator review why the score moved.
    """
    action_id:        str
    delta:            int           # +10, -3, -5, etc.
    reason:           str
    running_total:    int
    tool:             str
    hypothesis_id:    str           = ""


class RankedPathDocument(BaseDocument):
    """
    Collection: ranked_paths
    Snapshot of ranked attack paths at each reasoning loop iteration.
    """
    iteration:        int
    paths:            List[Dict[str, Any]]            = []
    top_path_score:   float                           = 0.0
    top_path_id:      str                             = ""


class PauseRequest(BaseModel):
    save_checkpoint: bool = True


class ResumeRequest(BaseModel):
    checkpoint_id: Optional[str] = None   # None = use latest checkpoint


class AgentStatusUpdate(BaseModel):
    agent:    str           # str for forward-compat
    status:   AgentStatus
    phase:    str
    message:  str
    tool:     Optional[str] = None


class WebSocketMessage(BaseModel):
    type:       str
    session_id: str
    agent:      Optional[str] = None
    data:       Dict[str, Any]
    timestamp:  datetime = Field(default_factory=datetime.utcnow)
    host_id:    Optional[str] = None
