"""
KALI PENTEST PLATFORM v2 — Database Schemas
Pydantic models mapping to MongoDB collections.
All IDs are strings (MongoDB ObjectId serialized as str).
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ═══════════════════════════════════════════════════════════
#  ENUMERATIONS
# ═══════════════════════════════════════════════════════════

class AttackPhase(str, Enum):
    """Standard penetration testing lifecycle phases."""
    RECON        = "recon"           # Network/app reconnaissance
    SCAN         = "scan"            # Port/service scanning
    VULN_ID      = "vuln_id"         # Vulnerability identification
    OSINT        = "osint"           # Internet intel gathering
    EXPLOIT      = "exploit"         # Initial foothold
    POST_EXPLOIT = "post_exploit"    # Post-exploitation
    PRIVESC      = "privesc"         # Privilege escalation
    PERSISTENCE  = "persistence"     # Maintaining access
    REPORTING    = "reporting"       # Evidence collection
    # ── Specialist phases (v3) ────────────────────────────────
    LATERAL      = "lateral"         # Lateral movement (AD/Kerberos/NTLM)
    CLOUD        = "cloud"           # Cloud infrastructure enumeration
    CONTAINER    = "container"       # Docker/Kubernetes security audit
    EVASION      = "evasion"         # AV/EDR evasion techniques
    TRAFFIC      = "traffic"         # Passive traffic capture & credential sniff
    EVIDENCE     = "evidence"        # Screenshot/flag capture (EvidenceAgent)
    FORENSICS    = "forensics"       # Digital forensics (artifacts/timeline/memory)
    WIRELESS     = "wireless"        # Wireless assessment (WiFi/WPA2/EvilTwin)
    IOT          = "iot"             # IoT device enumeration & exploitation


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
    """How the target was specified."""
    SINGLE = "single"   # Single IP or hostname
    CIDR   = "cidr"     # CIDR range e.g. 192.168.1.0/24
    MULTI  = "multi"    # Comma-separated list of IPs


class AgentStatus(str, Enum):
    IDLE     = "idle"
    THINKING = "thinking"   # LLM processing
    RUNNING  = "running"    # Tool executing
    WAITING  = "waiting"    # Waiting for dependency
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


# ═══════════════════════════════════════════════════════════
#  COLLECTION: sessions
#  One document per pentest engagement
# ═══════════════════════════════════════════════════════════

class SessionCreate(BaseModel):
    target_ip:          str
    target_hostname:    Optional[str] = None
    target_type:        str = "unknown"          # linux, windows, web, ctf, iot
    scope:              Optional[str] = None     # CIDR or URL list
    notes:              Optional[str] = None
    threading_enabled:  bool = False
    max_threads:        int  = 3
    # Multi-target fields
    session_mode:       SessionMode = SessionMode.SINGLE
    max_parallel_hosts: int  = 5               # semaphore bound for parallel host testing


class Session(SessionCreate):
    id:               str
    status:           SessionStatus = SessionStatus.ACTIVE
    current_phase:    AttackPhase   = AttackPhase.RECON
    phases_completed: List[str]     = []
    started_at:       datetime      = Field(default_factory=datetime.utcnow)
    updated_at:       datetime      = Field(default_factory=datetime.utcnow)
    completed_at:     Optional[datetime] = None
    # Summary stats (updated live)
    findings_count:   int = 0
    tools_run:        int = 0
    flags_found:      List[str] = []
    # Multi-host tracking (populated by CIDROrchestrator)
    discovered_hosts: List[str] = []           # live IPs found during host-discovery
    hosts_completed:  List[str] = []           # subset that finished all phases
    host_count:       int = 0                  # len(discovered_hosts)


# ═══════════════════════════════════════════════════════════
#  COLLECTION: findings
#  Every vulnerability or notable finding
# ═══════════════════════════════════════════════════════════

class Finding(BaseModel):
    id:          str
    session_id:  str
    agent:       AgentName
    phase:       AttackPhase
    severity:    FindingSeverity
    title:       str
    description: str
    # Target info
    host:        str
    port:        Optional[int]    = None
    service:     Optional[str]    = None
    protocol:    Optional[str]    = None
    # CVE / exploit info
    cves:        List[str]        = []       # ["CVE-2021-44228", ...]
    exploits:    List[str]        = []       # exploit-db IDs or MSF modules
    # Evidence
    tool_used:   Optional[str]    = None
    raw_output:  Optional[str]    = None
    screenshot:  Optional[str]    = None     # base64 or file path
    # Remediation
    remediation: Optional[str]    = None
    # Timestamps
    found_at:    datetime = Field(default_factory=datetime.utcnow)
    verified:    bool     = False
    # Extra fields (flexible NoSQL advantage)
    extra:       Dict[str, Any] = {}


# ═══════════════════════════════════════════════════════════
#  COLLECTION: tool_outputs
#  Raw stdout/stderr from every tool execution
# ═══════════════════════════════════════════════════════════

class ToolOutput(BaseModel):
    id:          str
    session_id:  str
    agent:       AgentName
    phase:       AttackPhase
    tool_name:   str
    command:     str                         # Full command string
    target:      Optional[str] = None
    # Output
    stdout:      str   = ""
    stderr:      str   = ""
    exit_code:   Optional[int] = None
    # Parsed summary (LLM-generated)
    summary:     Optional[str] = None
    key_findings: List[str]    = []          # Extracted highlights
    # Timing
    started_at:  datetime = Field(default_factory=datetime.utcnow)
    ended_at:    Optional[datetime] = None
    duration_ms: Optional[int]     = None
    # Thread info
    thread_id:   Optional[str] = None


# ═══════════════════════════════════════════════════════════
#  COLLECTION: agent_logs
#  Agent reasoning, decisions, and status changes
# ═══════════════════════════════════════════════════════════

class AgentLog(BaseModel):
    id:          str
    session_id:  str
    agent:       AgentName
    phase:       AttackPhase
    # What the agent decided
    action:      str              # "decided_to_run_nmap", "escalated_to_master", etc.
    reasoning:   str              # LLM reasoning text
    tool:        Optional[str] = None
    # Status change
    prev_status: Optional[AgentStatus] = None
    new_status:  AgentStatus
    # Timestamps
    timestamp:   datetime = Field(default_factory=datetime.utcnow)
    # Communication between agents
    sent_to:     Optional[AgentName]   = None   # message target
    received_from: Optional[AgentName] = None   # message source
    message:     Optional[str]         = None


# ═══════════════════════════════════════════════════════════
#  COLLECTION: shell_sessions
#  Active and historic shell/reverse-shell connections
# ═══════════════════════════════════════════════════════════

class ShellSession(BaseModel):
    id:          str
    session_id:  str             # parent pentest session
    agent:       AgentName = AgentName.SHELL
    shell_type:  str             # "reverse_shell", "bind_shell", "web_shell", "ssh"
    # Connection info
    lhost:       Optional[str] = None    # listener host
    lport:       Optional[int] = None    # listener port
    rhost:       str                     # remote (target) host
    rport:       Optional[int] = None
    protocol:    str = "tcp"
    # State
    active:      bool     = False
    pid:         Optional[int] = None    # local process PID
    # Context
    shell_user:  Optional[str] = None    # user on target
    shell_cwd:   Optional[str] = None    # current directory
    # History
    commands:    List[Dict[str, Any]] = []  # [{cmd, output, ts}]
    # Timestamps
    opened_at:   datetime = Field(default_factory=datetime.utcnow)
    closed_at:   Optional[datetime] = None


# ═══════════════════════════════════════════════════════════
#  COLLECTION: flags
#  CTF flags and sensitive data discovered
# ═══════════════════════════════════════════════════════════

class Flag(BaseModel):
    id:          str
    session_id:  str
    flag_type:   str             # "user", "root", "admin", "custom"
    value:       str             # The actual flag text
    location:    str             # Where found (file path, URL, etc.)
    found_by:    AgentName
    context:     Optional[str] = None    # How it was found
    found_at:    datetime = Field(default_factory=datetime.utcnow)


# ═══════════════════════════════════════════════════════════
#  COLLECTION: attack_graph
#  Nodes and edges for attack path visualization
# ═══════════════════════════════════════════════════════════

class AttackNode(BaseModel):
    node_id:     str
    session_id:  str
    node_type:   str             # "host", "service", "vulnerability", "exploit", "access"
    label:       str
    phase:       AttackPhase
    host:        Optional[str] = None
    port:        Optional[int] = None
    severity:    Optional[FindingSeverity] = None
    metadata:    Dict[str, Any] = {}
    created_at:  datetime = Field(default_factory=datetime.utcnow)

class AttackEdge(BaseModel):
    edge_id:     str
    session_id:  str
    source:      str             # node_id
    target:      str             # node_id
    label:       str             # "exploited", "leads_to", "discovered", etc.
    tool:        Optional[str] = None
    created_at:  datetime = Field(default_factory=datetime.utcnow)


# ═══════════════════════════════════════════════════════════
#  COLLECTION: osint_results
#  Internet-sourced intelligence
# ═══════════════════════════════════════════════════════════

class OsintResult(BaseModel):
    id:          str
    session_id:  str
    query:       str             # What was searched
    source:      str             # "nvd", "exploit_db", "shodan", "web", "cvedetails"
    # Content
    title:       str
    url:         Optional[str]   = None
    summary:     str
    cves:        List[str]       = []
    exploits:    List[str]       = []
    severity:    Optional[FindingSeverity] = None
    raw:         Optional[Dict[str, Any]] = None
    # Relevance
    relevance_score: float = 0.0    # 0-1, how relevant to target
    # Timestamps
    fetched_at:  datetime = Field(default_factory=datetime.utcnow)


# ═══════════════════════════════════════════════════════════
#  API MODELS — Request/Response shapes
# ═══════════════════════════════════════════════════════════

class StartPentestRequest(BaseModel):
    target_ip:          str
    target_hostname:    Optional[str] = None
    target_type:        str = "unknown"
    scope:              Optional[str] = None
    notes:              Optional[str] = None
    threading_enabled:  bool = False
    max_threads:        int  = 3
    phases:             List[str] = []    # empty = all phases
    auto_exploit:       bool = False      # require confirmation before exploiting
    max_parallel_hosts: int  = 5         # max concurrent hosts (CIDR/multi mode)

class AgentStatusUpdate(BaseModel):
    agent:    AgentName
    status:   AgentStatus
    phase:    AttackPhase
    message:  str
    tool:     Optional[str] = None

class WebSocketMessage(BaseModel):
    """Standard WebSocket event structure."""
    type:       str              # "agent_status", "tool_output", "finding", "log", "phase_change", "shell"
    session_id: str
    agent:      Optional[str] = None
    data:       Dict[str, Any]
    timestamp:  datetime = Field(default_factory=datetime.utcnow)
    # Multi-host: which specific IP this event belongs to (None = session-wide)
    host_id:    Optional[str] = None
