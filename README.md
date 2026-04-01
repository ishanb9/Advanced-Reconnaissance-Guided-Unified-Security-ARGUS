# ARGUS — Advanced Reconnaissance & Guided Unified Security

An AI-driven autonomous penetration testing platform. ARGUS orchestrates a fleet of specialist agents through a full pentest lifecycle, powered by a local LLM (Ollama), with a real-time React dashboard for operator oversight.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                  React Frontend (port 5001)          │
│  MissionControl · FindingsBoard · ShellManager      │
│  AttackGraph · OsintIntel · PayloadBuilder · ...    │
└────────────────────┬────────────────────────────────┘
                     │  REST + WebSocket
┌────────────────────▼────────────────────────────────┐
│             agent_server.py  (FastAPI)               │
│  Session management · WS broadcast · Shell PTY       │
└──┬─────────────┬──────────────┬──────────────────────┘
   │             │              │
   ▼             ▼              ▼
MasterAgent  CIDROrchestrator  ShellAgent / PayloadAgent
   │
   │  AgentBus (pub/sub)
   ▼
Specialist Slave Agents (recon, vuln, web, exploit, post, privesc, ...)
   │
   ▼
MongoDB  (argus_pentest)  +  Ollama LLM  +  MCP Tool Server
```

**MasterAgent** is the sole LLM interface. It plans each phase, issues typed `Instruction` objects to slave agents via `AgentBus`, collects results, and re-consults the LLM to decide next steps. All reasoning is streamed to the frontend in real time.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+, FastAPI, Uvicorn |
| Frontend | React 18 (CDN, no build step), Babel standalone |
| Database | MongoDB 7+ via Motor (async) |
| LLM | Ollama (configurable model, default `glm-5:cloud`) |
| Tool execution | MCP server (`mcp-server.js`, port 3000) |
| Shell PTY | WebSocket + `pty` / `subprocess` |
| Payloads | msfvenom wrapper |
| Reports | Jinja2 HTML → optional PDF |

---

## Pentest Methodology

ARGUS follows the Standard Penetration testing methodology:

```
RECON → ENUM → VULN_ID → WEB_TESTING → EXPLOIT → POST_EXPLOIT → PRIVESC → REPORTING
```

Optional phases (auto-enabled based on target type):
- `OSINT` · `LATERAL` · `EVASION` · `EVIDENCE` · `WIRELESS` · `IOT` · `CLOUD` · `CONTAINER` · `TRAFFIC` · `FORENSICS`

---

## Agent Fleet

### Orchestration
| Agent | Role |
|-------|------|
| `MasterAgent` | LLM-driven planner; sole LLM interface |
| `CIDROrchestrator` | Manages parallel scans across CIDR/multi-target sessions |
| `AttackGraphAgent` | Builds live attack graph from findings |

### Specialist Agents (Slave)
| Domain | Subagents |
|--------|-----------|
| **Recon** | DNS recon, network scan, service banner, web fingerprint |
| **Vuln** | CVE lookup, SMB, SSH, SSL, LDAP, FTP, service vuln |
| **Web** | Dir fuzz, SQLi, XSS, SSRF, auth bypass, broken access control, CMS, injection, Burp integration |
| **Exploit** | Metasploit, searchsploit, exploit chain, credential spray, post-module |
| **Post-Exploit** | Local cred harvest, persistence, data exfil, C2 deploy, log evasion |
| **Privesc** | Linux/Windows enum & exploit, container escape, cloud metadata |
| **Lateral** | AD enum, Kerberos, NTLM capture |
| **Evasion** | AMSI bypass, defense enumeration |
| **Evidence** | Flag capture, screenshot, artifact collection |
| **Forensics** | Memory analysis, timeline, artifact collect |
| **Cloud** | AWS, Azure, GCP enumeration |
| **Container** | Docker audit, Kubernetes audit |
| **Wireless** | WiFi scan, WPA2 crack, evil twin |
| **IoT** | Device scan, default creds, firmware, protocol |
| **Traffic** | PCAP capture, MITM, credential sniff |
| **OSINT** | Open-source intelligence gathering |
| **Shell** | PTY shell management |
| **Payload** | msfvenom payload generation |

---

## Session Modes

| Mode | Description |
|------|-------------|
| **Single target** | One IP/hostname — full sequential methodology |
| **CIDR / multi-target** | Subnet or comma-separated IPs — `CIDROrchestrator` fans out parallel `MasterAgent` instances with configurable concurrency |

---

## Key Features

### Real-time Dashboard
- Live phase timeline (Gantt-style) with per-step status
- Attack tree / attack graph visualization
- Findings board with severity filtering
- Agent console (per-agent log streaming)
- OSINT intel panel
- Shell manager (interactive PTY shells over WebSocket)
- Payload builder (msfvenom)
- Lateral/post-exploit tracker (credentials, tunnels, persistence)
- Subagent console
- MITRE ATT&CK mapping
- AI observability (LLM reasoning trace)
- Metrics dashboard

### Pause & Resume
- Pause a running scan at any phase boundary
- Full agent state serialized to `session_checkpoints` in MongoDB
- Resume restores all phase results and continues from the next phase
- No LLM re-planning on resume; plan is cached in the checkpoint
- Plan steps retain their done/active/pending status in the UI (never reset)

### Session Archiving
- Archive completed sessions (moved to `archived_*` collections)
- Inline report HTML stored in `session_archives`
- Unarchive at any time

### Knowledge Base (RAG)
- Ingest pentest playbooks, command references, technique guides
- Injected as context into LLM prompts per-phase
- Searchable from the UI (Knowledge page)

### Long-term Memory
- Store and recall cross-session findings and patterns
- `/memory/store`, `/memory/recall`, `/memory/stats` endpoints

### Manual Control
- Tool Workshop: run any tool manually with live streaming output
- Subagent Console: trigger any registered subagent on demand
- Operator guidance: inject freeform guidance mid-scan
- Human-in-the-loop phase confirmations (optional)

---

## Database Schema

MongoDB database: **`argus_pentest`**

| Collection | Contents |
|-----------|----------|
| `sessions` | Session metadata, status, config |
| `findings` | Vulnerabilities with severity, CVSS, MITRE tags |
| `agent_logs` | Full agent action log (TTL: 90 days) |
| `agent_logs_realtime` | Capped 100MB ring buffer for live streaming |
| `tool_outputs` | Raw tool stdout/stderr (64KB cap, TTL: 180 days) |
| `shell_sessions` | PTY shell state |
| `flags` | CTF-style captured flags |
| `osint_results` | OSINT findings |
| `attack_trees` | Attack tree snapshots |
| `chain_analyses` | Exploit chain analysis |
| `rag_history` | LLM conversation history (TTL: 30 days) |
| `credentials` | Harvested credentials |
| `tunnels` | Active tunnel state |
| `persistence` | Persistence mechanism records |
| `lateral_movement` | Lateral movement records |
| `session_checkpoints` | Pause/resume state (auto-checkpoints TTL: 30 days) |
| `archived_sessions` | Archived session metadata |
| `session_archives` | Archived session report HTML |

---

## Installation

### Prerequisites
- Python 3.11+
- MongoDB 7+ (running on `localhost:27017`)
- Node.js (for MCP server)
- Ollama with a model loaded (default: `glm-5:cloud`)
- Kali Linux or equivalent (for pentest tools: nmap, metasploit, etc.)

### Setup

```bash
# 1. Install Python dependencies
pip install -r requirements.txt --break-system-packages

# 2. Install MCP server dependencies
npm install

# 3. Set environment variables (optional — defaults shown)
export OLLAMA_URL=http://192.168.0.100:11434
export OLLAMA_MODEL=glm-5:cloud
export MONGO_URI=mongodb://localhost:27017

# 4. Start the MCP tool server
node mcp-server.js &

# 5. Start the agent server
python agent_server.py
```

Access the dashboard at: **http://localhost:5001**

---

## API Reference

### Sessions
| Method | Endpoint | Description |
|--------|---------|-------------|
| `POST` | `/sessions` | Create & start a new pentest session |
| `GET` | `/sessions` | List all sessions |
| `GET` | `/sessions/{id}` | Get session detail |
| `POST` | `/sessions/{id}/stop` | Stop a session |
| `POST` | `/sessions/{id}/pause` | Pause at next phase boundary |
| `POST` | `/sessions/{id}/resume` | Resume from latest checkpoint |
| `DELETE` | `/sessions/{id}` | Delete session and all data |
| `POST` | `/sessions/{id}/archive` | Archive session |
| `POST` | `/sessions/{id}/unarchive` | Unarchive session |
| `GET` | `/sessions/{id}/checkpoints` | List checkpoints |

### Session Data
| Method | Endpoint | Description |
|--------|---------|-------------|
| `GET` | `/sessions/{id}/findings` | Findings (filterable by severity/phase) |
| `GET` | `/sessions/{id}/logs` | Agent logs |
| `GET` | `/sessions/{id}/tool-outputs` | Tool stdout/stderr |
| `GET` | `/sessions/{id}/hosts` | Multi-host scan status |
| `GET` | `/sessions/{id}/shells` | Active shells |
| `GET` | `/sessions/{id}/credentials` | Harvested credentials |
| `GET` | `/sessions/{id}/attack-tree` | Attack tree |
| `GET` | `/sessions/{id}/mitre` | MITRE ATT&CK mapping |
| `GET` | `/sessions/{id}/report?format=html` | Generated report |

### Tools & Shells
| Method | Endpoint | Description |
|--------|---------|-------------|
| `GET` | `/tools` | List available tools |
| `GET` | `/tools/stream` | Stream tool execution (SSE) |
| `POST` | `/shells/create` | Create a new PTY shell |
| `POST` | `/shells/{id}/cmd` | Send command to shell |
| `POST` | `/payloads/generate` | Generate msfvenom payload |

### WebSocket
```
ws://localhost:5001/ws/{session_id}
```
Streams all agent events in real time. The frontend subscribes on session activation.

---

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `OLLAMA_URL` | `http://192.168.0.100:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `glm-5:cloud` | Model name to use |
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection string |

---

## Frontend Pages

| Page | Route fragment | Description |
|------|---------------|-------------|
| Target Config | `#target` | Configure target, mode, scope, options |
| Mission Control | `#mission` | Live scan dashboard — primary operator view |
| Findings Board | `#findings` | All findings, filterable, exportable |
| Shell Manager | `#shells` | Interactive PTY shells |
| Payload Builder | `#payloads` | msfvenom payload generation |
| OSINT Intel | `#osint` | OSINT results panel |
| Lateral/Post | `#lateral` | Credentials, tunnels, persistence |
| Attack Graph | `#graph` | Visual attack path graph |
| Agent Console | `#agents` | Per-agent log view |
| Subagent Console | `#subagents` | Manual subagent execution |
| Tool Workshop | `#tools` | Manual tool execution |
| Knowledge Base | `#knowledge` | RAG knowledge ingestion & search |
| Report | `#report` | Generated pentest report |
| Session History | `#history` | All past sessions |
| Metrics | `#metrics` | Platform performance metrics |
| AI Observability | `#observability` | LLM reasoning trace |

---

## Disclaimer

ARGUS is intended for **authorized penetration testing only**. Use only against systems you own or have explicit written permission to test. Unauthorized use against third-party systems is illegal.
