// ═══════════════════════════════════════════════════════════
// ARGUS Pentest Platform — Global Store
// ─── Fixes in this version ─────────────────────────────────
//  1. normalizeAgent(): "AgentName.RECON" → "recon"
//  2. normalizePhase(): "AttackPhase.RECON" → "recon"
//  3. state_change event routed → phase + completed update
//  4. attack_tree_ready / evidence events handled
//  5. parallel_intel event shows all agents active at once
//  6. Session delete updates sessions list
// ─── v3 additions ──────────────────────────────────────────
//  7. 11 new state slices: credentials, tunnels, persistence,
//     lateralFindings, cloudFindings, containerFindings,
//     wirelessEvents, trafficCaptures, subagentStates,
//     ragHistory, llmThoughts
//  8. New WS event handlers for subagent lifecycle, credential
//     discovery, tunnels, persistence, burp, attack chains,
//     and privesc success
// ═══════════════════════════════════════════════════════════

const { createContext, useContext, useReducer, useEffect, useCallback, useRef } = React;

// ─── Normalisers ───────────────────────────────────────────
// Backend sends Python enum strings: "AgentName.RECON", "AttackPhase.VULN_ID"
// We strip the prefix and lowercase to get the store key.
function normalizeAgent(raw) {
  if (!raw) return null;
  const s = String(raw);
  // "AgentName.RECON" → "recon", "agentname.master" → "master"
  const dot = s.lastIndexOf('.');
  const key = dot >= 0 ? s.slice(dot + 1) : s;
  return key.toLowerCase();
}

function normalizePhase(raw) {
  if (!raw) return null;
  const s = String(raw);
  // "AttackPhase.VULN_ID" → "vuln_id", "recon" → "recon"
  const dot = s.lastIndexOf('.');
  const key = dot >= 0 ? s.slice(dot + 1) : s;
  return key.toLowerCase();
}

// ─── Initial state ─────────────────────────────────────────
const INIT = {
  sessions:       [],
  activeSession:  null,
  sessionId:      null,

  sysStatus: { mcp: 'unknown', mongo: 'unknown', ollama: 'unknown' },
  llmStatus: { available: null, url: '', model: '', message: '' },

  agents: {
    master:  { status: 'idle', phase: null, message: '' },
    recon:   { status: 'idle', phase: null, message: '' },
    vuln:    { status: 'idle', phase: null, message: '' },
    web:     { status: 'idle', phase: null, message: '' },
    osint:   { status: 'idle', phase: null, message: '' },
    exploit: { status: 'idle', phase: null, message: '' },
    privesc: { status: 'idle', phase: null, message: '' },
    iot:     { status: 'idle', phase: null, message: '' },
    shell:   { status: 'idle', phase: null, message: '' },
    payload: { status: 'idle', phase: null, message: '' },
  },

  // State machine (new architecture)
  smState:        'INIT',   // current state machine state from backend

  currentPhase:    'idle',
  phasesCompleted: [],
  feedEntries:     [],
  reasoningLog:    [],
  toolOutputs:     {},
  findingsSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
  flags:           [],
  shells:          [],
  payloads:        [],

  graphNodes: [],
  graphEdges: [],

  // Attack chain analyses produced by AttackGraphAgent
  chainAnalysis:      null,   // latest full analysis object
  chainAnalysisStatus: null,  // {status, message} from agent

  // ── Multi-host / CIDR state ─────────────────────────────
  sessionMode:       'single',  // 'single' | 'cidr' | 'multi'
  discoveredHosts:   [],        // [{ip, status, findings_count, severity_counts}]
  hostFilter:        null,      // null = show all; 'x.x.x.x' = filter to this host

  // New architecture state
  attackTree:   null,   // attack planner output
  mitreMap:     [],     // [{id, tactic, name, tool}]
  evidence:     [],     // structured evidence items
  memoryHits:   0,      // long-term memory hits this session

  shellBuffers: {},
  wsConnected:  false,
  llmThinking:  false,
  lastLlmResponse: '',

  // Attack plan tracking — each step in the master strategy with live status
  planSteps:      [],   // [{id, label, technique, tool, mitre_id, probability, status, result, detail, found, ts}]
  planHypothesis: '',   // Master's attack hypothesis from initial plan
  planAssessment: '',   // Assessment type (ctf, network, web, etc.)

  // Agent communications — per-agent log of LLM and RAG interactions
  agentComms: {
    // agent_name -> [{type:'llm'|'rag', prompt, response, ts, phase, found}]
    master: [], recon: [], vuln: [], web: [],
    osint: [], exploit: [], privesc: [], shell: [], payload: []
  },

  // ── v3 new state slices ───────────────────────────────────
  credentials:      [],  // [{id, user, host, service, type, secret, found_by, timestamp}]
  tunnels:          [],  // [{id, type, local_port, remote_host, remote_port, active}]
  persistenceItems: [],  // [{id, type, host, mechanism, trigger, user}]
  lateralFindings:  [],  // lateral movement specific findings
  cloudFindings:    [],  // cloud security findings
  containerFindings:[], // container escape findings
  wirelessEvents:   [],  // wireless attack events
  trafficCaptures:  [],  // network traffic captures
  subagentStates:   {},  // {subagent_name: {status, findings_count, duration, target}}
  subagentLines:    {},  // {subagent_name: [{tool, line, ts}]}  — live tool output per subagent
  ragHistory:       [],  // [{query, results, timestamp}]
  llmThoughts:      [],  // [{agent, thought, timestamp}]

  // Operator console state
  operatorMode:     'guided',   // 'guided' | 'auto'
  guidanceHistory:  [],         // [{directive, note, tool, dns_host, ts}] — last 20

  // Tool timeout popup — set when a tool exceeds its deadline
  toolTimeoutWarning: null,     // null | {tool, subagent, elapsed_sec, deadline_sec}

  // Phase time-extension popup — set when a phase hits its operator-configured timeout
  phaseTimeExtension: null,     // null | {phase, timeout_secs, message}

  // Web testing confirmation gate — set when confirm_web=true and web phase is ready
  webConfirmPending:  false,
};

// ─── Selectors / derived state helpers ─────────────────────
// These are pure functions — call them with state to get derived data.

/** Returns credentials sorted newest first */
function selectCredentialsSorted(state) {
  return [...state.credentials].sort((a, b) =>
    new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
}

/** Returns count of subagents by status */
function selectSubagentCounts(state) {
  const counts = { running: 0, complete: 0, error: 0, idle: 0 };
  Object.values(state.subagentStates).forEach(s => {
    const k = s.status || 'idle';
    if (counts[k] !== undefined) counts[k]++;
    else counts.idle++;
  });
  return counts;
}

/** Returns total findings across all subagents */
function selectSubagentTotalFindings(state) {
  return Object.values(state.subagentStates)
    .reduce((acc, s) => acc + (s.findings_count || 0), 0);
}

/** Returns critical/admin credentials */
function selectHighValueCreds(state) {
  const adminUsers = ['root', 'admin', 'administrator', 'sa', 'system', 'sudo'];
  return state.credentials.filter(c =>
    adminUsers.some(a => (c.user || '').toLowerCase().includes(a)));
}

window.storeSelectors = {
  credentialsSorted:      selectCredentialsSorted,
  subagentCounts:         selectSubagentCounts,
  subagentTotalFindings:  selectSubagentTotalFindings,
  highValueCreds:         selectHighValueCreds,
};

// ─── Reducer ───────────────────────────────────────────────
function reducer(state, action) {
  switch (action.type) {

    case 'SET_SESSIONS':
      return { ...state, sessions: action.payload };

    case 'REMOVE_SESSION':
      return { ...state,
        sessions: state.sessions.filter(s => s.id !== action.payload),
        // clear active session if it was deleted
        activeSession: state.activeSession?.id === action.payload ? null : state.activeSession,
        sessionId:     state.sessionId         === action.payload ? null : state.sessionId,
      };

    case 'SET_SESSION':
      return { ...state, activeSession: action.payload, sessionId: action.payload?.id || null };

    // Patch only the status field of the active session without needing full state access
    case 'UPDATE_SESSION_STATUS':
      if (!state.activeSession) return state;
      return { ...state, activeSession: { ...state.activeSession, status: action.payload } };

    case 'SET_SYS_STATUS':
      return { ...state, sysStatus: { ...state.sysStatus, ...action.payload } };

    case 'SET_LLM_STATUS':
      return { ...state, llmStatus: { ...state.llmStatus, ...action.payload } };

    case 'LLM_THINKING':
      return { ...state, llmThinking: action.payload };

    case 'LLM_RESPONSE':
      return { ...state, llmThinking: false, lastLlmResponse: action.payload };

    case 'AGENT_STATUS': {
      const { agent, status, phase, message } = action.payload;
      if (!agent) return state;
      const key = normalizeAgent(agent);
      if (!key) return state;
      return { ...state, agents: { ...state.agents,
        [key]: { status: status || 'idle', phase: normalizePhase(phase), message: message || '' }
      }};
    }

    case 'PHASE_CHANGE': {
      const phase = normalizePhase(action.payload.phase);
      return { ...state, currentPhase: phase || state.currentPhase };
    }

    case 'PHASE_DONE': {
      const phase = normalizePhase(action.payload.phase);
      if (!phase) return state;
      const done = [...state.phasesCompleted];
      if (!done.includes(phase)) done.push(phase);
      return { ...state, phasesCompleted: done };
    }

    // State machine transition (new)
    case 'STATE_CHANGE': {
      const newSm = String(action.payload.to || '').toUpperCase();
      // Also update currentPhase if the SM state maps to a phase
      const smToPhase = {
        'RECON':                    'recon',
        'INTELLIGENCE_AGGREGATION': 'vuln_id',
        'VULNERABILITY_ANALYSIS':   'vuln_id',
        'ATTACK_PLANNING':          'exploit',
        'EXPLOITATION':             'exploit',
        'POST_EXPLOITATION':        'post_exploit',
        'PRIVILEGE_ESCALATION':     'privesc',
        'LATERAL_MOVEMENT':         'post_exploit',
        'EVIDENCE_COLLECTION':      'reporting',
        'REPORT_GENERATION':        'reporting',
        'COMPLETE':                 'reporting',
      };
      const mappedPhase = smToPhase[newSm] || state.currentPhase;
      // Mark previous phase done
      const done = [...state.phasesCompleted];
      if (state.currentPhase && !done.includes(state.currentPhase) && state.currentPhase !== mappedPhase) {
        done.push(state.currentPhase);
      }
      return { ...state, smState: newSm, currentPhase: mappedPhase, phasesCompleted: done };
    }

    case 'FEED_ENTRY': {
      const entries = [action.payload, ...state.feedEntries].slice(0, 500);
      return { ...state, feedEntries: entries };
    }

    case 'REASONING_ENTRY': {
      const entries = [action.payload, ...state.reasoningLog].slice(0, 200);
      return { ...state, reasoningLog: entries };
    }

    case 'TOOL_LINE': {
      const { agent, line, lineType } = action.payload;
      if (!agent) return state;
      const key = normalizeAgent(agent);
      const prev = state.toolOutputs[key] || [];
      const next = [...prev, { line, type: lineType || 'stdout', ts: Date.now() }].slice(-2000);
      return { ...state, toolOutputs: { ...state.toolOutputs, [key]: next } };
    }

    case 'FINDING_ADDED': {
      const sev = (action.payload.severity || 'info').toLowerCase();
      const s   = { ...state.findingsSummary };
      if (s[sev] !== undefined) s[sev]++;
      s.total = (s.total || 0) + 1;
      return { ...state, findingsSummary: s };
    }

    case 'SET_FINDINGS_SUMMARY':
      return { ...state, findingsSummary: action.payload };

    case 'FLAG_FOUND':
      return { ...state, flags: [...state.flags, action.payload] };

    case 'SET_FLAGS':
      return { ...state, flags: action.payload };

    // ── Attack Graph ─────────────────────────────────────
    case 'GRAPH_NODE': {
      // Normalize: always use node_id as the canonical key
      const node = { ...action.payload };
      if (!node.node_id && node.id) node.node_id = node.id;
      const exists = state.graphNodes.find(n => n.node_id === node.node_id);
      if (exists) return { ...state, graphNodes: state.graphNodes.map(n => n.node_id === node.node_id ? {...n,...node} : n) };
      return { ...state, graphNodes: [...state.graphNodes, node] };
    }
    case 'GRAPH_EDGE': {
      const edge = { ...action.payload };
      if (!edge.edge_id && edge.id) edge.edge_id = edge.id;
      const exists = state.graphEdges.find(e => e.edge_id === edge.edge_id);
      if (exists) return state;
      return { ...state, graphEdges: [...state.graphEdges, edge] };
    }
    case 'SET_GRAPH':
      return { ...state, graphNodes: action.payload.nodes || [], graphEdges: action.payload.edges || [] };

    // ── New architecture ──────────────────────────────────
    case 'ATTACK_TREE_READY':
      return { ...state, attackTree: action.payload };

    case 'MITRE_MAPPED': {
      const existing = state.mitreMap.find(t => t.id === action.payload.id);
      if (existing) return state;
      return { ...state, mitreMap: [...state.mitreMap, action.payload] };
    }

    case 'CHAIN_ANALYSIS':
      return { ...state, chainAnalysis: action.payload };

    case 'CHAIN_ANALYSIS_STATUS':
      return { ...state, chainAnalysisStatus: action.payload };

    // ── Multi-host reducers ───────────────────────────────
    case 'SET_SESSION_MODE':
      return { ...state, sessionMode: action.payload };

    case 'HOST_DISCOVERED': {
      const ip = action.payload.host;
      const already = state.discoveredHosts.some(h => h.ip === ip);
      if (already) return state;
      return {
        ...state,
        discoveredHosts: [...state.discoveredHosts, {
          ip,
          status:          'scanning',
          findings_count:  0,
          severity_counts: { critical:0, high:0, medium:0, low:0, info:0 },
        }],
      };
    }

    case 'HOST_DISCOVERY_COMPLETE': {
      const hosts = (action.payload.hosts || []).map(ip => ({
        ip,
        status:          'scanning',
        findings_count:  0,
        severity_counts: { critical:0, high:0, medium:0, low:0, info:0 },
      }));
      return { ...state, discoveredHosts: hosts };
    }

    case 'HOST_COMPLETE': {
      const ip = action.payload.host;
      return {
        ...state,
        discoveredHosts: state.discoveredHosts.map(h =>
          h.ip === ip ? { ...h, status: 'complete' } : h
        ),
      };
    }

    case 'HOST_FINDING_COUNT': {
      const { host: hIp, severity } = action.payload;
      return {
        ...state,
        discoveredHosts: state.discoveredHosts.map(h => {
          if (h.ip !== hIp) return h;
          const sev = (severity || 'info').toLowerCase();
          return {
            ...h,
            findings_count: h.findings_count + 1,
            severity_counts: {
              ...h.severity_counts,
              [sev]: (h.severity_counts[sev] || 0) + 1,
            },
          };
        }),
      };
    }

    case 'CIDR_SCAN_COMPLETE':
      return {
        ...state,
        discoveredHosts: state.discoveredHosts.map(h => ({ ...h, status: 'complete' })),
      };

    case 'SET_HOST_FILTER':
      return { ...state, hostFilter: action.payload };

    case 'EVIDENCE_ADDED':
      return { ...state, evidence: [...state.evidence, action.payload].slice(-100) };

    case 'MEMORY_LOADED':
      return { ...state, memoryHits: action.payload };

    // ── Shells / Payloads ─────────────────────────────────
    case 'SHELL_UPDATE':
      return { ...state, shells: action.payload };

    case 'SHELL_OBTAINED': {
      const shell = action.payload;
      const isDupe = state.shells.some(s => s.id === shell.id);
      if (isDupe) return state;
      return { ...state, shells: [...state.shells, shell] };
    }

    case 'SHELL_PTY_OUTPUT': {
      const { shellId, data } = action.payload;
      return { ...state, shellBuffers: { ...state.shellBuffers,
        [shellId]: (state.shellBuffers[shellId] || '') + data } };
    }

    case 'CLEAR_SHELL_BUFFER': {
      const nb = { ...state.shellBuffers };
      delete nb[action.payload];
      return { ...state, shellBuffers: nb };
    }

    case 'SHELL_STATUS_UPDATE': {
      const { shellId, active } = action.payload;
      return { ...state, shells: state.shells.map(s => s.id === shellId ? {...s, active} : s) };
    }

    case 'PAYLOAD_ADDED':
      return { ...state, payloads: [action.payload, ...state.payloads] };

    case 'SET_PAYLOADS':
      return { ...state, payloads: action.payload };

    case 'WS_STATUS':
      return { ...state, wsConnected: action.payload };

    case 'SET_PLAN_STEPS':
      return { ...state, planSteps: action.payload || [] };

    case 'AGENT_COMM_LLM': {
      const { agent, phase, prompt, response, model, ts } = action.payload;
      const key = agent || 'master';
      const prev = state.agentComms[key] || [];
      const entry = { type: 'llm', phase, prompt, response, model, ts };
      return { ...state, agentComms: {
        ...state.agentComms,
        [key]: [entry, ...prev].slice(0, 100)  // newest first, cap at 100 per agent
      }};
    }

    case 'AGENT_COMM_RAG': {
      const { agent, phase, query, result, found, ts } = action.payload;
      const key = agent || 'master';
      const prev = state.agentComms[key] || [];
      const entry = { type: 'rag', phase, query, result, found, ts };
      return { ...state, agentComms: {
        ...state.agentComms,
        [key]: [entry, ...prev].slice(0, 100)
      }};
    }

    case 'SET_PLAN_SKELETON': {
      // Fired immediately at scan start — sets skeleton steps
      // Only sets if we don't already have a richer plan (from attack_tree_ready)
      const hasRichPlan = state.planSteps.some(s => s.probability != null || s.mitre_id);
      if (hasRichPlan) return state;
      const steps = (action.payload?.steps || []).map(s => ({
        ...s,
        status:     s.status || 'pending',
        result:     s.result || '',
        detail:     s.detail || '',
      }));
      return {
        ...state,
        planSteps:    steps,
        planHypothesis: action.payload?.hypothesis || '',
        planAssessment: action.payload?.assessment_type || '',
      };
    }

    case 'MERGE_TREE_STEPS': {
      // Called when attack tree arrives — merges tree nodes into existing skeleton steps
      // Preserves status of any steps already active/done
      const incoming = action.payload || [];
      const existing = state.planSteps;
      const existingById = {};
      existing.forEach(s => { existingById[s.id] = s; });

      // Update existing steps with richer data from tree; add new tree nodes
      const merged = [];
      const addedIds = new Set();

      incoming.forEach(step => {
        const prev = existingById[step.id];
        merged.push({
          ...step,
          // Preserve any live status already set
          status: (prev && prev.status !== 'pending') ? prev.status : step.status,
          result: (prev && prev.result) ? prev.result : step.result,
          detail: (prev && prev.detail) ? prev.detail : step.detail,
        });
        addedIds.add(step.id);
      });

      // Keep existing skeleton steps that weren't in tree (e.g. recon/osint completed)
      existing.forEach(s => {
        if (!addedIds.has(s.id)) merged.push(s);
      });

      return { ...state, planSteps: merged };
    }

    case 'RESTORE_PLAN_SKELETON': {
      // Resume path: incoming steps have status 'done'/'pending' set by backend.
      // Merge with any existing planSteps — never downgrade a step that is already
      // 'active' or 'done' in the current store.
      const STATUS_RANK = { done: 3, active: 2, pending: 1 };
      const incomingSteps = action.payload?.steps || [];
      const existingById  = {};
      (state.planSteps || []).forEach(s => { existingById[s.id] = s; });

      const restored = incomingSteps.map(step => {
        const prev = existingById[step.id];
        const prevRank = STATUS_RANK[prev?.status] || 0;
        const newRank  = STATUS_RANK[step.status]  || 0;
        return {
          ...step,
          // Keep richer label/tool data from prev if available
          label:  (prev?.label  && prev.label  !== step.id) ? prev.label  : step.label,
          tool:   prev?.tool   || step.tool,
          // Never downgrade status
          status: prevRank >= newRank ? prev.status : step.status,
          result: prev?.result || step.result,
          detail: prev?.detail || step.detail,
        };
      });

      // Keep any existing steps that weren't in the restore payload (edge case)
      const restoredIds = new Set(restored.map(s => s.id));
      (state.planSteps || []).forEach(s => {
        if (!restoredIds.has(s.id)) restored.push(s);
      });

      return {
        ...state,
        planSteps:      restored,
        planHypothesis: action.payload?.hypothesis       || state.planHypothesis,
        planAssessment: action.payload?.assessment_type  || state.planAssessment,
      };
    }

    case 'PLAN_STEP_UPDATE': {
      const { step_id, status, result, detail, found, ts, label, icon } = action.payload;
      const existing = state.planSteps.find(s => s.id === step_id);
      if (existing) {
        return { ...state, planSteps: state.planSteps.map(s =>
          s.id === step_id ? { ...s, status, result, detail, found, ts,
            // Allow label/icon to be enriched by later updates
            label: label || s.label,
            icon:  icon  || s.icon,
          } : s
        )};
      }
      // New step created dynamically (e.g. individual exploit vectors)
      // Insert after the last 'exploit' step for grouping
      const exploitIdx = state.planSteps.map((s,i) => s.phase === 'exploit' ? i : -1)
                                         .filter(i => i >= 0).pop() ?? state.planSteps.length - 1;
      const newStep = {
        id:     step_id,
        label:  label || step_id,
        icon:   icon  || '💥',
        phase:  step_id.startsWith('exploit') ? 'exploit' : 'unknown',
        status, result, detail, found, ts,
        is_substep: true,  // marks this as a child of the exploit step
      };
      const steps = [...state.planSteps];
      steps.splice(exploitIdx + 1, 0, newStep);
      return { ...state, planSteps: steps };
    }

    // ── v3: Subagent lifecycle ────────────────────────────
    case 'SUBAGENT_START': {
      const { subagent } = action.payload;
      if (!subagent) return state;
      return { ...state, subagentStates: {
        ...state.subagentStates,
        [subagent]: {
          ...(state.subagentStates[subagent] || {}),
          status:       'running',
          last_event:   action.payload.ts || new Date().toISOString(),
          findings_count: state.subagentStates[subagent]?.findings_count || 0,
          started_at:   action.payload.ts || new Date().toISOString(),
        }
      }};
    }

    case 'SUBAGENT_COMPLETE': {
      const { subagent, duration, finding_count } = action.payload;
      if (!subagent) return state;
      return { ...state, subagentStates: {
        ...state.subagentStates,
        [subagent]: {
          ...(state.subagentStates[subagent] || {}),
          status:         'complete',
          last_event:     action.payload.ts || new Date().toISOString(),
          duration:       duration,
          findings_count: finding_count ?? state.subagentStates[subagent]?.findings_count ?? 0,
        }
      }};
    }

    case 'SUBAGENT_ERROR': {
      const { subagent, error } = action.payload;
      if (!subagent) return state;
      return { ...state, subagentStates: {
        ...state.subagentStates,
        [subagent]: {
          ...(state.subagentStates[subagent] || {}),
          status:     'error',
          last_event: action.payload.ts || new Date().toISOString(),
          error:      error || 'Unknown error',
        }
      }};
    }

    case 'SUBAGENT_STOPPED': {
      const { subagent } = action.payload;
      if (!subagent) return state;
      return { ...state, subagentStates: {
        ...state.subagentStates,
        [subagent]: {
          ...(state.subagentStates[subagent] || {}),
          status:     'stopped',
          last_event: action.payload.ts || new Date().toISOString(),
        }
      }};
    }

    case 'SUBAGENT_FINDING': {
      // Increment finding count for this subagent
      const { subagent, finding } = action.payload;
      const prev = state.subagentStates[subagent] || { status: 'running', findings_count: 0 };
      const newSubagentStates = {
        ...state.subagentStates,
        [subagent]: { ...prev, findings_count: (prev.findings_count || 0) + 1 }
      };

      // Also route to subagent-specific slices by agent type
      const agentKey = (subagent || '').toLowerCase();
      let extraSlice = {};
      if (agentKey.includes('lateral') || agentKey.includes('movement')) {
        extraSlice = { lateralFindings: [...state.lateralFindings, finding].slice(-500) };
      } else if (agentKey.includes('cloud') || agentKey.includes('aws') || agentKey.includes('azure') || agentKey.includes('gcp')) {
        extraSlice = { cloudFindings: [...state.cloudFindings, finding].slice(-500) };
      } else if (agentKey.includes('container') || agentKey.includes('docker') || agentKey.includes('k8s') || agentKey.includes('kube')) {
        extraSlice = { containerFindings: [...state.containerFindings, finding].slice(-500) };
      } else if (agentKey.includes('wireless') || agentKey.includes('wifi') || agentKey.includes('wlan')) {
        extraSlice = { wirelessEvents: [...state.wirelessEvents, finding].slice(-500) };
      }

      // Always update findingsSummary too
      const sev = (finding?.severity || 'info').toLowerCase();
      const fs = { ...state.findingsSummary };
      if (fs[sev] !== undefined) fs[sev]++;
      fs.total = (fs.total || 0) + 1;

      return { ...state, subagentStates: newSubagentStates, findingsSummary: fs, ...extraSlice };
    }

    case 'SUBAGENT_TOOL_LINE': {
      // Append a tool output line for a specific subagent, capped at 500 lines
      const { subagent, tool, line, ts } = action.payload;
      if (!subagent) return state;
      const prev = state.subagentLines[subagent] || [];
      return { ...state, subagentLines: {
        ...state.subagentLines,
        [subagent]: [...prev, { tool, line, ts }].slice(-500),
      }};
    }

    case 'SUBAGENT_TOOL_EXIT': {
      // Track per-tool exit codes in subagentStates[sa].toolExits
      const { subagent, tool, exit_code, success, ts } = action.payload;
      if (!subagent) return state;
      const prev = state.subagentStates[subagent] || {};
      const prevExits = prev.toolExits || {};
      return { ...state, subagentStates: {
        ...state.subagentStates,
        [subagent]: {
          ...prev,
          toolExits: { ...prevExits, [tool]: { exit_code, success, ts } },
          lastToolExit: { tool, exit_code, success, ts },
        }
      }};
    }

    // ── Operator console ──────────────────────────────────
    case 'OPERATOR_MODE':
      return { ...state, operatorMode: action.payload };

    case 'GUIDANCE_SENT': {
      const entry = { ...action.payload, ts: new Date().toLocaleTimeString([], { hour12: false }) };
      return { ...state, guidanceHistory: [entry, ...state.guidanceHistory].slice(0, 20) };
    }

    // ── v3: Credentials ───────────────────────────────────
    case 'CREDENTIAL_FOUND': {
      const cred = action.payload;
      // Deduplicate by user+host+secret combination
      const isDupe = state.credentials.some(c =>
        c.user === cred.user && c.host === cred.host && c.secret === cred.secret);
      if (isDupe) return state;
      return { ...state, credentials: [...state.credentials, {
        id:        cred.id || `cred_${Date.now()}_${Math.random().toString(36).slice(2,7)}`,
        user:      cred.user || '',
        host:      cred.host || '',
        service:   cred.service || '',
        type:      cred.type || 'plaintext',
        secret:    cred.secret || '',
        found_by:  cred.found_by || cred.subagent || '',
        timestamp: cred.timestamp || new Date().toISOString(),
      }]};
    }

    // ── v3: Tunnels ───────────────────────────────────────
    case 'TUNNEL_ESTABLISHED': {
      const tunnel = action.payload;
      return { ...state, tunnels: [...state.tunnels, {
        id:          tunnel.id || `tunnel_${Date.now()}`,
        type:        tunnel.type || 'ssh',
        local_port:  tunnel.local_port,
        remote_host: tunnel.remote_host || '',
        remote_port: tunnel.remote_port,
        active:      true,
        established_at: tunnel.timestamp || new Date().toISOString(),
      }]};
    }

    // ── v3: Persistence ───────────────────────────────────
    case 'PERSISTENCE_PLANTED': {
      const item = action.payload;
      return { ...state, persistenceItems: [...state.persistenceItems, {
        id:        item.id || `persist_${Date.now()}`,
        type:      item.type || 'unknown',
        host:      item.host || '',
        mechanism: item.mechanism || '',
        trigger:   item.trigger || '',
        user:      item.user || '',
        planted_at: item.timestamp || new Date().toISOString(),
      }]};
    }

    // ── v3: Burp scan complete → append summary to findings ──
    case 'BURP_SCAN_COMPLETE': {
      const { summary, issue_count, high_count, medium_count } = action.payload;
      const sev = high_count > 0 ? 'high' : medium_count > 0 ? 'medium' : 'info';
      const fs = { ...state.findingsSummary };
      if (fs[sev] !== undefined) fs[sev]++;
      fs.total = (fs.total || 0) + 1;
      return { ...state, findingsSummary: fs };
    }

    // ── v3: Attack chain success ──────────────────────────
    case 'CHAIN_EXPLOIT_SUCCESS': {
      const { chain_id, step_id } = action.payload;
      // Mark the matching plan step as success
      const planSteps = state.planSteps.map(s =>
        (s.id === chain_id || s.id === step_id)
          ? { ...s, status: 'success', result: action.payload.result || 'Chain exploit succeeded' }
          : s
      );
      return { ...state, planSteps };
    }

    // ── v3: Privesc success → mark shell elevated ─────────
    case 'PRIVESC_SUCCESS': {
      const { shell_id, new_user } = action.payload;
      const shells = state.shells.map(s =>
        s.id === shell_id ? { ...s, elevated: true, elevated_user: new_user || 'root' } : s
      );
      return { ...state, shells };
    }

    // ── v3: RAG history ───────────────────────────────────
    case 'RAG_HISTORY_ENTRY': {
      const entry = {
        query:     action.payload.query,
        results:   action.payload.results || [],
        timestamp: action.payload.timestamp || new Date().toISOString(),
        agent:     action.payload.agent || '',
        found:     action.payload.found || false,
      };
      return { ...state, ragHistory: [entry, ...state.ragHistory].slice(0, 200) };
    }

    // ── v3: LLM thoughts ─────────────────────────────────
    case 'LLM_THOUGHT': {
      const thought = {
        agent:     action.payload.agent || '',
        thought:   action.payload.thought || action.payload.response || '',
        timestamp: action.payload.timestamp || new Date().toISOString(),
        phase:     action.payload.phase || '',
      };
      return { ...state, llmThoughts: [thought, ...state.llmThoughts].slice(0, 200) };
    }

    // ── v3: Traffic captures ─────────────────────────────
    case 'TRAFFIC_CAPTURE_ADDED': {
      return { ...state, trafficCaptures: [...state.trafficCaptures, action.payload].slice(-100) };
    }

    case 'TOOL_TIMEOUT_WARNING':
      return { ...state, toolTimeoutWarning: action.payload };

    case 'TOOL_TIMEOUT_CLEAR':
      return { ...state, toolTimeoutWarning: null };

    case 'PHASE_TIME_EXTENSION':
      return { ...state, phaseTimeExtension: action.payload };

    case 'CLEAR_PHASE_TIME_EXTENSION':
      return { ...state, phaseTimeExtension: null };

    case 'WEB_CONFIRM_PENDING':
      return { ...state, webConfirmPending: action.payload };

    case 'RESET_SESSION':
      return { ...INIT, sysStatus: state.sysStatus, llmStatus: state.llmStatus, sessions: state.sessions };

    default:
      return state;
  }
}

// ─── Context + Provider ────────────────────────────────────
const StoreCtx = createContext(null);

function StoreProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, INIT);
  const wsRef             = useRef(null);
  const sessionIdRef      = useRef(null);
  const shellListenersRef = useRef({});

  const connectWS = useCallback((sessionId) => {
    if (wsRef.current) wsRef.current.close();
    sessionIdRef.current = sessionId;
    const ws = window.API.ws(sessionId);
    wsRef.current = ws;
    ws.onopen  = () => dispatch({ type: 'WS_STATUS', payload: true });
    ws.onclose = () => {
      dispatch({ type: 'WS_STATUS', payload: false });
      setTimeout(() => {
        if (sessionIdRef.current === sessionId) connectWS(sessionId);
      }, 3000);
    };
    ws.onerror   = () => dispatch({ type: 'WS_STATUS', payload: false });
    ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      routeWsEvent(msg, dispatch, shellListenersRef.current);
    };
  }, []);

  const disconnectWS = useCallback(() => {
    sessionIdRef.current = null;
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    dispatch({ type: 'WS_STATUS', payload: false });
  }, []);

  const sendWS = useCallback((msg) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN)
      wsRef.current.send(JSON.stringify(msg));
  }, []);

  const registerShellListener = useCallback((shellId, cb) => {
    shellListenersRef.current[shellId] = cb;
    return () => { delete shellListenersRef.current[shellId]; };
  }, []);

  const refreshSessions = useCallback(async () => {
    try {
      const res = await window.API.sessions.list();
      dispatch({ type: 'SET_SESSIONS', payload: res.sessions || [] });
    } catch {}
  }, []);

  const loadGraph = useCallback(async (sessionId) => {
    try {
      const g = await window.API.graph(sessionId);
      dispatch({ type: 'SET_GRAPH', payload: { nodes: g.nodes || [], edges: g.edges || [] } });
    } catch {}
  }, []);

  // System status poll
  useEffect(() => {
    const poll = async () => {
      try {
        const s = await window.API.status();
        dispatch({ type: 'SET_SYS_STATUS', payload: { mcp: s.mcp, mongo: s.mongo, ollama: s.ollama } });
        dispatch({ type: 'SET_LLM_STATUS', payload: {
          available: s.ollama === 'online',
          message:   s.ollama === 'online' ? 'LLM online' : 'LLM offline'
        }});
      } catch {
        dispatch({ type: 'SET_SYS_STATUS', payload: { mcp: 'offline', mongo: 'offline', ollama: 'offline' } });
      }
    };
    poll();
    const t = setInterval(poll, 10000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => { refreshSessions(); }, []);

  const value = { state, dispatch, connectWS, disconnectWS, sendWS,
                  registerShellListener, refreshSessions, loadGraph };
  return React.createElement(StoreCtx.Provider, { value }, children);
}

// ─── WebSocket Event Router ────────────────────────────────
function routeWsEvent(msg, dispatch, shellListeners) {
  const { type, data, timestamp } = msg;
  // Normalize agent name from enum string
  const rawAgent = msg.agent || data?.agent || '';
  const agent    = normalizeAgent(rawAgent) || '';
  const ts       = new Date(timestamp || Date.now()).toLocaleTimeString();

  // Feed entry (skip heartbeats)
  if (type !== 'heartbeat' && type !== 'pong') {
    const feedMsg = extractFeedMessage(type, agent, data);
    if (feedMsg) {
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent, eventType: type, message: feedMsg, data } });
    }
  }

  switch (type) {

    // ── Agent & Phase ────────────────────────────────────
    case 'agent_status':
      dispatch({ type: 'AGENT_STATUS', payload: {
        agent:   normalizeAgent(data.agent),
        status:  data.status,
        phase:   normalizePhase(data.phase),
        message: data.message
      }});
      break;

    case 'phase_change':
    case 'phase_start':
      // Mark previous phase as done when a new one starts
      dispatch({ type: 'PHASE_CHANGE', payload: { phase: normalizePhase(data.phase) } });
      // Also mark prior phases complete via PHASE_DONE implicitly
      break;

    case 'phase_done':
      dispatch({ type: 'PHASE_DONE', payload: { phase: normalizePhase(data.phase) } });
      break;

    // State machine transition (new architecture)
    case 'state_change': {
      dispatch({ type: 'STATE_CHANGE', payload: { from: data.from, to: data.to } });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'state_change',
        message: `State: ${data.from} → ${data.to}`, data
      }});
      // Mark the entering phase as active in plan steps
      const phaseMap = {
        'RECON':                    'recon',
        'INTELLIGENCE_AGGREGATION': ['vuln_id','web_testing','osint'],
        'EXPLOITATION':             'exploit',
        'POST_EXPLOITATION':        'post_exploit',
        'PRIVILEGE_ESCALATION':     'privesc',
      };
      const entering = phaseMap[data.to];
      if (entering) {
        const ids = Array.isArray(entering) ? entering : [entering];
        ids.forEach(id => dispatch({ type: 'PLAN_STEP_UPDATE', payload: { step_id: id, status: 'active', result: `${data.to} in progress...`, detail: '' } }));
      }
      break;
    }

    // ── LLM ──────────────────────────────────────────────
    case 'llm_status':
      dispatch({ type: 'SET_LLM_STATUS', payload: {
        available: data.available, url: data.url, model: data.model, message: data.message
      }});
      if (!data.available) {
        dispatch({ type: 'FEED_ENTRY', payload: {
          ts, agent: 'master', eventType: 'llm_offline',
          message: `LLM OFFLINE: ${data.message}`, data
        }});
      }
      break;

    case 'llm_halt':
      dispatch({ type: 'SET_LLM_STATUS', payload: { available: false, message: data.reason || data.message } });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'llm_halt',
        message: `HALTED: ${data.reason || data.message}`, data
      }});
      break;

    case 'agent_thinking':
      dispatch({ type: 'LLM_THINKING', payload: true });
      dispatch({ type: 'AGENT_STATUS', payload: {
        agent:   normalizeAgent(data.agent),
        status:  'thinking',
        message: 'Consulting LLM...'
      }});
      break;

    case 'llm_response':
      dispatch({ type: 'LLM_RESPONSE', payload: data.response });
      // Also record as a thought for the LLM thoughts log
      dispatch({ type: 'LLM_THOUGHT', payload: {
        agent:     normalizeAgent(data.agent) || agent,
        thought:   data.response,
        phase:     normalizePhase(data.phase) || '',
        timestamp: new Date().toISOString(),
      }});
      break;

    // ── Reasoning ────────────────────────────────────────
    case 'agent_reasoning':
      dispatch({ type: 'REASONING_ENTRY', payload: {
        ts,
        agent:       normalizeAgent(data.agent),
        phase:       normalizePhase(data.phase),
        step:        data.step,
        reasoning:   data.reasoning,
        decision:    data.decision,
        next_action: data.next_action,
        data:        data.data
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: normalizeAgent(data.agent), eventType: 'reasoning',
        message: `[${data.step}] ${data.decision}`, data
      }});
      // Update master agent status with the current decision
      if (normalizeAgent(data.agent) === 'master') {
        dispatch({ type: 'AGENT_STATUS', payload: {
          agent:   'master',
          status:  'thinking',
          message: data.decision || data.reasoning || 'Planning...'
        }});
      }
      break;

    // ── Tools ────────────────────────────────────────────
    case 'tool_start':
      dispatch({ type: 'AGENT_STATUS', payload: {
        agent:   normalizeAgent(data.agent),
        status:  'running',
        phase:   normalizePhase(data.phase || ''),
        message: `▶ ${data.tool}`
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: normalizeAgent(data.agent), eventType: 'tool_start',
        message: `▶ ${data.tool}: ${(data.command || '').slice(0, 100)}`, data
      }});
      break;

    case 'tool_output':
      dispatch({ type: 'TOOL_LINE', payload: {
        agent: normalizeAgent(data.agent), line: data.line, lineType: data.type
      }});
      // Also feed the ToolExecutions tab (which reads subagentLines)
      if (data.agent && data.tool && data.line) {
        dispatch({ type: 'SUBAGENT_TOOL_LINE', payload: {
          subagent: normalizeAgent(data.agent),
          tool: data.tool,
          line: data.line,
          ts,
        }});
      }
      break;

    case 'tool_done':
      dispatch({ type: 'AGENT_STATUS', payload: {
        agent:   normalizeAgent(data.agent),
        status:  'running',
        message: `✓ ${data.tool} done`
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: normalizeAgent(data.agent), eventType: 'tool_done',
        message: `✓ ${data.tool} (exit ${data.exit_code}, ${data.lines} lines)`, data
      }});
      // Also populate the ToolExecutions tab (which reads subagentStates[].toolExits)
      if (data.agent && data.tool) {
        dispatch({ type: 'SUBAGENT_TOOL_EXIT', payload: {
          subagent:  normalizeAgent(data.agent),
          tool:      data.tool,
          exit_code: data.exit_code ?? -1,
          success:   (data.exit_code ?? -1) === 0,
          ts,
        }});
      }
      break;

    case 'tool_findings':
      if (data.ports?.length)
        dispatch({ type: 'FEED_ENTRY', payload: { ts, agent, eventType: 'tool_findings',
          message: `${data.tool}: ports ${data.ports.join(',')}`, data }});
      if (data.cves?.length)
        dispatch({ type: 'FEED_ENTRY', payload: { ts, agent, eventType: 'tool_findings',
          message: `${data.tool}: CVEs ${data.cves.slice(0,3).join(',')}`, data }});
      break;

    // ── New architecture events ───────────────────────────
    case 'attack_tree_ready': {
      const tree = data.tree || {};
      dispatch({ type: 'ATTACK_TREE_READY', payload: tree });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'attack_tree_ready',
        message: `Attack tree ready — ${(tree.attack_nodes||[]).length} nodes`, data
      }});
      dispatch({ type: 'PHASE_CHANGE', payload: { phase: 'exploit' } });

      // Build planSteps from attack tree nodes — these become the live strategy cards
      const steps = [];

      // Fixed recon/vuln/web phases first
      steps.push({ id: 'recon',       label: 'Reconnaissance',       icon: 'R', phase: 'recon',       status: 'pending', result: '', detail: '' });
      steps.push({ id: 'vuln_id',     label: 'Vulnerability ID',      icon: 'V', phase: 'vuln_id',     status: 'pending', result: '', detail: '' });
      steps.push({ id: 'web_testing', label: 'Web App Testing',       icon: 'W', phase: 'web_testing',  status: 'pending', result: '', detail: '' });
      steps.push({ id: 'osint',       label: 'OSINT / ExploitDB',     icon: 'O', phase: 'osint',       status: 'pending', result: '', detail: '' });

      // Attack tree nodes become exploit steps
      const nodes = tree.attack_nodes || [];
      const optimal = tree.optimal_path || [];
      nodes.forEach((n, i) => {
        steps.push({
          id:          n.id || `node_${i}`,
          label:       n.technique || n.step || `Step ${i+1}`,
          icon:        'X',
          phase:       'exploit',
          mitre_id:    n.mitre_id,
          mitre_name:  n.mitre_name,
          tool:        n.tool,
          probability: n.probability,
          produces:    n.produces,
          requires:    n.requires || [],
          is_optimal:  optimal.includes(n.id),
          status:      'pending',
          result:      '',
          detail:      ''
        });
      });

      // Post-exploit phases
      steps.push({ id: 'post_exploit', label: 'Post Exploitation',   icon: 'P', phase: 'post_exploit', status: 'pending', result: '', detail: '' });
      steps.push({ id: 'privesc',      label: 'Privilege Escalation', icon: 'E', phase: 'privesc',      status: 'pending', result: '', detail: '' });

      dispatch({ type: 'MERGE_TREE_STEPS', payload: steps });
      break;
    }

    case 'memory_loaded':
      dispatch({ type: 'MEMORY_LOADED', payload: (data.memories || []).length });
      if ((data.memories || []).length > 0)
        dispatch({ type: 'FEED_ENTRY', payload: {
          ts, agent: 'master', eventType: 'memory_loaded',
          message: `Loaded ${data.memories.length} memories from past engagements`, data
        }});
      break;

    case 'parallel_intel':
      // All parallel agents become active at once
      ['vuln', 'web', 'osint'].forEach(a => {
        dispatch({ type: 'AGENT_STATUS', payload: {
          agent: a, status: 'running', message: 'Running in parallel...'
        }});
      });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'parallel_intel',
        message: `Parallel scan: ${data.decision}`, data
      }});
      break;

    // ── Findings & Flags ─────────────────────────────────
    case 'finding': {
      const f = data.finding || {};
      dispatch({ type: 'FINDING_ADDED', payload: f });
      // Track per-host counts for multi-host sessions
      const findingHost = f.host || msg.host_id;
      if (findingHost) dispatch({ type: 'HOST_FINDING_COUNT', payload: { host: findingHost, severity: f.severity } });
      break;
    }

    case 'flag_found':
      dispatch({ type: 'FLAG_FOUND', payload: data });
      break;

    // ── Attack Graph ─────────────────────────────────────
    case 'graph_node':
      dispatch({ type: 'GRAPH_NODE', payload: {
        node_id:   data.node_id,
        node_type: data.type || data.node_type,
        label:     data.label,
        host:      data.host,
        port:      data.port,
        severity:  data.severity,
        phase:     data.phase,
        metadata:  data.metadata || {}
      }});
      break;

    case 'graph_edge':
      dispatch({ type: 'GRAPH_EDGE', payload: {
        edge_id: data.edge_id,
        source:  data.source,
        target:  data.target,
        label:   data.label,
        tool:    data.tool
      }});
      break;

    case 'graph_refresh':
      // Backend added new chain nodes — reload graph from API
      if (state.sessionId) {
        window.API.graph(state.sessionId).then(g => {
          dispatch({ type: 'SET_GRAPH', payload: { nodes: g.nodes || [], edges: g.edges || [] } });
        }).catch(() => {});
      }
      break;

    // ── Attack Chain Analysis (AttackGraphAgent) ──────────
    case 'chain_analysis':
      dispatch({ type: 'CHAIN_ANALYSIS', payload: data });
      break;

    case 'chain_analysis_status':
      dispatch({ type: 'CHAIN_ANALYSIS_STATUS', payload: data });
      break;

    // ── Multi-host / CIDR events ──────────────────────────
    case 'cidr_expansion_start':
      dispatch({ type: 'SET_SESSION_MODE', payload: msg.data.target_input && msg.data.target_input.includes('/') ? 'cidr' : 'multi' });
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent: 'orchestrator', eventType: 'cidr_expansion_start', message: msg.data.message || 'Discovering live hosts...', data } });
      break;

    case 'host_discovery_complete':
      dispatch({ type: 'HOST_DISCOVERY_COMPLETE', payload: { hosts: data.hosts || [] } });
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent: 'orchestrator', eventType: 'host_discovery_complete', message: data.message || `Found ${(data.hosts||[]).length} live hosts`, data } });
      break;

    case 'host_discovered':
      dispatch({ type: 'HOST_DISCOVERED', payload: { host: data.host || msg.host_id } });
      break;

    case 'host_scan_start':
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent: 'orchestrator', eventType: 'host_scan_start', message: `Started testing ${data.host || msg.host_id}`, data, host: data.host || msg.host_id } });
      break;

    case 'host_scan_complete':
      dispatch({ type: 'HOST_COMPLETE', payload: { host: data.host || msg.host_id } });
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent: 'orchestrator', eventType: 'host_scan_complete', message: `Completed testing ${data.host || msg.host_id}`, data, host: data.host || msg.host_id } });
      break;

    case 'cidr_scan_complete':
      dispatch({ type: 'CIDR_SCAN_COMPLETE' });
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent: 'orchestrator', eventType: 'cidr_scan_complete', message: data.message || 'All hosts tested', data } });
      break;

    case 'iot_phase_start':
      dispatch({ type: 'AGENT_STATUS', payload: { agent: 'iot', status: 'running', phase: 'iot', message: data.message || `IoT assessment started on ${data.target}` } });
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent: 'iot', eventType: 'iot_phase_start', message: data.message || `IoT assessment started on ${data.target}`, data, host: data.target || msg.host_id } });
      break;

    case 'iot_phase_complete':
      dispatch({ type: 'AGENT_STATUS', payload: { agent: 'iot', status: 'complete', phase: 'iot', message: data.message || 'IoT assessment complete' } });
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent: 'iot', eventType: 'iot_phase_complete', message: data.message || 'IoT assessment complete', data, host: data.target || msg.host_id } });
      break;

    case 'iot_autodetect':
      dispatch({ type: 'FEED_ENTRY', payload: { ts, agent: 'master', eventType: 'iot_autodetect', message: 'IoT device characteristics detected — enabling IoT assessment', data } });
      break;

    // ── Shells / Payloads ─────────────────────────────────
    case 'shell_ready':
      dispatch({ type: 'AGENT_STATUS', payload: {
        agent: 'shell', status: 'running', message: `Shell ${data?.shell_id} ready`
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'shell', eventType: 'shell_ready',
        message: `Shell ready: ${data?.shell_id || ''}`, data
      }});
      break;

    case 'shell_closed':
      dispatch({ type: 'AGENT_STATUS', payload: {
        agent: 'shell', status: 'idle', message: 'Shell closed'
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'shell', eventType: 'shell_closed',
        message: `Shell closed: ${data?.shell_id || ''}`, data
      }});
      break;

    case 'shell_output': {
      const shellId  = data.shell_id;
      const listener = shellListeners[shellId];
      if (listener) { try { listener(data.data); } catch {} }
      else dispatch({ type: 'SHELL_PTY_OUTPUT', payload: { shellId, data: data.data } });
      break;
    }
    case 'shell_status':
      dispatch({ type: 'SHELL_STATUS_UPDATE', payload: { shellId: data.shell_id, active: data.active } });
      break;

    case 'payload_generated':
      if (data && !data.error) dispatch({ type: 'PAYLOAD_ADDED', payload: data });
      break;

    // Session deleted (backend broadcast)
    case 'session_deleted':
      dispatch({ type: 'REMOVE_SESSION', payload: data.session_id });
      break;

    case 'llm_comm':
      dispatch({ type: 'AGENT_COMM_LLM', payload: {
        agent:    normalizeAgent(data.agent || agent),
        phase:    normalizePhase(data.phase),
        prompt:   data.prompt,
        response: data.response,
        model:    data.model,
        ts,
      }});
      break;

    case 'rag_query':
      dispatch({ type: 'AGENT_COMM_RAG', payload: {
        agent:  normalizeAgent(data.agent || agent),
        phase:  normalizePhase(data.phase),
        query:  data.query,
        result: data.result,
        found:  data.found,
        ts,
      }});
      // Also store in ragHistory for the RAGInspector page
      dispatch({ type: 'RAG_HISTORY_ENTRY', payload: {
        agent:     normalizeAgent(data.agent || agent),
        query:     data.query,
        results:   data.result ? [data.result] : [],
        found:     data.found,
        timestamp: new Date().toISOString(),
      }});
      break;

    case 'plan_skeleton':
      // Fired immediately when master plan is created — shows skeleton before recon starts
      dispatch({ type: 'SET_PLAN_SKELETON', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'plan_skeleton',
        message: `Attack plan: ${(data?.steps||[]).length} phases — ${data?.assessment_type||''}`,
        data
      }});
      break;

    case 'plan_skeleton_restore': {
      // Fired on resume — merges incoming steps into existing planSteps.
      // Incoming steps already carry correct status ('done'/'pending') from backend.
      // We never downgrade an existing 'active' or 'done' step to 'pending'.
      dispatch({ type: 'RESTORE_PLAN_SKELETON', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'plan_skeleton_restore',
        message: `Scan resumed — ${(data?.phases_completed||[]).length} phase(s) already complete`,
        data
      }});
      break;
    }

    case 'plan_step_update':
      dispatch({ type: 'PLAN_STEP_UPDATE', payload: data });
      break;

    case 'guidance_applied':
    case 'guidance_queued':
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'guidance',
        message: `Guidance: ${data.message}`, data
      }});
      break;

    // ── v3: Subagent lifecycle events ─────────────────────
    // Events may arrive as flat dict (base_subagent raw broadcast, no .data wrapper)
    // OR as WebSocketMessage (msg.data = payload). Normalise both here.
    case 'subagent_start': {
      // flat: msg = { type, agent, subagent, target, session_id }
      // wrapped: msg = { type, agent, data: { subagent, target } }
      const saD = data || msg;
      const saName = saD.subagent || saD.agent || msg.subagent || agent;
      dispatch({ type: 'SUBAGENT_START', payload: {
        subagent: saName,
        target:   saD.target || '',
        ts:       new Date().toISOString(),
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'subagent_start',
        message: `Subagent started: ${saName}`, data: saD
      }});
      break;
    }

    case 'subagent_complete': {
      const saD = data || msg;
      const saName     = saD.subagent || saD.agent || msg.subagent || agent;
      const saDuration = saD.duration_seconds ?? saD.duration ?? 0;
      const saFindings = saD.finding_count ?? saD.findings_count ?? 0;
      dispatch({ type: 'SUBAGENT_COMPLETE', payload: {
        subagent:      saName,
        duration:      saDuration,
        finding_count: saFindings,
        error:         saD.error || null,
        ts:            new Date().toISOString(),
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'subagent_complete',
        message: `Subagent done: ${saName} (${Number(saDuration).toFixed(1)}s, ${saFindings} findings)`,
        data: saD
      }});
      break;
    }

    case 'subagent_error': {
      const saD = data || msg;
      const saName = saD.subagent || saD.agent || msg.subagent || agent;
      const saErr  = saD.error || saD.message || 'unknown error';
      dispatch({ type: 'SUBAGENT_ERROR', payload: {
        subagent: saName,
        error:    saErr,
        ts:       new Date().toISOString(),
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'subagent_error',
        message: `Subagent error: ${saName} — ${saErr}`, data: saD
      }});
      break;
    }

    case 'subagent_stopped': {
      const saName = (data || msg).subagent || agent;
      dispatch({ type: 'SUBAGENT_STOPPED', payload: { subagent: saName, ts: new Date().toISOString() } });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'subagent_stopped',
        message: `⏹ ${saName} cancelled by operator`, data: data || msg
      }});
      break;
    }

    case 'subagent_restarted': {
      const saName = (data || msg).subagent || agent;
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'subagent_restarted',
        message: `↺ ${saName} restart queued`, data: data || msg
      }});
      break;
    }

    case 'subagent_finding': {
      const saD    = data || msg;
      const saName = saD.subagent || saD.agent || msg.subagent || agent;
      const finding = saD.finding || saD;
      // SUBAGENT_FINDING already updates findingsSummary — do NOT also dispatch FINDING_ADDED
      dispatch({ type: 'SUBAGENT_FINDING', payload: { subagent: saName, finding } });
      // Track per-host counts for multi-host sessions
      const sfHost = (finding.host) || msg.host_id;
      if (sfHost) dispatch({ type: 'HOST_FINDING_COUNT', payload: { host: sfHost, severity: finding.severity } });
      break;
    }

    case 'subagent_tool_line': {
      const saD    = data || msg;
      const saName = saD.subagent || saD.agent || msg.subagent || agent;
      const line   = saD.line || saD.text || saD.output || '';
      const tool   = saD.tool || '';
      if (saName && line) {
        dispatch({ type: 'SUBAGENT_TOOL_LINE', payload: {
          subagent: saName, tool, line, ts: new Date().toLocaleTimeString(),
        }});
      }
      break;
    }

    case 'subagent_tool_exit': {
      const saD     = data || msg;
      const saName  = saD.subagent || saD.agent || msg.subagent || agent;
      const toolName = saD.tool || '';
      const exitCode = saD.exit_code ?? saD.exitCode ?? null;
      const success  = saD.success ?? (exitCode === 0);
      if (saName) {
        dispatch({ type: 'SUBAGENT_TOOL_EXIT', payload: {
          subagent: saName, tool: toolName, exit_code: exitCode, success,
          ts: new Date().toISOString(),
        }});
      }
      break;
    }

    // ── v3: Network scan complete (from network_scan_subagent) ────────────────
    case 'network_scan_complete': {
      const saD = data || msg;
      const saName = saD.subagent || 'network_scan';
      dispatch({ type: 'SUBAGENT_COMPLETE', payload: {
        subagent:      saName,
        duration:      saD.duration_seconds ?? saD.duration ?? 0,
        finding_count: saD.open_ports?.length ?? saD.finding_count ?? 0,
        ts:            new Date().toISOString(),
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'recon', eventType: 'network_scan_complete',
        message: `Network scan done: ${(saD.open_ports || []).join(',')} open ports`,
        data: saD,
      }});
      break;
    }

    // ── v3: Shell obtained (from shell_agent, before PTY upgrade) ─────────────
    case 'shell_obtained': {
      const sd = data || msg;
      const shellObj = {
        id:         sd.shell_id || sd.id || `shell_${Date.now()}`,
        type:       sd.shell_type || 'reverse_shell',
        rhost:      sd.rhost || sd.host || '',
        rport:      sd.rport || sd.port || '',
        lhost:      sd.lhost || '',
        lport:      sd.lport || '',
        active:     true,
        elevated:   false,
        obtained_at: sd.timestamp || new Date().toISOString(),
      };
      dispatch({ type: 'SHELL_OBTAINED', payload: shellObj });
      dispatch({ type: 'AGENT_STATUS', payload: {
        agent: 'shell', status: 'running',
        message: `Shell on ${shellObj.rhost}:${shellObj.rport}`,
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'shell', eventType: 'shell_obtained',
        message: `Shell obtained: ${shellObj.rhost}:${shellObj.rport} (${shellObj.type})`,
        data: sd,
      }});
      break;
    }

    // ── v3: Traffic capture from traffic subagents ─────────────────────────────
    case 'traffic_capture_added': {
      const td = data || msg;
      dispatch({ type: 'TRAFFIC_CAPTURE_ADDED', payload: {
        id:          td.id || `cap_${Date.now()}`,
        interface:   td.interface || td.iface || '',
        file:        td.file || td.pcap_file || '',
        credentials: td.credentials || [],
        packets:     td.packet_count ?? td.packets ?? 0,
        duration:    td.duration ?? 0,
        timestamp:   td.timestamp || new Date().toISOString(),
        summary:     td.summary || '',
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'traffic_capture_added',
        message: `Traffic capture: ${td.packets ?? 0} packets${td.credentials?.length ? `, ${td.credentials.length} creds sniffed` : ''}`,
        data: td,
      }});
      break;
    }

    // ── v3: MITRE technique mapped ────────────────────────────────────────────
    case 'mitre_mapped': {
      const md = data || msg;
      dispatch({ type: 'MITRE_MAPPED', payload: {
        id:       md.id || md.technique_id || '',
        tactic:   md.tactic || '',
        name:     md.name || md.technique_name || '',
        tool:     md.tool || '',
        phase:    normalizePhase(md.phase || ''),
        evidence: md.evidence || '',
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'mitre_mapped',
        message: `MITRE: ${md.id || md.technique_id} ${md.name || ''} (${md.tactic || ''})`,
        data: md,
      }});
      break;
    }

    // ── v3: Evidence captured ─────────────────────────────────────────────────
    case 'evidence_added': {
      const ed = data || msg;
      dispatch({ type: 'EVIDENCE_ADDED', payload: {
        id:            ed.id || `ev_${Date.now()}`,
        type:          ed.evidence_type || ed.type || 'unknown',
        host:          ed.host || '',
        description:   ed.description || '',
        file:          ed.file || ed.screenshot_path || '',
        flag:          ed.flag || '',
        timestamp:     ed.timestamp || new Date().toISOString(),
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'evidence_added',
        message: `Evidence: [${ed.evidence_type || ed.type || '?'}] ${ed.description || ed.flag || ''}`,
        data: ed,
      }});
      break;
    }

    // ── v3: Credential found ──────────────────────────────
    case 'credential_found':
      dispatch({ type: 'CREDENTIAL_FOUND', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'credential_found',
        message: `Credential found: ${data.user}@${data.host} [${data.service || data.type}]`, data
      }});
      break;

    // ── v3: Tunnel established ────────────────────────────
    case 'tunnel_established':
      dispatch({ type: 'TUNNEL_ESTABLISHED', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'tunnel_established',
        message: `Tunnel: ${data.type} :${data.local_port} → ${data.remote_host}:${data.remote_port}`, data
      }});
      break;

    // ── v3: Persistence planted ───────────────────────────
    case 'persistence_planted':
      dispatch({ type: 'PERSISTENCE_PLANTED', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'persistence_planted',
        message: `Persistence: ${data.mechanism} on ${data.host} (${data.trigger})`, data
      }});
      break;

    // ── v3: Burp scan complete ────────────────────────────
    case 'burp_scan_complete':
      dispatch({ type: 'BURP_SCAN_COMPLETE', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'burp_scan_complete',
        message: `Burp scan done: ${data.issue_count || 0} issues (${data.high_count || 0} high, ${data.medium_count || 0} med)`,
        data
      }});
      break;

    // ── v3: Attack chain success ──────────────────────────
    case 'chain_exploit_success':
      dispatch({ type: 'CHAIN_EXPLOIT_SUCCESS', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'chain_exploit_success',
        message: `Chain exploit success: ${data.chain_id || data.step_id}`, data
      }});
      break;

    // ── v3: Privesc success ───────────────────────────────
    case 'privesc_success':
      dispatch({ type: 'PRIVESC_SUCCESS', payload: data });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'privesc_success',
        message: `PRIVESC: shell ${data.shell_id} elevated to ${data.new_user || 'root'}`, data
      }});
      break;

    case 'connected': {
      // Full session hydration on WS connect (page refresh or session switch)
      if (data?.session) dispatch({ type: 'SET_SESSION',          payload: data.session });
      if (data?.findings) dispatch({ type: 'SET_FINDINGS_SUMMARY', payload: data.findings });
      if (data?.flags)    dispatch({ type: 'SET_FLAGS',            payload: data.flags });

      // Restore attack graph
      if (data?.graph) {
        dispatch({ type: 'SET_GRAPH', payload: {
          nodes: data.graph.nodes || [],
          edges: data.graph.edges || []
        }});
      }

      // Restore current phase and completed phases
      if (data?.current_phase) {
        dispatch({ type: 'PHASE_CHANGE', payload: { phase: data.current_phase } });
      }
      if (data?.phases_completed?.length) {
        data.phases_completed.forEach(phase => {
          dispatch({ type: 'PHASE_DONE', payload: { phase } });
        });
      }

      // Replay recent logs into feed
      if (data?.recent_logs?.length) {
        [...data.recent_logs].reverse().forEach(log => {
          dispatch({ type: 'FEED_ENTRY', payload: {
            ts:        new Date(log.timestamp || Date.now()).toLocaleTimeString(),
            agent:     normalizeAgent(log.agent || 'master'),
            eventType: 'agent_log',
            message:   log.message || log.action || '',
            data:      log
          }});
        });
      }

      // Replay tool outputs into per-agent terminal buffers
      if (data?.tool_outputs?.length) {
        data.tool_outputs.forEach(out => {
          const agentKey = normalizeAgent(out.agent || 'master');
          (out.stdout || '').split('\n').filter(Boolean).forEach(line => {
            dispatch({ type: 'TOOL_LINE', payload: { agent: agentKey, line, lineType: 'stdout' } });
          });
        });
      }

      // Restore attack tree / plan steps from session summary
      if (data?.session?.attack_tree) {
        dispatch({ type: 'ATTACK_TREE_READY', payload: data.session.attack_tree });
      }

      // v3: Restore credential/tunnel/persistence snapshots if backend sends them
      if (data?.credentials?.length) {
        data.credentials.forEach(c => dispatch({ type: 'CREDENTIAL_FOUND', payload: c }));
      }
      if (data?.tunnels?.length) {
        data.tunnels.forEach(t => dispatch({ type: 'TUNNEL_ESTABLISHED', payload: t }));
      }
      if (data?.persistence?.length) {
        data.persistence.forEach(p => dispatch({ type: 'PERSISTENCE_PLANTED', payload: p }));
      }

      break;
    }

    // ── Pause / Resume ────────────────────────────────────
    case 'scan_paused':
      dispatch({ type: 'UPDATE_SESSION_STATUS', payload: 'paused' });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'scan_paused',
        message: `Scan paused — ${data?.message || ''}`, data
      }});
      break;

    case 'scan_resumed':
      dispatch({ type: 'UPDATE_SESSION_STATUS', payload: 'active' });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'scan_resumed',
        message: `Scan resumed`, data
      }});
      break;

    case 'checkpoint_restored':
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent, eventType: 'checkpoint_restored',
        message: `Checkpoint restored — resuming after ${data?.resume_after || '?'}`, data
      }});
      break;

    // ── Tool timeout warning ───────────────────────────────
    case 'tool_timeout_warning': {
      const saD = data || msg;
      dispatch({ type: 'TOOL_TIMEOUT_WARNING', payload: {
        tool:         saD.tool         || '',
        subagent:     saD.subagent     || '',
        elapsed_sec:  saD.elapsed_sec  || 0,
        deadline_sec: saD.deadline_sec || 600,
      }});
      break;
    }

    // ── Awaiting confirmation (exploit gate or web gate) ──
    case 'awaiting_confirmation': {
      const phase = data?.phase || '';
      if (phase === 'web_testing') {
        dispatch({ type: 'WEB_CONFIRM_PENDING', payload: true });
      }
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'awaiting_confirmation',
        message: phase === 'web_testing'
          ? `⚠ Web testing ready — confirm to proceed`
          : `⚠ Exploitation ready — confirm to proceed`,
        data
      }});
      break;
    }

    // ── Phase time-extension request ──────────────────────
    case 'awaiting_time_extension': {
      const etd = data || msg;
      dispatch({ type: 'PHASE_TIME_EXTENSION', payload: {
        phase:       etd.phase       || 'web_testing',
        timeout_secs: etd.timeout_secs || 0,
        message:     etd.message     || 'Phase timed out — extend or stop?',
      }});
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'awaiting_time_extension',
        message: `⏱ ${etd.phase || 'Phase'} timed out — extend or stop?`, data: etd
      }});
      break;
    }

    // ── Phase extended by operator ────────────────────────
    case 'phase_extended': {
      dispatch({ type: 'CLEAR_PHASE_TIME_EXTENSION' });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'phase_extended',
        message: `⏱ ${data?.phase || 'Phase'} extended by operator`, data
      }});
      break;
    }

    // ── Phase stopped (timeout with no extension) ─────────
    case 'phase_stopped': {
      dispatch({ type: 'CLEAR_PHASE_TIME_EXTENSION' });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'phase_stopped',
        message: `⏹ ${data?.phase || 'Phase'} stopped — no extension received`, data
      }});
      break;
    }

    // ── Phase skipped (confirmation denied or timed out) ──
    case 'phase_skipped': {
      dispatch({ type: 'WEB_CONFIRM_PENDING', payload: false });
      dispatch({ type: 'FEED_ENTRY', payload: {
        ts, agent: 'master', eventType: 'phase_skipped',
        message: `⏭ ${data?.phase || 'Phase'} skipped`, data
      }});
      break;
    }

    default: break;
  }
}

function extractFeedMessage(type, agent, data) {
  switch (type) {
    case 'agent_status':          return data?.message || `${agent} → ${data?.status}`;
    case 'tool_start':            return `▶ ${data?.tool}: ${(data?.command||'').slice(0,80)}`;
    case 'tool_done':             return `✓ ${data?.tool} done (exit ${data?.exit_code})`;
    case 'phase_change':          return `Phase: ${normalizePhase(data?.phase)?.toUpperCase()}`;
    case 'phase_done':            return `Phase ${normalizePhase(data?.phase)} complete`;
    case 'state_change':          return `${data?.from} → ${data?.to}`;
    case 'finding':               return `[${(data?.finding?.severity||'?').toUpperCase()}] ${data?.finding?.title}`;
    case 'flag_found':            return `FLAG: ${data?.flag_type} — ${data?.value}`;
    case 'master_plan':           return `Plan ready for ${data?.target}`;
    case 'llm_status':            return data?.available ? `LLM online: ${data?.model}` : `LLM offline`;
    case 'awaiting_confirmation':      return data?.phase === 'web_testing' ? `⚠ Confirm web testing` : `⚠ Confirm exploitation`;
    case 'awaiting_time_extension':    return `⏱ ${data?.phase||'Phase'} timed out — extend or stop?`;
    case 'phase_extended':             return `⏱ ${data?.phase||'Phase'} extended`;
    case 'phase_stopped':              return `⏹ ${data?.phase||'Phase'} stopped`;
    case 'phase_skipped':              return `⏭ ${data?.phase||'Phase'} skipped`;
    case 'scan_paused':           return `⏸ Scan paused`;
    case 'scan_resumed':          return `▶ Scan resumed`;
    case 'checkpoint_restored':   return `♻ Checkpoint restored — resuming after ${data?.resume_after || '?'}`;
    case 'plan_skeleton_restore': return `▶ Resumed — ${(data?.phases_completed||[]).length} phase(s) already done`;
    case 'pentest_complete':      return `Pentest complete`;
    case 'attack_tree_ready':     return `Attack tree: ${(data?.tree?.attack_nodes||[]).length} nodes`;
    case 'graph_node':            return `${data?.label} (${data?.type})`;
    case 'graph_edge':            return `${data?.source} → ${data?.target}`;
    case 'report_ready':          return `Report ready`;
    case 'guidance_applied':      return `${data?.message}`;
    // v3 events
    case 'network_scan_complete': return `Network scan done: ${(data?.open_ports||[]).length} ports`;
    case 'shell_obtained':        return `Shell on ${data?.rhost}:${data?.rport}`;
    case 'traffic_capture_added':return `Traffic: ${data?.packets??0} pkts${data?.credentials?.length?`, ${data.credentials.length} creds`:''}`;
    case 'mitre_mapped':          return `MITRE ${data?.id}: ${data?.name} (${data?.tactic})`;
    case 'evidence_added':        return `Evidence [${data?.evidence_type||data?.type}]: ${data?.description||data?.flag||''}`;
    case 'subagent_start':        return `Subagent started: ${data?.subagent || data?.agent}`;
    case 'subagent_complete':     return `Subagent done: ${data?.subagent || data?.agent}`;
    case 'subagent_error':        return `Subagent error: ${data?.subagent || data?.agent}`;
    case 'credential_found':      return `Credential: ${data?.user}@${data?.host}`;
    case 'tunnel_established':    return `Tunnel: ${data?.type} :${data?.local_port} → ${data?.remote_host}:${data?.remote_port}`;
    case 'persistence_planted':   return `Persistence: ${data?.mechanism} on ${data?.host}`;
    case 'burp_scan_complete':    return `Burp: ${data?.issue_count || 0} issues`;
    case 'chain_exploit_success': return `Chain success: ${data?.chain_id || data?.step_id}`;
    case 'privesc_success':       return `PRIVESC: ${data?.new_user || 'root'} on ${data?.shell_id}`;
    default:                      return data?.message || null;
  }
}

function useStore() {
  const ctx = useContext(StoreCtx);
  if (!ctx) throw new Error('useStore must be inside StoreProvider');
  return ctx;
}

window.StoreProvider = StoreProvider;
window.useStore      = useStore;
