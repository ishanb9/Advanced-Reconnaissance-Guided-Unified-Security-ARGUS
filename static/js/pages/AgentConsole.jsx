// ═══════════════════════════════════════════════════════════
// AgentConsole.jsx — Unified Agent + Subagent hierarchical view
//   Tabs: Output | Reasoning | Comms | Subagents
// ═══════════════════════════════════════════════════════════
const { useState, useEffect, useRef, useCallback } = React;

// Order reflects the operator-driven model: the Operator drives the engagement;
// the meta-agents advise it live; the classic phase agents are fallback-only
// (they run when the operator/LLM is unavailable, or when the operator delegates
// a bulk macro).  Mission Control is the live cockpit — this page lets you
// inspect each agent's output / reasoning / comms.
const AGENT_ORDER = ['operator','error_analyzer','red_team','attack_graph',
                     'master','recon','vuln','web','osint','exploit','privesc','iot','shell','payload'];
const AGENT_META = {
  operator:       { icon: '🎯', color: '#7B6CF6',     label: 'Operator', group: 'driver' },
  error_analyzer: { icon: '🩺', color: 'var(--amber)', label: 'Error Analyzer', group: 'meta' },
  red_team:       { icon: '🛡', color: 'var(--red)',   label: 'Red-Team Expert', group: 'meta' },
  attack_graph:   { icon: '🕸', color: '#00cfff',      label: 'Attack Graph', group: 'meta' },
  master:  { icon: '⚡', color: 'var(--cyan)',   label: 'Master',  group: 'fallback' },
  recon:   { icon: '🔍', color: 'var(--green)',  label: 'Recon',   group: 'fallback' },
  vuln:    { icon: '🔬', color: 'var(--amber)',  label: 'Vuln',    group: 'fallback' },
  web:     { icon: '🌐', color: '#00cfff',       label: 'Web',     group: 'fallback' },
  osint:   { icon: '🕵', color: '#a050ff',       label: 'OSINT',   group: 'fallback' },
  exploit: { icon: '💥', color: 'var(--red)',    label: 'Exploit', group: 'fallback' },
  privesc: { icon: '🔑', color: '#ff6400',       label: 'Privesc', group: 'fallback' },
  iot:     { icon: '📟', color: '#73d13d',       label: 'IoT',     group: 'fallback' },
  shell:   { icon: '🐚', color: 'var(--cyan)',   label: 'Shell',   group: 'fallback' },
  payload: { icon: '📦', color: 'var(--amber)',  label: 'Payload', group: 'fallback' },
};

// Maps each agent to the subagents/tools it spawns
const AGENT_SUBAGENTS = {
  operator:       ['run_tool', 'http', 'shell', 'cve_lookup', 'handover', 'loot_hunt'],
  error_analyzer: [],
  red_team:       [],
  attack_graph:   [],
  master:  [],
  recon:   ['network_scan', 'dns_recon', 'service_banner', 'web_fingerprint'],
  vuln:    ['cve_lookup', 'service_vuln', 'ssl_audit', 'smb_vuln', 'ldap_vuln', 'ftp_vuln', 'ssh_audit'],
  web:     ['dir_fuzz', 'web_vuln_scan', 'sqli', 'xss', 'ssrf', 'cms_detect', 'auth_bypass'],
  osint:   [
    'theharvester', 'recon_ng', 'wayback', 'ahmia',
    'shodan', 'hibp', 'builtwith', 'bgpview',
    'google_dorks', 'security_trails', 'tineye', 'spiderfoot', 'censys',
  ],
  exploit: ['searchsploit', 'web_exploit', 'credential_spray', 'metasploit', 'exploit_chain', 'post_module'],
  privesc: ['linux_enum', 'windows_enum', 'linux_exploit', 'windows_exploit', 'container_escape', 'cloud_meta'],
  iot:     ['iot_device_scan', 'iot_default_creds', 'iot_protocol', 'iot_firmware'],
  shell:   ['shell_stabilise', 'pty_upgrade'],
  payload: ['payload_gen', 'encoder', 'av_check'],
  // lateral and post are phases not agents in the sidebar, but are shown via master
};

const SUBAGENT_META = {
  // Operator toolbelt (the operator drives tools directly via these)
  run_tool:           { icon: '🛠', label: 'Run Tool (any)'   },
  http:               { icon: '🌐', label: 'Stateful HTTP'    },
  handover:           { icon: '🤝', label: 'Shell Handover'   },
  loot_hunt:          { icon: '💎', label: 'Loot Hunt'        },
  network_scan:       { icon: '📡', label: 'Network Scan'     },
  dns_recon:          { icon: '🌍', label: 'DNS Recon'        },
  service_banner:     { icon: '🏷',  label: 'Service Banner'  },
  web_fingerprint:    { icon: '🖐',  label: 'Web Fingerprint' },
  cve_lookup:         { icon: '🔎', label: 'CVE Lookup'       },
  service_vuln:       { icon: '🔩', label: 'Service Vuln'     },
  ssl_audit:          { icon: '🔒', label: 'SSL Audit'        },
  smb_vuln:           { icon: '🗂',  label: 'SMB Vuln'        },
  ldap_vuln:          { icon: '📂', label: 'LDAP Vuln'        },
  ftp_vuln:           { icon: '📁', label: 'FTP Vuln'         },
  ssh_audit:          { icon: '🔑', label: 'SSH Audit'        },
  web_spider:         { icon: '🕸',  label: 'Web Spider'      },
  dir_fuzz:           { icon: '📂', label: 'Dir Fuzz'         },
  web_vuln_scan:      { icon: '🔬', label: 'Web Vuln Scan'    },
  sqli:               { icon: '💉', label: 'SQLi'             },
  xss:                { icon: '🪲', label: 'XSS'              },
  ssrf:               { icon: '🌀', label: 'SSRF'             },
  cms_detect:         { icon: '🏗',  label: 'CMS Detect'      },
  auth_bypass:        { icon: '🔓', label: 'Auth Bypass'      },
  // OSINT subagents
  theharvester:       { icon: '📧', label: 'theHarvester'      },
  recon_ng:           { icon: '🔗', label: 'Recon-ng'          },
  wayback:            { icon: '📜', label: 'Wayback Machine'   },
  ahmia:              { icon: '🧅', label: 'Ahmia (Dark Web)'  },
  shodan:             { icon: '🔭', label: 'Shodan'            },
  hibp:               { icon: '🔓', label: 'Have I Been Pwned' },
  builtwith:          { icon: '🏗',  label: 'BuiltWith'        },
  bgpview:            { icon: '🌐', label: 'BGPView'           },
  google_dorks:       { icon: '🎯', label: 'Google Dorks'      },
  security_trails:    { icon: '🗂',  label: 'SecurityTrails'   },
  tineye:             { icon: '🖼',  label: 'TinEye'           },
  spiderfoot:         { icon: '🕷',  label: 'SpiderFoot'       },
  censys:             { icon: '🔬', label: 'Censys'            },
  searchsploit:       { icon: '🔍', label: 'Searchsploit'     },
  web_exploit:        { icon: '💉', label: 'Web Exploit'      },
  credential_spray:   { icon: '🔓', label: 'Cred Spray'       },
  metasploit:         { icon: '🎯', label: 'Metasploit'       },
  exploit_chain:      { icon: '⛓',  label: 'Exploit Chain'   },
  post_module:        { icon: '📦', label: 'Post Module'      },
  linux_enum:         { icon: '🐧', label: 'Linux Enum'       },
  windows_enum:       { icon: '🪟', label: 'Windows Enum'     },
  linux_exploit:      { icon: '🐧', label: 'Linux Exploit'    },
  windows_exploit:    { icon: '🪟', label: 'Win Exploit'      },
  container_escape:   { icon: '🐳', label: 'Container Esc'    },
  cloud_meta:         { icon: '☁',  label: 'Cloud Meta'       },
  shell_stabilise:    { icon: '🐚', label: 'Shell Stabilise'  },
  pty_upgrade:        { icon: '💻', label: 'PTY Upgrade'      },
  payload_gen:        { icon: '🧨', label: 'Payload Gen'      },
  encoder:            { icon: '🔧', label: 'Encoder'          },
  av_check:           { icon: '🛡',  label: 'AV Check'        },
  // IoT subagents
  iot_device_scan:    { icon: '📟', label: 'Device Scan'      },
  iot_default_creds:  { icon: '🔑', label: 'Default Creds'    },
  iot_protocol:       { icon: '📡', label: 'Protocol Analysis' },
  iot_firmware:       { icon: '💾', label: 'Firmware CVEs'    },
};

// ── Status helpers ─────────────────────────────────────────────────────────────
function statusColor(s) {
  return ({ running: 'var(--green)', complete: 'var(--cyan)', done: 'var(--cyan)',
            error: 'var(--red)', idle: 'var(--border)', waiting: 'var(--amber)', thinking: 'var(--cyan)' }[s] || 'var(--border)');
}
function statusIcon(s) {
  return ({ running: '▶', complete: '✓', done: '✓', error: '✗', idle: '○', waiting: '…' }[s] || '○');
}

// ── CommsEntry (unchanged) ─────────────────────────────────────────────────────
function CommsEntry({ entry, agentColor }) {
  const [expanded, setExpanded] = useState(false);
  const isLLM  = entry.type === 'llm';
  const typeColor = isLLM ? '#00d4ff' : '#a050ff';
  const typeIcon  = isLLM ? '🧠' : '📚';
  const typeLabel = isLLM ? 'LLM' : 'RAG';
  const query     = isLLM ? entry.prompt   : entry.query;
  const reply     = isLLM ? entry.response : entry.result;
  const hasReply  = reply && reply !== '(no results)';

  return React.createElement('div', { 'data-slot': 'AgentConsole.CommsEntry',
    onClick: () => setExpanded(e => !e),
    style: {
      borderRadius: 6, padding: '8px 10px', marginBottom: 5, cursor: 'pointer',
      border: `1px solid ${expanded ? typeColor + '40' : 'var(--border)'}`,
      background: expanded ? `${typeColor}06` : 'var(--bg-surface)',
      transition: 'all 0.15s',
    }
  },
    React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6, marginBottom: expanded ? 8 : 0 } },
      React.createElement('span', {
        style: { fontSize: 9, padding: '2px 6px', borderRadius: 3, flexShrink: 0, fontWeight: 700,
                 background: `${typeColor}15`, border: `1px solid ${typeColor}40`,
                 color: typeColor, fontFamily: 'var(--font-mono)' }
      }, `${typeIcon} ${typeLabel}`),
      entry.phase && React.createElement('span', {
        style: { fontSize: 8, color: 'var(--border-light)', fontFamily: 'var(--font-mono)', flexShrink: 0 }
      }, entry.phase.toUpperCase()),
      entry.type === 'rag' && React.createElement('span', {
        style: { fontSize: 8, flexShrink: 0, color: entry.found ? 'var(--green)' : 'var(--border-light)' }
      }, entry.found ? '✓ hit' : '○ miss'),
      React.createElement('div', {
        style: { flex: 1, minWidth: 0, fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                 whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }
      }, query ? query.slice(0, 70) + (query.length > 70 ? '…' : '') : ''),
      React.createElement('span', {
        style: { fontSize: 8, color: 'var(--bg-elevated)', flexShrink: 0, fontFamily: 'var(--font-mono)' }
      }, entry.ts ? new Date(entry.ts).toLocaleTimeString() : ''),
      React.createElement('span', { style: { fontSize: 8, color: 'var(--border)', flexShrink: 0 } }, expanded ? '▲' : '▼'),
    ),
    expanded && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 6 } },
      React.createElement('div', {
        style: { borderRadius: 4, padding: '6px 8px', background: 'var(--bg-surface)', border: `1px solid ${typeColor}20` }
      },
        React.createElement('div', {
          style: { fontSize: 8, color: typeColor, fontWeight: 700, letterSpacing: 0.8,
                   textTransform: 'uppercase', marginBottom: 4 }
        }, isLLM ? '▸ Prompt' : '▸ RAG Query'),
        React.createElement('div', {
          style: { fontSize: 10, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)',
                   lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                   maxHeight: 150, overflowY: 'auto' }
        }, query || '—')
      ),
      hasReply && React.createElement('div', {
        style: { borderRadius: 4, padding: '6px 8px', background: 'var(--bg-surface)', border: `1px solid ${agentColor}15` }
      },
        React.createElement('div', {
          style: { fontSize: 8, color: agentColor, fontWeight: 700, letterSpacing: 0.8,
                   textTransform: 'uppercase', marginBottom: 4 }
        }, isLLM ? '◂ Response' : '◂ KB Results'),
        React.createElement('div', {
          style: { fontSize: 10, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)',
                   lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                   maxHeight: 180, overflowY: 'auto' }
        }, reply),
        isLLM && entry.model && React.createElement('div', {
          style: { marginTop: 4, fontSize: 8, color: 'var(--border)', fontFamily: 'var(--font-mono)' }
        }, `model: ${entry.model}`)
      ),
      !hasReply && React.createElement('div', {
        style: { fontSize: 10, color: 'var(--border)', fontFamily: 'var(--font-mono)', padding: '2px 0' }
      }, entry.type === 'rag' ? '⊘ No KB results' : '⟳ Awaiting response…')
    )
  );
}

// ── SubagentRow: expandable subagent entry ────────────────────────────────────
function SubagentRow({ name, agentColor, sessionId }) {
  const { state } = window.useStore();
  const { subagentStates = {}, subagentLines = {} } = state;
  const [expanded,      setExpanded]     = useState(false);
  const [showRestart,   setShowRestart]  = useState(false);
  const [restartNote,   setRestartNote]  = useState('');
  const [restartTool,   setRestartTool]  = useState('');
  const [restartArgs,   setRestartArgs]  = useState('');
  const [actionPending, setActionPending]= useState(false);
  const [actionMsg,     setActionMsg]    = useState('');

  const saState   = subagentStates[name] || {};
  const lines     = subagentLines[name] || [];
  const meta      = SUBAGENT_META[name] || { icon: '◆', label: name };
  const status    = saState.status || 'idle';
  const isRunning = status === 'running';
  const isStopped = status === 'stopped';
  const sColor    = status === 'stopped' ? 'var(--amber)' : statusColor(status);

  // ── Run: injects guidance so master queues this subagent's tool ──
  const handleRun = useCallback(async (e) => {
    e.stopPropagation();
    if (!sessionId) return;
    setActionPending(true); setActionMsg('');
    try {
      const res = await fetch('/api/subagents/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, subagent: name }),
      });
      if (res.ok) setActionMsg('✓ Queued');
      else setActionMsg('✗ Failed');
    } catch { setActionMsg('✗ Error'); }
    setActionPending(false);
    setTimeout(() => setActionMsg(''), 3000);
  }, [sessionId, name]);

  // ── Stop: cancels this specific subagent/tool ──
  const handleStop = useCallback(async (e) => {
    e.stopPropagation();
    if (!sessionId) return;
    setActionPending(true);
    try {
      await fetch(`/sessions/${sessionId}/subagent/${encodeURIComponent(name)}/stop`, { method: 'POST' });
      setActionMsg('⏹ Stopped');
      setShowRestart(true);
    } catch { setActionMsg('✗ Error'); }
    setActionPending(false);
    setTimeout(() => setActionMsg(''), 4000);
  }, [sessionId, name]);

  // ── Restart: stop + inject guidance with optional note ──
  const handleRestart = useCallback(async (e) => {
    e.stopPropagation();
    if (!sessionId) return;
    setActionPending(true);
    try {
      const res = await fetch(`/sessions/${sessionId}/subagent/${encodeURIComponent(name)}/restart`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: restartNote, force_tool: restartTool, force_args: restartArgs }),
      });
      if (res.ok) { setActionMsg('↺ Restart queued'); setShowRestart(false); setRestartNote(''); }
      else setActionMsg('✗ Failed');
    } catch { setActionMsg('✗ Error'); }
    setActionPending(false);
    setTimeout(() => setActionMsg(''), 4000);
  }, [sessionId, name, restartNote, restartTool, restartArgs]);

  const inp = {
    width: '100%', background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
    color: 'var(--text-primary)', fontSize: 10, padding: '5px 8px', outline: 'none',
    fontFamily: 'var(--font-mono)', boxSizing: 'border-box',
  };

  return React.createElement('div', { 'data-slot': 'AgentConsole.SubagentRow',
    style: {
      borderRadius: 6, marginBottom: 4, overflow: 'hidden',
      border: `1px solid ${expanded ? agentColor + '30' : isStopped ? 'rgba(255,170,0,0.2)' : 'var(--border)'}`,
      background: expanded ? `${agentColor}04` : isStopped ? 'rgba(255,170,0,0.02)' : 'var(--bg-surface)',
      transition: 'all 0.15s',
    }
  },
    // ── Header row ───────────────────────────────────────────────────────
    React.createElement('div', {
      onClick: () => setExpanded(e => !e),
      style: { display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px', cursor: 'pointer' }
    },
      // Status dot
      React.createElement('span', {
        style: {
          width: 7, height: 7, borderRadius: '50%', flexShrink: 0, background: sColor,
          boxShadow: isRunning ? `0 0 5px ${sColor}` : 'none',
        }
      }),
      React.createElement('span', { style: { fontSize: 13, flexShrink: 0 } }, meta.icon),
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },
        React.createElement('div', {
          style: { fontSize: 11, color: status === 'idle' ? 'var(--text-muted)' : 'var(--text-primary)',
                   fontFamily: 'var(--font-mono)', fontWeight: status !== 'idle' ? 600 : 400 }
        }, meta.label),
        React.createElement('div', {
          style: { display: 'flex', gap: 6, marginTop: 1, fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--border-light)' }
        },
          React.createElement('span', { style: { color: sColor } },
            `${isStopped ? '⏹' : statusIcon(status)} ${status.toUpperCase()}`),
          saState.findings_count > 0 && React.createElement('span', { style: { color: 'var(--amber)' } },
            `${saState.findings_count} findings`),
          saState.duration && React.createElement('span', null, `${saState.duration}s`),
          saState.target && React.createElement('span', {
            style: { color: 'var(--border)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 100 }
          }, saState.target),
        )
      ),
      // Lines badge
      lines.length > 0 && React.createElement('span', {
        style: { fontSize: 9, color: 'var(--border-light)', fontFamily: 'var(--font-mono)',
                 padding: '1px 5px', borderRadius: 3, background: 'var(--bg-panel)', flexShrink: 0 }
      }, `${lines.length} lines`),

      // Action feedback
      actionMsg && React.createElement('span', {
        style: { fontSize: 9, color: actionMsg.startsWith('✓') || actionMsg.startsWith('↺') ? 'var(--green)'
                   : actionMsg.startsWith('⏹') ? 'var(--amber)' : 'var(--red)',
                 fontFamily: 'var(--font-mono)', flexShrink: 0 }
      }, actionMsg),

      // ── Stop button (only when running) ──────────────────────────────
      sessionId && isRunning && React.createElement('button', {
        onClick: handleStop,
        disabled: actionPending,
        title: `Stop ${meta.label}`,
        className: 'btn btn-danger',
        style: {
          padding: '2px 8px', borderRadius: 4, cursor: 'pointer', flexShrink: 0, fontSize: 9,
          fontFamily: 'var(--font-mono)', fontWeight: 700,
          border: `1px solid var(--critical)`,
          background: 'var(--critical-bg)', color: 'var(--critical)',
          opacity: actionPending ? 0.5 : 1,
        }
      }, actionPending ? '…' : '■ Stop'),

      // ── Restart button (when stopped) ─────────────────────────────────
      sessionId && isStopped && React.createElement('button', {
        onClick: e => { e.stopPropagation(); setShowRestart(r => !r); },
        title: `Restart ${meta.label}`,
        className: 'btn',
        style: {
          padding: '2px 8px', borderRadius: 4, cursor: 'pointer', flexShrink: 0, fontSize: 9,
          fontFamily: 'var(--font-mono)', fontWeight: 700,
          border: `1px solid var(--medium)`,
          background: 'rgba(255,170,0,0.08)', color: 'var(--medium)',
        }
      }, showRestart ? '✕ Cancel' : '↺ Restart'),

      // ── Run button (when idle/complete/error — not running/stopped) ───
      sessionId && !isRunning && !isStopped && React.createElement('button', {
        onClick: handleRun,
        disabled: actionPending,
        title: `Run ${meta.label} manually`,
        className: 'btn btn-primary',
        style: {
          padding: '2px 8px', borderRadius: 4, cursor: 'pointer', flexShrink: 0, fontSize: 9,
          fontFamily: 'var(--font-mono)',
          border: `1px solid var(--accent)`,
          background: 'var(--accent)', color: '#0D0E14',
          opacity: actionPending ? 0.5 : 1,
        }
      }, actionPending ? '…' : '▶ Run'),

      // Expand toggle
      lines.length > 0 && React.createElement('span', {
        style: { fontSize: 9, color: 'var(--border)', flexShrink: 0, marginLeft: 2 }
      }, expanded ? '▲' : '▼'),
    ),

    // ── Restart panel ─────────────────────────────────────────────────────
    showRestart && React.createElement('div', {
      style: {
        padding: '10px 12px', background: 'var(--bg-surface)',
        borderTop: '1px solid rgba(255,170,0,0.15)',
        display: 'flex', flexDirection: 'column', gap: 6,
      }
    },
      React.createElement('div', {
        style: { fontSize: 9, color: 'var(--amber)', fontFamily: 'var(--font-mono)', fontWeight: 700, marginBottom: 2 }
      }, `↺ RESTART ${meta.label.toUpperCase()}`),
      React.createElement('textarea', {
        style: { ...inp, minHeight: 52, resize: 'vertical' },
        placeholder: `Operator note — why restarting, what to change, any hints for the agent (e.g. "try port 8443 instead", "add -sV flag")`,
        value: restartNote, onChange: e => setRestartNote(e.target.value),
      }),
      React.createElement('div', { style: { display: 'flex', gap: 5 } },
        React.createElement('input', {
          style: { ...inp, flex: 1 },
          placeholder: 'Override tool (optional, e.g. nmap)',
          value: restartTool, onChange: e => setRestartTool(e.target.value),
        }),
        React.createElement('input', {
          style: { ...inp, flex: 2 },
          placeholder: 'Tool args override (optional)',
          value: restartArgs, onChange: e => setRestartArgs(e.target.value),
        }),
      ),
      React.createElement('div', { style: { display: 'flex', gap: 6 } },
        React.createElement('button', {
          onClick: handleRestart,
          disabled: actionPending,
          className: 'btn',
          style: {
            flex: 1, padding: '6px', borderRadius: 4, cursor: 'pointer', fontSize: 10,
            fontFamily: 'var(--font-mono)', fontWeight: 700,
            border: `1px solid var(--medium)`,
            background: 'rgba(255,170,0,0.1)', color: 'var(--medium)',
            opacity: actionPending ? 0.5 : 1,
          }
        }, actionPending ? '⟳ Sending…' : '↺ Restart with Note'),
        React.createElement('button', {
          onClick: handleRun,
          disabled: actionPending,
          className: 'btn btn-primary',
          style: {
            padding: '6px 12px', borderRadius: 4, cursor: 'pointer', fontSize: 10,
            fontFamily: 'var(--font-mono)',
            border: `1px solid var(--accent)`,
            background: 'var(--accent)', color: '#0D0E14',
            opacity: actionPending ? 0.5 : 1,
          }
        }, '▶ Skip note & Run'),
      ),
    ),

    // ── Tool exit code badges ──────────────────────────────────────────────
    saState.toolExits && Object.keys(saState.toolExits).length > 0 && React.createElement('div', {
      style: {
        padding: '0 10px 6px', display: 'flex', flexWrap: 'wrap', gap: 4,
        borderTop: expanded ? 'none' : `1px solid ${agentColor}10`,
      }
    },
      Object.entries(saState.toolExits).map(([tool, ex]) =>
        React.createElement('span', {
          key: tool,
          style: {
            fontSize: 9, padding: '2px 6px', borderRadius: 3,
            fontFamily: 'var(--font-mono)', fontWeight: 700,
            background: ex.exit_code === -2 ? 'rgba(255,170,0,0.10)'
                      : ex.success ? 'rgba(0,255,136,0.08)' : 'var(--critical-bg)',
            border: `1px solid ${ex.exit_code === -2 ? 'var(--medium)'
                      : ex.success ? 'rgba(0,255,136,0.25)' : 'var(--critical)'}`,
            color: ex.exit_code === -2 ? 'var(--medium)'
                 : ex.success ? 'var(--green)' : 'var(--critical)',
          }
        }, ex.exit_code === -2 ? `${tool} [CANCELLED]` : `${tool} [${ex.exit_code}]`)
      )
    ),

    // ── Expanded live output ───────────────────────────────────────────────
    expanded && lines.length > 0 && React.createElement('div', {
      style: {
        borderTop: `1px solid ${agentColor}15`, padding: '6px 10px',
        maxHeight: 280, overflowY: 'auto',
        fontFamily: 'var(--font-mono)', fontSize: 10, lineHeight: 1.6, background: 'var(--bg-surface)',
      }
    },
      lines.map((entry, i) => {
        const l = entry.line || '';
        const isCancelled = l.startsWith('[CANCELLED]');
        const lineColor = isCancelled            ? 'var(--amber)'
                        : l.startsWith('[EXIT 0]')  ? 'var(--green)'
                        : l.startsWith('[EXIT ')    ? 'var(--red)'
                        : l.startsWith('[ERROR]')   ? '#ff4466'
                        : l.startsWith('[STDERR]')  ? 'var(--amber)'
                        : l.startsWith('[+]')       ? 'var(--green)'
                        : l.startsWith('[-]')       ? 'var(--red)'
                        : l.startsWith('[*]')       ? agentColor
                        : l.startsWith('[MCP ')     ? 'var(--amber)'
                        : 'var(--text-muted)';
        const isSeparator = l.startsWith('[EXIT ') || isCancelled;
        return React.createElement('div', {
          key: i,
          style: {
            display: 'flex', gap: 6, alignItems: 'baseline', color: lineColor,
            borderTop: isSeparator ? `1px solid var(--bg-panel)` : 'none',
            paddingTop: isSeparator ? 4 : 0, marginTop: isSeparator ? 2 : 0,
          }
        },
          entry.ts && React.createElement('span', { style: { color: 'var(--bg-elevated)', fontSize: 9, flexShrink: 0 } }, entry.ts),
          entry.tool && React.createElement('span', {
            style: { color: agentColor + '80', fontSize: 9, flexShrink: 0,
                     padding: '0 4px', background: agentColor + '12', borderRadius: 2 }
          }, entry.tool),
          React.createElement('span', { style: { wordBreak: 'break-all', whiteSpace: 'pre-wrap', fontWeight: isSeparator ? 700 : 400 } }, l)
        );
      })
    ),

    // Expanded: empty output hint
    expanded && lines.length === 0 && status !== 'idle' && React.createElement('div', {
      style: {
        borderTop: `1px solid ${agentColor}15`, padding: '8px 12px',
        fontSize: 10, color: 'var(--border)', fontFamily: 'var(--font-mono)', background: 'var(--bg-surface)',
      }
    }, isRunning ? '⟳ Collecting output…' : '⊘ No output captured')
  );
}

// ── Subagents tab panel ────────────────────────────────────────────────────────
function SubagentsPanel({ selectedAgent, agentColor, sessionId }) {
  const subagentNames = AGENT_SUBAGENTS[selectedAgent] || [];

  if (subagentNames.length === 0) {
    return React.createElement('div', { 'data-slot': 'AgentConsole.SubagentsPanel',
      style: { flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
               flexDirection: 'column', gap: 8, color: 'var(--border)', fontFamily: 'var(--font-mono)' }
    },
      React.createElement('div', { style: { fontSize: 28 } }, '—'),
      React.createElement('div', { style: { fontSize: 12 } }, `${selectedAgent} has no subagents`),
    );
  }

  return React.createElement('div', {
    style: { flex: 1, overflowY: 'auto', padding: '10px 12px' }
  },
    // Section header: hierarchy label
    React.createElement('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '0 0 8px', marginBottom: 6,
        borderBottom: `1px solid ${agentColor}20`,
      }
    },
      React.createElement('span', { style: { fontSize: 10, color: agentColor, fontFamily: 'var(--font-mono)', fontWeight: 700 } },
        `${(AGENT_META[selectedAgent] || {}).icon || '◆'} ${selectedAgent.toUpperCase()}`),
      React.createElement('span', { style: { fontSize: 10, color: 'var(--border-light)', fontFamily: 'var(--font-mono)' } }, '→'),
      React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } },
        `${subagentNames.length} subagents`),
    ),

    // Subagent rows
    subagentNames.map(name =>
      React.createElement(SubagentRow, {
        key: name,
        name,
        agentColor,
        sessionId,
      })
    )
  );
}

// ── SubagentMatrix: compact grid of all 9 top-level agents ───────────────────
function SubagentMatrix() {
  const { state } = window.useStore();
  const { subagentStates = {}, agentStatus = {}, agents = {} } = state;
  const [collapsed, setCollapsed] = useState(false);

  // Resolve status for a given agent name
  function resolveStatus(name) {
    const fromSubagentStates = subagentStates[name]?.status;
    const fromAgentStatus    = agentStatus[name];
    const fromAgents         = agents[name]?.status;
    return fromSubagentStates || fromAgentStatus || fromAgents || 'idle';
  }

  function resolveCurrentTool(name) {
    const tool = subagentStates[name]?.currentTool || subagentStates[name]?.current_tool || '';
    if (!tool) return null;
    return tool.length > 8 ? tool.slice(0, 8) + '…' : tool;
  }

  function cellBg(status) {
    switch (status) {
      case 'running':
      case 'thinking': return 'rgba(var(--accent-rgb, 0,255,136), 0.08)';
      case 'complete':
      case 'done':     return 'rgba(82,196,26, 0.08)';
      case 'error':    return 'rgba(255,77,79, 0.10)';
      default:         return 'transparent';
    }
  }

  function cellBorder(status) {
    switch (status) {
      case 'running':
      case 'thinking': return '1px solid var(--accent)';
      case 'complete':
      case 'done':     return '1px solid var(--low)';
      case 'error':    return '1px solid var(--critical)';
      default:         return '1px solid var(--border)';
    }
  }

  function statusDotColor(status) {
    switch (status) {
      case 'running':
      case 'thinking': return 'var(--accent)';
      case 'complete':
      case 'done':     return 'var(--low)';
      case 'error':    return 'var(--critical)';
      default:         return 'var(--border)';
    }
  }

  function nameColor(status) {
    switch (status) {
      case 'running':
      case 'thinking': return 'var(--cyan)';
      case 'complete':
      case 'done':     return 'var(--low)';
      case 'error':    return 'var(--critical)';
      default:         return 'var(--text-muted)';
    }
  }

  const isActive = (s) => s === 'running' || s === 'thinking';

  return React.createElement('div', { 'data-slot': 'AgentConsole.SubagentMatrix',
    style: {
      background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '8px 12px', flexShrink: 0,
    }
  },
    // Header row with toggle
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: collapsed ? 0 : 10 }
    },
      React.createElement('span', {
        style: { fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)',
                 textTransform: 'uppercase', letterSpacing: 1.5, fontWeight: 700 }
      }, 'Agent Matrix'),
      React.createElement('button', {
        onClick: () => setCollapsed(c => !c),
        style: {
          background: 'transparent', border: '1px solid var(--border)', borderRadius: 4,
          color: 'var(--text-muted)', cursor: 'pointer', fontSize: 9,
          fontFamily: 'var(--font-mono)', padding: '2px 8px',
        }
      }, collapsed ? '▼ expand' : '▲ collapse'),
    ),

    // Grid of agent cells
    !collapsed && React.createElement('div', {
      style: { display: 'flex', flexWrap: 'wrap', gap: 6 }
    },
      AGENT_ORDER.map(name => {
        const meta   = AGENT_META[name] || { icon: '◆', label: name };
        const status = resolveStatus(name);
        const tool   = resolveCurrentTool(name);
        const active = isActive(status);

        return React.createElement('div', {
          key: name,
          style: {
            width: 80, height: 64, borderRadius: 8,
            border: cellBorder(status),
            background: cellBg(status),
            display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center',
            gap: 2, padding: 4, position: 'relative',
            boxSizing: 'border-box',
            animation: active ? 'pulse 1.5s infinite' : 'none',
          }
        },
          // Status dot
          React.createElement('div', {
            style: {
              position: 'absolute', top: 5, right: 5,
              width: 5, height: 5, borderRadius: '50%',
              background: statusDotColor(status),
              boxShadow: active ? `0 0 4px ${statusDotColor(status)}` : 'none',
            }
          }),
          // Icon
          React.createElement('span', { style: { fontSize: 20, lineHeight: 1 } }, meta.icon),
          // Agent name
          React.createElement('span', {
            style: {
              fontSize: 9, fontFamily: 'var(--font-mono)', color: nameColor(status),
              textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: active ? 700 : 400,
            }
          }, name),
          // Current tool (only when active)
          tool && React.createElement('span', {
            style: {
              fontSize: 8, fontFamily: 'var(--font-mono)', color: 'var(--accent)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 72,
            }
          }, tool),
        );
      })
    )
  );
}

// ── Main AgentConsole ─────────────────────────────────────────────────────────
function AgentConsole() {
  const { state } = window.useStore();
  const { agents, toolOutputs, reasoningLog, agentComms, subagentStates = {}, sessionId,
          llmThoughts = [] } = state;

  const [selectedAgent, setSelectedAgent] = useState('operator');
  const [tab,           setTab]           = useState('output');   // 'output'|'reasoning'|'comms'|'subagents'|'thoughts'
  const [commsFilter,   setCommsFilter]   = useState('all');
  const outputRef = useRef(null);
  const reasonRef = useRef(null);
  const commsRef  = useRef(null);

  useEffect(() => {
    if (tab === 'output' && outputRef.current)
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [toolOutputs[selectedAgent]?.length, tab]);

  useEffect(() => {
    if (tab === 'comms' && commsRef.current)
      commsRef.current.scrollTop = 0;
  }, [(agentComms[selectedAgent] || []).length, tab]);

  const meta           = AGENT_META[selectedAgent] || { icon: '◆', color: 'var(--cyan)', label: selectedAgent };
  const agentLines     = toolOutputs[selectedAgent] || [];
  const _driverView   = selectedAgent === 'master' || selectedAgent === 'operator';
  const agentReasoning = reasoningLog.filter(r =>
    !selectedAgent || _driverView || r.agent === selectedAgent
  );
  const rawComms           = agentComms?.[selectedAgent] || [];
  const agentCommsFiltered = commsFilter === 'all' ? rawComms : rawComms.filter(c => c.type === commsFilter);
  const llmCount           = rawComms.filter(c => c.type === 'llm').length;
  const ragCount           = rawComms.filter(c => c.type === 'rag').length;

  // Subagent summary count for this agent
  const mySubagents      = AGENT_SUBAGENTS[selectedAgent] || [];
  const activeSubagents  = mySubagents.filter(n => (subagentStates[n] || {}).status === 'running').length;
  const doneSubagents    = mySubagents.filter(n => ['complete','done'].includes((subagentStates[n] || {}).status)).length;
  const subagentTabLabel = mySubagents.length > 0
    ? `🔩 Subagents${activeSubagents > 0 ? ` ▶${activeSubagents}` : doneSubagents > 0 ? ` ✓${doneSubagents}` : ` (${mySubagents.length})`}`
    : '🔩 Subagents';

  // LLM Thoughts for selected agent (or all for master)
  const agentThoughts = _driverView
    ? llmThoughts
    : llmThoughts.filter(t => t.agent === selectedAgent);

  const tabBtn = (key, label) => React.createElement('button', {
    key, onClick: () => setTab(key),
    style: {
      padding: '8px 14px', background: 'transparent', border: 'none', cursor: 'pointer',
      fontSize: 11, fontFamily: 'var(--font-mono)',
      color:       tab === key ? meta.color : 'var(--text-muted)',
      borderBottom: tab === key ? `2px solid ${meta.color}` : '2px solid transparent',
      textTransform: 'uppercase', letterSpacing: 0.8, whiteSpace: 'nowrap',
    }
  }, label);

  return React.createElement('div', { 'data-slot': 'AgentConsole.AgentConsole',
    style: { display: 'flex', flexDirection: 'column', height: '100%',
             padding: 16, gap: 12, background: 'var(--bg-base, var(--bg-surface))' }
  },

    // ── Header ──────────────────────────────────────────────
    React.createElement('div', { className: 'page-header', style: { flexShrink: 0 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '🤖 Agent Roster'),
        React.createElement('div', { className: 'page-subtitle' },
          sessionId
            ? 'The Operator drives the engagement (Mission Control is the live cockpit). Meta-agents advise it; the classic phase agents are fallback-only. Select any agent to inspect its output, reasoning and comms.'
            : 'No active session — start a scan from Target Config.'
        )
      )
    ),

    // ── Agent Matrix ────────────────────────────────────────
    React.createElement(SubagentMatrix, null),

    // ── Main grid ───────────────────────────────────────────
    React.createElement('div', {
      style: { display: 'flex', gap: 12, flex: 1, overflow: 'hidden', minHeight: 0 }
    },

      // ── Left: agent list ────────────────────────────────
      React.createElement('div', {
        style: {
          background: 'var(--bg-surface)', border: '1px solid var(--bg-panel)', borderRadius: 8,
          width: 200, overflowY: 'auto', flexShrink: 0, padding: '6px 0',
        }
      },
        AGENT_ORDER.map(name => {
          const a         = agents[name] || { status: 'idle', message: '' };
          const isActive  = selectedAgent === name;
          const color     = (AGENT_META[name] || {}).color || 'var(--cyan)';
          const icon      = (AGENT_META[name] || {}).icon  || '◆';
          const lineCount = (toolOutputs[name] || []).length;
          const commCount = (agentComms?.[name] || []).length;
          const isRunning = a.status === 'running' || a.status === 'thinking';
          const saList    = AGENT_SUBAGENTS[name] || [];
          const saActive  = saList.filter(n => (subagentStates[n] || {}).status === 'running').length;
          const saDone    = saList.filter(n => ['complete','done'].includes((subagentStates[n] || {}).status)).length;

          return React.createElement('div', {
            key: name,
            onClick: () => setSelectedAgent(name),
            style: {
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '9px 12px', cursor: 'pointer',
              background:  isActive ? `${color}08` : 'transparent',
              borderLeft:  isActive ? `3px solid ${color}` : '3px solid transparent',
              transition: 'all 0.15s', position: 'relative',
            }
          },
            React.createElement('span', {
              style: {
                width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                background: statusColor(a.status),
                boxShadow: isRunning ? `0 0 5px ${statusColor(a.status)}` : 'none',
              }
            }),
            React.createElement('span', { style: { fontSize: 15 } }, icon),
            React.createElement('div', { style: { flex: 1, minWidth: 0 } },
              React.createElement('div', {
                style: {
                  fontSize: 11, fontWeight: isActive ? 600 : 400,
                  color: isActive ? color : 'var(--text-primary)',
                  textTransform: 'capitalize',
                }
              }, name),
              React.createElement('div', {
                style: { fontSize: 9, color: 'var(--border-light)', overflow: 'hidden',
                         textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                         fontFamily: 'var(--font-mono)', marginTop: 1 }
              },
                lineCount > 0
                  ? `${lineCount}L · ${commCount}C${saActive > 0 ? ` · ${saActive}▶SA` : saDone > 0 ? ` · ${saDone}✓SA` : saList.length > 0 ? ` · ${saList.length}SA` : ''}`
                  : a.status.toUpperCase()
              )
            ),
            isRunning && React.createElement('div', {
              style: {
                width: 4, height: 4, borderRadius: '50%', background: color,
                animation: 'pulse 1s infinite', flexShrink: 0,
              }
            })
          );
        })
      ),

      // ── Right: content panel ────────────────────────────
      React.createElement('div', {
        style: {
          background: 'var(--bg-surface)', border: '1px solid var(--bg-panel)', borderRadius: 8,
          flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }
      },

        // ── Panel header: agent name + tabs ─────────────────
        React.createElement('div', {
          style: { borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-surface)' }
        },
          React.createElement('div', {
            style: { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px 0' }
          },
            React.createElement('span', { style: { fontSize: 18 } }, meta.icon),
            React.createElement('span', {
              style: { fontSize: 12, fontWeight: 700, color: meta.color,
                       letterSpacing: 0.5, fontFamily: 'var(--font-mono)' }
            }, meta.label.toUpperCase()),
            React.createElement('span', {
              style: { fontSize: 10, color: statusColor(agents[selectedAgent]?.status || 'idle'),
                       fontFamily: 'var(--font-mono)' }
            }, (agents[selectedAgent]?.status || 'idle').toUpperCase()),
            agents[selectedAgent]?.message && React.createElement('span', {
              style: { fontSize: 10, color: 'var(--border-light)', fontFamily: 'var(--font-mono)',
                       overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }
            }, `-- ${agents[selectedAgent].message}`)
          ),
          React.createElement('div', { style: { display: 'flex', gap: 0, paddingLeft: 4 } },
            tabBtn('output',    `📟 Output (${agentLines.length})`),
            tabBtn('reasoning', `💭 Reasoning (${agentReasoning.length})`),
            tabBtn('comms',     `💬 Comms 🧠${llmCount} 📚${ragCount}`),
            tabBtn('subagents', subagentTabLabel),
            tabBtn('thoughts',  `💡 Thoughts (${agentThoughts.length})`),
          )
        ),

        // ── Tool Output tab ──────────────────────────────────
        tab === 'output' && React.createElement('div', {
          ref: outputRef,
          style: {
            flex: 1, overflowY: 'auto', padding: '8px 14px',
            fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.7,
          }
        },
          agentLines.length === 0
            ? React.createElement('div', {
                style: { color: 'var(--border)', textAlign: 'center', paddingTop: 40, fontSize: 12 }
              },
                React.createElement('div', { style: { fontSize: 32, marginBottom: 12 } }, meta.icon),
                sessionId ? `No output for ${meta.label} yet` : 'Start a session to see output'
              )
            : agentLines.map((entry, i) => {
                const l = entry.line || '';
                const lineColor = entry.type === 'stderr'        ? 'var(--red)'
                               : entry.type === 'warning'        ? 'var(--amber)'
                               : l.startsWith('[EXIT 0]')        ? 'var(--green)'
                               : l.startsWith('[EXIT ')          ? 'var(--red)'
                               : l.startsWith('[ERROR]')         ? '#ff4466'
                               : l.startsWith('[STDERR]')        ? 'var(--amber)'
                               : l.startsWith('[MCP ')           ? 'var(--amber)'
                               : l.startsWith('[+]')             ? 'var(--green)'
                               : l.startsWith('[-]')             ? 'var(--red)'
                               : l.startsWith('[*]')             ? meta.color
                               : 'var(--text-primary)';
                return React.createElement('div', {
                  key: i,
                  style: { color: lineColor, whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.5 }
                }, l);
              })
        ),

        // ── Reasoning tab ────────────────────────────────────
        tab === 'reasoning' && React.createElement('div', {
          ref: reasonRef,
          style: { flex: 1, overflowY: 'auto', padding: 12, display: 'flex', flexDirection: 'column', gap: 6 }
        },
          agentReasoning.length === 0
            ? React.createElement('div', {
                style: { color: 'var(--border)', textAlign: 'center', paddingTop: 40, fontSize: 12 }
              }, 'Reasoning steps appear here when agents make decisions')
            : [...agentReasoning].reverse().map((r, i) =>
                React.createElement('div', {
                  key: i,
                  style: { padding: '10px 12px', borderRadius: 7, background: 'var(--bg-panel)', border: '1px solid var(--border)' }
                },
                  React.createElement('div', {
                    style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }
                  },
                    React.createElement('span', {
                      style: { fontFamily: 'var(--font-mono)', fontSize: 9, color: meta.color, fontWeight: 700, letterSpacing: 0.5 }
                    }, r.step?.toUpperCase()),
                    React.createElement('div', { style: { display: 'flex', gap: 8 } },
                      r.phase && React.createElement('span', {
                        style: { fontSize: 8, color: 'var(--border-light)', fontFamily: 'var(--font-mono)' }
                      }, r.phase.toUpperCase()),
                      React.createElement('span', { style: { fontSize: 9, color: 'var(--border)' } }, r.ts)
                    )
                  ),
                  r.reasoning && React.createElement('div', {
                    style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 5, lineHeight: 1.6 }
                  }, r.reasoning),
                  r.decision && React.createElement('div', {
                    style: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--green)', marginBottom: 3 }
                  }, `> ${r.decision}`),
                  r.next_action && React.createElement('div', {
                    style: { fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--amber)' }
                  }, `! ${r.next_action}`)
                )
              )
        ),

        // ── Comms tab ────────────────────────────────────────
        tab === 'comms' && React.createElement('div', {
          style: { flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }
        },
          React.createElement('div', {
            style: { display: 'flex', gap: 4, padding: '8px 12px 6px',
                     borderBottom: '1px solid var(--border)', flexShrink: 0 }
          },
            ['all','llm','rag'].map(f =>
              React.createElement('div', {
                key: f,
                onClick: () => setCommsFilter(f),
                style: {
                  padding: '3px 10px', borderRadius: 5, cursor: 'pointer', fontSize: 9,
                  fontFamily: 'var(--font-mono)', fontWeight: 600,
                  border: commsFilter === f
                    ? `1px solid ${f === 'llm' ? '#00d4ff' : f === 'rag' ? '#a050ff' : meta.color}`
                    : '1px solid var(--border-light)',
                  background: commsFilter === f
                    ? (f === 'llm' ? 'rgba(0,212,255,0.08)' : f === 'rag' ? 'rgba(160,80,255,0.08)' : `${meta.color}10`)
                    : 'transparent',
                  color: commsFilter === f
                    ? (f === 'llm' ? '#00d4ff' : f === 'rag' ? '#a050ff' : meta.color)
                    : 'var(--border-light)',
                }
              }, f === 'all' ? `ALL (${rawComms.length})` : f === 'llm' ? `🧠 LLM (${llmCount})` : `📚 RAG (${ragCount})`)
            ),
            React.createElement('span', {
              style: { marginLeft: 'auto', fontSize: 9, color: 'var(--bg-elevated)',
                       fontFamily: 'var(--font-mono)', alignSelf: 'center' }
            }, 'click entry to expand')
          ),
          React.createElement('div', {
            ref: commsRef,
            style: { flex: 1, overflowY: 'auto', padding: '8px 10px' }
          },
            agentCommsFiltered.length === 0
              ? React.createElement('div', {
                  style: { color: 'var(--border)', textAlign: 'center', paddingTop: 40, fontSize: 12 }
                },
                  React.createElement('div', { style: { fontSize: 32, marginBottom: 12 } },
                    commsFilter === 'rag' ? '📚' : '🧠'),
                  sessionId
                    ? `No ${commsFilter === 'all' ? '' : commsFilter.toUpperCase() + ' '}communications yet`
                    : 'Start a session to see communications'
                )
              : agentCommsFiltered.map((entry, i) =>
                  React.createElement(CommsEntry, { key: i, entry, agentColor: meta.color })
                )
          )
        ),

        // ── Subagents tab ─────────────────────────────────────
        tab === 'subagents' && React.createElement(SubagentsPanel, {
          selectedAgent,
          agentColor: meta.color,
          sessionId,
        }),

        // ── LLM Thoughts tab ──────────────────────────────────
        tab === 'thoughts' && React.createElement('div', {
          style: { flex: 1, overflowY: 'auto', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 6 }
        },
          agentThoughts.length === 0
            ? React.createElement('div', {
                style: { color: 'var(--border)', textAlign: 'center', paddingTop: 40, fontSize: 12, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }
              },
                React.createElement('div', { style: { fontSize: 32 } }, '💡'),
                sessionId ? `No LLM thoughts recorded for ${meta.label} yet` : 'Start a session to capture LLM thoughts'
              )
            : agentThoughts.map((t, i) =>
                React.createElement('div', {
                  key: i,
                  style: {
                    padding: '10px 12px', borderRadius: 7,
                    background: 'var(--bg-panel)', border: `1px solid ${meta.color}18`,
                    borderLeft: `3px solid ${meta.color}50`,
                  }
                },
                  React.createElement('div', {
                    style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }
                  },
                    React.createElement('div', { style: { display: 'flex', gap: 8, alignItems: 'center' } },
                      React.createElement('span', {
                        style: { fontSize: 9, fontFamily: 'var(--font-mono)', color: meta.color,
                                 fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase' }
                      }, t.agent || selectedAgent),
                      t.phase && React.createElement('span', {
                        style: { fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--border-light)',
                                 background: 'var(--bg-surface)', padding: '1px 5px', borderRadius: 3 }
                      }, t.phase.toUpperCase())
                    ),
                    React.createElement('span', { style: { fontSize: 9, color: 'var(--bg-elevated)', fontFamily: 'var(--font-mono)' } },
                      new Date(t.timestamp).toLocaleTimeString())
                  ),
                  React.createElement('div', {
                    style: { fontSize: 11, color: 'var(--text-primary)', lineHeight: 1.7,
                             fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }
                  }, (t.thought || '').slice(0, 800) + (t.thought?.length > 800 ? '…' : ''))
                )
              )
        )
      )
    )
  );
}

window.AgentConsole = AgentConsole;
