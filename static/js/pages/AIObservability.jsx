// AIObservability.jsx — Enterprise AI Interaction Observatory
// Real-time visibility into every LLM call, RAG query, and agent reasoning step
const { useState, useEffect, useRef, useMemo } = React;

// ── Constants ─────────────────────────────────────────────────────────────────
const OBS_AGENTS = ['master','recon','vuln','web','osint','exploit','privesc','shell','payload'];

const OBS_PALETTE = {
  master:  { color: 'var(--cyan)',     bg: 'rgba(0,212,255,0.06)',   icon: '⚡', label: 'Master'  },
  recon:   { color: 'var(--low)',      bg: 'rgba(0,255,136,0.06)',   icon: '🔍', label: 'Recon'   },
  vuln:    { color: 'var(--medium)',   bg: 'rgba(255,170,0,0.06)',   icon: '🔬', label: 'Vuln'    },
  web:     { color: 'var(--cyan)',     bg: 'rgba(0,207,255,0.06)',   icon: '🌐', label: 'Web'     },
  osint:   { color: 'var(--violet)',   bg: 'rgba(160,80,255,0.06)',  icon: '🕵', label: 'OSINT'  },
  exploit: { color: 'var(--critical)', bg: 'rgba(255,68,102,0.06)',  icon: '💥', label: 'Exploit' },
  privesc: { color: '#ff6400',         bg: 'rgba(255,100,0,0.06)',   icon: '⬆',  label: 'Privesc' },
  shell:   { color: 'var(--cyan)',     bg: 'rgba(0,207,255,0.04)',   icon: '🐚', label: 'Shell'   },
  payload: { color: 'var(--medium)',   bg: 'rgba(255,170,0,0.04)',   icon: '📦', label: 'Payload' },
};

function agColor(name) { return (OBS_PALETTE[name] || {}).color || 'var(--text-secondary)'; }
function agIcon(name)  { return (OBS_PALETTE[name] || {}).icon  || '◆';  }
function agLabel(name) { return (OBS_PALETTE[name] || {}).label || name; }

function fmtTime(ts) {
  if (!ts) return '--:--:--';
  const s = String(ts);
  // Already a formatted locale time string like "15:30:45" or "3:30:45 PM"
  if (/^\d{1,2}:\d{2}(:\d{2})?/.test(s) && s.length < 25) return s;
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '--:--:--';
    return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return '--:--:--'; }
}

function estTokens(text) { return Math.ceil((text || '').length / 4); }

// ── Small building blocks ─────────────────────────────────────────────────────

function AgentBadge({ name, size }) {
  const p = OBS_PALETTE[name] || { color: 'var(--text-secondary)', icon: '◆', label: name || '?' };
  const small = size === 'xs';
  return React.createElement('span', { 'data-slot': 'AIObservability.AgentBadge',
    style: {
      fontSize: small ? 8 : 9, padding: small ? '0 4px' : '1px 6px', borderRadius: 3, flexShrink: 0,
      background: `${p.color}14`, border: `1px solid ${p.color}40`, color: p.color,
      fontFamily: 'var(--font-mono)', fontWeight: 700,
      display: 'inline-flex', alignItems: 'center', gap: 3,
    }
  }, p.icon, ' ', (p.label || name || '?').toUpperCase());
}

function PhasePill({ phase }) {
  if (!phase) return null;
  return React.createElement('span', { 'data-slot': 'AIObservability.PhasePill',
    style: {
      fontSize: 8, padding: '0 5px', borderRadius: 3, flexShrink: 0,
      background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)',
      color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
    }
  }, phase);
}

function TypePill({ type, found }) {
  const cfg = {
    llm:       { color: 'var(--cyan)', icon: '🧠', label: 'LLM'       },
    rag:       { color: found ? 'var(--violet)' : '#3d2060', icon: '📚', label: found ? 'RAG ✓' : 'RAG ✗' },
    reasoning: { color: 'var(--medium)', icon: '💭', label: 'REASON'    },
  }[type] || { color: 'var(--text-muted)', icon: '◆', label: (type || '').toUpperCase() };
  return React.createElement('span', { 'data-slot': 'AIObservability.TypePill',
    style: {
      fontSize: 8, padding: '1px 6px', borderRadius: 3, flexShrink: 0, minWidth: 58,
      textAlign: 'center', fontFamily: 'var(--font-mono)', fontWeight: 700,
      background: `${cfg.color}14`, border: `1px solid ${cfg.color}40`, color: cfg.color,
      display: 'inline-flex', alignItems: 'center', gap: 3, justifyContent: 'center',
    }
  }, cfg.icon, ' ', cfg.label);
}

// ── Scrollable code block with token counter ──────────────────────────────────
function CodeBlock({ text, color, label, maxH }) {
  if (!text) return null;
  const tokens = estTokens(text);
  return React.createElement('div', { 'data-slot': 'AIObservability.CodeBlock',
    style: { borderRadius: 5, background: 'var(--bg-surface)', border: `1px solid ${color}1a`, overflow: 'hidden' }
  },
    React.createElement('div', {
      style: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '4px 8px', background: `${color}08`, borderBottom: `1px solid ${color}15`,
      }
    },
      React.createElement('span', {
        style: { fontSize: 8, color, fontWeight: 700, fontFamily: 'var(--font-mono)',
                 textTransform: 'uppercase', letterSpacing: 0.8 }
      }, label),
      React.createElement('span', {
        style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
      }, `~${tokens} tokens · ${text.length} chars`)
    ),
    React.createElement('div', {
      style: {
        padding: '8px 10px', fontSize: 10, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)',
        lineHeight: 1.65, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
        maxHeight: maxH || 200, overflowY: 'auto',
      }
    }, text)
  );
}

// ── Unified Interaction Entry ─────────────────────────────────────────────────
function InteractionEntry({ item }) {
  const [exp, setExp] = useState(false);
  const isLLM = item.type === 'llm';
  const isRAG = item.type === 'rag';
  const isRsn = item.type === 'reasoning';
  const agCol  = agColor(item.agent);
  const typeColor = isLLM ? 'var(--cyan)' : isRAG ? (item.found ? 'var(--violet)' : '#3d2060') : 'var(--medium)';

  const queryText = isLLM ? item.prompt    : isRAG ? item.query   : null;
  const replyText = isLLM ? item.response  : isRAG ? item.result  : item.text;
  const hasContent = !!(queryText || replyText);
  const previewText = (queryText || replyText || '—');

  return React.createElement('div', { 'data-slot': 'AIObservability.InteractionEntry',
    onClick: hasContent ? () => setExp(e => !e) : undefined,
    style: {
      padding: '7px 10px', borderRadius: 6, marginBottom: 3,
      border: `1px solid ${exp ? typeColor + '35' : 'var(--border)'}`,
      background: exp ? `${typeColor}05` : 'transparent',
      cursor: hasContent ? 'pointer' : 'default',
      transition: 'border-color 0.1s, background 0.1s',
    }
  },
    // Header row
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }
    },
      React.createElement(TypePill, { type: item.type, found: item.found }),
      React.createElement(AgentBadge, { name: item.agent }),
      React.createElement(PhasePill, { phase: item.phase }),
      React.createElement('div', {
        style: {
          flex: 1, minWidth: 0, fontSize: 10, color: exp ? 'var(--text-muted)' : 'var(--text-muted)',
          fontFamily: 'var(--font-mono)', overflow: 'hidden',
          textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }
      }, previewText.slice(0, 90) + (previewText.length > 90 ? '…' : '')),
      React.createElement('span', {
        style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }
      }, fmtTime(item.ts || item.timestamp)),
      hasContent && React.createElement('span', {
        style: { fontSize: 9, color: 'var(--text-muted)', flexShrink: 0 }
      }, exp ? '▲' : '▼'),
    ),

    // Expanded content
    exp && React.createElement('div', {
      style: { marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }
    },
      // LLM
      isLLM && React.createElement(CodeBlock, { text: queryText, color: 'var(--cyan)', label: '▸ Prompt sent to LLM', maxH: 220 }),
      isLLM && React.createElement(CodeBlock, { text: replyText, color: agCol,    label: '◂ LLM Response',       maxH: 240 }),
      isLLM && item.model && React.createElement('div', {
        style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', paddingLeft: 2 }
      }, `model: ${item.model}`),
      // RAG
      isRAG && React.createElement(CodeBlock, { text: queryText, color: 'var(--violet)', label: '▸ RAG query → Knowledge Base', maxH: 100 }),
      isRAG && replyText && React.createElement(CodeBlock, {
        text: replyText, maxH: 240,
        color: item.found ? 'var(--violet)' : '#3d2060',
        label: item.found ? '◂ KB Results  ✓ HIT' : '◂ KB Results  ✗ MISS',
      }),
      isRAG && !replyText && React.createElement('div', {
        style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', padding: '4px 0' }
      }, '⊘ No knowledge base results returned'),
      // Reasoning
      isRsn && React.createElement(CodeBlock, { text: replyText, color: 'var(--medium)', label: '💭 Agent Reasoning', maxH: 240 }),
    )
  );
}

// ── Tab 1: Intelligence Feed ──────────────────────────────────────────────────
function IntelligenceFeed({ items }) {
  const [search,      setSearch]      = useState('');
  const [filterType,  setFilterType]  = useState('all');
  const [filterAgent, setFilterAgent] = useState('all');
  const [autoScroll,  setAutoScroll]  = useState(true);
  const topRef   = useRef(null);
  const prevLen  = useRef(items.length);

  useEffect(() => {
    if (autoScroll && topRef.current && items.length !== prevLen.current) {
      topRef.current.scrollTop = 0;
      prevLen.current = items.length;
    }
  }, [items.length, autoScroll]);

  const activeAgents = useMemo(() =>
    Array.from(new Set(items.map(i => i.agent).filter(Boolean))), [items]);

  const filtered = useMemo(() => {
    let r = items;
    if (filterType  !== 'all') r = r.filter(i => i.type  === filterType);
    if (filterAgent !== 'all') r = r.filter(i => (i.agent || '') === filterAgent);
    if (search.trim()) {
      const q = search.toLowerCase();
      r = r.filter(i =>
        (i.prompt || i.query || i.text || i.response || i.result || '').toLowerCase().includes(q)
      );
    }
    return r;
  }, [items, filterType, filterAgent, search]);

  const fBtn = (key, label, color) => React.createElement('button', {
    onClick: () => setFilterType(key),
    style: {
      padding: '3px 10px', borderRadius: 5, cursor: 'pointer', fontSize: 9,
      fontFamily: 'var(--font-mono)', fontWeight: 600,
      border: filterType === key ? `1px solid ${color}` : '1px solid var(--border-light)',
      background: filterType === key ? `${color}14` : 'rgba(255,255,255,0.04)',
      color: filterType === key ? color : 'var(--text-secondary)', transition: 'all 0.1s',
    }
  }, label);

  return React.createElement('div', { 'data-slot': 'AIObservability.IntelligenceFeed', style: { display: 'flex', flexDirection: 'column', height: '100%' } },
    // Toolbar
    React.createElement('div', {
      style: { display: 'flex', gap: 6, alignItems: 'center', paddingBottom: 10, flexShrink: 0, flexWrap: 'wrap' }
    },
      fBtn('all',       '◉ ALL',       'var(--text-secondary)'),
      fBtn('llm',       '🧠 LLM',      'var(--cyan)'),
      fBtn('rag',       '📚 RAG',      'var(--violet)'),
      fBtn('reasoning', '💭 REASON',   'var(--medium)'),
      React.createElement('div', { style: { width: 1, height: 14, background: 'var(--border-light)', flexShrink: 0 } }),
      React.createElement('select', {
        value: filterAgent, onChange: e => setFilterAgent(e.target.value),
        style: {
          padding: '3px 8px', borderRadius: 'var(--radius)', fontSize: 9, fontFamily: 'var(--font-mono)',
          border: '1px solid var(--border)', background: 'var(--bg-panel)', color: 'var(--text-primary)', cursor: 'pointer',
        }
      },
        React.createElement('option', { value: 'all' }, '◉ All Agents'),
        ...activeAgents.map(a =>
          React.createElement('option', { key: a, value: a }, `${agIcon(a)} ${a.toUpperCase()}`)
        )
      ),
      React.createElement('input', {
        value: search, onChange: e => setSearch(e.target.value),
        placeholder: 'Search prompts, responses, queries...',
        style: {
          flex: 1, minWidth: 160, padding: '3px 10px', borderRadius: 'var(--radius)', fontSize: 10,
          border: '1px solid var(--border)', background: 'var(--bg-panel)', color: 'var(--text-primary)',
          fontFamily: 'var(--font-mono)', outline: 'none',
        }
      }),
      React.createElement('button', {
        onClick: () => setAutoScroll(s => !s),
        style: {
          padding: '3px 9px', borderRadius: 5, cursor: 'pointer', fontSize: 9,
          fontFamily: 'var(--font-mono)',
          border: `1px solid ${autoScroll ? 'var(--green)' : 'var(--border-light)'}`,
          background: autoScroll ? 'rgba(0,255,136,0.06)' : 'rgba(255,255,255,0.04)',
          color: autoScroll ? 'var(--green)' : 'var(--text-secondary)', flexShrink: 0,
        }
      }, autoScroll ? '↑ LIVE' : '⏸ PAUSED'),
      React.createElement('span', {
        style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }
      }, `${filtered.length} / ${items.length}`),
    ),
    // List
    React.createElement('div', {
      ref: topRef,
      style: { flex: 1, overflowY: 'auto', paddingRight: 2 }
    },
      filtered.length === 0
        ? React.createElement('div', {
            style: { textAlign: 'center', padding: '56px 24px', fontFamily: 'var(--font-mono)' }
          },
            React.createElement('div', {
              style: { color: 'var(--text-muted)', fontSize: 12, marginBottom: 10 }
            }, search ? '— no matching interactions —' : '⚡ Live feed — waiting for AI activity'),
            !search && React.createElement('div', {
              style: { color: 'var(--text-muted)', fontSize: 10, opacity: 0.75,
                       maxWidth: 440, margin: '0 auto', lineHeight: 1.6 }
            }, 'This feed streams every LLM call, RAG query and agent-reasoning step in real time '
             + 'as a scan runs. It is empty right now because no scan is active — start a scan and it '
             + 'will populate live.'))
        : filtered.map((item, i) => React.createElement(InteractionEntry, { key: i, item }))
    )
  );
}

// ── Tab 2: LLM Deep Dive ──────────────────────────────────────────────────────
function LLMDeepDive({ agentComms, agents }) {
  const [selected, setSelected] = useState('master');
  const comms = (agentComms[selected] || []).filter(c => c.type === 'llm');
  const totalLLM = OBS_AGENTS.reduce((s, a) => s + (agentComms[a] || []).filter(c => c.type === 'llm').length, 0);

  return React.createElement('div', { 'data-slot': 'AIObservability.LLMDeepDive', style: { display: 'flex', height: '100%', gap: 10 } },
    // Sidebar: agent list
    React.createElement('div', {
      style: {
        width: 148, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 3,
        paddingRight: 8, borderRight: '1px solid var(--bg-surface)',
      }
    },
      React.createElement('div', {
        style: { fontSize: 8, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1,
                 fontFamily: 'var(--font-mono)', marginBottom: 6, paddingTop: 2 }
      }, `${totalLLM} total calls`),
      ...OBS_AGENTS.map(name => {
        const cnt = (agentComms[name] || []).filter(c => c.type === 'llm').length;
        const p = OBS_PALETTE[name] || { color: 'var(--text-secondary)', icon: '◆', label: name };
        const isSel = selected === name;
        const agSt  = agents[name]?.status || 'idle';
        const isLive = agSt === 'running' || agSt === 'thinking';
        return React.createElement('div', {
          key: name, onClick: () => setSelected(name),
          style: {
            padding: '7px 9px', borderRadius: 6, cursor: 'pointer',
            border: `1px solid ${isSel ? p.color + '55' : 'var(--border)'}`,
            background: isSel ? `${p.color}0d` : 'transparent',
            transition: 'all 0.1s',
          }
        },
          React.createElement('div', {
            style: { display: 'flex', alignItems: 'center', gap: 5 }
          },
            React.createElement('span', { style: { fontSize: 13 } }, p.icon),
            React.createElement('span', {
              style: { fontSize: 9, fontWeight: 700, color: isSel ? p.color : 'var(--text-muted)',
                       fontFamily: 'var(--font-mono)', flex: 1 }
            }, p.label.toUpperCase()),
            isLive && React.createElement('span', {
              style: { width: 5, height: 5, borderRadius: '50%', background: 'var(--green)',
                       boxShadow: '0 0 5px var(--green)', animation: 'pulse 1s infinite' }
            }),
          ),
          React.createElement('div', {
            style: { fontSize: 8, color: cnt > 0 ? '#00d4ff55' : 'var(--border)',
                     fontFamily: 'var(--font-mono)', marginTop: 2 }
          }, `🧠 ${cnt} calls`)
        );
      })
    ),

    // Main: selected agent LLM comms
    React.createElement('div', { style: { flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column' } },
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: 8, paddingTop: 2, marginBottom: 8, flexShrink: 0 }
      },
        React.createElement(AgentBadge, { name: selected }),
        React.createElement('span', {
          style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
        }, `${comms.length} LLM interactions`)
      ),
      comms.length === 0
        ? React.createElement('div', {
            style: { color: 'var(--text-muted)', fontSize: 11, textAlign: 'center', padding: '60px 0', fontFamily: 'var(--font-mono)' }
          }, '— no LLM calls from this agent —')
        : comms.map((entry, i) =>
            React.createElement(InteractionEntry, { key: i, item: { ...entry, agent: selected } })
          )
    )
  );
}

// ── Tab 3: RAG Inspector ──────────────────────────────────────────────────────
function RAGInspector({ agentComms }) {
  const [filterHit,   setFilterHit]   = useState('all');
  const [filterAgent, setFilterAgent] = useState('all');

  const allRAG = useMemo(() => {
    const entries = [];
    OBS_AGENTS.forEach(name =>
      (agentComms[name] || []).filter(c => c.type === 'rag')
        .forEach(c => entries.push({ ...c, agent: name }))
    );
    return entries.sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0));
  }, [agentComms]);

  const hits    = allRAG.filter(r => r.found).length;
  const misses  = allRAG.length - hits;
  const hitRate = allRAG.length > 0 ? Math.round((hits / allRAG.length) * 100) : 0;
  const hitColor = hitRate >= 60 ? 'var(--green)' : hitRate >= 30 ? 'var(--amber)' : 'var(--red)';

  const filtered = useMemo(() => {
    let r = allRAG;
    if (filterHit   === 'hit')  r = r.filter(e => e.found);
    if (filterHit   === 'miss') r = r.filter(e => !e.found);
    if (filterAgent !== 'all')  r = r.filter(e => e.agent === filterAgent);
    return r;
  }, [allRAG, filterHit, filterAgent]);

  const activeRagAgents = useMemo(() =>
    Array.from(new Set(allRAG.map(e => e.agent).filter(Boolean))), [allRAG]);

  const fBtn = (key, label, color) => React.createElement('button', {
    onClick: () => setFilterHit(key),
    style: {
      padding: '3px 10px', borderRadius: 5, cursor: 'pointer', fontSize: 9,
      fontFamily: 'var(--font-mono)', fontWeight: 600,
      border: filterHit === key ? `1px solid ${color}` : '1px solid var(--border-light)',
      background: filterHit === key ? `${color}14` : 'rgba(255,255,255,0.04)',
      color: filterHit === key ? color : 'var(--text-secondary)',
    }
  }, label);

  const statCard = (val, label, color) => React.createElement('div', {
    style: { padding: '8px 16px', borderRadius: 7, background: 'var(--bg-panel)',
             border: `1px solid ${color}20`, textAlign: 'center', minWidth: 80 }
  },
    React.createElement('div', { style: { fontSize: 22, fontWeight: 700, color, fontFamily: 'var(--font-mono)' } }, val),
    React.createElement('div', { style: { fontSize: 8, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginTop: 2 } }, label)
  );

  return React.createElement('div', { 'data-slot': 'AIObservability.RAGInspector', style: { display: 'flex', flexDirection: 'column', height: '100%' } },
    // Stats strip
    React.createElement('div', {
      style: { display: 'flex', gap: 8, marginBottom: 10, flexShrink: 0, alignItems: 'center', flexWrap: 'wrap' }
    },
      statCard(allRAG.length, 'Queries',  'var(--violet)'),
      statCard(hits,           'KB Hits',  'var(--green)'),
      statCard(misses,         'KB Misses','var(--text-muted)'),
      statCard(`${hitRate}%`,  'Hit Rate', hitColor),
      // Visual hit-rate bar
      React.createElement('div', {
        style: { flex: 1, minWidth: 100, display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '0 6px' }
      },
        React.createElement('div', { style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: 5 } }, 'Knowledge Base Hit Rate'),
        React.createElement('div', {
          style: { height: 8, borderRadius: 4, background: 'var(--bg-surface)', overflow: 'hidden', position: 'relative' }
        },
          React.createElement('div', {
            style: {
              height: '100%', borderRadius: 4, width: `${hitRate}%`,
              background: hitColor, transition: 'width 0.6s ease',
              boxShadow: `0 0 10px ${hitColor}60`,
            }
          }),
        ),
        React.createElement('div', {
          style: { display: 'flex', justifyContent: 'space-between', marginTop: 3 }
        },
          React.createElement('span', { style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, '0%'),
          React.createElement('span', { style: { fontSize: 8, color: hitColor, fontFamily: 'var(--font-mono)', fontWeight: 700 } }, `${hitRate}%`),
          React.createElement('span', { style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, '100%'),
        )
      )
    ),
    // Filter bar
    React.createElement('div', {
      style: { display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8, flexShrink: 0, flexWrap: 'wrap' }
    },
      fBtn('all',  '◉ ALL',    'var(--text-secondary)'),
      fBtn('hit',  '✓ HITS',   'var(--green)'),
      fBtn('miss', '✗ MISSES', 'var(--text-muted)'),
      React.createElement('div', { style: { width: 1, height: 14, background: 'var(--border-light)' } }),
      React.createElement('select', {
        value: filterAgent, onChange: e => setFilterAgent(e.target.value),
        style: {
          padding: '3px 8px', borderRadius: 'var(--radius)', fontSize: 9, fontFamily: 'var(--font-mono)',
          border: '1px solid var(--border)', background: 'var(--bg-panel)', color: 'var(--text-primary)', cursor: 'pointer',
        }
      },
        React.createElement('option', { value: 'all' }, '◉ All Agents'),
        ...activeRagAgents.map(a =>
          React.createElement('option', { key: a, value: a }, `${agIcon(a)} ${a.toUpperCase()}`)
        )
      ),
      React.createElement('span', {
        style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginLeft: 'auto' }
      }, `${filtered.length} entries`),
    ),
    // Entries
    React.createElement('div', { style: { flex: 1, overflowY: 'auto' } },
      filtered.length === 0
        ? React.createElement('div', {
            style: { color: 'var(--text-muted)', fontSize: 11, textAlign: 'center', padding: '60px 0', fontFamily: 'var(--font-mono)' }
          }, '— no RAG queries recorded yet —')
        : filtered.map((e, i) => React.createElement(InteractionEntry, { key: i, item: { ...e, type: 'rag' } }))
    )
  );
}

// ── Tab 4: Stats & Metrics ────────────────────────────────────────────────────
function StatsPanel({ agentComms, reasoningLog, llmStatus }) {
  const rows = useMemo(() =>
    OBS_AGENTS.map(name => {
      const comms = agentComms[name] || [];
      const llm   = comms.filter(c => c.type === 'llm');
      const rag   = comms.filter(c => c.type === 'rag');
      const hits  = rag.filter(c => c.found).length;
      const toks  = llm.reduce((s, c) => s + estTokens((c.prompt || '') + (c.response || '')), 0);
      return { name, llm: llm.length, rag: rag.length, hits, hr: rag.length ? Math.round(hits / rag.length * 100) : null, toks };
    }).filter(r => r.llm > 0 || r.rag > 0),
  [agentComms]);

  const tot = rows.reduce((a, r) => ({
    llm: a.llm + r.llm, rag: a.rag + r.rag, hits: a.hits + r.hits, toks: a.toks + r.toks,
  }), { llm: 0, rag: 0, hits: 0, toks: 0 });

  const globalHR = tot.rag > 0 ? Math.round(tot.hits / tot.rag * 100) : 0;

  const bigStat = (icon, val, label, color) => React.createElement('div', {
    style: { padding: '12px 16px', borderRadius: 8, background: 'var(--bg-surface)',
             border: `1px solid ${color}20`, textAlign: 'center', flex: 1, minWidth: 90 }
  },
    React.createElement('div', { style: { fontSize: 20, marginBottom: 4 } }, icon),
    React.createElement('div', { style: { fontSize: 24, fontWeight: 700, color, fontFamily: 'var(--font-mono)' } }, val),
    React.createElement('div', { style: { fontSize: 8, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginTop: 3 } }, label)
  );

  const fmtToks = t => t >= 1000 ? `${Math.round(t / 1000)}k` : t;

  return React.createElement('div', { 'data-slot': 'AIObservability.StatsPanel', style: { display: 'flex', flexDirection: 'column', gap: 14 } },
    // Global tiles
    React.createElement('div', { style: { display: 'flex', gap: 8, flexWrap: 'wrap' } },
      bigStat('🧠', tot.llm, 'LLM Calls',  'var(--cyan)'),
      bigStat('📚', tot.rag, 'RAG Queries','var(--violet)'),
      bigStat('✓',  tot.hits,'KB Hits',    'var(--green)'),
      bigStat('📊', `${globalHR}%`, 'Hit Rate', globalHR >= 60 ? 'var(--green)' : 'var(--amber)'),
      bigStat('⚡', fmtToks(tot.toks), 'Est. Tokens','var(--medium)'),
      bigStat('💭', reasoningLog.length, 'Reasonings','var(--medium)'),
    ),

    // Model card — PRIMARY LLM
    llmStatus?.model && React.createElement('div', {
      style: { padding: '10px 14px', borderRadius: 7, background: 'var(--bg-surface)',
               border: '1px solid var(--bg-panel)', display: 'flex', gap: 12, alignItems: 'center' }
    },
      React.createElement('span', { style: { fontSize: 18 } }, '🤖'),
      React.createElement('div', { style: { flex: 1 } },
        React.createElement('div', { style: { fontSize: 11, color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontWeight: 700 } },
          `PRIMARY${llmStatus.llm_provider ? ' · ' + llmStatus.llm_provider : ''} · ${llmStatus.model}`),
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 1 } }, llmStatus.url || llmStatus.llm_message || ''),
      ),
      React.createElement('span', {
        style: {
          fontSize: 9, padding: '2px 10px', borderRadius: 10, fontFamily: 'var(--font-mono)',
          background: llmStatus.available ? 'rgba(0,255,136,0.08)' : 'rgba(255,68,102,0.08)',
          border: `1px solid ${llmStatus.available ? 'var(--green)' : 'var(--red)'}`,
          color: llmStatus.available ? 'var(--green)' : 'var(--red)',
        }
      }, llmStatus.available ? '● ONLINE' : '● OFFLINE')
    ),

    // Model card — SECONDARY / BACKUP LLM (e.g. a locally-hosted Ollama model)
    llmStatus?.llm_fallback_model && React.createElement('div', {
      style: { padding: '10px 14px', borderRadius: 7, background: 'var(--bg-surface)',
               border: '1px solid rgba(160,100,200,0.30)', display: 'flex', gap: 12, alignItems: 'center', marginTop: 6 }
    },
      React.createElement('span', { style: { fontSize: 18 } }, '🛡'),
      React.createElement('div', { style: { flex: 1 } },
        React.createElement('div', { style: { fontSize: 11, color: 'var(--violet)', fontFamily: 'var(--font-mono)', fontWeight: 700 } },
          `BACKUP${llmStatus.llm_fallback_provider ? ' · ' + llmStatus.llm_fallback_provider : ''} · ${llmStatus.llm_fallback_model}`),
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 1 } }, llmStatus.llm_fallback_message || 'failover provider'),
      ),
      React.createElement('span', {
        style: {
          fontSize: 9, padding: '2px 10px', borderRadius: 10, fontFamily: 'var(--font-mono)',
          background: llmStatus.llm_fallback_available ? 'rgba(0,255,136,0.08)' : 'rgba(150,150,150,0.08)',
          border: `1px solid ${llmStatus.llm_fallback_available ? 'var(--green)' : 'var(--border)'}`,
          color: llmStatus.llm_fallback_available ? 'var(--green)' : 'var(--text-muted)',
        }
      }, llmStatus.llm_fallback_available ? '● READY' : '○ STANDBY')
    ),

    // Per-agent table
    rows.length > 0 && React.createElement('div', {
      style: { borderRadius: 7, border: '1px solid var(--bg-surface)', overflow: 'hidden' }
    },
      React.createElement('div', {
        style: { padding: '8px 14px', background: 'var(--bg-panel)', borderBottom: '1px solid var(--bg-surface)' }
      },
        React.createElement('span', { style: { fontSize: 10, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 1 } }, 'Per-Agent Breakdown')
      ),
      React.createElement('table', { style: { width: '100%', borderCollapse: 'collapse', fontSize: 10, fontFamily: 'var(--font-mono)' } },
        React.createElement('thead', null,
          React.createElement('tr', { style: { background: 'var(--bg-surface)', borderBottom: '1px solid var(--bg-surface)' } },
            ['Agent','LLM Calls','RAG Queries','KB Hits','Hit Rate','Est. Tokens'].map(h =>
              React.createElement('th', {
                key: h,
                style: { padding: '6px 12px', textAlign: h === 'Agent' ? 'left' : 'right',
                         color: 'var(--text-muted)', fontWeight: 600, fontSize: 9, textTransform: 'uppercase', letterSpacing: 0.5 }
              }, h)
            )
          )
        ),
        React.createElement('tbody', null,
          rows.map((r, i) => {
            const p = OBS_PALETTE[r.name] || { color: 'var(--text-secondary)', icon: '◆', label: r.name };
            return React.createElement('tr', {
              key: r.name,
              style: { borderBottom: '1px solid var(--bg-surface)', background: i % 2 === 0 ? 'transparent' : 'var(--bg-surface)' }
            },
              React.createElement('td', { style: { padding: '7px 12px', color: p.color, fontWeight: 700 } },
                React.createElement('span', { style: { display: 'inline-flex', alignItems: 'center', gap: 5 } }, p.icon, ' ', p.label)),
              React.createElement('td', { style: { padding: '7px 12px', textAlign: 'right', color: r.llm  > 0 ? 'var(--cyan)' : 'var(--text-muted)' } }, r.llm),
              React.createElement('td', { style: { padding: '7px 12px', textAlign: 'right', color: r.rag  > 0 ? 'var(--violet)' : 'var(--text-muted)' } }, r.rag),
              React.createElement('td', { style: { padding: '7px 12px', textAlign: 'right', color: r.hits > 0 ? 'var(--green)' : 'var(--text-muted)' } }, r.hits),
              React.createElement('td', { style: { padding: '7px 12px', textAlign: 'right',
                color: r.hr === null ? 'var(--text-muted)' : r.hr >= 60 ? 'var(--green)' : r.hr >= 30 ? 'var(--amber)' : 'var(--red)' } },
                r.hr !== null ? `${r.hr}%` : '—'),
              React.createElement('td', { style: { padding: '7px 12px', textAlign: 'right', color: r.toks > 0 ? 'var(--medium)' : 'var(--text-muted)' } },
                r.toks > 0 ? `~${fmtToks(r.toks)}` : '—')
            );
          })
        )
      )
    ),

    // Reasoning log
    reasoningLog.length > 0 && React.createElement('div', {
      style: { borderRadius: 7, border: '1px solid var(--bg-surface)', overflow: 'hidden' }
    },
      React.createElement('div', {
        style: { padding: '8px 14px', background: 'var(--bg-panel)', borderBottom: '1px solid var(--bg-surface)' }
      },
        React.createElement('span', {
          style: { fontSize: 10, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 1 }
        }, `💭 Reasoning Log  (${reasoningLog.length})`)
      ),
      React.createElement('div', {
        style: { maxHeight: 300, overflowY: 'auto', padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 3 }
      },
        reasoningLog.slice(0, 60).map((r, i) => {
          const text  = typeof r === 'string' ? r : (r.reasoning || r.message || r.text || JSON.stringify(r));
          const agent = r.agent || 'master';
          return React.createElement('div', {
            key: i,
            style: { display: 'flex', gap: 6, alignItems: 'flex-start', padding: '3px 0',
                     borderBottom: '1px solid var(--bg-surface)', fontSize: 10 }
          },
            React.createElement('span', { style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0, paddingTop: 1 } }, fmtTime(r.ts || r.timestamp)),
            React.createElement(AgentBadge, { name: agent, size: 'xs' }),
            React.createElement('span', { style: { color: 'var(--text-secondary)', lineHeight: 1.5, wordBreak: 'break-word' } }, text)
          );
        })
      )
    )
  );
}

// ── Tab 5: Tool Executions ────────────────────────────────────────────────────
function ToolExecutions({ subagentStates, subagentLines }) {
  const [filterAgent,  setFilterAgent]  = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [expanded,     setExpanded]     = useState({});

  // Build flat list: { subagent, tool, exit_code, success, ts, lines[] }
  const allExecs = useMemo(() => {
    const out = [];
    Object.entries(subagentStates || {}).forEach(([subagent, st]) => {
      Object.entries(st.toolExits || {}).forEach(([tool, ex]) => {
        const lines = (subagentLines[subagent] || []).filter(l => l.tool === tool);
        out.push({ subagent, tool, exit_code: ex.exit_code, success: ex.success, ts: ex.ts, lines });
      });
    });
    return out.sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0));
  }, [subagentStates, subagentLines]);

  const activeSubagents = useMemo(() => Array.from(new Set(allExecs.map(e => e.subagent))), [allExecs]);

  const filtered = useMemo(() => {
    let r = allExecs;
    if (filterAgent  !== 'all')   r = r.filter(e => e.subagent === filterAgent);
    if (filterStatus === 'ok')    r = r.filter(e => e.success);
    if (filterStatus === 'fail')  r = r.filter(e => !e.success);
    return r;
  }, [allExecs, filterAgent, filterStatus]);

  const total   = allExecs.length;
  const success = allExecs.filter(e => e.success).length;
  const failed  = total - success;

  const toggle = key => setExpanded(p => ({ ...p, [key]: !p[key] }));

  const statCard = (val, label, color) => React.createElement('div', {
    style: { padding: '7px 14px', borderRadius: 7, background: 'var(--bg-panel)',
             border: `1px solid ${color}20`, textAlign: 'center', minWidth: 70 }
  },
    React.createElement('div', { style: { fontSize: 20, fontWeight: 700, color, fontFamily: 'var(--font-mono)' } }, val),
    React.createElement('div', { style: { fontSize: 8, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginTop: 2 } }, label)
  );

  const fBtn = (key, label, color) => React.createElement('button', {
    onClick: () => setFilterStatus(key),
    style: {
      padding: '3px 10px', borderRadius: 5, cursor: 'pointer', fontSize: 9,
      fontFamily: 'var(--font-mono)', fontWeight: 600,
      border: filterStatus === key ? `1px solid ${color}` : '1px solid var(--border-light)',
      background: filterStatus === key ? `${color}14` : 'rgba(255,255,255,0.04)',
      color: filterStatus === key ? color : 'var(--text-secondary)',
    }
  }, label);

  return React.createElement('div', { 'data-slot': 'AIObservability.ToolExecutions', style: { display: 'flex', flexDirection: 'column', height: '100%' } },

    // Stats strip
    React.createElement('div', {
      style: { display: 'flex', gap: 8, marginBottom: 10, flexShrink: 0, alignItems: 'center', flexWrap: 'wrap' }
    },
      statCard(total,   'Total',   'var(--cyan)'),
      statCard(success, 'Success', 'var(--green)'),
      statCard(failed,  'Failed',  failed > 0 ? 'var(--red)' : 'var(--border-light)'),
      total > 0 && statCard(
        `${Math.round(success / total * 100)}%`, 'Pass Rate',
        success / total >= 0.8 ? 'var(--green)' : success / total >= 0.5 ? 'var(--amber)' : 'var(--red)'
      ),
    ),

    // Filter bar
    React.createElement('div', {
      style: { display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8, flexShrink: 0, flexWrap: 'wrap' }
    },
      fBtn('all',  '◉ ALL',     'var(--text-secondary)'),
      fBtn('ok',   '✓ SUCCESS', 'var(--green)'),
      fBtn('fail', '✗ FAILED',  'var(--red)'),
      React.createElement('div', { style: { width: 1, height: 14, background: 'var(--border-light)', flexShrink: 0 } }),
      React.createElement('select', {
        value: filterAgent, onChange: e => setFilterAgent(e.target.value),
        style: {
          padding: '3px 8px', borderRadius: 'var(--radius)', fontSize: 9, fontFamily: 'var(--font-mono)',
          border: '1px solid var(--border)', background: 'var(--bg-panel)', color: 'var(--text-primary)', cursor: 'pointer',
        }
      },
        React.createElement('option', { value: 'all' }, '◉ All Subagents'),
        ...activeSubagents.map(a => React.createElement('option', { key: a, value: a }, a.toUpperCase()))
      ),
      React.createElement('span', {
        style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginLeft: 'auto' }
      }, `${filtered.length} / ${total} executions`),
    ),

    // Tool execution list
    React.createElement('div', { style: { flex: 1, overflowY: 'auto' } },
      filtered.length === 0
        ? React.createElement('div', {
            style: { color: 'var(--text-muted)', fontSize: 11, textAlign: 'center', padding: '60px 0', fontFamily: 'var(--font-mono)' }
          }, '— no tool executions recorded yet —')
        : filtered.map((ex, i) => {
            const key = `${ex.subagent}::${ex.tool}::${i}`;
            const isOpen = !!expanded[key];
            const sc = ex.success ? 'var(--green)' : 'var(--red)';
            const agentName = ex.subagent.replace(/_subagent$/, '').replace(/_agent$/, '');
            return React.createElement('div', {
              key,
              style: {
                marginBottom: 3, borderRadius: 6,
                border: `1px solid ${isOpen ? sc + '35' : 'var(--border)'}`,
                background: isOpen ? `${sc}04` : 'transparent',
                transition: 'border-color 0.1s, background 0.1s',
              }
            },
              // Row header
              React.createElement('div', {
                onClick: () => toggle(key),
                style: {
                  padding: '7px 10px', display: 'flex', alignItems: 'center',
                  gap: 6, cursor: 'pointer', flexWrap: 'wrap',
                }
              },
                // Success/fail badge
                React.createElement('span', {
                  style: {
                    fontSize: 9, padding: '1px 7px', borderRadius: 3, fontFamily: 'var(--font-mono)', fontWeight: 700,
                    flexShrink: 0, minWidth: 54, textAlign: 'center',
                    background: `${sc}14`, border: `1px solid ${sc}40`, color: sc,
                  }
                }, ex.success ? '✓ OK' : `✗ ${ex.exit_code ?? 'ERR'}`),
                // Tool name
                React.createElement('span', {
                  style: {
                    fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
                    color: 'var(--text-primary)', flex: 1, minWidth: 80,
                  }
                }, ex.tool),
                // Subagent badge
                React.createElement(AgentBadge, { name: agentName }),
                // Line count
                ex.lines.length > 0 && React.createElement('span', {
                  style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }
                }, `${ex.lines.length} lines`),
                // Timestamp
                React.createElement('span', {
                  style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }
                }, fmtTime(ex.ts)),
                // Expand chevron
                ex.lines.length > 0 && React.createElement('span', {
                  style: { fontSize: 9, color: 'var(--text-muted)', flexShrink: 0 }
                }, isOpen ? '▲' : '▼'),
              ),
              // Expanded output
              isOpen && ex.lines.length > 0 && React.createElement('div', {
                style: {
                  margin: '0 8px 8px', borderRadius: 5, background: 'var(--bg-surface)',
                  border: '1px solid var(--bg-surface)', maxHeight: 280, overflowY: 'auto',
                  padding: '8px 10px',
                }
              },
                ex.lines.map((l, li) => {
                  const isErr = /stderr|error|fail|denied|refused/i.test(l.line);
                  return React.createElement('div', {
                    key: li,
                    style: {
                      fontSize: 10, fontFamily: 'var(--font-mono)', lineHeight: 1.6,
                      color: isErr ? 'var(--critical)' : 'var(--text-muted)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                    }
                  }, l.line);
                })
              )
            );
          })
    )
  );
}

// ── Tab 6: Tool Waterfall ─────────────────────────────────────────────────────
function ToolWaterfall({ interactions }) {
  const [hoveredKey, setHoveredKey] = React.useState(null);

  // Group interactions by agent, preserving order
  const agentGroups = React.useMemo(() => {
    const map = {};
    const order = [];
    interactions.forEach(item => {
      const ag = item.agent || 'unknown';
      if (!map[ag]) { map[ag] = []; order.push(ag); }
      map[ag].push(item);
    });
    return order.map(ag => ({ agent: ag, items: map[ag] }));
  }, [interactions]);

  if (interactions.length === 0) {
    return React.createElement('div', { 'data-slot': 'AIObservability.ToolWaterfall',
      style: { color: 'var(--text-muted)', fontSize: 11, textAlign: 'center', padding: '60px 0', fontFamily: 'var(--font-mono)' }
    }, '— no interactions to display in waterfall —');
  }

  // Compute per-block widths: proportional to token count, clamped [20, 120]
  function blockWidth(item) {
    const tokens = estTokens((item.prompt || item.query || item.text || item.response || item.result || ''));
    const maxTok = 800;
    const raw = Math.max(20, Math.min(120, 20 + (tokens / maxTok) * 100));
    return Math.round(raw);
  }

  function blockColor(item) {
    if (item.type === 'llm')       return 'var(--cyan)';
    if (item.type === 'rag')       return 'var(--violet)';
    if (item.type === 'reasoning') return 'var(--medium)';
    return 'var(--text-muted)';
  }

  function blockPreview(item) {
    const text = item.prompt || item.query || item.text || item.response || item.result || '';
    return text.slice(0, 80) + (text.length > 80 ? '…' : '');
  }

  const rowH = 32;
  const labelW = 80;
  const timeLabels = ['0%', '25%', '50%', '75%', '100%'];

  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', height: '100%' } },

    // Time axis header
    React.createElement('div', {
      style: {
        display: 'flex', alignItems: 'center', marginBottom: 6, flexShrink: 0,
        paddingLeft: labelW + 8,
      }
    },
      React.createElement('div', {
        style: { flex: 1, display: 'flex', justifyContent: 'space-between' }
      },
        timeLabels.map(lbl =>
          React.createElement('span', {
            key: lbl,
            style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
          }, lbl)
        )
      )
    ),

    // Agent rows
    React.createElement('div', { style: { flex: 1, overflowY: 'auto' } },
      agentGroups.map(({ agent, items }) => {
        const p = OBS_PALETTE[agent] || { color: 'var(--text-secondary)', icon: '◆', label: agent };
        return React.createElement('div', {
          key: agent,
          style: {
            display: 'flex', alignItems: 'center', height: rowH,
            marginBottom: 4, gap: 8,
          }
        },
          // Agent label (fixed 80px)
          React.createElement('div', {
            style: {
              width: labelW, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4,
              overflow: 'hidden',
            }
          },
            React.createElement('span', { style: { fontSize: 13, flexShrink: 0 } }, p.icon),
            React.createElement('span', {
              style: {
                fontSize: 8, fontWeight: 700, color: p.color, fontFamily: 'var(--font-mono)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }
            }, (p.label || agent).toUpperCase())
          ),

          // Timeline blocks
          React.createElement('div', {
            style: {
              flex: 1, display: 'flex', alignItems: 'center',
              gap: 2, height: rowH, overflowX: 'auto',
              background: 'var(--bg-surface)', borderRadius: 4,
              padding: '0 4px',
              border: '1px solid var(--border)',
            }
          },
            items.map((item, idx) => {
              const bKey = `${agent}-${idx}`;
              const w = blockWidth(item);
              const bc = blockColor(item);
              const isHov = hoveredKey === bKey;
              const preview = blockPreview(item);
              return React.createElement('div', {
                key: bKey,
                onMouseEnter: () => setHoveredKey(bKey),
                onMouseLeave: () => setHoveredKey(null),
                title: `${(item.type || '').toUpperCase()}: ${preview}`,
                style: {
                  width: w, height: 20, borderRadius: 3, flexShrink: 0,
                  background: isHov ? bc : `${bc}55`,
                  border: `1px solid ${bc}`,
                  transition: 'background 0.1s',
                  cursor: 'default',
                  position: 'relative',
                }
              },
                // Tiny type label inside block if wide enough
                w >= 36 && React.createElement('span', {
                  style: {
                    position: 'absolute', top: '50%', left: '50%',
                    transform: 'translate(-50%, -50%)',
                    fontSize: 7, fontFamily: 'var(--font-mono)', fontWeight: 700,
                    color: isHov ? 'var(--bg-base)' : bc,
                    pointerEvents: 'none', whiteSpace: 'nowrap',
                    overflow: 'hidden',
                  }
                }, (item.type || '').toUpperCase().slice(0, 6))
              );
            })
          )
        );
      })
    )
  );
}

// ── Root: AIObservability ─────────────────────────────────────────────────────
function AIObservability() {
  const { state } = window.useStore();
  const {
    agentComms      = {},
    ragHistory      = [],
    reasoningLog    = [],
    agents          = {},
    subagentStates  = {},
    subagentLines   = {},
    wsConnected,
    llmThinking,
    currentPhase,
    activeSession,
    llmStatus       = {},
  } = state;

  const [tab, setTab] = useState('feed');

  // Unified chronological feed
  const unifiedFeed = useMemo(() => {
    const items = [];
    OBS_AGENTS.forEach(name =>
      (agentComms[name] || []).forEach(c => items.push({ ...c, agent: name }))
    );
    reasoningLog.forEach(r => {
      const text = typeof r === 'string' ? r : (r.reasoning || r.message || r.text || '');
      items.push({ type: 'reasoning', agent: r.agent || 'master', text, ts: r.ts || r.timestamp, phase: r.phase });
    });
    return items.sort((a, b) => new Date(b.ts || b.timestamp || 0) - new Date(a.ts || a.timestamp || 0));
  }, [agentComms, reasoningLog]);

  const totalLLM = OBS_AGENTS.reduce((s, a) => s + (agentComms[a] || []).filter(c => c.type === 'llm').length, 0);
  const totalRAG = OBS_AGENTS.reduce((s, a) => s + (agentComms[a] || []).filter(c => c.type === 'rag').length, 0);
  const ragHits  = OBS_AGENTS.reduce((s, a) => s + (agentComms[a] || []).filter(c => c.type === 'rag' && c.found).length, 0);
  const hitRate  = totalRAG > 0 ? Math.round(ragHits / totalRAG * 100) : null;
  const hitColor = hitRate !== null ? (hitRate >= 60 ? 'var(--green)' : 'var(--amber)') : 'var(--text-muted)';

  const liveAgents = Object.entries(agents).filter(([, a]) => a.status === 'running' || a.status === 'thinking');

  const totalTools = useMemo(() =>
    Object.values(subagentStates).reduce((s, st) => s + Object.keys(st.toolExits || {}).length, 0),
  [subagentStates]);

  const tabBtn = (key, icon, label, count) => React.createElement('div', {
    onClick: () => setTab(key),
    style: {
      padding: '6px 14px', borderRadius: 6, cursor: 'pointer', fontSize: 11, whiteSpace: 'nowrap',
      fontFamily: 'var(--font-mono)', fontWeight: tab === key ? 700 : 400,
      border: tab === key ? '1px solid var(--cyan)' : '1px solid var(--bg-panel)',
      background: tab === key ? 'rgba(0,212,255,0.07)' : 'rgba(255,255,255,0.04)',
      color: tab === key ? 'var(--cyan)' : 'var(--text-muted)',
      display: 'flex', alignItems: 'center', gap: 5, transition: 'all 0.1s',
    }
  },
    icon, ' ', label,
    count != null && count > 0 && React.createElement('span', {
      style: {
        fontSize: 9, padding: '0 5px', borderRadius: 9, fontWeight: 700,
        background: tab === key ? 'rgba(0,212,255,0.18)' : 'var(--bg-panel)',
        color: tab === key ? 'var(--cyan)' : 'var(--text-secondary)',
        border: `1px solid ${tab === key ? 'rgba(0,212,255,0.25)' : 'var(--bg-panel)'}`,
      }
    }, count)
  );

  return React.createElement('div', { 'data-slot': 'AIObservability.AIObservability',
    style: { padding: 16, height: '100%', display: 'flex', flexDirection: 'column',
             background: 'var(--bg-base,#0a0a0a)', overflow: 'hidden' }
  },

    // ── Header ──────────────────────────────────────────────────────────────
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12, flexShrink: 0, gap: 10 }
    },
      React.createElement('div', null,
        React.createElement('div', {
          style: { fontSize: 16, fontWeight: 700, color: 'var(--text-primary)',
                   display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }
        },
          '🔬 AI Observability',
          wsConnected && React.createElement('span', {
            style: { fontSize: 9, padding: '2px 7px', borderRadius: 10,
                     background: 'rgba(0,255,136,0.07)', border: '1px solid var(--green)', color: 'var(--green)' }
          }, '● LIVE'),
          llmThinking && React.createElement('span', {
            style: { fontSize: 10, color: 'var(--cyan)', animation: 'pulse 1s infinite', marginLeft: 4 }
          }, '🧠 Thinking...')
        ),
        React.createElement('div', {
          style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', display: 'flex', gap: 10, flexWrap: 'wrap' }
        },
          activeSession && React.createElement('span', null, activeSession.target_ip),
          currentPhase  && React.createElement('span', null, `Phase: ${currentPhase.toUpperCase()}`),
          liveAgents.length > 0 && React.createElement('span', { style: { color: 'var(--green)' } },
            `${liveAgents.length} agent${liveAgents.length > 1 ? 's' : ''} active`)
        )
      ),
      // Live metric pills
      React.createElement('div', { style: { display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' } },
        [
          { val: totalLLM, label: 'LLM',     color: 'var(--cyan)',   icon: '🧠', bg: 'rgba(0,212,255,0.06)' },
          { val: totalRAG, label: 'RAG',     color: 'var(--violet)', icon: '📚', bg: 'rgba(160,80,255,0.06)' },
          hitRate !== null && { val: `${hitRate}%`, label: 'HIT', color: hitColor, icon: '📊', bg: `${hitColor}0d` },
        ].filter(Boolean).map(({ val, label, color, icon, bg }) =>
          React.createElement('div', {
            key: label,
            style: { padding: '5px 12px', borderRadius: 20, background: bg,
                     border: `1px solid ${color}30`, display: 'flex', alignItems: 'center', gap: 5 }
          },
            React.createElement('span', { style: { fontSize: 10 } }, icon),
            React.createElement('span', { style: { fontSize: 12, fontWeight: 700, color, fontFamily: 'var(--font-mono)' } }, val),
            React.createElement('span', { style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, label)
          )
        )
      )
    ),

    // ── Tab bar ─────────────────────────────────────────────────────────────
    React.createElement('div', {
      style: { display: 'flex', gap: 4, marginBottom: 12, flexShrink: 0, overflowX: 'auto', paddingBottom: 2 }
    },
      tabBtn('feed',      '⚡', 'Intelligence Feed', unifiedFeed.length),
      tabBtn('llm',       '🧠', 'LLM Deep Dive',     totalLLM),
      tabBtn('rag',       '📚', 'RAG Inspector',      totalRAG),
      tabBtn('tools',     '🔧', 'Tool Executions',    totalTools),
      tabBtn('waterfall', '📶', 'Waterfall',          unifiedFeed.length),
      tabBtn('stats',     '📊', 'Stats & Metrics',    null),
    ),

    // ── Content ─────────────────────────────────────────────────────────────
    React.createElement('div', { style: { flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' } },
      tab === 'feed'      && React.createElement(IntelligenceFeed, { items: unifiedFeed }),
      tab === 'llm'       && React.createElement(LLMDeepDive,      { agentComms, agents }),
      tab === 'rag'       && React.createElement(RAGInspector,     { agentComms }),
      tab === 'tools'     && React.createElement(ToolExecutions,   { subagentStates, subagentLines }),
      tab === 'waterfall' && React.createElement(ToolWaterfall,    { interactions: unifiedFeed }),
      tab === 'stats'     && React.createElement('div', { style: { flex: 1, overflowY: 'auto', paddingRight: 4 } },
        React.createElement(StatsPanel, { agentComms, reasoningLog, llmStatus })
      ),
    )
  );
}

window.AIObservability = AIObservability;
