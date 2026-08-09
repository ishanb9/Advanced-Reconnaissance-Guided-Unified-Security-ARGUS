// ═══════════════════════════════════════════════════════════
// ToolWorkshop.jsx — Manual tool execution with SSE streaming
// Lists all 134+ MCP tools, allows direct execution with
// live output stream and optional session attachment
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useRef, useCallback } = React;

const CATEGORY_ICONS = {
  recon:       '🔍', network:      '📡', vuln:        '🔬',
  web:         '🌐', exploit:      '💥', password:    '🔑',
  post_exploit:'🎭', privesc:      '⬆',  forensics:   '🧪',
  osint:       '📰', wireless:     '📶', mobile:      '📱',
  crypto:      '🔐', fuzzing:      '🌊', database:    '🗄',
  reporting:   '📄', misc:         '⚙'
};

function ToolWorkshop() {
  const { state } = window.useStore();
  const { sessionId } = state;

  const [tools,      setTools]      = useState([]);
  const [categories, setCategories] = useState([]);
  const [selCat,     setSelCat]     = useState('all');
  const [search,     setSearch]     = useState('');
  const [selTool,    setSelTool]    = useState(null);
  const [target,     setTarget]     = useState('');
  const [options,    setOptions]    = useState('');
  const [running,    setRunning]    = useState(false);
  const [output,     setOutput]     = useState([]);
  const [loadingTools, setLoadingTools] = useState(false);

  const outputRef  = useRef(null);
  const esRef      = useRef(null);

  // Load tools from MCP
  const loadTools = useCallback(async () => {
    setLoadingTools(true);
    try {
      const res = await window.API.tools();
      const list = res.tools || [];
      setTools(list);
      const cats = ['all', ...Array.from(new Set(list.map(t => t.category || 'misc').filter(Boolean))).sort()];
      setCategories(cats);
    } catch (e) {
      setOutput([{ type: 'error', line: `Failed to load tools: ${e.message}` }]);
    }
    setLoadingTools(false);
  }, []);

  useEffect(() => { loadTools(); }, [loadTools]);

  // Auto-scroll output
  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [output.length]);

  // Cleanup SSE on unmount
  useEffect(() => () => { if (esRef.current) esRef.current.close(); }, []);

  const filteredTools = tools.filter(t => {
    if (selCat !== 'all' && (t.category || 'misc') !== selCat) return false;
    if (search) {
      const q = search.toLowerCase();
      return (t.name || '').toLowerCase().includes(q) ||
             (t.description || '').toLowerCase().includes(q);
    }
    return true;
  });

  function runTool() {
    if (!selTool || running) return;
    if (esRef.current) esRef.current.close();
    setOutput([{ type: 'info', line: `▶ Running: ${selTool.name} ${options}` }]);
    setRunning(true);

    const url = window.API.toolStream(selTool.name, target, options);
    const es  = new EventSource(url);
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const evt = JSON.parse(e.data);
        const type = evt.type || 'stdout';
        const line = evt.data || evt.message || '';
        if (line) setOutput(prev => [...prev, { type, line }].slice(-3000));
        if (type === 'exit') {
          setRunning(false);
          setOutput(prev => [...prev, {
            type: 'info',
            line: `✓ Exit code: ${evt.code}`
          }]);
          es.close();
        }
        if (type === 'error') {
          setOutput(prev => [...prev, { type: 'error', line: `[ERROR] ${line}` }]);
        }
      } catch {}
    };
    es.onerror = () => {
      setRunning(false);
      setOutput(prev => [...prev, { type: 'error', line: '[SSE connection closed]' }]);
      es.close();
    };
  }

  function stopTool() {
    if (esRef.current) { esRef.current.close(); esRef.current = null; }
    setRunning(false);
    setOutput(prev => [...prev, { type: 'warning', line: '[Stopped by user]' }]);
    window.API.toolStream && fetch('/api/stop', { method: 'POST' }).catch(() => {});
  }

  const card = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8 };
  const inp  = {
    background: 'var(--bg-panel)', border: '1px solid var(--border)',
    borderRadius: 'var(--radius)', color: 'var(--text-primary)', fontSize: 11,
    padding: '5px 10px', outline: 'none', fontFamily: 'var(--font-mono)',
    width: '100%', boxSizing: 'border-box'
  };

  return React.createElement('div', { 'data-slot': 'ToolWorkshop.ToolWorkshop',
    style: { display: 'flex', height: '100%', background: 'var(--bg-surface)', overflow: 'hidden' }
  },

    // ── Left: Tool browser ────────────────────────────────────
    React.createElement('div', {
      style: { width: 280, borderRight: '1px solid var(--border)', display: 'flex', flexDirection: 'column', flexShrink: 0 }
    },
      // Search
      React.createElement('div', { style: { padding: 10, borderBottom: '1px solid var(--border)' } },
        React.createElement('input', {
          value: search, placeholder: '🔍 Search tools...',
          onChange: e => setSearch(e.target.value),
          style: inp
        })
      ),
      // Category filter
      React.createElement('div', {
        style: { padding: '6px 10px', borderBottom: '1px solid var(--border)',
                 display: 'flex', flexWrap: 'wrap', gap: 4 }
      },
        categories.map(c =>
          React.createElement('button', {
            key: c, onClick: () => setSelCat(c),
            style: {
              padding: '2px 8px', borderRadius: 4, border: 'none', cursor: 'pointer', fontSize: 10,
              background: selCat === c ? 'rgba(0,212,255,0.15)' : 'transparent',
              color: selCat === c ? 'var(--cyan)' : 'var(--text-muted)',
              fontFamily: 'var(--font-mono)'
            }
          }, c === 'all' ? `ALL (${tools.length})` : `${CATEGORY_ICONS[c] || '⚙'} ${c}`)
        )
      ),
      // Tool list
      React.createElement('div', { style: { flex: 1, overflowY: 'auto' } },
        loadingTools
          ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 20, fontSize: 11 } }, 'Loading tools...')
          : filteredTools.map(t =>
              React.createElement('div', {
                key: t.name,
                onClick: () => { setSelTool(t); setOptions(t.default_options || ''); },
                style: {
                  padding: '7px 12px', cursor: 'pointer', borderBottom: '1px solid var(--border)',
                  background: selTool?.name === t.name ? 'rgba(0,212,255,0.07)' : 'transparent',
                  borderLeft: `2px solid ${selTool?.name === t.name ? 'var(--cyan)' : 'transparent'}`
                }
              },
                React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6 } },
                  React.createElement('span', { style: { fontSize: 12 } }, CATEGORY_ICONS[t.category] || '⚙'),
                  React.createElement('span', {
                    style: {
                      fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
                      color: selTool?.name === t.name ? 'var(--cyan)' : 'var(--text-primary)'
                    }
                  }, t.name)
                ),
                React.createElement('div', {
                  style: { fontSize: 10, color: 'var(--text-muted)', marginTop: 2, paddingLeft: 18,
                           overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
                }, t.description || '')
              )
            )
      )
    ),

    // ── Right: Execution pane ─────────────────────────────────
    React.createElement('div', { style: { flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' } },
      // Tool header + run controls
      React.createElement('div', { style: { padding: '12px 16px', borderBottom: '1px solid var(--border)', flexShrink: 0 } },
        selTool
          ? React.createElement('div', null,
              React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 } },
                React.createElement('span', { style: { fontFamily: 'var(--font-mono)', fontSize: 15, color: 'var(--cyan)', fontWeight: 700 } },
                  selTool.name),
                React.createElement('span', { style: { fontSize: 11, color: 'var(--text-muted)' } },
                  selTool.description)
              ),
              React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 8 } },
                React.createElement('div', { style: { flex: 1 } },
                  React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 3 } }, 'TARGET'),
                  React.createElement('input', {
                    value: target, placeholder: 'e.g. 10.10.10.1 or http://target',
                    onChange: e => setTarget(e.target.value),
                    style: inp
                  })
                ),
                React.createElement('div', { style: { flex: 2 } },
                  React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 3 } }, 'OPTIONS'),
                  React.createElement('input', {
                    value: options, placeholder: 'e.g. -sV -p 80,443 or dir -w /usr/share/wordlists/...',
                    onChange: e => setOptions(e.target.value),
                    style: inp
                  })
                )
              ),
              React.createElement('div', { style: { display: 'flex', gap: 8 } },
                React.createElement('button', {
                  onClick: runTool, disabled: running,
                  style: {
                    padding: '6px 18px', borderRadius: 5, cursor: 'pointer',
                    background: running ? 'rgba(255,255,255,0.04)' : 'var(--accent)',
                    color: running ? 'var(--text-secondary)' : '#0D0E14',
                    border: running ? '1px solid var(--border-light)' : '1px solid var(--accent)',
                    boxShadow: running ? 'none' : '0 0 10px var(--accent-glow)',
                    fontSize: 12, fontWeight: 600
                  }
                }, running ? '⟳ Running...' : '▶ Run'),
                running && React.createElement('button', {
                  onClick: stopTool,
                  style: {
                    padding: '6px 14px', borderRadius: 5, cursor: 'pointer',
                    background: 'var(--critical-bg)', border: '1px solid var(--critical-bd)',
                    color: 'var(--critical)', fontSize: 12
                  }
                }, '■ Stop'),
                React.createElement('button', {
                  onClick: () => setOutput([]),
                  style: {
                    padding: '6px 12px', borderRadius: 5, cursor: 'pointer',
                    background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-light)',
                    color: 'var(--text-secondary)', fontSize: 12
                  }
                }, 'Clear')
              )
            )
          : React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 12, padding: '8px 0' } },
              '← Select a tool from the list to run it manually')
      ),

      // Output terminal
      React.createElement('div', {
        ref: outputRef,
        style: {
          flex: 1, overflowY: 'auto', padding: '8px 14px',
          fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.7,
          background: 'var(--bg-panel)'
        }
      },
        output.length === 0
          ? React.createElement('div', { style: { color: 'var(--text-muted)', paddingTop: 20 } },
              '$ _')
          : output.map((o, i) =>
              React.createElement('div', {
                key: i,
                style: {
                  color: o.type === 'stderr'  ? '#ff6666' :
                         o.type === 'error'   ? 'var(--red)' :
                         o.type === 'warning' ? 'var(--amber)' :
                         o.type === 'info'    ? 'var(--cyan)' :
                         'var(--text-primary)',
                  whiteSpace: 'pre-wrap', wordBreak: 'break-all'
                }
              }, o.line)
            )
      )
    )
  );
}

window.ToolWorkshop = ToolWorkshop;
