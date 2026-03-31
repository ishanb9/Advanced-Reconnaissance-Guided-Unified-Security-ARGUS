// ShellManager.jsx — Phase 3: Real PTY shells via WebSocket + xterm.js
// Replaces polling REST cmd with live bidirectional PTY I/O
const { useState, useEffect, useRef, useCallback } = React;
const { Card, Button, Tag, Modal, Input, Select, Space, Alert, Tooltip, Tabs } = antd;

function ShellManager() {
  const { state, sendWS, registerShellListener, refreshSessions } = window.useStore();
  const sessionId = state.sessionId;

  const [shells,       setShells]       = useState([]);
  const [loading,      setLoading]      = useState(false);
  const [creating,     setCreating]     = useState(false);
  const [activeShellId, setActiveShellId] = useState(null);
  const [createForm,   setCreateForm]   = useState({
    shell_type: 'reverse_shell', lport: 4444, rhost: '', protocol: 'tcp',
    username: '', password: '', key_file: ''
  });
  const [payloads,     setPayloads]     = useState([]);
  const [lhostForPayloads, setLhostForPayloads] = useState('');
  const [activeTab,    setActiveTab]    = useState('terminal');
  const [upgrading,    setUpgrading]    = useState(false);

  const termRef   = useRef(null);   // DOM container for xterm
  const xtermRef  = useRef(null);   // Terminal instance
  const fitRef    = useRef(null);   // FitAddon instance
  const shellIdRef = useRef(null);  // Current active shell id

  // ── Load shells on mount / session change ───────────────
  useEffect(() => {
    if (sessionId) {
      loadShells();
      loadPayloadSuggestions();
    }
  }, [sessionId]);

  // ── Sync shells from store shell_status events ──────────
  useEffect(() => {
    setShells(prev => prev.map(s => {
      const storeShell = state.shells.find(ss => ss.id === s.id);
      return storeShell ? { ...s, active: storeShell.active } : s;
    }));
  }, [state.shells]);

  async function loadShells() {
    if (!sessionId) return;
    setLoading(true);
    try {
      const res = await window.API.shells(sessionId);
      setShells(res.shells || []);
    } catch {}
    setLoading(false);
  }

  async function loadPayloadSuggestions() {
    if (!sessionId) return;
    try {
      const res = await window.API.shellPayloads(sessionId, createForm.lport);
      setPayloads(res.payloads || []);
      setLhostForPayloads(res.lhost || '');
    } catch {}
  }

  // ── xterm.js terminal lifecycle ─────────────────────────
  useEffect(() => {
    if (!activeShellId || !termRef.current || !window.Terminal) return;

    // Dispose previous terminal
    if (xtermRef.current) {
      xtermRef.current.dispose();
      xtermRef.current = null;
    }

    shellIdRef.current = activeShellId;

    const term = new window.Terminal({
      theme: { background: 'var(--bg-surface)', foreground: '#e2e8f0', cursor: 'var(--cyan)',
               cursorAccent: '#000', selection: 'rgba(0,212,255,0.2)' },
      fontFamily: "'JetBrains Mono', 'Courier New', monospace",
      fontSize: 13,
      cursorBlink: true,
      allowProposedApi: true,
      scrollback: 10000,
    });

    term.open(termRef.current);
    xtermRef.current = term;

    // Welcome banner
    const shell = shells.find(s => s.id === activeShellId);
    term.writeln(`\x1b[90m╔══ ARGUS — Shell Terminal ══╗\x1b[0m`);
    term.writeln(`\x1b[90m║ Shell: ${activeShellId.slice(-8)} │ Host: ${shell?.rhost || '?'} │ Type: ${shell?.shell_type || '?'}\x1b[0m`);
    term.writeln(`\x1b[90m╚═══════════════════════════════════════════════╝\x1b[0m`);
    term.writeln('');

    // Replay command history from DB
    if (shell?.commands?.length) {
      term.writeln(`\x1b[90m── Replaying ${Math.min(shell.commands.length, 50)} commands from history ──\x1b[0m`);
      shell.commands.slice(-50).forEach(({ cmd, output }) => {
        term.writeln(`\x1b[36m$ ${cmd}\x1b[0m`);
        if (output) term.write(output);
      });
    }

    // Drain any buffered PTY output from store
    const buffered = state.shellBuffers[activeShellId];
    if (buffered) {
      term.write(buffered);
      // Clear buffer after draining
    }

    // Register live output listener — receives raw PTY data
    const unregister = registerShellListener(activeShellId, (data) => {
      if (xtermRef.current) xtermRef.current.write(data);
    });

    // Route keystrokes → WS shell_input
    term.onData((data) => {
      if (shellIdRef.current) {
        sendWS({ type: 'shell_input', shell_id: shellIdRef.current, data });
      }
    });

    // Handle resize
    const resizeObserver = new ResizeObserver(() => {
      if (!xtermRef.current || !termRef.current) return;
      const { clientWidth, clientHeight } = termRef.current;
      const cellW = xtermRef.current._core._renderService._renderer?._actualCellWidth || 8;
      const cellH = xtermRef.current._core._renderService._renderer?._actualCellHeight || 17;
      const cols = Math.max(10, Math.floor(clientWidth / cellW));
      const rows = Math.max(5, Math.floor(clientHeight / cellH));
      try { xtermRef.current.resize(cols, rows); } catch {}
      sendWS({ type: 'shell_resize', shell_id: shellIdRef.current, cols, rows });
    });
    if (termRef.current) resizeObserver.observe(termRef.current);

    return () => {
      unregister();
      resizeObserver.disconnect();
      if (xtermRef.current) { xtermRef.current.dispose(); xtermRef.current = null; }
      shellIdRef.current = null;
    };
  }, [activeShellId]);

  // ── Actions ─────────────────────────────────────────────
  async function createShell() {
    if (!sessionId) return;
    try {
      const body = { ...createForm, session_id: sessionId };
      const res  = await window.API.createShell(body);
      setCreating(false);
      await loadShells();
      if (res.shell_id) setActiveShellId(res.shell_id);
    } catch (e) {
      alert('Failed: ' + e.message);
    }
  }

  async function upgradeShell() {
    if (!activeShellId || !sessionId) return;
    setUpgrading(true);
    try {
      await window.API.upgradeShell(activeShellId, sessionId);
      if (xtermRef.current) {
        xtermRef.current.writeln('\r\n\x1b[33m[Sending TTY upgrade commands...]\x1b[0m');
      }
    } catch {}
    setUpgrading(false);
  }

  async function terminateShell() {
    if (!activeShellId || !sessionId) return;
    await window.API.terminateShell(activeShellId, sessionId);
    setActiveShellId(null);
    await loadShells();
  }

  const activeShell = shells.find(s => s.id === activeShellId);

  // ── Render ───────────────────────────────────────────────
  return React.createElement('div', null,

    React.createElement('div', { className: 'page-header' },
      React.createElement('div', { className: 'page-title' }, '🐚 Shell Manager'),
      React.createElement('div', { style: { display: 'flex', gap: 8 } },
        React.createElement('button', {
          style: { padding: '6px 14px', borderRadius: 6, border: '1px solid var(--accent)',
                   background: 'var(--accent)', color: '#0D0E14', cursor: 'pointer',
                   fontWeight: 600, fontSize: 12, boxShadow: '0 0 10px var(--accent-glow)' },
          onClick: () => setCreating(true)
        }, '+ New Shell Listener'),
        React.createElement('button', {
          style: { padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border-light)',
                   background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 },
          onClick: loadShells
        }, '↻')
      )
    ),

    !sessionId && React.createElement(Alert, {
      type: 'info', message: 'Start a session to manage shells', style: { marginBottom: 16 }
    }),

    React.createElement('div', { style: { display: 'flex', gap: 14, height: 'calc(100vh - 160px)' } },

      // ── Shell list ──────────────────────────────────────
      React.createElement('div', {
        style: { width: 240, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 8 }
      },
        React.createElement(Card, {
          title: `Shell Sessions (${shells.length})`,
          style: { flex: 1, overflow: 'auto' },
          bodyStyle: { padding: '10px 12px', overflowY: 'auto' },
          loading
        },
          shells.length === 0
            ? React.createElement('div', {
                style: { color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', padding: '20px 0' }
              }, 'No shells yet')
            : shells.map(s => React.createElement('div', {
                key: s.id,
                style: {
                  padding: '10px 12px', borderRadius: 6, cursor: 'pointer', marginBottom: 6,
                  border: `1px solid ${activeShellId === s.id ? 'var(--cyan)' : 'var(--border)'}`,
                  background: activeShellId === s.id ? 'rgba(0,212,255,0.06)' : 'var(--bg-panel)',
                  transition: 'all 0.15s'
                },
                onClick: () => setActiveShellId(s.id)
              },
                React.createElement('div', {
                  style: { display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }
                },
                  React.createElement('span', {
                    style: { width: 7, height: 7, borderRadius: '50%',
                             background: s.active ? 'var(--green)' : 'var(--text-muted)',
                             boxShadow: s.active ? '0 0 6px var(--green)' : 'none',
                             flexShrink: 0 }
                  }),
                  React.createElement('span', { style: { fontSize: 12, fontWeight: 600 } },
                    s.shell_type?.replace(/_/g, ' '))
                ),
                React.createElement('div', {
                  style: { fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }
                }, `${s.rhost || '0.0.0.0'}${s.lport ? ':' + s.lport : ''}`),
                s.shell_user && React.createElement('div', {
                  style: { fontSize: 10, color: 'var(--cyan)', marginTop: 2 }
                }, `👤 ${s.shell_user}`),
                React.createElement('div', {
                  style: { fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }
                }, `${s.commands?.length || 0} cmds · ${s.id.slice(-6)}`)
              ))
        )
      ),

      // ── Main terminal area ──────────────────────────────
      React.createElement('div', { style: { flex: 1, display: 'flex', flexDirection: 'column', gap: 10 } },

        activeShellId ? React.createElement('div', {
          style: { flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }
        },

          // Toolbar
          React.createElement('div', {
            style: { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
                     background: 'var(--bg-card)', borderRadius: 6,
                     border: '1px solid var(--border)' }
          },
            React.createElement('span', {
              style: { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--cyan)', flex: 1 }
            }, `${activeShell?.shell_type?.replace(/_/g,' ') || 'Shell'} @ ${activeShell?.rhost || '?'} [${activeShellId.slice(-8)}]`),
            React.createElement('button', {
              style: { padding: '4px 12px', borderRadius: 4,
                       border: '1px solid var(--border-light)', background: 'rgba(255,255,255,0.04)',
                       color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 11 },
              onClick: upgradeShell, disabled: upgrading
            }, upgrading ? '...' : '⬆ Upgrade TTY'),
            React.createElement('button', {
              style: { padding: '4px 12px', borderRadius: 4,
                       border: '1px solid var(--border-light)', background: 'rgba(255,255,255,0.04)',
                       color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 11 },
              onClick: () => xtermRef.current?.clear()
            }, '⌫ Clear'),
            React.createElement('button', {
              style: { padding: '4px 12px', borderRadius: 4,
                       border: '1px solid var(--critical-bd)', background: 'var(--critical-bg)',
                       color: 'var(--critical)', cursor: 'pointer', fontSize: 11 },
              onClick: terminateShell
            }, '✕ Kill')
          ),

          // xterm.js terminal
          React.createElement('div', {
            ref: termRef,
            style: {
              flex: 1, background: 'var(--bg-surface)', borderRadius: 8,
              border: `1px solid ${activeShell?.active ? 'var(--cyan)' : 'var(--border)'}`,
              overflow: 'hidden', minHeight: 300,
              boxShadow: activeShell?.active ? '0 0 20px rgba(0,212,255,0.05)' : 'none'
            }
          }),

          // Payload suggestions (compact row under terminal)
          payloads.length > 0 && React.createElement('div', {
            style: { background: 'var(--bg-card)', borderRadius: 6,
                     border: '1px solid var(--border)', padding: '8px 12px' }
          },
            React.createElement('div', {
              style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 6,
                       textTransform: 'uppercase', letterSpacing: 1 }
            }, `💡 Run on target (LHOST: ${lhostForPayloads})`),
            React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 4 } },
              payloads.slice(0, 5).map((p, i) => React.createElement('div', {
                key: i, style: { display: 'flex', gap: 8, alignItems: 'center' }
              },
                React.createElement('span', {
                  style: { fontFamily: 'var(--font-mono)', fontSize: 10, minWidth: 100,
                           color: 'var(--cyan)', flexShrink: 0 }
                }, p.label),
                React.createElement('code', {
                  style: { flex: 1, fontSize: 10, fontFamily: 'var(--font-mono)',
                           color: 'var(--green)', background: 'rgba(0,255,136,0.04)',
                           padding: '3px 8px', borderRadius: 4, overflow: 'hidden',
                           textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
                }, p.cmd),
                React.createElement('button', {
                  style: { padding: '2px 8px', borderRadius: 4,
                           border: '1px solid var(--border-light)', background: 'rgba(255,255,255,0.04)',
                           color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 10, flexShrink: 0 },
                  onClick: () => navigator.clipboard.writeText(p.cmd)
                }, '📋')
              ))
            )
          )
        ) : React.createElement(Card, { style: { flex: 1 } },
          React.createElement('div', {
            style: { color: 'var(--text-muted)', textAlign: 'center', padding: 80 }
          },
            React.createElement('div', { style: { fontSize: 48, marginBottom: 12 } }, '🐚'),
            React.createElement('div', { style: { marginBottom: 8 } },
              'Select a shell session or create a new listener'),
            React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)' } },
              'Shells use real PTY — full interactive terminal support')
          )
        )
      )
    ),

    // ── Create shell modal ──────────────────────────────────
    creating && React.createElement(Modal, {
      title: '🐚 Create Shell Listener',
      open: true,
      onOk: createShell,
      onCancel: () => setCreating(false),
      okText: 'Start Listener'
    },
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
        // Shell type
        React.createElement('div', null,
          React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 } },
            'Shell Type'),
          React.createElement('select', {
            style: { width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)',
                     border: '1px solid var(--border)', background: 'var(--bg-panel)',
                     color: 'var(--text-primary)' },
            value: createForm.shell_type,
            onChange: e => setCreateForm(f => ({ ...f, shell_type: e.target.value }))
          },
            ['reverse_shell','netcat','socat','bind_shell','ssh'].map(t =>
              React.createElement('option', { key: t, value: t }, t.replace(/_/g, ' '))
            )
          )
        ),

        // Listen port
        React.createElement('div', null,
          React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 } },
            'Listen Port (LPORT)'),
          React.createElement('input', {
            style: { width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)',
                     border: '1px solid var(--border)', background: 'var(--bg-panel)',
                     color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' },
            type: 'number', value: createForm.lport,
            onChange: e => setCreateForm(f => ({ ...f, lport: parseInt(e.target.value) }))
          })
        ),

        // Target host
        React.createElement('div', null,
          React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 } },
            'Target Host (RHOST)'),
          React.createElement('input', {
            style: { width: '100%', padding: '6px 10px', borderRadius: 'var(--radius)',
                     border: '1px solid var(--border)', background: 'var(--bg-panel)',
                     color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' },
            placeholder: 'e.g. 10.10.10.100',
            value: createForm.rhost,
            onChange: e => setCreateForm(f => ({ ...f, rhost: e.target.value }))
          })
        ),

        // SSH credentials (shown only for ssh type)
        createForm.shell_type === 'ssh' && React.createElement('div', {
          style: { display: 'flex', flexDirection: 'column', gap: 10,
                   padding: 12, background: 'var(--bg-panel)', borderRadius: 6,
                   border: '1px solid var(--border)' }
        },
          React.createElement('div', {
            style: { fontSize: 11, color: 'var(--cyan)', fontWeight: 600, marginBottom: 2 }
          }, 'SSH Credentials'),
          ...['username', 'password', 'key_file'].map(field =>
            React.createElement('div', { key: field },
              React.createElement('div', {
                style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 3 }
              }, field.replace('_', ' ').toUpperCase()),
              React.createElement('input', {
                style: { width: '100%', padding: '5px 10px', borderRadius: 'var(--radius)',
                         border: '1px solid var(--border)', background: 'var(--bg-panel)',
                         color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 12 },
                type: field === 'password' ? 'password' : 'text',
                placeholder: field === 'key_file' ? '/home/user/.ssh/id_rsa' : '',
                value: createForm[field] || '',
                onChange: e => setCreateForm(f => ({ ...f, [field]: e.target.value }))
              })
            )
          )
        )
      )
    )
  );
}
window.ShellManager = ShellManager;
