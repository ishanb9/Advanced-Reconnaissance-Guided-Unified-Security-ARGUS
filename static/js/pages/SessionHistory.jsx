// SessionHistory.jsx — Browse, switch, stop, and delete pentest sessions
const { useState, useEffect } = React;

const STATUS_COLOR = {
  active:    'var(--green)',
  completed: 'var(--cyan)',
  paused:    'var(--amber)',
  failed:    'var(--red)',
};

function SessionHistory() {
  const { state, dispatch, connectWS, refreshSessions } = window.useStore();
  const { sessions, sessionId: activeSessionId } = state;

  const [loading,      setLoading]      = useState(false);
  const [switching,    setSwitching]    = useState(null);
  const [confirmStop,  setConfirmStop]  = useState(null);
  const [confirmDel,   setConfirmDel]   = useState(null);
  const [deleting,     setDeleting]     = useState(null);
  const [filterStatus, setFilterStatus] = useState('all');
  const [search,       setSearch]       = useState('');

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    await refreshSessions();
    setLoading(false);
  }

  async function switchSession(session) {
    if (session.id === activeSessionId) return;
    setSwitching(session.id);
    try {
      // Fetch full session summary (includes graph, findings list, logs, etc.)
      const summary = await window.API.sessions.activate(session.id);

      // 1. Reset store cleanly first — keep sysStatus/sessions intact
      dispatch({ type: 'RESET_SESSION' });

      // 2. Restore session identity
      dispatch({ type: 'SET_SESSION',          payload: summary.session || session });

      // 3. Restore findings
      dispatch({ type: 'SET_FINDINGS_SUMMARY', payload: summary.findings || {} });
      dispatch({ type: 'SET_FLAGS',            payload: summary.flags    || [] });

      // 4. Restore attack graph
      if (summary.graph) {
        dispatch({ type: 'SET_GRAPH', payload: {
          nodes: summary.graph.nodes || [],
          edges: summary.graph.edges || []
        }});
      }

      // 5. Restore phase state
      if (summary.current_phase) {
        dispatch({ type: 'PHASE_CHANGE', payload: { phase: summary.current_phase } });
      }
      if (summary.phases_completed?.length) {
        summary.phases_completed.forEach(phase => {
          dispatch({ type: 'PHASE_DONE', payload: { phase } });
        });
      }

      // 6. Replay recent logs into feed so Mission Control shows history
      if (summary.recent_logs?.length) {
        summary.recent_logs.slice().reverse().forEach(log => {
          dispatch({ type: 'FEED_ENTRY', payload: {
            ts:        new Date(log.timestamp || Date.now()).toLocaleTimeString(),
            agent:     (log.agent || '').split('.').pop().toLowerCase(),
            eventType: 'agent_log',
            message:   log.message || log.action || '',
            data:      log
          }});
        });
      }

      // 7. Replay tool outputs into terminal buffers
      if (summary.tool_outputs?.length) {
        summary.tool_outputs.forEach(out => {
          const agentKey = (out.agent || '').split('.').pop().toLowerCase();
          const lines = (out.stdout || '').split('\n').filter(Boolean);
          lines.forEach(line => {
            dispatch({ type: 'TOOL_LINE', payload: { agent: agentKey, line, lineType: 'stdout' } });
          });
        });
      }

      // 8. Connect WebSocket for live updates
      connectWS(session.id);

    } catch (e) {
      alert('Failed to switch session: ' + e.message);
    }
    setSwitching(null);
  }

  async function stopSession(session) {
    try {
      await window.API.sessions.stop(session.id);
      await load();
    } catch {}
    setConfirmStop(null);
  }

  async function deleteSession(session) {
    setDeleting(session.id);
    setConfirmDel(null);
    try {
      await window.API.sessions.delete(session.id);
      if (session.id === activeSessionId) {
        dispatch({ type: 'SET_SESSION', payload: null });
      }
      await load();
    } catch (e) {
      alert('Failed to delete session: ' + e.message);
    }
    setDeleting(null);
  }

  const filtered = sessions
    .filter(s => filterStatus === 'all' || s.status === filterStatus)
    .filter(s => !search || s.target_ip?.includes(search) || s.id?.includes(search));

  const statusCounts = sessions.reduce((acc, s) => {
    acc[s.status] = (acc[s.status] || 0) + 1;
    return acc;
  }, {});

  const inputStyle = {
    padding: '7px 12px', borderRadius: 6,
    border: '1px solid var(--border)', background: 'var(--bg-panel)',
    color: 'var(--text-primary)', fontSize: 12, outline: 'none'
  };
  const card = {
    background: 'var(--bg-card)', border: '1px solid var(--border)',
    borderRadius: 8, padding: '14px 16px', position: 'relative', transition: 'all 0.15s'
  };
  const btnBase = {
    padding: '3px 10px', borderRadius: 4, cursor: 'pointer', fontSize: 10, border: '1px solid'
  };

  return React.createElement('div', {
    style: { padding: 16, height: '100%', overflowY: 'auto', background: 'var(--bg-surface)' }
  },

    // Header
    React.createElement('div', { className: 'page-header', style: { marginBottom: 16 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '📋 Session History'),
        React.createElement('div', { className: 'page-subtitle' },
          `${sessions.length} total · ${statusCounts.active || 0} active`)
      ),
      React.createElement('button', {
        style: { padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border-light)',
                 background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 },
        onClick: load
      }, '↻ Refresh')
    ),

    // Status pills
    React.createElement('div', { style: { display: 'flex', gap: 10, marginBottom: 14 } },
      ...Object.entries(STATUS_COLOR).map(([status, color]) =>
        React.createElement('div', {
          key: status,
          style: {
            padding: '8px 16px', borderRadius: 6, background: 'var(--bg-card)',
            border: `1px solid ${(statusCounts[status] || 0) > 0 ? color : 'var(--border)'}`,
            cursor: 'pointer'
          },
          onClick: () => setFilterStatus(filterStatus === status ? 'all' : status)
        },
          React.createElement('div', { style: { fontSize: 20, fontWeight: 700, color } }, statusCounts[status] || 0),
          React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' } }, status)
        )
      )
    ),

    // Search
    React.createElement('div', { style: { display: 'flex', gap: 10, marginBottom: 14 } },
      React.createElement('input', {
        style: { ...inputStyle, flex: 1 },
        placeholder: 'Search by IP or session ID...',
        value: search, onChange: e => setSearch(e.target.value)
      }),
      React.createElement('select', {
        style: { ...inputStyle, minWidth: 140 },
        value: filterStatus, onChange: e => setFilterStatus(e.target.value)
      },
        ['all','active','completed','paused','failed'].map(s =>
          React.createElement('option', { key: s, value: s }, s === 'all' ? 'All Status' : s)
        )
      )
    ),

    // Grid
    loading
      ? React.createElement('div', { style: { textAlign: 'center', padding: 60, color: 'var(--text-muted)' } }, 'Loading...')
      : filtered.length === 0
        ? React.createElement('div', { style: { textAlign: 'center', padding: 60, color: 'var(--text-muted)' } },
            React.createElement('div', { style: { fontSize: 40, marginBottom: 12 } }, '📋'),
            'No sessions found'
          )
        : React.createElement('div', {
            style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px,1fr))', gap: 12 }
          },
            filtered.map(s => {
              const isActive   = s.id === activeSessionId;
              const isDeleting = deleting === s.id;
              const isSwitching = switching === s.id;
              return React.createElement('div', {
                key: s.id,
                style: {
                  ...card,
                  border: `1px solid ${isActive ? 'var(--cyan)' : 'var(--border)'}`,
                  background: isActive ? 'rgba(0,212,255,0.04)' : 'var(--bg-card)',
                  opacity: isDeleting ? 0.4 : 1,
                }
              },
                isActive && React.createElement('div', {
                  style: { position: 'absolute', top: 10, right: 12, fontSize: 10,
                           color: 'var(--cyan)', fontWeight: 600 }
                }, '● ACTIVE'),

                React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 } },
                  React.createElement('span', {
                    style: {
                      width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                      background: STATUS_COLOR[s.status] || 'var(--text-secondary)',
                      boxShadow: s.status === 'active' ? `0 0 8px ${STATUS_COLOR[s.status]}` : 'none'
                    }
                  }),
                  React.createElement('div', { style: { flex: 1 } },
                    React.createElement('div', { style: { fontFamily: 'var(--font-mono)', fontSize: 15, fontWeight: 700 } },
                      s.target_ip || 'Unknown'),
                    React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } },
                      `${s.target_type?.toUpperCase() || 'UNKNOWN'} · ${s.id?.slice(-8)}`)
                  )
                ),

                React.createElement('div', { style: { display: 'flex', gap: 16, marginBottom: 10, fontSize: 11 } },
                  React.createElement('div', null,
                    React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 10 } }, 'PHASE'),
                    React.createElement('div', { style: { color: 'var(--cyan)', fontFamily: 'var(--font-mono)' } },
                      s.current_phase?.toUpperCase() || 'IDLE')
                  ),
                  React.createElement('div', null,
                    React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 10 } }, 'FINDINGS'),
                    React.createElement('div', { style: { color: 'var(--amber)', fontFamily: 'var(--font-mono)' } },
                      s.findings_count || 0)
                  ),
                  React.createElement('div', null,
                    React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 10 } }, 'FLAGS'),
                    React.createElement('div', { style: { color: 'var(--violet)', fontFamily: 'var(--font-mono)' } },
                      s.flags_found?.length || 0)
                  ),
                  React.createElement('div', null,
                    React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 10 } }, 'STATUS'),
                    React.createElement('div', { style: { color: STATUS_COLOR[s.status] || 'var(--text-secondary)', fontFamily: 'var(--font-mono)' } },
                      s.status?.toUpperCase() || '?')
                  )
                ),

                React.createElement('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' } },
                  React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } },
                    s.started_at ? new Date(s.started_at).toLocaleString() : 'Unknown'),
                  React.createElement('div', { style: { display: 'flex', gap: 6 } },
                    s.status === 'active' && React.createElement('button', {
                      style: { ...btnBase, borderColor: 'var(--red)', background: 'rgba(255,68,102,0.1)', color: 'var(--red)' },
                      onClick: e => { e.stopPropagation(); setConfirmStop(s); }
                    }, 'Stop'),
                    !isActive && React.createElement('button', {
                      style: {
                        ...btnBase, borderColor: 'var(--cyan)', background: 'rgba(0,212,255,0.08)', color: 'var(--cyan)',
                        opacity: isSwitching ? 0.6 : 1, cursor: isSwitching ? 'wait' : 'pointer'
                      },
                      onClick: e => { e.stopPropagation(); switchSession(s); },
                      disabled: isSwitching
                    }, isSwitching ? 'Loading...' : 'Switch'),
                    React.createElement('button', {
                      style: { ...btnBase, borderColor: 'var(--border-light)', background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)',
                               opacity: isDeleting ? 0.5 : 1 },
                      onClick: e => { e.stopPropagation(); setConfirmDel(s); },
                      disabled: isDeleting,
                      title: 'Delete permanently'
                    }, isDeleting ? '...' : '🗑')
                  )
                )
              );
            })
          ),

    // Stop modal
    confirmStop && React.createElement('div', {
      style: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
               display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
      onClick: e => { if (e.target === e.currentTarget) setConfirmStop(null); }
    },
      React.createElement('div', {
        style: { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 10, width: 420, padding: 24 }
      },
        React.createElement('div', { style: { fontSize: 15, fontWeight: 700, marginBottom: 12 } }, '⏹ Stop Session'),
        React.createElement('p', { style: { color: 'var(--text-muted)', fontSize: 13, marginBottom: 20 } },
          `Stop pentest on ${confirmStop.target_ip}? All agents will be halted.`),
        React.createElement('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: 8 } },
          React.createElement('button', {
            onClick: () => setConfirmStop(null),
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--border-light)',
                     background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 }
          }, 'Cancel'),
          React.createElement('button', {
            onClick: () => stopSession(confirmStop),
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--critical-bd)',
                     background: 'var(--critical-bg)', color: 'var(--critical)', cursor: 'pointer', fontSize: 12 }
          }, 'Stop Session')
        )
      )
    ),

    // Delete modal
    confirmDel && React.createElement('div', {
      style: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)',
               display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
      onClick: e => { if (e.target === e.currentTarget) setConfirmDel(null); }
    },
      React.createElement('div', {
        style: { background: 'var(--bg-card)', border: '1px solid rgba(255,68,102,0.4)', borderRadius: 10, width: 440, padding: 24 }
      },
        React.createElement('div', { style: { fontSize: 15, fontWeight: 700, marginBottom: 8, color: 'var(--red)' } },
          '🗑 Delete Session Permanently'),
        React.createElement('div', {
          style: { background: 'rgba(255,68,102,0.08)', border: '1px solid rgba(255,68,102,0.2)',
                   borderRadius: 6, padding: '10px 14px', marginBottom: 16 }
        },
          React.createElement('div', { style: { fontFamily: 'var(--font-mono)', fontSize: 14, marginBottom: 4 } },
            confirmDel.target_ip),
          React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)' } },
            `Session: ${confirmDel.id?.slice(-12)} · ${confirmDel.status}`)
        ),
        React.createElement('p', { style: { color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.7, marginBottom: 16 } },
          'Permanently deletes all findings, logs, flags, graph, shells, and payloads. Cannot be undone.'),
        confirmDel.status === 'active' && React.createElement('div', {
          style: { padding: '8px 12px', borderRadius: 5, background: 'rgba(255,170,0,0.08)',
                   border: '1px solid rgba(255,170,0,0.3)', color: 'var(--amber)', fontSize: 11, marginBottom: 12 }
        }, '⚠ Active session — will be stopped before deletion.'),
        React.createElement('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: 8 } },
          React.createElement('button', {
            onClick: () => setConfirmDel(null),
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--border-light)',
                     background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 }
          }, 'Cancel'),
          React.createElement('button', {
            onClick: () => deleteSession(confirmDel),
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--critical-bd)',
                     background: 'var(--critical-bg)', color: 'var(--critical)', cursor: 'pointer', fontSize: 12, fontWeight: 700 }
          }, '🗑 Delete Permanently')
        )
      )
    )
  );
}

window.SessionHistory = SessionHistory;
