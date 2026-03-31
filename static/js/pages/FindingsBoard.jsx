// ═══════════════════════════════════════════════════════════
// FindingsBoard.jsx — Findings table with live updates
//
// Fixed in v3:
//  - Loads initial findings from REST on mount/session change
//  - New findings appended live via WS 'finding' events (via store)
//  - Filter by severity and search by title/host
//  - Expandable rows with evidence and remediation
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useRef, useCallback } = React;

const SEV_ORDER  = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLOR  = {
  critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)'
};
const SEV_BG = {
  critical: 'rgba(255,68,102,0.10)', high: 'rgba(255,140,0,0.10)',
  medium: 'rgba(255,204,0,0.08)', low: 'rgba(74,222,128,0.08)', info: 'rgba(0,180,255,0.08)'
};

function SevBadge({ sev }) {
  const c = SEV_COLOR[sev] || '#888';
  return React.createElement('span', {
    style: {
      padding: '2px 8px', borderRadius: 4, fontSize: 10,
      background: SEV_BG[sev] || 'transparent',
      border: `1px solid ${c}`, color: c,
      fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: 0.5, whiteSpace: 'nowrap'
    }
  }, (sev || 'info').toUpperCase());
}

// ── SeverityDonut ────────────────────────────────────────────
function SeverityDonut({ findings, findingsSummary }) {
  const CIRC = 2 * Math.PI * 45; // ≈ 282.74
  const SEV_DONUT_COLOR = {
    critical: 'var(--critical)', high: 'var(--high)',
    medium: 'var(--medium)',     low: 'var(--low)', info: 'var(--cyan)'
  };

  const counts = SEV_ORDER.map(s => ({ sev: s, count: findingsSummary[s] || 0 }));
  const total  = counts.reduce((a, b) => a + b.count, 0);

  // Build arc segments (stroke-dasharray trick)
  let cumOffset = 0; // starts at top (rotate -90deg on the group)
  const segments = counts.map(({ sev, count }) => {
    const dash   = total > 0 ? (count / total) * CIRC : 0;
    const gap    = total > 0 && count > 0 ? 2 : 0;
    const offset = cumOffset;
    cumOffset   += dash + gap;
    return { sev, count, dash, gap, offset };
  });

  return React.createElement('div', {
    style: { display: 'flex', alignItems: 'center', gap: 20,
             background: 'var(--bg-surface)', border: '1px solid var(--border)',
             borderRadius: 8, padding: '10px 16px', flexShrink: 0 }
  },
    // SVG donut
    React.createElement('svg', {
      viewBox: '0 0 120 120', width: 100, height: 100,
      style: { flexShrink: 0 }
    },
      // background track
      React.createElement('circle', {
        cx: 60, cy: 60, r: 45,
        fill: 'none', stroke: 'rgba(255,255,255,0.05)', strokeWidth: 14
      }),
      // arc segments — rotate group so 0° is at 12-o'clock
      React.createElement('g', { style: { transform: 'rotate(-90deg)', transformOrigin: '60px 60px' } },
        total === 0
          ? React.createElement('circle', {
              cx: 60, cy: 60, r: 45, fill: 'none',
              stroke: 'rgba(255,255,255,0.08)', strokeWidth: 14
            })
          : segments.map(({ sev, dash, gap, offset }) =>
              React.createElement('circle', {
                key: sev, cx: 60, cy: 60, r: 45,
                fill: 'none',
                stroke: SEV_DONUT_COLOR[sev],
                strokeWidth: 14,
                strokeLinecap: 'round',
                strokeDasharray: `${Math.max(0, dash - gap)} ${CIRC}`,
                strokeDashoffset: -offset,
                style: { transition: 'stroke-dasharray 0.4s ease' }
              })
            )
      ),
      // centre total label
      React.createElement('text', {
        x: 60, y: 56, textAnchor: 'middle',
        style: { fill: 'var(--text-primary)', fontSize: 20, fontWeight: 700,
                 fontFamily: 'var(--font-mono)' }
      }, total),
      React.createElement('text', {
        x: 60, y: 70, textAnchor: 'middle',
        style: { fill: 'var(--text-muted)', fontSize: 8, fontFamily: 'var(--font-mono)',
                 letterSpacing: 0.8 }
      }, 'TOTAL')
    ),
    // Legend
    React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 5 } },
      counts.map(({ sev, count }) =>
        React.createElement('div', { key: sev, style: { display: 'flex', alignItems: 'center', gap: 8 } },
          React.createElement('div', {
            style: {
              width: 8, height: 8, borderRadius: '50%',
              background: SEV_DONUT_COLOR[sev], flexShrink: 0
            }
          }),
          React.createElement('span', {
            style: { fontSize: 10, fontFamily: 'var(--font-mono)',
                     color: 'var(--text-muted)', textTransform: 'uppercase',
                     letterSpacing: 0.6, minWidth: 52 }
          }, sev),
          React.createElement('span', {
            style: { fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)',
                     color: count > 0 ? SEV_DONUT_COLOR[sev] : 'var(--text-muted)' }
          }, count)
        )
      )
    )
  );
}

function FindingsBoard() {
  const { state } = window.useStore();
  const { sessionId, findingsSummary, discoveredHosts, hostFilter, dispatch } = state;

  // All findings loaded from DB + appended from WS
  const [findings,    setFindings]    = useState([]);
  const [loading,     setLoading]     = useState(false);
  const [filterSev,   setFilterSev]   = useState('all');
  const [filterHost,  setFilterHost]  = useState('all');  // per-host filter
  const [search,      setSearch]      = useState('');
  const [expanded,    setExpanded]    = useState(null);
  const [exploitAnalysis, setExploitAnalysis] = useState({});
  const seenIds = useRef(new Set());

  // Sync local host filter with global store (HostSelector in MissionControl sets it too)
  useEffect(() => { if (hostFilter) setFilterHost(hostFilter); }, [hostFilter]);

  const isMultiHost = discoveredHosts && discoveredHosts.length > 1;

  // Derive severity counts from the authoritative findings array
  const sevCounts = findings.reduce((acc, f) => {
    const s = (f.severity || 'info').toLowerCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  // Load from REST on mount and whenever session or host filter changes
  const loadFindings = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const q = {};
      if (filterHost && filterHost !== 'all') q.host = filterHost;
      const res = await window.API.findings(sessionId, q);
      const list = res.findings || [];
      seenIds.current = new Set(list.map(f => f.id || f._id));
      setFindings(list);
    } catch (e) {
      console.error('FindingsBoard load error:', e);
    }
    setLoading(false);
  }, [sessionId, filterHost]);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  // Subscribe to live WS findings via store's findingsSummary changes
  // When findingsSummary.total changes, reload from DB to get new findings
  const prevTotal = useRef(0);
  useEffect(() => {
    const total = findingsSummary.total || 0;
    if (total > prevTotal.current && sessionId) {
      prevTotal.current = total;
      // Debounced reload
      const t = setTimeout(loadFindings, 800);
      return () => clearTimeout(t);
    }
    prevTotal.current = total;
  }, [findingsSummary.total, loadFindings, sessionId]);

  // Filter logic
  const displayed = findings.filter(f => {
    if (filterSev !== 'all' && f.severity !== filterSev) return false;
    if (filterHost !== 'all' && f.host !== filterHost) return false;
    if (search) {
      const q = search.toLowerCase();
      return (f.title || '').toLowerCase().includes(q) ||
             (f.host  || '').toLowerCase().includes(q) ||
             (f.description || '').toLowerCase().includes(q) ||
             (f.service || '').toLowerCase().includes(q);
    }
    return true;
  });

  const card = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8 };
  const inp  = {
    background: 'var(--bg-panel)', border: '1px solid var(--border)',
    borderRadius: 'var(--radius)', color: 'var(--text-primary)', fontSize: 11,
    padding: '5px 10px', outline: 'none', fontFamily: 'var(--font-mono)'
  };

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', height: '100%', padding: 16, gap: 14, background: 'var(--bg-base)' }
  },

    // ── Header ──────────────────────────────────────────────
    React.createElement('div', { className: 'page-header', style: { flexShrink: 0 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '⚠ Findings Board'),
        React.createElement('div', { className: 'page-subtitle' },
          `${findings.length} findings` + (loading ? ' — refreshing...' : ' — updates live')
        )
      ),
      React.createElement('button', {
        onClick: loadFindings,
        style: {
          padding: '5px 14px', borderRadius: 5, border: '1px solid var(--border-light)',
          background: 'rgba(255,255,255,0.04)', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 11
        }
      }, '⟳ Refresh')
    ),

    // ── Severity Donut ───────────────────────────────────────
    React.createElement(SeverityDonut, { findings, findingsSummary: sevCounts }),

    // ── Summary counts ───────────────────────────────────────
    React.createElement('div', { style: { display: 'flex', gap: 8, flexShrink: 0 } },
      ['all', ...SEV_ORDER].map(s => {
        const count = s === 'all' ? findings.length : (sevCounts[s] || 0);
        return React.createElement('div', {
          key: s, onClick: () => setFilterSev(s),
          style: {
            padding: '6px 14px', borderRadius: 6, cursor: 'pointer',
            background: filterSev === s ? (SEV_BG[s] || 'rgba(0,212,255,0.08)') : 'var(--bg-surface)',
            border: `1px solid ${filterSev === s ? (SEV_COLOR[s] || 'var(--cyan)') : 'var(--border)'}`,
            color: filterSev === s ? (SEV_COLOR[s] || 'var(--cyan)') : 'var(--text-muted)',
            fontSize: 11, textAlign: 'center', transition: 'all 0.15s'
          }
        },
          React.createElement('div', { style: { fontWeight: 700, fontFamily: 'var(--font-mono)' } }, count),
          React.createElement('div', { style: { fontSize: 9, letterSpacing: 0.8, textTransform: 'uppercase' } }, s)
        );
      })
    ),

    // ── Search + Host filter row ─────────────────────────────
    React.createElement('div', { style: { display: 'flex', gap: 8, flexShrink: 0 } },
      React.createElement('input', {
        value: search, placeholder: 'Search by title, host, service...',
        onChange: e => setSearch(e.target.value),
        style: { ...inp, flex: 1 }
      }),
      isMultiHost && React.createElement('select', {
        value: filterHost,
        onChange: e => setFilterHost(e.target.value),
        style: { ...inp, flexShrink: 0, cursor: 'pointer' },
      },
        React.createElement('option', { value: 'all' }, 'All Hosts'),
        ...discoveredHosts.map(h =>
          React.createElement('option', { key: h.ip, value: h.ip }, `${h.ip} (${h.findings_count})`)
        )
      )
    ),

    // ── Findings list ────────────────────────────────────────
    React.createElement('div', { style: { ...card, flex: 1, overflowY: 'auto' } },
      loading && findings.length === 0
        ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } }, 'Loading...')
        : !sessionId
          ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } }, 'No active session')
          : displayed.length === 0
            ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } },
                findings.length > 0 ? 'No findings match filter' : 'No findings yet — findings appear here as agents discover vulnerabilities')
            : displayed.map((f, i) => {
                const isOpen = expanded === i;
                const sev = f.severity || 'info';
                return React.createElement('div', {
                  key: f.id || f._id || i,
                  style: {
                    borderBottom: '1px solid var(--border)',
                    background: isOpen ? (SEV_BG[sev] || 'transparent') : 'transparent'
                  }
                },
                  // Summary row
                  React.createElement('div', {
                    onClick: () => setExpanded(isOpen ? null : i),
                    style: {
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '11px 16px', cursor: 'pointer',
                      transition: 'background 0.1s',
                      ':hover': { background: 'rgba(0,229,160,0.03)' }
                    }
                  },
                    React.createElement('span', { style: { fontSize: 12, flexShrink: 0, color: 'var(--text-muted)' } },
                      isOpen ? '▼' : '▶'),
                    React.createElement(SevBadge, { sev }),
                    React.createElement('span', {
                      style: { flex: 1, fontSize: 12, color: 'var(--text-primary)',
                               overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
                    }, f.title || '(untitled)'),
                    // HOST badge (clickable in multi-host mode to filter)
                    isMultiHost && f.host && React.createElement('span', {
                      onClick: e => { e.stopPropagation(); setFilterHost(filterHost === f.host ? 'all' : f.host); },
                      title: `Filter to ${f.host}`,
                      style: {
                        padding: '1px 6px', borderRadius: 4, cursor: 'pointer', flexShrink: 0,
                        background: filterHost === f.host ? 'rgba(0,212,255,0.15)' : 'rgba(255,255,255,0.04)',
                        border: `1px solid ${filterHost === f.host ? 'var(--cyan)' : 'var(--border-light)'}`,
                        fontSize: 10, fontFamily: 'var(--font-mono)',
                        color: filterHost === f.host ? 'var(--cyan)' : 'var(--text-muted)',
                      }
                    }, f.host),
                    // Port:service (host shown inline only in single-host mode)
                    React.createElement('span', {
                      style: { fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)',
                               whiteSpace: 'nowrap', flexShrink: 0 }
                    }, [!isMultiHost && f.host, f.port && `:${f.port}`, f.service && `/${f.service}`].filter(Boolean).join('')),
                    // Tool badge
                    f.tool_used && React.createElement('span', {
                      style: {
                        padding: '1px 6px', borderRadius: 4,
                        background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-light)',
                        fontSize: 10, color: 'var(--text-muted)', flexShrink: 0
                      }
                    }, f.tool_used)
                  ),

                  // Expanded detail
                  isOpen && React.createElement('div', {
                    style: { padding: '10px 16px 16px 46px', fontSize: 11 }
                  },
                    f.description && React.createElement('div', {
                      style: { color: 'var(--text-muted)', marginBottom: 8, lineHeight: 1.7, fontSize: 12 }
                    }, f.description),
                    f.cves && f.cves.length > 0 && React.createElement('div', { style: { marginBottom: 6 } },
                      React.createElement('span', { style: { color: '#555', marginRight: 6 } }, 'CVEs:'),
                      f.cves.map(c => React.createElement('span', {
                        key: c, style: {
                          display: 'inline-block', margin: '0 4px 0 0', padding: '1px 6px',
                          borderRadius: 3, background: 'var(--critical-bg)',
                          border: '1px solid var(--critical-bd)', color: 'var(--critical)', fontSize: 10
                        }
                      }, c))
                    ),
                    f.evidence && React.createElement('div', { style: { marginBottom: 6 } },
                      React.createElement('div', { style: { color: '#555', fontSize: 10, marginBottom: 3 } }, 'EVIDENCE:'),
                      React.createElement('pre', {
                        style: {
                          background: 'var(--bg-panel)', border: '1px solid var(--border)',
                          borderRadius: 4, padding: 8, fontSize: 10,
                          color: 'var(--text-muted)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                          maxHeight: 120, overflow: 'auto', margin: 0
                        }
                      }, f.evidence)
                    ),
                    f.remediation && React.createElement('div', {
                      style: {
                        padding: '6px 10px', borderRadius: 4,
                        background: 'rgba(74,222,128,0.06)', border: '1px solid rgba(74,222,128,0.2)'
                      }
                    },
                      React.createElement('span', { style: { color: 'var(--low)', fontSize: 10, marginRight: 6 } }, '🛡 FIX:'),
                      React.createElement('span', { style: { color: 'var(--text-muted)', fontSize: 10 } }, f.remediation)
                    ),
                    // Exploit chain analysis button + result
                    React.createElement('div', {
                      style: { marginTop: 10, borderTop: '1px solid var(--border)', paddingTop: 8 }
                    },
                      !exploitAnalysis[i] && React.createElement('button', {
                        onClick: async (e) => {
                          e.stopPropagation();
                          setExploitAnalysis(prev => ({ ...prev, [i]: { loading: true, text: '', error: '' } }));
                          try {
                            const resp = await fetch('/api/analyze-finding', {
                              method: 'POST',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify({ finding: f, session_id: sessionId })
                            });
                            const data = await resp.json();
                            setExploitAnalysis(prev => ({ ...prev, [i]: { loading: false, text: data.analysis || 'No analysis returned', error: '' } }));
                          } catch(err) {
                            setExploitAnalysis(prev => ({ ...prev, [i]: { loading: false, text: '', error: 'Analysis request failed' } }));
                          }
                        },
                        style: {
                          padding: '5px 12px', borderRadius: 5, cursor: 'pointer', fontSize: 10,
                          background: 'rgba(123,108,246,0.1)', border: '1px solid rgba(123,108,246,0.4)',
                          color: 'var(--violet)', fontFamily: 'var(--font-mono)', fontWeight: 600
                        }
                      }, '🔬 Analyze Exploit Chain'),
                      exploitAnalysis[i]?.loading && React.createElement('div', {
                        style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', padding: '4px 0', animation: 'pulse 1.5s infinite' }
                      }, '⟳ Querying AI for exploit chain analysis...'),
                      exploitAnalysis[i]?.text && React.createElement('div', {
                        style: {
                          marginTop: 6, padding: '10px 12px', borderRadius: 6, fontSize: 11, lineHeight: 1.7,
                          background: 'rgba(123,108,246,0.06)', border: '1px solid rgba(123,108,246,0.2)',
                          color: 'var(--text-primary)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                          fontFamily: 'var(--font-ui)'
                        }
                      },
                        React.createElement('div', { style: { fontSize: 9, color: 'var(--violet)', fontFamily: 'var(--font-mono)', fontWeight: 700, marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.8 } }, '🔬 Exploit Chain Analysis'),
                        exploitAnalysis[i].text
                      ),
                      exploitAnalysis[i]?.error && React.createElement('div', {
                        style: { fontSize: 10, color: 'var(--critical)', padding: '4px 0', fontFamily: 'var(--font-mono)' }
                      }, `⚠ ${exploitAnalysis[i].error}`)
                    )
                  )
                );
              })
    )
  );
}

window.FindingsBoard = FindingsBoard;
