// ═══════════════════════════════════════════════════════════
// OsintIntel.jsx — OSINT results browser
// Loads from /sessions/{id}/osint and refreshes live via
// store findingsSummary changes (OSINT findings stored there)
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useCallback } = React;

const SOURCE_COLORS = {
  nvd:        { bg: 'rgba(255,68,102,0.1)',  border: 'var(--critical)', text: 'var(--critical)' },
  exploit_db: { bg: 'rgba(255,140,0,0.1)',   border: '#ff8c00', text: '#ff8c00' },
  shodan:     { bg: 'rgba(0,180,255,0.1)',   border: '#00b4ff', text: '#00b4ff' },
  web:        { bg: 'rgba(0,212,255,0.08)',  border: 'var(--cyan)', text: 'var(--cyan)' },
  default:    { bg: 'rgba(255,255,255,0.04)', border: 'var(--border-light)',   text: 'var(--text-secondary)' },
};

function SourceBadge({ source }) {
  const c = SOURCE_COLORS[source] || SOURCE_COLORS.default;
  return React.createElement('span', {
    style: {
      padding: '1px 7px', borderRadius: 4, fontSize: 10,
      background: c.bg, border: `1px solid ${c.border}`, color: c.text,
      fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap'
    }
  }, (source || 'unknown').toUpperCase());
}

function OsintIntel() {
  const { state } = window.useStore();
  const { sessionId, findingsSummary } = state;

  const [results,  setResults]  = useState([]);
  const [loading,  setLoading]  = useState(false);
  const [filter,   setFilter]   = useState('all');
  const [search,   setSearch]   = useState('');
  const [expanded, setExpanded] = useState(null);

  const load = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const res = await window.API.osint(sessionId);
      setResults(res.results || []);
    } catch (e) {
      console.error('OSINT load error:', e);
    }
    setLoading(false);
  }, [sessionId]);

  useEffect(() => { load(); }, [load]);

  // Re-load when findings change (OSINT phase adds results)
  const prevTotal = React.useRef(0);
  useEffect(() => {
    const t = findingsSummary.total || 0;
    if (t > prevTotal.current) {
      prevTotal.current = t;
      const timer = setTimeout(load, 1500);
      return () => clearTimeout(timer);
    }
    prevTotal.current = t;
  }, [findingsSummary.total, load]);

  const sources = ['all', ...Array.from(new Set(results.map(r => r.source).filter(Boolean)))];

  const displayed = results.filter(r => {
    if (filter !== 'all' && r.source !== filter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (r.title || '').toLowerCase().includes(q) ||
             (r.summary || '').toLowerCase().includes(q) ||
             (r.cves || []).some(c => c.toLowerCase().includes(q));
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
    style: { display: 'flex', flexDirection: 'column', height: '100%', padding: 16, gap: 14, background: 'var(--bg-surface)' }
  },
    // Header
    React.createElement('div', { className: 'page-header', style: { flexShrink: 0 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '🌐 OSINT Intel'),
        React.createElement('div', { className: 'page-subtitle' },
          `${results.length} intelligence entries` + (loading ? ' — loading...' : '')
        )
      ),
      React.createElement('button', {
        onClick: load,
        style: {
          padding: '5px 14px', borderRadius: 5, border: '1px solid var(--border-light)',
          background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 11
        }
      }, '⟳ Refresh')
    ),

    // Source filter tabs
    React.createElement('div', { style: { display: 'flex', gap: 6, flexShrink: 0, flexWrap: 'wrap' } },
      sources.map(s => {
        const c = SOURCE_COLORS[s] || SOURCE_COLORS.default;
        const cnt = s === 'all' ? results.length : results.filter(r => r.source === s).length;
        return React.createElement('button', {
          key: s, onClick: () => setFilter(s),
          style: {
            padding: '4px 12px', borderRadius: 5, border: `1px solid ${filter === s ? c.border : 'var(--border)'}`,
            background: filter === s ? c.bg : 'transparent',
            color: filter === s ? c.text : 'var(--text-muted)',
            cursor: 'pointer', fontSize: 11, fontFamily: 'var(--font-mono)'
          }
        }, `${s.toUpperCase()} (${cnt})`)
      })
    ),

    // Search
    React.createElement('input', {
      value: search, placeholder: 'Search title, summary, CVE...',
      onChange: e => setSearch(e.target.value),
      style: { ...inp, flexShrink: 0 }
    }),

    // Results list
    React.createElement('div', { style: { ...card, flex: 1, overflowY: 'auto' } },
      !sessionId
        ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } }, 'No active session')
        : loading && results.length === 0
          ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } }, 'Loading...')
          : displayed.length === 0
            ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } },
                results.length > 0 ? 'No results match filter' :
                'No OSINT results yet — runs automatically during the OSINT phase')
            : displayed.map((r, i) => {
                const isOpen = expanded === i;
                return React.createElement('div', {
                  key: r.id || r._id || i,
                  style: { borderBottom: '1px solid var(--border)' }
                },
                  // Row
                  React.createElement('div', {
                    onClick: () => setExpanded(isOpen ? null : i),
                    style: {
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '9px 14px', cursor: 'pointer'
                    }
                  },
                    React.createElement('span', { style: { fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 } },
                      isOpen ? '▼' : '▶'),
                    React.createElement(SourceBadge, { source: r.source }),
                    React.createElement('span', {
                      style: { flex: 1, fontSize: 12, color: 'var(--text-primary)',
                               overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
                    }, r.title || r.query || '(untitled)'),
                    // CVE count
                    r.cves && r.cves.length > 0 && React.createElement('span', {
                      style: {
                        padding: '1px 7px', borderRadius: 4, fontSize: 10,
                        background: 'rgba(255,68,102,0.1)', border: '1px solid rgba(255,68,102,0.3)',
                        color: 'var(--red)', flexShrink: 0
                      }
                    }, `${r.cves.length} CVE${r.cves.length !== 1 ? 's' : ''}`),
                    // Relevance score
                    r.relevance_score != null && React.createElement('span', {
                      style: {
                        fontSize: 10, color: r.relevance_score > 7 ? 'var(--red)' :
                                            r.relevance_score > 4 ? 'var(--amber)' : 'var(--text-muted)',
                        fontFamily: 'var(--font-mono)', flexShrink: 0
                      }
                    }, `rel: ${r.relevance_score}/10`)
                  ),

                  // Expanded detail
                  isOpen && React.createElement('div', {
                    style: { padding: '0 14px 12px 44px' }
                  },
                    r.summary && React.createElement('div', {
                      style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, lineHeight: 1.6 }
                    }, r.summary),
                    r.url && React.createElement('a', {
                      href: r.url, target: '_blank', rel: 'noreferrer',
                      style: { fontSize: 10, color: 'var(--cyan)', display: 'block', marginBottom: 8,
                               overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
                    }, r.url),
                    r.cves && r.cves.length > 0 && React.createElement('div', { style: { marginBottom: 6 } },
                      React.createElement('span', { style: { color: 'var(--text-muted)', fontSize: 10, marginRight: 6 } }, 'CVEs:'),
                      r.cves.map(c => React.createElement('span', {
                        key: c, style: {
                          display: 'inline-block', margin: '0 4px 0 0', padding: '1px 6px',
                          borderRadius: 3, background: 'rgba(255,68,102,0.1)',
                          border: '1px solid rgba(255,68,102,0.3)', color: 'var(--red)', fontSize: 10
                        }
                      }, c))
                    ),
                    r.exploits && r.exploits.length > 0 && React.createElement('div', null,
                      React.createElement('span', { style: { color: 'var(--text-muted)', fontSize: 10, marginRight: 6 } }, 'Exploits:'),
                      r.exploits.slice(0, 5).map((e, j) => React.createElement('div', {
                        key: j,
                        style: { fontSize: 10, color: 'var(--amber)', fontFamily: 'var(--font-mono)', paddingLeft: 8 }
                      }, `• ${e}`))
                    )
                  )
                );
              })
    )
  );
}

window.OsintIntel = OsintIntel;
