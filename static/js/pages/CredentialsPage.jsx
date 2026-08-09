// CredentialsPage.jsx — Credential & secret harvest viewer
'use strict';
const { useState, useEffect, useCallback } = React;
const { Table, Tag, Card, Input, Select, Button, Tooltip, Typography,
        Space, Statistic, Row, Col, Badge, Modal, message } = antd;
const { Text, Title } = Typography;

const SEVERITY_COLOR = { CRITICAL:'#ff4d4f', HIGH:'#ff7a45', MEDIUM:'#ffa940', LOW:'#52c41a', INFO:'#1890ff' };
const TYPE_COLOR = {
  hash:    'var(--violet)',   plaintext:'var(--critical)', ssh_key:'var(--cyan)',
  cookie:  'var(--cyan)',     token:'var(--medium)',       api_key:'var(--low)',
  unknown: 'var(--text-muted)',
};

function maskSecret(s, show) {
  if (!s) return '';
  if (show) return s;
  if (s.length <= 4) return '****';
  return s.slice(0, 2) + '****' + s.slice(-2);
}

function CopyBtn({ text }) {
  return React.createElement(Button, {
    size: 'small', type: 'text',
    style: { color: 'var(--cyan)', padding: '0 4px' },
    onClick: () => { navigator.clipboard.writeText(text); message.success('Copied'); },
  }, '📋');
}

// ── CredTypeDonut: SVG donut chart for credential types ──────────────────────
function CredTypeDonut({ creds }) {
  const TYPES = ['hash', 'plaintext', 'ssh_key', 'token', 'api_key', 'cookie', 'unknown'];
  const total = creds.length;

  if (total === 0) {
    return React.createElement('div', { 'data-slot': 'CredentialsPage.CredTypeDonut',
      style: { display: 'flex', alignItems: 'center', justifyContent: 'center',
               height: 100, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }
    }, '— no data —');
  }

  // Count each type
  const counts = {};
  TYPES.forEach(t => { counts[t] = 0; });
  creds.forEach(c => {
    const t = c.type && TYPES.includes(c.type) ? c.type : 'unknown';
    counts[t] = (counts[t] || 0) + 1;
  });

  const r = 30;
  const cx = 40;
  const cy = 40;
  const circumference = 2 * Math.PI * r; // ≈ 188.5

  // Build arc segments
  let offset = 0;
  const segments = TYPES
    .filter(t => counts[t] > 0)
    .map(t => {
      const pct = counts[t] / total;
      const dash = pct * circumference;
      const gap  = circumference - dash;
      const seg  = { type: t, count: counts[t], dash, gap, offset };
      offset += dash;
      return seg;
    });

  return React.createElement('div', {
    style: { display: 'flex', alignItems: 'center', gap: 16 }
  },
    // SVG donut
    React.createElement('svg', {
      viewBox: '0 0 80 80',
      width: 80, height: 80,
      style: { flexShrink: 0 },
    },
      // Background ring
      React.createElement('circle', {
        cx, cy, r,
        fill: 'none',
        stroke: 'var(--bg-elevated, rgba(255,255,255,0.06))',
        strokeWidth: 12,
      }),
      // Arc segments
      ...segments.map(seg =>
        React.createElement('circle', {
          key: seg.type,
          cx, cy, r,
          fill: 'none',
          stroke: TYPE_COLOR[seg.type] || 'var(--text-muted)',
          strokeWidth: 12,
          strokeDasharray: `${seg.dash} ${seg.gap}`,
          strokeDashoffset: -seg.offset,
          style: { transform: 'rotate(-90deg)', transformOrigin: '40px 40px', transition: 'stroke-dasharray 0.4s ease' },
        })
      ),
      // Center total
      React.createElement('text', {
        x: cx, y: cy + 1,
        textAnchor: 'middle', dominantBaseline: 'middle',
        style: { fontSize: 10, fill: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 700 },
      }, total),
      React.createElement('text', {
        x: cx, y: cy + 12,
        textAnchor: 'middle', dominantBaseline: 'middle',
        style: { fontSize: 7, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' },
      }, 'total'),
    ),

    // Legend
    React.createElement('div', {
      style: { display: 'flex', flexDirection: 'column', gap: 4 }
    },
      segments.map(seg =>
        React.createElement('div', {
          key: seg.type,
          style: { display: 'flex', alignItems: 'center', gap: 6 }
        },
          React.createElement('span', {
            style: {
              width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
              background: TYPE_COLOR[seg.type] || 'var(--text-muted)',
            }
          }),
          React.createElement('span', {
            style: { fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', minWidth: 60 }
          }, seg.type),
          React.createElement('span', {
            style: { fontSize: 10, fontFamily: 'var(--font-mono)', color: TYPE_COLOR[seg.type] || 'var(--text-muted)', fontWeight: 700 }
          }, seg.count),
        )
      )
    )
  );
}

// ── ServiceBar: horizontal bar chart for top services ───────────────────────
function ServiceBar({ creds }) {
  if (creds.length === 0) {
    return React.createElement('div', { 'data-slot': 'CredentialsPage.ServiceBar',
      style: { display: 'flex', alignItems: 'center', justifyContent: 'center',
               height: 100, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }
    }, '— no data —');
  }

  // Count per service
  const counts = {};
  creds.forEach(c => {
    const svc = c.service || 'unknown';
    counts[svc] = (counts[svc] || 0) + 1;
  });

  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  const max = sorted[0]?.[1] || 1;

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: 8, width: '100%' }
  },
    sorted.map(([svc, count]) =>
      React.createElement('div', {
        key: svc,
        style: { display: 'flex', alignItems: 'center', gap: 8 }
      },
        // Label
        React.createElement('span', {
          style: {
            width: 80, fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)',
            textAlign: 'right', flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }
        }, svc),
        // Track
        React.createElement('div', {
          style: {
            flex: 1, height: 16, borderRadius: 4,
            background: 'var(--bg-elevated, rgba(255,255,255,0.06))',
            position: 'relative', overflow: 'hidden',
          }
        },
          // Filled bar
          React.createElement('div', {
            style: {
              position: 'absolute', left: 0, top: 0, bottom: 0,
              width: `${(count / max) * 100}%`,
              borderRadius: 4,
              background: 'linear-gradient(90deg, var(--accent), var(--cyan))',
              transition: 'width 0.5s ease',
            }
          })
        ),
        // Count
        React.createElement('span', {
          style: {
            width: 28, fontSize: 10, fontFamily: 'var(--font-mono)',
            color: 'var(--cyan)', fontWeight: 700, textAlign: 'right', flexShrink: 0,
          }
        }, count),
      )
    )
  );
}

function CredentialsPage({ sessionId }) {
  const [creds,     setCreds]     = useState([]);
  const [loading,   setLoading]   = useState(false);
  const [filter,    setFilter]    = useState({ search: '', type: '', service: '' });
  const [showAll,   setShowAll]   = useState({});
  const [selected,  setSelected]  = useState(null);

  const load = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const data = await API.credentials(sessionId);
      setCreds(data.credentials || []);
    } catch (e) {
      // Fall back to store state
      const state = window.__store ? window.__store.getState() : null;
      if (state) setCreds(state.credentials || []);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => { load(); }, [load]);
  // Live updates from Redux store
  useEffect(() => {
    if (!window.__store) return;
    const unsub = window.__store.subscribe(() => {
      const s = window.__store.getState();
      setCreds(s.credentials || []);
    });
    return unsub;
  }, []);

  const filtered = creds.filter(c => {
    const blob = `${c.user} ${c.host} ${c.service} ${c.type} ${c.secret}`.toLowerCase();
    return (
      (!filter.search  || blob.includes(filter.search.toLowerCase())) &&
      (!filter.type    || c.type === filter.type) &&
      (!filter.service || c.service === filter.service)
    );
  });

  const types    = [...new Set(creds.map(c => c.type).filter(Boolean))];
  const services = [...new Set(creds.map(c => c.service).filter(Boolean))];

  // Stats
  const criticalCreds = creds.filter(c => c.type === 'plaintext' || c.type === 'api_key' || c.type === 'hash');
  const uniqueHosts   = new Set(creds.map(c => c.host)).size;
  const uniqueUsers   = new Set(creds.map(c => c.user)).size;

  const columns = [
    {
      title: 'User', dataIndex: 'user', key: 'user', width: 140,
      render: v => React.createElement(Text, { code: true, style: { color: '#e6d74a' } }, v || '—'),
    },
    {
      title: 'Host / Service', key: 'host', width: 160,
      render: (_, r) => React.createElement('div', null,
        React.createElement(Text, { style: { color: 'var(--cyan)' } }, r.host || '—'),
        React.createElement('br'),
        React.createElement(Tag, { color: 'blue', style: { fontSize: 10 } }, r.service || 'unknown'),
      ),
    },
    {
      title: 'Type', dataIndex: 'type', key: 'type', width: 100,
      render: v => React.createElement(Tag, { color: TYPE_COLOR[v] || TYPE_COLOR.unknown }, (v || 'unknown').toUpperCase()),
    },
    {
      title: 'Secret', key: 'secret', ellipsis: true,
      render: (_, r) => React.createElement(Space, null,
        React.createElement(Text, {
          code: true,
          style: { fontFamily: 'monospace', fontSize: 11, color: 'var(--medium)' },
        }, maskSecret(r.secret, showAll[r.id])),
        React.createElement(CopyBtn, { text: r.secret || '' }),
        React.createElement(Button, {
          size: 'small', type: 'text',
          style: { color: 'var(--text-secondary)', padding: '0 4px' },
          onClick: () => setShowAll(p => ({ ...p, [r.id]: !p[r.id] })),
        }, showAll[r.id] ? '🙈' : '👁'),
      ),
    },
    {
      title: 'Found By', dataIndex: 'found_by', key: 'found_by', width: 120,
      render: v => React.createElement(Tag, { color: 'purple', style: { fontSize: 10 } }, v || 'unknown'),
    },
    {
      title: 'Time', dataIndex: 'timestamp', key: 'timestamp', width: 90,
      render: v => v ? React.createElement(Text, { style: { fontSize: 11, color: 'var(--text-secondary)' } },
        new Date(v).toLocaleTimeString()) : '—',
    },
    {
      title: '', key: 'actions', width: 60,
      render: (_, r) => React.createElement(Button, {
        size: 'small', type: 'text',
        style: { color: 'var(--cyan)' },
        onClick: () => setSelected(r),
      }, '…'),
    },
  ];

  return React.createElement('div', { 'data-slot': 'CredentialsPage.CredentialsPage', style: { padding: 24 } },

    // Title
    React.createElement(Title, { level: 3, style: { color: 'var(--cyan)', marginBottom: 16 } },
      '🔑 Credentials Vault'),

    // Stats
    React.createElement(Row, { gutter: 16, style: { marginBottom: 20 } },
      React.createElement(Col, { span: 6 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: 'Total Credentials', value: creds.length,
            valueStyle: { color: 'var(--cyan)' } }))),
      React.createElement(Col, { span: 6 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: 'High-Value', value: criticalCreds.length,
            valueStyle: { color: 'var(--critical)' } }))),
      React.createElement(Col, { span: 6 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: 'Unique Hosts', value: uniqueHosts,
            valueStyle: { color: 'var(--medium)' } }))),
      React.createElement(Col, { span: 6 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: 'Unique Users', value: uniqueUsers,
            valueStyle: { color: 'var(--low)' } }))),
    ),

    // Credential Intelligence charts
    React.createElement(Card, {
      size: 'small',
      style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)', marginBottom: 16 },
      title: React.createElement('span', {
        style: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: 1 }
      }, 'Credential Intelligence'),
    },
      React.createElement('div', { style: { display: 'flex', gap: 16, flexWrap: 'wrap' } },
        // Type Breakdown Donut
        React.createElement('div', {
          style: {
            flex: '1 1 240px', background: 'var(--bg-surface)', borderRadius: 8,
            padding: 12, border: '1px solid var(--border)',
          }
        },
          React.createElement('div', {
            style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                     textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 10 }
          }, 'Type Breakdown'),
          React.createElement(CredTypeDonut, { creds }),
        ),
        // Service Distribution Bar
        React.createElement('div', {
          style: {
            flex: '2 1 320px', background: 'var(--bg-surface)', borderRadius: 8,
            padding: 12, border: '1px solid var(--border)',
          }
        },
          React.createElement('div', {
            style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                     textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 10 }
          }, 'Top Services'),
          React.createElement(ServiceBar, { creds }),
        ),
      )
    ),

    // Filters
    React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)', marginBottom: 16 } },
      React.createElement(Space, { wrap: true },
        React.createElement(Input.Search, {
          placeholder: 'Search user, host, secret…',
          style: { width: 260 },
          allowClear: true,
          onSearch: v => setFilter(p => ({ ...p, search: v })),
          onChange: e => !e.target.value && setFilter(p => ({ ...p, search: '' })),
        }),
        React.createElement(Select, {
          placeholder: 'Type', allowClear: true, style: { width: 130 },
          onChange: v => setFilter(p => ({ ...p, type: v || '' })),
          options: types.map(t => ({ value: t, label: t.toUpperCase() })),
        }),
        React.createElement(Select, {
          placeholder: 'Service', allowClear: true, style: { width: 130 },
          onChange: v => setFilter(p => ({ ...p, service: v || '' })),
          options: services.map(s => ({ value: s, label: s })),
        }),
        React.createElement(Button, {
          type: 'primary', onClick: load, loading,
          style: { background: 'var(--accent)', border: '1px solid var(--accent)', color: '#0D0E14', boxShadow: '0 0 10px var(--accent-glow)' },
        }, 'Refresh'),
        React.createElement(Button, {
          onClick: () => {
            const csv = ['user,host,service,type,secret,found_by',
              ...filtered.map(c => `${c.user},${c.host},${c.service},${c.type},"${c.secret}",${c.found_by}`)
            ].join('\n');
            const a = document.createElement('a');
            a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
            a.download = 'credentials.csv';
            a.click();
          },
          style: { background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-light)', color: 'var(--text-secondary)' },
        }, '⬇ Export CSV'),
      ),
    ),

    // Table
    React.createElement(Table, {
      dataSource: filtered,
      columns,
      rowKey: r => r.id || `${r.user}-${r.host}-${r.timestamp}`,
      loading,
      size: 'small',
      pagination: { pageSize: 25, showSizeChanger: true },
      style: { background: 'var(--bg-surface)' },
      rowClassName: r => r.type === 'hash' ? 'cred-row-hash' : r.type === 'plaintext' ? 'cred-row-plain' : '',
    }),

    // Detail Modal
    selected && React.createElement(Modal, {
      open: !!selected,
      title: React.createElement(Text, { style: { color: 'var(--cyan)' } }, `Credential: ${selected.user}@${selected.host}`),
      onCancel: () => setSelected(null),
      footer: null,
      style: { top: 80 },
    },
      React.createElement('div', { style: { fontFamily: 'monospace', fontSize: 12 } },
        ['user','host','service','type','secret','found_by','timestamp'].map(k =>
          React.createElement(Row, { key: k, style: { marginBottom: 6 } },
            React.createElement(Col, { span: 8 },
              React.createElement(Text, { style: { color: 'var(--text-secondary)' } }, k.toUpperCase() + ':')),
            React.createElement(Col, { span: 16 },
              React.createElement(Space, null,
                React.createElement(Text, { code: true, style: { wordBreak: 'break-all' } },
                  k === 'secret' ? (selected[k] || '') : (selected[k] || '—')),
                k === 'secret' && React.createElement(CopyBtn, { text: selected[k] || '' }),
              )),
          )
        ),
        React.createElement('div', { style: { marginTop: 16 } },
          React.createElement(Button, {
            block: true, type: 'primary', danger: true,
            onClick: () => {
              const crack = selected.type === 'hash'
                ? `hashcat -m 1000 '${selected.secret}' /usr/share/wordlists/rockyou.txt`
                : `echo '${selected.user}:${selected.secret}' # plaintext`;
              navigator.clipboard.writeText(crack);
              message.success('Crack command copied');
            },
          }, selected.type === 'hash' ? '📋 Copy hashcat command' : '📋 Copy credential'),
        ),
      ),
    ),
  );
}

window.CredentialsPage = CredentialsPage;
