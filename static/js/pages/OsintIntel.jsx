// ═══════════════════════════════════════════════════════════
// OsintIntel.jsx — OSINT Intel Dashboard
// Displays results from all 13 OSINT sources in real time.
// Sources auto-appear as filter tabs when results arrive.
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useCallback, useRef } = React;

// ── Source metadata: color + icon per source ──────────────────────────────
const SOURCE_META = {
  nvd:              { bg: 'rgba(255,68,102,0.12)',  border: 'var(--critical)',  text: 'var(--critical)',  icon: '🛡', label: 'NVD' },
  exploit_db:       { bg: 'rgba(255,140,0,0.12)',   border: '#ff8c00',          text: '#ff8c00',          icon: '💥', label: 'ExploitDB' },
  shodan:           { bg: 'rgba(0,180,255,0.12)',   border: '#00b4ff',          text: '#00b4ff',          icon: '🔍', label: 'Shodan' },
  theharvester:     { bg: 'rgba(0,230,120,0.10)',   border: '#00e678',          text: '#00e678',          icon: '🌾', label: 'theHarvester' },
  recon_ng:         { bg: 'rgba(180,80,255,0.12)',  border: '#b450ff',          text: '#b450ff',          icon: '🔭', label: 'Recon-ng' },
  wayback:          { bg: 'rgba(255,200,0,0.10)',   border: '#ffc800',          text: '#ffc800',          icon: '📦', label: 'Wayback' },
  ahmia:            { bg: 'rgba(120,120,120,0.14)', border: '#888',             text: '#aaa',             icon: '🌑', label: 'Ahmia' },
  security_trails:  { bg: 'rgba(0,200,200,0.10)',   border: '#00c8c8',          text: '#00c8c8',          icon: '🗺', label: 'SecurityTrails' },
  bgpview:          { bg: 'rgba(80,160,255,0.10)',  border: '#50a0ff',          text: '#50a0ff',          icon: '🌐', label: 'BGPView' },
  hibp:             { bg: 'rgba(255,80,80,0.12)',   border: '#ff5050',          text: '#ff5050',          icon: '🔓', label: 'HIBP' },
  google_dorks:     { bg: 'rgba(66,133,244,0.12)',  border: '#4285f4',          text: '#4285f4',          icon: '🔎', label: 'Google Dorks' },
  builtwith:        { bg: 'rgba(255,160,0,0.10)',   border: '#ffa000',          text: '#ffa000',          icon: '🏗', label: 'BuiltWith' },
  tineye:           { bg: 'rgba(100,220,100,0.10)', border: '#64dc64',          text: '#64dc64',          icon: '👁', label: 'TinEye' },
  spiderfoot:       { bg: 'rgba(255,100,180,0.10)', border: '#ff64b4',          text: '#ff64b4',          icon: '🕷', label: 'SpiderFoot' },
  web:              { bg: 'rgba(0,212,255,0.08)',   border: 'var(--cyan)',      text: 'var(--cyan)',      icon: '🌍', label: 'Web' },
  default:          { bg: 'rgba(255,255,255,0.04)', border: 'var(--border-light)', text: 'var(--text-secondary)', icon: '📄', label: null },
};

// ── Data-type → display label mapping ────────────────────────────────────────
const DATA_TYPE_LABELS = {
  cve:                   { icon: '🛡', color: 'var(--critical)', label: 'CVE' },
  exploit:               { icon: '💥', color: '#ff8c00',         label: 'Exploit' },
  email:                 { icon: '✉',  color: '#00e678',         label: 'Email' },
  email_breach:          { icon: '🔓', color: '#ff5050',         label: 'Breach' },
  corporate_breach:      { icon: '🏢', color: '#ff5050',         label: 'Corp Breach' },
  subdomain:             { icon: '🔗', color: 'var(--cyan)',     label: 'Subdomain' },
  subdomains:            { icon: '🔗', color: 'var(--cyan)',     label: 'Subdomains' },
  dns_records:           { icon: '📡', color: '#50a0ff',         label: 'DNS' },
  dns_history:           { icon: '📜', color: '#50a0ff',         label: 'DNS History' },
  associated_domains:    { icon: '🔁', color: '#50a0ff',         label: 'Associated' },
  archived_urls:         { icon: '📦', color: '#ffc800',         label: 'Archive' },
  interesting_archived_url: { icon: '⚠', color: 'var(--amber)', label: 'Old Page' },
  dark_web_mentions:     { icon: '🌑', color: '#888',            label: 'Dark Web' },
  harvester_results:     { icon: '🌾', color: '#00e678',         label: 'Harvest' },
  recon_ng_results:      { icon: '🔭', color: '#b450ff',         label: 'Recon-ng' },
  shodan_host:           { icon: '🔍', color: '#00b4ff',         label: 'Host' },
  shodan_cve:            { icon: '💀', color: 'var(--critical)', label: 'Shodan CVE' },
  shodan_dns:            { icon: '📡', color: '#00b4ff',         label: 'DNS' },
  ssl_cert:              { icon: '🔒', color: '#ffc800',         label: 'SSL Cert' },
  tech_profile:          { icon: '🏗', color: '#ffa000',         label: 'Tech Stack' },
  risky_tech:            { icon: '⚠', color: 'var(--amber)',    label: 'Risky Tech' },
  image_usage:           { icon: '🖼', color: '#64dc64',         label: 'Image' },
  google_dork:           { icon: '🔎', color: '#4285f4',         label: 'Dork' },
  bgp_routing:           { icon: '🌐', color: '#50a0ff',         label: 'BGP/ASN' },
  asn_lookup:            { icon: '🌐', color: '#50a0ff',         label: 'ASN' },
  asn_prefixes:          { icon: '📊', color: '#50a0ff',         label: 'Prefixes' },
  ip_neighbors:          { icon: '🏘', color: '#50a0ff',         label: 'Neighbours' },
  spiderfoot:            { icon: '🕷', color: '#ff64b4',         label: 'SpiderFoot' },
};

// ── Severity colour ────────────────────────────────────────────────────────
function severityColor(sev) {
  if (!sev) return 'var(--text-muted)';
  const s = sev.toLowerCase();
  if (s.includes('critical')) return 'var(--critical)';
  if (s.includes('high'))     return 'var(--red)';
  if (s.includes('medium'))   return 'var(--amber)';
  if (s.includes('low'))      return '#90ee90';
  return 'var(--text-muted)';
}

// ── Source badge component ─────────────────────────────────────────────────
function SourceBadge({ source }) {
  const m = SOURCE_META[source] || SOURCE_META.default;
  return React.createElement('span', {
    style: {
      padding: '1px 7px', borderRadius: 4, fontSize: 10, whiteSpace: 'nowrap',
      background: m.bg, border: `1px solid ${m.border}`, color: m.text,
      fontFamily: 'var(--font-mono)',
    }
  }, `${m.icon || ''} ${(m.label || source || 'UNKNOWN').toUpperCase()}`.trim());
}

// ── Data-type pill ─────────────────────────────────────────────────────────
function DataTypePill({ dataType }) {
  if (!dataType) return null;
  const m = DATA_TYPE_LABELS[dataType];
  if (!m) return null;
  return React.createElement('span', {
    style: {
      padding: '1px 6px', borderRadius: 3, fontSize: 9, whiteSpace: 'nowrap',
      background: 'rgba(255,255,255,0.04)', border: `1px solid ${m.color}30`,
      color: m.color, fontFamily: 'var(--font-mono)', marginLeft: 4,
    }
  }, `${m.icon} ${m.label}`);
}

// ── Expanded detail: render data_type-specific sections ───────────────────
function DetailSection({ result }) {
  const raw = result.raw || {};
  const dt  = raw.data_type || '';
  const s   = { fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7, marginBottom: 6 };
  const tag = { display: 'inline-block', margin: '2px 3px', padding: '1px 6px', borderRadius: 3,
                fontSize: 10, fontFamily: 'var(--font-mono)' };

  // ── Email / breach tags ──
  if (dt === 'email_breach' && raw.breaches) {
    return React.createElement('div', null,
      result.summary && React.createElement('p', { style: s }, result.summary),
      React.createElement('div', { style: { marginTop: 4 } },
        raw.breaches.slice(0, 6).map((b, i) =>
          React.createElement('span', {
            key: i,
            style: { ...tag, background: 'rgba(255,80,80,0.1)', border: '1px solid #ff505040', color: '#ff5050' }
          }, `${b.name || b} (${b.date || '?'})`)
        )
      )
    );
  }

  // ── Subdomain list ──
  if ((dt === 'subdomains' || dt === 'harvester_results' || dt === 'recon_ng_results') && raw.subdomains) {
    return React.createElement('div', null,
      result.summary && React.createElement('p', { style: s }, result.summary),
      raw.subdomains.length > 0 && React.createElement('div', { style: { marginTop: 4 } },
        React.createElement('span', { style: { ...s, display: 'block', marginBottom: 4 } }, 'Subdomains:'),
        raw.subdomains.slice(0, 20).map((h, i) =>
          React.createElement('span', {
            key: i, style: { ...tag, background: 'rgba(0,212,255,0.07)', border: '1px solid #00d4ff30', color: 'var(--cyan)' }
          }, h)
        )
      )
    );
  }

  // ── Tech stack ──
  if (dt === 'tech_profile' && raw.categories) {
    const entries = Object.entries(raw.categories || {}).slice(0, 12);
    return React.createElement('div', null,
      entries.map(([cat, techs]) =>
        React.createElement('div', { key: cat, style: { marginBottom: 4 } },
          React.createElement('span', { style: { ...s, color: 'var(--text-secondary)', marginRight: 6 } }, `${cat}:`),
          techs.slice(0, 6).map((t, i) =>
            React.createElement('span', {
              key: i, style: { ...tag, background: 'rgba(255,160,0,0.08)', border: '1px solid #ffa00030', color: '#ffa000' }
            }, t)
          )
        )
      )
    );
  }

  // ── Google dork results ──
  if (dt === 'google_dork' && raw.items) {
    return React.createElement('div', null,
      React.createElement('div', { style: { ...s, fontFamily: 'var(--font-mono)', marginBottom: 6 } }, `Query: ${raw.dork || ''}`),
      raw.items.slice(0, 5).map((item, i) =>
        React.createElement('div', { key: i, style: { marginBottom: 6 } },
          React.createElement('div', { style: { fontSize: 11, color: 'var(--text-primary)' } }, item.title || ''),
          React.createElement('a', {
            href: item.url, target: '_blank', rel: 'noreferrer',
            style: { fontSize: 10, color: 'var(--cyan)', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
          }, item.url || ''),
          item.snippet && React.createElement('div', { style: { ...s, fontSize: 10 } }, item.snippet)
        )
      )
    );
  }

  // ── BGP / ASN ──
  if ((dt === 'bgp_routing' || dt === 'asn_lookup') && raw.asns) {
    return React.createElement('div', null,
      result.summary && React.createElement('pre', { style: { ...s, fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', fontSize: 10 } }, result.summary)
    );
  }

  // ── SpiderFoot event values ──
  if (dt === 'spiderfoot' && raw.values) {
    return React.createElement('div', null,
      React.createElement('div', { style: { ...s, marginBottom: 4 } }, `Event type: ${raw.event_type || ''}`),
      raw.values.slice(0, 15).map((v, i) =>
        React.createElement('div', { key: i, style: { ...s, fontFamily: 'var(--font-mono)', fontSize: 10, paddingLeft: 8 } }, `• ${v}`)
      )
    );
  }

  // ── Default: summary + URL ──
  return React.createElement('div', null,
    result.summary && React.createElement('div', { style: s }, result.summary),
    result.url && React.createElement('a', {
      href: result.url, target: '_blank', rel: 'noreferrer',
      style: { fontSize: 10, color: 'var(--cyan)', display: 'block', marginTop: 4,
               overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
    }, result.url)
  );
}

// ── Stats bar ─────────────────────────────────────────────────────────────
function StatsBar({ results }) {
  const byCve    = results.filter(r => (r.cves || []).length > 0).length;
  const byExpl   = results.filter(r => (r.exploits || []).length > 0).length;
  const byHigh   = results.filter(r => {
    const s = (r.severity || '').toLowerCase();
    return s.includes('critical') || s.includes('high');
  }).length;
  const byEmail  = results.filter(r => (r.raw || {}).data_type === 'email').length;

  const pill = (label, val, color) => val > 0 && React.createElement('span', {
    style: {
      padding: '2px 10px', borderRadius: 4, fontSize: 10, marginRight: 6,
      background: `${color}18`, border: `1px solid ${color}40`, color,
      fontFamily: 'var(--font-mono)',
    }
  }, `${val} ${label}`);

  return React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 4, flexShrink: 0 } },
    pill('CVE records',  byCve,   'var(--critical)'),
    pill('exploits',     byExpl,  '#ff8c00'),
    pill('high/critical',byHigh,  '#ff5050'),
    pill('emails',       byEmail, '#00e678'),
  );
}

// ── Main component ─────────────────────────────────────────────────────────
function OsintIntel() {
  const { state, dispatch } = window.useStore();
  const { sessionId, feedEntries } = state;

  const [results,  setResults]  = useState([]);
  const [loading,  setLoading]  = useState(false);
  const [filter,   setFilter]   = useState('all');
  const [search,   setSearch]   = useState('');
  const [expanded, setExpanded] = useState(null);
  const prevCount = useRef(0);

  // ── Load from API ──────────────────────────────────────────────
  const load = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const res = await window.API.osint(sessionId);
      setResults(res.results || []);
    } catch (e) {
      console.error('OSINT load error:', e);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => { load(); }, [load]);

  // ── Live reload on new OSINT results via WS feed ───────────────
  useEffect(() => {
    const osintEvents = feedEntries.filter(e =>
      e.eventType === 'osint_result' || e.eventType === 'osint_complete'
    ).length;
    if (osintEvents > prevCount.current) {
      prevCount.current = osintEvents;
      const t = setTimeout(load, 1200);
      return () => clearTimeout(t);
    }
    prevCount.current = osintEvents;
  }, [feedEntries, load]);

  // ── Build filter tabs from live results ───────────────────────
  const activeSources = ['all', ...Array.from(
    new Set(results.map(r => r.source).filter(Boolean))
  ).sort()];

  // ── Apply filter + search ──────────────────────────────────────
  const displayed = results.filter(r => {
    if (filter !== 'all' && r.source !== filter) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    const raw = r.raw || {};
    return (r.title   || '').toLowerCase().includes(q)
        || (r.summary || '').toLowerCase().includes(q)
        || (r.source  || '').toLowerCase().includes(q)
        || (r.cves    || []).some(c => c.toLowerCase().includes(q))
        || (raw.emails     || []).some(e => String(e).toLowerCase().includes(q))
        || (raw.subdomains || []).some(s => String(s).toLowerCase().includes(q))
        || (raw.event_type || '').toLowerCase().includes(q);
  });

  // ── Styles ────────────────────────────────────────────────────
  const inp = {
    background: 'var(--bg-panel)', border: '1px solid var(--border)',
    borderRadius: 'var(--radius)', color: 'var(--text-primary)', fontSize: 11,
    padding: '5px 10px', outline: 'none', fontFamily: 'var(--font-mono)', width: '100%',
  };
  const card = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8 };

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', height: '100%', padding: 16, gap: 12, background: 'var(--bg-surface)' }
  },
    // ── Header ──────────────────────────────────────────────────
    React.createElement('div', { className: 'page-header', style: { flexShrink: 0 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '🌐 OSINT Intel'),
        React.createElement('div', { className: 'page-subtitle' },
          `${results.length} intelligence entries across ${activeSources.length - 1} source(s)`
          + (loading ? ' — refreshing...' : '')
        )
      ),
      React.createElement('button', {
        onClick: load,
        style: {
          padding: '5px 14px', borderRadius: 5, cursor: 'pointer', fontSize: 11,
          border: '1px solid var(--border-light)', background: 'rgba(255,255,255,0.04)',
          color: 'var(--text-secondary)',
        }
      }, '⟳ Refresh')
    ),

    // ── Stats bar ────────────────────────────────────────────────
    results.length > 0 && React.createElement(StatsBar, { results }),

    // ── Source filter tabs ───────────────────────────────────────
    React.createElement('div', { style: { display: 'flex', gap: 5, flexShrink: 0, flexWrap: 'wrap' } },
      activeSources.map(s => {
        const m   = SOURCE_META[s] || SOURCE_META.default;
        const cnt = s === 'all' ? results.length : results.filter(r => r.source === s).length;
        const sel = filter === s;
        return React.createElement('button', {
          key: s, onClick: () => { setFilter(s); setExpanded(null); },
          style: {
            padding: '3px 11px', borderRadius: 5, cursor: 'pointer', fontSize: 10,
            border:      `1px solid ${sel ? m.border : 'var(--border)'}`,
            background:  sel ? m.bg : 'transparent',
            color:       sel ? m.text : 'var(--text-muted)',
            fontFamily:  'var(--font-mono)',
          }
        }, `${s === 'all' ? '📋 ALL' : (m.icon ? m.icon + ' ' : '') + s.toUpperCase()} (${cnt})`)
      })
    ),

    // ── Search ────────────────────────────────────────────────────
    React.createElement('input', {
      value: search, placeholder: 'Search title, summary, CVE, email, subdomain...',
      onChange: e => setSearch(e.target.value), style: { ...inp, flexShrink: 0 }
    }),

    // ── Results list ──────────────────────────────────────────────
    React.createElement('div', { style: { ...card, flex: 1, overflowY: 'auto' } },
      !sessionId
        ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } },
            'No active session')
        : loading && results.length === 0
          ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } },
              'Loading OSINT results...')
          : displayed.length === 0
            ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } },
                results.length > 0
                  ? 'No results match filter'
                  : 'No OSINT results yet — runs automatically during the OSINT phase')
            : displayed.map((r, i) => {
                const isOpen  = expanded === i;
                const src     = SOURCE_META[r.source] || SOURCE_META.default;
                const raw     = r.raw || {};
                const dt      = raw.data_type || '';
                const dtMeta  = DATA_TYPE_LABELS[dt];
                const sevColor = severityColor(r.severity);

                return React.createElement('div', {
                  key: r.id || r._id || i,
                  style: { borderBottom: '1px solid var(--border)' }
                },
                  // ── Row ──────────────────────────────────────
                  React.createElement('div', {
                    onClick: () => setExpanded(isOpen ? null : i),
                    style: {
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '8px 14px', cursor: 'pointer',
                      background: isOpen ? 'rgba(255,255,255,0.02)' : 'transparent',
                    }
                  },
                    // Chevron
                    React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 } },
                      isOpen ? '▼' : '▶'),
                    // Source badge
                    React.createElement(SourceBadge, { source: r.source }),
                    // Data type pill
                    dtMeta && React.createElement(DataTypePill, { dataType: dt }),
                    // Title
                    React.createElement('span', {
                      style: {
                        flex: 1, fontSize: 12, color: 'var(--text-primary)',
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        marginLeft: 4,
                      }
                    }, r.title || r.query || '(untitled)'),
                    // CVE count pill
                    r.cves && r.cves.length > 0 && React.createElement('span', {
                      style: {
                        padding: '1px 7px', borderRadius: 4, fontSize: 10, flexShrink: 0,
                        background: 'rgba(255,68,102,0.1)', border: '1px solid rgba(255,68,102,0.3)',
                        color: 'var(--red)',
                      }
                    }, `${r.cves.length} CVE${r.cves.length !== 1 ? 's' : ''}`),
                    // Severity dot
                    r.severity && r.severity !== 'info' && React.createElement('span', {
                      style: {
                        width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
                        background: sevColor, boxShadow: `0 0 4px ${sevColor}80`,
                      }
                    }),
                    // Relevance score
                    r.relevance_score != null && React.createElement('span', {
                      style: {
                        fontSize: 9, color: r.relevance_score > 0.7 ? sevColor : 'var(--text-muted)',
                        fontFamily: 'var(--font-mono)', flexShrink: 0,
                      }
                    }, `${Math.round(r.relevance_score * 10)}/10`)
                  ),

                  // ── Expanded detail ──────────────────────────
                  isOpen && React.createElement('div', {
                    style: { padding: '4px 14px 14px 44px', borderTop: '1px solid rgba(255,255,255,0.04)' }
                  },
                    // CVE tags
                    r.cves && r.cves.length > 0 && React.createElement('div', { style: { marginBottom: 8 } },
                      React.createElement('span', { style: { color: 'var(--text-muted)', fontSize: 10, marginRight: 6 } }, 'CVEs:'),
                      r.cves.map(c => React.createElement('span', {
                        key: c,
                        style: {
                          display: 'inline-block', margin: '0 4px 2px 0', padding: '1px 6px',
                          borderRadius: 3, fontSize: 10,
                          background: 'rgba(255,68,102,0.1)', border: '1px solid rgba(255,68,102,0.3)',
                          color: 'var(--red)',
                        }
                      }, c))
                    ),
                    // Exploit IDs
                    r.exploits && r.exploits.length > 0 && React.createElement('div', { style: { marginBottom: 8 } },
                      React.createElement('span', { style: { color: 'var(--text-muted)', fontSize: 10, marginRight: 6 } }, 'Exploits:'),
                      r.exploits.slice(0, 6).map((e, j) =>
                        React.createElement('span', {
                          key: j,
                          style: {
                            display: 'inline-block', margin: '0 4px 2px 0', padding: '1px 6px',
                            borderRadius: 3, fontSize: 10,
                            background: 'rgba(255,140,0,0.1)', border: '1px solid rgba(255,140,0,0.3)',
                            color: '#ff8c00',
                          }
                        }, `EDB-${e}`)
                      )
                    ),
                    // Data-type specific rendering
                    React.createElement(DetailSection, { result: r }),
                    // Timestamp
                    r.fetched_at && React.createElement('div', {
                      style: { fontSize: 9, color: 'var(--text-muted)', marginTop: 6, fontFamily: 'var(--font-mono)' }
                    }, `Fetched: ${new Date(r.fetched_at).toLocaleString()}`)
                  )
                );
              })
    )
  );
}

window.OsintIntel = OsintIntel;
