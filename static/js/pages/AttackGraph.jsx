// AttackGraph.jsx — Intelligent Attack Chain Analyzer & Graph Visualizer
// Primary view: LLM-analyzed attack chains with step-by-step exploitation guides
// Secondary views: D3 force graph + MITRE ATT&CK heatmap
const { useEffect, useRef, useState, useCallback, useMemo } = React;

// ── Color + icon constants ────────────────────────────────────────────────────
const NODE_COLOR = {
  host:          'var(--cyan)',
  service:       'var(--low)',
  vulnerability: 'var(--critical)',
  finding:       'var(--medium)',
  exploit:       '#ff6400',
  access:        'var(--violet)',
  credential:    '#ff6400',
};
const NODE_RADIUS = { host:22, service:16, vulnerability:14, finding:13, exploit:15, access:18, credential:14 };
const NODE_ICON   = { host:'🖥', service:'⚙', vulnerability:'⚠', finding:'🔍', exploit:'💥', access:'🔑', credential:'🔐' };
const SEV_COLOR   = { CRITICAL:'var(--critical)', HIGH:'#ff6400', MEDIUM:'var(--medium)', LOW:'var(--low)', INFO:'var(--border-bright)' };
const IMPACT_COLOR = { critical:'var(--critical)', high:'#ff6400', medium:'var(--medium)', low:'var(--low)' };
const SEV_EDGE_COLOR = { critical:'var(--critical)', high:'#ff6400', medium:'var(--medium)', low:'var(--low)', info:'#4a5568' };

const MITRE_TACTICS = [
  'reconnaissance','initial_access','execution','persistence','privilege_escalation',
  'defense_evasion','credential_access','discovery','lateral_movement',
  'collection','exfiltration','command_and_control','impact',
];

// ── Utility ───────────────────────────────────────────────────────────────────
function probColor(p) {
  if (p >= 0.7) return 'var(--low)';
  if (p >= 0.4) return 'var(--amber)';
  return 'var(--text-muted)';
}
function probLabel(p) {
  if (p >= 0.7) return 'High';
  if (p >= 0.4) return 'Medium';
  return 'Low';
}
function copyText(t) {
  try { navigator.clipboard.writeText(t); } catch {}
}

// ── Sub-components ────────────────────────────────────────────────────────────

function TabBtn({ label, active, onClick, badge }) {
  return React.createElement('button', {
    onClick,
    style: {
      padding: '5px 14px', borderRadius: 6, cursor: 'pointer', fontSize: 11,
      fontFamily: 'var(--font-mono)', fontWeight: 600, letterSpacing: 0.5,
      border: active ? '1px solid var(--cyan)' : '1px solid var(--border-light)',
      background: active ? 'rgba(0,212,255,0.08)' : 'rgba(255,255,255,0.03)',
      color: active ? 'var(--cyan)' : 'var(--text-muted)',
      display: 'flex', alignItems: 'center', gap: 5,
    }
  },
    label,
    badge != null && React.createElement('span', {
      style: {
        fontSize: 9, padding: '0 5px', borderRadius: 8,
        background: active ? 'rgba(0,212,255,0.2)' : 'rgba(255,255,255,0.08)',
        color: active ? 'var(--cyan)' : 'var(--text-muted)',
      }
    }, badge)
  );
}

function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  return React.createElement('button', {
    onClick: (e) => { e.stopPropagation(); copyText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); },
    style: {
      padding: '2px 8px', borderRadius: 4, border: '1px solid var(--border)',
      background: 'var(--bg-elevated)', color: copied ? 'var(--low)' : 'var(--text-muted)',
      cursor: 'pointer', fontSize: 9, fontFamily: 'var(--font-mono)', flexShrink: 0,
    }
  }, copied ? '✓ copied' : '⎘ copy');
}

function StepCard({ step, index }) {
  const [expanded, setExpanded] = useState(false);
  const mitreColor = 'var(--cyan)';
  return React.createElement('div', {
    style: {
      borderRadius: 6, border: '1px solid var(--border)',
      background: 'var(--bg-elevated)', overflow: 'hidden',
    }
  },
    // Step header
    React.createElement('div', {
      onClick: () => setExpanded(e => !e),
      style: {
        display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
        cursor: 'pointer',
      }
    },
      React.createElement('div', {
        style: {
          width: 22, height: 22, borderRadius: '50%', flexShrink: 0,
          background: 'rgba(0,212,255,0.12)', border: '1px solid rgba(0,212,255,0.3)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 9, fontWeight: 700, color: 'var(--cyan)', fontFamily: 'var(--font-mono)',
        }
      }, index + 1),
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },
        React.createElement('div', { style: { fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' } },
          step.technique || step.description || 'Step'),
        React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', display: 'flex', gap: 8, marginTop: 2 } },
          step.tool && React.createElement('span', null, `🔧 ${step.tool}`),
          step.mitre_id && React.createElement('span', { style: { color: mitreColor } }, step.mitre_id),
          step.mitre_tactic && React.createElement('span', null, step.mitre_tactic.replace(/_/g,' ')),
        )
      ),
      React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, expanded ? '▲' : '▼')
    ),

    // Expanded detail
    expanded && React.createElement('div', {
      style: { padding: '0 12px 12px', borderTop: '1px solid var(--border)', paddingTop: 10, display: 'flex', flexDirection: 'column', gap: 8 }
    },
      step.description && React.createElement('div', { style: { fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6 } }, step.description),

      step.command && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 4 } },
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8 } }, 'COMMAND'),
        React.createElement('div', {
          style: {
            display: 'flex', alignItems: 'flex-start', gap: 6,
            background: 'var(--bg-base)', borderRadius: 5, padding: '8px 10px',
            border: '1px solid var(--border)',
          }
        },
          React.createElement('pre', {
            style: {
              flex: 1, margin: 0, fontSize: 11, color: 'var(--low)',
              fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              lineHeight: 1.5,
            }
          }, step.command),
          React.createElement(CopyBtn, { text: step.command })
        )
      ),

      step.expected_outcome && React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } },
        React.createElement('span', { style: { color: 'var(--cyan)' } }, '→ Expected: '),
        step.expected_outcome
      ),
      step.produces && React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } },
        React.createElement('span', { style: { color: 'var(--low)' } }, '✓ Produces: '),
        step.produces
      ),
    )
  );
}

function ChainCard({ chain, isRecommended, isExpanded, onToggle }) {
  const steps = chain.steps || [];
  const pColor = IMPACT_COLOR[chain.impact] || 'var(--text-muted)';
  const pc = probColor(chain.probability || 0);

  return React.createElement('div', {
    style: {
      borderRadius: 8,
      border: `1px solid ${isRecommended ? 'rgba(0,229,160,0.4)' : 'var(--border)'}`,
      background: isRecommended ? 'rgba(0,229,160,0.04)' : 'var(--bg-surface)',
      overflow: 'hidden',
      transition: 'border-color 0.2s',
    }
  },
    // Chain header — always visible
    React.createElement('div', {
      onClick: onToggle,
      style: {
        display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px',
        cursor: 'pointer',
      }
    },
      // Recommended star
      isRecommended && React.createElement('span', {
        style: { fontSize: 14, flexShrink: 0, filter: 'drop-shadow(0 0 6px var(--accent))' }
      }, '⭐'),

      // Chain info
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 } },
          React.createElement('span', { style: { fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' } }, chain.title || 'Attack Chain'),
          React.createElement('span', {
            style: {
              fontSize: 9, padding: '1px 6px', borderRadius: 4, flexShrink: 0,
              background: `${pColor}20`, border: `1px solid ${pColor}60`, color: pColor,
              fontFamily: 'var(--font-mono)', fontWeight: 700,
            }
          }, chain.impact ? chain.impact.toUpperCase() : 'UNKNOWN'),
        ),
        React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', display: 'flex', gap: 10, flexWrap: 'wrap' } },
          chain.entry_point && React.createElement('span', null, `🚪 ${chain.entry_point}`),
          chain.objective   && React.createElement('span', null, `🎯 ${chain.objective}`),
          steps.length > 0  && React.createElement('span', null, `${steps.length} steps`),
        )
      ),

      // Probability badge
      React.createElement('div', {
        style: { textAlign: 'center', flexShrink: 0 }
      },
        React.createElement('div', { style: { fontSize: 14, fontWeight: 800, color: pc, fontFamily: 'var(--font-mono)' } },
          `${Math.round((chain.probability || 0) * 100)}%`),
        React.createElement('div', { style: { fontSize: 8, color: pc } }, probLabel(chain.probability || 0))
      ),

      React.createElement('span', { style: { fontSize: 12, color: 'var(--text-muted)', flexShrink: 0, marginLeft: 4 } },
        isExpanded ? '▲' : '▼')
    ),

    // Expanded body
    isExpanded && React.createElement('div', {
      style: { borderTop: '1px solid var(--border)', padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 12 }
    },
      // Description
      chain.description && React.createElement('div', {
        style: { fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.7,
                 padding: '8px 10px', borderRadius: 6, background: 'var(--bg-base)', border: '1px solid var(--border)' }
      }, chain.description),

      // Missing requirements
      (chain.missing_requirements || []).length > 0 && React.createElement('div', {
        style: { display: 'flex', flexDirection: 'column', gap: 4 }
      },
        React.createElement('div', { style: { fontSize: 9, color: 'var(--amber)', textTransform: 'uppercase', letterSpacing: 0.8 } }, '⚠ Needed to complete this chain'),
        ...(chain.missing_requirements || []).map((req, i) =>
          React.createElement('div', {
            key: i,
            style: { fontSize: 10, color: 'var(--amber)', display: 'flex', gap: 6 }
          },
            React.createElement('span', { style: { flexShrink: 0 } }, '•'),
            req
          )
        )
      ),

      // Steps
      steps.length > 0 && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 6 } },
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 2 } },
          'EXPLOITATION STEPS'),
        ...steps.map((step, i) => React.createElement(StepCard, { key: step.id || i, step, index: i }))
      ),

      // Finding refs
      (chain.finding_refs || []).length > 0 && React.createElement('div', {
        style: { fontSize: 10, color: 'var(--text-muted)' }
      }, `Based on findings: ${chain.finding_refs.join(', ')}`)
    )
  );
}

// ── Main Component ────────────────────────────────────────────────────────────
function AttackGraph() {
  const { state } = window.useStore();
  const svgRef      = useRef(null);
  const simRef      = useRef(null);
  const [nodes,    setNodes]    = useState([]);
  const [edges,    setEdges]    = useState([]);
  const [loading,  setLoading]  = useState(false);
  const [selected, setSelected] = useState(null);
  const [filter,   setFilter]   = useState('all');
  const [view,     setView]     = useState('chains'); // 'chains' | 'graph' | 'mitre'
  const [minimap,  setMinimap]  = useState(true);
  const [expandedChain, setExpandedChain] = useState(null);

  const mitreMap     = state.mitreMap || [];
  const chainAnalysis = state.chainAnalysis;
  const chainStatus   = state.chainAnalysisStatus;

  // ── Load graph data ────────────────────────────────────────────────────────
  const loadGraph = useCallback(async () => {
    if (!state.sessionId) return;
    setLoading(true);
    try {
      const g = await window.API.graph(state.sessionId);
      setNodes(g.nodes || []);
      setEdges(g.edges || []);
    } catch {}
    setLoading(false);
  }, [state.sessionId]);

  // Load chain analyses persisted from previous runs on session open
  const loadChainAnalyses = useCallback(async () => {
    if (!state.sessionId) return;
    try {
      const r = await window.API.chainAnalyses(state.sessionId);
      const latest = (r.analyses || [])[0];
      if (latest && !chainAnalysis) {
        window.useStore().dispatch({ type: 'CHAIN_ANALYSIS', payload: latest });
      }
    } catch {}
  }, [state.sessionId]);

  useEffect(() => { loadGraph(); loadChainAnalyses(); }, [state.sessionId]);

  // Live graph node updates via WS
  useEffect(() => {
    if (state.graphNodes?.length > nodes.length) {
      setNodes(state.graphNodes);
      setEdges(state.graphEdges || []);
    }
  }, [state.graphNodes, state.graphEdges]);

  // Redraw D3 graph when data or filter changes
  useEffect(() => {
    if (view !== 'graph' || !svgRef.current) return;
    const filtered    = filter === 'all' ? nodes : nodes.filter(n => (n.node_type||n.type) === filter);
    const filteredIds = new Set(filtered.map(n => n.node_id));
    const filtEdges   = edges.filter(e => filteredIds.has(e.source) && filteredIds.has(e.target));
    drawGraph(filtered, filtEdges, svgRef.current, setSelected, simRef);
  }, [nodes, edges, filter, view]);

  // Auto-expand recommended chain
  useEffect(() => {
    if (chainAnalysis?.recommended_chain && !expandedChain) {
      setExpandedChain(chainAnalysis.recommended_chain);
    }
  }, [chainAnalysis]);

  const chains       = chainAnalysis?.chains || [];
  const recommended  = chainAnalysis?.recommended_chain || '';
  const immediates   = chainAnalysis?.immediate_actions || [];
  const assessment   = chainAnalysis?.target_assessment || '';

  const typeCounts = nodes.reduce((acc, n) => {
    const t = n.node_type || n.type || 'unknown';
    acc[t] = (acc[t] || 0) + 1;
    return acc;
  }, {});

  // ── RENDER ─────────────────────────────────────────────────────────────────
  return React.createElement('div', {
    style: { display:'flex', flexDirection:'column', height:'100%', padding:16, background:'var(--bg-base,#0a0a0a)', gap:12, overflowY:'auto' }
  },

    // ── Header ──────────────────────────────────────────────────────────────
    React.createElement('div', { style: { display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:8 } },
      React.createElement('div', null,
        React.createElement('div', { className:'page-title' }, '⛓ Attack Graph & Chain Analyzer'),
        React.createElement('div', { style: { fontSize:11, color:'var(--text-muted)', marginTop:2 } },
          chainStatus?.status === 'analyzing'
            ? React.createElement('span', { style:{ color:'var(--cyan)', animation:'pulse 1s infinite' } }, `⟳ ${chainStatus.message}`)
            : chainStatus?.status === 'complete'
              ? `${chainStatus.message}`
              : `${nodes.length} graph nodes · ${chains.length} attack chains${loading?' · loading...':''}`
        )
      ),
      React.createElement('div', { style: { display:'flex', gap:6, flexWrap:'wrap', alignItems:'center' } },
        React.createElement(TabBtn, { label:'⛓ Chains', active: view==='chains', onClick:()=>setView('chains'), badge: chains.length||undefined }),
        React.createElement(TabBtn, { label:'🗺 Graph',  active: view==='graph',  onClick:()=>{ setView('graph'); setTimeout(loadGraph,50); } }),
        React.createElement(TabBtn, { label:'🛡 MITRE',  active: view==='mitre',  onClick:()=>setView('mitre'), badge: mitreMap.length||undefined }),
        React.createElement('div', { style:{ width:1, height:18, background:'var(--border-light)' } }),
        React.createElement('button', {
          onClick: ()=>{ loadGraph(); loadChainAnalyses(); },
          style:{ padding:'5px 11px', borderRadius:6, border:'1px solid var(--border-light)',
                  background:'rgba(255,255,255,0.04)', color:'var(--text-secondary)', cursor:'pointer', fontSize:11 }
        }, '↻ Refresh'),
      )
    ),

    // ── No session ───────────────────────────────────────────────────────────
    !state.sessionId && React.createElement('div', {
      style:{ padding:'40px 24px', borderRadius:10, background:'var(--bg-surface)', border:'1px solid var(--border)',
              textAlign:'center', display:'flex', flexDirection:'column', alignItems:'center', gap:10 }
    },
      React.createElement('div', { style:{fontSize:40, opacity:0.2} }, '⛓'),
      React.createElement('div', { style:{fontSize:14, fontWeight:700, color:'var(--text-secondary)'} }, 'No Active Session'),
      React.createElement('div', { style:{fontSize:11, color:'var(--text-muted)', maxWidth:360, lineHeight:1.7} },
        'Start a pentest to generate attack chains. The analyzer watches findings in real-time and maps viable exploitation paths.'
      )
    ),

    // ══════════════════════════════════════════════════════════════════════════
    // VIEW: CHAINS
    // ══════════════════════════════════════════════════════════════════════════
    view === 'chains' && state.sessionId && React.createElement('div', {
      style: { display:'flex', flexDirection:'column', gap:12 }
    },

      // Target assessment banner
      assessment && React.createElement('div', {
        style:{
          padding:'10px 14px', borderRadius:8,
          background:'rgba(0,212,255,0.04)', border:'1px solid rgba(0,212,255,0.2)',
          fontSize:11, color:'var(--text-secondary)', lineHeight:1.7,
          display:'flex', gap:8, alignItems:'flex-start',
        }
      },
        React.createElement('span', { style:{fontSize:14, flexShrink:0} }, '🎯'),
        React.createElement('div', null,
          React.createElement('span', { style:{fontWeight:700, color:'var(--cyan)', marginRight:6} }, 'Target Assessment:'),
          assessment
        )
      ),

      // Immediate actions
      immediates.length > 0 && React.createElement('div', {
        style:{
          padding:'10px 14px', borderRadius:8,
          background:'rgba(255,170,0,0.05)', border:'1px solid rgba(255,170,0,0.2)',
        }
      },
        React.createElement('div', { style:{fontSize:10, fontWeight:700, color:'var(--amber)', textTransform:'uppercase', letterSpacing:0.8, marginBottom:6} },
          '⚡ Immediate Actions'),
        React.createElement('div', { style:{display:'flex', flexDirection:'column', gap:4} },
          ...(immediates.map((a, i) => React.createElement('div', {
            key:i, style:{display:'flex', gap:8, fontSize:11, color:'var(--text-secondary)'}
          },
            React.createElement('span', { style:{color:'var(--amber)', fontFamily:'var(--font-mono)', fontWeight:700, flexShrink:0} }, `${i+1}.`),
            a
          )))
        )
      ),

      // No chains yet
      chains.length === 0 && React.createElement('div', {
        style:{
          padding:'40px 24px', borderRadius:10, background:'var(--bg-surface)',
          border:'1px solid var(--border)', textAlign:'center',
          display:'flex', flexDirection:'column', alignItems:'center', gap:10
        }
      },
        chainStatus?.status === 'analyzing'
          ? React.createElement('div', { style:{color:'var(--cyan)', fontSize:12, animation:'pulse 1.5s infinite'} },
              '⟳ Analyzing findings for attack chains...')
          : React.createElement(React.Fragment, null,
              React.createElement('div', { style:{fontSize:36, opacity:0.2} }, '⛓'),
              React.createElement('div', { style:{fontSize:13, fontWeight:700, color:'var(--text-secondary)'} }, 'No Chains Analyzed Yet'),
              React.createElement('div', { style:{fontSize:11, color:'var(--text-muted)', maxWidth:380, lineHeight:1.7} },
                'The Attack Graph Agent monitors findings in real-time. Chains appear automatically once enough findings accumulate (typically within 1-2 minutes of first results).'
              )
            )
      ),

      // Chain list — recommended first, then sorted by probability
      ...([...chains]
        .sort((a, b) => {
          if (a.id === recommended) return -1;
          if (b.id === recommended) return 1;
          return (b.probability||0) - (a.probability||0);
        })
        .map(chain => React.createElement(ChainCard, {
          key: chain.id,
          chain,
          isRecommended: chain.id === recommended,
          isExpanded:    expandedChain === chain.id,
          onToggle:      () => setExpandedChain(prev => prev === chain.id ? null : chain.id),
        }))
      )
    ),

    // ══════════════════════════════════════════════════════════════════════════
    // VIEW: GRAPH (D3 force-directed)
    // ══════════════════════════════════════════════════════════════════════════
    view === 'graph' && state.sessionId && React.createElement('div', {
      style:{ display:'flex', gap:12, flex:1, minHeight:500 }
    },
      // Canvas
      React.createElement('div', {
        style:{ flex:1, borderRadius:8, border:'1px solid var(--border)',
                background:'var(--bg-surface)', overflow:'hidden', position:'relative', minHeight:500 }
      },
        // Type filter strip
        React.createElement('div', {
          style:{ position:'absolute', top:8, left:8, display:'flex', gap:4, zIndex:10, flexWrap:'wrap' }
        },
          ['all',...Object.keys(NODE_COLOR)].map(t => {
            const count = t==='all' ? nodes.length : (typeCounts[t]||0);
            if (t!=='all' && !count) return null;
            const active = filter===t;
            const col    = NODE_COLOR[t] || 'var(--text-secondary)';
            return React.createElement('div', {
              key:t, onClick:()=>setFilter(active?'all':t),
              style:{
                padding:'2px 8px', borderRadius:10, cursor:'pointer', fontSize:9,
                border:`1px solid ${active?col:col+'40'}`,
                background: active?col+'20':'rgba(0,0,0,0.5)',
                color: active?col:'var(--text-muted)',
                backdropFilter:'blur(4px)',
              }
            }, `${NODE_ICON[t]||''} ${t} (${count})`);
          })
        ),

        nodes.length === 0
          ? React.createElement('div', {
              style:{ position:'absolute', inset:0, display:'flex', alignItems:'center',
                      justifyContent:'center', flexDirection:'column', gap:8, color:'var(--text-muted)' }
            },
              loading
                ? React.createElement('div', null, '⟳ Building graph...')
                : React.createElement('div', { style:{textAlign:'center'} },
                    React.createElement('div', { style:{fontSize:36, marginBottom:8} }, '🗺'),
                    React.createElement('div', null, 'Graph builds as agents discover assets')
                  )
            )
          : React.createElement(React.Fragment, null,
              React.createElement('svg', { ref:svgRef, style:{ width:'100%', height:'100%', display:'block' } }),
              minimap && React.createElement('div', {
                style:{
                  position:'absolute', bottom:8, right:8, width:120, height:80,
                  background:'rgba(10,10,10,0.82)', border:'1px solid rgba(255,255,255,0.12)',
                  borderRadius:6, overflow:'hidden', pointerEvents:'none', backdropFilter:'blur(4px)'
                }
              },
                React.createElement('div', {
                  style:{ position:'absolute', top:3, left:5, fontSize:7,
                          color:'rgba(255,255,255,0.35)', letterSpacing:0.5, textTransform:'uppercase' }
                }, 'minimap'),
                React.createElement('svg', { style:{ width:'100%', height:'100%' }, viewBox:'0 0 120 80' },
                  ...(() => {
                    const filtered = filter==='all' ? nodes : nodes.filter(n=>(n.node_type||n.type)===filter);
                    if (!filtered.length) return [];
                    const xs = filtered.map(n=>n.x||0), ys = filtered.map(n=>n.y||0);
                    const minX = Math.min(...xs), maxX = Math.max(...xs)||1;
                    const minY = Math.min(...ys), maxY = Math.max(...ys)||1;
                    return filtered.map(n => React.createElement('circle', {
                      key:n.node_id, cx:5+((n.x||0)-minX)/(maxX-minX)*110,
                      cy:12+((n.y||0)-minY)/(maxY-minY)*55, r:2,
                      fill: NODE_COLOR[n.node_type||n.type] || 'var(--text-muted)', opacity:0.8
                    }));
                  })()
                )
              )
            ),
        // Freeze / minimap controls
        React.createElement('div', {
          style:{ position:'absolute', top:8, right:8, display:'flex', gap:4, zIndex:10 }
        },
          React.createElement('button', {
            onClick:()=>{ if(simRef.current) simRef.current.stop(); },
            style:{ padding:'3px 8px', borderRadius:5, border:'1px solid var(--border)',
                    background:'rgba(0,0,0,0.6)', color:'var(--text-muted)', cursor:'pointer', fontSize:9 }
          }, '⏸'),
          React.createElement('button', {
            onClick:()=>setMinimap(m=>!m),
            style:{ padding:'3px 8px', borderRadius:5, border:`1px solid ${minimap?'var(--violet)':'var(--border)'}`,
                    background: minimap?'rgba(139,92,246,0.15)':'rgba(0,0,0,0.6)',
                    color: minimap?'var(--violet)':'var(--text-muted)', cursor:'pointer', fontSize:9 }
          }, '⊞')
        )
      ),

      // Node detail panel
      selected && React.createElement('div', {
        style:{
          width:260, flexShrink:0, borderRadius:8, border:'1px solid var(--border)',
          background:'var(--bg-surface)', padding:14, display:'flex', flexDirection:'column', gap:8,
          overflowY:'auto', maxHeight:600,
        }
      },
        React.createElement('div', { style:{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' } },
          React.createElement('div', { style:{ fontSize:20 } }, NODE_ICON[selected.node_type||selected.type] || '◆'),
          React.createElement('button', {
            onClick:()=>setSelected(null),
            style:{ background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer', fontSize:14, padding:0 }
          }, '✕')
        ),
        React.createElement('div', { style:{ fontSize:12, fontWeight:700, color: NODE_COLOR[selected.node_type||selected.type]||'var(--text-primary)' } },
          selected.label),
        React.createElement('div', { style:{ fontSize:10, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:0.5 } },
          selected.node_type || selected.type),
        selected.severity && React.createElement('div', {
          style:{ fontSize:10, padding:'2px 8px', borderRadius:4, alignSelf:'flex-start',
                  background:`${SEV_COLOR[selected.severity?.toUpperCase()]||'var(--border)'}20`,
                  border:`1px solid ${SEV_COLOR[selected.severity?.toUpperCase()]||'var(--border)'}60`,
                  color: SEV_COLOR[selected.severity?.toUpperCase()]||'var(--text-muted)' }
        }, selected.severity?.toUpperCase()),
        selected.host && React.createElement('div', { style:{fontSize:10, color:'var(--text-muted)'} }, `Host: ${selected.host}`),
        selected.port && React.createElement('div', { style:{fontSize:10, color:'var(--text-muted)'} }, `Port: ${selected.port}`),
        selected.phase && React.createElement('div', { style:{fontSize:10, color:'var(--text-muted)'} }, `Phase: ${selected.phase}`),
        selected.metadata && Object.keys(selected.metadata).length > 0 && React.createElement('div', {
          style:{ fontSize:9, fontFamily:'var(--font-mono)', color:'var(--text-muted)',
                  background:'var(--bg-base)', borderRadius:4, padding:'6px 8px', lineHeight:1.6, wordBreak:'break-all' }
        }, JSON.stringify(selected.metadata, null, 2))
      )
    ),

    // ══════════════════════════════════════════════════════════════════════════
    // VIEW: MITRE ATT&CK heatmap
    // ══════════════════════════════════════════════════════════════════════════
    view === 'mitre' && React.createElement('div', { style:{ display:'flex', flexDirection:'column', gap:12 } },
      mitreMap.length === 0
        ? React.createElement('div', {
            style:{ padding:'40px 24px', borderRadius:10, background:'var(--bg-surface)',
                    border:'1px solid var(--border)', textAlign:'center', color:'var(--text-muted)' }
          }, 'No MITRE techniques mapped yet. Start a pentest to see ATT&CK coverage.')
        : React.createElement(React.Fragment, null,
            // Summary strip
            React.createElement('div', { style:{ fontSize:11, color:'var(--text-muted)' } },
              `${mitreMap.length} techniques identified across ${new Set(mitreMap.map(t=>t.tactic)).size} tactics`
            ),

            // Tactics grid
            React.createElement('div', { style:{ display:'flex', gap:6, overflowX:'auto', paddingBottom:4 } },
              MITRE_TACTICS.map(tactic => {
                const tacTechniques = mitreMap.filter(t => t.tactic === tactic);
                const count = tacTechniques.length;
                const intensity = Math.min(count/5, 1);
                return React.createElement('div', {
                  key: tactic,
                  style:{
                    minWidth: 130, flexShrink:0, borderRadius:7, padding:'8px 10px',
                    background: count > 0 ? `rgba(0,212,255,${0.05+intensity*0.15})` : 'var(--bg-surface)',
                    border: `1px solid ${count>0 ? 'rgba(0,212,255,'+(0.2+intensity*0.4)+')' : 'var(--border)'}`,
                  }
                },
                  React.createElement('div', {
                    style:{ fontSize:9, fontWeight:700, color: count>0?'var(--cyan)':'var(--text-muted)',
                            textTransform:'uppercase', letterSpacing:0.5, marginBottom:4 }
                  }, tactic.replace(/_/g,' ')),
                  count > 0
                    ? tacTechniques.map(t => React.createElement('div', {
                        key:t.id,
                        style:{ fontSize:9, color:'var(--text-secondary)', marginBottom:3,
                                display:'flex', gap:4, alignItems:'flex-start' }
                      },
                        React.createElement('span', { style:{color:'var(--cyan)', fontFamily:'var(--font-mono)', flexShrink:0} }, t.id),
                        React.createElement('span', null, t.name || '')
                      ))
                    : React.createElement('div', { style:{fontSize:9, color:'var(--border-bright)'} }, 'No techniques')
                );
              })
            )
          )
    )
  );
}

// ── D3 Graph renderer (unchanged from original — keeps all existing behavior) ─
function drawGraph(nodes, edges, svgEl, onSelect, simRef) {
  if (!window.d3 || !svgEl) return;
  const d3 = window.d3;
  d3.select(svgEl).selectAll('*').remove();

  const W = svgEl.clientWidth  || 900;
  const H = svgEl.clientHeight || 600;

  const svg = d3.select(svgEl)
    .attr('width', W).attr('height', H);

  const defs = svg.append('defs');
  Object.entries(SEV_EDGE_COLOR).forEach(([sev, col]) => {
    defs.append('marker').attr('id','arr-'+sev)
      .attr('viewBox','0 -5 10 10').attr('refX',20).attr('refY',0)
      .attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
      .append('path').attr('d','M0,-5L10,0L0,5').attr('fill',col);
  });

  // Glow filter for high-severity nodes
  const filt = defs.append('filter').attr('id','glow');
  filt.append('feGaussianBlur').attr('stdDeviation','3').attr('result','coloredBlur');
  const fm = filt.append('feMerge');
  fm.append('feMergeNode').attr('in','coloredBlur');
  fm.append('feMergeNode').attr('in','SourceGraphic');

  const g = svg.append('g');

  svg.call(d3.zoom().scaleExtent([0.1,4])
    .on('zoom', ev => g.attr('transform', ev.transform)));

  // Hierarchy levels for vertical layering
  const levelMap = { host:0, service:1, vulnerability:2, finding:3, exploit:4, access:5, credential:5 };
  const ns = nodes.map(n => ({...n, _level: levelMap[n.node_type||n.type] ?? 3 }));

  const sim = d3.forceSimulation(ns)
    .force('link', d3.forceLink(edges.map(e => ({...e})))
      .id(d => d.node_id).distance(110).strength(0.3))
    .force('charge', d3.forceManyBody().strength(-220))
    .force('x', d3.forceX(W/2).strength(0.04))
    .force('y', d3.forceY(d => 80 + d._level * (H-120)/5).strength(0.25))
    .force('collision', d3.forceCollide(d => (NODE_RADIUS[d.node_type||d.type]||14)+10));

  if (simRef) simRef.current = sim;

  const edgeG = g.append('g');
  const link = edgeG.selectAll('line').data(edges)
    .enter().append('line')
    .attr('stroke', d => SEV_EDGE_COLOR[d.severity||d.label?.toLowerCase()] || SEV_EDGE_COLOR.info)
    .attr('stroke-width', 1.5).attr('opacity', 0.65)
    .attr('marker-end', d => 'url(#arr-'+(d.severity||'info')+')');

  const edgeLabelG = g.append('g');
  const eLabel = edgeLabelG.selectAll('text').data(edges)
    .enter().append('text')
    .attr('font-size', 7).attr('fill','rgba(255,255,255,0.35)')
    .attr('text-anchor','middle').text(d => (d.label||'').slice(0,18));

  const nodeG = g.append('g');
  const node = nodeG.selectAll('g').data(ns)
    .enter().append('g')
    .attr('cursor','pointer')
    .call(d3.drag()
      .on('start', (ev,d) => { if(!ev.active) sim.alphaTarget(0.2).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',  (ev,d) => { d.fx=ev.x; d.fy=ev.y; })
      .on('end',   (ev,d) => { if(!ev.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }))
    .on('click', (ev, d) => { ev.stopPropagation(); onSelect(d); });

  const isCrit = d => ['CRITICAL','HIGH'].includes((d.severity||'').toUpperCase());

  node.append('circle')
    .attr('r', d => NODE_RADIUS[d.node_type||d.type] || 13)
    .attr('fill', d => NODE_COLOR[d.node_type||d.type] || 'var(--text-muted)')
    .attr('fill-opacity', 0.18)
    .attr('stroke', d => NODE_COLOR[d.node_type||d.type] || 'var(--text-muted)')
    .attr('stroke-width', d => isCrit(d) ? 2 : 1.5)
    .attr('filter', d => isCrit(d) ? 'url(#glow)' : null);

  node.append('text')
    .attr('text-anchor','middle').attr('dominant-baseline','central')
    .attr('font-size', d => (NODE_RADIUS[d.node_type||d.type]||13)*0.7)
    .style('user-select','none').style('pointer-events','none')
    .text(d => NODE_ICON[d.node_type||d.type] || '◆');

  node.append('text')
    .attr('text-anchor','middle').attr('y', d => (NODE_RADIUS[d.node_type||d.type]||13)+12)
    .attr('font-size',8).attr('fill','rgba(255,255,255,0.7)')
    .style('user-select','none').style('pointer-events','none')
    .text(d => (d.label||'').slice(0,20));

  sim.on('tick', () => {
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
        .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    eLabel.attr('x',d=>((d.source.x||0)+(d.target.x||0))/2)
          .attr('y',d=>((d.source.y||0)+(d.target.y||0))/2);
    node.attr('transform',d=>`translate(${d.x},${d.y})`);
  });
}

window.AttackGraph = AttackGraph;
