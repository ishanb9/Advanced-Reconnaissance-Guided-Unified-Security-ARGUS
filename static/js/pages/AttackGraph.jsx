// AttackGraph.jsx — Stellar Ops unified attack graph
// 6 tabs: Stellar (particle canvas) · Chains · Graph (D3) · Relationships · Paths · MITRE
// Restores all original tabs from baseline 7f9c74f + adds the cinematic
// particle showpiece (T4) as the new default view, all under the
// Stellar Ops aesthetic with var(--*) tokens.
const { useEffect, useRef, useState, useCallback, useMemo } = React;

// ── Color + icon constants ────────────────────────────────────────────────────
const NODE_COLOR = {
  host:          'var(--cyan)',
  service:       'var(--low)',
  vulnerability: 'var(--critical)',
  finding:       'var(--medium)',
  exploit:       'var(--high)',
  access:        'var(--violet)',
  credential:    'var(--high)',
};
const NODE_RADIUS = { host:22, service:16, vulnerability:14, finding:13, exploit:15, access:18, credential:14 };
const NODE_ICON   = { host:'🖥', service:'⚙', vulnerability:'⚠', finding:'🔍', exploit:'💥', access:'🔑', credential:'🔐' };
const SEV_COLOR   = { CRITICAL:'var(--critical)', HIGH:'var(--high)', MEDIUM:'var(--medium)', LOW:'var(--low)', INFO:'var(--border-bright)' };
const IMPACT_COLOR = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)' };
const SEV_EDGE_COLOR = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)', info:'var(--border)' };

const MITRE_TACTICS = [
  'reconnaissance','initial_access','execution','persistence','privilege_escalation',
  'defense_evasion','credential_access','discovery','lateral_movement',
  'collection','exfiltration','command_and_control','impact',
];

// ── Relationship type color map (Neo4j) ──────────────────────────────────────
const REL_COLOR = {
  EXPOSES:         'var(--cyan)',
  RUNS:            'var(--low)',
  VULNERABLE_TO:   'var(--critical)',
  LEADS_TO:        'var(--high)',
  REFERENCES:      'var(--text-muted)',
  EXPLOITABLE_WITH:'var(--amber)',
  HAS_CREDENTIAL:  'var(--high)',
  COMPROMISED_VIA: 'var(--critical)',
  ESCALATES_TO:    'var(--violet)',
  PIVOTS_TO:       'var(--medium)',
  AFFECTS:         'var(--medium)',
  RELATED_TO:      'var(--border-bright)',
};

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

// Resolve a CSS variable name (e.g. 'var(--high)' or '--high') to a real
// hex/rgb literal at the moment of call.  Used by canvas/SVG code paths
// that can't accept var() strings as fill/stroke.
function resolveCssVar(token, fallback) {
  if (!token) return fallback;
  const t = String(token).trim();
  if (t.startsWith('#') || t.startsWith('rgb')) return t;
  const m = t.match(/var\(\s*(--[a-z0-9-]+)\s*\)/i);
  const name = m ? m[1] : (t.startsWith('--') ? t : null);
  if (!name) return t || fallback;
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  } catch { return fallback; }
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
              background: 'rgba(255,255,255,0.04)', border: `1px solid ${pColor}`, color: pColor,
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

// ── Neo4j Settings Form ───────────────────────────────────────────────────────
function Neo4jSetup({ onConnected }) {
  const [uri,      setUri]      = useState('bolt://localhost:7687');
  const [user,     setUser]     = useState('neo4j');
  const [pass,     setPass]     = useState('');
  const [saving,   setSaving]   = useState(false);
  const [msg,      setMsg]      = useState('');
  const [ok,       setOk]       = useState(false);

  // Pre-fill with current settings on mount
  React.useEffect(() => {
    window.API.get('/settings/neo4j').then(d => {
      if (d.uri)  setUri(d.uri);
      if (d.user) setUser(d.user);
    }).catch(() => {});
  }, []);

  const save = async () => {
    setSaving(true); setMsg(''); setOk(false);
    try {
      const r = await window.API.post('/settings/neo4j', { uri, user, password: pass });
      setOk(r.connected);
      setMsg(r.message);
      if (r.connected && onConnected) onConnected();
    } catch (e) {
      setMsg('Request failed: ' + e.message);
    }
    setSaving(false);
  };

  const inp = (val, set, placeholder, type='text') =>
    React.createElement('input', {
      type, value: val, placeholder,
      onChange: e => set(e.target.value),
      style: {
        width: '100%', padding: '7px 10px', borderRadius: 6,
        border: '1px solid var(--border-light)', background: 'var(--bg-elevated)',
        color: 'var(--text-primary)', fontSize: 12, fontFamily: 'var(--font-mono)',
        outline: 'none', boxSizing: 'border-box',
      }
    });

  return React.createElement('div', {
    style: {
      maxWidth: 440, margin: '0 auto', padding: '24px 28px', borderRadius: 10,
      background: 'var(--bg-surface)', border: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', gap: 14,
    }
  },
    React.createElement('div', { style: { display:'flex', alignItems:'center', gap:10, marginBottom:4 } },
      React.createElement('div', { style:{fontSize:28} }, '🔗'),
      React.createElement('div', null,
        React.createElement('div', { style:{fontWeight:700, color:'var(--text-secondary)', fontSize:14} }, 'Connect Neo4j'),
        React.createElement('div', { style:{fontSize:11, color:'var(--text-muted)', lineHeight:1.5} },
          'Neo4j stores semantic relationships between discovered hosts, services, and vulnerabilities.'
        )
      )
    ),
    React.createElement('div', { style:{display:'flex', flexDirection:'column', gap:8} },
      React.createElement('label', { style:{fontSize:10, color:'var(--text-muted)', fontWeight:600, letterSpacing:0.5} }, 'BOLT URI'),
      inp(uri, setUri, 'bolt://localhost:7687'),
    ),
    React.createElement('div', { style:{display:'flex', gap:10} },
      React.createElement('div', { style:{flex:1, display:'flex', flexDirection:'column', gap:8} },
        React.createElement('label', { style:{fontSize:10, color:'var(--text-muted)', fontWeight:600, letterSpacing:0.5} }, 'USERNAME'),
        inp(user, setUser, 'neo4j'),
      ),
      React.createElement('div', { style:{flex:1, display:'flex', flexDirection:'column', gap:8} },
        React.createElement('label', { style:{fontSize:10, color:'var(--text-muted)', fontWeight:600, letterSpacing:0.5} }, 'PASSWORD'),
        inp(pass, setPass, '••••••••', 'password'),
      ),
    ),
    React.createElement('button', {
      onClick: save, disabled: saving,
      style: {
        padding: '9px 0', borderRadius: 7, border: 'none', cursor: saving ? 'not-allowed' : 'pointer',
        background: saving ? 'var(--border)' : 'var(--cyan)', color: '#000',
        fontWeight: 700, fontSize: 12, letterSpacing: 0.5,
      }
    }, saving ? 'Connecting…' : 'Save & Connect'),
    msg && React.createElement('div', {
      style: {
        padding: '8px 12px', borderRadius: 6, fontSize: 11,
        background: ok ? 'rgba(0,212,120,0.08)' : 'rgba(255,80,80,0.08)',
        border: `1px solid ${ok ? 'rgba(0,212,120,0.3)' : 'rgba(255,80,80,0.3)'}`,
        color: ok ? 'var(--low)' : 'var(--critical)',
      }
    }, (ok ? '✓ ' : '✗ ') + msg),
    React.createElement('div', { style:{fontSize:10, color:'var(--text-muted)', lineHeight:1.7} },
      'Default Neo4j Community password is set during first-run setup. ',
      'Settings are saved to .env in the server directory.'
    )
  );
}

// ── Stellar Particle Canvas ──────────────────────────────────────────────────
// Cinematic showpiece — ported from the T4 canvas-only AttackGraph.
//   • ~600 background particles drifting (cosmic backdrop)
//   • Attack-graph nodes laid out on a deterministic circle
//   • Edges drawn as faint azure light-paths
//   • Drag-to-pan, wheel-to-zoom, theme-aware via CSS-var resolution
function StellarParticleCanvas({ nodes, edges }) {
  const { state } = window.useStore();
  const canvasRef  = useRef(null);
  const wrapperRef = useRef(null);
  const [pan,  setPan]  = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const dragRef = useRef(null);

  // Persist particles across renders so they keep momentum
  const particlesRef = useRef(null);
  if (particlesRef.current === null) {
    particlesRef.current = Array.from({ length: 600 }, () => ({
      x: Math.random() * 1920,
      y: Math.random() * 1080,
      vx: (Math.random() - 0.5) * 0.05,
      vy: (Math.random() - 0.5) * 0.05,
    }));
  }

  // Canvas accent/violet/text — resolved from CSS at mount and theme-change
  const colorsRef = useRef({ accent: '#4FA8FF', violet: '#7B6CF6', text: '#E5EAF6' });

  // ── Resolve canvas colours from current CSS variables ───────────────────
  useEffect(() => {
    const cs = getComputedStyle(document.documentElement);
    colorsRef.current = {
      accent: cs.getPropertyValue('--accent').trim()       || '#4FA8FF',
      violet: cs.getPropertyValue('--violet').trim()       || '#7B6CF6',
      text:   cs.getPropertyValue('--text-primary').trim() || '#E5EAF6',
    };
  }, [state.theme]);

  // ── Resize canvas to container ─────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    function fit() {
      const r = wrapperRef.current?.getBoundingClientRect();
      if (!r) return;
      canvas.width  = Math.max(300, Math.floor(r.width));
      canvas.height = Math.max(300, Math.floor(r.height));
    }
    fit();
    window.addEventListener('resize', fit);
    return () => window.removeEventListener('resize', fit);
  }, []);

  // ── Animation loop ─────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let raf;
    function tick() {
      const W = canvas.width, H = canvas.height;
      ctx.clearRect(0, 0, W, H);

      // 1. Background particles — drift slowly, wrap toroidally
      ctx.fillStyle = 'rgba(229, 234, 246, 0.15)';
      const ps = particlesRef.current;
      for (const p of ps) {
        p.x = (p.x + p.vx + W) % W;
        p.y = (p.y + p.vy + H) % H;
        ctx.fillRect(p.x, p.y, 1, 1);
      }

      // 2. Node positions — deterministic circular layout (panable + zoomable)
      const cx    = W / 2 + pan.x;
      const cy    = H / 2 + pan.y;
      const r     = 200 * zoom;
      const total = nodes.length || 1;
      function nodePos(i) {
        const angle = (i / total) * Math.PI * 2 - Math.PI / 2;
        return { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r };
      }
      const nodeIndex = {};
      nodes.forEach((n, i) => {
        const key = n.node_id || n.id || n.host || i;
        nodeIndex[key] = i;
      });

      // 3. Edges — faint azure light-paths
      ctx.strokeStyle = colorsRef.current.accent;
      ctx.globalAlpha = 0.4;
      ctx.lineWidth   = 1;
      for (const e of edges) {
        const sk = e.source ?? e.from;
        const tk = e.target ?? e.to;
        const ai = nodeIndex[sk];
        const bi = nodeIndex[tk];
        if (ai == null || bi == null) continue;
        const a = nodePos(ai), b = nodePos(bi);
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;

      // 4. Nodes — circles + labels. HVA / high-priority nodes use violet.
      nodes.forEach((n, i) => {
        const { x, y } = nodePos(i);
        const t = (n.node_type || n.type || '').toLowerCase();
        const isHVA = !!(n.is_hva || n.is_high_value
                         || n.priority === 'high' || n.priority === 'critical'
                         || t === 'access' || t === 'credential' || t === 'exploit');
        ctx.beginPath();
        ctx.arc(x, y, isHVA ? 8 : 5, 0, Math.PI * 2);
        ctx.fillStyle = isHVA ? colorsRef.current.violet : colorsRef.current.accent;
        ctx.fill();

        // Label below node
        const lbl = n.label || n.host || n.node_id || n.id;
        if (lbl) {
          ctx.fillStyle    = colorsRef.current.text;
          ctx.globalAlpha  = 0.7;
          ctx.font         = '11px "JetBrains Mono", monospace';
          ctx.textAlign    = 'center';
          ctx.fillText(String(lbl).slice(0, 22), x, y + 18);
          ctx.globalAlpha  = 1;
        }
      });

      raf = requestAnimationFrame(tick);
    }
    tick();
    return () => cancelAnimationFrame(raf);
  }, [nodes, edges, pan, zoom]);

  // ── Drag-to-pan ────────────────────────────────────────────────────────
  function onMouseDown(e) {
    dragRef.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
  }
  function onMouseMove(e) {
    if (!dragRef.current) return;
    setPan({
      x: dragRef.current.panX + (e.clientX - dragRef.current.x),
      y: dragRef.current.panY + (e.clientY - dragRef.current.y),
    });
  }
  function onMouseUp() { dragRef.current = null; }

  // ── Wheel-to-zoom ──────────────────────────────────────────────────────
  function onWheel(e) {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    setZoom(z => Math.max(0.3, Math.min(3, z * factor)));
  }

  // ── Empty state ────────────────────────────────────────────────────────
  if (!nodes || nodes.length === 0) {
    return React.createElement('div', {
      style: {
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '70vh', color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)', fontSize: 12,
        background: 'var(--bg-base)', borderRadius: 10, border: '1px solid var(--border)',
      }
    }, 'No attack graph data yet — start a scan to populate.');
  }

  // ── Render ─────────────────────────────────────────────────────────────
  return React.createElement('div', {
    ref: wrapperRef,
    style: {
      width: '100%', height: '70vh', position: 'relative', overflow: 'hidden',
      background: 'var(--bg-base)', borderRadius: 10, border: '1px solid var(--border)',
      cursor: dragRef.current ? 'grabbing' : 'grab',
    },
    onMouseDown, onMouseMove, onMouseUp, onMouseLeave: onMouseUp, onWheel,
  },
    React.createElement('canvas', {
      ref: canvasRef,
      style: { display: 'block', width: '100%', height: '100%' },
    }),
    // Floating help/zoom indicator
    React.createElement('div', {
      style: {
        position: 'absolute', top: 10, right: 12,
        padding: '4px 10px', borderRadius: 14,
        background: 'rgba(8,12,30,0.55)', border: '1px solid var(--border)',
        color: 'var(--text-muted)', fontSize: 10, fontFamily: 'var(--font-mono)',
        letterSpacing: 0.4, pointerEvents: 'none',
      }
    }, `${nodes.length} nodes · ${edges.length} edges · ${zoom.toFixed(2)}×`)
  );
}

// ── Main Component ────────────────────────────────────────────────────────────
function AttackGraph(props) {
  const { state, loadNeo4jGraph, loadNeo4jPaths } = window.useStore();
  const vm = (props && props.viewMode) || 'OPERATOR';
  const svgRef      = useRef(null);
  const neo4jSvgRef = useRef(null);
  const simRef      = useRef(null);
  const neo4jSimRef = useRef(null);
  const [nodes,    setNodes]    = useState([]);
  const [edges,    setEdges]    = useState([]);
  const [loading,  setLoading]  = useState(false);
  const [selected, setSelected] = useState(null);
  const [filter,   setFilter]   = useState('all');
  // Default tab: ✨ Stellar — the new cinematic showpiece.
  // Other valid views: 'chains' | 'graph' | 'rel' | 'paths' | 'mitre'.
  const [view,     setView]     = useState('stellar');
  const [minimap,  setMinimap]  = useState(true);
  const [expandedChain, setExpandedChain] = useState(null);
  const [relFilter, setRelFilter] = useState('all');

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

  // Neo4j data + filtered views — defined before effects that depend on them.
  const neo4jGraph     = state.neo4jGraph     || { nodes: [], edges: [] };
  const neo4jPaths     = state.neo4jPaths     || [];
  const neo4jAvailable = state.neo4jAvailable;

  const visibleNeo4jEdges = relFilter === 'all'
    ? neo4jGraph.edges
    : neo4jGraph.edges.filter(e => (e.rel_type || '') === relFilter);
  const visibleNeo4jNodeIds = new Set([
    ...visibleNeo4jEdges.map(e => e.source),
    ...visibleNeo4jEdges.map(e => e.target),
  ]);
  const visibleNeo4jNodes = relFilter === 'all'
    ? neo4jGraph.nodes
    : neo4jGraph.nodes.filter(n => visibleNeo4jNodeIds.has(n.node_id));
  const neo4jRelTypes = [...new Set(neo4jGraph.edges.map(e => e.rel_type).filter(Boolean))].sort();

  // Redraw D3 graph when data or filter changes
  useEffect(() => {
    if (view !== 'graph' || !svgRef.current) return;
    const filtered    = filter === 'all' ? nodes : nodes.filter(n => (n.node_type||n.type) === filter);
    const filteredIds = new Set(filtered.map(n => n.node_id));
    const filtEdges   = edges.filter(e => filteredIds.has(e.source) && filteredIds.has(e.target));
    drawGraph(filtered, filtEdges, svgRef.current, setSelected, simRef);
  }, [nodes, edges, filter, view]);

  // Redraw Neo4j relationship graph when data or rel-type filter changes
  useEffect(() => {
    if (view !== 'rel' || !neo4jSvgRef.current) return;
    drawNeo4jGraph(visibleNeo4jNodes, visibleNeo4jEdges, neo4jSvgRef.current, neo4jSimRef);
  }, [visibleNeo4jNodes, visibleNeo4jEdges, view]);

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

  // Stellar tab data: prefer live WS feed, fall back to fetched HTTP data.
  const liveNodes   = Array.isArray(state.graphNodes) ? state.graphNodes : [];
  const liveEdges   = Array.isArray(state.graphEdges) ? state.graphEdges : [];
  const stellarNodes = liveNodes.length > 0 ? liveNodes : nodes;
  const stellarEdges = liveEdges.length > 0 ? liveEdges : edges;

  // ── RENDER ─────────────────────────────────────────────────────────────────
  return React.createElement('div', {
    'data-view-mode': vm,
    className: vm === 'CLIENT' ? 'client-mode' : undefined,
    style: { display:'flex', flexDirection:'column', height:'100%', padding:16, background:'var(--bg-base)', gap:12, overflowY:'auto' }
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
        React.createElement(TabBtn, { label:'✨ Stellar',  active: view==='stellar', onClick:()=>setView('stellar') }),
        React.createElement(TabBtn, { label:'⛓ Chains',   active: view==='chains', onClick:()=>setView('chains'), badge: chains.length||undefined }),
        React.createElement(TabBtn, { label:'🗺 Graph',    active: view==='graph',  onClick:()=>{ setView('graph'); setTimeout(loadGraph,50); } }),
        React.createElement(TabBtn, {
          label:'🔗 Relationships',
          active: view==='rel',
          onClick:()=>{ setView('rel'); if (state.sessionId) { loadNeo4jGraph(state.sessionId); } },
          badge: neo4jGraph.edges.length || undefined,
        }),
        React.createElement(TabBtn, {
          label:'🛤 Attack Paths',
          active: view==='paths',
          onClick:()=>{ setView('paths'); if (state.sessionId) { loadNeo4jPaths(state.sessionId); } },
          badge: neo4jPaths.length || undefined,
        }),
        React.createElement(TabBtn, { label:'🛡 MITRE',    active: view==='mitre',  onClick:()=>setView('mitre'), badge: mitreMap.length||undefined }),
        React.createElement('div', { style:{ width:1, height:18, background:'var(--border-light)' } }),
        React.createElement('button', {
          onClick: ()=>{ loadGraph(); loadChainAnalyses(); if(state.sessionId){loadNeo4jGraph(state.sessionId);loadNeo4jPaths(state.sessionId);} },
          style:{ padding:'5px 11px', borderRadius:6, border:'1px solid var(--border-light)',
                  background:'rgba(255,255,255,0.04)', color:'var(--text-secondary)', cursor:'pointer', fontSize:11 }
        }, '↻ Refresh'),
      )
    ),

    // ══════════════════════════════════════════════════════════════════════════
    // VIEW: STELLAR (NEW — cinematic particle starburst)
    // ══════════════════════════════════════════════════════════════════════════
    view === 'stellar' && React.createElement(StellarParticleCanvas, {
      nodes: stellarNodes,
      edges: stellarEdges,
    }),

    // ── No session ───────────────────────────────────────────────────────────
    view !== 'stellar' && !state.sessionId && React.createElement('div', {
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
                border:`1px solid ${active?col:'var(--border-light)'}`,
                background: active?'rgba(255,255,255,0.06)':'rgba(0,0,0,0.5)',
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
                  background: 'rgba(255,255,255,0.04)',
                  border:`1px solid ${SEV_COLOR[selected.severity?.toUpperCase()]||'var(--border)'}`,
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
    ),

    // ══════════════════════════════════════════════════════════════════════════
    // VIEW: RELATIONSHIP GRAPH (Neo4j)
    // ══════════════════════════════════════════════════════════════════════════
    view === 'rel' && state.sessionId && React.createElement('div', {
      style: { display:'flex', flexDirection:'column', gap:10, flex:1 }
    },
      neo4jAvailable === false
        ? React.createElement(Neo4jSetup, {
            onConnected: () => {
              if (state.sessionId) {
                loadNeo4jGraph(state.sessionId);
                loadNeo4jPaths(state.sessionId);
              }
            }
          })
        : React.createElement(React.Fragment, null,
            // Rel-type filter bar
            neo4jRelTypes.length > 0 && React.createElement('div', {
              style:{ display:'flex', gap:5, flexWrap:'wrap', alignItems:'center' }
            },
              React.createElement('span', { style:{fontSize:10, color:'var(--text-muted)', marginRight:2} }, 'Filter:'),
              ['all', ...neo4jRelTypes].map(rt =>
                React.createElement('button', {
                  key: rt,
                  onClick: () => setRelFilter(rt),
                  style:{
                    padding:'3px 9px', borderRadius:12, fontSize:9, cursor:'pointer',
                    fontFamily:'var(--font-mono)', fontWeight:600,
                    border: relFilter===rt ? `1px solid ${REL_COLOR[rt]||'var(--cyan)'}` : '1px solid var(--border-light)',
                    background: relFilter===rt ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.03)',
                    color: relFilter===rt ? (REL_COLOR[rt]||'var(--cyan)') : 'var(--text-muted)',
                  }
                }, rt)
              )
            ),
            // Stats strip
            React.createElement('div', { style:{fontSize:10, color:'var(--text-muted)'} },
              `${visibleNeo4jNodes.length} nodes · ${visibleNeo4jEdges.length} relationships`
              + (relFilter !== 'all' ? ` (filtered: ${relFilter})` : '')
            ),
            // SVG canvas
            neo4jGraph.nodes.length === 0
              ? React.createElement('div', {
                  style:{ padding:'40px 24px', borderRadius:10, background:'var(--bg-surface)',
                          border:'1px dashed var(--border)', textAlign:'center', color:'var(--text-muted)', fontSize:11 }
                }, 'No semantic relationships captured yet. Relationships are inferred automatically as tools run.')
              : React.createElement('svg', {
                  ref: neo4jSvgRef,
                  style:{ width:'100%', height:520, borderRadius:10, border:'1px solid var(--border)',
                          background:'var(--bg-surface)' }
                }),
            // Legend
            React.createElement('div', { style:{ display:'flex', gap:8, flexWrap:'wrap', marginTop:2 } },
              Object.entries(REL_COLOR).slice(0,8).map(([rt, col]) =>
                React.createElement('div', { key:rt, style:{ display:'flex', alignItems:'center', gap:4, fontSize:9, color:'var(--text-muted)' } },
                  React.createElement('div', { style:{ width:20, height:2, background:col, borderRadius:1 } }),
                  rt.replace(/_/g,' ')
                )
              )
            )
          )
    ),

    // ══════════════════════════════════════════════════════════════════════════
    // VIEW: ATTACK PATHS (Neo4j shortest paths)
    // ══════════════════════════════════════════════════════════════════════════
    view === 'paths' && state.sessionId && React.createElement('div', {
      style: { display:'flex', flexDirection:'column', gap:10 }
    },
      neo4jAvailable === false
        ? React.createElement(Neo4jSetup, {
            onConnected: () => {
              if (state.sessionId) {
                loadNeo4jGraph(state.sessionId);
                loadNeo4jPaths(state.sessionId);
              }
            }
          })
        : neo4jPaths.length === 0
          ? React.createElement('div', {
              style:{ padding:'40px 24px', borderRadius:10, background:'var(--bg-surface)',
                      border:'1px dashed var(--border)', textAlign:'center', color:'var(--text-muted)', fontSize:11 }
            }, 'No attack paths found yet. Paths appear once Neo4j has enough host → access relationships.')
          : React.createElement(React.Fragment, null,
              React.createElement('div', { style:{ fontSize:11, color:'var(--text-muted)', marginBottom:4 } },
                `${neo4jPaths.length} shortest path${neo4jPaths.length!==1?'s':''} from Host → Access`
              ),
              neo4jPaths.map((path, pi) =>
                React.createElement('div', {
                  key: pi,
                  style:{
                    padding:'12px 14px', borderRadius:8, marginBottom:6,
                    background:'var(--bg-surface)', border:'1px solid var(--border)',
                  }
                },
                  React.createElement('div', { style:{ fontSize:10, color:'var(--text-muted)', marginBottom:6 } },
                    `Path ${pi+1} — length ${path.length}`
                  ),
                  // Path as a chain of nodes + rels
                  React.createElement('div', {
                    style:{ display:'flex', alignItems:'center', flexWrap:'wrap', gap:4 }
                  },
                    (path.nodes || []).map((pn, ni) =>
                      React.createElement(React.Fragment, { key: ni },
                        React.createElement('div', {
                          style:{
                            padding:'4px 10px', borderRadius:16, fontSize:10, fontFamily:'var(--font-mono)',
                            background: NODE_COLOR[((pn.node_type||'finding').toLowerCase())] || 'rgba(255,255,255,0.06)',
                            border:'1px solid rgba(255,255,255,0.12)',
                            color:'var(--text-primary)',
                          }
                        }, pn.label || pn.node_id),
                        ni < (path.nodes||[]).length-1 && React.createElement('div', {
                          style:{
                            fontSize:9, padding:'2px 6px', borderRadius:10,
                            background: 'rgba(255,255,255,0.04)',
                            color: REL_COLOR[(path.rels||[])[ni]] || 'var(--text-muted)',
                            border: `1px solid ${REL_COLOR[(path.rels||[])[ni]] || 'var(--border-light)'}`,
                            fontFamily:'var(--font-mono)', whiteSpace:'nowrap',
                          }
                        }, `→ ${((path.rels||[])[ni]||'').replace(/_/g,' ')} →`)
                      )
                    )
                  )
                )
              )
            )
    )
  );
}

// ── D3 Graph renderer (preserves original behaviour) ─────────────────────────
// Resolves CSS-var fills/strokes to literal rgb at the moment of render so
// SVG markers and paths (which can't accept var() strings directly) display
// correctly across the active theme.
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
      .append('path').attr('d','M0,-5L10,0L0,5').attr('fill', resolveCssVar(col, '#94A0C5'));
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
    .attr('stroke', d => resolveCssVar(SEV_EDGE_COLOR[d.severity||d.label?.toLowerCase()] || SEV_EDGE_COLOR.info, '#94A0C5'))
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
    .attr('fill', d => resolveCssVar(NODE_COLOR[d.node_type||d.type] || 'var(--text-muted)', '#4F5876'))
    .attr('fill-opacity', 0.18)
    .attr('stroke', d => resolveCssVar(NODE_COLOR[d.node_type||d.type] || 'var(--text-muted)', '#4F5876'))
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

// ── Neo4j Relationship Graph renderer ────────────────────────────────────────
function drawNeo4jGraph(nodes, edges, svgEl, simRef) {
  if (!window.d3 || !svgEl || !nodes.length) return;
  const d3 = window.d3;
  d3.select(svgEl).selectAll('*').remove();

  const W = svgEl.clientWidth  || 900;
  const H = svgEl.clientHeight || 520;

  const svg = d3.select(svgEl).attr('width', W).attr('height', H);

  // Resolve once per draw — markers need literal colours.
  const fallbackEdge = resolveCssVar('var(--border)', '#2D3F75');
  const usedColors = [...new Set(edges.map(e => resolveCssVar(REL_COLOR[e.rel_type] || 'var(--border)', fallbackEdge)))];

  // Arrow markers — one per rel type colour
  const defs = svg.append('defs');
  usedColors.forEach((col, i) => {
    defs.append('marker').attr('id', `neo-arr-${i}`)
      .attr('viewBox','0 -5 10 10').attr('refX',22).attr('refY',0)
      .attr('markerWidth',5).attr('markerHeight',5).attr('orient','auto')
      .append('path').attr('d','M0,-5L10,0L0,5').attr('fill', col);
  });
  const colorIndex = col => usedColors.indexOf(col);

  const g = svg.append('g');
  svg.call(d3.zoom().scaleExtent([0.1,4]).on('zoom', ev => g.attr('transform', ev.transform)));

  const ns = nodes.map(n => ({...n}));
  const edgeData = edges.map(e => ({...e}));

  const sim = d3.forceSimulation(ns)
    .force('link', d3.forceLink(edgeData).id(d => d.node_id).distance(120).strength(0.4))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(20));

  if (simRef) simRef.current = sim;

  // Edges
  const link = g.append('g').selectAll('line')
    .data(edgeData).join('line')
    .attr('stroke', d => resolveCssVar(REL_COLOR[d.rel_type] || 'var(--border)', fallbackEdge))
    .attr('stroke-width', 1.5)
    .attr('stroke-opacity', 0.7)
    .attr('marker-end', d => {
      const col = resolveCssVar(REL_COLOR[d.rel_type] || 'var(--border)', fallbackEdge);
      return `url(#neo-arr-${colorIndex(col)})`;
    });

  // Edge labels
  const edgeLabel = g.append('g').selectAll('text')
    .data(edgeData).join('text')
    .attr('font-size', 7).attr('font-family', 'monospace')
    .attr('fill', d => resolveCssVar(REL_COLOR[d.rel_type] || 'var(--border)', fallbackEdge))
    .attr('text-anchor', 'middle').attr('opacity', 0.8)
    .text(d => (d.rel_type || '').replace(/_/g,' '));

  // Nodes
  const nodeType = n => (n.node_type || 'finding').toLowerCase();
  const nodeGroup = g.append('g').selectAll('g')
    .data(ns).join('g')
    .attr('cursor','pointer')
    .call(d3.drag()
      .on('start', (ev,d) => { if(!ev.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',  (ev,d) => { d.fx=ev.x; d.fy=ev.y; })
      .on('end',   (ev,d) => { if(!ev.active) sim.alphaTarget(0); d.fx=null; d.fy=null; })
    );

  nodeGroup.append('circle')
    .attr('r', d => NODE_RADIUS[nodeType(d)] || 12)
    .attr('fill', d => resolveCssVar(NODE_COLOR[nodeType(d)] || 'var(--text-muted)', '#4F5876'))
    .attr('fill-opacity', 0.2)
    .attr('stroke', d => resolveCssVar(NODE_COLOR[nodeType(d)] || 'var(--text-muted)', '#4F5876'))
    .attr('stroke-width', 1.5);

  nodeGroup.append('text')
    .attr('text-anchor','middle').attr('dy','0.35em')
    .attr('font-size', 10).attr('pointer-events','none')
    .text(d => NODE_ICON[nodeType(d)] || '●');

  nodeGroup.append('text')
    .attr('text-anchor','middle').attr('dy', d => (NODE_RADIUS[nodeType(d)]||12)+12)
    .attr('font-size', 8).attr('fill', resolveCssVar('var(--text-muted)', '#4F5876')).attr('pointer-events','none')
    .text(d => (d.label||d.node_id||'').slice(0,22));

  nodeGroup.append('title').text(d => `${d.node_type||'node'}: ${d.label||d.node_id}`);

  sim.on('tick', () => {
    link
      .attr('x1', d => (d.source.x||0)).attr('y1', d => (d.source.y||0))
      .attr('x2', d => (d.target.x||0)).attr('y2', d => (d.target.y||0));
    edgeLabel
      .attr('x', d => ((d.source.x||0)+(d.target.x||0))/2)
      .attr('y', d => ((d.source.y||0)+(d.target.y||0))/2);
    nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
  });
}

window.AttackGraph = AttackGraph;
