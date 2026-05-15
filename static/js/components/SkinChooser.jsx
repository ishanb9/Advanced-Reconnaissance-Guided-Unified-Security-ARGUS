/* ═════════════════════════════════════════════════════════════
   SkinChooser — runtime visual-skin picker (v2 with role families)
   ─────────────────────────────────────────────────────────────
   ARGUS ships 18 distinct skins across three families:

   AESTHETIC (7) — pure visual treatments, role-neutral:
     stellar    — default cosmic-blue ARGUS look
     apollo     — NASA / SpaceX phosphor mission control
     tactical   — Palantir Gotham / Anduril defense C2
     bloomberg  — terminal amber-on-black trading floor
     glass      — visionOS hyperreal frosted depth
     editorial  — Stripe Press magazine-typography
     webgl      — Three.js spatial 3D scene (heavy)

   OPERATOR (6) — for red-team / pentest practitioners:
     veteran    — greybeard, dense, vim, MITRE raw, no chrome
     novice     — friendly, hints, plain-English MITRE, big icons
     genz       — vaporwave, RGB sweep, glitch FX, BANGER/FIRE labels
     redcell    — blood-red ops, stencil display, crosshair watermark
     hunter     — bug-bounty $$$ stack, P1/P2/P3 tiers, PWN badges
     ctf        — gamified, pixel font, FLAGS CAPTURED, point values

   MANAGEMENT (5) — for oversight / leadership / compliance:
     auditor    — read-only evidence + citation chain + hash watermark
     manager    — PM dashboard, progress bars, ETA, traffic-light status
     executive  — C-suite boardroom, ONE big number, QoQ trends
     cfo        — finance lens, $/ROI/budget burn, tabular numerics
     legal      — compliance, PCI/HIPAA/SOX/GDPR strips, citations

   The core ARGUS functionality (hacking, red-teaming, compromise
   assessment) is identical across every skin — only visuals change.
   Routing, agents, tool execution, findings, WebSocket events,
   keyboard shortcuts, and all data flows are skin-independent.

   How it works:
   - Each non-stellar skin lives at /static/css/skins/<id>.css
     and is loaded into a single <link id="argus-skin"> slot in
     index.html.  The skin id is reflected as data-skin="<id>" on
     <html> so CSS uses :root[data-skin="<id>"] selectors.
   - Choice is persisted in localStorage under argus.ui.skin.v1.
   - The WebGL skin lazy-loads its Three.js scene module so users
     who never select it pay no perf cost.
   - The popover groups skins by family with section headers so
     the chooser stays navigable as the catalog grows.
   ─────────────────────────────────────────────────────────────
*/
(function () {
  const { useState, useEffect, useRef } = React;

  const SKIN_KEY = 'argus.ui.skin.v1';

  // Skin catalog — kept in sync with skin CSS files.
  // family: 'aesthetic' | 'operator' | 'management'
  // swatches: [bg, accent, secondary, tertiary] for the thumbnail
  const SKINS = [
    // ── AESTHETIC ─────────────────────────────────────────────
    { id: 'stellar',   family: 'aesthetic', label: 'Stellar Ops',
      tagline: 'Default · cosmic-blue cockpit',           mood: 'ARGUS core',
      swatches: ['#04050E', '#4FA8FF', '#38E5FF', '#7B6CF6'], icon: '◉' },
    { id: 'apollo',    family: 'aesthetic', label: 'Apollo',
      tagline: 'Mission Control · phosphor terminal',     mood: 'NASA · JPL · SpaceX',
      swatches: ['#0A0A0A', '#FFB000', '#33FF66', '#FF3030'], icon: '◐' },
    { id: 'tactical',  family: 'aesthetic', label: 'Tactical',
      tagline: 'Defense C2 · topographic overlay',        mood: 'Palantir · Anduril',
      swatches: ['#13180F', '#7BAB47', '#D9A441', '#C03C3C'], icon: '⌖' },
    { id: 'bloomberg', family: 'aesthetic', label: 'Trading Floor',
      tagline: 'Terminal · amber on black',               mood: 'Bloomberg · TradingView',
      swatches: ['#000000', '#FFB000', '#FF6600', '#00B050'], icon: '▦' },
    { id: 'glass',     family: 'aesthetic', label: 'Hyperreal Glass',
      tagline: 'visionOS · frosted depth',                 mood: 'Apple · spatial UI',
      swatches: ['#1A1B2E', '#A1A8FF', '#FF96D5', '#73E8FF'], icon: '◇' },
    { id: 'editorial', family: 'aesthetic', label: 'Editorial',
      tagline: 'Magazine · serif minimalism',              mood: 'Stripe Press',
      swatches: ['#FAFAF7', '#1A1A1A', '#A8311F', '#1A4D3A'], icon: 'A' },
    { id: 'webgl',     family: 'aesthetic', label: 'Spatial 3D',
      tagline: 'WebGL · orbital scene (heavy)',            mood: 'Three.js · Bruno Simon',
      swatches: ['#000814', '#00D9FF', '#FF6FB5', '#8A4FFF'], icon: '◈' },

    // ── OPERATOR ─────────────────────────────────────────────
    { id: 'veteran',   family: 'operator', label: 'Veteran',
      tagline: 'Greybeard · terminal-dense, raw MITRE',    mood: 'Decade-plus operator',
      swatches: ['#0C0C0C', '#7AB87A', '#C8C8C8', '#C44949'], icon: '$' },
    { id: 'novice',    family: 'operator', label: 'Novice',
      tagline: 'Learning · hints + plain-English MITRE',   mood: 'Junior · trainee',
      swatches: ['#F5F8FA', '#2EB68F', '#3FA7E0', '#E0594E'], icon: '💡' },
    { id: 'genz',      family: 'operator', label: 'GenZ',
      tagline: 'Vaporwave · RGB sweep · BANGER 🔥',         mood: 'Cyberpunk native',
      swatches: ['#14002A', '#FF55E0', '#00F0FF', '#B14AFF'], icon: '✺' },
    { id: 'redcell',   family: 'operator', label: 'Red Cell',
      tagline: 'Adversary · stencil display · crosshair',  mood: 'Pure offensive',
      swatches: ['#0E0606', '#C92020', '#F5E8E0', '#C2884A'], icon: '◢' },
    { id: 'hunter',    family: 'operator', label: 'Bug Hunter',
      tagline: 'Bounty $$$ stack · P1 PWN badges',         mood: 'Bug-bounty researcher',
      swatches: ['#1A1612', '#E8B53A', '#4EC8A4', '#E04A4A'], icon: '💰' },
    { id: 'ctf',       family: 'operator', label: 'CTF',
      tagline: 'Gamified · FLAGS captured · pixel font',   mood: 'Capture-the-flag',
      swatches: ['#0F0524', '#FF33A1', '#00F5FF', '#3CFF8C'], icon: '🚩' },

    // ── MANAGEMENT ───────────────────────────────────────────
    { id: 'auditor',   family: 'management', label: 'Auditor',
      tagline: 'Read-only · evidence + citation chain',    mood: 'Audit / forensic',
      swatches: ['#F4F4F2', '#2C4A6B', '#1F2937', '#8B2C2C'], icon: '§' },
    { id: 'manager',   family: 'management', label: 'Manager',
      tagline: 'PM dashboard · progress bars · ETA',       mood: 'Team lead · scrum',
      swatches: ['#F7F9FC', '#4364E2', '#2EB68F', '#DC3545'], icon: '◧' },
    { id: 'executive', family: 'management', label: 'Executive',
      tagline: 'Boardroom · ONE big number · QoQ trends',  mood: 'CEO / CISO / Board',
      swatches: ['#FFFFFF', '#0F172A', '#991B1B', '#166534'], icon: '◆' },
    { id: 'cfo',       family: 'management', label: 'CFO',
      tagline: 'Finance · $ cost-of-fix · ROI',            mood: 'Budget · finance',
      swatches: ['#F8FAFC', '#0F766E', '#0E8A4A', '#B91C1C'], icon: '$' },
    { id: 'legal',     family: 'management', label: 'Legal',
      tagline: 'Compliance · PCI/HIPAA/SOX/GDPR strips',   mood: 'GRC · counsel',
      swatches: ['#FFFEF5', '#1E40AF', '#991B1B', '#047857'], icon: '⚖' },
  ];

  const FAMILIES = [
    { id: 'aesthetic',  label: 'Aesthetic',  desc: 'Pure visual treatments — role-neutral' },
    { id: 'operator',   label: 'Operator',   desc: 'For red-team / pentest practitioners' },
    { id: 'management', label: 'Management', desc: 'For oversight / leadership / compliance' },
  ];

  function loadSkin() {
    try {
      const v = localStorage.getItem(SKIN_KEY);
      return (v && SKINS.find(s => s.id === v)) ? v : 'stellar';
    } catch { return 'stellar'; }
  }
  function saveSkin(id) {
    try { localStorage.setItem(SKIN_KEY, id); } catch {}
  }

  // ── Skin application ──────────────────────────────────────
  // Swaps the <link id="argus-skin"> href + sets data-skin attribute.
  // Tears down the WebGL scene when leaving the webgl skin so the
  // canvas + animation loop don't leak GPU memory.
  function applySkin(id) {
    const safeId = SKINS.find(s => s.id === id) ? id : 'stellar';
    document.documentElement.setAttribute('data-skin', safeId);

    let link = document.getElementById('argus-skin');
    if (!link) {
      link = document.createElement('link');
      link.id = 'argus-skin';
      link.rel = 'stylesheet';
      document.head.appendChild(link);
    }
    if (safeId === 'stellar') {
      link.href = '';
      link.removeAttribute('href');
    } else {
      link.href = `/static/css/skins/${safeId}.css?v=1`;
    }

    // WebGL — lazy-mount/unmount Three.js scene
    if (safeId === 'webgl') {
      if (!window.__argusWebglScene) {
        const s = document.createElement('script');
        s.id = 'argus-webgl-bootstrap';
        s.src = '/static/js/skins/webgl_scene.js?v=1';
        s.async = true;
        document.head.appendChild(s);
      } else {
        try { window.__argusWebglScene.mount && window.__argusWebglScene.mount(); } catch (_) {}
      }
    } else {
      try { window.__argusWebglScene && window.__argusWebglScene.unmount && window.__argusWebglScene.unmount(); } catch (_) {}
    }
  }

  // Expose loader API at the global scope so app.jsx can call it
  // on cold-boot before the chooser ever mounts.
  window.ArgusSkin = {
    list:    () => SKINS.slice(),
    families: () => FAMILIES.slice(),
    load:    loadSkin,
    save:    saveSkin,
    apply:   applySkin,
    current: () => document.documentElement.getAttribute('data-skin') || loadSkin(),
  };

  // ───────────────────────────────────────────────────────────
  function SkinChooser() {
    const [current, setCurrent] = useState(loadSkin());
    const [open, setOpen] = useState(false);
    const [activeFamily, setActiveFamily] = useState(() => {
      const cur = SKINS.find(s => s.id === loadSkin());
      return cur ? cur.family : 'aesthetic';
    });
    const ref = useRef(null);

    useEffect(() => {
      function close(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
      if (open) document.addEventListener('mousedown', close);
      return () => document.removeEventListener('mousedown', close);
    }, [open]);

    function pick(id) {
      setCurrent(id);
      saveSkin(id);
      applySkin(id);
      setOpen(false);
    }

    const meta = SKINS.find(s => s.id === current) || SKINS[0];
    const filtered = SKINS.filter(s => s.family === activeFamily);

    return React.createElement('div', { ref, style: { position: 'relative' } },
      // Trigger button
      React.createElement('button', {
        onClick: () => setOpen(o => !o),
        title: `Visual skin: ${meta.label} — click to switch`,
        style: {
          display: 'flex', alignItems: 'center', gap: 7,
          padding: '4px 10px', borderRadius: 18, cursor: 'pointer',
          background: 'var(--bg-panel)', border: '1px solid var(--border-dim)',
          color: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-ui)',
          transition: 'border-color 0.15s, color 0.15s',
        },
        onMouseEnter: e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-primary)'; },
        onMouseLeave: e => { e.currentTarget.style.borderColor = 'var(--border-dim)'; e.currentTarget.style.color = 'var(--text-secondary)'; },
      },
        // Mini palette swatch (4 dots)
        React.createElement('span', {
          style: { display: 'flex', gap: 2, alignItems: 'center', flexShrink: 0 }
        },
          meta.swatches.slice(0, 4).map((c, i) =>
            React.createElement('span', {
              key: i,
              style: {
                width: 7, height: 7, borderRadius: '50%',
                background: c,
                border: '1px solid rgba(255,255,255,0.08)',
              }
            })
          )
        ),
        React.createElement('span', { style: { fontWeight: 600 } }, meta.label),
        React.createElement('span', { style: { fontSize: 9, opacity: 0.5 } }, '▾')
      ),

      // Popover with family tabs + skin grid
      open && React.createElement('div', {
        style: {
          position: 'absolute', top: 'calc(100% + 6px)', right: 0, zIndex: 1300,
          width: 360, maxHeight: '78vh',
          display: 'flex', flexDirection: 'column',
          padding: 0, borderRadius: 12,
          background: 'var(--bg-surface)', border: '1px solid var(--border-bright)',
          boxShadow: '0 20px 48px rgba(0,0,0,0.7)',
          overflow: 'hidden',
        }
      },
        // Header
        React.createElement('div', {
          style: {
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '10px 14px',
            borderBottom: '1px solid var(--border-dim)',
            flexShrink: 0,
          }
        },
          React.createElement('span', {
            style: { fontSize: 9, color: 'var(--text-muted)', letterSpacing: 1.8,
                     textTransform: 'uppercase', fontWeight: 700 }
          }, 'Visual Skin'),
          React.createElement('span', {
            style: { fontSize: 9, color: 'var(--text-muted)', letterSpacing: 0.5 }
          }, `${SKINS.length} skins · 3 families`)
        ),

        // Family tabs
        React.createElement('div', {
          style: {
            display: 'flex', borderBottom: '1px solid var(--border-dim)',
            flexShrink: 0,
          }
        },
          FAMILIES.map(fam => {
            const active = fam.id === activeFamily;
            const count = SKINS.filter(s => s.family === fam.id).length;
            return React.createElement('div', {
              key: fam.id,
              onClick: () => setActiveFamily(fam.id),
              style: {
                flex: 1, padding: '8px 10px',
                fontSize: 11, fontWeight: 700, letterSpacing: 1,
                textTransform: 'uppercase', textAlign: 'center',
                cursor: 'pointer',
                color: active ? 'var(--accent)' : 'var(--text-muted)',
                borderBottom: active ? '2px solid var(--accent)' : '2px solid transparent',
                background: active ? 'var(--accent-subtle)' : 'transparent',
                transition: 'all 0.15s',
              }
            },
              fam.label,
              React.createElement('span', {
                style: { marginLeft: 5, fontSize: 9, opacity: 0.7 }
              }, `(${count})`)
            );
          })
        ),

        // Family description
        React.createElement('div', {
          style: {
            padding: '6px 14px', fontSize: 10, color: 'var(--text-muted)',
            fontStyle: 'italic', letterSpacing: 0.3,
            borderBottom: '1px solid var(--border-dim)',
            flexShrink: 0,
          }
        }, FAMILIES.find(f => f.id === activeFamily)?.desc),

        // Scrollable skin list
        React.createElement('div', {
          style: { flex: 1, overflowY: 'auto', padding: 8 }
        },
          filtered.map(s => {
            const active = s.id === current;
            return React.createElement('div', {
              key: s.id,
              onClick: () => pick(s.id),
              style: {
                display: 'flex', alignItems: 'center', gap: 11,
                padding: '9px 10px', borderRadius: 8, cursor: 'pointer',
                background: active ? `linear-gradient(90deg, ${s.swatches[1]}1A, transparent)` : 'transparent',
                borderLeft: active ? `3px solid ${s.swatches[1]}` : '3px solid transparent',
                transition: 'background 0.12s',
                marginBottom: 2,
              },
              onMouseEnter: e => { if (!active) e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; },
              onMouseLeave: e => { if (!active) e.currentTarget.style.background = 'transparent'; },
            },
              // Thumbnail
              React.createElement('div', {
                style: {
                  width: 44, height: 44, borderRadius: 8, flexShrink: 0,
                  background: `linear-gradient(135deg, ${s.swatches[0]} 0%, ${s.swatches[1]} 100%)`,
                  border: `1px solid ${s.swatches[1]}66`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: s.swatches[2],
                  fontSize: 22, fontWeight: 700,
                  boxShadow: active ? `0 0 12px ${s.swatches[1]}55` : 'none',
                  fontFamily: s.id === 'editorial' ? 'serif' : 'monospace',
                }
              }, s.icon),

              React.createElement('div', { style: { flex: 1, minWidth: 0 } },
                React.createElement('div', {
                  style: {
                    fontSize: 13, fontWeight: 700,
                    color: active ? s.swatches[1] : 'var(--text-primary)',
                  }
                }, s.label),
                React.createElement('div', {
                  style: { fontSize: 10, color: 'var(--text-muted)', marginTop: 1,
                           overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
                }, s.tagline),
                React.createElement('div', {
                  style: { display: 'flex', gap: 2, marginTop: 5, alignItems: 'center' }
                },
                  s.swatches.map((c, i) =>
                    React.createElement('span', {
                      key: i,
                      style: { width: 9, height: 9, borderRadius: 2, background: c,
                               border: '1px solid rgba(255,255,255,0.08)' }
                    })
                  ),
                  React.createElement('span', {
                    style: {
                      fontSize: 9, color: 'var(--text-muted)', marginLeft: 6,
                      letterSpacing: 0.5, textTransform: 'uppercase',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }
                  }, s.mood)
                )
              ),

              active && React.createElement('span', {
                style: { color: s.swatches[1], fontSize: 14, flexShrink: 0 }
              }, '✓')
            );
          })
        ),

        // Footer
        React.createElement('div', {
          style: {
            padding: '8px 14px', fontSize: 9, color: 'var(--text-muted)',
            borderTop: '1px solid var(--border-dim)',
            letterSpacing: 0.4, lineHeight: 1.5,
            flexShrink: 0,
          }
        },
          'Saved per-browser · Live preview · ARGUS core functionality is identical across every skin'
        )
      )
    );
  }

  window.SkinChooser = SkinChooser;
})();
