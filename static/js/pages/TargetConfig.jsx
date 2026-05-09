// ═══════════════════════════════════════════════════════════
// TargetConfig.jsx — Session creation & pentest launcher
// ═══════════════════════════════════════════════════════════

const { useState } = React;

const TARGET_TYPES = [
  { value: 'linux',    label: 'Linux Server',      icon: '🐧' },
  { value: 'windows',  label: 'Windows Server',    icon: '🪟' },
  { value: 'web',      label: 'Web Application',   icon: '🌐' },
  { value: 'ctf',      label: 'CTF / HTB / THM',   icon: '🏁' },
  { value: 'network',  label: 'Network Range',     icon: '📡' },
  { value: 'ad',       label: 'Active Directory',  icon: '🏢' },
  { value: 'unknown',  label: 'Unknown / Auto',    icon: '❓' },
];

const ALL_PHASES = [
  { key: 'recon',        label: 'Recon',        desc: 'nmap, whatweb, dnsrecon, enum4linux' },
  { key: 'vuln_id',      label: 'Vuln ID',      desc: 'NSE scripts, searchsploit, sslscan' },
  { key: 'osint',        label: 'OSINT',        desc: 'NVD, ExploitDB lookups' },
  { key: 'exploit',      label: 'Exploit',      desc: 'MSF, hydra, sqlmap — requires confirm' },
  { key: 'post_exploit', label: 'Post Exploit', desc: 'Credential harvest, network map' },
  { key: 'privesc',      label: 'PrivEsc',      desc: 'linPEAS, SUID, GTFOBins, sudo' },
  { key: 'iot',          label: 'IoT',          desc: 'Device fingerprint, default creds, MQTT/CoAP/Modbus, firmware CVEs (auto-detected)' },
];

// Detect target shape — mirrors server-side normalise_target() classification.
// Returns one of: SINGLE | CIDR | MULTI | URL | DOMAIN | APP | null
const _IPV4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const _IPV6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;
const _URL  = /^https?:\/\//i;
const _FQDN = /^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$/;
const _HOSTPORT = /^[A-Za-z0-9.-]+:\d{1,5}$/;

function detectMode(val) {
  if (!val || !val.trim()) return null;
  const v = val.trim();
  if (v.includes(',')) return 'MULTI';
  if (v.includes('/') && !_URL.test(v)) return 'CIDR';
  if (_URL.test(v))                     return 'URL';
  if (_IPV4.test(v) || _IPV6.test(v))   return 'SINGLE';
  if (_FQDN.test(v))                    return 'DOMAIN';
  if (_HOSTPORT.test(v))                return 'DOMAIN';   // host:port
  return v.includes('.') ? 'DOMAIN' : 'SINGLE';
}

const MODE_META = {
  SINGLE: { label: 'IP Address',     color: '#00d4ff', icon: '◉',  desc: 'Single host (IPv4 or IPv6)' },
  CIDR:   { label: 'Network Range',  color: '#73d13d', icon: '◫',  desc: 'All live hosts in CIDR' },
  MULTI:  { label: 'Multi-Target',   color: '#faad14', icon: '⬡',  desc: 'Each target tested in parallel' },
  DOMAIN: { label: 'Domain / Host',  color: '#7B6CF6', icon: '◆',  desc: 'Hostname or FQDN — resolves to IP for network probes' },
  URL:    { label: 'URL / Web App',  color: '#FF8C42', icon: '◊',  desc: 'Web application target — focus on HTTP-layer testing' },
  APP:    { label: 'Application',    color: '#FF4560', icon: '⊠',  desc: 'Pure application target — skip network probes' },
};

function TargetConfig() {
  const { state, dispatch, connectWS } = window.useStore();
  const { sessions } = state;

  // Derive recent unique targets from session history
  const recentTargets = React.useMemo(() => {
    const seen = new Set();
    return (sessions || [])
      .filter(s => s.target_ip && !seen.has(s.target_ip) && seen.add(s.target_ip))
      .slice(0, 6)
      .map(s => ({
        ip:          s.target_ip,
        type:        s.target_type || 'unknown',
        last_status: s.status,
        last_phase:  s.current_phase,
        findings:    s.findings_count || 0,
      }));
  }, [sessions]);

  const [form, setForm] = useState({
    target_ip:          '',
    target_hostname:    '',
    target_type:        'unknown',
    scope:              '',
    notes:              '',
    auto_exploit:       false,
    threading_enabled:  true,
    max_threads:        5,
    max_parallel_hosts: 5,
    phases:             ALL_PHASES.map(p => p.key),
    // ── Mission Brief (Improvement #1) ─────────────────────────────────
    mb_objective:        'Establish foothold, capture flags, and demonstrate impact.',
    mb_win_conditions:   'shell_obtained, user_flag_captured, root_flag_captured',
    mb_scope_in:         '',
    mb_scope_out:        '',
    mb_time_budget_min:  240,
    mb_noise_budget:     70,
    mb_blast_radius:     'active',
  });

  // Auto-detect mode from target input
  const targetMode = detectMode(form.target_ip);

  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');
  const [launched, setLaunched] = useState(null);

  function set(key, val) { setForm(f => ({ ...f, [key]: val })); }

  function togglePhase(key) {
    set('phases', form.phases.includes(key)
      ? form.phases.filter(p => p !== key)
      : [...form.phases, key]
    );
  }

  async function launch() {
    if (!form.target_ip.trim()) { setError('Target is required (IP, CIDR, domain, or URL)'); return; }
    setError(''); setLoading(true);
    try {
      // Assemble the formal mission brief from the dedicated form fields
      const splitList = s => (s || '')
        .split(/[,\n]/)
        .map(x => x.trim())
        .filter(Boolean);
      const mission_brief = {
        objective:        form.mb_objective || '',
        win_conditions:   splitList(form.mb_win_conditions),
        scope_in:         splitList(form.mb_scope_in),
        scope_out:        splitList(form.mb_scope_out),
        time_budget_min:  Number(form.mb_time_budget_min) || 0,
        noise_budget:     Math.max(0, Math.min(100, Number(form.mb_noise_budget) || 0)),
        blast_radius:     form.mb_blast_radius || 'active',
        notes:            form.notes || null,
      };
      const payload = { ...form, mission_brief };
      // Strip the local-only mb_* fields so the backend schema is clean
      Object.keys(payload).forEach(k => { if (k.startsWith('mb_')) delete payload[k]; });
      const res = await window.API.sessions.create(payload);
      const session = res.session;
      dispatch({ type: 'SET_SESSION', payload: session });
      connectWS(session.id);
      setLaunched(session);
      // Auto-navigate to Mission Control after short delay
      // so user sees the attack plan as it builds
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('navigate', { detail: 'mission' }));
      }, 1500);
    } catch (e) {
      setError(e.message || 'Failed to start session');
    }
    setLoading(false);
  }

  // Styles
  const card = {
    background: 'var(--bg-surface)', border: '1px solid var(--border)',
    borderRadius: 10, padding: '16px 18px', marginBottom: 14,
    boxShadow: '0 1px 4px rgba(0,0,0,0.3)',
  };
  const label = { fontSize: 11, color: 'var(--text-muted)', marginBottom: 5,
                  fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 0.8 };
  const inp = {
    width: '100%', background: 'var(--bg-panel)',
    border: '1px solid var(--border)', borderRadius: 'var(--radius)',
    color: 'var(--text-primary)', fontSize: 12, padding: '7px 10px',
    outline: 'none', fontFamily: 'var(--font-mono)', boxSizing: 'border-box'
  };
  const row = { marginBottom: 14 };

  if (launched) {
    return React.createElement('div', {
      style: {
        maxWidth: 520, margin: '60px auto', padding: 40,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14,
        background: 'var(--bg-surface)', border: '1px solid rgba(74,222,128,0.25)',
        borderRadius: 16, textAlign: 'center', position: 'relative', overflow: 'hidden',
      }
    },
      // Glow orb
      React.createElement('div', {
        style: {
          position: 'absolute', top: -60, left: '50%', transform: 'translateX(-50%)',
          width: 200, height: 200, borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(74,222,128,0.15) 0%, transparent 70%)',
          pointerEvents: 'none',
        }
      }),
      React.createElement('div', {
        style: { fontSize: 40, animation: 'pulse 1s ease-in-out 3', lineHeight: 1 }
      }, '◉'),
      React.createElement('div', { style: { fontSize: 20, fontWeight: 800, color: 'var(--low)', letterSpacing: -0.5 } },
        'Session Active'),
      React.createElement('div', {
        style: {
          fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontSize: 18, fontWeight: 700,
          background: 'var(--bg-panel)', border: '1px solid var(--border-light)',
          padding: '6px 18px', borderRadius: 8,
        }
      }, launched.target_ip),
      React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' } },
        `ID: ${launched.id}`),
      React.createElement('div', { style: { color: 'var(--text-muted)', fontSize: 12 } },
        detectMode(launched.target_ip) === 'CIDR'
          ? 'Discovering live hosts in range… Redirecting to Mission Control.'
          : detectMode(launched.target_ip) === 'MULTI'
            ? `Launching parallel scan on ${launched.target_ip.split(',').length} targets… Redirecting to Mission Control.`
            : 'Agents are initializing… Redirecting to Mission Control.'),
      React.createElement('div', { style: { display: 'flex', gap: 10, marginTop: 8 } },
        React.createElement('button', {
          onClick: () => setLaunched(null),
          style: {
            padding: '8px 18px', borderRadius: 7, border: '1px solid var(--border-light)',
            background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12, fontFamily: 'var(--font-ui)',
          }
        }, '+ New Session'),
        React.createElement('button', {
          onClick: () => window.dispatchEvent(new CustomEvent('navigate', { detail: 'mission' })),
          style: {
            padding: '8px 18px', borderRadius: 7, cursor: 'pointer', fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-ui)',
            border: '1px solid var(--accent)', background: 'var(--accent)', color: '#0D0E14',
            boxShadow: '0 0 14px var(--accent-glow)',
          }
        }, '→ Mission Control')
      )
    );
  }

  return React.createElement('div', {
    style: { padding: 16, maxWidth: 740, margin: '0 auto' }
  },
    React.createElement('div', { className: 'page-header', style: { marginBottom: 18 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '🎯 Target Config'),
        React.createElement('div', { className: 'page-subtitle' }, 'Configure and launch a new autonomous pentest')
      )
    ),

    // Recent targets quick-launch
    recentTargets.length > 0 && React.createElement('div', {
      style: { marginBottom: 16 }
    },
      React.createElement('div', {
        style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 8,
                 textTransform: 'uppercase', letterSpacing: 1, fontFamily: 'var(--font-mono)' }
      }, '⏱ Recent Targets'),
      React.createElement('div', {
        style: { display: 'flex', gap: 8, flexWrap: 'wrap' }
      },
        recentTargets.map((t, i) => {
          const statusColors = {
            completed: 'var(--cyan)', active: 'var(--green)',
            failed: 'var(--red)', paused: 'var(--amber)'
          };
          const typeIcons = {
            linux: '🐧', windows: '🪟', web: '🌐',
            ctf: '🏁', network: '📡', ad: '🏢', unknown: '❓'
          };
          return React.createElement('div', {
            key: i,
            onClick: () => {
              set('target_ip', t.ip);
              set('target_type', t.type || 'unknown');
            },
            style: {
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '7px 12px', borderRadius: 6, cursor: 'pointer',
              border: form.target_ip === t.ip
                ? '1px solid var(--cyan)'
                : '1px solid var(--border)',
              background: form.target_ip === t.ip
                ? 'rgba(0,212,255,0.06)'
                : 'var(--bg-surface)',
              transition: 'all 0.15s',
            }
          },
            React.createElement('span', { style: { fontSize: 14 } },
              typeIcons[t.type] || '❓'),
            React.createElement('div', null,
              React.createElement('div', {
                style: { fontSize: 12, fontFamily: 'var(--font-mono)',
                         fontWeight: 600, color: 'var(--text-primary)' }
              }, t.ip),
              React.createElement('div', {
                style: { fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }
              }, [
                t.type?.toUpperCase(),
                t.last_phase?.toUpperCase(),
                t.findings > 0 ? `${t.findings} findings` : null
              ].filter(Boolean).join(' · '))
            ),
            t.last_status && React.createElement('span', {
              style: {
                fontSize: 8, padding: '1px 5px', borderRadius: 3, marginLeft: 'auto',
                color: statusColors[t.last_status] || 'var(--text-muted)',
                border: `1px solid ${(statusColors[t.last_status] || 'var(--border-light)') + '40'}`,
                background: (statusColors[t.last_status] || 'var(--border-light)') + '10',
                fontFamily: 'var(--font-mono)',
              }
            }, t.last_status.toUpperCase())
          );
        })
      )
    ),

    // Target input — single IP / CIDR / multi
    React.createElement('div', { style: { ...card } },

      // Label row with live mode badge
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 } },
        React.createElement('div', { style: label }, 'Target  *'),
        targetMode && React.createElement('div', {
          style: {
            display: 'flex', alignItems: 'center', gap: 5,
            padding: '2px 10px', borderRadius: 20, fontSize: 10, fontWeight: 700,
            fontFamily: 'var(--font-mono)', letterSpacing: 0.8,
            background: MODE_META[targetMode].color + '15',
            border: `1px solid ${MODE_META[targetMode].color}50`,
            color: MODE_META[targetMode].color,
          }
        },
          React.createElement('span', null, MODE_META[targetMode].icon),
          React.createElement('span', null, MODE_META[targetMode].label),
        )
      ),

      // Helper text describing accepted formats
      React.createElement('div', {
        style: {
          fontSize: 10, color: 'var(--text-muted)', marginBottom: 6,
          letterSpacing: 0.3, lineHeight: 1.5,
        }
      }, 'Accepts IP, CIDR range, comma-separated list, hostname/FQDN, or full URL. Domains are auto-resolved before scanning. URLs route web-aware tools to the exact endpoint.'),

      // Main input — placeholder now reflects expanded scope
      React.createElement('input', {
        type: 'text',
        value: form.target_ip,
        placeholder: '10.10.10.5  ·  10.10.10.0/24  ·  app.example.com  ·  https://target.com/login',
        onChange: e => set('target_ip', e.target.value),
        style: {
          ...inp,
          borderColor: targetMode ? MODE_META[targetMode].color + '50' : 'var(--border)',
          fontSize: 13,
        }
      }),

      // Format hint chips
      React.createElement('div', {
        style: { display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }
      },
        [
          { example: '10.10.10.5',                  label: 'IP' },
          { example: '10.10.10.0/24',               label: 'CIDR' },
          { example: '10.0.1.1,10.0.1.2',           label: 'Multi' },
          { example: 'app.example.com',             label: 'Domain' },
          { example: 'https://target.com/login',    label: 'URL' },
        ].map(({ example, label: chipLabel }) =>
          React.createElement('div', {
            key: example,
            onClick: () => set('target_ip', example),
            style: {
              padding: '3px 10px', borderRadius: 4, cursor: 'pointer',
              fontSize: 10, fontFamily: 'var(--font-mono)',
              border: '1px solid var(--border)',
              color: form.target_ip === example ? 'var(--cyan)' : 'var(--text-muted)',
              background: form.target_ip === example ? 'rgba(0,212,255,0.08)' : 'transparent',
              transition: 'all 0.12s',
            }
          }, chipLabel + ': ' + example)
        )
      ),

      // CIDR/Multi extra options
      targetMode && targetMode !== 'SINGLE' && React.createElement('div', {
        style: {
          marginTop: 12, padding: '10px 14px',
          background: MODE_META[targetMode].color + '08',
          border: `1px solid ${MODE_META[targetMode].color}25`,
          borderRadius: 6,
        }
      },
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' } },
          React.createElement('div', { style: { fontSize: 11, color: MODE_META[targetMode].color, fontWeight: 600 } },
            MODE_META[targetMode].icon + ' ' + MODE_META[targetMode].desc),
          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto' } },
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } },
              'Parallel hosts:'),
            React.createElement('select', {
              value: form.max_parallel_hosts,
              onChange: e => set('max_parallel_hosts', Number(e.target.value)),
              style: {
                ...inp, width: 64, padding: '4px 6px',
                border: `1px solid ${MODE_META[targetMode].color}40`, cursor: 'pointer',
              }
            },
              [1,2,3,4,5,6,8,10,12,16].map(n =>
                React.createElement('option', { key: n, value: n }, n)
              )
            ),
            React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)' } }, 'hosts at once')
          )
        ),
        targetMode === 'CIDR' && React.createElement('div', {
          style: { fontSize: 10, color: 'var(--text-muted)', marginTop: 6 }
        }, '⚡ Live host discovery runs first (nmap -sn). Max 64 live hosts per session.')
      ),

      // Hostname field (single-host only)
      targetMode === 'SINGLE' && React.createElement('div', { style: { marginTop: 12 } },
        React.createElement('div', { style: label }, 'Hostname (optional)'),
        React.createElement('input', {
          type: 'text', value: form.target_hostname, placeholder: 'target.htb',
          onChange: e => set('target_hostname', e.target.value),
          style: inp
        })
      ),
    ),

    // ── Mission Brief (Improvement #1) ───────────────────────────────────
    React.createElement('div', {
      style: {
        ...card,
        borderColor: 'rgba(232,67,90,0.35)',
        background: 'rgba(232,67,90,0.04)',
      }
    },
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 } },
        React.createElement('span', { style: { fontSize: 14 } }, '🎖'),
        React.createElement('span', { style: { fontSize: 12, fontWeight: 700, color: '#E8435A', letterSpacing: 0.5 } },
          'MISSION BRIEF'),
        React.createElement('span', {
          style: {
            fontSize: 9, padding: '1px 6px', borderRadius: 3, marginLeft: 'auto',
            color: '#E8435A', background: 'rgba(232,67,90,0.10)',
            border: '1px solid rgba(232,67,90,0.35)', fontFamily: 'var(--font-mono)',
          }
        }, 'GOAL-DRIVEN')
      ),
      React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 12, lineHeight: 1.5 } },
        'Defines what success looks like. Injected into every Expert prompt and planning call so the whole engagement stays aligned with the goal.'),

      // Objective
      React.createElement('div', { style: row },
        React.createElement('div', { style: label }, 'Objective'),
        React.createElement('input', {
          type: 'text', value: form.mb_objective,
          placeholder: 'e.g. Capture root.txt and demonstrate domain admin',
          onChange: e => set('mb_objective', e.target.value),
          style: inp,
        })
      ),
      // Win conditions
      React.createElement('div', { style: row },
        React.createElement('div', { style: label }, 'Win conditions  (comma or newline separated)'),
        React.createElement('textarea', {
          value: form.mb_win_conditions, rows: 2,
          placeholder: 'shell_obtained, user_flag_captured, root_flag_captured',
          onChange: e => set('mb_win_conditions', e.target.value),
          style: { ...inp, resize: 'vertical', lineHeight: 1.5 }
        })
      ),
      // Scope in / out
      React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 } },
        React.createElement('div', null,
          React.createElement('div', { style: label }, 'Scope IN'),
          React.createElement('textarea', {
            value: form.mb_scope_in, rows: 2,
            placeholder: '10.10.10.0/24\nexample.htb',
            onChange: e => set('mb_scope_in', e.target.value),
            style: { ...inp, resize: 'vertical', lineHeight: 1.5 }
          })
        ),
        React.createElement('div', null,
          React.createElement('div', { style: label }, 'Scope OUT'),
          React.createElement('textarea', {
            value: form.mb_scope_out, rows: 2,
            placeholder: 'prod.example.com',
            onChange: e => set('mb_scope_out', e.target.value),
            style: { ...inp, resize: 'vertical', lineHeight: 1.5 }
          })
        )
      ),
      // Budgets row
      React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 } },
        React.createElement('div', null,
          React.createElement('div', { style: label }, 'Time budget (min)'),
          React.createElement('input', {
            type: 'number', min: 0, value: form.mb_time_budget_min,
            onChange: e => set('mb_time_budget_min', Number(e.target.value) || 0),
            style: inp,
          })
        ),
        React.createElement('div', null,
          React.createElement('div', { style: label }, `Noise budget (${form.mb_noise_budget}/100)`),
          React.createElement('input', {
            type: 'range', min: 0, max: 100, step: 5,
            value: form.mb_noise_budget,
            onChange: e => set('mb_noise_budget', Number(e.target.value)),
            style: { ...inp, padding: 0, height: 28, accentColor: '#E8435A' },
          })
        ),
        React.createElement('div', null,
          React.createElement('div', { style: label }, 'Blast radius'),
          React.createElement('select', {
            value: form.mb_blast_radius,
            onChange: e => set('mb_blast_radius', e.target.value),
            style: { ...inp, cursor: 'pointer' },
          },
            React.createElement('option', { value: 'passive' },     'passive — OSINT only'),
            React.createElement('option', { value: 'active' },      'active — scans + exploits'),
            React.createElement('option', { value: 'destructive' }, 'destructive — DoS / data-altering'),
          )
        )
      ),
    ),

    // Target type selection
    React.createElement('div', { style: card },
      React.createElement('div', { style: { ...label, marginBottom: 10 } }, 'Target Type'),
      React.createElement('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 } },
        TARGET_TYPES.map(t =>
          React.createElement('div', {
            key: t.value, onClick: () => set('target_type', t.value),
            style: {
              padding: '10px 8px', borderRadius: 6, textAlign: 'center', cursor: 'pointer',
              border: `1px solid ${form.target_type === t.value ? 'var(--cyan)' : 'var(--border)'}`,
              background: form.target_type === t.value ? 'rgba(0,212,255,0.07)' : 'transparent',
              transition: 'all 0.15s'
            }
          },
            React.createElement('div', { style: { fontSize: 20, marginBottom: 4 } }, t.icon),
            React.createElement('div', { style: {
              fontSize: 10, color: form.target_type === t.value ? 'var(--cyan)' : 'var(--text-muted)',
              fontFamily: 'var(--font-mono)'
            }}, t.label)
          )
        )
      )
    ),

    // Scope + Notes
    React.createElement('div', { style: card },
      React.createElement('div', { style: row },
        React.createElement('div', { style: label }, 'Scope / Notes'),
        React.createElement('textarea', {
          value: form.notes, rows: 3,
          placeholder: 'e.g. Focus on web app at port 80. Known services: Apache 2.4, PHP 7.x',
          onChange: e => set('notes', e.target.value),
          style: { ...inp, resize: 'vertical', lineHeight: 1.6 }
        })
      )
    ),

    // Phase selection
    React.createElement('div', { style: card },
      React.createElement('div', { style: { ...label, marginBottom: 10 } }, 'Phases to run'),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
        ALL_PHASES.map(p => {
          const on = form.phases.includes(p.key);
          return React.createElement('div', {
            key: p.key, onClick: () => togglePhase(p.key),
            style: {
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '8px 12px', borderRadius: 5, cursor: 'pointer',
              border: `1px solid ${on ? 'rgba(0,212,255,0.3)' : 'var(--border)'}`,
              background: on ? 'rgba(0,212,255,0.05)' : 'transparent',
              transition: 'all 0.15s'
            }
          },
            React.createElement('div', {
              style: {
                width: 14, height: 14, borderRadius: 3, flexShrink: 0,
                border: `2px solid ${on ? 'var(--cyan)' : 'var(--border-light)'}`,
                background: on ? 'var(--cyan)' : 'transparent',
                display: 'flex', alignItems: 'center', justifyContent: 'center'
              }
            }, on && React.createElement('span', { style: { color: '#000', fontSize: 9, fontWeight: 900 } }, '✓')),
            React.createElement('div', null,
              React.createElement('div', {
                style: { fontSize: 12, color: on ? 'var(--text-primary)' : 'var(--text-muted)',
                         fontWeight: on ? 600 : 400 }
              }, p.label),
              React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } }, p.desc)
            )
          );
        })
      )
    ),

    // Options row
    React.createElement('div', { style: { ...card, display: 'flex', gap: 20, alignItems: 'center' } },
      // Auto-exploit toggle
      React.createElement('div', {
        onClick: () => set('auto_exploit', !form.auto_exploit),
        style: { display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }
      },
        React.createElement('div', {
          style: {
            width: 36, height: 20, borderRadius: 10, position: 'relative',
            background: form.auto_exploit ? 'var(--red)' : 'var(--bg-elevated)',
            border: `1px solid ${form.auto_exploit ? 'rgba(255,68,102,0.5)' : 'var(--border-light)'}`,
            transition: 'background 0.2s'
          }
        },
          React.createElement('div', {
            style: {
              position: 'absolute', top: 2, width: 14, height: 14, borderRadius: '50%',
              background: '#fff', transition: 'left 0.2s',
              left: form.auto_exploit ? 18 : 2
            }
          })
        ),
        React.createElement('div', null,
          React.createElement('div', { style: { fontSize: 11, color: form.auto_exploit ? 'var(--red)' : 'var(--text-muted)' } },
            'Auto-exploit'),
          React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)' } },
            form.auto_exploit ? 'Will exploit without confirmation' : 'Will pause for confirmation')
        )
      ),
      // Threading
      React.createElement('div', {
        onClick: () => set('threading_enabled', !form.threading_enabled),
        style: { display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }
      },
        React.createElement('div', {
          style: {
            width: 36, height: 20, borderRadius: 10, position: 'relative',
            background: form.threading_enabled ? 'var(--green)' : 'var(--bg-elevated)',
            border: `1px solid ${form.threading_enabled ? 'rgba(0,255,136,0.4)' : 'var(--border-light)'}`,
            transition: 'background 0.2s'
          }
        },
          React.createElement('div', {
            style: {
              position: 'absolute', top: 2, width: 14, height: 14, borderRadius: '50%',
              background: '#fff', transition: 'left 0.2s',
              left: form.threading_enabled ? 18 : 2
            }
          })
        ),
        React.createElement('div', null,
          React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)' } }, 'Threading'),
          React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)' } }, 'Parallel tool execution')
        )
      ),
      // Max threads
      form.threading_enabled && React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 8 } },
        React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)' } }, 'Threads:'),
        React.createElement('select', {
          value: form.max_threads, onChange: e => set('max_threads', Number(e.target.value)),
          style: {
            ...inp, width: 60, padding: '5px 6px',
            border: '1px solid var(--border)', cursor: 'pointer'
          }
        },
          [1,2,3,4,5,6,7,8,10,12,15,20].map(n => React.createElement('option', { key: n, value: n }, n))
        )
      )
    ),

    // Reasoning Engine — always-on info card
    React.createElement('div', {
      style: {
        ...card,
        background: 'rgba(0,229,160,0.04)',
        border: '1px solid rgba(0,229,160,0.25)',
      }
    },
      React.createElement('div', { style: { display: 'flex', alignItems: 'flex-start', gap: 12 } },
        // Pulsing indicator
        React.createElement('div', {
          style: {
            width: 8, height: 8, borderRadius: '50%', flexShrink: 0, marginTop: 3,
            background: 'var(--accent)',
            boxShadow: '0 0 8px var(--accent)',
            animation: 'pulse 2s infinite',
          }
        }),
        React.createElement('div', { style: { flex: 1 } },
          React.createElement('div', {
            style: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }
          },
            React.createElement('span', { style: { fontSize: 12, fontWeight: 700, color: 'var(--accent)' } },
              '🧠 Adaptive Reasoning Engine'
            ),
            React.createElement('span', {
              style: {
                fontSize: 8, padding: '1px 6px', borderRadius: 3,
                background: 'rgba(0,229,160,0.15)', color: 'var(--accent)',
                border: '1px solid rgba(0,229,160,0.3)',
                fontFamily: 'var(--font-mono)', letterSpacing: 0.6,
              }
            }, 'ALWAYS ON')
          ),
          React.createElement('div', {
            style: { fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.6 }
          }, 'ARGUS thinks like a human attacker: start with full recon → form hypotheses about attack vectors → execute the most promising path → validate → chain post-exploitation automatically. All dashboards update in real time.'),
          React.createElement('div', {
            style: { marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }
          },
            ...[
              { label: '🔍 Full Recon',       color: 'var(--cyan)'   },
              { label: '🧠 Hypothesis Loop',   color: 'var(--accent)' },
              { label: '⚡ Parallel Evidence', color: 'var(--violet)' },
              { label: '🎯 Auto Post-Exploit', color: 'var(--amber)'  },
              { label: '↔️ Lateral Movement',  color: 'var(--green)'  },
            ].map(({ label: l, color }) =>
              React.createElement('span', {
                key: l,
                style: {
                  fontSize: 9, padding: '2px 7px', borderRadius: 4,
                  background: color + '18', color,
                  border: `1px solid ${color}40`,
                }
              }, l)
            )
          )
        )
      )
    ),

    // Error
    error && React.createElement('div', {
      style: {
        padding: '10px 14px', borderRadius: 6, marginBottom: 12,
        background: 'rgba(255,68,102,0.1)', border: '1px solid rgba(255,68,102,0.3)',
        color: 'var(--red)', fontSize: 12
      }
    }, `⚠ ${error}`),

    // Launch button
    React.createElement('button', {
      onClick: (!loading && form.target_ip.trim()) ? launch : undefined,
      style: (() => {
        const isDisabled = !form.target_ip.trim();
        const base = {
          width: '100%', padding: '14px', borderRadius: 8,
          fontSize: 14, fontWeight: 700, letterSpacing: 1,
          fontFamily: 'var(--font-mono)', transition: 'all 0.2s',
          cursor: loading ? 'wait' : isDisabled ? 'not-allowed' : 'pointer',
          position: 'relative', overflow: 'hidden',
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
        };
        if (loading) return {
          ...base,
          background: 'var(--bg-panel)', color: '#00E5A0',
          border: '1px solid #00E5A040',
          boxShadow: 'none', opacity: 1,
        };
        if (isDisabled) return {
          ...base,
          background: 'var(--bg-surface)',
          color: 'rgba(255,255,255,0.2)',
          border: '1px dashed rgba(255,255,255,0.12)',
          boxShadow: 'none', opacity: 1,
        };
        return {
          ...base,
          background: 'linear-gradient(135deg, #00E5A0 0%, #00C87A 100%)',
          color: '#05120D',
          border: '1px solid #00E5A0',
          boxShadow: '0 0 24px rgba(0,229,160,0.35), 0 4px 12px rgba(0,0,0,0.4)',
          opacity: 1,
        };
      })()
    },
      // Animated shimmer overlay for ready state
      !loading && form.target_ip.trim() && React.createElement('div', {
        style: {
          position: 'absolute', inset: 0,
          background: 'linear-gradient(105deg, transparent 40%, rgba(255,255,255,0.15) 50%, transparent 60%)',
          backgroundSize: '200% 100%',
          animation: 'shimmer 2.4s ease-in-out infinite',
          pointerEvents: 'none',
        }
      }),
      loading
        ? React.createElement('span', { style: { animation: 'spin 0.8s linear infinite', display: 'inline-block' } }, '⟳')
        : React.createElement('span', { style: { fontSize: 16 } }, '🚀'),
      loading
        ? 'Launching…'
        : !form.target_ip.trim()
          ? 'Enter a target to launch'
          : targetMode === 'CIDR'
            ? `LAUNCH NETWORK SCAN → ${form.target_ip}`
            : targetMode === 'MULTI'
              ? `LAUNCH MULTI-TARGET → ${form.target_ip.split(',').length} hosts`
              : `LAUNCH PENTEST → ${form.target_ip}`
    )
  );
}

window.TargetConfig = TargetConfig;
