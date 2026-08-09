// ═══════════════════════════════════════════════════════════
// RiskDashboard.jsx — Cyber Risk view (NEW for v2 UI revamp)
//
// Pure read-only consumer of the existing store.  Computes:
//   • Aggregate risk score (0..100) from severity-weighted findings
//   • Kill-chain progress  (recon → exploit → post-ex → lateral → loot)
//   • Time-to-foothold     (engagement clock until first register_shell)
//   • Severity treemap     (visual proportions of findings)
//   • Loot summary         (DoI count by category)
//   • Primer coverage      (chains that fired, chains degraded)
//   • Active sessions      (multi-target view)
//   • Top-3 next actions   (highest-confidence pending hypotheses)
//
// NO dispatched actions, NO WS events handled — this is purely a
// presentation layer over `useStore().state`.  Adding/removing/changing
// it CANNOT break any platform behaviour.
// ═══════════════════════════════════════════════════════════

(function() {
'use strict';

const { useMemo, useState, useEffect } = React;

// Severity → numeric weight for risk score
const SEV_WEIGHT = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };

// Kill-chain stages — read from the actual top-level store shape.
// Each test predicate is defensive (optional chaining) so missing fields
// silently mean "stage not yet reached" rather than throwing.
//
// Store fields used:
//   state.findingsSummary.total       — overall finding count
//   state.discoveredHosts             — recon host count (CIDR mode)
//   state.shells                      — list of registered shells
//   state.credentials                 — captured creds
//   state.evidence / state.flags      — post-ex artefacts
//   state.lateralFindings             — lateral movement signals
const KILL_CHAIN_STAGES = [
  { id: 'recon',     label: 'Recon',          test: s => (s.findingsSummary?.total || 0) > 0 || (s.discoveredHosts || []).length > 0 || (s.planSteps || []).some(p => p.id === 'recon' && p.status !== 'pending') },
  { id: 'enum',      label: 'Enumeration',    test: s => (s.findingsSummary?.total || 0) >= 3 || (s.planSteps || []).some(p => ['vuln_id','web_testing','enum'].includes(p.id) && p.status === 'done') },
  { id: 'exploit',   label: 'Exploitation',   test: s => (s.shells || []).length > 0 || (s.credentials || []).length > 0 || (s.flags || []).length > 0 },
  { id: 'foothold',  label: 'Foothold',       test: s => (s.shells || []).some(sh => sh && sh.active !== false) || (s.flags || []).length > 0 },
  { id: 'lateral',   label: 'Lateral / Loot', test: s => (s.lateralFindings || []).length > 0 || (s.persistenceItems || []).length > 0 || (s.tunnels || []).length > 0 },
];

// ─── Helpers ──────────────────────────────────────────────────
function fmtDuration(secs) {
  if (!secs || secs < 0) return '—';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function calcRiskScore(summary) {
  const s = summary || {};
  const score =
    (s.critical || 0) * SEV_WEIGHT.critical +
    (s.high     || 0) * SEV_WEIGHT.high +
    (s.medium   || 0) * SEV_WEIGHT.medium +
    (s.low      || 0) * SEV_WEIGHT.low;
  return Math.min(100, score);
}

function riskBand(score) {
  if (score >= 70) return { label: 'CRITICAL', color: 'var(--critical)' };
  if (score >= 40) return { label: 'HIGH',     color: 'var(--high)' };
  if (score >= 15) return { label: 'MEDIUM',   color: 'var(--medium)' };
  if (score > 0)   return { label: 'LOW',      color: 'var(--low)' };
  return            { label: 'BASELINE', color: 'var(--text-muted)' };
}

// ─── Risk gauge (semi-circle SVG) ─────────────────────────────
function RiskGauge({ score, summary }) {
  const band = riskBand(score);
  const pct = Math.min(1, score / 100);
  const radius = 100;
  const circ = Math.PI * radius;       // semicircle perimeter
  const dash = pct * circ;

  return React.createElement('div', { 'data-slot': 'RiskDashboard.RiskGauge',
    className: 'hero-card panel-ambient panel-hud',
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 14, padding: 22,
      display: 'flex', flexDirection: 'column', alignItems: 'center',
    }
  },
    React.createElement('div', {
      style: { fontSize: 11, letterSpacing: 1.5, color: 'var(--text-muted)',
               textTransform: 'uppercase', fontWeight: 700, marginBottom: 14 }
    }, 'Aggregate Risk Score'),

    // SVG semicircle gauge wrapped in halo (3 concentric rotating rings)
    React.createElement('div', { className: 'halo-wrap' },
      React.createElement('div', { className: 'halo-ring outer' }),
      React.createElement('div', { className: 'halo-ring' }),
      React.createElement('div', { className: 'halo-ring inner' }),
      React.createElement('svg', {
        width: 240, height: 130, viewBox: '0 0 240 130',
        style: { display: 'block', position: 'relative', zIndex: 1 },
      },
        // Background arc
        React.createElement('path', {
          d: 'M 20 120 A 100 100 0 0 1 220 120',
          stroke: 'var(--border)', strokeWidth: 14, fill: 'none', strokeLinecap: 'round',
        }),
        // Foreground arc — colored by band
        React.createElement('path', {
          d: 'M 20 120 A 100 100 0 0 1 220 120',
          stroke: band.color, strokeWidth: 14, fill: 'none', strokeLinecap: 'round',
          strokeDasharray: `${dash} ${circ}`,
          style: { transition: 'stroke-dasharray 0.6s ease, stroke 0.3s ease',
                   filter: `drop-shadow(0 0 8px ${band.color}66)` },
        }),
        // Score number
        React.createElement('text', {
          x: 120, y: 100, textAnchor: 'middle',
          fontFamily: 'var(--font-mono)', fontSize: 36, fontWeight: 700, fill: band.color,
        }, Math.round(score)),
        // /100 suffix
        React.createElement('text', {
          x: 120, y: 122, textAnchor: 'middle',
          fontFamily: 'var(--font-mono)', fontSize: 12, fill: 'var(--text-muted)',
        }, '/ 100'),
      )
    ),

    // Band label
    React.createElement('div', {
      style: {
        marginTop: 10, padding: '4px 14px', borderRadius: 20,
        background: `${band.color}15`, border: `1px solid ${band.color}40`,
        color: band.color, fontSize: 11, fontWeight: 700, letterSpacing: 1.2,
        fontFamily: 'var(--font-mono)',
      }
    }, band.label),

    // Severity row underneath
    React.createElement('div', {
      style: { display: 'flex', gap: 14, marginTop: 16, fontSize: 10, fontFamily: 'var(--font-mono)' }
    },
      ['critical', 'high', 'medium', 'low', 'info'].map(s => {
        const cMap = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)' };
        return React.createElement('div', {
          key: s,
          style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }
        },
          React.createElement('span', {
            style: { color: cMap[s], fontSize: 14, fontWeight: 700 }
          }, summary[s] || 0),
          React.createElement('span', {
            style: { color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.6 }
          }, s.slice(0, 3)),
        );
      })
    )
  );
}

// ─── Kill-chain progress strip ────────────────────────────────
function KillChainStrip({ state }) {
  const stages = KILL_CHAIN_STAGES.map(stg => ({ ...stg, reached: !!stg.test(state) }));
  const reachedCount = stages.filter(s => s.reached).length;

  return React.createElement('div', { 'data-slot': 'RiskDashboard.KillChainStrip',
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 14, padding: 22,
    }
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }
    },
      React.createElement('div', {
        style: { fontSize: 11, letterSpacing: 1.5, color: 'var(--text-muted)',
                 textTransform: 'uppercase', fontWeight: 700 }
      }, 'Kill-Chain Progress'),
      React.createElement('div', {
        style: { fontSize: 12, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 600 }
      }, `${reachedCount} / ${stages.length}`)
    ),
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 0 }
    },
      stages.map((stg, i) =>
        React.createElement(React.Fragment, { key: stg.id },
          React.createElement('div', {
            style: {
              flex: 'none', display: 'flex', flexDirection: 'column',
              alignItems: 'center', gap: 8, minWidth: 78,
            }
          },
            React.createElement('div', {
              style: {
                width: 32, height: 32, borderRadius: '50%',
                background: stg.reached ? 'var(--accent-subtle)' : 'var(--bg-panel)',
                border: `2px solid ${stg.reached ? 'var(--accent)' : 'var(--border)'}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: stg.reached ? 'var(--accent)' : 'var(--text-muted)',
                fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
                boxShadow: stg.reached ? '0 0 12px var(--accent-glow)' : 'none',
                transition: 'all 0.3s ease',
              }
            }, stg.reached ? '✓' : i + 1),
            React.createElement('div', {
              style: {
                fontSize: 10, color: stg.reached ? 'var(--text-primary)' : 'var(--text-muted)',
                fontWeight: stg.reached ? 600 : 400, letterSpacing: 0.4,
              }
            }, stg.label),
          ),
          i < stages.length - 1 && React.createElement('div', {
            style: {
              flex: 1, height: 2, marginTop: -22,
              background: stages[i + 1].reached
                ? `linear-gradient(90deg, var(--accent), var(--accent-glow))`
                : 'var(--border)',
              transition: 'background 0.4s ease',
            }
          })
        )
      )
    )
  );
}

// ─── Stat tile ────────────────────────────────────────────────
function StatTile({ label, value, sub, color, accent }) {
  return React.createElement('div', { 'data-slot': 'RiskDashboard.StatTile',
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 12, padding: '16px 18px',
      display: 'flex', flexDirection: 'column', gap: 4,
      position: 'relative', overflow: 'hidden',
    }
  },
    accent && React.createElement('div', {
      style: {
        position: 'absolute', top: 0, left: 0, width: 3, height: '100%',
        background: accent,
      }
    }),
    React.createElement('span', {
      style: { fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase',
               letterSpacing: 1.2, fontWeight: 700 }
    }, label),
    React.createElement('span', {
      style: { fontFamily: 'var(--font-mono)', fontSize: 24, fontWeight: 700,
               color: color || 'var(--text-primary)', lineHeight: 1.1 }
    }, value),
    sub && React.createElement('span', {
      style: { fontSize: 10, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }
    }, sub),
  );
}

// ─── Severity treemap (proportional bars) ─────────────────────
function SeverityTreemap({ summary }) {
  const total = summary?.total || 0;
  const rows = [
    { sev: 'critical', count: summary?.critical || 0, color: 'var(--critical)' },
    { sev: 'high',     count: summary?.high     || 0, color: 'var(--high)' },
    { sev: 'medium',   count: summary?.medium   || 0, color: 'var(--medium)' },
    { sev: 'low',      count: summary?.low      || 0, color: 'var(--low)' },
    { sev: 'info',     count: summary?.info     || 0, color: 'var(--info)' },
  ];

  return React.createElement('div', { 'data-slot': 'RiskDashboard.SeverityTreemap',
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 14, padding: 22,
    }
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between',
               alignItems: 'center', marginBottom: 14 }
    },
      React.createElement('div', {
        style: { fontSize: 11, letterSpacing: 1.5, color: 'var(--text-muted)',
                 textTransform: 'uppercase', fontWeight: 700 }
      }, 'Severity Distribution'),
      React.createElement('div', {
        style: { fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontWeight: 600 }
      }, total ? `${total} findings` : 'no findings yet')
    ),
    total > 0 ? React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 10 } },
      rows.map(r => {
        if (r.count === 0) return null;
        const pct = (r.count / total) * 100;
        return React.createElement('div', { key: r.sev,
          style: { display: 'flex', alignItems: 'center', gap: 10 }
        },
          React.createElement('div', {
            style: {
              width: 70, fontSize: 10, color: r.color, fontWeight: 700,
              textTransform: 'uppercase', letterSpacing: 1, fontFamily: 'var(--font-ui)',
            }
          }, r.sev),
          React.createElement('div', {
            style: { flex: 1, height: 22, background: 'var(--bg-panel)', borderRadius: 5, overflow: 'hidden' }
          },
            React.createElement('div', {
              style: {
                width: `${pct}%`, height: '100%',
                background: `linear-gradient(90deg, ${r.color}cc, ${r.color}88)`,
                transition: 'width 0.5s ease',
              }
            })
          ),
          React.createElement('div', {
            style: { width: 50, textAlign: 'right', fontFamily: 'var(--font-mono)',
                     fontSize: 13, fontWeight: 700, color: r.color }
          }, r.count),
        );
      })
    ) : React.createElement('div', {
      style: { padding: '30px 0', textAlign: 'center', color: 'var(--text-muted)',
               fontSize: 12, fontStyle: 'italic' }
    }, 'Findings will appear here as the engagement progresses.')
  );
}

// ─── Loot summary card ────────────────────────────────────────
//
// Loot is sourced from the platform's exfil_pipeline which emits
// per-DoI findings.  In the current store shape these are visible via:
//   1. state.credentials             — captured creds (hashes, plaintext)
//   2. state.evidence                — structured evidence items
//   3. state.flags                   — CTF flags
//   4. state.findingsSummary.critical — high-severity loot indicators
// We aggregate all sources rather than requiring a single intel.loot_entries.
function LootCard({ state }) {
  const creds = state.credentials || [];
  const evidence = state.evidence || [];
  const flags = state.flags || [];
  const totalLoot = creds.length + evidence.length + flags.length;
  const bySev = {
    critical: flags.length + creds.filter(c => (c.type||'').toLowerCase().includes('hash')).length,
    high:     creds.filter(c => !(c.type||'').toLowerCase().includes('hash')).length,
    medium:   evidence.filter(e => (e.severity||'').toLowerCase() === 'medium').length,
    low:      evidence.filter(e => (e.severity||'').toLowerCase() === 'low').length,
    info:     evidence.filter(e => !['critical','high','medium','low'].includes((e.severity||'').toLowerCase())).length,
  };

  return React.createElement('div', { 'data-slot': 'RiskDashboard.LootCard',
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 14, padding: 22,
    }
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between',
               alignItems: 'center', marginBottom: 14 }
    },
      React.createElement('div', {
        style: { fontSize: 11, letterSpacing: 1.5, color: 'var(--text-muted)',
                 textTransform: 'uppercase', fontWeight: 700 }
      }, 'Harvested Loot'),
      React.createElement('div', {
        style: {
          padding: '2px 10px', borderRadius: 10, fontSize: 10, fontWeight: 700,
          background: totalLoot ? 'color-mix(in srgb, var(--violet) 9%, transparent)' : 'var(--bg-panel)',
          color:      totalLoot ? 'var(--violet)'      : 'var(--text-muted)',
          border: `1px solid ${totalLoot ? 'var(--violet-glow)' : 'var(--border)'}`,
          fontFamily: 'var(--font-mono)', letterSpacing: 0.5,
        }
      }, `${totalLoot} ITEM${totalLoot !== 1 ? 'S' : ''}`)
    ),
    totalLoot > 0
      ? React.createElement('div', { style: { display: 'grid', gap: 8 } },
          ['critical', 'high', 'medium', 'low', 'info'].map(sev => {
            const cMap = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)' };
            const n = bySev[sev] || 0;
            if (n === 0) return null;
            return React.createElement('div', {
              key: sev,
              style: {
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '8px 12px', background: 'var(--bg-panel)', borderRadius: 8,
                borderLeft: `3px solid ${cMap[sev]}`,
              }
            },
              React.createElement('span', {
                style: { fontSize: 11, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: 0.8 }
              }, sev),
              React.createElement('span', {
                style: { fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: cMap[sev] }
              }, n)
            );
          })
        )
      : React.createElement('div', {
          style: { padding: '20px 0', textAlign: 'center', color: 'var(--text-muted)',
                   fontSize: 11, fontStyle: 'italic' }
        }, 'NTLM hashes, SSH keys, secrets and PII captured during post-exploitation will appear here.')
  );
}

// ─── Primer coverage card ─────────────────────────────────────
function PrimerCoverageCard({ state }) {
  const cov = state.primerToolCoverage || {};
  const chains = cov.coverage || {};
  const present = cov.present ?? 0;
  const total   = cov.total   ?? 0;
  const chainsArr = Object.entries(chains).map(([name, info]) => ({
    name,
    present: (info?.present || []).length,
    total:   (info?.deps    || []).length,
    missing: (info?.missing || []),
    coverage: info?.coverage ?? 1,
  }));
  chainsArr.sort((a, b) => a.coverage - b.coverage);

  const overallCov = total ? present / total : 0;
  const overallPct = Math.round(overallCov * 100);
  const ringColor = overallCov >= 0.85 ? 'var(--low)' : overallCov >= 0.6 ? 'var(--medium)' : 'var(--high)';

  return React.createElement('div', { 'data-slot': 'RiskDashboard.PrimerCoverageCard',
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 14, padding: 22,
    }
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between',
               alignItems: 'center', marginBottom: 14 }
    },
      React.createElement('div', {
        style: { fontSize: 11, letterSpacing: 1.5, color: 'var(--text-muted)',
                 textTransform: 'uppercase', fontWeight: 700 }
      }, 'Primer Tool Coverage'),
      total > 0 && React.createElement('div', {
        style: {
          padding: '2px 10px', borderRadius: 10, fontSize: 10, fontWeight: 700,
          background: `${ringColor}18`, color: ringColor,
          border: `1px solid ${ringColor}40`,
          fontFamily: 'var(--font-mono)', letterSpacing: 0.5,
        }
      }, `${overallPct}%`)
    ),
    chainsArr.length === 0 ? React.createElement('div', {
      style: { padding: '20px 0', textAlign: 'center', color: 'var(--text-muted)',
               fontSize: 11, fontStyle: 'italic' }
    }, 'Probe runs at engagement start.')
    : React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 6 } },
        chainsArr.slice(0, 7).map(c => {
          const cPct = Math.round((c.coverage || 0) * 100);
          const ok = c.missing.length === 0;
          return React.createElement('div', {
            key: c.name,
            style: { display: 'flex', alignItems: 'center', gap: 10,
                     padding: '6px 10px', background: 'var(--bg-panel)', borderRadius: 6 }
          },
            React.createElement('span', {
              style: {
                width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                background: ok ? 'var(--low)' : 'var(--high)',
                boxShadow: ok ? '0 0 5px var(--low-bd)' : 'none',
              }
            }),
            React.createElement('span', {
              style: { fontSize: 11, fontFamily: 'var(--font-mono)',
                       color: 'var(--text-primary)', flex: 1 }
            }, c.name),
            React.createElement('span', {
              style: { fontSize: 10, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }
            }, `${c.present}/${c.total}`)
          );
        })
      )
  );
}

// ─── Top hypotheses card ──────────────────────────────────────
function TopHypothesesCard({ state }) {
  const all = state.hypotheses || [];
  const candidates = all
    .filter(h => !h.invalidated && (h.recommended_next_actions || []).length > 0)
    .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
    .slice(0, 3);

  return React.createElement('div', { 'data-slot': 'RiskDashboard.TopHypothesesCard',
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 14, padding: 22, gridColumn: 'span 2',
    }
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between',
               alignItems: 'center', marginBottom: 14 }
    },
      React.createElement('div', {
        style: { fontSize: 11, letterSpacing: 1.5, color: 'var(--text-muted)',
                 textTransform: 'uppercase', fontWeight: 700 }
      }, 'Top Attack Hypotheses'),
      React.createElement('button', {
        onClick: () => window.dispatchEvent(new CustomEvent('navigate', { detail: 'reasoning' })),
        style: {
          background: 'transparent', border: 'none', cursor: 'pointer',
          color: 'var(--cyan)', fontSize: 10, fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase', letterSpacing: 1, fontWeight: 600,
        }
      }, 'View all →')
    ),
    candidates.length === 0
      ? React.createElement('div', {
          style: { padding: '20px 0', textAlign: 'center', color: 'var(--text-muted)',
                   fontSize: 11, fontStyle: 'italic' }
        }, 'Hypotheses will appear once recon produces actionable evidence.')
      : React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
          candidates.map((h, i) => {
            const conf = h.confidence || 0;
            const confColor = conf >= 0.75 ? 'var(--low)' : conf >= 0.5 ? 'var(--medium)' : 'var(--high)';
            return React.createElement('div', {
              key: h.hypothesis_id || i,
              style: {
                padding: '10px 14px', background: 'var(--bg-panel)',
                border: `1px solid ${'var(--border)'}`, borderRadius: 8,
                display: 'flex', alignItems: 'center', gap: 12,
                borderLeft: `3px solid ${confColor}`,
              }
            },
              React.createElement('div', {
                style: {
                  width: 42, fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 700,
                  color: confColor, flexShrink: 0,
                }
              }, `${Math.round(conf * 100)}%`),
              React.createElement('div', { style: { flex: 1, minWidth: 0 } },
                React.createElement('div', {
                  style: {
                    fontSize: 12, color: 'var(--text-primary)', fontWeight: 500,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }
                }, h.statement || '(unnamed hypothesis)'),
                (h.recommended_next_actions || []).length > 0 && React.createElement('div', {
                  style: {
                    fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    marginTop: 2,
                  }
                }, '▶ ' + h.recommended_next_actions[0])
              ),
            );
          })
        )
  );
}

// ─── Device classification card ───────────────────────────────
//
// Shows the most-recent device taxonomy verdict produced by the
// classifier (intel['device_classification']).  Multi-host engagements
// also list the per-host breakdown when state.hostClassifications is
// populated.
function DeviceTaxonomyCard({ state }) {
  const single = state.deviceClassification;
  const hosts  = state.hostClassifications || {};
  const hostList = Object.entries(hosts);

  // Color-code by os_family / kind
  const osColor = (osf) => {
    if (osf === 'linux')    return 'var(--low)';
    if (osf === 'windows')  return 'var(--cyan)';
    if (osf === 'macos')    return 'var(--violet)';
    if (osf === 'embedded') return 'var(--high)';
    return 'var(--text-muted)';
  };

  return React.createElement('div', { 'data-slot': 'RiskDashboard.DeviceTaxonomyCard',
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 14, padding: 22,
    }
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }
    },
      React.createElement('div', {
        style: { fontSize: 11, letterSpacing: 1.5, color: 'var(--text-muted)',
                 textTransform: 'uppercase', fontWeight: 700 }
      }, 'Device Taxonomy'),
      hostList.length > 0 && React.createElement('div', {
        style: {
          padding: '2px 10px', borderRadius: 10, fontSize: 10, fontWeight: 700,
          background: 'color-mix(in srgb, var(--cyan) 9%, transparent)', color: 'var(--cyan)',
          border: '1px solid color-mix(in srgb, var(--cyan) 25%, transparent)',
          fontFamily: 'var(--font-mono)', letterSpacing: 0.5,
        }
      }, `${hostList.length} HOST${hostList.length !== 1 ? 'S' : ''}`)
    ),

    // Single-host verdict
    !single && hostList.length === 0 && React.createElement('div', {
      style: { padding: '20px 0', textAlign: 'center', color: 'var(--text-muted)',
               fontSize: 11, fontStyle: 'italic' }
    }, 'Classifier runs after recon completes.'),

    single && hostList.length === 0 && React.createElement('div', null,
      React.createElement('div', {
        style: {
          padding: '12px 14px', background: 'var(--bg-panel)', borderRadius: 8,
          borderLeft: `3px solid ${osColor(single.os_family)}`,
          marginBottom: 10,
        }
      },
        React.createElement('div', { style: { display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 4 } },
          React.createElement('span', {
            style: { fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 700, color: osColor(single.os_family) }
          }, (single.kind || 'unknown').replace(/_/g, ' ')),
          React.createElement('span', {
            style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
          }, `conf=${(single.confidence || 0).toFixed(2)}  prio=${single.priority || 0}`)
        ),
        React.createElement('div', {
          style: { fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }
        }, single.notes || ''),
        (single.labels || []).length > 0 && React.createElement('div', {
          style: { display: 'flex', gap: 5, marginTop: 8, flexWrap: 'wrap' }
        },
          (single.labels || []).slice(0, 6).map(l =>
            React.createElement('span', {
              key: l,
              style: {
                padding: '1px 7px', borderRadius: 10,
                background: `${osColor(single.os_family)}15`,
                border: `1px solid ${osColor(single.os_family)}30`,
                color: osColor(single.os_family),
                fontSize: 9, fontFamily: 'var(--font-mono)', fontWeight: 600,
              }
            }, l)
          )
        )
      ),
      // Playbook chain preview
      (single.playbooks || []).length > 0 && React.createElement('div', null,
        React.createElement('div', {
          style: { fontSize: 9, color: 'var(--text-muted)', letterSpacing: 1, fontWeight: 700, marginBottom: 6 }
        }, 'PLAYBOOK CHAIN'),
        React.createElement('div', { style: { display: 'flex', gap: 4, flexWrap: 'wrap' } },
          (single.playbooks || []).slice(0, 6).map((pb, i) =>
            React.createElement(React.Fragment, { key: pb },
              React.createElement('span', {
                style: {
                  padding: '3px 8px', borderRadius: 5,
                  background: 'var(--bg-panel)', color: 'var(--text-primary)',
                  fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 600,
                  border: `1px solid ${'var(--border-dim)'}`,
                }
              }, pb),
              i < Math.min(5, (single.playbooks || []).length - 1) &&
                React.createElement('span', { style: { color: 'var(--text-muted)', fontSize: 10, alignSelf: 'center' } }, '→')
            )
          )
        )
      )
    ),

    // Multi-host breakdown
    hostList.length > 0 && React.createElement('div', { style: { display: 'grid', gap: 6 } },
      hostList.slice(0, 8).map(([host, c]) =>
        React.createElement('div', {
          key: host,
          style: {
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '6px 10px', background: 'var(--bg-panel)', borderRadius: 6,
            borderLeft: `3px solid ${osColor(c?.os_family)}`,
          }
        },
          React.createElement('span', {
            style: { fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', flex: 1 }
          }, host),
          React.createElement('span', {
            style: {
              padding: '1px 7px', borderRadius: 10, fontSize: 9, fontWeight: 700,
              background: `${osColor(c?.os_family)}15`,
              color: osColor(c?.os_family),
              fontFamily: 'var(--font-mono)', letterSpacing: 0.4,
            }
          }, (c?.kind || 'unknown').replace(/_/g, ' ')),
          React.createElement('span', {
            style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
          }, `p${c?.priority || 0}`)
        )
      ),
      hostList.length > 8 && React.createElement('div', {
        style: { fontSize: 10, color: 'var(--text-muted)', fontStyle: 'italic', textAlign: 'center', marginTop: 4 }
      }, `+ ${hostList.length - 8} more — see Mission Control for full host list`)
    )
  );
}

// ─── Active session info card ─────────────────────────────────
function SessionInfoCard({ state, sessionDuration }) {
  const sess = state.activeSession;
  if (!sess) {
    return React.createElement('div', { 'data-slot': 'RiskDashboard.SessionInfoCard',
      style: {
        background: 'var(--bg-surface)',
        border: `1px dashed ${'var(--border)'}`,
        borderRadius: 14, padding: 26, textAlign: 'center',
      }
    },
      React.createElement('div', { style: { fontSize: 28, color: 'var(--text-muted)', marginBottom: 8 } }, '○'),
      React.createElement('div', {
        style: { fontSize: 12, color: 'var(--text-muted)', marginBottom: 12, letterSpacing: 0.5 }
      }, 'No active engagement'),
      React.createElement('button', {
        onClick: () => window.dispatchEvent(new CustomEvent('navigate', { detail: 'target' })),
        style: {
          background: 'var(--accent-subtle)', border: '1px solid var(--accent-glow)',
          color: 'var(--accent)', padding: '6px 16px', borderRadius: 6, cursor: 'pointer',
          fontSize: 11, fontWeight: 600, letterSpacing: 1,
        }
      }, '+ NEW SESSION')
    );
  }

  return React.createElement('div', {
    style: {
      background: 'var(--bg-surface)',
      border: `1px solid ${'var(--border)'}`,
      borderRadius: 14, padding: 22,
    }
  },
    React.createElement('div', {
      style: { fontSize: 11, letterSpacing: 1.5, color: 'var(--text-muted)',
               textTransform: 'uppercase', fontWeight: 700, marginBottom: 12 }
    }, 'Active Engagement'),
    React.createElement('div', {
      style: {
        fontFamily: 'var(--font-mono)', fontSize: 18, fontWeight: 700,
        color: 'var(--accent)', marginBottom: 4,
      }
    }, sess.target_ip || sess.target_hostname || 'unknown'),
    React.createElement('div', {
      style: { fontSize: 11, color: 'var(--text-secondary)', marginBottom: 16 }
    }, sess.target_type || 'pentest'),

    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 } },
      React.createElement('div', null,
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', letterSpacing: 1, fontWeight: 700 } }, 'PHASE'),
        React.createElement('div', { style: { fontSize: 12, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: 2 } },
          state.currentPhase || 'idle'),
      ),
      React.createElement('div', null,
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', letterSpacing: 1, fontWeight: 700 } }, 'DURATION'),
        React.createElement('div', { style: { fontSize: 12, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: 2 } },
          fmtDuration(sessionDuration)),
      ),
    )
  );
}

// ─── Main page ────────────────────────────────────────────────
function RiskDashboard({ sessionId, activeSession, viewMode, client }) {
  const { state } = window.useStore();
  const [now, setNow] = useState(Date.now());
  const vm = viewMode || 'OPERATOR';
  const fontScale = vm === 'BRIEFING' ? 16 : 14;

  // Tick once per second to keep duration live
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const duration = useMemo(() => {
    const sess = state.activeSession;
    if (!sess?.started_at) return 0;
    try {
      const startMs = new Date(sess.started_at).getTime();
      return Math.max(0, Math.floor((now - startMs) / 1000));
    } catch { return 0; }
  }, [state.activeSession, now]);

  const summary = state.findingsSummary || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const score = useMemo(() => calcRiskScore(summary), [summary]);

  // Time-to-foothold — earliest shell registration.  Walks state.shells
  // which contains shell records emitted by the platform's
  // shell_obtained / register_shell events.  Falls back to a flag-found
  // timestamp when no shell is registered but a flag was captured.
  const timeToFoothold = useMemo(() => {
    const shells = state.shells || [];
    const flags  = state.flags  || [];
    const earliestShell = shells
      .filter(sh => sh && (sh.created_at || sh.timestamp || sh.ts))
      .map(sh => new Date(sh.created_at || sh.timestamp || sh.ts).getTime())
      .reduce((a, b) => Math.min(a, b), Infinity);
    const earliestFlag = flags
      .filter(f => f && (f.found_at || f.timestamp))
      .map(f => new Date(f.found_at || f.timestamp).getTime())
      .reduce((a, b) => Math.min(a, b), Infinity);
    const earliest = Math.min(earliestShell, earliestFlag);
    if (!isFinite(earliest) || !state.activeSession?.started_at) return null;
    try {
      const startMs = new Date(state.activeSession.started_at).getTime();
      return Math.max(0, Math.floor((earliest - startMs) / 1000));
    } catch { return null; }
  }, [state.shells, state.flags, state.activeSession]);

  const shells = state.shells || [];
  const confirmedShells = shells.filter(s => s && (s.active !== false)).length;
  // Open-ports / services are emitted via subagent_finding events but
  // not stored as a top-level summary slice.  Best proxy is the host
  // discovery count + planSteps progress.
  const hosts = (state.discoveredHosts || []).length;
  const planDone = (state.phasesCompleted || []).length;
  const openPorts = hosts || (planDone > 0 ? planDone : 0);
  const services = (state.subagentStates && Object.keys(state.subagentStates).length) || 0;

  return React.createElement('div', { 'data-slot': 'RiskDashboard.RiskDashboard',
    'data-view-mode': vm,
    className: vm === 'CLIENT' ? 'client-mode' : undefined,
    style: { fontSize: fontScale },
  },
   React.createElement('div', {
    style: {
      maxWidth: 1400, margin: '0 auto', padding: '4px 0',
      fontFamily: 'var(--font-ui)', color: 'var(--text-primary)',
    }
  },

    // ── Page header ──────────────────────────────────────────
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between',
               alignItems: 'flex-end', marginBottom: 22 }
    },
      React.createElement('div', null,
        React.createElement('div', {
          style: { fontSize: 11, letterSpacing: 2, color: 'var(--accent)',
                   textTransform: 'uppercase', fontWeight: 700, marginBottom: 4 }
        }, '◈ RISK COMMAND DASHBOARD'),
        React.createElement('div', {
          style: { fontSize: 24, fontWeight: 700, color: 'var(--text-primary)' }
        }, 'Cyber Risk View'),
        React.createElement('div', {
          style: { fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }
        }, 'Real-time engagement posture, kill-chain progress and exploitation telemetry.')
      ),
      React.createElement('div', { style: { display: 'flex', gap: 8 } },
        React.createElement('button', {
          onClick: () => window.dispatchEvent(new CustomEvent('navigate', { detail: 'mission' })),
          style: {
            background: 'var(--bg-panel)', border: `1px solid ${'var(--border)'}`,
            color: 'var(--text-secondary)', padding: '8px 14px', borderRadius: 8,
            cursor: 'pointer', fontSize: 11, fontWeight: 600, letterSpacing: 0.5,
          }
        }, 'Mission Control'),
        React.createElement('button', {
          onClick: () => window.dispatchEvent(new CustomEvent('navigate', { detail: 'findings' })),
          style: {
            background: 'var(--accent-subtle)', border: '1px solid var(--accent-glow)',
            color: 'var(--accent)', padding: '8px 14px', borderRadius: 8,
            cursor: 'pointer', fontSize: 11, fontWeight: 700, letterSpacing: 0.5,
          }
        }, 'View All Findings →'),
      )
    ),

    // ── Top stat tiles row ────────────────────────────────────
    React.createElement('div', {
      style: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: 12, marginBottom: 18,
      }
    },
      React.createElement(StatTile, {
        label: hosts ? 'Discovered Hosts' : 'Phases Completed',
        value: openPorts,
        color: 'var(--cyan)', accent: 'var(--cyan)',
        sub: services ? `${services} active subagent${services !== 1 ? 's' : ''}` : 'awaiting first finding',
      }),
      React.createElement(StatTile, {
        label: 'Total Findings', value: summary.total || 0, color: 'var(--text-primary)', accent: 'var(--accent)',
        sub: `${summary.critical || 0} critical · ${summary.high || 0} high`,
      }),
      React.createElement(StatTile, {
        label: 'Confirmed Shells', value: confirmedShells, color: confirmedShells > 0 ? 'var(--low)' : 'var(--text-muted)', accent: confirmedShells > 0 ? 'var(--low)' : 'var(--border)',
        sub: `${shells.length - confirmedShells} pending`,
      }),
      React.createElement(StatTile, {
        label: 'Time to Foothold',
        value: timeToFoothold !== null ? fmtDuration(timeToFoothold) : '—',
        color: timeToFoothold !== null ? 'var(--low)' : 'var(--text-muted)',
        accent: timeToFoothold !== null ? 'var(--low)' : 'var(--border)',
        sub: timeToFoothold !== null ? 'first shell registered' : 'not yet achieved',
      }),
      React.createElement(StatTile, {
        label: 'Engagement Time',
        value: state.activeSession ? fmtDuration(duration) : '—',
        color: 'var(--text-primary)',
        sub: state.currentPhase ? `phase: ${state.currentPhase}` : 'no active session',
      }),
    ),

    // ── Risk gauge + Kill-chain row ──────────────────────────
    React.createElement('div', {
      className: 'hero-tilt',
      style: { display: 'grid', gridTemplateColumns: '380px 1fr', gap: 14, marginBottom: 18 }
    },
      React.createElement(RiskGauge, { score, summary }),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
        React.createElement(KillChainStrip, { state }),
        React.createElement(SessionInfoCard, { state, sessionDuration: duration })
      )
    ),

    // ── Device taxonomy strip (full width) ─────────────────────
    (state.deviceClassification || (state.hostClassifications && Object.keys(state.hostClassifications).length))
      ? React.createElement('div', { style: { marginBottom: 14 } },
          React.createElement(DeviceTaxonomyCard, { state })
        )
      : null,

    // ── Severity + Loot + Primer + Hypotheses grid ────────────
    React.createElement('div', {
      style: { display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }
    },
      React.createElement(SeverityTreemap, { summary }),
      React.createElement(LootCard, { state }),
      React.createElement(PrimerCoverageCard, { state }),
      React.createElement(TopHypothesesCard, { state }),
    ),
   )
  );
}

// ─── Expose globally so app.jsx can pick it up ───────────────
window.RiskDashboard = RiskDashboard;
})();
