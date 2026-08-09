// ReportPage.jsx — View and export pentest report (HTML/PDF)
const { useState, useEffect, useRef } = React;
const { Card, Button, Alert, Tag, Space } = window.antd;

function ReportPage(props) {
  const { state } = window.useStore();
  const sessionId  = state.sessionId;
  const { activeSession, findingsSummary, flags, currentPhase } = state;
  const vm = (props && props.viewMode) || 'OPERATOR';
  const fontScale = vm === 'BRIEFING' ? 16 : 14;

  const [loading, setLoading]   = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const iframeRef = useRef(null);

  // Two selectable report designs — Dark and Light. The chosen theme is threaded
  // into every report URL (preview iframe, Export PDF, Print / Save-as-PDF), so the
  // operator generates exactly the design they picked.
  const [theme, setTheme] = useState('dark');
  // [70] Drive the picker from the backend theme registry (/report/themes) so it
  // can never drift from what the server actually renders.  The dark/light literal
  // is kept as the fallback if the fetch fails (preserves today's behavior offline).
  const [themes, setThemes] = useState([['dark', '◐ Dark'], ['light', '◑ Light']]);
  useEffect(() => {
    window.API.reportThemes()
      .then(list => {
        const arr = Array.isArray(list) ? list : (list && list.themes);
        if (Array.isArray(arr) && arr.length) {
          setThemes(arr.map(t => [t.key, t.name || t.key]));
        }
      })
      .catch(() => {});
  }, []);
  useEffect(() => { if (sessionId) preview(); }, [sessionId, theme]);

  // Report URL (reportUrl carries ?format= and the selected &theme=).
  function reportUrlT(fmt) {
    return window.API.reportUrl(sessionId, fmt, theme);
  }

  async function preview() {
    if (!sessionId) return;
    setPreviewing(true);
    if (iframeRef.current) {
      iframeRef.current.src = reportUrlT('html') + '&_t=' + Date.now();
    }
  }

  function openInNewTab() {
    if (!sessionId) return;
    window.open(reportUrlT('html'), '_blank');
  }

  // Browser print-to-PDF fallback (zero-dependency, pixel-perfect) — used when
  // the server has no styled PDF engine (weasyprint absent). Opens the styled
  // themed report and triggers the print dialog ("Save as PDF").
  function printToPdf() {
    if (!sessionId) return;
    const w = window.open(reportUrlT('html'), '_blank');
    if (!w) return;
    const t = setInterval(() => {
      try {
        if (w.document && w.document.readyState === 'complete') {
          clearInterval(t); w.focus(); w.print();
        }
      } catch (e) { clearInterval(t); }
    }, 400);
    setTimeout(() => { try { clearInterval(t); } catch (e) {} }, 8000);
  }

  async function downloadPDF() {
    if (!sessionId) return;
    try {
      const res = await fetch(reportUrlT('pdf'));
      const ct = (res.headers.get('content-type') || '');
      if (res.ok && ct.indexOf('pdf') >= 0) {
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `pentest_report_${sessionId.slice(-8)}.pdf`;
        a.click();
        setTimeout(() => { try { URL.revokeObjectURL(a.href); } catch (e) {} }, 4000);
        return;
      }
      // 503 / X-PDF-Engine: none → browser print-to-PDF of the styled report.
      printToPdf();
    } catch (e) {
      printToPdf();
    }
  }

  const canExport = sessionId && activeSession;

  const sevColor = { critical: 'var(--red)', high: 'var(--amber)',
                     medium: 'var(--amber)', low: 'var(--cyan)', info: 'var(--text-muted)' };

  return React.createElement('div', { 'data-slot': 'ReportPage.ReportPage',
    'data-view-mode': vm,
    className: vm === 'CLIENT' ? 'client-mode' : undefined,
    style: { fontSize: fontScale, height: '100%' },
  },
   React.createElement('div', { style: { display: 'flex', flexDirection: 'column', height: 'calc(100vh - 60px)' } },

    // Header
    React.createElement('div', { className: 'page-header' },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '📄 Report Generator'),
        activeSession && React.createElement('div', { className: 'page-subtitle' },
          `Target: ${activeSession.target_ip} · Session: ${sessionId?.slice(-8)}`)
      ),
      React.createElement('div', { style: { display: 'flex', gap: 8, alignItems: 'center' } },
        // Report design selector — Dark / Light (segmented toggle).
        React.createElement('div', {
          style: { display: 'flex', border: '1px solid var(--border-light)', borderRadius: 6,
                   overflow: 'hidden', marginRight: 4 },
          title: 'Report design'
        },
          ...themes.map(([key, label]) =>
            React.createElement('button', {
              key,
              onClick: () => setTheme(key),
              style: { padding: '6px 12px', border: 'none', cursor: 'pointer', fontSize: 12,
                       fontWeight: theme === key ? 700 : 400,
                       background: theme === key ? 'var(--accent)' : 'transparent',
                       color: theme === key ? '#0D0E14' : 'var(--text-secondary)' }
            }, label)
          )
        ),
        React.createElement('button', {
          style: { padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border-light)',
                   background: 'rgba(255,255,255,0.04)', color: canExport ? 'var(--text-secondary)' : 'var(--text-muted)',
                   cursor: canExport ? 'pointer' : 'not-allowed', fontSize: 12 },
          onClick: preview, disabled: !canExport
        }, '↻ Refresh'),
        React.createElement('button', {
          style: { padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border-light)',
                   background: 'rgba(255,255,255,0.04)',
                   color: canExport ? 'var(--text-secondary)' : 'var(--text-muted)',
                   cursor: canExport ? 'pointer' : 'not-allowed', fontSize: 12 },
          onClick: openInNewTab, disabled: !canExport
        }, '↗ Full Page'),
        React.createElement('button', {
          style: { padding: '6px 14px', borderRadius: 6,
                   border: canExport ? '1px solid var(--accent)' : '1px solid var(--border)',
                   background: canExport ? 'var(--accent)' : 'transparent',
                   color: canExport ? '#0D0E14' : 'var(--text-muted)',
                   cursor: canExport ? 'pointer' : 'not-allowed', fontSize: 12, fontWeight: 600,
                   boxShadow: canExport ? '0 0 10px var(--accent-glow)' : 'none' },
          onClick: downloadPDF, disabled: !canExport
        }, '⬇ Export PDF'),
        React.createElement('button', {
          style: { padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border-light)',
                   background: 'rgba(255,255,255,0.04)',
                   color: canExport ? 'var(--text-secondary)' : 'var(--text-muted)',
                   cursor: canExport ? 'pointer' : 'not-allowed', fontSize: 12 },
          onClick: printToPdf, disabled: !canExport,
          title: 'Open the styled report and Save as PDF via the browser (works without weasyprint)'
        }, '🖨 Print / Save as PDF')
      )
    ),

    !sessionId && React.createElement(Alert, {
      type: 'info',
      message: 'No active session',
      description: 'Start a pentest session to generate a report.',
      style: { margin: '0 0 16px 0' },
      showIcon: true
    }),

    // Quick stats
    sessionId && React.createElement('div', {
      style: { display: 'flex', gap: 10, marginBottom: 14, flexShrink: 0 }
    },
      ...Object.entries(findingsSummary).filter(([k]) => k !== 'total').map(([sev, count]) =>
        React.createElement('div', {
          key: sev,
          style: { padding: '8px 16px', borderRadius: 6, background: 'var(--bg-card)',
                   border: `1px solid var(--border)`, textAlign: 'center', minWidth: 80 }
        },
          React.createElement('div', {
            style: { fontSize: 22, fontWeight: 700, color: sevColor[sev] || 'var(--text-primary)' }
          }, count),
          React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' } }, sev)
        )
      ),
      React.createElement('div', {
        style: { padding: '8px 16px', borderRadius: 6, background: 'var(--bg-card)',
                 border: '1px solid var(--border)', textAlign: 'center', minWidth: 80 }
      },
        React.createElement('div', { style: { fontSize: 22, fontWeight: 700, color: 'var(--accent)' } },
          flags.length),
        React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' } }, 'Flags')
      )
    ),

    // iframe report preview
    sessionId && React.createElement('div', {
      style: { flex: 1, borderRadius: 8, overflow: 'hidden',
               border: '1px solid var(--border-light)', background: '#fff',
               boxShadow: '0 0 0 1px var(--border)' }
    },
      React.createElement('iframe', {
        ref: iframeRef,
        src: reportUrlT('html'),
        style: { width: '100%', height: '100%', border: 'none' },
        onLoad: () => setPreviewing(false)
      })
    ),

    !sessionId && React.createElement('div', {
      style: { flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
               background: 'var(--bg-card)', borderRadius: 8, border: '1px solid var(--border)' }
    },
      React.createElement('div', { style: { textAlign: 'center', color: 'var(--text-muted)' } },
        React.createElement('div', { style: { fontSize: 64, marginBottom: 16 } }, '📄'),
        React.createElement('div', { style: { fontSize: 16, marginBottom: 8 } }, 'Report Preview'),
        React.createElement('div', { style: { fontSize: 12 } },
          'Start a session and run a pentest to generate a professional report')
      )
    )
   )
  );
}
window.ReportPage = ReportPage;
