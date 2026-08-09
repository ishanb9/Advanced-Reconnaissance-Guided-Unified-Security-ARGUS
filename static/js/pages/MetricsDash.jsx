// ═══════════════════════════════════════════════════════════
// MetricsDash.jsx — System resource monitor
// Polls /metrics every 3s for CPU, RAM, disk, network
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useRef } = React;

function GaugeBar({ label, value, max = 100, color, unit = '%', warn = 70, danger = 90 }) {
  const pct   = Math.min(100, (value / max) * 100);
  const barColor = pct >= danger ? 'var(--critical)' : pct >= warn ? 'var(--medium)' : color || 'var(--low)';
  return React.createElement('div', { 'data-slot': 'MetricsDash.GaugeBar', style: { marginBottom: 14 } },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between', marginBottom: 5, fontSize: 11 }
    },
      React.createElement('span', { style: { color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, label),
      React.createElement('span', {
        style: { color: barColor, fontFamily: 'var(--font-mono)', fontWeight: 600 }
      }, `${typeof value === 'number' ? value.toFixed(1) : value}${unit}`)
    ),
    React.createElement('div', {
      style: {
        height: 5, borderRadius: 4, background: 'var(--bg-elevated)',
        border: '1px solid var(--border)', overflow: 'hidden'
      }
    },
      React.createElement('div', {
        style: {
          height: '100%', width: `${pct}%`, borderRadius: 4,
          background: barColor,
          boxShadow: pct > 60 ? `0 0 8px ${barColor}44` : 'none',
          transition: 'width 0.4s ease, background 0.3s'
        }
      })
    )
  );
}

function CircularGauge({ label, value, max = 100, color, unit = '%', warn = 70, danger = 90 }) {
  const pct      = Math.min(100, (value / max) * 100);
  const barColor = pct >= danger ? 'var(--critical)' : pct >= warn ? 'var(--medium)' : color || 'var(--low)';
  const circumference = 226;
  const arcLength     = 170; // 75% of circumference (270/360 sweep)
  const filled        = (pct / 100) * arcLength;

  return React.createElement('div', { 'data-slot': 'MetricsDash.CircularGauge',
    style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }
  },
    React.createElement('svg', {
      viewBox: '0 0 90 90', width: 90, height: 90,
      style: { display: 'block', overflow: 'visible' }
    },
      // Track circle (background)
      React.createElement('circle', {
        cx: 45, cy: 45, r: 36,
        fill: 'none',
        stroke: 'var(--bg-elevated)',
        strokeWidth: 7,
        opacity: 0.3,
      }),
      // Value arc
      React.createElement('circle', {
        cx: 45, cy: 45, r: 36,
        fill: 'none',
        stroke: barColor,
        strokeWidth: 7,
        strokeLinecap: 'round',
        strokeDasharray: `${filled} ${circumference}`,
        strokeDashoffset: 0,
        transform: 'rotate(-225 45 45)',
        style: { transition: 'stroke-dasharray 0.4s ease, stroke 0.3s' }
      }),
      // Center value text
      React.createElement('text', {
        x: 45, y: 43,
        textAnchor: 'middle', dominantBaseline: 'middle',
        style: {
          fontSize: 12, fontWeight: 700,
          fill: 'var(--text-primary)',
          fontFamily: 'var(--font-mono)',
        }
      }, `${typeof value === 'number' ? value.toFixed(1) : value}${unit}`),
      // Label below value
      React.createElement('text', {
        x: 45, y: 56,
        textAnchor: 'middle', dominantBaseline: 'middle',
        style: {
          fontSize: 8,
          fill: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)',
        }
      }, label)
    )
  );
}

function SparkLine({ history, color = 'var(--cyan)', height = 40 }) {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || history.length < 2) return;
    const ctx    = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    const max = Math.max(...history, 1);
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = color;
    ctx.lineWidth   = 1.5;
    ctx.beginPath();
    history.forEach((v, i) => {
      const x = (i / (history.length - 1)) * w;
      const y = h - (v / max) * h;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
  }, [history]);
  return React.createElement('canvas', { 'data-slot': 'MetricsDash.SparkLine',
    ref: canvasRef, width: 200, height,
    style: { width: '100%', height, display: 'block', opacity: 0.8 }
  });
}

function fmt(bytes) {
  if (bytes > 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes > 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes > 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function MetricsDash() {
  const [metrics,   setMetrics]   = useState(null);
  const [error,     setError]     = useState('');
  const [cpuHist,   setCpuHist]   = useState([]);
  const [memHist,   setMemHist]   = useState([]);
  const [netSentRef, setNetSentRef] = useState(0);
  const [netRecvRef, setNetRecvRef] = useState(0);
  const [netSentRate, setNetSentRate] = useState(0);
  const [netRecvRate, setNetRecvRate] = useState(0);

  async function poll() {
    try {
      const m = await window.API.metrics();
      setMetrics(m);
      setError('');
      setCpuHist(h => [...h, m.cpu?.overall || 0].slice(-60));
      setMemHist(h => [...h, m.memory?.percent || 0].slice(-60));
      // Calculate network rate
      setNetSentRef(prev => {
        const rate = Math.max(0, m.network.bytes_sent - prev) / 3;
        setNetSentRate(rate);
        return m.network.bytes_sent;
      });
      setNetRecvRef(prev => {
        const rate = Math.max(0, m.network.bytes_recv - prev) / 3;
        setNetRecvRate(rate);
        return m.network.bytes_recv;
      });
    } catch (e) {
      setError('Cannot reach /metrics — is the server running?');
    }
  }

  useEffect(() => {
    poll();
    const t = setInterval(poll, 3000);
    return () => clearInterval(t);
  }, []);

  const card = {
    background: 'var(--bg-surface)', border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)', padding: '16px'
  };
  const sectionTitle = {
    fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase',
    letterSpacing: 1.2, marginBottom: 12, fontFamily: 'var(--font-mono)', fontWeight: 600
  };

  const uptime = metrics
    ? (() => {
        const s = Math.floor(metrics.uptime_sec || 0);
        const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
        return `${h}h ${m}m`;
      })()
    : '--';

  return React.createElement('div', { 'data-slot': 'MetricsDash.MetricsDash',
    style: { padding: 16, height: '100%', overflowY: 'auto', background: 'var(--bg-base, #0a0a0a)' }
  },
    React.createElement('div', { className: 'page-header', style: { marginBottom: 16 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '📊 System Metrics'),
        React.createElement('div', { className: 'page-subtitle' }, 'Kali host resource monitor — refreshes every 3s')
      ),
      error
        ? React.createElement('span', { style: { color: 'var(--red)', fontSize: 11 } }, error)
        : React.createElement('span', { style: { color: 'var(--low)', fontSize: 11, fontFamily: 'var(--font-mono)' } }, '● live')
    ),

    !metrics
      ? React.createElement('div', { style: { color: 'var(--text-muted)', textAlign: 'center', paddingTop: 60 } }, 'Loading...')
      : React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 } },

          // CPU
          React.createElement('div', { style: card },
            React.createElement('div', { style: sectionTitle }, '⚡ CPU'),
            React.createElement('div', { style: { display: 'flex', justifyContent: 'center', marginBottom: 10 } },
              React.createElement(CircularGauge, { label: 'Overall', value: metrics.cpu.overall, color: 'var(--cyan)' })
            ),
            metrics.cpu.per_core && metrics.cpu.per_core.slice(0, 8).map((v, i) =>
              React.createElement(GaugeBar, { key: i, label: `Core ${i}`, value: v, color: 'var(--cyan)' })
            ),
            React.createElement('div', { style: { marginTop: 8 } },
              React.createElement(SparkLine, { history: cpuHist, color: 'var(--cyan)' })
            ),
            React.createElement('div', { style: { marginTop: 6, display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)' } },
              React.createElement('span', null, `${metrics.cpu.count} cores`),
              React.createElement('span', null, `${metrics.cpu.freq_mhz?.toFixed(0)} MHz`)
            )
          ),

          // Memory + Disk
          React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
            React.createElement('div', { style: card },
              React.createElement('div', { style: sectionTitle }, '🧠 Memory'),
              React.createElement('div', { style: { display: 'flex', justifyContent: 'center', marginBottom: 8 } },
                React.createElement(CircularGauge, { label: 'Used', value: metrics.memory.percent, color: 'var(--amber)' })
              ),
              React.createElement(SparkLine, { history: memHist, color: 'var(--amber)', height: 30 }),
              React.createElement('div', {
                style: { marginTop: 6, display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)' }
              },
                React.createElement('span', null, `${metrics.memory.used_gb} GB used`),
                React.createElement('span', null, `${metrics.memory.total_gb} GB total`)
              )
            ),
            React.createElement('div', { style: card },
              React.createElement('div', { style: sectionTitle }, '💾 Disk'),
              React.createElement('div', { style: { display: 'flex', justifyContent: 'center', marginBottom: 8 } },
                React.createElement(CircularGauge, { label: 'Used', value: metrics.disk.percent, color: 'var(--green)' })
              ),
              React.createElement('div', {
                style: { marginTop: 4, display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)' }
              },
                React.createElement('span', null, `${metrics.disk.used_gb} GB used`),
                React.createElement('span', null, `${metrics.disk.free_gb} GB free`)
              )
            )
          ),

          // Network + System
          React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
            React.createElement('div', { style: card },
              React.createElement('div', { style: sectionTitle }, '🌐 Network'),
              React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
                [
                  ['↑ Sent',    fmt(metrics.network.bytes_sent), fmt(netSentRate) + '/s'],
                  ['↓ Recv',    fmt(metrics.network.bytes_recv), fmt(netRecvRate) + '/s'],
                  ['Pkts sent', metrics.network.packets_sent?.toLocaleString(), ''],
                  ['Pkts recv', metrics.network.packets_recv?.toLocaleString(), ''],
                ].map(([lbl, val, rate]) =>
                  React.createElement('div', { key: lbl, style: { display: 'flex', justifyContent: 'space-between', fontSize: 11 } },
                    React.createElement('span', { style: { color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, lbl),
                    React.createElement('span', { style: { color: 'var(--cyan)', fontFamily: 'var(--font-mono)' } },
                      `${val}${rate ? ' · ' + rate : ''}`)
                  )
                )
              )
            ),
            React.createElement('div', { style: card },
              React.createElement('div', { style: sectionTitle }, '🖥 System'),
              React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 } },
                [
                  ['Processes', metrics.processes],
                  ['Uptime',    uptime],
                  ['CPU cores', metrics.cpu.count],
                  ['Total RAM', `${metrics.memory.total_gb} GB`],
                  ['Disk total', `${metrics.disk.total_gb} GB`],
                ].map(([lbl, val]) =>
                  React.createElement('div', { key: lbl, style: { display: 'flex', justifyContent: 'space-between' } },
                    React.createElement('span', { style: { color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, lbl),
                    React.createElement('span', { style: { color: 'var(--text-primary)' } }, val)
                  )
                )
              )
            )
          )
        )
  );
}

window.MetricsDash = MetricsDash;
