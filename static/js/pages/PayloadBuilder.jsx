// PayloadBuilder.jsx — msfvenom payload generation + history
const { useState, useEffect } = React;
const { Card, Tag } = window.antd;


const PLATFORMS = ['linux','windows','osx','android','java','php','python','powershell','asp','aspx'];

const SEV_COLOR = {
  linux: 'var(--green)', windows: 'var(--cyan)', osx: 'var(--text-secondary)',
  android: 'var(--amber)', java: 'var(--amber)', php: 'var(--purple)',
  python: 'var(--cyan)', powershell: 'var(--cyan)',
  asp: 'var(--red)', aspx: 'var(--red)'
};

const PLATFORM_ICON = {
  linux: '🐧', windows: '🪟', osx: '🍎', android: '🤖', java: '☕',
  php: '🐘', python: '🐍', powershell: '💠', asp: '🔷', aspx: '🔷'
};

function PayloadBuilder() {
  const { state } = window.useStore();
  const sessionId  = state.sessionId;

  const [options,    setOptions]    = useState(null);
  const [payloads,   setPayloads]   = useState([]);
  const [generating, setGenerating] = useState(false);
  const [form, setForm] = useState({
    platform: 'linux', arch: 'x64', format: 'elf',
    lhost: '', lport: 4444, payload_type: 'staged',
    encoder: '', iterations: 1, custom_payload: ''
  });
  const [lastResult, setLastResult] = useState(null);
  const [loadingHistory, setLoadingHistory] = useState(false);

  useEffect(() => { loadOptions(); }, []);
  useEffect(() => { if (sessionId) loadHistory(); }, [sessionId]);

  // Auto-update arch/format when platform changes
  useEffect(() => {
    if (!options) return;
    const defaults = options.platform_defaults?.[form.platform];
    if (defaults) {
      setForm(f => ({ ...f, arch: defaults.arch, format: defaults.format }));
    }
  }, [form.platform, options]);

  async function loadOptions() {
    try {
      const res = await window.API.payloadOptions();
      setOptions(res);
    } catch {}
  }

  async function loadHistory() {
    if (!sessionId) return;
    setLoadingHistory(true);
    try {
      const res = await window.API.payloads(sessionId);
      setPayloads(res.payloads || []);
    } catch {}
    setLoadingHistory(false);
  }

  async function generate() {
    if (!sessionId) return alert('Start a session first');
    setGenerating(true);
    setLastResult(null);
    try {
      const body = {
        session_id:    sessionId,
        platform:      form.platform,
        arch:          form.arch,
        format:        form.format,
        lhost:         form.lhost || undefined,
        lport:         parseInt(form.lport),
        payload_type:  form.payload_type,
        encoder:       form.encoder || undefined,
        iterations:    parseInt(form.iterations),
        custom_payload: form.custom_payload || undefined,
      };
      const res = await window.API.generatePayload(body);
      setLastResult(res);
      await loadHistory();
    } catch (e) {
      setLastResult({ error: e.message });
    }
    setGenerating(false);
  }

  async function deletePayload(id) {
    try {
      await window.API.deletePayload(id);
      setPayloads(p => p.filter(x => x.id !== id));
    } catch {}
  }

  const formatOpts   = options?.format_options?.[form.platform] || ['raw'];
  const encoderOpts  = options?.encoder_options || [];
  const archDefaults = { linux: ['x86','x64'], windows: ['x86','x64'], osx: ['x64'],
                          android: ['dalvik'], java: ['java'], php: ['php'],
                          python: ['python'], powershell: ['cmd'], asp: ['x86'], aspx: ['x64'] };
  const archOpts = archDefaults[form.platform] || ['x86','x64'];

  const inputStyle = {
    width: '100%', padding: '7px 10px', borderRadius: 'var(--radius)', fontFamily: 'var(--font-mono)',
    border: '1px solid var(--border)', background: 'var(--bg-panel)',
    color: 'var(--text-primary)', fontSize: 12
  };
  const labelStyle = { fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 };

  function Field({ label, children }) {
    return React.createElement('div', null,
      React.createElement('div', { style: labelStyle }, label),
      children
    );
  }

  function Select2({ value, onChange, children }) {
    return React.createElement('select', {
      value, onChange, style: inputStyle
    }, children);
  }

  return React.createElement('div', null,

    React.createElement('div', { className: 'page-header' },
      React.createElement('div', { className: 'page-title' }, '⚙ Payload Builder'),
      React.createElement('div', { className: 'page-subtitle' }, 'msfvenom payload generation')
    ),

    !sessionId && React.createElement('div', {
      style: { padding: '10px 14px', borderRadius: 6, marginBottom: 16,
               background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.25)',
               color: 'var(--cyan)', fontSize: 12 }
    }, 'ℹ Start a session to generate payloads'),

    React.createElement('div', { style: { display: 'flex', gap: 14 } },

      // ── Config panel ─────────────────────────────────────
      React.createElement('div', { style: { width: 320, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12 } },

        React.createElement('div', {
          style: { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }
        },
          React.createElement('div', { style: { padding: '10px 14px', borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' } }, '⚙ Configure Payload'),
          React.createElement('div', { style: { padding: '14px', display: 'flex', flexDirection: 'column', gap: 12 } },

            // Platform selector
            React.createElement('div', null,
              React.createElement('div', { style: labelStyle }, 'Platform'),
              React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 6 } },
                PLATFORMS.map(p => React.createElement('button', {
                  key: p,
                  style: {
                    padding: '4px 10px', borderRadius: 4, cursor: 'pointer', fontSize: 11,
                    border: `1px solid ${form.platform === p ? SEV_COLOR[p] || 'var(--cyan)' : 'var(--border)'}`,
                    background: form.platform === p ? 'rgba(0,212,255,0.08)' : 'transparent',
                    color: form.platform === p ? 'var(--text-primary)' : 'var(--text-muted)'
                  },
                  onClick: () => setForm(f => ({ ...f, platform: p }))
                }, `${PLATFORM_ICON[p] || ''} ${p}`))
              )
            ),

            // Arch
            React.createElement(Field, { label: 'Architecture' },
              React.createElement(Select2, {
                value: form.arch,
                onChange: e => setForm(f => ({ ...f, arch: e.target.value }))
              },
                archOpts.map(a => React.createElement('option', { key: a, value: a }, a))
              )
            ),

            // Format
            React.createElement(Field, { label: 'Output Format' },
              React.createElement(Select2, {
                value: form.format,
                onChange: e => setForm(f => ({ ...f, format: e.target.value }))
              },
                formatOpts.map(fmt => React.createElement('option', { key: fmt, value: fmt }, fmt))
              )
            ),

            // Payload type
            React.createElement(Field, { label: 'Payload Type' },
              React.createElement(Select2, {
                value: form.payload_type,
                onChange: e => setForm(f => ({ ...f, payload_type: e.target.value }))
              },
                ['staged','stageless','shell'].map(t =>
                  React.createElement('option', { key: t, value: t },
                    t === 'staged' ? 'Staged (meterpreter/)' :
                    t === 'stageless' ? 'Stageless (meterpreter_)' : 'Shell (shell_)')
                )
              )
            ),

            // LHOST
            React.createElement(Field, { label: 'LHOST (auto-detected if blank)' },
              React.createElement('input', {
                style: inputStyle, placeholder: 'e.g. 10.10.14.5 (leave blank for auto)',
                value: form.lhost,
                onChange: e => setForm(f => ({ ...f, lhost: e.target.value }))
              })
            ),

            // LPORT
            React.createElement(Field, { label: 'LPORT' },
              React.createElement('input', {
                style: inputStyle, type: 'number',
                value: form.lport,
                onChange: e => setForm(f => ({ ...f, lport: e.target.value }))
              })
            ),

            // Encoder
            React.createElement(Field, { label: 'Encoder' },
              React.createElement(Select2, {
                value: form.encoder,
                onChange: e => setForm(f => ({ ...f, encoder: e.target.value }))
              },
                encoderOpts.map(e => React.createElement('option', { key: e.value, value: e.value }, e.label))
              )
            ),

            // Iterations (shown only when encoder selected)
            form.encoder && React.createElement(Field, { label: 'Encode Iterations' },
              React.createElement('input', {
                style: inputStyle, type: 'number', min: 1, max: 20,
                value: form.iterations,
                onChange: e => setForm(f => ({ ...f, iterations: e.target.value }))
              })
            ),

            // Custom payload override
            React.createElement(Field, { label: 'Custom Payload (override)' },
              React.createElement('input', {
                style: inputStyle,
                placeholder: 'e.g. linux/x64/meterpreter/reverse_tcp',
                value: form.custom_payload,
                onChange: e => setForm(f => ({ ...f, custom_payload: e.target.value }))
              })
            ),

            // Generate button
            React.createElement('button', {
              style: {
                marginTop: 4, padding: '10px', borderRadius: 6, cursor: generating ? 'wait' : 'pointer',
                border: generating ? '1px solid var(--border)' : '1px solid var(--accent)',
                background: generating ? 'var(--bg-panel)' : 'var(--accent)',
                color: generating ? 'var(--text-muted)' : '#0D0E14', fontWeight: 700,
                fontSize: 13, letterSpacing: 0.5,
                boxShadow: generating ? 'none' : '0 0 10px var(--accent-glow)'
              },
              onClick: generate, disabled: generating
            }, generating
              ? React.createElement('span', null, '⚙ Generating...')
              : '⚡ Generate Payload'
            )
          )
        ),

        // Last result
        lastResult && React.createElement(Card, {
          title: lastResult.error ? '✗ Generation Failed' : '✓ Payload Ready',
          headStyle: { color: lastResult.error ? 'var(--red)' : 'var(--green)' }
        },
          lastResult.error
            ? React.createElement('div', { style: { color: 'var(--red)', fontSize: 12, fontFamily: 'var(--font-mono)' } },
                lastResult.error)
            : React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
                ...[ 
                  ['Payload',   lastResult.payload_name],
                  ['Path',      lastResult.output_path],
                  ['Size',      `${lastResult.size_bytes} bytes`],
                  ['Listener',  lastResult.listener_cmd],
                ].map(([k,v]) => React.createElement('div', { key: k },
                  React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' } }, k),
                  React.createElement('div', {
                    style: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--green)',
                             background: 'rgba(0,255,136,0.04)', padding: '3px 8px', borderRadius: 4,
                             display: 'flex', alignItems: 'center', justifyContent: 'space-between' }
                  },
                    React.createElement('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, v),
                    React.createElement('button', {
                      style: { padding: '0 4px', border: 'none', background: 'transparent',
                               color: 'var(--text-muted)', cursor: 'pointer', flexShrink: 0 },
                      onClick: () => navigator.clipboard.writeText(v)
                    }, '📋')
                  )
                ))
              )
        )
      ),

      // ── Payload history ───────────────────────────────────
      React.createElement('div', { style: { flex: 1 } },
        React.createElement(Card, {
          title: `📦 Payload History (${payloads.length})`,
          loading: loadingHistory,
          extra: React.createElement('button', {
            style: { padding: '3px 10px', borderRadius: 4, border: '1px solid var(--border-light)',
                     background: 'rgba(255,255,255,0.04)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 11 },
            onClick: loadHistory
          }, '↻ Refresh')
        },
          payloads.length === 0
            ? React.createElement('div', {
                style: { color: 'var(--text-muted)', textAlign: 'center', padding: 60 }
              },
                React.createElement('div', { style: { fontSize: 32, marginBottom: 8 } }, '⚙'),
                'No payloads generated yet'
              )
            : payloads.map(p => React.createElement('div', {
                key: p.id,
                style: { padding: '12px 16px', borderRadius: 6, marginBottom: 8,
                         border: `1px solid ${p.success ? 'var(--border)' : 'rgba(255,68,102,0.3)'}`,
                         background: p.success ? 'var(--bg-panel)' : 'rgba(255,68,102,0.05)' }
              },
                React.createElement('div', {
                  style: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }
                },
                  React.createElement('span', {
                    style: { fontSize: 16 }
                  }, PLATFORM_ICON[p.platform] || '⚙'),
                  React.createElement('div', { style: { flex: 1 } },
                    React.createElement('div', {
                      style: { fontWeight: 600, fontSize: 13 }
                    }, p.payload_name),
                    React.createElement('div', {
                      style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
                    }, `${p.platform}/${p.arch} • ${p.format} • ${p.size_bytes}B • ${p.lhost}:${p.lport}`)
                  ),
                  p.success
                    ? React.createElement(Tag, { color: 'green' }, 'READY')
                    : React.createElement(Tag, { color: 'red' }, 'FAILED'),
                  React.createElement('button', {
                    style: { padding: '2px 8px', borderRadius: 4, border: '1px solid var(--critical-bd)',
                             background: 'var(--critical-bg)', color: 'var(--critical)',
                             cursor: 'pointer', fontSize: 11 },
                    onClick: () => deletePayload(p.id)
                  }, '✕')
                ),

                p.success && React.createElement('div', {
                  style: { display: 'flex', flexDirection: 'column', gap: 4 }
                },
                  // msfvenom command
                  React.createElement('div', {
                    style: { fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--cyan)',
                             background: 'var(--bg-surface)', padding: '4px 8px', borderRadius: 4,
                             display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden' }
                  },
                    React.createElement('span', { style: { flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } },
                      p.msfvenom_cmd),
                    React.createElement('button', {
                      style: { border: 'none', background: 'transparent', color: 'var(--text-muted)',
                               cursor: 'pointer', flexShrink: 0 },
                      onClick: () => navigator.clipboard.writeText(p.msfvenom_cmd)
                    }, '📋')
                  ),
                  // Listener command
                  React.createElement('div', {
                    style: { fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--green)',
                             background: 'var(--bg-surface)', padding: '4px 8px', borderRadius: 4,
                             display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden' }
                  },
                    React.createElement('span', { style: { color: 'var(--text-muted)', flexShrink: 0 } }, '🎧'),
                    React.createElement('span', { style: { flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } },
                      p.listener_cmd),
                    React.createElement('button', {
                      style: { border: 'none', background: 'transparent', color: 'var(--text-muted)',
                               cursor: 'pointer', flexShrink: 0 },
                      onClick: () => navigator.clipboard.writeText(p.listener_cmd)
                    }, '📋')
                  )
                ),

                p.error && React.createElement('div', {
                  style: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)',
                           background: 'rgba(255,68,102,0.05)', padding: '6px 10px', borderRadius: 4 }
                }, p.error)
              ))
        )
      )
    )
  );
}
window.PayloadBuilder = PayloadBuilder;
