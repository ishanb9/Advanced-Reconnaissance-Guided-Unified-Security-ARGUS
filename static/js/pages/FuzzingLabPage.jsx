// ═══════════════════════════════════════════════════════════
// FuzzingLabPage.jsx — human-controlled, parallel fuzzing (client #6).
//
// TWO modes, both parallel to the autonomous pentest, both scope-restricted:
//   • Quick Fuzzer — the classic catalog tool-runner (ffuf/nuclei/wfuzz/nmap/…).
//   • Custom Exploit Campaign — the fuzz→develop→PROVE workshop across all engines
//     (web/api/network/FILE/BINARY/AI): finds anomalies, has an LLM synthesise a
//     custom PoC, proves it with a deterministic oracle, and feeds it back as a
//     finding.  Ceiling-gated (auto below the chosen intrusiveness, approval above).
//
// Targets are restricted to the session's identified scope — the backend
// re-validates, so a target outside scope can never be fuzzed.
// ═══════════════════════════════════════════════════════════

const { useState: _flUseState, useEffect: _flUseEffect } = React;

function _flSafetyColor(s) {
  return s === 'dangerous' || s === 'disruptive' ? 'var(--bad, #f85149)'
       : s === 'intrusive' ? 'var(--warn, #d29922)'
       : 'var(--good, #3fb950)';
}
function _flStatusColor(s) {
  return s === 'completed' ? 'var(--good, #3fb950)'
       : s === 'error'     ? 'var(--bad, #f85149)'
       : s === 'running'   ? 'var(--accent, #58a6ff)'
       : s === 'stopped'   ? 'var(--warn, #d29922)'
       : 'var(--text-muted, #8b949e)';
}

function FLBadge({ text, color }) {
  return React.createElement('span', {
    style: {
      padding: '2px 9px', borderRadius: 10, fontSize: 10, fontWeight: 700,
      fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
      letterSpacing: 0.6, background: `${color}22`,
      border: `1px solid ${color}`, color,
    },
  }, text);
}

function FLField({ label, children, hint }) {
  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 } },
    React.createElement('label', {
      style: { fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
               letterSpacing: 0.6, color: 'var(--text-muted)' },
    }, label),
    children,
    hint && React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } }, hint),
  );
}

const _FL_INPUT = {
  padding: '7px 9px', borderRadius: 6, fontSize: 12,
  background: 'var(--bg-deep, #0d1117)', color: 'var(--text, #c9d1d9)',
  border: '1px solid var(--border-light, #30363d)', fontFamily: 'var(--font-mono)',
  width: '100%', boxSizing: 'border-box',
};

function FuzzingLabPage() {
  const store = window.useStore() || {};
  const state = store.state || {};
  const sessionId = state.sessionId || state.activeSession || (state.session && state.session.session_id) || '';
  const lab = state.fuzzLab || { status: 'idle', results: [], findings: [] };
  const camp = state.fuzzCampaign || { status: 'idle', stages: [], anomalies: [], exploitSteps: [], proofs: [], findings: [], approvals: [] };

  const [mode, setMode]         = _flUseState('quick');   // 'quick' | 'campaign'
  const [catalog, setCatalog]   = _flUseState({ tech_types: [], fuzzers: {}, scope: { hosts: [], count: 0 } });
  const [techType, setTechType] = _flUseState('web');
  const [fuzzerId, setFuzzerId] = _flUseState('');
  const [target,   setTarget]   = _flUseState('');
  const [port,     setPort]     = _flUseState('');
  const [wordlist, setWordlist] = _flUseState('');
  const [threads,  setThreads]  = _flUseState(40);
  const [rate,     setRate]     = _flUseState(200);
  const [extra,    setExtra]    = _flUseState('');
  const [feedback, setFeedback] = _flUseState(true);
  const [busy,     setBusy]     = _flUseState(false);
  const [err,      setErr]      = _flUseState('');
  const [targets,  setTargets]  = _flUseState({ targets: [], high_count: 0 });
  // ── Custom Exploit Campaign config ──
  const [engines,  setEngines]  = _flUseState([]);
  const [modality, setModality] = _flUseState('web');
  const [ceiling,  setCeiling]  = _flUseState('intrusive');
  const [sampleFile, setSampleFile] = _flUseState('');
  const [parseCmd,   setParseCmd]   = _flUseState('');
  const [binaryPath, setBinaryPath] = _flUseState('');
  // ── Binary / 0-day lab (binary_blackbox modality) — additive, default OFF ──
  const [sourcePath,  setSourcePath]  = _flUseState('');     // source/headers for harness synthesis
  const [synthHarness, setSynthHarness] = _flUseState(false); // synthesize libFuzzer harness from source
  const [triageOn,    setTriageOn]    = _flUseState(false);   // triage + novelty/dedup gate (enrich-only)
  const [authorized,  setAuthorized]  = _flUseState(false);   // REQUIRED authorized-lab-target gate
  const [seedsPath,   setSeedsPath]   = _flUseState('');      // optional corpus/seeds dir
  const [uploading,   setUploading]   = _flUseState(false);   // base64 upload in flight
  const [campMaxSec, setCampMaxSec] = _flUseState(1800);   // campaign time budget (s)
  const [campFeedback, setCampFeedback] = _flUseState(true);
  const [campSnap, setCampSnap] = _flUseState(null);       // live snapshot from /fuzz/campaigns

  const loadCatalog = () => {
    fetch(`/fuzz/catalog?session=${encodeURIComponent(sessionId)}`)
      .then(r => r.json())
      .then(d => {
        setCatalog(d || {});
        if ((d.tech_types || []).length && !(d.tech_types || []).includes(techType)) setTechType(d.tech_types[0]);
      }).catch(() => {});
  };
  const loadTargets = () => {
    fetch(`/fuzz/targets?session=${encodeURIComponent(sessionId)}`)
      .then(r => r.json()).then(d => setTargets(d || { targets: [] })).catch(() => {});
  };
  const loadEngines = () => {
    fetch('/fuzz/engines').then(r => r.json()).then(d => setEngines((d && d.engines) || [])).catch(() => {});
  };
  _flUseEffect(() => { loadCatalog(); loadTargets(); loadEngines(); /* eslint-disable-next-line */ }, [sessionId]);

  // Poll the authoritative campaign snapshot (status / stage / chance-of-success /
  // elapsed-vs-budget) while the campaign tab is open, so the operator always sees
  // what is happening and whether there is any chance — not a silent spinner.
  _flUseEffect(() => {
    if (mode !== 'campaign') return undefined;
    let alive = true;
    const poll = () => {
      fetch(`/fuzz/campaigns?session=${encodeURIComponent(sessionId)}`)
        .then(r => r.json())
        .then(d => { if (!alive) return;
          const list = (d && d.campaigns) || [];
          setCampSnap(list.find(c => c.active) || list[list.length - 1] || null);
        }).catch(() => {});
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => { alive = false; clearInterval(id); };
    // eslint-disable-next-line
  }, [mode, sessionId, busy]);

  const stopCampaign = () => {
    const jid = (campSnap && campSnap.job_id) || camp.jobId;
    if (!jid) { setErr('No running campaign to stop.'); return; }
    fetch('/fuzz/campaign/stop', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ job_id: jid }) }).catch(() => {});
  };

  const pickTarget = (surf) => {
    if (surf.surface_type) setTechType(surf.surface_type);
    setTarget(surf.host || surf.endpoint || '');
    setPort(surf.port != null ? String(surf.port) : '');
    if (surf.fuzzer_id) setFuzzerId(surf.fuzzer_id);
    setErr('');
  };

  const fuzzers = (catalog.fuzzers || {})[techType] || [];
  const scope   = catalog.scope || { hosts: [], count: 0 };
  const selFuzzer = fuzzers.find(f => f.id === fuzzerId) || fuzzers[0] || null;
  const selEngine = engines.find(e => e.modality === modality) || null;

  _flUseEffect(() => {
    const list = (catalog.fuzzers || {})[techType] || [];
    if (list.length) {
      setFuzzerId(list[0].id);
      const dc = list[0].default_config || {};
      if (dc.wordlist !== undefined) setWordlist(dc.wordlist || '');
      if (dc.threads)  setThreads(dc.threads);
      if (dc.rate)     setRate(dc.rate);
    }
    // eslint-disable-next-line
  }, [techType, catalog]);

  _flUseEffect(() => {
    if (!target && scope.hosts && scope.hosts.length) setTarget(scope.hosts[0].host);
    // eslint-disable-next-line
  }, [catalog]);

  const selHostRow = (scope.hosts || []).find(h => h.host === target || target.indexOf(h.host) >= 0) || null;
  const portOptions = (selHostRow && selHostRow.ports) || [];
  const needsPort = selFuzzer && selFuzzer.needs === 'hostport';
  const needsWordlist = selFuzzer && (selFuzzer.needs === 'url') && /ffuf|wfuzz/.test(selFuzzer.id);

  const start = () => {
    setErr('');
    // Standalone-capable: a typed target is sufficient authorization — no live scan required.
    if (!target)    { setErr('Enter a target host (or start a pentest to pick from identified scope).'); return; }
    if (!selFuzzer) { setErr('Pick a fuzzer.'); return; }
    setBusy(true);
    const config = { threads, rate, extra };
    if (port)     config.port = String(port);
    if (wordlist) config.wordlist = wordlist;
    fetch('/fuzz/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, target, tech_type: techType, fuzzer_id: selFuzzer.id, config, feedback }),
    }).then(async r => { const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`); return d; })
      .then(() => setBusy(false))
      .catch(e => { setBusy(false); setErr(String(e.message || e)); });
  };

  // Binary / 0-day lab: stage an uploaded binary or source via base64 JSON
  // (no multipart). On success the returned {path} populates binaryPath or sourcePath.
  const uploadLabFile = (file, into) => {
    if (!file) return;
    setErr('');
    setUploading(true);
    const reader = new FileReader();
    reader.onerror = () => { setUploading(false); setErr('Could not read the selected file.'); };
    reader.onload = () => {
      // reader.result is a data URL: "data:<mime>;base64,<payload>" — keep only the payload.
      const res = String(reader.result || '');
      const content_b64 = res.indexOf(',') >= 0 ? res.slice(res.indexOf(',') + 1) : res;
      fetch('/fuzz/lab/upload', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, filename: file.name, content_b64 }),
      }).then(async r => { const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`); return d; })
        .then(d => { setUploading(false); if (d && d.path) { if (into === 'source') setSourcePath(d.path); else setBinaryPath(d.path); } })
        .catch(e => { setUploading(false); setErr(String(e.message || e)); });
    };
    reader.readAsDataURL(file);
  };

  const startCampaign = () => {
    setErr('');
    // Standalone-capable: a typed in-scope target is sufficient — no live scan required.
    if (modality !== 'binary_blackbox' && !target) { setErr('Enter a target host (or start a pentest to pick from identified scope).'); return; }
    if (modality === 'file' && !sampleFile) { setErr('File-format fuzzing needs a sample file to mutate.'); return; }
    if (modality === 'binary' && !binaryPath) { setErr('Binary fuzzing needs a target harness binary.'); return; }
    if (modality === 'binary_blackbox') {
      if (!binaryPath && !sourcePath) { setErr('Binary / 0-day lab needs a target binary or a source path to synthesize a harness from.'); return; }
      if (!authorized) { setErr('You must confirm this is an authorized lab target before launching.'); return; }
    }
    setBusy(true);
    const surface = {};
    if (modality === 'file') {
      surface.sample_file = sampleFile;
      surface.parse_cmd = parseCmd.trim() ? parseCmd.trim().split(/\s+/) : [];
    } else if (modality === 'binary') {
      surface.binary = binaryPath;
    } else if (modality === 'binary_blackbox') {
      surface.greybox_mode = 'qemu';
      surface.synthesize_harness = synthHarness;
      surface.triage = triageOn;
      if (binaryPath) surface.binary = binaryPath;
      if (sourcePath) surface.source_path = sourcePath;
      if (seedsPath)  surface.seeds_path = seedsPath;
    } else if (port) { surface.port = String(port); }
    // binary_blackbox fuzzes a LOCAL file, not a host — the backend still requires a
    // non-empty `target`, so fall back to the binary/source path when no host is typed.
    const effTarget = (modality === 'binary_blackbox' && !target) ? (binaryPath || sourcePath) : target;
    fetch('/fuzz/campaign/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, target: effTarget, modality, ceiling, surface, authorized: authorized,
                             max_sec: Number(campMaxSec) || 1800, feedback: !!campFeedback }),
    }).then(async r => { const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`); return d; })
      .then(() => setBusy(false))
      .catch(e => { setBusy(false); setErr(String(e.message || e)); });
  };

  const stop = () => {
    if (!lab.jobId) return;
    fetch('/fuzz/stop', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ job_id: lab.jobId }) }).catch(() => {});
  };

  const running = lab.status === 'running';
  const results = Array.isArray(lab.results) ? lab.results : [];
  const findings = Array.isArray(lab.findings) ? lab.findings : [];

  const modeBtn = (m, txt) => React.createElement('button', {
    onClick: () => { setMode(m); setErr(''); },
    style: { padding: '6px 16px', borderRadius: 6, cursor: 'pointer', fontSize: 12, fontWeight: 700,
             border: '1px solid ' + (mode === m ? 'var(--accent, #58a6ff)' : 'var(--border-light, #30363d)'),
             background: mode === m ? 'rgba(88,166,255,0.15)' : 'transparent',
             color: mode === m ? 'var(--accent, #58a6ff)' : 'var(--text-muted)' },
  }, txt);

  return React.createElement('div', { style: { padding: 16, height: '100%', overflow: 'auto' } },
    // ── Header ──
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 14, paddingBottom: 10,
               borderBottom: '1px solid var(--border-light, #30363d)' },
    },
      React.createElement('span', { style: { fontSize: 18, fontWeight: 700, color: 'var(--text, #c9d1d9)' } }, '🎯 Fuzzing Lab'),
      React.createElement('span', { style: { fontSize: 12, color: 'var(--text-muted)' } }, 'Human-controlled · runs in parallel with the pentest'),
      FLBadge({ text: (mode === 'campaign' ? (camp.status || 'idle') : (lab.status || 'idle')), color: _flStatusColor(mode === 'campaign' ? camp.status : lab.status) }),
    ),

    // ── Mode toggle ──
    React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 12 } },
      modeBtn('quick', '⚡ Quick Fuzzer'),
      modeBtn('campaign', '🧬 Custom Exploit Campaign'),
    ),

    // ── Scope notice ──
    React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 } },
      scope.count > 0
        ? `${scope.count} in-scope target(s) identified by ARGUS — fuzzing is restricted to these.`
        : 'No in-scope targets yet. Start a pentest and let recon identify hosts; they appear here automatically.'),

    // ── Where to Fuzz (shared) ──
    (targets.targets && targets.targets.length > 0) && React.createElement('div', {
      style: { marginBottom: 14, padding: 12, borderRadius: 8, background: 'var(--bg-panel, #161b22)', border: '1px solid rgba(160,100,200,0.30)' },
    },
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 } },
        React.createElement('span', { style: { fontSize: 13, fontWeight: 700, color: 'var(--text, #c9d1d9)' } }, '🎯 Where to Fuzz'),
        React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, 'ARGUS-ranked surfaces · advisory'),
      ),
      targets.targets.slice(0, 12).map((t, i) => {
        const tc = t.tier === 'high' ? 'var(--bad, #f85149)' : t.tier === 'medium' ? 'var(--warn, #d29922)' : 'var(--text-muted, #8b949e)';
        const where = (t.host || '') + (t.port != null ? ':' + t.port : '') + (t.endpoint ? ' ' + t.endpoint : '');
        return React.createElement('div', { key: i, style: { display: 'flex', alignItems: 'center', gap: 10, padding: '6px 4px', borderTop: i ? '1px solid var(--bg-surface, #1c2230)' : 'none' } },
          React.createElement('span', { style: { fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: tc, width: 30, textAlign: 'right' } }, Math.round(t.score)),
          React.createElement('span', { style: { fontSize: 8, fontWeight: 700, textTransform: 'uppercase', color: tc, border: `1px solid ${tc}`, borderRadius: 4, padding: '1px 5px' } }, t.tier),
          React.createElement('div', { style: { flex: 1, minWidth: 0 } },
            React.createElement('div', { style: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text, #c9d1d9)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, `${(t.surface_type || '').toUpperCase()} · ${where} · ${t.service || ''}`),
            React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, t.rationale || '')),
          React.createElement('button', { onClick: () => pickTarget(t),
            style: { padding: '4px 10px', borderRadius: 5, border: '1px solid var(--accent, #58a6ff)', cursor: 'pointer', fontSize: 10, fontWeight: 700, background: 'transparent', color: 'var(--accent, #58a6ff)', flexShrink: 0 } }, t.fuzzer_id ? 'Fuzz this →' : 'Configure →'));
      }),
    ),

    // ════════════════ QUICK MODE ════════════════
    mode === 'quick' && React.createElement('div', null,
      React.createElement('div', {
        style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, padding: 14, borderRadius: 8, marginBottom: 14,
                 background: 'var(--bg-panel, #161b22)', border: '1px solid var(--border-light, #30363d)' },
      },
        FLField({ label: 'Technology type', children: React.createElement('select', { value: techType, onChange: e => setTechType(e.target.value), style: _FL_INPUT },
          (catalog.tech_types || []).map(t => React.createElement('option', { key: t, value: t }, t.toUpperCase()))) }),
        FLField({ label: 'Fuzzer', hint: selFuzzer && selFuzzer.desc, children: React.createElement('select', { value: selFuzzer ? selFuzzer.id : '', onChange: e => setFuzzerId(e.target.value), style: _FL_INPUT },
          fuzzers.map(f => React.createElement('option', { key: f.id, value: f.id }, `${f.label}${f.installed === false ? ' (not installed)' : ''}`))) }),
        FLField({ label: 'In-scope target', children: scope.hosts && scope.hosts.length
          ? React.createElement('select', { value: target, onChange: e => setTarget(e.target.value), style: _FL_INPUT }, scope.hosts.map(h => React.createElement('option', { key: h.host, value: h.host }, h.label || h.host)))
          : React.createElement('input', { value: target, onChange: e => setTarget(e.target.value), placeholder: 'host or http://host', style: _FL_INPUT }) }),
        needsPort && FLField({ label: 'Port', children: portOptions.length
          ? React.createElement('select', { value: port, onChange: e => setPort(e.target.value), style: _FL_INPUT }, [React.createElement('option', { key: '', value: '' }, '— pick —')].concat(portOptions.map(p => React.createElement('option', { key: p.port, value: p.port }, `${p.port}${p.service ? ' (' + p.service + ')' : ''}`))))
          : React.createElement('input', { value: port, onChange: e => setPort(e.target.value), placeholder: 'e.g. 502', style: _FL_INPUT }) }),
        needsWordlist && FLField({ label: 'Wordlist path', children: React.createElement('input', { value: wordlist, onChange: e => setWordlist(e.target.value), placeholder: '/usr/share/seclists/...', style: _FL_INPUT }) }),
        FLField({ label: 'Threads', children: React.createElement('input', { type: 'number', value: threads, onChange: e => setThreads(Number(e.target.value)), style: _FL_INPUT }) }),
        FLField({ label: 'Rate (req/s)', children: React.createElement('input', { type: 'number', value: rate, onChange: e => setRate(Number(e.target.value)), style: _FL_INPUT }) }),
        FLField({ label: 'Extra args', hint: 'appended verbatim', children: React.createElement('input', { value: extra, onChange: e => setExtra(e.target.value), placeholder: '-recursion -fc 403', style: _FL_INPUT }) }),
      ),
      selFuzzer && selFuzzer.safety !== 'safe' && React.createElement('div', {
        style: { padding: '8px 12px', borderRadius: 6, marginBottom: 12, fontSize: 12, background: `${_flSafetyColor(selFuzzer.safety)}18`, border: `1px solid ${_flSafetyColor(selFuzzer.safety)}`, color: _flSafetyColor(selFuzzer.safety) },
      }, selFuzzer.safety === 'dangerous' ? '⚠ DANGEROUS — fragile OT/IoT or raw-protocol fuzzing. Pressing Start is your explicit authorization.' : '⚠ Intrusive — this fuzzer sends active traffic to the target.'),
      React.createElement('div', { style: { display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 14 } },
        React.createElement('button', { onClick: start, disabled: busy || running || !selFuzzer || !target,
          style: { padding: '8px 20px', borderRadius: 6, border: 'none', cursor: (busy || running) ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: 13, opacity: (busy || running || !selFuzzer || !target) ? 0.5 : 1, background: 'var(--good, #3fb950)', color: '#06120a' } }, running ? '● Running…' : '▶ Start Fuzzing'),
        React.createElement('button', { onClick: stop, disabled: !running, style: { padding: '8px 20px', borderRadius: 6, cursor: running ? 'pointer' : 'not-allowed', fontWeight: 700, fontSize: 13, opacity: running ? 1 : 0.5, border: '1px solid var(--bad, #f85149)', background: 'transparent', color: 'var(--bad, #f85149)' } }, '■ Stop'),
        React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' } },
          React.createElement('input', { type: 'checkbox', checked: feedback, onChange: e => setFeedback(e.target.checked) }), 'Feed findings back to agents'),
        err && React.createElement('span', { style: { fontSize: 12, color: 'var(--bad, #f85149)' } }, `⚠ ${err}`),
      ),
      findings.length > 0 && React.createElement('div', { style: { marginBottom: 14 } },
        React.createElement('div', { style: { fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6, color: 'var(--good, #3fb950)', marginBottom: 6 } }, `${findings.length} finding(s) sent to agents`),
        findings.slice(-8).reverse().map((f, i) => React.createElement('div', { key: i, style: { fontFamily: 'var(--font-mono)', fontSize: 11, padding: '4px 8px', borderLeft: '2px solid var(--good, #3fb950)', marginBottom: 4, background: 'rgba(63,185,80,0.06)', color: 'var(--text-secondary)' } }, `✓ ${f.title || 'hit'} — ${(f.evidence || f.raw_output || '').slice(0, 120)}`))),
      React.createElement('div', { style: { fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6, color: 'var(--text-muted)', marginBottom: 6 } }, 'Live fuzzer output'),
      React.createElement('pre', { style: { margin: 0, padding: 12, borderRadius: 6, maxHeight: 420, overflow: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: 'var(--bg-deep, #0d1117)', border: '1px solid var(--border-light, #30363d)', color: 'var(--text, #c9d1d9)', minHeight: 80 } },
        results.length === 0 ? '— no output yet — configure a run and press Start —'
          : results.slice(-400).map((r, i) => React.createElement('div', { key: i, style: { color: r.hit ? 'var(--good, #3fb950)' : 'var(--text-secondary)' } }, `${r.hit ? '★ ' : '  '}${r.line}`))),
    ),

    // ════════════════ CAMPAIGN MODE ════════════════
    mode === 'campaign' && React.createElement('div', null,
      React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.5 } },
        'Fuzz → detect an anomaly → an LLM synthesises a CUSTOM PoC → ARGUS runs it and PROVES it with a deterministic oracle → it is fed back as a finding. Auto-runs at/below your ceiling; memory-corruption / DoS / OT pause for approval.'),
      React.createElement('div', {
        style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, padding: 14, borderRadius: 8, marginBottom: 14, background: 'var(--bg-panel, #161b22)', border: '1px solid var(--border-light, #30363d)' },
      },
        FLField({ label: 'Modality', hint: selEngine && selEngine.desc, children: React.createElement('select', { value: modality, onChange: e => setModality(e.target.value), style: _FL_INPUT },
          (engines.length ? engines : [{ modality: 'web', label: 'Web / HTTP', available: true }]).map(e =>
            React.createElement('option', { key: e.modality, value: e.modality }, `${e.label}${e.available ? '' : ' (tool missing)'}`))) }),
        FLField({ label: 'Intrusiveness ceiling', hint: 'auto-prove at/below; approval above', children: React.createElement('select', { value: ceiling, onChange: e => setCeiling(e.target.value), style: _FL_INPUT },
          ['safe', 'intrusive', 'disruptive'].map(c => React.createElement('option', { key: c, value: c }, c.toUpperCase()))) }),
        FLField({ label: 'In-scope target', children: scope.hosts && scope.hosts.length
          ? React.createElement('select', { value: target, onChange: e => setTarget(e.target.value), style: _FL_INPUT }, scope.hosts.map(h => React.createElement('option', { key: h.host, value: h.host }, h.label || h.host)))
          : React.createElement('input', { value: target, onChange: e => setTarget(e.target.value), placeholder: 'host or http://host', style: _FL_INPUT }) }),
        (modality === 'network' || modality === 'binary') && FLField({ label: 'Port', children: React.createElement('input', { value: port, onChange: e => setPort(e.target.value), placeholder: 'e.g. 8080', style: _FL_INPUT }) }),
        modality === 'file' && FLField({ label: 'Sample file (seed)', hint: 'a valid file to mutate', children: React.createElement('input', { value: sampleFile, onChange: e => setSampleFile(e.target.value), placeholder: '/path/to/sample.pdf', style: _FL_INPUT }) }),
        modality === 'file' && FLField({ label: 'Parser command', hint: 'use {input} for the mutated file', children: React.createElement('input', { value: parseCmd, onChange: e => setParseCmd(e.target.value), placeholder: 'pdfinfo {input}', style: _FL_INPUT }) }),
        modality === 'binary' && FLField({ label: 'Target binary (harness)', children: React.createElement('input', { value: binaryPath, onChange: e => setBinaryPath(e.target.value), placeholder: '/path/to/harness', style: _FL_INPUT }) }),
        // ── Binary / 0-day lab fields (binary_blackbox) ──
        modality === 'binary_blackbox' && FLField({ label: 'Target binary', hint: 'closed-source binary to fuzz (greybox)', children: React.createElement('input', { value: binaryPath, onChange: e => setBinaryPath(e.target.value), placeholder: '/path/to/target', style: _FL_INPUT }) }),
        modality === 'binary_blackbox' && FLField({ label: 'Source path', hint: 'for libFuzzer harness synthesis', children: React.createElement('input', { value: sourcePath, onChange: e => setSourcePath(e.target.value), placeholder: '/path/to/src or headers', style: _FL_INPUT }) }),
        modality === 'binary_blackbox' && FLField({ label: 'Greybox mode', hint: 'instrumentation reach', children: React.createElement('select', { value: 'qemu', disabled: true, style: { ..._FL_INPUT, opacity: 0.85, cursor: 'not-allowed' } }, React.createElement('option', { value: 'qemu' }, 'QEMU user-mode')) }),
        modality === 'binary_blackbox' && FLField({ label: 'Seeds path', hint: 'optional starting corpus dir', children: React.createElement('input', { value: seedsPath, onChange: e => setSeedsPath(e.target.value), placeholder: '/path/to/seeds (optional)', style: _FL_INPUT }) }),
        FLField({ label: 'Time budget (s)', hint: 'campaign auto-stops after this', children: React.createElement('input', { type: 'number', value: campMaxSec, onChange: e => setCampMaxSec(Number(e.target.value)), style: _FL_INPUT }) }),
        FLField({ label: 'Feed proven exploits back', children: React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer', padding: '7px 0' } },
          React.createElement('input', { type: 'checkbox', checked: campFeedback, onChange: e => setCampFeedback(e.target.checked) }), 'as findings to the agents') }),
      ),
      // ── Binary / 0-day lab: upload, toggles, and the required authorization gate ──
      modality === 'binary_blackbox' && React.createElement('div', {
        style: { display: 'flex', flexDirection: 'column', gap: 10, padding: 14, borderRadius: 8, marginBottom: 14, background: 'var(--bg-panel, #161b22)', border: '1px solid rgba(160,100,200,0.30)' },
      },
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' } },
          React.createElement('span', { style: { fontSize: 13, fontWeight: 700, color: 'var(--text, #c9d1d9)' } }, '🧪 Binary / 0-day lab'),
          FLBadge({ text: 'lab-gated', color: 'var(--warn, #d29922)' }),
          React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, 'AFL++ QEMU greybox · ASan/QASan oracle · offline novelty check'),
        ),
        // Upload binary/source — FileReader → base64 → JSON POST /fuzz/lab/upload
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' } },
          React.createElement('label', { style: { display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 700, cursor: uploading ? 'wait' : 'pointer', padding: '6px 12px', borderRadius: 6, border: '1px solid var(--accent, #58a6ff)', color: 'var(--accent, #58a6ff)', background: 'transparent' } },
            uploading ? '⏳ Uploading…' : '⬆ Upload binary/source',
            React.createElement('input', { type: 'file', disabled: uploading, onChange: e => { const f = e.target.files && e.target.files[0]; uploadLabFile(f, 'binary'); e.target.value = ''; }, style: { display: 'none' } })),
          React.createElement('label', { style: { display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 700, cursor: uploading ? 'wait' : 'pointer', padding: '6px 12px', borderRadius: 6, border: '1px solid var(--border-light, #30363d)', color: 'var(--text-secondary)', background: 'transparent' } },
            '⬆ Upload as source',
            React.createElement('input', { type: 'file', disabled: uploading, onChange: e => { const f = e.target.files && e.target.files[0]; uploadLabFile(f, 'source'); e.target.value = ''; }, style: { display: 'none' } })),
          React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, 'staged to a per-session lab dir; the returned path fills the field above'),
        ),
        // Toggles: harness synthesis + triage/novelty
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
          React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' } },
            React.createElement('input', { type: 'checkbox', checked: synthHarness, onChange: e => setSynthHarness(e.target.checked) }),
            'Synthesize harness from source ', React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, '(LLM writes a libFuzzer driver; the compiler is the oracle)')),
          React.createElement('label', { style: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' } },
            React.createElement('input', { type: 'checkbox', checked: triageOn, onChange: e => setTriageOn(e.target.checked) }),
            'Triage + novelty ', React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, '(dedup, exploitability, offline 0-day check)')),
        ),
        // REQUIRED authorization gate — red bordered; launch blocked unless checked
        React.createElement('label', {
          style: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, fontWeight: 700, cursor: 'pointer', padding: '8px 12px', borderRadius: 6,
                   color: authorized ? 'var(--good, #3fb950)' : 'var(--bad, #f85149)',
                   border: `1px solid ${authorized ? 'var(--good, #3fb950)' : 'var(--bad, #f85149)'}`,
                   background: authorized ? 'rgba(63,185,80,0.08)' : 'rgba(248,81,73,0.08)' },
        },
          React.createElement('input', { type: 'checkbox', checked: authorized, onChange: e => setAuthorized(e.target.checked) }),
          '✔ I confirm this is an authorized lab target',
          React.createElement('span', { style: { fontSize: 10, fontWeight: 400, color: 'var(--text-muted)' } }, '— required; the campaign will not launch without it'),
        ),
      ),
      // ── Engine tool availability — surfaces the installed fuzzers (radamsa/zzuf/AFL++/…) ──
      selEngine && Array.isArray(selEngine.tools) && selEngine.tools.length > 0 && React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 12, padding: '8px 12px', borderRadius: 6, background: 'var(--bg-deep, #0d1117)', border: '1px solid var(--border-light, #30363d)' },
      },
        React.createElement('span', { style: { fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6, color: 'var(--text-muted)' } }, 'Engine tools'),
        selEngine.tools.map((t, i) => {
          const c = t.installed ? 'var(--good, #3fb950)' : (t.kind === 'builtin' ? 'var(--good, #3fb950)' : 'var(--text-muted, #8b949e)');
          return React.createElement('span', { key: i, title: t.kind, style: { fontFamily: 'var(--font-mono)', fontSize: 11, padding: '2px 8px', borderRadius: 10, border: `1px solid ${c}`, color: c, background: `${c}14` } }, `${t.installed ? '✓' : '○'} ${t.name}`);
        }),
      ),
      selEngine && !selEngine.available && React.createElement('div', { style: { padding: '8px 12px', borderRadius: 6, marginBottom: 12, fontSize: 12, background: 'rgba(210,153,34,0.12)', border: '1px solid var(--warn, #d29922)', color: 'var(--warn, #d29922)' } }, `⚠ ${selEngine.reason || 'engine unavailable'}${(selEngine.tools_missing && selEngine.tools_missing.length) ? ' — optional tools missing: ' + selEngine.tools_missing.join(', ') + ' (a built-in fallback still runs)' : ''}.`),
      React.createElement('div', { style: { padding: '8px 12px', borderRadius: 6, marginBottom: 12, fontSize: 12, background: `${_flSafetyColor(ceiling)}14`, border: `1px solid ${_flSafetyColor(ceiling)}`, color: _flSafetyColor(ceiling) } },
        `⚠ This develops + PROVES live exploits up to the '${ceiling.toUpperCase()}' ceiling. Pressing Start is your authorization for this in-scope target.`),
      // ── Live status: what's happening, progress vs budget, chance of success ──
      _flCampaignStatus(campSnap),
      React.createElement('div', { style: { display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 14 } },
        (function () {
          // binary_blackbox is target-host-less; it launches on a local binary/source
          // plus the required authorization. Other modalities still require a target.
          const blDisabled = modality === 'binary_blackbox'
            ? (!authorized || (!binaryPath && !sourcePath))
            : !target;
          const campDisabled = busy || blDisabled || (campSnap && campSnap.active);
          return React.createElement('button', { onClick: startCampaign, disabled: campDisabled,
            style: { padding: '8px 20px', borderRadius: 6, border: 'none', cursor: busy ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: 13, opacity: campDisabled ? 0.5 : 1, background: 'var(--accent, #58a6ff)', color: '#04121f' } },
            modality === 'binary_blackbox' ? '🧬 Launch 0-day Lab' : '🧬 Start Exploit Campaign');
        })(),
        React.createElement('button', { onClick: stopCampaign, disabled: !(campSnap && campSnap.active),
          style: { padding: '8px 20px', borderRadius: 6, cursor: (campSnap && campSnap.active) ? 'pointer' : 'not-allowed', fontWeight: 700, fontSize: 13, opacity: (campSnap && campSnap.active) ? 1 : 0.4, border: '1px solid var(--bad, #f85149)', background: 'transparent', color: 'var(--bad, #f85149)' } }, '■ Stop Fuzzing'),
        err && React.createElement('span', { style: { fontSize: 12, color: 'var(--bad, #f85149)' } }, `⚠ ${err}`),
      ),
      // Live campaign view
      _flCampaignView(camp),
      // Per-finding triage / novelty cards (only when a finding carries a triage object)
      _flTriageFindings(camp),
    ),
  );
}

function _flPromiseColor(p) {
  return p >= 70 ? 'var(--good, #3fb950)' : p >= 35 ? 'var(--warn, #d29922)'
       : p > 0 ? 'var(--accent, #58a6ff)' : 'var(--text-muted, #8b949e)';
}

// Exploitability band → colour. probable = red, likely = orange, unlikely/unknown = grey.
function _flExploitColor(e) {
  return e === 'probable' ? 'var(--bad, #f85149)'
       : e === 'likely'   ? 'var(--warn, #d29922)'
       : 'var(--text-muted, #8b949e)';
}

// Compact triage / novelty card for a single campaign finding's optional `triage` object.
// Additive: findings WITHOUT a triage object render exactly as before (this returns null).
function _flTriageCard(t) {
  if (!t) return null;
  const ec = _flExploitColor(t.exploitability);
  const novel = t.novelty_label;
  // Novelty headline: candidate-0day stands out amber; known-nday / undetermined stay grey.
  const isCandidate = novel === 'no-known-public-match';
  const nc = isCandidate ? 'var(--warn, #d29922)' : 'var(--text-muted, #8b949e)';
  const nText = isCandidate ? 'CANDIDATE 0-DAY — no known public CVE match'
              : novel === 'known-nday' ? 'known issue'
              : 'undetermined';
  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: 5, padding: '7px 9px', borderRadius: 6, marginTop: 4,
             background: isCandidate ? 'rgba(210,153,34,0.08)' : 'var(--bg-deep, #0d1117)',
             border: `1px solid ${isCandidate ? 'var(--warn, #d29922)' : 'var(--border-light, #30363d)'}` },
  },
    React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' } },
      t.cluster_id && FLBadge({ text: `cluster ${String(t.cluster_id).slice(0, 12)}`, color: 'var(--text-muted, #8b949e)' }),
      t.exploitability && FLBadge({ text: `exploit: ${t.exploitability}`, color: ec }),
      FLBadge({ text: nText, color: nc }),
    ),
    t.novelty_evidence && React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, t.novelty_evidence),
  );
}

// Findings list that surfaces the per-finding triage / novelty card (binary / 0-day lab).
// Only rendered when at least one finding carries a `triage` object — pure addition.
function _flTriageFindings(camp) {
  const findings = (camp.findings || []).filter(f => f && f.triage);
  if (!findings.length) return null;
  return React.createElement('div', { style: { marginTop: 14 } },
    React.createElement('div', { style: { fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6, color: 'var(--warn, #d29922)', marginBottom: 6 } }, `Triage & novelty (${findings.length})`),
    React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 320, overflow: 'auto' } },
      findings.slice(-30).reverse().map((f, i) => React.createElement('div', { key: i, style: { padding: '6px 8px', borderRadius: 6, background: 'var(--bg-panel, #161b22)', border: '1px solid var(--border-light, #30363d)' } },
        React.createElement('div', { style: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text, #c9d1d9)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, `${f.exploit_class || f.type || 'crash'} — ${(f.title || '').slice(0, 70)}`),
        _flTriageCard(f.triage)))));
}

// Greybox (binary / 0-day lab) live counters: execs/sec, crashes, unique clusters.
// Strictly additive — renders nothing unless the snapshot carries at least one of them,
// so non-binary campaigns are unaffected.
function _flGreyboxCounters(snap) {
  const pick = (keys) => { for (const k of keys) { if (snap[k] != null) return snap[k]; } return null; };
  const execs    = pick(['execs_per_sec', 'execs_sec', 'exec_per_sec', 'execs_per_second']);
  const crashes  = pick(['crashes', 'crash_count', 'total_crashes']);
  const clusters = pick(['clusters', 'unique_clusters', 'cluster_count']);
  if (execs == null && crashes == null && clusters == null) return null;
  const cell = (label, val, color) => React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 2 } },
    React.createElement('span', { style: { fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6, color: 'var(--text-muted)' } }, label),
    React.createElement('span', { style: { fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 700, color: color || 'var(--text, #c9d1d9)' } }, val));
  const kids = [];
  if (execs != null)    kids.push(cell('Execs/sec', String(execs), 'var(--accent, #58a6ff)'));
  if (crashes != null)  kids.push(cell('Crashes', String(crashes), 'var(--bad, #f85149)'));
  if (clusters != null) kids.push(cell('Unique clusters', String(clusters), 'var(--warn, #d29922)'));
  return React.createElement('div', { style: { display: 'flex', gap: 22, flexWrap: 'wrap', marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border-light, #30363d)' } }, kids);
}

// Live status board: status + stage + chance-of-success + time budget + counts.
// This is the "what is happening / is there any chance" panel the operator asked for.
function _flCampaignStatus(snap) {
  if (!snap) {
    return React.createElement('div', { style: { padding: '10px 14px', borderRadius: 8, marginBottom: 12, fontSize: 12, color: 'var(--text-muted)', background: 'var(--bg-deep, #0d1117)', border: '1px dashed var(--border-light, #30363d)' } },
      'No campaign running. Configure above and press Start — status, progress and chance-of-success appear here.');
  }
  const mmss = (s) => { s = Math.max(0, s | 0); return ((s / 60) | 0) + 'm ' + (s % 60) + 's'; };
  const pct = snap.max_sec ? Math.min(100, Math.round((snap.elapsed_sec / snap.max_sec) * 100)) : 0;
  const promise = snap.promise || 0;
  const pc = _flPromiseColor(promise);
  const sc = _flStatusColor(snap.active ? 'running' : snap.status);
  const stat = (label, val, color) => React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 2 } },
    React.createElement('span', { style: { fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6, color: 'var(--text-muted)' } }, label),
    React.createElement('span', { style: { fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 700, color: color || 'var(--text, #c9d1d9)' } }, val));
  const meter = (title, frac, color, right) => React.createElement('div', { style: { marginBottom: 10 } },
    React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: 10, marginBottom: 4 } },
      React.createElement('span', { style: { fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6, color: 'var(--text-muted)' } }, title),
      React.createElement('span', { style: { fontWeight: 700, color: color } }, right)),
    React.createElement('div', { style: { height: 6, borderRadius: 3, background: 'var(--bg-surface, #1c2230)', overflow: 'hidden' } },
      React.createElement('div', { style: { width: Math.max(2, Math.min(100, frac)) + '%', height: '100%', background: color, transition: 'width 0.4s' } })));
  return React.createElement('div', { style: { padding: '12px 14px', borderRadius: 8, marginBottom: 12, background: 'var(--bg-panel, #161b22)', border: `1px solid ${sc}` } },
    React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 10 } },
      FLBadge({ text: snap.status_label || snap.status || 'idle', color: sc }),
      snap.active && React.createElement('span', { style: { fontSize: 11, color: 'var(--text-muted)' } }, `stage: ${snap.stage || '—'}`),
      React.createElement('span', { style: { fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto', fontFamily: 'var(--font-mono)' } }, `${mmss(snap.elapsed_sec)} / ${mmss(snap.max_sec)}`)),
    meter('Chance of success', promise, pc, `${snap.promise_label || '—'} · ${promise}%`),
    meter('Time budget', pct, 'var(--accent, #58a6ff)', `${mmss(snap.remaining_sec)} left`),
    React.createElement('div', { style: { display: 'flex', gap: 22, flexWrap: 'wrap' } },
      stat('Anomalies', snap.anomalies || 0, 'var(--warn, #d29922)'),
      stat('Proven', snap.proven || 0, 'var(--good, #3fb950)'),
      stat('Awaiting approval', snap.awaiting_approval || 0, 'var(--accent, #58a6ff)')),
    // Greybox live counters — only surfaced when the snapshot actually carries them.
    _flGreyboxCounters(snap),
    snap.note && React.createElement('div', { style: { marginTop: 8, fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' } }, snap.note));
}

function _flCampaignView(camp) {
  const col = (title, items, render, color) => React.createElement('div', { style: { flex: 1, minWidth: 220 } },
    React.createElement('div', { style: { fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6, color: color || 'var(--text-muted)', marginBottom: 6 } }, `${title} (${items.length})`),
    React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 260, overflow: 'auto' } },
      items.length === 0 ? React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)' } }, '—') : items.slice(-40).reverse().map(render)));

  const item = (txt, c) => (x, i) => React.createElement('div', { key: i, style: { fontFamily: 'var(--font-mono)', fontSize: 11, padding: '3px 7px', borderLeft: `2px solid ${c}`, background: `${c}10`, color: 'var(--text-secondary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, txt(x));

  return React.createElement('div', { style: { display: 'flex', gap: 12, flexWrap: 'wrap' } },
    col('Stages', camp.stages || [], item(s => `${String(s.stage || '').toUpperCase()}${s.message ? ' — ' + s.message : ''}`, 'var(--accent, #58a6ff)'), 'var(--accent, #58a6ff)'),
    col('Anomalies', camp.anomalies || [], item(a => `${a.type} → ${a.exploit_class}`, 'var(--warn, #d29922)'), 'var(--warn, #d29922)'),
    col('Exploit-dev', camp.exploitSteps || [], item(s => `iter ${s.iteration} ${s.exploit_class}: ${s.proven ? 'PROVEN' : (s.reason || 'refining')}`, 'var(--text-muted)')),
    col('Proven exploits', (camp.findings || []).filter(f => f.reproduce_status === 'reproduced'), item(f => `🟢 ${f.exploit_class || ''} — ${(f.title || '').slice(0, 60)}`, 'var(--good, #3fb950)'), 'var(--good, #3fb950)'),
    (camp.approvals && camp.approvals.length > 0) && col('⏸ Approvals', camp.approvals, item(a => `${a.exploit_class} on ${a.target}`, 'var(--bad, #f85149)'), 'var(--bad, #f85149)'),
  );
}

window.FuzzingLabPage = FuzzingLabPage;
