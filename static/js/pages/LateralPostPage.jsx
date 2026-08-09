// LateralPostPage.jsx — Lateral movement & post-exploitation dashboard
'use strict';
const { useState, useEffect, useCallback } = React;
const { Card, Table, Tag, Space, Typography, Row, Col,
        Statistic, Tabs, Badge, Button, Divider,
        Timeline, Tree, Tooltip, message } = antd;
const { Text, Title } = Typography;

const SEV_COLOR = { CRITICAL:'#ff4d4f', HIGH:'#ff7a45', MEDIUM:'#ffa940', LOW:'#52c41a', INFO:'#1890ff' };
const MITRE_URL = id => `https://attack.mitre.org/techniques/${id.replace('.', '/')}`;

// ── Reusable Finding Row ──────────────────────────────────────────────────────
function FindingRow({ f }) {
  return React.createElement(Card, {
    size: 'small',
    style: {
      background: 'var(--bg-panel)', borderLeft: `3px solid ${SEV_COLOR[f.severity] || 'var(--border-light)'}`,
      marginBottom: 6, borderTopColor: 'var(--border)', borderRightColor: 'var(--border)', borderBottomColor: 'var(--border)',
    },
    bodyStyle: { padding: '8px 14px' },
  },
    React.createElement(Row, { align: 'top' },
      React.createElement(Col, { flex: 1 },
        React.createElement(Space, { size: 4 },
          React.createElement(Tag, { color: SEV_COLOR[f.severity], style: { fontSize: 10 } }, f.severity),
          React.createElement(Text, { strong: true, style: { color: 'var(--text-primary)', fontSize: 13 } }, f.title),
          f.cve && React.createElement(Tag, { color: 'orange' }, f.cve),
          f.mitre_technique && React.createElement(Tooltip, { title: `MITRE ${f.mitre_technique}` },
            React.createElement('a', {
              href: MITRE_URL(f.mitre_technique), target: '_blank',
              style: { color: 'var(--medium)', fontSize: 11, textDecoration: 'none' },
            }, f.mitre_technique)
          ),
        ),
        React.createElement(Text, { style: { color: 'var(--text-secondary)', fontSize: 12, display: 'block', marginTop: 4 } },
          f.description?.slice(0, 180) + (f.description?.length > 180 ? '…' : '')),
        f.exploit_suggestion && React.createElement('pre', {
          style: {
            marginTop: 6, background: 'var(--bg-surface)', padding: '4px 8px', borderRadius: 3,
            fontSize: 11, color: 'var(--low)', whiteSpace: 'pre-wrap', overflowX: 'auto',
          },
        }, f.exploit_suggestion?.slice(0, 300)),
      ),
      React.createElement(Col, { style: { minWidth: 70, textAlign: 'right' } },
        React.createElement(Text, { style: { fontSize: 10, color: 'var(--text-muted)' } },
          f.tool || ''),
      ),
    ),
  );
}

// ── Lateral Panel ─────────────────────────────────────────────────────────────
function LateralPanel({ sessionId }) {
  const [findings, setFindings] = useState([]);
  const [targets,  setTargets]  = useState([]);
  const [loading,  setLoading]  = useState(false);

  const load = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const d = await API.lateral(sessionId);
      setFindings(d.findings || []);
    } catch {
      // Fallback from store
      const state = window.__store?.getState();
      setFindings(state?.lateralFindings || []);
    }
    try {
      const s = await API.sessionState(sessionId);
      setTargets(s?.lateral_targets || []);
    } catch { /**/ }
    setLoading(false);
  }, [sessionId]);

  useEffect(() => { load(); }, [load]);

  // AD enum findings
  const adFindings  = findings.filter(f => /ad|domain|ldap|kerb|smb|ntlm/i.test(f.title + f.description));
  const credFinds   = findings.filter(f => /credential|hash|password|ticket|kerberoast|asrep/i.test(f.title));
  const pivotFinds  = findings.filter(f => /pivot|lateral|movement|relay|capture/i.test(f.title));

  return React.createElement('div', null,
    // Stats
    React.createElement(Row, { gutter: 12, style: { marginBottom: 16 } },
      [
        { label: 'Total Findings',       value: findings.length,    color: 'var(--cyan)' },
        { label: 'AD/Domain Issues',     value: adFindings.length,  color: 'var(--violet)' },
        { label: 'Credential Findings',  value: credFinds.length,   color: 'var(--critical)' },
        { label: 'Pivot Targets Found',  value: targets.length,     color: 'var(--medium)' },
      ].map(s => React.createElement(Col, { key: s.label, span: 6 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: s.label, value: s.value,
            valueStyle: { color: s.color, fontSize: 20 } })))),
    ),

    // Discovered pivot targets
    targets.length > 0 && React.createElement(Card, {
      size: 'small', title: React.createElement(Text, { style: { color: 'var(--medium)' } }, '🎯 Internal Pivot Targets'),
      style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)', marginBottom: 12 },
    },
      // OVERFLOW: a wrapped tag row grows without bound once a scan discovers
      // dozens of pivot targets — the same defect as the MissionControl host
      // selector. Capped + internally scrolled via .a-chiprow-wrap.
      React.createElement(Space, { wrap: true, className: 'a-chiprow-wrap' },
        targets.map(ip => React.createElement(Tag, {
          key: ip, color: 'orange', style: { fontSize: 13, padding: '2px 10px' },
        }, ip)),
      ),
    ),

    // Quick run buttons
    React.createElement(Space, { style: { marginBottom: 12 } },
      ['ad_enum', 'kerberos', 'ntlm_capture'].map(sa =>
        React.createElement(Button, {
          key: sa, size: 'small',
          style: { background: 'var(--accent)', border: '1px solid var(--accent)', color: '#0D0E14', boxShadow: '0 0 10px var(--accent-glow)' },
          onClick: async () => {
            try { await API.subagents.run(sessionId, sa); message.success(`${sa} started`); }
            catch (e) { message.error(e.message); }
          },
        }, `▶ ${sa}`),
      ),
    ),

    // Findings list — wrapped in a capped, internally-scrolling pane so a long
    // result set cannot push the panels above it off-screen. The rows were
    // previously bare siblings with no container, so there was nothing to cap.
    loading
      ? React.createElement('div', { style: { color: 'var(--text-secondary)', padding: 20 } }, 'Loading…')
      : findings.length === 0
        ? React.createElement('div', { style: { color: 'var(--text-muted)', padding: 20 } }, 'No lateral movement findings yet.')
        : React.createElement('div', { className: 'a-listpane', 'data-slot': 'LateralPostPage.lateralFindings' },
            findings.map((f, i) => React.createElement(FindingRow, { key: f.finding_id || i, f }))),
  );
}

// ── Post-Exploit Panel ────────────────────────────────────────────────────────
function PostPanel({ sessionId }) {
  const [findings,    setFindings]    = useState([]);
  const [persistence, setPersistence] = useState([]);
  const [loading,     setLoading]     = useState(false);

  const load = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const d = await API.findings(sessionId, { agent: 'post' });
      setFindings(d.findings || d || []);
    } catch { /**/ }
    try {
      const d = await API.persistence(sessionId);
      setPersistence(d.persistence || []);
    } catch { /**/ }
    setLoading(false);
  }, [sessionId]);

  useEffect(() => { load(); }, [load]);

  const credFinds    = findings.filter(f => /credential|hash|password|loot/i.test(f.title));
  const c2Finds      = findings.filter(f => /c2|command.*control|implant|beacon|sliver|msf/i.test(f.title));
  const exfilFinds   = findings.filter(f => /exfil|data|shadow|file/i.test(f.title));
  const evasionFinds = findings.filter(f => /evasion|stealth|log|EDR|AV/i.test(f.title));

  return React.createElement('div', null,
    // Stats
    React.createElement(Row, { gutter: 12, style: { marginBottom: 16 } },
      [
        { label: 'Total Findings',       value: findings.length,     color: 'var(--cyan)' },
        { label: 'Credentials / Hashes', value: credFinds.length,    color: 'var(--critical)' },
        { label: 'C2 / Implants',        value: c2Finds.length,      color: 'var(--violet)' },
        { label: 'Data Exfiltrated',     value: exfilFinds.length,   color: 'var(--medium)' },
      ].map(s => React.createElement(Col, { key: s.label, span: 6 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: s.label, value: s.value,
            valueStyle: { color: s.color, fontSize: 20 } })))),
    ),

    // Persistence items
    persistence.length > 0 && React.createElement(Card, {
      size: 'small',
      title: React.createElement(Text, { style: { color: 'var(--violet)' } }, '🔒 Installed Persistence'),
      style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)', marginBottom: 12 },
    },
      persistence.map((p, i) => React.createElement('div', { key: i, style: { marginBottom: 4 } },
        React.createElement(Tag, { color: 'magenta' }, p.type || 'unknown'),
        React.createElement(Text, { code: true, style: { fontSize: 11 } }, p.detail || p.path || JSON.stringify(p)),
      )),
    ),

    // Quick run buttons
    React.createElement(Space, { style: { marginBottom: 12 } },
      ['persistence','data_exfil','local_cred_harvest','log_evasion','c2_deploy'].map(sa =>
        React.createElement(Button, {
          key: sa, size: 'small',
          style: { background: 'var(--accent)', border: '1px solid var(--accent)', color: '#0D0E14', boxShadow: '0 0 10px var(--accent-glow)' },
          onClick: async () => {
            try { await API.subagents.run(sessionId, sa); message.success(`${sa} started`); }
            catch (e) { message.error(e.message); }
          },
        }, `▶ ${sa}`),
      ),
    ),

    // Section breakdown
    [
      { label: '🔑 Credential & Hash Findings', items: credFinds,    color: 'var(--critical)' },
      { label: '📡 C2 & Implant Findings',      items: c2Finds,      color: 'var(--violet)' },
      { label: '📦 Data Exfiltration Findings',  items: exfilFinds,   color: 'var(--medium)' },
      { label: '🫥 Evasion Findings',            items: evasionFinds, color: 'var(--medium)' },
    ].filter(s => s.items.length > 0).map(section =>
      React.createElement('div', { key: section.label, style: { marginBottom: 16 } },
        React.createElement(Divider, { style: { borderColor: section.color } },
          React.createElement(Text, { style: { color: section.color } }, section.label),
        ),
        section.items.map((f, i) => React.createElement(FindingRow, { key: f.finding_id || i, f })),
      )
    ),

    // All findings fallback — capped + internally scrolling (see _containment.css)
    credFinds.length === 0 && c2Finds.length === 0 && exfilFinds.length === 0 && (
      loading
        ? React.createElement('div', { style: { color: 'var(--text-secondary)', padding: 20 } }, 'Loading…')
        : findings.length === 0
          ? React.createElement('div', { style: { color: 'var(--text-muted)', padding: 20 } }, 'No post-exploitation findings yet.')
          : React.createElement('div', { className: 'a-listpane', 'data-slot': 'LateralPostPage.postFindings' },
              findings.map((f, i) => React.createElement(FindingRow, { key: f.finding_id || i, f })))
    ),
  );
}

// ── Traffic Captures Panel ────────────────────────────────────────────────────
function TrafficPanel() {
  const { state } = window.useStore();
  const captures = state.trafficCaptures || [];

  return React.createElement('div', null,
    React.createElement(Row, { gutter: 12, style: { marginBottom: 16 } },
      [
        { label: 'Captures',         value: captures.length,                                              color: 'var(--cyan)' },
        { label: 'Total Packets',    value: captures.reduce((s, c) => s + (c.packets || 0), 0),          color: 'var(--cyan)'      },
        { label: 'Creds Sniffed',    value: captures.reduce((s, c) => s + (c.credentials?.length||0), 0), color: 'var(--critical)'  },
      ].map(s => React.createElement(Col, { key: s.label, span: 8 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: s.label, value: s.value,
            valueStyle: { color: s.color, fontSize: 20 } })))),
    ),
    captures.length === 0
      ? React.createElement('div', { style: { color: 'var(--text-muted)', padding: 20 } }, 'No traffic captures yet. Traffic subagents run during the post-exploit phase.')
      : React.createElement('div', { className: 'a-listpane', 'data-slot': 'LateralPostPage.captures' },
        captures.map((cap, i) =>
          React.createElement(Card, {
            key: cap.id || i, size: 'small',
            style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)', marginBottom: 8,
                     borderLeft: '3px solid var(--cyan)' },
            bodyStyle: { padding: '10px 14px' },
          },
            React.createElement(Row, { align: 'middle' },
              React.createElement(Col, { flex: 1 },
                React.createElement(Space, { size: 4 },
                  React.createElement(Tag, { color: 'blue' }, cap.interface || 'eth0'),
                  cap.file && React.createElement(Tag, { color: 'default', style: { fontSize: 10 } }, cap.file),
                  React.createElement(Text, { style: { color: 'var(--text-primary)', fontSize: 13 } },
                    `${cap.packets || 0} packets captured`),
                  cap.duration && React.createElement(Text, { style: { color: 'var(--text-secondary)', fontSize: 11 } },
                    `(${cap.duration.toFixed ? cap.duration.toFixed(1) : cap.duration}s)`),
                ),
                cap.summary && React.createElement(Text, {
                  style: { color: 'var(--text-secondary)', fontSize: 11, display: 'block', marginTop: 4 }
                }, cap.summary),
                cap.credentials?.length > 0 && React.createElement('div', { style: { marginTop: 6 } },
                  React.createElement(Tag, { color: 'red' }, `⚠ ${cap.credentials.length} credentials sniffed`),
                  cap.credentials.slice(0, 3).map((c, ci) =>
                    React.createElement(Tag, { key: ci, color: 'orange', style: { fontSize: 10 } },
                      `${c.user || c.username || '?'}@${c.host || '?'}`)
                  )
                )
              ),
              React.createElement(Col, { style: { minWidth: 80, textAlign: 'right' } },
                React.createElement(Text, { style: { fontSize: 10, color: 'var(--text-muted)' } },
                  new Date(cap.timestamp).toLocaleTimeString())
              )
            )
          )
        )
      )
  );
}

// ── Evidence Panel ────────────────────────────────────────────────────────────
function EvidencePanel({ sessionId }) {
  const { state } = window.useStore();
  const [extra, setExtra] = useState([]);

  useEffect(() => {
    if (!sessionId) return;
    window.API.evidence(sessionId).then(d => setExtra(d.evidence || [])).catch(() => {});
  }, [sessionId]);

  const all = [...(state.evidence || []), ...extra]
    .filter((e, i, arr) => arr.findIndex(x => x.id === e.id) === i)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const EVT_ICON = { screenshot: '📷', flag: '🚩', command_transcript: '📜',
                     file_exfil: '📦', hash: '🔑', unknown: '📄' };

  return React.createElement('div', null,
    React.createElement(Row, { gutter: 12, style: { marginBottom: 16 } },
      [
        { label: 'Evidence Items',  value: all.length,                                    color: 'var(--cyan)' },
        { label: 'Flags Captured',  value: all.filter(e => e.type === 'flag').length,     color: 'var(--low)'      },
        { label: 'Screenshots',     value: all.filter(e => e.type === 'screenshot').length, color: 'var(--cyan)'   },
        { label: 'Transcripts',     value: all.filter(e => e.type === 'command_transcript').length, color: 'var(--medium)' },
      ].map(s => React.createElement(Col, { key: s.label, span: 6 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: s.label, value: s.value,
            valueStyle: { color: s.color, fontSize: 20 } })))),
    ),
    all.length === 0
      ? React.createElement('div', { style: { color: 'var(--text-muted)', padding: 20 } }, 'No evidence captured yet. Evidence is collected by flag_capture and screenshot subagents.')
      : React.createElement('div', { className: 'a-listpane', 'data-slot': 'LateralPostPage.evidence' },
        all.map((ev, i) =>
          React.createElement(Card, {
            key: ev.id || i, size: 'small',
            style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)', marginBottom: 8,
                     borderLeft: `3px solid ${ev.type === 'flag' ? 'var(--low)' : ev.type === 'screenshot' ? 'var(--cyan)' : 'var(--text-secondary)'}` },
            bodyStyle: { padding: '10px 14px' },
          },
            React.createElement(Row, { align: 'top' },
              React.createElement(Col, { flex: 1 },
                React.createElement(Space, { size: 6 },
                  React.createElement('span', { style: { fontSize: 18 } }, EVT_ICON[ev.type] || EVT_ICON.unknown),
                  React.createElement(Tag, { color: ev.type === 'flag' ? 'green' : ev.type === 'screenshot' ? 'blue' : 'default' },
                    ev.type || 'evidence'),
                  ev.host && React.createElement(Tag, { color: 'orange' }, ev.host),
                ),
                ev.flag && React.createElement('div', {
                  style: { marginTop: 6, fontFamily: 'var(--font-mono)', fontSize: 13,
                           color: 'var(--low)', fontWeight: 700, background: 'var(--bg-surface)',
                           padding: '4px 8px', borderRadius: 4 }
                }, ev.flag),
                ev.description && React.createElement(Text, {
                  style: { color: 'var(--text-secondary)', fontSize: 12, display: 'block', marginTop: 4 }
                }, ev.description),
                ev.file && React.createElement(Text, {
                  style: { fontSize: 10, color: 'var(--text-muted)', display: 'block', marginTop: 2,
                           fontFamily: 'var(--font-mono)' }
                }, ev.file)
              ),
              React.createElement(Col, { style: { minWidth: 80, textAlign: 'right' } },
                React.createElement(Text, { style: { fontSize: 10, color: 'var(--text-muted)' } },
                  new Date(ev.timestamp).toLocaleTimeString())
              )
            )
          )
        )
      )
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
function LateralPostPage({ sessionId }) {
  const { state } = window.useStore();
  const trafficCount  = (state.trafficCaptures || []).length;
  const evidenceCount = (state.evidence || []).length;

  const tabItems = [
    {
      key: 'lateral',
      label: React.createElement(Space, null,
        React.createElement(Text, { style: { color: 'var(--violet)' } }, '↔ Lateral Movement')),
      children: React.createElement(LateralPanel, { sessionId }),
    },
    {
      key: 'post',
      label: React.createElement(Space, null,
        React.createElement(Text, { style: { color: 'var(--cyan)' } }, '🎭 Post-Exploitation')),
      children: React.createElement(PostPanel, { sessionId }),
    },
    {
      key: 'traffic',
      label: React.createElement(Space, null,
        React.createElement(Text, { style: { color: 'var(--cyan)' } },
          `🚦 Traffic${trafficCount > 0 ? ` (${trafficCount})` : ''}`)),
      children: React.createElement(TrafficPanel, null),
    },
    {
      key: 'evidence',
      label: React.createElement(Space, null,
        React.createElement(Text, { style: { color: 'var(--low)' } },
          `🔍 Evidence${evidenceCount > 0 ? ` (${evidenceCount})` : ''}`)),
      children: React.createElement(EvidencePanel, { sessionId }),
    },
  ];

  return React.createElement('div', { 'data-slot': 'LateralPostPage.LateralPostPage', style: { padding: 24 } },
    React.createElement(Title, { level: 3, style: { color: 'var(--cyan)', marginBottom: 16 } },
      '↔🎭 Lateral Movement & Post-Exploitation'),
    React.createElement(Tabs, {
      defaultActiveKey: 'lateral',
      items: tabItems,
      tabBarStyle: { color: 'var(--text-secondary)', borderBottom: '1px solid var(--border)' },
    }),
  );
}

window.LateralPostPage = LateralPostPage;
