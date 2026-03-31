// SubagentConsolePage.jsx — Full subagent management & live execution console
'use strict';
const { useState, useEffect, useCallback, useRef } = React;
const { Card, Table, Tag, Button, Select, Input, Space, Typography,
        Tooltip, Badge, Drawer, Progress, Divider, Row, Col,
        Statistic, message, Collapse, Switch } = antd;
const { Text, Title, Paragraph } = Typography;
const { Panel } = Collapse;

const AGENT_GROUPS = {
  recon:    { label: 'Recon',          color: '#1890ff', icon: '🔍' },
  web:      { label: 'Web',            color: '#52c41a', icon: '🌐' },
  vuln:     { label: 'Vulnerability',  color: '#faad14', icon: '🔓' },
  exploit:  { label: 'Exploit',        color: '#ff4d4f', icon: '💥' },
  privesc:  { label: 'PrivEsc',        color: '#eb2f96', icon: '⬆' },
  lateral:  { label: 'Lateral',        color: '#722ed1', icon: '↔' },
  post:     { label: 'Post-Exploit',   color: '#13c2c2', icon: '🎭' },
  cloud:    { label: 'Cloud',          color: '#1890ff', icon: '☁' },
  container:{ label: 'Container',      color: '#08979c', icon: '🐳' },
  evasion:  { label: 'Evasion',        color: '#d48806', icon: '🫥' },
  forensics:{ label: 'Forensics',      color: '#597ef7', icon: '🔬' },
  evidence: { label: 'Evidence',       color: '#9254de', icon: '📸' },
  traffic:  { label: 'Traffic',        color: '#36cfc9', icon: '📡' },
  wireless: { label: 'Wireless',       color: '#ff7875', icon: '📶' },
  iot:      { label: 'IoT',            color: '#73d13d', icon: '📟' },
};

// Subagent catalogue — maps key → agent group
const SUBAGENT_CATALOGUE = {
  // Recon
  network_scan:'recon', web_fingerprint:'recon', service_banner:'recon', dns_recon:'recon',
  // Web
  dir_fuzz:'web', web_vuln_scan:'web', sqli:'web', xss:'web',
  injection:'web', burp:'web', cms:'web', ssrf:'web', auth_bypass:'web',
  // Vuln
  cve_lookup:'vuln', ssl_audit:'vuln', smb_vuln:'vuln', service_vuln:'vuln',
  ldap_vuln:'vuln', ftp_vuln:'vuln', ssh_audit:'vuln',
  // Exploit
  metasploit:'exploit', credential_spray:'exploit', web_exploit:'exploit',
  searchsploit:'exploit', exploit_chain:'exploit', post_module:'exploit',
  // Privesc
  linux_enum:'privesc', linux_exploit:'privesc', windows_enum:'privesc',
  windows_exploit:'privesc', container_escape:'privesc', cloud_meta:'privesc',
  // Lateral
  ad_enum:'lateral', kerberos:'lateral', ntlm_capture:'lateral',
  // Post
  persistence:'post', data_exfil:'post', local_cred_harvest:'post',
  log_evasion:'post', c2_deploy:'post',
  // Cloud
  aws_enum:'cloud', azure_enum:'cloud', gcp_enum:'cloud',
  // Container
  docker_audit:'container', k8s_audit:'container',
  // Evasion
  defense_enum:'evasion', av_evasion:'evasion', amsi_bypass:'evasion',
  // Forensics
  artifact_collect:'forensics', timeline:'forensics', memory_analysis:'forensics',
  // Evidence
  screenshot:'evidence', flag_capture:'evidence',
  // Traffic
  pcap_capture:'traffic', credential_sniff:'traffic', mitm:'traffic',
  // Wireless
  wifi_scan:'wireless', wpa2_crack:'wireless', evil_twin:'wireless',
  // IoT
  iot_device_scan:'iot', iot_default_creds:'iot', iot_protocol:'iot', iot_firmware:'iot',
};

const STATUS_COLOR = { running:'var(--cyan)', complete:'var(--low)', error:'var(--critical)', idle:'var(--text-secondary)' };

function LiveLog({ lines }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);
  return React.createElement('div', {
    ref,
    style: {
      background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 4,
      height: 220, overflowY: 'auto', padding: '8px 12px',
      fontFamily: 'monospace', fontSize: 11, color: 'var(--low)',
    },
  }, lines.length === 0
    ? React.createElement('span', { style: { color: 'var(--text-muted)' } }, '— no output yet —')
    : lines.map((l, i) => React.createElement('div', { key: i }, l)),
  );
}

function SubagentCard({ name, agentGroup, state, onRun }) {
  const grp    = AGENT_GROUPS[agentGroup] || { label: agentGroup, color: 'var(--text-secondary)', icon: '🔧' };
  const status = state?.status || 'idle';
  return React.createElement(Card, {
    size: 'small',
    style: {
      background: 'var(--bg-panel)', borderColor: status === 'running' ? grp.color : 'var(--bg-elevated)',
      borderLeft: `3px solid ${grp.color}`, marginBottom: 8,
      transition: 'border-color 0.3s',
    },
    bodyStyle: { padding: '10px 14px' },
  },
    React.createElement(Row, { align: 'middle', justify: 'space-between' },
      React.createElement(Col, { flex: 1 },
        React.createElement(Space, null,
          React.createElement(Text, { style: { color: grp.color } }, grp.icon),
          React.createElement(Text, { strong: true, style: { color: 'var(--text-primary)', fontSize: 13 } }, name),
          React.createElement(Tag, { color: grp.color, style: { fontSize: 10 } }, grp.label),
          status !== 'idle' && React.createElement(Badge, {
            status: status === 'running' ? 'processing' : status === 'complete' ? 'success' : 'error',
            text: React.createElement(Text, { style: { color: STATUS_COLOR[status], fontSize: 11 } }, status),
          }),
        ),
        state?.findings_count > 0 && React.createElement(Text, {
          style: { fontSize: 11, color: 'var(--medium)', display: 'block', marginTop: 2 },
        }, `${state.findings_count} finding(s) · ${state.duration ? state.duration.toFixed(1) + 's' : ''}`),
      ),
      React.createElement(Button, {
        size: 'small', type: 'primary',
        loading: status === 'running',
        disabled: status === 'running',
        style: { background: 'var(--accent)', border: '1px solid var(--accent)', color: '#0D0E14', boxShadow: '0 0 10px var(--accent-glow)' },
        onClick: () => onRun(name),
      }, status === 'running' ? 'Running…' : '▶ Run'),
    ),
  );
}

function SubagentConsolePage({ sessionId }) {
  const [states,    setStates]    = useState({});
  const [logs,      setLogs]      = useState({});      // { subagentName: [lines] }
  const [target,    setTarget]    = useState('');
  const [groupFilter, setGroupFilter] = useState('all');
  const [search,    setSearch]    = useState('');
  const [drawerSA,  setDrawerSA]  = useState(null);   // subagent name for detail drawer

  // Subscribe to Redux store for live subagent states
  useEffect(() => {
    if (!window.__store) return;
    const sync = () => {
      const s = window.__store.getState();
      setStates(s.subagentStates || {});
    };
    sync();
    const unsub = window.__store.subscribe(sync);
    return unsub;
  }, []);

  // Subscribe to WebSocket log events
  useEffect(() => {
    if (!sessionId || !window.__store) return;
    const unsubWS = window.__store.subscribe(() => {
      // The store middleware updates subagentStates on WS events
      // We hook into the raw WS for tool lines
    });
    // Also patch WS dispatcher for tool lines
    const orig = window.__wsDispatch;
    window.__wsDispatch = (ev) => {
      if (orig) orig(ev);
      if (ev.type === 'subagent_tool_line') {
        const sa = ev.data?.subagent;
        const line = ev.data?.line || ev.data?.text || '';
        if (sa) setLogs(p => ({ ...p, [sa]: [...(p[sa] || []).slice(-300), line] }));
      }
    };
    return () => { window.__wsDispatch = orig; };
  }, [sessionId]);

  const handleRun = useCallback(async (name) => {
    if (!sessionId) { message.error('No active session'); return; }
    try {
      const tgt = target || undefined;
      await API.subagents.run(sessionId, name, tgt, {});
      message.success(`${name} started`);
    } catch (e) {
      message.error(`Failed to start ${name}: ${e.message}`);
    }
  }, [sessionId, target]);

  // Aggregate stats
  const running  = Object.values(states).filter(s => s.status === 'running').length;
  const complete = Object.values(states).filter(s => s.status === 'complete').length;
  const errors   = Object.values(states).filter(s => s.status === 'error').length;
  const totalFindings = Object.values(states).reduce((a, s) => a + (s.findings_count || 0), 0);

  // Filter catalogue
  const entries = Object.entries(SUBAGENT_CATALOGUE).filter(([name, group]) => {
    const matchGroup  = groupFilter === 'all' || group === groupFilter;
    const matchSearch = !search || name.includes(search.toLowerCase());
    return matchGroup && matchSearch;
  });

  // Group for display
  const grouped = {};
  entries.forEach(([name, group]) => {
    if (!grouped[group]) grouped[group] = [];
    grouped[group].push(name);
  });

  return React.createElement('div', { style: { padding: 24 } },

    React.createElement(Title, { level: 3, style: { color: 'var(--cyan)', marginBottom: 16 } },
      '🤖 Subagent Console'),

    // Stats bar
    React.createElement(Row, { gutter: 12, style: { marginBottom: 20 } },
      [
        { label: 'Running',  value: running,       color: 'var(--cyan)' },
        { label: 'Complete', value: complete,       color: 'var(--low)' },
        { label: 'Errors',   value: errors,         color: 'var(--critical)' },
        { label: 'Findings', value: totalFindings,  color: 'var(--medium)' },
      ].map(s => React.createElement(Col, { key: s.label, span: 6 },
        React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)' } },
          React.createElement(Statistic, { title: s.label, value: s.value,
            valueStyle: { color: s.color, fontSize: 22 } })))),
    ),

    // Controls
    React.createElement(Card, { size: 'small', style: { background: 'var(--bg-panel)', borderColor: 'var(--border-light)', marginBottom: 16 } },
      React.createElement(Space, { wrap: true },
        React.createElement(Input, {
          placeholder: 'Override target IP/host (optional)',
          style: { width: 240 },
          prefix: '🎯',
          value: target,
          onChange: e => setTarget(e.target.value),
        }),
        React.createElement(Input.Search, {
          placeholder: 'Search subagent…',
          style: { width: 200 },
          allowClear: true,
          onSearch: setSearch,
          onChange: e => !e.target.value && setSearch(''),
        }),
        React.createElement(Select, {
          value: groupFilter,
          style: { width: 160 },
          onChange: setGroupFilter,
          options: [
            { value: 'all', label: 'All Groups' },
            ...Object.entries(AGENT_GROUPS).map(([k, v]) => ({ value: k, label: `${v.icon} ${v.label}` })),
          ],
        }),
      ),
    ),

    // Subagent cards grouped by phase
    React.createElement(Collapse, {
      defaultActiveKey: Object.keys(grouped),
      style: { background: 'transparent', border: 'none' },
    },
      Object.entries(grouped).map(([group, names]) => {
        const grp = AGENT_GROUPS[group] || { label: group, color: 'var(--text-secondary)', icon: '🔧' };
        return React.createElement(Panel, {
          key: group,
          header: React.createElement(Space, null,
            React.createElement(Text, { style: { color: grp.color, fontSize: 14 } }, grp.icon + ' ' + grp.label),
            React.createElement(Tag, { color: grp.color }, names.length + ' subagents'),
          ),
          style: { background: 'var(--bg-surface)', marginBottom: 8, border: '1px solid var(--border)', borderRadius: 6 },
        },
          names.map(name =>
            React.createElement(SubagentCard, {
              key: name,
              name,
              agentGroup: group,
              state: states[name],
              onRun: handleRun,
            })
          ),
        );
      })
    ),

    // Detail drawer — shows live log for running subagent
    drawerSA && React.createElement(Drawer, {
      title: React.createElement(Text, { style: { color: 'var(--cyan)' } }, `Live Output: ${drawerSA}`),
      placement: 'right', width: 600,
      open: !!drawerSA,
      onClose: () => setDrawerSA(null),
      bodyStyle: { background: 'var(--bg-surface)', padding: 16 },
    },
      React.createElement(LiveLog, { lines: logs[drawerSA] || [] }),
      states[drawerSA]?.findings_count > 0 && React.createElement('div', { style: { marginTop: 12 } },
        React.createElement(Text, { style: { color: 'var(--medium)' } },
          `${states[drawerSA].findings_count} finding(s) stored to session`),
      ),
    ),
  );
}

window.SubagentConsolePage = SubagentConsolePage;
