// MetaAgentsPanel.jsx — Collapsible panel showing live workings of
// MasterCheckerAgent and IssueValidatorAgent.
//
// Contains two sub-panels (one per agent), each with 3 tabs:
//   1. Thought Stream  — live LLM conversation via LiveTerminal
//   2. Corrections     — chronological CorrectionCard list
//   3. Summary         — running stats
'use strict';
const { useState: _useState } = React;
const {
  Collapse: _Collapse, Tabs: _Tabs, Badge: _Badge,
  Statistic: _Statistic, Row: _Row, Col: _Col,
} = antd;
const { Panel: _Panel } = _Collapse;
const { TabPane: _TabPane } = _Tabs;

function MetaAgentSubPanel({ agentKey, label, agentState }) {
  if (!agentState) return null;

  const { history, corrections, stats, status, phase } = agentState;

  // Convert history to LiveTerminal line format
  const termLines = (history || []).map(entry => ({
    line: entry.role === 'user'
      ? `[PROMPT] ${entry.content}`
      : `[RESPONSE] ${entry.content}`,
    type: entry.role === 'user' ? 'stderr' : 'stdout',
  }));

  const blockingCount = stats ? stats.blocking  : 0;
  const advisoryCount = stats ? stats.advisory  : 0;
  const totalCount    = stats ? stats.total      : 0;

  const statusColor = status === 'thinking' ? 'var(--amber)' : 'var(--text-muted)';
  const statusLabel = status === 'thinking'
    ? `⟳ Thinking${phase ? ` [${phase}]` : ''}…`
    : `● Idle${phase ? ` (last: ${phase})` : ''}`;

  const tabBarStyle = { marginBottom: 8 };

  return React.createElement('div', null,
    // Status bar
    React.createElement('div', {
      style: {
        fontSize:    10,
        color:       statusColor,
        marginBottom: 8,
        fontFamily:  'var(--font-mono)',
      }
    }, statusLabel),

    React.createElement(_Tabs, {
      defaultActiveKey: 'stream',
      size: 'small',
      tabBarStyle,
    },
      // ── Tab 1: Thought Stream ────────────────────────────────
      React.createElement(_TabPane, { tab: '💬 Thought Stream', key: 'stream' },
        React.createElement(window.LiveTerminal, {
          lines:      termLines,
          height:     260,
          agentColor: agentKey === 'checker' ? 'var(--violet)' : 'var(--cyan)',
          title:      `${label} — LLM conversation`,
        }),
      ),

      // ── Tab 2: Corrections ───────────────────────────────────
      React.createElement(_TabPane, {
        tab: React.createElement('span', null,
          '🔧 Corrections ',
          totalCount > 0 && React.createElement(_Badge, {
            count: totalCount,
            style: { backgroundColor: blockingCount > 0 ? '#ff4d4f' : '#faad14' },
          }),
        ),
        key: 'corrections',
      },
        React.createElement('div', {
          style: { maxHeight: 280, overflowY: 'auto' }
        },
          corrections && corrections.length > 0
            ? corrections.map((c, i) =>
                React.createElement(window.CorrectionCard, { key: i, correction: c })
              )
            : React.createElement('div', {
                style: { color: 'var(--text-muted)', fontSize: 11, padding: 8 }
              }, 'No corrections yet.'),
        ),
      ),

      // ── Tab 3: Summary ───────────────────────────────────────
      React.createElement(_TabPane, { tab: '📊 Summary', key: 'summary' },
        React.createElement(_Row, { gutter: [12, 12], style: { marginTop: 8 } },
          React.createElement(_Col, { span: 8 },
            React.createElement(_Statistic, {
              title: 'Total',
              value: totalCount,
              valueStyle: { fontSize: 20, color: 'var(--text-primary)' },
            }),
          ),
          React.createElement(_Col, { span: 8 },
            React.createElement(_Statistic, {
              title: '⛔ Blocking',
              value: blockingCount,
              valueStyle: { fontSize: 20, color: blockingCount > 0 ? 'var(--red)' : 'var(--text-muted)' },
            }),
          ),
          React.createElement(_Col, { span: 8 },
            React.createElement(_Statistic, {
              title: '💡 Advisory',
              value: advisoryCount,
              valueStyle: { fontSize: 20, color: advisoryCount > 0 ? 'var(--amber)' : 'var(--text-muted)' },
            }),
          ),
          agentKey === 'checker' && stats &&
            React.createElement(_Col, { span: 12 },
              React.createElement(_Statistic, {
                title: 'Phases Reviewed',
                value: stats.phasesReviewed || 0,
                valueStyle: { fontSize: 16, color: 'var(--text-secondary)' },
              }),
            ),
          agentKey === 'validator' && stats &&
            React.createElement(_Col, { span: 12 },
              React.createElement(_Statistic, {
                title: 'Tools Validated',
                value: stats.toolsValidated || 0,
                valueStyle: { fontSize: 16, color: 'var(--text-secondary)' },
              }),
            ),
        ),
      ),
    ),
  );
}

function MetaAgentsPanel() {
  const { state } = window.useStore();
  const checkerState   = state.metaCheckerState;
  const validatorState = state.metaValidatorState;

  const checkerTotal   = checkerState   ? checkerState.stats.total   : 0;
  const validatorTotal = validatorState ? validatorState.stats.total : 0;
  const totalAll       = checkerTotal + validatorTotal;

  const hasBlocking = (
    (checkerState   ? checkerState.stats.blocking   : 0) +
    (validatorState ? validatorState.stats.blocking : 0)
  ) > 0;

  const headerLabel = React.createElement('span', {
    style: { color: 'var(--violet)', fontWeight: 600 }
  },
    '🛡 Meta-Agents',
    React.createElement('span', {
      style: { color: 'var(--text-muted)', fontWeight: 400, marginLeft: 6, fontSize: 11 }
    }, '— Auditor & Validator'),
    totalAll > 0 && React.createElement(_Badge, {
      count: totalAll,
      style: { backgroundColor: hasBlocking ? '#ff4d4f' : '#faad14', marginLeft: 8 },
    }),
  );

  return React.createElement(_Collapse, {
    defaultActiveKey: [],
    style: { marginTop: 12 },
  },
    React.createElement(_Panel, { header: headerLabel, key: 'meta' },
      React.createElement(_Collapse, {
        defaultActiveKey: ['checker'],
        accordion: false,
      },
        // Master Checker sub-panel
        React.createElement(_Panel, {
          header: React.createElement('span', { style: { color: 'var(--violet)' } },
            `🔎 Master Checker`,
            checkerTotal > 0 && React.createElement(_Badge, {
              count: checkerTotal,
              style: {
                backgroundColor: checkerState && checkerState.stats.blocking > 0
                  ? '#ff4d4f' : '#faad14',
                marginLeft: 6,
              },
            }),
          ),
          key: 'checker',
        },
          React.createElement(MetaAgentSubPanel, {
            agentKey:   'checker',
            label:      'Master Checker',
            agentState: checkerState,
          }),
        ),

        // Issue Validator sub-panel
        React.createElement(_Panel, {
          header: React.createElement('span', { style: { color: 'var(--cyan)' } },
            `🔍 Issue Validator`,
            validatorTotal > 0 && React.createElement(_Badge, {
              count: validatorTotal,
              style: {
                backgroundColor: validatorState && validatorState.stats.blocking > 0
                  ? '#ff4d4f' : '#faad14',
                marginLeft: 6,
              },
            }),
          ),
          key: 'validator',
        },
          React.createElement(MetaAgentSubPanel, {
            agentKey:   'validator',
            label:      'Issue Validator',
            agentState: validatorState,
          }),
        ),
      ),
    ),
  );
}
window.MetaAgentsPanel = MetaAgentsPanel;
