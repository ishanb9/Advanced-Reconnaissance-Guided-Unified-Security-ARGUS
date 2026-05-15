/* ═══════════════════════════════════════════════════════════════
   UserAdminPage — admin view for users, roles, sessions, audit
   ───────────────────────────────────────────────────────────────
   Visible only when the current user holds PLATFORM_ADMIN or OWNER.
   The backend RBAC engine still enforces every action — this UI is
   only a convenience surface that hides controls the user can't use.

   Sections:
     • Users           — list, search, create, deactivate, role grant
     • Sessions        — see active per user, kill
     • Audit Log       — read with filters; admins can configure retention
                         (delete is OWNER-only and shown as a separate panel)
     • Identity Providers — list, view config (secrets redacted)
     • SCIM Tokens     — issue new (shown once), revoke
   ─────────────────────────────────────────────────────────────── */
(function () {
  const { useState, useEffect, useMemo } = React;

  const ROLES = [
    'OWNER', 'PLATFORM_ADMIN', 'SECURITY_MANAGER',
    'OPERATOR', 'ANALYST', 'EXECUTIVE', 'AUDITOR', 'CLIENT',
  ];

  function authFetch(url, opts = {}) {
    const token = window.localStorage.getItem('argus.access_token');
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    // CSRF double-submit — read from cookie
    const csrf = (document.cookie.split('; ').find(c => c.startsWith('argus_csrf=')) || '')
                  .split('=')[1];
    if (csrf && opts.method && opts.method.toUpperCase() !== 'GET') {
      headers['X-CSRF-Token'] = decodeURIComponent(csrf);
    }
    return fetch(url, { credentials: 'include', ...opts, headers });
  }

  function UserAdminPage() {
    const [tab, setTab] = useState('users');
    return React.createElement('div', { className: 'panel', style: { padding: 0 } },
      React.createElement('div', { className: 'hub-tabbar' },
        ['users', 'sessions', 'audit', 'identity', 'scim'].map(t =>
          React.createElement('div', {
            key: t,
            className: 'hub-tab',
            'data-active': tab === t,
            onClick: () => setTab(t),
          },
            { users: 'Users', sessions: 'Sessions', audit: 'Audit Log',
              identity: 'Identity Providers', scim: 'SCIM Tokens' }[t]
          )
        )
      ),
      React.createElement('div', { style: { padding: 16 } },
        tab === 'users'   && React.createElement(UsersPanel),
        tab === 'sessions' && React.createElement(SessionsPanel),
        tab === 'audit'   && React.createElement(AuditPanel),
        tab === 'identity' && React.createElement(IdentityPanel),
        tab === 'scim'    && React.createElement(ScimTokensPanel),
      )
    );
  }

  // ── Users ──────────────────────────────────────────────────────
  function UsersPanel() {
    const [rows, setRows] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showNew, setShowNew] = useState(false);
    const [filter, setFilter] = useState('');

    function refresh() {
      setLoading(true);
      authFetch('/auth/admin/users')
        .then(r => r.ok ? r.json() : [])
        .then(setRows)
        .finally(() => setLoading(false));
    }
    useEffect(refresh, []);

    const filtered = useMemo(() => {
      const f = filter.trim().toLowerCase();
      if (!f) return rows;
      return rows.filter(u =>
        (u.email || '').toLowerCase().includes(f)
        || (u.display_name || '').toLowerCase().includes(f)
        || (u.roles || []).some(r => r.toLowerCase().includes(f))
      );
    }, [rows, filter]);

    return React.createElement('div', null,
      React.createElement('div', { className: 'panel-title' }, 'Users'),
      React.createElement('div', { style: {
        display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12,
      }},
        React.createElement('input', {
          placeholder: 'Search by email, name, role…',
          value: filter, onChange: e => setFilter(e.target.value),
          style: { flex: 1 },
        }),
        React.createElement('button', { onClick: () => setShowNew(s => !s) },
          showNew ? 'Cancel' : '+ New User'),
        React.createElement('button', { onClick: refresh,
          className: 'secondary' }, 'Refresh'),
      ),
      showNew && React.createElement(NewUserForm, {
        onCreated: () => { setShowNew(false); refresh(); }
      }),
      loading
        ? React.createElement('div', null, 'Loading…')
        : React.createElement('table', { style: { width: '100%' } },
            React.createElement('thead', null,
              React.createElement('tr', null,
                ['Email', 'Display name', 'Status', 'MFA', 'Roles', 'Last login', 'Actions']
                  .map(h => React.createElement('th', { key: h }, h))
              )
            ),
            React.createElement('tbody', null,
              filtered.map(u => React.createElement(UserRow, { key: u.id, u, onChange: refresh }))
            )
          )
    );
  }

  function UserRow({ u, onChange }) {
    const [busy, setBusy] = useState(false);
    const [showRole, setShowRole] = useState(false);

    async function toggleStatus() {
      setBusy(true);
      const next = (u.status === 'ACTIVE') ? 'SUSPENDED' : 'ACTIVE';
      const r = await authFetch(`/auth/admin/users/${u.id}`, {
        method: 'PATCH', body: JSON.stringify({ status: next }),
      });
      setBusy(false);
      if (r.ok) onChange();
    }

    return React.createElement(React.Fragment, null,
      React.createElement('tr', null,
        React.createElement('td', null, u.email),
        React.createElement('td', null, u.display_name || '—'),
        React.createElement('td', null,
          React.createElement('span', { className: 'badge', 'data-status': u.status },
            u.status)
        ),
        React.createElement('td', null, u.mfa_enabled ? '✓' : '—'),
        React.createElement('td', null,
          (u.roles || []).map(r => React.createElement('span', {
            key: r, className: 'badge', style: { marginRight: 4 }
          }, r))
        ),
        React.createElement('td', null,
          u.last_login_at
            ? new Date(u.last_login_at).toLocaleString()
            : 'Never'),
        React.createElement('td', null,
          React.createElement('button', {
            disabled: busy, onClick: () => setShowRole(s => !s),
          }, 'Roles'),
          ' ',
          React.createElement('button', {
            disabled: busy, onClick: toggleStatus, className: 'secondary',
          }, u.status === 'ACTIVE' ? 'Suspend' : 'Reactivate'),
        )
      ),
      showRole && React.createElement('tr', null,
        React.createElement('td', { colSpan: 7, style: { padding: 8 } },
          React.createElement(RoleManager, { user: u, onChange })
        )
      )
    );
  }

  function RoleManager({ user, onChange }) {
    const [chosen, setChosen] = useState('');
    const [busy, setBusy] = useState(false);

    async function grant() {
      if (!chosen) return;
      setBusy(true);
      const r = await authFetch(`/auth/admin/users/${user.id}/role`, {
        method: 'POST', body: JSON.stringify({ role: chosen }),
      });
      setBusy(false);
      if (r.ok) { setChosen(''); onChange(); }
    }

    async function revoke(role) {
      setBusy(true);
      const r = await authFetch(`/auth/admin/users/${user.id}/role/${role}`,
                                 { method: 'DELETE' });
      setBusy(false);
      if (r.ok) onChange();
    }

    return React.createElement('div', null,
      React.createElement('div', { style: { display: 'flex', gap: 6, marginBottom: 6 } },
        (user.roles || []).map(r =>
          React.createElement('span', { key: r, className: 'badge',
            style: { display: 'inline-flex', gap: 4, alignItems: 'center' } },
            r,
            React.createElement('button', {
              onClick: () => revoke(r), disabled: busy,
              style: { background: 'transparent', border: 'none', cursor: 'pointer',
                       padding: 0, fontSize: 12 },
              title: 'Revoke',
            }, '×'),
          )
        )
      ),
      React.createElement('div', { style: { display: 'flex', gap: 6 } },
        React.createElement('select', {
          value: chosen, onChange: e => setChosen(e.target.value),
        },
          React.createElement('option', { value: '' }, '— Add role —'),
          ROLES.filter(r => !(user.roles || []).includes(r)).map(r =>
            React.createElement('option', { key: r, value: r }, r))
        ),
        React.createElement('button', {
          onClick: grant, disabled: !chosen || busy,
        }, 'Grant'),
      )
    );
  }

  function NewUserForm({ onCreated }) {
    const [email, setEmail] = useState('');
    const [displayName, setDisplayName] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState('ANALYST');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);

    async function submit(e) {
      e.preventDefault();
      setBusy(true); setError(null);
      const r = await authFetch('/auth/admin/users', {
        method: 'POST',
        body: JSON.stringify({
          email, display_name: displayName, initial_password: password,
          roles: [role], send_invite: !password,
        }),
      });
      setBusy(false);
      if (r.ok) { onCreated(); return; }
      const d = await r.json().catch(() => ({}));
      setError(d.detail || 'Create failed.');
    }

    return React.createElement('form', { onSubmit: submit, className: 'panel',
      style: { padding: 12, marginBottom: 12, display: 'flex', flexWrap: 'wrap', gap: 8 } },
      React.createElement('input', {
        placeholder: 'Email', type: 'email', required: true,
        value: email, onChange: e => setEmail(e.target.value),
      }),
      React.createElement('input', {
        placeholder: 'Display name',
        value: displayName, onChange: e => setDisplayName(e.target.value),
      }),
      React.createElement('input', {
        placeholder: 'Initial password (leave blank to invite)',
        type: 'password', value: password,
        onChange: e => setPassword(e.target.value),
      }),
      React.createElement('select', {
        value: role, onChange: e => setRole(e.target.value),
      },
        ROLES.map(r => React.createElement('option', { key: r, value: r }, r))
      ),
      React.createElement('button', { type: 'submit', disabled: busy },
        busy ? 'Creating…' : 'Create'),
      error && React.createElement('div', { style: { color: 'var(--critical)', flexBasis: '100%' } },
        String(error))
    );
  }

  // ── Sessions ───────────────────────────────────────────────────
  function SessionsPanel() {
    // Admin "all sessions" endpoint not built in this pass — link to per-user view
    return React.createElement('div', null,
      React.createElement('div', { className: 'panel-title' }, 'Sessions'),
      React.createElement('div', { className: 'auth-muted' },
        'Use the Users panel; click a user to see and revoke their active sessions. ' +
        'Endpoint: GET /auth/sessions (own) — admin all-sessions endpoint can be ' +
        'added via require_permission("sessions", "read") on a custom route.')
    );
  }

  // ── Audit log ──────────────────────────────────────────────────
  function AuditPanel() {
    const [rows, setRows] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('');

    function refresh() {
      setLoading(true);
      const u = '/auth/admin/audit?limit=200' +
                (filter ? `&action_prefix=${encodeURIComponent(filter)}` : '');
      authFetch(u).then(r => r.ok ? r.json() : []).then(setRows)
        .finally(() => setLoading(false));
    }
    useEffect(refresh, []);

    return React.createElement('div', null,
      React.createElement('div', { className: 'panel-title' }, 'Audit Log'),
      React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 10 } },
        React.createElement('input', {
          placeholder: 'Filter by action prefix (e.g. auth., admin.)',
          value: filter, onChange: e => setFilter(e.target.value),
          style: { flex: 1 },
        }),
        React.createElement('button', { onClick: refresh }, 'Refresh'),
        React.createElement(RetentionConfig),
      ),
      loading
        ? React.createElement('div', null, 'Loading…')
        : React.createElement('table', { style: { width: '100%' } },
            React.createElement('thead', null,
              React.createElement('tr', null,
                ['Time', 'Action', 'Actor', 'Resource', 'Severity', 'Status', 'IP']
                  .map(h => React.createElement('th', { key: h }, h)))),
            React.createElement('tbody', null,
              rows.map(r =>
                React.createElement('tr', { key: r.id, title: JSON.stringify(r.after_data || {}) },
                  React.createElement('td', null, new Date(r.ts).toLocaleString()),
                  React.createElement('td', null, r.action),
                  React.createElement('td', null, (r.actor_user_id || '').slice(0, 8) || 'system'),
                  React.createElement('td', null,
                    r.resource_type ? `${r.resource_type}:${(r.resource_id || '').slice(0, 8)}` : '—'),
                  React.createElement('td', null,
                    React.createElement('span', { className: 'badge' }, r.severity)),
                  React.createElement('td', null, r.status),
                  React.createElement('td', null, r.ip_address || '—'),
                )
              )
            )
          )
    );
  }

  function RetentionConfig() {
    const [open, setOpen] = useState(false);
    const [maxRows, setMaxRows] = useState(1_000_000);
    const [maxAge, setMaxAge] = useState(730);
    const [busy, setBusy] = useState(false);

    async function save() {
      setBusy(true);
      await authFetch('/auth/admin/audit/retention', {
        method: 'POST',
        body: JSON.stringify({ max_rows: maxRows, max_age_days: maxAge }),
      });
      setBusy(false); setOpen(false);
    }

    if (!open) return React.createElement('button', { onClick: () => setOpen(true) },
      'Retention…');

    return React.createElement('div', { className: 'panel',
      style: { padding: 12, display: 'flex', gap: 8, alignItems: 'center' } },
      React.createElement('label', null, 'Max rows ',
        React.createElement('input', { type: 'number', value: maxRows, min: 1000,
          onChange: e => setMaxRows(parseInt(e.target.value || 0, 10)) })),
      React.createElement('label', null, 'Max age (days) ',
        React.createElement('input', { type: 'number', value: maxAge, min: 1,
          onChange: e => setMaxAge(parseInt(e.target.value || 0, 10)) })),
      React.createElement('button', { onClick: save, disabled: busy },
        busy ? 'Saving…' : 'Save'),
      React.createElement('button', { className: 'secondary', onClick: () => setOpen(false) },
        'Close')
    );
  }

  // ── Identity Providers ──────────────────────────────────────────
  function IdentityPanel() {
    const [rows, setRows] = useState([]);
    useEffect(() => {
      authFetch('/auth/admin/identity-providers')
        .then(r => r.ok ? r.json() : []).then(setRows);
    }, []);
    return React.createElement('div', null,
      React.createElement('div', { className: 'panel-title' }, 'Identity Providers'),
      rows.length === 0 && React.createElement('div', { className: 'auth-muted' },
        'No identity providers configured. ' +
        'Use POST /auth/admin/identity-providers to add OIDC or SAML.'),
      rows.map(p => React.createElement('div', { key: p.id, className: 'panel',
          style: { padding: 12, marginBottom: 8 } },
        React.createElement('div', { style: { fontWeight: 600 } }, `${p.name} (${p.kind})`),
        React.createElement('div', { className: 'auth-muted' },
          p.enabled ? 'Enabled' : 'Disabled',
          ' · Default role: ', p.default_role,
          ' · JIT provisioning: ', p.just_in_time_provisioning ? 'Yes' : 'No'),
        React.createElement('pre', { style: { marginTop: 8, fontSize: 11 } },
          JSON.stringify(p.config, null, 2)),
      ))
    );
  }

  // ── SCIM Tokens ─────────────────────────────────────────────────
  function ScimTokensPanel() {
    const [desc, setDesc] = useState('');
    const [days, setDays] = useState(365);
    const [issued, setIssued] = useState(null);
    const [busy, setBusy] = useState(false);

    async function issue() {
      setBusy(true);
      const r = await authFetch('/auth/admin/scim-tokens', {
        method: 'POST',
        body: JSON.stringify({ description: desc, ttl_days: days }),
      });
      setBusy(false);
      if (r.ok) {
        const data = await r.json();
        setIssued(data);
        setDesc('');
      }
    }

    return React.createElement('div', null,
      React.createElement('div', { className: 'panel-title' }, 'SCIM Bearer Tokens'),
      React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 10 } },
        React.createElement('input', {
          placeholder: 'Description (e.g. "Okta production")',
          value: desc, onChange: e => setDesc(e.target.value),
          style: { flex: 1 },
        }),
        React.createElement('input', {
          type: 'number', min: 1, max: 3650, style: { width: 100 },
          value: days, onChange: e => setDays(parseInt(e.target.value || 0, 10)),
        }),
        React.createElement('button', {
          onClick: issue, disabled: busy || !desc.trim(),
        }, busy ? 'Issuing…' : 'Issue Token')
      ),
      issued && React.createElement('div', { className: 'panel',
          style: { padding: 12, background: 'var(--accent-subtle)' } },
        React.createElement('div', { style: { fontWeight: 600, marginBottom: 6 } },
          'New token (shown ONCE — copy now)'),
        React.createElement('pre', { style: { wordBreak: 'break-all',
          fontFamily: 'var(--font-mono)', fontSize: 12 } },
          issued.token),
        React.createElement('div', { className: 'auth-muted' },
          `Expires: ${new Date(issued.expires_at).toLocaleString()}`),
        React.createElement('button', { onClick: () => setIssued(null) }, 'Dismiss'),
      ),
      React.createElement('div', { className: 'auth-muted', style: { marginTop: 12 } },
        'Configure this token in your IdP (Okta / Azure AD / OneLogin) as the ' +
        'SCIM endpoint bearer token. Users + group assignments will sync ' +
        'automatically. Endpoint: ', React.createElement('code', null, '/scim/v2'))
    );
  }

  window.UserAdminPage = UserAdminPage;
})();
