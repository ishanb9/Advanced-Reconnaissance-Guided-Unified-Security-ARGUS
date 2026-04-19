// ═══════════════════════════════════════════════════════════
// ARGUS Pentest Platform — API Client
// All REST calls to agent_server.py (port 5001)
// ═══════════════════════════════════════════════════════════

const API = (() => {
  const BASE = '';

  async function req(method, path, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(BASE + path, opts);
    if (!r.ok) {
      const err = await r.text();
      throw new Error(`${r.status}: ${err}`);
    }
    return r.json();
  }

  const get  = (p)    => req('GET',    p);
  const post = (p, b) => req('POST',   p, b);
  const del  = (p)    => req('DELETE', p);

  function qstr(q) {
    const p = Object.entries(q)
      .filter(([, v]) => v != null && v !== '')
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`);
    return p.length ? '?' + p.join('&') : '';
  }

  return {
    // ── Raw helpers (used by inline forms / settings panels) ──────────
    get,
    post,

    // ── Status / metrics ──────────────────────────────────────────────
    status:       () => get('/status'),
    metrics:      () => get('/metrics'),
    cacheMetrics: () => get('/metrics/cache'),
    flushCache:   (prefix) => post('/metrics/cache/flush' + (prefix ? `?prefix=${encodeURIComponent(prefix)}` : ''), {}),

    // ── Session management ────────────────────────────────────────────
    sessions: {
      list:     ()          => get('/sessions'),
      get:      (id)        => get(`/sessions/${id}`),
      summary:  (id)        => get(`/sessions/${id}/summary`),
      create:   (body)      => post('/sessions', body),
      stop:        (id)        => post(`/sessions/${id}/stop`),
      pause:       (id)        => post(`/sessions/${id}/pause`),
      resume:      (id)        => post(`/sessions/${id}/resume`),
      confirm:     (id, phase) => post(`/sessions/${id}/confirm/${phase}`),
      extend:      (id, phase) => post(`/sessions/${id}/extend/${phase}`),
      activate:    (id)        => post(`/sessions/${id}/activate`),
      guidance:    (id, body)  => post(`/sessions/${id}/guidance`, body),
      ask:         (id, question, context) => post(`/sessions/${id}/ask`, { question, context }),
      delete:      (id)        => del(`/sessions/${id}`),
      checkpoints: (id)        => get(`/sessions/${id}/checkpoints`),
      archive:     (id)        => post(`/sessions/${id}/archive`),
      unarchive:   (id)        => post(`/sessions/${id}/unarchive`),
    },

    // ── Session data ──────────────────────────────────────────────────
    findings:    (id, q={}) => get(`/sessions/${id}/findings${qstr(q)}`),
    logs:        (id, q={}) => get(`/sessions/${id}/logs${qstr(q)}`),
    toolOutputs: (id, q={}) => get(`/sessions/${id}/tool-outputs${qstr(q)}`),
    flags:       (id)       => get(`/sessions/${id}/flags`),
    graph:          (id)       => get(`/sessions/${id}/graph`),
    graphNeo4j:     (id)       => get(`/sessions/${id}/graph/neo4j`),
    graphPaths:     (id, fromType='Host', toType='Access', maxDepth=10) =>
      get(`/sessions/${id}/graph/paths?from_type=${fromType}&to_type=${toType}&max_depth=${maxDepth}`),
    chainAnalyses:  (id)       => get(`/sessions/${id}/chain_analyses`),
    // Multi-host: returns {hosts:[{ip,status,findings_count,severity_counts}], session_mode}
    hosts:       (id)       => get(`/sessions/${id}/hosts`),
    osint:       (id)       => get(`/sessions/${id}/osint`),
    shells:      (id, q={}) => get(`/sessions/${id}/shells${qstr(q)}`),
    payloads:    (id)       => get(`/sessions/${id}/payloads`),

    // ── Credentials, tunnels, persistence (phase data) ───────────────
    credentials: (id)       => get(`/sessions/${id}/credentials`),
    tunnels:     (id)       => get(`/sessions/${id}/tunnels`),
    persistence: (id)       => get(`/sessions/${id}/persistence`),

    // ── Lateral movement data ─────────────────────────────────────────
    lateral:     (id)       => get(`/sessions/${id}/lateral`),

    // ── Subagent management ───────────────────────────────────────────
    subagents: {
      /**
       * List all subagent results for a session.
       * @param {string} id   - session id
       * @param {string} [agent]    - filter by agent name (optional)
       * @param {string} [subagent] - filter by subagent name (optional)
       */
      list:    (id, agent=null, subagent=null) =>
        get(`/sessions/${id}/subagents${qstr({ agent, subagent })}`),

      /**
       * Manually trigger a specific subagent.
       * @param {string} id          - session id
       * @param {string} name        - subagent registry key (e.g. 'ssrf', 'aws_enum')
       * @param {string} [target]    - override target IP/host
       * @param {object} [options]   - extra kwargs forwarded to subagent.run()
       */
      run:     (id, name, target=null, options={}) =>
        post(`/sessions/${id}/subagents/${name}/run`, { target, options }),

      /** Available subagent names (from registry) */
      available: () => get('/tools'),   // tool list includes subagent registry hint
    },

    // ── Attack tree, MITRE, evidence ──────────────────────────────────
    attackTree:   (id)           => get(`/sessions/${id}/attack-tree`),
    attackChains: (id)           => get(`/sessions/${id}/attack_chains`),
    evidence:     (id, type=null) =>
      get(`/sessions/${id}/evidence${type ? '?evidence_type=' + type : ''}`),
    mitre:        (id)           => get(`/sessions/${id}/mitre`),
    sessionState: (id)           => get(`/sessions/${id}/state`),

    // ── Report ────────────────────────────────────────────────────────
    reportUrl: (id, fmt='html') => `${BASE}/sessions/${id}/report?format=${fmt}`,

    // ── Shells ────────────────────────────────────────────────────────
    createShell:    (body)         => post('/shells/create', body),
    shellCmd:       (id, cmd, sid) =>
      post(`/shells/${id}/cmd${sid ? '?session_id=' + sid : ''}`, { command: cmd }),
    upgradeShell:   (id, sid)      => post(`/shells/${id}/upgrade?session_id=${sid}`),
    terminateShell: (id, sid)      => post(`/shells/${id}/terminate?session_id=${sid}`),
    shellPayloads:  (sid, lport)   =>
      get(`/shells/payloads?session_id=${sid}&lport=${lport}`),

    // ── Payload generation ────────────────────────────────────────────
    generatePayload: (body) => post('/payloads/generate', body),
    payloadOptions:  ()     => get('/payloads/options'),
    deletePayload:   (id)   => del(`/payloads/${id}`),

    // ── Tools (manual execution) ──────────────────────────────────────
    tools:      () => get('/tools'),
    toolStream: (toolName, target, options) =>
      `${BASE}/tools/stream?tool_name=${encodeURIComponent(toolName)}&target=${encodeURIComponent(target)}&options=${encodeURIComponent(options)}`,

    // ── Chat (AI assistant) ───────────────────────────────────────────
    chat: (message, sessionId) =>
      post('/api/chat', { message, session_id: sessionId }),

    // ── Knowledge base (RAG) ──────────────────────────────────────────
    knowledge: {
      stats:  ()                          => get('/knowledge/stats'),
      search: (query, opts={})            =>
        post('/knowledge/search', {
          query,
          top_k:             opts.top_k          || 5,
          phase_filter:      opts.phase          || null,
          outcome_filter:    opts.outcome        || null,
          chunk_type_filter: opts.chunk_type_filter || null,
        }),
      ingest: (text, source, metadata)   =>
        post('/knowledge/ingest', {
          text,
          source_file: source   || 'manual_entry',
          metadata:    metadata || null,
        }),
    },

    // ── Long-term memory ──────────────────────────────────────────────
    memory: {
      recall: (body) => post('/memory/recall', body),
      store:  (body) => post('/memory/store',  body),
      stats:  ()     => get('/memory/stats'),
    },

    // ── RAG / conversation history ────────────────────────────────────
    ragHistory: (id) => get(`/sessions/${id}/rag_history`),

    // ── WebSocket factory ─────────────────────────────────────────────
    ws: (sessionId) => {
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
      return new WebSocket(`${proto}://${window.location.host}/ws/${sessionId}`);
    },
  };
})();

window.API = API;
