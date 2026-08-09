/* ═══════════════════════════════════════════════════════════════════════
   ARGUS — AVATAR COPY PACKS
   ───────────────────────────────────────────────────────────────────────
   Same data, different voice. Each avatar maps a STABLE string id to its
   own phrasing. A DEFAULT pack always backs every id, so a missing key
   renders the default string — never blank, never a raw key.

     window.ArgusCopy.t('risk.title')            -> avatar string
     window.ArgusCopy.t('x.y', 'Fallback text')  -> explicit fallback
     window.ArgusCopy.pack()                     -> active merged pack
     window.ArgusCopy.audit()                    -> key-coverage report

   ── GUARDRAIL — VOICE MAY NOT OVERSTATE EVIDENCE ────────────────────────
   Copy packs change TONE, never TRUTH CLAIMS. No avatar may render an
   unproven finding as "BREACH CONFIRMED" / "PWNED" / "ROOT". Status
   vocabulary maps 1:1 onto the same underlying states in every avatar.
   `ArgusCopy.audit()` fails the build-time check if a pack introduces a
   claim-strength word that the default pack does not also use.

   NOTE ON CLIENT_TOOL_DEFANG (app.jsx): that layer is MODE-driven
   (CLIENT mode rewrites tool jargon to outcomes). It is orthogonal to
   avatars and is intentionally left in place — the two compose, they do
   not compete: defang acts on TOOL NAMES, copy packs act on UI LABELS.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ── DEFAULT PACK — the safety net. Every id must exist here. ──────── */
  var DEFAULT = {
    // Risk / posture
    'risk.title':            'Aggregate Risk Score',
    'risk.subtitle':         'Weighted by severity of confirmed findings',
    'risk.band.critical':    'Critical',
    'risk.band.high':        'High',
    'risk.band.medium':      'Medium',
    'risk.band.low':         'Low',

    // Findings
    'findings.title':        'Findings',
    'findings.empty':        'No findings recorded yet.',
    'findings.register':     'Findings Register',
    'findings.proven':       'Confirmed',
    'findings.unproven':     'Unconfirmed',

    // Kill chain
    'killchain.title':       'Attack Chain Progress',
    'killchain.stage':       'Stage',

    // Actions
    'action.next':           'Next Best Actions',
    'action.rankedBy':       'ranked by value of information',

    // Scan / session state
    'scan.running':          'Scan in progress',
    'scan.paused':           'Scan paused',
    'scan.complete':         'Scan complete',
    'scan.idle':             'No active scan',
    'scan.degraded':         'Engine degraded — results may be incomplete',

    // Hosts / assets
    'host.unreachable':      'Host did not respond',
    'host.title':            'Hosts',
    'host.assessed':         'Assessed',
    'host.notAssessed':      'Not assessed',

    // Agents
    'agent.title':           'Agents',
    'agent.idle':            'Idle',
    'agent.active':          'Active',

    // Evidence / data availability  (anti-fabrication vocabulary)
    'data.none':             'No data',
    'data.notCollected':     'Not collected',
    'data.notConfigured':    'Not configured',
    'data.notConfiguredWhy': 'This view requires data ARGUS does not collect yet.',
    'data.unavailable':      'Unavailable',
    'data.pending':          'Pending',

    // Report
    'report.title':          'Report',
    'report.generated':      'Generated',

    // Governance (WARDEN-leaning, but must exist for all)
    'gov.residual':          'Residual Exposure',
    'gov.coverageGap':       'Coverage Gap',
    'gov.treatment':         'Treatment Priorities',
    'gov.controlFailure':    'Control Failure Points',
    'gov.aging':             'Remediation Aging',
    'gov.recurrence':        'Recurring Findings'
  };

  /* ── AVATAR PACKS — only the ids that differ need to be listed ─────── */
  var PACKS = {
    blacksite: {
      'risk.title':       'AGGREGATE RISK SCORE',
      'findings.title':   'FINDINGS',
      'findings.empty':   'No findings yet — recon in progress',
      'findings.register':'FINDINGS REGISTER',
      'killchain.title':  'KILL-CHAIN PROGRESS',
      'action.next':      'NEXT BEST ACTIONS',
      'scan.running':     'SCANNING',
      'scan.paused':      'HOLD',
      'scan.complete':    'COMPLETE',
      'scan.idle':        'STANDBY',
      'scan.degraded':    'ENGINE DEGRADED — PARTIAL RESULTS',
      'host.unreachable': 'Host unreachable',
      'host.title':       'HOSTS',
      'agent.title':      'AGENTS',
      'data.none':        'NO DATA'
    },

    phosphor: {
      'risk.title':       'risk',
      'risk.subtitle':    'weighted by confirmed severity',
      'findings.title':   'findings',
      'findings.empty':   '-- no findings --',
      'findings.register':'register',
      'killchain.title':  'chain',
      'action.next':      'next',
      'action.rankedBy':  'by voi',
      'scan.running':     '[run]',
      'scan.paused':      '[hold]',
      'scan.complete':    '[done]',
      'scan.idle':        '[idle]',
      'scan.degraded':    '[degraded] partial results',
      'host.unreachable': 'host down',
      'host.title':       'hosts',
      'host.notAssessed': 'not assessed',
      'agent.title':      'agents',
      'agent.idle':       'idle',
      'agent.active':     'active',
      'data.none':        'n/a',
      'data.notCollected':'not collected',
      'data.notConfigured':'not configured',
      'report.title':     'report'
    },

    redcell: {
      'risk.title':       'TARGET VALUE',
      'risk.subtitle':    'Weighted by confirmed attack surface',
      'findings.title':   'WEAKNESSES',
      'findings.empty':   'NO WEAKNESSES SURFACED YET',
      'findings.register':'TARGET REGISTER',
      'killchain.title':  'KILL CHAIN',
      'action.next':      'PRIORITY TARGETS',
      'action.rankedBy':  'ranked by value of information',
      'scan.running':     'OPERATION ACTIVE',
      'scan.paused':      'OPERATION HELD',
      'scan.complete':    'OPERATION COMPLETE',
      'scan.idle':        'STANDING BY',
      'scan.degraded':    'ENGINE DEGRADED — PARTIAL RESULTS',
      'host.unreachable': 'NO ROUTE TO TARGET',
      'host.title':       'TARGETS',
      'agent.title':      'OPERATORS',
      'data.none':        'NO DATA'
    },

    ghostwire: {
      'risk.title':       'ICE LEVEL',
      'risk.subtitle':    'Weighted by confirmed intrusion surface',
      'findings.title':   'VECTORS',
      'findings.empty':   'NO ICE MAPPED',
      'findings.register':'VECTOR REGISTER',
      'killchain.title':  'INTRUSION PATH',
      'action.next':      'NEXT MOVES',
      'scan.running':     'DAEMONS RUNNING',
      'scan.paused':      'SUSPENDED',
      'scan.complete':    'RUN COMPLETE',
      'scan.idle':        'DORMANT',
      'scan.degraded':    'ENGINE DEGRADED — PARTIAL RESULTS',
      'host.unreachable': 'GHOST — NO SIGNAL',
      'host.title':       'NODES',
      'agent.title':      'DAEMONS',
      'data.none':        'NO SIGNAL'
    },

    dossier: {
      'risk.title':       'Threat Assessment',
      'risk.subtitle':    'Weighted by severity of confirmed findings',
      'findings.title':   'Observations',
      'findings.empty':   'No issues identified at this stage.',
      'findings.register':'Schedule of Findings',
      'killchain.title':  'Attack Progression',
      'action.next':      'Recommended Priorities',
      'action.rankedBy':  'ordered by assessed priority',
      'scan.running':     'Assessment in progress',
      'scan.paused':      'Assessment paused',
      'scan.complete':    'Assessment complete',
      'scan.idle':        'No assessment running',
      'scan.degraded':    'Assessment incomplete — engine degraded',
      'host.unreachable': 'Host did not respond',
      'host.title':       'Subjects',
      'agent.title':      'Assessors',
      'data.none':        'Not recorded',
      'data.notCollected':'Not recorded',
      'report.title':     'Engagement Report'
    },

    warden: {
      'risk.title':       'Residual Exposure',
      'risk.subtitle':    'Derived from confirmed findings in this engagement',
      'findings.title':   'Exposure Register',
      'findings.empty':   'No material exposure identified in this assessment.',
      'findings.register':'Exposure Register',
      'killchain.title':  'Control Failure Points',
      'action.next':      'Treatment Priorities',
      'action.rankedBy':  'ordered by risk reduction per unit of effort',
      'scan.running':     'Assessment in progress — posture not yet final',
      'scan.paused':      'Assessment paused',
      'scan.complete':    'Assessment complete',
      'scan.idle':        'No assessment running',
      'scan.degraded':    'Posture incomplete — assessment engine degraded',
      'host.unreachable': 'Asset not assessed — coverage gap',
      'host.title':       'Assets',
      'host.notAssessed': 'Coverage gap',
      'agent.title':      'Assessors',
      'data.none':        'Not measured',
      'data.notCollected':'Not measured',
      'data.notConfigured':'Not configured',
      'data.notConfiguredWhy':
        'This governance metric requires data ARGUS does not collect yet (e.g. asset criticality, owner, SLA policy or framework mapping). It is shown as unconfigured rather than estimated.'
    }
  };

  /* ── Claim-strength words that may NEVER be introduced by a pack ────── */
  var FORBIDDEN_CLAIMS = [
    'pwned', 'owned', 'breach confirmed', 'root obtained',
    'fully compromised', 'compromised', 'exploited successfully'
  ];

  function currentAvatar() {
    try {
      return (window.ArgusAvatar && window.ArgusAvatar.current()) ||
             document.documentElement.getAttribute('data-avatar') || 'blacksite';
    } catch (e) { return 'blacksite'; }
  }

  function t(key, fallback) {
    if (!key) return fallback || '';
    var pack = PACKS[currentAvatar()];
    if (pack && Object.prototype.hasOwnProperty.call(pack, key)) return pack[key];
    if (Object.prototype.hasOwnProperty.call(DEFAULT, key)) return DEFAULT[key];
    return (fallback !== undefined && fallback !== null) ? fallback : key;
  }

  function pack() {
    var merged = {};
    var k;
    for (k in DEFAULT) if (Object.prototype.hasOwnProperty.call(DEFAULT, k)) merged[k] = DEFAULT[k];
    var p = PACKS[currentAvatar()];
    if (p) for (k in p) if (Object.prototype.hasOwnProperty.call(p, k)) merged[k] = p[k];
    return merged;
  }

  /* ── Key-coverage + claim-strength audit (dev-time guard) ──────────── */
  function audit() {
    var problems = [];
    var id, k, i;
    for (id in PACKS) {
      if (!Object.prototype.hasOwnProperty.call(PACKS, id)) continue;
      for (k in PACKS[id]) {
        if (!Object.prototype.hasOwnProperty.call(PACKS[id], k)) continue;
        // 1. every avatar key must exist in DEFAULT (no orphan ids)
        if (!Object.prototype.hasOwnProperty.call(DEFAULT, k)) {
          problems.push({ type: 'orphan-key', avatar: id, key: k });
        }
        // 2. no pack may introduce an overstated claim
        var val = String(PACKS[id][k]).toLowerCase();
        for (i = 0; i < FORBIDDEN_CLAIMS.length; i++) {
          if (val.indexOf(FORBIDDEN_CLAIMS[i]) !== -1 &&
              String(DEFAULT[k] || '').toLowerCase().indexOf(FORBIDDEN_CLAIMS[i]) === -1) {
            problems.push({ type: 'overstated-claim', avatar: id, key: k, term: FORBIDDEN_CLAIMS[i] });
          }
        }
      }
    }
    return { ok: problems.length === 0, problems: problems,
             defaultKeys: Object.keys(DEFAULT).length, avatars: Object.keys(PACKS).length };
  }

  window.ArgusCopy = {
    t: t,
    pack: pack,
    audit: audit,
    defaults: function () { return JSON.parse(JSON.stringify(DEFAULT)); },
    packs: function () { return JSON.parse(JSON.stringify(PACKS)); }
  };
})();
