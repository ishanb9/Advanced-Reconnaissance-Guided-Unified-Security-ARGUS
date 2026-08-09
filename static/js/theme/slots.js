/* ═══════════════════════════════════════════════════════════════════════
   ARGUS — SLOT REGISTRY & COMPLETENESS VALIDATOR
   ───────────────────────────────────────────────────────────────────────
   The zero-loss guarantee, enforced structurally rather than by memory.

   THE RULE (amended after Phase-0 discovered HUB_MODE_VISIBILITY):
     For a given (avatar × mode), the rendered slot set must equal the
     MODE-EXPECTED slot set. An avatar may reorder, resize, restyle or
     relocate a slot — it may NEVER subtract one.

     Mode gating (CLIENT/BRIEFING/PRESENT hiding operator hubs) is
     intentional product behaviour and is respected, not "fixed".

   USAGE
     window.ArgusSlots.register({ id, page, kind, label })   // declare
     window.ArgusSlots.seen(id)                              // mark rendered
     window.ArgusSlots.validate(page)                        // check one page
     window.ArgusSlots.audit()                               // full report
     window.ArgusSlots.pages()                               // page manifest

   Pages opt in by adding  data-slot="<id>"  to a panel's root element —
   the validator then verifies presence directly from the DOM, so it works
   without refactoring page internals.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ── Page manifest — mirrors app.jsx HUBS + HUB_MODE_VISIBILITY ────── */
  var PAGES = [
    { comp: 'RiskDashboard',       hub: 'risk',       label: 'Risk Score' },
    { comp: 'MissionControl',      hub: 'operations', label: 'Mission Control' },
    { comp: 'AgentConsole',        hub: 'operations', label: 'Agent Roster' },
    { comp: 'FindingsBoard',       hub: 'findings',   label: 'All Findings' },
    { comp: 'WebTesting',          hub: 'findings',   label: 'WSTG Matrix' },
    { comp: 'OsintIntel',          hub: 'findings',   label: 'OSINT Intel' },
    { comp: 'AttackGraph',         hub: 'graph',      label: 'Attack Graph' },
    { comp: 'ReasoningEnginePage', hub: 'reasoning',  label: 'Hypothesis Tree' },
    { comp: 'AIObservability',     hub: 'reasoning',  label: 'LLM Trace' },
    { comp: 'CredentialsPage',     hub: 'foothold',   label: 'Credentials' },
    { comp: 'ShellManager',        hub: 'foothold',   label: 'Active Shells' },
    { comp: 'ExploitLabPage',      hub: 'foothold',   label: 'Exploit Lab' },
    { comp: 'FuzzingLabPage',      hub: 'foothold',   label: 'Fuzzing Lab' },
    { comp: 'LateralPostPage',     hub: 'foothold',   label: 'Lateral & Post-Ex' },
    { comp: 'PayloadBuilder',      hub: 'foothold',   label: 'Payload Builder' },
    { comp: 'TargetConfig',        hub: 'workshop',   label: 'Target Config' },
    { comp: 'ToolWorkshop',        hub: 'workshop',   label: 'Tool Workshop' },
    { comp: 'ReportPage',          hub: 'reports',    label: 'Reports' },
    { comp: 'SessionHistory',      hub: 'system',     label: 'Sessions' },
    { comp: 'KnowledgePage',       hub: 'system',     label: 'Knowledge Base' },
    { comp: 'MetricsDash',         hub: 'system',     label: 'Metrics' },
    { comp: 'UserAdminPage',       hub: 'users',      label: 'User Admin' },
    { comp: 'LoginPage',           hub: null,         label: 'Login' },
    { comp: 'SubagentConsolePage', hub: null,         label: 'Subagent Console' }
  ];

  /* Mirrors HUB_MODE_VISIBILITY in app.jsx — kept in sync deliberately. */
  var HUB_MODE_VISIBILITY = {
    risk:       { OPERATOR: true, BRIEFING: true,  PRESENT: true,  CLIENT: true  },
    operations: { OPERATOR: true, BRIEFING: true,  PRESENT: true,  CLIENT: false },
    findings:   { OPERATOR: true, BRIEFING: true,  PRESENT: true,  CLIENT: true  },
    graph:      { OPERATOR: true, BRIEFING: true,  PRESENT: true,  CLIENT: true  },
    reasoning:  { OPERATOR: true, BRIEFING: false, PRESENT: false, CLIENT: false },
    foothold:   { OPERATOR: true, BRIEFING: false, PRESENT: false, CLIENT: false },
    workshop:   { OPERATOR: true, BRIEFING: false, PRESENT: false, CLIENT: false },
    reports:    { OPERATOR: true, BRIEFING: true,  PRESENT: true,  CLIENT: true  },
    system:     { OPERATOR: true, BRIEFING: false, PRESENT: false, CLIENT: false },
    users:      { OPERATOR: true, BRIEFING: false, PRESENT: false, CLIENT: false }
  };

  var registry = {};   // id -> slot descriptor
  var seenSet  = {};   // id -> true (rendered at least once this session)

  function register(slot) {
    if (!slot || !slot.id) return;
    registry[slot.id] = {
      id: slot.id,
      page: slot.page || null,
      kind: slot.kind || 'panel',
      label: slot.label || slot.id,
      critical: slot.critical !== false   // default: required
    };
  }

  function registerMany(list) {
    (list || []).forEach(register);
  }

  function seen(id) { if (id) seenSet[id] = true; }

  function isPageVisible(comp, mode) {
    var p = null;
    for (var i = 0; i < PAGES.length; i++) if (PAGES[i].comp === comp) { p = PAGES[i]; break; }
    if (!p || !p.hub) return true;                 // non-hub pages always allowed
    var v = HUB_MODE_VISIBILITY[p.hub];
    return v ? (v[mode] !== false) : true;
  }

  /* ── DOM-based presence check (works without page refactors) ───────── */
  function domSlots() {
    var out = {};
    try {
      var nodes = document.querySelectorAll('[data-slot]');
      for (var i = 0; i < nodes.length; i++) {
        var id = nodes[i].getAttribute('data-slot');
        if (id) out[id] = true;
      }
    } catch (e) {}
    return out;
  }

  /* ── Auto-discovery ───────────────────────────────────────────────────
     Panels carry data-slot="<Page>.<Component>" (added across all pages).
     Rather than maintaining a hand-written duplicate of that list, the
     registry LEARNS the slots it observes and remembers them for the
     session. That turns the validator into a real regression detector:
     once a slot has been seen under any avatar, its later ABSENCE under a
     different avatar is reported as missing.
     ──────────────────────────────────────────────────────────────────── */
  function discover() {
    var present = domSlots();
    var page = null;
    try { page = document.documentElement.getAttribute('data-page'); } catch (e) {}
    var added = 0;
    for (var id in present) {
      if (!Object.prototype.hasOwnProperty.call(present, id)) continue;
      if (!registry[id]) {
        register({ id: id, page: (id.indexOf('.') > 0 ? id.split('.')[0] : page), kind: 'panel', label: id });
        added++;
      }
      seenSet[id] = true;
    }
    return { discovered: added, total: Object.keys(registry).length };
  }

  /* Compare the CURRENT DOM against everything ever seen for this page —
     the per-avatar parity check. */
  function diffAgainstKnown(page) {
    var present = domSlots();
    var missing = [];
    for (var id in registry) {
      if (!Object.prototype.hasOwnProperty.call(registry, id)) continue;
      var s = registry[id];
      if (page && s.page && s.page !== page) continue;
      if (!present[id]) missing.push(id);
    }
    return missing;
  }

  /* ── Validate one page against the registry ────────────────────────── */
  function validate(page) {
    var present = domSlots();
    var missing = [], found = [];
    for (var id in registry) {
      if (!Object.prototype.hasOwnProperty.call(registry, id)) continue;
      var s = registry[id];
      if (page && s.page && s.page !== page) continue;
      if (present[id] || seenSet[id]) found.push(id);
      else if (s.critical) missing.push(id);
    }
    return {
      page: page || '(all)',
      avatar: (window.ArgusAvatar && window.ArgusAvatar.current()) || null,
      ok: missing.length === 0,
      found: found,
      missing: missing
    };
  }

  /* ── Full audit: pages × modes visibility matrix + slot coverage ───── */
  function audit() {
    var modes = ['OPERATOR', 'BRIEFING', 'PRESENT', 'CLIENT'];
    var matrix = PAGES.map(function (p) {
      var row = { page: p.comp, hub: p.hub, label: p.label };
      modes.forEach(function (m) { row[m] = isPageVisible(p.comp, m); });
      return row;
    });
    var v = validate(null);
    return {
      avatars: (window.ArgusAvatar ? window.ArgusAvatar.list().map(function (a) { return a.id; }) : []),
      modes: modes,
      pages: PAGES.length,
      registeredSlots: Object.keys(registry).length,
      renderedSlots: Object.keys(seenSet).length,
      slotCoverage: v,
      visibilityMatrix: matrix,
      copyAudit: (window.ArgusCopy ? window.ArgusCopy.audit() : null)
    };
  }

  /* ── Console-friendly summary for manual verification ──────────────── */
  function report() {
    var a = audit();
    try {
      console.group('%cARGUS slot/avatar audit', 'color:#35C8DE;font-weight:700');
      console.log('avatar        :', (window.ArgusAvatar && window.ArgusAvatar.current()));
      console.log('pages         :', a.pages);
      console.log('slots declared:', a.registeredSlots, ' rendered:', a.renderedSlots);
      if (a.slotCoverage.missing.length) {
        console.warn('MISSING SLOTS :', a.slotCoverage.missing);
      } else {
        console.log('%cslot coverage : OK', 'color:#4ADE80');
      }
      if (a.copyAudit && !a.copyAudit.ok) {
        console.warn('COPY PROBLEMS :', a.copyAudit.problems);
      } else if (a.copyAudit) {
        console.log('%ccopy packs    : OK (' + a.copyAudit.defaultKeys + ' keys × ' +
                    a.copyAudit.avatars + ' avatars)', 'color:#4ADE80');
      }
      console.table(a.visibilityMatrix);
      console.groupEnd();
    } catch (e) {}
    return a;
  }

  /* ── Per-avatar parity sweep ──────────────────────────────────────────
     Cycles every avatar on the CURRENT page and asserts the rendered slot
     set is identical. This is the zero-loss guarantee, executable on demand:
       ArgusSlots.parityCheck()  ->  { ok: true, perAvatar: {...} }
     ──────────────────────────────────────────────────────────────────── */
  function parityCheck() {
    if (!window.ArgusAvatar) return { ok: false, reason: 'avatar engine unavailable' };
    var page = document.documentElement.getAttribute('data-page');
    var original = window.ArgusAvatar.current();
    var list = window.ArgusAvatar.list();
    var per = {}, baseline = null, ok = true, diffs = [];

    for (var i = 0; i < list.length; i++) {
      window.ArgusAvatar.apply(list[i].id);
      var ids = Object.keys(domSlots()).sort();
      per[list[i].id] = ids.length;
      if (baseline === null) baseline = ids;
      else if (ids.join('|') !== baseline.join('|')) {
        ok = false;
        var missing = baseline.filter(function (x) { return ids.indexOf(x) === -1; });
        var extra   = ids.filter(function (x) { return baseline.indexOf(x) === -1; });
        diffs.push({ avatar: list[i].id, missing: missing, extra: extra });
      }
    }
    window.ArgusAvatar.apply(original);
    return { ok: ok, page: page, slotsPerAvatar: per, differences: diffs };
  }

  window.ArgusSlots = {
    register: register,
    registerMany: registerMany,
    seen: seen,
    discover: discover,
    diffAgainstKnown: diffAgainstKnown,
    parityCheck: parityCheck,
    validate: validate,
    audit: audit,
    report: report,
    pages: function () { return PAGES.slice(); },
    visibility: function () { return JSON.parse(JSON.stringify(HUB_MODE_VISIBILITY)); },
    isPageVisible: isPageVisible
  };
})();
