"""
report/report_template.py — ARGUS professional, print-ready report template.

A polished, client-deliverable Jinja2 template (light theme, A4 print CSS, cover
page, document control, executive summary with metric cards, methodology, host
& service overview, findings summary, engagement timeline, kill-chain attack
narrative, per-finding detail cards, coverage matrix with negative results,
proof of compromise, remediation roadmap, MITRE ATT&CK map, appendices).

It is driven by the EXACT same context dict that report.generator._build_context
produces, so it is a drop-in styling/structure upgrade — no pipeline changes.
report.generator imports REPORT_TEMPLATE from here and prefers it, keeping its
own inline dark-dashboard template as a guaranteed fallback.

Every field access is guarded (| default / {% if %}) so a sparse engagement
(recon-only, no findings) still renders a clean, complete document.
"""

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ARGUS — Penetration Test Report — {{ target_display | default('target') }}</title>
<style>
  @page {
    size: A4;
    margin: 18mm 15mm 16mm 15mm;
    @bottom-center { content: "CONFIDENTIAL — ARGUS Penetration Test Report"; font-family: 'Inter', sans-serif; font-size: 7.5pt; color: #8a93a3; }
    @bottom-right  { content: "Page " counter(page) " of " counter(pages); font-family: 'Inter', sans-serif; font-size: 7.5pt; color: #8a93a3; }
  }
  @page cover { margin: 0; @bottom-center { content: ""; } @bottom-right { content: ""; } }

  :root {
    --brand:#0b66c3; --brand-dark:#0a2d5e; --ink:#1a2230; --muted:#5b6472;
    --line:#d9dee7; --bg-soft:#f4f6fa; --crit:#b00020; --high:#d9534f;
    --med:#e8951b; --low:#2f8fd6; --info:#6c757d; --ok:#2e9e5b; --accent:#0bb6d4;
  }
  * { box-sizing: border-box; }
  html { -weasy-hyphens: none; }
  body { font-family: 'Inter','Helvetica Neue',Arial,sans-serif; color: var(--ink); font-size: 10pt; line-height: 1.5; margin: 0; background:#fff; }
  h1,h2,h3,h4 { color: var(--brand-dark); line-height: 1.2; font-weight: 700; }
  h2 { font-size: 16.5pt; margin: 0 0 10px 0; padding-bottom: 6px; border-bottom: 2.5px solid var(--brand); break-after: avoid; }
  h3 { font-size: 12.5pt; margin: 18px 0 6px 0; color: var(--brand); break-after: avoid; }
  h4 { font-size: 10.5pt; margin: 12px 0 4px 0; color: var(--ink); break-after: avoid; }
  p { margin: 0 0 8px 0; }
  a { color: var(--brand); text-decoration: none; }
  code, pre, .mono { font-family: 'JetBrains Mono','DejaVu Sans Mono',monospace; }
  code { background: var(--bg-soft); padding: 0.5px 4px; border-radius: 3px; font-size: 8.8pt; color: #233; }
  pre { background: #0f1626; color: #e7ecf5; border-radius: 6px; padding: 11px 13px; font-size: 8.2pt; line-height: 1.45; overflow-wrap: break-word; white-space: pre-wrap; border: 1px solid #1d2840; margin: 6px 0 12px 0; }
  pre .c { color: #7fd1b9; } pre .o { color: #8fb7ff; }
  .section { break-before: page; }
  .nobreak { break-inside: avoid; }

  /* Cover */
  .cover { page: cover; break-after: page; position: relative; height: 297mm; color:#fff; background: linear-gradient(150deg,#06122b 0%, #0a2d5e 55%, #0b66c3 100%); padding: 32mm 22mm; overflow: hidden; }
  .cover .grid-deco { position:absolute; right:-40mm; top:-40mm; width:170mm; height:170mm; border-radius:50%; background: radial-gradient(circle at center, rgba(11,182,212,.18), rgba(255,255,255,0) 70%); }
  .cover .kicker { font-size:10pt; letter-spacing:4px; text-transform:uppercase; color:#7fd6ff; font-weight:600; }
  .cover h1 { color:#fff; font-size:38pt; font-weight:800; margin:14px 0 6px; line-height:1.05; word-break:break-all; }
  .cover .sub { font-size:15pt; color:#cfe0fb; font-weight:500; margin-bottom:38mm; }
  .cover .meta { border-top:1px solid rgba(255,255,255,.25); padding-top:14px; width:100%; font-size:10pt; color:#eaf1ff; }
  .cover .meta table { width:100%; border-collapse:collapse; }
  .cover .meta td { padding:5px 0; vertical-align:top; }
  .cover .meta td.lbl { color:#8fb7e8; width:42mm; text-transform:uppercase; font-size:8pt; letter-spacing:1.5px; padding-top:7px; }
  .cover .brandmark { font-size:22pt; font-weight:800; letter-spacing:1px; }
  .cover .brandmark .lite { color:#0bb6d4; }
  .cover .result-tag { display:inline-block; margin-top:6px; padding:6px 14px; border-radius:4px; font-weight:800; font-size:11pt; letter-spacing:.5px; }
  .cover .conf-tag { position:absolute; bottom:24mm; left:22mm; font-size:8pt; letter-spacing:3px; text-transform:uppercase; color:#7fd6ff; border:1px solid rgba(255,255,255,.3); padding:5px 12px; border-radius:3px; }

  table.dt { width:100%; border-collapse:collapse; margin:6px 0 14px; font-size:9pt; }
  table.dt th { background:var(--brand-dark); color:#fff; text-align:left; padding:7px 9px; font-weight:600; font-size:8.5pt; }
  table.dt td { border:1px solid var(--line); padding:6px 9px; vertical-align:top; }
  table.dt tr:nth-child(even) td { background:var(--bg-soft); }
  table.dt.fixed { table-layout:fixed; }

  .badge { display:inline-block; padding:1.5px 8px; border-radius:10px; color:#fff; font-size:7.8pt; font-weight:700; letter-spacing:.4px; text-transform:uppercase; white-space:nowrap; }
  .b-crit{background:var(--crit);} .b-high{background:var(--high);} .b-med{background:var(--med);} .b-low{background:var(--low);} .b-info{background:var(--info);} .b-ok{background:var(--ok);}
  .pill { display:inline-block; padding:1px 7px; border:1px solid var(--line); border-radius:10px; font-size:8pt; color:var(--muted); background:#fff; }

  .callout { border-left:4px solid var(--brand); background:var(--bg-soft); padding:9px 13px; margin:8px 0 12px; border-radius:0 5px 5px 0; }
  .callout.warn { border-left-color:var(--high); background:#fdf2f2; }
  .callout.win  { border-left-color:var(--ok); background:#eefaf2; }
  .callout .t { font-weight:700; color:var(--brand-dark); font-size:9pt; text-transform:uppercase; letter-spacing:.5px; }
  .callout.warn .t { color:#9a2b2b; } .callout.win .t { color:#1d7a44; }

  .kc { display:flex; align-items:center; gap:10px; margin:18px 0 4px; break-after:avoid; }
  .kc .n { background:var(--brand); color:#fff; width:24px; height:24px; border-radius:50%; text-align:center; font-weight:800; font-size:10pt; line-height:24px; flex:0 0 24px; }
  .kc h3 { margin:0; } .kc .atk { margin-left:auto; }

  .cards { display:flex; gap:9px; margin:10px 0 14px; }
  .card { flex:1; border:1px solid var(--line); border-radius:7px; padding:10px 11px; background:#fff; text-align:center; }
  .card .big { font-size:19pt; font-weight:800; line-height:1; }
  .card .lbl { font-size:7.2pt; text-transform:uppercase; letter-spacing:1px; color:var(--muted); margin-top:5px; }

  .toc li { margin:4px 0; } .toc .num { color:var(--brand); font-weight:700; display:inline-block; width:24px; }
  ul.tight { margin:4px 0 10px; padding-left:18px; } ul.tight li { margin:2.5px 0; }
  .small { font-size:8.4pt; color:var(--muted); }
  hr.soft { border:none; border-top:1px solid var(--line); margin:14px 0; }
  .flag { font-family:'JetBrains Mono','DejaVu Sans Mono',monospace; background:#0f1626; color:#7CFFB0; padding:3px 8px; border-radius:4px; font-size:9pt; word-break:break-all; }
  .finding-card { border:1px solid var(--line); border-radius:7px; padding:12px 14px; margin:10px 0; break-inside:avoid; }
  .exec-narr { white-space:pre-line; }
</style>
</head>
<body>

{% macro sevclass(s) -%}
{%- set sl = (s | string | lower) -%}
{%- if 'crit' in sl %}b-crit{% elif 'high' in sl %}b-high{% elif 'med' in sl %}b-med{% elif 'low' in sl %}b-low{% else %}b-info{% endif -%}
{%- endmacro %}

<!-- ============ COVER ============ -->
<section class="cover">
  <div class="grid-deco"></div>
  <div class="kicker">Offensive Security Assessment</div>
  <h1>{{ target_display | default('Target') }}</h1>
  <div class="sub">Network &amp; Application Penetration Test Report</div>
  <div>
    {% set oc = outcome | default({}) %}
    <span class="result-tag" style="background:{% if oc.root %}#2e9e5b{% elif oc.compromised %}#2e9e5b{% else %}rgba(255,255,255,.12){% endif %}; color:{% if oc.compromised %}#fff{% else %}#cfe0fb{% endif %};">
      {{ oc.label | default('ASSESSMENT COMPLETE') }}
    </span>
  </div>

  <div class="meta">
    <table>
      <tr><td class="lbl">Engagement</td><td>Autonomous black-box penetration test — full-compromise objective</td></tr>
      <tr><td class="lbl">Target</td><td><span class="mono">{{ target_display | default('—') }}</span></td></tr>
      <tr><td class="lbl">Engagement type</td><td>{{ engagement_type | default('pentest') | upper }}</td></tr>
      <tr><td class="lbl">Duration</td><td>{{ duration | default('N/A') }}</td></tr>
      <tr><td class="lbl">Generated</td><td>{{ generated_at | default('') }}</td></tr>
      <tr><td class="lbl">Classification</td><td>Confidential</td></tr>
      <tr><td class="lbl">Result</td><td><strong>{{ (outcome | default({})).label | default('Assessment complete') }}</strong></td></tr>
    </table>
  </div>

  <div style="position:absolute; top:32mm; right:22mm; text-align:right;">
    <div class="brandmark">ARG<span class="lite">US</span></div>
    <div style="font-size:7.5pt; letter-spacing:2px; color:#8fb7e8; text-transform:uppercase;">Advanced Reconnaissance<br/>&amp; Guided Unified Security</div>
  </div>
  <div class="conf-tag">Confidential · Authorized Test</div>
</section>

<!-- ============ DOC CONTROL + TOC ============ -->
<section>
  <h2>Document Control</h2>
  <table class="dt">
    <tr><th style="width:32%">Field</th><th>Detail</th></tr>
    <tr><td>Report title</td><td>ARGUS — Penetration Test Report — {{ target_display | default('target') }}</td></tr>
    <tr><td>Target</td><td><span class="mono">{{ target_display | default('—') }}</span></td></tr>
    <tr><td>Engagement type</td><td>{{ engagement_type | default('pentest') }}</td></tr>
    <tr><td>Primary objective</td><td>{{ (mission_brief | default({})).objective | default('Establish a foothold, escalate privilege, and recover proof artifacts.') }}</td></tr>
    <tr><td>Duration</td><td>{{ duration | default('N/A') }}</td></tr>
    <tr><td>Date issued</td><td>{{ generated_at | default('') }}</td></tr>
    <tr><td>Result</td><td><strong>{{ (outcome | default({})).label | default('Assessment complete') }}</strong></td></tr>
    <tr><td>Distribution</td><td>Confidential — authorized stakeholders only</td></tr>
  </table>

  <div class="callout">
    <div class="t">Confidentiality &amp; authorization notice</div>
    All activity described in this report was performed by the ARGUS autonomous penetration-testing
    platform under explicit authorization, confined to the designated target. The report contains
    live exploitation detail and any captured proof artifacts solely for the report recipient.
  </div>

  <h2 style="margin-top:18px">Contents</h2>
  <ol class="toc" style="list-style:none; padding-left:0; font-size:10pt;">
    <li><span class="num">1</span> Executive Summary</li>
    <li><span class="num">2</span> Scope &amp; Objectives</li>
    <li><span class="num">3</span> Testing Methodology &amp; Approach</li>
    <li><span class="num">4</span> Host &amp; Service Overview</li>
    <li><span class="num">5</span> Findings Summary</li>
    <li><span class="num">6</span> Engagement Timeline</li>
    <li><span class="num">7</span> Attack Narrative — Path to Compromise</li>
    <li><span class="num">8</span> Detailed Findings</li>
    <li><span class="num">9</span> Tests Conducted (Coverage Matrix)</li>
    <li><span class="num">10</span> Other Discovered Issues</li>
    <li><span class="num">11</span> Proof of Compromise</li>
    <li><span class="num">12</span> Remediation Roadmap</li>
    <li><span class="num">13</span> MITRE ATT&amp;CK Mapping</li>
    <li><span class="num">14</span> Appendices</li>
  </ol>
</section>

<!-- ============ 1. EXEC SUMMARY ============ -->
<section class="section">
  <h2>1 · Executive Summary</h2>
  {% set s = sev | default({}) %}
  <div class="cards">
    <div class="card"><div class="big" style="color:var(--crit)">{{ s.critical | default(0) }}</div><div class="lbl">Critical</div></div>
    <div class="card"><div class="big" style="color:var(--high)">{{ s.high | default(0) }}</div><div class="lbl">High</div></div>
    <div class="card"><div class="big" style="color:var(--med)">{{ s.medium | default(0) }}</div><div class="lbl">Medium</div></div>
    <div class="card"><div class="big" style="color:var(--low)">{{ s.low | default(0) }}</div><div class="lbl">Low</div></div>
    <div class="card"><div class="big" style="color:var(--info)">{{ s.info | default(0) }}</div><div class="lbl">Info</div></div>
    <div class="card"><div class="big" style="color:{% if (outcome|default({})).compromised %}var(--ok){% else %}var(--muted){% endif %}">{% if (outcome|default({})).root %}ROOT{% elif (outcome|default({})).compromised %}SHELL{% else %}—{% endif %}</div><div class="lbl">Access</div></div>
  </div>

  <div class="exec-narr">{{ executive_summary | default('This assessment evaluated the externally exposed attack surface of the target. The findings, attack narrative, and remediation guidance below document what was attempted, what was discovered, and what was exploited.') }}</div>

  {% if flags %}
  <div class="callout win">
    <div class="t">Proof of compromise</div>
    {{ flags | length }} proof artifact(s) were recovered during the engagement (see §11).
  </div>
  {% endif %}
</section>

<!-- ============ 2. SCOPE ============ -->
<section class="section">
  <h2>2 · Scope &amp; Objectives</h2>
  <h3>2.1 In scope</h3>
  <table class="dt">
    <tr><th style="width:30%">Item</th><th>Value</th></tr>
    <tr><td>Authorized target</td><td><span class="mono">{{ target_display | default('—') }}</span></td></tr>
    <tr><td>Engagement type</td><td>{{ engagement_type | default('pentest') }}</td></tr>
    <tr><td>Test type</td><td>Black-box — autonomous, no credentials or source provided in advance</td></tr>
    <tr><td>Permitted actions</td><td>Enumeration, exploitation, privilege escalation, proof-artifact retrieval</td></tr>
  </table>

  <h3>2.2 Objectives &amp; outcomes</h3>
  {% if objectives %}
  <table class="dt fixed">
    <tr><th style="width:8%">#</th><th style="width:52%">Objective</th><th style="width:14%">Status</th><th>Answer / evidence</th></tr>
    {% for o in objectives %}
    <tr>
      <td><strong>{{ o.index }}</strong></td>
      <td>{{ o.question | default('—') }}</td>
      <td>{% if o.answered %}<span class="badge b-ok">Met</span>{% else %}<span class="badge b-info">Open</span>{% endif %}</td>
      <td>{{ (o.answer | default(''))[:200] or '—' }}</td>
    </tr>
    {% endfor %}
  </table>
  <p class="small">{{ objectives_done | default(0) }} of {{ objectives_total | default(0) }} objective(s) answered.</p>
  {% else %}
  <ul class="tight">
    <li>Identify the external attack surface of the target.</li>
    <li>Discover and exploit vulnerabilities to gain an initial foothold.</li>
    <li>Escalate privileges to the highest level available.</li>
    <li>Recover proof artifacts and document the full kill chain.</li>
  </ul>
  {% endif %}
</section>

<!-- ============ 3. METHODOLOGY ============ -->
<section class="section">
  <h2>3 · Testing Methodology &amp; Approach</h2>
  <p>Testing followed a structured, hypothesis-driven methodology aligned with the PTES phases and the
  Lockheed Martin Cyber Kill Chain. Each action was framed as a hypothesis, tested deliberately, and the
  result fed the next decision — so every exploited weakness was understood before being weaponized, and
  avenues that did not work are documented as negative results (see §9).</p>

  <h3>3.1 Phases executed</h3>
  <table class="dt fixed">
    <tr><th style="width:26%">Phase</th><th style="width:14%">Status</th><th>Focus</th></tr>
    {% set done = phases_completed | default([]) %}
    {% for ph in all_phases | default([]) %}
    <tr>
      <td><code>{{ ph }}</code></td>
      <td>{% if ph in done %}<span class="badge b-ok">Completed</span>{% else %}<span class="pill">not reached</span>{% endif %}</td>
      <td>{% if ph in ['recon','scan'] %}Intelligence gathering — port/service discovery, fingerprinting.
          {% elif ph == 'vuln_id' %}Vulnerability analysis — functional abuse + injection probing.
          {% elif ph == 'osint' %}Open-source intelligence — version→CVE→PoC correlation.
          {% elif ph == 'exploit' %}Exploitation — driving a verified weakness to code execution.
          {% elif ph in ['post_exploit','privesc'] %}Post-exploitation &amp; privilege escalation.
          {% elif ph == 'lateral' %}Lateral movement across the environment.
          {% else %}{{ ph | replace('_',' ') | capitalize }}.{% endif %}</td>
    </tr>
    {% endfor %}
  </table>

  {% if tools_used %}
  <h3>3.2 Tooling used</h3>
  <p>{% for t in tools_used %}<code>{{ t }}</code>{% if not loop.last %} · {% endif %}{% endfor %}</p>
  {% endif %}

  <h3>3.3 Risk rating scale</h3>
  <table class="dt">
    <tr><th>Severity</th><th>Meaning</th></tr>
    <tr><td><span class="badge b-crit">Critical</span></td><td>Direct, reliable path to full compromise or root; exploit trivial.</td></tr>
    <tr><td><span class="badge b-high">High</span></td><td>Serious impact (RCE, major data exposure), possibly with a precondition.</td></tr>
    <tr><td><span class="badge b-med">Medium</span></td><td>Meaningful weakness that aids an attacker or amplifies other issues.</td></tr>
    <tr><td><span class="badge b-low">Low</span></td><td>Limited impact; hygiene or defense-in-depth gap.</td></tr>
  </table>
</section>

<!-- ============ 4. HOST & SERVICE OVERVIEW ============ -->
<section class="section">
  <h2>4 · Host &amp; Service Overview</h2>
  {% set it = intel | default({}) %}
  <table class="dt">
    <tr><th style="width:26%">Attribute</th><th>Detail</th></tr>
    <tr><td>Target</td><td><span class="mono">{{ target_display | default('—') }}</span></td></tr>
    <tr><td>Operating system</td><td>{{ it.os_guess | default('unknown') }}</td></tr>
    <tr><td>Open ports</td><td>{% if it.open_ports %}{{ it.open_ports | join(', ') }}{% else %}—{% endif %}</td></tr>
    <tr><td>Interactive access</td><td>{% if it.shell_access %}<span class="badge b-ok">Foothold achieved</span>{% else %}Not achieved{% endif %}</td></tr>
  </table>

  {% if it.services %}
  <h3>4.1 Service detail</h3>
  <table class="dt fixed">
    <tr><th style="width:18%">Port</th><th style="width:32%">Service</th><th>Version</th></tr>
    {% for port, svc in it.services.items() %}
    <tr>
      <td><code>{{ port }}{% if svc.protocol %}/{{ svc.protocol }}{% endif %}</code></td>
      <td>{{ svc.service | default('—') if svc is mapping else svc }}</td>
      <td>{{ svc.version | default('') if svc is mapping else '' }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</section>

<!-- ============ 5. FINDINGS SUMMARY ============ -->
<section class="section">
  <h2>5 · Findings Summary</h2>
  {% if findings %}
  <table class="dt fixed">
    <tr><th style="width:9%">ID</th><th style="width:52%">Finding</th><th style="width:14%">Severity</th><th>Host</th></tr>
    {% for f in findings %}
    <tr>
      <td><strong>F-{{ '%02d' % loop.index }}</strong></td>
      <td>{{ f.title | default('Untitled finding') }}{% if f.cve %} <span class="pill">{{ f.cve }}</span>{% endif %}</td>
      <td><span class="badge {{ sevclass(f.severity) }}">{{ (f.severity | default('info')) | upper }}</span></td>
      <td class="mono" style="font-size:8.5pt;">{{ f.host | default(target_display) }}{% if f.port %}:{{ f.port }}{% endif %}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No confirmed vulnerability findings were recorded. Issues observed during testing — including those
  that were tested and ruled out — are documented in §9 (coverage matrix) and §10 (other discovered issues).</p>
  {% endif %}
</section>

<!-- ============ 6. ENGAGEMENT TIMELINE ============ -->
{% if engagement_timeline %}
<section class="section">
  <h2>6 · Engagement Timeline</h2>
  <p>Chronological milestones reconstructed from phase transitions and registered attack-path steps, so a
  reader can follow the engagement from first contact to its final outcome.</p>
  <table class="dt fixed">
    <tr><th style="width:22%">When</th><th style="width:24%">Milestone</th><th>Detail</th></tr>
    {% for ev in engagement_timeline %}
    <tr>
      <td class="mono" style="font-size:8.2pt;">{{ (ev.ts | default(''))[:19] }}</td>
      <td><strong>{{ ev.label | default('—') }}</strong></td>
      <td>{{ ev.detail | default('') }}</td>
    </tr>
    {% endfor %}
  </table>
</section>
{% endif %}

<!-- ============ 7. ATTACK NARRATIVE ============ -->
{% if attack_path %}
<section class="section">
  <h2>7 · Attack Narrative — Path to Compromise</h2>
  <p>The compromise is presented step-by-step in the order it was achieved, so each action shows not only
  <em>what</em> was done but how it advanced the attack.</p>
  {% for step in attack_path %}
  <div class="kc nobreak">
    <span class="n">{{ step.__step | default(loop.index) }}</span>
    <h3>{{ (step.phase | default('step')) | replace('_',' ') | title }}</h3>
    <span class="atk pill">{{ step.source | default('argus') }}</span>
  </div>
  <p style="margin-left:34px;">{{ step.result | default(step.description) | default('—') }}{% if step.ts %} <span class="small">({{ (step.ts | string)[:19] }})</span>{% endif %}</p>
  {% endfor %}
</section>
{% endif %}

<!-- ============ 8. DETAILED FINDINGS ============ -->
{% if findings %}
<section class="section">
  <h2>8 · Detailed Findings</h2>
  {% for f in findings %}
  <div class="finding-card">
    <h3 style="margin-top:0;">F-{{ '%02d' % loop.index }} · {{ f.title | default('Finding') }}
      <span class="badge {{ sevclass(f.severity) }}" style="float:right;">{{ (f.severity | default('info')) | upper }}</span></h3>
    <table class="dt" style="margin-top:4px;">
      <tr><th style="width:20%">Location</th><td class="mono">{{ f.host | default(target_display) }}{% if f.port %}:{{ f.port }}{% endif %}{% if f.service %} ({{ f.service }}){% endif %}</td></tr>
      {% if f.cve %}<tr><th>Reference</th><td>{{ f.cve }}</td></tr>{% endif %}
      {% if f.mitre_technique %}<tr><th>MITRE</th><td>{{ f.mitre_technique }}</td></tr>{% endif %}
    </table>
    {% if f.description %}<p><strong>Description.</strong> {{ f.description }}</p>{% endif %}
    {% if f.evidence %}<p><strong>Evidence.</strong></p><pre>{{ (f.evidence | string)[:900] }}</pre>{% endif %}
    {% if f.exploit_suggestion %}<p><strong>Exploitation / impact.</strong> {{ f.exploit_suggestion }}</p>{% endif %}
    {% if f.remediation %}<p><strong>Remediation.</strong> {{ f.remediation }}</p>{% endif %}
  </div>
  {% endfor %}
</section>
{% endif %}

<!-- ============ 9. TESTS CONDUCTED (COVERAGE MATRIX) ============ -->
{% if coverage_tests %}
<section class="section">
  <h2>9 · Tests Conducted (Coverage Matrix)</h2>
  <p>Every probe ARGUS executed and its outcome. Negative results are reported deliberately — they show the
  breadth of testing and document where the target's controls held.
  {% if coverage_counts %}<br><strong>Totals:</strong>
  {% for k, v in coverage_counts.items() %}<span style="margin-right:12px;">{{ k }}: {{ v }}</span>{% endfor %}{% endif %}</p>
  <table class="dt fixed">
    <tr><th style="width:14%">Tool</th><th style="width:12%">Outcome</th><th style="width:44%">Command / target</th><th>Note</th></tr>
    {% for t in coverage_tests %}
    <tr>
      <td class="mono" style="font-size:8.2pt;">{{ t.tool | default('—') }}</td>
      <td>{% if t.outcome == 'success' %}<span class="badge b-ok">Hit</span>
          {% elif t.outcome == 'blocked' %}<span class="badge b-med">Blocked</span>
          {% elif t.outcome == 'error' %}<span class="badge b-high">Error</span>
          {% else %}<span class="pill">Negative</span>{% endif %}</td>
      <td class="mono" style="font-size:7.8pt;">{{ (t.command | default(''))[:90] }}</td>
      <td style="font-size:8.5pt;">{{ (t.note | default(''))[:90] }}</td>
    </tr>
    {% endfor %}
  </table>
</section>
{% endif %}

<!-- ============ 10. OTHER DISCOVERED ISSUES ============ -->
{% if discovered_issues %}
<section class="section">
  <h2>10 · Other Discovered Issues</h2>
  <p>Additional weaknesses observed while testing. These are reported for completeness even where they were
  not exploited, so remediation can address the full attack surface.</p>
  <table class="dt fixed">
    <tr><th style="width:14%">Severity</th><th style="width:52%">Issue</th><th style="width:18%">Host</th><th>Observed via</th></tr>
    {% for d in discovered_issues %}
    <tr>
      <td><span class="badge {{ sevclass(d.severity) }}">{{ (d.severity | default('info')) | upper }}</span></td>
      <td>{{ d.title | default('—') }}</td>
      <td class="mono" style="font-size:8.2pt;">{{ d.host | default('—') }}</td>
      <td class="mono" style="font-size:8.2pt; color:var(--muted);">{{ d.tool | default('—') }}</td>
    </tr>
    {% endfor %}
  </table>
</section>
{% endif %}

<!-- ============ 11. PROOF OF COMPROMISE ============ -->
<section class="section">
  <h2>11 · Proof of Compromise</h2>
  {% if flags %}
  <div class="callout win">
    <div class="t">Proof artifacts recovered</div>
    <table style="width:100%; border-collapse:collapse; margin-top:6px;">
      {% for fl in flags %}
      <tr><td style="padding:4px 0; width:30%"><strong>{{ (fl.flag_type | default('flag')) | capitalize }} flag</strong>
        {% if fl.location %}<br><span class="small mono">{{ fl.location }}</span>{% endif %}</td>
        <td><span class="flag">{{ fl.value | default('—') }}</span></td></tr>
      {% endfor %}
    </table>
  </div>
  {% else %}
  <p>No proof artifacts (flags) were recovered during this engagement.</p>
  {% endif %}

  {% if win_conditions and win_conditions.conditions %}
  <h3>11.1 Win conditions</h3>
  <table class="dt fixed">
    <tr><th style="width:50%">Condition</th><th style="width:14%">Status</th><th>Evidence</th></tr>
    {% for c in win_conditions.conditions %}
    <tr>
      <td>{{ (c.name | default('—')) | replace('_',' ') }}</td>
      <td>{% if c.achieved %}<span class="badge b-ok">Achieved</span>{% else %}<span class="pill">Open</span>{% endif %}</td>
      <td class="mono" style="font-size:8pt;">{{ (c.evidence | default(''))[:80] }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if creds_summary %}
  <h3>11.2 Credentials &amp; secrets recovered</h3>
  <table class="dt fixed">
    <tr><th style="width:26%">User</th><th style="width:18%">Secret</th><th style="width:18%">Source</th><th>Note</th></tr>
    {% for c in creds_summary %}
    <tr>
      <td class="mono">{{ c.user | default('—') }}{% if c.domain %}@{{ c.domain }}{% endif %}</td>
      <td class="mono">{{ c.password | default('—') }}</td>
      <td>{{ c.source | default('—') }}</td>
      <td style="font-size:8.5pt;">{{ (c.note | default(''))[:90] }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</section>

<!-- ============ 12. REMEDIATION ROADMAP ============ -->
{% if findings %}
<section class="section">
  <h2>12 · Remediation Roadmap</h2>
  <p>Recommendations are grouped by urgency. Address Priority 1 items first — they represent the most direct
  path to compromise.</p>

  {% set crit_high = findings | selectattr('severity', 'defined') | list %}
  <h3>Priority 1 — Immediate (Critical / High)</h3>
  <table class="dt fixed">
    <tr><th style="width:9%">ID</th><th style="width:46%">Finding</th><th>Remediation</th></tr>
    {% set p1 = [] %}
    {% for f in findings %}{% if (f.severity | string | lower) in ['critical','high'] %}
    <tr><td><strong>F-{{ '%02d' % loop.index }}</strong></td><td>{{ f.title | default('—') }}</td>
      <td>{{ f.remediation | default(f.exploit_suggestion) | default('Apply least privilege, patch the affected component, and remove the exposed surface.') }}</td></tr>
    {% endif %}{% endfor %}
  </table>

  <h3>Priority 2 — Short term (Medium)</h3>
  <table class="dt fixed">
    <tr><th style="width:9%">ID</th><th style="width:46%">Finding</th><th>Remediation</th></tr>
    {% for f in findings %}{% if (f.severity | string | lower) in ['medium','med'] %}
    <tr><td><strong>F-{{ '%02d' % loop.index }}</strong></td><td>{{ f.title | default('—') }}</td>
      <td>{{ f.remediation | default('Harden configuration and reduce the affected surface.') }}</td></tr>
    {% endif %}{% endfor %}
  </table>

  <h3>Priority 3 — Ongoing (Low / Info / hygiene)</h3>
  <ul class="tight">
    {% for f in findings %}{% if (f.severity | string | lower) in ['low','info','informational'] %}
    <li>{{ f.title | default('—') }} — {{ f.remediation | default('hygiene / defense-in-depth improvement.') }}</li>
    {% endif %}{% endfor %}
    <li>Suppress verbose version banners; centralize and alert on authentication and exploitation events.</li>
  </ul>
</section>
{% endif %}

<!-- ============ 13. MITRE ATT&CK ============ -->
{% if mitre_mappings %}
<section class="section">
  <h2>13 · MITRE ATT&amp;CK Mapping</h2>
  <table class="dt fixed">
    <tr><th style="width:22%">Tactic / Technique</th><th>Observed behaviour</th></tr>
    {% for m in mitre_mappings %}
    {% if m is mapping %}
    <tr><td><strong>{{ m.technique | default(m.id) | default('—') }}</strong>{% if m.tactic %}<br><span class="small">{{ m.tactic }}</span>{% endif %}</td>
      <td>{{ m.observed | default(m.description) | default(m.tool) | default('—') }}</td></tr>
    {% else %}
    <tr><td colspan="2">{{ m }}</td></tr>
    {% endif %}
    {% endfor %}
  </table>
</section>
{% endif %}

<!-- ============ 14. APPENDICES ============ -->
<section class="section">
  <h2>14 · Appendices</h2>

  {% if exploit_modules %}
  <h3>Appendix A — Exploit modules &amp; public PoCs considered</h3>
  <table class="dt fixed">
    <tr><th style="width:24%">Reference</th><th style="width:14%">Used</th><th>Source</th></tr>
    {% for e in exploit_modules %}
    <tr>
      <td>{% if e.cves %}{{ e.cves | join(', ') }}{% else %}{{ e.type | default('module') }}{% endif %}</td>
      <td>{% if e.used %}<span class="badge b-ok">Yes</span>{% else %}<span class="pill">No</span>{% endif %}</td>
      <td class="mono" style="font-size:8pt;">{{ (e.url | default(''))[:90] }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if loot_entries %}
  <h3>Appendix B — Harvested loot &amp; data of interest</h3>
  <table class="dt fixed">
    <tr><th style="width:14%">Severity</th><th style="width:26%">Category</th><th>Source</th></tr>
    {% for e in loot_entries %}
    <tr><td><strong>{{ (e.severity | default('info')) | upper }}</strong></td>
      <td>{{ e.doi_label | default(e.doi_id) | default('—') }}</td>
      <td class="mono" style="font-size:8pt;">{{ e.source | default('—') }}</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if web_intel_hints %}
  <h3>Appendix C — Web-intel sources</h3>
  <ul class="tight">
    {% for h in web_intel_hints %}
    <li>{{ h.hint | default(h.note) | default(h.source) | default('—') }}{% if h.confidence %} <span class="pill">conf {{ h.confidence }}</span>{% endif %}</li>
    {% endfor %}
  </ul>
  {% endif %}

  {% if primer_rows %}
  <h3>Appendix D — Platform capability map</h3>
  <table class="dt fixed">
    <tr><th style="width:40%">Chain</th><th style="width:16%">Status</th><th>Coverage</th></tr>
    {% for r in primer_rows %}
    <tr><td class="mono">{{ r.chain }}</td>
      <td>{% if r.status == 'DEGRADED' %}<span class="badge b-med">DEGRADED</span>{% else %}<span class="badge b-ok">OK</span>{% endif %}</td>
      <td>{{ r.present }}/{{ r.total }} ({{ r.coverage }}%)</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if reasoning_journal %}
  <h3>Appendix E — Reasoning journal (excerpt)</h3>
  <table class="dt fixed">
    <tr><th style="width:18%">Step</th><th>Reasoning</th></tr>
    {% for j in reasoning_journal %}
    <tr><td>{{ j.step | default(j.phase) | default('—') }}</td>
      <td style="font-size:8.5pt;">{{ (j.reasoning | default(j.decision) | default(''))[:240] }}</td></tr>
    {% endfor %}
  </table>
  {% if journal_truncated %}<p class="small">Journal truncated for brevity — {{ journal_total }} total entries preserved in the session record.</p>{% endif %}
  {% endif %}

  <hr class="soft">
  <p class="small">End of report. Auto-generated by ARGUS — Advanced Reconnaissance &amp; Guided Unified Security —
  {{ generated_at | default('') }}. Prepared from contemporaneous engagement telemetry; all testing was
  authorized and confined to the designated target.</p>
</section>

</body>
</html>
"""
