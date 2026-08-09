# -*- coding: utf-8 -*-
"""Assemble the self-contained ARGUS enterprise report (HTML + inlined fonts + SVG)."""
import os, html, json
import data as D
import charts as C

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "ARGUS_Report.html")
FONTS = os.path.join(HERE, "assets_fonts.css")

SEV_CLASS = {"Critical":"crit","High":"high","Medium":"med","Low":"low","Info":"info"}


def esc(s):
    return html.escape(str(s), quote=True)


def sev_chip(sev, big=False):
    cls = SEV_CLASS[sev]
    b = " chip-lg" if big else ""
    return '<span class="chip chip-%s%s">%s</span>' % (cls, b, esc(sev.upper()))


def risk_pill(level):
    return '<span class="chip chip-%s chip-lg">%s</span>' % (SEV_CLASS[level], esc(level.upper()))


# ---------------------------------------------------------------- CSS
CSS = r"""
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--plane);color:var(--ink);
  font-family:var(--font-body);font-size:15.5px;line-height:1.65;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;
  font-feature-settings:"kern" 1,"liga" 1}
/*__ROOT_TOKENS__*/
::selection{background:var(--accent);color:var(--on-accent)}
a{color:var(--accent-2);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:3px}
h1,h2,h3,h4{margin:0;font-weight:400;text-wrap:balance;letter-spacing:-.01em}
p{margin:0 0 1em}
.mono{font-family:var(--font-mono)}
.tnum{font-variant-numeric:tabular-nums}

/* ---- layout shells ---- */
.wrap{max-width:var(--maxw);margin:0 auto;padding-left:var(--pad);padding-right:var(--pad)}
section{position:relative}
.band{border-top:1px solid var(--line)}
.sec-pad{padding-top:clamp(56px,8vw,104px);padding-bottom:clamp(56px,8vw,104px)}
.eyebrow{font-family:var(--font-mono);font-size:11px;font-weight:500;letter-spacing:.3em;
  text-transform:uppercase;color:var(--accent);display:flex;align-items:center;gap:12px}
.eyebrow::before{content:"";width:26px;height:1px;background:var(--accent);opacity:.7}
.sec-head{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;
  margin:16px 0 40px;flex-wrap:wrap}
.sec-num{font-family:var(--font-mono);font-size:12px;color:var(--ink-3);letter-spacing:.2em}
.sec-title{font-family:var(--font-display);font-size:clamp(1.9rem,4vw,2.9rem);line-height:1.02;
  font-optical-sizing:auto;font-weight:430}
.sec-title em{font-style:italic;color:var(--accent-2);font-weight:400}
.lede{color:var(--ink-2);max-width:62ch;font-size:1.02rem}

/* ---- top nav ---- */
.topbar{position:sticky;top:0;z-index:40;background:var(--topbar-bg);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.topbar-in{max-width:var(--maxw);margin:0 auto;padding:11px var(--pad);
  display:flex;align-items:center;gap:20px}
.brand{display:flex;align-items:center;gap:11px;font-family:var(--font-mono);
  font-size:12.5px;letter-spacing:.24em;text-transform:uppercase;color:var(--ink)}
.brand b{font-weight:600}
.mark{width:26px;height:26px;flex:none;display:grid;place-items:center;border:1px solid var(--accent);
  color:var(--accent);border-radius:6px;font-family:var(--font-display);font-size:16px;font-weight:600;
  box-shadow:0 0 0 3px var(--accent-glow)}
.nav{margin-left:auto;display:flex;gap:5px;flex-wrap:wrap}
.nav a{font-family:var(--font-mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--ink-2);padding:6px 10px;border-radius:6px}
.nav a:hover{color:var(--ink);background:var(--panel-2);text-decoration:none}
.classtag{font-family:var(--font-mono);font-size:10px;letter-spacing:.2em;color:var(--sev-high);
  border:1px solid color-mix(in srgb,var(--sev-high) 45%,transparent);padding:3px 8px;border-radius:5px;
  text-transform:uppercase;white-space:nowrap}

/* ---- cover ---- */
.cover{position:relative;overflow:hidden;min-height:clamp(640px,94vh,940px);
  display:flex;flex-direction:column;justify-content:center;
  background:var(--cover-bg)}
.cover-grid{position:absolute;inset:0;pointer-events:none;opacity:.5;
  background-image:linear-gradient(var(--line) 1px,transparent 1px),
    linear-gradient(90deg,var(--line) 1px,transparent 1px);
  background-size:52px 52px;mask-image:radial-gradient(120% 90% at 70% 20%,#000 25%,transparent 78%)}
.scan{position:absolute;left:0;right:0;height:180px;pointer-events:none;
  background:linear-gradient(180deg,transparent,var(--scan),transparent);
  animation:scan 7.5s linear infinite}
@keyframes scan{0%{transform:translateY(-200px)}100%{transform:translateY(96vh)}}
.cover-in{position:relative;z-index:2;width:100%}
.cover-top{display:flex;align-items:center;gap:16px;margin-bottom:clamp(40px,7vh,90px)}
.cover-top .mark{width:44px;height:44px;font-size:26px;border-radius:9px}
.cover-brandtext{font-family:var(--font-mono);letter-spacing:.34em;text-transform:uppercase}
.cover-brandtext .n{font-size:19px;font-weight:600;color:var(--ink);letter-spacing:.3em}
.cover-brandtext .t{font-size:10px;color:var(--accent);margin-top:3px}
.cover-grid-main{display:grid;grid-template-columns:1.55fr .95fr;gap:clamp(28px,5vw,64px);align-items:center}
.cover-kicker{font-family:var(--font-mono);font-size:12px;letter-spacing:.26em;text-transform:uppercase;
  color:var(--ink-2);margin-bottom:22px}
.cover-title{font-family:var(--font-display);font-optical-sizing:auto;font-weight:400;
  font-size:clamp(2.5rem,6.4vw,5rem);line-height:.98;letter-spacing:-.022em;margin-bottom:22px}
.cover-title em{font-style:italic;color:var(--accent-2)}
.cover-scope{font-family:var(--font-mono);font-size:12.5px;color:var(--ink-2);line-height:1.9;
  padding:14px 18px;border:1px solid var(--line);border-left:2px solid var(--accent);
  background:var(--wash);border-radius:0 8px 8px 0;max-width:560px;word-break:break-word}
.cover-scope b{color:var(--ink);font-weight:500}
.gauge-card{background:linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--line-2);
  border-radius:16px;padding:26px 26px 20px;text-align:center;box-shadow:var(--shadow)}
.gauge-card .lab{font-family:var(--font-mono);font-size:10.5px;letter-spacing:.28em;
  text-transform:uppercase;color:var(--ink-2)}
.gauge-verdict{font-family:var(--font-display);font-size:2.5rem;line-height:1;margin:2px 0 2px}
.gauge-sub{font-size:12.5px;color:var(--ink-2)}
.cover-meta{margin-top:clamp(34px,6vh,64px);display:grid;
  grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1px;background:var(--line);
  border:1px solid var(--line);border-radius:12px;overflow:hidden}
.cover-meta div{background:var(--plane-2);padding:15px 16px}
.cover-meta .k{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.2em;text-transform:uppercase;color:var(--ink-3)}
.cover-meta .v{font-size:14px;margin-top:5px;color:var(--ink);font-weight:500}
.confid-strip{position:relative;z-index:2;margin-top:clamp(30px,5vh,52px);
  display:flex;align-items:center;gap:14px;font-family:var(--font-mono);font-size:10.5px;
  letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3)}
.confid-strip .dot{width:6px;height:6px;border-radius:50%;background:var(--sev-high)}

/* ---- severity chips ---- */
.chip{display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono);font-weight:500;
  font-size:10.5px;letter-spacing:.1em;padding:3px 9px;border-radius:999px;white-space:nowrap;line-height:1.5}
.chip::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;flex:none}
.chip-lg{font-size:12px;padding:5px 13px}
.chip-crit{color:var(--sev-crit);background:color-mix(in srgb,var(--sev-crit) 15%,transparent);
  border:1px solid color-mix(in srgb,var(--sev-crit) 40%,transparent)}
.chip-high{color:var(--sev-high);background:color-mix(in srgb,var(--sev-high) 15%,transparent);
  border:1px solid color-mix(in srgb,var(--sev-high) 40%,transparent)}
.chip-med{color:var(--sev-med);background:color-mix(in srgb,var(--sev-med) 14%,transparent);
  border:1px solid color-mix(in srgb,var(--sev-med) 38%,transparent)}
.chip-low{color:var(--sev-low);background:color-mix(in srgb,var(--sev-low) 15%,transparent);
  border:1px solid color-mix(in srgb,var(--sev-low) 40%,transparent)}
.chip-info{color:var(--sev-info);background:color-mix(in srgb,var(--sev-info) 14%,transparent);
  border:1px solid color-mix(in srgb,var(--sev-info) 36%,transparent)}
.badge{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--good);border:1px solid color-mix(in srgb,var(--good) 42%,transparent);
  background:color-mix(in srgb,var(--good) 12%,transparent);padding:2px 7px;border-radius:5px}

/* ---- KPI tiles ---- */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:14px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:18px 18px 16px;
  position:relative;overflow:hidden}
.kpi .n{font-family:var(--font-display);font-size:2.5rem;line-height:1;font-weight:430;
  font-variant-numeric:tabular-nums}
.kpi .l{font-family:var(--font-mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;
  color:var(--ink-2);margin-top:8px}
.kpi .rail{position:absolute;left:0;top:0;bottom:0;width:3px}
.kpi.k-crit .n{color:var(--sev-crit)} .kpi.k-crit .rail{background:var(--sev-crit)}
.kpi.k-high .n{color:var(--sev-high)} .kpi.k-high .rail{background:var(--sev-high)}
.kpi.k-med .n{color:var(--sev-med)} .kpi.k-med .rail{background:var(--sev-med)}
.kpi.k-low .n{color:var(--sev-low)} .kpi.k-low .rail{background:var(--sev-low)}
.kpi.k-info .n{color:var(--sev-info)} .kpi.k-info .rail{background:var(--sev-info)}
.kpi.k-accent .n{color:var(--accent-2)} .kpi.k-accent .rail{background:var(--accent)}

/* ---- generic cards / grid ---- */
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:22px}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px 24px}
.card-h{font-family:var(--font-mono);font-size:11px;letter-spacing:.2em;text-transform:uppercase;
  color:var(--ink-2);margin-bottom:18px;display:flex;align-items:center;gap:10px}

/* ---- donut + legend ---- */
.donut-wrap{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.donut{width:200px;height:200px;flex:none}
.don-seg{transition:stroke-width .2s} .donut:hover .don-seg{opacity:.55}
.donut .don-seg:hover{opacity:1;stroke-width:40}
.don-num{font-family:var(--font-display);font-size:44px;fill:var(--ink);font-weight:440;font-variant-numeric:tabular-nums}
.don-lbl{font-family:var(--font-mono);font-size:9px;letter-spacing:.24em;fill:var(--ink-3)}
.legend{display:flex;flex-direction:column;gap:9px;min-width:180px;flex:1}
.legend-row{display:flex;align-items:center;gap:11px;font-size:13.5px}
.legend-row .sw{width:11px;height:11px;border-radius:3px;flex:none}
.legend-row .nm{color:var(--ink-2)} .legend-row .ct{margin-left:auto;font-family:var(--font-mono);
  font-variant-numeric:tabular-nums;color:var(--ink);font-weight:500}
.legend-row .bar{flex:1;height:4px;background:var(--line);border-radius:2px;overflow:hidden;max-width:120px}
.legend-row .bar i{display:block;height:100%;border-radius:2px}

/* ---- per-host stacked bars ---- */
.hostbars{display:flex;flex-direction:column;gap:15px}
.hb{display:grid;grid-template-columns:150px 1fr auto;gap:14px;align-items:center}
.hb .ip{font-family:var(--font-mono);font-size:12.5px;color:var(--ink)}
.hb .ip small{display:block;color:var(--ink-3);font-size:10px;letter-spacing:.04em;margin-top:2px}
.hb-track{height:15px;background:var(--panel-2);border-radius:5px;display:flex;gap:2px;padding:0;overflow:hidden}
.hb-seg{height:100%;min-width:3px}
.hb-seg:first-child{border-radius:5px 0 0 5px} .hb-seg:last-child{border-radius:0 5px 5px 0}
.hb .tot{font-family:var(--font-mono);font-size:12.5px;color:var(--ink-2);font-variant-numeric:tabular-nums;min-width:26px;text-align:right}
.seg-crit{background:var(--sev-crit)} .seg-high{background:var(--sev-high)}
.seg-med{background:var(--sev-med)} .seg-low{background:var(--sev-low)} .seg-info{background:var(--sev-info)}

/* ---- tables ---- */
.tbl-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;
  color:var(--ink-3);text-align:left;padding:13px 14px;background:var(--panel-2);
  border-bottom:1px solid var(--line-2);white-space:nowrap;position:sticky;top:0}
tbody td{padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--wash-hover)}
.td-id{font-family:var(--font-mono);color:var(--accent-2);font-size:12px;white-space:nowrap}
.td-host{font-family:var(--font-mono);font-size:12px;color:var(--ink-2);white-space:nowrap}
.td-mono{font-family:var(--font-mono);font-size:12px;color:var(--ink-2)}
.td-find{color:var(--ink);min-width:260px}
.cvss{font-family:var(--font-mono);font-variant-numeric:tabular-nums}

/* ---- register controls ---- */
.reg-controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.filt{display:flex;gap:6px;flex-wrap:wrap}
.filt button{font-family:var(--font-mono);font-size:11px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--ink-2);background:var(--panel);border:1px solid var(--line-2);padding:6px 12px;border-radius:999px;
  cursor:pointer;transition:.15s}
.filt button:hover{color:var(--ink);border-color:var(--ink-3)}
.filt button[aria-pressed="true"]{color:var(--on-accent);background:var(--accent);border-color:var(--accent)}
.reg-search{margin-left:auto;font-family:var(--font-mono);font-size:12px;color:var(--ink);
  background:var(--panel);border:1px solid var(--line-2);border-radius:999px;padding:7px 15px;min-width:210px}
.reg-search::placeholder{color:var(--ink-3)}
.reg-count{font-family:var(--font-mono);font-size:11px;color:var(--ink-3);white-space:nowrap}

/* ---- attack surface ---- */
.surf-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.surf-card{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden;display:flex;flex-direction:column}
.surf-card .hd{display:flex;align-items:center;justify-content:space-between;gap:10px;
  padding:15px 18px;border-bottom:1px solid var(--line);background:var(--panel-2)}
.surf-card .ip{font-family:var(--font-mono);font-size:14px;color:var(--ink);font-weight:500}
.surf-card .os{font-family:var(--font-mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3)}
.ports{display:flex;flex-direction:column}
.port{display:grid;grid-template-columns:60px 1fr auto;gap:12px;padding:10px 18px;border-bottom:1px solid var(--line);align-items:baseline}
.port:last-child{border-bottom:0}
.port .pn{font-family:var(--font-mono);font-size:13px;font-weight:600;font-variant-numeric:tabular-nums}
.port .svc{font-family:var(--font-mono);font-size:11px;color:var(--ink-2);text-transform:uppercase;letter-spacing:.06em}
.port .prod{font-size:12.5px;color:var(--ink-2);margin-top:2px}
.port .prisk{font-family:var(--font-mono);font-size:9px;letter-spacing:.12em;text-transform:uppercase;
  padding:2px 6px;border-radius:5px;border:1px solid var(--line-2);color:var(--ink-3);align-self:center;white-space:nowrap}
.port.r-high .pn{color:var(--sev-high)} .port.r-med .pn{color:var(--sev-med)}
.port.r-low .pn{color:var(--sev-low)} .port.r-info .pn{color:var(--ink-2)}
.port.r-high .prisk{color:var(--sev-high);border-color:color-mix(in srgb,var(--sev-high) 40%,transparent)}
.port.r-med .prisk{color:var(--sev-med);border-color:color-mix(in srgb,var(--sev-med) 38%,transparent)}
.port.r-low .prisk{color:var(--sev-low);border-color:color-mix(in srgb,var(--sev-low) 40%,transparent)}

/* ---- kill chain ---- */
.chain{position:relative;padding-left:34px}
.chain::before{content:"";position:absolute;left:9px;top:6px;bottom:6px;width:2px;
  background:linear-gradient(180deg,var(--accent),var(--sev-info))}
.chain-step{position:relative;padding:0 0 26px}
.chain-step:last-child{padding-bottom:0}
.chain-step::before{content:"";position:absolute;left:-30px;top:3px;width:16px;height:16px;border-radius:50%;
  background:var(--plane);border:2px solid var(--accent);box-shadow:0 0 0 4px var(--plane)}
.chain-step.ph-exploit::before{border-color:var(--sev-high)}
.chain-step .ph{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--accent)}
.chain-step.ph-exploit .ph{color:var(--sev-high)}
.chain-step .lb{font-size:15px;color:var(--ink);font-weight:500;margin:3px 0 2px}
.chain-step .dt{font-size:13px;color:var(--ink-2);max-width:64ch}
.phase-tags{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.phase-tags span{font-family:var(--font-mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--ink-3);border:1px solid var(--line-2);border-radius:6px;padding:4px 9px}
.phase-tags span.on{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 40%,transparent)}

/* ---- detailed finding cards ---- */
.host-group{margin-bottom:40px}
.host-group-h{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:6px;
  padding-bottom:14px;border-bottom:1px solid var(--line-2)}
.host-group-h .hip{font-family:var(--font-mono);font-size:19px;color:var(--ink);font-weight:600}
.host-group-h .hcounts{display:flex;gap:6px;margin-left:auto;flex-wrap:wrap}
.host-note{color:var(--ink-2);font-size:13.5px;margin:12px 0 22px;max-width:82ch}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:0;
  margin-bottom:16px;overflow:hidden;break-inside:avoid}
.finding.f-high{border-left:3px solid var(--sev-high)} .finding.f-crit{border-left:3px solid var(--sev-crit)}
.finding.f-med{border-left:3px solid var(--sev-med)} .finding.f-low{border-left:3px solid var(--sev-low)}
.finding.f-info{border-left:3px solid var(--sev-info)}
.f-hd{display:flex;align-items:flex-start;gap:14px;padding:18px 22px 14px;flex-wrap:wrap}
.f-hd .fid{font-family:var(--font-mono);font-size:12px;color:var(--accent-2);padding-top:3px}
.f-hd .ftitle{font-size:16px;color:var(--ink);font-weight:600;flex:1;min-width:220px;line-height:1.35}
.f-hd .fmeta{display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.f-sub{display:flex;gap:14px;flex-wrap:wrap;padding:0 22px 14px;
  font-family:var(--font-mono);font-size:11px;color:var(--ink-3);letter-spacing:.04em}
.f-sub b{color:var(--ink-2);font-weight:500}
.f-body{padding:0 22px 20px;display:flex;flex-direction:column;gap:14px}
.f-desc{color:var(--ink-2);font-size:13.8px;max-width:88ch}
.f-block{background:var(--plane-2);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.f-block .bh{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;
  color:var(--ink-3);margin-bottom:7px;display:flex;align-items:center;gap:7px}
.f-block.basis .bh{color:var(--accent)}
.f-block.fix{border-color:color-mix(in srgb,var(--good) 30%,transparent);
  background:color-mix(in srgb,var(--good) 6%,var(--plane-2))}
.f-block.fix .bh{color:var(--good)}
.f-block .bt{font-size:13px;color:var(--ink-2)}
.evi{font-family:var(--font-mono);font-size:11.5px;color:var(--ink-2);white-space:pre-wrap;
  word-break:break-word;line-height:1.6;overflow-x:auto}

/* ---- MITRE ---- */
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.mit{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:18px 20px}
.mit .tid{font-family:var(--font-mono);font-size:15px;color:var(--accent-2);font-weight:600}
.mit .tac{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--ink-3);margin-top:2px}
.mit .tnm{font-size:14.5px;color:var(--ink);font-weight:600;margin:11px 0 6px}
.mit .tdt{font-size:12.8px;color:var(--ink-2)}
.mit .tfoot{display:flex;align-items:center;gap:10px;margin-top:13px}
.mit .cnt{font-family:var(--font-mono);font-size:11px;color:var(--ink-2)}
.mit .refs{display:flex;gap:5px;flex-wrap:wrap;margin-left:auto}
.mit .refs span{font-family:var(--font-mono);font-size:10px;color:var(--accent-2);
  border:1px solid var(--line-2);border-radius:5px;padding:2px 6px}

/* ---- remediation roadmap ---- */
.road{display:flex;flex-direction:column;gap:14px}
.rd{display:grid;grid-template-columns:66px 1fr;gap:20px;background:var(--panel);
  border:1px solid var(--line);border-radius:14px;padding:20px 22px;break-inside:avoid}
.rd .rank{font-family:var(--font-display);font-size:1.9rem;color:var(--accent-2);font-weight:500;line-height:1}
.rd .rank small{display:block;font-family:var(--font-mono);font-size:9px;letter-spacing:.16em;
  text-transform:uppercase;color:var(--ink-3);margin-top:6px}
.rd .rtitle{font-size:16.5px;color:var(--ink);font-weight:600;margin-bottom:6px;line-height:1.3}
.rd .rsum{color:var(--ink-2);font-size:13.5px;max-width:90ch;margin-bottom:14px}
.rd-meta{display:flex;gap:22px;flex-wrap:wrap;align-items:center}
.rd-meta .m{display:flex;flex-direction:column;gap:3px}
.rd-meta .mk{font-family:var(--font-mono);font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3)}
.rd-meta .mv{font-size:12.5px;color:var(--ink);font-family:var(--font-mono)}
.rd-meta .mv.pri{color:var(--sev-high)}
.rd-refs{display:flex;gap:5px;flex-wrap:wrap}
.rd-refs span{font-family:var(--font-mono);font-size:10px;color:var(--ink-3);
  border:1px solid var(--line);border-radius:5px;padding:2px 6px}
.impact-dot{display:inline-flex;gap:3px;align-items:center}
.impact-dot i{width:7px;height:7px;border-radius:50%;background:var(--line-2)}
.impact-dot i.on{background:var(--accent)}

/* ---- methodology ---- */
.method{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;counter-reset:m}
.mstep{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px}
.mstep .mn{font-family:var(--font-mono);font-size:11px;color:var(--accent);letter-spacing:.2em}
.mstep h4{font-family:var(--font-display);font-size:1.5rem;font-weight:440;margin:8px 0 10px}
.mstep p{color:var(--ink-2);font-size:13.5px;margin:0}
.bands{margin-top:22px}
.band-row{display:grid;grid-template-columns:110px 100px 1fr;gap:14px;align-items:center;
  padding:11px 0;border-bottom:1px solid var(--line)}
.band-row:last-child{border-bottom:0}
.band-row .bb{font-family:var(--font-mono);font-size:13px;color:var(--ink);font-variant-numeric:tabular-nums}
.band-row .bd{color:var(--ink-2);font-size:13px}

/* ---- appendix / doc control ---- */
.dc{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1px;
  background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.dc>div{background:var(--panel);padding:16px 18px}
.dc .k{font-family:var(--font-mono);font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3)}
.dc .v{font-size:13.5px;color:var(--ink);margin-top:6px;word-break:break-word}
.legal{color:var(--ink-3);font-size:12px;line-height:1.7;max-width:90ch;margin-top:22px}
.footer{border-top:1px solid var(--line);padding:26px 0;display:flex;justify-content:space-between;
  gap:16px;flex-wrap:wrap;font-family:var(--font-mono);font-size:11px;color:var(--ink-3);letter-spacing:.05em}

/* callouts */
.callout{display:flex;gap:14px;padding:16px 18px;border-radius:12px;background:var(--panel-2);
  border:1px solid var(--line-2)}
.callout .ic{width:30px;height:30px;flex:none;border-radius:8px;display:grid;place-items:center;
  font-family:var(--font-display);font-weight:600;font-size:16px}
.callout.warn{border-color:color-mix(in srgb,var(--sev-high) 34%,transparent)}
.callout.warn .ic{background:color-mix(in srgb,var(--sev-high) 16%,transparent);color:var(--sev-high)}
.callout.ok{border-color:color-mix(in srgb,var(--good) 32%,transparent)}
.callout.ok .ic{background:color-mix(in srgb,var(--good) 14%,transparent);color:var(--good)}
.callout .ct{font-size:13.5px;color:var(--ink-2)}
.callout .ct b{color:var(--ink);font-weight:600}

.two-col{display:grid;grid-template-columns:1.15fr .85fr;gap:30px;align-items:start}

/* reveal animation */
.reveal{opacity:0;transform:translateY(14px)}
.reveal.in{opacity:1;transform:none;transition:opacity .7s ease,transform .7s cubic-bezier(.2,.7,.2,1)}

@media (max-width:860px){
  .cover-grid-main{grid-template-columns:1fr}
  .grid-2,.two-col,.method{grid-template-columns:1fr}
  .grid-3{grid-template-columns:1fr}
  .hb{grid-template-columns:120px 1fr auto}
  .nav{display:none}
  .rd{grid-template-columns:1fr}
}
@media (prefers-reduced-motion:reduce){
  .scan{animation:none;display:none}
  .reveal{opacity:1;transform:none;transition:none}
  *{scroll-behavior:auto!important}
}
html{scroll-behavior:smooth}

/* ---------- print / PDF ---------- */
@media print{
  @page{size:A4;margin:12mm 11mm}
  html,body{background:var(--plane)!important}
  *{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
  .topbar,.scan,.reg-controls{display:none!important}
  /* compact single-page cover */
  .cover{min-height:auto;page-break-after:always;padding:2mm 0 0;display:block}
  .cover-top{margin-bottom:12mm}
  .cover-top .mark{width:36px;height:36px;font-size:22px}
  .cover-title{font-size:30pt;margin-bottom:16px}
  .cover-grid-main{gap:16px;align-items:start}
  .cover-scope{font-size:10.5px}
  .gauge-card{padding:12px 14px 8px}
  .gauge{width:210px}
  .gauge-verdict{font-size:2rem}
  .cover-meta{grid-template-columns:repeat(3,1fr);margin-top:9mm}
  .cover-meta .v{white-space:normal}
  .confid-strip{margin-top:8mm}
  /* natural flow — keep headers with content, don't split cards */
  section.band{border-top:0}
  .sec-pad{padding:9mm 0}
  .sec-head{break-after:avoid}
  .host-group-h,.card-h{break-after:avoid}
  #register.band,#findings.band{break-before:page}
  .finding,.rd,.kpi,.surf-card,.mit,.card,.chain-step,.host-group,.band-row,.legend-row{break-inside:avoid}
  thead{display:table-header-group}
  tr,.hb{break-inside:avoid}
  .reveal{opacity:1!important;transform:none!important}
  .f-row{display:table-row!important}
  a{color:var(--ink)}
  .nav{display:none}
  #register.band,#findings.band,#compromise.band,#aisec.band{break-before:page}
}

/* ---- extended ARGUS sections ---- */
.tag-row{display:flex;gap:8px;flex-wrap:wrap}
.tag{font-family:var(--font-mono);font-size:11px;letter-spacing:.06em;color:var(--ink-2);
  border:1px solid var(--line-2);border-radius:6px;padding:5px 11px;background:var(--panel);white-space:nowrap}
.tag.on{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 40%,transparent)}
.tag.done{color:var(--good);border-color:color-mix(in srgb,var(--good) 40%,transparent);
  background:color-mix(in srgb,var(--good) 10%,transparent)}
.tag.skip{color:var(--ink-3);opacity:.7}
.tag.warn{color:var(--sev-high);border-color:color-mix(in srgb,var(--sev-high) 40%,transparent)}
.tag.mut{color:var(--ink-3)}
.progress{height:8px;background:var(--panel-2);border-radius:5px;overflow:hidden;margin:6px 0 2px}
.progress i{display:block;height:100%;background:var(--accent);border-radius:5px}
.wc-row{display:flex;align-items:center;gap:12px;padding:11px 0;border-bottom:1px solid var(--line)}
.wc-row:last-child{border-bottom:0}
.wc-row .wn{flex:1;color:var(--ink);font-size:14px}
.wc-row .wev{font-family:var(--font-mono);font-size:11px;color:var(--ink-3);max-width:38ch;text-align:right}
.wc-row .wm{font-family:var(--font-display);font-size:18px;line-height:1;width:20px;text-align:center;flex:none}
.wc-row .wm.ok{color:var(--good)} .wc-row .wm.no{color:var(--ink-3)}
.jr{display:grid;grid-template-columns:34px 1fr;gap:12px;padding:9px 0;border-bottom:1px solid var(--line)}
.jr:last-child{border-bottom:0}
.jr .jn{font-family:var(--font-mono);font-size:11px;color:var(--accent);padding-top:2px}
.jr .jt{color:var(--ink-2);font-size:13.5px}
.sha{font-family:var(--font-mono);font-size:11px;color:var(--ink-3);word-break:break-all}
"""

# ---------------------------------------------------------------- JS
JS = r"""
(function(){
  // scroll reveal
  var io=new IntersectionObserver(function(es){es.forEach(function(e){
    if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target)}})},
    {threshold:.12,rootMargin:'0px 0px -8% 0px'});
  document.querySelectorAll('.reveal').forEach(function(el){io.observe(el)});

  // findings register filter + search
  var rows=[].slice.call(document.querySelectorAll('.f-row'));
  var btns=[].slice.call(document.querySelectorAll('.filt button'));
  var search=document.getElementById('regSearch');
  var count=document.getElementById('regCount');
  var cur='all';
  function apply(){
    var q=(search&&search.value||'').toLowerCase().trim();var shown=0;
    rows.forEach(function(r){
      var okSev=cur==='all'||r.getAttribute('data-sev')===cur;
      var okQ=!q||r.getAttribute('data-search').indexOf(q)>-1;
      var vis=okSev&&okQ;r.style.display=vis?'':'none';if(vis)shown++;});
    if(count)count.textContent=shown+' / '+rows.length+' findings';
  }
  btns.forEach(function(b){b.addEventListener('click',function(){
    btns.forEach(function(x){x.setAttribute('aria-pressed','false')});
    b.setAttribute('aria-pressed','true');cur=b.getAttribute('data-sev');apply();});});
  if(search)search.addEventListener('input',apply);
  apply();
})();
"""

# ---------------------------------------------------------------- themes
FONT_VARS = ('--font-display:"Fraunces",Georgia,"Times New Roman",serif;'
             '--font-body:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;'
             '--font-mono:"IBM Plex Mono",ui-monospace,"SF Mono",Menlo,Consolas,monospace;'
             '--maxw:1120px;--pad:clamp(20px,5vw,64px);')

THEME_TOKENS = {
    "dark": {
        "plane": "#0A0B0F", "plane-2": "#0C0E15", "panel": "#12141C", "panel-2": "#171A24",
        "panel-3": "#1F2430", "line": "rgba(234,237,243,.085)", "line-2": "rgba(234,237,243,.17)",
        "ink": "#ECEEF3", "ink-2": "#9AA2B4", "ink-3": "#868D9E",
        "accent": "#E8B04B", "accent-2": "#F3CE85", "accent-deep": "#B7862B",
        "accent-glow": "rgba(232,176,75,.13)", "good": "#40B47F",
        "sev-crit": "#F04A5C", "sev-high": "#FB6A3C", "sev-med": "#F2B840",
        "sev-low": "#5B8DEF", "sev-info": "#7D93A9",
        "on-accent": "#0A0B0F", "topbar-bg": "rgba(10,11,15,.82)",
        "cover-bg": ("radial-gradient(120% 80% at 82% 8%,rgba(232,176,75,.10),transparent 55%),"
                     "radial-gradient(90% 70% at 6% 96%,rgba(240,74,92,.09),transparent 55%),"
                     "linear-gradient(180deg,#0B0D13,#090A0E)"),
        "scan": "rgba(232,176,75,.06)", "wash": "rgba(255,255,255,.015)",
        "wash-hover": "rgba(255,255,255,.018)", "shadow": "0 24px 60px -30px rgba(0,0,0,.8)",
    },
    "light": {
        "plane": "#F4F5F7", "plane-2": "#EDF0F4", "panel": "#FFFFFF", "panel-2": "#F6F7F9",
        "panel-3": "#EAEDF1", "line": "rgba(18,21,28,.10)", "line-2": "rgba(18,21,28,.18)",
        "ink": "#12151C", "ink-2": "#47505F", "ink-3": "#5E6675",
        "accent": "#8A6516", "accent-2": "#86610E", "accent-deep": "#6E5210",
        "accent-glow": "rgba(138,101,22,.16)", "good": "#1C844A",
        "sev-crit": "#C62828", "sev-high": "#C1531A", "sev-med": "#9A6A00",
        "sev-low": "#2E6FD1", "sev-info": "#5B6674",
        "on-accent": "#FFFFFF", "topbar-bg": "rgba(255,255,255,.82)",
        "cover-bg": ("radial-gradient(120% 80% at 82% 8%,rgba(138,101,22,.10),transparent 55%),"
                     "radial-gradient(90% 70% at 6% 96%,rgba(198,40,40,.06),transparent 55%),"
                     "linear-gradient(180deg,#FBFBFC,#EFF2F6)"),
        "scan": "rgba(138,101,22,.05)", "wash": "rgba(18,21,28,.022)",
        "wash-hover": "rgba(18,21,28,.03)", "shadow": "0 20px 48px -30px rgba(25,32,50,.35)",
    },
}


def root_css(theme):
    decls = ";".join("--%s:%s" % (k, v) for k, v in THEME_TOKENS[theme].items())
    return ":root{" + decls + ";" + FONT_VARS + "}"


# ---------------------------------------------------------------- helpers
def stacked_bar(counts, total, max_total):
    scale = total / max_total if max_total else 0
    segs = ""
    for s in D.SEVERITY_ORDER:
        v = counts.get(s, 0)
        if v <= 0:
            continue
        w = (v / total) * 100 if total else 0
        segs += ('<i class="hb-seg seg-%s" style="flex:%.4f" title="%s: %d"></i>'
                 % (SEV_CLASS[s], v, esc(s), v))
    return segs, scale


def legend_block(counts, total):
    rows = ""
    for s in D.SEVERITY_ORDER:
        v = counts.get(s, 0)
        pct = (v / total * 100) if total else 0
        rows += (
            '<div class="legend-row"><span class="sw" style="background:var(--sev-%s)"></span>'
            '<span class="nm">%s</span>'
            '<span class="bar"><i style="width:%.1f%%;background:var(--sev-%s)"></i></span>'
            '<span class="ct tnum">%d</span></div>'
            % (SEV_CLASS[s], esc(s), pct, SEV_CLASS[s], v))
    return rows


# ---------------------------------------------------------------- sections
def cover():
    e = D.ENGAGEMENT
    scope = ("<b>Scope</b> &nbsp;%s &nbsp;·&nbsp; %d in scope, %d with findings<br>"
             "<b>Targets</b> &nbsp;%s"
             % (esc(e["scope_cidr"]), len(e["targets"]), e["hosts_with_findings"],
                esc(", ".join(e["targets"]))))
    meta = [
        ("Engagement", e["engagement_type"]),
        ("Started", e["started"]),
        ("Duration", e["duration"]),
        ("Generated", e["generated"]),
        ("Access obtained", e["access_achieved"]),
        ("Findings", str(D.TOTAL_FINDINGS)),
    ]
    meta_html = "".join('<div><div class="k">%s</div><div class="v">%s</div></div>'
                        % (esc(k), esc(v)) for k, v in meta)
    return """
<section class="cover" id="cover">
  <div class="cover-grid"></div><div class="scan"></div>
  <div class="wrap cover-in">
    <div class="cover-top">
      <div class="mark">A</div>
      <div class="cover-brandtext"><div class="n">ARGUS</div><div class="t">Autonomous Offensive Security</div></div>
    </div>
    <div class="cover-grid-main">
      <div>
        <div class="cover-kicker">%s</div>
        <h1 class="cover-title">Autonomous<br>Penetration&nbsp;Test<br><em>Engagement Report</em></h1>
        <div class="cover-scope mono">%s</div>
      </div>
      <div class="gauge-card">
        <div class="lab">Overall Risk</div>
        %s
        <div class="gauge-verdict" style="color:var(--sev-high)">%s</div>
        <div class="gauge-sub">%s</div>
      </div>
    </div>
    <div class="cover-meta">%s</div>
    <div class="confid-strip"><span class="dot"></span> %s · Distribution restricted to authorised personnel · Prepared by ARGUS</div>
  </div>
</section>""" % (
        esc(e["doc_type"]), scope, C.risk_gauge(e["overall_risk"]),
        esc(e["overall_risk"]), esc(e["overall_risk_note"]),
        meta_html, esc(e["classification"]))


def topbar():
    links = [("summary","Summary"),("dashboard","Dashboard"),("surface","Surface"),
             ("register","Findings"),("mitre","ATT&CK"),("remediation","Remediation"),
             ("methodology","Method")]
    nav = "".join('<a href="#%s">%s</a>' % (i, esc(t)) for i, t in links)
    return """
<div class="topbar"><div class="topbar-in">
  <div class="brand"><span class="mark">A</span><b>ARGUS</b></div>
  <nav class="nav">%s</nav>
  <span class="classtag">%s</span>
</div></div>""" % (nav, esc(D.ENGAGEMENT["classification"]))


def sec_header(num, eyebrow, title_html, num_label):
    return """<div class="sec-head reveal">
      <div><div class="eyebrow">%s</div><h2 class="sec-title">%s</h2></div>
      <div class="sec-num">%s</div></div>""" % (esc(eyebrow), title_html, esc(num_label))


def executive_summary():
    e = D.ENGAGEMENT
    counts = D.SEVERITY_COUNTS
    donut = C.donut(counts, D.TOTAL_FINDINGS)
    # ── narrative computed from the live engagement (not hard-coded to one scan) ──
    _crit = int(counts.get("Critical", 0) or 0)
    _access = str(e.get("access_achieved") or "None").strip()
    _no_access = _access.lower() in ("", "none", "no access", "no access obtained")
    _hosts = D.HOSTS or []
    _h0 = (_hosts[0]["ip"] if _hosts else
           (e["targets"][0] if e.get("targets") else e.get("scope_cidr", "the target")))
    _h1 = _hosts[1]["ip"] if len(_hosts) > 1 else ""
    _tophosts = ('<span class="mono">%s</span>' % esc(_h0)
                 + (' and <span class="mono">%s</span>' % esc(_h1) if _h1 else ""))
    _crit_clause = ("no critical issues" if _crit == 0
                    else "<b>%d critical issue%s</b>" % (_crit, "" if _crit == 1 else "s"))
    _access_clause = ("<b>no access obtained</b> against engagement objectives."
                      if _no_access else
                      "<b>%s</b> against engagement objectives." % esc(_access))
    narrative = (
        "This autonomous penetration test against the %s internal segment ran for "
        "<b>%s</b> and swept <b>%d in-scope host%s</b> — %d of which returned findings. "
        "ARGUS published <b>%d validated finding%s</b> — "
        "%d high, %d medium, %d low and %d informational — with %s and %s"
        % (esc(e["scope_cidr"]), esc(e["duration"]), len(e["targets"]),
           "" if len(e["targets"]) == 1 else "s", e["hosts_with_findings"],
           D.TOTAL_FINDINGS, "" if D.TOTAL_FINDINGS == 1 else "s",
           counts["High"], counts["Medium"], counts["Low"], counts["Info"],
           _crit_clause, _access_clause))
    _priority = ("The priority signals concentrate on %s. The Findings Register and "
                 "Remediation Roadmap set out the specific weaknesses and the order in "
                 "which they should be triaged — severity and exploitability first, not "
                 "raw finding volume." % _tophosts)
    _warn = ("<b>Highest priority.</b> Confirm and contain the highest-severity findings on %s, "
             "then work the Remediation Roadmap in priority order." % _tophosts)
    if _no_access:
        _second = ('<div class="callout ok reveal" style="margin-top:12px"><div class="ic">&#10003;</div>'
                   '<div class="ct"><b>Containment held.</b> Despite the exposed surface, ARGUS '
                   'achieved <b>no foothold, no credentials and no privilege escalation</b> during '
                   'the window.</div></div>')
    else:
        _second = ('<div class="callout warn reveal" style="margin-top:12px"><div class="ic">!</div>'
                   '<div class="ct"><b>Access achieved.</b> ARGUS obtained <b>%s</b>. See the Basis '
                   'of Compromise and the Detailed Findings for the exact steps and impact.</div></div>'
                   % esc(_access))
    return """
<section class="band sec-pad" id="summary"><div class="wrap">
  %s
  <div class="two-col">
    <div class="reveal">
      <p class="lede">%s</p>
      <p class="lede">%s</p>
      <div class="callout warn reveal" style="margin-top:8px">
        <div class="ic">!</div>
        <div class="ct">%s</div>
      </div>
      %s
    </div>
    <div class="card reveal">
      <div class="card-h">Findings by severity</div>
      <div class="donut-wrap"><div>%s</div><div class="legend">%s</div></div>
    </div>
  </div>
</div></section>""" % (
        sec_header("01","For Leadership","Executive <em>Summary</em>","01 / Executive Summary"),
        narrative, _priority, _warn, _second, donut, legend_block(counts, D.TOTAL_FINDINGS))


def dashboard():
    e = D.ENGAGEMENT
    counts = D.SEVERITY_COUNTS
    kpis = [
        ("k-crit", counts["Critical"], "Critical"),
        ("k-high", counts["High"], "High"),
        ("k-med", counts["Medium"], "Medium"),
        ("k-low", counts["Low"], "Low"),
        ("k-info", counts["Info"], "Info"),
    ]
    kpi_html = "".join(
        '<div class="kpi %s reveal"><span class="rail"></span><div class="n tnum">%d</div>'
        '<div class="l">%s</div></div>' % (c, n, esc(l)) for c, n, l in kpis)
    port_count = sum(1 for h in D.ATTACK_SURFACE for s in h["services"] if s["port"].isdigit())
    stat_kpis = [
        ("k-accent", "%d / %d" % (int(e.get("hosts_with_findings", 0) or 0),
                                  len(e.get("targets") or [])), "Hosts: findings / in scope"),
        ("k-accent", str(port_count), "Ports &amp; services observed"),
        ("k-accent", str(len(D.MITRE)), "ATT&CK techniques"),
        ("k-accent", (e.get("access_achieved") or "None"), "Access obtained"),
    ]
    stat_html = "".join(
        '<div class="kpi %s reveal"><span class="rail"></span><div class="n">%s</div>'
        '<div class="l">%s</div></div>' % (c, esc(n), esc(l)) for c, n, l in stat_kpis)
    max_total = max(h["total"] for h in D.HOSTS)
    bars = ""
    for h in D.HOSTS:
        segs, scale = stacked_bar(h["counts"], h["total"], max_total)
        bars += ("""<div class="hb reveal"><div class="ip">%s<small>%s</small></div>
          <div class="hb-track" style="width:%.1f%%">%s</div>
          <div class="tot tnum">%d</div></div>"""
                 % (esc(h["ip"]), esc(h["label"]), max(scale*100, 8), segs, h["total"]))
    return """
<section class="band sec-pad" id="dashboard"><div class="wrap">
  %s
  <div class="kpis reveal" style="margin-bottom:14px">%s</div>
  <div class="kpis reveal" style="margin-bottom:34px">%s</div>
  <div class="card reveal">
    <div class="card-h">Findings by host &nbsp;·&nbsp; most severe first
      <span style="margin-left:auto;display:flex;gap:12px;font-family:var(--font-mono);font-size:10px;color:var(--ink-3)">
      <span style="color:var(--sev-high)">■ High</span><span style="color:var(--sev-med)">■ Med</span>
      <span style="color:var(--sev-low)">■ Low</span><span style="color:var(--sev-info)">■ Info</span></span></div>
    <div class="hostbars">%s</div>
  </div>
</div></section>""" % (
        sec_header("04","At a Glance","Engagement <em>Dashboard</em>","04 / Dashboard"),
        kpi_html, stat_html, bars)


def scope():
    e = D.ENGAGEMENT
    rows = ""
    for h in D.HOSTS:
        rows += ("""<tr><td class="td-host">%s</td><td>%s</td><td class="td-mono">%s</td>
          <td class="tnum" style="font-family:var(--font-mono)">%d</td>
          <td>%s</td></tr>""" % (
            esc(h["ip"]), esc(h["label"]), esc(h["os"]), h["total"],
            " ".join(sev_chip(s) for s in D.SEVERITY_ORDER if h["counts"].get(s,0)>0) or
            '<span class="td-mono">—</span>'))
    rows += ("""<tr><td class="td-host">%s</td><td>In-scope target</td>
      <td class="td-mono">—</td><td class="tnum" style="font-family:var(--font-mono)">0</td>
      <td class="td-mono">No observable services / no findings</td></tr>""" % esc(D.HOST_NO_DATA))
    fw = " ".join('<span class="mit"><span class="refs"><span>%s</span></span></span>' % esc(f)
                  for f in [])
    frameworks = "".join('<span class="rd-refs"><span>%s</span></span>' % esc(f) for f in e["frameworks"])
    return """
<section class="band sec-pad" id="scope"><div class="wrap">
  %s
  <div class="two-col" style="margin-bottom:30px">
    <p class="lede reveal">The engagement covered <b>%d in-scope hosts</b> on <span class="mono">%s</span>.
      Testing was fully autonomous and conducted under authorisation; every published finding is
      grounded in concrete tool evidence and reproduction steps, gated by the %s.</p>
    <div class="dc reveal">
      <div><div class="k">Window</div><div class="v">%s → %s</div></div>
      <div><div class="k">Duration</div><div class="v">%s</div></div>
      <div><div class="k">Access obtained</div><div class="v">%s</div></div>
      <div><div class="k">Frameworks</div><div class="v" style="display:flex;gap:5px;flex-wrap:wrap;margin-top:4px">%s</div></div>
    </div>
  </div>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Host</th><th>Role</th><th>OS</th><th>Findings</th><th>Severity mix</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("05","Rules of Engagement","Scope &amp; <em>Targets</em>","05 / Scope"),
        len(e["targets"]), esc(e["scope_cidr"]), esc(e["findings_gate"]),
        esc(e["started"]), esc(e["completed"]), esc(e["duration"]),
        esc(e["access_achieved"]), frameworks, rows)


def attack_surface():
    risk_label = {"high":"High risk","med":"Medium","low":"Low","info":"Info"}
    cards = ""
    for host in D.ATTACK_SURFACE:
        ports = ""
        for s in host["services"]:
            ports += ("""<div class="port r-%s"><div class="pn tnum">%s</div>
              <div><span class="svc">%s / %s</span><div class="prod">%s</div></div>
              <span class="prisk">%s</span></div>"""
                     % (esc(s["risk"]), esc(s["port"]), esc(s["service"]), esc(s["proto"]),
                        esc(s["product"]), esc(risk_label.get(s["risk"], s["risk"]))))
        cards += ("""<div class="surf-card reveal"><div class="hd">
          <span class="ip">%s</span><span class="os">%s</span></div>
          <div class="ports">%s</div></div>""" % (esc(host["ip"]), esc(host["os"]), ports))
    return """
<section class="band sec-pad" id="surface"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:30px">Services and ports observed across the
    segment, compiled from ARGUS recon findings. Each service is annotated with a risk weighting,
    and the host cards below are ordered by exposure. Every finding's evidence shows the raw port
    state — some services nmap reported as <em>filtered</em> are noted per host.</p>
  <div class="surf-grid">%s</div>
</div></section>""" % (
        sec_header("07","Reconnaissance","Attack <em>Surface</em>","07 / Attack Surface"), cards)


def kill_chain():
    steps = ""
    for s in D.KILL_CHAIN:
        cls = "ph-exploit" if s["phase"].lower().startswith("exploit") else ""
        steps += ("""<div class="chain-step %s reveal"><div class="ph">%02d · %s</div>
          <div class="lb">%s</div><div class="dt">%s</div></div>"""
                 % (cls, s["n"], esc(s["phase"]), esc(s["label"]), esc(s["detail"])))
    tags = "".join('<span class="%s">%s</span>' % ("on" if p in ("Recon","Exploit / Foothold") else "", esc(p))
                   for p in D.KILL_CHAIN_PHASES)
    _acc = str(D.ENGAGEMENT.get("access_achieved") or "None").strip()
    _no_acc = _acc.lower() in ("", "none", "no access", "no access obtained")
    if _no_acc:
        _kc_lede = ("The ordered sequence ARGUS executed from first contact to deepest access. "
                    "The engagement ended with <b>no access obtained</b> against objectives.")
        _kc_note = ("No privilege escalation, post-exploitation, persistence or lateral movement "
                    "was achieved — a positive containment outcome.")
    else:
        _kc_lede = ("The ordered sequence ARGUS executed from first contact to deepest access, "
                    "culminating in <b>%s</b>." % esc(_acc))
        _kc_note = ("Access was established during the engagement — see the Basis of Compromise and "
                    "the Detailed Findings for the exact reproduction steps and impact.")
    return """
<section class="band sec-pad" id="killchain"><div class="wrap">
  %s
  <div class="two-col">
    <div class="reveal"><div class="chain">%s</div></div>
    <div class="reveal">
      <p class="lede">%s</p>
      <div class="card" style="margin-top:18px">
        <div class="card-h">Kill-chain phases reached</div>
        <div class="phase-tags">%s</div>
        <p style="color:var(--ink-2);font-size:13px;margin:16px 0 0">%s</p>
      </div>
    </div>
  </div>
</div></section>""" % (
        sec_header("09","Attack Path","Kill <em>Chain</em>","09 / Kill Chain"),
        steps, _kc_lede, tags, _kc_note)


def register():
    rows = ""
    for f in D.F:
        sc = SEV_CLASS[f["sev"]]
        search = ("%s %s %s %s %s" % (f["id"], f["title"], f["host"], f["sev"], f.get("mitre",""))).lower()
        cvss = f["cvss"] if f["cvss"] else "—"
        mitre = f["mitre"] if f["mitre"] else "—"
        host = f["host"] + ((":"+f["port"]) if f["port"] else "")
        rows += ("""<tr class="f-row" data-sev="%s" data-search="%s">
          <td class="td-id">%s</td><td class="td-find">%s</td><td>%s</td>
          <td class="cvss">%s</td><td class="td-host">%s</td><td class="td-mono">%s</td>
          <td><span class="badge">Verified</span></td></tr>"""
                 % (sc, esc(search), esc(f["id"]), esc(f["title"]), sev_chip(f["sev"]),
                    esc(cvss), esc(host), esc(mitre)))
    filt = "".join(
        '<button data-sev="%s" aria-pressed="%s">%s</button>'
        % (v, "true" if v == "all" else "false", esc(l))
        for v, l in [("all","All"),("high","High"),("med","Medium"),("low","Low"),("info","Info")])
    return """
<section class="band sec-pad" id="register"><div class="wrap">
  %s
  <div class="reg-controls reveal">
    <div class="filt">%s</div>
    <input id="regSearch" class="reg-search" type="search" placeholder="Filter findings…" aria-label="Filter findings">
    <span class="reg-count" id="regCount"></span>
  </div>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>Host</th><th>ATT&amp;CK</th><th>Retest</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("18","Consolidated","Findings <em>Register</em>","18 / Register"), filt, rows)


def detailed_findings():
    groups = ""
    order = [h["ip"] for h in D.HOSTS]
    host_map = {h["ip"]: h for h in D.HOSTS}
    by_host = {}
    for f in D.F:
        by_host.setdefault(f["host"], []).append(f)
    sev_rank = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
    for ip in order:
        fs = by_host.get(ip, [])
        fs.sort(key=lambda x: (sev_rank[x["sev"]], x["id"]))
        h = host_map[ip]
        chips = "".join(sev_chip(s) + '<span style="font-family:var(--font-mono);font-size:11px;color:var(--ink-3);margin-right:8px">&#215;%d</span>' % h["counts"][s]
                        for s in D.SEVERITY_ORDER if h["counts"].get(s,0)>0)
        cards = ""
        for f in fs:
            sc = SEV_CLASS[f["sev"]]
            sub = []
            sub.append('<span><b>Target</b> %s%s</span>' % (esc(f["host"]), (":"+esc(f["port"])) if f["port"] else ""))
            sub.append('<span><b>Vector</b> %s</span>' % esc(f["proto"]))
            if f["cvss"]:
                sub.append('<span><b>CVSS</b> %s</span>' % esc(f["cvss"]))
            if f["mitre"]:
                sub.append('<span><b>ATT&amp;CK</b> %s</span>' % esc(f["mitre"]))
            evi = ('<div class="f-block"><div class="bh">&#9679; Evidence</div><div class="evi">%s</div></div>'
                   % esc(f["evidence"])) if f.get("evidence") else ""
            cards += ("""<article class="finding f-%s">
              <div class="f-hd"><span class="fid">%s</span>
                <span class="ftitle">%s</span>
                <span class="fmeta">%s<span class="badge">Verified</span></span></div>
              <div class="f-sub">%s</div>
              <div class="f-body">
                <div class="f-desc">%s</div>
                <div class="f-block basis"><div class="bh">&#9650; Severity basis</div><div class="bt">%s</div></div>
                %s
                <div class="f-block fix"><div class="bh">&#10003; Recommended remediation</div><div class="bt">%s</div></div>
              </div></article>""" % (
                sc, esc(f["id"]), esc(f["title"]), sev_chip(f["sev"]),
                " ".join(sub), esc(f["desc"]), esc(f["basis"]), evi, esc(f["fix"])))
        groups += ("""<div class="host-group reveal"><div class="host-group-h">
          <span class="hip">%s</span><span class="td-mono" style="color:var(--ink-3)">%s</span>
          <span class="hcounts">%s</span></div>
          <p class="host-note">%s</p>%s</div>""" % (
            esc(ip), esc(h["label"]), chips, esc(h["note"]), cards))
    return """
<section class="band sec-pad" id="findings"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:34px">Every finding with its evidence, severity basis
    and recommended remediation, grouped by host in descending order of exposure.</p>
  %s
</div></section>""" % (
        sec_header("19","Technical Detail","Detailed <em>Findings</em>","19 / Detailed Findings"), groups)


def mitre_section():
    cards = ""
    for m in D.MITRE:
        refs = "".join('<span>%s</span>' % esc(x) for x in m["findings"])
        cards += ("""<div class="mit reveal"><div class="tid">%s</div>
          <div class="tac">%s</div><div class="tnm">%s</div>
          <div class="tdt">%s</div>
          <div class="tfoot"><span class="cnt">%d finding%s</span><span class="refs">%s</span></div></div>"""
                 % (esc(m["id"]), esc(m["tactic"]), esc(m["name"]), esc(m["detail"]),
                    m["count"], "" if m["count"]==1 else "s", refs))
    drows = ""
    for d in D.DETECTION:
        drows += ("""<tr><td class="td-find">%s</td><td class="td-mono">%s</td>
          <td class="td-host">%s</td><td><span class="chip chip-high" style="color:var(--sev-med);
          background:color-mix(in srgb,var(--sev-med) 14%%,transparent);
          border-color:color-mix(in srgb,var(--sev-med) 38%%,transparent)">OPEN</span></td></tr>"""
                 % (esc(d["finding"]), esc(d["tech"]), esc(d["host"])))
    return """
<section class="band sec-pad" id="mitre"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">Observed activity mapped to MITRE ATT&amp;CK Enterprise.
    Five techniques across Execution, Credential Access and Lateral Movement were exercised against the segment.</p>
  <div class="mitre-grid" style="margin-bottom:38px">%s</div>
  <div class="card reveal">
    <div class="card-h">Blue-team detection opportunities</div>
    <div class="tbl-scroll" style="border:0"><table>
      <thead><tr><th>Finding</th><th>Technique</th><th>Telemetry host</th><th>Status</th></tr></thead>
      <tbody>%s</tbody></table></div>
    <p style="color:var(--ink-3);font-size:12px;margin:14px 0 0">Detection opportunity for each:
      correlate the producing tool/command with host telemetry and alert on the matching ATT&amp;CK behaviour.</p>
  </div>
</div></section>""" % (
        sec_header("22","Adversary Mapping","MITRE ATT&amp;CK <em>Coverage</em>","22 / ATT&CK"),
        cards, drows)


def _impact_dots(level):
    n = {"High":3,"Medium":2,"Low":1}.get(level,1)
    return '<span class="impact-dot">%s</span>' % "".join(
        '<i class="%s"></i>' % ("on" if i < n else "") for i in range(3))


def remediation():
    cards = ""
    for r in D.REMEDIATION:
        refs = "".join('<span>%s</span>' % esc(x) for x in r["findings"])
        cards += ("""<div class="rd reveal">
          <div><div class="rank">%s<small>Priority</small></div></div>
          <div><div class="rtitle">%s</div><div class="rsum">%s</div>
            <div class="rd-meta">
              <div class="m"><span class="mk">Priority</span><span class="mv pri">%s</span></div>
              <div class="m"><span class="mk">Risk reduction</span><span class="mv">%s %s</span></div>
              <div class="m"><span class="mk">Effort</span><span class="mv">%s</span></div>
              <div class="m"><span class="mk">Owner</span><span class="mv">%s</span></div>
              <div class="m"><span class="mk">Findings (%d)</span><div class="rd-refs">%s</div></div>
            </div></div></div>""" % (
            esc(r["rank"]), esc(r["title"]), esc(r["summary"]), esc(r["priority"]),
            _impact_dots(r["impact"]), esc(r["impact"]), esc(r["effort"]),
            esc(r["owner"]), len(r["findings"]), refs))
    return """
<section class="band sec-pad" id="remediation"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:30px">The %d finding%s consolidated into %d prioritised
    workstream%s — ordered by risk reduction per unit of effort, so remediation can be planned and owned
    rather than triaged finding-by-finding.</p>
  <div class="road">%s</div>
</div></section>""" % (
        sec_header("24","Action Plan","Remediation <em>Roadmap</em>","24 / Remediation"),
        D.TOTAL_FINDINGS, "" if D.TOTAL_FINDINGS == 1 else "s",
        len(D.REMEDIATION), "" if len(D.REMEDIATION) == 1 else "s", cards)


def methodology():
    steps = ""
    for i, m in enumerate(D.METHODOLOGY, 1):
        steps += ("""<div class="mstep reveal"><div class="mn">0%d</div>
          <h4>%s</h4><p>%s</p></div>""" % (i, esc(m["step"]), esc(m["body"])))
    bands = ""
    for b in D.CVSS_BANDS:
        bands += ("""<div class="band-row"><span class="bb tnum">%s</span>%s<span class="bd">%s</span></div>"""
                 % (esc(b["band"]), sev_chip(b["sev"]), esc(b["desc"])))
    return """
<section class="band sec-pad" id="methodology"><div class="wrap">
  %s
  <div class="method" style="margin-bottom:30px">%s</div>
  <div class="card reveal">
    <div class="card-h">CVSS v3.1 severity bands</div>
    <div class="bands">%s</div>
  </div>
</div></section>""" % (
        sec_header("28","How ARGUS Works","Methodology &amp; <em>Assurance</em>","28 / Methodology"),
        steps, bands)


def appendix():
    e = D.ENGAGEMENT
    dc = [
        ("Classification", e["classification"]),
        ("Target / scope", "%s · %d in scope, %d with findings" % (e["scope_cidr"], len(e["targets"]), e["hosts_with_findings"])),
        ("Engagement window", "%s → %s (%s)" % (e["started"], e["completed"], e["duration"])),
        ("Report generated", e["generated"]),
        ("Findings gate", e["findings_gate"]),
        ("Access obtained", e["access_achieved"]),
    ]
    dc_html = "".join('<div><div class="k">%s</div><div class="v">%s</div></div>'
                      % (esc(k), esc(v)) for k, v in dc)
    legal = ("This report and its evidence artifacts are strictly confidential and intended solely for "
             "authorised personnel of the engaging organisation. Do not reproduce or distribute without "
             "written authorisation. All testing was conducted under an authorised engagement against "
             "systems in scope. Every published finding is grounded in concrete tool evidence and "
             "reproduction steps; credential and key material is redacted.")
    return """
<section class="band sec-pad" id="appendix"><div class="wrap">
  %s
  <div class="dc reveal" style="margin-bottom:20px">%s</div>
  <div class="card reveal" style="margin-bottom:8px">
    <div class="card-h">Evidence &amp; severity provenance</div>
    <p style="color:var(--ink-2);font-size:13px;margin:0 0 10px;max-width:92ch">Findings, severities,
      CVSS scores and evidence are reproduced from the ARGUS Issue-Validator output. Each severity reflects
      the <b>finding producer's assessment</b> and does not, on its own, assert demonstrated exploitation —
      the per-finding <em>Severity basis</em> states the grounds.</p>
    <p style="color:var(--ink-2);font-size:13px;margin:0;max-width:92ch">Raw tool output is preserved
      verbatim. Where an evidence block shows a probe was <span class="mono">filtered</span>, returned
      <span class="mono">EXIT&nbsp;28</span> (no response), or reported no archived match, that context is
      shown as-is and should be weighed before acting. Items requiring manual verification are flagged in
      the finding text and prioritised accordingly in the Remediation Roadmap.</p>
  </div>
  <p class="legal reveal">%s</p>
  <div class="footer">
    <span>ARGUS · Autonomous Offensive Security</span>
    <span>%s · Generated %s</span>
  </div>
</div></section>""" % (
        sec_header("29","Reference","Appendix &amp; <em>Handling</em>","29 / Appendix"),
        dc_html, esc(legal), esc(e["classification"]), esc(e["generated"]))


# ---------------------------------------------------------------- extended sections
def _fmt_int(v):
    try:
        return format(int(v), ",")
    except Exception:
        return "0"


def _fmt_bytes(n):
    try:
        n = int(n)
    except Exception:
        return "—"
    if n <= 0:
        return "—"
    val = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if val < 1024 or unit == "GB":
            return ("%d %s" % (int(val), unit)) if unit == "B" else ("%.1f %s" % (val, unit))
        val /= 1024.0
    return "%d B" % n


def mission_win():
    mb = D.MISSION_BRIEF
    wc = D.WIN_CONDITIONS
    if not (mb or (wc and wc.get("conditions"))):
        return ""
    left = ""
    if mb:
        facts = []
        if mb.get("blast_radius"):
            facts.append(("Blast radius", mb["blast_radius"]))
        if mb.get("time_budget_min"):
            facts.append(("Time budget", "%s min" % mb["time_budget_min"]))
        if mb.get("noise_budget"):
            facts.append(("Noise budget", "%d / 100" % mb["noise_budget"]))
        if D.AUTONOMY:
            facts.append(("Autonomy", D.AUTONOMY))
        fact_html = "".join('<div><div class="k">%s</div><div class="v">%s</div></div>'
                            % (esc(k), esc(v)) for k, v in facts)
        fact_block = ('<div class="dc" style="margin-top:2px">%s</div>' % fact_html) if fact_html else ""
        scope_in = "".join('<span class="tag on">%s</span>' % esc(x) for x in mb.get("scope_in", []))
        scope_out = "".join('<span class="tag skip">%s</span>' % esc(x) for x in mb.get("scope_out", []))
        scope_block = ""
        if scope_in or scope_out:
            scope_block = ('<div style="margin-top:14px"><div class="card-h" style="margin-bottom:8px">In / out of scope</div>'
                           '<div class="tag-row">%s%s</div></div>' % (scope_in, scope_out))
        notes = ('<p style="color:var(--ink-2);font-size:13px;margin:14px 0 0">%s</p>'
                 % esc(mb["notes"])) if mb.get("notes") else ""
        obj = mb.get("objective") or "—"
        left = ('<div class="card reveal"><div class="card-h">Mission brief</div>'
                '<div class="callout" style="margin-bottom:16px"><div class="ic" '
                'style="background:color-mix(in srgb,var(--accent) 16%%,transparent);color:var(--accent)">&#9678;</div>'
                '<div class="ct"><b>Objective.</b> %s</div></div>%s%s%s</div>'
                % (esc(obj), fact_block, scope_block, notes))
    right = ""
    if wc and wc.get("conditions"):
        pct = int(wc.get("progress_pct") or 0)
        rows = ""
        for c in wc["conditions"]:
            mark = ('<span class="wm ok">&#10003;</span>' if c.get("achieved")
                    else '<span class="wm no">&#8226;</span>')
            ev = ('<span class="wev">%s</span>' % esc(c["evidence"])) if c.get("evidence") else ""
            rows += '<div class="wc-row">%s<span class="wn">%s</span>%s</div>' % (mark, esc(c["name"]), ev)
        right = ('<div class="card reveal"><div class="card-h">Win conditions'
                 '<span style="margin-left:auto;font-family:var(--font-mono);font-size:11px;color:var(--ink-2)">'
                 '%d / %d achieved</span></div>'
                 '<div class="progress"><i style="width:%d%%"></i></div>'
                 '<div style="font-family:var(--font-mono);font-size:11px;color:var(--ink-3);margin-bottom:8px">'
                 '%d%% complete</div>%s</div>'
                 % (int(wc.get("achieved_count") or 0), int(wc.get("total") or 0), pct, pct, rows))
    inner = ('<div class="two-col">%s%s</div>' % (left, right)) if (left and right) else (left + right)
    return """
<section class="band sec-pad" id="mission"><div class="wrap">
  %s
  %s
</div></section>""" % (
        sec_header("02", "Engagement Brief", "Mission &amp; <em>Win Conditions</em>", "02 / Mission Brief"),
        inner)


def objectives():
    if not D.OBJECTIVES:
        return ""
    rows = ""
    for o in D.OBJECTIVES:
        badge = ('<span class="badge">Answered</span>' if o["answered"]
                 else '<span class="tag skip">Open</span>')
        ans = o["answer"] or "—"
        meta = " · ".join(x for x in (o.get("section"), o.get("tool")) if x)
        meta_html = ('<div style="color:var(--ink-3);font-family:var(--font-mono);font-size:10.5px;margin-top:4px">%s</div>'
                     % esc(meta)) if meta else ""
        rows += ('<tr><td class="td-id">%02d</td><td class="td-find">%s%s</td>'
                 '<td class="td-mono">%s</td><td>%s</td></tr>'
                 % (o["index"], esc(o["question"]), meta_html, esc(ans), badge))
    return """
<section class="band sec-pad" id="objectives"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">%s objective set — <b>%d of %d</b> answered.
    Each question is paired with the answer ARGUS recovered and the tool that produced it.</p>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>#</th><th>Question</th><th>Answer</th><th>Status</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("03", "Question Set", "Engagement <em>Objectives</em>", "03 / Objectives"),
        esc(D.ENGAGEMENT.get("engagement_type") or "Engagement"),
        D.OBJECTIVES_DONE, D.OBJECTIVES_TOTAL, rows)


def phase_coverage():
    if not D.PHASES_COMPLETED:
        return ""
    done = set(D.PHASES_COMPLETED)
    chips = "".join('<span class="tag %s">%s</span>'
                    % ("done" if p in done else "skip", esc(p.replace("_", " ")))
                    for p in D.ALL_PHASES)
    return """
<section class="band sec-pad" id="phases"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:24px">Which phases of the ARGUS methodology actually executed —
    <b>%d of %d</b> ran. Skipped phases were not applicable or not reached.</p>
  <div class="card reveal"><div class="card-h">Phase execution</div>
    <div class="tag-row">%s</div></div>
</div></section>""" % (
        sec_header("06", "Execution", "Phase <em>Coverage</em>", "06 / Phase Coverage"),
        len(done), len(D.ALL_PHASES), chips)


def primer_map():
    if not D.PRIMER_ROWS:
        return ""
    rows = ""
    for r in D.PRIMER_ROWS:
        st = r["status"].upper()
        tag = '<span class="tag %s">%s</span>' % ("done" if st == "OK" else "warn", esc(st))
        rows += ('<tr><td class="td-mono" style="color:var(--ink)">%s</td>'
                 '<td class="cvss">%d%%</td><td class="td-mono">%d / %d</td>'
                 '<td class="td-mono">%s</td><td>%s</td></tr>'
                 % (esc(r["chain"]), r["coverage"], r["present"], r["total"], esc(r["missing"]), tag))
    return """
<section class="band sec-pad" id="capability"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">Which automation chains ARGUS had tooling for on this
    engagement. Degraded chains ran with missing tools, so their findings may under-report.</p>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Capability chain</th><th>Coverage</th><th>Present</th><th>Missing tools</th><th>Status</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("08", "Platform", "Capability <em>Map</em>", "08 / Capability Map"), rows)


def attack_path_section():
    if not D.ATTACK_PATH:
        return ""
    rows = ""
    for s in D.ATTACK_PATH:
        rows += ('<tr><td class="td-id">%02d</td><td class="td-mono" style="color:var(--accent-2)">%s</td>'
                 '<td class="td-find">%s</td><td class="td-mono">%s</td><td class="td-mono">%s</td></tr>'
                 % (s["step"], esc(s["phase"]), esc(s["result"]), esc(s["source"] or "—"), esc(s["ts"] or "—")))
    return """
<section class="band sec-pad" id="attackpath"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">The chronological foothold → pivot → privilege-escalation
    trail, with the producing tool and timestamp for each step.</p>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Step</th><th>Phase</th><th>Result</th><th>Source</th><th>Timestamp</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("10", "Chronology", "Path to <em>Compromise</em>", "10 / Path to Compromise"), rows)


def timeline_section():
    if not D.ENGAGEMENT_TIMELINE:
        return ""
    rows = ""
    for t in D.ENGAGEMENT_TIMELINE:
        rows += ('<tr><td class="td-mono" style="white-space:nowrap">%s</td>'
                 '<td class="td-mono" style="color:var(--accent-2)">%s</td>'
                 '<td class="td-find">%s</td></tr>'
                 % (esc(t["ts"]), esc(t["label"]), esc(t["detail"])))
    return """
<section class="band sec-pad" id="timeline"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">Time-ordered engagement milestones assembled from phase
    history and attack-path steps.</p>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Timestamp</th><th>Milestone</th><th>Detail</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("11", "Chronology", "Engagement <em>Timeline</em>", "11 / Timeline"), rows)


def compromise_section():
    ce = D.COMPROMISE_EVIDENCE
    if not (ce and ce.get("claimed")):
        return ""
    proven = ce.get("proven")
    cls = "ok" if proven else "warn"
    icon = "&#10003;" if proven else "!"
    head = "Proof of access captured" if proven else "Access reached — artifact not persisted"
    callout = ('<div class="callout %s reveal"><div class="ic">%s</div>'
               '<div class="ct"><b>%s.</b> Compromise level: <b>%s</b>. %s</div></div>'
               % (cls, icon, esc(head), esc(ce.get("level") or "foothold"), esc(ce.get("basis") or "")))
    blocks = ""
    if ce.get("proof_items"):
        blocks += ('<div class="f-block basis" style="margin-top:16px"><div class="bh">&#9679; Proof artifacts</div>'
                   '<div class="evi">%s</div></div>' % esc("\n".join(ce["proof_items"])))
    if ce.get("method_steps"):
        blocks += ('<div class="f-block" style="margin-top:12px"><div class="bh">&#8250; Reproduction — exact commands</div>'
                   '<div class="evi">%s</div></div>' % esc("\n".join(ce["method_steps"])))
    if not proven and ce.get("no_artifact_reason"):
        blocks += ('<div class="f-block" style="margin-top:12px;'
                   'border-color:color-mix(in srgb,var(--sev-high) 30%%,transparent);'
                   'background:color-mix(in srgb,var(--sev-high) 6%%,var(--plane-2))">'
                   '<div class="bh" style="color:var(--sev-high)">&#9888; Why no artifact</div>'
                   '<div class="bt">%s</div></div>' % esc(ce["no_artifact_reason"]))
    return """
<section class="band sec-pad" id="compromise"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:20px">The documented basis for the compromise claim, with the
    exact human-reproducible steps and any proof artifacts ARGUS persisted.</p>
  %s
  %s
</div></section>""" % (
        sec_header("12", "Impact", "Basis of <em>Compromise</em>", "12 / Basis of Compromise"),
        callout, blocks)


def flags_section():
    if not D.FLAGS:
        return ""
    rows = ""
    for fl in D.FLAGS:
        ft = (fl.get("flag_type") or "flag").lower()
        cls = "chip-crit" if ft == "root" else ("chip-high" if ft == "user" else "chip-info")
        chip = '<span class="chip %s">%s</span>' % (cls, esc((fl.get("flag_type") or "flag").upper()))
        rows += ('<tr><td>%s</td><td class="td-mono" style="color:var(--ink);word-break:break-all">%s</td>'
                 '<td class="td-mono">%s</td><td class="td-host">%s</td><td class="td-mono">%s</td></tr>'
                 % (chip, esc(fl.get("value") or "—"), esc(fl.get("location") or "—"),
                    esc(fl.get("host") or "—"), esc(fl.get("found_by") or "—")))
    return """
<section class="band sec-pad" id="flags"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">High-value proofs captured during the engagement.</p>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Type</th><th>Value</th><th>Location</th><th>Host</th><th>Found by</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("13", "Captured", "Flags <em>Captured</em>", "13 / Flags"), rows)


def creds_section():
    if not D.CREDS_SUMMARY:
        return ""
    rows = ""
    for c in D.CREDS_SUMMARY:
        rows += ('<tr><td class="td-mono" style="color:var(--ink)">%s</td><td class="td-mono">%s</td>'
                 '<td class="td-mono">%s</td><td class="td-mono">%s</td><td class="td-find">%s</td></tr>'
                 % (esc(c["user"]), esc(c["domain"] or "—"), esc(c["password"]),
                    esc(c["source"]), esc(c["note"] or "—")))
    return """
<section class="band sec-pad" id="credentials"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:20px">Logins and secrets recovered during the engagement.
    Passwords are redacted; treat every row as a live exposure requiring rotation.</p>
  <div class="callout warn reveal" style="margin-bottom:22px"><div class="ic">!</div>
    <div class="ct"><b>Handling.</b> Rotate all listed credentials and revoke harvested keys/tokens.</div></div>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>User</th><th>Domain</th><th>Password</th><th>Source</th><th>Note</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("14", "Recovered", "Credentials &amp; <em>Identities</em>", "14 / Credentials"), rows)


def loot_section():
    if not D.LOOT_ENTRIES:
        return ""
    kpis = ""
    for cat, n in sorted(D.LOOT_SUMMARY.items(), key=lambda kv: (-kv[1], kv[0])):
        kpis += ('<div class="kpi k-accent reveal"><span class="rail"></span>'
                 '<div class="n tnum">%d</div><div class="l">%s</div></div>' % (n, esc(cat)))
    kpi_html = ('<div class="kpis reveal" style="margin-bottom:24px">%s</div>' % kpis) if kpis else ""
    rows = ""
    for e in D.LOOT_ENTRIES:
        rows += ('<tr><td>%s</td><td class="td-mono" style="color:var(--ink)">%s</td>'
                 '<td class="td-mono">%s</td><td class="td-host">%s</td>'
                 '<td class="cvss">%s</td><td class="sha">%s</td></tr>'
                 % (sev_chip(e["severity"]), esc(e["doi_label"]), esc(e["source"]),
                    esc(e["target"]), esc(_fmt_bytes(e["size_bytes"])), esc(e["sha256"] or "—")))
    return """
<section class="band sec-pad" id="loot"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:24px">Post-exploitation artifacts archived by ARGUS, each
    fingerprinted by SHA-256 for chain-of-custody.</p>
  %s
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Severity</th><th>Category</th><th>Source</th><th>Target</th><th>Size</th><th>SHA-256</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("15", "Data of Interest", "Harvested <em>Loot</em>", "15 / Loot"), kpi_html, rows)


def exploit_modules_section():
    if not D.EXPLOIT_MODULES:
        return ""
    rows = ""
    for e in D.EXPLOIT_MODULES:
        cves = ", ".join(e.get("cves") or []) or "—"
        name = e.get("title") or e.get("product") or (e.get("cves") or ["—"])[0]
        used = ('<span class="badge">Used</span>' if e.get("used")
                else '<span class="tag mut">considered</span>')
        url = e.get("url")
        ref = (('<a href="%s" class="td-mono" style="word-break:break-all">%s</a>' % (esc(url), esc(url)))
               if url else ('<span class="td-mono">%s</span>' % esc(e.get("path") or "—")))
        rows += ('<tr><td class="td-find">%s</td><td class="td-mono" style="color:var(--accent-2)">%s</td>'
                 '<td class="td-mono">%s</td><td>%s</td><td>%s</td></tr>'
                 % (esc(name), esc(cves), esc(e.get("type") or "—"), used, ref))
    return """
<section class="band sec-pad" id="exploits"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">Public exploits and proof-of-concept modules ARGUS
    evaluated; the module that drove the foothold is flagged <b>Used</b>.</p>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Module</th><th>CVEs</th><th>Type</th><th>Status</th><th>Reference</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("16", "Weaponization", "Exploits &amp; <em>PoCs</em>", "16 / Exploits"), rows)


def web_intel_section():
    if not D.WEB_INTEL_HINTS:
        return ""
    rows = ""
    for h in D.WEB_INTEL_HINTS:
        raw = h.get("confidence") or 0
        conf = int(round(raw * 100)) if raw <= 1 else int(raw)
        ref = h.get("source_url")
        link = (('<a href="%s" class="td-mono" style="word-break:break-all">%s</a>' % (esc(ref), esc(ref)))
                if ref else "—")
        tags = " ".join('<span class="tag">%s</span>' % esc(x)
                        for x in (h.get("cve"), h.get("mitre"), h.get("tool")) if x)
        rows += ('<tr><td class="cvss">%d%%</td><td class="td-find">%s</td><td>%s</td><td>%s</td></tr>'
                 % (conf, esc(h.get("description") or "—"), tags or "—", link))
    return """
<section class="band sec-pad" id="webintel"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">Exploit techniques ARGUS mined from authoritative web
    sources (Exploit-DB, HackTricks, AttackerKB, vendor advisories), ranked by confidence.</p>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Conf.</th><th>Technique</th><th>Refs</th><th>Source</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("17", "Threat Intel", "Web-Intel <em>Sources</em>", "17 / Web Intel"), rows)


def ai_security_section():
    ai = D.AI_SECURITY
    if not (ai and ai.get("count")):
        return ""
    kpis = [
        ("k-crit", str(ai.get("count") or 0), "AI findings"),
        ("k-high", "%.1f" % (ai.get("max_aivss") or 0), "Max AIVSS"),
        ("k-med", "%d%%" % int(ai.get("avg_asr") or 0), "Avg attack success"),
        ("k-accent", str(len(ai.get("owasp_classes") or [])), "OWASP-LLM classes"),
    ]
    kpi_html = "".join('<div class="kpi %s reveal"><span class="rail"></span><div class="n">%s</div>'
                       '<div class="l">%s</div></div>' % (c, esc(n), esc(l)) for c, n, l in kpis)
    rows = ""
    for f in ai.get("findings") or []:
        rows += ('<tr><td class="td-find">%s</td><td>%s</td><td class="cvss">%s</td>'
                 '<td class="cvss">%d%%</td><td class="td-mono">%s</td><td class="td-mono">%s</td></tr>'
                 % (esc(f.get("title") or "—"), sev_chip(f.get("sev") or "Info"),
                    esc("%.1f" % (f.get("aivss") or 0)), int(f.get("asr") or 0),
                    esc(f.get("owasp_llm") or "—"), esc(f.get("atlas") or "—")))
    return """
<section class="band sec-pad" id="aisec"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">Adversarial testing of AI/LLM components — scored with
    AIVSS and attack-success rate, mapped to OWASP Top 10 for LLM and MITRE ATLAS.</p>
  <div class="kpis reveal" style="margin-bottom:26px">%s</div>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Finding</th><th>Severity</th><th>AIVSS</th><th>ASR</th><th>OWASP-LLM</th><th>ATLAS</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("20", "AI Red Team", "AI / LLM <em>Findings</em>", "20 / AI Security"), kpi_html, rows)


def discovered_issues_section():
    if not D.DISCOVERED_ISSUES:
        return ""
    rows = ""
    for d in D.DISCOVERED_ISSUES:
        rows += ('<tr><td class="td-find">%s</td><td>%s</td><td class="td-mono">%s</td>'
                 '<td class="td-mono">%s</td><td class="td-host">%s</td></tr>'
                 % (esc(d["title"]), sev_chip(d["sev"]), esc(d["tool"] or "—"),
                    esc(d["status"]), esc(d["host"] or "—")))
    return """
<section class="band sec-pad" id="observed"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:26px">Lower-signal observations ARGUS noted but did not promote
    to formal findings — useful context and hardening leads.</p>
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Observation</th><th>Severity</th><th>Tool</th><th>Status</th><th>Host</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("21", "Storyline", "Observed <em>Issues</em>", "21 / Observed Issues"), rows)


def reasoning_journal_section():
    if not D.REASONING_JOURNAL:
        return ""
    items = "".join('<div class="jr"><span class="jn">%02d</span><span class="jt">%s</span></div>'
                    % (i, esc(s)) for i, s in enumerate(D.REASONING_JOURNAL, 1))
    note = ""
    if D.JOURNAL_TRUNCATED:
        note = ('<p style="color:var(--ink-3);font-size:12px;margin:14px 0 0">Showing the most recent %d of %d '
                'iteration summaries.</p>' % (len(D.REASONING_JOURNAL), D.JOURNAL_TOTAL))
    return """
<section class="band sec-pad" id="journal"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:24px">ARGUS's iteration-by-iteration decision trail — the
    situational assessment recorded at each step.</p>
  <div class="card reveal"><div class="card-h">Decision trail</div>%s%s</div>
</div></section>""" % (
        sec_header("23", "Transparency", "Reasoning <em>Journal</em>", "23 / Reasoning Journal"),
        items, note)


def coverage_section():
    if not D.COVERAGE_TESTS:
        return ""

    def _cc_cls(o):
        o = (o or "").lower()
        if o in ("success", "positive"):
            return "done"
        if o == "negative":
            return "skip"
        if o in ("error", "fail", "failed"):
            return "warn"
        return "mut"

    kpis, seen = "", set()
    for o in ["success", "positive", "negative", "error"] + sorted(D.COVERAGE_COUNTS):
        if o in seen or o not in D.COVERAGE_COUNTS:
            continue
        seen.add(o)
        kpis += ('<div class="kpi k-accent reveal"><span class="rail"></span><div class="n tnum">%d</div>'
                 '<div class="l">%s</div></div>' % (D.COVERAGE_COUNTS[o], esc(o)))
    kpi_html = ('<div class="kpis reveal" style="margin-bottom:24px">%s</div>' % kpis) if kpis else ""
    rows = ""
    for t in D.COVERAGE_TESTS:
        tag = '<span class="tag %s">%s</span>' % (_cc_cls(t["outcome"]), esc(t["outcome"]))
        rows += ('<tr><td class="td-mono" style="color:var(--ink)">%s</td><td class="td-host">%s</td>'
                 '<td class="td-mono" style="word-break:break-all">%s</td><td>%s</td><td class="td-mono">%s</td></tr>'
                 % (esc(t["tool"]), esc(t["target"]), esc(t["command"] or "—"), tag, esc(t["note"] or "")))
    return """
<section class="band sec-pad" id="coverage"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:24px">Every probe ARGUS executed — including negative results —
    so coverage is auditable, not just the hits.</p>
  %s
  <div class="tbl-scroll reveal"><table>
    <thead><tr><th>Tool</th><th>Target</th><th>Command</th><th>Outcome</th><th>Note</th></tr></thead>
    <tbody>%s</tbody></table></div>
</div></section>""" % (
        sec_header("25", "Assurance", "Test <em>Coverage</em>", "25 / Test Coverage"), kpi_html, rows)


def tools_section():
    if not D.TOOLS_USED:
        return ""
    chips = "".join('<span class="tag">%s</span>' % esc(t) for t in D.TOOLS_USED)
    return """
<section class="band sec-pad" id="tooling"><div class="wrap">
  %s
  <p class="lede reveal" style="margin-bottom:22px">The <b>%d</b> distinct tools ARGUS invoked during the engagement.</p>
  <div class="card reveal"><div class="card-h">Tooling inventory</div><div class="tag-row">%s</div></div>
</div></section>""" % (
        sec_header("26", "Inventory", "Tooling <em>Inventory</em>", "26 / Tooling"),
        len(D.TOOLS_USED), chips)


def observability_section():
    o = D.OBSERVABILITY
    if not (o and o.get("total_tokens")):
        return ""
    est = " (est.)" if o.get("tokens_estimated") else ""
    kpis = [
        ("k-accent", _fmt_int(o.get("total_tokens")), "Total tokens" + est),
        ("k-accent", _fmt_int(o.get("prompt_tokens")), "Prompt tokens"),
        ("k-accent", _fmt_int(o.get("completion_tokens")), "Completion tokens"),
        ("k-accent", _fmt_int(o.get("total_invocations")), "Tool invocations"),
    ]
    kpi_html = "".join('<div class="kpi %s reveal"><span class="rail"></span><div class="n tnum">%s</div>'
                       '<div class="l">%s</div></div>' % (c, esc(n), esc(l)) for c, n, l in kpis)
    per = o.get("invocations_per_tool") or {}
    rows = "".join('<tr><td class="td-mono" style="color:var(--ink)">%s</td><td class="cvss">%d</td></tr>'
                   % (esc(tool), n) for tool, n in sorted(per.items(), key=lambda kv: (-kv[1], kv[0])))
    table = (('<div class="tbl-scroll reveal" style="margin-top:24px;max-width:520px"><table>'
              '<thead><tr><th>Tool</th><th>Invocations</th></tr></thead><tbody>%s</tbody></table></div>' % rows)
             if rows else "")
    return """
<section class="band sec-pad" id="observability"><div class="wrap">
  %s
  <div class="kpis reveal">%s</div>
  %s
</div></section>""" % (
        sec_header("27", "Observability", "Engagement <em>Telemetry</em>", "27 / Observability"),
        kpi_html, table)


# ---------------------------------------------------------------- assemble
def build(theme="dark", out=None, fragment=False):
    out = out or OUT
    with open(FONTS, "r", encoding="utf-8") as f:
        fonts_css = f.read()
    title = "ARGUS Engagement Report · %s" % D.ENGAGEMENT["scope_cidr"]
    css = CSS.replace("/*__ROOT_TOKENS__*/", root_css(theme))
    body = "".join([
        topbar(), cover(),
        executive_summary(),           # 01
        mission_win(),                 # 02
        objectives(),                  # 03
        dashboard(),                   # 04
        scope(),                       # 05
        phase_coverage(),              # 06
        attack_surface(),              # 07
        primer_map(),                  # 08
        kill_chain(),                  # 09
        attack_path_section(),         # 10
        timeline_section(),            # 11
        compromise_section(),          # 12
        flags_section(),               # 13
        creds_section(),               # 14
        loot_section(),                # 15
        exploit_modules_section(),     # 16
        web_intel_section(),           # 17
        register(),                    # 18
        detailed_findings(),           # 19
        ai_security_section(),         # 20
        discovered_issues_section(),   # 21
        mitre_section(),               # 22
        reasoning_journal_section(),   # 23
        remediation(),                 # 24
        coverage_section(),            # 25
        tools_section(),               # 26
        observability_section(),       # 27
        methodology(),                 # 28
        appendix(),                    # 29
    ])
    style = ("<style>" + fonts_css + css + "</style>"
             "<noscript><style>.reveal{opacity:1!important;transform:none!important}</style></noscript>")
    if fragment:
        doc = style + body + "<script>" + JS + "</script>"
    else:
        doc = (
            "<!doctype html><html lang=\"en\" data-report-theme=\"" + theme + "\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<meta name=\"color-scheme\" content=\"" + theme + "\">"
            "<title>" + esc(title) + "</title>"
            + style +
            "</head><body>"
            + body +
            "<script>" + JS + "</script></body></html>"
        )
    with open(out, "w", encoding="utf-8") as f:
        f.write(doc)
    print("Wrote %s  (%.1f KB, theme=%s%s)"
          % (out, os.path.getsize(out) / 1024, theme, ", fragment" if fragment else ""))


if __name__ == "__main__":
    import sys
    LIGHT = os.path.join(ROOT, "ARGUS_Report_light.html")
    build("dark", OUT)
    build("light", LIGHT)
    # artifact fragments (no doctype/head/body wrappers — for hosted Artifact publishing)
    build("dark", os.path.join(HERE, "ARGUS_Report_artifact.html"), fragment=True)
    build("light", os.path.join(HERE, "ARGUS_Report_light_artifact.html"), fragment=True)
