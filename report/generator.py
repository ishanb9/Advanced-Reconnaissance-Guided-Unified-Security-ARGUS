"""
KALI PENTEST PLATFORM v2 — Report Generator
Queries MongoDB for full session data, renders Jinja2 HTML template,
optionally converts to PDF with wkhtmltopdf.

Usage:
  report = ReportGenerator()
  html   = await report.generate_html(session_id)
  pdf    = await report.generate_pdf(session_id)     # returns bytes

API endpoints (added to agent_server.py):
  GET /sessions/{id}/report?format=html|pdf
"""

import asyncio, os, re, subprocess, tempfile
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from jinja2 import Environment, BaseLoader

import db.mongo_client as db


REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Pentest Report — {{ session.target_ip }}</title>
<style>
  :root {
    --primary: #1a2332;
    --accent:  #00d4ff;
    --red:     #e53e3e;
    --orange:  #dd6b20;
    --yellow:  #d69e2e;
    --blue:    #3182ce;
    --green:   #38a169;
    --gray:    #718096;
    --light:   #f7fafc;
    --border:  #e2e8f0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "Segoe UI", Arial, sans-serif; font-size: 13px; color: #1a202c; line-height: 1.6; background: #fff; }
  .cover { background: linear-gradient(135deg, #0a0c10 0%, #1a2332 100%); color: #fff; padding: 80px 60px; min-height: 300px; page-break-after: always; }
  .cover h1 { font-size: 32px; font-weight: 700; margin-bottom: 8px; color: #00d4ff; letter-spacing: -0.5px; }
  .cover .subtitle { font-size: 14px; color: #a0aec0; margin-bottom: 40px; }
  .cover .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 32px; }
  .cover .meta-item label { display: block; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #718096; margin-bottom: 2px; }
  .cover .meta-item value { font-size: 14px; color: #e2e8f0; font-family: monospace; }
  .cover .classification { display: inline-block; padding: 4px 16px; border: 1px solid #e53e3e; color: #e53e3e; font-size: 11px; letter-spacing: 2px; text-transform: uppercase; border-radius: 3px; margin-bottom: 16px; }
  .toc { padding: 40px 60px; border-bottom: 2px solid var(--border); page-break-after: always; }
  .toc h2 { font-size: 20px; margin-bottom: 20px; color: var(--primary); }
  .toc ol { list-style: decimal; padding-left: 20px; }
  .toc li { margin-bottom: 6px; }
  .toc a { color: var(--accent); text-decoration: none; }
  .page { padding: 40px 60px; }
  h2.section { font-size: 22px; color: var(--primary); border-bottom: 2px solid var(--accent); padding-bottom: 8px; margin: 32px 0 20px 0; }
  h3.subsection { font-size: 16px; color: var(--primary); margin: 24px 0 12px 0; }
  .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 24px 0; }
  .stat-box { padding: 20px; border-radius: 8px; text-align: center; border: 1px solid var(--border); }
  .stat-box .num { font-size: 36px; font-weight: 700; }
  .stat-box .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--gray); }
  .stat-box.critical { border-color: #e53e3e; background: #fff5f5; } .stat-box.critical .num { color: #e53e3e; }
  .stat-box.high     { border-color: #dd6b20; background: #fffaf0; } .stat-box.high .num     { color: #dd6b20; }
  .stat-box.medium   { border-color: #d69e2e; background: #fffff0; } .stat-box.medium .num   { color: #d69e2e; }
  .stat-box.low      { border-color: #3182ce; background: #ebf8ff; } .stat-box.low .num      { color: #3182ce; }
  .stat-box.info     { border-color: #718096; background: #f7fafc; } .stat-box.info .num     { color: #718096; }
  .stat-box.total    { border-color: var(--primary); background: var(--light); } .stat-box.total .num { color: var(--primary); }
  .finding { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
  .finding-header { padding: 12px 16px; display: flex; align-items: center; gap: 12px; }
  .finding-header.critical { background: #fff5f5; border-bottom: 1px solid #fed7d7; }
  .finding-header.high     { background: #fffaf0; border-bottom: 1px solid #fbd38d; }
  .finding-header.medium   { background: #fffff0; border-bottom: 1px solid #fefcbf; }
  .finding-header.low      { background: #ebf8ff; border-bottom: 1px solid #bee3f8; }
  .finding-header.info     { background: #f7fafc; border-bottom: 1px solid #e2e8f0; }
  .sev-badge { padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; color: #fff; }
  .sev-badge.critical { background: #e53e3e; }
  .sev-badge.high     { background: #dd6b20; }
  .sev-badge.medium   { background: #d69e2e; color: #1a202c; }
  .sev-badge.low      { background: #3182ce; }
  .sev-badge.info     { background: #718096; }
  .finding-body { padding: 14px 16px; }
  .finding-title { font-weight: 600; font-size: 14px; color: var(--primary); }
  .finding-meta { font-size: 11px; color: var(--gray); font-family: monospace; margin-top: 4px; }
  .finding-desc { margin-top: 10px; font-size: 13px; color: #2d3748; }
  .cve-badge { display: inline-block; padding: 2px 7px; background: #ebf8ff; border: 1px solid #90cdf4; border-radius: 4px; font-size: 10px; font-family: monospace; color: #2b6cb0; margin: 2px; }
  .raw-output { background: #0d1117; color: #e2e8f0; font-family: monospace; font-size: 11px; padding: 12px; border-radius: 6px; max-height: 300px; overflow: auto; white-space: pre-wrap; word-break: break-all; margin-top: 10px; }
  .flag-box { background: linear-gradient(135deg, #1a2332, #0d1117); color: #00d4ff; padding: 20px; border-radius: 8px; margin: 12px 0; border: 1px solid rgba(0,212,255,0.3); font-family: monospace; }
  .flag-box .flag-type { font-size: 11px; color: #a0aec0; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
  .flag-box .flag-value { font-size: 16px; font-weight: 700; letter-spacing: 1px; }
  .phase-timeline { display: flex; gap: 8px; flex-wrap: wrap; margin: 16px 0; }
  .phase-chip { padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .phase-chip.done { background: #c6f6d5; color: #276749; }
  .phase-chip.skipped { background: #e2e8f0; color: #718096; }
  .info-table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  .info-table th { text-align: left; padding: 8px 12px; background: var(--light); border: 1px solid var(--border); font-size: 11px; text-transform: uppercase; color: var(--gray); }
  .info-table td { padding: 8px 12px; border: 1px solid var(--border); font-size: 13px; }
  .info-table tr:nth-child(even) td { background: #f7fafc; }
  .executive-summary { background: #f7fafc; border-left: 4px solid var(--accent); padding: 20px 24px; border-radius: 0 8px 8px 0; margin: 20px 0; white-space: pre-wrap; line-height: 1.8; }
  .footer { margin-top: 60px; padding: 20px 60px; border-top: 1px solid var(--border); font-size: 11px; color: var(--gray); display: flex; justify-content: space-between; }
  @media print {
    .page { page-break-inside: avoid; }
    .finding { page-break-inside: avoid; }
  }
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
  <div class="classification">CONFIDENTIAL</div>
  <h1>Penetration Test Report</h1>
  <div class="subtitle">Security Assessment — Kali Pentest Platform v2</div>
  <div class="meta-grid">
    <div class="meta-item"><label>Target</label><value>{{ session.target_ip }}</value></div>
    <div class="meta-item"><label>Hostname</label><value>{{ session.target_hostname or "N/A" }}</value></div>
    <div class="meta-item"><label>OS / Type</label><value>{{ session.target_type | upper }}</value></div>
    <div class="meta-item"><label>OS Fingerprint</label><value>{{ intel.os_guess or "Unknown" }}</value></div>
    <div class="meta-item"><label>Assessment Date</label><value>{{ session.started_at[:10] }}</value></div>
    <div class="meta-item"><label>Duration</label><value>{{ duration }}</value></div>
    <div class="meta-item"><label>Total Findings</label><value>{{ summary.total }}</value></div>
    <div class="meta-item"><label>Flags Captured</label><value>{{ flags | length }}</value></div>
  </div>
</div>

<!-- TABLE OF CONTENTS -->
<div class="toc">
  <h2>Table of Contents</h2>
  <ol>
    <li><a href="#executive-summary">Executive Summary</a></li>
    <li><a href="#scope">Scope & Methodology</a></li>
    <li><a href="#findings-summary">Findings Summary</a></li>
    <li><a href="#findings-detail">Detailed Findings</a></li>
    {% if flags %}<li><a href="#flags">Flags Captured</a></li>{% endif %}
    <li><a href="#attack-path">Attack Path</a></li>
    <li><a href="#remediation">Remediation Recommendations</a></li>
  </ol>
</div>

<div class="page">

<!-- EXECUTIVE SUMMARY -->
<h2 class="section" id="executive-summary">1. Executive Summary</h2>
<div class="executive-summary">{{ executive_summary or "No executive summary generated." }}</div>

<!-- SCOPE -->
<h2 class="section" id="scope">2. Scope & Methodology</h2>
<table class="info-table">
  <tr><th>Parameter</th><th>Value</th></tr>
  <tr><td>Target IP / CIDR</td><td><code>{{ session.target_ip }}</code></td></tr>
  <tr><td>Scope Notes</td><td>{{ session.scope or "N/A" }}</td></tr>
  <tr><td>Phases Executed</td><td>
    <div class="phase-timeline">
      {% for phase in all_phases %}
      <span class="phase-chip {{ 'done' if phase in phases_completed else 'skipped' }}">
        {{ phase.upper() }}
      </span>
      {% endfor %}
    </div>
  </td></tr>
  <tr><td>Open Ports</td><td><code>{{ intel.open_ports | join(", ") or "None detected" }}</code></td></tr>
  <tr><td>Services Detected</td><td>{{ intel.services | length }} service(s)</td></tr>
  <tr><td>Shell Access</td><td>{{ "YES" if intel.shell_access else "NO" }}</td></tr>
  <tr><td>Assessment Notes</td><td>{{ session.notes or "N/A" }}</td></tr>
</table>

{% if intel.services %}
<h3 class="subsection">Discovered Services</h3>
<table class="info-table">
  <tr><th>Port</th><th>Service</th><th>Version</th><th>Protocol</th></tr>
  {% for port, svc in intel.services.items() %}
  <tr>
    <td><code>{{ port }}</code></td>
    <td>{{ svc.service }}</td>
    <td>{{ svc.version or "—" }}</td>
    <td>{{ svc.protocol or "tcp" }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

<!-- FINDINGS SUMMARY -->
<h2 class="section" id="findings-summary">3. Findings Summary</h2>
<div class="summary-grid">
  <div class="stat-box critical"><div class="num">{{ summary.critical }}</div><div class="lbl">Critical</div></div>
  <div class="stat-box high">   <div class="num">{{ summary.high }}</div>    <div class="lbl">High</div></div>
  <div class="stat-box medium"> <div class="num">{{ summary.medium }}</div>  <div class="lbl">Medium</div></div>
  <div class="stat-box low">    <div class="num">{{ summary.low }}</div>     <div class="lbl">Low</div></div>
  <div class="stat-box info">   <div class="num">{{ summary.info }}</div>    <div class="lbl">Info</div></div>
  <div class="stat-box total">  <div class="num">{{ summary.total }}</div>   <div class="lbl">Total</div></div>
</div>

<!-- DETAILED FINDINGS -->
<h2 class="section" id="findings-detail">4. Detailed Findings</h2>
{% if findings %}
  {% for f in findings %}
  <div class="finding">
    <div class="finding-header {{ f.severity }}">
      <span class="sev-badge {{ f.severity }}">{{ f.severity | upper }}</span>
      <span class="finding-title">{{ f.title }}</span>
    </div>
    <div class="finding-body">
      <div class="finding-meta">
        Host: {{ f.host }}{% if f.port %}:{{ f.port }}{% endif %}
        {% if f.service %} | Service: {{ f.service }}{% endif %}
        {% if f.tool_used %} | Tool: {{ f.tool_used }}{% endif %}
        | Found: {{ f.found_at[:19] if f.found_at else "N/A" }}
      </div>
      <div class="finding-desc">{{ f.description }}</div>
      {% if f.cves %}
      <div style="margin-top: 8px;">
        {% for cve in f.cves %}
        <span class="cve-badge">{{ cve }}</span>
        {% endfor %}
      </div>
      {% endif %}
      {% if f.raw_output %}
      <div class="raw-output">{{ f.raw_output[:1500] }}{% if f.raw_output | length > 1500 %}...{% endif %}</div>
      {% endif %}
      {% if f.remediation %}
      <div style="margin-top: 10px; padding: 10px; background: #f0fff4; border-radius: 6px; border-left: 3px solid #38a169; font-size: 12px;">
        <strong>Remediation:</strong> {{ f.remediation }}
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
{% else %}
<p style="color: #718096;">No findings recorded.</p>
{% endif %}

<!-- FLAGS -->
{% if flags %}
<h2 class="section" id="flags">5. Flags Captured</h2>
{% for flag in flags %}
<div class="flag-box">
  <div class="flag-type">{{ flag.flag_type | upper }} FLAG — found by {{ flag.found_by }}</div>
  <div class="flag-value">{{ flag.value }}</div>
  <div style="font-size: 11px; color: #a0aec0; margin-top: 4px;">Location: {{ flag.location }}</div>
  {% if flag.context %}<div style="font-size: 12px; color: #718096; margin-top: 4px;">{{ flag.context }}</div>{% endif %}
</div>
{% endfor %}
{% endif %}

<!-- ATTACK PATH -->
<h2 class="section" id="attack-path">{% if flags %}6{% else %}5{% endif %}. Attack Path</h2>
{% if graph.nodes %}
<table class="info-table">
  <tr><th>Type</th><th>Label</th><th>Host</th><th>Port</th><th>Phase</th></tr>
  {% for node in graph.nodes %}
  <tr>
    <td>{{ node.node_type }}</td>
    <td>{{ node.label }}</td>
    <td>{{ node.host or "—" }}</td>
    <td>{{ node.port or "—" }}</td>
    <td>{{ node.phase or "—" }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p style="color: #718096;">No attack graph data available.</p>
{% endif %}

<!-- REMEDIATION -->
<h2 class="section" id="remediation">{% if flags %}7{% else %}6{% endif %}. Remediation Recommendations</h2>
<table class="info-table">
  <tr><th>#</th><th>Priority</th><th>Finding</th><th>Action</th></tr>
  {% set ns = namespace(i=1) %}
  {% for f in findings if f.severity in ("critical", "high") %}
  <tr>
    <td>{{ ns.i }}</td>
    <td><span class="sev-badge {{ f.severity }}">{{ f.severity | upper }}</span></td>
    <td>{{ f.title }}</td>
    <td>{{ f.remediation or "Review and patch immediately. Consult vendor advisories." }}</td>
  </tr>
  {% set ns.i = ns.i + 1 %}
  {% endfor %}
  {% for f in findings if f.severity == "medium" %}
  <tr>
    <td>{{ ns.i }}</td>
    <td><span class="sev-badge medium">MEDIUM</span></td>
    <td>{{ f.title }}</td>
    <td>{{ f.remediation or "Schedule remediation within 30 days." }}</td>
  </tr>
  {% set ns.i = ns.i + 1 %}
  {% endfor %}
</table>

</div>
<div class="footer">
  <span>Kali Pentest Platform v2 — Auto-generated Report</span>
  <span>Generated: {{ generated_at }}</span>
</div>
</body>
</html>
"""


class ReportGenerator:
    """Generates HTML and PDF pentest reports from MongoDB session data."""

    def __init__(self):
        self._jinja_env = Environment(loader=BaseLoader())
        self._template  = self._jinja_env.from_string(REPORT_TEMPLATE)

    async def generate_html(self, session_id: str) -> str:
        """Build and return full HTML report string."""
        ctx = await self._build_context(session_id)
        return self._template.render(**ctx)

    async def generate_pdf(self, session_id: str) -> Optional[bytes]:
        """
        Generate PDF via wkhtmltopdf.
        Returns bytes or None if wkhtmltopdf unavailable.
        """
        html = await self.generate_html(session_id)

        # Write HTML to temp file
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as hf:
            hf.write(html)
            html_path = hf.name

        pdf_path = html_path.replace(".html", ".pdf")

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["wkhtmltopdf",
                     "--page-size", "A4",
                     "--margin-top", "15mm",
                     "--margin-bottom", "15mm",
                     "--margin-left", "15mm",
                     "--margin-right", "15mm",
                     "--enable-local-file-access",
                     html_path, pdf_path],
                    capture_output=True, timeout=60
                )
            )
            if result.returncode == 0 and os.path.exists(pdf_path):
                with open(pdf_path, "rb") as f:
                    return f.read()
            else:
                print(f"[REPORT] wkhtmltopdf error: {result.stderr.decode()[:500]}")
                return None
        except FileNotFoundError:
            print("[REPORT] wkhtmltopdf not found. Install: apt install wkhtmltopdf")
            return None
        except subprocess.TimeoutExpired:
            print("[REPORT] wkhtmltopdf timed out")
            return None
        finally:
            for p in (html_path, pdf_path):
                try:
                    os.unlink(p)
                except Exception:
                    pass

    async def _build_context(self, session_id: str) -> Dict:
        """Query MongoDB and build template context."""
        session  = await db.get_session(session_id) or {}
        findings = await db.get_findings(session_id)
        summary  = await db.get_findings_summary(session_id)
        flags    = await db.get_flags(session_id)
        graph    = await db.get_attack_graph(session_id)
        logs     = await db.get_agent_logs(session_id, limit=5)

        # Duration
        duration = "N/A"
        try:
            started = datetime.fromisoformat(session["started_at"].replace("Z", ""))
            ended   = datetime.fromisoformat(
                (session.get("completed_at") or datetime.utcnow().isoformat()).replace("Z", "")
            )
            delta = ended - started
            h, rem = divmod(int(delta.total_seconds()), 3600)
            m, s   = divmod(rem, 60)
            duration = f"{h}h {m}m {s}s"
        except Exception:
            pass

        # Intel from flags_found on session
        intel = {
            "os_guess":    session.get("target_type", "unknown"),
            "open_ports":  [],
            "services":    {},
            "shell_access": any(f.get("flag_type") == "user" for f in flags),
        }

        # Try to rebuild intel from logs (agent decisions include intel snapshots)
        # This is best-effort from what agents stored
        for log in logs:
            msg = log.get("message", "")
            if "open_ports" in msg:
                try:
                    import json as _j
                    data = _j.loads(msg)
                    intel.update(data)
                except Exception:
                    pass

        all_phases = [
            "recon", "scan", "vuln_id", "osint",
            "exploit", "post_exploit", "privesc", "persistence", "reporting"
        ]

        # Executive summary: get from master agent report_ready event log
        executive_summary = "This automated penetration test identified several security issues on the target system. Review the detailed findings below and prioritise remediation of critical and high severity issues immediately."

        # Check if report_ready log entry exists with summary
        log_handle = db.get_db()
        rep_log = await log_handle.agent_logs.find_one({
            "session_id": session_id, "action": "status_change:thinking->done"
        })

        return {
            "session":           session,
            "findings":          findings,
            "summary":           summary,
            "flags":             flags,
            "graph":             graph,
            "intel":             intel,
            "duration":          duration,
            "phases_completed":  session.get("phases_completed", []),
            "all_phases":        all_phases,
            "executive_summary": executive_summary,
            "generated_at":      datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        }
