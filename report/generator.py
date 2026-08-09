"""
ARGUS Pentest Platform — Report Generator
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


def _clean_finding_title(title: Any) -> str:
    """Turn a raw scanner-output title into a short, clean report title.

    Web scanners (ZAP/nikto/…) store a whole alert sentence as the finding title
    ("[007352] /: The X-Content-Type-Options header is not set. This could allow the
    user agent to render…"), which the register then truncates mid-word.  Strip the
    plugin-id + path prefix and tool-status markers, and cap a verbose title at the
    first sentence / a WORD boundary so it reads cleanly and never cuts mid-word.
    The caller keeps the full original text in the finding description."""
    t = " ".join(str(title or "").split())
    if not t:
        return ""
    t = re.sub(r"^\[\d{3,}\]\s*", "", t)          # "[007352] " ZAP/nikto plugin id
    t = re.sub(r"^/[^\s:]*:\s+", "", t)           # "/: " or "/path: " location prefix
    t = re.sub(r"^\[(FAIL|ERROR|WARN|EXIT\s*\d+)\]\s*", "", t, flags=re.I)  # tool status
    t = t.strip()
    if len(t) > 72:
        first = re.split(r"(?<=[.;:])\s", t, maxsplit=1)[0].strip().rstrip(".;:,")
        t = first if 8 <= len(first) <= 72 else (t[:71].rsplit(" ", 1)[0].rstrip(",.;:") + "…")
    return t


# ANSI CSI / escape sequences (colour codes from commix, sqlmap, metasploit, …) and
# other C0 control bytes render as tofu boxes (□[1m□[0m) in the PDF — WeasyPrint has
# no terminal to interpret them.  Strip them so a tool's coloured banner shows as
# clean text instead of garbage.  Applied to every finding's evidence at render time.
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")   # CSI: ESC [ … final-byte
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")  # OSC: ESC ] … BEL/ST
_ANSI_OTHER_RE = re.compile(r"\x1b[@-Z\\-_]")            # other two-char ESC sequences
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # C0 ctrls except \t \n \r


def _sanitize_evidence(text: Any) -> str:
    """Strip terminal control sequences from captured tool output so evidence
    blocks render as clean monospace text (no ``□[1m`` tofu).  Preserves the
    actual content — only the non-printable escape/colour bytes are removed."""
    if not text:
        return "" if text is None else str(text)
    s = str(text)
    if "\x1b" in s:
        s = _ANSI_OSC_RE.sub("", s)
        s = _ANSI_CSI_RE.sub("", s)
        s = _ANSI_OTHER_RE.sub("", s)
    s = _CTRL_RE.sub("", s)
    return s


REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ARGUS Pentest Report — {{ session.target_ip }}</title>
<style>
  /* ── Variables ─────────────────────────────────────────── */
  :root {
    --bg:        #0b0d12;
    --surface:   #111520;
    --surface2:  #161b28;
    --border:    #1e2638;
    --accent:    #00d4ff;
    --accent2:   #0099bb;
    --text:      #d4dbe8;
    --text-dim:  #697080;
    --critical:  #ff4d4d;
    --high:      #ff8c42;
    --medium:    #f5c518;
    --low:       #4da6ff;
    --info:      #8899aa;
    --green:     #2ecc71;
    --radius:    8px;
    --font-mono: "JetBrains Mono", "Fira Code", "Consolas", monospace;
    --font-sans: "Inter", "Segoe UI", system-ui, sans-serif;
  }

  /* ── Reset ──────────────────────────────────────────────── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.65;
    color: var(--text);
    background: var(--bg);
  }

  /* ── Layout ─────────────────────────────────────────────── */
  .page-wrap { max-width: 1100px; margin: 0 auto; padding: 0 32px 80px; }

  /* ── Cover ──────────────────────────────────────────────── */
  .cover {
    background: linear-gradient(160deg, #070910 0%, #0e1422 60%, #091624 100%);
    padding: 72px 64px 56px;
    border-bottom: 1px solid var(--border);
    position: relative;
    overflow: hidden;
    page-break-after: always;
  }
  .cover::before {
    content: "";
    position: absolute;
    top: -120px; right: -120px;
    width: 480px; height: 480px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(0,212,255,.07) 0%, transparent 70%);
    pointer-events: none;
  }
  .cover-logo {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 52px;
  }
  .cover-logo svg { width: 40px; height: 40px; flex-shrink: 0; }
  .cover-logo-text { font-size: 22px; font-weight: 700; letter-spacing: 4px; color: var(--accent); }
  .cover-logo-sub  { font-size: 11px; letter-spacing: 2px; color: var(--text-dim); text-transform: uppercase; margin-top: 1px; }
  .cover-badge {
    display: inline-block;
    border: 1px solid var(--critical);
    color: var(--critical);
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    padding: 3px 14px;
    border-radius: 3px;
    margin-bottom: 24px;
  }
  .cover h1 {
    font-size: 42px;
    font-weight: 800;
    color: #fff;
    letter-spacing: -1px;
    line-height: 1.1;
    margin-bottom: 10px;
  }
  .cover h1 span { color: var(--accent); }
  .cover-sub {
    font-size: 14px;
    color: var(--text-dim);
    margin-bottom: 52px;
    letter-spacing: 0.5px;
  }
  .cover-meta {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 20px;
    padding-top: 32px;
    border-top: 1px solid var(--border);
  }
  .cover-meta-item label {
    display: block;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--text-dim);
    margin-bottom: 5px;
  }
  .cover-meta-item value {
    display: block;
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--text);
  }

  /* ── Risk Banner ────────────────────────────────────────── */
  .risk-banner {
    display: flex;
    align-items: center;
    gap: 24px;
    padding: 20px 28px;
    border-radius: var(--radius);
    margin: 32px 0;
    border: 1px solid;
  }
  .risk-banner.critical { background: rgba(255,77,77,.08);  border-color: rgba(255,77,77,.3);  }
  .risk-banner.high     { background: rgba(255,140,66,.08); border-color: rgba(255,140,66,.3); }
  .risk-banner.medium   { background: rgba(245,197,24,.07); border-color: rgba(245,197,24,.3); }
  .risk-banner.low      { background: rgba(77,166,255,.07); border-color: rgba(77,166,255,.3); }
  .risk-banner .risk-label { font-size: 11px; text-transform: uppercase; letter-spacing: 2px; color: var(--text-dim); }
  .risk-banner .risk-value { font-size: 28px; font-weight: 800; letter-spacing: 1px; }
  .risk-banner.critical .risk-value { color: var(--critical); }
  .risk-banner.high     .risk-value { color: var(--high); }
  .risk-banner.medium   .risk-value { color: var(--medium); }
  .risk-banner.low      .risk-value { color: var(--low); }
  .risk-banner .risk-desc { font-size: 13px; color: var(--text-dim); }

  /* ── Table of Contents ──────────────────────────────────── */
  .toc {
    padding: 40px 0;
    border-bottom: 1px solid var(--border);
    page-break-after: always;
  }
  .toc-title { font-size: 13px; text-transform: uppercase; letter-spacing: 2px; color: var(--text-dim); margin-bottom: 20px; }
  .toc-list { list-style: none; }
  .toc-list li { display: flex; align-items: center; padding: 9px 0; border-bottom: 1px solid rgba(30,38,56,.6); }
  .toc-list li:last-child { border-bottom: none; }
  .toc-num { font-family: var(--font-mono); font-size: 11px; color: var(--accent); width: 28px; flex-shrink: 0; }
  .toc-list a { color: var(--text); text-decoration: none; font-size: 14px; flex: 1; }
  .toc-list a:hover { color: var(--accent); }
  .toc-dots { flex: 1; border-bottom: 1px dotted var(--border); margin: 0 12px; }

  /* ── Sections ───────────────────────────────────────────── */
  .section-header {
    display: flex;
    align-items: flex-end;
    gap: 16px;
    margin: 56px 0 24px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }
  .section-num {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--accent);
    letter-spacing: 1px;
    padding-bottom: 2px;
  }
  .section-title {
    font-size: 22px;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.3px;
  }

  /* ── Stat Tiles ─────────────────────────────────────────── */
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    margin: 24px 0 32px;
  }
  .stat-tile {
    padding: 18px 12px;
    border-radius: var(--radius);
    background: var(--surface);
    border: 1px solid var(--border);
    text-align: center;
  }
  .stat-tile .num { font-size: 34px; font-weight: 800; line-height: 1; margin-bottom: 6px; }
  .stat-tile .lbl { font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px; color: var(--text-dim); }
  .stat-tile.critical { border-color: rgba(255,77,77,.35);  } .stat-tile.critical .num { color: var(--critical); }
  .stat-tile.high     { border-color: rgba(255,140,66,.35); } .stat-tile.high     .num { color: var(--high); }
  .stat-tile.medium   { border-color: rgba(245,197,24,.35); } .stat-tile.medium   .num { color: var(--medium); }
  .stat-tile.low      { border-color: rgba(77,166,255,.35); } .stat-tile.low      .num { color: var(--low); }
  .stat-tile.info-sev { border-color: rgba(136,153,170,.3); } .stat-tile.info-sev .num { color: var(--info); }
  .stat-tile.total    { border-color: rgba(0,212,255,.2);   } .stat-tile.total    .num { color: var(--accent); }

  /* ── Executive Summary ──────────────────────────────────── */
  .exec-summary {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 0 var(--radius) var(--radius) 0;
    padding: 24px 28px;
    font-size: 14px;
    line-height: 1.85;
    color: var(--text);
    white-space: pre-wrap;
    margin: 20px 0;
  }

  /* ── Info Table ─────────────────────────────────────────── */
  .info-table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  .info-table th {
    text-align: left;
    padding: 10px 14px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--text-dim);
    background: var(--surface2);
    border: 1px solid var(--border);
  }
  .info-table td {
    padding: 10px 14px;
    border: 1px solid var(--border);
    font-size: 13px;
    background: var(--surface);
    vertical-align: top;
  }
  .info-table tr:nth-child(even) td { background: var(--surface2); }
  code {
    font-family: var(--font-mono);
    font-size: 12px;
    background: rgba(0,212,255,.07);
    border: 1px solid rgba(0,212,255,.15);
    padding: 1px 6px;
    border-radius: 4px;
    color: var(--accent);
  }

  /* ── Phase Timeline ─────────────────────────────────────── */
  .phase-row { display: flex; flex-wrap: wrap; gap: 8px; }
  .phase-chip {
    padding: 4px 14px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
  }
  .phase-chip.done    { background: rgba(46,204,113,.12); border: 1px solid rgba(46,204,113,.3); color: #2ecc71; }
  .phase-chip.skipped { background: var(--surface2); border: 1px solid var(--border); color: var(--text-dim); }

  /* ── Service Table ──────────────────────────────────────── */
  .port-badge {
    font-family: var(--font-mono);
    font-size: 11px;
    background: rgba(0,212,255,.08);
    border: 1px solid rgba(0,212,255,.15);
    color: var(--accent);
    padding: 2px 8px;
    border-radius: 4px;
  }

  /* ── Finding Cards ──────────────────────────────────────── */
  .finding {
    border-radius: var(--radius);
    border: 1px solid var(--border);
    margin-bottom: 16px;
    overflow: hidden;
    background: var(--surface);
  }
  .finding-header {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
  }
  .finding-header.critical { background: rgba(255,77,77,.06);  }
  .finding-header.high     { background: rgba(255,140,66,.06); }
  .finding-header.medium   { background: rgba(245,197,24,.05); }
  .finding-header.low      { background: rgba(77,166,255,.05); }
  .finding-header.info     { background: rgba(136,153,170,.04); }
  .sev-badge {
    padding: 3px 12px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    flex-shrink: 0;
  }
  .sev-badge.critical { background: rgba(255,77,77,.15);  color: var(--critical); border: 1px solid rgba(255,77,77,.4);  }
  .sev-badge.high     { background: rgba(255,140,66,.15); color: var(--high);     border: 1px solid rgba(255,140,66,.4); }
  .sev-badge.medium   { background: rgba(245,197,24,.12); color: var(--medium);   border: 1px solid rgba(245,197,24,.4); }
  .sev-badge.low      { background: rgba(77,166,255,.1);  color: var(--low);      border: 1px solid rgba(77,166,255,.3); }
  .sev-badge.info     { background: rgba(136,153,170,.1); color: var(--info);     border: 1px solid rgba(136,153,170,.3); }
  .finding-title { font-weight: 600; font-size: 15px; color: #fff; flex: 1; }
  .finding-body  { padding: 16px 18px; }
  .finding-meta  { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); margin-bottom: 10px; }
  .finding-meta span { margin-right: 14px; }
  .finding-desc  { font-size: 13px; color: var(--text); line-height: 1.75; }
  .cve-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
  .cve-tag {
    font-family: var(--font-mono);
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 4px;
    background: rgba(77,166,255,.1);
    border: 1px solid rgba(77,166,255,.2);
    color: var(--low);
  }
  .raw-output {
    margin-top: 12px;
    background: #060810;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px 16px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: #9aacbf;
    max-height: 260px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .remediation-block {
    margin-top: 12px;
    padding: 12px 16px;
    background: rgba(46,204,113,.06);
    border: 1px solid rgba(46,204,113,.2);
    border-radius: 6px;
    font-size: 13px;
    color: #9aefbe;
  }
  .remediation-block strong { color: var(--green); }

  /* ── Flag Cards ─────────────────────────────────────────── */
  .flag-card {
    display: flex;
    align-items: center;
    gap: 20px;
    background: linear-gradient(135deg, #0b1020, #0d1828);
    border: 1px solid rgba(0,212,255,.2);
    border-radius: var(--radius);
    padding: 20px 24px;
    margin-bottom: 12px;
  }
  .flag-icon { font-size: 28px; }
  .flag-type-label { font-size: 10px; text-transform: uppercase; letter-spacing: 2px; color: var(--text-dim); margin-bottom: 4px; }
  .flag-value { font-family: var(--font-mono); font-size: 16px; font-weight: 700; color: var(--accent); letter-spacing: 1px; }
  .flag-location { font-size: 12px; color: var(--text-dim); margin-top: 4px; }

  /* ── Objectives (CTF / engagement questions) ──────────────── */
  .obj-progress {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 12px 0 20px;
    font-size: 13px;
    color: var(--text-dim);
  }
  .obj-progress-bar {
    flex: 1;
    height: 6px;
    border-radius: 3px;
    background: var(--surface2);
    overflow: hidden;
  }
  .obj-progress-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent2), var(--accent));
  }
  .obj-row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 10px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 8px;
    background: var(--surface);
  }
  .obj-row.answered { border-color: rgba(46,204,113,.35); background: rgba(46,204,113,.05); }
  .obj-check {
    flex-shrink: 0;
    width: 22px; height: 22px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text-dim);
    font-weight: 700;
  }
  .obj-row.answered .obj-check { background: rgba(46,204,113,.12); border-color: var(--green); color: var(--green); }
  .obj-body { flex: 1; min-width: 0; }
  .obj-question { font-size: 13px; color: var(--text); margin-bottom: 4px; line-height: 1.4; }
  .obj-section { font-size: 10px; letter-spacing: 1.5px; color: var(--text-dim); text-transform: uppercase; margin-right: 8px; }
  .obj-answer {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--green);
    background: rgba(46,204,113,.08);
    border-radius: 4px;
    padding: 4px 8px;
    margin-top: 4px;
    word-break: break-all;
  }
  .obj-meta { font-size: 10px; color: var(--text-dim); margin-top: 4px; }

  /* ── Reasoning Journal ────────────────────────────────────── */
  .journal-wrap {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface);
    overflow: hidden;
    margin-top: 16px;
  }
  .journal-entry {
    display: flex;
    gap: 12px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
  }
  .journal-entry:last-child { border-bottom: none; }
  .journal-idx {
    flex-shrink: 0;
    width: 40px;
    font-family: var(--font-mono);
    color: var(--accent);
    font-weight: 700;
  }
  .journal-text { flex: 1; color: var(--text); line-height: 1.5; word-break: break-word; }
  .journal-note {
    font-size: 11px;
    color: var(--text-dim);
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    background: var(--surface2);
  }

  /* ── MITRE Table ─────────────────────────────────────────── */
  .mitre-badge {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 2px 8px;
    background: rgba(0,212,255,.07);
    border: 1px solid rgba(0,212,255,.15);
    color: var(--accent);
    border-radius: 4px;
    white-space: nowrap;
  }
  .tactic-badge {
    font-size: 10px;
    padding: 2px 10px;
    border-radius: 20px;
    background: rgba(245,197,24,.1);
    border: 1px solid rgba(245,197,24,.25);
    color: var(--medium);
    white-space: nowrap;
  }

  /* ── Attack Path ─────────────────────────────────────────── */
  .attack-path { list-style: none; position: relative; padding-left: 28px; }
  .attack-path::before {
    content: "";
    position: absolute;
    left: 8px; top: 8px; bottom: 8px;
    width: 2px;
    background: linear-gradient(to bottom, var(--accent), transparent);
  }
  .attack-step {
    position: relative;
    padding: 12px 0 12px 20px;
  }
  .attack-step::before {
    content: "";
    position: absolute;
    left: -4px; top: 18px;
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--accent);
    border: 2px solid var(--bg);
  }
  .attack-step-phase {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--accent);
    margin-bottom: 3px;
  }
  .attack-step-result { font-size: 13px; color: var(--text); }

  /* ── Remediation Table ───────────────────────────────────── */
  .priority-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 6px;
  }
  .priority-dot.critical { background: var(--critical); }
  .priority-dot.high     { background: var(--high); }
  .priority-dot.medium   { background: var(--medium); }

  /* ── Footer ─────────────────────────────────────────────── */
  .report-footer {
    margin-top: 80px;
    padding: 24px 0;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 11px;
    color: var(--text-dim);
  }
  .footer-brand { display: flex; align-items: center; gap: 8px; }
  .footer-brand svg { width: 18px; height: 18px; opacity: .6; }

  /* ── Print ───────────────────────────────────────────────── */
  @media print {
    body { background: #fff; color: #000; }
    .cover { background: #000 !important; }
    .finding, .flag-card { page-break-inside: avoid; }
    .section-header { page-break-after: avoid; }
  }
</style>
</head>
<body>

<!-- ═══════════ COVER PAGE ═══════════ -->
<div class="cover">
  <div class="cover-logo">
    <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="20" cy="20" r="19" stroke="#00d4ff" stroke-width="1.5"/>
      <circle cx="20" cy="20" r="12" stroke="#00d4ff" stroke-width="1" stroke-dasharray="2 3"/>
      <circle cx="20" cy="20" r="4" fill="#00d4ff"/>
      <line x1="20" y1="1" x2="20" y2="8" stroke="#00d4ff" stroke-width="1.5"/>
      <line x1="20" y1="32" x2="20" y2="39" stroke="#00d4ff" stroke-width="1.5"/>
      <line x1="1" y1="20" x2="8" y2="20" stroke="#00d4ff" stroke-width="1.5"/>
      <line x1="32" y1="20" x2="39" y2="20" stroke="#00d4ff" stroke-width="1.5"/>
    </svg>
    <div>
      <div class="cover-logo-text">ARGUS</div>
      <div class="cover-logo-sub">Advanced Reconnaissance & Guided Unified Security</div>
    </div>
  </div>

  <div class="cover-badge">Confidential — Restricted Distribution</div>
  <h1>Penetration Test<br/><span>Security Report</span></h1>
  <div class="cover-sub">Automated AI-Driven Security Assessment</div>

  <div class="cover-meta">
    <div class="cover-meta-item">
      <label>Target</label>
      <value>{{ session.target_ip }}</value>
    </div>
    <div class="cover-meta-item">
      <label>Hostname</label>
      <value>{{ session.target_hostname or "N/A" }}</value>
    </div>
    <div class="cover-meta-item">
      <label>Platform / OS</label>
      <value>{{ (session.target_type or "Unknown") | upper }}</value>
    </div>
    <div class="cover-meta-item">
      <label>Assessment Date</label>
      <value>{{ session.started_at[:10] if session.started_at else "N/A" }}</value>
    </div>
    <div class="cover-meta-item">
      <label>Duration</label>
      <value>{{ duration }}</value>
    </div>
    <div class="cover-meta-item">
      <label>Total Findings</label>
      <value>{{ summary.total }}</value>
    </div>
    <div class="cover-meta-item">
      <label>Flags Captured</label>
      <value>{{ flags | length }}</value>
    </div>
    <div class="cover-meta-item">
      <label>Report Generated</label>
      <value>{{ generated_at }}</value>
    </div>
  </div>
</div>

<div class="page-wrap">

<!-- ═══════════ RISK BANNER ═══════════ -->
{# Canonical verdict from _build_context — identical to every other theme. #}
{% set overall_risk = (final_rating if (final_rating is defined and final_rating and final_rating != 'none') else ("critical" if summary.critical > 0 else ("high" if summary.high > 0 else ("medium" if summary.medium > 0 else "low")))) %}
{% set risk_text = {
  "critical": "Critical Risk — Immediate Action Required",
  "high":     "High Risk — Urgent Remediation Needed",
  "medium":   "Medium Risk — Schedule Remediation",
  "low":      "Low Risk — Monitor and Review",
  "info":     "Informational — Attack Surface Only"
} %}
<div class="risk-banner {{ overall_risk }}" style="margin-top: 40px;">
  <div>
    <div class="risk-label">Overall Risk Rating</div>
    <div class="risk-value">{{ (final_rating_label if final_rating_label is defined and final_rating_label else (overall_risk | upper)) }}</div>
  </div>
  <div class="risk-desc">{{ risk_text[overall_risk] | default("Issues Identified") }}</div>
</div>

<!-- ═══════════ TABLE OF CONTENTS ═══════════ -->
<div class="toc">
  <div class="toc-title">Contents</div>
  <ul class="toc-list">
    <li><span class="toc-num">01</span><a href="#executive-summary">Executive Summary</a></li>
    <li><span class="toc-num">02</span><a href="#scope">Scope &amp; Methodology</a></li>
    <li><span class="toc-num">03</span><a href="#findings-summary">Findings Summary</a></li>
    <li><span class="toc-num">04</span><a href="#findings-detail">Detailed Findings</a></li>
    {% if flags %}<li><span class="toc-num">05</span><a href="#flags">Flags Captured</a></li>{% endif %}
    {% if objectives %}<li><span class="toc-num">{% if flags %}06{% else %}05{% endif %}</span><a href="#objectives">Objectives ({{ objectives_done }}/{{ objectives_total }})</a></li>{% endif %}
    {% set _toc_base = 4 + (1 if flags else 0) + (1 if objectives else 0) %}
    <li><span class="toc-num">0{{ _toc_base + 1 }}</span><a href="#attack-path">Attack Narrative</a></li>
    <li><span class="toc-num">0{{ _toc_base + 2 }}</span><a href="#mitre">MITRE ATT&amp;CK Coverage</a></li>
    <li><span class="toc-num">0{{ _toc_base + 3 }}</span><a href="#remediation">Remediation Roadmap</a></li>
    {% if reasoning_journal %}<li><span class="toc-num">0{{ _toc_base + 4 }}</span><a href="#reasoning-journal">Reasoning Journal</a></li>{% endif %}
  </ul>
</div>

<!-- ═══════════ 1. EXECUTIVE SUMMARY ═══════════ -->
<div class="section-header" id="executive-summary">
  <span class="section-num">01</span>
  <span class="section-title">Executive Summary</span>
</div>
<div class="exec-summary">{{ executive_summary or "No executive summary generated." }}</div>

<!-- ═══════════ 2. SCOPE & METHODOLOGY ═══════════ -->
<div class="section-header" id="scope">
  <span class="section-num">02</span>
  <span class="section-title">Scope &amp; Methodology</span>
</div>
<table class="info-table">
  <tr><th>Parameter</th><th>Value</th></tr>
  <tr><td>Target IP / CIDR</td><td><code>{{ session.target_ip }}</code></td></tr>
  <tr><td>Target Hostname</td><td><code>{{ session.target_hostname or "N/A" }}</code></td></tr>
  <tr><td>OS / Platform</td><td>{{ (session.target_type or "Unknown") | upper }}</td></tr>
  <tr><td>Scope Notes</td><td>{{ session.scope or "Full scope automated assessment" }}</td></tr>
  <tr><td>Assessment Notes</td><td>{{ session.notes or "N/A" }}</td></tr>
  <tr><td>Open Ports Detected</td><td><code>{{ intel.open_ports | join(", ") if intel.open_ports else "None detected" }}</code></td></tr>
  <tr><td>Services Identified</td><td>{{ intel.services | length }} service(s)</td></tr>
  <tr><td>Shell Access Obtained</td><td>
    {% if intel.shell_access %}
      <span style="color: var(--critical); font-weight: 600;">YES — Compromised</span>
    {% else %}
      <span style="color: var(--text-dim);">No</span>
    {% endif %}
  </td></tr>
  <tr><td>Phases Executed</td><td>
    <div class="phase-row">
      {% for phase in all_phases %}
      <span class="phase-chip {{ 'done' if phase in phases_completed else 'skipped' }}">{{ phase | upper }}</span>
      {% endfor %}
    </div>
  </td></tr>
</table>

{% if intel.services %}
<h3 style="font-size:15px; color:#fff; margin: 24px 0 12px; font-weight:600;">Discovered Services</h3>
<table class="info-table">
  <tr><th>Port</th><th>Service</th><th>Version</th><th>Protocol</th></tr>
  {% for port, svc in intel.services.items() %}
  {% set svc_d = svc if svc is mapping else {} %}
  <tr>
    <td><span class="port-badge">{{ port }}</span></td>
    <td>{{ svc_d.get("service", svc) if svc is mapping else svc }}</td>
    <td>{{ svc_d.get("version", "—") if svc is mapping else "—" }}</td>
    <td>{{ svc_d.get("protocol", "tcp") if svc is mapping else "tcp" }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

<!-- ═══════════ 3. FINDINGS SUMMARY ═══════════ -->
<div class="section-header" id="findings-summary">
  <span class="section-num">03</span>
  <span class="section-title">Findings Summary</span>
</div>
<div class="stat-grid">
  <div class="stat-tile critical"><div class="num">{{ summary.critical }}</div><div class="lbl">Critical</div></div>
  <div class="stat-tile high">    <div class="num">{{ summary.high }}</div>    <div class="lbl">High</div></div>
  <div class="stat-tile medium">  <div class="num">{{ summary.medium }}</div>  <div class="lbl">Medium</div></div>
  <div class="stat-tile low">     <div class="num">{{ summary.low }}</div>     <div class="lbl">Low</div></div>
  <div class="stat-tile info-sev"><div class="num">{{ summary.info }}</div>    <div class="lbl">Info</div></div>
  <div class="stat-tile total">   <div class="num">{{ summary.total }}</div>   <div class="lbl">Total</div></div>
</div>

<!-- ═══════════ 4. DETAILED FINDINGS ═══════════ -->
<div class="section-header" id="findings-detail">
  <span class="section-num">04</span>
  <span class="section-title">Detailed Findings</span>
</div>
{% if findings %}
  {% for f in findings %}
  <div class="finding">
    <div class="finding-header {{ f.severity or 'info' }}">
      <span class="sev-badge {{ f.severity or 'info' }}">{{ (f.severity or 'INFO') | upper }}</span>
      <span class="finding-title">{{ f.title }}</span>
    </div>
    <div class="finding-body">
      <div class="finding-meta">
        <span>Host: <code>{{ f.host }}{% if f.port %}:{{ f.port }}{% endif %}</code></span>
        {% if f.service %}<span>Service: {{ f.service }}</span>{% endif %}
        {% if f.tool_used %}<span>Tool: {{ f.tool_used }}</span>{% endif %}
        {% if f.phase %}<span>Phase: {{ f.phase }}</span>{% endif %}
        <span>Found: {{ f.found_at[:19] if f.found_at else "N/A" }}</span>
      </div>
      <div class="finding-desc">{{ f.description }}</div>
      {% if f.cves %}
      <div class="cve-list">
        {% for cve in f.cves %}<span class="cve-tag">{{ cve }}</span>{% endfor %}
      </div>
      {% endif %}
      {% if f.raw_output %}
      <div class="raw-output">{{ f.raw_output[:2000] }}{% if f.raw_output | length > 2000 %}
... [truncated]{% endif %}</div>
      {% endif %}
      {% if f.remediation %}
      <div class="remediation-block"><strong>Remediation:</strong> {{ f.remediation }}</div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
{% else %}
<p style="color: var(--text-dim); padding: 20px 0;">No findings recorded for this session.</p>
{% endif %}

<!-- ═══════════ 5. FLAGS CAPTURED ═══════════ -->
{% if flags %}
<div class="section-header" id="flags">
  <span class="section-num">05</span>
  <span class="section-title">Flags Captured</span>
</div>
{% for flag in flags %}
<div class="flag-card">
  <div class="flag-icon">{{ "🏴" if flag.flag_type == "root" else "🚩" }}</div>
  <div>
    <div class="flag-type-label">{{ (flag.flag_type or "?") | upper }} FLAG — Found by {{ flag.found_by or "agent" }}</div>
    <div class="flag-value">{{ flag.value }}</div>
    <div class="flag-location">Location: {{ flag.location or "Unknown" }}{% if flag.context %} — {{ flag.context }}{% endif %}</div>
  </div>
</div>
{% endfor %}
{% endif %}

<!-- ═══════════ OBJECTIVES (CTF / engagement questions) ═══════════ -->
{% if objectives %}
{% set obj_section_num = "06" if flags else "05" %}
<div class="section-header" id="objectives">
  <span class="section-num">{{ obj_section_num }}</span>
  <span class="section-title">
    Objectives
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      ({{ engagement_type | upper }})
    </span>
  </span>
</div>
<div class="obj-progress">
  <span><strong style="color: var(--accent);">{{ objectives_done }}</strong> / {{ objectives_total }} answered</span>
  <div class="obj-progress-bar">
    <div class="obj-progress-fill" style="width: {{ (objectives_done * 100 / objectives_total) | round(0) if objectives_total else 0 }}%;"></div>
  </div>
  <span>{{ (objectives_done * 100 / objectives_total) | round(0) if objectives_total else 0 }}%</span>
</div>
{% for obj in objectives %}
<div class="obj-row{% if obj.answered %} answered{% endif %}">
  <div class="obj-check">{% if obj.answered %}✓{% else %}{{ obj.index }}{% endif %}</div>
  <div class="obj-body">
    <div class="obj-question">
      {% if obj.section %}<span class="obj-section">{{ obj.section }}</span>{% endif %}
      <strong>[{{ obj.index }}]</strong> {{ obj.question }}
    </div>
    {% if obj.answered %}
    <div class="obj-answer">{{ obj.answer }}</div>
    <div class="obj-meta">
      Found via <code>{{ obj.tool or "agent" }}</code>{% if obj.iteration is not none %} at iteration {{ obj.iteration }}{% endif %}
    </div>
    {% else %}
    <div class="obj-meta" style="color: var(--text-dim);">Not answered</div>
    {% endif %}
  </div>
</div>
{% endfor %}
{% endif %}

<!-- ═══════════ ATTACK NARRATIVE ═══════════ -->
{% set sec_offset = 4 + (1 if flags else 0) + (1 if objectives else 0) %}
<div class="section-header" id="attack-path">
  <span class="section-num">0{{ sec_offset + 1 }}</span>
  <span class="section-title">Attack Narrative</span>
</div>
{% if graph.nodes | length > 1 %}
<ul class="attack-path">
  {% for node in graph.nodes if node.node_type != "host" %}
  <li class="attack-step">
    <div class="attack-step-phase">{{ (node.phase or "scan") | upper }} — {{ node.node_type | upper }}</div>
    <div class="attack-step-result">{{ node.label }}{% if node.host %} on <code>{{ node.host }}{% if node.port %}:{{ node.port }}{% endif %}</code>{% endif %}</div>
  </li>
  {% endfor %}
</ul>
{% else %}
<p style="color: var(--text-dim); padding: 20px 0;">No attack path data available.</p>
{% endif %}

<!-- ═══════════ 7/6. MITRE ATT&CK ═══════════ -->
<div class="section-header" id="mitre">
  <span class="section-num">0{{ sec_offset + 2 }}</span>
  <span class="section-title">MITRE ATT&amp;CK Coverage</span>
</div>
{% if mitre_mappings %}
<table class="info-table">
  <tr><th>Technique ID</th><th>Tactic</th><th>Technique</th><th>Tool Used</th><th>Outcome</th></tr>
  {% for t in mitre_mappings %}
  <tr>
    <td><span class="mitre-badge">{{ t.technique_id or t.id or "?" }}</span></td>
    <td><span class="tactic-badge">{{ t.tactic or "?" }}</span></td>
    <td>{{ t.technique_name or t.name or "?" }}</td>
    <td><code>{{ t.tool_used or t.tool or "—" }}</code></td>
    <td>{{ t.outcome or t.result or "Executed" }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p style="color: var(--text-dim); padding: 20px 0;">No MITRE ATT&amp;CK mappings recorded.</p>
{% endif %}

<!-- ═══════════ 8/7. REMEDIATION ROADMAP ═══════════ -->
<div class="section-header" id="remediation">
  <span class="section-num">0{{ sec_offset + 3 }}</span>
  <span class="section-title">Remediation Roadmap</span>
</div>
<table class="info-table">
  <tr><th>#</th><th>Priority</th><th>Finding</th><th>Recommended Action</th><th>Timeline</th></tr>
  {% set ns = namespace(i=1) %}
  {% for f in findings if f.severity == "critical" %}
  <tr>
    <td>{{ ns.i }}</td>
    <td><span class="sev-badge critical">CRITICAL</span></td>
    <td>{{ f.title }}{% if f.host %}<br/><small style="color:var(--text-dim)"><code>{{ f.host }}{% if f.port %}:{{ f.port }}{% endif %}</code></small>{% endif %}</td>
    <td>{{ f.remediation or "Patch immediately. Consult vendor advisory. Isolate affected system." }}</td>
    <td style="white-space:nowrap; color: var(--critical);">Immediate</td>
  </tr>
  {% set ns.i = ns.i + 1 %}
  {% endfor %}
  {% for f in findings if f.severity == "high" %}
  <tr>
    <td>{{ ns.i }}</td>
    <td><span class="sev-badge high">HIGH</span></td>
    <td>{{ f.title }}{% if f.host %}<br/><small style="color:var(--text-dim)"><code>{{ f.host }}{% if f.port %}:{{ f.port }}{% endif %}</code></small>{% endif %}</td>
    <td>{{ f.remediation or "Remediate within 7 days. Apply patches and review access controls." }}</td>
    <td style="white-space:nowrap; color: var(--high);">Within 7 days</td>
  </tr>
  {% set ns.i = ns.i + 1 %}
  {% endfor %}
  {% for f in findings if f.severity == "medium" %}
  <tr>
    <td>{{ ns.i }}</td>
    <td><span class="sev-badge medium">MEDIUM</span></td>
    <td>{{ f.title }}</td>
    <td>{{ f.remediation or "Schedule remediation within 30 days." }}</td>
    <td style="white-space:nowrap; color: var(--medium);">Within 30 days</td>
  </tr>
  {% set ns.i = ns.i + 1 %}
  {% endfor %}
</table>

<!-- ═══════════ REASONING JOURNAL (audit trail) ═══════════ -->
{% if reasoning_journal %}
<div class="section-header" id="reasoning-journal">
  <span class="section-num">0{{ sec_offset + 4 }}</span>
  <span class="section-title">
    Reasoning Journal
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      (agent decision trail)
    </span>
  </span>
</div>
<p style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px;">
  Iteration-by-iteration situational assessments from the reasoning loop. Each entry captures
  the agent's summarized understanding of the engagement state at that point in time.
  {% if journal_truncated %}
  Displaying the last {{ reasoning_journal | length }} of {{ journal_total }} total entries.
  {% endif %}
</p>
<div class="journal-wrap">
  {% for entry in reasoning_journal %}
  <div class="journal-entry">
    <div class="journal-idx">#{{ loop.index }}</div>
    <div class="journal-text">{{ entry }}</div>
  </div>
  {% endfor %}
  {% if journal_truncated %}
  <div class="journal-note">
    Earlier journal entries were truncated for report brevity. Full history is preserved in the session checkpoint record.
  </div>
  {% endif %}
</div>
{% endif %}

<!-- ═══════════ B-6: PATH TO COMPROMISE ═══════════ -->
{% if attack_path %}
<div class="section-header" id="attack-path">
  <span class="section-num">{{ '%02d' % (sec_offset + 5) }}</span>
  <span class="section-title">
    Path to Compromise
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      (chronological foothold &amp; pivot timeline)
    </span>
  </span>
</div>
<p style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px;">
  Each step records a registered foothold, lateral movement, or privilege escalation, in the
  order it was achieved during the engagement. Source values like <code>evil-winrm:primer</code>
  or <code>shell_agent:listener</code> identify which platform component captured the shell.
</p>
<table style="width:100%; margin-top:10px; border-collapse:collapse;">
  <thead><tr style="background: var(--bg-soft);">
    <th style="text-align:left; padding:8px;">#</th>
    <th style="text-align:left; padding:8px;">Phase</th>
    <th style="text-align:left; padding:8px;">Result</th>
    <th style="text-align:left; padding:8px;">Source</th>
    <th style="text-align:left; padding:8px;">Time</th>
  </tr></thead>
  <tbody>
  {% for step in attack_path %}
    <tr style="border-bottom:1px solid var(--bg-soft);">
      <td style="padding:8px; color:var(--accent);"><strong>#{{ step.__step or loop.index }}</strong></td>
      <td style="padding:8px;">{{ step.phase or '—' }}</td>
      <td style="padding:8px;">{{ step.result or '—' }}</td>
      <td style="padding:8px; font-family:monospace; font-size:11px; color:var(--text-dim);">{{ step.source or '—' }}</td>
      <td style="padding:8px; font-size:11px; color:var(--text-dim);">{{ (step.ts or '')[:19] }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ═══════════ B-6: HARVESTED LOOT ═══════════ -->
{% if loot_entries %}
<div class="section-header" id="loot-manifest">
  <span class="section-num">{{ '%02d' % (sec_offset + 6) }}</span>
  <span class="section-title">
    Harvested Loot &amp; Data of Interest
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      ({{ loot_entries | length }} item{% if loot_entries|length != 1 %}s{% endif %})
    </span>
  </span>
</div>
<p style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px;">
  Authenticated assets, secrets, and DoI patterns captured during post-exploitation. Cleartext
  is redacted from the report and stored on the operator's loot directory only.
</p>
<table style="width:100%; margin-top:10px; border-collapse:collapse;">
  <thead><tr style="background: var(--bg-soft);">
    <th style="text-align:left; padding:8px;">Severity</th>
    <th style="text-align:left; padding:8px;">Category</th>
    <th style="text-align:left; padding:8px;">Source</th>
    <th style="text-align:left; padding:8px;">Target</th>
    <th style="text-align:left; padding:8px;">Size</th>
    <th style="text-align:left; padding:8px;">SHA-256</th>
  </tr></thead>
  <tbody>
  {% for e in loot_entries %}
    <tr style="border-bottom:1px solid var(--bg-soft);">
      <td style="padding:8px;"><strong>{{ (e.severity or '?') | upper }}</strong></td>
      <td style="padding:8px;">{{ e.doi_label or e.doi_id }}</td>
      <td style="padding:8px; font-family:monospace; font-size:11px;">{{ e.source or '—' }}</td>
      <td style="padding:8px; font-family:monospace; font-size:11px;">{{ e.target or '—' }}</td>
      <td style="padding:8px;">{{ e.size_bytes or 0 }} B</td>
      <td style="padding:8px; font-family:monospace; font-size:10px; color:var(--text-dim);">{{ (e.sha256 or '')[:16] }}…</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ═══════════ B-6: WEB-INTEL SOURCES ═══════════ -->
{% if web_intel_hints %}
<div class="section-header" id="web-intel">
  <span class="section-num">{{ '%02d' % (sec_offset + 7) }}</span>
  <span class="section-title">
    Web-Intel Sources
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      ({{ web_intel_hints | length }} authoritative-source hint{% if web_intel_hints|length != 1 %}s{% endif %})
    </span>
  </span>
</div>
<p style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px;">
  Exploit techniques extracted from authoritative sources (exploit-db, HackTricks, AttackerKB,
  vendor advisories) and grounded against the discovered services. Each hint is a runnable
  command vetted against the platform's tool catalog.
</p>
<table style="width:100%; margin-top:10px; border-collapse:collapse;">
  <thead><tr style="background: var(--bg-soft);">
    <th style="text-align:left; padding:8px;">Conf</th>
    <th style="text-align:left; padding:8px;">Tool</th>
    <th style="text-align:left; padding:8px;">CVE / MITRE</th>
    <th style="text-align:left; padding:8px;">Description</th>
    <th style="text-align:left; padding:8px;">Source</th>
  </tr></thead>
  <tbody>
  {% for h in web_intel_hints %}
    <tr style="border-bottom:1px solid var(--bg-soft);">
      <td style="padding:8px;"><strong>{{ '%.2f' % (h.confidence or 0) }}</strong></td>
      <td style="padding:8px; font-family:monospace; font-size:11px;">{{ h.tool or '—' }}</td>
      <td style="padding:8px; font-size:11px; color:var(--accent);">{{ h.cve or '' }}{% if h.mitre %} {{ h.mitre }}{% endif %}</td>
      <td style="padding:8px;">{{ (h.description or '')[:120] }}</td>
      <td style="padding:8px; font-size:10px; color:var(--text-dim); word-break:break-all;">{{ (h.source_url or '')[:60] }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ═══════════ B-6: CREDENTIALS DISCOVERED ═══════════ -->
{% if creds_summary %}
<div class="section-header" id="credentials">
  <span class="section-num">{{ '%02d' % (sec_offset + 8) }}</span>
  <span class="section-title">
    Credentials &amp; Identities
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      ({{ creds_summary | length }} record{% if creds_summary|length != 1 %}s{% endif %})
    </span>
  </span>
</div>
<table style="width:100%; margin-top:10px; border-collapse:collapse;">
  <thead><tr style="background: var(--bg-soft);">
    <th style="text-align:left; padding:8px;">Domain</th>
    <th style="text-align:left; padding:8px;">User</th>
    <th style="text-align:left; padding:8px;">Password</th>
    <th style="text-align:left; padding:8px;">Source</th>
  </tr></thead>
  <tbody>
  {% for c in creds_summary %}
    <tr style="border-bottom:1px solid var(--bg-soft);">
      <td style="padding:8px;">{{ c.domain or '—' }}</td>
      <td style="padding:8px; font-family:monospace;">{{ c.user }}</td>
      <td style="padding:8px; font-family:monospace; color:var(--text-dim);">{{ c.password }}</td>
      <td style="padding:8px; font-size:11px; color:var(--text-dim);">{{ c.source }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ═══════════ B-6: PRIMER CHAIN COVERAGE ═══════════ -->
{% if primer_rows %}
<div class="section-header" id="primer-coverage">
  <span class="section-num">{{ '%02d' % (sec_offset + 9) }}</span>
  <span class="section-title">
    Platform Capability Map
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      (which automation chains were available)
    </span>
  </span>
</div>
<p style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px;">
  Tool-availability matrix at scan start. Chains marked DEGRADED had one or more required tools
  missing on the operator host — those steps were skipped automatically rather than failing
  silently. Install the listed tools to unlock the full chain.
</p>
<table style="width:100%; margin-top:10px; border-collapse:collapse;">
  <thead><tr style="background: var(--bg-soft);">
    <th style="text-align:left; padding:8px;">Chain</th>
    <th style="text-align:left; padding:8px;">Status</th>
    <th style="text-align:left; padding:8px;">Coverage</th>
    <th style="text-align:left; padding:8px;">Missing tools</th>
  </tr></thead>
  <tbody>
  {% for row in primer_rows %}
    <tr style="border-bottom:1px solid var(--bg-soft);">
      <td style="padding:8px; font-family:monospace;">{{ row.chain }}</td>
      <td style="padding:8px;">
        {% if row.status == 'DEGRADED' %}
          <strong style="color:#ff8a3d;">DEGRADED</strong>
        {% else %}
          <strong style="color:#3bd16f;">OK</strong>
        {% endif %}
      </td>
      <td style="padding:8px;">{{ row.present }}/{{ row.total }} ({{ row.coverage }}%)</td>
      <td style="padding:8px; font-family:monospace; font-size:11px; color:var(--text-dim);">{{ row.missing or '—' }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ═══════════ ENGAGEMENT TIMELINE ═══════════ -->
{% if engagement_timeline %}
<div class="section-header" id="engagement-timeline">
  <span class="section-num">{{ '%02d' % (sec_offset + 10) }}</span>
  <span class="section-title">
    Engagement Timeline
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      (chronological milestones — what happened, when)
    </span>
  </span>
</div>
<p style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px;">
  Reconstructed from phase transitions and registered attack-path steps so a reader can follow the
  engagement from first contact to final outcome.
</p>
<table style="width:100%; margin-top:10px; border-collapse:collapse;">
  <thead><tr style="background: var(--bg-soft);">
    <th style="text-align:left; padding:8px;">When</th>
    <th style="text-align:left; padding:8px;">Milestone</th>
    <th style="text-align:left; padding:8px;">Detail</th>
  </tr></thead>
  <tbody>
  {% for ev in engagement_timeline %}
    <tr style="border-bottom:1px solid var(--bg-soft);">
      <td style="padding:8px; font-size:11px; color:var(--text-dim); white-space:nowrap;">{{ (ev.ts or '')[:19] }}</td>
      <td style="padding:8px;"><strong>{{ ev.label or '—' }}</strong></td>
      <td style="padding:8px; font-size:12px;">{{ ev.detail or '' }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ═══════════ TESTS CONDUCTED (COVERAGE MATRIX) ═══════════ -->
{% if coverage_tests %}
<div class="section-header" id="coverage-matrix">
  <span class="section-num">{{ '%02d' % (sec_offset + 11) }}</span>
  <span class="section-title">
    Tests Conducted
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      (coverage matrix — including avenues tested and ruled out)
    </span>
  </span>
</div>
<p style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px;">
  Every probe ARGUS executed and its outcome. Negative results are reported deliberately — they show
  the breadth of testing and document where the target's controls held.
  {% if coverage_counts %}
  <br><strong>Totals:</strong>
  {% for k, v in coverage_counts.items() %}<span style="margin-right:12px;">{{ k }}: {{ v }}</span>{% endfor %}
  {% endif %}
</p>
<table style="width:100%; margin-top:10px; border-collapse:collapse;">
  <thead><tr style="background: var(--bg-soft);">
    <th style="text-align:left; padding:8px;">Tool</th>
    <th style="text-align:left; padding:8px;">Outcome</th>
    <th style="text-align:left; padding:8px;">Command / Target</th>
    <th style="text-align:left; padding:8px;">Note</th>
  </tr></thead>
  <tbody>
  {% for t in coverage_tests %}
    <tr style="border-bottom:1px solid var(--bg-soft);">
      <td style="padding:8px; font-family:monospace; font-size:11px;">{{ t.tool or '—' }}</td>
      <td style="padding:8px;">
        {% if t.outcome == 'success' %}<strong style="color:#3bd16f;">success</strong>
        {% elif t.outcome == 'blocked' %}<strong style="color:#ff8a3d;">blocked</strong>
        {% elif t.outcome == 'error' %}<strong style="color:#ff5d6c;">error</strong>
        {% else %}<span style="color:var(--text-dim);">negative</span>{% endif %}
      </td>
      <td style="padding:8px; font-family:monospace; font-size:10px; color:var(--text-dim);">{{ (t.command or '')[:90] }}</td>
      <td style="padding:8px; font-size:11px;">{{ (t.note or '')[:90] }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ═══════════ OTHER DISCOVERED ISSUES ═══════════ -->
{% if discovered_issues %}
<div class="section-header" id="discovered-issues">
  <span class="section-num">{{ '%02d' % (sec_offset + 12) }}</span>
  <span class="section-title">
    Other Discovered Issues
    <span style="font-size: 13px; color: var(--text-dim); font-weight: 400; letter-spacing: 0; text-transform: none; margin-left: 8px;">
      (observed weaknesses not (yet) weaponised)
    </span>
  </span>
</div>
<p style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px;">
  Additional weaknesses ARGUS observed while testing. These are reported for completeness even
  where they were not exploited, so remediation can address the full attack surface.
</p>
<table style="width:100%; margin-top:10px; border-collapse:collapse;">
  <thead><tr style="background: var(--bg-soft);">
    <th style="text-align:left; padding:8px;">Severity</th>
    <th style="text-align:left; padding:8px;">Issue</th>
    <th style="text-align:left; padding:8px;">Host</th>
    <th style="text-align:left; padding:8px;">Observed via</th>
  </tr></thead>
  <tbody>
  {% for d in discovered_issues %}
    <tr style="border-bottom:1px solid var(--bg-soft);">
      <td style="padding:8px;"><strong>{{ (d.severity or 'INFO') | upper }}</strong></td>
      <td style="padding:8px;">{{ d.title or '—' }}</td>
      <td style="padding:8px; font-family:monospace; font-size:11px;">{{ d.host or '—' }}</td>
      <td style="padding:8px; font-family:monospace; font-size:11px; color:var(--text-dim);">{{ d.tool or '—' }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ═══════════ FOOTER ═══════════ -->
<div class="report-footer">
  <div class="footer-brand">
    <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="20" cy="20" r="19" stroke="#00d4ff" stroke-width="1.5"/>
      <circle cx="20" cy="20" r="4" fill="#00d4ff"/>
    </svg>
    <span>ARGUS — Advanced Reconnaissance &amp; Guided Unified Security</span>
  </div>
  <span>Auto-generated report — {{ generated_at }}</span>
</div>

</div><!-- /.page-wrap -->
</body>
</html>
"""


# ── Professional report template (preferred) ───────────────────────────────
# The dark-dashboard REPORT_TEMPLATE above is kept as a guaranteed fallback.
# When the professional, print-ready, light-theme template module is importable
# it supersedes it — a polished client deliverable (cover page, document
# control, executive summary with metric cards, methodology, host overview,
# findings summary, engagement timeline, kill-chain attack narrative, per-
# finding detail cards, coverage matrix with negative results, proof of
# compromise, remediation roadmap, MITRE map, appendices).  Driven by the SAME
# _build_context data, so nothing in the pipeline changes — only the styling
# and section richness.  Override-not-delete keeps the fallback intact.
try:
    from report.report_template import REPORT_TEMPLATE as _PRO_REPORT_TEMPLATE
    if _PRO_REPORT_TEMPLATE and "<!DOCTYPE html>" in _PRO_REPORT_TEMPLATE:
        REPORT_TEMPLATE = _PRO_REPORT_TEMPLATE
except Exception:
    pass


_DEVICE_FAMILY = [
    ("IP camera / NVR",   re.compile(r"hikvision|dahua|\bonvif\b|\brtsp\b|ip camera|\bnvr\b|\bdvr\b|\baxis\b", re.I)),
    ("VoIP phone",        re.compile(r"yealink|\bvoip\b|sip phone|polycom|grandstream|cisco ip phone", re.I)),
    ("Smart TV",          re.compile(r"\btizen\b|smart ?tv|\bwebos\b|android tv", re.I)),
    ("AV control system", re.compile(r"crestron|\bamx\b|extron|biamp|q-?sys|din-?dli|digital.?loggers", re.I)),
    ("Firewall",          re.compile(r"fortigate|fortios|palo alto|pan-os|sonicwall|check ?point", re.I)),
    ("Router",            re.compile(r"mikrotik|routeros|\bpfsense\b|openwrt", re.I)),
    ("In-flight entertainment", re.compile(r"in-?flight|\bife\b|inflight entertainment", re.I)),
    ("Mobile device",     re.compile(r"\bipados\b|jailbreak|\bmdm\b", re.I)),
    ("Printer",           re.compile(r"\bprinter\b|jetdirect|\bpjl\b", re.I)),
]


def _device_family(f: Any):
    """The mutually-exclusive device family a 'X detected' finding claims, or None."""
    blob = str((f or {}).get("title") or "") + " " + str((f or {}).get("description") or "")
    for name, rx in _DEVICE_FAMILY:
        if rx.search(blob):
            return name
    return None


def _deconflict_device_identities(findings: "list") -> "list":
    """[35/I7] Per host, keep the SINGLE strongest device-identity 'X detected' finding and
    fold contradictory mutually-exclusive family detections into a note — so a host is never
    reported as two device types (camera+IFE off 554/RTSP, phone+TV off 5060/SIP).  Pure +
    render-only; returns the de-conflicted list."""
    if not isinstance(findings, list) or len(findings) < 2:
        return findings
    _sevrank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    by_host: "dict" = {}
    for f in findings:
        if not isinstance(f, dict) or "detect" not in str(f.get("title") or "").lower():
            continue
        fam = _device_family(f)
        if fam:
            by_host.setdefault(str(f.get("host") or "").lower(), []).append((fam, f))
    drop = set()
    for _host, items in by_host.items():
        if len({fam for fam, _ in items}) <= 1:
            continue
        ranked = sorted(items, key=lambda it: (
            _sevrank.get(str(it[1].get("inherent_risk") or it[1].get("severity") or "info").lower(), 5),
            -len(str(it[1].get("evidence") or ""))))
        keep_fam, keep_f = ranked[0]
        others = sorted({fam for fam, _ in ranked[1:] if fam != keep_fam})
        if others:
            keep_f["description"] = (
                str(keep_f.get("description") or "")
                + " Device-identity de-confliction: this host also matched "
                + ", ".join(others) + " on shared ports (likely false positives from generic "
                "port/banner overlap); kept the strongest identity (" + keep_fam + ").").strip()
        for _fam, f in ranked[1:]:
            drop.add(id(f))
    return [f for f in findings if id(f) not in drop] if drop else findings


class ReportGenerator:
    """Generates HTML and PDF pentest reports from MongoDB session data."""

    def __init__(self):
        self._jinja_env = Environment(loader=BaseLoader())
        self._template  = self._jinja_env.from_string(REPORT_TEMPLATE)
        # Dedicated autoescape env for the canonical theme: user/tool text is escaped
        # by default (defence-in-depth for the print path) while charts use |safe.  The
        # legacy REPORT_TEMPLATE stays on the non-autoescape env so it is unaffected.
        self._theme_env = Environment(loader=BaseLoader(), autoescape=True)

    def _render(self, ctx: Dict, theme: Optional[str] = None) -> str:
        """Render the report HTML for a theme key.  The selectable themes 'dark'
        and 'light' are rendered by the vendored operator-authored builder
        (report/argus_template, used verbatim) from the SAME context; the legacy
        Jinja template remains only as an internal fallback (override-not-delete)."""
        import logging as _logging
        _rlog = _logging.getLogger("report")
        try:
            from report.themes import DEFAULT_THEME, is_builder_theme
            _theme = theme or DEFAULT_THEME
            if is_builder_theme(_theme):
                try:
                    from report.argus_template.render import render_html
                except Exception as _imp:              # module missing = NOT DEPLOYED
                    _rlog.error("[REPORT] builder theme '%s' selected but report/argus_template is "
                                "NOT importable (%s). The dark/light design is NOT deployed on this "
                                "host — the report will use the LEGACY design (dark==light). "
                                "Deploy report/argus_template/ and RESTART the server.", _theme, _imp)
                    raise
                _html = render_html(ctx, _theme if _theme in ("dark", "light") else "dark")
                if _html:
                    return _html
                _rlog.error("[REPORT] builder theme '%s' rendered EMPTY — see the 'render_html FAILED' "
                            "traceback above; falling back to the LEGACY design (dark==light).", _theme)
        except Exception as _bexc:                     # noqa: BLE001
            _rlog.error("[REPORT] builder theme '%s' render path failed (%s); falling back to the "
                        "LEGACY design.", theme, _bexc)
        # [68] On builder failure, route to the CANONICAL themed template
        # (report/themes/argus.html.j2 + the report/charts.py SVG engine) BEFORE the
        # legacy dark==light fallback.  get_theme() returns "" for builder themes by
        # design, so this fallback used to skip argus.html.j2 entirely and the whole
        # charts engine was dead code.  get_canonical_theme() reads it unconditionally.
        try:
            from report.themes import get_canonical_theme, DEFAULT_THEME
            tpl = get_canonical_theme(theme or DEFAULT_THEME)
            if tpl:
                return self._theme_env.from_string(tpl).render(**ctx)
        except Exception as _texc:                     # noqa: BLE001
            print(f"[REPORT] theme '{theme}' render failed ({_texc}); using fallback template")
        return self._template.render(**ctx)

    def list_themes(self):
        """Theme registry (key/name/description) for the UI picker."""
        try:
            from report.themes import list_themes as _lt
            return _lt()
        except Exception:
            return []

    async def generate_html(self, session_id: str, theme: Optional[str] = None) -> str:
        """Build and return the full HTML report string for the chosen theme."""
        ctx = await self._build_context(session_id)
        # [71] Offload the (blocking) template render off the event loop so a report
        # build never starves the loop while scans stream.  The builder's process-
        # global state is already serialized by report/argus_template's _LOCK, so a
        # threaded render is safe.  Mirrors the PDF-engine run_in_executor pattern.
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._render, ctx, theme)

    async def generate_pdf(self, session_id: str, theme: Optional[str] = None,
                           engine: Optional[str] = None) -> Optional[bytes]:
        """
        Render the SELECTED theme's styled HTML to PDF.

        Order (best fidelity first): headless Chromium via Playwright → weasyprint
        (pure-python) → wkhtmltopdf (if the binary exists).  Returns None when no
        styled engine is available, so the endpoint can fall back to the browser's
        print-to-PDF (pixel-perfect, zero-dependency) — we NEVER silently serve the
        raw plaintext writer as the styled download.  The stdlib plaintext writer is
        reachable ONLY via engine='text' (an explicit headless/API opt-in).
        """
        ctx  = await self._build_context(session_id)
        # [71] Render off the event loop (see generate_html).
        html = await asyncio.get_event_loop().run_in_executor(None, self._render, ctx, theme)

        # Pin the engine via env when the default chain is undesirable — e.g. set
        # ARGUS_PDF_ENGINE=weasyprint on a host where the apt Playwright/Chromium is
        # broken, so ARGUS skips the doomed Chromium attempt entirely.  An explicit
        # ?engine= query param still wins over the env default.
        if not engine:
            engine = os.environ.get("ARGUS_PDF_ENGINE") or None

        if engine == "text":
            try:
                from report.pdf_writer import lines_to_pdf, report_lines_from_context
                target = (ctx.get("session") or {}).get("target", "target")
                return lines_to_pdf(report_lines_from_context(ctx),
                                    title=f"ARGUS Report — {target}")
            except Exception as exc:                   # noqa: BLE001
                print(f"[REPORT] stdlib PDF fallback failed: {exc}")
                return None

        # Styled engines, best fidelity first.  Chromium (headless, via Playwright) is
        # the PRIMARY renderer — browser-grade CSS/flex/grid/gradients/web-fonts — with
        # WeasyPrint as the pure-python fallback and wkhtmltopdf as a last resort.  An
        # explicit engine= pins one.  Returns None when none succeed so the endpoint
        # falls back to browser print-to-PDF (we NEVER serve the raw plaintext writer).
        _order = ([engine] if engine in ("chromium", "weasyprint", "wkhtmltopdf")
                  else ["chromium", "weasyprint", "wkhtmltopdf"])
        for _eng in _order:
            try:
                if _eng == "chromium":
                    pdf = await self._playwright_pdf_bytes(html)
                elif _eng == "weasyprint":
                    pdf = await self._weasyprint_bytes(html)
                else:
                    pdf = await self._wkhtmltopdf_bytes(html)
            except Exception:                          # noqa: BLE001
                pdf = None
            if pdf:
                return pdf
        return None

    async def _playwright_pdf_bytes(self, html: str) -> Optional[bytes]:
        """Render HTML→PDF via headless Chromium (Playwright) — browser-grade fidelity.
        Chromium ignores CSS @page margin-boxes, so page numbering is drawn via the
        native footer template.  None if Playwright/Chromium is unavailable."""
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return None
        _footer = (
            '<div style="font-size:7px;color:#9aa4b2;width:100%;margin:0 12mm;'
            'display:flex;justify-content:space-between;font-family:sans-serif;">'
            '<span>ARGUS &middot; CONFIDENTIAL</span>'
            '<span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>')
        try:
            async with async_playwright() as _pw:
                browser = await _pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
                try:
                    page = await browser.new_page()
                    await page.set_content(html, wait_until="load")
                    await page.emulate_media(media="print")
                    return await page.pdf(
                        format="A4", print_background=True,
                        display_header_footer=True,
                        header_template="<span></span>",
                        footer_template=_footer,
                        margin={"top": "14mm", "bottom": "16mm", "left": "12mm", "right": "12mm"})
                finally:
                    await browser.close()
        except Exception as exc:                       # noqa: BLE001
            print(f"[REPORT] Chromium/Playwright PDF failed ({exc}); trying next engine.")
            return None

    async def _weasyprint_bytes(self, html: str) -> Optional[bytes]:
        """Render HTML→PDF via WeasyPrint (pure-python) off the event loop."""
        try:
            import weasyprint  # type: ignore
        except Exception:
            return None
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, lambda: weasyprint.HTML(string=html).write_pdf())
        except Exception as exc:                       # noqa: BLE001
            print(f"[REPORT] WeasyPrint PDF failed ({exc}); trying next engine.")
            return None

    async def _wkhtmltopdf_bytes(self, html: str) -> Optional[bytes]:
        """Render HTML→PDF via wkhtmltopdf; None if the binary is missing/fails."""
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
                     "--background",
                     html_path, pdf_path],
                    capture_output=True, timeout=90
                )
            )
            if result.returncode == 0 and os.path.exists(pdf_path):
                with open(pdf_path, "rb") as f:
                    return f.read()
            print(f"[REPORT] wkhtmltopdf error: {result.stderr.decode()[:500]}")
            return None
        except FileNotFoundError:
            print("[REPORT] wkhtmltopdf not found — using pure-python PDF fallback.")
            return None
        except subprocess.TimeoutExpired:
            print("[REPORT] wkhtmltopdf timed out — using pure-python PDF fallback.")
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
        import os as _os_rg
        # Read-time gate: exclude Issue-Validator-rejected findings (verified
        # explicitly False) so faulty/silly issues never render in the report.
        _validated_only = _os_rg.environ.get("ARGUS_ISSUE_VALIDATOR", "1") != "0"
        # Per-host isolation: a multi-target PARENT session's findings live under its
        # per-host CHILD sessions.  Aggregate parent + children so the report is ONE
        # combined document covering every host.  For a plain single scan this is just
        # [session_id], so behaviour is unchanged.
        try:
            _scope = await db.resolve_session_scope(session_id)
        except Exception:
            _scope = [str(session_id)]
        _scope_set = {str(s) for s in _scope}
        findings = await db.get_findings(_scope, validated_only=_validated_only)
        summary  = await db.get_findings_summary(_scope)
        flags    = await db.get_flags(_scope)
        graph    = await db.get_attack_graph(session_id)

        # Cross-engagement bleed backstop: drop any finding/flag stamped with an origin
        # OUTSIDE this report's scope (a prior engagement's evidence must never render).
        # The scope is the parent + its per-host child sessions, so a child host's
        # findings (origin = child sid) are KEPT.  Legacy items without `_origin` are
        # kept (cannot be proven foreign).
        def _same_session(x):
            o = (x or {}).get("_origin") if isinstance(x, dict) else None
            return (not o) or str(o.get("session_id", "")) in _scope_set
        if isinstance(findings, list):
            findings = [f for f in findings if _same_session(f)]
        if isinstance(flags, list):
            flags = [fl for fl in flags if _same_session(fl)]

        # [P3] RAW-store total (before the Issue-Validator dropped verified=False) so the
        # disclosed reconciliation accounts for EVERY stored finding — validator-rejected +
        # policy-dropped + deduped + reported == raw store — not just the validated subset.
        _raw_store_total = None
        if _validated_only:
            try:
                _raw_all = await db.get_findings(_scope, validated_only=False)
                if isinstance(_raw_all, list):
                    _raw_all = [f for f in _raw_all if _same_session(f)]
                    _raw_store_total = len([f for f in _raw_all if isinstance(f, dict)])
            except Exception:
                _raw_store_total = None

        # ── Operational severity normalization — the SINGLE source of truth ──
        # Render-time only (the DB is never mutated): drop tool-noise / internal
        # diagnostics, and re-grade every finding to an HONEST severity so the report
        # never inflates (service-discovery→info, unproven-RCE→capped, validated CVE
        # kept, demonstrated kept).  This is what makes "critical" mean something.
        # [I3] disclosed store->report reconciliation — every stored finding is accounted for
        # (assessed -> dropped-as-unsupported/noise -> deduped -> reported), any severity
        # downgrade carries a rationale, so the report total is RECONCILABLE to the store
        # instead of a third mystery number (98 != 93 != 80).
        _assessed = len([f for f in (findings or []) if isinstance(f, dict)])
        _recon = {"assessed": _assessed,
                  # [P3] the raw store count + how many the validator rejected before assessment
                  "raw_store_total": _raw_store_total if _raw_store_total is not None else _assessed,
                  "validator_rejected": (max(0, _raw_store_total - _assessed)
                                         if _raw_store_total is not None else 0),
                  "dropped_unsupported": 0, "regraded": 0, "downgraded_from_high": 0, "deduped": 0}
        _RK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        try:
            from knowledge import severity_policy as _sp
            _normed = []
            for _f in (findings or []):
                if not isinstance(_f, dict):
                    _normed.append(_f); continue
                _orig_sev = str(_f.get("severity") or "").lower().replace("findingseverity.", "").strip()
                _v = _sp.normalize_finding(_f)
                if _v.get("drop"):
                    _recon["dropped_unsupported"] += 1
                    continue   # raw tool output / internal status — never shown to a client
                # Backstop for the wildcard-DNS false positive: "Wildcard DNS Detected:
                # *.<bare IP>" is provably bogus (an IP has no DNS zone).  Drop it here
                # too so it disappears from the report even for findings that predate
                # the dns_recon subagent fix.
                if re.match(r"^\s*wildcard dns detected:\s*\*\.\d{1,3}(?:\.\d{1,3}){3}\s*$",
                            str(_f.get("title") or ""), re.I):
                    _recon["dropped_unsupported"] += 1
                    continue
                # [I3] a re-grade is disclosed, never silent — count it, and flag a
                # HIGH/CRITICAL downgrade specifically (the report zeroed all 6 HIGH before).
                _new_sev = str(_v["severity"]).lower()
                if _orig_sev and _new_sev != _orig_sev:
                    _recon["regraded"] += 1
                    if _RK.get(_orig_sev, 0) >= _RK["high"] and _RK.get(_new_sev, 0) < _RK["high"]:
                        _recon["downgraded_from_high"] += 1
                # Title-case the canonical severity so BOTH the themes' capitalized
                # selectattr filters ('Critical'…) AND their `|lower` comparisons agree.
                _f["severity"] = str(_v["severity"]).capitalize()
                if _v.get("evidence_tag"):
                    _f["evidence_tag"] = _v["evidence_tag"]
                if _v.get("rationale"):
                    _f.setdefault("severity_rationale", _v["rationale"])
                # Clean a raw scanner-output title into a short report title (strips a
                # ZAP/nikto '[007352] /:' plugin+path prefix and tool-status markers,
                # caps a verbose sentence at a WORD boundary) so the register never
                # truncates mid-word ("…This could allow the u").  The full original
                # text is preserved in the description so nothing is lost.
                _ot = _f.get("title")
                _ct = _clean_finding_title(_ot)
                if _ct and _ct != str(_ot or "").strip():
                    _dsc = str(_f.get("description") or "")
                    if _ot and str(_ot) not in _dsc:
                        _f["description"] = (str(_ot) + (("\n\n" + _dsc) if _dsc else "")).strip()
                    _f["title"] = _ct
                # Strip ANSI/terminal control bytes from captured tool output so the
                # evidence block renders as clean text instead of "□[1m□[0m" tofu.
                for _ekey in ("evidence", "raw_output"):
                    if _f.get(_ekey):
                        _f[_ekey] = _sanitize_evidence(_f[_ekey])
                _ex_f = _f.get("extra")
                if isinstance(_ex_f, dict) and _ex_f.get("raw"):
                    _ex_f["raw"] = _sanitize_evidence(_ex_f["raw"])
                _normed.append(_f)
            findings = _normed
        except Exception:
            pass

        # ── Reconcile each finding's CVSS with its HONEST severity band ──────
        #    A detection re-graded to INFO must not still advertise a stale CVSS
        #    9.8 inherited from a raw CVE keyword-match (the register otherwise
        #    read "AD/SMB detected · INFO · 9.8", which looks like a broken
        #    report).  Render-time only: if the stored cvss_base falls OUTSIDE
        #    the band the finding's severity implies, suppress it → shows "—".
        def _cvss_in_band(_sev_name: Any, _cvss: Any) -> bool:
            try:
                _v = float(_cvss)
            except (TypeError, ValueError):
                return False
            _b = {"critical": (9.0, 10.0), "high": (7.0, 8.9),
                  "medium": (4.0, 6.9), "low": (0.1, 3.9)}.get(
                      str(_sev_name or "").strip().lower())
            return bool(_b) and _b[0] <= _v <= _b[1]   # info => no band => suppress
        try:
            for _f in (findings or []):
                if not isinstance(_f, dict):
                    continue
                _sev = _f.get("severity")
                _ex = _f.get("extra")
                if isinstance(_ex, dict) and _ex.get("cvss_base") not in (None, "", 0, "0"):
                    if not _cvss_in_band(_sev, _ex.get("cvss_base")):
                        _ex["cvss_base"] = None
                # [I7] the register + per-host table read these top-level score fields
                # directly — reconcile them too so a re-graded finding can never still
                # advertise a stale 9.8 next to an INFO/LOW band.  Vector STRINGS
                # (CVSS:3.1/…) are left intact — only numeric SCORES are banded.
                for _ck in ("cvss", "cvss_base", "cvss_score"):
                    _cv = _f.get(_ck)
                    if _cv in (None, "", 0, "0"):
                        continue
                    try:
                        float(_cv)
                    except (TypeError, ValueError):
                        continue   # a vector string, not a score — leave it
                    if not _cvss_in_band(_sev, _cv):
                        _f[_ck] = None
        except Exception:
            pass

        # ── Collapse exact-duplicate findings ───────────────────────────────
        #    Multiple passes (triage + deep) or multiple subagents can each store
        #    the SAME issue (same host:port:title:severity) — the register showed
        #    F-06≡F-07, F-08≡F-09 … which inflated the PDF to 58 pages and
        #    over-counted per-host totals.  Keep the RICHEST copy (most evidence).
        #    Render-time only; the DB is never mutated.  Everything downstream
        #    (fids, counts, donut, per-host, register, detail) derives from this.
        try:
            if isinstance(findings, list) and len(findings) > 1:
                _dedup_before = len(findings)
                def _dedup_key(_f: Any) -> tuple:
                    _g = _f if isinstance(_f, dict) else {}
                    return (str(_g.get("host") or "").strip().lower(),
                            str(_g.get("port") or "").strip(),
                            " ".join(str(_g.get("title") or "").split()).lower(),
                            str(_g.get("severity") or "").strip().lower())
                def _richness(_f: Any) -> tuple:
                    _g = _f if isinstance(_f, dict) else {}
                    return (len(str(_g.get("evidence") or _g.get("raw_output") or "")),
                            1 if _g.get("verified") else 0)
                _best: Dict[Any, Any] = {}
                _order: List[Any] = []
                for _f in findings:
                    _k = _dedup_key(_f)
                    if _k not in _best:
                        _best[_k] = _f
                        _order.append(_k)
                    elif _richness(_f) > _richness(_best[_k]):
                        _best[_k] = _f
                findings = [_best[_k] for _k in _order]
                try:
                    _recon["deduped"] += _dedup_before - len(findings)
                except Exception:
                    pass
        except Exception:
            pass

        # ── Device-identity de-confliction [35/I7] — no host is two device types ──
        try:
            _dc_before = len(findings) if isinstance(findings, list) else 0
            findings = _deconflict_device_identities(findings)
            _recon["deduped"] += max(0, _dc_before - len(findings))
        except Exception:
            pass

        # ── One severity sort + one stable ID stamp (every theme reads these) ──
        # Critical→High→Medium→Low→Info, ties broken by host then title; unknown last.
        try:
            _rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            if isinstance(findings, list):
                findings.sort(key=lambda f: (
                    _rank.get(str((f or {}).get("severity") or "").lower().replace("findingseverity.", ""), 5),
                    str((f or {}).get("host") or ""), str((f or {}).get("title") or "")))
                for _i, _f in enumerate(findings):
                    if isinstance(_f, dict):
                        _f["fid"] = "F-%02d" % (_i + 1)
        except Exception:
            pass

        # ── Counts are recomputed from the SAME findings the register renders (NOT the
        #    stale DB summary) so the metric cards / donut / headline can never disagree
        #    with the table below them, and dropped-noise + demoted-severity are reflected
        #    exactly.  This is what killed the "report shows a CRITICAL that isn't in the
        #    findings" class of bug.
        try:
            _cnt = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for _f in (findings or []):
                _s = (str((_f or {}).get("severity") or "").lower()
                      .replace("findingseverity.", "").strip())
                if _s in _cnt:
                    _cnt[_s] += 1
            _cnt["total"] = sum(_cnt.values())
            summary = _cnt
        except Exception:
            pass

        # ── Per-host grouping for the COMBINED multi-target report: a unified summary
        #    up top (the counts/charts above cover every host), then one detail section
        #    per host.  `hosts_report` is [] for a single-host scan → the report keeps its
        #    flat layout.  Hosts are ranked most-severe first.
        hosts_report: List[Dict[str, Any]] = []
        try:
            _byh: Dict[str, List[Dict[str, Any]]] = {}
            for _f in (findings or []):
                if isinstance(_f, dict):
                    _byh.setdefault(str(_f.get("host") or "unspecified"), []).append(_f)
            if len(_byh) > 1:
                for _h, _fs in _byh.items():
                    _hs = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                    for _f in _fs:
                        _s = str((_f or {}).get("severity") or "").lower().replace("findingseverity.", "").strip()
                        if _s in _hs:
                            _hs[_s] += 1
                    hosts_report.append({"host": _h, "findings": _fs, "sev": _hs,
                                         "total": len(_fs)})
                hosts_report.sort(key=lambda g: (g["sev"]["critical"], g["sev"]["high"],
                                                 g["sev"]["medium"], g["total"]), reverse=True)
        except Exception:
            hosts_report = []

        # [I7] Label each host by how its engagement ACTUALLY terminated.  A host
        # that hit the hard time cap (or errored) was only PARTIALLY assessed — the
        # report must say so rather than implying every host was fully tested (the
        # audit found 12/14 hosts time-capped yet presented as complete).  The
        # per-host terminal status is the LAST host_status log entry for that host;
        # absent (single-host / legacy single-phase runs) => treated as finalized.
        try:
            _hstat: Dict[str, str] = {}
            for _e in (session.get("host_status") or []):
                if isinstance(_e, dict) and _e.get("host"):
                    _hstat[str(_e["host"])] = str(_e.get("status") or "")   # last-wins
            _unfinal = 0
            for _g in hosts_report:
                _st = _hstat.get(str(_g.get("host")), "")
                _final = _st in ("", "completed")
                _g["finalized"] = _final
                _g["status_label"] = {
                    "time_capped": "Partial — reached time cap before assessment finished",
                    "error":       "Partial — engagement error",
                }.get(_st, "Assessed")
                if not _final:
                    _unfinal += 1
            session["hosts_unfinalized"] = _unfinal
            session["hosts_total"] = len(hosts_report)
        except Exception:
            pass

        # Keep the headline severity counts consistent with the findings that
        # are ACTUALLY rendered (normalized + validated + same-session) so a
        # gated-out finding never inflates the metric cards above the visible rows.
        try:
            _rs = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
            for _f in (findings or []):
                _sv = str((_f or {}).get("severity") or "").lower().replace("findingseverity.", "")
                if _sv in _rs:
                    _rs[_sv] += 1
                _rs["total"] += 1
            summary = _rs
        except Exception:
            pass

        # MITRE mappings — best-effort
        mitre_mappings = []
        try:
            mitre_mappings = await db.get_mitre_mappings(session_id)
        except Exception:
            pass

        # ── Pull the latest intel snapshot from checkpoints (contains
        #    reasoning_journal, ctf_objectives, ctf_answers, engagement_context)
        intel_snapshot: Dict[str, Any] = {}
        try:
            cp = await db.get_latest_checkpoint(session_id)
            if cp and isinstance(cp, dict):
                intel_snapshot = cp.get("intel_snapshot") or {}
        except Exception:
            pass

        reasoning_journal = list(intel_snapshot.get("reasoning_journal", []) or [])
        ctf_answers       = intel_snapshot.get("ctf_answers", {}) or {}
        engagement_ctx    = intel_snapshot.get("engagement_context") or {}
        ctf_objectives    = (
            engagement_ctx.get("objectives")
            or intel_snapshot.get("ctf_objectives", [])
            or []
        )
        engagement_type   = engagement_ctx.get("engagement_type", session.get("target_type", "pentest"))
        # An unknown/blank engagement type must not print as "Unknown" on the cover
        # + subtitle + appendix — fall back to a real label.
        if str(engagement_type or "").strip().lower() in ("", "none", "null", "unknown", "auto", "n/a"):
            engagement_type = "penetration_test"

        # Build answered-objectives rows for the template (stable shape)
        objectives_rows = []
        for i, obj in enumerate(ctf_objectives):
            if isinstance(obj, dict):
                q_text  = obj.get("task") or obj.get("question") or str(obj)
                section = obj.get("section", "")
            else:
                q_text  = str(obj)
                section = ""
            ans_data = ctf_answers.get(str(i), {}) if isinstance(ctf_answers, dict) else {}
            if isinstance(ans_data, dict):
                ans_text = ans_data.get("answer", "")
                ans_tool = ans_data.get("tool", "")
                ans_iter = ans_data.get("iteration")
            else:
                ans_text = str(ans_data) if ans_data else ""
                ans_tool = ""
                ans_iter = None
            objectives_rows.append({
                "index":     i + 1,
                "question":  q_text,
                "section":   section,
                "answer":    ans_text,
                "tool":      ans_tool,
                "iteration": ans_iter,
                "answered":  bool(ans_text),
            })

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

        # ── Human display values for the cover + appendix (render-time only) ──
        #    Turn raw ISO microseconds and the literal string "None" into clean,
        #    readable values: the cover no longer shows "Completed: None" or
        #    "Started: 2026-07-04T14:32:54.970000Z", and the appendix engagement
        #    window no longer reads "… → None".  Runs AFTER duration is computed
        #    (which parses the raw ISO), so nothing downstream re-parses these.
        def _fmt_ts(_v: Any) -> str:
            _s = str(_v or "").strip()
            if not _s or _s.lower() in ("none", "null"):
                return ""
            try:
                return datetime.fromisoformat(_s.replace("Z", "")).strftime("%Y-%m-%d %H:%M UTC")
            except Exception:
                return _s.replace("T", " ")[:16]
        try:
            _st_disp = _fmt_ts(session.get("started_at"))
            _ct_disp = _fmt_ts(session.get("completed_at"))
            session["started_at"]   = _st_disp or "—"
            session["completed_at"] = _ct_disp or "In progress"
            if not str(session.get("scope") or "").strip():
                session["scope"] = (f"{len(hosts_report)} hosts"
                                    if len(hosts_report) > 1 else "Single host")
            if str(session.get("target_hostname") or "").strip().lower() in ("none", "null"):
                session["target_hostname"] = ""
        except Exception:
            pass

        # Intel — populate from session state or agent logs
        intel: Dict[str, Any] = {
            "os_guess":    session.get("target_type", "unknown"),
            "open_ports":  [],
            "services":    {},
            "shell_access": any(f.get("flag_type") in ("user", "root") for f in flags),
        }

        # Try to pull intel from agent_logs
        try:
            logs = await db.get_agent_logs(session_id, limit=10)
            for log in logs:
                msg = log.get("message", "")
                if "open_ports" in msg:
                    try:
                        import json as _j
                        data = _j.loads(msg)
                        if isinstance(data, dict):
                            if "open_ports" in data:
                                intel["open_ports"] = data["open_ports"]
                            if "services" in data:
                                intel["services"] = data["services"]
                    except Exception:
                        pass
        except Exception:
            pass

        # Build services from findings if intel still empty
        if not intel["services"] and findings:
            for f in findings:
                port = f.get("port")
                svc  = f.get("service")
                if port and svc and port not in intel["services"]:
                    intel["services"][str(port)] = {
                        "service": svc,
                        "version": f.get("extra", {}).get("version", "") if isinstance(f.get("extra"), dict) else "",
                        "protocol": "tcp",
                    }
            # Rebuild open_ports from services
            if not intel["open_ports"]:
                intel["open_ports"] = [int(p) for p in intel["services"].keys() if str(p).isdigit()]

        all_phases = [
            "recon", "scan", "vuln_id", "osint",
            "exploit", "post_exploit", "privesc", "persistence",
            "lateral", "wireless", "iot", "reporting"
        ]

        # ── Synthesize a richer executive summary from actual session data ────
        executive_summary = self._build_executive_summary(
            session           = session,
            summary           = summary,
            flags             = flags,
            intel             = intel,
            duration          = duration,
            engagement_type   = engagement_type,
            objectives_rows   = objectives_rows,
            findings          = findings,
        )

        # Trim reasoning journal to last 60 entries for report readability
        # (full journal stays in checkpoint for audit purposes)
        journal_display = reasoning_journal[-60:]

        # ── B-6 — surface platform-internal post-exploitation artefacts ─
        # These four sections are what differentiates the platform's
        # output from a vanilla scanner.  Without them the report only
        # shows discovered vulns; with them the operator sees the full
        # attack-path narrative + harvested loot + intel sources.
        loot_entries     = list(intel_snapshot.get("loot_entries") or [])
        loot_summary     = intel_snapshot.get("loot_summary") or {}
        loot_by_doi: Dict[str, list] = {}
        for e in loot_entries:
            if not isinstance(e, dict):
                continue
            doi = e.get("doi_id") or "uncategorized"
            loot_by_doi.setdefault(doi, []).append(e)

        web_intel_hints = list(intel_snapshot.get("web_intel_hints") or [])
        # Sort by confidence desc so the strongest hints appear first
        web_intel_hints = sorted(
            (h for h in web_intel_hints if isinstance(h, dict)),
            key=lambda h: h.get("confidence", 0) or 0,
            reverse=True,
        )

        primer_coverage = intel_snapshot.get("primer_tool_availability") or {}
        # Build a compact rows list for the template
        primer_rows = []
        if isinstance(primer_coverage, dict):
            for chain_name, info in primer_coverage.items():
                if not isinstance(info, dict):
                    continue
                deps     = info.get("deps") or []
                present  = info.get("present") or []
                missing  = info.get("missing") or []
                cov      = info.get("coverage", 1.0)
                primer_rows.append({
                    "chain":    chain_name,
                    "present":  len(present),
                    "total":    len(deps),
                    "missing":  ", ".join(missing[:8]) + (" …" if len(missing) > 8 else ""),
                    "coverage": int(round(cov * 100)),
                    "status":   "OK" if not missing else ("DEGRADED" if missing else "OK"),
                })
            primer_rows.sort(key=lambda r: (r["status"] != "DEGRADED", r["chain"]))

        attack_path = list(intel_snapshot.get("attack_path") or [])
        # Annotate each step with sequence number for the timeline section
        for i, step in enumerate(attack_path):
            if isinstance(step, dict):
                step["__step"] = i + 1

        # Credentials harvested or operator-supplied (redact passwords for
        # report safety — operator can find full creds in the loot dir).
        creds_summary: list = []
        for c in (intel_snapshot.get("credentials") or []):
            if isinstance(c, dict) and c.get("user"):
                pwd = c.get("password") or c.get("pass") or ""
                creds_summary.append({
                    "user":     c.get("user", ""),
                    "domain":   c.get("domain", ""),
                    "password": ("•" * min(len(pwd), 8)) if pwd else "(none)",
                    "source":   c.get("source", "unknown"),
                })
            elif isinstance(c, dict) and c.get("note"):
                # Harvested secret / API key / hardcoded credential recorded as a
                # note (no user/pass pair) — this is a real finding and MUST appear
                # in the report (it was silently dropped before, e.g. the leaked
                # SENSOR_API_KEY on the Reactor run).
                creds_summary.append({
                    "user":     "(secret / key)",
                    "domain":   "",
                    "password": "(see note)",
                    "source":   "harvested",
                    "note":     str(c.get("note"))[:500],
                })
            elif isinstance(c, str) and c.strip():
                creds_summary.append({
                    "user": "(credential)", "domain": "", "password": "",
                    "source": "harvested", "note": c[:500],
                })

        # Union DB-persisted credentials.  The operator writes every recovered
        # credential to db.credentials (store_credential), but the report used to
        # read ONLY the intel snapshot — so a cred saved to the vault yet not
        # mirrored into the snapshot never surfaced here (the founder's "it had
        # credentials, why wasn't it highlighted" gap for any DB-only cred).
        # Scope-aware, redacted, de-duplicated against the snapshot rows above.
        try:
            _seen_users = {str(r.get("user") or "").strip().lower()
                           for r in creds_summary if r.get("user")}
            for _c in (await db.get_credentials(_scope) or []):
                if not isinstance(_c, dict):
                    continue
                _u = str(_c.get("user") or "").strip()
                if not _u or _u.lower() in _seen_users:
                    continue
                _sec = _c.get("secret") or ""
                _loc = str(_c.get("host") or "").strip()
                _svc = str(_c.get("service") or "").strip()
                creds_summary.append({
                    "user":     _u,
                    "domain":   str(_c.get("domain") or ""),
                    "password": ("•" * min(len(str(_sec)), 8)) if _sec else "(none)",
                    "source":   str(_c.get("found_by") or _svc or "credential vault"),
                    "note":     (_loc + (" · " + _svc if _svc else "")).strip(" ·"),
                })
                _seen_users.add(_u.lower())
        except Exception:
            pass

        # ── Coverage matrix + discovered-issue storyline (concern: rich report) ─
        # The operator now records EVERY probe it ran (with negative results) and
        # every issue it observed, so the report can tell the full storyline —
        # what was attempted, what was ruled out, what was found — not just wins.
        coverage_tests: list = []
        for tr in (intel_snapshot.get("test_results") or [])[:200]:
            if isinstance(tr, dict):
                coverage_tests.append({
                    "tool":    tr.get("tool", ""),
                    "target":  tr.get("target", ""),
                    "command": tr.get("command", ""),
                    "outcome": tr.get("outcome", "negative"),
                    "note":    tr.get("note", ""),
                })
        coverage_counts: dict = {}
        for _t in coverage_tests:
            coverage_counts[_t["outcome"]] = coverage_counts.get(_t["outcome"], 0) + 1
        discovered_issues: list = []
        _seen_di = set()
        for di in (intel_snapshot.get("discovered_issues") or [])[:120]:
            if isinstance(di, dict) and di.get("title"):
                _k = (di.get("title"), di.get("host"))
                if _k in _seen_di:
                    continue
                _seen_di.add(_k)
                discovered_issues.append({
                    "title":    di.get("title", ""),
                    "severity": di.get("severity", "INFO"),
                    "tool":     di.get("tool", ""),
                    "status":   di.get("status", "observed"),
                    "host":     di.get("host", ""),
                })

        # ── Engagement timeline — chronological milestones from phase history
        #    and registered attack-path steps, so a reader can follow the run
        #    from first contact to outcome.
        engagement_timeline: list = []
        _ph_src = (intel_snapshot.get("phase_history")
                   or session.get("phase_history")
                   or (summary or {}).get("phase_history") or [])
        for ph in _ph_src:
            if isinstance(ph, dict) and ph.get("ts"):
                engagement_timeline.append({
                    "ts":     ph.get("ts", ""),
                    "label":  str(ph.get("phase", "")).replace("AttackPhase.", "") or "phase",
                    "detail": ph.get("detail", "") or ph.get("status", ""),
                })
        for step in attack_path:
            if isinstance(step, dict) and (step.get("ts") or step.get("timestamp")):
                engagement_timeline.append({
                    "ts":     step.get("ts") or step.get("timestamp", ""),
                    "label":  step.get("phase") or step.get("technique") or "step",
                    "detail": (step.get("result") or step.get("description")
                               or step.get("source") or "")[:160],
                })
        engagement_timeline = [e for e in engagement_timeline if e.get("ts")]
        engagement_timeline.sort(key=lambda e: str(e.get("ts")))
        engagement_timeline = engagement_timeline[:60]

        # ── Derived fields for the professional (light-theme) report ─────────
        # Purely presentational helpers; additive — the dark-dashboard template
        # ignores them, the professional template uses them for the cover banner,
        # metric cards, and tooling section.
        _sev = {k: int((summary or {}).get(k, 0) or 0)
                for k in ("critical", "high", "medium", "low", "info", "total")}
        _root_flag = any((f or {}).get("flag_type") == "root" for f in (flags or []))
        _user_flag = any((f or {}).get("flag_type") == "user" for f in (flags or []))
        _shelled   = bool(intel.get("shell_access")) or _user_flag or _root_flag
        # ── ONE canonical engagement verdict (identical across every report theme) ──
        # Derived from the SAME normalized counts the metric cards use, so a theme can
        # never print "CRITICAL" while another prints "PARTIAL".  outcome.label is set
        # from it too, so legacy theme code that reads outcome.label stays consistent.
        try:
            from knowledge import severity_policy as _sp_rate
            final_rating, final_rating_label = _sp_rate.compute_final_rating(
                _sev, root=_root_flag, shell=_shelled,
                has_issues=bool(_sev["total"] or discovered_issues))
        except Exception:
            final_rating, final_rating_label = (
                ("critical", "FULL COMPROMISE — ROOT") if _root_flag else
                ("critical", "COMPROMISED — FOOTHOLD") if _shelled else
                ("critical", "CRITICAL — UNEXPLOITED CRITICAL ISSUES") if _sev.get("critical") else
                ("high", "HIGH — SIGNIFICANT ISSUES IDENTIFIED") if _sev.get("high") else
                ("medium", "PARTIAL — ISSUES IDENTIFIED") if (_sev["total"] or discovered_issues) else
                ("none", "RECON ONLY"))
        outcome = {
            "compromised": _shelled or _root_flag or _user_flag,
            "root":        _root_flag,
            "label":       final_rating_label,
            "final_rating": final_rating,
            "final_rating_label": final_rating_label,
        }
        target_display = (session.get("target") or session.get("target_ip")
                          or session.get("target_host") or intel.get("target") or "target")
        # Compact the COVER TITLE for a multi-host engagement — an 88-char comma list
        # of IPs rendered as a 52px serif headline is a wall of text.  Collapse it to
        # "N hosts — 192.168.40.0/24"; the full list still appears in the subtitle,
        # the meta grid, and the appendix (all read session.target, unchanged).
        try:
            _parts = [p.strip() for p in re.split(r"[,\s]+", str(target_display)) if p.strip()]
            if len(_parts) > 2:
                _subnets = set()
                for _p in _parts:
                    _oct = _p.split(".")
                    if len(_oct) == 4:
                        _subnets.add(".".join(_oct[:3]))
                _pfx = (next(iter(_subnets)) + ".0/24") if len(_subnets) == 1 else "multiple subnets"
                target_display = f"{len(_parts)} hosts — {_pfx}"
        except Exception:
            pass
        tools_used = sorted({(t.get("tool") or "").strip()
                             for t in coverage_tests if t.get("tool")})

        # ── Per-finding retest status (drives the register's Verified/Open/Gated
        #    column) + a best-effort, content-agnostic detection/purple-team map.
        try:
            from knowledge.severity_policy import evidence_is_successful as _eok_rs
        except Exception:
            _eok_rs = None
        for _f in (findings or []):
            if isinstance(_f, dict):
                # [S5/S57] A finding may wear a VERIFIED badge ONLY if its OWN evidence
                # confirms it.  The report shipped 13/14 findings "VERIFIED · grounded in
                # the recorded tool output" whose evidence blocks read "filtered" / "0
                # hosts up" / "EXIT 28".  Reconcile the stored verified flag against the
                # evidence so a failed/negating log can never be badged Verified — this
                # also keeps I7's executed-activity ATT&CK gate honest.
                if _f.get("verified") is True and _eok_rs is not None and not _eok_rs(_f):
                    _f["verified"] = False
                    _f.setdefault("verified_downgrade_reason",
                                  "VERIFIED cleared — the cited evidence does not confirm the claim")
                if _f.get("verified") is True:
                    _f["retest_status"] = "Verified"
                elif _f.get("gated_reason"):
                    _f["retest_status"] = "Gated"
                else:
                    _f["retest_status"] = "Open"
                # [S57] Strip leaked Enum reprs (e.g. "AttackPhase.RECON",
                # "FindingSeverity.HIGH") from human-facing fields so the report never
                # prints a nonsensical "Vector: AttackPhase.RECON".  These class prefixes
                # are internal enum names, never legitimate data.
                for _ek in ("phase", "vector", "attack_phase", "attack_vector"):
                    _ev = _f.get(_ek)
                    if isinstance(_ev, str) and _ev:
                        _f[_ek] = re.sub(
                            r"\b(?:AttackPhase|AttackVector|FindingSeverity|Severity|Phase)\.",
                            "", _ev).strip()
        # [I7] ATT&CK is attributed ONLY to EXECUTED activity — a passive banner
        # grab or a NEGATIVE scan result must never manufacture technique coverage
        # (the audit found techniques mapped from passive/negative detections).  A
        # finding is "executed activity" iff it was verified/demonstrated/reproduced,
        # carries a captured PoC, OR its evidence shows a genuinely successful run.
        def _is_executed_activity(_f: Any) -> bool:
            if not isinstance(_f, dict):
                return False
            if (_f.get("verified") is True or _f.get("demonstrated") or _f.get("reproduced")
                    or _f.get("exploited") or _f.get("poc_captured")):
                return True
            if str(_f.get("reproduce_status") or "").strip().lower() in (
                    "reproduced", "confirmed", "verified", "success"):
                return True
            try:
                from knowledge.severity_policy import evidence_is_successful as _eis
                return bool(_eis(_f))
            except Exception:
                return False
        _executed_techs: set = set()
        _passive_techs: set = set()
        for _f in (findings or []):
            if not isinstance(_f, dict):
                continue
            _t = str(_f.get("mitre") or _f.get("mitre_technique") or "").strip().upper()
            if not _t:
                continue
            (_executed_techs if _is_executed_activity(_f) else _passive_techs).add(_t)

        # [I7] Prune the ATT&CK Coverage table: drop a mapping whose recorded outcome
        # was negative/failed, or that is attributable ONLY to a passive/negative
        # detection (present among passive findings, absent from executed ones).
        # Operator-recorded techniques with a success/unknown outcome are preserved.
        try:
            _mm = []
            for _m in (mitre_mappings or []):
                if not isinstance(_m, dict):
                    _mm.append(_m)
                    continue
                _tid = str(_m.get("technique_id") or _m.get("id") or "").strip().upper()
                _outcome = str(_m.get("outcome") or "").strip().lower()
                if _outcome in ("negative", "fail", "failed", "error", "blocked", "not vulnerable"):
                    continue
                if _tid and _tid in _passive_techs and _tid not in _executed_techs:
                    continue
                _mm.append(_m)
            mitre_mappings = _mm
        except Exception:
            pass

        detection_map = []
        for _f in (findings or []):
            if not isinstance(_f, dict):
                continue
            # A technique is shown for a detection row ONLY when the finding is
            # executed activity — passive/negative observations carry no ATT&CK id.
            _exec = _is_executed_activity(_f)
            _tech = str(_f.get("mitre") or _f.get("mitre_technique") or "").strip() if _exec else ""
            _host = _f.get("host") or ""
            detection_map.append({
                "finding":     _f.get("title", ""),
                "technique":   _tech or "—",
                "opportunity": f"Activity on {_host or 'the asset'} consistent with this finding",
                "telemetry":   ("Correlate the producing tool/command with host telemetry"
                                + ("; alert on the " + _tech + " behaviour" if _tech
                                   else " (no executed ATT&CK technique for this observation)")),
                "caught":      "Open",
            })

        # ── AI / LLM security section (Slice 3) — populated ONLY when this
        #    engagement produced AI findings (extra.ai_finding / ai_red_team);
        #    empty {} for a normal pentest so existing reports are unchanged. ──
        ai_security: Dict[str, Any] = {}
        try:
            from utils.cvss_scorer import score_ai_findings as _score_ai
            _ai_scored = _score_ai(findings or [])
            if _ai_scored:
                _by_id = {str(f.get("finding_id") or f.get("id") or ""): f
                          for f in (findings or []) if isinstance(f, dict)}
                _ai_rows: List[Dict[str, Any]] = []
                _by_class: Dict[str, int] = {}
                _asr_vals: List[float] = []
                for _s in _ai_scored:
                    _src = _by_id.get(_s.finding_id, {}) or {}
                    _ex = _src.get("extra") if isinstance(_src.get("extra"), dict) else {}
                    _cls = str(_ex.get("attack_vector") or _ex.get("category") or "ai")
                    _by_class[_cls] = _by_class.get(_cls, 0) + 1
                    try:
                        _asr_vals.append(float(_ex.get("asr")))
                    except (TypeError, ValueError):
                        pass
                    _ai_rows.append({
                        "title":         _s.title or _src.get("title", ""),
                        "severity":      _s.severity,
                        "aivss":         _s.aivss_score,
                        "cvss":          _s.cvss_base,
                        "asr":           int(round(float(_ex.get("asr") or 0) * 100)),
                        "trials":        _ex.get("trials", ""),
                        "successes":     _ex.get("successes", ""),
                        "owasp_llm":     _ex.get("owasp_llm", ""),
                        "atlas":         _ex.get("atlas", "") or _src.get("mitre", ""),
                        "attack_vector": _cls,
                        "vector":        _s.vector,
                        "target_model":  _ex.get("target_model", ""),
                        "evidence":      _src.get("evidence", ""),
                        "remediation":   _src.get("remediation", ""),
                    })
                ai_security = {
                    "findings":      _ai_rows,
                    "count":         len(_ai_rows),
                    "by_class":      _by_class,
                    "max_aivss":     max((r["aivss"] for r in _ai_rows), default=0.0),
                    "avg_asr":       int(round(sum(_asr_vals) / len(_asr_vals) * 100)) if _asr_vals else 0,
                    "owasp_classes": sorted({r["owasp_llm"].split()[0] for r in _ai_rows if r["owasp_llm"]}),
                }
        except Exception:
            ai_security = {}

        # ── Reproducibility + basis-of-claim (report defensibility) ──────────
        #    Every finding is enriched with the EXACT human-rerunnable steps ARGUS
        #    executed (real recorded commands only — never fabricated).  A compromise
        #    claim additionally gets a transparency block: the BASIS it rests on,
        #    whether a proof artifact was captured, and — when not — the honest reason
        #    plus the method steps, so a client can manually reproduce and verify.
        compromise_evidence: Dict[str, Any] = {}
        try:
            from knowledge import severity_policy as _sp_repro
            for _f in (findings or []):
                if not isinstance(_f, dict):
                    continue
                _f["reproduction"] = _sp_repro.build_reproduction(_f, coverage_tests)
                _bk, _bnote = _sp_repro.finding_basis(_f)
                _f.setdefault("basis_kind", _bk)
                if _bnote:
                    _f.setdefault("basis_note", _bnote)
            compromise_evidence = _sp_repro.compromise_evidence_state(
                findings, flags, intel, coverage_tests, loot_entries)
        except Exception:
            compromise_evidence = {}

        # ── Charts: server-side inline SVG (WeasyPrint runs no JavaScript) ────
        #    The chart engine takes primitives; we adapt the real scan data here.
        charts: Dict[str, Any] = {}
        try:
            from report import charts as _ch
            _rating_ratio = {"critical": 1.0, "high": 0.78, "medium": 0.52,
                             "low": 0.30, "none": 0.08, "info": 0.16}
            _rating_color = {"critical": "#c0392b", "high": "#e8743b", "medium": "#d9a441",
                             "low": "#3d7fc1", "none": "#2f9e5f", "info": "#7a8699"}
            _cov_rows = [{"label": str(k).capitalize(), "value": int(v),
                          "color": _ch.OUTCOME_COLORS.get(str(k).lower(), _ch.ACCENT)}
                         for k, v in (coverage_counts or {}).items() if v]
            _tac: Dict[str, int] = {}
            for _m in (mitre_mappings or []):
                _t = str((_m or {}).get("tactic") or "").strip() or "Uncategorised"
                _tac[_t] = _tac.get(_t, 0) + 1
            _mitre_rows = [{"label": k, "value": v, "color": "#15233b"}
                           for k, v in sorted(_tac.items(), key=lambda kv: -kv[1])][:10]
            _kc: List[Dict[str, Any]] = []
            for _s in (attack_path if isinstance(attack_path, list) else []):
                if not isinstance(_s, dict):
                    continue
                _lbl = str(_s.get("result") or _s.get("label") or _s.get("phase") or "").strip()
                if _lbl:
                    _kc.append({"label": _lbl[:60], "phase": _s.get("phase") or ""})
            if not _kc and isinstance(graph, dict):
                for _nd in (graph.get("nodes") or []):
                    if isinstance(_nd, dict) and _nd.get("label"):
                        _kc.append({"label": str(_nd.get("label"))[:60],
                                    "phase": _nd.get("phase") or _nd.get("node_type") or ""})
            # Author each chart at the width it actually renders (no CSS down-scaling →
            # SVG text stays crisp): ~300px in a .panel-2 cell, ~640px full-width.
            charts = {
                "severity_donut": _ch.severity_donut(_sev, size=300),
                "risk_gauge":     _ch.risk_gauge(_rating_ratio.get(final_rating, 0.5),
                                                 (final_rating or "info").upper(),
                                                 _rating_color.get(final_rating, "#c0392b")),
                "severity_stack": _ch.stacked_severity_bar(_sev, width=640),
                "coverage_bars":  _ch.hbar_chart(_cov_rows, width=300) if _cov_rows else "",
                "mitre_tactics":  _ch.hbar_chart(_mitre_rows, width=640) if _mitre_rows else "",
                "killchain":      _ch.killchain(_kc) if _kc else "",
                "has_any":        True,
            }
        except Exception:
            charts = {}

        # [I3] finalize the disclosed store->report reconciliation (every assessed finding
        # accounted for; totals reconcile; downgrades are counted, never silent).
        try:
            _recon["reported_total"] = len([f for f in (findings or []) if isinstance(f, dict)])
            # [P3] Reconcile to the RAW STORE: raw = validator-rejected + policy-dropped +
            # deduped + reported.  Every stored finding is accounted for, including the ones
            # the Issue-Validator rejected before assessment — no silent completeness claim.
            _recon["reconciles"] = (
                _recon.get("raw_store_total", _recon.get("assessed", 0)) ==
                _recon.get("validator_rejected", 0) + _recon.get("dropped_unsupported", 0)
                + _recon.get("deduped", 0) + _recon["reported_total"])
            _recon["note"] = (
                "%d in store -> %d rejected by the issue-validator, %d dropped as unsupported/"
                "tool-noise, %d de-duplicated -> %d reported (%d re-graded to an honest severity; "
                "%d downgraded from HIGH+ each with a stated rationale)." % (
                    _recon.get("raw_store_total", _recon.get("assessed", 0)),
                    _recon.get("validator_rejected", 0), _recon.get("dropped_unsupported", 0),
                    _recon.get("deduped", 0), _recon["reported_total"],
                    _recon.get("regraded", 0), _recon.get("downgraded_from_high", 0)))
        except Exception:
            _recon = {"note": "", "reconciles": True}
        return {
            "findings_reconciliation": _recon,
            "ai_security":       ai_security,
            "compromise_evidence": compromise_evidence,
            "charts":            charts,
            "session":           session,
            "findings":          findings,
            "hosts_report":      hosts_report,
            "detection_map":     detection_map,
            "summary":           summary,
            "sev":               _sev,
            "outcome":           outcome,
            "final_rating":       final_rating,
            "final_rating_label": final_rating_label,
            "target_display":    target_display,
            "tools_used":        tools_used,
            "flags":             flags,
            "graph":             graph,
            "intel":             intel,
            "coverage_tests":    coverage_tests,
            "coverage_counts":   coverage_counts,
            "discovered_issues": discovered_issues,
            "engagement_timeline": engagement_timeline,
            "mitre_mappings":    mitre_mappings,
            "duration":          duration,
            "phases_completed":  session.get("phases_completed", []),
            "all_phases":        all_phases,
            "executive_summary": executive_summary,
            "generated_at":      datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            # ── New fields for objectives and reasoning journal sections ─────
            "engagement_type":   engagement_type,
            "objectives":        objectives_rows,
            "objectives_done":   sum(1 for o in objectives_rows if o["answered"]),
            "objectives_total":  len(objectives_rows),
            "reasoning_journal": journal_display,
            "journal_truncated": len(reasoning_journal) > len(journal_display),
            "journal_total":     len(reasoning_journal),
            # ── B-6 — new platform-output sections ──────────────────────
            "loot_entries":      loot_entries,
            "loot_summary":      loot_summary,
            "loot_by_doi":       loot_by_doi,
            "web_intel_hints":   web_intel_hints,
            "primer_rows":       primer_rows,
            "attack_path":       attack_path,
            "creds_summary":     creds_summary,
            # ── Objective outcomes + exploit selection (for the comprehensive
            #    PDF and the objectives section) ──────────────────────────────
            "win_conditions":    intel_snapshot.get("win_conditions") or {},
            "mission_brief":     intel_snapshot.get("mission_brief") or {},
            "exploit_modules":   list(intel_snapshot.get("exploit_modules") or [])[:25],
        }

    # ------------------------------------------------------------------
    # Executive-summary synthesis (heuristic, no LLM required)
    # ------------------------------------------------------------------

    def _build_executive_summary(
        self,
        session:         Dict,
        summary:         Dict,
        flags:           list,
        intel:           Dict,
        duration:        str,
        engagement_type: str,
        objectives_rows: list,
        findings:        list,
    ) -> str:
        """
        Produce a 2-3 sentence executive summary from real session data.
        Avoids boilerplate — every report reads differently based on outcomes.
        """
        target = session.get("target_ip") or session.get("target_hostname") or "the target"
        crit   = int(summary.get("critical", 0) or 0)
        high   = int(summary.get("high", 0) or 0)
        medium = int(summary.get("medium", 0) or 0)
        low    = int(summary.get("low", 0) or 0)
        total  = int(summary.get("total", 0) or 0)

        eng_label = {
            "pentest":          "penetration test",
            "ctf":              "CTF engagement",
            "forensics":        "forensics investigation",
            "network_analysis": "network traffic analysis",
            "malware_analysis": "malware analysis engagement",
            "compliance":       "compliance assessment",
            "bug_bounty":       "bug bounty assessment",
            "red_team":         "red team engagement",
        }.get(engagement_type, "security assessment")

        # Severity phrase
        if crit:
            sev_phrase = f"{crit} critical and {high} high severity issue(s)"
        elif high:
            sev_phrase = f"{high} high severity issue(s)"
        elif medium:
            sev_phrase = f"{medium} medium severity issue(s)"
        elif low:
            sev_phrase = f"{low} low severity issue(s)"
        elif total:
            sev_phrase = f"{total} informational finding(s)"
        else:
            sev_phrase = "no significant issues"

        # Opening sentence
        parts = [
            f"This {eng_label} against {target} ran for {duration} and surfaced {sev_phrase}."
        ]

        # Foothold / flag phrase
        shell = bool(intel.get("shell_access"))
        if shell:
            parts.append(
                f"The engagement achieved an interactive foothold on the target; "
                f"any privilege escalation path and post-exploitation access should be treated as urgent."
            )
        elif flags:
            parts.append(
                f"{len(flags)} flag(s) or high-value artifact(s) were captured during the assessment."
            )

        # Objectives phrase
        if objectives_rows:
            done  = sum(1 for o in objectives_rows if o["answered"])
            total_obj = len(objectives_rows)
            if done == total_obj:
                parts.append(f"All {total_obj} defined objective(s) were answered.")
            else:
                parts.append(f"{done}/{total_obj} defined objective(s) were answered — see the Objectives section for details.")

        # Remediation sentence
        if crit or high:
            parts.append(
                "Priority remediation items are listed in the Remediation Roadmap; "
                "critical and high findings should be triaged first."
            )
        elif total:
            parts.append(
                "Remediation guidance is provided per finding in the Detailed Findings section."
            )
        else:
            parts.append(
                "No remediation is required for this engagement; continue routine monitoring."
            )

        return " ".join(parts)
