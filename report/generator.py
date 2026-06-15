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
{% set overall_risk = "critical" if summary.critical > 0 else ("high" if summary.high > 0 else ("medium" if summary.medium > 0 else "low")) %}
{% set risk_text = {
  "critical": "Critical Risk — Immediate Action Required",
  "high":     "High Risk — Urgent Remediation Needed",
  "medium":   "Medium Risk — Schedule Remediation",
  "low":      "Low Risk — Monitor and Review"
} %}
<div class="risk-banner {{ overall_risk }}" style="margin-top: 40px;">
  <div>
    <div class="risk-label">Overall Risk Rating</div>
    <div class="risk-value">{{ overall_risk | upper }}</div>
  </div>
  <div class="risk-desc">{{ risk_text[overall_risk] }}</div>
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
        Generate a REAL PDF, always.

        Order of attempts (best fidelity first), with a guaranteed fallback so we
        NEVER return HTML masquerading as a PDF (the old behaviour: when
        wkhtmltopdf was absent this returned None, the endpoint served HTML, and
        the browser saved it as `.pdf` → a file that opened as a "corrupted PDF"):
          1. wkhtmltopdf   — renders the full styled HTML (if the binary exists)
          2. weasyprint    — pure-python HTML→PDF (if importable)
          3. pdf_writer    — stdlib-only structured PDF built from the SAME
                             context that feeds the HTML; always succeeds.
        """
        ctx  = await self._build_context(session_id)
        html = self._template.render(**ctx)

        pdf = await self._wkhtmltopdf_bytes(html)
        if pdf:
            return pdf

        # 2) weasyprint — renders the styled HTML without any system binary.
        try:
            import weasyprint  # type: ignore
            return weasyprint.HTML(string=html).write_pdf()
        except Exception:
            pass

        # 3) Guaranteed, dependency-free structured PDF from the context.
        try:
            from report.pdf_writer import lines_to_pdf, report_lines_from_context
            target = (ctx.get("session") or {}).get("target", "target")
            return lines_to_pdf(report_lines_from_context(ctx),
                                title=f"ARGUS Report — {target}")
        except Exception as exc:                       # noqa: BLE001
            print(f"[REPORT] stdlib PDF fallback failed: {exc}")
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
        findings = await db.get_findings(session_id)
        summary  = await db.get_findings_summary(session_id)
        flags    = await db.get_flags(session_id)
        graph    = await db.get_attack_graph(session_id)

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

        return {
            "session":           session,
            "findings":          findings,
            "summary":           summary,
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
