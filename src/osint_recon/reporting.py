"""Portable, escaped reports without external assets or executable content."""

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, StrictUndefined

from .demo import DEMO_LABEL, DEMO_MODE

TEMPLATE = """<!doctype html>
<html lang="en" {% if view.demo %}data-classification="{{ label }}"{% endif %}>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{% if view.demo %}SYNTHETIC TRAINING — {% endif %}OSINT assessment — {{ r.target.value }}</title>
<style>

:root {
  color-scheme: light;
  --bg: #f1f5fa;
  --panel: #ffffff;
  --line: #cdd9e6;
  --muted: #52657b;
  --text: #17283b;
  --blue: #245dc5;
  --cyan: #087d83;
  --amber: #8b5b0c;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: linear-gradient(180deg, #eaf2fc 0, #f5f8fc 500px, var(--bg) 100%);
  color: var(--text);
  font: 16px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  overflow-wrap: anywhere;
}
a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }
a:focus-visible, summary:focus-visible { outline: 3px solid var(--blue); outline-offset: 5px; }
header, main, footer { width: 100%; max-width: 1240px; margin: auto; padding: 0 32px; min-width: 0; }
header { padding-top: 32px; }
.masthead { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding-bottom: 22px; border-bottom: 2px solid #b9cee7; }
.brand { display: flex; gap: 13px; align-items: center; color: #163656; font-size: 19px; font-weight: 750; letter-spacing: .015em; }
.brand-mark { width: 38px; height: 44px; color: var(--cyan); flex-shrink: 0; }
.brand small { display: block; color: var(--muted); font-size: 12px; letter-spacing: .1em; font-weight: 600; margin-top: 3px; }
.eyebrow { text-transform: uppercase; letter-spacing: .1em; font-size: 13px; color: var(--cyan); font-weight: 750; }
.pill, .badge { display: inline-flex; align-items: center; gap: 7px; border-radius: 22px; font-size: 13px; line-height: 1.5; padding: 5px 11px; border: 1px solid #bbcee2; background: #f3f7fd; font-weight: 650; }
.pill { color: #244d78; flex-shrink: 0; }
.pill:before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: var(--cyan); }
.training-banner { margin-top: 24px; display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; border: 1px solid #ddc38f; border-left: 4px solid #b47a19; background: #fff8e8; border-radius: 9px; padding: 14px 17px; color: #694710; font-size: 14px; }
.training-banner strong { font-size: 13px; line-height: 1.6; }
.training-banner span { color: #735319; }
.intro { padding: 32px 0 24px; display: flex; justify-content: space-between; gap: 28px; align-items: flex-end; }
.intro > div { min-width: 0; }
.intro h1 { font-size: clamp(30px, 2.5vw, 36px); line-height: 1.22; margin: 10px 0 12px; font-weight: 700; letter-spacing: -.7px; }
.target { font-size: 20px; font-weight: 600; color: #274b6d; }
.metadata { text-align: right; font-size: 13px; color: var(--muted); min-width: 215px; line-height: 1.8; }
.report-nav { display: flex; flex-wrap: wrap; gap: 12px 26px; font-size: 15px; border-bottom: 1px solid var(--line); padding: 12px 0 20px; margin-bottom: 28px; }
.report-nav a { padding: 6px 0; font-weight: 600; }
section { scroll-margin-top: 20px; margin: 28px 0; }
.section-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px 18px; margin-bottom: 16px; }
.section-heading h2 { font-size: 24px; font-weight: 700; letter-spacing: -.3px; margin: 0; }
.section-heading small { color: var(--muted); font-size: 14px; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
.metric, .panel, .finding, .evidence-card { background: var(--panel); border: 1px solid var(--line); border-radius: 11px; box-shadow: 0 5px 15px #1b3d6410; min-width: 0; }
.metric { padding: 20px; border-top: 3px solid #a9c7e8; }
.metric:nth-child(2) { border-top-color: #6fb5b6; }
.metric:nth-child(3) { border-top-color: #c8b2e3; }
.metric:nth-child(4) { border-top-color: #dfbc77; }
.metric .metric-label { color: #435b74; font-size: 15px; font-weight: 600; }
.metric strong { display: block; font-size: 34px; font-weight: 700; line-height: 1.25; margin: 10px 0 7px; letter-spacing: -.7px; }
.metric small { color: var(--muted); font-size: 14px; line-height: 1.55; display: block; }
.metric .accent { color: var(--cyan); }
.summary { margin-top: 20px; padding: 19px 22px; border: 1px solid #c9dbee; border-left: 4px solid var(--blue); background: #eaf2fb; border-radius: 0 9px 9px 0; color: #254767; }
.summary p { margin: 0; }
.summary small { display: block; color: var(--muted); margin-top: 8px; font-size: 14px; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
.panel { padding: 22px; }
.panel h3 { margin: 0 0 20px; font-size: 22px; font-weight: 650; line-height: 1.35; }
.coverage-row, .vendor-row { display: grid; grid-template-columns: minmax(90px, 120px) minmax(0, 1fr) minmax(25px, auto); gap: 14px; align-items: center; font-size: 14px; margin: 16px 0; }
.track { height: 9px; background: #e3ebf4; border-radius: 10px; overflow: hidden; }
.fill { height: 100%; background: var(--blue); border-radius: 10px; }
.fill.synthetic { background: #6e64b5; }
.fill.unavailable { background: #c18b2e; }
.fill.error { background: #b95066; }
.legend { display: flex; flex-wrap: wrap; gap: 14px; font-size: 13px; color: var(--muted); margin-top: 20px; }
.legend i { display: inline-block; width: 7px; height: 7px; background: var(--cyan); border-radius: 100%; margin-right: 5px; }
.fineprint { font-size: 14px; color: var(--muted); margin: 14px 0 0; }
.ports { display: flex; gap: 9px; flex-wrap: wrap; }
.port { font: 14px ui-monospace, monospace; background: #e8f5f4; color: #176b6b; border: 1px solid #b6d9d7; border-radius: 7px; padding: 8px 12px; }
.source-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.source-table th { text-align: left; font-size: 13px; color: #486078; font-weight: 650; letter-spacing: .035em; padding: 14px; border-bottom: 1px solid var(--line); background: #eef4fb; }
.source-table td { padding: 15px 14px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
.source-table tr:last-child td { border-bottom: 0; }
.source-table td:first-child { font-weight: 650; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); min-width: 0; }
.status-observed { color: #17675a; background: #e8f6f0; border-color: #acd4c6; }
.status-synthetic { color: #775017; background: #fff4dc; border-color: #dfc28b; }
.status-unavailable { color: #7b5a19; background: #faf2e0; border-color: #ddc99f; }
.status-error { color: #973a50; background: #fdeef1; border-color: #e0b1bc; }
.finding { padding: 22px 24px; margin: 15px 0; border-left: 4px solid var(--blue); }
.finding-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 15px; }
.finding h3 { font-size: 21px; line-height: 1.4; margin: 0; }
.finding p { margin: 15px 0; color: #334e69; }
.recommendation { border-top: 1px solid var(--line); padding-top: 15px; font-size: 15px; }
.recommendation strong { color: var(--cyan); font-size: 13px; letter-spacing: .04em; display: block; margin-bottom: 7px; }
.evidence-card { margin: 18px 0; overflow: hidden; }
.evidence-head { display: flex; align-items: center; justify-content: space-between; gap: 15px; padding: 18px 22px; border-bottom: 1px solid var(--line); background: #f0f5fb; }
.evidence-head h3 { margin: 0; font-size: 22px; }
.evidence-content { padding: 21px 22px; }
.evidence-meta { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; font-size: 15px; margin-bottom: 20px; }
.evidence-meta > div { min-width: 0; }
.evidence-meta span { display: block; color: var(--muted); font-size: 13px; font-weight: 600; margin-bottom: 4px; }
.evidence-meta code { font-size: 14px; overflow-wrap: anywhere; }
.fields { width: 100%; table-layout: fixed; border-collapse: collapse; font-size: 14px; }
.fields td { padding: 11px 0; border-top: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
.fields td:first-child { color: var(--muted); width: 30%; padding-right: 18px; }
.fields code { white-space: pre-wrap; overflow-wrap: anywhere; font: 14px/1.6 ui-monospace, SFMono-Regular, monospace; }
details { margin-top: 20px; border-top: 1px solid var(--line); }
summary { cursor: pointer; padding: 14px 0 2px; color: var(--blue); font-size: 15px; font-weight: 650; }
pre { background: #f2f6fb; border: 1px solid var(--line); padding: 17px; border-radius: 8px; font: 14px/1.65 ui-monospace, SFMono-Regular, monospace; white-space: pre-wrap; overflow-wrap: anywhere; color: #284662; max-height: 520px; overflow: auto; }
.empty { border: 1px dashed #aabdd1; border-radius: 10px; padding: 25px; color: var(--muted); background: #f8fafd; }
.scope { padding: 22px; border: 1px solid var(--line); border-radius: 10px; background: #edf4fb; font-size: 15px; color: #435d77; }
.scope strong { display: block; color: var(--text); margin-bottom: 9px; }
footer { font-size: 12px; color: var(--muted); padding-top: 20px; padding-bottom: 30px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px 20px; border-top: 1px solid var(--line); margin-top: 30px; }
.print-note { display: none; }
@media(max-width: 850px) {
  .intro { display: block; padding-top: 26px; }
  .metadata { text-align: left; min-width: 0; margin-top: 16px; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .grid { grid-template-columns: 1fr; }
}
@media(max-width: 560px) {
  header, main, footer { padding-left: 18px; padding-right: 18px; }
  .intro h1 { font-size: 30px; }
  .masthead { align-items: flex-start; flex-wrap: wrap; }
  .training-banner { display: block; }
  .training-banner span { display: block; margin-top: 7px; }
  .section-heading { display: block; }
  .section-heading small { display: block; margin-top: 5px; }
  .finding-head { display: block; }
  .finding-head .badge { margin-top: 11px; }
  .evidence-meta { grid-template-columns: 1fr; }
  .metric { padding: 16px; }
  .source-table { min-width: 580px; }
  .source-table td, .source-table th { padding: 12px; }
  .coverage-row, .vendor-row { grid-template-columns: minmax(80px, 100px) minmax(0, 1fr) minmax(20px, auto); gap: 10px; }
  .panel, .evidence-content { padding: 18px; }
  .evidence-head { padding: 16px 18px; }
}
@page{size:A4;margin:14mm 13mm 15mm}
@media print {
  :root { color-scheme: light; --bg: #fff; --text: #17283b; --muted: #536479; --line: #c9d4df; --cyan: #147f7a; --blue: #357bc0; }
  html, body { background: #fff !important; color: #17283b !important; font-size: 11pt; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  header, main, footer { width: 100%; max-width: none; padding: 0; }
  header { padding-top: 0; }
  .masthead { padding-bottom: 12px; }
  .brand { font-size: 15pt; }
  .brand-mark { height: 32px; }
  .brand small, .eyebrow, .metadata, .metric .metric-label, .metric small, .fineprint, .legend, .section-heading small, footer, .evidence-meta span, .fields td:first-child { color: #536479 !important; }
  .brand small, .eyebrow, .metadata, .badge, footer { font-size: 9.5pt; }
  .intro { display: block; padding: 18px 0 14px; }
  .intro h1 { font-size: 22pt; }
  .target { font-size: 14pt; }
  .metadata { text-align: left; margin-top: 10px; min-width: 0; }
  .report-nav { display: none; }
  .training-banner { background: #fff7e3 !important; border-color: #d2b878 !important; color: #5e471d !important; margin-top: 14px; padding: 10px 13px; font-size: 10pt; }
  .training-banner strong, .training-banner span { color: #5e471d !important; font-size: 10pt; }
  .metric, .panel, .finding, .evidence-card, .scope, .table-wrap { background: #fff !important; border-color: #c9d4df !important; box-shadow: none; border-radius: 6px; }
  .summary { background: #f0f5fa !important; border-color: #3977b9; }
  .metric strong { font-size: 22pt; }
  .metric .accent { color: #147f7a !important; }
  .grid { gap: 12px; }
  .panel { padding: 15px; }
  .metrics { gap: 10px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .metric { padding: 12px 15px; }
  .metric .metric-label, .metric small, .fineprint, .coverage-row, .vendor-row, .recommendation, .scope, .summary small, .section-heading small, .evidence-meta { font-size: 10.5pt; }
  .track { background: #e4ebf1 !important; }
  .fill { background: #357bc0 !important; }
  .fill.synthetic { background: #7568ad !important; }
  .fill.unavailable { background: #c29035 !important; }
  .fill.error { background: #c25763 !important; }
  .source-table, .fields { min-width: 0; width: 100%; font-size: 10.5pt; }
  .source-table { table-layout: fixed; }
  .source-table th, .source-table td { padding: 9px; border-color: #dce4eb; }
  .source-table th { font-size: 10pt; color: #536479; }
  .source-table thead { display: table-header-group; }
  .table-wrap { overflow: visible; border-radius: 0; }
  .source-table tr, .fields tr { break-inside: avoid; }
  .finding, .panel, .scope { break-inside: avoid; }
  .finding { padding: 15px 18px; }
  .finding h3, .evidence-head h3 { font-size: 14pt; }
  .recommendation strong { color: #147f7a; font-size: 10pt; }
  .evidence-head { padding: 13px 17px; border-color: #dce4eb; break-after: avoid; background: #f0f5fa !important; }
  .evidence-content { padding: 13px 17px; }
  .evidence-card { break-inside: auto; overflow: visible; }
  .fields td { border-color: #dce4eb; padding: 7px 0; }
  .fields code, .evidence-meta code, pre { font-size: 10pt; line-height: 1.55; }
  pre { background: #f3f6f9 !important; color: #203349 !important; border-color: #dce4eb; max-height: none; overflow: visible; break-inside: auto; }
  details { border-color: #dce4eb; }
  summary { color: #2b66a4; font-size: 10.5pt; }
  .print-note { display: block; font-size: 10pt; color: #536479; }
  .ports .port { background: #eaf5f5 !important; color: #1d6967 !important; border-color: #9cc7c6; font-size: 10.5pt; }
  .scope { color: #536479; }
  .scope strong { color: #17283b; }
  .status-observed { background: #e6f5ee !important; color: #1d6652 !important; border-color: #9cc8b8; }
  .status-synthetic, .status-unavailable { background: #fbf1de !important; color: #805c21 !important; border-color: #ddc28c; }
  .status-error { background: #fce9ed !important; color: #91404c !important; border-color: #dfa6b0; }
  section { margin: 22px 0; }
  .section-heading { margin-bottom: 12px; break-after: avoid; }
  .section-heading h2 { font-size: 16pt; }
  footer { margin-top: 20px; padding-top: 12px; break-inside: avoid; }
}
</style></head>
<body>
<header><div class="masthead"><div class="brand"><svg class="brand-mark" viewBox="0 0 32 38" fill="none" aria-hidden="true"><path d="M16 2 29 7v11c0 8-6 14-13 18C9 32 3 26 3 18V7L16 2Z" stroke="currentColor" stroke-width="1.5"/><path d="m9 19 5 5 9-11" stroke="currentColor" stroke-width="2"/></svg><div>RECON <span style="color:var(--cyan)">TOOLKIT</span><small>EXTERNAL INTELLIGENCE ASSESSMENT</small></div></div><span class="pill">{% if view.demo %}DEMO · Synthetic{% else %}LIVE · Source retrieval{% endif %}</span></div>
{% if view.demo %}<aside class="training-banner" role="note"><strong>{{ label }}</strong><span>Offline demonstration · 0 live observations · Nothing was retrieved from providers.</span></aside>{% endif %}
<div class="intro"><div><div class="eyebrow">{% if view.demo %}Training assessment{% else %}Intelligence assessment{% endif %}</div><h1>{% if view.demo %}Offline OSINT workflow demonstration{% else %}External intelligence assessment{% endif %}</h1><div class="target">{{ r.target.value }}</div></div><div class="metadata">REPORT GENERATED<br><strong>{{ r.generated_at|timestamp }}</strong><br>{{ r.target.kind|upper }} · Schema {{ r.schema_version }}</div></div>
<nav class="report-nav" aria-label="Report sections"><a href="#overview">Overview</a><a href="#findings">Findings &amp; recommendations</a><a href="#evidence">Source evidence</a><a href="#scope">Scope &amp; methodology</a></nav></header>
<main>
<section id="overview"><div class="section-heading"><h2>Executive summary</h2><small>{% if view.demo %}Fictional scenario · {{ r.scenario_id }}{% else %}Passive, read-only collection{% endif %}</small></div>
<div class="metrics"><div class="metric"><div class="metric-label">Sources selected</div><strong>{{ view.source_count }}</strong><small>Independently attributed records</small></div><div class="metric"><div class="metric-label">{% if view.demo %}Synthetic examples{% else %}Records retrieved{% endif %}</div><strong class="accent">{% if view.demo %}{{ view.counts.synthetic }}{% else %}{{ view.counts.observed }}{% endif %}<span style="font-size:16px;color:var(--muted)"> / {{ view.source_count }}</span></strong><small>{% if view.demo %}Training fixtures only{% else %}Confirmed source responses{% endif %}</small></div><div class="metric"><div class="metric-label">Review items</div><strong>{{ r.findings|length }}</strong><small>{% if view.demo %}Synthetic training findings{% else %}Analyst verification required{% endif %}</small></div><div class="metric"><div class="metric-label">Coverage gaps</div><strong>{{ view.counts.unavailable + view.counts.error }}</strong><small>Unavailable or failed retrievals</small></div></div>
<div class="summary"><p>{% if view.demo %}This fictional scenario illustrates registration context, indexed services and vendor reputation. No real asset was assessed.{% else %}{{ r.summary.interpretation }}{% endif %}</p><small>{% if view.demo %}Fixture dates are synthetic; the generation timestamp records report preparation only.{% else %}Source observations do not prove current reachability, ownership, vulnerability or compromise. No target scanning or independent validation was performed.{% endif %}</small></div>
<div class="grid" style="margin-top:18px"><div class="panel"><h3>Source coverage</h3>{% for status, count in view.counts.items() %}{% if count or status in ['observed','unavailable','error'] %}<div class="coverage-row"><span>{{ status|capitalize }}</span><div class="track"><div class="fill {{ status }}" style="width:{{ (count * 100 / view.source_count) if view.source_count else 0 }}%"></div></div><strong>{{ count }}</strong></div>{% endif %}{% endfor %}<p class="fineprint">Coverage describes retrieval availability, not a security or risk score.</p></div>
<div class="panel"><h3>{% if view.vendors %}Vendor classification distribution{% else %}Indexed service context{% endif %}</h3>{% if view.vendors %}{% for name,count in view.vendors.items() %}<div class="vendor-row"><span>{{ name|replace('_',' ')|capitalize }}</span><div class="track"><div class="fill{% if name in ['malicious','suspicious'] %} unavailable{% endif %}" style="width:{{ (count * 100 / view.vendor_total) if view.vendor_total else 0 }}%"></div></div><strong>{{ count }}</strong></div>{% endfor %}<p class="fineprint">{% if view.demo %}Invented training counts; no real vendor verdict is asserted.{% else %}Provider-reported classifications; disagreement and false positives require review.{% endif %}</p>{% elif view.ports %}<div class="ports">{% for port in view.ports %}<span class="port">Port {{ port }}</span>{% endfor %}</div><p class="fineprint">Port identifiers are source-reported metadata. Protocol and present reachability are not independently verified.</p>{% else %}<div class="empty">No service or vendor data available.</div><p class="fineprint">Missing intelligence is not evidence that a target is secure.</p>{% endif %}</div></div>
</section>
<section><div class="section-heading"><h2>Source summary</h2><small>{% if view.demo %}Local fictional records{% else %}Availability &amp; provenance{% endif %}</small></div><div class="table-wrap"><table class="source-table"><thead><tr><th>Source</th><th>Target / asset</th><th>Status</th><th>{% if view.demo %}Fixture timestamp{% else %}Collection timestamp{% endif %}</th></tr></thead><tbody>{% for e in r.evidence %}<tr{% if view.demo %} data-classification="{{ label }}"{% endif %}><td>{{ e.source }}</td><td>{{ e.target }}</td><td><span class="badge status-{{ e.status }}">{{ e.status|capitalize }}</span></td><td>{{ e.collected_at|timestamp }}</td></tr>{% else %}<tr><td colspan="4">No source evidence is present.</td></tr>{% endfor %}</tbody></table></div></section>
<section id="findings"><div class="section-heading"><h2>Findings &amp; recommendations</h2><small>{{ r.findings|length }} review item{% if r.findings|length != 1 %}s{% endif %}</small></div>{% for f in r.findings %}<article class="finding"{% if view.demo %} data-classification="{{ label }}"{% endif %}><div class="finding-head"><h3>{{ f.title|training_text(view.demo) }}</h3><span class="badge">{% if view.demo %}Synthetic · {% endif %}{{ f.severity|replace('training exercise — ','') }}</span></div><p>{{ f.interpretation|training_text(view.demo) }}</p><div class="recommendation"><strong>{{ f.source }} · Recommended action</strong>{{ f.recommendation }}</div></article>{% else %}<div class="empty">No evidence-supported findings generated. This does not establish that the target is secure.</div>{% endfor %}</section>
<section id="evidence"><div class="section-heading"><h2>Source evidence</h2><small>Selected fields &amp; inspectable JSON</small></div>{% for e in r.evidence %}<article class="evidence-card"{% if view.demo %} data-classification="{{ label }}"{% endif %}><div class="evidence-head"><h3>{{ e.source }}</h3><span class="badge status-{{ e.status }}">{% if view.demo %}Synthetic fixture{% else %}{{ e.status|capitalize }}{% endif %}</span></div><div class="evidence-content"><div class="evidence-meta"><div><span>RECORD TARGET</span>{{ e.target }}</div><div><span>{% if view.demo %}Synthetic fixture timestamp{% else %}COLLECTED{% endif %}</span>{{ e.collected_at|timestamp }}</div><div style="grid-column:1/-1"><span>{% if view.demo %}LOCAL FIXTURE IDENTIFIER{% else %}SOURCE ENDPOINT{% endif %}</span><code>{{ e.endpoint }}</code></div></div>{% if e.observations %}<table class="fields" aria-label="{{ e.source }} evidence fields"><tbody>{% for key,value in e.observations.items() %}<tr><td>{{ key|replace('_',' ')|capitalize }}</td><td>{% if key in ['last_analysis_date','last_modification_date'] and value is number %}{{ value|timestamp }}{% elif value is mapping or (value is sequence and value is not string) %}<code>{{ value|tojson }}</code>{% else %}{{ value }}{% endif %}</td></tr>{% endfor %}</tbody></table>{% else %}<p class="fineprint">{{ e.message }}</p>{% endif %}<details><summary>Inspect normalized evidence JSON</summary><pre>{{ e.observations|tojson(indent=2) }}</pre></details><p class="fineprint">{% if view.demo %}Synthetic training fixture; no provider contact or source verification.{% else %}{{ e.message }} {{ e.verification }}{% endif %}</p></div></article>{% endfor %}</section>
<section id="scope"><div class="section-heading"><h2>Scope &amp; methodology</h2></div><div class="scope"><strong>{% if view.demo %}Offline training scenario{% else %}Authorized passive intelligence{% endif %}</strong>{% if view.demo %}{{ r.scope }} All training findings and source examples retain synthetic provenance in JSON and CSV exports.{% else %}Scope: one operator-approved target, {{ r.target.value }}. Only existing third-party records were retrieved. Source timestamps describe provider records; collection timestamps describe retrieval. Coverage, licensing, historical accuracy and asset ownership require analyst review. Retain reports under organizational evidence-handling policy.{% if r.get('authorization') %}<p>Authorization record: {{ r.authorization|tojson }}</p>{% endif %}{% endif %}</div><p class="print-note">Raw JSON is available in the companion assessment.json export. Expand disclosure panels before printing to include full raw records.</p></section>
</main><footer{% if view.demo %} data-classification="{{ label }}"{% endif %}><span>OSINT RECON TOOLKIT</span><span>{% if view.demo %}DEMO · Synthetic training data{% else %}LIVE · Analyst review required{% endif %} · {{ r.generated_at|timestamp }}</span></footer>
</body></html>
"""


def redact(value, secrets):
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {redact(str(k), secrets): redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    return value


def prepare_report(report, secrets=()):
    # Longest-first replacement prevents a shorter key exposing a longer key's prefix.
    secrets = sorted({secret for secret in secrets if secret}, key=len, reverse=True)
    report = redact(report, secrets)
    demo = report.get("mode") == DEMO_MODE
    synthetic = [
        record.get("is_synthetic", False) or record.get("status") == "synthetic"
        for record in report["evidence"] + report["findings"]
    ]
    if demo:
        if (
            report.get("is_synthetic") is not True
            or any(
                record.get("is_synthetic") is not True
                for record in report["evidence"] + report["findings"]
            )
            or any(record.get("status") != "synthetic" for record in report["evidence"])
        ):
            raise ValueError(
                "Demo exports require exclusively synthetic records and findings."
            )
    elif report.get("is_synthetic") or any(synthetic):
        raise ValueError("Synthetic evidence cannot be exported as live intelligence.")
    return report


def readable_timestamp(value):
    """Readable UTC timestamp; preserve unknown source text as escaped output."""
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            moment = datetime.fromtimestamp(value, timezone.utc)
        else:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")
    except (ValueError, TypeError, OverflowError, OSError):
        return str(value)


def training_text(value, demo=False):
    if not demo or not isinstance(value, str):
        return value
    return value.removeprefix(DEMO_LABEL + ". ").removeprefix(
        "Synthetic training example: "
    )


def presentation(report):
    """Derived display-only counts; no inference of risk or missing evidence."""
    demo = report.get("mode") == DEMO_MODE
    evidence = report.get("evidence", [])
    counts = {
        status: sum(item.get("status") == status for item in evidence)
        for status in ("observed", "synthetic", "unavailable", "error")
    }
    ports = set()
    vendors = {}
    for item in evidence:
        if item.get("status") not in ("observed", "synthetic"):
            continue
        observations = item.get("observations", {})
        if item.get("source") == "Shodan":
            candidates = observations.get("ports", [])
            if isinstance(candidates, list):
                ports.update(
                    port
                    for port in candidates
                    if type(port) is int and 1 <= port <= 65535
                )
        if item.get("source") == "VirusTotal":
            stats = observations.get("last_analysis_stats", {})
            if isinstance(stats, dict):
                vendors.update(
                    {
                        name: count
                        for name, count in stats.items()
                        if isinstance(name, str) and type(count) is int and count >= 0
                    }
                )
    total = len(evidence)
    return {
        "demo": demo,
        "counts": counts,
        "coverage": round(100 * counts["observed"] / total) if total else 0,
        "ports": sorted(ports),
        "vendors": vendors,
        "vendor_total": sum(vendors.values()),
        "source_count": total,
    }


def render_report(report, secrets=()):
    report = prepare_report(report, secrets)
    environment = Environment(autoescape=True, undefined=StrictUndefined)
    environment.filters["timestamp"] = readable_timestamp
    environment.filters["training_text"] = training_text
    return environment.from_string(TEMPLATE).render(
        r=report, view=presentation(report), label=DEMO_LABEL
    )


def export_report(report, directory, secrets=()):
    report = prepare_report(report, secrets)
    demo = report.get("mode") == DEMO_MODE
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    html = render_report(report)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "target",
            "source",
            "status",
            "collected_at",
            "endpoint",
            "observations",
            "message",
            "mode",
            "data_classification",
            "findings",
            "record_target",
            "timestamp_kind",
        ]
    )
    for e in report["evidence"]:
        row = [
            report["target"]["value"],
            e["source"],
            e["status"],
            e["collected_at"],
            e["endpoint"],
            json.dumps(e["observations"], ensure_ascii=True),
            e["message"],
            report["mode"],
            DEMO_LABEL
            if demo
            else "Source observations; analyst verification required",
            json.dumps(
                [
                    finding
                    for finding in report["findings"]
                    if finding["source"] == e["source"]
                ],
                ensure_ascii=True,
            ),
            e["target"],
            e.get("timestamp_kind", "UTC source retrieval time"),
        ]
        writer.writerow(
            [
                "'" + x
                if x.lstrip().startswith(("=", "+", "-", "@"))
                or x.startswith(("\t", "\r", "\n"))
                else x
                for x in row
            ]
        )
    # Exclusive creation prevents accidental overwrite and symlink following.
    payloads = {
        "assessment.json": json.dumps(report, indent=2, ensure_ascii=True),
        "assessment.csv": output.getvalue(),
        "assessment.html": html,
    }
    created = []
    try:
        for name, payload in payloads.items():
            path = directory / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
                stream.write(payload)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return list(payloads)
