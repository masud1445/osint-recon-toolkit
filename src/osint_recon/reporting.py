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
:root{color-scheme:dark;--bg:#080f1c;--panel:#101c2e;--line:#22344b;--muted:#a1b2c8;--text:#edf4ff;--blue:#5897ff;--cyan:#54dbc9;--amber:#f4c773}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(ellipse at 85% 0,#172b48 0,transparent 48%),var(--bg);color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:inherit;text-decoration:none}header,main,footer{max-width:1180px;margin:auto;padding:0 34px}header{padding-top:38px}.masthead{display:flex;align-items:center;justify-content:space-between;gap:20px;padding-bottom:24px;border-bottom:1px solid var(--line)}.brand{display:flex;gap:12px;align-items:center;font-weight:750;letter-spacing:.02em}.brand-mark{width:38px;height:42px;color:var(--cyan)}.brand small{display:block;color:var(--muted);font-size:10px;letter-spacing:.2em;font-weight:500}.eyebrow{text-transform:uppercase;letter-spacing:.18em;font-size:10px;color:var(--cyan);font-weight:750}.pill,.badge{display:inline-flex;align-items:center;gap:7px;border-radius:30px;font-size:11px;padding:4px 10px;border:1px solid var(--line);font-weight:650}.pill:before{content:"";width:6px;height:6px;border-radius:50%;background:var(--cyan)}.training-banner{margin-top:22px;display:flex;align-items:center;justify-content:space-between;gap:18px;border:1px solid #675536;background:#30281b80;border-radius:10px;padding:12px 16px;color:#ffdc9b;font-size:12px}.training-banner strong{font-size:12px}.training-banner span{color:#d8c4a0}.intro{padding:40px 0 24px;display:flex;justify-content:space-between;gap:28px;align-items:flex-end}.intro h1{font-size:32px;line-height:1.2;margin:10px 0;font-weight:650;letter-spacing:-1px}.target{font-size:18px;color:#d9e6fa;overflow-wrap:anywhere}.metadata{text-align:right;font-size:11px;color:var(--muted);white-space:nowrap}.report-nav{display:flex;gap:24px;color:var(--muted);font-size:12px;border-bottom:1px solid var(--line);padding:15px 0 19px;margin-bottom:28px}.report-nav a:hover{color:var(--cyan)}section{scroll-margin-top:20px;margin:28px 0}.section-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}.section-heading h2{font-size:18px;font-weight:600;letter-spacing:-.25px;margin:0}.section-heading small{color:var(--muted);font-size:11px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.metric,.panel,.finding,.evidence-card{background:linear-gradient(145deg,#142237,#101b2c);border:1px solid var(--line);border-radius:12px}.metric{padding:20px 22px}.metric .metric-label{color:var(--muted);font-size:11px}.metric strong{display:block;font-size:32px;font-weight:650;line-height:1.3;margin-top:9px;letter-spacing:-1px}.metric small{color:var(--muted);font-size:10px}.metric .accent{color:var(--cyan)}.summary{margin-top:18px;padding:18px 22px;border-left:3px solid var(--blue);background:#142239;border-radius:0 8px 8px 0;color:#c5d4e8}.summary p{margin:0}.summary small{display:block;color:var(--muted);margin-top:7px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.panel{padding:22px}.panel h3{margin:0 0 18px;font-size:13px;font-weight:600}.coverage-row,.vendor-row{display:grid;grid-template-columns:105px 1fr 30px;gap:14px;align-items:center;font-size:11px;margin:15px 0}.track{height:7px;background:#23334a;border-radius:10px;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));border-radius:10px}.fill.unavailable{background:#e2b865}.fill.error{background:#f2808a}.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:10px;color:var(--muted);margin-top:20px}.legend i{display:inline-block;width:6px;height:6px;background:var(--cyan);border-radius:100%;margin-right:5px}.fineprint{font-size:11px;color:var(--muted);margin:12px 0 0}.ports{display:flex;gap:8px;flex-wrap:wrap}.port{font:12px ui-monospace,monospace;background:#173449;color:#9be6df;border:1px solid #235269;border-radius:6px;padding:6px 12px}.source-table{width:100%;border-collapse:collapse;font-size:12px}.source-table th{text-align:left;font-size:10px;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:.08em;padding:13px 12px;border-bottom:1px solid var(--line)}.source-table td{padding:15px 12px;border-bottom:1px solid var(--line);vertical-align:top}.source-table tr:last-child td{border-bottom:0}.source-table td:first-child{font-weight:650}.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:#101b2c}.status-observed,.status-synthetic{color:#76e6c9;background:#13372f;border-color:#235347}.status-unavailable{color:#f4cd86;background:#382e1f;border-color:#59452a}.status-error{color:#ffabb2;background:#3a2530;border-color:#63323b}.finding{padding:22px 24px;margin:13px 0;border-left:3px solid var(--blue)}.finding-head{display:flex;justify-content:space-between;align-items:center;gap:15px}.finding h3{font-size:15px;margin:0}.finding p{margin:13px 0;color:#c7d6e9}.recommendation{border-top:1px solid var(--line);padding-top:13px;font-size:12px}.recommendation strong{color:var(--cyan);font-size:10px;text-transform:uppercase;letter-spacing:.08em;display:block;margin-bottom:4px}.evidence-card{margin:16px 0;overflow:hidden}.evidence-head{display:flex;align-items:center;justify-content:space-between;gap:15px;padding:19px 22px;border-bottom:1px solid var(--line)}.evidence-head h3{margin:0;font-size:15px}.evidence-content{padding:18px 22px}.evidence-meta{display:grid;grid-template-columns:1fr 1fr;gap:16px;font-size:11px;margin-bottom:17px}.evidence-meta span{display:block;color:var(--muted);font-size:10px;margin-bottom:3px}.evidence-meta code{font-size:10px;overflow-wrap:anywhere}.fields{width:100%;border-collapse:collapse;font-size:11px}.fields td{padding:8px 0;border-top:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}.fields td:first-child{color:var(--muted);width:29%;padding-right:18px}.fields code{white-space:pre-wrap;word-break:break-word;font:10px/1.5 ui-monospace,SFMono-Regular,monospace}details{margin-top:17px;border-top:1px solid var(--line)}summary{cursor:pointer;padding:12px 0 0;color:#89b8ff;font-size:11px;font-weight:600}pre{background:#081321;border:1px solid var(--line);padding:16px;border-radius:7px;font:10px/1.65 ui-monospace,SFMono-Regular,monospace;white-space:pre-wrap;overflow-wrap:anywhere;color:#b4cce8;max-height:380px;overflow:auto}.empty{border:1px dashed #3a4d67;border-radius:10px;padding:26px;color:var(--muted);text-align:center}.scope{padding:20px 22px;border:1px solid var(--line);border-radius:10px;background:#0e1a2a;font-size:11px;color:var(--muted)}.scope strong{display:block;color:var(--text);margin-bottom:7px}footer{font-size:10px;color:var(--muted);padding-top:20px;padding-bottom:35px;display:flex;justify-content:space-between;gap:20px;border-top:1px solid var(--line);margin-top:35px}.print-note{display:none}@media(max-width:700px){header,main,footer{padding-left:18px;padding-right:18px}.intro{display:block;padding-top:25px}.metadata{text-align:left;margin-top:15px}.intro h1{font-size:26px}.metrics{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.training-banner{display:block}.training-banner span{display:block;margin-top:5px}.report-nav{gap:17px;overflow-x:auto;white-space:nowrap}.finding-head{display:block}.finding-head .badge{margin-top:9px}.evidence-meta{grid-template-columns:1fr}.metric{padding:16px}.source-table{min-width:560px}}@page{size:A4;margin:14mm 13mm 15mm}@media print{color-scheme:light;html,body{background:#fff!important;color:#17283b!important;font-size:10px;-webkit-print-color-adjust:exact;print-color-adjust:exact}header,main,footer{max-width:none;padding:0}.masthead{padding-bottom:12px}.brand-mark{height:30px}.brand small,.eyebrow,.metadata,.metric .metric-label,.metric small,.fineprint,.legend,.section-heading small,footer,.evidence-meta span,.fields td:first-child{color:#536479!important}.intro{padding:20px 0 15px}.intro h1{font-size:24px}.target,.finding p,.summary,.evidence-meta{color:#203349}.report-nav{display:none}.training-banner{background:#fff7e3!important;border-color:#d2b878!important;color:#5e471d!important;margin-top:14px;padding:8px 12px}.training-banner span{color:#5e471d!important}.metric,.panel,.finding,.evidence-card,.scope,.table-wrap{background:#fff!important;border-color:#c9d4df!important;box-shadow:none;border-radius:6px}.summary{background:#f0f5fa!important;border-color:#3977b9}.metric strong{font-size:25px}.metric .accent{color:#147f7a!important}.grid{gap:12px}.panel{padding:14px}.metrics{gap:10px}.metric{padding:12px 15px}.track{background:#e4ebf1!important}.fill{background:#357bc0!important}.fill.unavailable{background:#c29035!important}.fill.error{background:#c25763!important}.source-table th,.source-table td{padding:10px;border-color:#dce4eb}.source-table th{color:#536479}.finding,.panel,.scope{break-inside:avoid}.finding{padding:15px 18px}.finding h3{font-size:13px}.recommendation strong{color:#147f7a}.evidence-head{padding:13px 17px;border-color:#dce4eb;break-after:avoid}.evidence-content{padding:13px 17px}.evidence-card{break-inside:auto}.fields tr{break-inside:avoid}.fields td{border-color:#dce4eb;padding:6px 0}.fields code{font-size:8px}pre{background:#f3f6f9!important;color:#203349!important;border-color:#dce4eb;max-height:none;overflow:visible;font-size:8px}details{border-color:#dce4eb}details:not([open])>pre{display:block}summary{color:#2b66a4;font-size:10px}.print-note{display:block;font-size:9px;color:#536479}.ports .port{background:#eaf5f5!important;color:#1d6967!important;border-color:#9cc7c6}.scope{color:#536479}.scope strong{color:#17283b}.badge{font-size:9px}.status-observed,.status-synthetic{background:#e6f5ee!important;color:#1d6652!important;border-color:#9cc8b8}.status-unavailable{background:#fbf1de!important;color:#805c21!important;border-color:#ddc28c}.status-error{background:#fce9ed!important;color:#91404c!important;border-color:#dfa6b0}.evidence-card h3{font-size:13px}section{margin:20px 0}.section-heading{margin-bottom:10px}.section-heading h2{font-size:15px}footer{margin-top:20px;padding-top:12px;break-inside:avoid}}
</style></head>
<body>
<header><div class="masthead"><div class="brand"><svg class="brand-mark" viewBox="0 0 32 38" fill="none" aria-hidden="true"><path d="M16 2 29 7v11c0 8-6 14-13 18C9 32 3 26 3 18V7L16 2Z" stroke="currentColor" stroke-width="1.5"/><path d="m9 19 5 5 9-11" stroke="currentColor" stroke-width="2"/></svg><div>RECON <span style="color:var(--cyan)">TOOLKIT</span><small>EXTERNAL INTELLIGENCE · PROJECT 6.1</small></div></div><span class="pill">{% if view.demo %}DEMO · Synthetic{% else %}LIVE · Source retrieval{% endif %}</span></div>
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
</main><footer{% if view.demo %} data-classification="{{ label }}"{% endif %}><span>OSINT RECON TOOLKIT · PROJECT 6.1</span><span>{% if view.demo %}DEMO · Synthetic training data{% else %}LIVE · Analyst review required{% endif %} · {{ r.generated_at|timestamp }}</span></footer>
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
