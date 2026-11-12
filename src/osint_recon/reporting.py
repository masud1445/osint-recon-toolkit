"""Portable, escaped reports without external assets or executable content."""

import csv
import io
import json
import os
from pathlib import Path

from jinja2 import Environment, StrictUndefined

from .demo import DEMO_LABEL, DEMO_MODE

TEMPLATE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{% if demo %}SYNTHETIC TRAINING — {% endif %}OSINT assessment — {{ r.target.value }}</title>
<style>body{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:0 1.5rem;color:#183047;background:#f7f9fc}h1,h2{color:#10243a}section,article{background:white;border:1px solid #d6dfeb;border-radius:8px;padding:1.3rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#40556b}.badge{font-weight:bold}.training-banner{background:#fff0ca;border:3px solid #a76300;color:#532f00;padding:1.2rem;font-weight:700;margin:1rem 0}.training-banner p{font-weight:400}@media print{.training-banner{border:3px solid black}body{background:white;margin:0}}footer{margin:2rem 0}</style>
{% if demo %}<aside class="training-banner" role="note">{{ label }}<p>Offline internship demonstration. No network calls, real provider records, target assessment or verified findings.</p><p>Scenario: {{ r.scenario_id }}. Fixture timestamps are fictional; generated_at records report preparation only.</p></aside>{% endif %}
<header><small>PROJECT 6.1 · {% if demo %}OFFLINE TRAINING WORKFLOW{% else %}AUTHORIZED PASSIVE INTELLIGENCE{% endif %}</small><h1>{% if demo %}Offline OSINT workflow demonstration{% else %}External intelligence assessment{% endif %}</h1><p>{{ r.target.value }} · {{ r.target.kind }}</p><p>{{ r.generated_at }} · {{ r.mode }}</p></header>
<section><h2>Executive summary</h2>{% if demo %}<p>{{ r.summary.synthetic_sources }} synthetic source examples · {{ r.findings|length }} synthetic training findings · 0 live observations.</p><p>Fictional associated IP: {{ r.target.associated_ip }}</p>{% else %}<p>{{ r.summary.observed_sources }} of {{ r.summary.total_sources }} sources returned records. {{ r.findings|length }} items require analyst review.</p>{% endif %}<p>{{ r.summary.interpretation }}</p>{% if demo %}<p>This demonstration uses only local fictional fixtures. Nothing was retrieved from RDAP, Shodan or VirusTotal.</p>{% else %}<p>This assessment retrieves existing third-party records. No target scanning or independent validation was performed.</p>{% endif %}</section>
<section><h2>Findings and recommendations</h2>{% for f in r.findings %}<article>{% if demo %}<p class="badge">{{ label }}</p>{% endif %}<h3>{{ f.title }}</h3><p class="badge">{{ f.severity }} · {{ f.source }}</p><p>{{ f.interpretation }}</p><p>{{ f.recommendation }}</p></article>{% else %}<p>No evidence-supported findings generated. This does not establish that the target is secure.</p>{% endfor %}</section>
<section><h2>Source evidence</h2>{% for e in r.evidence %}<article>{% if demo %}<p class="badge">{{ label }}</p>{% endif %}<h3>{{ e.source }} — {{ e.status }}</h3><p>Record target: {{ e.target }}</p><p>{{ e.message }}</p><p>{% if demo %}Synthetic fixture timestamp{% else %}Collected{% endif %}: {{ e.collected_at }}</p><p>{% if demo %}Local fixture ID{% else %}Endpoint{% endif %}: {{ e.endpoint }}</p><p>{{ e.verification }}</p><pre>{{ e.observations|tojson(indent=2) }}</pre></article>{% endfor %}</section>
<footer>{% if demo %}{{ label }}. Scope: {{ r.scope }}{% else %}Scope: one operator-approved target. Source timestamps describe source records; collection timestamps describe retrieval. Coverage, licensing, historical accuracy and asset ownership require analyst review. Retain reports under organizational evidence-handling policy.{% endif %}</footer></html>"""


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


def export_report(report, directory, secrets=()):
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
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    environment = Environment(autoescape=True, undefined=StrictUndefined)
    html = environment.from_string(TEMPLATE).render(
        r=report, demo=demo, label=DEMO_LABEL
    )
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
