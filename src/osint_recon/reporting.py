"""Portable, escaped reports without external assets or executable content."""

import csv
import io
import json
import os
from pathlib import Path

from jinja2 import Environment, StrictUndefined

TEMPLATE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>OSINT assessment — {{ r.target.value }}</title>
<style>body{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:0 1.5rem;color:#183047;background:#f7f9fc}h1,h2{color:#10243a}section,article{background:white;border:1px solid #d6dfeb;border-radius:8px;padding:1.3rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#40556b}.badge{font-weight:bold}footer{margin:2rem 0}</style>
<header><small>PROJECT 6.1 · AUTHORIZED PASSIVE INTELLIGENCE</small><h1>External intelligence assessment</h1><p>{{ r.target.value }} · {{ r.target.kind }}</p><p>{{ r.generated_at }} · {{ r.mode }}</p></header>
<section><h2>Executive summary</h2><p>{{ r.summary.observed_sources }} of {{ r.summary.total_sources }} sources returned records. {{ r.findings|length }} items require analyst review.</p><p>{{ r.summary.interpretation }}</p><p>This assessment retrieves existing third-party records. No target scanning or independent validation was performed.</p></section>
<section><h2>Findings and recommendations</h2>{% for f in r.findings %}<article><h3>{{ f.title }}</h3><p class="badge">{{ f.severity }} · {{ f.source }}</p><p>{{ f.interpretation }}</p><p>{{ f.recommendation }}</p></article>{% else %}<p>No evidence-supported findings generated. This does not establish that the target is secure.</p>{% endfor %}</section>
<section><h2>Source evidence</h2>{% for e in r.evidence %}<article><h3>{{ e.source }} — {{ e.status }}</h3><p>{{ e.message }}</p><p>Collected: {{ e.collected_at }}</p><p>Endpoint: {{ e.endpoint }}</p><p>{{ e.verification }}</p><pre>{{ e.observations|tojson(indent=2) }}</pre></article>{% endfor %}</section>
<footer>Scope: one operator-approved target. Source timestamps describe source records; collection timestamps describe retrieval. Coverage, licensing, historical accuracy and asset ownership require analyst review. Retain reports under organizational evidence-handling policy.</footer></html>"""


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
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    environment = Environment(autoescape=True, undefined=StrictUndefined)
    html = environment.from_string(TEMPLATE).render(r=report)
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
