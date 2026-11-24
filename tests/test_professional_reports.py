"""Readable, self-contained assessment reports retain operational provenance."""

import re

from osint_recon.assessment import assess
from osint_recon.demo import DEMO_LABEL, build_demo_report
from osint_recon.models import Evidence
from osint_recon.reporting import render_report
from osint_recon.targets import validate_target


def test_report_has_no_tiny_pixel_font_rules_or_academic_branding():
    html = render_report(build_demo_report())
    sizes = [
        float(value)
        for value in re.findall(r"font(?:-size)?:\s*(\d+(?:\.\d+)?)px", html)
    ]
    assert sizes and min(sizes) >= 12
    assert "font: 16px/1.65" in html
    assert "font: 14px/1.65 ui-monospace" in html
    assert "PROJECT 6.1" not in html
    assert "<script" not in html
    assert "<link " not in html


def test_bright_report_keeps_live_and_demo_classes_distinct():
    target = validate_target("example.com")
    live = assess(
        target,
        [
            Evidence(
                "RDAP",
                "unavailable",
                target.value,
                "https://rdap.org/domain/example.com",
            )
        ],
    )
    live_html = render_report(live)
    demo_html = render_report(build_demo_report())
    assert "color-scheme: light" in live_html
    assert "LIVE · Source retrieval" in live_html
    assert DEMO_LABEL not in live_html
    assert "DEMO · Synthetic" in demo_html
    assert demo_html.count(DEMO_LABEL) >= 7
    assert "0 live observations" in demo_html
    assert "No evidence-supported findings generated" in live_html


def test_print_contract_retains_readable_physical_type_and_breaks():
    html = render_report(build_demo_report())
    assert "@page{size:A4" in html
    assert "font-size: 11pt" in html
    assert "font-size: 10.5pt" in html
    assert "font-size: 10pt; line-height: 1.55" in html
    assert "table-header-group" in html
    assert "break-inside: avoid" in html
    assert "Inspect normalized evidence JSON" in html
    assert "max-height: none; overflow: visible" in html
