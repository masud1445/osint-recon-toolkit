"""Source-backed report presentation, escaping and print contract tests."""

import pytest

from osint_recon.assessment import assess
from osint_recon.demo import DEMO_LABEL, build_demo_report
from osint_recon.models import Evidence
from osint_recon.reporting import presentation, readable_timestamp, render_report
from osint_recon.targets import validate_target


def test_live_unavailable_report_never_shows_synthetic_or_vendor_chart():
    evidence = Evidence(
        "VirusTotal",
        "unavailable",
        "example.com",
        "https://www.virustotal.com/api/v3/domains/example.com",
    )
    report = assess(validate_target("example.com"), [evidence])
    html = render_report(report)
    assert "LIVE · Source retrieval" in html
    assert DEMO_LABEL not in html
    assert "Vendor classification distribution" not in html
    assert "No service or vendor data available." in html
    assert "No evidence-supported findings generated" in html
    assert presentation(report)["coverage"] == 0
    assert presentation(report)["counts"]["unavailable"] == 1


def test_observations_drive_chart_without_implying_risk():
    report = assess(
        validate_target("example.com"),
        [
            Evidence(
                "VirusTotal",
                "observed",
                "example.com",
                "https://www.virustotal.com/api/v3/domains/example.com",
                observations={"last_analysis_stats": {"malicious": 2, "harmless": 8}},
            ),
        ],
    )
    view = presentation(report)
    assert view["vendors"] == {"malicious": 2, "harmless": 8}
    assert view["vendor_total"] == 10
    assert view["coverage"] == 100
    html = render_report(report)
    assert "Vendor classification distribution" in html
    assert "risk score" in html
    assert "LIVE · Source retrieval" in html
    assert "DEMO · Synthetic" not in html


def test_unavailable_observations_do_not_feed_charts():
    report = assess(
        validate_target("example.com"),
        [
            Evidence(
                "VirusTotal",
                "error",
                "example.com",
                "https://www.virustotal.com/",
                observations={"last_analysis_stats": {"malicious": 500}},
            ),
            Evidence(
                "Shodan",
                "unavailable",
                "example.com",
                "https://api.shodan.io/",
                observations={"ports": [22]},
            ),
        ],
    )
    view = presentation(report)
    assert view["vendors"] == {}
    assert view["ports"] == []


def test_report_print_disclosures_and_offline_assets():
    html = render_report(build_demo_report())
    assert "@page{size:A4" in html
    assert "@media print" in html
    assert "<details>" in html
    assert "Inspect normalized evidence JSON" in html
    assert "<script" not in html
    assert "<link " not in html
    assert "<img " not in html
    assert "Synthetic fixture timestamp" in html
    assert html.count(DEMO_LABEL) >= 7
    assert "0 live observations" in html


def test_report_redacts_before_html_and_keeps_escape_boundary():
    report = build_demo_report()
    report["findings"][0]["title"] = '<svg onload="alert(1)">PRIVATE_KEY</svg>'
    html = render_report(report, ("PRIVATE_KEY",))
    assert "PRIVATE_KEY" not in html
    assert "<svg onload=" not in html
    assert "&lt;svg onload=" in html
    assert "[REDACTED]" in html


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2025-01-15T10:00:00+00:00", "15 Jan 2025, 10:00:00 UTC"),
        ("2025-01-15T12:00:00+02:00", "15 Jan 2025, 10:00:00 UTC"),
        (0, "01 Jan 1970, 00:00:00 UTC"),
        ("not provided", "not provided"),
    ],
)
def test_readable_timestamp(value, expected):
    assert readable_timestamp(value) == expected


def test_render_rejects_mixed_provenance_even_without_export():
    report = build_demo_report()
    report["mode"] = "live-source retrieval"
    with pytest.raises(ValueError):
        render_report(report)
