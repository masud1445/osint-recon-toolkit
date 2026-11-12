"""Demo fixtures must never cross the network or live-evidence boundaries."""

import csv
import json
import socket
from unittest.mock import Mock

import pytest
import requests

from osint_recon.cli import main
from osint_recon.connectors import RDAP, Shodan, VirusTotal
from osint_recon.demo import DEMO_LABEL, DEMO_MODE, FIXTURE_TIME, build_demo_report
from osint_recon.reporting import export_report
from osint_recon.targets import validate_target


@pytest.fixture
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Demo attempted network or live collection")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr("osint_recon.cli.Transport", forbidden)
    for connector in (RDAP, Shodan, VirusTotal):
        monkeypatch.setattr(connector, "collect", forbidden)
    return forbidden


def test_complete_demo_offline_without_keys(tmp_path, monkeypatch, offline, capsys):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    assert main(["--demo", "--output", str(tmp_path)]) == 0
    stdout = capsys.readouterr().out
    assert "SYNTHETIC TRAINING DATA" in stdout
    assert "No network requests" in stdout
    assert {p.name for p in tmp_path.iterdir()} == {
        "assessment.html",
        "assessment.json",
        "assessment.csv",
    }
    report = json.loads((tmp_path / "assessment.json").read_text(encoding="utf-8"))
    assert report["mode"] == DEMO_MODE
    assert report["is_synthetic"] is True
    assert report["summary"]["observed_sources"] == 0
    assert report["summary"]["synthetic_sources"] == 3
    assert len(report["findings"]) == 2
    assert {e["source"] for e in report["evidence"]} == {"RDAP", "Shodan", "VirusTotal"}
    for record in report["findings"] + report["evidence"]:
        assert record["is_synthetic"] is True
        assert record["data_classification"] == DEMO_LABEL
    for record in report["evidence"]:
        assert record["status"] == "synthetic"
        assert record["collected_at"] == FIXTURE_TIME
        assert "no collection" in record["timestamp_kind"]
        assert record["endpoint"].startswith("synthetic://")


def test_demo_ignores_existing_keys(tmp_path, monkeypatch, offline):
    sentinel = "SYNTHETIC_SENTINEL_NOT_A_REAL_KEY"
    monkeypatch.setenv("SHODAN_API_KEY", sentinel)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", sentinel)
    import os

    original_get = os.environ.get

    def guarded_get(key, *args):
        if key in {"SHODAN_API_KEY", "VIRUSTOTAL_API_KEY"}:
            raise AssertionError("Demo read API credentials")
        return original_get(key, *args)

    monkeypatch.setattr(os.environ, "get", guarded_get)
    assert main(["--demo", "--output", str(tmp_path)]) == 0
    for path in tmp_path.iterdir():
        assert sentinel not in path.read_text(encoding="utf-8")


def test_html_and_csv_label_each_finding_and_record(tmp_path, offline):
    export_report(build_demo_report(), tmp_path)
    html = (tmp_path / "assessment.html").read_text(encoding="utf-8")
    assert "training-banner" in html
    assert html.count(DEMO_LABEL) >= 7
    assert "0 live observations" in html
    assert "Synthetic fixture timestamp" in html
    assert "operator-approved target" not in html
    assert "Nothing was retrieved" in html
    assert "default-src 'none'" in html
    with (tmp_path / "assessment.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 3
    assert sum(len(json.loads(row["findings"])) for row in rows) == 2
    for row in rows:
        assert row["mode"] == DEMO_MODE
        assert row["status"] == "synthetic"
        assert row["data_classification"] == DEMO_LABEL
        for finding in json.loads(row["findings"]):
            assert finding["is_synthetic"] is True
            assert finding["data_classification"] == DEMO_LABEL


@pytest.mark.parametrize(
    "extra",
    [
        ["example.com"],
        ["192.0.2.10"],
        ["--authorized"],
        ["--sources", "rdap"],
        ["--sources", "shodan", "virustotal"],
        ["--vt-license", "noncommercial-public"],
        ["--vt-license", "licensed-commercial"],
    ],
)
def test_demo_rejects_live_options(extra, tmp_path, offline):
    with pytest.raises(SystemExit) as exc:
        main(["--demo", "--output", str(tmp_path), *extra])
    assert exc.value.code == 2
    assert list(tmp_path.iterdir()) == []


def test_live_still_requires_target_and_authorization(tmp_path, offline):
    for args in ([], ["example.com"], ["internship-lab.example", "--authorized"]):
        with pytest.raises(SystemExit) as exc:
            main([*args, "--output", str(tmp_path)])
        assert exc.value.code == 2
    assert list(tmp_path.iterdir()) == []


def test_live_failure_never_falls_back_to_demo(tmp_path, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    fallback = Mock(side_effect=AssertionError("Synthetic fallback must not run"))
    monkeypatch.setattr("osint_recon.cli.build_demo_report", fallback)
    assert (
        main(
            [
                "example.com",
                "--authorized",
                "--sources",
                "shodan",
                "--output",
                str(tmp_path),
            ]
        )
        == 1
    )
    fallback.assert_not_called()
    report = json.loads((tmp_path / "assessment.json").read_text(encoding="utf-8"))
    assert report["mode"] == "live-source retrieval"
    assert report["findings"] == []
    assert report["evidence"][0]["status"] == "unavailable"
    assert DEMO_LABEL not in (tmp_path / "assessment.html").read_text(encoding="utf-8")


def test_fixture_independence_and_reserved_identifiers():
    first, second = build_demo_report(), build_demo_report()
    assert first["target"]["value"].endswith(".example")
    assert first["target"]["associated_ip"] == "192.0.2.10"
    first["evidence"][0]["observations"].clear()
    first["findings"][0]["title"] = "changed"
    assert second["evidence"][0]["observations"]["objectClassName"] == "domain"
    assert second["findings"][0]["title"] != "changed"
    with pytest.raises(ValueError):
        validate_target(second["target"]["value"])
    with pytest.raises(ValueError):
        validate_target(second["target"]["associated_ip"])


@pytest.mark.parametrize(
    "mutation", ["live-mode", "live-evidence", "live-finding", "top-level"]
)
def test_mixed_provenance_export_refused(mutation, tmp_path):
    report = build_demo_report()
    if mutation == "live-mode":
        report["mode"] = "live-source retrieval"
    elif mutation == "live-evidence":
        report["evidence"][0].update(status="observed", is_synthetic=False)
    elif mutation == "live-finding":
        report["findings"][0]["is_synthetic"] = False
    else:
        report["is_synthetic"] = False
    with pytest.raises(ValueError):
        export_report(report, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_demo_export_does_not_overwrite_and_handles_failure(tmp_path, offline, capsys):
    assert main(["--demo", "--output", str(tmp_path)]) == 0
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(SystemExit) as exc:
        main(["--demo", "--output", str(tmp_path)])
    assert exc.value.code == 2
    assert "Report export failed" in capsys.readouterr().err
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_demo_html_keeps_escaping(tmp_path):
    report = build_demo_report()
    report["findings"][0]["title"] = "<script>alert('training')</script>"
    report["evidence"][1]["observations"]["org"] = "<img src=x onerror=alert(1)>"
    export_report(report, tmp_path)
    html = (tmp_path / "assessment.html").read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html


def test_false_synthetic_evidence_flag_refused(tmp_path):
    report = build_demo_report()
    report["evidence"][0]["is_synthetic"] = False
    with pytest.raises(ValueError):
        export_report(report, tmp_path)


def test_live_mode_refuses_even_one_synthetic_record(tmp_path):
    from osint_recon.assessment import assess
    from osint_recon.models import Evidence

    report = assess(
        validate_target("example.com"),
        [Evidence("RDAP", "synthetic", "example.com", "synthetic://fixture")],
    )
    with pytest.raises(ValueError):
        export_report(report, tmp_path)


def test_demo_console_entry_in_network_blocked_process(tmp_path):
    import subprocess
    import sys

    code = """import socket, requests, sys
from osint_recon.cli import main

def forbidden(*args, **kwargs):
    raise AssertionError("Network access is forbidden in this process")
socket.socket = forbidden
socket.create_connection = forbidden
socket.getaddrinfo = forbidden
requests.sessions.Session.request = forbidden
raise SystemExit(main(["--demo", "--output", sys.argv[1]]))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "SYNTHETIC TRAINING DATA" in result.stdout
    assert len(list(tmp_path.iterdir())) == 3
