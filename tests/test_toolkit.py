"""Synthetic fixtures only: these tests make no external intelligence requests."""

import json
from unittest.mock import Mock

import pytest
import requests

from osint_recon.assessment import assess
from osint_recon.cli import main
from osint_recon.connectors import RDAP, Shodan, VirusTotal
from osint_recon.reporting import export_report
from osint_recon.targets import validate_target
from osint_recon.transport import SourceError, Transport


def response(code=200, data=None, headers=None, raw=None):
    r = Mock()
    r.__enter__ = Mock(return_value=r)
    r.__exit__ = Mock(return_value=False)
    r.status_code = code
    r.headers = headers or {}
    r.iter_content.return_value = [
        raw if raw is not None else json.dumps(data or {}).encode()
    ]
    return r


def transport(*responses):
    session, sleep = Mock(), Mock()
    session.get.side_effect = responses
    return Transport(session=session, sleep=sleep), session, sleep


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "example.com/x",
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "224.0.0.1",
        "example.com:443",
        "example.com?x=y",
        " example.com",
        "example.com\n",
        "localhost",
        "-a.com",
        "a-.com",
        "a..com",
        "a.local",
        "a.onion",
        "999.999.1.1",
        "a.123",
        "a%2ecom",
        "a.com@evil.com",
        "a" * 64 + ".com",
        "a.com\\evil",
    ],
)
def test_invalid_targets(value):
    with pytest.raises(ValueError):
        validate_target(value)


@pytest.mark.parametrize(
    "value,expected,kind",
    [
        ("EXAMPLE.COM", "example.com", "domain"),
        ("bücher.de", "xn--bcher-kva.de", "domain"),
        ("8.8.8.8", "8.8.8.8", "ip"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111", "ip"),
    ],
)
def test_valid_targets(value, expected, kind):
    target = validate_target(value)
    assert (target.value, target.kind) == (expected, kind)


@pytest.mark.parametrize(
    "code,status",
    [
        (401, "unavailable"),
        (403, "unavailable"),
        (404, "unavailable"),
        (400, "error"),
        (302, "unavailable"),
    ],
)
def test_http_errors(code, status):
    t, session, _ = transport(response(code))
    with pytest.raises(SourceError) as exc:
        t.get("https://api.shodan.io/shodan/host/8.8.8.8")
    assert exc.value.status == status
    assert session.get.call_count == 1


@pytest.mark.parametrize("code", [429, 500, 502, 503])
def test_retry_success(code):
    t, session, sleep = transport(
        response(code, headers={"Retry-After": "2"}), response(data={"ok": True})
    )
    assert t.get("https://rdap.org/ip/8.8.8.8") == {"ok": True}
    assert session.get.call_count == 2
    sleep.assert_called_once_with(2)


def test_retry_exhaustion():
    t, session, _ = transport(*[response(429) for _ in range(3)])
    with pytest.raises(SourceError, match="rate limit"):
        t.get("https://rdap.org/ip/8.8.8.8")
    assert session.get.call_count == 3


@pytest.mark.parametrize("retry", ["61", "999999999999999999999"])
def test_long_cooldown_does_not_retry_early(retry):
    t, session, sleep = transport(response(429, headers={"Retry-After": retry}))
    with pytest.raises(SourceError, match="longer cooldown"):
        t.get("https://rdap.org/ip/8.8.8.8")
    assert session.get.call_count == 1
    sleep.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        requests.Timeout("SECRET"),
        requests.ConnectionError("SECRET"),
        requests.exceptions.SSLError("SECRET"),
    ],
)
def test_network_errors_are_sanitized(error):
    t, session, _ = transport(error, error, error)
    with pytest.raises(SourceError) as exc:
        t.get("https://rdap.org/ip/8.8.8.8")
    assert "SECRET" not in str(exc.value)
    assert session.get.call_count == 3


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'"string"', b"x" * 2_000_001])
def test_bad_response(raw):
    t, _, _ = transport(response(raw=raw))
    with pytest.raises(SourceError):
        t.get("https://rdap.org/ip/8.8.8.8")


@pytest.mark.parametrize(
    "url",
    [
        "http://rdap.org/ip/8.8.8.8",
        "https://localhost/",
        "https://api.shodan.io.evil.com/",
        "https://api.shodan.io:444/",
        "https://key@api.shodan.io/",
    ],
)
def test_destination_restriction(url):
    t, session, _ = transport()
    with pytest.raises(SourceError):
        t.get(url)
    session.get.assert_not_called()


def test_rdap_registry_redirect():
    t, session, _ = transport(
        response(
            302,
            headers={"Location": "https://rdap.verisign.com/com/v1/domain/example.com"},
        ),
        response(data={"objectClassName": "domain"}),
    )
    assert RDAP(t).collect(validate_target("example.com")).status == "observed"
    assert session.get.call_count == 2
    assert all(c.kwargs["allow_redirects"] is False for c in session.get.call_args_list)


@pytest.mark.parametrize(
    "location",
    [
        "https://169.254.169.254/",
        "http://rdap.verisign.com/",
        "https://evil.com/",
        "https://key@rdap.verisign.com/",
    ],
)
def test_rdap_redirect_rejected(location):
    t, session, _ = transport(response(302, headers={"Location": location}))
    assert RDAP(t).collect(validate_target("example.com")).status == "unavailable"
    assert session.get.call_count == 1


def test_api_key_not_forwarded_on_redirect():
    t, session, _ = transport(response(302, headers={"Location": "https://rdap.org/"}))
    assert (
        Shodan(t, "SECRET").collect(validate_target("8.8.8.8")).status == "unavailable"
    )
    assert session.get.call_count == 1


@pytest.mark.parametrize("connector", [Shodan, VirusTotal])
def test_missing_key_no_request(connector):
    t, session, _ = transport()
    result = connector(t).collect(validate_target("example.com"))
    assert result.status == "unavailable"
    assert result.observations == {}
    session.get.assert_not_called()


@pytest.mark.parametrize(
    "connector,data",
    [(RDAP, {}), (Shodan, {}), (VirusTotal, {"data": {"attributes": []}})],
)
def test_malformed_schema(connector, data):
    t, _, _ = transport(response(data=data))
    assert (
        connector(t, "SECRET").collect(validate_target("example.com")).status == "error"
    )


def test_connector_contracts_and_assessment_integration(tmp_path):
    # Synthetic responses exercise real transport -> connectors -> assessment -> files.
    t, session, _ = transport(
        response(
            data={
                "objectClassName": "ip network",
                "startAddress": "8.8.8.0",
                "endAddress": "8.8.8.255",
                "entities": [{"secret": "omit"}],
            }
        ),
        response(
            data={"ip_str": "8.8.8.8", "ports": [443], "data": [{"banner": "SECRET"}]}
        ),
        response(
            data={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 2},
                        "last_analysis_date": 1700000000,
                    }
                }
            }
        ),
    )
    target = validate_target("8.8.8.8")
    evidence = [
        RDAP(t).collect(target),
        Shodan(t, "SECRET").collect(target),
        VirusTotal(t, "VTSECRET").collect(target),
    ]
    report = assess(target, evidence)
    assert report["summary"]["observed_sources"] == 3
    assert len(report["findings"]) == 2
    export_report(report, tmp_path, ("SECRET", "VTSECRET"))
    assert len(list(tmp_path.iterdir())) == 3
    assert (
        json.loads((tmp_path / "assessment.json").read_text())["target"]["value"]
        == "8.8.8.8"
    )
    assert "banner" not in (tmp_path / "assessment.json").read_text()
    assert session.get.call_args_list[1].kwargs["params"] == {
        "key": "SECRET",
        "minify": "true",
    }
    assert session.get.call_args_list[2].kwargs["headers"] == {"x-apikey": "VTSECRET"}
    assert session.get.call_args_list[0].kwargs["timeout"] == (5, 20)


def test_domain_shodan_contract():
    t, _session, _ = transport(response(data={"domain": "example.com", "more": True}))
    r = Shodan(t, "SECRET").collect(validate_target("example.com"))
    assert r.endpoint.endswith("/dns/domain/example.com")
    assert r.observations["more"] is True


def test_unavailable_generates_no_findings(tmp_path):
    t, _, _ = transport()
    target = validate_target("example.com")
    report = assess(target, [Shodan(t).collect(target), VirusTotal(t).collect(target)])
    assert report["findings"] == []
    assert report["summary"]["observed_sources"] == 0
    export_report(report, tmp_path)
    assert (
        "No evidence-supported findings" in (tmp_path / "assessment.html").read_text()
    )


def test_escaping_redaction_csv_and_no_overwrite(tmp_path):
    from osint_recon.models import Evidence

    target = validate_target("example.com")
    evidence = Evidence(
        "Shodan",
        "observed",
        target.value,
        "https://api.shodan.io/",
        observations={"org": "<script>alert(1)</script> SECRET"},
        message="=1+2",
    )
    report = assess(target, [evidence])
    export_report(report, tmp_path, ("SECRET",))
    for file in tmp_path.iterdir():
        assert "SECRET" not in file.read_text()
    assert "<script>" not in (tmp_path / "assessment.html").read_text()
    assert "'=1+2" in (tmp_path / "assessment.csv").read_text()
    before = (tmp_path / "assessment.json").read_text()
    with pytest.raises(FileExistsError):
        export_report(report, tmp_path)
    assert (tmp_path / "assessment.json").read_text() == before


def test_partial_export_cleanup(tmp_path):
    (tmp_path / "assessment.csv").write_text("user data")
    with pytest.raises(FileExistsError):
        export_report(assess(validate_target("example.com"), []), tmp_path)
    assert not (tmp_path / "assessment.json").exists()
    assert (tmp_path / "assessment.csv").read_text() == "user data"


@pytest.mark.parametrize(
    "argv",
    [
        ["example.com", "--output", "x"],
        ["https://example.com", "--authorized", "--output", "x"],
        ["example.com", "--authorized", "--sources", "virustotal", "--output", "x"],
    ],
)
def test_cli_validation(argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_cli_missing_credentials_integration(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
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
    assert "Sources observed: 0/1" in capsys.readouterr().out
    assert json.loads((tmp_path / "assessment.json").read_text())["findings"] == []


def test_cli_mocked_success(tmp_path, monkeypatch):
    t, _, _ = transport(
        response(data={"objectClassName": "domain", "ldhName": "example.com"})
    )
    monkeypatch.setattr("osint_recon.cli.Transport", lambda: t)
    assert main(["example.com", "--authorized", "--output", str(tmp_path)]) == 0


def test_pacing():
    t, _, sleep = transport(response(data={"ok": True}), response(data={"ok": True}))
    for _ in range(2):
        t.get("https://www.virustotal.com/api/v3/domains/example.com", interval=15)
    assert 0 < sleep.call_args.args[0] <= 15


def test_http_date_cooldown():
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime

    retry = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30))
    t, _, sleep = transport(
        response(429, headers={"Retry-After": retry}), response(data={"ok": True})
    )
    assert t.get("https://rdap.org/ip/8.8.8.8")["ok"]
    assert 28 <= sleep.call_args.args[0] <= 30


def test_invalid_cooldown_fallback():
    t, _, sleep = transport(
        response(429, headers={"Retry-After": "garbage"}), response(data={"ok": True})
    )
    assert t.get("https://rdap.org/ip/8.8.8.8")["ok"]
    sleep.assert_called_once_with(1)


def test_selected_dns_records():
    t, _, _ = transport(
        response(
            data={
                "domain": "example.com",
                "data": [
                    {
                        "subdomain": "www",
                        "type": "A",
                        "value": "8.8.8.8",
                        "last_seen": "2025-01-01",
                        "unwanted": "SECRET",
                    }
                ],
            }
        )
    )
    r = Shodan(t, "SECRET").collect(validate_target("example.com"))
    assert r.observations["dns_records"] == [
        {"subdomain": "www", "type": "A", "value": "8.8.8.8", "last_seen": "2025-01-01"}
    ]


def test_invalid_attempt_count():
    with pytest.raises(ValueError):
        Transport(attempts=0)


def test_cli_export_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    (tmp_path / "assessment.html").write_text("existing")
    with pytest.raises(SystemExit) as exc:
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
    assert exc.value.code == 2
    assert "Report export failed" in capsys.readouterr().err


def test_rdap_redirect_loop():
    t, session, _ = transport(
        *[
            response(302, headers={"Location": "https://rdap.org/domain/example.com"})
            for _ in range(4)
        ]
    )
    assert RDAP(t).collect(validate_target("example.com")).status == "unavailable"
    assert session.get.call_count == 4


def test_report_symlink_rejected(tmp_path):
    victim = tmp_path / "private.txt"
    victim.write_text("untouched")
    try:
        (tmp_path / "assessment.json").symlink_to(victim)
    except OSError:
        pytest.skip("Symlink creation unavailable for this OS/account")
    with pytest.raises(FileExistsError):
        export_report(assess(validate_target("example.com"), []), tmp_path)
    assert victim.read_text() == "untouched"


def test_mismatched_source_target_is_not_evidence():
    t, _, _ = transport(response(data={"domain": "wrong.org", "ports": [22]}))
    target = validate_target("example.com")
    evidence = Shodan(t, "SECRET").collect(target)
    assert evidence.status == "error"
    assert evidence.observations == {}
    assert assess(target, [evidence])["findings"] == []


def test_deeply_nested_json_is_sanitized():
    t, _, _ = transport(
        response(raw=b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}")
    )
    with pytest.raises(SourceError, match="invalid JSON|nesting limit"):
        t.get("https://rdap.org/ip/8.8.8.8")


@pytest.mark.parametrize("ports", ["443", [0], [65536], [True], [-1], ["443"]])
def test_invalid_port_observations(ports):
    t, _, _ = transport(response(data={"ip_str": "8.8.8.8", "ports": ports}))
    assert Shodan(t, "SECRET").collect(validate_target("8.8.8.8")).status == "error"


@pytest.mark.parametrize(
    "stats", [[], {"malicious": True}, {"malicious": -1}, {"malicious": "2"}]
)
def test_invalid_vendor_counts(stats):
    t, _, _ = transport(
        response(data={"data": {"attributes": {"last_analysis_stats": stats}}})
    )
    result = VirusTotal(t, "SECRET").collect(validate_target("example.com"))
    assert result.status == "error"
    assert result.observations == {}


def test_invalid_dns_records():
    t, _, _ = transport(response(data={"domain": "example.com", "data": "unexpected"}))
    assert Shodan(t, "SECRET").collect(validate_target("example.com")).status == "error"
