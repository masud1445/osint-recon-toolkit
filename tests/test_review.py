"""Regression tests from post-push security and reporting review; no network."""

import pytest
from test_toolkit import response, transport

from osint_recon.assessment import assess
from osint_recon.connectors import RDAP, Shodan, VirusTotal
from osint_recon.models import Evidence
from osint_recon.reporting import export_report
from osint_recon.targets import Target, validate_target


@pytest.mark.parametrize(
    "value",
    ["2606:4700:4700::1111%eth0", "8.8.8.8.nip.io\x00", "2606:4700:4700::1111%2F"],
)
def test_scoped_or_control_input_rejected(value):
    with pytest.raises(ValueError):
        validate_target(value)


@pytest.mark.parametrize(
    "target",
    [
        Target("example.com/../../scan", "domain"),
        Target("example.com", "ip"),
        Target("127.0.0.1", "ip"),
    ],
)
def test_library_cannot_bypass_validation(target):
    t, session, _ = transport()
    with pytest.raises(ValueError):
        Shodan(t, "SYNTHETIC_KEY").collect(target)
    session.get.assert_not_called()


@pytest.mark.parametrize(
    "data",
    [
        {
            "data": {
                "id": "wrong.org",
                "type": "domain",
                "attributes": {"last_analysis_stats": {"malicious": 9}},
            }
        },
        {"data": {"id": "example.com", "type": "ip_address", "attributes": {}}},
        {"data": {"attributes": {}}},
    ],
)
def test_vt_identity_is_required(data):
    target = validate_target("example.com")
    t, _, _ = transport(response(data=data))
    result = VirusTotal(t, "SYNTHETIC_KEY").collect(target)
    assert result.status == "error"
    assert result.observations == {}
    assert assess(target, [result])["findings"] == []


@pytest.mark.parametrize(
    "data",
    [
        {"objectClassName": "domain", "ldhName": "example.com"},
        {
            "objectClassName": "ip network",
            "startAddress": "9.0.0.0",
            "endAddress": "9.0.0.255",
        },
        {"objectClassName": "ip network"},
    ],
)
def test_rdap_ip_record_must_contain_target(data):
    t, _, _ = transport(response(data=data))
    assert RDAP(t).collect(validate_target("8.8.8.8")).status == "error"


def test_shodan_empty_identity_rejected():
    t, _, _ = transport(response(data={"domain": "", "ports": [22]}))
    assert (
        Shodan(t, "SYNTHETIC_KEY").collect(validate_target("example.com")).status
        == "error"
    )


def test_equivalent_ipv6_source_identity_is_accepted():
    t, _, _ = transport(
        response(data={"ip_str": "2606:4700:4700:0:0:0:0:1111", "ports": []})
    )
    assert (
        Shodan(t, "SYNTHETIC_KEY")
        .collect(validate_target("2606:4700:4700::1111"))
        .status
        == "observed"
    )


@pytest.mark.parametrize(
    "raw", [b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e999}']
)
def test_nonfinite_source_json_rejected(raw):
    from osint_recon.transport import SourceError

    t, _, _ = transport(response(raw=raw))
    with pytest.raises(SourceError):
        t.get("https://rdap.org/domain/example.com")


def test_invalid_utf8_source_rejected():
    from osint_recon.transport import SourceError

    t, _, _ = transport(response(raw=b'{"value":"\xff"}'))
    with pytest.raises(SourceError):
        t.get("https://rdap.org/domain/example.com")


def test_export_secret_overlap_and_nested_strings(tmp_path):
    target = validate_target("example.com")
    e = Evidence(
        "Shodan",
        "observed",
        target.value,
        "https://api.shodan.io/",
        observations={
            "org": "SYNTHETIC_LONG_KEY and LONG_KEY",
            "tags": ["SYNTHETIC_LONG_KEY"],
        },
    )
    export_report(assess(target, [e]), tmp_path, ("LONG_KEY", "SYNTHETIC_LONG_KEY"))
    for path in tmp_path.iterdir():
        text = path.read_text()
        assert "SYNTHETIC_" not in text
        assert "LONG_KEY" not in text


def test_unrepresentable_unicode_source_is_rejected():
    from osint_recon.transport import SourceError

    t, _, _ = transport(response(raw=b'{"value":"\\ud800"}'))
    with pytest.raises(SourceError):
        t.get("https://rdap.org/domain/example.com")
