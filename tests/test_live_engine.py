"""Provider contracts and redirect safety with entirely mocked responses."""

import pytest
from test_toolkit import response, transport

from osint_recon.connectors import RDAP, Shodan
from osint_recon.targets import validate_target
from osint_recon.transport import SourceError


def test_rdap_relative_registry_redirect_stays_on_approved_source():
    engine, session, _ = transport(
        response(302, headers={"Location": "/domain/example.com?format=rdap"}),
        response(data={"objectClassName": "domain", "ldhName": "example.com"}),
    )
    result = RDAP(engine).collect(validate_target("example.com"))
    assert result.status == "observed"
    assert (
        session.get.call_args_list[1].args[0]
        == "https://rdap.org/domain/example.com?format=rdap"
    )
    assert session.get.call_args_list[1].kwargs["headers"] == {
        "Accept": "application/rdap+json"
    }
    assert session.get.call_args_list[1].kwargs["params"] is None


@pytest.mark.parametrize(
    "location",
    ["//evil.example/collect", "https://rdap.org:invalid/", "https://[invalid/", ""],
)
def test_invalid_or_cross_source_redirect_is_unavailable(location):
    engine, session, _ = transport(response(302, headers={"Location": location}))
    result = RDAP(engine).collect(validate_target("example.com"))
    assert result.status == "unavailable"
    assert result.observations == {}
    assert session.get.call_count == 1


@pytest.mark.parametrize(
    "url", ["https://rdap.org:invalid/", "https://[invalid/", None]
)
def test_invalid_transport_urls_have_sanitized_errors(url):
    engine, session, _ = transport()
    with pytest.raises(SourceError, match="Invalid intelligence source URL"):
        engine.get(url)
    session.get.assert_not_called()


def test_registration_nameservers_keep_names_without_arbitrary_links():
    engine, _, _ = transport(
        response(
            data={
                "objectClassName": "domain",
                "ldhName": "example.com",
                "nameservers": [
                    {
                        "ldhName": "ns.example.com",
                        "links": [{"href": "https://private.invalid/"}],
                    }
                ],
                "entities": [{"vcardArray": ["vcard", ["private contact"]]}],
            }
        )
    )
    result = RDAP(engine).collect(validate_target("example.com"))
    assert result.status == "observed"
    assert result.observations["nameservers"] == [{"ldhName": "ns.example.com"}]
    assert "entities" not in result.observations


@pytest.mark.parametrize("nameservers", ["unexpected", ["ns.example.com"]])
def test_bad_registration_nameserver_schema_is_an_error(nameservers):
    engine, _, _ = transport(
        response(
            data={
                "objectClassName": "domain",
                "ldhName": "example.com",
                "nameservers": nameservers,
            }
        )
    )
    result = RDAP(engine).collect(validate_target("example.com"))
    assert result.status == "error"
    assert result.observations == {}


def test_shodan_preserves_source_asn_and_subdomain_metadata():
    engine, _, _ = transport(
        response(
            data={
                "domain": "example.com",
                "subdomains": ["www", "mail"],
                "asn": "AS15169",
                "more": True,
            }
        )
    )
    result = Shodan(engine, "SYNTHETIC_KEY").collect(validate_target("example.com"))
    assert result.status == "observed"
    assert result.observations["asn"] == "AS15169"
    assert result.observations["subdomains"] == ["www", "mail"]
    assert result.observations["more"] is True


def test_successful_retrieval_timestamp_records_completion(monkeypatch):
    completed = "2026-01-01T12:00:20+00:00"
    monkeypatch.setattr("osint_recon.connectors.now", lambda: completed)
    engine, _, _ = transport(
        response(data={"objectClassName": "domain", "ldhName": "example.com"})
    )
    result = RDAP(engine).collect(validate_target("example.com"))
    assert result.status == "observed"
    assert result.collected_at == completed
