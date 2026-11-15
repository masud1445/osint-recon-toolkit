"""Rendered form and provenance regressions for recovered dashboard templates."""

from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from flask import render_template_string
from werkzeug.datastructures import MultiDict

from osint_recon.web import create_app


class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.items = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.items.append((tag, dict(attrs)))

    def inputs(self, name):
        return [
            attrs
            for tag, attrs in self.items
            if tag == "input" and attrs.get("name") == name
        ]


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    def no_network(*args, **kwargs):
        raise AssertionError("Template tests must not contact providers")

    monkeypatch.setattr(requests.sessions.Session, "request", no_network)
    return create_app({"DATA_DIR": tmp_path, "TESTING": True, "INLINE_JOBS": True})


@pytest.fixture
def client(app):
    return app.test_client()


def live_assessment(client, reference="APPROVAL-001"):
    page = Elements(client.get("/assessments/new?mode=live").get_data(as_text=True))
    data = MultiDict(
        [
            ("csrf_token", page.inputs("csrf_token")[0]["value"]),
            ("mode", "live"),
            ("target", "example.com"),
            ("sources", "shodan"),
            ("authorized", page.inputs("authorized")[0]["value"]),
            ("authorization_ref", reference),
        ]
    )
    response = client.post("/assessments", data=data)
    assert response.status_code == 303
    return response.headers["Location"]


def test_live_form_checkbox_value_is_accepted_by_backend(client):
    location = live_assessment(client)
    html = client.get(location).get_data(as_text=True)
    assert "APPROVAL-001" in html
    assert "LIVE" in html
    assert "unavailable" in html.lower()


def test_prefill_selects_live_target_and_requested_sources(client):
    html = client.get(
        "/assessments/new?mode=live&target=approved.example.com&sources=shodan&sources=virustotal"
    ).get_data(as_text=True)
    elements = Elements(html)
    assert [item["value"] for item in elements.inputs("mode") if "checked" in item] == [
        "live"
    ]
    assert elements.inputs("target")[0]["value"] == "approved.example.com"
    assert "disabled" not in elements.inputs("target")[0]
    assert [
        item["value"] for item in elements.inputs("sources") if "checked" in item
    ] == ["shodan", "virustotal"]
    assert "checked" not in elements.inputs("authorized")[0]
    assert "value" not in elements.inputs("authorization_ref")[0]


def test_prefill_target_is_escaped_not_rendered_as_markup(client):
    value = '"><script>alert("scope")</script>'
    response = client.get(
        "/assessments/new", query_string={"mode": "live", "target": value}
    )
    html = response.get_data(as_text=True)
    assert Elements(html).inputs("target")[0]["value"] == value
    assert "<script>alert" not in html


def test_demo_prefill_has_no_live_submission_fields(client):
    elements = Elements(client.get("/assessments/new").get_data(as_text=True))
    assert [item["value"] for item in elements.inputs("mode") if "checked" in item] == [
        "demo"
    ]
    for name in ("target", "sources", "authorized", "authorization_ref"):
        assert all("disabled" in item for item in elements.inputs(name))


def test_result_shows_escaped_real_authorization_reference(client):
    location = live_assessment(client, '<img src=x onerror="alert(1)">')
    html = client.get(location).get_data(as_text=True)
    assert "&lt;img" in html
    assert "<img src=x" not in html
    assert "Recorded by operator" not in html


def test_live_refresh_prefills_scope_but_requires_new_authorization(client):
    location = live_assessment(client)
    result = Elements(client.get(location).get_data(as_text=True))
    links = [
        attrs["href"]
        for tag, attrs in result.items
        if tag == "a" and attrs.get("href", "").startswith("/assessments/new?")
    ]
    assert len(links) == 1
    query = parse_qs(urlsplit(links[0]).query)
    assert query == {"mode": ["live"], "target": ["example.com"], "sources": ["shodan"]}
    fields = Elements(client.get(links[0]).get_data(as_text=True))
    assert "checked" not in fields.inputs("authorized")[0]
    assert "value" not in fields.inputs("authorization_ref")[0]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-11-15T08:30:00+08:00", "15 Nov 2026 · 00:30 UTC"),
        ("2026-11-15T08:30:00", "15 Nov 2026 · 08:30 UTC"),
    ],
)
def test_template_timestamp_macro_uses_utc_conversion(app, value, expected):
    with app.test_request_context("/"):
        html = render_template_string(
            "{% from 'base.html' import stamp %}{{ stamp(value) }}", value=value
        )
    assert expected in html


def test_history_delete_form_is_csrf_protected_and_only_for_finished_jobs(app, client):
    import uuid

    from osint_recon.models import now

    location = live_assessment(client)
    pending = uuid.uuid4().hex
    app.extensions["assessment_store"].create(
        pending, "demo", "internship-lab.example", now()
    )
    html = client.get("/history").get_data(as_text=True)
    elements = Elements(html)
    forms = [
        attrs
        for tag, attrs in elements.items
        if tag == "form" and attrs.get("class") == "delete-form"
    ]
    assert len(forms) == 1
    assert forms[0]["method"] == "post"
    assert forms[0]["action"] == location + "/delete"
    assert pending + "/delete" not in html
    csrf = elements.inputs("csrf_token")[0]["value"]
    assert client.post(forms[0]["action"], data={"csrf_token": csrf}).status_code == 303
    assert client.get(location).status_code == 404


def test_metrics_disclose_latest_100_window(client):
    assert "latest 100" in client.get("/").get_data(as_text=True).lower()
    assert "latest 100" in client.get("/history").get_data(as_text=True).lower()


def coverage_segments(html):
    return [
        attrs
        for tag, attrs in Elements(html).items
        if tag == "circle" and "coverage-segment" in attrs.get("class", "")
    ]


def test_empty_overview_coverage_ring_is_neutral(client):
    html = client.get("/").get_data(as_text=True)
    assert "coverage-background" in html
    assert coverage_segments(html) == []
    assert "mini-line" not in html
    assert 'class="metric-accent blue-line" aria-hidden="true"' in html


def test_demo_overview_coverage_ring_only_shows_synthetic_records(client):
    client.get("/")
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    assert (
        client.post(
            "/assessments", data={"mode": "demo", "csrf_token": csrf}
        ).status_code
        == 303
    )
    segments = coverage_segments(client.get("/").get_data(as_text=True))
    assert len(segments) == 1
    assert segments[0]["class"] == "coverage-segment synthetic"
    assert segments[0]["data-count"] == "3"
    assert segments[0]["stroke-dasharray"] == "100.0 0.0"


def test_unavailable_overview_coverage_ring_only_shows_gap_records(client):
    live_assessment(client)
    segments = coverage_segments(client.get("/").get_data(as_text=True))
    assert len(segments) == 1
    assert segments[0]["class"] == "coverage-segment unavailable"
    assert segments[0]["data-count"] == "1"
    assert segments[0]["stroke-dasharray"] == "100.0 0.0"
