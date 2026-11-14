"""Local dashboard security and mocked collection integration; never live APIs."""

import json
from unittest.mock import Mock

import pytest
import requests
from werkzeug.datastructures import MultiDict

from osint_recon.models import Evidence
from osint_recon.web import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    def no_network(*args, **kwargs):
        raise AssertionError("Dashboard tests must not contact external APIs")

    monkeypatch.setattr(requests.sessions.Session, "request", no_network)
    return create_app({"DATA_DIR": tmp_path, "TESTING": True, "INLINE_JOBS": True})


@pytest.fixture
def client(app):
    return app.test_client()


def token(client):
    assert client.get("/").status_code == 200
    with client.session_transaction() as session:
        return session["csrf_token"]


def submit(client, mode="demo", **values):
    data = MultiDict([("csrf_token", token(client)), ("mode", mode)])
    for name, value in values.items():
        if isinstance(value, list):
            for item in value:
                data.add(name, item)
        else:
            data.add(name, value)
    return client.post("/assessments", data=data)


def demo(client):
    response = submit(client)
    assert response.status_code == 303
    return response.headers["Location"].rsplit("/", 1)[-1]


@pytest.mark.parametrize(
    "path", ["/", "/assessments/new", "/history", "/findings", "/sources"]
)
def test_dashboard_pages_have_real_local_navigation(client, path):
    response = client.get(path)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "/assessments/new" in body
    assert "/history" in body
    assert "<script src=" in body
    assert "https://cdn" not in body


def test_headers_and_cookie_protect_local_data(client):
    response = client.get("/")
    policy = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "script-src 'self'" in policy
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "no-store" in response.headers["Cache-Control"]
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


@pytest.mark.parametrize(
    "host", ["evil.example", "127.0.0.1.evil.example", "0.0.0.0", "192.168.1.1"]
)
def test_host_rebinding_is_rejected(client, host):
    assert client.get("/", headers={"Host": host}).status_code == 403


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
    ],
)
def test_cross_site_requests_cannot_read_local_results(client, headers):
    assert client.get("/history", headers=headers).status_code == 403


def test_nonloopback_clients_are_rejected(client):
    response = client.get("/", environ_overrides={"REMOTE_ADDR": "192.168.1.10"})
    assert response.status_code == 403


def test_csrf_is_required_and_session_bound(app, client):
    csrf = token(client)
    assert client.post("/assessments", data={"mode": "demo"}).status_code == 403
    assert (
        client.post(
            "/assessments", data={"mode": "demo", "csrf_token": "wrong"}
        ).status_code
        == 403
    )
    other = app.test_client()
    token(other)
    assert (
        other.post(
            "/assessments", data={"mode": "demo", "csrf_token": csrf}
        ).status_code
        == 403
    )


def test_demo_jobs_never_construct_live_transport(app, client, monkeypatch):
    transport = Mock(side_effect=AssertionError("Demo constructed the live transport"))
    monkeypatch.setattr("osint_recon.web.Transport", transport)
    identifier = demo(client)
    transport.assert_not_called()
    result = app.extensions["assessment_store"].get(identifier)
    assert result["status"] == "completed"
    assert result["mode"] == "demo"
    assert result["report"]["is_synthetic"] is True
    assert result["report"]["summary"]["observed_sources"] == 0
    assert len(result["report"]["evidence"]) == 3
    assert all(e["status"] == "synthetic" for e in result["report"]["evidence"])
    page = client.get(f"/assessments/{identifier}")
    assert page.status_code == 200
    assert "Demo" in page.get_data(as_text=True) or "DEMO" in page.get_data(
        as_text=True
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"target": "example.com"},
        {"authorized": "on"},
        {"sources": ["rdap"]},
        {"vt_license": "noncommercial-public"},
        {"authorization_ref": "real engagement"},
    ],
)
def test_demo_rejects_live_options(client, extra):
    assert submit(client, **extra).status_code == 400


@pytest.mark.parametrize(
    "values",
    [
        {"target": "example.com", "sources": ["rdap"], "authorization_ref": "ENG-01"},
        {"target": "example.com", "sources": ["rdap"], "authorized": "on"},
        {
            "target": "example.com",
            "sources": ["rdap"],
            "authorized": "false",
            "authorization_ref": "ENG-01",
        },
        {
            "target": "http://example.com",
            "sources": ["rdap"],
            "authorized": "on",
            "authorization_ref": "ENG-01",
        },
        {
            "target": "127.0.0.1",
            "sources": ["rdap"],
            "authorized": "on",
            "authorization_ref": "ENG-01",
        },
        {
            "target": "example.com",
            "sources": ["arbitrary"],
            "authorized": "on",
            "authorization_ref": "ENG-01",
        },
        {
            "target": "example.com",
            "sources": [],
            "authorized": "on",
            "authorization_ref": "ENG-01",
        },
        {
            "target": "example.com",
            "sources": ["rdap"],
            "authorized": "on",
            "authorization_ref": " ",
        },
        {
            "target": "example.com",
            "sources": ["rdap"],
            "authorized": "on",
            "authorization_ref": "x" * 201,
        },
        {
            "target": "example.com",
            "sources": ["virustotal"],
            "authorized": "on",
            "authorization_ref": "ENG-01",
        },
        {
            "target": "example.com",
            "sources": ["virustotal"],
            "authorized": "on",
            "authorization_ref": "ENG-01",
            "vt_license": "unlicensed",
        },
    ],
)
def test_live_input_scope_authorization_and_licensing_are_required(client, values):
    assert submit(client, mode="live", **values).status_code == 400


def test_invalid_mode_is_not_a_synthetic_fallback(client):
    assert submit(client, mode="anything").status_code == 400


def test_live_missing_credentials_stays_live_and_unavailable(app, client):
    response = submit(
        client,
        mode="live",
        target="example.com",
        sources=["shodan"],
        authorized="on",
        authorization_ref="INTERNSHIP-APPROVAL-001",
    )
    assert response.status_code == 303
    identifier = response.headers["Location"].rsplit("/", 1)[-1]
    result = app.extensions["assessment_store"].get(identifier)
    report = result["report"]
    assert result["status"] == "completed"
    assert result["mode"] == "live"
    assert report["mode"] == "live-source retrieval"
    assert not report.get("is_synthetic", False)
    assert report["evidence"][0]["status"] == "unavailable"
    assert report["findings"] == []
    assert report["authorization"]["acknowledged"] is True
    assert report["authorization"]["reference"] == "INTERNSHIP-APPROVAL-001"
    assert report["authorization"]["target"] == "example.com"


def test_mocked_live_collection_persists_only_redacted_evidence(
    app, client, monkeypatch
):
    secret = "NOT_A_REAL_PROVIDER_KEY_FOR_TESTING"
    monkeypatch.setenv("SHODAN_API_KEY", secret)
    evidence = Evidence(
        "Shodan",
        "observed",
        "8.8.8.8",
        "https://api.shodan.io/shodan/host/8.8.8.8",
        observations={
            "ip_str": "8.8.8.8",
            "ports": [443],
            "org": f"<script>alert(1)</script> {secret}",
        },
    )
    collect = Mock(return_value=evidence)
    monkeypatch.setattr("osint_recon.web.Shodan.collect", collect)
    response = submit(
        client,
        mode="live",
        target="8.8.8.8",
        sources=["shodan"],
        authorized="on",
        authorization_ref="ENG-READONLY",
    )
    assert response.status_code == 303
    identifier = response.headers["Location"].rsplit("/", 1)[-1]
    result = app.extensions["assessment_store"].get(identifier)
    report = result["report"]
    collect.assert_called_once()
    assert report["summary"]["observed_sources"] == 1
    assert report["evidence"][0]["status"] == "observed"
    assert secret not in json.dumps(report)
    assert "[REDACTED]" in json.dumps(report)
    page = client.get(f"/assessments/{identifier}").get_data(as_text=True)
    assert secret not in page
    assert "<script>alert(1)</script>" not in page
    for path in app.config["DATA_DIR"].rglob("*.sqlite3"):
        assert secret.encode() not in path.read_bytes()


def test_worker_failure_is_sanitized_without_fabricated_report(
    app, client, monkeypatch
):
    def fail(*args):
        raise RuntimeError("SECRET_INTERNAL_PROVIDER_FAILURE")

    monkeypatch.setattr("osint_recon.web.RDAP.collect", fail)
    response = submit(
        client,
        mode="live",
        target="example.com",
        sources=["rdap"],
        authorized="on",
        authorization_ref="ENG-ERROR",
    )
    identifier = response.headers["Location"].rsplit("/", 1)[-1]
    result = app.extensions["assessment_store"].get(identifier)
    assert result["status"] == "error"
    assert result["report"] is None
    status = client.get(f"/api/assessments/{identifier}")
    assert "SECRET_INTERNAL_PROVIDER_FAILURE" not in status.get_data(as_text=True)
    assert "Traceback" not in status.get_data(as_text=True)


def test_polling_returns_status_without_secrets_or_embedded_evidence(client):
    identifier = demo(client)
    response = client.get(f"/api/assessments/{identifier}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == identifier
    assert data["status"] == "completed"
    assert data["report_url"].endswith(identifier)
    assert "evidence" not in data
    assert "api_key" not in data


@pytest.mark.parametrize(
    "fmt,content_type",
    [("html", "text/html"), ("json", "application/json"), ("csv", "text/csv")],
)
def test_exports_preserve_provenance_and_force_attachment(client, fmt, content_type):
    identifier = demo(client)
    response = client.get(f"/assessments/{identifier}/export/{fmt}")
    assert response.status_code == 200
    assert response.content_type.startswith(content_type)
    assert "attachment" in response.headers["Content-Disposition"]
    assert "synthetic" in response.get_data(as_text=True).lower()
    if fmt == "json":
        report = json.loads(response.get_data(as_text=True))
        assert report["mode"] == "offline demonstration"
        assert report["summary"]["observed_sources"] == 0


@pytest.mark.parametrize(
    "path",
    [
        "/assessments/not-a-valid-id",
        "/api/assessments/not-a-valid-id",
        "/assessments/" + "f" * 32,
        "/assessments/" + "f" * 32 + "/export/json",
    ],
)
def test_unknown_or_invalid_identifiers_do_not_reach_filesystem(client, path):
    assert client.get(path).status_code == 404


def test_unsupported_export_format_is_not_an_arbitrary_file_download(client):
    identifier = demo(client)
    assert client.get(f"/assessments/{identifier}/export/sqlite3").status_code == 404
    assert (
        client.get(f"/assessments/{identifier}/export/../../etc/passwd").status_code
        == 404
    )


def test_history_survives_app_restart_and_delete_requires_csrf(app, client):
    identifier = demo(client)
    other_app = create_app(
        {"DATA_DIR": app.config["DATA_DIR"], "TESTING": True, "INLINE_JOBS": True}
    )
    other = other_app.test_client()
    assert other.get(f"/assessments/{identifier}").status_code == 200
    assert other.post(f"/assessments/{identifier}/delete").status_code == 403
    response = other.post(
        f"/assessments/{identifier}/delete", data={"csrf_token": token(other)}
    )
    assert response.status_code == 303
    assert other.get(f"/assessments/{identifier}").status_code == 404


def test_non_ascii_csrf_is_a_rejection_not_a_server_error(client):
    token(client)
    response = client.post("/assessments", data={"mode": "demo", "csrf_token": "é"})
    assert response.status_code == 403


def test_repeated_live_assessments_reuse_provider_pacing_transport(
    app, client, monkeypatch
):
    transport = Mock()
    transport.get.return_value = {"objectClassName": "domain", "ldhName": "example.com"}
    constructor = Mock(return_value=transport)
    monkeypatch.setattr("osint_recon.web.Transport", constructor)
    ids = []
    for _ in range(2):
        response = submit(
            client,
            mode="live",
            target="example.com",
            sources=["rdap"],
            authorized="on",
            authorization_ref="ENG-APPROVED",
        )
        assert response.status_code == 303
        identifier = response.headers["Location"].rsplit("/", 1)[-1]
        ids.append(identifier)
        assert (
            app.extensions["assessment_store"].get(identifier)["report"]["evidence"][0][
                "status"
            ]
            == "observed"
        )
    assert ids[0] != ids[1]
    constructor.assert_called_once()
    assert transport.get.call_count == 2


def test_active_assessment_cannot_be_deleted(app, client):
    import uuid

    from osint_recon.models import now

    identifier = uuid.uuid4().hex
    app.extensions["assessment_store"].create(identifier, "live", "example.com", now())
    response = client.post(
        f"/assessments/{identifier}/delete", data={"csrf_token": token(client)}
    )
    assert response.status_code == 409
    assert app.extensions["assessment_store"].get(identifier) is not None


def test_local_server_entry_binds_loopback_only(tmp_path, monkeypatch):
    from osint_recon.web import main

    server, application = Mock(), Mock()
    monkeypatch.setattr("waitress.serve", server)
    monkeypatch.setattr("osint_recon.web.create_app", Mock(return_value=application))
    main(["--port", "9876", "--data-dir", str(tmp_path)])
    assert server.call_args.args == (application,)
    assert server.call_args.kwargs["host"] == "127.0.0.1"
    assert server.call_args.kwargs["port"] == 9876
    assert server.call_args.kwargs["clear_untrusted_proxy_headers"] is True


@pytest.mark.parametrize(
    "argv", [["--port", "80"], ["--port", "65536"], ["--host", "0.0.0.0"]]
)
def test_dashboard_entry_does_not_offer_public_or_invalid_bindings(argv):
    from osint_recon.web import main

    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_authorization_survives_worker_failure(app, client, monkeypatch):
    monkeypatch.setattr(
        "osint_recon.web.RDAP.collect", Mock(side_effect=RuntimeError("private"))
    )
    response = submit(
        client,
        mode="live",
        target="example.com",
        sources=["rdap"],
        authorized="on",
        authorization_ref="APPROVAL-RETAINED",
    )
    identifier = response.headers["Location"].rsplit("/", 1)[-1]
    assessment = app.extensions["assessment_store"].get(identifier)
    assert assessment["status"] == "error"
    assert assessment["authorization"]["reference"] == "APPROVAL-RETAINED"
    assert assessment["authorization"]["target"] == "example.com"


def test_authorization_survives_interrupted_job_recovery(app):
    import uuid

    from osint_recon.models import now

    identifier = uuid.uuid4().hex
    authorization = {
        "acknowledged": True,
        "reference": "APPROVAL-RESTART",
        "target": "example.com",
        "recorded_at": now(),
        "sources": ["rdap"],
    }
    store = app.extensions["assessment_store"]
    store.create(identifier, "live", "example.com", now(), authorization=authorization)
    store.update(identifier, "running", "Collecting RDAP")
    resumed = create_app(
        {"DATA_DIR": app.config["DATA_DIR"], "TESTING": True, "INLINE_JOBS": True}
    )
    assessment = resumed.extensions["assessment_store"].get(identifier)
    assert assessment["status"] == "error"
    assert assessment["report"] is None
    assert assessment["authorization"] == authorization


def test_queue_is_bounded(app, client):
    import uuid

    from osint_recon.models import now

    store = app.extensions["assessment_store"]
    for _ in range(5):
        store.create(uuid.uuid4().hex, "demo", "internship-lab.example", now())
    response = submit(client)
    assert response.status_code == 400
    assert store.pending() == 5


def test_api_credentials_are_not_rendered_on_configuration_pages(client, monkeypatch):
    secret = "SYNTHETIC_NOT_A_REAL_API_SECRET"
    monkeypatch.setenv("SHODAN_API_KEY", secret)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", secret)
    for path in ("/", "/sources", "/assessments/new", "/history", "/findings"):
        assert secret not in client.get(path).get_data(as_text=True)


def test_authorization_reference_is_redacted_before_failure_storage(
    app, client, monkeypatch
):
    secret = "SYNTHETIC_NEVER_A_REAL_PROVIDER_SECRET"
    monkeypatch.setenv("SHODAN_API_KEY", secret)
    monkeypatch.setattr(
        "osint_recon.web.RDAP.collect", Mock(side_effect=RuntimeError("private"))
    )
    response = submit(
        client,
        mode="live",
        target="example.com",
        sources=["rdap"],
        authorized="on",
        authorization_ref=f"ENG-{secret}",
    )
    identifier = response.headers["Location"].rsplit("/", 1)[-1]
    assessment = app.extensions["assessment_store"].get(identifier)
    assert assessment["status"] == "error"
    assert secret not in json.dumps(assessment)
    assert "[REDACTED]" in assessment["authorization"]["reference"]


def test_repeated_source_selection_does_not_duplicate_collection(
    app, client, monkeypatch
):
    evidence = Evidence(
        "RDAP",
        "observed",
        "example.com",
        "https://rdap.org/domain/example.com",
        observations={"objectClassName": "domain", "ldhName": "example.com"},
    )
    collect = Mock(return_value=evidence)
    monkeypatch.setattr("osint_recon.web.RDAP.collect", collect)
    response = submit(
        client,
        mode="live",
        target="example.com",
        sources=["rdap", "rdap"],
        authorized="on",
        authorization_ref="ENG-ONE",
    )
    identifier = response.headers["Location"].rsplit("/", 1)[-1]
    collect.assert_called_once()
    assert (
        len(app.extensions["assessment_store"].get(identifier)["report"]["evidence"])
        == 1
    )


def test_background_assessment_reports_progress_and_completes(tmp_path, monkeypatch):
    import threading
    import time

    started, release = threading.Event(), threading.Event()

    def collect(self, target):
        started.set()
        assert release.wait(5)
        return Evidence(
            "RDAP",
            "observed",
            target.value,
            "https://rdap.org/domain/example.com",
            observations={"objectClassName": "domain", "ldhName": target.value},
        )

    monkeypatch.setattr("osint_recon.web.RDAP.collect", collect)
    application = create_app(
        {"DATA_DIR": tmp_path / "background", "TESTING": True, "INLINE_JOBS": False}
    )
    browser = application.test_client()
    try:
        response = submit(
            browser,
            mode="live",
            target="example.com",
            sources=["rdap"],
            authorized="on",
            authorization_ref="ENG-ASYNC",
        )
        assert response.status_code == 303
        identifier = response.headers["Location"].rsplit("/", 1)[-1]
        assert started.wait(3)
        status = browser.get(f"/api/assessments/{identifier}").get_json()
        assert status["status"] == "running"
        assert "RDAP" in status["progress"]
        assert (
            browser.post(
                f"/assessments/{identifier}/delete", data={"csrf_token": token(browser)}
            ).status_code
            == 409
        )
        release.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = browser.get(f"/api/assessments/{identifier}").get_json()
            if status["status"] == "completed":
                break
            time.sleep(0.01)
        assert status["status"] == "completed"
    finally:
        release.set()
        application.extensions["assessment_jobs"].executor.shutdown(wait=True)


@pytest.mark.parametrize("license_", ["noncommercial-public", "licensed-commercial"])
def test_approved_vt_license_is_recorded_without_fabricating_missing_key_data(
    app, client, license_
):
    response = submit(
        client,
        mode="live",
        target="example.com",
        sources=["virustotal"],
        authorized="on",
        authorization_ref="ENG-VT",
        vt_license=license_,
    )
    assert response.status_code == 303
    identifier = response.headers["Location"].rsplit("/", 1)[-1]
    result = app.extensions["assessment_store"].get(identifier)
    assert result["authorization"]["vt_license"] == license_
    assert result["report"]["authorization"]["vt_license"] == license_
    assert result["report"]["mode"] == "live-source retrieval"
    assert result["report"]["evidence"][0]["status"] == "unavailable"
    assert result["report"]["findings"] == []


def test_configured_secret_in_target_is_rejected_before_history_or_collection(
    app, client, monkeypatch
):
    secret = "0123456789abcdef0123456789abcdef"
    monkeypatch.setenv("SHODAN_API_KEY", secret)
    constructor = Mock(
        side_effect=AssertionError("Secret-bearing target reached collection")
    )
    monkeypatch.setattr("osint_recon.web.Transport", constructor)
    response = submit(
        client,
        mode="live",
        target=f"{secret}.com",
        sources=["rdap"],
        authorized="on",
        authorization_ref="ENG-SAFE",
    )
    assert response.status_code == 400
    assert secret not in response.get_data(as_text=True)
    constructor.assert_not_called()
    assert app.extensions["assessment_store"].list() == []


def test_three_mocked_live_connectors_flow_into_a_real_live_report(
    app, client, monkeypatch
):
    monkeypatch.setenv("SHODAN_API_KEY", "SYNTHETIC_SHODAN")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "SYNTHETIC_VIRUSTOTAL")
    transport = Mock()
    transport.get.side_effect = [
        {"objectClassName": "domain", "ldhName": "example.com", "status": ["active"]},
        {
            "domain": "example.com",
            "more": False,
            "data": [
                {
                    "subdomain": "www",
                    "type": "A",
                    "value": "8.8.8.8",
                    "last_seen": "2025-01-01T00:00:00Z",
                }
            ],
        },
        {
            "data": {
                "id": "example.com",
                "type": "domain",
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "harmless": 70},
                    "last_analysis_date": 1700000000,
                },
            }
        },
    ]
    monkeypatch.setattr("osint_recon.web.Transport", Mock(return_value=transport))
    response = submit(
        client,
        mode="live",
        target="example.com",
        sources=["rdap", "shodan", "virustotal"],
        authorized="on",
        authorization_ref="ENG-MOCKED-CONTRACT",
        vt_license="noncommercial-public",
    )
    assert response.status_code == 303
    identifier = response.headers["Location"].rsplit("/", 1)[-1]
    report = app.extensions["assessment_store"].get(identifier)["report"]
    assert report["mode"] == "live-source retrieval"
    assert not report.get("is_synthetic", False)
    assert report["summary"]["observed_sources"] == 3
    assert len(report["evidence"]) == 3
    assert all(e["status"] == "observed" for e in report["evidence"])
    assert {e["source"] for e in report["evidence"]} == {"RDAP", "Shodan", "VirusTotal"}
    assert len(report["findings"]) == 1
    assert report["findings"][0]["source"] == "VirusTotal"
    assert "not a confirmed compromise" in report["findings"][0]["interpretation"]
    assert transport.get.call_count == 3
    urls = [call.args[0] for call in transport.get.call_args_list]
    assert urls == [
        "https://rdap.org/domain/example.com",
        "https://api.shodan.io/dns/domain/example.com",
        "https://www.virustotal.com/api/v3/domains/example.com",
    ]


def test_display_timestamp_converts_offset_to_utc():
    from osint_recon.web import stamp

    assert stamp("2026-11-13T08:15:00+08:00") == "13 Nov 2026 · 00:15 UTC"
    assert stamp("not-a-date") == "Timestamp unavailable"
    assert stamp(None) == "Timestamp unavailable"
