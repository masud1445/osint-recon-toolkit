"""Single-user loopback dashboard around the existing passive collection engine."""

import argparse
import hmac
import os
import secrets
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from .assessment import assess
from .connectors import RDAP, Shodan, VirusTotal
from .demo import build_demo_report
from .models import now
from .reporting import export_report, prepare_report, presentation, redact
from .store import AssessmentStore, dashboard_lock
from .targets import validate_target
from .transport import Transport


class JobManager:
    """One worker maintains pacing across assessments; demo never uses transport."""

    def __init__(self, store, inline=False):
        self.store, self.inline = store, inline
        self.executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="passive-intelligence"
        )
        self.transport = None
        self.lock = threading.Lock()

    def submit(self, spec):
        with self.lock:
            if self.store.pending() >= 5:
                raise ValueError(
                    "The local queue is full. Wait for an assessment to finish."
                )
            identifier = uuid.uuid4().hex
            created_at = now()
            authorization = None
            if spec["mode"] == "live":
                authorization = {
                    "acknowledged": True,
                    "reference": spec["authorization_ref"],
                    "recorded_at": created_at,
                    "target": spec["target"],
                    "sources": spec["sources"],
                    "vt_license": spec.get("vt_license"),
                }
                private = sorted(
                    {
                        os.environ.get(name)
                        for name in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY")
                    }
                    - {None, ""},
                    key=len,
                    reverse=True,
                )
                if any(key.lower() in spec["target"].lower() for key in private):
                    raise ValueError("Target must not contain configured credentials.")
                authorization = redact(authorization, private)
            self.store.create(
                identifier,
                spec["mode"],
                spec.get("target", "internship-lab.example"),
                created_at,
                authorization,
            )
            if self.inline:
                self.run(identifier, spec, created_at)
            else:
                self.executor.submit(self.run, identifier, spec, created_at)
            return identifier

    def run(self, identifier, spec, created_at):
        try:
            if spec["mode"] == "demo":
                self.store.update(
                    identifier, "running", "Preparing local synthetic records"
                )
                report = prepare_report(build_demo_report())
            else:
                keys = {
                    "shodan": os.environ.get("SHODAN_API_KEY"),
                    "virustotal": os.environ.get("VIRUSTOTAL_API_KEY"),
                }
                private = sorted(
                    {key for key in keys.values() if key}, key=len, reverse=True
                )
                self.transport = self.transport or Transport()
                target = validate_target(spec["target"])
                connectors = {
                    "rdap": RDAP(self.transport),
                    "shodan": Shodan(self.transport, keys["shodan"]),
                    "virustotal": VirusTotal(self.transport, keys["virustotal"]),
                }
                evidence = []
                for index, name in enumerate(spec["sources"], 1):
                    self.store.update(
                        identifier,
                        "running",
                        f"Retrieving {name.upper()} records ({index}/{len(spec['sources'])}); provider quotas may require waiting",
                    )
                    evidence.append(connectors[name].collect(target))
                report = assess(target, evidence)
                report["authorization"] = {
                    "acknowledged": True,
                    "reference": spec["authorization_ref"],
                    "recorded_at": created_at,
                    "target": target.value,
                    "sources": spec["sources"],
                    "vt_license": spec.get("vt_license"),
                }
                report = prepare_report(report, private)
            self.store.update(
                identifier,
                "completed",
                "Assessment complete. Review source coverage before interpreting findings.",
                report,
            )
        except Exception:
            # Never persist exception text, request URLs with keys, or response bodies.
            self.store.update(
                identifier,
                "error",
                "Assessment could not be completed. Check local setup and start a new assessment.",
            )


def stamp(value):
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    except (ValueError, TypeError, AttributeError):
        return "Timestamp unavailable"


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        DATA_DIR=Path.home() / ".osint-recon",
        INLINE_JOBS=False,
        MAX_CONTENT_LENGTH=16_384,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    if config:
        app.config.update(config)
    store = AssessmentStore(app.config["DATA_DIR"])
    jobs = JobManager(store, app.config["INLINE_JOBS"])
    app.extensions["assessment_store"] = store
    app.extensions["assessment_jobs"] = jobs
    app.jinja_env.filters["stamp"] = stamp

    @app.before_request
    def local_security():
        try:
            host = urlsplit("http://" + request.host)
            if (
                host.hostname not in {"127.0.0.1", "localhost"}
                or host.username
                or host.password
            ):
                abort(403)
        except ValueError:
            abort(403)
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            abort(403)
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            abort(403)
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            abort(403)
        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        if request.method == "POST":
            supplied = request.form.get("csrf_token", "")
            if not supplied or not hmac.compare_digest(
                session["csrf_token"].encode("utf-8"), supplied.encode("utf-8")
            ):
                abort(403)

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def common():
        return {
            "csrf_token": session.get("csrf_token", ""),
            "view": presentation,
            "keys": {
                "shodan": bool(os.environ.get("SHODAN_API_KEY")),
                "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
            },
        }

    def page(template, active, **context):
        return render_template(
            template, active=active, assessments=store.list(), **context
        )

    @app.get("/favicon.ico")
    def favicon():
        return "", 204

    @app.get("/")
    def dashboard():
        return page("dashboard.html", "dashboard")

    @app.get("/assessments/new")
    def new_assessment():
        initial = {
            "mode": "live" if request.args.get("mode") == "live" else "demo",
            "target": request.args.get("target", ""),
            "sources": request.args.getlist("sources") or ["rdap"],
        }
        return page("new.html", "new", initial=initial, error=None)

    @app.post("/assessments")
    def create_assessment():
        form = request.form
        mode = form.get("mode")
        try:
            if mode == "demo":
                if any(
                    form.get(name)
                    for name in (
                        "target",
                        "authorized",
                        "authorization_ref",
                        "vt_license",
                    )
                ) or form.getlist("sources"):
                    raise ValueError(
                        "Demo mode cannot include live targets, sources, authorization or API licensing options."
                    )
                spec = {"mode": "demo"}
            elif mode == "live":
                target = validate_target(form.get("target", ""))
                sources = list(dict.fromkeys(form.getlist("sources")))
                if not sources or any(
                    source not in {"rdap", "shodan", "virustotal"} for source in sources
                ):
                    raise ValueError(
                        "Select one or more supported intelligence sources."
                    )
                reference = form.get("authorization_ref", "").strip()
                if (
                    form.get("authorized") not in {"on", "true", "1"}
                    or not reference
                    or len(reference) > 200
                    or any(ord(char) < 32 for char in reference)
                ):
                    raise ValueError(
                        "Record a scope approval reference (up to 200 characters) and confirm target authorization."
                    )
                license_ = form.get("vt_license", "")
                if "virustotal" in sources and license_ not in {
                    "noncommercial-public",
                    "licensed-commercial",
                }:
                    raise ValueError(
                        "Confirm a permitted VirusTotal license before selecting VirusTotal."
                    )
                spec = {
                    "mode": "live",
                    "target": target.value,
                    "sources": sources,
                    "authorization_ref": reference,
                    "vt_license": license_ or None,
                }
            else:
                raise ValueError("Select Live or Demo mode.")
            identifier = jobs.submit(spec)
        except ValueError as exc:
            # Errors contain fixed validation guidance; never echo form values.
            return page(
                "new.html",
                "new",
                initial={
                    "mode": "live" if mode == "live" else "demo",
                    "target": "",
                    "sources": ["rdap"],
                },
                error=str(exc),
            ), 400
        return redirect(url_for("assessment_result", identifier=identifier), code=303)

    def lookup(identifier):
        assessment = store.get(identifier)
        if not assessment:
            abort(404)
        return assessment

    @app.get("/assessments/<identifier>")
    def assessment_result(identifier):
        assessment = lookup(identifier)
        return page(
            "result.html", "results", assessment=assessment, report=assessment["report"]
        )

    @app.get("/api/assessments/<identifier>")
    def assessment_status(identifier):
        assessment = lookup(identifier)
        return {key: assessment[key] for key in ("id", "status", "progress")} | {
            "report_url": url_for("assessment_result", identifier=identifier)
        }

    @app.get("/assessments/<identifier>/export/<format_>")
    def assessment_export(identifier, format_):
        if format_ not in {"html", "json", "csv"}:
            abort(404)
        assessment = lookup(identifier)
        if assessment["status"] != "completed" or not assessment["report"]:
            abort(409)
        with tempfile.TemporaryDirectory(prefix="osint-export-") as directory:
            export_report(assessment["report"], directory)
            payload = (Path(directory) / f"assessment.{format_}").read_bytes()
        from io import BytesIO

        return send_file(
            BytesIO(payload),
            mimetype={
                "html": "text/html",
                "json": "application/json",
                "csv": "text/csv",
            }[format_],
            as_attachment=True,
            download_name=f"assessment-{identifier}.{format_}",
        )

    @app.post("/assessments/<identifier>/delete")
    def assessment_delete(identifier):
        assessment = lookup(identifier)
        if assessment["status"] in {"queued", "running"}:
            abort(409)
        store.delete(identifier)
        return redirect(url_for("history"), code=303)

    @app.get("/history")
    def history():
        return page("history.html", "history")

    @app.get("/findings")
    def findings():
        return page("findings.html", "findings")

    @app.get("/sources")
    def sources():
        return page("sources.html", "sources")

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(413)
    @app.errorhandler(500)
    def safe_error(error):
        return {
            "error": {
                400: "Invalid request",
                403: "Local origin or security token rejected",
                404: "Assessment or page not found",
                409: "Assessment is not ready for this action",
                413: "Request exceeds size limit",
                500: "Local application error",
            }.get(error.code, "Request failed")
        }, error.code

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Start the single-user local OSINT dashboard (loopback only)."
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", type=Path, default=Path.home() / ".osint-recon")
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    from waitress import serve

    try:
        with dashboard_lock(args.data_dir):
            app = create_app({"DATA_DIR": args.data_dir})
            print(
                f"OSINT dashboard listening locally on http://127.0.0.1:{args.port} (no public binding)."
            )
            serve(
                app,
                host="127.0.0.1",
                port=args.port,
                threads=4,
                clear_untrusted_proxy_headers=True,
            )
    except (ValueError, OSError):
        parser.exit(
            2,
            "Dashboard could not start. Check port, data directory permissions, and whether another dashboard is running.\n",
        )


if __name__ == "__main__":
    main()
