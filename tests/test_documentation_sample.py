"""Guard the intentionally public example against drift or real-data replacement."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from osint_recon import demo
from osint_recon.reporting import export_report

SAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "offline-demo"


def test_public_sample_is_exact_builtin_fiction(monkeypatch):
    report = json.loads((SAMPLE / "assessment.json").read_text(encoding="utf-8"))
    prepared = datetime.fromisoformat(report["generated_at"])
    assert prepared.utcoffset().total_seconds() == 0
    monkeypatch.setattr(demo, "now", lambda: report["generated_at"])
    # Full equality excludes extra targets, contact data, credentials and claims
    # of live collection, rather than trusting a top-level Demo label alone.
    assert report == demo.build_demo_report()


@pytest.mark.parametrize("extension", ["html", "json", "csv"])
def test_public_sample_exports_match_current_exporter(tmp_path, extension):
    report = json.loads((SAMPLE / "assessment.json").read_text(encoding="utf-8"))
    export_report(report, tmp_path)
    name = "assessment." + extension
    assert (SAMPLE / name).read_bytes() == (tmp_path / name).read_bytes()
