"""Operational presentation contracts without changing the collection engine."""

from html.parser import HTMLParser

import pytest

from osint_recon.web import create_app


class PageStructure(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.theme = None
        self.h1 = []
        self.in_h1 = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        if tag == "html":
            self.theme = dict(attrs).get("data-theme")
        if tag == "h1":
            self.in_h1 = True

    def handle_endtag(self, tag):
        if tag == "h1":
            self.in_h1 = False

    def handle_data(self, data):
        if self.in_h1:
            self.h1.append(data)


@pytest.fixture
def client(tmp_path):
    application = create_app(
        {"DATA_DIR": tmp_path, "TESTING": True, "INLINE_JOBS": True}
    )
    return application.test_client()


@pytest.mark.parametrize(
    "path,heading",
    [
        ("/", "Assessment Dashboard"),
        ("/assessments/new", "New Reconnaissance Assessment"),
        ("/history", "Assessment History"),
        ("/findings", "Findings & Recommendations"),
        ("/sources", "Intelligence Sources"),
    ],
)
def test_bright_operational_pages_have_clear_headings(client, path, heading):
    response = client.get(path)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    structure = PageStructure(body)
    assert structure.theme == "light"
    assert "".join(structure.h1) == heading
    assert 'id="theme-toggle"' in body
    assert 'id="nav-toggle"' in body
    assert "PROJECT 6.1" not in body
    assert "READY FOR YOUR NEXT PRESENTATION" not in body
    assert "Your next insight starts here" not in body
    assert "/assessments/new" in body
    assert "/history" in body


def test_offline_entry_remains_explicit_and_csrf_protected(client):
    body = client.get("/").get_data(as_text=True)
    assert "Start Offline Demo" in body
    assert 'action="/assessments" method="post"' in body
    assert 'name="csrf_token"' in body
    assert 'name="mode" value="demo"' in body
    assert "Synthetic training" in body
