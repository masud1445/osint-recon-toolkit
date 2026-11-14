"""Browser acceptance checks against a loopback server; generates visual evidence.

Run with dashboard already running on 127.0.0.1:8765, or set OSINT_TEST_URL.
Set OSINT_BROWSER to a system Chromium path, otherwise use Playwright's browser.
Never performs live collection; only submits the fixed offline demo.
"""

import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

base = os.environ.get("OSINT_TEST_URL", "http://127.0.0.1:8765")
if urlsplit(base).hostname != "127.0.0.1":
    raise SystemExit("Browser checks require a loopback dashboard URL")
output = Path(os.environ.get("OSINT_VISUAL_DIR", "reports/visual-review"))
output.mkdir(parents=True, exist_ok=True)
errors, external = [], []
with sync_playwright() as playwright:
    options = {"headless": True}
    if os.environ.get("OSINT_BROWSER"):
        options["executable_path"] = os.environ["OSINT_BROWSER"]
    browser = playwright.chromium.launch(**options)
    context = browser.new_context(
        viewport={"width": 1440, "height": 1050}, accept_downloads=True
    )
    page = context.new_page()
    page.on("pageerror", lambda error: errors.append(str(error)))

    def restrict(route):
        if urlsplit(route.request.url).scheme == "file":
            route.continue_()
        elif urlsplit(route.request.url).hostname != "127.0.0.1":
            external.append(route.request.url)
            route.abort()
        else:
            route.continue_()

    context.route("**/*", restrict)
    page.goto(base)
    assert page.locator("h1").count() == 1
    page.screenshot(path=str(output / "desktop-empty.png"), full_page=True)
    page.goto(base + "/assessments/new")
    page.locator('input[name="mode"][value="demo"]').check()
    page.locator('form[action="/assessments"] button[type="submit"]').click()
    page.wait_for_url(re.compile(r"/assessments/[a-f0-9]{32}$"))
    identifier = page.url.rsplit("/", 1)[-1]
    for _ in range(100):
        status = context.request.get(base + "/api/assessments/" + identifier).json()
        if status["status"] in ("completed", "error"):
            break
        page.wait_for_timeout(100)
    assert status["status"] == "completed", status
    page.goto(base + "/assessments/" + identifier)
    page.screenshot(path=str(output / "desktop-results.png"), full_page=True)
    assert "demo" in page.locator("body").inner_text().lower()
    for width, height, name in [(768, 1024, "tablet"), (390, 844, "mobile")]:
        page.set_viewport_size({"width": width, "height": height})
        assert page.evaluate(
            "document.documentElement.scrollWidth <= innerWidth + 1"
        ), name + " overflow"
        page.screenshot(path=str(output / (name + "-results.png")), full_page=True)
    page.set_viewport_size({"width": 1440, "height": 1050})
    page.goto(base + "/")
    page.screenshot(path=str(output / "desktop-overview.png"), full_page=True)
    for route in ("/history", "/findings", "/sources", "/assessments/new?mode=live"):
        response = page.goto(base + route)
        assert response.status == 200
    # Fetch attachment bytes through the authenticated browser context.
    for format_ in ("html", "json", "csv"):
        response = context.request.get(
            f"{base}/assessments/{identifier}/export/{format_}"
        )
        assert response.status == 200
        (output / ("assessment." + format_)).write_bytes(response.body())
    report = json.loads((output / "assessment.json").read_text(encoding="utf-8"))
    assert report["is_synthetic"] and report["summary"]["observed_sources"] == 0
    # Review the standalone file with no network and its actual print stylesheet.
    page.goto((output / "assessment.html").resolve().as_uri())
    page.set_viewport_size({"width": 794, "height": 1123})
    page.emulate_media(media="print")
    page.pdf(
        path=str(output / "assessment-a4.pdf"),
        format="A4",
        print_background=True,
        prefer_css_page_size=True,
    )
    page.screenshot(path=str(output / "a4-report.png"), full_page=True)
    assert not errors, errors
    assert not external, external
    browser.close()
print(
    "Browser checks passed: desktop/tablet/mobile, offline demo, navigation, exports, A4; no external requests or JavaScript errors."
)
