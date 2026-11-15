"""Browser acceptance checks for the local dashboard; no live provider requests.

Start osint-dashboard first. OSINT_TEST_URL defaults to http://127.0.0.1:8765.
OSINT_BROWSER optionally selects a system Chromium; otherwise use Playwright's.
OSINT_VISUAL_DIR selects a new artifact directory (default reports/visual-review).
"""

import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

base = os.environ.get("OSINT_TEST_URL", "http://127.0.0.1:8765").rstrip("/")
if urlsplit(base).hostname != "127.0.0.1":
    raise SystemExit("Browser checks require a loopback dashboard URL")
output = Path(os.environ.get("OSINT_VISUAL_DIR", "reports/visual-review"))
output.mkdir(parents=True, exist_ok=True)
errors, console_errors, external = [], [], []

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
    page.on(
        "console",
        lambda message: (
            console_errors.append(message.text) if message.type == "error" else None
        ),
    )

    def restrict(route):
        if urlsplit(route.request.url).hostname != "127.0.0.1":
            external.append(route.request.url)
            route.abort()
        else:
            route.continue_()

    def no_overflow(name):
        assert page.evaluate(
            "document.documentElement.scrollWidth <= innerWidth + 1"
        ), name + " horizontal overflow"

    context.route("**/*", restrict)
    try:
        page.goto(base)
        assert page.locator("h1").count() == 1
        page.screenshot(path=str(output / "desktop-empty.png"), full_page=True)
        page.goto(base + "/assessments/new")
        page.locator('input[name="mode"][value="demo"]').check()
        with page.expect_response(
            lambda response: (
                response.request.method == "POST"
                and response.url == base + "/assessments"
            )
        ) as submitted:
            page.locator('form[action="/assessments"] button[type="submit"]').click()
        assert submitted.value.status == 303, (
            "Legitimate same-origin demo form must pass CSRF/Origin checks"
        )
        page.wait_for_url(re.compile(r"/assessments/[a-f0-9]{32}$"))
        identifier = page.url.rsplit("/", 1)[-1]
        for _ in range(100):
            status = context.request.get(base + "/api/assessments/" + identifier).json()
            if status["status"] in ("completed", "error"):
                break
            page.wait_for_timeout(100)
        assert status["status"] == "completed", status
        page.goto(base + "/assessments/" + identifier)
        assert "demo" in page.locator("body").inner_text().lower()
        no_overflow("desktop")
        page.screenshot(path=str(output / "desktop-results.png"), full_page=True)
        disclosure = page.locator("details.raw-evidence").first
        disclosure.locator("summary").click()
        assert disclosure.get_attribute("open") is not None
        assert disclosure.locator("pre").is_visible()
        disclosure.locator("summary").click()
        for width, height, name in [(768, 1024, "tablet"), (390, 844, "mobile")]:
            page.set_viewport_size({"width": width, "height": height})
            no_overflow(name)
            page.screenshot(path=str(output / (name + "-results.png")), full_page=True)
        page.locator("#nav-toggle").click()
        assert page.locator("#nav-toggle").get_attribute("aria-expanded") == "true"
        page.locator('#sidebar a[href="/history"]').click()
        page.wait_for_url(base + "/history")
        no_overflow("mobile history")
        page.set_viewport_size({"width": 1440, "height": 1050})
        page.goto(base)
        ring = page.locator("svg.coverage-ring")
        assert ring.is_visible() and ring.bounding_box()["width"] >= 100
        assert (
            ring.locator("circle").first.evaluate("e => getComputedStyle(e).stroke")
            != "none"
        )
        page.screenshot(path=str(output / "desktop-overview.png"), full_page=True)
        page.locator("#theme-toggle").click()
        assert page.locator("html").get_attribute("data-theme") == "light"
        page.screenshot(path=str(output / "desktop-light.png"), full_page=True)
        page.reload()
        assert page.locator("html").get_attribute("data-theme") == "light", (
            "Theme selection must survive navigation"
        )
        page.goto(base + "/assessments/" + identifier)
        for width, height, name in [(768, 1024, "tablet"), (390, 844, "mobile")]:
            page.set_viewport_size({"width": width, "height": height})
            no_overflow(name + " light")
            page.screenshot(path=str(output / (name + "-light.png")), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 1050})
        page.locator("#theme-toggle").click()
        assert page.locator("html").get_attribute("data-theme") == "dark"
        page.goto(base + "/history")
        page.locator("#history-search").fill("this-record-does-not-exist")
        assert page.locator("#history-no-match").is_visible()
        page.locator("#history-search").fill("")
        page.locator("#history-mode").select_option("demo")
        assert page.locator(f'a[href="/assessments/{identifier}"]').first.is_visible()
        for route in ("/findings", "/sources", "/assessments/new?mode=live"):
            assert page.goto(base + route).status == 200
        assert page.locator('[name="mode"][value="live"]').is_checked()
        assert page.locator("#live-scope").is_visible()
        page.locator('[name="sources"][value="virustotal"]').check()
        assert page.locator("#vt-license").is_enabled()
        assert page.locator("#vt-license").get_attribute("required") is not None
        page.locator('[name="sources"][value="virustotal"]').uncheck()
        page.locator("#target").fill("https://invalid-target.invalid/path")
        page.locator("#authorization-ref").fill(
            "Browser validation only; invalid input must never collect"
        )
        assert page.locator('[name="authorized"]').input_value() == "on"
        page.locator('[name="authorized"]').check()
        with page.expect_response(
            lambda response: (
                response.request.method == "POST"
                and response.url == base + "/assessments"
            )
        ) as rejected:
            page.locator("#start-assessment").click()
        assert rejected.value.status == 400
        assert page.locator('[role="alert"]').is_visible()
        # Expected invalid-input response is intentional; all other console errors fail.
        console_errors[:] = [error for error in console_errors if "400" not in error]
        page.screenshot(path=str(output / "live-validation.png"), full_page=True)
        page.goto(base + "/assessments/" + identifier)
        with page.expect_download() as downloaded:
            page.locator(f'a[href="/assessments/{identifier}/export/html"]').click()
        downloaded.value.save_as(output / "assessment.html")
        for format_ in ("json", "csv"):
            response = context.request.get(
                f"{base}/assessments/{identifier}/export/{format_}"
            )
            assert response.status == 200
            (output / ("assessment." + format_)).write_bytes(response.body())
        report = json.loads((output / "assessment.json").read_text(encoding="utf-8"))
        assert report["is_synthetic"] and report["summary"]["observed_sources"] == 0
        # Render downloaded, self-contained bytes in a fresh document. This verifies
        # offline output without depending on managed-browser file:// permission.
        report_page = context.new_page()
        report_page.on("pageerror", lambda error: errors.append(str(error)))
        report_page.set_content(
            (output / "assessment.html").read_text(encoding="utf-8")
        )
        report_page.set_viewport_size({"width": 794, "height": 1123})
        report_page.emulate_media(media="print")
        assert report_page.evaluate(
            "document.documentElement.scrollWidth <= innerWidth + 1"
        ), "A4 horizontal overflow"
        assert (
            report_page.evaluate("getComputedStyle(document.body).backgroundColor")
            == "rgb(255, 255, 255)"
        ), "Print background must be white"
        assert (
            report_page.evaluate("getComputedStyle(document.body).color")
            == "rgb(23, 40, 59)"
        ), "Print text must remain readable"
        report_page.pdf(
            path=str(output / "assessment-a4.pdf"),
            format="A4",
            print_background=True,
            prefer_css_page_size=True,
        )
        report_page.screenshot(path=str(output / "a4-report.png"), full_page=True)
        page.goto(base + "/history")
        page.once("dialog", lambda dialog: dialog.accept())
        page.locator(f'form[action="/assessments/{identifier}/delete"] button').click()
        page.wait_for_url(base + "/history")
        assert (
            context.request.get(base + "/api/assessments/" + identifier).status == 404
        )
        assert not errors, errors
        assert not console_errors, console_errors
        assert not external, external
    except Exception:
        page.screenshot(path=str(output / "failure.png"), full_page=True)
        (output / "failure.json").write_text(
            json.dumps(
                {
                    "url": page.url,
                    "javascript_errors": errors,
                    "console_errors": console_errors,
                    "external_requests": external,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        raise
    finally:
        browser.close()
print(
    "Browser checks passed: same-origin form/CSRF, offline demo, disclosures, themes, desktop/tablet/mobile, navigation, filters, live validation, exports/delete, A4; no external requests or unexpected JavaScript/console errors."
)
