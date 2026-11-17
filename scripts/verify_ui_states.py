"""Exercise actual queued/running/error/empty demo UI in an isolated test server.

Only this test process delays/fails the synthetic builder. The installed dashboard
and real connectors are unchanged. No live assessment or provider request occurs.
"""

import threading
import time
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from verify_professional_layouts import assert_layout
from waitress import create_server

from osint_recon import web


def verify_states(playwright, output, options):
    release = threading.Event()
    original = web.build_demo_report
    calls = []

    def controlled_demo():
        calls.append(1)
        if len(calls) == 1:
            release.wait(30)
            return original()
        raise RuntimeError("Deliberate synthetic UI-state test; not a provider failure")

    with TemporaryDirectory(prefix="osint-state-fixture-") as directory:
        web.build_demo_report = controlled_demo
        app = web.create_app({"DATA_DIR": directory})
        server = create_server(
            app, host="127.0.0.1", port=0, clear_untrusted_proxy_headers=True
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        context = None
        try:
            browser = playwright.chromium.launch(**options)
            context = browser.new_context(viewport={"width": 1440, "height": 1050})
            page = context.new_page()
            unexpected = []
            page.on("pageerror", lambda error: unexpected.append(str(error)))

            def local_only(route):
                if urlsplit(route.request.url).hostname == "127.0.0.1":
                    route.continue_()
                else:
                    unexpected.append("External request during demo state test")
                    route.abort()

            context.route("**/*", local_only)
            base = f"http://127.0.0.1:{server.effective_port}"
            page.goto(base)
            for theme in ("light", "dark"):
                if page.locator("html").get_attribute("data-theme") != theme:
                    page.locator("#theme-toggle").click()
                for width in (1440, 360):
                    page.set_viewport_size(
                        {"width": width, "height": 1050 if width == 1440 else 800}
                    )
                    assert_layout(page, f"{theme}/{width}/empty")
            ids = []
            for _ in range(2):
                page.goto(base + "/assessments/new")
                page.locator("#start-assessment").click()
                page.wait_for_url("**/assessments/*")
                ids.append(page.url.rsplit("/", 1)[-1])
            store = app.extensions["assessment_store"]
            assert store.get(ids[0])["status"] == "running"
            assert store.get(ids[1])["status"] == "queued"
            for identifier, state in zip(ids, ("running", "queued")):
                for theme in ("light", "dark"):
                    page.goto(base + "/assessments/" + identifier)
                    if page.locator("html").get_attribute("data-theme") != theme:
                        page.locator("#theme-toggle").click()
                    for width in (1440, 360):
                        page.set_viewport_size(
                            {"width": width, "height": 1050 if width == 1440 else 800}
                        )
                        assert_layout(page, f"{theme}/{width}/{state}")
                        assert page.locator('[role="status"]').is_visible()
                        if width == 1440 and theme == "light":
                            page.screenshot(
                                path=str(output / f"professional-{state}.png")
                            )
            release.set()
            for _ in range(100):
                if store.get(ids[1])["status"] == "error":
                    break
                time.sleep(0.05)
            assert store.get(ids[0])["status"] == "completed"
            assert store.get(ids[1])["status"] == "error"
            for theme in ("light", "dark"):
                page.goto(base + "/assessments/" + ids[1])
                if page.locator("html").get_attribute("data-theme") != theme:
                    page.locator("#theme-toggle").click()
                for width in (1440, 360):
                    page.set_viewport_size(
                        {"width": width, "height": 1050 if width == 1440 else 800}
                    )
                    assert_layout(page, f"{theme}/{width}/error")
                    assert (
                        "Assessment could not be completed"
                        in page.locator("body").inner_text()
                    )
                    if width == 1440 and theme == "light":
                        page.screenshot(path=str(output / "professional-error.png"))
            assert not unexpected, unexpected
            print(
                "UI state review passed: 16 real local demo queued/running/error/empty cases, two themes and two widths."
            )
        finally:
            release.set()
            app.extensions["assessment_jobs"].executor.shutdown(wait=True)
            if context:
                context.close()
                browser.close()
            server.close()
            thread.join(timeout=2)
            web.build_demo_report = original
