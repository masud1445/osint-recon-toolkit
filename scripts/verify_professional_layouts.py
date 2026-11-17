"""Readability, responsive and native Chromium zoom checks on saved demo evidence.

Fresh temporary browser profiles set Chromium's native default zoom preference.
No CSS scaling, disabled security policy, extension, API call or user profile is used.
"""

import base64
import json
import math
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

READABILITY = """() => [...document.body.querySelectorAll('*')]
.filter(e => !['SCRIPT','STYLE','OPTION'].includes(e.tagName) && [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim()))
.filter(e => e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden' && e.checkVisibility({checkVisibilityCSS:true}))
.map(e => ({tag:e.tagName, class:e.className.baseVal ?? e.className, size:parseFloat(getComputedStyle(e).fontSize), text:e.textContent.trim().slice(0,45)}))
.filter(e => e.size < 12)"""


def assert_layout(page, label):
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (
        label + " document overflow"
    )
    tiny = page.evaluate(READABILITY)
    assert not tiny, (label, "Text below 12 CSS pixels", tiny)
    assert (
        16
        <= page.locator("body").evaluate("e=>parseFloat(getComputedStyle(e).fontSize)")
        <= 17
    ), label + " body type scale"
    for selector, minimum in (
        ("table", 14),
        ("pre", 13),
        ("input.text-input", 15),
        ("button.button", 15),
    ):
        for element in page.locator(selector).all():
            if element.is_visible():
                assert (
                    element.evaluate("e=>parseFloat(getComputedStyle(e).fontSize)")
                    >= minimum
                ), (label, selector, minimum)


def verify_layouts(playwright, context, page, base, output, identifier, options):
    routes = {
        "dashboard": "/",
        "form": "/assessments/new",
        "live-form": "/assessments/new?mode=live",
        "results": "/assessments/" + identifier,
        "findings": "/findings",
        "history": "/history",
        "sources": "/sources",
    }
    checks = []
    for theme in ("light", "dark"):
        page.goto(base)
        if page.locator("html").get_attribute("data-theme") != theme:
            page.locator("#theme-toggle").click()
        for width, height in (
            (1440, 1050),
            (1920, 1080),
            (768, 1024),
            (390, 844),
            (360, 800),
        ):
            page.set_viewport_size({"width": width, "height": height})
            for name, route in routes.items():
                page.goto(base + route)
                assert page.locator("html").get_attribute("data-theme") == theme
                assert_layout(page, f"{theme}/{width}/{name}")
                checks.append({"theme": theme, "width": width, "page": name})
                if (
                    theme == "light"
                    and width in (1440, 1920, 390, 360)
                    and name in ("dashboard", "form", "results")
                ) or (
                    theme == "dark"
                    and width in (1440, 390)
                    and name in ("dashboard", "results")
                ):
                    page.screenshot(
                        path=str(output / f"professional-{theme}-{width}-{name}.png"),
                        full_page=False,
                    )
            page.goto(base + routes["results"])
            disclosure = page.locator("details.raw-evidence").first
            disclosure.locator("summary").click()
            assert_layout(page, f"{theme}/{width}/evidence-open")
            assert (
                disclosure.locator("pre").evaluate(
                    "e=>parseFloat(getComputedStyle(e).fontSize)"
                )
                >= 13
            )
            if width == 1440 and theme == "light":
                page.screenshot(
                    path=str(output / "professional-evidence.png"), full_page=False
                )
    zoom_checks = []
    for zoom in (1.25, 2.0):
        with tempfile.TemporaryDirectory(prefix="osint-browser-zoom-") as directory:
            profile = Path(directory) / "Default"
            profile.mkdir()
            # Chromium uses logarithmic native zoom levels keyed by the default
            # storage partition 'x'. This is a fresh test profile, never an operator profile.
            preferences = {
                "partition": {
                    "default_zoom_level": {"x": math.log(zoom) / math.log(1.2)}
                }
            }
            (profile / "Preferences").write_text(
                json.dumps(preferences), encoding="utf-8"
            )
            native_options = dict(options)
            if "executable_path" not in native_options:
                native_options["channel"] = (
                    "chromium"  # full/new-headless browser, not headless shell
                )
            zoom_context = playwright.chromium.launch_persistent_context(
                directory,
                no_viewport=True,
                args=["--window-size=1440,1050"],
                **native_options,
            )
            denied, errors = [], []

            def restrict(route):
                if urlsplit(route.request.url).hostname != "127.0.0.1":
                    denied.append(route.request.url)
                    route.abort()
                else:
                    route.continue_()

            zoom_context.route("**/*", restrict)
            zoom_page = zoom_context.pages[0]
            zoom_page.on("pageerror", lambda error: errors.append(str(error)))
            for theme in ("light", "dark"):
                zoom_page.goto(base)
                if zoom_page.locator("html").get_attribute("data-theme") != theme:
                    zoom_page.locator("#theme-toggle").click()
                metrics = zoom_page.evaluate(
                    "({width:innerWidth,outer:outerWidth,dpr:devicePixelRatio})"
                )
                assert abs(metrics["outer"] / metrics["width"] - zoom) < 0.03, (
                    "Native zoom not applied",
                    zoom,
                    metrics,
                )
                for name, route in routes.items():
                    zoom_page.goto(base + route)
                    assert_layout(zoom_page, f"native-{zoom}/{theme}/{name}")
                zoom_page.goto(base + routes["results"])
                # Native zoom changes CSS viewport dimensions; capture the physical
                # browser surface directly so Playwright does not clip the image.
                capture = zoom_context.new_cdp_session(zoom_page).send(
                    "Page.captureScreenshot",
                    {
                        "format": "png",
                        "fromSurface": True,
                        "captureBeyondViewport": False,
                    },
                )
                (
                    output / f"professional-zoom-{int(zoom * 100)}-{theme}.png"
                ).write_bytes(base64.b64decode(capture["data"]))
                zoom_checks.append({"zoom": zoom, "theme": theme, **metrics})
            assert not denied and not errors, (denied, errors)
            zoom_context.close()
    page.set_viewport_size({"width": 1440, "height": 1050})
    page.goto(base)
    if page.locator("html").get_attribute("data-theme") != "light":
        page.locator("#theme-toggle").click()
    (output / "readability-checks.json").write_text(
        json.dumps({"viewports": checks, "native_zoom": zoom_checks}, indent=2),
        encoding="utf-8",
    )
    print(
        f"Professional review passed: {len(checks)} page/viewport/theme cases, 10 expanded JSON checks and 28 native-zoom page cases."
    )
