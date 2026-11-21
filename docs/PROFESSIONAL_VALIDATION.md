# Professional workspace redesign: verification record — 5d22f8f

This preserved record describes the professional redesign at `5d22f8f0c51ac30a6b35549fce6f99caf9ccb959`. See [release readiness](RELEASE_READINESS.md) for the subsequent documentation release; earlier verification is not proof for a newer commit.

## Scope and preservation

Starting point: verified `fix/dashboard-validation`, commit `362ee6ae5cbaec3fe8838d4a4506337e8e157f4f`. Delivery branch: `feature/professional-workspace-redesign`. Existing recovery, validation and default branches remain intact; no merge or default-branch change was made.

This revision changes the visual presentation and documentation. The collection engine, CLI, Flask security/server code, SQLite store, target validation, transport and demo builder are byte-identical to the starting point. A separate read-only review also compared the reporting functions by AST: normalization/presentation calculations, provenance validation, redaction and HTML/JSON/CSV export logic are unchanged. Only the HTML report template is redesigned. Tests use isolated data directories; no schema migration, history reset or live collection is performed.

## Supervisor review before implementation

The [formal compliance matrix](SUPERVISOR_COMPLIANCE.md) records the 12 requested capabilities against source/test evidence. The existing implementation already supplied modular connectors, scope validation, conservative evidence interpretation and reporting. The genuine deliverable gaps were a consolidated workbook, reusable scope/authorization form, assessed synthetic exercises and an operator mini-audit sign-off checklist. These are now supplied in the linked documents.

RDAP is the implemented registration-intelligence mechanism. Legacy port-43 WHOIS is not implemented or silently substituted. The [workbook](OSINT_OPERATIONS_WORKBOOK.md) maps RDAP fields to familiar WHOIS questions and documents omissions. Literal WHOIS-protocol compatibility remains a separate requirement only if the supervisor explicitly requires it; no additional network fallback was added solely for terminology.

## Automated checks executed

Local platform: Linux, Python 3.12.14, Chromium 156.

| Check | Result |
| --- | --- |
| Complete Python suite | **247 passed, 0 failed, 0 skipped**, final run 11.22 seconds |
| Statement coverage | **96%** — 741 statements, 27 uncovered; unchanged from the previous verified branch |
| Existing regression suite | All 238 baseline cases retained and passing; nine new presentation/report cases added |
| Ruff: `ruff check src tests scripts` | Passed |
| JavaScript: `node --check src/osint_recon/static/app.js` | Passed |
| Dependency consistency: `pip check` | No broken requirements |
| Installed-package vulnerability audit: `pip-audit` | No known vulnerabilities in audited packages; unpublished local project skipped by advisory database |
| Wheel packaging | Successful; templates/static resources included and compared with current source |
| Installed dashboard startup | Waitress served HTTP 200 on loopback; no public binding |
| Browser functional workflow | Passed actual same-origin form/CSRF submission, async demo completion, disclosures, theme persistence, source/license controls, invalid-input rejection, navigation, history filters, downloads and deletion |
| Network behavior | No external requests or unexpected JavaScript/console errors during the offline review |

The counts above are executed local results, not an assertion of live provider access. [GitHub Actions run 44060415987](https://github.com/masud1445/osint-recon-toolkit/actions/runs/44060415987) succeeded on exact commit `5d22f8f0c51ac30a6b35549fce6f99caf9ccb959`: all **11 jobs** passed (nine OS/Python combinations, dependency checks and interface/browser checks), in **5m 35s**. Each job conclusion was checked. This establishes that revision's CI result only; use the release-readiness record for later commits.

## Responsive, typography and zoom checks

The browser runner verifies:

- **70 page/viewport/theme cases**: seven operational pages at 1440, 1920, 768, 390 and 360 CSS-pixel widths, in bright and dark themes.
- **10 expanded-JSON checks**: technical evidence remains readable and does not create document-level overflow.
- **28 native browser-zoom page cases**: seven pages, both themes, at 125% and 200%.
- **16 state cases**: empty, queued, running and error states, both themes at 1440 and 360 pixels.
- **Six standalone-report screen cases**: five widths and an expanded technical-JSON view, followed by actual A4 PDF generation.

Computed-style assertions require 16–17px body type, no visible text below 12 CSS pixels, at least 14px tables, at least 13px technical blocks, and at least 15px primary inputs/buttons where present. These assertions run at every sampled operational viewport/theme and native-zoom case. The stylesheet uses larger 14–15px supporting text and the requested heading hierarchy. This is practical readability verification, not an accessibility certification.

Native zoom uses fresh temporary Chromium profiles with the browser's own zoom preference, not CSS `zoom`, pinch scale, reduced-font substitutes or disabled browser policy. The captured metrics prove actual reflow:

| Native zoom | Physical outer width | CSS viewport width | Device pixel ratio |
| --- | --- | --- | --- |
| 125% | 1440 | 1152 | 1.25 |
| 200% | 1440 | 720 | 2 |

The [recorded viewport and native-zoom manifest](evidence/professional-readability.json) contains the actual measurements from this run.

Native-zoom screenshots use direct browser-surface capture to avoid Playwright clipping a physical image to CSS-sized dimensions. No operator browser profile is modified.

The state checks run a separate local test server that deliberately delays and then fails only the synthetic demo builder. This produces real queued/running/error transitions through the existing job manager; no provider or production server is mocked into reporting real intelligence. The test process restores the builder and closes its server/executor afterwards.

## Visual quality review and A4 evidence

The interface was visually inspected after automated checks. The bright default combines an off-white/light-blue background, white panels and a navy sidebar with blue/teal/amber/purple accents. Optional dark styling uses the same hierarchy. Marketing/assignment labels were removed from the operational interface. Independent dashboard columns avoid blank panel gaps; status badges retain complete words. Chart segments continue to come only from saved source counts; no fabricated trends or threat ratings are introduced.

The standalone report is bright on screen and white on A4, with readable evidence tables, source timestamps, findings, technical disclosures and safe exports. The demo report is **five A4 pages**, approximately **595×842 points**, with no PDF JavaScript. The extra page versus the older design reflects larger readable type; no fixed page count is used to force smaller text. Source and fixture dates remain explicitly distinct from report preparation time.

| View | Verified screenshot |
| --- | --- |
| Bright desktop overview | [1440px](screenshots/professional-desktop.png) |
| Wide desktop | [1920px](screenshots/professional-desktop-1920.png) |
| New assessment | [Form](screenshots/professional-form.png) |
| Evidence review | [Expanded JSON](screenshots/professional-evidence.png) |
| Mobile results | [390px](screenshots/professional-mobile.png) |
| Mobile assessment form | [360px](screenshots/professional-mobile-form.png) |
| Optional dark theme | [Desktop](screenshots/professional-dark.png) |
| Native 200% zoom | [Browser surface](screenshots/professional-zoom-200.png) |
| White A4 report | [PDF first page](screenshots/professional-report-a4.png) |

All screenshot records are fictional demo data. Full browser artifacts include the viewport/zoom JSON evidence, additional screenshots and HTML/JSON/CSV/PDF files. They are generated under `reports/` and uploaded by CI, not presented as live intelligence.

## Reproduce

Follow the exact [Mac startup instructions](DASHBOARD.md). For browser verification, use a separate dashboard data directory so existing assessment history is untouched:

```sh
python -m pip install -e '.[test,browser]'
python -m playwright install chromium
osint-dashboard --port 8766 --data-dir "$HOME/.osint-recon-ui-review"
```

In another activated environment terminal:

```sh
OSINT_TEST_URL=http://127.0.0.1:8766 python scripts/verify_dashboard.py
```

If using an installed compatible Chromium, set `OSINT_BROWSER` to its executable path. The runner performs only the fixed offline scenario plus intentionally invalid Live input that is rejected before collection. It creates/deletes its own demo record; never point it at a shared operator data directory. CI installs a full Chromium browser for native zoom checks, rather than relying only on a headless shell.

## Missing or unverified operational requirements

- Genuine live RDAP/Shodan/VirusTotal acceptance remains unverified: an approved target, usable keys, correct entitlements/licensing and permitted network access are prerequisites.
- Public VirusTotal licensing does not become commercial permission through a UI checkbox. Commercial readiness, privacy/security review and real client assessment acceptance are not claimed.
- Legacy WHOIS protocol support is absent; RDAP registration mapping is documented rather than disguised as WHOIS interoperability.
- Curated RDAP redirects, Shodan page-1 coverage, account/day quotas, source freshness and per-operation timeouts remain documented limits.
- Native browser checks used Linux Chromium; real-device Mac Safari, other browser engines and accessibility certification are not claimed.
- The tool remains local/single-operator; it provides neither a public multi-user deployment nor encrypted/signed evidence custody or certified secure deletion.
