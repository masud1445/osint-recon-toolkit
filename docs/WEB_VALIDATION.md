# Historical dashboard validation and CI correction

This record covers the recovery/CI correction before the professional redesign and final documentation release. Counts, screenshots and print page counts below apply to that revision. See [release readiness](RELEASE_READINESS.md) for current verification.

## Recovery baseline and original failed run

The recovered implementation was preserved unchanged on `recovery/local-intelligence-dashboard` at `cefb039a7fbe50f49e9a8d538fee80fbb8c50507`. Corrections are on `fix/dashboard-validation`. No default-branch change, merge, reset or rebuild was performed.

[Original workflow run 43600738211](https://github.com/masud1445/osint-recon-toolkit/actions/runs/43600738211) was inspected job-by-job. The nine Linux/macOS/Windows × Python 3.10/3.12/3.13 test jobs and the dependency audit succeeded. Only `interface` failed, job `132464724075`, at **Browser, responsive and print checks**. Its public annotation reports `Process completed with exit code 1.`

Detailed remote step logs require GitHub authentication, and the environment denied the documented GitHub API log endpoint. They were not read. The diagnosis below comes from a local reproduction of the exact browser workflow, not an invented remote traceback. The final commit's workflow status can be checked in [Actions for the corrections branch](https://github.com/masud1445/osint-recon-toolkit/actions?query=branch%3Afix%2Fdashboard-validation).

## Reproduced cause and corrections

The demo form had a valid session cookie and CSRF token but the browser sent `Origin: null`, while `Sec-Fetch-Site` was `same-origin`. The response policy `Referrer-Policy: no-referrer` caused this behavior for a browser form POST. The server correctly rejected the opaque Origin with HTTP 403, leaving the browser at `/assessments` and causing the results-URL wait to time out.

The response now uses `Referrer-Policy: same-origin`. Legitimate form submissions preserve their Origin; cross-origin requests do not receive a referrer. CSRF, opaque/null-Origin rejection, foreign-Origin rejection, hostile Host rejection and loopback-client restrictions remain enabled. The browser check requires a genuine HTTP 303 form response, rather than skipping the form or bypassing CSRF.

Additional corrections:

- Live authorization checkbox now submits the backend's supported value. Live target/source prefill works; refresh requires fresh authorization and does not copy an old approval reference.
- Actual stored authorization references appear in results. Offset timestamps are converted to UTC before display.
- Finished history records have CSRF-protected deletion with an accurate confirmation; downloaded exports remain unaffected. Running records cannot be deleted.
- Overview charts derive source segments from actual counts. Empty coverage is neutral, synthetic-only records show only the synthetic segment, and fabricated rising metric sparklines were removed.
- Metrics explicitly describe the newest 100 records, matching the history query.
- A malformed print-media CSS declaration was repaired. A4 output now has a white background and legible dark text, verified by computed styles and inspection of a rendered PDF page.
- The workflow now polls HTTP readiness for up to 20 seconds and checks that the server process remains alive, instead of assuming a two-second startup.
- The downloaded standalone report is rendered from its actual bytes in a fresh offline document. The review browser restricted `file://`; rendering the exact bytes avoided that restriction without changing content or disabling browser policy.
- README and operator instructions point to the published corrections branch and identify the recovery branch as the preservation baseline.

## Local verification

On Linux/Python 3.12.14:

- Complete suite: **238 passed**, 0 failed, 0 skipped; **96% statement coverage**. All 225 recovered tests remain present and pass, with 13 new template/chart regression cases. Coverage remains at least the recovered baseline.
- `ruff check src tests scripts`: passed.
- `pip check`: no broken requirements.
- `pip-audit`: no known vulnerabilities in audited installed packages. The unpublished local toolkit is skipped by the advisory service; this is not an application-code vulnerability proof.
- Playwright with system Chromium 156: passed same-origin form/CSRF, asynchronous demo completion, JSON disclosure controls, history filtering/deletion, source/license form controls, expected invalid-live-input rejection, HTML/JSON/CSV downloads and dark/light theme persistence.
- Browser viewports: desktop **1440×1050**, tablet **768×1024**, mobile **390×844**, both themes; no document-level horizontal overflow.
- Standalone report: **four A4 pages**, approximately **595×842 PDF points**, white print background, readable dark print text, no PDF JavaScript.
- Browser checks observed no external requests and no unexpected JavaScript or console errors. No authorized live target was queried; the invalid live-input test is rejected before collection.

Screenshots below contain only fictional demo records and no credentials:

| View | Evidence |
| --- | --- |
| Dark desktop | [Screenshot](screenshots/dashboard-dark.png) |
| Light desktop | [Screenshot](screenshots/dashboard-light.png) |
| Mobile results | [Screenshot](screenshots/dashboard-mobile.png) |
| A4 PDF first page | [Screenshot](screenshots/report-a4.png) |

The browser job uploads its full screenshot/export artifacts. To reproduce locally, install `.[test,browser]`, install a Playwright Chromium browser (or set `OSINT_BROWSER` to a system Chromium), start `osint-dashboard`, then run `python scripts/verify_dashboard.py`. This script creates and deletes only its own synthetic assessment; use a separate `--data-dir` for isolated review. `OSINT_TEST_URL` can select another loopback port; `OSINT_VISUAL_DIR` selects the artifact directory.

## Remaining boundaries

Live RDAP, Shodan and VirusTotal acceptance remains **unverified**. Written authorization for an exact target, securely configured keys, provider entitlements/licensing and permitted egress are prerequisites. Shodan domain coverage is page 1; RDAP redirects use a curated registry allowlist. Account/day quotas and source freshness require operator review. Request timeouts apply per socket operation rather than imposing a whole-job deadline.

The dashboard is a local, single-operator application. It is not intended for public hosting or untrusted multi-user access. The SQLite database is not encrypted; enforce OS account controls and suitable Windows ACLs. Deleting a record is not secure erasure and does not recall downloaded exports. One server per data directory is enforced by a process lock. No claims of accessibility certification or real-device Safari testing are made; viewport and print checks used Chromium.
