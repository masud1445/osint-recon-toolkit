# Local intelligence dashboard

The dashboard adds an interactive local interface around the existing passive collection engine. It runs on your own computer and separates offline fictional demonstrations from fresh authorized provider queries. This version is intended for one trusted operator, not a public website or multi-user security platform.

## Exact Mac Terminal startup

The professional dashboard, workbook and final teaching handouts are on [`feature/academic-release-readiness`](https://github.com/masud1445/osint-recon-toolkit/tree/feature/academic-release-readiness). The separate [`recovery/local-intelligence-dashboard`](https://github.com/masud1445/osint-recon-toolkit/tree/recovery/local-intelligence-dashboard) branch retains the unchanged recovery checkpoint (`cefb039`). The default branch can still contain the older CLI release; do not rely on a default-branch checkout for this interface.

For a new clone, use a new Terminal window:

```sh
git clone https://github.com/masud1445/osint-recon-toolkit.git
cd osint-recon-toolkit
git switch feature/academic-release-readiness
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
osint-dashboard
```

Keep the server Terminal open. In another Terminal tab:

```sh
open http://127.0.0.1:8765
```

For an existing clone, use that checkout and inspect it before switching:

```sh
cd /path/to/osint-recon-toolkit
git status --short
```

If this reports local changes, stop and preserve them before continuing. From a clean checkout:

```sh
git fetch origin
git switch feature/academic-release-readiness
git pull --ff-only origin feature/academic-release-readiness
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
osint-dashboard
```

If `.venv` does not exist, create it with `python3 -m venv .venv` before activation. A fast-forward-only pull refuses divergent history; it does not merge or reset it. Do not clone over an existing directory. The Flask application runs through Waitress on `127.0.0.1`; Flask debug/reloader is not used. Control-C stops the server.

An alternative local port or data directory can be selected:

```sh
osint-dashboard --port 8766 --data-dir "$HOME/.osint-recon-internship"
```

Ports are restricted to 1024–65535. The host cannot be changed through this command. Use only one dashboard process per data directory, and do not tunnel, publicly proxy or otherwise expose the local endpoint. Installing dependencies may need Internet access; the installed Demo workflow uses no provider connection.

For Windows and Linux setup, use the explicit [cross-platform installation commands](../README.md#install-on-macos-linux-or-windows). Windows can invoke the environment's executables directly without changing PowerShell execution policy. No external database service is needed.

## Offline training: Demo

1. Open **New Reconnaissance Assessment** and choose **Demo**. No target, source selection, keys, authorization declaration or provider license is required.
2. Start the assessment. The queue/progress view leads to results without contacting a provider.
3. Review the fixed fictional registration record, service context and reputation statistics. The scope uses `internship-lab.example` and documentation-only IP `192.0.2.10`.
4. Inspect findings, recommendations, source availability and normalized JSON disclosures. A concise Demo indicator identifies the presentation; structured evidence and exports keep per-record/per-finding synthetic flags.
5. Export HTML, JSON or CSV. The HTML includes a professional print layout for A4; expand JSON disclosures before printing if you want their complete content included.

The concise [student lab](teaching/student-laboratory.pdf) and [reviewed fictional sample](examples/offline-demo/README.md) support teaching without a real domain or account. Demo success verifies the offline workflow only. It does not demonstrate provider account access, a real target, a current exposure, or live connector acceptance. Existing CLI usage remains available:

```sh
osint-recon --demo --output reports/supervisor-demo
```

## Authorized Live collection

Each Live submission starts a fresh collection. It does not silently overwrite or refresh an earlier assessment. Obtain written approval for the exact domain/IP and sources first, then select **Live**, enter the approved target, choose sources, enter a scope-approval reference and acknowledge authorization. References are retained metadata, not legal proof. Never put a secret in this field.

RDAP requires no API key but network policy must permit its bootstrap and applicable curated registry. Shodan and VirusTotal use server-side `SHODAN_API_KEY` and `VIRUSTOTAL_API_KEY`. Sources shows configured/not-configured presence only; keys cannot be entered or revealed in the browser. `.env` files are not loaded automatically. A server already running does not acquire later shell changes: stop it, configure the process environment and restart.

In the default macOS **zsh** shell, optional silent prompts keep key values out of shell history:

```sh
read -s "SHODAN_API_KEY?Shodan API key: "
printf '\n'
export SHODAN_API_KEY
read -s "VIRUSTOTAL_API_KEY?VirusTotal API key: "
printf '\n'
export VIRUSTOTAL_API_KEY
osint-dashboard
```

Skip a key if that source is not needed. Use an approved secret manager where available; do not paste values into source files, screenshots, tickets, environment setup scripts or command arguments. These zsh prompt commands are not Bash syntax. Environment values remain accessible to the trusted process owner.

Selecting VirusTotal also requires a permitted license declaration. Public API terms restrict use, including commercial scenarios; choose the public option only when eligible. A commercial declaration requires an appropriate agreement/key and does not grant one. Shodan domain intelligence can require an additional subscription. Missing keys, insufficient entitlements, no source records, blocked destinations and exhausted retries appear as unavailable/error states. They do not generate fictional findings or a “safe” verdict.

The collector retrieves existing provider records with existing timeouts, bounds, retry and pacing rules. It does not scan a target, submit a URL/file, request a rescan or exploit anything. A live report remains LIVE even when every source fails. Evidence JSON displays normalized selected provider fields, not every raw response field. Curated RDAP registry coverage and Shodan domain page 1 remain explicit limits; banners, personal contact entities and arbitrary source links are minimized.

No genuine live API acceptance result is recorded for this release. Offline/demo checks and mocked provider responses do not verify real source access. Operational acceptance requires approved targets, current terms/API review, secure credentials, permitted destinations and comparison of a genuine read-only result against the provider. No authorization or credential is implied by being an internship project.

## Interface and report workflow

The default theme uses light blue-grey backgrounds, white content panels, coordinated blue/teal accents and enlarged typography. Use the theme control for the optional dark alternative; appearance never changes an assessment mode or source state. The [operations workbook](OSINT_OPERATIONS_WORKBOOK.md) provides the end-to-end method, [scope form](SCOPE_AUTHORIZATION_FORM.md), synthetic exercises and [mini-audit checklist](MINI_AUDIT_CHECKLIST.md).

- **Assessment Dashboard:** history-based metrics and source-backed summaries. Availability percentages are retrieval coverage, not risk scores.
- **New Reconnaissance Assessment:** mode/target/source validation, authorization and provider-license acknowledgements.
- **Evidence Review / Collection Status:** progress for queued/running work, source statuses, source/collection timestamps, review items, recommendations and expandable normalized JSON.
- **Findings & Recommendations:** review items remain tied to their source and assessment. Synthetic items never become verified live observations.
- **Intelligence Sources:** supported API contracts and server-side credential presence; no credential value controls.
- **Assessment History:** recent records, filtering, exports and deliberate deletion of finished/error assessments. A fresh assessment is how to collect new information.
- **Theme and navigation:** responsive sidebar/top navigation and local light/dark preference; all assets are packaged locally.

The standalone HTML report uses executive cards, source summaries, field tables, source-availability/vendor charts only when data supports them, UTC timestamps and findings/recommendations. Native disclosures work without JavaScript. Print styling switches to white A4 pages. Source, target and provider text remain escaped; CSV cells neutralize formula triggers and JSON/CSV preserve mode/provenance.

## Persistence, queue and restart behavior

By default, history is `~/.osint-recon/assessments.sqlite3`. Newly created data directories/database files request POSIX modes 0700/0600. Review permissions on existing paths and configure Windows ACLs separately. The database stores normalized redacted reports plus authorization metadata; it is not encrypted, signed or a certified chain-of-custody archive.

The history list is limited to the newest 100 records; this is a display limit, not automatic pruning. Finished and error records may be removed using the protected delete action. Running/queued records cannot be deleted. Failed jobs retain authorization metadata until deleted. SQLite row deletion does not guarantee physical secure erasure, and exports/backups are not deleted with history.

One collection worker processes assessments sequentially with at most five queued/running records. Per-provider pacing is maintained by its shared Transport within that process. Account/day quotas and other CLI/dashboard processes are not coordinated. Closing the browser does not cancel a job. After a process shutdown, previously queued/running rows are marked error on startup rather than automatically resumed; create a new assessment when appropriate. Do not run two servers against one data directory.

The session signing key changes at restart. Reload browser forms after restarting to get a fresh CSRF token. Responses use `Referrer-Policy: same-origin`, which keeps referrer information within the local origin and preserves a usable same-origin `Origin` header on browser form submissions. The earlier `no-referrer` policy caused Chromium to submit `Origin: null`; strict origin validation correctly rejected those submissions. The policy correction retains rejection of null/foreign origins and the signed-session CSRF requirement. CSRF tokens, Host/Origin checks, loopback address checks and Fetch Metadata restrictions are security boundaries; do not disable them to work around access errors. The local HTTP cookie is HttpOnly and SameSite Strict, not Secure. No multi-user authentication is provided; use a trusted OS account and browser profile.

## Verification and troubleshooting

See [documentation release readiness](RELEASE_READINESS.md) for the final release checks and [professional redesign validation](PROFESSIONAL_VALIDATION.md) for the preserved earlier UI/browser evidence. Earlier CLI validation records describe their exact historical commits. New remote CI outcomes must be verified for the final dashboard commit; local or mocked success does not establish live provider access.

| Symptom | Action |
| --- | --- |
| Command not found | Activate the correct virtual environment and run `python -m pip install -e '.[test]'` in this checkout |
| Address already in use | Stop the other local server or use a different permitted port; do not expose a public host |
| CSRF/origin rejection after restart | Reload from the exact loopback URL and retry with a fresh form |
| Queue full | Wait for current work; do not launch duplicate workers to evade quotas |
| Source unavailable | Check approved network access, credential presence and provider entitlement privately |
| Interrupted assessment | Review its retained authorization record, then start a new run if still approved |
| Export not ready | Wait for completion; error/unfinished records do not fabricate export evidence |
| Print disclosure missing | Expand the normalized JSON panel before opening the browser print dialog |
