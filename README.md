# OSINT Recon Toolkit — Project 6.1

A portable Python CLI for authorized, passive domain and public-IP intelligence. Built for cybersecurity training and evidence-led external attack-surface review. Independent of CyberAssess and Phishing Awareness Tracker.

## What it does

- Retrieves existing **RDAP registration records** (the structured successor to WHOIS), **Shodan host/domain metadata**, and **VirusTotal v3 domain/IP records**.
- Validates targets without DNS resolution or target contact. Does not scan ports, request target webpages, submit samples, launch analyses, exploit systems, or collect credentials.
- Separates source observations, unavailable data, retrieval errors, and analyst review items.
- Produces a self-contained HTML assessment plus structured JSON and CSV evidence exports. Missing access never creates a fabricated finding or a “safe” verdict.
- Includes mocked unit/integration tests and a GitHub Actions OS/Python matrix with dependency vulnerability checks.

## Install

Python 3.10+ on macOS, Windows or Linux:

```sh
python -m venv .venv
# macOS/Linux
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m pytest --cov=osint_recon --cov-report=term-missing
```

The cloud checkout uses `/workspace/osint-venv`; activate it with `. /workspace/osint-venv/bin/activate`. No database, web server or background services are required.

## Offline internship demonstration

No domain ownership, API keys, target authorization or network access is needed for this **fictional local demonstration** once the application and dependencies are installed:

```sh
osint-recon --demo --output reports/supervisor-demo
```

Open `reports/supervisor-demo/assessment.html` locally. JSON and CSV are generated alongside it. Every record and training finding is labelled **SYNTHETIC TRAINING DATA — NOT LIVE INTELLIGENCE**. The fixed scenario uses `internship-lab.example` and documentation-only IP `192.0.2.10`; neither is submitted to an API. No source is contacted and no API credentials are read. Demo rejects live targets, `--authorized`, `--sources` and `--vt-license`, and live failures never fall back to fixtures. Use a new output directory for each run.

See the [supervisor presentation walkthrough](docs/DEMO_GUIDE.md). The domain/IP validator remains strict for live collection; reserved demo identifiers cannot be used as live targets.

## Operate with authorized live targets

First obtain written approval for the exact target and approved sources. Replace `APPROVED_DOMAIN` below with that target; placeholders are not intelligence or authorization.

```sh
osint-recon APPROVED_DOMAIN --authorized --sources rdap --output reports/assessment-001
osint-recon APPROVED_DOMAIN --authorized --sources rdap shodan virustotal --vt-license noncommercial-public --output reports/assessment-002
```

Set `SHODAN_API_KEY` and `VIRUSTOTAL_API_KEY` through your process environment or approved secret manager. Do not put real keys in shell history, command arguments, source files or tickets. `.env.example` documents variable names; `.env` is deliberately **not loaded**. Only enabled connectors use keys. RDAP needs no key.

VirusTotal public API usage is limited by its terms, including noncommercial restrictions. Choose `--vt-license noncommercial-public` only when eligible; `licensed-commercial` requires an appropriate paid agreement and key. The flag is an operator acknowledgement, not a license grant or entitlement check. Shodan domain intelligence can require additional subscription access.

Exit status: `0` = every selected source returned a record; `1` = one or more sources unavailable/error (reports still written); `2` = invalid invocation/export failure. Success does not establish that an asset is secure.

Outputs use fixed names `assessment.html`, `assessment.json`, `assessment.csv`. Use a new output directory per assessment; existing files are never overwritten. Reports may contain sensitive asset metadata. Protect the directory using OS permissions, especially on Windows where POSIX mode bits do not establish an ACL.

## Evidence and limits

“Observed” confirms retrieval of a source record, not current reachability, ownership, a vulnerability, or compromise. The HTML report includes an executive summary, target, retrieval timestamps, source endpoint, selected evidence, conservative risk interpretation and recommendations. Provider timestamps are preserved separately where available; no overall risk score is fabricated.

Shodan domain results include selected DNS records from the first page; `more` preserves the pagination indicator. This version intentionally does not enumerate every record. Raw banners, contact entities, per-vendor detail and arbitrary source links are omitted for data minimization. RDAP redirects are restricted to the explicitly reviewed registry hosts listed in the transport module; other registries yield unavailable status. Legacy port-43 WHOIS is not implemented. See [architecture](docs/ARCHITECTURE.md) and [operator manual](docs/OPERATOR_MANUAL.md).

Explicit offline demo fixtures are shipped in a separate module and are never represented as live evidence. Additional automated test fixtures are synthetic. No live source integrations have been verified for this release; provider documentation access was denied by the development environment's egress policy. Review current API documentation and run an authorized acceptance check before operational reliance.

## Development and assessment

- [Initial audit and implementation plan](docs/AUDIT_AND_PLAN.md)
- [Architecture and API contracts](docs/ARCHITECTURE.md)
- [Authorized OSINT workflow](docs/WORKFLOW.md)
- [Operator manual and troubleshooting](docs/OPERATOR_MANUAL.md)
- [Security policy](SECURITY.md)
- [Initial validation evidence](docs/VALIDATION.md)
- [Post-push verification, security fixes and main-branch proposal](docs/POST_PUSH_REVIEW.md)

CI runs Python 3.10, 3.12 and 3.13 on Linux, macOS and Windows. Local validation applies only to the platform actually tested. Dependency constraints permit compatible security updates; there is no reproducibility lock. For an assessed deployment, record `python -m pip freeze` in a private environment inventory after auditing installed versions. Do not include credentials or private package URLs in that inventory.
