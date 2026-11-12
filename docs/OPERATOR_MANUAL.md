# Operator manual

## Offline demonstration without a domain or API keys

After installation, run:

```sh
osint-recon --demo --output reports/supervisor-demo
```

Open `assessment.html` in that directory; `assessment.json` and `assessment.csv` contain the same synthetic evidence and findings. Demo exits 0 after successful export or 2 on invalid arguments/export failure. It never reads API credentials, constructs the HTTP transport, calls connectors, resolves DNS or contacts any target/provider. Existing API keys do not enable live activity in demo mode. Installing the application/dependencies may require network access; **running the installed demo does not**.

The fixed fictional scope is `internship-lab.example` plus documentation IP `192.0.2.10`. Both are deliberately rejected by live target validation. Do not supply a target or combine demo with `--authorized`, `--sources` or `--vt-license`; mixed invocations fail before collection. Demo does not accept arbitrary user targets or source selection. Only `--demo` enters this path; missing API credentials and live failures never select it.

The HTML banner, each finding/evidence card, JSON provenance fields and every CSV row identify synthetic training data. Demo uses JSON schema 1.1 with `mode: offline demonstration`, `is_synthetic: true`, `status: synthetic`, `data_classification` and `scenario_id`. `observed_sources` is always 0; `synthetic_sources` is 3. Each finding has its own synthetic flag and label. No real provider verdict, service exposure or compromise is implied.

`generated_at` is the real report-preparation timestamp. Demo `collected_at`, RDAP events and source analysis/update dates are fixed **fictional fixture timestamps**, not a live collection or an age-based risk conclusion. See [the presentation guide](DEMO_GUIDE.md) for the complete workflow.

## Before live collection

Use Python 3.10 or later and follow the README virtual environment instructions. Obtain written target/source authorization before setting `--authorized`. Inspect `osint-recon --help`. Input accepts one public IPv4/IPv6 address or DNS domain (Unicode labels canonicalize through IDNA). URLs, paths, ports, IP ranges, wildcards, local/private IPs and reserved suffixes are rejected. A syntactically valid domain is not proof of registration or scope approval.

Configure environment variables `SHODAN_API_KEY` and `VIRUSTOTAL_API_KEY` through a secure terminal/session manager or secret manager. Do not pass API keys on the CLI. The program does not load `.env` automatically, print keys or store raw provider response bodies. It does not verify credentials until a selected source is requested. Missing keys produce explicit unavailable evidence and exit status 1.

## Run and interpret

```sh
osint-recon APPROVED_DOMAIN --authorized --sources rdap shodan --output reports/run-001
```

VirusTotal additionally requires `--vt-license noncommercial-public` or `--vt-license licensed-commercial`. Confirm permitted usage directly with the provider; an internship context alone does not guarantee every intended usage is allowed. Choosing a flag does not upgrade an API plan. This implementation retrieves existing records and never submits URLs, files or rescans.

Generated files:

| File | Use |
| --- | --- |
| `assessment.html` | Self-contained human review, source status, conservative interpretation and recommendations |
| `assessment.json` | Structured assessment/evidence: live schema 1.0, offline demo schema 1.1 |
| `assessment.csv` | One row per source; observations and source-linked findings serialized as JSON, with explicit mode/classification and record target |

Live reports are labeled `live-source retrieval` to describe the execution path; check the observed source count to determine whether any live records were actually obtained. Zero successful sources means zero evidence-supported findings. Offline demo reports instead use `offline demonstration` and explicit synthetic labels; they must never be presented as operational evidence.

## Troubleshooting

| Result | Action |
| --- | --- |
| Authentication/entitlement unavailable | Check environment binding presence and provider subscription privately; do not paste keys into issues |
| No record | Record the coverage gap; do not infer that the target is safe |
| Rate limit/temporary service failure | Wait and review account quotas; do not launch concurrent retries |
| Longer cooldown | Wait at least the provider's cooldown before a new run |
| Connection failure | Check provider availability, approved egress destinations and trusted proxy CA configuration; never disable TLS verification |
| Redirect requires review | Ask a maintainer to review the registry domain; never bypass the destination allowlist |
| Invalid JSON/schema | Preserve sanitized status and consult provider documentation; do not fabricate replacement data |
| Export failure | Use a new writable output directory with trusted parents; existing files are intentionally protected |

Cloud networking must permit only the sources used: `rdap.org` and applicable approved registry hosts; `api.shodan.io`; `www.virustotal.com`. Documentation access additionally needs `developer.shodan.io`, `docs.virustotal.com`, and relevant RDAP documentation hosts. The current cloud policy blocks the intelligence/documentation hosts; mocked tests require no changes. Never insert real keys into repository network settings or saved shell scripts.

## Acceptance and maintenance

Run `python -m pytest --cov=osint_recon --cov-report=term-missing` after changes. Dependency checks: install `pip-audit`, then `python -m pip_audit`; use `--cache-dir /tmp/osint-audit-cache` on this cloud machine. Review CI results independently after pushing. A locally passing Linux suite is not evidence that remote Windows/macOS runs passed.

For a genuine authorized acceptance test, independently confirm the current official API contracts and licensing; configure source access and keys; select an explicitly approved target; run each connector; compare the selected fields and timestamps to provider records; inspect unavailable/error behavior; record sanitized outcomes privately. Do not place target reports or keys in Git. No live acceptance test was performed during implementation.

Use existing isolated checkouts in cloud tasks; do not create worktrees unless explicitly requested. No service processes need restarting. Reinstall with `python -m pip install -e ".[test]"` when dependencies or the checkout location change.
