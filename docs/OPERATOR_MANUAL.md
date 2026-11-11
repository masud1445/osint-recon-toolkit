# Operator manual

## Before collection

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
| `assessment.json` | Structured assessment/evidence contract version 1.0 |
| `assessment.csv` | One row per selected source, observations serialized as JSON |

Reports are labeled `live-source retrieval` to describe the execution path; check the observed source count to determine whether any live records were actually obtained. Zero successful sources means zero evidence-supported findings. Fixtures in automated tests are synthetic and never distributed as operational reports.

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
