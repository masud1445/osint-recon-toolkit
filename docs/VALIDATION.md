# Initial validation record — commit 4131bc4

For the subsequent security review and current local results, see [Post-push review](POST_PUSH_REVIEW.md). The figures below preserve the initial push evidence.

Local platform: Linux, Python 3.12.14. All provider responses in automated tests are synthetic. No authorized live API collection was performed. The application is operationally structured, but live API acceptance remains outstanding.

## Final checks

| Check | Exact result |
| --- | --- |
| `python -m pytest --cov=osint_recon --cov-report=term-missing` | **94 passed in 0.64 seconds**, 0 failed, 0 skipped; **99% statement coverage** (296 statements, 3 not covered) |
| `ruff check src tests` | All checks passed |
| `pip check` | No broken requirements found |
| `python -m pip_audit --cache-dir /tmp/osint-audit-cache --progress-spinner off` | No known vulnerabilities found in audited installed packages; local unpublished `osint-recon-toolkit` package skipped by the advisory service |
| Editable install | Successful; console entry point installed |
| Installed CLI offline smoke | Exit 1 as expected; missing Shodan key; three exports; unavailable evidence; zero findings; no API requests |
| Wheel build | Successful, platform-independent Python wheel |

The initial audit found advisories in the environment's pip 25.0.1. Upgrading the isolated environment to pip 26.3 resolved the reported audit findings. CI upgrades pip before dependency auditing. An initial audit attempt also encountered the cloud home directory's read-only cache; an explicit writable cache fixed that setup issue.

During security review, new tests exposed a stale synthetic RDAP fixture that described a domain during an IP query, retained observations on a target-mismatch error, and a nesting check that depended on Python's runtime recursion limit. The fixture was corrected, error evidence is cleared, and transport now enforces an explicit 32-level JSON nesting bound. The final complete suite above passed after those fixes.

## Test coverage scope

Unit and mocked integration tests exercise:

- Domain, IDNA, public IPv4/IPv6 validation and malicious/private/reserved input rejection.
- Connector endpoint/authentication contracts and selected DNS/registration/vendor evidence.
- Missing credentials, HTTP authentication/entitlement failure, no records, provider/server errors, malformed JSON/schema, unexpected ports/vendor counts, timeouts and connection/TLS failures.
- Bounded retries, numeric and HTTP-date Retry-After handling, source pacing, oversized and deeply nested JSON.
- Approved RDAP redirects, redirect loops, private/unapproved destinations and credential forwarding prevention.
- Target mismatch rejection; no invented findings when sources fail.
- HTML escaping/CSP, recursive key redaction, CSV formula protection, overwrite/symlink refusal and partial export cleanup.
- CLI authorization/licensing gates and mocked collection-through-export workflows.

## Remaining verification

- **Live API behavior:** not verified. No approved live target/API keys were provided. Environment policy denied provider/documentation hosts. Shodan paths/query authentication and VirusTotal API prefix/header conventions were cross-checked against retrieved official SDK source on GitHub; this does not replace live acceptance or a current terms review.
- **Platform matrix:** GitHub Actions is configured for Python 3.10/3.12/3.13 on Linux/macOS/Windows. Local results do not establish remote CI outcomes or cross-platform runtime success.
- **Coverage boundaries:** curated RDAP registries only; Shodan domain page 1 only; account/day quotas and concurrent-process pacing require operator management. No legacy WHOIS fallback.
- **Risk interpretation:** source observations remain unverified intelligence. There is no claim of confirmed exposure, compromise, exhaustive coverage or an overall risk score.
