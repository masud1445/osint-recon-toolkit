# Presenting the offline OSINT workflow

This walkthrough demonstrates the application to an internship supervisor without assessing a real asset. It uses entirely fictional records shaped like RDAP registration metadata, Shodan indexed host metadata and VirusTotal reputation statistics. No provider supplied these records and no actual vendor classification is attributed to a real target.

## Prepare and run

Install the project as documented in the README while package access is available. After installation, the demo works with networking disconnected and no API keys configured:

```sh
osint-recon --demo --output reports/supervisor-demo
```

Alternatively, with the environment active:

```sh
python -m osint_recon.cli --demo --output reports/supervisor-demo
```

Use a fresh directory if you run it again. Successful export exits 0. Open the generated `assessment.html` locally; it has embedded styles, no remote assets, and a restrictive content security policy. Keep `assessment.json` and `assessment.csv` alongside it when handing the demonstration to your supervisor. Do not remove the synthetic labels.

## Suggested presentation

1. **Declare the scope.** Show the synthetic banner and explain that `internship-lab.example` is reserved for examples and `192.0.2.10` belongs to an IP documentation range. You do not need to own a company or domain because no real target is assessed.
2. **Explain registration context.** The fictional RDAP record contains a registration handle, status, event dates and example nameservers. Explain the information that a permitted live RDAP lookup would normally provide.
3. **Explain external-service context.** The fictional Shodan host record associates the example IP with the fictional domain and lists ports 22, 80 and 443. Explain that even genuine indexed ports would need freshness and ownership verification, and would not prove a vulnerability.
4. **Explain reputation context.** The fictional VirusTotal record shows vendor disagreement: two malicious, one suspicious, 65 harmless and 22 undetected results. These are invented training counts. Discuss why real vendor verdicts can be stale or false positives rather than presenting the sample as a confirmed compromise.
5. **Review findings.** Both findings are labelled synthetic training examples with conservative recommendations. Discuss what further authorized evidence an analyst would need; do not contact the example identifiers.
6. **Inspect structured evidence.** Show JSON mode/provenance, per-record `status: synthetic`, source-linked findings, fixed fixture dates and real `generated_at`. In CSV, point out the mode/classification columns and JSON-encoded findings. All three formats retain the same training distinction.
7. **Describe the live workflow separately.** It still requires a real approved target, `--authorized`, credentials/subscriptions where applicable and permitted VirusTotal use. Demo success does not verify any live integration, source subscription or account entitlement.

## What this demonstrates

The complete **presentation workflow** runs from mode selection through local source examples, normalized provenance, analyst review items, recommendations and HTML/JSON/CSV exports. The collection stage is explicitly simulated; the application does not pretend to perform real reconnaissance. Live connectors and the live assessment engine remain independent of demo construction. There is no automatic conversion of missing/error data into sample findings.

Demo cannot be combined with a target, `--authorized`, `--sources` or `--vt-license`. It does not accept custom targets, import real reports or mix real and fictional evidence. A successful run demonstrates report generation and training behavior only.

## Dates and repeatability

Fixture/source dates intentionally stay fixed for reproducible classroom explanations. They may precede the actual report generation date by years; this is disclosed in the report and is not evidence of live data staleness. Each invocation builds fresh records, so editing one returned report in Python does not alter subsequent runs. `generated_at` is the actual report creation-preparation time.

## Verification for this enhancement

On Linux/Python 3.12.14, the complete suite passed: **136 tests, 0 failures, 0 skips in 0.96 seconds; 98% statement coverage** (369 statements, 6 uncovered). The 114 existing tests remain passing and 22 demo regression cases were added. The demo module itself has 100% statement coverage.

The tests block sockets, DNS resolution, requests and live collection; a separate-process run also blocks network entry points. They verify no key reads, ignored configured keys, fixed reserved scope, independent fixtures, all-format labels, per-finding provenance, mixed-mode rejection, no live fallback, retained live authorization/licensing gates, escaped HTML, overwrite refusal and export errors. CLI smoke execution generated HTML/JSON/CSV with synthetic records only. Ruff, wheel build and `pip check` passed. Dependency auditing found no known vulnerabilities in audited installed packages (the unpublished local toolkit is skipped by the advisory database). Gitleaks detected no secrets in working files. No new runtime dependencies were added.

These checks verify offline behavior and mocked contracts. No live provider integration or unauthorized target was tested. Remote CI conclusions should be checked for the exact enhancement commit rather than inferred from these local results.
