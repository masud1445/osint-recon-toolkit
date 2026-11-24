# Authorized external reconnaissance mini-audit checklist

This is an operator worksheet for a small, explicitly authorized passive review. It is not a penetration test, a complete external attack-surface inventory, a certification, or evidence that the application has passed live acceptance testing. Commercial use additionally requires suitable provider licensing and organizational approval. The local dashboard has no public multi-user authentication and must not be hosted as a shared service.

Engagement / approval reference: ____________________

Analyst: ____________________  Reviewer: ____________________

Approved window, with time zone and UTC equivalent: ____________________

Mode: [ ] Live, written approval attached  [ ] Synthetic training exercise only

## A. Preflight — do not collect until complete

- [ ] Complete and approve the [scope and authorization form](SCOPE_AUTHORIZATION_FORM.md).
- [ ] Verify the exact domain or public IP for this assessment; do not infer permission from a related provider record.
- [ ] Confirm selected sources, purpose, collection window and authorized recipients.
- [ ] Review current API terms, relevant privacy requirements and actual account entitlements.
- [ ] For VirusTotal, confirm permitted noncommercial public use or an appropriate commercial agreement/key; do not treat a UI selection as a license grant.
- [ ] Confirm Shodan subscription coverage, especially for domain intelligence, and remaining account quotas.
- [ ] Install and test the selected code revision in a Python virtual environment; record revision and dependency inventory privately.
- [ ] Confirm local-only startup, trusted OS account, private data directory and suitable Windows ACLs where applicable.
- [ ] Supply API keys through the server process environment/approved secret manager; do not put values in this worksheet, browser, source, tickets or reports.
- [ ] Check configured source presence and approved egress. A configured key is not proof of successful authentication.
- [ ] Ensure no other process is evading shared account limits; the app coordinates pacing only within its own worker/process.
- [ ] If this is the first operational use, complete a small genuinely authorized provider acceptance test and record sanitized results. Mock/demo results do not satisfy this item.

Stop reason / unresolved prerequisite: ____________________

## B. Collection

- [ ] Select **Live** only for the approved target, or **Demo** only for the fixed fictional scenario.
- [ ] Review target, source selection, approval reference and license declaration before submission.
- [ ] Start a new assessment for fresh information; do not silently relabel a historical record as current.
- [ ] Record assessment ID, selected sources and actual attempt/retrieval times in UTC.
- [ ] Observe progress and provider pacing; do not duplicate jobs to evade limits.
- [ ] Retain each source outcome: `observed`, `unavailable`, `error` or explicitly `synthetic`.
- [ ] Treat authentication, entitlement, rate-limit, no-record and network failures as coverage gaps. Do not substitute demo records.
- [ ] Stop or seek renewed approval if the scope changes, the approval window expires or permitted use becomes uncertain. Closing a browser tab does not cancel an active job.

| Assessment ID | Target | Source | State | Retrieval / attempt UTC | Provider record date | Coverage note |
| --- | --- | --- | --- | --- | --- | --- |
| | | RDAP | | | | |
| | | Shodan | | | | |
| | | VirusTotal | | | | |

## C. Evidence review

- [ ] Match the canonical target and mode to the approval record or training exercise.
- [ ] Separate retrieval time, provider event/analysis date and report-generation time.
- [ ] Review RDAP names/status/events or IP range as registration context, not verified asset ownership.
- [ ] Review indexed ports and DNS/host metadata as provider observations, not a current reachability or vulnerability test.
- [ ] Review vendor classifications for disagreement, age and false positives; do not equate a detection with compromise.
- [ ] Note RDAP registry restrictions, Shodan page-1 coverage and data-minimization omissions.
- [ ] Record missing sources and unsupported fields explicitly; absence of a finding is not proof of safety.
- [ ] Keep any related assets outside further collection until they have their own approval.
- [ ] Link each analyst conclusion to source evidence; distinguish observations, interpretations and items requiring independent authorized verification.
- [ ] Confirm that no arbitrary rating, fabricated trend or unsupported overall risk score was introduced.

| Review item | Supporting source / field and timestamp | Interpretation and confidence limits | Recommendation / owner |
| --- | --- | --- | --- |
| | | | |
| | | | |

## D. Reporting and delivery

- [ ] Review the executive summary, target, mode, timestamps, evidence, findings, recommendations and coverage limitations.
- [ ] Keep Demo classifications intact in every artifact; do not describe synthetic records as verified live findings.
- [ ] Export HTML, JSON and CSV and verify they describe the same assessment.
- [ ] Open HTML in the intended browser. Review A4 print preview/PDF if printing is required.
- [ ] Inspect normalized JSON disclosures when relevant. These are selected source fields, not complete raw API payloads.
- [ ] Check recipient, report filenames, permission settings and any sensitive asset/engagement metadata before delivery.
- [ ] Confirm secrets are absent. Do not enable HTTP debug logging when Shodan query-key authentication is in use.
- [ ] Optionally create an external file-hash inventory under organizational evidence policy; the app does not sign a chain-of-custody record.
- [ ] Send only through the approved channel to approved recipients. Record receipt and any unresolved limitations.

Delivered artifacts / version: ____________________

Recipients and delivery record: ____________________

## E. Retention, follow-up and sign-off

- [ ] Store approval, analyst notes, selected revision, dependency inventory and exports under the approved retention policy.
- [ ] Assign each recommendation and any later validation to a named owner; obtain separate permission for active checks.
- [ ] Record the next authorized review date, if any. New collection is a separate assessment.
- [ ] Review local SQLite history, downloaded exports and backups separately at the retention deadline.
- [ ] Remove only eligible finished/error records through the protected action; deletion is not certified secure media erasure.
- [ ] Rotate any accidentally exposed key through the provider and approved secret-management process.

**Analyst sign-off:** The report reflects the recorded source states and limitations. No unapproved collection or invented live evidence was used.

Name / signature / date: ____________________

**Reviewer sign-off:** Scope, licensing, evidence-to-conclusion traceability and delivery restrictions have been reviewed. This sign-off does not certify full asset security or application commercial readiness.

Name / signature / date: ____________________

Outstanding coverage, acceptance or approval items: ____________________
