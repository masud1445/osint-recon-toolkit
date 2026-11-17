# Scope and authorization record

Complete this form **outside the application** before any Live collection. Retain the signed approval in your approved engagement repository. Enter only its nonsecret reference in the dashboard. A checkbox, reference string or source record does not establish legal permission.

For the built-in Demo scenario, label the exercise synthetic, select Demo and do not invent a client authorization record. The reserved fixture identifiers must not be submitted for Live collection.

## Engagement

| Field | Approved value |
| --- | --- |
| Engagement identifier / approval reference | |
| Purpose and permitted decision | |
| Target owner / accountable organization | |
| Approver name, role and authority to approve | |
| Analyst name and role | |
| Analyst contact and escalation contact | |
| Approval document location / version | |
| Assessment classification and recipients | |
| Teaching, internal review or commercial engagement | |

Do not enter API keys, passwords or other credentials anywhere on this form.

## Exact scope

Record each allowed domain or public IP separately. The application collects one approved target per assessment; it does not accept CIDR ranges, URLs, wildcard targets or automatic scope expansion. A returned hostname, related IP, subdomain or nameserver is evidence to review, not permission to query another asset.

| Exact canonical domain or public IP | Owner / ownership evidence | Permitted sources | Included purpose | Explicit exclusions |
| --- | --- | --- | --- | --- |
| | | | | |
| | | | | |
| | | | | |

| Scope condition | Approved value |
| --- | --- |
| Earliest permitted collection time, with time zone | |
| Latest permitted collection time, with time zone | |
| Corresponding UTC window | |
| Allowed refresh frequency / maximum runs | |
| Permitted storage location and jurisdiction | |
| Prohibited targets, data categories or relationships | |
| Stop conditions, incident contact and escalation procedure | |

## Source and licensing approval

Configured key presence is not a successful authentication or entitlement check. Never attach a raw key to this record.

| Source | Approved? | Account / entitlement reference (nonsecret) | Permitted use and quota approval |
| --- | --- | --- | --- |
| RDAP and applicable approved registry | | No API key normally required | |
| Shodan host or domain intelligence | | | Confirm domain-intelligence subscription if needed |
| VirusTotal v3 existing domain/IP records | | | Confirm actual public noncommercial eligibility or appropriate commercial agreement |

- [ ] Current provider terms and institutional privacy requirements have been reviewed.
- [ ] Any paid/commercial use has the required provider agreement; public VirusTotal access is not being repurposed for a prohibited commercial service.
- [ ] Approved source destinations, proxy trust and source availability have been checked without disabling TLS validation.
- [ ] Account/day limits and other users/processes using those accounts have been considered.
- [ ] The approver understands that collection is limited to existing third-party records; no direct target scanning, exploitation, rescan submission or credential collection is authorized by this workflow.

## Evidence handling and delivery

| Field | Approved value |
| --- | --- |
| Local data-directory owner and OS permissions / Windows ACL | |
| Export destination and access restrictions | |
| Authorized report recipients and transfer method | |
| Retention period and deletion review date | |
| Backup policy and separate export disposal process | |
| Analyst review and acceptance criteria | |
| Person responsible for retention/deletion | |

The local SQLite database is not encrypted or signed. Removing a history row does not securely erase media, delete backups or recall exported reports. Apply organizational evidence controls separately.

## Approval and analyst acknowledgement

**Approver:** I approve the exact targets, sources, purpose, time window and handling conditions recorded above. I am authorized to grant this approval.

Name / role: ____________________  Signature or approved electronic approval: ____________________

Date and time zone: ____________________  Approval-record reference/version: ____________________

**Analyst:** I will verify the scope before each Live run, enter the approval reference, retain coverage gaps, avoid unsupported conclusions and stop when scope, licensing or permission is uncertain.

Name: ____________________  Acknowledgement: ____________________  Date/time: ____________________

## Run and review log

| Assessment ID | Exact target | Actual start/end UTC | Selected sources | Coverage / exceptions | Analyst / reviewer |
| --- | --- | --- | --- | --- | --- |
| | | | | | |
| | | | | | |

Any scope change, expired approval, new source or new target requires a revised approval before collection. See the [mini-audit checklist](MINI_AUDIT_CHECKLIST.md) and [operations workbook](OSINT_OPERATIONS_WORKBOOK.md).
