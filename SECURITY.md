# Security and responsible use

Use this project only for approved, read-only third-party intelligence collection. Authorization, API licensing, privacy compliance, report retention and account quota management remain operator duties. No scanning, exploitation, credential harvesting or automatic scope expansion is supported.

Never commit API keys, `.env` files, private engagement data or generated reports. Configure keys through environment variables or approved secret management. Do not enable requests/urllib3 HTTP debug logging while using Shodan: its documented authentication uses a query parameter. Sanitize bug reports and review artifacts before sharing. Rotate exposed keys immediately.

Treat third-party evidence as untrusted and potentially stale. HTML is escaped and CSV formula triggers are neutralized, but exported evidence still requires analyst review. Store reports in a trusted directory with appropriate OS ACLs. Do not deploy the CLI as a shared commercial service without a separate security review and suitable provider licenses.

Report suspected defects privately to the repository owner through an available private channel. Do not include live secrets or publish exploitable details before coordinated remediation. No dedicated security contact or response SLA has been configured.

Explicit `--demo` mode is an offline, fictional training exception to live target authorization: it accepts no target or live options and never reads API keys or initiates network access. Keep its synthetic labels intact when presenting or distributing generated artifacts. Do not interpret demo fixtures or findings as provider observations.


## Local dashboard boundary

The Flask dashboard is a single-user tool for a trusted personal OS account. Its Waitress entry point binds only to `127.0.0.1`; do not publish it, forward its port, place it behind a public reverse proxy, disable Host/Origin checks or expose it to a LAN. Loopback filtering, CSRF, escaped templates, a restrictive CSP and signed HttpOnly/SameSite Strict session cookies reduce browser-origin risks; they do not defend against a malicious local user, compromised browser extension or another process with the same OS privileges. Cookies are intentionally not Secure on the local HTTP endpoint. The session signing key changes at restart, so old forms must be reloaded. No public or multi-user authentication has been implemented.

The browser receives credential presence only. API keys remain in the server environment; no UI input or reveal feature is supplied and `.env` is not loaded. Do not put keys in authorization references. Reports and authorization records are retained locally in SQLite and may contain sensitive engagement metadata. Newly created directories/database files request POSIX modes 0700/0600, but existing directory permissions and Windows ACLs are operator responsibilities. Keep the data directory in a trusted, private location and avoid concurrent processes using it. Failed runs retain authorization metadata until deleted; active jobs cannot be deleted. Database deletion is not a guarantee of secure media erasure, and downloaded reports/backups remain separate artifacts.

Collection continues only through fixed approved source endpoints and preserves passive GET-only restrictions, input validation, provider licensing gates and the existing redaction/error policy. JSON disclosures show selected normalized source fields, not unfiltered raw provider payloads. No live provider acceptance test has been verified for this dashboard release; cloud provider egress and credentials remain prerequisites for any authorized operational test.
