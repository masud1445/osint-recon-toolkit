# Security and responsible use

Use this project only for approved, read-only third-party intelligence collection. Authorization, API licensing, privacy compliance, report retention and account quota management remain operator duties. No scanning, exploitation, credential harvesting or automatic scope expansion is supported.

Never commit API keys, `.env` files, private engagement data or generated reports. Configure keys through environment variables or approved secret management. Do not enable requests/urllib3 HTTP debug logging while using Shodan: its documented authentication uses a query parameter. Sanitize bug reports and review artifacts before sharing. Rotate exposed keys immediately.

Treat third-party evidence as untrusted and potentially stale. HTML is escaped and CSV formula triggers are neutralized, but exported evidence still requires analyst review. Store reports in a trusted directory with appropriate OS ACLs. Do not deploy the CLI as a shared commercial service without a separate security review and suitable provider licenses.

Report suspected defects privately to the repository owner through an available private channel. Do not include live secrets or publish exploitable details before coordinated remediation. No dedicated security contact or response SLA has been configured.
