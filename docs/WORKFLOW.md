# Authorized OSINT assessment workflow

1. Record written authorization, target owner, exact domain/IP, permitted sources, purpose, dates, retention and responsible analyst outside the tool. Confirm applicable API contracts and institutional policies.
2. Prepare a dedicated Python environment and API keys through approved secret management. Check subscriptions and VirusTotal noncommercial or commercial entitlement.
3. Run one target with `--authorized` and only approved sources. The default source is RDAP. Do not expand scope from discovered hostnames or source records without separate approval.
4. Review source status and collection timestamps before interpreting findings. Separate provider history from current asset state. An unavailable source is a coverage gap; it is never a negative result.
5. Review registration metadata, source-reported ports and vendor classifications. Correlate with approved asset inventories; document false-positive and staleness considerations. Follow a separate authorized process for any active validation.
6. Open the HTML report locally. Retain JSON for structured analysis and CSV for evidence review. Do not circulate reports publicly or treat CSV text as trusted formulas.
7. Document analyst conclusions, evidence limitations, source attribution and recommended actions. The generated report provides conservative guidance but does not replace analyst sign-off.
8. Store artifacts under access control and retain/delete according to the approved engagement policy. Rotate keys immediately if exposure is suspected.

The tool never initiates scans, submits VirusTotal analyses, or attempts authentication to the target. Test fixtures are synthetic and must never be cited as live target evidence.
