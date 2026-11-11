"""Evidence-driven interpretation; no evidence means no inferred findings."""

from .models import now


def assess(target, evidence):
    findings = []
    for item in evidence:
        if item.status != "observed":
            continue
        if item.source == "Shodan" and item.observations.get("ports"):
            findings.append(
                {
                    "title": "Source-reported exposed services",
                    "severity": "informational",
                    "source": item.source,
                    "interpretation": "Indexed ports indicate historical source observations; they do not prove current reachability or vulnerability.",
                    "recommendation": "Verify asset ownership, business need and observation freshness against approved asset records.",
                }
            )
        if item.source == "VirusTotal":
            stats = item.observations.get("last_analysis_stats", {})
            if (
                isinstance(stats, dict)
                and isinstance(stats.get("malicious"), int)
                and stats["malicious"] > 0
            ):
                findings.append(
                    {
                        "title": "Vendor detections require review",
                        "severity": "review required",
                        "source": item.source,
                        "interpretation": "One or more vendors reported a malicious classification. This is not a confirmed compromise or vulnerability.",
                        "recommendation": "Review source timestamps, false positives and organizational context before taking action.",
                    }
                )
    return {
        "schema_version": "1.0",
        "mode": "live-source retrieval",
        "generated_at": now(),
        "target": {"value": target.value, "kind": target.kind},
        "summary": {
            "observed_sources": sum(e.status == "observed" for e in evidence),
            "total_sources": len(evidence),
            "interpretation": "No overall risk score assigned. Missing intelligence is not evidence of safety.",
        },
        "findings": findings,
        "evidence": [e.to_dict() for e in evidence],
    }
