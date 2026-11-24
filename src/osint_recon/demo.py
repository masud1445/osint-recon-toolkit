"""Offline fixtures only. This module never imports connectors or transport."""

from .models import now

DEMO_MODE = "offline demonstration"
DEMO_LABEL = "SYNTHETIC TRAINING DATA — NOT LIVE INTELLIGENCE"
SCENARIO_ID = "internship-workflow-v1"
FIXTURE_TIME = "2025-01-15T10:00:00+00:00"


def build_demo_report():
    """Return fresh fictional evidence for a reserved domain/documentation IP.

    Fixture dates simulate provider record timestamps. generated_at is the real
    export preparation time; no collection time or source verification is claimed.
    """
    domain, address = "internship-lab.example", "192.0.2.10"
    records = [
        (
            "RDAP",
            domain,
            "domain-registration",
            {
                "objectClassName": "domain",
                "handle": "SYNTHETIC-DOMAIN-001",
                "ldhName": domain,
                "status": ["active"],
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "2023-06-01T00:00:00Z",
                    },
                    {"eventAction": "expiration", "eventDate": "2026-06-01T00:00:00Z"},
                ],
                "nameservers": [
                    {"ldhName": "ns1.internship-lab.example"},
                    {"ldhName": "ns2.internship-lab.example"},
                ],
            },
        ),
        (
            "Shodan",
            address,
            "host-metadata",
            {
                "ip_str": address,
                "hostnames": [domain],
                "org": "Fictional Internship Training Lab",
                "ports": [22, 80, 443],
                "tags": ["synthetic-training-fixture"],
                "last_update": "2025-01-14T18:30:00Z",
            },
        ),
        (
            "VirusTotal",
            domain,
            "domain-reputation",
            {
                "id": domain,
                "type": "domain",
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 65,
                    "undetected": 22,
                    "timeout": 0,
                },
                "last_analysis_date": 1736877600,
                "reputation": -3,
            },
        ),
    ]
    evidence = [
        {
            "source": source,
            "status": "synthetic",
            "target": target,
            "endpoint": f"synthetic://{SCENARIO_ID}/{fixture}",
            "collected_at": FIXTURE_TIME,
            "timestamp_kind": "synthetic fixture timestamp; no collection occurred",
            "observations": observations,
            "message": f"{DEMO_LABEL}. Locally generated fictional {source} example; source was not contacted.",
            "verification": "Training fixture only. No source observation, ownership, service exposure or reputation was verified.",
            "is_synthetic": True,
            "data_classification": DEMO_LABEL,
        }
        for source, target, fixture, observations in records
    ]
    findings = [
        {
            "title": "Synthetic training example: indexed management service",
            "source": "Shodan",
            "target": address,
            "severity": "training exercise — informational",
            "interpretation": f"{DEMO_LABEL}. The fictional record lists port 22 alongside web ports. This illustrates a review item, not a verified exposure or vulnerability.",
            "recommendation": "Training task: explain how an authorized analyst would check ownership, business need and record freshness before recommending a change. Do not contact this fixture address.",
        },
        {
            "title": "Synthetic training example: vendor detection disagreement",
            "source": "VirusTotal",
            "target": domain,
            "severity": "training exercise — review required",
            "interpretation": f"{DEMO_LABEL}. Two fictional malicious classifications illustrate vendor disagreement. No real vendor verdict or compromise is asserted.",
            "recommendation": "Training task: discuss false positives and source timestamps, then document what independently authorized evidence would be needed to reach a conclusion.",
        },
    ]
    for finding in findings:
        finding.update(is_synthetic=True, data_classification=DEMO_LABEL)
    return {
        "schema_version": "1.1",
        "mode": DEMO_MODE,
        "is_synthetic": True,
        "data_classification": DEMO_LABEL,
        "scenario_id": SCENARIO_ID,
        "generated_at": now(),
        "target": {
            "value": domain,
            "kind": "domain",
            "associated_ip": address,
            "is_synthetic": True,
        },
        "scope": "Fixed fictional domain and documentation IP; no real target, authorization claim or API access.",
        "summary": {
            "observed_sources": 0,
            "synthetic_sources": len(evidence),
            "total_sources": len(evidence),
            "interpretation": f"{DEMO_LABEL}. Three fictional records and two training review items illustrate the workflow. No assessment was conducted and no overall risk score is assigned.",
        },
        "findings": findings,
        "evidence": evidence,
    }
