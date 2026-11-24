"""Explicit authorization and licensing gates, no intrusive operations."""

import argparse
import os

from .assessment import assess
from .connectors import RDAP, Shodan, VirusTotal
from .demo import build_demo_report
from .reporting import export_report
from .targets import validate_target
from .transport import Transport


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Passive intelligence for a single authorized domain or public IP."
    )
    parser.add_argument(
        "target", nargs="?", help="Approved live target; omit for --demo"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate an entirely synthetic offline training assessment; no target or keys needed",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm approval to collect intelligence for this target",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=["rdap", "shodan", "virustotal"],
        default=None,
    )
    parser.add_argument(
        "--vt-license",
        choices=["noncommercial-public", "licensed-commercial"],
        help="Confirm a permitted VirusTotal use and API entitlement",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Directory for new assessment.html/json/csv files",
    )
    args = parser.parse_args(argv)
    if args.demo:
        if (
            args.target is not None
            or args.authorized
            or args.sources is not None
            or args.vt_license is not None
        ):
            parser.error(
                "--demo cannot be combined with a target, --authorized, --sources or --vt-license"
            )
        try:
            export_report(build_demo_report(), args.output)
        except OSError:
            parser.exit(
                2,
                "Report export failed: check output permissions and use a new output directory.\n",
            )
        print(
            "SYNTHETIC TRAINING DATA: exported offline HTML, JSON and CSV. No network requests or live assessment performed."
        )
        return 0
    if args.target is None:
        parser.error("provide an approved target for live collection, or use --demo")
    args.sources = args.sources or ["rdap"]
    if not args.authorized:
        parser.error(
            "--authorized is required; obtain target approval before collection"
        )
    try:
        target = validate_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    if "virustotal" in args.sources and not args.vt_license:
        parser.error(
            "VirusTotal requires --vt-license; public access is restricted to permitted noncommercial use"
        )
    keys = {
        "shodan": os.environ.get("SHODAN_API_KEY"),
        "virustotal": os.environ.get("VIRUSTOTAL_API_KEY"),
    }
    transport = Transport()
    connectors = {
        "rdap": RDAP(transport),
        "shodan": Shodan(transport, keys["shodan"]),
        "virustotal": VirusTotal(transport, keys["virustotal"]),
    }
    evidence = [
        connectors[name].collect(target) for name in dict.fromkeys(args.sources)
    ]
    report = assess(target, evidence)
    try:
        export_report(report, args.output, tuple(keys.values()))
    except OSError:
        parser.exit(
            2,
            "Report export failed: check output permissions and use a new output directory.\n",
        )
    print(
        f"Exported HTML, JSON and CSV. Sources observed: {report['summary']['observed_sources']}/{len(evidence)}."
    )
    return 0 if all(e.status == "observed" for e in evidence) else 1


if __name__ == "__main__":
    raise SystemExit(main())
