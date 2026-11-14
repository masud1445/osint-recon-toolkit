"""RDAP replaces legacy port-43 WHOIS; all operations retrieve existing records."""

import ipaddress

from .models import Evidence, now
from .targets import validate_target
from .transport import SourceError


class Connector:
    name = ""

    def __init__(self, transport, key=None):
        self.transport, self.key = transport, key

    def collect(self, target):
        canonical = validate_target(target.value)
        if canonical.kind != target.kind:
            raise ValueError("Target kind does not match its value.")
        target = canonical
        endpoint = self.endpoint(target)
        result = Evidence(self.name, "unavailable", target.value, endpoint)
        if self.name != "RDAP" and not self.key:
            result.message = "API key not configured; no intelligence collected."
            return result
        try:
            data = self.fetch(target, endpoint)
            result.collected_at = now()
            self.validate_record(target, data)
            result.observations = self.normalize(data)
            result.status = "observed"
            result.message = "Source record retrieved. Observations are not independently verified findings."
        except SourceError as exc:
            result.status, result.message = exc.status, exc.message
        except (KeyError, TypeError, ValueError, AttributeError):
            result.status = "error"
            result.message = "Unexpected source response schema or target mismatch."
            result.observations = {}
        return result

    def validate_record(self, target, data):
        """Each source must bind the returned record to the requested target."""
        raise NotImplementedError


class RDAP(Connector):
    name = "RDAP"

    def endpoint(self, target):
        return f"https://rdap.org/{'domain' if target.kind == 'domain' else 'ip'}/{target.value}"

    def fetch(self, target, endpoint):
        return self.transport.get(endpoint, headers={"Accept": "application/rdap+json"})

    def validate_record(self, target, data):
        if target.kind == "domain":
            if (
                data.get("objectClassName") != "domain"
                or validate_target(data.get("ldhName")).value != target.value
            ):
                raise ValueError("RDAP domain mismatch")
        else:
            if data.get("objectClassName") != "ip network":
                raise ValueError("RDAP object class mismatch")
            start = ipaddress.ip_address(data["startAddress"])
            end = ipaddress.ip_address(data["endAddress"])
            address = ipaddress.ip_address(target.value)
            if not start <= address <= end:
                raise ValueError("RDAP network does not contain target")

    def normalize(self, data):
        if data.get("objectClassName") not in ("domain", "ip network"):
            raise ValueError("Invalid RDAP object class")
        # Contact entities, free-text remarks and arbitrary links are intentionally omitted.
        selected = {
            k: data[k]
            for k in (
                "objectClassName",
                "handle",
                "ldhName",
                "name",
                "startAddress",
                "endAddress",
                "ipVersion",
                "country",
                "status",
                "events",
            )
            if k in data
        }
        if "nameservers" in data:
            nameservers = data["nameservers"]
            if not isinstance(nameservers, list) or any(
                not isinstance(item, dict) for item in nameservers
            ):
                raise ValueError("Invalid RDAP nameservers")
            selected["nameservers"] = [
                {key: item[key] for key in ("ldhName", "unicodeName") if key in item}
                for item in nameservers
            ]
        return selected


class Shodan(Connector):
    name = "Shodan"

    def endpoint(self, target):
        return f"https://api.shodan.io/{'shodan/host' if target.kind == 'ip' else 'dns/domain'}/{target.value}"

    def fetch(self, target, endpoint):
        return self.transport.get(
            endpoint,
            params={
                "key": self.key,
                **({"minify": "true"} if target.kind == "ip" else {"page": 1}),
            },
            interval=1,
        )

    def validate_record(self, target, data):
        identity = data.get("ip_str" if target.kind == "ip" else "domain")
        if validate_target(identity) != target:
            raise ValueError("Shodan target mismatch")

    def normalize(self, data):
        if not any(k in data for k in ("ip_str", "domain")):
            raise ValueError("Missing Shodan target")
        if "ports" in data and (
            not isinstance(data["ports"], list)
            or any(
                type(port) is not int or not 1 <= port <= 65535
                for port in data["ports"]
            )
        ):
            raise ValueError("Invalid indexed ports")
        # No banners or credentials; first-page domain records only.
        selected = {
            k: data[k]
            for k in (
                "ip_str",
                "domain",
                "ports",
                "hostnames",
                "org",
                "isp",
                "country_name",
                "last_update",
                "asn",
                "subdomains",
                "tags",
                "more",
            )
            if k in data
        }
        if "domain" in data and "data" in data:
            if not isinstance(data["data"], list) or any(
                not isinstance(record, dict) for record in data["data"]
            ):
                raise ValueError("Invalid DNS records")
            selected["dns_records"] = [
                {
                    k: record[k]
                    for k in ("subdomain", "type", "value", "last_seen")
                    if k in record
                }
                for record in data["data"]
                if isinstance(record, dict)
            ]
        return selected


class VirusTotal(Connector):
    name = "VirusTotal"

    def endpoint(self, target):
        return f"https://www.virustotal.com/api/v3/{'ip_addresses' if target.kind == 'ip' else 'domains'}/{target.value}"

    def fetch(self, target, endpoint):
        return self.transport.get(endpoint, headers={"x-apikey": self.key}, interval=15)

    def validate_record(self, target, data):
        record = data["data"]
        expected_type = "ip_address" if target.kind == "ip" else "domain"
        if (
            record.get("type") != expected_type
            or validate_target(record.get("id")) != target
        ):
            raise ValueError("VirusTotal target mismatch")

    def normalize(self, data):
        attributes = data["data"]["attributes"]
        if not isinstance(attributes, dict):
            raise TypeError("Invalid VT attributes")
        stats = attributes.get("last_analysis_stats", {})
        if not isinstance(stats, dict) or any(
            type(count) is not int or count < 0 for count in stats.values()
        ):
            raise ValueError("Invalid vendor counts")
        return {
            k: attributes[k]
            for k in (
                "last_analysis_stats",
                "last_analysis_date",
                "reputation",
                "country",
                "as_owner",
                "asn",
                "last_modification_date",
            )
            if k in attributes
        }
