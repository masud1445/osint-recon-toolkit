"""Validate without resolving or contacting targets."""

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    value: str
    kind: str


def validate_target(value: str) -> Target:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 253
    ):
        raise ValueError(
            "Provide one domain or public IP, without whitespace or URL syntax."
        )
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        if not address.is_global or address.is_multicast:
            raise ValueError("Only public unicast IP addresses are supported.")
        return Target(str(address), "ip")
    if any(c in value for c in "/:@?%#\\") or re.fullmatch(r"[0-9.]+", value):
        raise ValueError(
            "URLs, ports, paths and malformed IP addresses are unsupported."
        )
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid international domain name.") from None
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels
        )
    ):
        raise ValueError("Invalid domain name.")
    if labels[-1].isdigit() or labels[-1] in {
        "local",
        "localhost",
        "internal",
        "invalid",
        "test",
        "example",
        "onion",
    }:
        raise ValueError("Use a publicly registrable domain.")
    return Target(domain, "domain")
