"""Bounded, read-only transport with fixed destinations and sanitized failures."""

import json
import math
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

import requests


def reject_nonfinite(value):
    raise ValueError("Non-finite JSON number")


class SourceError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


class Transport:
    RDAP_HOSTS = frozenset(
        {
            "rdap.verisign.com",
            "rdap.publicinterestregistry.org",
            "rdap.org",
            "rdap.arin.net",
            "rdap.db.ripe.net",
            "rdap.apnic.net",
            "rdap.lacnic.net",
            "rdap.afrinic.net",
        }
    )
    HOSTS = RDAP_HOSTS | {"api.shodan.io", "www.virustotal.com"}

    def __init__(self, session=None, sleep=time.sleep, attempts=3):
        if not 1 <= attempts <= 5:
            raise ValueError("attempts must be between 1 and 5")
        self.session = session or requests.Session()
        self.sleep, self.attempts = sleep, attempts
        self.last = {}

    def get(self, url, *, params=None, headers=None, interval=0, redirects=0):
        if not isinstance(url, str):
            raise SourceError("error", "Invalid intelligence source URL.")
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except (TypeError, ValueError):
            raise SourceError("error", "Invalid intelligence source URL.") from None
        if (
            parsed.scheme != "https"
            or parsed.hostname not in self.HOSTS
            or port not in (None, 443)
            or parsed.username
            or parsed.password
        ):
            raise SourceError("error", "Unapproved intelligence source URL.")
        for attempt in range(self.attempts):
            delay = interval - (
                time.monotonic() - self.last.get(parsed.hostname, float("-inf"))
            )
            if delay > 0:
                self.sleep(delay)
            self.last[parsed.hostname] = time.monotonic()
            try:
                with self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=(5, 20),
                    allow_redirects=False,
                    stream=True,
                ) as response:
                    code = response.status_code
                    if code == 429 or 500 <= code <= 599:
                        if attempt + 1 == self.attempts:
                            raise SourceError(
                                "unavailable",
                                "Source rate limit or temporary service failure; retry later.",
                            )
                        retry = response.headers.get("Retry-After", "")
                        wait = min(2**attempt, 60)
                        if retry:
                            try:
                                if retry.isdigit():
                                    wait = float(retry) if len(retry) < 6 else 61
                                else:
                                    date = parsedate_to_datetime(retry)
                                    if date.tzinfo is None:
                                        date = date.replace(tzinfo=timezone.utc)
                                    wait = max(
                                        0,
                                        (
                                            date - datetime.now(timezone.utc)
                                        ).total_seconds(),
                                    )
                            except (ValueError, TypeError, OverflowError):
                                pass
                        if not math.isfinite(wait) or wait > 60:
                            raise SourceError(
                                "unavailable",
                                "Source requests a longer cooldown; retry later.",
                            )
                        self.sleep(wait)
                        continue
                    if code in (401, 403):
                        raise SourceError(
                            "unavailable",
                            "Source authentication or entitlement unavailable.",
                        )
                    if code == 404:
                        raise SourceError(
                            "unavailable",
                            "No source record available; this does not establish absence of exposure.",
                        )
                    if 300 <= code < 400:
                        location = response.headers.get("Location", "")
                        try:
                            destination = urlsplit(urljoin(url, location))
                            destination_port = destination.port
                        except (TypeError, ValueError):
                            raise SourceError(
                                "unavailable", "Source returned an invalid redirect."
                            ) from None
                        if (
                            location
                            and parsed.hostname in self.RDAP_HOSTS
                            and not params
                            and not (headers or {}).get("x-apikey")
                        ) and (
                            destination.scheme == "https"
                            and destination.hostname in self.RDAP_HOSTS
                            and not destination.username
                            and not destination.password
                            and destination_port in (None, 443)
                            and redirects < 3
                        ):
                            return self.get(
                                destination.geturl(),
                                headers={"Accept": "application/rdap+json"},
                                redirects=redirects + 1,
                            )
                        raise SourceError(
                            "unavailable",
                            "Source redirect requires review; unapproved redirects are not followed.",
                        )
                    if code != 200:
                        raise SourceError("error", f"Source returned HTTP {code}.")
                    body = bytearray()
                    for chunk in response.iter_content(65536):
                        body.extend(chunk)
                        if len(body) > 2_000_000:
                            raise SourceError(
                                "error", "Source response exceeds size limit."
                            )
                    try:
                        data = json.loads(body, parse_constant=reject_nonfinite)
                    except (ValueError, UnicodeError, RecursionError):
                        raise SourceError(
                            "error", "Source returned invalid JSON."
                        ) from None
                    if not isinstance(data, dict):
                        raise SourceError("error", "Unexpected source response schema.")
                    pending = [(data, 0)]
                    while pending:
                        node, depth = pending.pop()
                        if depth > 32:
                            raise SourceError(
                                "error", "Source JSON exceeds nesting limit."
                            )
                        if isinstance(node, float) and not math.isfinite(node):
                            raise SourceError(
                                "error", "Source contains a non-finite number."
                            )
                        if isinstance(node, str):
                            try:
                                node.encode("utf-8")
                            except UnicodeError:
                                raise SourceError(
                                    "error", "Source contains invalid Unicode."
                                ) from None
                        if isinstance(node, dict):
                            pending.extend((key, depth + 1) for key in node)
                            pending.extend(
                                (value, depth + 1) for value in node.values()
                            )
                        elif isinstance(node, list):
                            pending.extend((value, depth + 1) for value in node)
                    return data
            except requests.RequestException:
                if attempt + 1 == self.attempts:
                    raise SourceError(
                        "unavailable", "Source connection failed or timed out."
                    ) from None
                self.sleep(2**attempt)
        raise SourceError("error", "Source request failed.")
