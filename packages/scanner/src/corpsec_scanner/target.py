"""Input normalization (spec §7.1)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna
import tldextract

# Offline extractor: uses the Public Suffix List snapshot bundled with tldextract.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_RESERVED_SUFFIXES = (
    "local",
    "localhost",
    "internal",
    "intranet",
    "lan",
    "home.arpa",
    "test",
    "example",
    "invalid",
    "onion",
    "arpa",
)


class InvalidTargetError(ValueError):
    """Raised for input CorpSEC refuses to scan. The message is user-facing."""


@dataclass(frozen=True, slots=True)
class ScanTarget:
    raw: str
    host: str
    """ASCII (punycode) hostname, lower-case, without trailing dot."""
    registrable_domain: str
    """eTLD+1, e.g. ``example.co.uk``. Defines the scan scope."""

    def in_scope(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return host == self.registrable_domain or host.endswith("." + self.registrable_domain)


def normalize_target(raw: str) -> ScanTarget:
    text = raw.strip()
    if not text:
        raise InvalidTargetError("Please enter a website or domain.")
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise InvalidTargetError("That doesn't look like a website address.") from exc
    if parts.scheme not in ("http", "https"):
        raise InvalidTargetError("Only website addresses (http or https) can be checked.")
    if parts.username or parts.password:
        raise InvalidTargetError("Please enter the address without a username or password.")

    hostname = (parts.hostname or "").rstrip(".")
    if not hostname:
        raise InvalidTargetError("That doesn't look like a website address.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise InvalidTargetError("Please enter a domain name, not an IP address.")

    try:
        host = idna.encode(hostname, uts46=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise InvalidTargetError("That domain name contains invalid characters.") from exc

    if "." not in host or any(host == s or host.endswith("." + s) for s in _RESERVED_SUFFIXES):
        raise InvalidTargetError("CorpSEC can only check public websites.")

    ext = _extract(host)
    if not ext.suffix or not ext.domain:
        raise InvalidTargetError("CorpSEC can only check public websites.")

    return ScanTarget(raw=raw, host=host, registrable_domain=f"{ext.domain}.{ext.suffix}")
