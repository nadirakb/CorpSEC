"""Thin async DNS wrapper. Returns empty results instead of raising for "no such record"."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.resolver


class DnsError(Exception):
    """Resolver failure (timeout, SERVFAIL) — distinct from an authoritative "no record"."""


class DnsClient:
    def __init__(self, timeout: float = 5.0) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout

    async def resolve(self, name: str, rdtype: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise DnsError(f"{name} {rdtype}: {exc}") from exc
        return [rdata.to_text() for rdata in answer]
