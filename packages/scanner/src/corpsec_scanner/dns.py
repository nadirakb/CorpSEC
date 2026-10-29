"""Async DNS client with a per-scan cache.

Returns empty results instead of raising for "no such record"; ``lookup`` additionally
tells NXDOMAIN (name does not exist) apart from NoAnswer (name exists, no such record).
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver


class DnsError(Exception):
    """Resolver failure (timeout, SERVFAIL) — distinct from an authoritative "no record"."""


@dataclass(frozen=True, slots=True)
class DnsAnswer:
    records: tuple[str, ...]
    nxdomain: bool = False


class DnsClient:
    def __init__(
        self,
        timeout: float = 5.0,
        *,
        nameservers: list[str] | None = None,
        port: int = 53,
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=nameservers is None)
        if nameservers is not None:
            self._resolver.nameservers = nameservers
            self._resolver.port = port
        self._resolver.lifetime = timeout
        self._cache: dict[tuple[str, str], asyncio.Task[DnsAnswer]] = {}

    async def lookup(self, name: str, rdtype: str) -> DnsAnswer:
        key = (name.lower().rstrip("."), rdtype.upper())
        task = self._cache.get(key)
        if task is None:
            task = asyncio.ensure_future(self._lookup(*key))
            self._cache[key] = task
        return await asyncio.shield(task)

    async def _lookup(self, name: str, rdtype: str) -> DnsAnswer:
        try:
            try:
                answer = await self._resolver.resolve(name, rdtype)
            except dns.exception.Timeout:
                # one retry: local stub resolvers occasionally drop the first query
                answer = await self._resolver.resolve(name, rdtype)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(records=(), nxdomain=True)
        except dns.resolver.NoAnswer:
            return DnsAnswer(records=())
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise DnsError(f"{name} {rdtype}: {exc}") from exc
        if rdtype == "TXT":
            # Join the character-strings of each TXT record into one value.
            return DnsAnswer(
                records=tuple(
                    b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer
                )
            )
        return DnsAnswer(records=tuple(rdata.to_text() for rdata in answer))

    async def resolve(self, name: str, rdtype: str) -> list[str]:
        return list((await self.lookup(name, rdtype)).records)

    async def resolve_addresses(self, host: str, port: int = 443) -> list[str]:
        """A + AAAA through this client's nameservers. Matches ``netguard.Resolver``."""
        results = await asyncio.gather(
            self.lookup(host, "A"), self.lookup(host, "AAAA"), return_exceptions=True
        )
        addresses = [rec for r in results if isinstance(r, DnsAnswer) for rec in r.records]
        if not addresses:
            raise socket.gaierror(socket.EAI_NONAME, f"{host} has no address records")
        return addresses
