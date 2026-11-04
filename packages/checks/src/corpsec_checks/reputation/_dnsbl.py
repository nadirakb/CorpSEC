"""DNS blocklist lookups (Spamhaus).

Spamhaus's public servers are free for low-volume, non-commercial use and refuse queries
that arrive through big public resolvers. Commercial deployments set a Data Query Service
key (check config ``spamhaus_dqs_key``), which uses the same answers.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from corpsec_scanner.dns import DnsClient, DnsError

# 127.255.255.x answers mean "we didn't answer your question" (blocked resolver, typo, limit).
REFUSED_PREFIX = "127.255.255."


@dataclass(frozen=True, slots=True)
class Listing:
    listed: bool
    codes: tuple[str, ...] = ()


def zone(config: Mapping[str, str], public: str, dqs: str) -> str:
    key = config.get("spamhaus_dqs_key")
    return f"{key}.{dqs}" if key else public


async def query(dns: DnsClient, name: str) -> Listing | None:
    """``None`` when the list couldn't be asked; never treat that as "not listed"."""
    try:
        answer = await dns.lookup(name, "A")
    except DnsError:
        return None
    if answer.nxdomain or not answer.records:
        return Listing(listed=False)
    if any(r.startswith(REFUSED_PREFIX) for r in answer.records):
        return None
    return Listing(listed=True, codes=tuple(sorted(answer.records)))
