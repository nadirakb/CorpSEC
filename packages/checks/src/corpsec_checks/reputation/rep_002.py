"""REP-002 — the domain's own mail servers are not on the Spamhaus ZEN IP blocklist.

Big providers (Google, Microsoft, ...) are skipped: their addresses are shared and managed.
The policy list (PBL, "home internet addresses") is ignored for receiving servers.
"""

from __future__ import annotations

import asyncio
import ipaddress

from corpsec_checks._common import FACT_MAIL_PROVIDER, FACT_MX, observe
from corpsec_checks.mail._base import SendingDomainCheck
from corpsec_checks.reputation._dnsbl import query, zone
from corpsec_scanner import Observation, ScanContext, Severity
from corpsec_scanner.dns import DnsError

MAX_IPS = 4
ZEN_CODES = {
    "127.0.0.2": "known spam source (SBL)",
    "127.0.0.3": "spam source (CSS)",
    "127.0.0.4": "hacked or infected computer (XBL)",
    "127.0.0.5": "hacked or infected computer (XBL)",
    "127.0.0.6": "hacked or infected computer (XBL)",
    "127.0.0.7": "hacked or infected computer (XBL)",
    "127.0.0.9": "hijacked network (DROP)",
}


def reversed_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


class MailServerBlocklist(SendingDomainCheck):
    id = "REP-002"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]:
        if ctx.facts.get(FACT_MAIL_PROVIDER):
            return []  # hosted email: the provider looks after its servers
        hosts: list[str] = ctx.facts.get(FACT_MX) or []

        async def addresses(host: str) -> list[str]:
            try:
                return await ctx.dns.resolve(host, "A")
            except DnsError:
                return []

        ips: list[tuple[str, str]] = []
        resolved = await asyncio.gather(*map(addresses, hosts))
        for host, found in zip(hosts, resolved, strict=True):
            for ip in found:
                if ipaddress.ip_address(ip).is_global and (host, ip) not in ips:
                    ips.append((host, ip))
        zen = zone(ctx.config, "zen.spamhaus.org", "zen.dq.spamhaus.net")
        out: list[Observation] = []
        asked = 0
        for host, ip in ips[:MAX_IPS]:
            listing = await query(ctx.dns, f"{reversed_ip(ip)}.{zen}")
            if listing is None:
                continue
            asked += 1
            reasons = [ZEN_CODES[c] for c in listing.codes if c in ZEN_CODES]
            if listing.listed and reasons:
                out.append(
                    observe(
                        host,
                        Severity.MEDIUM,
                        "dns",
                        query=f"{reversed_ip(ip)}.zen.spamhaus.org A",
                        observed={"mail_server": host, "ip": ip, "reason": reasons[0]},
                        expected="Not listed",
                        dedupe_key=ip,
                        references=[f"https://check.spamhaus.org/results/?query={ip}"],
                        context=self.context(ctx),
                    )
                )
        if out:
            return out
        if asked:
            return [observe(domain, Severity.PASS, "dns", observed=[ip for _, ip in ips[:MAX_IPS]])]
        return []
