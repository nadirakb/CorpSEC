"""MAIL-001 — which servers receive email for the domain (informational, feeds MAIL-*)."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_MAIL_PROVIDER, FACT_MX, observe
from corpsec_checks.mail._mail import detect_provider, parse_mx
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class MailServers(Check):
    id = "MAIL-001"
    version = "1.0.0"
    stage = Stage.EMAIL
    provides: ClassVar[frozenset[str]] = frozenset({FACT_MX, FACT_MAIL_PROVIDER})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        domain = ctx.target.registrable_domain
        hosts = parse_mx(await ctx.dns.resolve(domain, "MX"))
        provider = detect_provider(hosts)
        ctx.set_fact(FACT_MX, hosts)
        ctx.set_fact(FACT_MAIL_PROVIDER, provider)
        return [
            observe(
                domain,
                Severity.INFO,
                "dns",
                query=f"{domain} MX",
                observed={"mail_servers": hosts, "provider": provider},
                context={"email_provider": provider} if provider else {},
            )
        ]
