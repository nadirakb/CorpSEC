"""DNS-002 — DNSSEC is enabled (a DS record is published at the registry)."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class Dnssec(Check):
    id = "DNS-002"
    version = "1.0.0"
    stage = Stage.EMAIL

    async def run(self, ctx: ScanContext) -> list[Observation]:
        domain = ctx.target.registrable_domain
        ds = await ctx.dns.resolve(domain, "DS")
        return [
            observe(
                domain,
                Severity.PASS if ds else Severity.LOW,
                "dns",
                query=f"{domain} DS",
                observed={"ds_records": len(ds)},
                expected="DNSSEC signing enabled",
            )
        ]
