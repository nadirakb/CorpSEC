"""MAIL-009 — BIMI: the brand logo shown next to the domain's emails (informational)."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_checks.mail._base import SendingDomainCheck
from corpsec_scanner import Observation, ScanContext, Severity


class Bimi(SendingDomainCheck):
    id = "MAIL-009"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]:
        name = f"default._bimi.{domain}"
        records = [t for t in await ctx.dns.resolve(name, "TXT") if "v=BIMI1" in t]
        return [
            observe(
                domain,
                Severity.PASS if records else Severity.INFO,
                "dns",
                query=f"{name} TXT",
                observed={"bimi": records[0] if records else None},
                context=self.context(ctx),
            )
        ]
