"""DNS-003 — a CAA record limits which authorities may issue certificates."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class Caa(Check):
    id = "DNS-003"
    version = "1.0.0"
    stage = Stage.EMAIL

    async def run(self, ctx: ScanContext) -> list[Observation]:
        domain = ctx.target.registrable_domain
        caa = await ctx.dns.resolve(domain, "CAA")
        return [
            observe(
                domain,
                Severity.PASS if caa else Severity.LOW,
                "dns",
                query=f"{domain} CAA",
                observed=caa,
                expected='e.g. 0 issue "letsencrypt.org"',
            )
        ]
