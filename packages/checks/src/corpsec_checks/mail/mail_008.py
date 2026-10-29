"""MAIL-008 — MTA-STS / TLS-RPT protect incoming mail from downgrade (informational)."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_checks.mail._base import SendingDomainCheck
from corpsec_scanner import Observation, ScanContext, Severity


class MtaSts(SendingDomainCheck):
    id = "MAIL-008"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]:
        sts = [t for t in await ctx.dns.resolve(f"_mta-sts.{domain}", "TXT") if "STSv1" in t]
        rpt = [t for t in await ctx.dns.resolve(f"_smtp._tls.{domain}", "TXT") if "TLSRPTv1" in t]
        return [
            observe(
                domain,
                Severity.PASS if sts and rpt else Severity.INFO,
                "dns",
                query=f"_mta-sts.{domain} TXT, _smtp._tls.{domain} TXT",
                observed={"mta_sts": bool(sts), "tls_rpt": bool(rpt)},
                context=self.context(ctx),
            )
        ]
