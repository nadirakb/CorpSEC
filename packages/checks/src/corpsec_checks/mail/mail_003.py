"""MAIL-003 — SPF ends with ``-all`` or ``~all`` so other servers are rejected."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_checks.mail._base import SendingDomainCheck
from corpsec_checks.mail._mail import analyze_spf, spf_records
from corpsec_scanner import Observation, ScanContext, Severity


class SpfAllQualifier(SendingDomainCheck):
    id = "MAIL-003"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]:
        records = spf_records(await ctx.dns.resolve(domain, "TXT"))
        if len(records) != 1:
            return []  # MAIL-002 reports missing / duplicate records
        spf = await analyze_spf(ctx.dns, records[0], max_depth=0)
        q = spf.all_qualifier
        if q in ("-", "~") or (q is None and spf.has_redirect):
            severity = Severity.PASS
        elif q == "+":
            severity = Severity.CRITICAL
        else:
            severity = Severity.HIGH
        return [
            observe(
                domain,
                severity,
                "dns",
                query=f"{domain} TXT",
                observed={"record": spf.record, "all": f"{q}all" if q else None},
                expected="-all or ~all at the end of the SPF record",
                context=self.context(ctx),
            )
        ]
