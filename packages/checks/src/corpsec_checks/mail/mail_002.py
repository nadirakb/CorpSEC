"""MAIL-002 — exactly one valid SPF record, within the 10-DNS-lookup limit."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_checks.mail._base import SendingDomainCheck
from corpsec_checks.mail._mail import analyze_spf, spf_records
from corpsec_scanner import Observation, ScanContext, Severity

REFERENCES = ["https://www.rfc-editor.org/rfc/rfc7208"]


class SpfValid(SendingDomainCheck):
    id = "MAIL-002"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]:
        records = spf_records(await ctx.dns.resolve(domain, "TXT"))

        def result(severity: Severity, observed: object, problem: str = "") -> list[Observation]:
            ctx_ = self.context(ctx) | ({"problem": problem} if problem else {})
            return [
                observe(
                    domain,
                    severity,
                    "dns",
                    query=f"{domain} TXT",
                    observed=observed,
                    expected="One SPF record (v=spf1 …) with at most 10 DNS lookups",
                    context=ctx_,
                    references=REFERENCES,
                )
            ]

        if not records:
            return result(Severity.HIGH, None, "missing")
        if len(records) > 1:
            return result(Severity.HIGH, records, "multiple")
        spf = await analyze_spf(ctx.dns, records[0])
        observed = {"record": spf.record, "dns_lookups": spf.lookups}
        if spf.invalid_terms:
            return result(Severity.HIGH, observed | {"invalid": spf.invalid_terms}, "syntax")
        if spf.lookups > 10:
            return result(Severity.HIGH, observed, "too_many_lookups")
        return result(Severity.PASS, observed)
