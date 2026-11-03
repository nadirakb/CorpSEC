"""MAIL-007 — a domain that sends no email says so (``v=spf1 -all`` + DMARC ``p=reject``)."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_MX, observe
from corpsec_checks.mail._mail import dmarc_record, parse_tags, spf_records
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class NonSendingDomainLocked(Check):
    id = "MAIL-007"
    version = "1.0.0"
    stage = Stage.EMAIL
    requires: ClassVar[frozenset[str]] = frozenset({FACT_MX})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        if ctx.facts.get(FACT_MX):
            return []
        domain = ctx.target.registrable_domain
        spf = spf_records(await ctx.dns.resolve(domain, "TXT"))
        dmarc = await dmarc_record(ctx.dns, domain)
        spf_ok = len(spf) == 1 and spf[0].split()[1:] == ["-all"]
        dmarc_ok = dmarc is not None and parse_tags(dmarc).get("p", "").lower() == "reject"
        return [
            observe(
                domain,
                Severity.PASS if spf_ok and dmarc_ok else Severity.MEDIUM,
                "dns",
                query=f"{domain} TXT, _dmarc.{domain} TXT",
                observed={"spf": spf, "dmarc": dmarc},
                expected='"v=spf1 -all" and "v=DMARC1; p=reject"',
            )
        ]
