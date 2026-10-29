"""MAIL-004 — a DMARC record exists."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_checks.mail._base import SendingDomainCheck
from corpsec_checks.mail._mail import dmarc_record
from corpsec_scanner import Observation, ScanContext, Severity


class DmarcPresent(SendingDomainCheck):
    id = "MAIL-004"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]:
        record = await dmarc_record(ctx.dns, domain)
        return [
            observe(
                domain,
                Severity.PASS if record else Severity.HIGH,
                "dns",
                query=f"_dmarc.{domain} TXT",
                observed=record,
                expected="v=DMARC1; p=quarantine (or reject)",
                context=self.context(ctx),
                references=["https://www.rfc-editor.org/rfc/rfc7489"],
            )
        ]
