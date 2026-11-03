"""MAIL-005 — the DMARC policy actually blocks fakes (``quarantine`` or ``reject``)."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_checks.mail._base import SendingDomainCheck
from corpsec_checks.mail._mail import dmarc_record, parse_tags
from corpsec_scanner import Observation, ScanContext, Severity


class DmarcEnforced(SendingDomainCheck):
    id = "MAIL-005"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]:
        record = await dmarc_record(ctx.dns, domain)
        if record is None:
            return []  # MAIL-004 reports it
        tags = parse_tags(record)
        policy = tags.get("p", "").lower()
        pct = tags.get("pct", "100")
        enforced = policy in ("quarantine", "reject") and pct == "100"
        return [
            observe(
                domain,
                Severity.PASS if enforced else Severity.MEDIUM,
                "dns",
                query=f"_dmarc.{domain} TXT",
                observed={"policy": policy or None, "pct": pct, "record": record},
                expected="p=quarantine or p=reject, applied to 100% of mail",
                context=self.context(ctx) | {"policy": policy},
            )
        ]
