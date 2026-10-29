"""MAIL-006 — DKIM signing key found for the email provider's usual selectors.

DKIM selectors can't be listed, so "not found" is phrased as "we couldn't find" and is
capped at medium (spec §8.3).
"""

from __future__ import annotations

import asyncio

from corpsec_checks._common import FACT_MAIL_PROVIDER, observe
from corpsec_checks.mail._base import SendingDomainCheck
from corpsec_checks.mail._mail import DKIM_SELECTORS
from corpsec_scanner import Confidence, Observation, ScanContext, Severity
from corpsec_scanner.dns import DnsError


class DkimFound(SendingDomainCheck):
    id = "MAIL-006"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]:
        provider = ctx.facts.get(FACT_MAIL_PROVIDER)
        selectors = DKIM_SELECTORS.get(provider, ()) + DKIM_SELECTORS[None]
        selectors = tuple(dict.fromkeys(selectors))

        async def has_key(selector: str) -> bool:
            try:
                txt = await ctx.dns.resolve(f"{selector}._domainkey.{domain}", "TXT")
            except DnsError:
                return False
            return any("p=" in t for t in txt)

        found = [
            s
            for s, ok in zip(selectors, await asyncio.gather(*map(has_key, selectors)), strict=True)
            if ok
        ]
        return [
            observe(
                domain,
                Severity.PASS if found else Severity.MEDIUM,
                "dns",
                confidence=Confidence.LIKELY if provider else Confidence.POSSIBLE,
                query=f"<selector>._domainkey.{domain} TXT",
                observed={"selectors_found": found, "selectors_tried": list(selectors)},
                expected="A DKIM public key for your email provider",
                context=self.context(ctx),
            )
        ]
