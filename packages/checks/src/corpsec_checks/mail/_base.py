"""Base for checks that only apply to domains that receive email."""

from __future__ import annotations

from abc import abstractmethod
from typing import ClassVar

from corpsec_checks._common import FACT_MAIL_PROVIDER, FACT_MX
from corpsec_scanner import Check, Observation, ScanContext, Stage


class SendingDomainCheck(Check):
    stage = Stage.EMAIL
    requires: ClassVar[frozenset[str]] = frozenset({FACT_MX, FACT_MAIL_PROVIDER})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        if not ctx.facts.get(FACT_MX):
            return []  # MAIL-007 covers domains without email
        return await self.check(ctx, ctx.target.registrable_domain)

    def context(self, ctx: ScanContext) -> dict[str, str]:
        provider = ctx.facts.get(FACT_MAIL_PROVIDER)
        return {"email_provider": provider} if provider else {}

    @abstractmethod
    async def check(self, ctx: ScanContext, domain: str) -> list[Observation]: ...
