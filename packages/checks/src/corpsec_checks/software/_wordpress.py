"""Base for WordPress-only checks."""

from __future__ import annotations

from abc import abstractmethod
from typing import ClassVar

from corpsec_checks._common import FACT_FINGERPRINTS, FACT_HOMEPAGE
from corpsec_checks.software._fingerprint import Fingerprint
from corpsec_scanner import Check, Observation, ScanContext, Stage
from corpsec_scanner.http import HttpResponse


class WordPressCheck(Check):
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_FINGERPRINTS, FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        fps: list[Fingerprint] = ctx.facts.get(FACT_FINGERPRINTS)
        if not any(f.product == "wordpress" for f in fps):
            return []
        home: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        return await self.check(ctx, "/".join(home.url.split("/", 3)[:3]))

    @abstractmethod
    async def check(self, ctx: ScanContext, base: str) -> list[Observation]: ...
