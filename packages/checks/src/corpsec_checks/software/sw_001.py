"""SW-001 — identify the website platform and server software (informational)."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_FINGERPRINTS, FACT_PAGES, observe
from corpsec_checks.software._fingerprint import fingerprint, platform
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class PlatformDetected(Check):
    id = "SW-001"
    version = "1.0.0"
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_PAGES})
    provides: ClassVar[frozenset[str]] = frozenset({FACT_FINGERPRINTS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        fps = fingerprint(ctx.facts.get(FACT_PAGES))
        ctx.set_fact(FACT_FINGERPRINTS, fps)
        if not fps:
            return []
        cms = platform(fps)
        return [
            observe(
                ctx.target.host,
                Severity.INFO,
                "fingerprint",
                observed=[
                    {"product": f.product, "version": f.version, "source": f.source}
                    for f in fps
                    if not f.product.startswith("wordpress-plugin:")
                ],
                context={"platform": cms} if cms else {},
            )
        ]
