"""SW-006 — server software (e.g. PHP) is still supported (not end-of-life)."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_FINGERPRINTS, observe
from corpsec_checks.software._fingerprint import Fingerprint
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class EndOfLifeSoftware(Check):
    id = "SW-006"
    version = "1.0.0"
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_FINGERPRINTS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        fps: list[Fingerprint] = ctx.facts.get(FACT_FINGERPRINTS)
        out: list[Observation] = []
        for fp in fps:
            product = ctx.intel.products.get(fp.product)
            if not fp.version or product is None or not product.cycles:
                continue
            eol = product.is_eol(fp.version)
            if eol is None:
                continue
            cycle = product.cycle_for(fp.version)
            out.append(
                observe(
                    ctx.target.host,
                    Severity.HIGH if eol else Severity.PASS,
                    "fingerprint",
                    confidence=fp.confidence,
                    observed={
                        "product": fp.product,
                        "version": fp.version,
                        "release_line": cycle.cycle if cycle else None,
                        "support_ended": str(cycle.eol) if cycle else None,
                    },
                    expected="A version that still receives security updates",
                    dedupe_key=fp.product,
                )
            )
        return out
