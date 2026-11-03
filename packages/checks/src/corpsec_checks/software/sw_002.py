"""SW-002 — the website platform (CMS) is up to date."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_FINGERPRINTS, observe
from corpsec_checks.software._fingerprint import VERSIONED_CMS, Fingerprint
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.intel import compare_versions


def _minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


class CmsUpToDate(Check):
    id = "SW-002"
    version = "1.0.0"
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_FINGERPRINTS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        fps: list[Fingerprint] = ctx.facts.get(FACT_FINGERPRINTS)
        out: list[Observation] = []
        for fp in fps:
            if fp.product not in VERSIONED_CMS or not fp.version:
                continue
            product = ctx.intel.products.get(fp.product)
            if product is None or product.latest is None:
                continue  # no intel: we can't tell, so we say nothing
            behind = compare_versions(_minor(fp.version), _minor(product.latest)) < 0
            out.append(
                observe(
                    ctx.target.host,
                    Severity.MEDIUM if behind else Severity.PASS,
                    "fingerprint",
                    confidence=fp.confidence,
                    observed={"product": fp.product, "version": fp.version, "source": fp.source},
                    expected=f"{fp.product} {product.latest}",
                    dedupe_key=fp.product,
                    context={"platform": fp.product, "latest": product.latest},
                )
            )
        return out
