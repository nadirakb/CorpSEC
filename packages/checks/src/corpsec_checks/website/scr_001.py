"""SCR-001 — files from public code sites (CDNs) are pinned with an integrity check (SRI).

If a CDN is hacked, every site loading its files runs the attacker's code. An ``integrity``
hash makes the browser refuse a changed file. Only flagged for public CDNs, where files are
fixed and versioned; analytics or chat widgets change all the time and can't be pinned.
"""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_PAGES, observe
from corpsec_checks.website._scripts import is_public_cdn, third_parties
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage

MAX_REPORTED = 10


class SubresourceIntegrity(Check):
    id = "SCR-001"
    version = "1.0.0"
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_PAGES})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        found = third_parties(ctx, ctx.facts.get(FACT_PAGES) or [])
        unpinned = [t for t in found if is_public_cdn(t.host) and not t.has_integrity]
        observed = {
            "third_party_sites": sorted({t.host for t in found})[:MAX_REPORTED],
            "unpinned_files": [t.url for t in unpinned][:MAX_REPORTED],
        }
        if not unpinned:
            return [observe(ctx.target.host, Severity.PASS, "http", observed=observed)]
        return [
            observe(
                ctx.target.host,
                Severity.LOW,
                "http",
                observed={**observed, "count": len(unpinned), "example": unpinned[0].url},
                expected='<script src="..." integrity="sha384-..." crossorigin="anonymous">',
                request={"method": "GET", "url": unpinned[0].page},
            )
        ]
