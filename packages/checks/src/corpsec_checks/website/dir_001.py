"""DIR-001 — no directory listings ("Index of /") on crawled pages."""

from __future__ import annotations

import re
from typing import ClassVar

from corpsec_checks._common import FACT_PAGES, observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

_LISTING_RE = re.compile(
    r"<title>\s*(Index of /|Directory listing for /)|<h1>\s*Index of /", re.IGNORECASE
)


class DirectoryListing(Check):
    id = "DIR-001"
    version = "1.0.0"
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_PAGES})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        pages: list[HttpResponse] = ctx.facts.get(FACT_PAGES)
        listings = [p.url for p in pages if p.status == 200 and _LISTING_RE.search(p.text[:4096])]
        if not listings:
            return [observe(ctx.target.host, Severity.PASS, "http", observed=len(pages))]
        return [
            observe(
                ctx.target.host,
                Severity.MEDIUM,
                "http",
                request={"method": "GET", "url": url},
                observed="Directory listing",
                dedupe_key=url,
            )
            for url in listings
        ]
