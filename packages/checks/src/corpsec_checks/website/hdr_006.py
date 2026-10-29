"""HDR-006 — response headers don't reveal software version numbers."""

from __future__ import annotations

import re
from typing import ClassVar

from corpsec_checks._common import FACT_HOMEPAGE, observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
)
_VERSION_RE = re.compile(r"\d+\.\d+")


class VersionBanners(Check):
    id = "HDR-006"
    version = "1.0.0"
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        resp: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        leaks = {
            h: resp.headers[h]
            for h in BANNER_HEADERS
            if h in resp.headers and _VERSION_RE.search(resp.headers[h])
        }
        if not leaks:
            return [observe(ctx.target.host, Severity.PASS, "http", observed=None)]
        return [
            observe(
                ctx.target.host,
                Severity.LOW,
                "http",
                observed={h: v},
                expected="No version numbers in response headers",
                dedupe_key=h,
            )
            for h, v in leaks.items()
        ]
