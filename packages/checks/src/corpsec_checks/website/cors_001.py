"""CORS-001 — other websites can't read logged-in visitors' data through CORS.

Sends one ordinary GET with an ``Origin`` header of a site we don't control and checks
whether the response would let that site read it with the visitor's cookies.
"""

from __future__ import annotations

from typing import ClassVar

import httpx

from corpsec_checks._common import FACT_HOMEPAGE, get_request, observe, response_summary
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

PROBE_ORIGIN = "https://corpsec-cors-check.invalid"


class CorsMisconfiguration(Check):
    id = "CORS-001"
    version = "1.0.0"
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        home: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        try:
            resp = await ctx.http.get(
                home.url, verify=False, max_body=0, headers={"Origin": PROBE_ORIGIN}
            )
        except httpx.TransportError:
            return []
        acao = resp.headers.get("access-control-allow-origin", "")
        credentials = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
        vulnerable = credentials and acao in (PROBE_ORIGIN, "*", "null")
        return [
            observe(
                ctx.target.host,
                Severity.HIGH if vulnerable else Severity.PASS,
                "http",
                request=get_request(home.url, Origin=PROBE_ORIGIN),
                response=response_summary(resp),
                observed={"allow_origin": acao or None, "allow_credentials": credentials},
                expected="No credentialed access for arbitrary origins",
            )
        ]
