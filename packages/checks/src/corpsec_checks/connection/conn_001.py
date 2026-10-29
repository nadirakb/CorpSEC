"""CONN-001 — the site answers over HTTPS.

Certificate validity is TLS-001's job, so this check connects without verifying the
certificate: a site with an expired certificate is still *reachable* over HTTPS.
"""

from __future__ import annotations

from typing import ClassVar

import httpx

from corpsec_checks._common import (
    FACT_HOMEPAGE,
    get_request,
    observe,
    redirect_chain,
    response_summary,
)
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class HttpsReachable(Check):
    id = "CONN-001"
    version = "1.0.0"
    stage = Stage.CONNECTION
    provides: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        host = ctx.target.host
        url = f"https://{host}/"
        try:
            resp = await ctx.http.get(url, verify=False)
        except httpx.TransportError as exc:
            return [
                observe(
                    host,
                    Severity.CRITICAL,
                    "http",
                    request=get_request(url),
                    observed=f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__,
                    expected="A response over HTTPS (port 443)",
                )
            ]

        ctx.set_fact(FACT_HOMEPAGE, resp)
        return [
            observe(
                host,
                Severity.PASS,
                "http",
                request=get_request(url),
                response=response_summary(resp),
                observed={"final_url": resp.url, "redirects": redirect_chain(resp)},
            )
        ]
