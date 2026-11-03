"""CONN-001 — the site answers over HTTPS.

Certificate validity is TLS-001's job, so this check connects without verifying the
certificate: a site with an expired certificate is still *reachable* over HTTPS.
"""

from __future__ import annotations

from typing import ClassVar

import httpx

from corpsec_checks._evidence import redirect_chain, response_summary
from corpsec_scanner import Check, Evidence, Observation, ScanContext, Severity, Stage

FACT_HOMEPAGE = "http.homepage"


class HttpsReachable(Check):
    id = "CONN-001"
    version = "1.0.0"
    stage = Stage.CONNECTION
    provides: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        url = f"https://{ctx.target.host}/"
        request = {"method": "GET", "url": url}
        try:
            resp = await ctx.http.get(url, verify=False)
        except httpx.TransportError as exc:
            return [
                Observation(
                    severity=Severity.CRITICAL,
                    host=ctx.target.host,
                    evidence=Evidence(
                        kind="http",
                        request=request,
                        observed=f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__,
                        expected="A response over HTTPS (port 443)",
                    ),
                )
            ]

        ctx.set_fact(FACT_HOMEPAGE, resp)
        return [
            Observation(
                severity=Severity.PASS,
                host=ctx.target.host,
                evidence=Evidence(
                    kind="http",
                    request=request,
                    response=response_summary(resp),
                    observed={"final_url": resp.url, "redirects": redirect_chain(resp)},
                ),
            )
        ]
