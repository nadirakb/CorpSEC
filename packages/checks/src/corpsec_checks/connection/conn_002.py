"""CONN-002 — plain HTTP (port 80) sends visitors to HTTPS."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from corpsec_checks._common import get_request, observe, redirect_chain, response_summary
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class HttpRedirectsToHttps(Check):
    id = "CONN-002"
    version = "1.0.0"
    stage = Stage.CONNECTION

    async def run(self, ctx: ScanContext) -> list[Observation]:
        host = ctx.target.host
        url = f"http://{host}/"
        try:
            resp = await ctx.http.get(url, max_body=0)
        except httpx.TransportError:
            # Nothing listening on port 80 means nothing can be served unencrypted.
            return [
                observe(
                    host,
                    Severity.PASS,
                    "http",
                    request=get_request(url),
                    observed="Port 80 does not accept connections",
                )
            ]

        if resp.left_scope and resp.history:
            final_scheme = urlsplit(resp.history[-1].location).scheme
        else:
            final_scheme = resp.scheme

        return [
            observe(
                host,
                Severity.PASS if final_scheme == "https" else Severity.HIGH,
                "http",
                request=get_request(url),
                response=response_summary(resp),
                observed={"final_url": resp.url, "redirects": redirect_chain(resp)},
                expected="A redirect to an https:// address",
            )
        ]
