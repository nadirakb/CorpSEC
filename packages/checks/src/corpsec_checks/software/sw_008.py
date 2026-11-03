"""SW-008 — WordPress ``xmlrpc.php`` (used for password-guessing attacks) is disabled."""

from __future__ import annotations

import httpx

from corpsec_checks._common import get_request, observe
from corpsec_checks.software._wordpress import WordPressCheck
from corpsec_scanner import Observation, ScanContext, Severity


class WordPressXmlRpc(WordPressCheck):
    id = "SW-008"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, base: str) -> list[Observation]:
        url = f"{base}/xmlrpc.php"
        enabled = False
        try:
            r = await ctx.http.get(url, verify=False, max_body=4096)
            enabled = r.status == 405 and "XML-RPC server accepts POST requests only" in r.text
        except httpx.TransportError:
            pass
        return [
            observe(
                ctx.target.host,
                Severity.LOW if enabled else Severity.PASS,
                "http",
                request=get_request(url),
                observed={"xmlrpc_enabled": enabled},
                expected="xmlrpc.php blocked",
            )
        ]
