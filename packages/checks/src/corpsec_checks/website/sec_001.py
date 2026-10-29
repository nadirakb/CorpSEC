"""SEC-001 — ``/.well-known/security.txt`` tells researchers how to report problems."""

from __future__ import annotations

from typing import ClassVar

import httpx

from corpsec_checks._common import FACT_HOMEPAGE, get_request, observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse


class SecurityTxt(Check):
    id = "SEC-001"
    version = "1.0.0"
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        home: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        base = home.url.split("/", 3)
        url = f"{base[0]}//{base[2]}/.well-known/security.txt"
        found = False
        try:
            resp = await ctx.http.get(url, verify=False, max_body=4096)
            found = (
                resp.status == 200
                and not resp.left_scope
                and "contact:" in resp.text.lower()
                and "<html" not in resp.text[:500].lower()
            )
        except httpx.TransportError:
            pass
        return [
            observe(
                ctx.target.host,
                Severity.PASS if found else Severity.INFO,
                "http",
                request=get_request(url),
                observed="security.txt with Contact field" if found else "Not found",
                references=["https://www.rfc-editor.org/rfc/rfc9116"],
            )
        ]
