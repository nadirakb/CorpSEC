"""SW-007 — WordPress doesn't list its user accounts through the REST API."""

from __future__ import annotations

import json

import httpx

from corpsec_checks._common import get_request, observe
from corpsec_checks.software._wordpress import WordPressCheck
from corpsec_scanner import Observation, ScanContext, Severity


class WordPressUserEnumeration(WordPressCheck):
    id = "SW-007"
    version = "1.0.0"

    async def check(self, ctx: ScanContext, base: str) -> list[Observation]:
        url = f"{base}/wp-json/wp/v2/users"
        count = 0
        try:
            r = await ctx.http.get(url, verify=False, max_body=65_536)
            if r.status == 200 and not r.left_scope:
                data = json.loads(r.text)
                if isinstance(data, list):
                    count = sum(1 for u in data if isinstance(u, dict) and "slug" in u)
        except (httpx.TransportError, ValueError):
            pass
        # Only the number of accounts is kept as evidence, never the names.
        return [
            observe(
                ctx.target.host,
                Severity.LOW if count else Severity.PASS,
                "http",
                request=get_request(url),
                observed={"accounts_listed": count},
                expected="User list not public",
            )
        ]
