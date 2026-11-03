"""Exposed-file probes (spec §6.5): one GET per fixed path, 4 KB body cap, and a finding
only when the content matches the file's signature (not just "200 OK")."""

from __future__ import annotations

import asyncio
import difflib
import re
from typing import ClassVar

import httpx

from corpsec_checks._common import FACT_HOMEPAGE, FACT_SOFT404, get_request, observe, redact
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

MAX_BODY = 4096


def looks_like_soft404(body: bytes, baseline: HttpResponse | None) -> bool:
    if baseline is None:
        return False
    ratio = difflib.SequenceMatcher(None, body[:2000], baseline.body[:2000]).ratio()
    return ratio > 0.9


class ExposedFileCheck(Check):
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE, FACT_SOFT404})
    paths: ClassVar[tuple[str, ...]]
    severity: ClassVar[Severity]
    pattern: ClassVar[re.Pattern[bytes] | None] = None
    show_excerpt: ClassVar[bool] = True
    """False for binary files (backups): evidence records only the match."""

    def signature(self, body: bytes) -> bool:
        """Does the body really look like this file? Override for binary formats."""
        return bool(self.pattern and self.pattern.search(body))

    async def run(self, ctx: ScanContext) -> list[Observation]:
        home: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        baseline: HttpResponse | None = ctx.facts.get(FACT_SOFT404)
        base = "/".join(home.url.split("/", 3)[:3])

        async def probe(path: str) -> Observation | None:
            url = base + path
            try:
                r = await ctx.http.get(url, verify=False, follow_redirects=False, max_body=MAX_BODY)
            except httpx.TransportError:
                return None
            if (
                r.status != 200
                or not self.signature(r.body)
                or looks_like_soft404(r.body, baseline)
            ):
                return None
            response: dict[str, object] = {"status": r.status}
            if self.show_excerpt:
                response["body_excerpt"] = redact(r.body.decode("utf-8", "replace"), limit=400)
            return observe(
                ctx.target.host,
                self.severity,
                "http",
                request=get_request(url),
                response=response,
                observed=f"{path} is publicly accessible",
                expected="404 Not Found or 403 Forbidden",
                dedupe_key=path,
            )

        results = await asyncio.gather(*(probe(p) for p in self.paths))
        found = [r for r in results if r is not None]
        return found or [observe(ctx.target.host, Severity.PASS, "http", observed=list(self.paths))]
