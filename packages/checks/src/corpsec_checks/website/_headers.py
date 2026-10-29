"""Base class for checks that only look at the homepage's response headers."""

from __future__ import annotations

from abc import abstractmethod
from typing import ClassVar

from corpsec_checks._common import FACT_HOMEPAGE, observe, response_summary
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse


def csp_directives(policy: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


class HeaderCheck(Check):
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})
    expected: ClassVar[str]

    @abstractmethod
    def evaluate(self, resp: HttpResponse) -> tuple[Severity, object]:
        """Return (severity, observed) for the homepage response."""

    async def run(self, ctx: ScanContext) -> list[Observation]:
        resp: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        severity, observed = self.evaluate(resp)
        return [
            observe(
                ctx.target.host,
                severity,
                "http",
                request={"method": "GET", "url": resp.url},
                response=response_summary(resp),
                observed=observed,
                expected=self.expected,
            )
        ]
