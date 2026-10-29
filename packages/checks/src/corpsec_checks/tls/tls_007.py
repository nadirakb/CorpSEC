"""TLS-007 — HSTS tells browsers to always use HTTPS (max-age ≥ 180 days)."""

from __future__ import annotations

import re
from typing import ClassVar

from corpsec_checks._common import FACT_HOMEPAGE, observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

MIN_MAX_AGE = 15_552_000  # 180 days
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)


class Hsts(Check):
    id = "TLS-007"
    version = "1.0.0"
    stage = Stage.ENCRYPTION
    requires: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        home: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        if home.scheme != "https":
            return []
        header = home.headers.get("strict-transport-security")
        m = _MAX_AGE_RE.search(header or "")
        max_age = int(m.group(1)) if m else None
        ok = max_age is not None and max_age >= MIN_MAX_AGE
        return [
            observe(
                ctx.target.host,
                Severity.PASS if ok else Severity.MEDIUM,
                "http",
                request={"method": "GET", "url": home.url},
                observed={"header": header, "max_age": max_age},
                expected=f"Strict-Transport-Security: max-age={MIN_MAX_AGE} or more",
                context={
                    "include_subdomains": str("includesubdomains" in (header or "").lower()).lower()
                },
            )
        ]
