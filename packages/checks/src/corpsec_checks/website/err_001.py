"""ERR-001 — pages don't show detailed error messages or stack traces."""

from __future__ import annotations

import re
from typing import ClassVar

from corpsec_checks._common import FACT_PAGES, observe, redact
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

ERROR_PATTERNS: dict[str, re.Pattern[str]] = {
    "python": re.compile(r"Traceback \(most recent call last\)"),
    "php": re.compile(r"<b>(?:Fatal error|Warning|Parse error)</b>:.{0,300} on line <b>\d+"),
    "php-stack": re.compile(r"Stack trace:\s*(?:<br\s*/?>)?\s*#0 "),
    "java": re.compile(r"\tat (?:java|javax|org\.springframework|org\.apache)\.[\w.$]+\("),
    "dotnet": re.compile(r"Server Error in '/' Application|\[\w+Exception: "),
    "django": re.compile(r"You're seeing this error because you have <code>DEBUG = True"),
    "laravel": re.compile(r"Whoops! There was an error|Illuminate\\\\"),
    "sql": re.compile(
        r"You have an error in your SQL syntax|SQLSTATE\[\w+\]|ORA-\d{5}|PG::SyntaxError"
    ),
}


class VerboseErrors(Check):
    id = "ERR-001"
    version = "1.0.0"
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_PAGES})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        pages: list[HttpResponse] = ctx.facts.get(FACT_PAGES)
        out: list[Observation] = []
        for page in pages:
            for kind, pattern in ERROR_PATTERNS.items():
                m = pattern.search(page.text)
                if m:
                    start = max(0, m.start() - 80)
                    out.append(
                        observe(
                            ctx.target.host,
                            Severity.MEDIUM,
                            "http",
                            request={"method": "GET", "url": page.url},
                            response={
                                "status": page.status,
                                "body_excerpt": redact(page.text[start : m.end() + 160], limit=400),
                            },
                            observed=kind,
                            dedupe_key=page.url,
                        )
                    )
                    break
        return out or [observe(ctx.target.host, Severity.PASS, "http", observed=len(pages))]
