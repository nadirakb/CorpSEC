"""Set-Cookie parsing and the shared logic of the CK-* checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from corpsec_checks._common import FACT_PAGES, observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

_SESSION_NAME_RE = re.compile(
    r"sess|sid$|^sid|auth|token|login|jwt|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid"
    r"|wordpress_logged_in|laravel_session|_session$|remember",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Cookie:
    name: str
    attrs: dict[str, str]
    """Lower-cased attribute names; flag attributes map to ""."""

    @property
    def session_like(self) -> bool:
        return bool(_SESSION_NAME_RE.search(self.name))


def parse_set_cookie(header: str) -> Cookie | None:
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        key, _, value = p.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return Cookie(name=name, attrs=attrs)


def session_cookies(pages: list[HttpResponse]) -> list[Cookie]:
    found: dict[str, Cookie] = {}
    for page in pages:
        for header in page.headers.get_list("set-cookie"):
            cookie = parse_set_cookie(header)
            if cookie and cookie.session_like:
                found.setdefault(cookie.name, cookie)
    return list(found.values())


class CookieCheck(Check):
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_PAGES})
    severity: ClassVar[Severity]
    expected: ClassVar[str]
    https_only: ClassVar[bool] = False

    def is_ok(self, cookie: Cookie) -> bool:
        raise NotImplementedError

    async def run(self, ctx: ScanContext) -> list[Observation]:
        pages: list[HttpResponse] = ctx.facts.get(FACT_PAGES)
        if self.https_only and pages[0].scheme != "https":
            return []
        cookies = session_cookies(pages)
        bad = [c for c in cookies if not self.is_ok(c)]
        if not bad:
            observed = {"session_cookies": [c.name for c in cookies]}
            return [observe(ctx.target.host, Severity.PASS, "http", observed=observed)]
        return [
            observe(
                ctx.target.host,
                self.severity,
                "http",
                observed={"cookie": c.name, "attributes": sorted(c.attrs)},
                expected=self.expected,
                dedupe_key=c.name,
            )
            for c in bad
        ]
