"""CRAWL-001 (internal) — fetch up to 20 same-site pages for other checks (spec §5).

Also records robots.txt rules and a soft-404 baseline: the response to a random path, used
by exposed-file checks to ignore sites that answer "200 OK" for every URL.
"""

from __future__ import annotations

import secrets
from typing import ClassVar
from urllib.parse import urldefrag, urlsplit

import httpx

from corpsec_checks._common import FACT_HOMEPAGE, FACT_PAGES, FACT_SOFT404
from corpsec_checks._html import is_html, parse_html
from corpsec_scanner import Check, Observation, ScanContext, Stage
from corpsec_scanner.http import HttpResponse, OutOfScopeError

MAX_PAGES = 20
MAX_DEPTH = 2
_SKIP_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".mp4", ".mp3", ".css", ".js", ".woff", ".woff2", ".xml", ".json", ".doc", ".docx",
)  # fmt: skip


def parse_robots(text: str) -> list[str]:
    """Disallow rules that apply to all user agents (``User-agent: *``)."""
    rules: list[str] = []
    applies = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (p.strip() for p in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            applies = value == "*"
        elif key == "disallow" and applies and value:
            rules.append(value)
    return rules


class Crawler(Check):
    id = "CRAWL-001"
    version = "1.0.0"
    stage = Stage.WEBSITE
    internal = True
    requires: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})
    provides: ClassVar[frozenset[str]] = frozenset({FACT_PAGES, FACT_SOFT404})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        home: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        origin = urlsplit(home.url)
        base = f"{origin.scheme}://{origin.netloc}"

        disallow: list[str] = []
        try:
            robots = await ctx.http.get(f"{base}/robots.txt", verify=False, max_body=64_000)
            if robots.status == 200 and not robots.left_scope:
                disallow = parse_robots(robots.text)
        except (httpx.TransportError, OutOfScopeError):
            pass

        soft404: HttpResponse | None = None
        try:
            probe = await ctx.http.get(
                f"{base}/corpsec-{secrets.token_hex(8)}", verify=False, max_body=4096
            )
            soft404 = probe if probe.status == 200 else None
        except (httpx.TransportError, OutOfScopeError):
            pass
        ctx.set_fact(FACT_SOFT404, soft404)

        pages = [home]
        seen = {urldefrag(home.url).url}
        frontier = [(home, 0)]
        while frontier and len(pages) < MAX_PAGES:
            page, depth = frontier.pop(0)
            if depth >= MAX_DEPTH or not is_html(page.headers.get("content-type")):
                continue
            for link in parse_html(page.text, page.url).links():
                if len(pages) >= MAX_PAGES:
                    break
                url = urldefrag(link).url
                parts = urlsplit(url)
                if (
                    url in seen
                    or parts.scheme != origin.scheme
                    or parts.netloc != origin.netloc
                    or parts.path.lower().endswith(_SKIP_EXTENSIONS)
                    or any(parts.path.startswith(rule) for rule in disallow)
                ):
                    continue
                seen.add(url)
                try:
                    resp = await ctx.http.get(url, verify=False, max_body=500_000)
                except (httpx.TransportError, OutOfScopeError):
                    continue
                if resp.left_scope:
                    continue
                pages.append(resp)
                frontier.append((resp, depth + 1))

        ctx.set_fact(FACT_PAGES, pages)
        return []
