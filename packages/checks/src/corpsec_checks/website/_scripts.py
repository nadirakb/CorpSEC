"""Scripts and stylesheets a site loads from other websites (third parties)."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from corpsec_checks._html import is_html, parse_html
from corpsec_scanner import ScanContext
from corpsec_scanner.http import HttpResponse

# Public CDNs that serve fixed, versioned files: an integrity hash is always possible there.
PUBLIC_CDNS = frozenset({
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "code.jquery.com",
    "ajax.googleapis.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "netdna.bootstrapcdn.com", "cdn.datatables.net", "ajax.aspnetcdn.com", "cdn.rawgit.com",
    "cdn.statically.io", "esm.sh", "ga.jspm.io",
})  # fmt: skip


@dataclass(frozen=True, slots=True)
class ThirdParty:
    url: str
    host: str
    page: str
    has_integrity: bool


def third_parties(ctx: ScanContext, pages: list[HttpResponse]) -> list[ThirdParty]:
    seen: set[str] = set()
    out: list[ThirdParty] = []
    for page in pages:
        if not is_html(page.headers.get("content-type")):
            continue
        doc = parse_html(page.text, page.url)
        for tag in doc.tags:
            if tag.name == "script":
                src = tag.attrs.get("src")
            elif tag.name == "link" and "stylesheet" in tag.attrs.get("rel", "").lower():
                src = tag.attrs.get("href")
            else:
                continue
            if not src:
                continue
            url = doc.absolute(src)
            host = (urlsplit(url).hostname or "").lower()
            if not host or ctx.target.in_scope(host) or url in seen:
                continue
            seen.add(url)
            out.append(ThirdParty(url, host, page.url, bool(tag.attrs.get("integrity"))))
    return out


def is_public_cdn(host: str) -> bool:
    return host in PUBLIC_CDNS
