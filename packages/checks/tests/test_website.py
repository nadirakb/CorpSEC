from collections.abc import Callable
from typing import Any

import httpx
import pytest

from corpsec_checks.connection.conn_001 import HttpsReachable
from corpsec_checks.connection.conn_003 import ApexAndWwwAgree
from corpsec_checks.connection.conn_004 import NoMixedContent
from corpsec_checks.connection.crawl_001 import Crawler, parse_robots
from corpsec_checks.tls.tls_007 import Hsts
from corpsec_checks.website.ck_001 import CookieSecure
from corpsec_checks.website.ck_002 import CookieHttpOnly
from corpsec_checks.website.ck_003 import CookieSameSite
from corpsec_checks.website.cors_001 import PROBE_ORIGIN, CorsMisconfiguration
from corpsec_checks.website.dir_001 import DirectoryListing
from corpsec_checks.website.err_001 import VerboseErrors
from corpsec_checks.website.hdr_001 import ContentSecurityPolicy
from corpsec_checks.website.hdr_002 import ClickjackingProtection
from corpsec_checks.website.hdr_003 import NoSniff
from corpsec_checks.website.hdr_004 import ReferrerPolicy
from corpsec_checks.website.hdr_005 import PermissionsPolicy
from corpsec_checks.website.hdr_006 import VersionBanners
from corpsec_checks.website.sec_001 import SecurityTxt
from corpsec_scanner import Severity

from .conftest import FakeSite, html, severities

Scan = Callable[..., Any]
HOME = "https://example.com/"

HEADER_CHECKS = [
    ContentSecurityPolicy(), ClickjackingProtection(), NoSniff(), ReferrerPolicy(),
    PermissionsPolicy(), VersionBanners(), Hsts(),
]  # fmt: skip

GOOD_HEADERS = {
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "server": "nginx",
}


async def test_good_headers_all_pass(scan: Scan) -> None:
    site = FakeSite({HOME: html("<p>hi</p>", headers=GOOD_HEADERS)})
    result = await scan([HttpsReachable(), *HEADER_CHECKS], site)
    bad = [(f.check_id, f.severity) for f in result.findings if f.severity != Severity.PASS]
    assert bad == []


async def test_missing_headers(scan: Scan) -> None:
    site = FakeSite(
        {
            HOME: html(
                "<p>hi</p>",
                headers={"server": "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.4.3"},
            )
        }
    )
    result = await scan([HttpsReachable(), *HEADER_CHECKS], site)
    got = {f.check_id: f.severity for f in result.findings if f.check_id != "HDR-006"}
    assert got == {
        "CONN-001": Severity.PASS,
        "HDR-001": Severity.MEDIUM,
        "HDR-002": Severity.MEDIUM,
        "HDR-003": Severity.LOW,
        "HDR-004": Severity.LOW,
        "HDR-005": Severity.INFO,
        "TLS-007": Severity.MEDIUM,
    }
    banners = sorted(f.dedupe_key for f in result.findings if f.check_id == "HDR-006")
    assert banners == ["server", "x-powered-by"]


@pytest.mark.parametrize(
    ("headers", "check", "expected"),
    [
        (
            {"content-security-policy": "script-src 'unsafe-inline' 'unsafe-eval'"},
            ContentSecurityPolicy(),
            Severity.LOW,
        ),
        ({"x-frame-options": "SAMEORIGIN"}, ClickjackingProtection(), Severity.PASS),
        ({"x-frame-options": "ALLOW-FROM x"}, ClickjackingProtection(), Severity.MEDIUM),
        ({"referrer-policy": "unsafe-url"}, ReferrerPolicy(), Severity.LOW),
        ({"strict-transport-security": "max-age=300"}, Hsts(), Severity.MEDIUM),
    ],
)
async def test_header_edge_cases(
    scan: Scan, headers: dict[str, str], check: Any, expected: Severity
) -> None:
    site = FakeSite({HOME: html("x", headers=headers)})
    result = await scan([HttpsReachable(), check], site)
    assert severities(result, check.id) == [expected]


async def test_mixed_content(scan: Scan) -> None:
    page = '<script src="http://cdn.example.net/a.js"></script><img src="https://ok/x.png">'
    result = await scan([HttpsReachable(), NoMixedContent()], FakeSite({HOME: html(page)}))
    [finding] = [f for f in result.findings if f.check_id == "CONN-004"]
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence.observed["insecure_resources"] == ["http://cdn.example.net/a.js"]


async def test_apex_and_www(scan: Scan) -> None:
    redirect = httpx.Response(301, headers={"location": "https://www.example.com/"})
    site = FakeSite({HOME: redirect, "https://www.example.com/": html("ok")})
    assert severities(await scan([ApexAndWwwAgree()], site), "CONN-003") == [Severity.PASS]
    site = FakeSite({HOME: html("ok")})  # www missing
    assert severities(await scan([ApexAndWwwAgree()], site), "CONN-003") == [Severity.LOW]


def test_parse_robots() -> None:
    text = "User-agent: Googlebot\nDisallow: /g\n\nUser-agent: *\nDisallow: /admin # x\nAllow: /"
    assert parse_robots(text) == ["/admin"]


async def test_crawler_respects_limits_and_robots(scan: Scan) -> None:
    links = "".join(f'<a href="/p{i}">p</a>' for i in range(40))
    routes: dict[str, Any] = {
        HOME: html(links + '<a href="/admin/x">a</a><a href="https://other.net/">o</a>'),
        "https://example.com/robots.txt": httpx.Response(
            200, text="User-agent: *\nDisallow: /admin"
        ),
    }
    for i in range(40):
        routes[f"https://example.com/p{i}"] = html("leaf")
    site = FakeSite(routes)
    result = await scan([HttpsReachable(), Crawler()], site)
    paths = [r.url.path for r in site.requests]
    assert "/admin/x" not in paths
    assert sum(p.startswith("/p") for p in paths) == 19  # 20 pages incl. homepage
    assert all(r.url.host == "example.com" for r in site.requests)
    assert [r.check_id for r in result.check_runs] == ["CONN-001", "CRAWL-001"]


def cookie_site(*cookies: str) -> FakeSite:
    resp = httpx.Response(
        200,
        headers=[("content-type", "text/html")] + [("set-cookie", c) for c in cookies],
        text="hi",
    )
    return FakeSite({HOME: resp})


async def test_cookie_flags(scan: Scan) -> None:
    site = cookie_site(
        "PHPSESSID=abc; path=/",
        "theme=dark; path=/",  # not session-like: ignored
        "auth_token=x; Secure; HttpOnly; SameSite=Lax",
    )
    checks = [HttpsReachable(), Crawler(), CookieSecure(), CookieHttpOnly(), CookieSameSite()]
    result = await scan(checks, site)
    flagged = {(f.check_id, f.dedupe_key) for f in result.findings if f.severity != Severity.PASS}
    assert flagged == {("CK-001", "PHPSESSID"), ("CK-002", "PHPSESSID"), ("CK-003", "PHPSESSID")}


async def test_cors(scan: Scan) -> None:
    def reflect(req: httpx.Request) -> httpx.Response:
        origin = req.headers.get("origin")
        headers = {
            "access-control-allow-origin": origin,
            "access-control-allow-credentials": "true",
        }
        return html("x", headers=headers if origin else {})

    result = await scan([HttpsReachable(), CorsMisconfiguration()], FakeSite({HOME: reflect}))
    [f] = [f for f in result.findings if f.check_id == "CORS-001"]
    assert f.severity == Severity.HIGH
    assert f.evidence.observed["allow_origin"] == PROBE_ORIGIN

    safe = FakeSite({HOME: html("x", headers={"access-control-allow-origin": "*"})})
    result = await scan([HttpsReachable(), CorsMisconfiguration()], safe)
    assert severities(result, "CORS-001") == [Severity.PASS]


async def test_directory_listing_and_errors(scan: Scan) -> None:
    site = FakeSite(
        {
            HOME: html('<a href="/files/">f</a><a href="/oops">o</a>'),
            "https://example.com/files/": html("<html><title>Index of /files</title></html>"),
            "https://example.com/oops": html(
                "<b>Fatal error</b>:  Uncaught Error in /var/www/html/index.php on line <b>12</b>"
            ),
        }
    )
    result = await scan([HttpsReachable(), Crawler(), DirectoryListing(), VerboseErrors()], site)
    assert [f.dedupe_key for f in result.findings if f.check_id == "DIR-001"] == [
        "https://example.com/files/"
    ]
    [err] = [f for f in result.findings if f.check_id == "ERR-001"]
    assert err.severity == Severity.MEDIUM and err.evidence.observed == "php"


async def test_security_txt(scan: Scan) -> None:
    site = FakeSite(
        {
            HOME: html("x"),
            "https://example.com/.well-known/security.txt": httpx.Response(
                200, text="Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z"
            ),
        }
    )
    assert severities(await scan([HttpsReachable(), SecurityTxt()], site), "SEC-001") == [
        Severity.PASS
    ]
    site = FakeSite({HOME: html("x")})
    assert severities(await scan([HttpsReachable(), SecurityTxt()], site), "SEC-001") == [
        Severity.INFO
    ]
