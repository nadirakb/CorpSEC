from collections.abc import Callable
from datetime import date
from typing import Any

import httpx

from corpsec_checks.connection.conn_001 import HttpsReachable
from corpsec_checks.connection.crawl_001 import Crawler
from corpsec_checks.software.sw_001 import PlatformDetected
from corpsec_checks.software.sw_002 import CmsUpToDate
from corpsec_checks.software.sw_003 import KnownVulnerableVersion
from corpsec_checks.software.sw_004 import VulnerablePlugins
from corpsec_checks.software.sw_005 import VulnerableJsLibraries, detect
from corpsec_checks.software.sw_006 import EndOfLifeSoftware
from corpsec_checks.software.sw_007 import WordPressUserEnumeration
from corpsec_checks.software.sw_008 import WordPressXmlRpc
from corpsec_scanner import Confidence, Severity
from corpsec_scanner.intel import (
    Attribution,
    IntelSnapshot,
    JsLibrary,
    Product,
    ReleaseCycle,
    VersionRange,
    Vulnerability,
)

from .conftest import FakeSite, html, severities

Scan = Callable[..., Any]
HOME = "https://example.com/"

WP_PAGE = """<html><head>
<meta name="generator" content="WordPress 5.8.1" />
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4" />
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.6.0"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
</head><body>hello</body></html>"""

INTEL = IntelSnapshot(
    generated_at="2026-10-29T00:00:00Z",
    products={
        "wordpress": Product(latest="6.8.3"),
        "php": Product(
            cycles=[
                ReleaseCycle(cycle="7.4", eol=date(2022, 11, 28)),
                ReleaseCycle(cycle="8.4", eol=date(2028, 12, 31)),
            ]
        ),
    },
    vulns={
        "wordpress": [
            Vulnerability(
                ids=["CVE-2022-21661"],
                cvss=7.5,
                ranges=[VersionRange(introduced="5.8", fixed="5.8.3")],
            )
        ],
        "wordpress-plugin:contact-form-7": [
            Vulnerability(
                ids=["CVE-2020-35489", "WF-a1"],
                cvss=10.0,
                severity="critical",
                ranges=[VersionRange(fixed="5.3.2")],
                url="https://www.wordfence.com/threat-intel/vulnerabilities/id/a1",
                copyright=["defiant", "mitre"],
            ),
        ],
    },
    js_libraries=[
        JsLibrary(
            name="jquery",
            uri_patterns=[r"/(§§version§§)/jquery(\.min)?\.js"],
            filename_patterns=[r"jquery-(§§version§§)(\.min)?\.js"],
            vulns=[
                Vulnerability(
                    ids=["CVE-2020-11022"],
                    severity="medium",
                    ranges=[VersionRange(introduced="1.2", fixed="3.5.0")],
                )
            ],
        )
    ],
    kev={"CVE-2022-21661"},
    attributions={
        "defiant": Attribution(
            notice="Copyright 2012-2026 Defiant Inc.",
            license="…",
            license_url="https://www.wordfence.com/wti-community-edition-terms-and-conditions/",
        ),
        "mitre": Attribution(
            notice="Copyright 1999-2026 The MITRE Corporation",
            license="…",
            license_url="https://www.cve.org/Legal/TermsOfUse",
        ),
    },
)

SW = [
    HttpsReachable(),
    Crawler(),
    PlatformDetected(),
    CmsUpToDate(),
    KnownVulnerableVersion(),
    VulnerablePlugins(),
    VulnerableJsLibraries(),
    EndOfLifeSoftware(),
]


def wp_site(**extra: Any) -> FakeSite:
    return FakeSite({HOME: html(WP_PAGE, headers={"x-powered-by": "PHP/7.4.33"}), **extra})


async def test_wordpress_stack(scan: Scan) -> None:
    readme = httpx.Response(200, text="=== Contact Form 7 ===\nStable tag: 5.3.1\n")
    site = wp_site(**{"https://example.com/wp-content/plugins/contact-form-7/readme.txt": readme})
    result = await scan(SW, site, intel=INTEL)
    by_check = {(f.check_id, f.dedupe_key): f for f in result.findings}

    sw1 = by_check[("SW-001", "")]
    assert sw1.context == {"platform": "wordpress"}
    assert {"product": "wordpress", "version": "5.8.1", "source": "generator meta tag"} in (
        sw1.evidence.observed
    )
    assert by_check[("SW-002", "wordpress")].severity == Severity.MEDIUM
    core = by_check[("SW-003", "wordpress")]
    assert (core.severity, core.confidence) == (Severity.CRITICAL, Confidence.LIKELY)  # KEV
    plugin = by_check[("SW-004", "wordpress-plugin:contact-form-7")]
    assert (plugin.severity, plugin.confidence) == (Severity.CRITICAL, Confidence.LIKELY)
    assert plugin.evidence.observed["version"] == "5.3.1"
    # Wordfence licence: record link + Defiant/MITRE notices travel with the finding
    [vuln] = plugin.evidence.observed["vulnerabilities"]
    assert vuln["url"].startswith("https://www.wordfence.com/threat-intel/")
    assert vuln["copyright"] == [
        "Copyright 2012-2026 Defiant Inc.",
        "Copyright 1999-2026 The MITRE Corporation",
    ]
    assert set(plugin.evidence.observed["attributions"]) == {"defiant", "mitre"}
    assert plugin.references[0] == vuln["url"]
    js = by_check[("SW-005", "jquery")]
    assert (js.severity, js.evidence.observed["version"]) == (Severity.MEDIUM, "1.12.4")
    assert by_check[("SW-006", "php")].severity == Severity.HIGH


async def test_plugin_version_from_ver_param_is_possible(scan: Scan) -> None:
    result = await scan(SW, wp_site(), intel=INTEL)
    [plugin] = [f for f in result.findings if f.check_id == "SW-004"]
    assert plugin.confidence == Confidence.POSSIBLE  # only ?ver=5.4 seen... not affected
    assert plugin.severity == Severity.PASS


async def test_no_intel_means_no_vulnerability_claims(scan: Scan) -> None:
    result = await scan(SW, wp_site())
    assert {f.check_id for f in result.findings} == {"CONN-001", "SW-001"}


async def test_unknown_version_never_matches(scan: Scan) -> None:
    site = FakeSite({HOME: html('<link href="/wp-content/themes/x/style.css">')})
    result = await scan(SW, site, intel=INTEL)
    assert severities(result, "SW-003") == []
    assert severities(result, "SW-002") == []


def test_retire_patterns() -> None:
    lib = INTEL.js_libraries[0]
    assert detect(lib, "https://code.jquery.com/jquery-3.4.1.min.js") == "3.4.1"
    assert detect(lib, "https://cdn.example/libs/jquery/2.2.4/jquery.js") == "2.2.4"
    assert detect(lib, "https://cdn.example/app.js") is None


async def test_wordpress_user_listing_and_xmlrpc(scan: Scan) -> None:
    site = wp_site(
        **{
            "https://example.com/wp-json/wp/v2/users": httpx.Response(
                200, json=[{"id": 1, "slug": "admin"}, {"id": 2, "slug": "leyla"}]
            ),
            "https://example.com/xmlrpc.php": httpx.Response(
                405, text="XML-RPC server accepts POST requests only."
            ),
        }
    )
    checks = [
        HttpsReachable(),
        Crawler(),
        PlatformDetected(),
        WordPressUserEnumeration(),
        WordPressXmlRpc(),
    ]
    result = await scan(checks, site)
    users = next(f for f in result.findings if f.check_id == "SW-007")
    assert users.severity == Severity.LOW
    assert users.evidence.observed == {"accounts_listed": 2}  # no names stored
    assert severities(result, "SW-008") == [Severity.LOW]


async def test_wordpress_checks_skip_other_platforms(scan: Scan) -> None:
    site = FakeSite({HOME: html("<p>plain</p>")})
    checks = [HttpsReachable(), Crawler(), PlatformDetected(), WordPressUserEnumeration()]
    result = await scan(checks, site)
    assert severities(result, "SW-007") == []
    assert not any("/wp-json" in r.url.path for r in site.requests)
