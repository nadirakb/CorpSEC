"""Coverage checks added after the MVP: certificate logs, look-alikes, blocklists, BIMI,
third-party code and open ports."""

import json
from collections.abc import Callable
from typing import Any

import httpx

from corpsec_checks.connection.conn_001 import HttpsReachable
from corpsec_checks.connection.crawl_001 import Crawler
from corpsec_checks.connection.port_001 import RiskyOpenPorts
from corpsec_checks.mail.dns_004 import SubdomainTakeover
from corpsec_checks.mail.dns_005 import CertificateTransparency, looks_forgotten, names_from_ct
from corpsec_checks.mail.dns_006 import LookalikeDomains, lookalikes
from corpsec_checks.mail.mail_001 import MailServers
from corpsec_checks.mail.mail_009 import Bimi
from corpsec_checks.reputation.rep_001 import DomainBlocklist
from corpsec_checks.reputation.rep_002 import MailServerBlocklist
from corpsec_checks.website.scr_001 import SubresourceIntegrity
from corpsec_checks.website.scr_002 import CompromisedScriptSource
from corpsec_scanner import Severity, run_scan
from corpsec_scanner.engine import ScanOptions
from corpsec_scanner.http import HttpPolicy
from corpsec_scanner.intel import IntelSnapshot

from .conftest import FakeDns, FakeSite, html, severities

Scan = Callable[..., Any]
CRT = "https://crt.sh/"


def finding(result: Any, check_id: str) -> Any:
    [f] = [f for f in result.findings if f.check_id == check_id]
    return f


# --- DNS-005 certificate transparency -------------------------------------------------


def test_names_from_ct_dedupes_and_drops_wildcards_and_other_domains() -> None:
    entries = [
        {"name_value": "*.example.com\nexample.com"},
        {"name_value": "dev.example.com\nwww.example.com"},
        {"name_value": "WWW.example.com"},
        {"name_value": "evil-example.com\nexample.com.evil.net"},
    ]
    assert names_from_ct(entries, "example.com") == ["dev.example.com", "www.example.com"]


def test_forgotten_name_patterns() -> None:
    forgotten = (
        "dev.example.com",
        "staging2.example.com",
        "old-shop.example.com",
        "qa.x.example.com",
    )
    for name in forgotten:
        assert looks_forgotten(name, "example.com"), name
    for name in ("www.example.com", "shop.example.com", "developer.example.com"):
        assert not looks_forgotten(name, "example.com"), name


async def test_ct_flags_live_test_sites_and_feeds_takeover_check(scan: Scan) -> None:
    ct = [{"name_value": n} for n in ("www.example.com", "dev.example.com", "old.example.com",
                                       "shop.example.com")]  # fmt: skip
    site = FakeSite({CRT: httpx.Response(200, json=ct)})
    dns = FakeDns({
        ("dev.example.com", "A"): ["203.0.113.5"],
        ("shop.example.com", "CNAME"): ["shop.myshopify.com."],
    })  # fmt: skip
    site.routes["http://shop.example.com/"] = html("Sorry, this shop is currently unavailable.")
    result = await scan([CertificateTransparency(), SubdomainTakeover()], site, dns=dns)
    f = finding(result, "DNS-005")
    assert f.severity == Severity.LOW
    assert f.evidence.observed["test_sites"] == ["dev.example.com"]  # old.* doesn't resolve
    assert f.evidence.observed["subdomains_found"] == 4
    # a name only known from the logs is checked for takeover
    assert [x.host for x in result.findings if x.check_id == "DNS-004"] == ["shop.example.com"]


async def test_ct_unavailable_is_not_a_finding(scan: Scan) -> None:
    site = FakeSite({CRT: httpx.Response(502)})
    result = await scan([CertificateTransparency()], site)
    assert severities(result, "DNS-005") == []


# --- DNS-006 look-alikes ----------------------------------------------------------------


def test_lookalike_candidates() -> None:
    names = lookalikes("google.com")
    assert names[0] == "google.net"
    assert {"g0ogle.com", "goog1e.com", "gogle.com", "gooogle.com", "goolge.com",
            "google-login.com"} <= set(names)  # fmt: skip
    assert "google.com" not in names
    assert len(names) == len(set(names)) <= 60
    assert all(n.split(".")[0][0] != "-" for n in names)


async def test_lookalikes_reported_but_own_registrations_ignored(scan: Scan) -> None:
    ns = ["ns1.host.example."]
    dns = FakeDns(
        {
            ("example.com", "NS"): ns,
            ("examp1e.com", "NS"): ["ns.badhost.net."],
            ("examp1e.com", "MX"): ["10 mail.badhost.net."],
            ("example.net", "NS"): ns,  # same name servers: probably a defensive registration
        },
        unknown_nxdomain=True,
    )
    result = await scan([LookalikeDomains()], dns=dns)
    f = finding(result, "DNS-006")
    assert f.severity == Severity.INFO
    assert f.evidence.observed["lookalikes"] == [
        {"domain": "examp1e.com", "receives_email": True, "has_website": False}
    ]
    assert f.evidence.observed["probably_yours"] == ["example.net"]


async def test_wildcard_endings_are_skipped(scan: Scan) -> None:
    dns = FakeDns({("example.com", "NS"): ["ns1.x."]})  # every name "exists"
    result = await scan([LookalikeDomains()], dns=dns)
    assert severities(result, "DNS-006") == [Severity.PASS]


# --- REP-001 / REP-002 blocklists -------------------------------------------------------


async def test_domain_blocklist(scan: Scan) -> None:
    listed = FakeDns({("example.com.dbl.spamhaus.org", "A"): ["127.0.1.4", "127.0.1.2"]})
    f = finding(await scan([DomainBlocklist()], dns=listed), "REP-001")
    assert f.severity == Severity.HIGH and f.evidence.observed["reason"] == "phishing"

    clean = FakeDns(unknown_nxdomain=True)
    assert severities(await scan([DomainBlocklist()], dns=clean), "REP-001") == [Severity.PASS]

    refused = FakeDns({("example.com.dbl.spamhaus.org", "A"): ["127.255.255.254"]})
    assert severities(await scan([DomainBlocklist()], dns=refused), "REP-001") == []


async def test_domain_blocklist_uses_licence_key_without_leaking_it() -> None:
    dns = FakeDns({("example.com.secretkey.dbl.dq.spamhaus.net", "A"): ["127.0.1.5"]})
    options = ScanOptions(
        preflight=False, dns=dns, check_config={"spamhaus_dqs_key": "secretkey"},
        transport_factory=lambda v: httpx.MockTransport(lambda r: httpx.Response(404)),
    )  # fmt: skip
    result = await run_scan("example.com", [DomainBlocklist()], options=options)
    f = finding(result, "REP-001")
    assert f.severity == Severity.HIGH
    assert "secretkey" not in json.dumps(f.model_dump(mode="json"))


async def test_self_hosted_mail_server_on_blocklist(scan: Scan) -> None:
    dns = FakeDns({
        ("example.com", "MX"): ["10 mail.example.com."],
        ("mail.example.com", "A"): ["198.51.100.7", "8.8.4.4"],
        ("4.4.8.8.zen.spamhaus.org", "A"): ["127.0.0.4"],
    })  # fmt: skip
    result = await scan([MailServers(), MailServerBlocklist()], dns=dns)
    # 198.51.100.7 is a documentation address (not global), so only 8.8.4.4 is asked
    f = finding(result, "REP-002")
    assert f.severity == Severity.MEDIUM and f.evidence.observed["ip"] == "8.8.4.4"


async def test_hosted_email_skips_ip_blocklist(scan: Scan) -> None:
    dns = FakeDns({("example.com", "MX"): ["1 aspmx.l.google.com."]})
    result = await scan([MailServers(), MailServerBlocklist()], dns=dns)
    assert severities(result, "REP-002") == []


# --- MAIL-009 BIMI ----------------------------------------------------------------------


async def test_bimi(scan: Scan) -> None:
    base = {("example.com", "MX"): ["10 mail.example.com."]}
    result = await scan([MailServers(), Bimi()], dns=FakeDns(base))
    assert severities(result, "MAIL-009") == [Severity.INFO]
    bimi = {**base, ("default._bimi.example.com", "TXT"): ["v=BIMI1; l=https://example.com/l.svg"]}
    result = await scan([MailServers(), Bimi()], dns=FakeDns(bimi))
    assert severities(result, "MAIL-009") == [Severity.PASS]


# --- SCR-001 / SCR-002 third-party code -------------------------------------------------

PAGE = """<html><head>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"
        integrity="sha384-abc" crossorigin="anonymous"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
<script src="/static/app.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/all.min.css">
</head><body>hi</body></html>"""


def home(body: str) -> FakeSite:
    return FakeSite({"https://example.com/": html(body), "http://example.com/": html(body)})


async def test_unpinned_cdn_files(scan: Scan) -> None:
    result = await scan([HttpsReachable(), Crawler(), SubresourceIntegrity()], home(PAGE))
    f = finding(result, "SCR-001")
    assert f.severity == Severity.LOW
    assert f.evidence.observed["unpinned_files"] == [
        "https://code.jquery.com/jquery-3.7.1.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/all.min.css",
    ]  # analytics can't be pinned and isn't flagged; the pinned file is fine
    assert "www.googletagmanager.com" in f.evidence.observed["third_party_sites"]


async def test_no_third_party_code_passes(scan: Scan) -> None:
    result = await scan(
        [HttpsReachable(), Crawler(), SubresourceIntegrity(), CompromisedScriptSource()],
        home('<script src="/app.js"></script>'),
    )
    assert severities(result, "SCR-001") == [Severity.PASS]
    assert severities(result, "SCR-002") == [Severity.PASS]


async def test_polyfill_io_is_flagged(scan: Scan) -> None:
    page = '<script src="https://cdn.polyfill.io/v3/polyfill.min.js?features=default"></script>'
    result = await scan([HttpsReachable(), Crawler(), CompromisedScriptSource()], home(page))
    f = finding(result, "SCR-002")
    assert f.severity == Severity.HIGH and f.evidence.observed["source"] == "polyfill.io"


# --- PORT-001 open ports ----------------------------------------------------------------


def port_scan(data: dict[str, Any] | None, *, enabled: bool = True) -> Any:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "internetdb.shodan.io":
            return httpx.Response(200, json=data) if data else httpx.Response(404)
        return httpx.Response(404)

    return run_scan(
        "example.com",
        [RiskyOpenPorts()],
        options=ScanOptions(
            preflight=False,
            http_policy=HttpPolicy(per_host_rps=1000),
            transport_factory=lambda v: httpx.MockTransport(handler),
            dns=FakeDns({("example.com", "A"): ["8.8.8.8"]}),
            intel=IntelSnapshot(),
            check_config={"internetdb": "on"} if enabled else {},
        ),
    )


async def test_risky_open_ports() -> None:
    result = await port_scan({"ip": "8.8.8.8", "ports": [80, 443, 3306, 3389]})
    found = {f.evidence.observed["port"]: f.severity for f in result.findings}
    assert found == {3306: Severity.HIGH, 3389: Severity.HIGH}


async def test_open_ports_pass_unknown_and_disabled() -> None:
    assert severities(await port_scan({"ports": [80, 443]}), "PORT-001") == [Severity.PASS]
    assert severities(await port_scan(None), "PORT-001") == [Severity.PASS]
    assert severities(await port_scan({"ports": [3306]}, enabled=False), "PORT-001") == []
