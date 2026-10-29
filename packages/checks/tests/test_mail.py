from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from corpsec_checks import CHECKS
from corpsec_checks.mail._mail import analyze_spf, detect_provider, parse_mx
from corpsec_checks.mail.dns_001 import DomainExpiry
from corpsec_checks.mail.dns_002 import Dnssec
from corpsec_checks.mail.dns_003 import Caa
from corpsec_checks.mail.dns_004 import SubdomainTakeover
from corpsec_scanner import Confidence, Severity
from corpsec_scanner.intel import IntelSnapshot

from .conftest import FakeDns, FakeSite, html, severities

Scan = Callable[..., Any]
MAIL = [c() for c in CHECKS if c.id.startswith("MAIL-")]
D = "example.com"


GOOD = {
    ("example.com", "MX"): ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."],
    ("example.com", "TXT"): ["v=spf1 include:_spf.google.com -all", "google-site-verification=x"],
    ("_spf.google.com", "TXT"): ["v=spf1 include:_netblocks.google.com ~all"],
    ("_netblocks.google.com", "TXT"): ["v=spf1 ip4:35.190.247.0/24 ~all"],
    ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
    ("google._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjAN"],
    ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=1"],
    ("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1; rua=mailto:t@example.com"],
}


async def test_well_configured_google_domain(scan: Scan) -> None:
    result = await scan(MAIL, dns=FakeDns(dict(GOOD)))
    got = {f.check_id: f.severity for f in result.findings}
    assert got.pop("MAIL-001") == Severity.INFO
    assert set(got.values()) == {Severity.PASS}
    assert set(got) == {"MAIL-002", "MAIL-003", "MAIL-004", "MAIL-005", "MAIL-006", "MAIL-008"}
    mx = next(f for f in result.findings if f.check_id == "MAIL-001")
    assert mx.context == {"email_provider": "google_workspace"}


async def test_spoofable_domain(scan: Scan) -> None:
    records = {
        ("example.com", "MX"): ["10 mx.example.com."],
        ("example.com", "TXT"): ["v=spf1 a mx ?all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
    }
    result = await scan(MAIL, dns=FakeDns(records))
    got = {f.check_id: f.severity for f in result.findings}
    assert got["MAIL-002"] == Severity.PASS
    assert got["MAIL-003"] == Severity.HIGH
    assert got["MAIL-005"] == Severity.MEDIUM
    dkim = next(f for f in result.findings if f.check_id == "MAIL-006")
    assert (dkim.severity, dkim.confidence) == (Severity.MEDIUM, Confidence.POSSIBLE)


async def test_missing_spf_dmarc_and_plus_all(scan: Scan) -> None:
    result = await scan(MAIL, dns=FakeDns({("example.com", "MX"): ["10 mx.example.com."]}))
    got = {f.check_id: f.severity for f in result.findings}
    assert (got["MAIL-002"], got["MAIL-004"]) == (Severity.HIGH, Severity.HIGH)
    assert "MAIL-003" not in got and "MAIL-005" not in got

    records = {
        ("example.com", "MX"): ["10 mx.example.com."],
        ("example.com", "TXT"): ["v=spf1 +all"],
    }
    result = await scan(MAIL, dns=FakeDns(records))
    assert severities(result, "MAIL-003") == [Severity.CRITICAL]


async def test_spf_lookup_limit() -> None:
    records = {("example.com", "TXT"): []}
    for i in range(12):
        records[(f"i{i}.example.net", "TXT")] = ["v=spf1 a -all"]
    spf = " ".join(f"include:i{i}.example.net" for i in range(6))
    result = await analyze_spf(FakeDns(records), f"v=spf1 {spf} -all")
    assert result.lookups == 12  # 6 includes + 6 nested "a"


async def test_non_sending_domain(scan: Scan) -> None:
    locked = {
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
    }
    result = await scan(MAIL, dns=FakeDns(locked))
    assert {f.check_id: f.severity for f in result.findings} == {
        "MAIL-001": Severity.INFO,
        "MAIL-007": Severity.PASS,
    }
    result = await scan(MAIL, dns=FakeDns({}))
    assert severities(result, "MAIL-007") == [Severity.MEDIUM]


async def test_dns_provider_detected(scan: Scan) -> None:
    records = dict(GOOD) | {
        ("example.com", "NS"): ["ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."]
    }
    result = await scan(MAIL, dns=FakeDns(records))
    mx = next(f for f in result.findings if f.check_id == "MAIL-001")
    assert mx.context == {"email_provider": "google_workspace", "dns_provider": "cloudflare"}


def test_parse_mx_and_provider() -> None:
    assert parse_mx(["0 ."]) == []
    hosts = parse_mx(["10 example-com.mail.protection.outlook.com."])
    assert detect_provider(hosts) == "microsoft_365"


async def test_dnssec_and_caa(scan: Scan) -> None:
    records = {
        ("example.com", "DS"): ["2371 13 2 ABCD"],
        ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
    }
    result = await scan([Dnssec(), Caa()], dns=FakeDns(records))
    assert {f.severity for f in result.findings} == {Severity.PASS}
    result = await scan([Dnssec(), Caa()], dns=FakeDns({}))
    assert {f.severity for f in result.findings} == {Severity.LOW}


@pytest.mark.parametrize(
    ("days", "severity"), [(5, Severity.CRITICAL), (20, Severity.HIGH), (200, Severity.PASS)]
)
async def test_domain_expiry(scan: Scan, days: int, severity: Severity) -> None:
    expiry = (datetime.now(UTC) + timedelta(days=days, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rdap = httpx.Response(
        200, json={"events": [{"eventAction": "expiration", "eventDate": expiry}]}
    )
    site = FakeSite({"https://rdap.verisign.com/com/v1/domain/example.com": rdap})
    intel = IntelSnapshot(rdap={"com": "https://rdap.verisign.com/com/v1/"})
    result = await scan([DomainExpiry()], site, intel=intel)
    assert severities(result, "DNS-001") == [severity]


async def test_domain_expiry_without_rdap_says_nothing(scan: Scan) -> None:
    assert (await scan([DomainExpiry()])).findings == []


async def test_subdomain_takeover(scan: Scan) -> None:
    records = {
        ("www.example.com", "CNAME"): ["example.github.io."],
        ("shop.example.com", "CNAME"): ["oldshop.azurewebsites.net."],
    }
    fake = FakeDns(records, nxdomain={"oldshop.azurewebsites.net"})
    site = FakeSite(
        {"http://www.example.com/": html("<h1>404</h1> There isn't a GitHub Pages site here.", 404)}
    )
    result = await scan([SubdomainTakeover()], site, dns=fake, target="shop.example.com")
    found = {(f.host, f.confidence) for f in result.findings if f.severity == Severity.HIGH}
    assert found == {
        ("www.example.com", Confidence.CONFIRMED),
        ("shop.example.com", Confidence.LIKELY),
    }


async def test_subdomain_cname_to_live_service_is_fine(scan: Scan) -> None:
    fake = FakeDns({("www.example.com", "CNAME"): ["example.github.io."]})
    site = FakeSite({"http://www.example.com/": html("my real site")})
    result = await scan([SubdomainTakeover()], site, dns=fake)
    assert severities(result, "DNS-004") == [Severity.PASS]
