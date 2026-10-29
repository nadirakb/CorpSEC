from datetime import UTC, datetime

from corpsec_checks.explain import SiteContext, explain
from corpsec_checks.explain.render import effort_text
from corpsec_scanner.models import Confidence, Evidence, Finding, Severity

NOW = datetime(2026, 10, 29, tzinfo=UTC)


def finding(check_id: str, **kw: object) -> Finding:
    data: dict[str, object] = {
        "check_id": check_id, "check_version": "1.0.0", "scan_id": "scn_x",
        "host": "example.com", "severity": Severity.HIGH, "confidence": Confidence.CONFIRMED,
        "evidence": Evidence(kind="dns"), "first_seen": NOW, "last_seen": NOW,
    }  # fmt: skip
    data.update(kw)
    return Finding.model_validate(data)


def test_provider_specific_fix_is_chosen() -> None:
    site = SiteContext(domain="bakery.az", host="bakery.az", email_provider="google_workspace")
    e = explain(finding("MAIL-006"), site)
    assert e is not None and e.fix_for == "google_workspace"
    assert any("Google Admin console" in s for s in e.fix_steps)

    e = explain(finding("MAIL-006"), SiteContext(domain="bakery.az", host="bakery.az"))
    assert e is not None and e.fix_for == "default"


def test_hosted_platform_fallback_and_dns_provider() -> None:
    site = SiteContext(domain="shop.az", host="shop.az", platform="wix", dns_provider="cloudflare")
    e = explain(finding("TLS-002", evidence=Evidence(kind="tls", observed={"days_left": 5})), site)
    assert e is not None and e.fix_for == "hosted"
    assert "Wix" in e.fix_steps[0]
    assert "5 days" in e.summary
    # a DNS fix prefers the DNS provider's guide
    e = explain(finding("DNS-002"), site)
    assert e is not None and e.fix_for == "cloudflare"


def test_variables_from_evidence_and_dedupe_key() -> None:
    f = finding(
        "SW-004",
        dedupe_key="wordpress-plugin:contact-form-7",
        evidence=Evidence(
            kind="fingerprint",
            observed={
                "product": "wordpress-plugin:contact-form-7",
                "version": "5.3.1",
                "total": 5,
            },
        ),
    )
    e = explain(f, SiteContext(domain="a.az", host="a.az", platform="wordpress"))
    assert e is not None
    assert e.summary.startswith("The plugin contact-form-7 (version 5.3.1) has security holes")
    assert "We found 5 in public lists." in e.summary


def test_pass_has_no_fix_steps() -> None:
    e = explain(finding("HDR-001", severity=Severity.PASS), SiteContext("a.az", "a.az"))
    assert e is not None
    assert e.title == "Your site limits which scripts may run" and e.fix_steps == []


def test_site_context_from_findings() -> None:
    fs = [
        finding("SW-001", severity=Severity.INFO, context={"platform": "wordpress"}),
        finding(
            "MAIL-001",
            severity=Severity.INFO,
            context={"email_provider": "microsoft_365", "dns_provider": "cloudflare"},
        ),
    ]
    site = SiteContext.from_findings("a.az", "a.az", fs)
    assert (site.platform, site.email_provider, site.dns_provider) == (
        "wordpress",
        "microsoft_365",
        "cloudflare",
    )


def test_effort_text() -> None:
    assert effort_text(15) == "about 15 minutes"
    assert effort_text(60) == "about 1 hour"
    assert effort_text(120) == "about 2 hours"
