"""End-to-end: scan the lab's broken and hardened sites with the full check catalog.

Runs only inside the lab network (``CORPSEC_LAB=1``); see deploy/lab/README.md.
"""

import os
from datetime import date

import pytest

from corpsec_checks.explain import SiteContext, explain
from corpsec_grader import GradeReport, grade
from corpsec_scanner import ScanOptions, ScanResult, ScanStatus, Severity, load_checks, run_scan
from corpsec_scanner.dns import DnsClient
from corpsec_scanner.intel import (
    IntelSnapshot,
    JsLibrary,
    Product,
    ReleaseCycle,
    VersionRange,
    Vulnerability,
)
from corpsec_scanner.netguard import IpPolicy, NetConfig

pytestmark = pytest.mark.skipif(os.environ.get("CORPSEC_LAB") != "1", reason="lab only")

# A small, fixed snapshot so results don't depend on today's real-world data.
INTEL = IntelSnapshot(
    generated_at="2026-10-29T00:00:00Z",
    products={
        "wordpress": Product(latest="6.8.3"),
        "php": Product(cycles=[ReleaseCycle(cycle="7.4", eol=date(2022, 11, 28))]),
        "nginx": Product(cycles=[ReleaseCycle(cycle="1.27", eol=False)]),
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
                ids=["CVE-2020-35489"], severity="critical", ranges=[VersionRange(fixed="5.3.2")]
            )
        ],
    },
    js_libraries=[
        JsLibrary(
            name="jquery",
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
)


async def lab_scan(target: str) -> ScanResult:
    dns = DnsClient(nameservers=[os.environ["CORPSEC_LAB_DNS"]])
    net = NetConfig(
        policy=IpPolicy(allowed_networks=("172.30.0.0/24",)),
        resolver=dns.resolve_addresses,
        ca_file=os.environ["CORPSEC_LAB_CA"],
    )
    return await run_scan(target, load_checks(), options=ScanOptions(net=net, dns=dns, intel=INTEL))


def lab_grade(result: ScanResult) -> GradeReport:
    stages = {c.id: c.stage for c in load_checks() if not c.internal}
    return grade(result.findings, stages.get)


def assert_all_explained(result: ScanResult) -> None:
    site = SiteContext.from_findings(result.registrable_domain, result.host, result.findings)
    for f in result.findings:
        e = explain(f, site)
        assert e is not None, f.check_id
        assert "{{" not in e.title + e.summary + " ".join(e.fix_steps)
        if f.severity not in (Severity.PASS, Severity.INFO):
            assert e.fix_steps, f.check_id


def problems(result: ScanResult) -> set[tuple[str, Severity]]:
    return {(f.check_id, f.severity) for f in result.findings if f.severity != Severity.PASS}


C, H, M, L, INFO = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO

EXPECTED_BAD = {
    ("CONN-002", H), ("CONN-003", L), ("CONN-004", M),
    ("TLS-001", C), ("TLS-002", C), ("TLS-003", M), ("TLS-007", M), ("TLS-008", H),
    ("HDR-001", M), ("HDR-002", M), ("HDR-003", L), ("HDR-004", L), ("HDR-005", INFO),
    ("HDR-006", L),
    ("CK-001", M), ("CK-002", M), ("CK-003", L),
    ("CORS-001", H), ("DIR-001", M), ("ERR-001", M), ("SEC-001", INFO),
    ("SW-001", INFO), ("SW-002", M), ("SW-003", C), ("SW-004", C), ("SW-005", M), ("SW-006", H),
    ("SW-007", L), ("SW-008", L),
    ("EXP-001", C), ("EXP-002", C), ("EXP-004", C), ("EXP-005", H), ("EXP-009", M),
    ("DNS-002", L), ("DNS-003", L), ("DNS-004", H),
    ("MAIL-001", INFO), ("MAIL-003", C), ("MAIL-004", H), ("MAIL-006", M), ("MAIL-008", INFO),
}  # fmt: skip
# Depends on which legacy suites the lab's OpenSSL build still ships.
OPTIONAL_BAD = {("TLS-005", H)}


async def test_broken_site_findings() -> None:
    result = await lab_scan("corpsec-lab-bad.com")
    assert result.status == ScanStatus.COMPLETED, [r for r in result.check_runs if r.detail]
    found = problems(result)
    assert found - OPTIONAL_BAD == EXPECTED_BAD
    tls003 = sorted(f.dedupe_key for f in result.findings if f.check_id == "TLS-003")
    assert tls003 == ["TLSv1.0", "TLSv1.1"]
    exposed = {
        f.dedupe_key
        for f in result.findings
        if f.check_id.startswith("EXP-") and f.severity != Severity.PASS
    }
    assert exposed == {
        "/.git/HEAD",
        "/.env",
        "/backup.sql",
        "/phpinfo.php",
        "/wp-content/debug.log",
    }
    env = next(f for f in result.findings if f.dedupe_key == "/.env")
    assert "Bakery2026!secret" not in str(env.evidence.response)

    report = lab_grade(result)
    assert (report.letter, report.score) == ("F", 0)
    assert {"critical", "no_valid_https"} <= set(report.caps)
    by_id = {f.id: f for f in result.findings}
    assert all(by_id[i].severity == Severity.CRITICAL for i in report.fix_first)
    assert_all_explained(result)


async def test_hardened_site_is_clean() -> None:
    result = await lab_scan("corpsec-lab-good.com")
    assert result.status == ScanStatus.COMPLETED, [r for r in result.check_runs if r.detail]
    assert {cid for cid, sev in problems(result) if sev != Severity.INFO} == set()
    assert len([f for f in result.findings if f.severity == Severity.PASS]) >= 35
    report = lab_grade(result)
    assert (report.letter, report.score, report.fix_first) == ("A+", 100, [])
    assert_all_explained(result)
