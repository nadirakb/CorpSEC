from collections.abc import Callable
from typing import Any

import pytest

from corpsec_checks.tls._cert import explain_verify_error
from corpsec_checks.tls.tls_001 import CertificateValid
from corpsec_checks.tls.tls_002 import CertificateExpiry
from corpsec_checks.tls.tls_003 import LegacyTlsDisabled
from corpsec_checks.tls.tls_004 import ModernTlsSupported
from corpsec_checks.tls.tls_005 import NoWeakCiphers
from corpsec_checks.tls.tls_006 import ForwardSecrecy
from corpsec_checks.tls.tls_008 import CertificateKeyStrength
from corpsec_scanner import Severity
from corpsec_scanner.testing import tls_server
from corpsec_scanner.tls import TlsProber

from .conftest import severities

Scan = Callable[..., Any]
ALL = [
    CertificateValid(), CertificateExpiry(), LegacyTlsDisabled(), ModernTlsSupported(),
    NoWeakCiphers(), ForwardSecrecy(), CertificateKeyStrength(),
]  # fmt: skip


async def test_healthy_tls_server_passes_everything(scan: Scan) -> None:
    async with tls_server(["example.com"]) as (port, net):
        result = await scan(ALL, tls=TlsProber(net, port=port))
    assert {f.check_id: f.severity for f in result.findings} == {c.id: Severity.PASS for c in ALL}
    tls001 = next(f for f in result.findings if f.check_id == "TLS-001")
    assert tls001.evidence.observed["certificate"]["names"] == ["example.com"]


async def test_untrusted_expiring_weak_key(scan: Scan) -> None:
    async with tls_server(["example.com"], trusted=False, days_valid=2, key="rsa1024") as (
        port,
        net,
    ):
        result = await scan(ALL, tls=TlsProber(net, port=port))
    assert severities(result, "TLS-001") == [Severity.CRITICAL]
    assert severities(result, "TLS-002") == [Severity.CRITICAL]
    assert severities(result, "TLS-008") == [Severity.HIGH]
    tls001 = next(f for f in result.findings if f.check_id == "TLS-001")
    assert tls001.evidence.observed["problem"] == "weak_key"


async def test_self_signed(scan: Scan) -> None:
    async with tls_server(["example.com"], trusted=False) as (port, net):
        result = await scan([CertificateValid()], tls=TlsProber(net, port=port))
    [f] = result.findings
    assert (f.severity, f.evidence.observed["problem"]) == (Severity.CRITICAL, "self_signed")


async def test_no_https_skips_dependents(scan: Scan) -> None:
    from corpsec_scanner.testing import loopback_net

    result = await scan(ALL, tls=TlsProber(loopback_net(), port=1))  # nothing listens on :1
    assert result.findings == []
    statuses = {r.check_id: r.status.value for r in result.check_runs}
    assert statuses["TLS-001"] == "ok"
    assert statuses["TLS-002"] == "skipped"


@pytest.mark.parametrize(
    ("message", "code"),
    [
        ("certificate has expired", "expired"),
        ("Hostname mismatch, certificate is not valid for 'x'.", "hostname_mismatch"),
        ("self-signed certificate", "self_signed"),
        ("unable to get local issuer certificate", "untrusted_or_incomplete_chain"),
        ("EE_KEY_TOO_SMALL", "weak_key"),
        ("EE certificate key too weak", "weak_key"),
    ],
)
def test_explain_verify_error(message: str, code: str) -> None:
    assert explain_verify_error(message) == code
