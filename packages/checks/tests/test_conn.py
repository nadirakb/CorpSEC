from collections.abc import Callable

import httpx
import pytest

from corpsec_checks import CHECKS
from corpsec_checks.connection.conn_001 import HttpsReachable
from corpsec_checks.connection.conn_002 import HttpRedirectsToHttps
from corpsec_scanner import ScanOptions, Severity, load_checks, run_scan

Handler = Callable[[httpx.Request], httpx.Response]
MockOptions = Callable[[Handler], ScanOptions]


def test_catalog_registered_via_entry_point() -> None:
    assert {c.id for c in load_checks()} == {c.id for c in CHECKS}


async def test_conn_001_pass(mock_options: MockOptions) -> None:
    result = await run_scan(
        "example.com", [HttpsReachable()], options=mock_options(lambda r: httpx.Response(200))
    )
    [finding] = result.findings
    assert finding.severity == Severity.PASS
    assert finding.evidence.response == {"status": 200, "headers": {}}


async def test_conn_001_unreachable(mock_options: MockOptions) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    result = await run_scan("example.com", [HttpsReachable()], options=mock_options(handler))
    [finding] = result.findings
    assert finding.severity == Severity.CRITICAL
    assert "connection refused" in finding.evidence.observed


@pytest.mark.parametrize(
    ("location", "severity"),
    [
        ("https://example.com/", Severity.PASS),
        ("https://www.example.com/", Severity.PASS),
        ("https://other-site.net/", Severity.PASS),  # leaves scope, but to HTTPS
        ("http://www.example.com/", Severity.HIGH),
        (None, Severity.HIGH),
    ],
)
async def test_conn_002(
    mock_options: MockOptions, location: str | None, severity: Severity
) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.scheme == "http" and req.url.host == "example.com" and location:
            return httpx.Response(301, headers={"location": location})
        return httpx.Response(200)

    result = await run_scan("example.com", [HttpRedirectsToHttps()], options=mock_options(handler))
    [finding] = result.findings
    assert finding.severity == severity


async def test_conn_002_port_80_closed(mock_options: MockOptions) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.scheme == "http":
            raise httpx.ConnectError("refused")
        return httpx.Response(200)

    result = await run_scan("example.com", [HttpRedirectsToHttps()], options=mock_options(handler))
    assert result.findings[0].severity == Severity.PASS
