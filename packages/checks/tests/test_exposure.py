from collections.abc import Callable
from typing import Any

import httpx
import pytest

from corpsec_checks import CHECKS
from corpsec_checks._common import mask, redact
from corpsec_checks.connection.conn_001 import HttpsReachable
from corpsec_checks.connection.crawl_001 import Crawler
from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity

from .conftest import FakeSite, html

Scan = Callable[..., Any]
HOME = "https://example.com/"
EXP = [c() for c in CHECKS if c.id.startswith("EXP-")]

EXPOSED = {
    "/.git/HEAD": (b"ref: refs/heads/main\n", "EXP-001"),
    "/.env": (b"APP_KEY=base64:abcdefghijkl\nDB_PASSWORD=supersecret123\n", "EXP-002"),
    "/wp-config.php.bak": (b"<?php define('DB_PASSWORD', 'hunter22pass');", "EXP-003"),
    "/backup.sql": (b"-- MySQL dump 10.13\nCREATE TABLE users (", "EXP-004"),
    "/phpinfo.php": (b"<html><head><title>phpinfo()</title>", "EXP-005"),
    "/.DS_Store": (b"\x00\x00\x00\x01Bud1\x00\x00", "EXP-006"),
    "/server-status": (b"<h1>Apache Server Status for example.com</h1>", "EXP-007"),
    "/.hg/requires": (b"revlogv1\nstore\nfncache\n", "EXP-008"),
    "/wp-content/debug.log": (b"[29-Oct-2026 10:00:00 UTC] PHP Warning: x", "EXP-009"),
}


def test_probe_count_within_spec_limit() -> None:
    assert sum(len(c.paths) for c in EXP if isinstance(c, ExposedFileCheck)) <= 25


async def test_every_exposed_file_is_found(scan: Scan) -> None:
    routes: dict[str, Any] = {HOME: html("home")}
    for path, (body, _) in EXPOSED.items():
        routes[f"https://example.com{path}"] = httpx.Response(200, content=body)
    result = await scan([HttpsReachable(), Crawler(), *EXP], FakeSite(routes))
    found = {(f.check_id, f.dedupe_key) for f in result.findings if f.severity != Severity.PASS}
    assert found == {(cid, path) for path, (_, cid) in EXPOSED.items()}


async def test_secrets_are_masked_in_evidence(scan: Scan) -> None:
    routes = {
        HOME: html("home"),
        "https://example.com/.env": httpx.Response(200, content=EXPOSED["/.env"][0]),
    }
    result = await scan([HttpsReachable(), Crawler(), *EXP], FakeSite(routes))
    [env] = [f for f in result.findings if f.check_id == "EXP-002" and f.dedupe_key == "/.env"]
    excerpt = env.evidence.response["body_excerpt"]
    assert "supersecret123" not in excerpt
    assert "DB_PASSWORD=su**********23" in excerpt


async def test_soft_404_sites_produce_nothing(scan: Scan) -> None:
    page = html("<html><body>Welcome! Page not found, here is our homepage. ref: refs/x</body>")

    def everything_200(req: httpx.Request) -> httpx.Response:
        return page

    site = FakeSite()
    site.handler = everything_200  # type: ignore[method-assign]
    result = await scan([HttpsReachable(), Crawler(), *EXP], site)
    assert all(f.severity == Severity.PASS for f in result.findings)


async def test_html_error_pages_dont_match(scan: Scan) -> None:
    routes = {
        HOME: html("home"),
        "https://example.com/.env": html("<html><body>APP=1\nDB=2</body></html>"),
    }
    result = await scan([HttpsReachable(), Crawler(), *EXP], FakeSite(routes))
    assert all(f.severity == Severity.PASS for f in result.findings)


@pytest.mark.parametrize(("value", "masked"), [("supersecret", "su*******et"), ("abc", "***")])
def test_mask(value: str, masked: str) -> None:
    assert mask(value) == masked


def test_redact_php_define() -> None:
    assert "hunter22pass" not in redact("define('DB_PASSWORD', 'hunter22pass');")
