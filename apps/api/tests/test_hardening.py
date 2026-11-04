"""M5: rate limits, client IP, sensitive targets, opt-out, redaction, sharing (spec §10)."""

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import ShareLink
from corpsec_api.mailer import MemoryMailer
from corpsec_api.scans import execute_scan
from corpsec_api.settings import Settings
from corpsec_scanner import load_checks
from corpsec_scanner.models import utcnow

from .conftest import (  # noqa: F401
    WEB_URL,
    FakeDns,
    FakeQueue,
    mock_options,
    pytestmark,
    sign_in,
)

LEAKY_ENV = b"APP_KEY=base64:abcdefghijkl\nDB_PASSWORD=supersecret123\n"


def leaky_site(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/.env":
        return httpx.Response(200, content=LEAKY_ENV)
    if req.url.path == "/":
        return httpx.Response(200, text="<html>hi</html>", headers={"content-type": "text/html"})
    return httpx.Response(404, text="nope")


def exposure_checks() -> list[Any]:
    wanted = {"CONN-001", "CRAWL-001", "EXP-001", "EXP-002"}
    return [c for c in load_checks() if c.id in wanted]


async def scan_of(client: httpx.AsyncClient, target: str, **headers: str) -> httpx.Response:
    return await client.post("/v1/scans", json={"target": target}, headers=headers)


async def test_anonymous_rate_limit_per_ip(client: httpx.AsyncClient) -> None:
    for i in range(5):
        assert (await scan_of(client, f"site{i}.az")).status_code == 202
    r = await scan_of(client, "site6.az")
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0
    assert r.json()["title"].startswith("You've reached the limit for now.")
    # another visitor (behind the trusted proxy) has their own allowance
    r = await scan_of(client, "site7.az", **{"X-Forwarded-For": "203.0.113.9, 198.51.100.7"})
    assert r.status_code == 202


async def test_forwarded_for_ignored_from_untrusted_peers(
    app_factory: Callable[[], httpx.AsyncClient], settings: Settings
) -> None:
    settings.trusted_proxies = []  # the test client's 127.0.0.1 is no longer a trusted proxy
    async with app_factory() as client:
        for i in range(5):
            spoof = {"X-Forwarded-For": f"203.0.113.{i}"}
            assert (await scan_of(client, f"site{i}.az", **spoof)).status_code == 202
        r = await scan_of(client, "site9.az", **{"X-Forwarded-For": "203.0.113.200"})
        assert r.status_code == 429  # spoofed header didn't buy a fresh allowance


async def test_same_target_reuses_recent_scan(client: httpx.AsyncClient, queue: FakeQueue) -> None:
    first = (await scan_of(client, "bakery.az")).json()["id"]
    second = (await scan_of(client, "https://bakery.az/")).json()["id"]
    assert first == second and queue.enqueued == [first]


async def test_signed_in_daily_limit(
    client: httpx.AsyncClient, mailer: MemoryMailer, settings: Settings
) -> None:
    settings.user_scans_per_day = 2
    await sign_in(client, mailer, "leyla@bakery.az")
    assert (await scan_of(client, "a.az")).status_code == 202
    assert (await scan_of(client, "b.az")).status_code == 202
    assert (await scan_of(client, "c.az")).status_code == 429


async def test_sensitive_domains_need_verified_owner(client: httpx.AsyncClient) -> None:
    for target in ("portal.gov.uk", "army.mil", "e-gov.gov.az"):
        r = await scan_of(client, target)
        assert r.status_code == 403, target
        assert "verified owners" in r.json()["title"]
    assert (await scan_of(client, "governor.az")).status_code == 202  # just a word in the name


async def test_opt_out(client: httpx.AsyncClient, mailer: MemoryMailer, settings: Settings) -> None:
    info = (await client.get("/v1/optout/www.bakery.az")).json()
    assert info["domain"] == "bakery.az" and not info["opted_out"]
    assert info["txt_value"].startswith("corpsec-optout=")

    app = client._transport.app  # type: ignore[attr-defined]
    app.state.dns = FakeDns()
    r = await client.post("/v1/optout", json={"domain": "bakery.az"})
    assert r.status_code == 422

    app.state.dns = FakeDns({("bakery.az", "TXT"): [info["txt_value"]]})
    r = await client.post("/v1/optout", json={"domain": "bakery.az"})
    assert r.json()["opted_out"] is True

    r = await scan_of(client, "shop.bakery.az")
    assert r.status_code == 403 and "asked us not to check" in r.json()["title"]
    await sign_in(client, mailer, "leyla@bakery.az")
    site = (await client.post("/v1/sites", json={"domain": "bakery.az"})).json()
    assert (await client.post(f"/v1/sites/{site['id']}/scans")).status_code == 403


async def test_site_cap(client: httpx.AsyncClient, mailer: MemoryMailer) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    for d in ("a.az", "b.az", "c.az"):
        assert (await client.post("/v1/sites", json={"domain": d})).status_code == 201
    r = await client.post("/v1/sites", json={"domain": "d.az"})
    assert r.status_code == 403 and "up to 3 sites" in r.json()["title"]


async def test_anonymous_reports_hide_exposed_file_details(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    scan_id = (await scan_of(client, "bakery.az")).json()["id"]
    await execute_scan(sessions, scan_id, exposure_checks(), mock_options(leaky_site))
    body = (await client.get(f"/v1/scans/{scan_id}")).json()
    assert body["redacted"] is True
    [exp] = [f for f in body["findings"] if f["check_id"] == "EXP-002" and f["severity"] != "pass"]
    assert exp["dedupe_key"] == ""
    assert "supersecret" not in str(exp) and "/.env" not in str(exp["evidence"])
    assert exp["explanation"]["title"]  # still explains the problem and the fix
    passes = [f for f in body["findings"] if f["check_id"] == "EXP-001"]
    assert passes and passes[0]["severity"] == "pass"
    assert passes[0]["evidence"]["observed"] == ["/.git/HEAD"]  # passes aren't hidden


async def verified_site_scan(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
    verify: bool = True,
) -> dict[str, Any]:
    await sign_in(client, mailer, "leyla@bakery.az")
    site = (await client.post("/v1/sites", json={"domain": "bakery.az"})).json()
    if verify:
        queue.dns = FakeDns({("bakery.az", "TXT"): [site["instructions"]["txt_value"]]})
        await client.post(f"/v1/sites/{site['id']}/verify", json={"method": "dns"})
    scan = (await client.post(f"/v1/sites/{site['id']}/scans")).json()
    await execute_scan(sessions, scan["id"], exposure_checks(), mock_options(leaky_site))
    body: dict[str, Any] = (await client.get(f"/v1/scans/{scan['id']}")).json()
    return body


async def test_verified_owner_sees_full_evidence(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    body = await verified_site_scan(client, mailer, queue, sessions)
    assert body["redacted"] is False and body["can_act"] is True
    [exp] = [f for f in body["findings"] if f["check_id"] == "EXP-002" and f["severity"] != "pass"]
    assert exp["dedupe_key"] == "/.env"
    excerpt = exp["evidence"]["response"]["body_excerpt"]
    assert "DB_PASSWORD=su**********23" in excerpt  # secrets stay masked even for owners


async def test_unverified_owner_still_redacted(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    body = await verified_site_scan(client, mailer, queue, sessions, verify=False)
    assert body["redacted"] is True


async def test_share_with_it_person(
    app_factory: Callable[[], httpx.AsyncClient],
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with app_factory() as owner, app_factory() as it_person, app_factory() as stranger:
        body = await verified_site_scan(owner, mailer, queue, sessions)
        r = await owner.post(
            f"/v1/scans/{body['id']}/share",
            json={"email": "IT@helpdesk.az", "note": "Can you fix the .env?"},
        )
        assert r.status_code == 202
        mail = mailer.sent[-1]
        assert mail.to == "it@helpdesk.az"
        assert "leyla@bakery.az shared" in mail.text and "Can you fix the .env?" in mail.text
        link = next(x for x in mail.text.splitlines() if "/scan/" in x)
        assert link.startswith(f"{WEB_URL}/scan/{body['id']}?share=")
        token = link.split("share=")[1]

        shared = (await it_person.get(f"/v1/scans/{body['id']}", params={"share": token})).json()
        assert shared["redacted"] is False and shared["can_act"] is False
        assert (await it_person.get(f"/v1/scans/{body['id']}")).status_code == 404
        r = await it_person.get(f"/v1/scans/{body['id']}", params={"share": "wrong"})
        assert r.status_code == 404

        await sign_in(stranger, mailer, "eve@evil.az")
        r = await stranger.post(f"/v1/scans/{body['id']}/share", json={"email": "x@evil.az"})
        assert r.status_code == 404

        async with sessions() as s:
            await s.execute(update(ShareLink).values(expires_at=utcnow() - timedelta(seconds=1)))
            await s.commit()
        r = await it_person.get(f"/v1/scans/{body['id']}", params={"share": token})
        assert r.status_code == 404


async def test_api_security_headers(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["referrer-policy"] == "no-referrer"


def test_production_refuses_development_defaults() -> None:
    dev = Settings(environment="production", smtp_host="mailpit")
    with pytest.raises(RuntimeError) as err:
        dev.check_production()
    message = str(err.value)
    for name in ("SECRET_KEY", "WEB_URL", "SMTP_HOST", "DATABASE_URL"):
        assert name in message

    ok = Settings(
        environment="production",
        secret_key="x" * 40,
        web_url="https://corpsec.example",
        smtp_host="smtp.example",
        database_url="postgresql+asyncpg://corpsec:s3cret@postgres:5432/corpsec",
    )
    ok.check_production()  # no exception
    # development never refuses
    Settings().check_production()


def test_scanner_user_agent_points_at_this_deployment() -> None:
    from corpsec_api.worker import scan_options
    from corpsec_scanner.intel import EMPTY_SNAPSHOT

    class Intel:
        def get(self) -> object:
            return EMPTY_SNAPSHOT

    ctx = {"settings": Settings(web_url="https://scan.example/"), "intel": Intel()}
    options = scan_options(ctx)
    assert options.http_policy.user_agent == "CorpSEC/0.1 (+https://scan.example/bot)"
    assert options.external_http_policy.user_agent == options.http_policy.user_agent
    assert options.external_http_policy.max_requests == 10
