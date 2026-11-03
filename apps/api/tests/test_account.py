from datetime import timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import AuditLog, LoginToken, Scan, Site, User
from corpsec_api.digest import send_weekly_digests
from corpsec_api.mailer import MemoryMailer
from corpsec_api.scans import execute_scan
from corpsec_api.settings import Settings
from corpsec_scanner.models import utcnow

from .conftest import FakeDns, FakeQueue, http_checks, mock_options, pytestmark, sign_in  # noqa: F401


def site_ok(req: httpx.Request) -> httpx.Response:
    if req.url.scheme == "http":
        return httpx.Response(301, headers={"location": f"https://{req.url.host}/"})
    return httpx.Response(200, text="hi")


async def site_with_scan(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
    email: str = "leyla@bakery.az",
) -> tuple[str, str]:
    await sign_in(client, mailer, email)
    site = (await client.post("/v1/sites", json={"domain": "bakery.az"})).json()
    dns = FakeDns({("bakery.az", "TXT"): [site["instructions"]["txt_value"]]})
    queue.dns = dns
    r = await client.post(f"/v1/sites/{site['id']}/verify", json={"method": "dns"})
    assert r.json()["verified"]
    r = await client.post(f"/v1/sites/{site['id']}/scans")
    assert r.status_code == 202, r.text
    scan_id: str = r.json()["id"]
    await execute_scan(sessions, scan_id, http_checks(), mock_options(site_ok, dns))
    site_id: str = site["id"]
    return site_id, scan_id


async def test_export_contains_sites_scans_and_activity(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    _, scan_id = await site_with_scan(client, mailer, queue, sessions)
    r = await client.get("/v1/me/export")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    data = r.json()
    assert data["account"]["email"] == "leyla@bakery.az"
    [site] = data["sites"]
    assert site["domain"] == "bakery.az" and site["verified_at"]
    [scan] = site["scans"]
    assert scan["id"] == scan_id and scan["findings"]
    assert {a["action"] for a in data["activity_log"]} >= {"auth.login", "site.verify.dns"}


async def test_export_needs_sign_in(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/me/export")).status_code == 401


async def test_digest_preference(client: httpx.AsyncClient, mailer: MemoryMailer) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    assert (await client.get("/v1/me")).json()["weekly_digest"] is False
    r = await client.patch("/v1/me", json={"weekly_digest": True})
    assert r.status_code == 200 and r.json()["weekly_digest"] is True
    assert (await client.get("/v1/me")).json()["weekly_digest"] is True


async def test_delete_account_removes_everything(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    site_id, scan_id = await site_with_scan(client, mailer, queue, sessions)
    user_id = (await client.get("/v1/me")).json()["id"]

    r = await client.request("DELETE", "/v1/me", json={"confirm_email": "wrong@bakery.az"})
    assert r.status_code == 422
    r = await client.request("DELETE", "/v1/me", json={"confirm_email": "Leyla@Bakery.az "})
    assert r.status_code == 204
    assert "corpsec_session" in r.headers.get("set-cookie", "")

    assert (await client.get("/v1/me")).status_code == 401
    # The old report link no longer works: scans of the user's sites are gone, not orphaned.
    assert (await client.get(f"/v1/scans/{scan_id}")).status_code == 404
    async with sessions() as s:
        assert await s.get(User, user_id) is None
        assert await s.get(Site, site_id) is None
        assert await s.get(Scan, scan_id) is None
        tokens = await s.scalar(
            select(func.count())
            .select_from(LoginToken)
            .where(LoginToken.email == "leyla@bakery.az")
        )
        assert tokens == 0
        actions = (await s.scalars(select(AuditLog.action).where(AuditLog.target == user_id))).all()
        assert "account.delete" in actions


async def test_weekly_digest_goes_to_opted_in_users_once_a_week(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    await site_with_scan(client, mailer, queue, sessions)
    mailer.sent.clear()

    # Not opted in: nothing.
    assert await send_weekly_digests(sessions, mailer, settings) == 0

    await client.patch("/v1/me", json={"weekly_digest": True})
    now = utcnow()
    assert await send_weekly_digests(sessions, mailer, settings, now=now) == 1
    [mail] = mailer.sent
    assert mail.to == "leyla@bakery.az"
    assert "bakery.az: grade A" in mail.text
    assert f"{settings.web_url}/account" in mail.text

    # Same week: no second email. Next week: yes.
    assert await send_weekly_digests(sessions, mailer, settings, now=now + timedelta(days=1)) == 0
    assert await send_weekly_digests(sessions, mailer, settings, now=now + timedelta(days=7)) == 1
