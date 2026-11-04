from datetime import timedelta

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api import events
from corpsec_api.db import AnalyticsEvent, Scan
from corpsec_api.insights_keys import site_key
from corpsec_api.mailer import MemoryMailer
from corpsec_api.scans import execute_scan
from corpsec_api.settings import DEV_SECRET
from corpsec_scanner.models import utcnow

from .conftest import FakeDns, FakeQueue, http_checks, mock_options, pytestmark, sign_in  # noqa: F401


def secure(req: httpx.Request) -> httpx.Response:
    if req.url.scheme == "http":
        return httpx.Response(301, headers={"location": f"https://{req.url.host}/"})
    return httpx.Response(200, text="hi")


def insecure(req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="hi")


async def add_site(client: httpx.AsyncClient, queue: FakeQueue, domain: str) -> tuple[str, FakeDns]:
    site = (await client.post("/v1/sites", json={"domain": domain})).json()
    dns = FakeDns({(domain, "TXT"): [site["instructions"]["txt_value"]]})
    queue.dns = dns
    await client.post(f"/v1/sites/{site['id']}/verify", json={"method": "dns"})
    site_id: str = site["id"]
    return site_id, dns


async def scan(
    client: httpx.AsyncClient,
    sessions: async_sessionmaker[AsyncSession],
    site_id: str,
    dns: FakeDns,
    handler: object,
) -> str:
    scan_id: str = (await client.post(f"/v1/sites/{site_id}/scans")).json()["id"]
    await execute_scan(sessions, scan_id, http_checks(), mock_options(handler, dns))  # type: ignore[arg-type]
    return scan_id


async def backdate(sessions: async_sessionmaker[AsyncSession], scan_id: str, days: int) -> None:
    async with sessions() as s:
        when = utcnow() - timedelta(days=days)
        await s.execute(
            update(Scan).where(Scan.id == scan_id).values(finished_at=when, created_at=when)
        )
        await s.commit()


async def test_trends_and_time_to_fix(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    site_id, dns = await add_site(client, queue, "bakery.az")
    first = await scan(client, sessions, site_id, dns, insecure)
    await backdate(sessions, first, 3)
    await scan(client, sessions, site_id, dns, secure)

    t = (await client.get(f"/v1/sites/{site_id}/trends")).json()
    assert [p["grade"] for p in t["points"]] == ["C", "A"]
    assert [p["open_problems"] for p in t["points"]] == [1, 0]
    assert t["points"][0]["stages"]["connection"] == "C"
    assert t["fixed_count"] == 1 and t["open_now"] == 0
    assert 0 <= t["median_days_to_fix"] <= 3.1  # first seen 3 days ago, gone in today's scan

    # someone else's site is not visible
    async with httpx.AsyncClient(transport=client._transport, base_url="https://test") as other:
        await sign_in(other, mailer, "someone@else.az")
        assert (await other.get(f"/v1/sites/{site_id}/trends")).status_code == 404


async def test_benchmark_needs_enough_sites_and_counts_each_once(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    site_id, dns = await add_site(client, queue, "bakery.az")
    await scan(client, sessions, site_id, dns, secure)  # score 100
    assert (await client.get(f"/v1/sites/{site_id}/benchmark")).json()["better_than"] is None

    async with sessions() as s:
        for i in range(30):
            score = 50 if i < 20 else 100  # 20 lower, 10 equal
            s.add(
                AnalyticsEvent(
                    name=events.SCAN_FINISHED, props={"site_key": f"k{i}", "score": score}
                )
            )
        # an older, better scan of k0 must not count: only each site's latest scan does
        s.add(
            AnalyticsEvent(
                name=events.SCAN_FINISHED,
                at=utcnow() - timedelta(days=10),
                props={"site_key": "k0", "score": 100},
            )
        )
        await s.commit()
    b = (await client.get(f"/v1/sites/{site_id}/benchmark")).json()
    assert b["sample"] == 30
    assert b["better_than"] == round((20 + 0.5 * 10) / 30, 3)

    # the site's own scans are never compared with itself
    async with sessions() as s:
        own = await s.scalar(
            select(AnalyticsEvent)
            .where(AnalyticsEvent.name == events.SCAN_FINISHED)
            .order_by(AnalyticsEvent.id)
            .limit(1)
        )
        assert own is not None and own.props["site_key"] == site_key(DEV_SECRET, "bakery.az")


async def test_monthly_report(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    site_id, dns = await add_site(client, queue, "bakery.az")
    await scan(client, sessions, site_id, dns, insecure)
    await scan(client, sessions, site_id, dns, secure)
    month = utcnow().strftime("%Y-%m")
    r = (await client.get(f"/v1/sites/{site_id}/monthly?month={month}")).json()
    assert r["scans"] == 2 and r["start_grade"] == "C" and r["end_grade"] == "A"
    assert [p["check_id"] for p in r["fixed"]] == ["CONN-002"]
    assert r["fixed"][0]["title"]
    assert r["open_at_end"] == [] and r["new"] == []
    bad = await client.get(f"/v1/sites/{site_id}/monthly?month=2026-13")
    assert bad.status_code == 422


async def test_portfolio_ranks_sites_and_problems(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    good, dns_good = await add_site(client, queue, "bakery.az")
    await scan(client, sessions, good, dns_good, secure)
    bad, dns_bad = await add_site(client, queue, "cafe.az")
    await scan(client, sessions, bad, dns_bad, insecure)
    p = (await client.get("/v1/portfolio")).json()
    assert [s["domain"] for s in p["sites"]] == ["cafe.az", "bakery.az"]  # worst first
    assert p["sites"][0]["open_by_severity"] == {"high": 1}
    assert p["open_serious"] == 1 and p["average_score"] is not None
    [item] = p["fix_first"]
    assert item["domain"] == "cafe.az" and item["check_id"] == "CONN-002" and item["title"]
