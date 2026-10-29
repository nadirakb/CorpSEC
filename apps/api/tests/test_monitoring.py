"""Spec §16 M4 exit criterion: a verified site gets weekly scans and an alert on regression."""

from collections.abc import Callable
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import Alert, FindingRow, Scan, Site
from corpsec_api.mailer import MemoryMailer
from corpsec_api.monitoring import (
    post_scan_alerts,
    run_light_checks,
    schedule_due_scans,
)
from corpsec_api.scans import execute_scan
from corpsec_api.settings import Settings
from corpsec_scanner import ScanOptions, load_checks
from corpsec_scanner.models import utcnow
from corpsec_scanner.testing import tls_server
from corpsec_scanner.tls import TlsProber

from .conftest import FakeDns, FakeQueue, http_checks, mock_options, pytestmark, sign_in  # noqa: F401

Handler = Callable[[httpx.Request], httpx.Response]


def secure_site(req: httpx.Request) -> httpx.Response:
    if req.url.scheme == "http":
        return httpx.Response(301, headers={"location": f"https://{req.url.host}/"})
    return httpx.Response(200, text="hi")


def regressed_site(req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="hi")  # stopped redirecting to HTTPS


async def verified_site(
    client: httpx.AsyncClient, mailer: MemoryMailer, queue: FakeQueue
) -> tuple[str, FakeDns]:
    await sign_in(client, mailer, "leyla@bakery.az")
    site = (await client.post("/v1/sites", json={"domain": "bakery.az"})).json()
    dns = FakeDns({("bakery.az", "TXT"): [site["instructions"]["txt_value"]]})
    queue.dns = dns
    assert (await client.post(f"/v1/sites/{site['id']}/verify", json={"method": "dns"})).json()[
        "verified"
    ]
    site_id: str = site["id"]
    return site_id, dns


async def run_due(
    sessions: async_sessionmaker[AsyncSession],
    mailer: MemoryMailer,
    settings: Settings,
    handler: Handler,
    dns: FakeDns,
    when: object,
) -> list[str]:
    """One tick of the scheduler, then run the scans it started like the worker would."""
    started: list[str] = []

    async def enqueue(scan_id: str) -> None:
        started.append(scan_id)

    await schedule_due_scans(
        sessions,
        enqueue,
        mailer,
        settings,
        mock_options(handler, dns),
        now=when,  # type: ignore[arg-type]
    )
    for scan_id in started:
        await execute_scan(sessions, scan_id, http_checks(), mock_options(handler, dns))
        await post_scan_alerts(sessions, scan_id, mailer, settings, now=when)  # type: ignore[arg-type]
    return started


async def test_weekly_scan_and_regression_alert(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    site_id, dns = await verified_site(client, mailer, queue)
    mailer.sent.clear()

    # Not due yet: nothing happens.
    assert await run_due(sessions, mailer, settings, secure_site, dns, utcnow()) == []

    # First weekly scan: baseline, no alert.
    week1 = utcnow() + timedelta(days=2)
    assert len(await run_due(sessions, mailer, settings, secure_site, dns, week1)) == 1
    assert mailer.sent == []
    async with sessions() as s:
        site = await s.get(Site, site_id)
        assert site and site.next_scan_at and site.next_scan_at - week1 == timedelta(days=7)

    # A week later the site regressed: new scan, grade drops, owner is emailed.
    week2 = week1 + timedelta(days=7)
    [second] = await run_due(sessions, mailer, settings, regressed_site, dns, week2)
    [mail] = mailer.sent
    assert mail.to == "leyla@bakery.az"
    assert mail.subject == "bakery.az: security grade dropped from A to C"
    assert f"{settings.web_url}/scan/{second}" in mail.text

    # The same problem next week doesn't email again.
    week3 = week2 + timedelta(days=7)
    await run_due(sessions, mailer, settings, regressed_site, dns, week3)
    assert len(mailer.sent) == 1

    async with sessions() as s:
        scans = (await s.scalars(select(Scan).where(Scan.site_id == site_id))).all()
        assert len(scans) == 3
        alerts = (await s.scalars(select(Alert).where(Alert.site_id == site_id))).all()
        assert [a.kind for a in alerts] == ["grade_drop"]
        # problem history survives re-scans (spec §8.1)
        conn = (
            await s.scalars(
                select(FindingRow)
                .where(FindingRow.site_id == site_id, FindingRow.check_id == "CONN-002")
                .order_by(FindingRow.created_at)
            )
        ).all()
        assert len({f.first_seen for f in conn}) == 1

    detail = (await client.get(f"/v1/sites/{site_id}")).json()
    assert [h["grade"] for h in detail["history"]] == ["C", "C", "A"]
    assert detail["previous_grade"] == "C" and detail["alerts"][0]["kind"] == "grade_drop"


async def test_monitoring_pauses_when_ownership_is_lost(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    site_id, _ = await verified_site(client, mailer, queue)
    mailer.sent.clear()
    dns = FakeDns()  # the TXT record was removed (fresh resolver: no cached answer)

    when = utcnow() + timedelta(days=2)
    assert await run_due(sessions, mailer, settings, secure_site, dns, when) == []
    assert mailer.sent == []  # one failure is tolerated
    when += timedelta(days=1, minutes=1)
    assert await run_due(sessions, mailer, settings, secure_site, dns, when) == []
    [mail] = mailer.sent
    assert mail.subject == "bakery.az: monitoring paused"
    detail = (await client.get(f"/v1/sites/{site_id}")).json()
    assert not detail["monitoring_enabled"]
    assert detail["monitoring_paused_reason"] == "verification_lost"


async def test_daily_checks_alert_on_expiring_certificate_and_downtime(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    await verified_site(client, mailer, queue)
    mailer.sent.clear()
    when = utcnow() + timedelta(hours=2)
    async with tls_server(["bakery.az"], days_valid=6) as (port, net):
        options = ScanOptions(
            preflight=False,
            net=net,
            tls=TlsProber(net, port=port),
            transport_factory=lambda verify: httpx.MockTransport(secure_site),
            dns=FakeDns(),
        )
        assert (
            await run_light_checks(sessions, load_checks(), mailer, settings, options, now=when)
            == 1
        )
    [mail] = mailer.sent
    assert mail.subject == "bakery.az: your security certificate expires in 5 days"

    def down(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    options = ScanOptions(
        preflight=False, transport_factory=lambda verify: httpx.MockTransport(down), dns=FakeDns()
    )
    when += timedelta(days=1, minutes=1)
    await run_light_checks(sessions, load_checks(), mailer, settings, options, now=when)
    assert mailer.sent[-1].subject == "bakery.az: we couldn't reach your website"
