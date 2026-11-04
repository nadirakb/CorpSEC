from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api import events
from corpsec_api.db import AnalyticsEvent, FindingFeedback, FindingRow
from corpsec_api.mailer import MemoryMailer
from corpsec_api.scans import execute_scan
from corpsec_api.settings import Settings
from corpsec_scanner.models import utcnow

from .conftest import FakeDns, FakeQueue, http_checks, mock_options, pytestmark, sign_in  # noqa: F401


def secure(req: httpx.Request) -> httpx.Response:
    if req.url.scheme == "http":
        return httpx.Response(301, headers={"location": f"https://{req.url.host}/"})
    return httpx.Response(200, text="hi")


def insecure(req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="hi")  # no redirect to HTTPS: CONN-002 problem


async def all_events(sessions: async_sessionmaker[AsyncSession]) -> list[AnalyticsEvent]:
    async with sessions() as s:
        return list((await s.scalars(select(AnalyticsEvent).order_by(AnalyticsEvent.id))).all())


def test_page_template_hides_ids() -> None:
    assert events.page_template("/scan/scn_abc123?share=x") == "/scan/[id]"
    assert events.page_template("/sites/sit_9/") == "/sites/[id]/"
    assert events.page_template("/auth/verify/AbCdEfGhIjKlMnOpQrStUvWx") == "/auth/verify/[id]"
    assert events.page_template("") == "/"


def test_visitor_id_rotates_daily_and_never_contains_the_ip() -> None:
    a = events.visitor_id("k", "203.0.113.9", "UA", "2026-11-04")
    assert a and len(a) == 16 and "203" not in a
    assert a == events.visitor_id("k", "203.0.113.9", "UA", "2026-11-04")
    assert a != events.visitor_id("k", "203.0.113.9", "UA", "2026-11-05")
    assert events.visitor_id("k", None, "UA", "2026-11-04") is None


async def test_scan_lifecycle_is_recorded(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    r = await client.post("/v1/scans", json={"target": "bakery.az"})
    await execute_scan(sessions, r.json()["id"], http_checks(), mock_options(insecure))
    started, finished = await all_events(sessions)
    assert started.name == events.SCAN_STARTED and started.props == {"kind": "anonymous"}
    assert started.visitor and started.user_id is None
    assert finished.name == events.SCAN_FINISHED
    assert finished.props["kind"] == "anonymous" and finished.props["status"] == "completed"
    assert finished.props["problem_checks"] == ["CONN-002"] and finished.props["problems"] == 1


async def test_global_privacy_control_is_respected(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await client.post("/v1/scans", json={"target": "bakery.az"}, headers={"Sec-GPC": "1"})
    r = await client.post("/v1/events", json={"name": "page.view"}, headers={"Sec-GPC": "1"})
    assert r.status_code == 204
    [started] = await all_events(sessions)  # the scan is counted, the visitor isn't
    assert started.visitor is None


async def test_client_events(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    r = await client.post("/v1/events", json={"name": "page.view", "path": "/scan/scn_x1?a=1"})
    assert r.status_code == 204
    r = await client.post(
        "/v1/events",
        json={"name": "report.fix_opened", "path": "/scan/scn_x1", "check_id": "TLS-003"},
    )
    assert r.status_code == 204
    assert (await client.post("/v1/events", json={"name": "made.up"})).status_code == 422
    view, fix = await all_events(sessions)
    assert view.props == {"path": "/scan/[id]"}
    assert fix.props == {"path": "/scan/[id]", "check_id": "TLS-003"}


async def test_feedback_is_stored_with_evidence_and_listed_for_admins(
    client: httpx.AsyncClient,
    app_factory: Callable[[], httpx.AsyncClient],
    mailer: MemoryMailer,
    sessions: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    r = await client.post("/v1/scans", json={"target": "bakery.az"})
    scan_id = r.json()["id"]
    await execute_scan(sessions, scan_id, http_checks(), mock_options(insecure))
    async with sessions() as s:
        row = await s.scalar(select(FindingRow).where(FindingRow.check_id == "CONN-002"))
        assert row is not None
    r = await client.post(
        f"/v1/findings/{row.id}/feedback",
        json={"reason": "false_positive", "note": "We redirect at the load balancer."},
    )
    assert r.status_code == 202
    async with sessions() as s:
        [fb] = (await s.scalars(select(FindingFeedback))).all()
        assert fb.check_id == "CONN-002" and fb.evidence and not fb.resolved

    # Only admins see it, and to everyone else the page doesn't exist.
    async with app_factory() as other:
        await sign_in(other, mailer, "someone@bakery.az")
        assert (await other.get("/v1/admin/feedback")).status_code == 404
        assert (await other.get("/v1/me")).json()["is_admin"] is False
    settings.admin_emails = ["Boss@CorpSEC.app"]
    async with app_factory() as admin:
        await sign_in(admin, mailer, "boss@corpsec.app")
        assert (await admin.get("/v1/me")).json()["is_admin"] is True
        [item] = (await admin.get("/v1/admin/feedback")).json()
        assert item["note"] == "We redirect at the load balancer."
        assert (await admin.post(f"/v1/admin/feedback/{item['id']}/resolve")).json()["resolved"]
        assert (await admin.get("/v1/admin/feedback")).json() == []


async def seed(
    sessions: async_sessionmaker[AsyncSession], rows: list[tuple[str, dict[str, Any]]]
) -> None:
    async with sessions() as s:
        for name, kw in rows:
            s.add(AnalyticsEvent(name=name, **kw))
        await s.commit()


async def test_overview_success_metrics(
    app_factory: Callable[[], httpx.AsyncClient],
    mailer: MemoryMailer,
    sessions: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    now = utcnow()
    old = now - timedelta(days=20)
    anon = {"kind": "anonymous"}
    fixed = events.FINDING_FIXED
    tls = {"check_id": "TLS-003"}

    def finished(
        problems: int, status: str, secs: int, checks: list[str], failed: list[str]
    ) -> Any:
        props = {"problems": problems, "status": status, "duration_s": secs,
                 "problem_checks": checks, "failed_checks": failed}  # fmt: skip
        return (events.SCAN_FINISHED, {"props": props})

    await seed(
        sessions,
        [
            # 4 anonymous scanners, 1 signs up -> activation 25 %
            *[(events.SCAN_STARTED, {"visitor": f"v{i}", "props": anon, "at": old})
              for i in range(4)],
            (events.SCAN_STARTED, {"visitor": "v0", "props": anon, "at": old}),  # again
            # two old accounts; one fixed something within 14 days -> action 50 %
            (events.ACCOUNT_CREATED, {"user_id": "u1", "props": {}, "at": old}),
            (events.ACCOUNT_CREATED, {"user_id": "u2", "props": {}, "at": old}),
            (fixed, {"user_id": "u1", "props": tls, "at": old + timedelta(days=3)}),
            (fixed, {"user_id": "u2", "props": tls, "at": old + timedelta(days=15)}),
            # 50 problems shown, 1 reported as a false alarm -> 2 %
            finished(30, "completed", 20, ["TLS-003"], ["DNS-005"]),
            finished(20, "partial", 40, ["TLS-003", "HDR-001"], []),
            (events.FINDING_REPORTED, {"props": {**tls, "reason": "false_positive"}}),
            (events.FINDING_REPORTED, {"props": {**tls, "reason": "unclear"}}),
        ],
    )  # fmt: skip
    settings.admin_emails = ["boss@corpsec.app"]
    async with app_factory() as admin:
        await sign_in(admin, mailer, "boss@corpsec.app")  # adds a 3rd, too-new account
        data = (await admin.get("/v1/admin/overview?days=30")).json()
    m = data["metrics"]
    assert m["activation"]["anonymous_scanners"] == 4 and m["activation"]["signups"] == 3
    assert m["action"] == {"value": 0.5, "target": 0.3, "acted": 1, "cohort": 2}
    assert m["false_positive"]["value"] == 0.02 and m["false_positive"]["problems_shown"] == 50
    scans = data["scans"]
    assert scans["common_problems"][0] == {"check_id": "TLS-003", "count": 2}
    assert scans["failing_checks"] == [{"check_id": "DNS-005", "count": 1}]
    assert scans["avg_seconds"] == 30.0
    assert sum(sum(v for k, v in d.items() if k != "day") for d in scans["per_day"]) == 2
    assert data["funnel"][1] == {"step": "Started a check", "visitors": 4}
    assert data["live"]["queued"] == 0


async def test_prometheus_endpoint_needs_its_token(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    assert (await client.get("/metrics")).status_code == 404  # off without a token
    settings.metrics_token = "t0ken"
    assert (
        await client.get("/metrics", headers={"Authorization": "Bearer nope"})
    ).status_code == 404
    r = await client.get("/metrics", headers={"Authorization": "Bearer t0ken"})
    assert r.status_code == 200 and "corpsec_scans_queued 0" in r.text


async def test_rescan_records_fixes_and_deletion_unlinks_events(
    client: httpx.AsyncClient,
    mailer: MemoryMailer,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await sign_in(client, mailer, "leyla@bakery.az")
    site = (await client.post("/v1/sites", json={"domain": "bakery.az"})).json()
    dns = FakeDns({("bakery.az", "TXT"): [site["instructions"]["txt_value"]]})
    queue.dns = dns
    await client.post(f"/v1/sites/{site['id']}/verify", json={"method": "dns"})
    first = (await client.post(f"/v1/sites/{site['id']}/scans")).json()["id"]
    await execute_scan(sessions, first, http_checks(), mock_options(insecure, dns))
    second = (await client.post(f"/v1/sites/{site['id']}/scans")).json()["id"]
    await execute_scan(sessions, second, http_checks(), mock_options(secure, dns))

    names = [(e.name, e.props.get("via")) for e in await all_events(sessions)]
    assert ("site.verified", None) in names
    assert names.count((events.FINDING_FIXED, "rescan")) == 1
    fixed = [e for e in await all_events(sessions) if e.name == events.FINDING_FIXED]
    assert fixed[0].user_id == user_id and fixed[0].props["check_id"] == "CONN-002"

    export = (await client.get("/v1/me/export")).json()
    assert any(e["event"] == events.FINDING_FIXED for e in export["usage_events"])
    r = await client.request("DELETE", "/v1/me", json={"confirm_email": "leyla@bakery.az"})
    assert r.status_code == 204
    assert all(e.user_id is None for e in await all_events(sessions))
