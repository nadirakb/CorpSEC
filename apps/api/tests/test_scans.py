import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import AuditLog
from corpsec_api.scans import execute_scan

from .conftest import FakeQueue, http_checks, mock_options, pytestmark  # noqa: F401


def site_handler(req: httpx.Request) -> httpx.Response:
    if req.url.scheme == "http":
        return httpx.Response(200, text="plain http, no redirect")
    return httpx.Response(200, text="hello")


async def test_healthz(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.json() == {"status": "ok"}


async def test_invalid_target_is_problem_json(client: httpx.AsyncClient) -> None:
    r = await client.post("/v1/scans", json={"target": "192.168.1.1"})
    assert r.status_code == 422
    assert r.headers["content-type"] == "application/problem+json"
    assert r.json()["title"] == "Please enter a domain name, not an IP address."


async def test_unknown_scan_404(client: httpx.AsyncClient) -> None:
    r = await client.get("/v1/scans/scn_nope")
    assert r.status_code == 404
    assert r.json()["title"] == "We couldn't find that scan."


async def test_scan_end_to_end(
    client: httpx.AsyncClient,
    queue: FakeQueue,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    r = await client.post("/v1/scans", json={"target": "https://www.Example.com/shop"})
    assert r.status_code == 202
    scan_id = r.json()["id"]
    assert queue.enqueued == [scan_id]

    r = await client.get(f"/v1/scans/{scan_id}")
    assert r.json()["status"] == "queued"

    options = mock_options(site_handler)
    checks = http_checks()
    status = await execute_scan(sessions, scan_id, checks, options)
    assert status == "completed"
    # a second run of the same job is a no-op
    assert await execute_scan(sessions, scan_id, checks, options) is None

    body = (await client.get(f"/v1/scans/{scan_id}")).json()
    assert body["status"] == "completed"
    assert body["host"] == "www.example.com"
    severities = {f["check_id"]: f["severity"] for f in body["findings"]}
    assert severities == {"CONN-001": "pass", "CONN-002": "high"}

    # graded at completion: one high finding -> 85 points, capped at C
    assert (body["score"], body["grade"], body["grade_caps"]) == (85, "C", ["high"])
    assert body["stage_grades"]["connection"] == {"score": 85, "letter": "C", "counted": 1}
    assert body["stage_grades"]["email"]["letter"] == "A"
    high = body["findings"][0]  # sorted: problems first
    assert high["check_id"] == "CONN-002"
    assert body["fix_first"] == [high["id"]]
    explanation = high["explanation"]
    assert explanation["title"] == "Visitors are not sent to the secure version of your site"
    assert explanation["fix_steps"] and explanation["effort"] == "about 15 minutes"
    passed = body["findings"][1]["explanation"]
    assert passed["title"] == "Your website opens securely" and passed["fix_steps"] == []

    r = await client.get(f"/v1/scans/{scan_id}", params={"lang": "xx"})
    assert r.status_code == 422
    assert {r["check_id"] for r in body["check_runs"]} == {"CONN-001", "CONN-002"}

    async with sessions() as session:
        audit = (await session.scalars(select(AuditLog))).all()
    assert [(a.action, a.target) for a in audit] == [("scan.create", "www.example.com")]
