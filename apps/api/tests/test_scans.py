import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import AuditLog
from corpsec_api.scans import execute_scan
from corpsec_scanner import ScanOptions, load_checks

from .conftest import FakeQueue, pytestmark  # noqa: F401


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

    options = ScanOptions(
        preflight=False, transport_factory=lambda verify: httpx.MockTransport(site_handler)
    )
    # Only checks that use HTTP: the mock transport doesn't cover DNS or raw TLS.
    checks = [c for c in load_checks() if c.id in ("CONN-001", "CONN-002")]
    status = await execute_scan(sessions, scan_id, checks, options)
    assert status == "completed"
    # a second run of the same job is a no-op
    assert await execute_scan(sessions, scan_id, checks, options) is None

    body = (await client.get(f"/v1/scans/{scan_id}")).json()
    assert body["status"] == "completed"
    assert body["host"] == "www.example.com"
    severities = {f["check_id"]: f["severity"] for f in body["findings"]}
    assert severities == {"CONN-001": "pass", "CONN-002": "high"}
    assert {r["check_id"] for r in body["check_runs"]} == {"CONN-001", "CONN-002"}

    async with sessions() as session:
        audit = (await session.scalars(select(AuditLog))).all()
    assert [(a.action, a.target) for a in audit] == [("scan.create", "www.example.com")]
