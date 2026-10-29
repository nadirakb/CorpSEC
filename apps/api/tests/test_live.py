import asyncio
import json

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.progress import MemoryProgressBus
from corpsec_api.scans import execute_scan

from .conftest import FakeQueue, http_checks, mock_options, pytestmark  # noqa: F401


def insecure_site(req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="hi")  # http:// is served without a redirect


def fixed_site(req: httpx.Request) -> httpx.Response:
    if req.url.scheme == "http":
        return httpx.Response(301, headers={"location": f"https://{req.url.host}/"})
    return httpx.Response(200, text="hi")


async def finished_scan(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> dict[str, object]:
    scan_id = (await client.post("/v1/scans", json={"target": "example.com"})).json()["id"]
    await execute_scan(sessions, scan_id, http_checks(), mock_options(insecure_site))
    body: dict[str, object] = (await client.get(f"/v1/scans/{scan_id}")).json()
    return body


def parse_sse(text: str) -> list[dict[str, object]]:
    return [
        json.loads(line[len("data: ") :]) for line in text.splitlines() if line.startswith("data: ")
    ]


async def test_events_for_finished_scan(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    scan = await finished_scan(client, sessions)
    r = await client.get(f"/v1/scans/{scan['id']}/events")
    assert r.headers["content-type"].startswith("text/event-stream")
    assert "no-transform" in r.headers["cache-control"]
    assert parse_sse(r.text) == [{"type": "done"}]


async def test_events_stream_progress_until_done(
    client: httpx.AsyncClient, progress: MemoryProgressBus
) -> None:
    scan_id = (await client.post("/v1/scans", json={"target": "example.com"})).json()["id"]
    await progress.publish(scan_id, {"type": "progress", "completed": 1, "total": 3})

    async def worker() -> None:
        await asyncio.sleep(0.1)
        await progress.publish(scan_id, {"type": "progress", "completed": 2, "total": 3})
        await progress.publish(scan_id, {"type": "done"})

    task = asyncio.create_task(worker())
    r = await client.get(f"/v1/scans/{scan_id}/events")
    await task
    assert parse_sse(r.text) == [
        {"type": "progress", "completed": 1, "total": 3},  # snapshot for late joiners
        {"type": "progress", "completed": 2, "total": 3},
        {"type": "done"},
    ]


async def test_events_unknown_scan(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/scans/scn_nope/events")).status_code == 404


async def test_recheck_marks_fixed_and_regrades(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession], queue: FakeQueue
) -> None:
    scan = await finished_scan(client, sessions)
    assert scan["grade"] == "C"
    problem = scan["findings"][0]  # type: ignore[index]
    assert problem["check_id"] == "CONN-002"

    queue.handler = insecure_site
    r = await client.post(f"/v1/findings/{problem['id']}/recheck")
    assert r.json() == {"result": "still_present", "grade": "C", "score": 85}

    queue.handler = fixed_site
    r = await client.post(f"/v1/findings/{problem['id']}/recheck")
    assert r.json() == {"result": "fixed", "grade": "A", "score": 100}
    body = (await client.get(f"/v1/scans/{scan['id']}")).json()
    fixed = next(f for f in body["findings"] if f["id"] == problem["id"])
    assert fixed["status"] == "fixed" and fixed["fixed_at"]
    assert body["fix_first"] == []


async def test_recheck_inconclusive_when_site_unreachable(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession], queue: FakeQueue
) -> None:
    scan = await finished_scan(client, sessions)
    problem = scan["findings"][0]  # type: ignore[index]

    def down(req: httpx.Request) -> httpx.Response:
        raise RuntimeError("boom")

    queue.handler = down
    r = await client.post(f"/v1/findings/{problem['id']}/recheck")
    assert r.json()["result"] == "inconclusive"


async def test_dismiss_and_restore(
    client: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    scan = await finished_scan(client, sessions)
    problem = scan["findings"][0]  # type: ignore[index]
    r = await client.post(f"/v1/findings/{problem['id']}/dismiss", json={"reason": "accepted_risk"})
    assert r.json()["grade"] == "A"
    body = (await client.get(f"/v1/scans/{scan['id']}")).json()
    f = next(x for x in body["findings"] if x["id"] == problem["id"])
    assert (f["status"], f["dismissed_reason"]) == ("dismissed", "accepted_risk")

    r = await client.post(f"/v1/findings/{problem['id']}/restore")
    assert r.json()["grade"] == "C"

    r = await client.post(f"/v1/findings/{problem['id']}/dismiss", json={"reason": "nope"})
    assert r.status_code == 422
    assert (await client.post("/v1/findings/fnd_nope/recheck")).status_code == 404
