from collections.abc import Callable

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.mailer import MemoryMailer
from corpsec_api.scans import execute_scan

from .conftest import FakeDns, FakeQueue, http_checks, mock_options, pytestmark, sign_in  # noqa: F401


def ok_site(req: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200, text="<html><head></head><body>hi</body></html>", headers={"content-type": "text/html"}
    )


async def add_site(client: httpx.AsyncClient, domain: str = "https://www.Bakery.az/menu") -> dict:
    r = await client.post("/v1/sites", json={"domain": domain, "platform": "wordpress"})
    assert r.status_code == 201, r.text
    body: dict = r.json()
    return body


async def test_sites_need_sign_in(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/sites")).status_code == 401
    assert (await client.post("/v1/sites", json={"domain": "bakery.az"})).status_code == 401


async def test_add_and_list(client: httpx.AsyncClient, mailer: MemoryMailer) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    site = await add_site(client)
    assert site["domain"] == "bakery.az"
    assert site["verified"] is False and site["monitoring_enabled"] is False
    ins = site["instructions"]
    assert ins["txt_value"].startswith("corpsec-verify=")
    assert ins["file_url"].startswith("https://bakery.az/.well-known/corpsec-")
    assert 'name="corpsec-verification"' in ins["meta_tag"]

    r = await client.post("/v1/sites", json={"domain": "bakery.az"})
    assert r.status_code == 409
    assert [s["domain"] for s in (await client.get("/v1/sites")).json()] == ["bakery.az"]

    r = await client.patch(f"/v1/sites/{site['id']}", json={"monitoring_enabled": True})
    assert r.status_code == 409  # not verified yet


async def test_verify_with_dns_turns_on_monitoring(
    client: httpx.AsyncClient, mailer: MemoryMailer, queue: FakeQueue
) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    site = await add_site(client)
    r = await client.post(f"/v1/sites/{site['id']}/verify", json={"method": "dns"})
    assert r.json() == {"verified": False, "message": r.json()["message"]}
    assert "TXT record" in r.json()["message"]

    queue.dns = FakeDns({("bakery.az", "TXT"): ["v=spf1 -all", site["instructions"]["txt_value"]]})
    r = await client.post(f"/v1/sites/{site['id']}/verify", json={"method": "dns"})
    assert r.json()["verified"] is True
    detail = (await client.get(f"/v1/sites/{site['id']}")).json()
    assert detail["verified"] and detail["monitoring_enabled"] and detail["next_scan_at"]
    assert detail["instructions"] is None and detail["verification_method"] == "dns"


async def test_verify_with_file_and_meta(
    client: httpx.AsyncClient, mailer: MemoryMailer, queue: FakeQueue
) -> None:
    await sign_in(client, mailer, "leyla@bakery.az")
    site = await add_site(client)
    token = site["instructions"]["file_content"]

    def with_file(req: httpx.Request) -> httpx.Response:
        if req.url.path == f"/.well-known/corpsec-{token}.txt":
            return httpx.Response(200, text=token + "\n")
        return httpx.Response(404)

    queue.handler = with_file
    r = await client.post(f"/v1/sites/{site['id']}/verify", json={"method": "file"})
    assert r.json()["verified"] is True

    other = await add_site(client, "shop.az")
    meta_token = other["instructions"]["file_content"]

    def with_meta(req: httpx.Request) -> httpx.Response:
        if req.url.host == "www.shop.az" and req.url.path == "/":
            tag = f'<meta name="corpsec-verification" content="{meta_token}">'
            html = f"<html><head>{tag}</head></html>"
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})
        return httpx.Response(301, headers={"location": "https://www.shop.az/"})

    queue.handler = with_meta
    r = await client.post(f"/v1/sites/{other['id']}/verify", json={"method": "meta"})
    assert r.json()["verified"] is True

    queue.handler = lambda req: httpx.Response(200, text="<html>nothing</html>")
    third = await add_site(client, "cafe.az")
    r = await client.post(f"/v1/sites/{third['id']}/verify", json={"method": "meta"})
    assert r.json()["verified"] is False


async def test_site_scans_are_private(
    app_factory: Callable[[], httpx.AsyncClient],
    mailer: MemoryMailer,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with app_factory() as owner, app_factory() as stranger, app_factory() as anon:
        await sign_in(owner, mailer, "leyla@bakery.az")
        await sign_in(stranger, mailer, "eve@evil.az")
        site = await add_site(owner)
        assert (await stranger.get(f"/v1/sites/{site['id']}")).status_code == 404

        scan = (await owner.post(f"/v1/sites/{site['id']}/scans")).json()
        await execute_scan(sessions, scan["id"], http_checks(), mock_options(ok_site))
        body = (await owner.get(f"/v1/scans/{scan['id']}")).json()
        assert body["site_id"] == site["id"] and body["grade"]
        for other in (stranger, anon):
            assert (await other.get(f"/v1/scans/{scan['id']}")).status_code == 404
            assert (await other.get(f"/v1/scans/{scan['id']}/events")).status_code == 404
            fid = body["findings"][0]["id"]
            r = await other.post(f"/v1/findings/{fid}/dismiss", json={"reason": "accepted_risk"})
            assert r.status_code == 404

        detail = (await owner.get(f"/v1/sites/{site['id']}")).json()
        assert [h["id"] for h in detail["history"]] == [scan["id"]]
        assert detail["latest"]["grade"] == body["grade"]

        assert (await owner.delete(f"/v1/sites/{site['id']}")).status_code == 204
        assert (await owner.get("/v1/sites")).json() == []
        # its scans are gone, not turned into public link-shared scans
        assert (await anon.get(f"/v1/scans/{scan['id']}")).status_code == 404
