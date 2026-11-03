from collections.abc import Callable
from datetime import timedelta
from urllib.parse import unquote

import httpx
import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.auth import safe_next
from corpsec_api.db import LoginToken
from corpsec_api.mailer import MemoryMailer
from corpsec_scanner.models import utcnow

from .conftest import WEB_URL, pytestmark, sign_in  # noqa: F401


def token_from(mail_text: str) -> str:
    line = next(x for x in mail_text.splitlines() if "/auth/verify?token=" in x)
    return unquote(line.split("token=")[1].split("&")[0])


async def test_magic_link_sign_in_and_out(client: httpx.AsyncClient, mailer: MemoryMailer) -> None:
    assert (await client.get("/v1/me")).status_code == 401
    r = await client.post(
        "/v1/auth/magic-link", json={"email": "Leyla@Bakery.AZ", "next": "/sites"}
    )
    assert r.status_code == 202
    [mail] = mailer.sent
    assert mail.to == "leyla@bakery.az"
    assert f"{WEB_URL}/auth/verify?token=" in mail.text and "next=/sites" in mail.text

    r = await client.post("/v1/auth/verify", json={"token": token_from(mail.text)})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie
    assert (await client.get("/v1/me")).json()["email"] == "leyla@bakery.az"

    assert (await client.post("/v1/auth/logout")).status_code == 204
    assert (await client.get("/v1/me")).status_code == 401


async def test_link_is_single_use(client: httpx.AsyncClient, mailer: MemoryMailer) -> None:
    await client.post("/v1/auth/magic-link", json={"email": "a@bakery.az"})
    token = token_from(mailer.sent[-1].text)
    assert (await client.post("/v1/auth/verify", json={"token": token})).status_code == 200
    r = await client.post("/v1/auth/verify", json={"token": token})
    assert r.status_code == 400
    assert "expired or was already used" in r.json()["title"]


async def test_expired_link(
    client: httpx.AsyncClient, mailer: MemoryMailer, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await client.post("/v1/auth/magic-link", json={"email": "a@bakery.az"})
    async with sessions() as s:
        await s.execute(update(LoginToken).values(expires_at=utcnow() - timedelta(seconds=1)))
        await s.commit()
    r = await client.post("/v1/auth/verify", json={"token": token_from(mailer.sent[-1].text)})
    assert r.status_code == 400


async def test_same_user_on_second_sign_in(client: httpx.AsyncClient, mailer: MemoryMailer) -> None:
    first = await sign_in(client, mailer, "a@bakery.az")
    second = await sign_in(client, mailer, "A@bakery.az")
    assert first == second


async def test_rate_limit_is_silent(client: httpx.AsyncClient, mailer: MemoryMailer) -> None:
    for _ in range(7):
        r = await client.post("/v1/auth/magic-link", json={"email": "a@bakery.az"})
        assert r.status_code == 202  # same answer either way
    assert len(mailer.sent) == 5


async def test_invalid_email(client: httpx.AsyncClient) -> None:
    r = await client.post("/v1/auth/magic-link", json={"email": "not-an-email"})
    assert r.status_code == 422


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/sites/1", "/sites/1"),
        ("//evil.com", "/dashboard"),
        ("https://evil.com", "/dashboard"),
        ("/\\evil.com", "/dashboard"),
        (None, "/dashboard"),
    ],
)
def test_safe_next(raw: str | None, expected: str) -> None:
    assert safe_next(raw) == expected


async def test_cross_site_writes_blocked(client: httpx.AsyncClient) -> None:
    r = await client.post(
        "/v1/scans", json={"target": "example.com"}, headers={"Origin": "https://evil.example"}
    )
    assert r.status_code == 403
    r = await client.post("/v1/scans", json={"target": "example.com"}, headers={"Origin": WEB_URL})
    assert r.status_code == 202


async def test_two_people_are_separate(
    app_factory: Callable[[], httpx.AsyncClient], mailer: MemoryMailer
) -> None:
    async with app_factory() as a, app_factory() as b:
        await sign_in(a, mailer, "a@bakery.az")
        assert (await b.get("/v1/me")).status_code == 401
