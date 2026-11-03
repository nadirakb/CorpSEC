import time
from collections.abc import Callable

import httpx
import pytest

from corpsec_scanner.http import (
    HttpPolicy,
    MethodNotAllowedError,
    OutOfScopeError,
    RequestBudgetExceededError,
    SafeHttpClient,
)
from corpsec_scanner.target import normalize_target

Handler = Callable[[httpx.Request], httpx.Response]


def make_client(handler: Handler, **policy: object) -> SafeHttpClient:
    target = normalize_target("example.com")
    return SafeHttpClient(
        target.in_scope,
        HttpPolicy(**policy),  # type: ignore[arg-type]
        transport_factory=lambda verify: httpx.MockTransport(handler),
    )


async def test_sets_user_agent() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers["user-agent"])
        return httpx.Response(200)

    client = make_client(handler)
    await client.get("https://example.com/")
    assert seen[0].startswith("CorpSEC/")


async def test_rejects_out_of_scope_url() -> None:
    client = make_client(lambda req: httpx.Response(200))
    with pytest.raises(OutOfScopeError):
        await client.get("https://evil.net/")


async def test_rejects_unsafe_methods() -> None:
    client = make_client(lambda req: httpx.Response(200))
    with pytest.raises(MethodNotAllowedError):
        await client.request("POST", "https://example.com/")


async def test_follows_in_scope_redirects() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://www.example.com/"})
        return httpx.Response(200, text="hello")

    r = await make_client(handler).get("http://example.com/")
    assert r.status == 200
    assert r.url == "https://www.example.com/"
    assert [h.status for h in r.history] == [301]
    assert not r.left_scope


async def test_stops_at_out_of_scope_redirect() -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return httpx.Response(302, headers={"location": "https://evil.net/"})

    r = await make_client(handler).get("https://example.com/")
    assert r.left_scope
    assert r.status == 302
    assert calls == ["https://example.com/"]


async def test_redirect_limit() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        n = int(req.url.params.get("n", "0"))
        return httpx.Response(302, headers={"location": f"/?n={n + 1}"})

    r = await make_client(handler, max_redirects=3).get("https://example.com/")
    assert r.status == 302
    assert len(r.history) == 3


async def test_request_budget() -> None:
    client = make_client(lambda req: httpx.Response(200), max_requests=2)
    await client.get("https://example.com/a")
    await client.get("https://example.com/b")
    with pytest.raises(RequestBudgetExceededError):
        await client.get("https://example.com/c")


async def test_body_cap() -> None:
    client = make_client(lambda req: httpx.Response(200, content=b"x" * 10_000))
    r = await client.get("https://example.com/", max_body=4096)
    assert len(r.body) == 4096
    assert r.truncated


async def test_per_host_rate_limit() -> None:
    client = make_client(lambda req: httpx.Response(200), per_host_rps=20.0)
    t0 = time.monotonic()
    for _ in range(5):
        await client.get("https://example.com/")
    # 5 requests at 20 req/s: starts at 0, 50, 100, 150, 200 ms
    assert time.monotonic() - t0 >= 0.19
