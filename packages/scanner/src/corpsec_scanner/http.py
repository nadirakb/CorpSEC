"""Rate-limited, scope-locked, SSRF-guarded HTTP client used by all checks (spec §5)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from corpsec_scanner.netguard import DEFAULT_IP_POLICY, GuardedTransport, IpPolicy

USER_AGENT = "CorpSEC/0.1 (+https://corpsec.app/bot)"
ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

TransportFactory = Callable[[bool], httpx.AsyncBaseTransport]
"""Called with ``verify`` (TLS certificate verification on/off)."""


class RequestBudgetExceededError(Exception):
    pass


class OutOfScopeError(Exception):
    pass


class MethodNotAllowedError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class HttpPolicy:
    max_requests: int = 150
    per_host_concurrency: int = 2
    per_host_rps: float = 5.0
    timeout: float = 10.0
    max_redirects: int = 5
    max_body_bytes: int = 1_000_000
    user_agent: str = USER_AGENT


@dataclass(frozen=True, slots=True)
class RedirectHop:
    url: str
    status: int
    location: str


@dataclass(slots=True)
class HttpResponse:
    url: str
    """Final URL after redirects that were followed."""
    status: int
    headers: httpx.Headers
    body: bytes
    truncated: bool
    history: list[RedirectHop] = field(default_factory=list)
    left_scope: bool = False
    """True when the last response redirected outside the scan scope and was not followed."""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme


class _HostLimiter:
    def __init__(self, concurrency: int, rps: float) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._interval = 1.0 / rps
        self._lock = asyncio.Lock()
        self._next_start = 0.0

    async def __aenter__(self) -> None:
        await self._sem.acquire()
        async with self._lock:
            now = time.monotonic()
            wait = self._next_start - now
            self._next_start = max(now, self._next_start) + self._interval
        if wait > 0:
            await asyncio.sleep(wait)

    async def __aexit__(self, *exc: object) -> None:
        self._sem.release()


def _default_transport_factory(ip_policy: IpPolicy) -> TransportFactory:
    def factory(verify: bool) -> httpx.AsyncBaseTransport:
        return GuardedTransport(verify=verify, policy=ip_policy)

    return factory


class SafeHttpClient:
    def __init__(
        self,
        in_scope: Callable[[str], bool],
        policy: HttpPolicy | None = None,
        *,
        ip_policy: IpPolicy = DEFAULT_IP_POLICY,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        self._in_scope = in_scope
        self.policy = policy or HttpPolicy()
        self._transport_factory = transport_factory or _default_transport_factory(ip_policy)
        self._clients: dict[bool, httpx.AsyncClient] = {}
        self._limiters: dict[str, _HostLimiter] = {}
        self._requests = 0

    @property
    def requests_made(self) -> int:
        return self._requests

    def _client(self, verify: bool) -> httpx.AsyncClient:
        client = self._clients.get(verify)
        if client is None:
            client = httpx.AsyncClient(
                transport=self._transport_factory(verify),
                timeout=httpx.Timeout(self.policy.timeout),
                headers={"User-Agent": self.policy.user_agent},
                follow_redirects=False,
                trust_env=False,  # never route scans through environment proxies
            )
            self._clients[verify] = client
        return client

    def _limiter(self, host: str) -> _HostLimiter:
        limiter = self._limiters.get(host)
        if limiter is None:
            limiter = _HostLimiter(self.policy.per_host_concurrency, self.policy.per_host_rps)
            self._limiters[host] = limiter
        return limiter

    async def get(self, url: str, **kwargs: object) -> HttpResponse:
        return await self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    async def head(self, url: str, **kwargs: object) -> HttpResponse:
        return await self.request("HEAD", url, **kwargs)  # type: ignore[arg-type]

    async def request(
        self,
        method: str,
        url: str,
        *,
        verify: bool = True,
        follow_redirects: bool = True,
        max_body: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise MethodNotAllowedError(method)
        cap = self.policy.max_body_bytes if max_body is None else max_body

        history: list[RedirectHop] = []
        current = url
        for hop in range(self.policy.max_redirects + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise OutOfScopeError(current)
            if not self._in_scope(parts.hostname):
                raise OutOfScopeError(current)

            resp = await self._send(method, current, verify=verify, cap=cap, headers=headers)
            location = resp.headers.get("location")
            if (
                not follow_redirects
                or resp.status not in REDIRECT_STATUSES
                or not location
                or hop == self.policy.max_redirects
            ):
                resp.history = history
                return resp

            target = urljoin(current, location)
            history.append(RedirectHop(url=current, status=resp.status, location=target))
            target_parts = urlsplit(target)
            if (
                target_parts.scheme not in ("http", "https")
                or not target_parts.hostname
                or not self._in_scope(target_parts.hostname)
            ):
                resp.history = history
                resp.left_scope = True
                return resp
            if resp.status == 303 and method != "HEAD":
                method = "GET"
            current = target

        raise AssertionError("unreachable: the last hop always returns")

    async def _send(
        self,
        method: str,
        url: str,
        *,
        verify: bool,
        cap: int,
        headers: dict[str, str] | None,
    ) -> HttpResponse:
        if self._requests >= self.policy.max_requests:
            raise RequestBudgetExceededError(f"limit of {self.policy.max_requests} requests")
        self._requests += 1
        host = urlsplit(url).hostname or ""
        async with self._limiter(host):
            client = self._client(verify)
            async with client.stream(method, url, headers=headers) as r:
                body = bytearray()
                truncated = False
                if method != "HEAD":
                    async for chunk in r.aiter_bytes():
                        room = cap - len(body)
                        if len(chunk) >= room:
                            body.extend(chunk[:room])
                            truncated = len(chunk) > room
                            break
                        body.extend(chunk)
                return HttpResponse(
                    url=str(r.url),
                    status=r.status_code,
                    headers=r.headers,
                    body=bytes(body),
                    truncated=truncated,
                )

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
