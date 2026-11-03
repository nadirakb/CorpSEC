"""SSRF guard: CorpSEC must never connect to private, internal or reserved addresses (spec §5).

The check happens at connect time, inside the HTTP connection pool, on the exact address
the socket is opened to. Validating a hostname up front and then letting the client resolve
it again would be vulnerable to DNS rebinding, so the backend resolves once, validates every
returned address, and connects to a validated address.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import httpcore
import httpx


class BlockedAddressError(Exception):
    """Raised when a host resolves to an address CorpSEC refuses to contact."""

    def __init__(self, host: str, address: str) -> None:
        super().__init__(f"{host} resolves to non-public address {address}")
        self.host = host
        self.address = address


@dataclass(frozen=True, slots=True)
class IpPolicy:
    allow_loopback: bool = False
    """Test-only escape hatch so the guarded client can be exercised against a local server."""
    allowed_networks: tuple[str, ...] = ()
    """Extra networks to allow. Only for the vulnerable lab (deploy/lab), never in production."""

    def is_allowed(self, address: str) -> bool:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if self.allow_loopback and ip.is_loopback:
            return True
        if any(ip in ipaddress.ip_network(net) for net in self.allowed_networks):
            return True
        return ip.is_global and not ip.is_multicast


DEFAULT_IP_POLICY = IpPolicy()

Resolver = Callable[[str, int], Awaitable[list[str]]]
"""Returns every address a host resolves to. Raises ``socket.gaierror`` if it doesn't."""


async def resolve_host(host: str, port: int = 443) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: dict[str, None] = {}
    for _family, _type, _proto, _canon, sockaddr in infos:
        seen.setdefault(str(sockaddr[0]), None)
    return list(seen)


def check_addresses(host: str, addresses: Iterable[str], policy: IpPolicy) -> list[str]:
    addresses = list(addresses)
    if not addresses:
        raise BlockedAddressError(host, "<none>")
    for address in addresses:
        if not policy.is_allowed(address):
            raise BlockedAddressError(host, address)
    return addresses


@dataclass(frozen=True, slots=True)
class NetConfig:
    """How the scanner reaches the network. Production uses the defaults."""

    policy: IpPolicy = DEFAULT_IP_POLICY
    resolver: Resolver = resolve_host
    ca_file: str | None = None
    """CA bundle for certificate verification; ``None`` uses certifi's bundle."""
    _ssl_cache: dict[str, ssl.SSLContext] = field(default_factory=dict, compare=False)

    async def resolve_public(self, host: str, port: int) -> list[str]:
        """Resolve and validate. Raises ``BlockedAddressError`` or ``socket.gaierror``."""
        return check_addresses(host, await self.resolver(host, port), self.policy)

    def verifying_context(self) -> ssl.SSLContext:
        ctx = self._ssl_cache.get("verify")
        if ctx is None:
            import certifi

            ctx = ssl.create_default_context(cafile=self.ca_file or certifi.where())
            self._ssl_cache["verify"] = ctx
        return ctx


DEFAULT_NET = NetConfig()


async def open_guarded_connection(
    net: NetConfig,
    host: str,
    port: int,
    *,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = 10.0,  # noqa: ASYNC109 - per-address connect timeout
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """asyncio.open_connection to a validated address of ``host`` (SNI = ``host``)."""
    addresses = await net.resolve_public(host, port)
    last_exc: Exception | None = None
    for address in addresses:
        try:
            async with asyncio.timeout(timeout):
                return await asyncio.open_connection(
                    address,
                    port,
                    ssl=ssl_context,
                    server_hostname=host if ssl_context else None,
                )
        except (OSError, TimeoutError) as exc:
            last_exc = exc
            if isinstance(exc, ssl.SSLError):
                raise
    assert last_exc is not None
    raise last_exc


class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, net: NetConfig = DEFAULT_NET) -> None:
        self._net = net
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - signature fixed by httpcore
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            # Rejects the host if *any* address is non-public, not just the one we pick.
            addresses = await self._net.resolve_public(host, port)
        except socket.gaierror as exc:
            raise httpcore.ConnectError(f"cannot resolve {host}: {exc}") from exc
        last_exc: Exception | None = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address, port, timeout, local_address, socket_options
                )
            except httpcore.ConnectError as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - signature fixed by httpcore
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise BlockedAddressError(path, "unix socket")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool uses :class:`GuardedNetworkBackend`.

    httpx does not expose ``network_backend``; we rebuild the pool with the SSL context
    httpx already configured. ``tests/test_netguard.py`` asserts this keeps working when
    httpx is upgraded.
    """

    def __init__(self, *, verify: bool = True, net: NetConfig = DEFAULT_NET) -> None:
        super().__init__(
            verify=net.verifying_context() if verify else False, http2=False, retries=0
        )
        ssl_context = self._pool._ssl_context
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=20,
            max_keepalive_connections=10,
            keepalive_expiry=5.0,
            http1=True,
            http2=False,
            network_backend=GuardedNetworkBackend(net),
        )
