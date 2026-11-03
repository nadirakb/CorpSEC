import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest

from corpsec_scanner.netguard import (
    BlockedAddressError,
    GuardedNetworkBackend,
    GuardedTransport,
    IpPolicy,
    NetConfig,
)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fd00::1",
        "fe80::1%eth0",
        "::ffff:127.0.0.1",
    ],
)
def test_blocks_non_public(address: str) -> None:
    assert not IpPolicy().is_allowed(address)


@pytest.mark.parametrize("address", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_allows_public(address: str) -> None:
    assert IpPolicy().is_allowed(address)


def test_transport_pool_uses_guarded_backend() -> None:
    # Guards against httpx internals changing under us (see GuardedTransport docstring).
    transport = GuardedTransport()
    assert isinstance(transport._pool._network_backend, GuardedNetworkBackend)


@pytest.fixture
async def local_server() -> AsyncIterator[int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


async def test_blocks_loopback_at_connect_time(local_server: int) -> None:
    async with httpx.AsyncClient(transport=GuardedTransport()) as client:
        with pytest.raises(BlockedAddressError):
            await client.get(f"http://localhost:{local_server}/")


async def test_loopback_escape_hatch_connects(local_server: int) -> None:
    transport = GuardedTransport(net=NetConfig(policy=IpPolicy(allow_loopback=True)))
    async with httpx.AsyncClient(transport=transport) as client:
        r = await client.get(f"http://localhost:{local_server}/")
    assert r.text == "ok"


def test_lab_networks_allowed_only_when_configured() -> None:
    assert not IpPolicy().is_allowed("172.30.0.5")
    assert IpPolicy(allowed_networks=("172.30.0.0/24",)).is_allowed("172.30.0.5")
    assert not IpPolicy(allowed_networks=("172.30.0.0/24",)).is_allowed("172.30.1.5")
