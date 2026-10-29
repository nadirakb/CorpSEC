"""Live scan progress: the worker publishes, the API streams it to browsers (SSE)."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Protocol

from redis.asyncio import Redis

Event = dict[str, Any]
SNAPSHOT_TTL = 3600


def _channel(scan_id: str) -> str:
    return f"corpsec:scan:{scan_id}:events"


def _snapshot_key(scan_id: str) -> str:
    return f"corpsec:scan:{scan_id}:progress"


class ProgressBus(Protocol):
    async def publish(self, scan_id: str, event: Event) -> None: ...

    async def snapshot(self, scan_id: str) -> Event | None:
        """The latest progress event, for clients that connect mid-scan."""

    def subscribe(self, scan_id: str) -> Any:
        """Async context manager yielding an async iterator of events."""


class RedisProgressBus:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def publish(self, scan_id: str, event: Event) -> None:
        data = json.dumps(event)
        if event.get("type") == "progress":
            await self._redis.set(_snapshot_key(scan_id), data, ex=SNAPSHOT_TTL)
        await self._redis.publish(_channel(scan_id), data)

    async def snapshot(self, scan_id: str) -> Event | None:
        raw = await self._redis.get(_snapshot_key(scan_id))
        return json.loads(raw) if raw else None

    @asynccontextmanager
    async def subscribe(self, scan_id: str) -> AsyncIterator[AsyncIterator[Event]]:
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(_channel(scan_id))

        async def events() -> AsyncIterator[Event]:
            async for msg in pubsub.listen():
                if msg.get("type") == "message":
                    yield json.loads(msg["data"])

        try:
            yield events()
        finally:
            await pubsub.unsubscribe(_channel(scan_id))
            await pubsub.aclose()  # type: ignore[no-untyped-call]


class MemoryProgressBus:
    """In-process bus for tests and single-process development."""

    def __init__(self) -> None:
        self._latest: dict[str, Event] = {}
        self._subscribers: dict[str, list[asyncio.Queue[Event]]] = defaultdict(list)

    async def publish(self, scan_id: str, event: Event) -> None:
        if event.get("type") == "progress":
            self._latest[scan_id] = event
        for q in self._subscribers[scan_id]:
            q.put_nowait(event)

    async def snapshot(self, scan_id: str) -> Event | None:
        return self._latest.get(scan_id)

    @asynccontextmanager
    async def subscribe(self, scan_id: str) -> AsyncIterator[AsyncIterator[Event]]:
        q: asyncio.Queue[Event] = asyncio.Queue()
        self._subscribers[scan_id].append(q)

        async def events() -> AsyncIterator[Event]:
            while True:
                yield await q.get()

        try:
            yield events()
        finally:
            self._subscribers[scan_id].remove(q)
