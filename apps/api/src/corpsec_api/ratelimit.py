"""Fixed-window rate limits (spec §10.3), shared across API processes through Redis."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from redis.asyncio import Redis


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    retry_after: int
    """Seconds until the window resets (0 when allowed)."""


class RateLimiter(Protocol):
    async def hit(self, key: str, limit: int, window_seconds: int) -> Decision: ...


class RedisRateLimiter:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def hit(self, key: str, limit: int, window_seconds: int) -> Decision:
        window = int(time.time()) // window_seconds
        full = f"corpsec:rl:{key}:{window}"
        count = await self._redis.incr(full)
        if count == 1:
            await self._redis.expire(full, window_seconds)
        if count > limit:
            return Decision(False, window_seconds - int(time.time()) % window_seconds)
        return Decision(True, 0)


class MemoryRateLimiter:
    """Tests and single-process development."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    async def hit(self, key: str, limit: int, window_seconds: int) -> Decision:
        window = int(time.time()) // window_seconds
        full = f"{key}:{window}"
        self._counts[full] = self._counts.get(full, 0) + 1
        if self._counts[full] > limit:
            return Decision(False, window_seconds - int(time.time()) % window_seconds)
        return Decision(True, 0)
