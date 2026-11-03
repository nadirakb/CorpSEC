"""Job queue abstraction so the API can be tested without Redis."""

from __future__ import annotations

from typing import Protocol

from arq.connections import ArqRedis

SCAN_JOB = "run_scan_job"


class ScanQueue(Protocol):
    async def enqueue_scan(self, scan_id: str) -> None: ...


class ArqScanQueue:
    def __init__(self, redis: ArqRedis) -> None:
        self._redis = redis

    async def enqueue_scan(self, scan_id: str) -> None:
        # job id = scan id, so a double submit can't run the same scan twice
        await self._redis.enqueue_job(SCAN_JOB, scan_id, _job_id=scan_id)
