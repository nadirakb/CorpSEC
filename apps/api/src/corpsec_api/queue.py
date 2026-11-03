"""Job queue abstraction so the API can be tested without Redis."""

from __future__ import annotations

from typing import Any, Protocol

from arq.connections import ArqRedis

SCAN_JOB = "run_scan_job"
RECHECK_JOB = "recheck_finding_job"
RECHECK_TIMEOUT = 60.0


class ScanQueue(Protocol):
    async def enqueue_scan(self, scan_id: str) -> None: ...

    async def recheck(self, finding_id: str) -> dict[str, Any] | None:
        """Run a re-check in the worker and wait for its result."""


class ArqScanQueue:
    def __init__(self, redis: ArqRedis) -> None:
        self._redis = redis

    async def enqueue_scan(self, scan_id: str) -> None:
        # job id = scan id, so a double submit can't run the same scan twice
        await self._redis.enqueue_job(SCAN_JOB, scan_id, _job_id=scan_id)

    async def recheck(self, finding_id: str) -> dict[str, Any] | None:
        job = await self._redis.enqueue_job(RECHECK_JOB, finding_id)
        if job is None:  # an identical job is already queued
            return None
        result: dict[str, Any] | None = await job.result(timeout=RECHECK_TIMEOUT)
        return result
