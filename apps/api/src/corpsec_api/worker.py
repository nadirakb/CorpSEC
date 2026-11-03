"""arq worker: ``arq corpsec_api.worker.WorkerSettings``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from arq import cron
from arq.connections import ArqRedis, RedisSettings
from sqlalchemy.ext.asyncio import async_sessionmaker

from corpsec_api.db import Scan, make_engine
from corpsec_api.mailer import make_mailer
from corpsec_api.monitoring import (
    execute_verify,
    post_scan_alerts,
    run_light_checks,
    schedule_due_scans,
)
from corpsec_api.progress import RedisProgressBus
from corpsec_api.queue import SCAN_JOB
from corpsec_api.retention import purge_old_data
from corpsec_api.scans import execute_recheck, execute_scan
from corpsec_api.settings import get_settings
from corpsec_scanner import ScanOptions, load_checks
from corpsec_scanner.engine import ProgressEvent
from corpsec_scanner.intel import EMPTY_SNAPSHOT, IntelSnapshot, load_snapshot


class IntelCache:
    """Reload the snapshot when its file changes (the sync job replaces it atomically)."""

    def __init__(self, path: str | None) -> None:
        self._path = Path(path) if path else None
        self._mtime: float | None = None
        self._snapshot: IntelSnapshot = EMPTY_SNAPSHOT

    def get(self) -> IntelSnapshot:
        if self._path is None or not self._path.exists():
            return self._snapshot
        mtime = self._path.stat().st_mtime
        if mtime != self._mtime:
            self._snapshot = load_snapshot(self._path)
            self._mtime = mtime
        return self._snapshot


async def startup(ctx: dict[str, Any]) -> None:
    engine = make_engine(get_settings().database_url)
    ctx["engine"] = engine
    ctx["sessions"] = async_sessionmaker(engine, expire_on_commit=False)
    ctx["checks"] = load_checks()
    ctx["intel"] = IntelCache(get_settings().intel_path)
    ctx["settings"] = get_settings()
    ctx["mailer"] = make_mailer(get_settings())


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["engine"].dispose()


async def run_scan_job(ctx: dict[str, Any], scan_id: str) -> str | None:
    bus = RedisProgressBus(ctx["redis"])
    stage_totals: dict[str, int] = {}
    for check in ctx["checks"]:
        stage_totals[check.stage.value] = stage_totals.get(check.stage.value, 0) + 1

    async def on_progress(event: ProgressEvent) -> None:
        await bus.publish(
            scan_id,
            {
                "type": "progress",
                "check_id": event.check_id,
                "stage": event.stage.value,
                "completed": event.completed,
                "total": event.total,
                "stage_totals": stage_totals,
            },
        )

    options = ScanOptions(intel=ctx["intel"].get())
    try:
        status = await execute_scan(ctx["sessions"], scan_id, ctx["checks"], options, on_progress)
    finally:
        await bus.publish(scan_id, {"type": "done"})
    async with ctx["sessions"]() as session:
        scan = await session.get(Scan, scan_id)
        site_scan = scan is not None and scan.site_id is not None
    if site_scan:
        await post_scan_alerts(ctx["sessions"], scan_id, ctx["mailer"], ctx["settings"])
    return status.value if status else None


async def verify_site_job(ctx: dict[str, Any], site_id: str, method: str) -> dict[str, Any]:
    return await execute_verify(ctx["sessions"], site_id, method)


async def schedule_due_scans_job(ctx: dict[str, Any]) -> int:
    redis: ArqRedis = ctx["redis"]

    async def enqueue(scan_id: str) -> None:
        await redis.enqueue_job(SCAN_JOB, scan_id, _job_id=scan_id)

    started = await schedule_due_scans(ctx["sessions"], enqueue, ctx["mailer"], ctx["settings"])
    return len(started)


async def light_checks_job(ctx: dict[str, Any]) -> int:
    options = ScanOptions(intel=ctx["intel"].get())
    return await run_light_checks(
        ctx["sessions"], ctx["checks"], ctx["mailer"], ctx["settings"], options
    )


async def purge_job(ctx: dict[str, Any]) -> dict[str, int]:
    return await purge_old_data(ctx["sessions"])


async def recheck_finding_job(ctx: dict[str, Any], finding_id: str) -> dict[str, Any] | None:
    options = ScanOptions(intel=ctx["intel"].get())
    return await execute_recheck(ctx["sessions"], finding_id, ctx["checks"], options)


class WorkerSettings:
    functions: ClassVar[list[Any]] = [run_scan_job, recheck_finding_job, verify_site_job]
    cron_jobs: ClassVar[list[Any]] = [
        cron(schedule_due_scans_job, minute={0, 15, 30, 45}, unique=True),
        cron(light_checks_job, minute={5, 35}, unique=True),
        cron(purge_job, hour={3}, minute={17}, unique=True),
    ]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = 300
    max_jobs = 10
