"""arq worker: ``arq corpsec_api.worker.WorkerSettings``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from arq import cron
from arq.connections import ArqRedis, RedisSettings
from sqlalchemy.ext.asyncio import async_sessionmaker

from corpsec_api.db import Scan, make_engine
from corpsec_api.digest import send_weekly_digests
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
from corpsec_intel.sync import sync_file
from corpsec_scanner import ScanOptions, load_checks
from corpsec_scanner.engine import ProgressEvent
from corpsec_scanner.http import HttpPolicy
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


def scan_options(ctx: dict[str, Any]) -> ScanOptions:
    """Current intel, and a user agent that points site owners at this deployment's bot page."""
    settings = ctx["settings"]
    agent = f"CorpSEC/0.1 (+{settings.web_url.rstrip('/')}/bot)"
    return ScanOptions(
        intel=ctx["intel"].get(),
        check_config=settings.check_config(),
        http_policy=HttpPolicy(user_agent=agent),
        external_http_policy=HttpPolicy(max_requests=10, max_body_bytes=200_000, user_agent=agent),
    )


async def startup(ctx: dict[str, Any]) -> None:
    get_settings().check_production()
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

    options = scan_options(ctx)
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
    return await execute_verify(ctx["sessions"], site_id, method, scan_options(ctx))


async def schedule_due_scans_job(ctx: dict[str, Any]) -> int:
    redis: ArqRedis = ctx["redis"]

    async def enqueue(scan_id: str) -> None:
        await redis.enqueue_job(SCAN_JOB, scan_id, _job_id=scan_id)

    started = await schedule_due_scans(
        ctx["sessions"], enqueue, ctx["mailer"], ctx["settings"], scan_options(ctx)
    )
    return len(started)


async def light_checks_job(ctx: dict[str, Any]) -> int:
    options = scan_options(ctx)
    return await run_light_checks(
        ctx["sessions"], ctx["checks"], ctx["mailer"], ctx["settings"], options
    )


async def purge_job(ctx: dict[str, Any]) -> dict[str, int]:
    return await purge_old_data(ctx["sessions"])


async def intel_sync_job(ctx: dict[str, Any]) -> list[str] | None:
    """Nightly vulnerability/product data refresh. Failed sources keep yesterday's data."""
    settings = ctx["settings"]
    if not settings.intel_path:
        return None
    path = Path(settings.intel_path)
    return await sync_file(
        path,
        previous=path,  # a missing file just means "no previous data"
        wordfence_key=settings.wordfence_api_key,
    )


async def digest_job(ctx: dict[str, Any]) -> int:
    return await send_weekly_digests(ctx["sessions"], ctx["mailer"], ctx["settings"])


async def recheck_finding_job(ctx: dict[str, Any], finding_id: str) -> dict[str, Any] | None:
    options = scan_options(ctx)
    return await execute_recheck(ctx["sessions"], finding_id, ctx["checks"], options)


class WorkerSettings:
    functions: ClassVar[list[Any]] = [run_scan_job, recheck_finding_job, verify_site_job]
    cron_jobs: ClassVar[list[Any]] = [
        cron(schedule_due_scans_job, minute={0, 15, 30, 45}, unique=True),
        cron(light_checks_job, minute={5, 35}, unique=True),
        cron(purge_job, hour={3}, minute={17}, unique=True),
        cron(intel_sync_job, hour={2}, minute={41}, unique=True, timeout=1800),
        cron(digest_job, weekday={0}, hour={8}, minute={7}, unique=True),
    ]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = 300
    max_jobs = 10
