"""arq worker: ``arq corpsec_api.worker.WorkerSettings``."""

from __future__ import annotations

from typing import Any, ClassVar

from arq.connections import RedisSettings
from sqlalchemy.ext.asyncio import async_sessionmaker

from corpsec_api.db import make_engine
from corpsec_api.scans import execute_scan
from corpsec_api.settings import get_settings
from corpsec_scanner import load_checks


async def startup(ctx: dict[str, Any]) -> None:
    engine = make_engine(get_settings().database_url)
    ctx["engine"] = engine
    ctx["sessions"] = async_sessionmaker(engine, expire_on_commit=False)
    ctx["checks"] = load_checks()


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["engine"].dispose()


async def run_scan_job(ctx: dict[str, Any], scan_id: str) -> str | None:
    status = await execute_scan(ctx["sessions"], scan_id, ctx["checks"])
    return status.value if status else None


class WorkerSettings:
    functions: ClassVar[list[Any]] = [run_scan_job]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = 300
    max_jobs = 10
