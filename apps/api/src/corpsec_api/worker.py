"""arq worker: ``arq corpsec_api.worker.WorkerSettings``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from arq.connections import RedisSettings
from sqlalchemy.ext.asyncio import async_sessionmaker

from corpsec_api.db import make_engine
from corpsec_api.scans import execute_scan
from corpsec_api.settings import get_settings
from corpsec_scanner import ScanOptions, load_checks
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


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["engine"].dispose()


async def run_scan_job(ctx: dict[str, Any], scan_id: str) -> str | None:
    options = ScanOptions(intel=ctx["intel"].get())
    status = await execute_scan(ctx["sessions"], scan_id, ctx["checks"], options)
    return status.value if status else None


class WorkerSettings:
    functions: ClassVar[list[Any]] = [run_scan_job]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = 300
    max_jobs = 10
