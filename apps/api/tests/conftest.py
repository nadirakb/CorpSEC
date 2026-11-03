import os
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import make_engine
from corpsec_api.main import create_app
from corpsec_api.progress import MemoryProgressBus
from corpsec_api.scans import execute_recheck
from corpsec_scanner import ScanOptions, load_checks

DATABASE_URL = os.environ.get("CORPSEC_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="CORPSEC_TEST_DATABASE_URL not set")


@pytest.fixture(scope="session")
def migrated_db() -> Iterator[str]:
    if not DATABASE_URL:
        pytest.skip("CORPSEC_TEST_DATABASE_URL not set")
    cfg = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    cfg.attributes["configure_logger"] = False
    # downgrade first so the test also proves the migration is reversible
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield DATABASE_URL


@pytest.fixture
async def sessions(migrated_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(migrated_db)
    yield async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE audit_log, finding_checks, findings, scans, sites, users "
                "RESTART IDENTITY CASCADE"
            )
        )
    await engine.dispose()


Handler = Callable[[httpx.Request], httpx.Response]


def mock_options(handler: Handler) -> ScanOptions:
    return ScanOptions(
        preflight=False, transport_factory=lambda verify: httpx.MockTransport(handler)
    )


def http_checks() -> list[Any]:
    """Only checks that use HTTP: the mock transport doesn't cover DNS or raw TLS."""
    return [c for c in load_checks() if c.id in ("CONN-001", "CONN-002")]


class FakeQueue:
    """Runs re-checks inline, the way the worker would, against a mock site."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.enqueued: list[str] = []
        self.sessions = sessions
        self.handler: Handler = lambda req: httpx.Response(404)

    async def enqueue_scan(self, scan_id: str) -> None:
        self.enqueued.append(scan_id)

    async def recheck(self, finding_id: str) -> dict[str, Any] | None:
        return await execute_recheck(
            self.sessions, finding_id, http_checks(), mock_options(self.handler)
        )


@pytest.fixture
def queue(sessions: async_sessionmaker[AsyncSession]) -> FakeQueue:
    return FakeQueue(sessions)


@pytest.fixture
def progress() -> MemoryProgressBus:
    return MemoryProgressBus()


@pytest.fixture
async def client(
    sessions: async_sessionmaker[AsyncSession], queue: FakeQueue, progress: MemoryProgressBus
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(sessions=sessions, queue=queue, progress=progress)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
