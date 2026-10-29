import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import make_engine
from corpsec_api.main import create_app

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
            text("TRUNCATE audit_log, findings, scans, sites, users RESTART IDENTITY CASCADE")
        )
    await engine.dispose()


class FakeQueue:
    def __init__(self) -> None:
        self.enqueued: list[str] = []

    async def enqueue_scan(self, scan_id: str) -> None:
        self.enqueued.append(scan_id)


@pytest.fixture
def queue() -> FakeQueue:
    return FakeQueue()


@pytest.fixture
async def client(
    sessions: async_sessionmaker[AsyncSession], queue: FakeQueue
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(sessions=sessions, queue=queue)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
