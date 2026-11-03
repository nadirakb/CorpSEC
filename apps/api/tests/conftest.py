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
from corpsec_api.mailer import MemoryMailer
from corpsec_api.main import create_app
from corpsec_api.monitoring import execute_verify
from corpsec_api.progress import MemoryProgressBus
from corpsec_api.scans import execute_recheck
from corpsec_api.settings import Settings
from corpsec_scanner import ScanOptions, load_checks
from corpsec_scanner.dns import DnsAnswer, DnsClient

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
                "TRUNCATE alerts, audit_log, finding_checks, findings, scans, sites, "
                "login_tokens, user_sessions, user_identities, oauth_flows, users "
                "RESTART IDENTITY CASCADE"
            )
        )
    await engine.dispose()


Handler = Callable[[httpx.Request], httpx.Response]
WEB_URL = "https://corpsec.test"


class FakeDns(DnsClient):
    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None) -> None:
        super().__init__(nameservers=["192.0.2.1"])
        self.records = records or {}

    async def _lookup(self, name: str, rdtype: str) -> DnsAnswer:
        return DnsAnswer(records=tuple(self.records.get((name, rdtype), [])))


def mock_options(handler: Handler, dns: DnsClient | None = None) -> ScanOptions:
    return ScanOptions(
        preflight=False,
        transport_factory=lambda verify: httpx.MockTransport(handler),
        dns=dns or FakeDns(),
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
        self.dns: DnsClient = FakeDns()

    async def enqueue_scan(self, scan_id: str) -> None:
        self.enqueued.append(scan_id)

    async def verify_site(self, site_id: str, method: str) -> dict[str, Any] | None:
        return await execute_verify(
            self.sessions, site_id, method, mock_options(self.handler, self.dns)
        )

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
def mailer() -> MemoryMailer:
    return MemoryMailer()


@pytest.fixture
def settings() -> Settings:
    return Settings(web_url=WEB_URL, smtp_host=None)


@pytest.fixture
def oauth_http() -> httpx.AsyncClient | None:
    """Client for reaching OAuth providers; test_oauth.py overrides it with a fake provider."""
    return None


@pytest.fixture
def app_factory(
    sessions: async_sessionmaker[AsyncSession],
    queue: FakeQueue,
    progress: MemoryProgressBus,
    mailer: MemoryMailer,
    settings: Settings,
    oauth_http: httpx.AsyncClient | None,
) -> Callable[[], httpx.AsyncClient]:
    """New clients share the app but not cookies, so tests can act as different people."""
    app = create_app(
        sessions=sessions,
        queue=queue,
        progress=progress,
        mailer=mailer,
        settings=settings,
        oauth_http=oauth_http,
    )

    def make() -> httpx.AsyncClient:
        # https so the Secure session cookie is sent back
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test")

    return make


@pytest.fixture
async def client(app_factory: Callable[[], httpx.AsyncClient]) -> AsyncIterator[httpx.AsyncClient]:
    async with app_factory() as c:
        yield c


async def sign_in(client: httpx.AsyncClient, mailer: MemoryMailer, email: str) -> str:
    """Full magic-link flow. Returns the user id."""
    r = await client.post("/v1/auth/magic-link", json={"email": email})
    assert r.status_code == 202
    link = mailer.sent[-1].text.split("\n")
    url = next(line for line in link if "/auth/verify?token=" in line)
    token = url.split("token=")[1].split("&")[0]
    r = await client.post("/v1/auth/verify", json={"token": token})
    assert r.status_code == 200, r.text
    user_id: str = r.json()["id"]
    return user_id
