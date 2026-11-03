from datetime import timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import AuditLog, Scan
from corpsec_api.mailer import MemoryMailer
from corpsec_api.retention import purge_old_data
from corpsec_scanner.models import utcnow

from .conftest import pytestmark, sign_in  # noqa: F401


async def test_purge_keeps_site_scans_and_recent_data(
    client: httpx.AsyncClient, mailer: MemoryMailer, sessions: async_sessionmaker[AsyncSession]
) -> None:
    anon = (await client.post("/v1/scans", json={"target": "bakery.az"})).json()["id"]
    await sign_in(client, mailer, "leyla@bakery.az")
    site = (await client.post("/v1/sites", json={"domain": "shop.az"})).json()
    owned = (await client.post(f"/v1/sites/{site['id']}/scans")).json()["id"]

    # Six days later nothing anonymous is gone yet; eight days later it is.
    early = await purge_old_data(sessions, utcnow() + timedelta(days=6))
    assert early["anonymous_scans"] == 0
    assert early["login_tokens"] == 1  # the used sign-in link expired over a day ago
    counts = await purge_old_data(sessions, utcnow() + timedelta(days=8))
    assert counts["anonymous_scans"] == 1
    async with sessions() as s:
        assert await s.get(Scan, anon) is None
        assert await s.get(Scan, owned) is not None  # monitored sites keep their history
        assert await s.scalar(select(func.count()).select_from(AuditLog)) > 0

    counts = await purge_old_data(sessions, utcnow() + timedelta(days=366))
    assert counts["audit_log"] > 0
