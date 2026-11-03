"""Data retention (spec §10.4, and what the privacy page promises)."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import AuditLog, LoginToken, Scan, ShareLink, UserSession
from corpsec_scanner.models import utcnow

ANONYMOUS_SCANS = timedelta(days=7)
AUDIT_LOG = timedelta(days=365)
EXPIRED_GRACE = timedelta(days=1)


async def purge_old_data(
    sessions: async_sessionmaker[AsyncSession], now: datetime | None = None
) -> dict[str, int]:
    now = now or utcnow()
    counts: dict[str, int] = {}
    async with sessions() as session:
        for name, stmt in (
            # findings and re-check history go with their scan (ON DELETE CASCADE)
            (
                "anonymous_scans",
                delete(Scan).where(Scan.site_id.is_(None), Scan.created_at < now - ANONYMOUS_SCANS),
            ),
            ("audit_log", delete(AuditLog).where(AuditLog.at < now - AUDIT_LOG)),
            ("login_tokens", delete(LoginToken).where(LoginToken.expires_at < now - EXPIRED_GRACE)),
            ("sessions", delete(UserSession).where(UserSession.expires_at < now - EXPIRED_GRACE)),
            ("share_links", delete(ShareLink).where(ShareLink.expires_at < now - EXPIRED_GRACE)),
        ):
            result = await session.execute(stmt)
            counts[name] = result.rowcount or 0  # type: ignore[attr-defined]
        await session.commit()
    return counts
