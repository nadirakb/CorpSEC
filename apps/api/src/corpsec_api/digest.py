"""Opt-in weekly summary email (spec §4.5): one line per site with its latest grade and
open problems. Alerts still go out immediately; this is the calm "all is well" view."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api import emails
from corpsec_api.db import FindingRow, Scan, Site, User
from corpsec_api.mailer import Mailer
from corpsec_api.monitoring import FINISHED
from corpsec_api.settings import Settings
from corpsec_scanner import Severity
from corpsec_scanner.models import FindingStatus, utcnow

DIGEST_INTERVAL = timedelta(days=7)
_SLACK = timedelta(hours=12)
"""Cron jitter shouldn't skip a week."""
PROBLEMS = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


async def _site_line(session: AsyncSession, site: Site) -> str:
    scan = await session.scalar(
        select(Scan)
        .where(Scan.site_id == site.id, Scan.status.in_(FINISHED))
        .order_by(Scan.finished_at.desc())
        .limit(1)
    )
    if scan is None:
        return f"{site.domain}: not checked yet"
    problems = await session.scalar(
        select(func.count())
        .select_from(FindingRow)
        .where(
            FindingRow.scan_id == scan.id,
            FindingRow.severity.in_(PROBLEMS),
            FindingRow.status == FindingStatus.OPEN,
        )
    )
    noun = "problem" if problems == 1 else "problems"
    state = f"{problems} open {noun}" if problems else "no open problems"
    return f"{site.domain}: grade {scan.grade or '?'}, {state}"


async def send_weekly_digests(
    sessions: async_sessionmaker[AsyncSession],
    mailer: Mailer,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> int:
    """Email every opted-in user who has sites and wasn't emailed this week."""
    now = now or utcnow()
    cutoff = now - DIGEST_INTERVAL + _SLACK
    sent = 0
    async with sessions() as session:
        users = (
            await session.scalars(
                select(User).where(
                    User.weekly_digest.is_(True),
                    or_(User.last_digest_at.is_(None), User.last_digest_at < cutoff),
                )
            )
        ).all()
        for user in users:
            sites = (
                await session.scalars(
                    select(Site).where(Site.owner_id == user.id).order_by(Site.domain)
                )
            ).all()
            if not sites:
                continue
            lines = [await _site_line(session, s) for s in sites]
            base = settings.web_url.rstrip("/")
            await mailer.send(
                emails.weekly_digest(user.email, lines, f"{base}/sites", f"{base}/account")
            )
            user.last_digest_at = now
            await session.commit()  # per user: a mail failure later doesn't resend earlier ones
            sent += 1
    return sent
