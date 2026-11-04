"""Monitoring (spec §4.5): weekly scans, daily expiry/uptime checks, alerts.

All functions take their collaborators as arguments so tests can drive them with a fake
clock, mock network and an in-memory mailer.
"""

from __future__ import annotations

import random
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime, timedelta
from functools import partial
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api import emails, events
from corpsec_api.db import Alert, FindingRow, Scan, Site, User
from corpsec_api.mailer import Mail, Mailer
from corpsec_api.policy import is_opted_out
from corpsec_api.reporting import row_to_finding
from corpsec_api.scans import new_scan, with_dependencies
from corpsec_api.settings import Settings
from corpsec_api.verification import as_method, check_ownership
from corpsec_checks.explain import SiteContext, explain
from corpsec_scanner import Check, ScanOptions, ScanStatus, Severity, run_scan
from corpsec_scanner.models import Confidence, FindingStatus, utcnow
from corpsec_scanner.target import normalize_target

SCAN_INTERVAL = timedelta(days=7)
LIGHT_INTERVAL = timedelta(days=1)
RETRY_AFTER_FAILED_VERIFY = timedelta(days=1)
MAX_VERIFY_FAILURES = 2
ALERT_COOLDOWN = timedelta(days=7)
LIGHT_CHECKS = ("CONN-001", "TLS-002", "DNS-001")
FINISHED = (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
GRADE_ORDER = ["A+", "A", "B", "C", "D", "F"]
ALERTING = (Severity.CRITICAL, Severity.HIGH)

Enqueue = Callable[[str], Awaitable[None]]


def first_scan_time(now: datetime | None = None) -> datetime:
    """Spread first scans over the next day so weekly load doesn't pile up (spec §4.5)."""
    return (now or utcnow()) + timedelta(minutes=random.randint(30, 24 * 60))  # noqa: S311


def site_link(settings: Settings, site_id: str) -> str:
    return f"{settings.web_url.rstrip('/')}/sites/{site_id}"


async def send_alert(
    session: AsyncSession,
    mailer: Mailer,
    site: Site,
    kind: str,
    key: str,
    mail: Callable[[str], Mail],
    payload: dict[str, Any],
    now: datetime,
) -> bool:
    """Record and email an alert, unless the same one was sent within the cooldown."""
    recent = await session.scalar(
        select(Alert).where(
            Alert.site_id == site.id,
            Alert.kind == kind,
            Alert.key == key,
            Alert.created_at >= now - ALERT_COOLDOWN,
        )
    )
    if recent is not None:
        return False
    owner = await session.get(User, site.owner_id)
    if owner is None or owner.deleted_at is not None:
        return False
    session.add(
        Alert(site_id=site.id, kind=kind, key=key, payload=payload, sent_at=now, created_at=now)
    )
    await session.flush()
    await mailer.send(mail(owner.email))
    return True


async def execute_verify(
    sessions: async_sessionmaker[AsyncSession],
    site_id: str,
    method: str,
    options: ScanOptions | None = None,
) -> dict[str, Any]:
    async with sessions() as session:
        site = await session.get(Site, site_id)
        if site is None or not site.verification_token:
            return {"verified": False, "message": "We couldn't find that site."}
        result = await check_ownership(
            site.domain,
            site.verification_token,
            as_method(method),
            options,
        )
        if result.verified:
            now = utcnow()
            if site.verified_at is None:
                events.record(session, events.SITE_VERIFIED, user_id=site.owner_id, method=method)
            site.verified_at = site.verified_at or now
            site.verification_method = method
            site.last_verified_at = now
            site.verify_failures = 0
            if site.monitoring_paused_reason in (None, "verification_lost"):
                # Verifying is the user's way of saying "watch this site".
                site.monitoring_enabled = True
                site.monitoring_paused_reason = None
                site.next_scan_at = site.next_scan_at or first_scan_time(now)
                site.next_light_check_at = site.next_light_check_at or now + timedelta(hours=1)
            await session.commit()
        return {"verified": result.verified, "message": result.message}


async def schedule_due_scans(
    sessions: async_sessionmaker[AsyncSession],
    enqueue: Enqueue,
    mailer: Mailer,
    settings: Settings,
    options: ScanOptions | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Start weekly scans that are due. Ownership is re-checked before every one (§4.3)."""
    now = now or utcnow()
    started: list[str] = []
    async with sessions() as session:
        sites = (
            await session.scalars(
                select(Site)
                .where(
                    Site.monitoring_enabled.is_(True),
                    Site.verified_at.is_not(None),
                    Site.next_scan_at <= now,
                )
                .order_by(Site.next_scan_at)
                .limit(100)
                .with_for_update(skip_locked=True)
            )
        ).all()
        for site in sites:
            if await is_opted_out(session, site.domain):
                site.next_scan_at = now + SCAN_INTERVAL
                continue
            result = await check_ownership(
                site.domain,
                site.verification_token or "",
                as_method(site.verification_method or "dns"),
                options,
            )
            if not result.verified:
                site.verify_failures += 1
                site.next_scan_at = now + RETRY_AFTER_FAILED_VERIFY
                if site.verify_failures >= MAX_VERIFY_FAILURES:
                    site.monitoring_enabled = False
                    site.monitoring_paused_reason = "verification_lost"
                    link = site_link(settings, site.id)
                    await send_alert(
                        session,
                        mailer,
                        site,
                        "verification_lost",
                        "",
                        partial(emails.verification_lost, domain=site.domain, link=link),
                        {"message": result.message},
                        now,
                    )
                continue
            site.verify_failures = 0
            site.last_verified_at = now
            scan = new_scan(normalize_target(site.domain), site.domain, site_id=site.id, ip=None)
            events.record(session, events.SCAN_STARTED, user_id=site.owner_id, kind="scheduled")
            session.add(scan)
            site.next_scan_at = now + SCAN_INTERVAL
            started.append(scan.id)
        await session.commit()
    for scan_id in started:
        await enqueue(scan_id)
    return started


async def run_light_checks(
    sessions: async_sessionmaker[AsyncSession],
    checks: Sequence[Check],
    mailer: Mailer,
    settings: Settings,
    options: ScanOptions | None = None,
    now: datetime | None = None,
) -> int:
    """Daily: is the site up, and are the certificate and domain far from expiring?"""
    now = now or utcnow()
    subset: dict[str, Check] = {}
    for check_id in LIGHT_CHECKS:
        if check_id in {c.id for c in checks}:
            subset.update({c.id: c for c in with_dependencies(check_id, checks)})
    count = 0
    async with sessions() as session:
        sites = (
            await session.scalars(
                select(Site)
                .where(Site.monitoring_enabled.is_(True), Site.next_light_check_at <= now)
                .limit(200)
                .with_for_update(skip_locked=True)
            )
        ).all()
        for site in sites:
            site.next_light_check_at = now + LIGHT_INTERVAL
            result = await run_scan(site.domain, list(subset.values()), options=options)
            link = site_link(settings, site.id)
            for f in result.findings:
                if f.check_id == "CONN-001" and f.severity == Severity.CRITICAL:
                    await send_alert(
                        session,
                        mailer,
                        site,
                        "site_down",
                        "",
                        partial(emails.site_down, domain=site.domain, link=link),
                        {},
                        now,
                    )
                elif f.check_id in ("TLS-002", "DNS-001") and f.severity in ALERTING:
                    observed = f.evidence.observed if isinstance(f.evidence.observed, dict) else {}
                    days = int(observed.get("days_left", 0))
                    what = "cert" if f.check_id == "TLS-002" else "domain"
                    expiry = str(observed.get("valid_until") or observed.get("expires") or "")
                    await send_alert(
                        session,
                        mailer,
                        site,
                        f"{what}_expiring",
                        expiry,
                        partial(
                            emails.expiring, domain=site.domain, what=what, days=days, link=link
                        ),
                        {"days_left": days, "expires": expiry},
                        now,
                    )
            count += 1
        await session.commit()
    return count


def identity(f: FindingRow) -> tuple[str, str, str]:
    return (f.check_id, f.host, f.dedupe_key)


async def post_scan_alerts(
    sessions: async_sessionmaker[AsyncSession],
    scan_id: str,
    mailer: Mailer,
    settings: Settings,
    now: datetime | None = None,
) -> list[str]:
    """After a site scan: email the owner if the grade dropped or new problems appeared.

    The first scan of a site is the baseline and never alerts.
    """
    now = now or utcnow()
    sent: list[str] = []
    async with sessions() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None or scan.site_id is None or scan.status not in FINISHED:
            return sent
        site = await session.get(Site, scan.site_id)
        if site is None:
            return sent
        prev = await session.scalar(
            select(Scan)
            .where(
                Scan.site_id == site.id,
                Scan.id != scan.id,
                Scan.status.in_(FINISHED),
                Scan.created_at < scan.created_at,
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        if prev is None:
            return sent

        rows = (
            await session.scalars(select(FindingRow).where(FindingRow.scan_id == scan.id))
        ).all()
        prev_rows = (
            await session.scalars(select(FindingRow).where(FindingRow.scan_id == prev.id))
        ).all()
        before = {
            identity(f) for f in prev_rows if f.severity not in (Severity.PASS, Severity.INFO)
        }
        new = [
            f
            for f in rows
            if f.status == FindingStatus.OPEN
            and f.severity in ALERTING
            and f.confidence in (Confidence.CONFIRMED, Confidence.LIKELY)
            and identity(f) not in before
        ]
        link = f"{settings.web_url.rstrip('/')}/scan/{scan.id}"
        dropped = (
            prev.grade in GRADE_ORDER
            and scan.grade in GRADE_ORDER
            and GRADE_ORDER.index(scan.grade) > GRADE_ORDER.index(prev.grade)
        )
        if dropped:
            if await send_alert(
                session,
                mailer,
                site,
                "grade_drop",
                scan.id,
                lambda to: emails.grade_drop(
                    to, site.domain, prev.grade or "", scan.grade or "", link
                ),
                {"from": prev.grade, "to": scan.grade, "scan_id": scan.id},
                now,
            ):
                sent.append("grade_drop")
        elif new:
            findings = [row_to_finding(f) for f in rows]
            ctx = SiteContext.from_findings(scan.registrable_domain, scan.host, findings)
            by_id = {f.id: f for f in findings}
            titles = []
            for f in new:
                e = explain(by_id[f.id], ctx)
                titles.append(e.title if e else f.check_id)
            key = ",".join(sorted(":".join(identity(f)) for f in new))
            if await send_alert(
                session,
                mailer,
                site,
                "new_problem",
                key[:256],
                lambda to: emails.new_problems(to, site.domain, titles, link),
                {"count": len(new), "scan_id": scan.id},
                now,
            ):
                sent.append("new_problem")
        await session.commit()
    return sent
