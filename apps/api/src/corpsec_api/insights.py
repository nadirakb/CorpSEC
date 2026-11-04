"""Site owners' analytics: trends, time to fix, how a site compares, monthly report, and an
overview across all of a person's sites.

No ``from __future__ import annotations``: FastAPI resolves annotations at runtime.
"""

import statistics
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel
from sqlalchemy import Float, cast, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api import events
from corpsec_api.db import Alert, AnalyticsEvent, FindingRow, Scan, Site
from corpsec_api.deps import CurrentUser, SessionDep
from corpsec_api.insights_keys import site_key
from corpsec_api.reporting import effort_minutes, explained_findings
from corpsec_api.settings import Settings
from corpsec_api.sites import owned_site
from corpsec_grader import priority
from corpsec_scanner import ScanStatus, Severity
from corpsec_scanner.models import FindingStatus, utcnow

FINISHED = (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
PROBLEMS = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
TREND_LENGTH = 52  # a year of weekly scans
BENCHMARK_DAYS = 180
MIN_BENCHMARK_SAMPLE = 20
"""Below this, a percentile says more about chance than about the site."""

router = APIRouter(tags=["insights"])

Identity = tuple[str, str, str]


async def finished_scans(session: AsyncSession, site_id: str, limit: int) -> list[Scan]:
    rows = await session.scalars(
        select(Scan)
        .where(Scan.site_id == site_id, Scan.status.in_(FINISHED))
        .order_by(Scan.finished_at.desc())
        .limit(limit)
    )
    return list(reversed(rows.all()))  # oldest first


async def latest_scan(session: AsyncSession, site_id: str) -> Scan | None:
    found = await finished_scans(session, site_id, 1)
    return found[0] if found else None


async def problems_by_scan(
    session: AsyncSession, scan_ids: list[str]
) -> dict[str, dict[Identity, FindingRow]]:
    out: dict[str, dict[Identity, FindingRow]] = {s: {} for s in scan_ids}
    if not scan_ids:
        return out
    rows = await session.scalars(
        select(FindingRow).where(
            FindingRow.scan_id.in_(scan_ids), FindingRow.severity.in_(PROBLEMS)
        )
    )
    for r in rows:
        out[r.scan_id][(r.check_id, r.host, r.dedupe_key)] = r
    return out


def fix_times(scans: list[Scan], problems: dict[str, dict[Identity, FindingRow]]) -> list[float]:
    """Days from first seen to fixed: marked fixed by a re-check, or gone in the next scan."""
    days: list[float] = []
    for i, scan in enumerate(scans):
        current = problems[scan.id]
        following = problems[scans[i + 1].id] if i + 1 < len(scans) else None
        for ident, row in current.items():
            fixed_at: datetime | None
            if row.status == FindingStatus.FIXED and row.fixed_at:
                fixed_at = row.fixed_at
            elif (
                following is not None
                and row.status == FindingStatus.OPEN
                and ident not in following
                and scans[i + 1].finished_at
            ):
                fixed_at = scans[i + 1].finished_at
            else:
                continue
            if fixed_at is not None:
                days.append(max(0.0, (fixed_at - row.first_seen).total_seconds() / 86400))
    return days


class TrendPoint(BaseModel):
    scan_id: str
    finished_at: datetime
    score: int | None
    grade: str | None
    stages: dict[str, str]
    """Stage -> letter."""
    open_problems: int


class Trends(BaseModel):
    points: list[TrendPoint]
    fixed_count: int
    median_days_to_fix: float | None
    open_now: int


@router.get("/v1/sites/{site_id}/trends")
async def site_trends(site_id: str, user: CurrentUser, session: SessionDep) -> Trends:
    site = await owned_site(session, site_id, user.id)
    scans = await finished_scans(session, site.id, TREND_LENGTH)
    problems = await problems_by_scan(session, [s.id for s in scans])
    points = [
        TrendPoint(
            scan_id=s.id,
            finished_at=s.finished_at or s.created_at,
            score=s.score,
            grade=s.grade,
            stages={k: v.get("letter", "") for k, v in (s.stage_grades or {}).items()},
            open_problems=sum(1 for r in problems[s.id].values() if r.status == FindingStatus.OPEN),
        )
        for s in scans
    ]
    times = fix_times(scans, problems)
    return Trends(
        points=points,
        fixed_count=len(times),
        median_days_to_fix=round(statistics.median(times), 1) if times else None,
        open_now=points[-1].open_problems if points else 0,
    )


class Benchmark(BaseModel):
    score: int | None
    platform: str | None
    """Compared with sites on the same platform when there are enough of them."""
    sample: int
    better_than: float | None
    """Share of compared sites with a lower score (ties count half). None: not enough data."""


@router.get("/v1/sites/{site_id}/benchmark")
async def site_benchmark(
    site_id: str, request: Request, user: CurrentUser, session: SessionDep
) -> Benchmark:
    settings: Settings = request.app.state.settings
    site = await owned_site(session, site_id, user.id)
    latest = await latest_scan(session, site.id)
    score = latest.score if latest else None
    own = site_key(settings.secret_key, site.domain)
    since = utcnow() - timedelta(days=BENCHMARK_DAYS)
    E = AnalyticsEvent

    async def scores(platform: str | None) -> list[float]:
        prop = E.props["site_key"].astext
        latest_per_site = (
            select(prop.label("k"), cast(E.props["score"].astext, Float).label("score"))
            .where(
                E.name == events.SCAN_FINISHED,
                E.at >= since,
                E.props["score"].astext.is_not(None),
                prop.is_not(None),
                prop != own,
                *([E.props["platform"].astext == platform] if platform else []),
            )
            .ext(distinct_on(prop))
            .order_by(prop, E.at.desc())
            .subquery()
        )
        return list((await session.scalars(select(latest_per_site.c.score))).all())

    platform = site.platform if site.platform not in (None, "unknown", "custom") else None
    sample = await scores(platform) if platform else []
    if len(sample) < MIN_BENCHMARK_SAMPLE:
        platform, sample = None, await scores(None)
    if score is None or len(sample) < MIN_BENCHMARK_SAMPLE:
        return Benchmark(score=score, platform=platform, sample=len(sample), better_than=None)
    lower = sum(1 for s in sample if s < score) + 0.5 * sum(1 for s in sample if s == score)
    return Benchmark(
        score=score,
        platform=platform,
        sample=len(sample),
        better_than=round(lower / len(sample), 3),
    )


class ProblemLine(BaseModel):
    check_id: str
    title: str
    severity: str
    item: str


class MonthlyReport(BaseModel):
    domain: str
    month: str
    scans: int
    start_grade: str | None
    end_grade: str | None
    start_score: int | None
    end_score: int | None
    fixed: list[ProblemLine]
    new: list[ProblemLine]
    open_at_end: list[ProblemLine]
    alerts: list[dict[str, Any]]


def _month_bounds(month: str) -> tuple[datetime, datetime]:
    try:
        start = datetime.strptime(month, "%Y-%m").replace(tzinfo=UTC)
    except ValueError as exc:
        raise StarletteHTTPException(422, "Month must look like 2026-10.") from exc
    end = (start + timedelta(days=32)).replace(day=1)
    return start, end


@router.get("/v1/sites/{site_id}/monthly")
async def monthly_report(
    site_id: str,
    user: CurrentUser,
    session: SessionDep,
    month: Annotated[str, Query(pattern=r"^\d{4}-\d{2}$")],
) -> MonthlyReport:
    site = await owned_site(session, site_id, user.id)
    start, end = _month_bounds(month)
    all_scans = await finished_scans(session, site.id, 1000)
    before = [s for s in all_scans if s.finished_at and s.finished_at < start]
    during = [s for s in all_scans if s.finished_at and start <= s.finished_at < end]
    baseline = before[-1] if before else (during[0] if during else None)
    last = during[-1] if during else baseline
    ids = [s.id for s in {baseline, last} if s is not None]
    problems = await problems_by_scan(session, ids)

    async def lines(scan: Scan | None, idents: set[Identity]) -> list[ProblemLine]:
        if scan is None or not idents:
            return []
        rows = [problems[scan.id][i] for i in idents]
        out = []
        for f, e in explained_findings(scan, rows, redacted=False):
            out.append(
                ProblemLine(
                    check_id=f.check_id,
                    title=e.title if e else f.check_id,
                    severity=f.severity,
                    item=f.dedupe_key,
                )
            )
        return out

    def open_idents(scan: Scan | None) -> set[Identity]:
        if scan is None:
            return set()
        return {i for i, r in problems[scan.id].items() if r.status == FindingStatus.OPEN}

    # No scan before the month: compare with the month's first scan.
    start_open = open_idents(baseline)
    end_open = open_idents(last)
    alerts = (
        await session.scalars(
            select(Alert)
            .where(Alert.site_id == site.id, Alert.created_at >= start, Alert.created_at < end)
            .order_by(Alert.created_at)
        )
    ).all()
    return MonthlyReport(
        domain=site.domain,
        month=month,
        scans=len(during),
        start_grade=baseline.grade if baseline else None,
        end_grade=last.grade if last else None,
        start_score=baseline.score if baseline else None,
        end_score=last.score if last else None,
        fixed=await lines(baseline, start_open - end_open),
        new=await lines(last, end_open - start_open),
        open_at_end=await lines(last, end_open),
        alerts=[{"kind": a.kind, "at": a.created_at.isoformat()} for a in alerts],
    )


class PortfolioSite(BaseModel):
    id: str
    domain: str
    grade: str | None
    score: int | None
    open_by_severity: dict[str, int]
    last_checked: datetime | None


class PortfolioItem(BaseModel):
    site_id: str
    domain: str
    scan_id: str
    finding_id: str
    check_id: str
    title: str
    severity: str
    effort: str


class Portfolio(BaseModel):
    sites: list[PortfolioSite]
    average_score: float | None
    open_serious: int
    """Critical + high problems across all sites."""
    fix_first: list[PortfolioItem]


@router.get("/v1/portfolio")
async def portfolio(user: CurrentUser, session: SessionDep) -> Portfolio:
    sites = (await session.scalars(select(Site).where(Site.owner_id == user.id))).all()
    out_sites: list[PortfolioSite] = []
    candidates: list[tuple[float, PortfolioItem]] = []
    for site in sites:
        latest = await latest_scan(session, site.id)
        rows = []
        if latest is not None:
            rows = list(
                (
                    await session.scalars(
                        select(FindingRow).where(
                            FindingRow.scan_id == latest.id,
                            FindingRow.severity.in_(PROBLEMS),
                            FindingRow.status == FindingStatus.OPEN,
                        )
                    )
                ).all()
            )
        counts: dict[str, int] = {}
        for r in rows:
            counts[r.severity] = counts.get(r.severity, 0) + 1
        out_sites.append(
            PortfolioSite(
                id=site.id,
                domain=site.domain,
                grade=latest.grade if latest else None,
                score=latest.score if latest else None,
                open_by_severity=counts,
                last_checked=latest.finished_at if latest else None,
            )
        )
        if latest is None:
            continue
        seen: set[str] = set()
        for f, e in explained_findings(latest, rows, redacted=False):
            if e is None or f.check_id in seen:
                continue  # one entry per kind of problem per site
            seen.add(f.check_id)
            effort = effort_minutes(f.check_id)
            candidates.append(
                (
                    priority(f, effort),
                    PortfolioItem(
                        site_id=site.id,
                        domain=site.domain,
                        scan_id=latest.id,
                        finding_id=f.id,
                        check_id=f.check_id,
                        title=e.title,
                        severity=f.severity,
                        effort=e.effort,
                    ),
                )
            )
    candidates.sort(key=lambda c: (-c[0], c[1].domain, c[1].check_id))
    scores = [s.score for s in out_sites if s.score is not None]
    order = ["F", "D", "C", "B", "A", "A+"]
    out_sites.sort(key=lambda s: (order.index(s.grade) if s.grade in order else 6, s.domain))
    return Portfolio(
        sites=out_sites,
        average_score=round(sum(scores) / len(scores), 1) if scores else None,
        open_serious=sum(
            s.open_by_severity.get(Severity.CRITICAL, 0) + s.open_by_severity.get(Severity.HIGH, 0)
            for s in out_sites
        ),
        fix_first=[item for _, item in candidates[:10]],
    )
