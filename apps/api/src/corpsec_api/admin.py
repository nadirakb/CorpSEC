"""Operator dashboard (spec §18 success metrics) and Prometheus metrics.

All numbers come from the analytics event log (events.py), which outlives the 7-day purge
of anonymous scans, plus a few live queue figures.

No ``from __future__ import annotations``: FastAPI resolves annotations at runtime.
"""

import hmac
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import Float, and_, cast, func, literal_column, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api import events
from corpsec_api.db import AnalyticsEvent, FindingFeedback, Scan, User
from corpsec_api.deps import CurrentUser, SessionDep
from corpsec_api.settings import Settings
from corpsec_scanner import ScanStatus
from corpsec_scanner.intel import load_snapshot
from corpsec_scanner.models import utcnow

ACTION_DAYS = 14
TARGETS = {"activation": 0.25, "action": 0.30, "false_positive": 0.02}


async def require_admin(request: Request, user: CurrentUser) -> User:
    settings: Settings = request.app.state.settings
    if not settings.is_admin(user.email):
        raise StarletteHTTPException(404, "Not found.")  # don't reveal that it exists
    return user


AdminUser = Annotated[User, Depends(require_admin)]
router = APIRouter(prefix="/v1/admin", tags=["admin"])

E = AnalyticsEvent


def _prop(name: str) -> Any:
    # Key names are constants, inlined so GROUP BY sees the same expression as SELECT.
    assert name.isidentifier()
    return E.props.op("->>")(literal_column(f"'{name}'"))


async def _count(session: AsyncSession, name: str, since: datetime, *where: Any) -> int:
    q = select(func.count()).select_from(E).where(E.name == name, E.at >= since, *where)
    return int(await session.scalar(q) or 0)


async def _distinct_visitors(session: AsyncSession, name: str, since: datetime, *where: Any) -> int:
    q = select(func.count(func.distinct(E.visitor))).where(
        E.name == name, E.at >= since, E.visitor.is_not(None), *where
    )
    return int(await session.scalar(q) or 0)


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


async def success_metrics(session: AsyncSession, since: datetime, now: datetime) -> dict[str, Any]:
    # Activation: anonymous scanners who create an account (visitor hashes rotate daily, so
    # this is an approximation that can only undercount repeat visitors).
    scanners = await _distinct_visitors(
        session, events.SCAN_STARTED, since, _prop("kind") == "anonymous"
    )
    signups = await _count(session, events.ACCOUNT_CREATED, since)

    # Action: accounts at least 14 days old that fixed something within 14 days of signing up.
    cohort_end = now - timedelta(days=ACTION_DAYS)
    signup = E.__table__.alias("signup")
    fixed = E.__table__.alias("fixed")
    cohort = int(
        await session.scalar(
            select(func.count())
            .select_from(signup)
            .where(
                signup.c.name == events.ACCOUNT_CREATED,
                signup.c.at >= since,
                signup.c.at < cohort_end,
            )
        )
        or 0
    )
    acted = int(
        await session.scalar(
            select(func.count(func.distinct(signup.c.user_id)))
            .select_from(
                signup.join(
                    fixed,
                    and_(
                        fixed.c.user_id == signup.c.user_id,
                        fixed.c.name == events.FINDING_FIXED,
                        fixed.c.at >= signup.c.at,
                        fixed.c.at < signup.c.at + timedelta(days=ACTION_DAYS),
                    ),
                )
            )
            .where(
                signup.c.name == events.ACCOUNT_CREATED,
                signup.c.at >= since,
                signup.c.at < cohort_end,
            )
        )
        or 0
    )

    # Trust: false alarms reported or dismissed, per problem shown.
    shown = int(
        await session.scalar(
            select(func.coalesce(func.sum(cast(_prop("problems"), Float)), 0)).where(
                E.name == events.SCAN_FINISHED, E.at >= since
            )
        )
        or 0
    )
    false_alarms = await _count(
        session, events.FINDING_REPORTED, since, _prop("reason") == "false_positive"
    ) + await _count(session, events.FINDING_DISMISSED, since, _prop("reason") == "false_positive")

    return {
        "activation": {
            "value": _ratio(signups, scanners),
            "target": TARGETS["activation"],
            "signups": signups,
            "anonymous_scanners": scanners,
        },
        "action": {
            "value": _ratio(acted, cohort),
            "target": TARGETS["action"],
            "acted": acted,
            "cohort": cohort,
        },
        "false_positive": {
            "value": _ratio(false_alarms, shown),
            "target": TARGETS["false_positive"],
            "reports": false_alarms,
            "problems_shown": shown,
        },
        "safety": {
            "optouts": await _count(session, events.OPTOUT_ADDED, since),
            "note": "Abuse complaints arrive by email; count them there.",
        },
    }


async def scan_stats(session: AsyncSession, since: datetime) -> dict[str, Any]:
    day = func.date_trunc("day", E.at).label("day")
    rows = (
        await session.execute(
            select(day, _prop("status"), func.count())
            .where(E.name == events.SCAN_FINISHED, E.at >= since)
            .group_by(day, _prop("status"))
            .order_by(day)
        )
    ).all()
    per_day: dict[str, dict[str, int]] = {}
    for d, status, n in rows:
        per_day.setdefault(d.date().isoformat(), {})[status or "unknown"] = n
    durations = (
        await session.execute(
            select(
                func.avg(cast(_prop("duration_s"), Float)),
                func.percentile_cont(0.95).within_group(cast(_prop("duration_s"), Float)),
            ).where(E.name == events.SCAN_FINISHED, E.at >= since)
        )
    ).one()

    async def top(field: str, limit: int = 10) -> list[dict[str, Any]]:
        item = func.jsonb_array_elements_text(E.props[field]).table_valued("value").alias("item")
        q = (
            select(item.c.value, func.count())
            .select_from(E)
            .join(item, text("true"))
            .where(E.name == events.SCAN_FINISHED, E.at >= since)
            .group_by(item.c.value)
            .order_by(func.count().desc(), item.c.value)
            .limit(limit)
        )
        return [{"check_id": c, "count": n} for c, n in (await session.execute(q)).all()]

    kinds = (
        await session.execute(
            select(_prop("kind"), func.count())
            .where(E.name == events.SCAN_STARTED, E.at >= since)
            .group_by(_prop("kind"))
        )
    ).all()
    return {
        "per_day": [{"day": d, **v} for d, v in per_day.items()],
        "started_by_kind": {k or "unknown": n for k, n in kinds},
        "avg_seconds": round(durations[0], 1) if durations[0] is not None else None,
        "p95_seconds": round(durations[1], 1) if durations[1] is not None else None,
        "failing_checks": await top("failed_checks"),
        "common_problems": await top("problem_checks"),
    }


async def funnel(session: AsyncSession, since: datetime) -> list[dict[str, Any]]:
    steps = [
        ("Visited the home page", "page.view", _prop("path") == "/"),
        ("Started a check", events.SCAN_STARTED, _prop("kind") == "anonymous"),
        ("Opened fix steps", "report.fix_opened", None),
        ("Created an account", events.ACCOUNT_CREATED, None),
    ]
    out = []
    for label, name, cond in steps:
        where = [cond] if cond is not None else []
        out.append(
            {"step": label, "visitors": await _distinct_visitors(session, name, since, *where)}
        )
    return out


async def live(session: AsyncSession, settings: Settings, now: datetime) -> dict[str, Any]:
    queued = (
        await session.execute(
            select(func.count(), func.min(Scan.created_at)).where(Scan.status == ScanStatus.QUEUED)
        )
    ).one()
    running = await session.scalar(
        select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.RUNNING)
    )
    intel_age = None
    if settings.intel_path:
        try:
            snap = load_snapshot(settings.intel_path)
            if snap.generated_at:
                intel_age = (now - snap.generated_at).total_seconds()
        except ValueError:
            intel_age = None
    return {
        "queued": int(queued[0] or 0),
        "oldest_queued_seconds": (now - queued[1]).total_seconds() if queued[1] else 0,
        "running": int(running or 0),
        "intel_age_hours": round(intel_age / 3600, 1) if intel_age is not None else None,
    }


@router.get("/overview")
async def overview(
    request: Request,
    session: SessionDep,
    _: AdminUser,
    days: Annotated[int, Query(ge=1, le=400)] = 30,
) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    now = utcnow()
    since = now - timedelta(days=days)
    return {
        "days": days,
        "generated_at": now.isoformat(),
        "metrics": await success_metrics(session, since, now),
        "scans": await scan_stats(session, since),
        "funnel": await funnel(session, since),
        "live": await live(session, settings, now),
        "feedback_by_check": [
            {"check_id": c, "open": n}
            for c, n in (
                await session.execute(
                    select(FindingFeedback.check_id, func.count())
                    .where(FindingFeedback.resolved.is_(False))
                    .group_by(FindingFeedback.check_id)
                    .order_by(func.count().desc())
                )
            ).all()
        ],
    }


class FeedbackOut(BaseModel):
    id: int
    check_id: str
    check_version: str
    reason: str
    note: str | None
    created_at: datetime
    evidence: dict[str, Any]
    resolved: bool


@router.get("/feedback")
async def list_feedback(
    session: SessionDep, _: AdminUser, resolved: bool = False
) -> list[FeedbackOut]:
    rows = (
        await session.scalars(
            select(FindingFeedback)
            .where(FindingFeedback.resolved.is_(resolved))
            .order_by(FindingFeedback.created_at.desc())
            .limit(100)
        )
    ).all()
    return [FeedbackOut.model_validate(r, from_attributes=True) for r in rows]


@router.post("/feedback/{feedback_id}/resolve")
async def resolve_feedback(feedback_id: int, session: SessionDep, _: AdminUser) -> FeedbackOut:
    row = await session.get(FindingFeedback, feedback_id)
    if row is None:
        raise StarletteHTTPException(404, "Not found.")
    row.resolved = True
    await session.commit()
    return FeedbackOut.model_validate(row, from_attributes=True)


# --- Prometheus ---------------------------------------------------------------------------

metrics_router = APIRouter()


@metrics_router.get("/metrics", include_in_schema=False)
async def prometheus(request: Request, session: SessionDep) -> PlainTextResponse:
    settings: Settings = request.app.state.settings
    expected = f"Bearer {settings.metrics_token}" if settings.metrics_token else None
    given = request.headers.get("authorization", "")
    if expected is None or not hmac.compare_digest(given.encode(), expected.encode()):
        raise StarletteHTTPException(404, "Not found.")
    now = utcnow()
    state = await live(session, settings, now)
    day_ago = now - timedelta(days=1)
    finished = (
        await session.execute(
            select(_prop("status"), func.count())
            .where(E.name == events.SCAN_FINISHED, E.at >= day_ago)
            .group_by(_prop("status"))
        )
    ).all()
    lines = [
        "# HELP corpsec_scans_queued Scans waiting for a worker.",
        "# TYPE corpsec_scans_queued gauge",
        f"corpsec_scans_queued {state['queued']}",
        "# HELP corpsec_scans_oldest_queued_seconds Age of the oldest waiting scan.",
        "# TYPE corpsec_scans_oldest_queued_seconds gauge",
        f"corpsec_scans_oldest_queued_seconds {state['oldest_queued_seconds']:.0f}",
        "# HELP corpsec_scans_running Scans in progress.",
        "# TYPE corpsec_scans_running gauge",
        f"corpsec_scans_running {state['running']}",
        "# HELP corpsec_scans_finished_24h Scans finished in the last 24 hours.",
        "# TYPE corpsec_scans_finished_24h gauge",
        *(f'corpsec_scans_finished_24h{{status="{s}"}} {n}' for s, n in finished),
    ]
    if state["intel_age_hours"] is not None:
        lines += [
            "# HELP corpsec_intel_age_hours Age of the vulnerability data snapshot.",
            "# TYPE corpsec_intel_age_hours gauge",
            f"corpsec_intel_age_hours {state['intel_age_hours']}",
        ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
