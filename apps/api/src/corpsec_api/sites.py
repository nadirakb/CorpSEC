"""Sites: the domains a user monitors (spec §4.2-§4.5, §13).

No ``from __future__ import annotations``: FastAPI resolves annotations at runtime.
"""

from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api import events
from corpsec_api.db import Alert, AuditLog, Scan, Site
from corpsec_api.deps import CurrentUser, QueueDep, SessionDep, client_ip
from corpsec_api.monitoring import first_scan_time
from corpsec_api.policy import check_target
from corpsec_api.ratelimit import RateLimiter
from corpsec_api.scans import new_scan
from corpsec_api.settings import Settings
from corpsec_api.verification import METHODS, instructions, new_token
from corpsec_scanner import ScanStatus, normalize_target
from corpsec_scanner.models import new_id, utcnow

router = APIRouter(prefix="/v1/sites", tags=["sites"])

Platform = Literal[
    "wordpress", "joomla", "drupal", "shopify", "wix", "squarespace", "webflow", "custom", "unknown"
]
HISTORY_LENGTH = 12
FINISHED = (ScanStatus.COMPLETED, ScanStatus.PARTIAL)


class SiteCreate(BaseModel):
    domain: str = Field(max_length=2048, examples=["bakery.az"])
    platform: Platform | None = None


class SitePatch(BaseModel):
    platform: Platform | None = None
    monitoring_enabled: bool | None = None


class VerifyIn(BaseModel):
    method: Literal["dns", "file", "meta"]


class VerifyOut(BaseModel):
    verified: bool
    message: str


class InstructionsOut(BaseModel):
    txt_name: str
    txt_value: str
    file_url: str
    file_content: str
    meta_tag: str


class ScanSummary(BaseModel):
    id: str
    status: str
    grade: str | None
    score: int | None
    finished_at: datetime | None


class AlertOut(BaseModel):
    kind: str
    created_at: datetime
    payload: dict[str, object]


class SiteOut(BaseModel):
    id: str
    domain: str
    platform: str | None
    verified: bool
    verification_method: str | None
    monitoring_enabled: bool
    monitoring_paused_reason: str | None
    next_scan_at: datetime | None
    latest: ScanSummary | None
    previous_grade: str | None
    instructions: InstructionsOut | None
    """How to verify ownership; only while unverified."""


class SiteDetail(SiteOut):
    history: list[ScanSummary]
    """Most recent first."""
    alerts: list[AlertOut]


def summary(scan: Scan) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        status=scan.status,
        grade=scan.grade,
        score=scan.score,
        finished_at=scan.finished_at,
    )


async def recent_scans(session: AsyncSession, site_id: str, limit: int) -> list[Scan]:
    rows = await session.scalars(
        select(Scan).where(Scan.site_id == site_id).order_by(Scan.created_at.desc()).limit(limit)
    )
    return list(rows)


def site_out(site: Site, scans: list[Scan]) -> SiteOut:
    finished = [s for s in scans if s.status in FINISHED]
    verified = site.verified_at is not None
    return SiteOut(
        id=site.id,
        domain=site.domain,
        platform=site.platform,
        verified=verified,
        verification_method=site.verification_method,
        monitoring_enabled=site.monitoring_enabled,
        monitoring_paused_reason=site.monitoring_paused_reason,
        next_scan_at=site.next_scan_at,
        latest=summary(scans[0]) if scans else None,
        previous_grade=finished[1].grade if len(finished) > 1 else None,
        instructions=(
            None
            if verified
            else InstructionsOut(**asdict(instructions(site.domain, site.verification_token or "")))
        ),
    )


async def owned_site(session: AsyncSession, site_id: str, user_id: str) -> Site:
    site = await session.get(Site, site_id)
    if site is None or site.owner_id != user_id:
        raise StarletteHTTPException(404, "We couldn't find that site.")
    return site


@router.post("", status_code=201)
async def add_site(
    body: SiteCreate, request: Request, user: CurrentUser, session: SessionDep
) -> SiteOut:
    target = normalize_target(body.domain)
    domain = target.registrable_domain
    settings: Settings = request.app.state.settings
    count = await session.scalar(select(func.count()).where(Site.owner_id == user.id)) or 0
    if count >= settings.max_sites_per_user:
        raise StarletteHTTPException(
            403, f"Free accounts can add up to {settings.max_sites_per_user} sites."
        )
    existing = await session.scalar(
        select(Site).where(Site.owner_id == user.id, Site.domain == domain)
    )
    if existing is not None:
        raise StarletteHTTPException(409, f"{domain} is already in your list.")
    site = Site(
        id=new_id("site"),
        owner_id=user.id,
        domain=domain,
        platform=body.platform,
        verification_token=new_token(),
        monitoring_enabled=False,
    )
    session.add(site)
    await session.commit()
    return site_out(site, [])


@router.get("")
async def list_sites(user: CurrentUser, session: SessionDep) -> list[SiteOut]:
    sites = await session.scalars(
        select(Site).where(Site.owner_id == user.id).order_by(Site.created_at)
    )
    out = []
    for site in sites:
        out.append(site_out(site, await recent_scans(session, site.id, 5)))
    # Worst grade first: the sites that need attention (spec §7.4, agency view)
    order = ["F", "D", "C", "B", "A", "A+"]
    out.sort(
        key=lambda s: order.index(s.latest.grade) if s.latest and s.latest.grade in order else 6
    )
    return out


@router.get("/{site_id}")
async def get_site(site_id: str, user: CurrentUser, session: SessionDep) -> SiteDetail:
    site = await owned_site(session, site_id, user.id)
    scans = await recent_scans(session, site.id, HISTORY_LENGTH)
    alerts = await session.scalars(
        select(Alert).where(Alert.site_id == site.id).order_by(Alert.created_at.desc()).limit(20)
    )
    base = site_out(site, scans)
    return SiteDetail(
        **base.model_dump(),
        history=[summary(s) for s in scans],
        alerts=[AlertOut(kind=a.kind, created_at=a.created_at, payload=a.payload) for a in alerts],
    )


@router.patch("/{site_id}")
async def update_site(
    site_id: str, body: SitePatch, user: CurrentUser, session: SessionDep
) -> SiteOut:
    site = await owned_site(session, site_id, user.id)
    if body.platform is not None:
        site.platform = body.platform
    if body.monitoring_enabled is not None:
        if body.monitoring_enabled and site.verified_at is None:
            raise StarletteHTTPException(
                409, "Verify that you own this site to turn on monitoring."
            )
        site.monitoring_enabled = body.monitoring_enabled
        if body.monitoring_enabled:
            site.monitoring_paused_reason = None
            site.next_scan_at = site.next_scan_at or first_scan_time()
            site.next_light_check_at = site.next_light_check_at or utcnow() + timedelta(hours=1)
    await session.commit()
    return site_out(site, await recent_scans(session, site.id, 5))


@router.delete("/{site_id}", status_code=204)
async def delete_site(site_id: str, user: CurrentUser, session: SessionDep) -> None:
    site = await owned_site(session, site_id, user.id)
    # Delete its scans too: with site_id cleared they would become public, link-shared scans.
    await session.execute(sa_delete(Scan).where(Scan.site_id == site.id))
    await session.delete(site)
    await session.commit()


@router.post("/{site_id}/verify")
async def verify_site(
    site_id: str,
    body: VerifyIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    queue: QueueDep,
) -> VerifyOut:
    site = await owned_site(session, site_id, user.id)
    assert body.method in METHODS
    session.add(
        AuditLog(
            actor_user_id=user.id,
            actor_ip=client_ip(request),
            action=f"site.verify.{body.method}",
            target=site.domain,
        )
    )
    await session.commit()
    try:
        result = await queue.verify_site(site.id, body.method)
    except TimeoutError as exc:
        raise StarletteHTTPException(504, "Checking took too long. Please try again.") from exc
    if result is None:
        raise StarletteHTTPException(409, "We're already checking. Please wait a moment.")
    return VerifyOut.model_validate(result)


@router.post("/{site_id}/scans", status_code=202)
async def scan_site(
    site_id: str, request: Request, user: CurrentUser, session: SessionDep, queue: QueueDep
) -> ScanSummary:
    site = await owned_site(session, site_id, user.id)
    target = normalize_target(site.domain)
    await check_target(session, target, verified_owner=site.verified_at is not None)
    settings: Settings = request.app.state.settings
    limiter: RateLimiter = request.app.state.limiter
    decision = await limiter.hit(f"scan:user:{user.id}", settings.user_scans_per_day, 86400)
    if not decision.allowed:
        raise StarletteHTTPException(
            429,
            "You've reached today's limit of checks. Weekly checks still run.",
            headers={"Retry-After": str(decision.retry_after)},
        )
    scan = new_scan(target, site.domain, site_id=site.id, ip=client_ip(request))
    session.add(scan)
    events.record_request(session, request, events.SCAN_STARTED, user_id=user.id, kind="site")
    session.add(
        AuditLog(
            actor_user_id=user.id,
            actor_ip=client_ip(request),
            action="scan.create",
            target=site.domain,
        )
    )
    await session.commit()
    await queue.enqueue_scan(scan.id)
    return summary(scan)
