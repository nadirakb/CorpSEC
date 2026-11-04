"""CorpSEC HTTP API (spec §13). Run: ``uvicorn corpsec_api.main:app``.

No ``from __future__ import annotations`` here: FastAPI must resolve the dependency
aliases defined inside ``create_app`` at runtime.
"""

import asyncio
import json
import logging
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from arq import create_pool
from arq.connections import RedisSettings
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api import account, admin, auth, emails, events, insights, optout, sites
from corpsec_api.db import (
    AuditLog,
    FindingFeedback,
    FindingRow,
    Scan,
    ShareLink,
    Site,
    User,
    make_engine,
)
from corpsec_api.deps import (
    CurrentUser,
    MailerDep,
    OptionalUser,
    QueueDep,
    SessionDep,
    client_ip,
    token_hash,
)
from corpsec_api.mailer import Mailer, make_mailer
from corpsec_api.observability import init_error_tracking
from corpsec_api.oidc import OidcClient
from corpsec_api.policy import ScanRefusedError, check_target
from corpsec_api.progress import Event, ProgressBus, RedisProgressBus
from corpsec_api.queue import ArqScanQueue, ScanQueue
from corpsec_api.ratelimit import MemoryRateLimiter, RateLimiter, RedisRateLimiter
from corpsec_api.reporting import explained_findings
from corpsec_api.scans import new_scan, regrade
from corpsec_api.settings import DEV_SECRET, Settings, get_settings
from corpsec_checks.explain import Explanation, load_templates
from corpsec_scanner import InvalidTargetError, ScanStatus, Severity, load_checks, normalize_target
from corpsec_scanner.models import FindingStatus, utcnow


class ScanCreate(BaseModel):
    target: str = Field(max_length=2048, examples=["example.com"])


class ScanCreated(BaseModel):
    id: str
    status: str


class FindingOut(BaseModel):
    id: str
    check_id: str
    check_version: str
    host: str
    dedupe_key: str
    severity: str
    confidence: str
    status: str
    evidence: dict[str, Any]
    context: dict[str, Any]
    references: list[str]
    first_seen: datetime
    fixed_at: datetime | None
    dismissed_reason: str | None
    explanation: Explanation | None


class StageGradeOut(BaseModel):
    score: int
    letter: str
    counted: int


class ScanOut(BaseModel):
    id: str
    site_id: str | None
    redacted: bool
    """True when exposed-file locations and contents are hidden (viewer hasn't proved
    ownership of the site, spec §10.2)."""
    can_act: bool
    """Whether this viewer may re-check or hide findings."""
    """Set for scans of a monitored site; those are visible to the site owner only."""
    target: str
    host: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    score: int | None
    grade: str | None
    grade_caps: list[str]
    stage_grades: dict[str, StageGradeOut]
    fix_first: list[str]
    """Finding ids, most important first."""
    error: str | None
    check_runs: list[dict[str, Any]]
    findings: list[FindingOut]
    """Sorted by severity (critical first; passes last)."""


class ShareIn(BaseModel):
    email: EmailStr
    note: str | None = Field(default=None, max_length=1000)


class FeedbackIn(BaseModel):
    reason: Literal["false_positive", "wrong_advice", "unclear", "other"]
    note: str | None = Field(None, max_length=1000)


class DismissIn(BaseModel):
    reason: Literal["accepted_risk", "false_positive", "not_applicable"]


class RecheckOut(BaseModel):
    result: Literal["fixed", "still_present", "inconclusive"]
    grade: str | None = None
    score: int | None = None


FINISHED = {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED}
HEARTBEAT_SECONDS = 15.0


def sse(event: Event) -> str:
    return f"event: {event.get('type', 'message')}\ndata: {json.dumps(event)}\n\n"


def allowed_origins(settings: Settings) -> set[str]:
    """Origins the web app is served from; only they may make writes (POST/PATCH/DELETE)."""
    return {
        "{0.scheme}://{0.netloc}".format(urlsplit(u))
        for u in [settings.web_url, *settings.extra_origins]
    }


def problem(status: int, title: str, detail: str | None = None) -> JSONResponse:
    """RFC 9457 problem details. ``title`` is user-facing."""
    body: dict[str, Any] = {"type": "about:blank", "title": title, "status": status}
    if detail:
        body["detail"] = detail
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


def create_app(
    *,
    sessions: async_sessionmaker[AsyncSession] | None = None,
    queue: ScanQueue | None = None,
    progress: ProgressBus | None = None,
    mailer: Mailer | None = None,
    settings: Settings | None = None,
    oauth_http: httpx.AsyncClient | None = None,
    limiter: RateLimiter | None = None,
) -> FastAPI:
    """Build the app. Tests inject ``sessions`` and ``queue``; otherwise they come from settings.

    ``oauth_http`` is the client used to reach Google and Microsoft (tests pass a fake provider).
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cleanup: list[Callable[[], Awaitable[Any]]] = []
        settings = get_settings()
        if app.state.sessions is None:
            engine = make_engine(settings.database_url)
            app.state.sessions = async_sessionmaker(engine, expire_on_commit=False)
            cleanup.append(engine.dispose)
        if app.state.queue is None:
            redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
            app.state.queue = ArqScanQueue(redis)
            if app.state.progress is None:
                app.state.progress = RedisProgressBus(redis)
            if app.state.limiter is None:
                app.state.limiter = RedisRateLimiter(redis)
            cleanup.append(redis.aclose)
        if oauth_http is None:
            cleanup.append(app.state.oidc.http.aclose)
        yield
        for fn in cleanup:
            await fn()

    app = FastAPI(title="CorpSEC API", version="0.1.0", lifespan=lifespan)
    app.state.sessions = sessions
    app.state.queue = queue
    app.state.progress = progress
    app.state.settings = settings or get_settings()
    app.state.settings.check_production()
    init_error_tracking(app.state.settings, "api")
    app.state.mailer = mailer or make_mailer(app.state.settings)
    app.state.oidc = OidcClient(oauth_http or httpx.AsyncClient(timeout=10))
    if app.state.settings.secret_key == DEV_SECRET and not app.state.settings.web_url.startswith(
        "http://localhost"
    ):
        logging.getLogger("corpsec").warning(
            "CORPSEC_SECRET_KEY is the development default; set a long random value."
        )
    # injected queue = tests: limits stay in-process unless a limiter is given too
    app.state.limiter = limiter or (MemoryRateLimiter() if queue is not None else None)
    checks = load_checks()
    app.include_router(auth.router)
    app.include_router(insights.router)  # before sites: /v1/sites/{id}/trends etc.
    app.include_router(sites.router)
    app.include_router(optout.router)
    app.include_router(account.router)
    app.include_router(events.router)
    app.include_router(admin.router)
    app.include_router(admin.metrics_router)

    @app.middleware("http")
    async def same_origin_writes(request: Request, call_next: Any) -> Any:
        # Defence in depth next to SameSite=Lax cookies: browsers send Origin on POST/PATCH/
        # DELETE, so cross-site form posts and fetches are refused outright.
        origin = request.headers.get("origin")
        if (
            request.method not in ("GET", "HEAD", "OPTIONS")
            and origin
            and origin not in allowed_origins(request.app.state.settings)
        ):
            return problem(403, "This request came from another website and was blocked.")
        response = await call_next(request)
        # JSON API: never sniffed, framed or cached by shared caches.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        return response

    async def rate_limit(request: Request, key: str, limit: int, window: int) -> None:
        limiter: RateLimiter = request.app.state.limiter
        decision = await limiter.hit(key, limit, window)
        if not decision.allowed:
            minutes = max(1, round(decision.retry_after / 60))
            raise StarletteHTTPException(
                429,
                f"You've reached the limit for now. Please try again in about {minutes} "
                f"minute{'s' if minutes != 1 else ''}.",
                headers={"Retry-After": str(decision.retry_after)},
            )

    async def viewer_access(
        session: AsyncSession, scan: Scan, user: User | None, share: str | None
    ) -> tuple[bool, bool]:
        """(redacted, can_act) for this viewer, or 404 if they may not see the scan."""
        if scan.site_id is None:
            return True, True  # link-shared anonymous scan: details stay hidden for everyone
        site = await session.get(Site, scan.site_id)
        if site is None:
            raise StarletteHTTPException(404, "We couldn't find that scan.")
        owner = user is not None and site.owner_id == user.id
        shared = False
        if not owner and share:
            link = await session.scalar(
                select(ShareLink).where(
                    ShareLink.token_hash == token_hash(share), ShareLink.scan_id == scan.id
                )
            )
            shared = link is not None and link.expires_at > utcnow()
        if not owner and not shared:
            raise StarletteHTTPException(404, "We couldn't find that scan.")
        return site.verified_at is None, owner

    async def check_scan_access(session: AsyncSession, scan: Scan, user: User | None) -> None:
        """Anonymous scans are shared by link; scans of a monitored site are owner-only."""
        if scan.site_id is None:
            return
        site = await session.get(Site, scan.site_id)
        if site is None or user is None or site.owner_id != user.id:
            raise StarletteHTTPException(404, "We couldn't find that scan.")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        response = problem(exc.status_code, str(exc.detail))
        for key, value in (exc.headers or {}).items():
            response.headers[key] = value
        return response

    @app.exception_handler(ScanRefusedError)
    async def refused(request: Request, exc: ScanRefusedError) -> JSONResponse:
        return problem(403, str(exc))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return problem(422, "The request is not valid.", detail=str(exc.errors()))

    @app.exception_handler(InvalidTargetError)
    async def invalid_target(request: Request, exc: InvalidTargetError) -> JSONResponse:
        return problem(422, str(exc))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/scans", status_code=202)
    async def create_scan(
        body: ScanCreate,
        request: Request,
        session: SessionDep,
        queue: QueueDep,
        user: OptionalUser,
    ) -> ScanCreated:
        target = normalize_target(body.target)
        settings: Settings = request.app.state.settings
        await check_target(session, target, verified_owner=False)
        # Someone just scanned this site: show that report instead of scanning again (§10.3).
        recent = await session.scalar(
            select(Scan)
            .where(
                Scan.site_id.is_(None),
                Scan.host == target.host,
                Scan.status != ScanStatus.FAILED,
                Scan.created_at >= utcnow() - timedelta(minutes=settings.same_target_minutes),
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        if recent is not None:
            return ScanCreated(id=recent.id, status=recent.status)
        ip = client_ip(request)
        if user is not None:
            await rate_limit(request, f"scan:user:{user.id}", settings.user_scans_per_day, 86400)
        else:
            await rate_limit(request, f"scan:ip:{ip}:h", settings.anon_scans_per_hour, 3600)
            await rate_limit(request, f"scan:ip:{ip}:d", settings.anon_scans_per_day, 86400)
        scan = new_scan(target, body.target, site_id=None, ip=ip)
        session.add(scan)
        events.record_request(
            session,
            request,
            events.SCAN_STARTED,
            user_id=user.id if user else None,
            kind="signed_in" if user else "anonymous",
        )
        session.add(
            AuditLog(
                actor_user_id=user.id if user else None,
                actor_ip=ip,
                action="scan.create",
                target=target.host,
            )
        )
        await session.commit()
        await queue.enqueue_scan(scan.id)
        return ScanCreated(id=scan.id, status=scan.status)

    @app.get("/v1/scans/{scan_id}")
    async def get_scan(
        scan_id: str,
        session: SessionDep,
        user: OptionalUser,
        lang: str = "en",
        share: str | None = None,
    ) -> ScanOut:
        if not load_templates(lang):
            raise StarletteHTTPException(422, "That language isn't available yet.")
        scan = await session.scalar(
            select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
        )
        if scan is None:
            raise StarletteHTTPException(404, "We couldn't find that scan.")
        redacted, can_act = await viewer_access(session, scan, user, share)
        return ScanOut(
            id=scan.id,
            site_id=scan.site_id,
            redacted=redacted,
            can_act=can_act,
            target=scan.target,
            host=scan.host,
            status=scan.status,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            score=scan.score,
            grade=scan.grade,
            grade_caps=scan.grade_caps or [],
            stage_grades={
                k: StageGradeOut.model_validate(v) for k, v in (scan.stage_grades or {}).items()
            },
            fix_first=scan.fix_first or [],
            error=scan.error,
            check_runs=scan.check_runs or [],
            findings=[
                FindingOut(
                    id=f.id,
                    check_id=f.check_id,
                    check_version=f.check_version,
                    host=f.host,
                    dedupe_key=f.dedupe_key,
                    severity=f.severity,
                    confidence=f.confidence,
                    status=f.status,
                    evidence=f.evidence.model_dump(mode="json"),
                    context=f.context,
                    references=f.references,
                    first_seen=f.first_seen,
                    fixed_at=f.fixed_at,
                    dismissed_reason=f.dismissed_reason,
                    explanation=explanation,
                )
                for f, explanation in explained_findings(
                    scan, scan.findings, lang, redacted=redacted
                )
            ],
        )

    @app.get("/v1/scans/{scan_id}/events")
    async def scan_events(
        scan_id: str, request: Request, session: SessionDep, user: OptionalUser
    ) -> StreamingResponse:
        """Server-Sent Events: ``progress`` events while running, then one ``done``."""
        found = await session.get(Scan, scan_id)
        if found is None:
            raise StarletteHTTPException(404, "We couldn't find that scan.")
        await check_scan_access(session, found, user)
        await session.close()
        bus: ProgressBus = request.app.state.progress
        sessions: async_sessionmaker[AsyncSession] = request.app.state.sessions

        async def status() -> str | None:
            async with sessions() as s:
                scan = await s.get(Scan, scan_id)
                return scan.status if scan else None

        async def stream() -> AsyncIterator[str]:
            # Subscribe before reading the status so a "done" can't slip in between.
            async with bus.subscribe(scan_id) as events:
                if await status() in FINISHED:
                    yield sse({"type": "done"})
                    return
                if snap := await bus.snapshot(scan_id):
                    yield sse(snap)
                inbox: asyncio.Queue[Event] = asyncio.Queue()

                async def pump() -> None:
                    async for ev in events:
                        await inbox.put(ev)

                pump_task = asyncio.create_task(pump())
                try:
                    while True:
                        try:
                            ev = await asyncio.wait_for(inbox.get(), HEARTBEAT_SECONDS)
                        except TimeoutError:
                            if await request.is_disconnected():
                                return
                            if await status() in FINISHED:  # missed "done" (worker restart)
                                yield sse({"type": "done"})
                                return
                            yield ": keep-alive\n\n"
                            continue
                        yield sse(ev)
                        if ev.get("type") == "done":
                            return
                finally:
                    pump_task.cancel()

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            # no-transform: proxies (Next.js rewrites, nginx, CDNs) must not gzip the stream,
            # or the browser only sees events once the scan has finished.
            headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
        )

    async def finding_or_404(
        session: AsyncSession, finding_id: str, user: User | None
    ) -> FindingRow:
        row = await session.get(FindingRow, finding_id)
        scan = await session.get(Scan, row.scan_id) if row else None
        if row is None or scan is None:
            raise StarletteHTTPException(404, "We couldn't find that problem.")
        await check_scan_access(session, scan, user)
        return row

    @app.post("/v1/scans/{scan_id}/share", status_code=202)
    async def share_scan(
        scan_id: str,
        body: ShareIn,
        request: Request,
        session: SessionDep,
        user: CurrentUser,
        mailer: MailerDep,
    ) -> dict[str, str]:
        """Email the report to someone else, e.g. the person who will fix it (spec §7.5).
        The signed-in user types the address and presses Send; we never pick recipients."""
        settings: Settings = request.app.state.settings
        scan = await session.scalar(
            select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
        )
        if scan is None:
            raise StarletteHTTPException(404, "We couldn't find that scan.")
        await check_scan_access(session, scan, user)
        await rate_limit(request, f"share:user:{user.id}", settings.shares_per_day, 86400)
        link = f"{settings.web_url.rstrip('/')}/scan/{scan.id}"
        if scan.site_id is not None:
            token = secrets.token_urlsafe(32)
            session.add(
                ShareLink(
                    scan_id=scan.id,
                    token_hash=token_hash(token),
                    created_by=user.id,
                    recipient=body.email.lower(),
                    expires_at=utcnow() + timedelta(days=30),
                )
            )
            link += f"?share={token}"
        explained = dict(
            (f.id, e) for f, e in explained_findings(scan, scan.findings, redacted=True)
        )
        top = [e.title for i in (scan.fix_first or []) if (e := explained.get(i)) is not None]
        session.add(
            AuditLog(
                actor_user_id=user.id,
                actor_ip=client_ip(request),
                action="scan.share",
                target=f"{scan.id}->{body.email.lower()}",
            )
        )
        events.record(session, events.REPORT_SHARED, user_id=user.id)
        await session.commit()
        await mailer.send(
            emails.share_report(
                body.email.lower(),
                user.email,
                scan.registrable_domain,
                scan.grade,
                top,
                link,
                body.note,
            )
        )
        return {"status": "sent"}

    @app.post("/v1/findings/{finding_id}/recheck")
    async def recheck(
        finding_id: str,
        request: Request,
        session: SessionDep,
        queue: QueueDep,
        user: OptionalUser,
    ) -> RecheckOut:
        row = await finding_or_404(session, finding_id, user)
        ip = client_ip(request)
        who = f"user:{user.id}" if user else f"ip:{ip}"
        settings: Settings = request.app.state.settings
        await rate_limit(request, f"recheck:{who}", settings.rechecks_per_hour, 3600)
        session.add(AuditLog(actor_ip=ip, action="finding.recheck", target=row.id))
        await session.commit()
        try:
            result = await queue.recheck(finding_id)
        except TimeoutError as exc:
            raise StarletteHTTPException(504, "Checking took too long. Please try again.") from exc
        if result is None:
            raise StarletteHTTPException(409, "This is already being checked. Please wait.")
        return RecheckOut.model_validate(result)

    @app.post("/v1/findings/{finding_id}/dismiss")
    async def dismiss(
        finding_id: str,
        body: DismissIn,
        request: Request,
        session: SessionDep,
        user: OptionalUser,
    ) -> RecheckOut:
        row = await finding_or_404(session, finding_id, user)
        if row.severity == Severity.CRITICAL and body.reason != "false_positive":
            # spec §7.6: serious problems can only be dismissed as false alarms
            raise StarletteHTTPException(
                422, "Serious problems can only be hidden if they are a false alarm."
            )
        row.status = FindingStatus.DISMISSED
        row.dismissed_reason = body.reason
        events.record(
            session,
            events.FINDING_DISMISSED,
            user_id=user.id if user else None,
            check_id=row.check_id,
            reason=body.reason,
        )
        session.add(
            AuditLog(
                actor_ip=client_ip(request),
                action=f"finding.dismiss.{body.reason}",
                target=row.id,
            )
        )
        scan = await session.get(Scan, row.scan_id)
        assert scan is not None
        await session.flush()
        await regrade(session, scan, checks)
        await session.commit()
        return RecheckOut(result="still_present", grade=scan.grade, score=scan.score)

    @app.post("/v1/findings/{finding_id}/feedback", status_code=202)
    async def finding_feedback(
        finding_id: str,
        body: FeedbackIn,
        request: Request,
        session: SessionDep,
        user: OptionalUser,
    ) -> dict[str, str]:
        """ "This looks wrong": reviewed by the CorpSEC team to fix the check (spec §18)."""
        row = await finding_or_404(session, finding_id, user)
        await rate_limit(request, f"feedback:ip:{client_ip(request)}", 20, 86400)
        session.add(
            FindingFeedback(
                finding_id=row.id,
                check_id=row.check_id,
                check_version=row.check_version,
                reason=body.reason,
                note=body.note,
                user_id=user.id if user else None,
                evidence=row.evidence,
            )
        )
        events.record_request(
            session,
            request,
            events.FINDING_REPORTED,
            user_id=user.id if user else None,
            check_id=row.check_id,
            reason=body.reason,
        )
        await session.commit()
        return {"status": "received"}

    @app.post("/v1/findings/{finding_id}/restore")
    async def restore(
        finding_id: str, request: Request, session: SessionDep, user: OptionalUser
    ) -> RecheckOut:
        row = await finding_or_404(session, finding_id, user)
        if row.status == FindingStatus.DISMISSED:
            row.status = FindingStatus.OPEN
            row.dismissed_reason = None
            session.add(
                AuditLog(actor_ip=client_ip(request), action="finding.restore", target=row.id)
            )
        scan = await session.get(Scan, row.scan_id)
        assert scan is not None
        await session.flush()
        await regrade(session, scan, checks)
        await session.commit()
        return RecheckOut(result="still_present", grade=scan.grade, score=scan.score)

    return app


app = create_app()
