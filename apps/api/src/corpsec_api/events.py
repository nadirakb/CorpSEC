"""First-party product analytics (spec §18): what happened, never who it was.

Server code records events where things happen (scan started, account created, problem
fixed). The web app may send a few page-level events through ``POST /v1/events``. No cookies,
no IP addresses, no third parties: visitors are counted with a hash of (secret, day, IP,
browser) that changes every day. Browsers sending Global Privacy Control or Do Not Track are
not counted at all.

No ``from __future__ import annotations``: FastAPI resolves annotations at runtime.
"""

import hashlib
import hmac
import re
from typing import Any, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from corpsec_api.db import AnalyticsEvent
from corpsec_api.deps import OptionalUser, SessionDep, client_ip
from corpsec_api.ratelimit import RateLimiter
from corpsec_api.settings import Settings
from corpsec_scanner.models import utcnow

# Server-side events.
SCAN_STARTED = "scan.started"  # props: kind = anonymous | signed_in | site | scheduled
SCAN_FINISHED = "scan.finished"  # props: status, grade, kind, duration_s, problems, ...
ACCOUNT_CREATED = "account.created"  # props: method
SITE_VERIFIED = "site.verified"
FINDING_FIXED = "finding.fixed"  # props: check_id, via = recheck | rescan
FINDING_DISMISSED = "finding.dismissed"  # props: check_id, reason
FINDING_REPORTED = "finding.reported"  # props: check_id, reason
REPORT_SHARED = "report.shared"
OPTOUT_ADDED = "optout.added"

# Sent by the web app.
ClientEventName = Literal["page.view", "report.fix_opened", "cta.signup_clicked"]

_ID_SEGMENT_RE = re.compile(r"/(scn|sit|usr|fnd)_[A-Za-z0-9]+")
_TOKENISH_RE = re.compile(r"/[A-Za-z0-9_-]{20,}")


def visitor_id(secret: str, ip: str | None, user_agent: str | None, day: str) -> str | None:
    if not ip:
        return None
    msg = f"{day}|{ip}|{user_agent or ''}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()[:16]


def visitor_for(request: Request) -> str | None:
    settings: Settings = request.app.state.settings
    return visitor_id(
        settings.secret_key,
        client_ip(request),
        request.headers.get("user-agent"),
        utcnow().date().isoformat(),
    )


def opted_out(request: Request) -> bool:
    return request.headers.get("sec-gpc") == "1" or request.headers.get("dnt") == "1"


def record(
    session: AsyncSession,
    name: str,
    *,
    user_id: str | None = None,
    visitor: str | None = None,
    **props: Any,
) -> None:
    """Add an event to the session; it is saved with the caller's commit."""
    session.add(AnalyticsEvent(name=name, user_id=user_id, visitor=visitor, props=props))


def record_request(
    session: AsyncSession, request: Request, name: str, *, user_id: str | None = None, **props: Any
) -> None:
    visitor = None if opted_out(request) else visitor_for(request)
    record(session, name, user_id=user_id, visitor=visitor, **props)


def page_template(path: str) -> str:
    """``/scan/scn_abc`` -> ``/scan/[id]``: pages are counted by kind, never by report."""
    path = path.split("?", 1)[0].split("#", 1)[0][:200] or "/"
    return _TOKENISH_RE.sub("/[id]", _ID_SEGMENT_RE.sub("/[id]", path))


router = APIRouter(prefix="/v1/events", tags=["events"])


class EventIn(BaseModel):
    name: ClientEventName
    path: str = Field("/", max_length=500)
    check_id: str | None = Field(None, pattern=r"^[A-Z]{2,5}-[0-9]{3}$")


@router.post("", status_code=204)
async def track(
    body: EventIn, request: Request, session: SessionDep, user: OptionalUser
) -> Response:
    if opted_out(request):
        return Response(status_code=204)
    visitor = visitor_for(request)
    limiter: RateLimiter = request.app.state.limiter
    if not (await limiter.hit(f"events:{visitor}", 300, 3600)).allowed:
        return Response(status_code=204)  # silently drop floods
    props: dict[str, Any] = {"path": page_template(body.path)}
    if body.check_id:
        props["check_id"] = body.check_id
    record(session, body.name, user_id=user.id if user else None, visitor=visitor, **props)
    await session.commit()
    return Response(status_code=204)
