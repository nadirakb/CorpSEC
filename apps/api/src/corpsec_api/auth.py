"""Email magic-link sign-in (spec §4.2). OAuth providers can be added beside it later.

No ``from __future__ import annotations``: FastAPI resolves annotations at runtime.
"""

import secrets
from datetime import timedelta
from urllib.parse import quote

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api import emails
from corpsec_api.db import AuditLog, LoginToken, User, UserSession
from corpsec_api.deps import (
    SESSION_COOKIE,
    CurrentUser,
    MailerDep,
    SessionDep,
    SettingsDep,
    client_ip,
    token_hash,
)
from corpsec_scanner.models import new_id, utcnow

router = APIRouter(prefix="/v1", tags=["auth"])

MAX_LINKS_PER_EMAIL_HOUR = 5
MAX_LINKS_PER_IP_HOUR = 20


class MagicLinkIn(BaseModel):
    email: EmailStr
    next: str | None = Field(default=None, max_length=512)
    """Where to go after signing in. Only same-site paths are honoured."""


class VerifyIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class MeOut(BaseModel):
    id: str
    email: str


def safe_next(path: str | None) -> str:
    # Only relative paths on this site: blocks open redirects like //evil.com or https://…
    if path and path.startswith("/") and not path.startswith("//") and "\\" not in path:
        return path
    return "/dashboard"


@router.post("/auth/magic-link", status_code=202)
async def request_magic_link(
    body: MagicLinkIn,
    request: Request,
    session: SessionDep,
    mailer: MailerDep,
    settings: SettingsDep,
) -> dict[str, str]:
    email = body.email.lower()
    ip = client_ip(request)
    since = utcnow() - timedelta(hours=1)
    per_email = await session.scalar(
        select(func.count()).where(LoginToken.email == email, LoginToken.created_at >= since)
    )
    per_ip = await session.scalar(
        select(func.count()).where(LoginToken.requested_ip == ip, LoginToken.created_at >= since)
    )
    # The answer is the same whether or not we send, so it doesn't reveal accounts or limits.
    response = {"status": "sent"}
    if (per_email or 0) >= MAX_LINKS_PER_EMAIL_HOUR or (per_ip or 0) >= MAX_LINKS_PER_IP_HOUR:
        return response

    token = secrets.token_urlsafe(32)
    session.add(
        LoginToken(
            email=email,
            token_hash=token_hash(token),
            expires_at=utcnow() + timedelta(minutes=settings.login_token_minutes),
            requested_ip=ip,
        )
    )
    await session.commit()
    link = (
        f"{settings.web_url.rstrip('/')}/auth/verify?token={quote(token)}"
        f"&next={quote(safe_next(body.next))}"
    )
    await mailer.send(emails.magic_link(email, link, settings.login_token_minutes))
    return response


@router.post("/auth/verify")
async def verify_magic_link(
    body: VerifyIn,
    request: Request,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
) -> MeOut:
    now = utcnow()
    row = await session.scalar(
        select(LoginToken).where(LoginToken.token_hash == token_hash(body.token)).with_for_update()
    )
    if row is None or row.used_at is not None or row.expires_at <= now:
        raise StarletteHTTPException(
            400, "This sign-in link has expired or was already used. Please ask for a new one."
        )
    row.used_at = now

    user = await session.scalar(select(User).where(User.email == row.email))
    if user is None:
        user = User(id=new_id("usr"), email=row.email)
        session.add(user)
    elif user.deleted_at is not None:
        raise StarletteHTTPException(400, "This account was deleted.")
    user.last_login_at = now

    token = secrets.token_urlsafe(32)
    session.add(
        UserSession(
            user_id=user.id,
            token_hash=token_hash(token),
            expires_at=now + timedelta(days=settings.session_days),
            last_seen_at=now,
            user_agent=(request.headers.get("user-agent") or "")[:256],
        )
    )
    session.add(
        AuditLog(
            actor_user_id=user.id,
            actor_ip=client_ip(request),
            action="auth.login",
            target=user.email,
        )
    )
    await session.commit()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_days * 86400,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return MeOut(id=user.id, email=user.email)


@router.get("/me")
async def me(user: CurrentUser) -> MeOut:
    return MeOut(id=user.id, email=user.email)


@router.post("/auth/logout", status_code=204)
async def logout(request: Request, response: Response, session: SessionDep) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        row = await session.scalar(
            select(UserSession).where(UserSession.token_hash == token_hash(token))
        )
        if row is not None:
            await session.delete(row)
            await session.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.status_code = 204
    return response
