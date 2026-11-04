"""Sign-in (spec §4.2): email magic link, and Google/Microsoft via OpenID Connect when configured.

No ``from __future__ import annotations``: FastAPI resolves annotations at runtime.
"""

import logging
import secrets
from datetime import timedelta
from typing import Annotated
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api import emails
from corpsec_api.db import AuditLog, LoginToken, OAuthFlow, User, UserIdentity, UserSession
from corpsec_api.deps import (
    SESSION_COOKIE,
    CurrentUser,
    MailerDep,
    OidcDep,
    SessionDep,
    SettingsDep,
    client_ip,
    token_hash,
)
from corpsec_api.oidc import OidcError, enabled_providers, verified_identity
from corpsec_api.settings import Settings
from corpsec_scanner.models import new_id, utcnow

router = APIRouter(prefix="/v1", tags=["auth"])
log = logging.getLogger("corpsec.auth")

MAX_LINKS_PER_EMAIL_HOUR = 5
MAX_LINKS_PER_IP_HOUR = 20
OAUTH_COOKIE = "corpsec_oauth_state"
OAUTH_FLOW_MINUTES = 10
MAX_OAUTH_STARTS_PER_IP_HOUR = 60


class MagicLinkIn(BaseModel):
    email: EmailStr
    next: str | None = Field(default=None, max_length=512)
    """Where to go after signing in. Only same-site paths are honoured."""


class VerifyIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class MeOut(BaseModel):
    id: str
    email: str
    weekly_digest: bool = False


class ProvidersOut(BaseModel):
    providers: list[str]
    """Enabled OAuth providers, e.g. ``["google", "microsoft"]``."""


def safe_next(path: str | None) -> str:
    # Only relative paths on this site: blocks open redirects like //evil.com or https://…
    if path and path.startswith("/") and not path.startswith("//") and "\\" not in path:
        return path
    return "/dashboard"


def start_session(
    session: AsyncSession, request: Request, user: User, settings: Settings, *, method: str
) -> str:
    """Add a browser session for ``user`` (caller commits). Returns the cookie value."""
    now = utcnow()
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
            target=f"{user.email} via {method}",
        )
    )
    return token


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_days * 86400,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


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
    token = start_session(session, request, user, settings, method="email")
    await session.commit()
    set_session_cookie(response, token, settings)
    return MeOut(id=user.id, email=user.email, weekly_digest=user.weekly_digest)


def oauth_redirect_uri(settings: Settings, provider: str) -> str:
    # Through the web app's /api rewrite, so the provider sends the browser back to our own origin.
    return f"{settings.web_url.rstrip('/')}/api/v1/auth/oauth/{provider}/callback"


def login_error(settings: Settings, code: str, next_path: str | None = None) -> RedirectResponse:
    query = {"error": code} | ({"next": next_path} if next_path else {})
    response = RedirectResponse(
        f"{settings.web_url.rstrip('/')}/login?{urlencode(query)}", status_code=303
    )
    response.delete_cookie(OAUTH_COOKIE, path="/")
    return response


@router.get("/auth/providers")
async def oauth_providers(settings: SettingsDep) -> ProvidersOut:
    return ProvidersOut(providers=list(enabled_providers(settings)))


@router.get("/auth/oauth/{provider}/start")
async def oauth_start(
    provider: str,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    oidc: OidcDep,
    next_path: Annotated[str | None, Query(alias="next", max_length=512)] = None,
) -> RedirectResponse:
    p = enabled_providers(settings).get(provider)
    if p is None:
        raise StarletteHTTPException(404, "This sign-in option isn't available.")
    next_path = safe_next(next_path)
    now = utcnow()
    ip = client_ip(request)
    await session.execute(delete(OAuthFlow).where(OAuthFlow.expires_at <= now))
    recent = await session.scalar(
        select(func.count()).where(
            OAuthFlow.requested_ip == ip, OAuthFlow.created_at >= now - timedelta(hours=1)
        )
    )
    if (recent or 0) >= MAX_OAUTH_STARTS_PER_IP_HOUR:
        await session.commit()
        return login_error(settings, "oauth_failed", next_path)

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    try:
        url = await oidc.authorization_url(
            p, oauth_redirect_uri(settings, provider), state, nonce, verifier
        )
    except OidcError as exc:
        log.warning("oauth start for %s failed: %s", provider, exc)
        await session.commit()
        return login_error(settings, exc.code, next_path)
    session.add(
        OAuthFlow(
            state_hash=token_hash(state),
            provider=provider,
            nonce=nonce,
            code_verifier=verifier,
            next_path=next_path,
            expires_at=now + timedelta(minutes=OAUTH_FLOW_MINUTES),
            requested_ip=ip,
        )
    )
    await session.commit()
    response = RedirectResponse(url, status_code=302)
    # Ties the callback to this browser, so nobody can sign someone else in to their account.
    response.set_cookie(
        OAUTH_COOKIE,
        state,
        max_age=OAUTH_FLOW_MINUTES * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/auth/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    oidc: OidcDep,
    code: Annotated[str | None, Query(max_length=4096)] = None,
    state: Annotated[str | None, Query(max_length=200)] = None,
    error: Annotated[str | None, Query(max_length=200)] = None,
) -> RedirectResponse:
    p = enabled_providers(settings).get(provider)
    if p is None:
        raise StarletteHTTPException(404, "This sign-in option isn't available.")
    cookie_state = request.cookies.get(OAUTH_COOKIE)
    if (
        not state
        or not cookie_state
        or not secrets.compare_digest(state.encode(), cookie_state.encode())
    ):
        return login_error(settings, "oauth_expired")
    now = utcnow()
    flow = await session.scalar(
        select(OAuthFlow).where(OAuthFlow.state_hash == token_hash(state)).with_for_update()
    )
    if flow is None or flow.provider != provider or flow.expires_at <= now:
        return login_error(settings, "oauth_expired")
    await session.delete(flow)  # single use, whatever happens next
    await session.commit()
    if error or not code:
        # e.g. access_denied when the person pressed Cancel at the provider
        return login_error(settings, "oauth_cancelled", flow.next_path)

    try:
        claims = await oidc.exchange(
            p, code, oauth_redirect_uri(settings, provider), flow.code_verifier, flow.nonce
        )
        identity = verified_identity(p, claims)
    except OidcError as exc:
        log.warning("oauth sign-in with %s refused: %s", provider, exc)
        return login_error(settings, exc.code, flow.next_path)

    # The provider's subject is the stable key; email is only used to link the first time.
    link = await session.scalar(
        select(UserIdentity).where(
            UserIdentity.provider == provider, UserIdentity.subject == identity.subject
        )
    )
    if link is not None:
        user = await session.get(User, link.user_id)
    else:
        user = await session.scalar(select(User).where(User.email == identity.email))
        if user is None:
            user = User(id=new_id("usr"), email=identity.email)
            session.add(user)
        link = UserIdentity(
            user_id=user.id, provider=provider, subject=identity.subject, email=identity.email
        )
        session.add(link)
        session.add(
            AuditLog(
                actor_user_id=user.id,
                actor_ip=client_ip(request),
                action="auth.link",
                target=f"{provider}:{identity.email}",
            )
        )
    if user is None or user.deleted_at is not None:
        return login_error(settings, "account_deleted")
    link.email = identity.email
    link.last_login_at = now

    token = start_session(session, request, user, settings, method=provider)
    await session.commit()
    response = RedirectResponse(f"{settings.web_url.rstrip('/')}{flow.next_path}", status_code=303)
    set_session_cookie(response, token, settings)
    response.delete_cookie(OAUTH_COOKIE, path="/")
    return response


@router.get("/me")
async def me(user: CurrentUser) -> MeOut:
    return MeOut(id=user.id, email=user.email, weekly_digest=user.weekly_digest)


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
