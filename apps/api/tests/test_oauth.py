"""Google/Microsoft sign-in against a fake OpenID Connect provider."""

import secrets
import time
from collections.abc import AsyncIterator, Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import OAuthFlow, UserIdentity
from corpsec_api.mailer import MemoryMailer
from corpsec_api.oidc import MICROSOFT_CONSUMER_TENANT, pkce_challenge
from corpsec_api.settings import Settings

from .conftest import WEB_URL, pytestmark, sign_in  # noqa: F401

GOOGLE_ISSUER = "https://accounts.google.com"
MS_TENANT = "72f988bf-0000-0000-0000-000000000001"
MS_BASE = "https://login.microsoftonline.com"
CLIENT_IDS = {"google": "google-client", "microsoft": "ms-client"}
SECRETS = {"google": "google-secret", "microsoft": "ms-secret"}


class FakeProvider:
    """Discovery, JWKS and token endpoints for both providers, signing with a generated key."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "test-key"
        self.codes: dict[str, dict[str, Any]] = {}
        self.claims: dict[str, Any] = {}
        """Extra or replacement ID-token claims for the next sign-in."""
        self.sign_with: Any = None
        """Sign with this key instead (to simulate a forged token)."""

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == f"{GOOGLE_ISSUER}/.well-known/openid-configuration":
            return httpx.Response(200, json=self.discovery(GOOGLE_ISSUER, "google"))
        if url == f"{MS_BASE}/common/v2.0/.well-known/openid-configuration":
            return httpx.Response(
                200, json=self.discovery(f"{MS_BASE}/{{tenantid}}/v2.0", "microsoft")
            )
        if url.endswith("/jwks"):
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
            return httpx.Response(200, json={"keys": [jwk | {"kid": self.kid, "use": "sig"}]})
        if url.endswith("/token") and request.method == "POST":
            return self.token(request)
        return httpx.Response(404)

    def discovery(self, issuer: str, name: str) -> dict[str, str]:
        base = f"https://idp.test/{name}"
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": f"{base}/jwks",
        }

    def authorize(self, location: str, sub: str, email: str) -> dict[str, str]:
        """What the provider does after the person signs in: returns the callback query."""
        url = urlsplit(location)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        provider = url.path.split("/")[1]
        assert q["response_type"] == "code"
        assert q["client_id"] == CLIENT_IDS[provider]
        assert q["code_challenge_method"] == "S256"
        assert q["redirect_uri"] == f"{WEB_URL}/api/v1/auth/oauth/{provider}/callback"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "provider": provider,
            "challenge": q["code_challenge"],
            "redirect_uri": q["redirect_uri"],
            "nonce": q["nonce"],
            "sub": sub,
            "email": email,
        }
        return {"code": code, "state": q["state"]}

    def token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        grant = self.codes.pop(form.get("code", ""), None)
        if grant is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        provider = grant["provider"]
        if (
            form["client_id"] != CLIENT_IDS[provider]
            or form["client_secret"] != SECRETS[provider]
            or form["redirect_uri"] != grant["redirect_uri"]
            or pkce_challenge(form["code_verifier"]) != grant["challenge"]
        ):
            return httpx.Response(400, json={"error": "invalid_grant"})
        now = int(time.time())
        claims: dict[str, Any] = {
            "aud": CLIENT_IDS[provider],
            "sub": grant["sub"],
            "email": grant["email"],
            "iat": now,
            "exp": now + 300,
            "nonce": grant["nonce"],
        }
        if provider == "google":
            claims |= {"iss": GOOGLE_ISSUER, "email_verified": True}
        else:
            claims |= {"iss": f"{MS_BASE}/{MS_TENANT}/v2.0", "tid": MS_TENANT, "xms_edov": True}
        claims |= self.claims
        claims = {k: v for k, v in claims.items() if v is not None}
        token = jwt.encode(
            claims, self.sign_with or self.key, algorithm="RS256", headers={"kid": self.kid}
        )
        return httpx.Response(200, json={"id_token": token, "token_type": "Bearer"})


@pytest.fixture
def idp() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
async def oauth_http(idp: FakeProvider) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.MockTransport(idp.handler)) as c:
        yield c


@pytest.fixture
def settings() -> Settings:
    return Settings(
        web_url=WEB_URL,
        smtp_host=None,
        google_client_id=CLIENT_IDS["google"],
        google_client_secret=SECRETS["google"],
        microsoft_client_id=CLIENT_IDS["microsoft"],
        microsoft_client_secret=SECRETS["microsoft"],
    )


async def oauth_sign_in(
    client: httpx.AsyncClient,
    idp: FakeProvider,
    provider: str = "google",
    *,
    sub: str = "sub-1",
    email: str = "leyla@bakery.az",
    next_path: str = "/sites",
) -> httpx.Response:
    """Start, "sign in" at the fake provider, and follow the callback. Returns the callback."""
    r = await client.get(f"/v1/auth/oauth/{provider}/start", params={"next": next_path})
    assert r.status_code == 302, r.text
    query = idp.authorize(r.headers["location"], sub, email)
    return await client.get(f"/v1/auth/oauth/{provider}/callback", params=query)


def login_error(r: httpx.Response) -> str | None:
    assert r.status_code == 303
    url = urlsplit(r.headers["location"])
    assert f"{url.scheme}://{url.netloc}{url.path}" == f"{WEB_URL}/login"
    return parse_qs(url.query)["error"][0]


async def test_providers_listed(client: httpx.AsyncClient) -> None:
    r = await client.get("/v1/auth/providers")
    assert r.json() == {"providers": ["google", "microsoft"]}


@pytest.mark.parametrize("provider", ["google", "microsoft"])
async def test_sign_in_creates_account(
    client: httpx.AsyncClient,
    idp: FakeProvider,
    provider: str,
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    r = await oauth_sign_in(client, idp, provider, email="Leyla@Bakery.AZ")
    assert r.status_code == 303
    assert r.headers["location"] == f"{WEB_URL}/sites"
    cookies = r.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith("corpsec_session=")).lower()
    assert "httponly" in session_cookie and "secure" in session_cookie
    assert "samesite=lax" in session_cookie
    assert any(c.startswith("corpsec_oauth_state=") and "max-age=0" in c.lower() for c in cookies)

    me = (await client.get("/v1/me")).json()
    assert me["email"] == "leyla@bakery.az"
    async with sessions() as s:
        [identity] = (await s.scalars(select(UserIdentity))).all()
        assert (identity.provider, identity.subject, identity.user_id) == (
            provider,
            "sub-1",
            me["id"],
        )
        assert (await s.scalars(select(OAuthFlow))).all() == []


async def test_links_existing_magic_link_account(
    app_factory: Callable[[], httpx.AsyncClient], idp: FakeProvider, mailer: MemoryMailer
) -> None:
    async with app_factory() as a, app_factory() as b, app_factory() as c:
        user_id = await sign_in(a, mailer, "leyla@bakery.az")
        await oauth_sign_in(b, idp, "google", sub="g-1", email="leyla@bakery.az")
        assert (await b.get("/v1/me")).json()["id"] == user_id
        # Later the Google account's email changes: the subject still finds the same person.
        await oauth_sign_in(c, idp, "google", sub="g-1", email="leyla@new-bakery.az")
        me = (await c.get("/v1/me")).json()
        assert me == {"id": user_id, "email": "leyla@bakery.az"}


async def test_bad_state_is_refused(
    app_factory: Callable[[], httpx.AsyncClient], idp: FakeProvider
) -> None:
    async with app_factory() as attacker, app_factory() as victim:
        r = await attacker.get("/v1/auth/oauth/google/start")
        query = idp.authorize(r.headers["location"], "attacker", "evil@example.com")
        # The attacker's callback link opened in someone else's browser (login CSRF)
        r = await victim.get("/v1/auth/oauth/google/callback", params=query)
        assert login_error(r) == "oauth_expired"
        assert (await victim.get("/v1/me")).status_code == 401
        # A state that doesn't match the cookie
        r = await attacker.get("/v1/auth/oauth/google/callback", params=query | {"state": "x" * 43})
        assert login_error(r) == "oauth_expired"
        assert (await attacker.get("/v1/me")).status_code == 401


async def test_flow_is_single_use(client: httpx.AsyncClient, idp: FakeProvider) -> None:
    r = await client.get("/v1/auth/oauth/google/start")
    state_cookie = client.cookies["corpsec_oauth_state"]
    query = idp.authorize(r.headers["location"], "sub-1", "a@bakery.az")
    assert (await client.get("/v1/auth/oauth/google/callback", params=query)).status_code == 303
    client.cookies.set("corpsec_oauth_state", state_cookie)
    r = await client.get("/v1/auth/oauth/google/callback", params=query)
    assert login_error(r) == "oauth_expired"


async def test_cancelled_at_provider(client: httpx.AsyncClient) -> None:
    r = await client.get("/v1/auth/oauth/google/start", params={"next": "/sites"})
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    r = await client.get(
        "/v1/auth/oauth/google/callback", params={"state": state, "error": "access_denied"}
    )
    assert login_error(r) == "oauth_cancelled"
    assert "next=%2Fsites" in r.headers["location"]


@pytest.mark.parametrize(
    ("provider", "claims"),
    [
        ("google", {"nonce": "not-the-nonce"}),
        ("google", {"aud": "someone-else"}),
        ("google", {"iss": "https://evil.example"}),
        ("google", {"exp": int(time.time()) - 600}),
        ("google", {"nonce": None}),
        ("microsoft", {"iss": f"{MS_BASE}/another-tenant/v2.0"}),
        ("microsoft", {"tid": None}),
    ],
)
async def test_invalid_id_token_is_refused(
    client: httpx.AsyncClient, idp: FakeProvider, provider: str, claims: dict[str, Any]
) -> None:
    idp.claims = claims
    r = await oauth_sign_in(client, idp, provider)
    assert login_error(r) == "oauth_failed"
    assert (await client.get("/v1/me")).status_code == 401


async def test_forged_signature_is_refused(client: httpx.AsyncClient, idp: FakeProvider) -> None:
    idp.sign_with = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    r = await oauth_sign_in(client, idp)
    assert login_error(r) == "oauth_failed"


@pytest.mark.parametrize(
    ("provider", "claims"),
    [
        ("google", {"email_verified": False}),
        ("google", {"email_verified": None}),
        ("google", {"email": None}),
        ("microsoft", {"xms_edov": None}),
        ("microsoft", {"xms_edov": False}),
    ],
)
async def test_unverified_email_is_refused(
    client: httpx.AsyncClient,
    idp: FakeProvider,
    mailer: MemoryMailer,
    app_factory: Callable[[], httpx.AsyncClient],
    provider: str,
    claims: dict[str, Any],
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with app_factory() as owner:
        await sign_in(owner, mailer, "leyla@bakery.az")
    idp.claims = claims
    r = await oauth_sign_in(client, idp, provider, email="leyla@bakery.az")
    assert login_error(r) == "oauth_unverified"
    assert (await client.get("/v1/me")).status_code == 401
    async with sessions() as s:
        assert (await s.scalars(select(UserIdentity))).all() == []


async def test_microsoft_personal_account(client: httpx.AsyncClient, idp: FakeProvider) -> None:
    idp.claims = {
        "tid": MICROSOFT_CONSUMER_TENANT,
        "iss": f"{MS_BASE}/{MICROSOFT_CONSUMER_TENANT}/v2.0",
        "xms_edov": None,
    }
    r = await oauth_sign_in(client, idp, "microsoft", email="leyla@outlook.com")
    assert r.status_code == 303 and r.headers["location"] == f"{WEB_URL}/sites"
    assert (await client.get("/v1/me")).json()["email"] == "leyla@outlook.com"


async def test_next_is_kept_on_site(client: httpx.AsyncClient, idp: FakeProvider) -> None:
    r = await oauth_sign_in(client, idp, next_path="//evil.com")
    assert r.headers["location"] == f"{WEB_URL}/dashboard"


@pytest.mark.parametrize(
    "settings", [Settings(web_url=WEB_URL, smtp_host=None, google_client_id=None)]
)
async def test_disabled_provider(client: httpx.AsyncClient, settings: Settings) -> None:
    assert settings.google_client_id is None
    assert (await client.get("/v1/auth/providers")).json() == {"providers": []}
    assert (await client.get("/v1/auth/oauth/google/start")).status_code == 404
    r = await client.get("/v1/auth/oauth/google/callback", params={"code": "x", "state": "y"})
    assert r.status_code == 404
    assert (await client.get("/v1/auth/oauth/github/start")).status_code == 404
