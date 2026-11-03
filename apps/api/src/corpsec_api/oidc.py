"""OpenID Connect sign-in with Google and Microsoft (spec §4.2).

Authorization-code flow with PKCE, ``state`` and ``nonce``. Endpoints and signing keys come from
each provider's discovery document; the ID token is checked for signature, issuer, audience,
expiry and nonce before any of its claims are used.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

from corpsec_api.settings import Settings

# Personal Microsoft accounts (outlook.com, hotmail.com, …) all sign in through this tenant.
MICROSOFT_CONSUMER_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
CACHE_SECONDS = 3600
CLOCK_SKEW_SECONDS = 60


class OidcError(Exception):
    """Sign-in can't continue. ``code`` is what the web app is told (``/login?error=…``)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class Provider:
    id: str
    discovery_url: str
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class Identity:
    subject: str
    email: str


def enabled_providers(settings: Settings) -> dict[str, Provider]:
    """Providers whose client id and secret are both configured."""
    found: dict[str, Provider] = {}
    if settings.google_client_id and settings.google_client_secret:
        found["google"] = Provider(
            "google",
            "https://accounts.google.com/.well-known/openid-configuration",
            settings.google_client_id,
            settings.google_client_secret,
        )
    if settings.microsoft_client_id and settings.microsoft_client_secret:
        found["microsoft"] = Provider(
            "microsoft",
            f"https://login.microsoftonline.com/{settings.microsoft_tenant}"
            "/v2.0/.well-known/openid-configuration",
            settings.microsoft_client_id,
            settings.microsoft_client_secret,
        )
    return found


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _truthy(value: Any) -> bool:
    return value is True or value == "true"


def verified_identity(provider: Provider, claims: dict[str, Any]) -> Identity:
    """The account's subject and email, if the provider vouches for the email.

    Google sets ``email_verified``. Microsoft's ``email`` claim is not verified by default: we
    accept it from personal accounts (Microsoft verifies those) or when ``xms_edov`` says the
    email domain's owner is verified (an optional claim to enable in the app registration).
    """
    email = claims.get("email")
    if not isinstance(email, str) or "@" not in email:
        raise OidcError("oauth_unverified", "no email in ID token")
    if provider.id == "google":
        verified = _truthy(claims.get("email_verified"))
    else:
        verified = claims.get("tid") == MICROSOFT_CONSUMER_TENANT or _truthy(claims.get("xms_edov"))
    if not verified:
        raise OidcError("oauth_unverified", f"{provider.id} did not verify {email}")
    return Identity(subject=str(claims["sub"]), email=email.strip().lower())


class OidcClient:
    """Talks to providers. Discovery documents and key sets are cached for an hour."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self.http = http
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}

    async def _get_json(self, url: str, *, fresh: bool = False) -> dict[str, Any]:
        cached = self._cache.get(url)
        if cached and not fresh and cached[0] > time.monotonic():
            return cached[1]
        try:
            r = await self.http.get(url)
            r.raise_for_status()
            body = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OidcError("oauth_failed", f"fetching {url}: {exc}") from exc
        if not isinstance(body, dict):
            raise OidcError("oauth_failed", f"{url} did not return an object")
        self._cache[url] = (time.monotonic() + CACHE_SECONDS, body)
        return body

    async def metadata(self, provider: Provider) -> dict[str, Any]:
        meta = await self._get_json(provider.discovery_url)
        for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = meta.get(key)
            if not isinstance(value, str) or urlsplit(value).scheme != "https":
                raise OidcError("oauth_failed", f"discovery for {provider.id} lacks {key}")
        return meta

    async def authorization_url(
        self, provider: Provider, redirect_uri: str, state: str, nonce: str, verifier: str
    ) -> str:
        meta = await self.metadata(provider)
        query = {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        return f"{meta['authorization_endpoint']}?{urlencode(query)}"

    async def exchange(
        self, provider: Provider, code: str, redirect_uri: str, verifier: str, nonce: str
    ) -> dict[str, Any]:
        """Trade the code for tokens and return the validated ID token's claims."""
        meta = await self.metadata(provider)
        try:
            r = await self.http.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": provider.client_id,
                    "client_secret": provider.client_secret,
                    "code_verifier": verifier,
                },
                headers={"accept": "application/json"},
            )
            body = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OidcError("oauth_failed", f"token request failed: {exc}") from exc
        id_token = body.get("id_token") if isinstance(body, dict) else None
        if r.status_code != 200 or not isinstance(id_token, str):
            error = body.get("error") if isinstance(body, dict) else None
            raise OidcError("oauth_failed", f"token endpoint said {r.status_code} {error}")
        return await self.validate_id_token(provider, meta, id_token, nonce)

    async def _signing_key(self, jwks_uri: str, kid: str | None) -> jwt.PyJWK:
        for fresh in (False, True):  # refetch once: the provider may have rotated its keys
            jwks = await self._get_json(jwks_uri, fresh=fresh)
            try:
                keys = jwt.PyJWKSet.from_dict(jwks).keys
            except jwt.PyJWTError as exc:
                raise OidcError("oauth_failed", f"bad key set: {exc}") from exc
            for key in keys:
                if key.key_id == kid or (kid is None and len(keys) == 1):
                    return key
        raise OidcError("oauth_failed", f"no signing key {kid!r}")

    async def validate_id_token(
        self, provider: Provider, meta: dict[str, Any], id_token: str, nonce: str
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcError("oauth_failed", f"malformed ID token: {exc}") from exc
        if header.get("alg") != "RS256":
            raise OidcError("oauth_failed", f"unexpected alg {header.get('alg')!r}")
        key = await self._signing_key(meta["jwks_uri"], header.get("kid"))
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key.key,
                algorithms=["RS256"],
                audience=provider.client_id,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError("oauth_failed", f"ID token rejected: {exc}") from exc

        # Microsoft's multi-tenant discovery gives an issuer template: .../{tenantid}/v2.0
        if provider.id == "google":
            issuers: tuple[str, ...] = (meta["issuer"], *GOOGLE_ISSUERS)
        else:
            tid = claims.get("tid")
            if not isinstance(tid, str) or not tid:
                raise OidcError("oauth_failed", "ID token has no tenant")
            issuers = (meta["issuer"].replace("{tenantid}", tid),)
        if claims["iss"] not in issuers:
            raise OidcError("oauth_failed", f"unexpected issuer {claims['iss']!r}")
        aud = claims["aud"]
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != provider.client_id:
            raise OidcError("oauth_failed", "ID token issued to another party")
        if not secrets.compare_digest(str(claims["nonce"]).encode(), nonce.encode()):
            raise OidcError("oauth_failed", "nonce mismatch")
        return claims
