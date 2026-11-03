from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_SECRET = "dev-only-change-me"  # noqa: S105 - development default, warned about at startup


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CORPSEC_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://corpsec:corpsec@localhost:5432/corpsec"
    redis_url: str = "redis://localhost:6379/0"
    intel_path: str | None = None
    """Snapshot written by ``corpsec-intel-sync``; reloaded when the file changes."""

    web_url: str = "http://localhost:3000"
    """Public address of the web app, used in emailed links. Its origin may make writes."""
    extra_origins: list[str] = []
    """Other origins the web app is served from (e.g. a direct dev port next to the proxy)."""
    cookie_secure: bool = True
    """Browsers accept Secure cookies on http://localhost, so this stays on in development."""
    session_days: int = 30
    login_token_minutes: int = 15

    smtp_host: str | None = None
    """No SMTP host: emails are written to the log (development only)."""
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_starttls: bool = True
    mail_from: str = "CorpSEC <no-reply@corpsec.app>"

    # Sign in with Google / Microsoft (OpenID Connect). A provider is offered only when both its
    # client id and secret are set. Redirect URI to register with the provider:
    # {web_url}/api/v1/auth/oauth/<google|microsoft>/callback
    google_client_id: str | None = None
    google_client_secret: str | None = None
    microsoft_client_id: str | None = None
    microsoft_client_secret: str | None = None
    microsoft_tenant: str = "common"
    """``common`` accepts work, school and personal accounts; a tenant id limits it to one org."""

    secret_key: str = DEV_SECRET
    """Signs opt-out tokens. Must be set to a long random value in production."""
    trusted_proxies: list[str] = ["127.0.0.1/32", "::1/128"]
    """Requests from these addresses may say who the real client is (X-Forwarded-For).
    In production put CorpSEC behind a reverse proxy that *overwrites* X-Forwarded-For
    (see deploy/Caddyfile) and list that proxy and the web app here."""

    # Rate limits (spec §10.3)
    anon_scans_per_hour: int = 5
    anon_scans_per_day: int = 20
    user_scans_per_day: int = 10
    max_sites_per_user: int = 3
    rechecks_per_hour: int = 30
    shares_per_day: int = 10
    same_target_minutes: int = 10
    """Anonymous scans of the same site within this window reuse the latest scan."""


@lru_cache
def get_settings() -> Settings:
    return Settings()
