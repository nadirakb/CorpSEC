from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_SECRET = "dev-only-change-me"  # noqa: S105 - development default, warned about at startup


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CORPSEC_", env_file=".env", extra="ignore")

    environment: Literal["development", "production"] = "development"
    """``production`` refuses to start with development defaults (see ``production_problems``)."""
    database_url: str = "postgresql+asyncpg://corpsec:corpsec@localhost:5432/corpsec"
    redis_url: str = "redis://localhost:6379/0"
    intel_path: str | None = None
    """Snapshot written by ``corpsec-intel-sync``; reloaded when the file changes. The worker
    refreshes it nightly."""
    wordfence_api_key: str | None = None
    """``CORPSEC_WORDFENCE_API_KEY``: WordPress vulnerabilities in the nightly refresh."""
    spamhaus_dqs_key: str | None = None
    """Spamhaus Data Query Service key for the blocklist checks (REP-001/002). Without it the
    free public servers are used, which allow only low-volume, non-commercial use and refuse
    queries from big public DNS resolvers."""
    internetdb_enabled: bool = False
    """Open-port check (PORT-001) from Shodan InternetDB. Off until its terms are confirmed
    for how this deployment is offered."""

    def check_config(self) -> dict[str, str]:
        config = {"internetdb": "on" if self.internetdb_enabled else "off"}
        if self.spamhaus_dqs_key:
            config["spamhaus_dqs_key"] = self.spamhaus_dqs_key
        return config

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

    def production_problems(self) -> list[str]:
        """Settings that are fine on a laptop but unsafe or broken on a public server."""
        problems: list[str] = []
        if self.secret_key == DEV_SECRET or len(self.secret_key) < 32:
            problems.append("CORPSEC_SECRET_KEY must be a random value of 32+ characters")
        web = urlsplit(self.web_url)
        if web.scheme != "https" or web.hostname in (None, "localhost", "127.0.0.1"):
            problems.append("CORPSEC_WEB_URL must be the public https:// address")
        if not self.cookie_secure:
            problems.append("CORPSEC_COOKIE_SECURE must stay on")
        if not self.smtp_host:
            problems.append("CORPSEC_SMTP_HOST is required: sign-in links are sent by email")
        elif self.smtp_host == "mailpit":
            problems.append("CORPSEC_SMTP_HOST points at the development mail catcher")
        if ":corpsec@" in self.database_url:
            problems.append("CORPSEC_DATABASE_URL uses the development database password")
        if any(o.startswith("http://") for o in self.extra_origins):
            problems.append("CORPSEC_EXTRA_ORIGINS must not list plain-http origins")
        return problems

    def check_production(self) -> None:
        if self.environment == "production" and (problems := self.production_problems()):
            raise RuntimeError("Refusing to start in production:\n- " + "\n- ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()
