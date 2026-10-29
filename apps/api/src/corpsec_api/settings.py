from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CORPSEC_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://corpsec:corpsec@localhost:5432/corpsec"
    redis_url: str = "redis://localhost:6379/0"
    intel_path: str | None = None
    """Snapshot written by ``corpsec-intel-sync``; reloaded when the file changes."""

    web_url: str = "http://localhost:3000"
    """Public address of the web app, used in emailed links."""
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
