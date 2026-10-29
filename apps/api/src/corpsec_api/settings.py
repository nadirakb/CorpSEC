from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CORPSEC_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://corpsec:corpsec@localhost:5432/corpsec"
    redis_url: str = "redis://localhost:6379/0"
    intel_path: str | None = None
    """Snapshot written by ``corpsec-intel-sync``; reloaded when the file changes."""


@lru_cache
def get_settings() -> Settings:
    return Settings()
